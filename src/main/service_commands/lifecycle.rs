use super::*;

pub(super) async fn run_foreground_command(
    config: Option<&PathBuf>,
    command: RunCommand,
) -> Result<()> {
    let default_state_dir = process_manager::default_state_dir();
    let run_paths = resolve_run_paths(
        default_state_dir,
        env::var_os("TABBYMEW_STATE_FILE").map(PathBuf::from),
        env::var_os("TABBYMEW_STATE_DIR").map(PathBuf::from),
        env::var_os("TABBYMEW_LOG_FILE").map(PathBuf::from),
    )?;
    let config_path = resolve_launch_config_path(config, &run_paths.state_dir)?;
    let config = Config::load(&config_path)?;
    let level = config
        .log
        .as_ref()
        .map(|log| log.level.as_str())
        .unwrap_or("info");
    init_logging(level, run_paths.log_file.as_deref())?;
    validate_runtime_config(&config, config_base_dir(&config_path))?;
    let options = app::RunOptions {
        config_path: Some(config_path.clone()),
        control_listen: command
            .control_listen
            .or_else(|| env::var("TABBYMEW_CONTROL_LISTEN").ok())
            .or_else(|| env::var("TABBYMEW_CONSOLE_LISTEN").ok()),
        log_file: run_paths.log_file,
        state_file: run_paths.state_file,
        state_dir: run_paths.state_dir,
    };
    app::run(
        config,
        config_base_dir(&config_path).map(Path::to_path_buf),
        options,
    )
    .await
}

pub(super) fn run_start_command(config: Option<&PathBuf>, command: StartCommand) -> Result<()> {
    let state_dir = command
        .state_dir
        .unwrap_or_else(process_manager::default_state_dir);
    let json = command.json;
    let start_paths = process_manager::paths(&state_dir, command.log.as_deref());
    let cleanup_report = cleanup_service_state(&state_dir)?;
    let mut warnings = Vec::new();
    if !cleanup_report.ok {
        let warning =
            "failed to clean stale TabbyMew-owned runtime state before start; run `TabbyMew cleanup`"
                .to_string();
        if json {
            warnings.push(warning);
        } else {
            eprintln!("warning: {warning}");
        }
    }
    let config_path = resolve_launch_config_path(config, &state_dir)?;
    let config = Config::load(&config_path)?;
    validate_runtime_config(&config, config_base_dir(&config_path))?;
    let state = process_manager::start(StartOptions {
        config: config_path,
        state_dir: state_dir.clone(),
        log: command.log,
        control_listen: command.control_listen,
    })?;
    if json {
        let report = start_json_report(&state, &state_dir, &start_paths.state_file, warnings);
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_start_report(io::stdout().lock(), &state)?;
    }
    Ok(())
}

pub(super) fn run_stop_command(command: StopCommand) -> Result<()> {
    let state_dir = command
        .state_dir
        .unwrap_or_else(process_manager::default_state_dir);
    let paths = process_manager::paths(&state_dir, None);
    let json = command.json;
    let state_from_file = command.pid.is_none();
    let (state, state_file) = match command.pid {
        Some(pid) => (
            ProcessState {
                pid,
                config: PathBuf::new(),
                log: paths.log_file.clone(),
                listen: None,
                control_token: None,
                started_at_unix: 0,
                heartbeat_at_unix: None,
            },
            paths.state_file.clone(),
        ),
        None => match load_local_process_state_for_stop(&state_dir)? {
            Some(state) => state,
            None => {
                let message = "TabbyMew is not running; no local state file found";
                if json {
                    let report = stop_json_report(StopJsonReportInput {
                        ok: true,
                        status: "not_running",
                        message: message.to_string(),
                        pid: None,
                        state_dir: &state_dir,
                        state_file: &paths.state_file,
                        log_file: None,
                        removed_state_file: false,
                        terminated: false,
                    });
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("{message}");
                }
                return Ok(());
            }
        },
    };
    if !process_manager::is_process_running(state.pid) {
        if state_from_file {
            let log_path = owned_lifecycle_log_path(&state_dir, &state.log);
            record_process_lifecycle_event(
                log_path,
                &state,
                "stale_state_removed_by_stop",
                vec![("state_file", state_file.display().to_string())],
            );
            process_manager::remove_state_file(&state_file)?;
            let message = format!(
                "TabbyMew is not running; removed stale state for pid {}",
                state.pid
            );
            if json {
                let report = stop_json_report(StopJsonReportInput {
                    ok: true,
                    status: "stale_removed",
                    message: message.clone(),
                    pid: Some(state.pid),
                    state_dir: &state_dir,
                    state_file: &state_file,
                    log_file: Some(&state.log),
                    removed_state_file: true,
                    terminated: false,
                });
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{message}");
            }
        } else {
            let message = format!("TabbyMew is not running for pid {}", state.pid);
            if json {
                let report = stop_json_report(StopJsonReportInput {
                    ok: true,
                    status: "not_running",
                    message: message.clone(),
                    pid: Some(state.pid),
                    state_dir: &state_dir,
                    state_file: &state_file,
                    log_file: Some(&state.log),
                    removed_state_file: false,
                    terminated: false,
                });
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{message}");
            }
        }
        return Ok(());
    }
    let log_path = if state_from_file {
        owned_lifecycle_log_path(&state_dir, &state.log)
    } else {
        None
    };
    record_process_lifecycle_event(
        log_path,
        &state,
        "stop_requested",
        vec![
            ("force", command.force.to_string()),
            ("timeout_ms", command.timeout_ms.to_string()),
        ],
    );
    let stopped = match process_manager::stop(
        state.pid,
        command.force,
        timeout_duration(command.timeout_ms)?,
    ) {
        Ok(stopped) => {
            record_process_lifecycle_event(
                log_path,
                &state,
                "stop_completed",
                vec![("terminated", stopped.to_string())],
            );
            stopped
        }
        Err(err) => {
            record_process_lifecycle_event(
                log_path,
                &state,
                "stop_failed",
                vec![("error", format!("{err:#}"))],
            );
            return Err(err);
        }
    };
    if command.pid.is_none() {
        process_manager::remove_state_file(&state_file)?;
    }
    let message = format!("stopped TabbyMew pid {}", state.pid);
    if json {
        let report = stop_json_report(StopJsonReportInput {
            ok: true,
            status: "stopped",
            message: message.clone(),
            pid: Some(state.pid),
            state_dir: &state_dir,
            state_file: &state_file,
            log_file: Some(&state.log),
            removed_state_file: command.pid.is_none(),
            terminated: stopped,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{message}");
    }
    Ok(())
}

pub(super) fn run_cleanup_command(command: CleanupCommand) -> Result<()> {
    let state_dir = command
        .state_dir
        .unwrap_or_else(process_manager::default_state_dir);
    let report = cleanup_service_state(&state_dir)?;
    if command.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_cleanup_report(io::stdout().lock(), &report)?;
    }
    Ok(())
}

pub(super) async fn run_doctor_command(command: DoctorCommand) -> Result<()> {
    let state_dir = command
        .state_dir
        .unwrap_or_else(process_manager::default_state_dir);
    let timeout = timeout_duration(command.timeout_ms)?;
    let report = doctor_service_state(&state_dir, timeout).await;
    if command.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_doctor_report(io::stdout().lock(), &report)?;
    }
    Ok(())
}

pub(super) fn run_logs_command(command: LogsCommand) -> Result<()> {
    let log_path = match command.log {
        Some(log) => log,
        None => {
            let state_dir = command
                .state_dir
                .unwrap_or_else(process_manager::default_state_dir);
            let paths = process_manager::paths(&state_dir, None);
            process_manager::load_state(&paths.state_file)?.log
        }
    };
    if command.follow && command.json {
        bail!("logs --json does not support --follow");
    }
    if command.follow {
        follow_log(&log_path, command.lines)?;
    } else {
        let content = process_manager::read_log_tail(&log_path, command.lines)?;
        if command.json {
            let report = logs_json_report(&log_path, command.lines, content);
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            print!("{content}");
        }
    }
    Ok(())
}

pub(super) async fn run_status_command(command: StatusCommand) -> Result<()> {
    let state_dir = command
        .state_dir
        .unwrap_or_else(process_manager::default_state_dir);
    let timeout = timeout_duration(command.timeout_ms)?;
    let output = build_status_report(&state_dir, command.listen, timeout).await?;
    if command.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print_status_report(io::stdout().lock(), &output)?;
    }
    Ok(())
}

pub(super) fn load_local_process_state_for_stop(
    state_dir: &Path,
) -> Result<Option<(ProcessState, PathBuf)>> {
    let paths = process_manager::paths(state_dir, None);
    let runtime_state_file = process_manager::runtime_state_file(state_dir);
    for state_file in [&paths.state_file, &runtime_state_file] {
        match process_manager::load_state(state_file) {
            Ok(state) => return Ok(Some((state, state_file.clone()))),
            Err(_) if !state_file.exists() => {}
            Err(err) => {
                process_manager::remove_state_file(state_file)?;
                println!(
                    "removed unreadable TabbyMew state file {} ({err:#})",
                    state_file.display()
                );
            }
        }
    }
    Ok(None)
}
