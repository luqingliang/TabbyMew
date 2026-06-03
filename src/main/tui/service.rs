use super::*;

pub(super) async fn ensure_tui_service_running(session: &ShellSession) -> Result<TuiServiceStartup> {
    let status = process_manager::service_status(&session.state_dir);
    if status.running {
        if service_status_is_runtime_state(&status)
            && let Some(message) = adopt_independent_runtime(session).await?
        {
            return Ok(TuiServiceStartup {
                kind: TuiServiceStartupKind::AdoptedRuntime,
                message,
            });
        }
        return Ok(TuiServiceStartup {
            kind: TuiServiceStartupKind::Existing,
            message: tui_running_service_startup_message(&status, session.timeout).await,
        });
    }
    if let Some(message) = adopt_independent_runtime(session).await? {
        return Ok(TuiServiceStartup {
            kind: TuiServiceStartupKind::AdoptedRuntime,
            message,
        });
    }

    let output = tui_start_service(session).await?;
    let start_summary = first_non_empty_line(&output).unwrap_or("service started");
    Ok(TuiServiceStartup {
        kind: TuiServiceStartupKind::Started,
        message: format!(
            "TabbyMew service started ({start_summary}). Press q to detach the TUI, or /quit to stop the service."
        ),
    })
}

pub(super) fn service_status_is_runtime_state(status: &ServiceStatus) -> bool {
    status.state_source.as_deref() == Some("runtime")
}

pub(super) async fn tui_running_service_startup_message(status: &ServiceStatus, timeout: Duration) -> String {
    let service = status
        .pid
        .map(|pid| format!("TabbyMew service pid {pid} is running"))
        .unwrap_or_else(|| "TabbyMew service is running".to_string());
    let controls = "Press q to detach the TUI, or /quit to stop the service.";
    let Some(listen) = status.listen.as_deref() else {
        return format!(
            "{service}, but no control API listen address is recorded. Run /restart or `TabbyMew doctor`. {controls}"
        );
    };
    let listen = match control::parse_listen(listen) {
        Ok(listen) => listen,
        Err(err) => {
            return format!(
                "{service}, but the recorded control API listen address is invalid: {err:#}. Run /restart or `TabbyMew doctor`. {controls}"
            );
        }
    };
    let control_api = collect_control_status(listen, timeout).await;
    if control_api.healthy {
        format!(
            "{service}; control API is healthy at http://{}. {controls}",
            control_api.listen
        )
    } else {
        format!(
            "{service}, but control API http://{} is unhealthy: {}. Run /restart or `TabbyMew doctor`. {controls}",
            control_api.listen,
            control_api.error.as_deref().unwrap_or("unknown error")
        )
    }
}

pub(super) async fn adopt_independent_runtime(session: &ShellSession) -> Result<Option<String>> {
    let paths = process_manager::paths(&session.state_dir, None);
    let runtime_state_file = process_manager::runtime_state_file(&session.state_dir);
    let state = match process_manager::load_state(&runtime_state_file) {
        Ok(state) => state,
        Err(_) if !runtime_state_file.exists() => return Ok(None),
        Err(err) => {
            process_manager::remove_state_file(&runtime_state_file)?;
            record_lifecycle_event(
                Some(paths.log_file.as_path()),
                "tui_removed_unreadable_runtime_state",
                vec![
                    ("runtime_state", runtime_state_file.display().to_string()),
                    ("error", format!("{err:#}")),
                ],
            );
            return Ok(None);
        }
    };
    if !process_manager::is_process_running(state.pid) {
        process_manager::remove_state_file(&runtime_state_file)?;
        return Ok(None);
    }
    let listen = state
        .listen
        .as_deref()
        .context("independent TabbyMew runtime has no control API listen address")?;
    let listen = control::parse_listen(listen)
        .context("independent TabbyMew runtime has invalid control API listen address")?;
    let control_api = collect_control_status(listen, session.timeout).await;
    if !control_api.healthy {
        bail!(
            "independent TabbyMew runtime pid {} is running but control API http://{} is unhealthy: {}",
            state.pid,
            control_api.listen,
            control_api.error.as_deref().unwrap_or("unknown error")
        );
    }
    process_manager::save_state_file(&paths.state_file, &state)?;
    Ok(Some(format!(
        "Adopted independent TabbyMew service pid {}. Press q to detach the TUI, or /quit to stop the service.",
        state.pid
    )))
}

pub(super) fn first_non_empty_line(text: &str) -> Option<&str> {
    text.lines().find(|line| !line.trim().is_empty())
}

pub(super) fn load_local_process_state_for_stop(state_dir: &Path) -> Result<Option<(ProcessState, PathBuf)>> {
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

pub(super) fn tui_control_token(session: &ShellSession) -> Result<String> {
    control_token_from_state_dir(&session.state_dir)
}
