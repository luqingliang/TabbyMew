mod app;
mod config;
mod config_normalize;
mod control;
mod control_client;
mod fs_security;
mod inbound;
mod net;
mod outbound;
mod platform;
mod process_manager;
mod proxy_runtime;
mod resource_limits;
mod router;
mod session;
mod subscription;
mod subscription_remote;
mod system_proxy;

use std::{
    borrow::Cow,
    collections::BTreeMap,
    env, fs,
    io::{self, IsTerminal, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use config::Config;
use control_client::ControlClient;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use process_manager::{ProcessState, ServiceStatus, ServiceStatusKind, StartOptions};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, TableState, Wrap,
    },
};
use serde::Serialize;
use serde_json::{Map, Value};
use tokio::{sync::mpsc, task::JoinHandle, time::sleep};
use tracing_subscriber::{EnvFilter, fmt::time::ChronoLocal};

const DEFAULT_CONTROL_TIMEOUT_MS: u64 = 1000;
const TUI_SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const TUI_EXIT_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(4);
const TUI_ROUTE_RULE_ADD_FIELDS: usize = 3;
const TUI_ROUTE_RULE_ADD_CONTENT_FIELD: usize = 0;
const TUI_ROUTE_RULE_ADD_MATCH_FIELD: usize = 1;
const TUI_ROUTE_RULE_ADD_TARGET_FIELD: usize = 2;
const TUI_SUBSCRIPTION_ADD_FIELDS: usize = 3;
const TUI_SUBSCRIPTION_ADD_NAME_FIELD: usize = 0;
const TUI_SUBSCRIPTION_ADD_URL_FIELD: usize = 1;
const TUI_SUBSCRIPTION_ADD_AUTO_UPDATE_FIELD: usize = 2;

include!("main/cli.rs");

#[tokio::main]
async fn main() -> Result<()> {
    let Cli { config, command } = Cli::parse();
    let command = command.unwrap_or(Command::Shell(ShellCommand::default()));

    match command {
        Command::Shell(command) => run_interactive_shell(config, command).await,
        Command::Example => {
            println!("{}", Config::example_json()?);
            Ok(())
        }
        Command::Config(command) => match command.command {
            ConfigSubcommand::Schema => {
                println!("{}", crate::config::config_schema_json()?);
                Ok(())
            }
            ConfigSubcommand::Normalize(command) => {
                init_logging("info", None)?;
                let config_path = resolve_config_path(config.as_ref())?;
                let config = Config::load(&config_path)?;
                let output = config_normalize::normalize_json(&config, !command.show_secrets)?;
                match command.output {
                    Some(path) => {
                        fs_security::write_private_file(&path, format!("{output}\n"))
                            .with_context(|| {
                                format!("failed to write normalized config {}", path.display())
                            })?;
                        println!(
                            "normalized {} into {}",
                            config_path.display(),
                            path.display()
                        );
                    }
                    None => {
                        println!("{output}");
                    }
                }
                Ok(())
            }
        },
        Command::Import(command) => {
            init_logging("info", None)?;
            let input = command.input;
            let output_path = command.output;
            let json = command.json;
            let text = fs::read_to_string(&input)
                .with_context(|| format!("failed to read import input {}", input.display()))?;
            let options = subscription::ImportOptions {
                inbound_tag: command.inbound_tag,
                listen: command.listen.unwrap_or_else(Config::default_local_listen),
                listen_port: command
                    .listen_port
                    .unwrap_or_else(Config::default_local_listen_port),
            };
            let result = subscription::import_from_text(&text, options)
                .with_context(|| format!("failed to import {}", input.display()))?;
            validate_runtime_config(&result.config, None)?;
            let output = serde_json::to_string_pretty(&result.config)
                .context("failed to serialize imported config")?;
            match output_path {
                Some(path) => {
                    fs_security::write_private_file(&path, format!("{output}\n")).with_context(
                        || format!("failed to write imported config {}", path.display()),
                    )?;
                    if json {
                        let report =
                            import_json_report(&result, &input, Some(path.as_path()), None);
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        let mut stdout = io::stdout().lock();
                        print_import_report(&mut stdout, &result, &input, Some(path.as_path()))?;
                    }
                }
                None => {
                    if json {
                        let config_json = serde_json::to_value(&result.config)
                            .context("failed to serialize imported config as JSON value")?;
                        let report = import_json_report(&result, &input, None, Some(config_json));
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        let mut stderr = io::stderr().lock();
                        print_import_report(&mut stderr, &result, &input, None)?;
                        println!("{output}");
                    }
                }
            }
            Ok(())
        }
        Command::Subscription(command) => match command.command {
            SubscriptionSubcommand::Add(command) => {
                init_logging("info", None)?;
                add_subscription(command).await
            }
            SubscriptionSubcommand::List(command) => list_subscriptions(command).await,
            SubscriptionSubcommand::Update(command) => {
                init_logging("info", None)?;
                update_subscriptions(command).await
            }
            SubscriptionSubcommand::Set(command) => set_subscription(command).await,
            SubscriptionSubcommand::Remove(command) => remove_subscription(command).await,
        },
        Command::InternalTunHelper(command) => {
            inbound::tun::run_privileged_helper_command(command).await
        }
        Command::Check(command) => {
            init_logging("info", None)?;
            let config_path = resolve_config_path(config.as_ref())?;
            let config = Config::load(&config_path)?;
            validate_runtime_config(&config, config_base_dir(&config_path))?;
            if command.json {
                let report = check_json_report(&config_path, &config);
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_check_report(&config_path, &config);
            }
            Ok(())
        }
        Command::Start(command) => {
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
            let config_path = resolve_launch_config_path(config.as_ref(), &state_dir)?;
            warn_if_active_subscription_config_migration_fails(&state_dir, &config_path);
            let config = Config::load(&config_path)?;
            validate_runtime_config(&config, config_base_dir(&config_path))?;
            let state = process_manager::start(StartOptions {
                config: config_path,
                state_dir: state_dir.clone(),
                log: command.log,
                control_listen: command.control_listen,
            })?;
            if json {
                let report =
                    start_json_report(&state, &state_dir, &start_paths.state_file, warnings);
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_start_report(io::stdout().lock(), &state)?;
            }
            Ok(())
        }
        Command::Stop(command) => {
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
        Command::Cleanup(command) => {
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
        Command::Doctor(command) => {
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
        Command::Wait(command) => run_wait_command(config.as_ref(), command).await,
        Command::Logs(command) => {
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
        Command::Status(command) => {
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
        Command::Mode(command) => run_mode_command(config.as_ref(), command).await,
        Command::Global(command) => run_global_command(config.as_ref(), command).await,
        Command::Groups(command) => run_groups_command(config.as_ref(), command).await,
        Command::Tun(command) => run_tun_command(config.as_ref(), command).await,
        Command::SystemProxy(command) => run_system_proxy_command(config.as_ref(), command).await,
        Command::Api(command) => match command.command {
            ApiSubcommand::Get(command) => {
                let config_path = resolve_config_path(config.as_ref())?;
                let listen =
                    resolve_control_listen(&config_path, command.listen, command.state_dir)?;
                let client = ControlClient::new(listen, timeout_duration(command.timeout_ms)?);
                let response = client.get_json(&command.path).await?;
                if command.compact {
                    println!("{}", serde_json::to_string(&response)?);
                } else {
                    println!("{}", serde_json::to_string_pretty(&response)?);
                }
                Ok(())
            }
        },
        Command::Rules(command) => run_rules_command(config.as_ref(), command).await,
        Command::Run(command) => {
            let default_state_dir = process_manager::default_state_dir();
            let run_paths = resolve_run_paths(
                default_state_dir,
                env::var_os("TABBYMEW_STATE_FILE").map(PathBuf::from),
                env::var_os("TABBYMEW_STATE_DIR").map(PathBuf::from),
                env::var_os("TABBYMEW_LOG_FILE").map(PathBuf::from),
            )?;
            let config_path = resolve_launch_config_path(config.as_ref(), &run_paths.state_dir)?;
            warn_if_active_subscription_config_migration_fails(&run_paths.state_dir, &config_path);
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
    }
}

include!("main/tui.rs");

include!("main/rules_cli.rs");

include!("main/runtime_cli.rs");

include!("main/tui_service.rs");

include!("main/service_commands.rs");

#[cfg(test)]
#[path = "main_tests/mod.rs"]
mod tests;
