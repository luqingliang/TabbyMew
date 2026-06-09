mod app;
mod autostart;
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
#[path = "main/runtime_model.rs"]
mod runtime_model;
mod session;
mod subscription;
mod subscription_remote;
mod system_proxy;
#[path = "main/tui.rs"]
mod tui;

use std::{
    env, fs,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use config::Config;
use control_client::ControlClient;
use process_manager::{ProcessState, ServiceStatus, ServiceStatusKind, StartOptions};
use runtime_model::*;
use serde::Serialize;
use serde_json::{Map, Value};
use tokio::time::sleep;
use tracing_subscriber::{EnvFilter, fmt::time::ChronoLocal};
use tui::run_interactive_shell;

const DEFAULT_CONTROL_TIMEOUT_MS: u64 = 1000;

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
        Command::Subscription(command) => match command.command {
            SubscriptionSubcommand::Add(command) => {
                init_logging("info", None)?;
                add_subscription(command).await
            }
            SubscriptionSubcommand::ImportFile(command) => {
                init_logging("info", None)?;
                import_file_subscription(command).await
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
        Command::Start(command) => run_start_command(config.as_ref(), command),
        Command::Stop(command) => run_stop_command(command),
        Command::Cleanup(command) => run_cleanup_command(command),
        Command::Doctor(command) => run_doctor_command(command).await,
        Command::Wait(command) => run_wait_command(config.as_ref(), command).await,
        Command::Logs(command) => run_logs_command(command),
        Command::Status(command) => run_status_command(command).await,
        Command::Mode(command) => run_mode_command(config.as_ref(), command).await,
        Command::Global(command) => run_global_command(config.as_ref(), command).await,
        Command::Groups(command) => run_groups_command(config.as_ref(), command).await,
        Command::Tun(command) => run_tun_command(config.as_ref(), command).await,
        Command::SystemProxy(command) => run_system_proxy_command(config.as_ref(), command).await,
        Command::Autostart(command) => run_autostart_command(config.as_ref(), command),
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
        Command::Run(command) => run_foreground_command(config.as_ref(), command).await,
    }
}

include!("main/rules_cli.rs");

include!("main/runtime_cli.rs");

include!("main/service_commands.rs");

#[cfg(test)]
use tui::*;

#[cfg(test)]
#[path = "main_tests/mod.rs"]
mod tests;
