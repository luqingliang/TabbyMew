#[path = "service_commands/cleanup.rs"]
mod cleanup;
#[path = "service_commands/config_paths.rs"]
mod config_paths;
#[path = "service_commands/doctor.rs"]
mod doctor;
#[path = "service_commands/formatting.rs"]
mod formatting;
#[path = "service_commands/lifecycle.rs"]
mod lifecycle;
#[path = "service_commands/reports.rs"]
mod reports;
#[path = "service_commands/status.rs"]
mod status;
#[path = "service_commands/autostart.rs"]
mod autostart_command;
#[path = "service_commands/subscriptions.rs"]
mod subscriptions;
#[path = "service_commands/wait.rs"]
mod wait;

use self::{
    autostart_command::*, cleanup::*, config_paths::*, doctor::*, formatting::*, lifecycle::*,
    reports::*, status::*, subscriptions::*, wait::*,
};
