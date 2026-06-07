use std::{
    borrow::Cow,
    fs,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
#[cfg(not(test))]
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
#[cfg(test)]
pub(crate) use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
#[cfg(not(test))]
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
#[cfg(test)]
pub(crate) use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, TableState, Wrap,
    },
};
use serde_json::{Map, Value};
#[cfg(not(test))]
use tokio::{sync::mpsc, task::JoinHandle, time::sleep};
#[cfg(test)]
pub(crate) use tokio::{sync::mpsc, task::JoinHandle, time::sleep};

use crate::{
    Config, ControlClient, ProcessState, ServiceStatus, ServiceStatusKind, ShellCommand,
    StartOptions, StatusReport, build_status_report, classify_user_error, cleanup_service_state,
    collect_control_snapshot_for_report, collect_control_status, config_base_dir, control,
    control_token_from_state_dir, doctor_service_state, format_duration, format_memory_bytes,
    on_off, owned_lifecycle_log_path, print_cleanup_report, print_doctor_report,
    print_start_report, process_manager, record_lifecycle_event, record_process_lifecycle_event,
    resolve_launch_config_path, router, runtime_model::*, subscription_remote, timeout_duration,
    user_error_suggestion, validate_runtime_config, value_array, value_array_len, value_bool,
    value_str, value_u64,
};

pub(crate) const TUI_SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const TUI_EXIT_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(4);
pub(crate) const TUI_ROUTE_RULE_ADD_FIELDS: usize = 3;
pub(crate) const TUI_ROUTE_RULE_ADD_CONTENT_FIELD: usize = 0;
pub(crate) const TUI_ROUTE_RULE_ADD_MATCH_FIELD: usize = 1;
pub(crate) const TUI_ROUTE_RULE_ADD_TARGET_FIELD: usize = 2;
pub(crate) const TUI_SUBSCRIPTION_ADD_FIELDS: usize = 3;
pub(crate) const TUI_SUBSCRIPTION_ADD_NAME_FIELD: usize = 0;
pub(crate) const TUI_SUBSCRIPTION_ADD_URL_FIELD: usize = 1;
pub(crate) const TUI_SUBSCRIPTION_ADD_AUTO_UPDATE_FIELD: usize = 2;

#[path = "tui/groups/actions.rs"]
mod group_actions;
#[path = "tui/groups/delay.rs"]
mod group_delay;
#[path = "tui/groups/model.rs"]
mod group_model;
#[path = "tui/groups/runtime.rs"]
mod group_runtime;
#[path = "tui/input.rs"]
mod input;
#[path = "tui/input/groups.rs"]
mod input_groups;
#[path = "tui/input/normal.rs"]
mod input_normal;
#[path = "tui/input/palette.rs"]
mod input_palette;
#[path = "tui/input/routing.rs"]
mod input_routing;
#[path = "tui/input/rules.rs"]
mod input_rules;
#[path = "tui/input/subscriptions.rs"]
mod input_subscriptions;
#[path = "tui/render.rs"]
mod render;
#[path = "tui/render/dashboard.rs"]
mod render_dashboard;
#[path = "tui/render/groups.rs"]
mod render_groups;
#[path = "tui/render/output.rs"]
mod render_output;
#[path = "tui/render/palette.rs"]
mod render_palette;
#[path = "tui/render/routing.rs"]
mod render_routing;
#[path = "tui/render/rules.rs"]
mod render_rules;
#[path = "tui/render/shared.rs"]
mod render_shared;
#[path = "tui/render/status.rs"]
mod render_status;
#[path = "tui/render/subscriptions.rs"]
mod render_subscriptions;
#[path = "tui/rules/commands.rs"]
mod rule_commands;
#[path = "tui/rules/form.rs"]
mod rule_form;
#[path = "tui/rules/model.rs"]
mod rule_model;
#[path = "tui/service.rs"]
mod service;
#[path = "tui/state.rs"]
mod state;
#[path = "tui/terminal.rs"]
mod terminal;
#[path = "tui_service.rs"]
mod tui_service;

#[cfg(not(test))]
pub(crate) use self::state::run_interactive_shell;

#[cfg(not(test))]
use self::{
    group_actions::*,
    group_delay::*,
    group_model::*,
    group_runtime::*,
    input::*,
    input_groups::*,
    input_normal::*,
    input_palette::*,
    input_routing::*,
    input_rules::*,
    input_subscriptions::*,
    render::*,
    render_dashboard::*,
    render_groups::*,
    render_output::*,
    render_palette::*,
    render_routing::*,
    render_rules::*,
    render_shared::*,
    render_status::*,
    render_subscriptions::*,
    rule_commands::*,
    rule_form::*,
    rule_model::*,
    service::*,
    state::{
        ShellCommandSpec, ShellSession, TuiApp, TuiExitAction, TuiExitConfirmation, TuiMode,
        TuiServiceStartup, TuiServiceStartupKind, TuiTerminal, TuiTrafficSpeed,
    },
    terminal::*,
    tui_service::*,
};

#[cfg(test)]
pub(crate) use self::{
    group_actions::*, group_delay::*, group_model::*, group_runtime::*, input::*, input_groups::*,
    input_normal::*, input_palette::*, input_routing::*, input_rules::*, input_subscriptions::*,
    render::*, render_dashboard::*, render_groups::*, render_output::*, render_palette::*,
    render_routing::*, render_rules::*, render_shared::*, render_status::*,
    render_subscriptions::*, rule_commands::*, rule_form::*, rule_model::*, service::*, state::*,
    terminal::*, tui_service::*,
};
