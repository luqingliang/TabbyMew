use super::*;

pub(super) const CLI_JSON_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub(super) struct CliIssue {
    pub(super) code: String,
    pub(super) severity: String,
    pub(super) message: String,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub(super) struct CliNextAction {
    pub(super) code: String,
    pub(super) commands: Vec<Vec<String>>,
    pub(super) description: String,
}

#[derive(Debug, Serialize)]
pub(super) struct ControlApiReport {
    pub(super) listen: String,
    pub(super) healthy: bool,
    pub(super) health: Option<Value>,
    pub(super) config: Option<Value>,
    pub(super) counters: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error_code: Option<String>,
    pub(super) error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct StatusReport {
    pub(super) schema_version: u16,
    pub(super) ok: bool,
    pub(super) service: ServiceStatus,
    pub(super) control_api: Option<ControlApiReport>,
    pub(super) issues: Vec<CliIssue>,
    pub(super) next_actions: Vec<CliNextAction>,
}

impl StatusReport {
    pub(super) fn new(service: ServiceStatus, control_api: Option<ControlApiReport>) -> Self {
        let control_ok = control_api
            .as_ref()
            .is_none_or(|control_api| control_api.healthy);
        let ok = match service.status {
            ServiceStatusKind::Running => control_api.is_some() && control_ok,
            ServiceStatusKind::Stopped => {
                control_ok
                    && !service.needs_cleanup()
                    && service.state_error.is_none()
                    && service.preference_error.is_none()
            }
            ServiceStatusKind::Stale => false,
        };
        let issues = status_report_issues(&service, control_api.as_ref());
        let next_actions = next_actions_for_issues_with_state_dir(&issues, Some(&service.state_dir));
        Self {
            schema_version: CLI_JSON_SCHEMA_VERSION,
            ok,
            service,
            control_api,
            issues,
            next_actions,
        }
    }
}

pub(super) async fn build_status_report(
    state_dir: &Path,
    listen: Option<String>,
    timeout: Duration,
) -> Result<StatusReport> {
    let service = process_manager::service_status(state_dir);
    let control = match status_control_listen(listen, &service)? {
        Some(listen) => Some(collect_control_status(listen, timeout).await),
        None => None,
    };
    Ok(StatusReport::new(service, control))
}

#[derive(Debug, Serialize)]
pub(super) struct CleanupAction {
    pub(super) name: &'static str,
    pub(super) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error_code: Option<&'static str>,
    pub(super) message: String,
}

#[derive(Debug, Serialize)]
pub(super) struct CleanupStateSummary {
    pub(super) service_status: String,
    pub(super) running: bool,
    pub(super) cleanup_items: Vec<String>,
    pub(super) state_file_exists: bool,
    pub(super) runtime_state_file_exists: bool,
    pub(super) managed_system_proxy_recorded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) system_proxy: Option<CleanupSystemProxySummary>,
}

#[derive(Debug, Serialize)]
pub(super) struct CleanupSystemProxySummary {
    pub(super) candidate_source: String,
    pub(super) status: system_proxy::SystemProxyStatus,
}

#[derive(Debug, Serialize)]
pub(super) struct CleanupReport {
    pub(super) schema_version: u16,
    pub(super) ok: bool,
    pub(super) before: ServiceStatus,
    pub(super) after: ServiceStatus,
    pub(super) before_summary: CleanupStateSummary,
    pub(super) after_summary: CleanupStateSummary,
    pub(super) actions: Vec<CleanupAction>,
    pub(super) errors: Vec<String>,
    pub(super) issues: Vec<CliIssue>,
    pub(super) next_actions: Vec<CliNextAction>,
}

#[derive(Debug, Serialize)]
pub(super) struct DoctorCheck {
    pub(super) name: &'static str,
    pub(super) ok: bool,
    pub(super) severity: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error_code: Option<&'static str>,
    pub(super) message: String,
}

#[derive(Debug, Serialize)]
pub(super) struct DoctorReport {
    pub(super) schema_version: u16,
    pub(super) ok: bool,
    pub(super) service: ServiceStatus,
    pub(super) control_api: Option<ControlApiReport>,
    pub(super) checks: Vec<DoctorCheck>,
    pub(super) issues: Vec<CliIssue>,
    pub(super) recommendations: Vec<String>,
    pub(super) next_actions: Vec<CliNextAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WaitTarget {
    Service,
    Tun,
    SystemProxy,
}

impl WaitTarget {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Tun => "tun",
            Self::SystemProxy => "system_proxy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WaitDesired {
    Ready,
    Stopped,
    On,
    Off,
}

impl WaitDesired {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Stopped => "stopped",
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub(super) struct WaitReport {
    pub(super) schema_version: u16,
    pub(super) ok: bool,
    pub(super) target: &'static str,
    pub(super) desired: &'static str,
    pub(super) current: String,
    pub(super) waited_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error_code: Option<&'static str>,
    pub(super) message: String,
    pub(super) next_actions: Vec<CliNextAction>,
}

pub(super) fn cli_issue(
    code: impl Into<String>,
    severity: impl Into<String>,
    message: impl Into<String>,
) -> CliIssue {
    CliIssue {
        code: code.into(),
        severity: severity.into(),
        message: message.into(),
    }
}

pub(super) fn cli_next_action(
    code: impl Into<String>,
    commands: Vec<Vec<String>>,
    description: impl Into<String>,
) -> CliNextAction {
    CliNextAction {
        code: code.into(),
        commands,
        description: description.into(),
    }
}

pub(super) fn push_cli_next_action(actions: &mut Vec<CliNextAction>, action: CliNextAction) {
    if !actions.iter().any(|existing| existing.code == action.code) {
        actions.push(action);
    }
}

pub(super) fn status_report_issues(
    service: &ServiceStatus,
    control_api: Option<&ControlApiReport>,
) -> Vec<CliIssue> {
    let mut issues = Vec::new();

    if service.stale {
        issues.push(cli_issue(
            "stale_state_file",
            "error",
            "state file exists but its process is not running",
        ));
    }
    if let Some(error) = &service.state_error {
        issues.push(cli_issue("state_file_unreadable", "error", error.clone()));
    }
    if let Some(error) = &service.preference_error {
        issues.push(cli_issue("preferences_unreadable", "error", error.clone()));
    }
    if service.heartbeat_stale {
        let age = service
            .heartbeat_age_seconds
            .map(|age| format!("{age}s"))
            .unwrap_or_else(|| "unknown age".to_string());
        issues.push(cli_issue(
            "runtime_heartbeat_stale",
            "warning",
            format!("runtime heartbeat is stale ({age})"),
        ));
    }
    for item in &service.cleanup_items {
        issues.push(cli_issue(
            item.clone(),
            "warning",
            format!("cleanup item recorded: {item}"),
        ));
    }
    if service.running {
        match control_api {
            Some(control) if control.healthy => {}
            Some(control) => issues.push(cli_issue(
                control
                    .error_code
                    .as_deref()
                    .unwrap_or("control_api_unhealthy"),
                "error",
                control
                    .error
                    .clone()
                    .unwrap_or_else(|| "control API is unhealthy".to_string()),
            )),
            None => issues.push(cli_issue(
                "control_api_missing",
                "error",
                "service is running but no control API status is available",
            )),
        }
    }

    issues
}

pub(super) fn doctor_report_issues(checks: &[DoctorCheck]) -> Vec<CliIssue> {
    checks
        .iter()
        .filter(|check| !check.ok || check.error_code.is_some())
        .map(|check| {
            cli_issue(
                check.error_code.unwrap_or("doctor_check_failed"),
                check.severity,
                check.message.clone(),
            )
        })
        .collect()
}

pub(super) fn cleanup_report_issues(
    actions: &[CleanupAction],
    after: &ServiceStatus,
    errors: &[String],
) -> Vec<CliIssue> {
    let mut issues = Vec::new();
    for action in actions.iter().filter(|action| !action.ok) {
        issues.push(cli_issue(
            action.error_code.unwrap_or("cleanup_action_failed"),
            "error",
            action.message.clone(),
        ));
    }
    for item in &after.cleanup_items {
        issues.push(cli_issue(
            item.clone(),
            "warning",
            format!("cleanup item still recorded after cleanup: {item}"),
        ));
    }
    if after.state_error.is_some() {
        issues.push(cli_issue(
            "state_file_unreadable",
            "error",
            after.state_error.clone().unwrap_or_default(),
        ));
    }
    if after.preference_error.is_some() {
        issues.push(cli_issue(
            "preferences_unreadable",
            "error",
            after.preference_error.clone().unwrap_or_default(),
        ));
    }
    for error in errors {
        if !issues.iter().any(|issue| issue.message == *error) {
            issues.push(cli_issue("cleanup_error", "error", error.clone()));
        }
    }
    issues
}

pub(super) fn next_actions_for_issues(issues: &[CliIssue]) -> Vec<CliNextAction> {
    next_actions_for_issues_with_state_dir(issues, None)
}

pub(super) fn next_actions_for_issues_with_state_dir(
    issues: &[CliIssue],
    state_dir: Option<&Path>,
) -> Vec<CliNextAction> {
    let mut actions = Vec::new();
    for issue in issues {
        push_next_actions_for_error_code(&mut actions, &issue.code, state_dir);
    }
    actions
}

pub(super) fn push_next_actions_for_error_code(
    actions: &mut Vec<CliNextAction>,
    code: &str,
    state_dir: Option<&Path>,
) {
    match code {
        "stale_state_file"
        | "stale_runtime_state_file"
        | "managed_system_proxy"
        | "cleanup_required"
        | "managed_system_proxy_residue"
        | "system_proxy_unrecorded_residue"
        | "managed_system_proxy_record_stale" => push_cli_next_action(
            actions,
            cli_next_action(
                "cleanup",
                vec![argv_with_state_dir(
                    &["TabbyMew", "cleanup", "--json"],
                    state_dir,
                )],
                "clean stale TabbyMew-owned runtime state and matching system proxy residue",
            ),
        ),
        "runtime_heartbeat_stale"
        | "runtime_heartbeat_missing"
        | "runtime_status_unavailable"
        | "control_api_missing"
        | "control_api_unreachable"
        | "control_api_unhealthy"
        | "operation_timeout"
        | "wait_timeout" => {
            push_cli_next_action(
                actions,
                cli_next_action(
                    "inspect_logs",
                    vec![argv_with_state_dir(
                        &["TabbyMew", "logs", "--lines", "120", "--json"],
                        state_dir,
                    )],
                    "inspect recent runtime logs before changing local network state",
                ),
            );
            push_cli_next_action(
                actions,
                cli_next_action(
                    "restart_service",
                    vec![
                        argv_with_state_dir(&["TabbyMew", "stop", "--json"], state_dir),
                        argv_with_state_dir(&["TabbyMew", "start", "--json"], state_dir),
                    ],
                    "restart the managed service if diagnostics stay stale or unreachable",
                ),
            );
        }
        "tun_listener_stopped"
        | "tun_failed"
        | "tun_not_running"
        | "tun_egress_binding_missing"
        | "tun_egress_binding_drift"
        | "tun_startup_warnings" => {
            push_cli_next_action(
                actions,
                cli_next_action(
                    "inspect_logs",
                    vec![argv_with_state_dir(
                        &["TabbyMew", "logs", "--lines", "120", "--json"],
                        state_dir,
                    )],
                    "inspect recent runtime logs before changing local network state",
                ),
            );
            push_cli_next_action(
                actions,
                cli_next_action(
                    "restart_tun",
                    vec![
                        argv_with_state_dir(&["TabbyMew", "tun", "off", "--json"], state_dir),
                        argv_with_state_dir(&["TabbyMew", "tun", "on", "--json"], state_dir),
                    ],
                    "restart TUN so routes, DNS, and outbound binding can be rebuilt",
                ),
            );
        }
        "tun_requires_permission" => push_cli_next_action(
            actions,
            cli_next_action(
                "disable_tun",
                vec![argv_with_state_dir(
                    &["TabbyMew", "tun", "off", "--json"],
                    state_dir,
                )],
                "turn TUN off if administrator/root permission is unavailable",
            ),
        ),
        "tun_requires_configuration"
        | "tun_bypass_empty"
        | "tun_proxy_bypass_missing"
        | "tun_status_unavailable"
        | "wintun_runtime_missing"
        | "wintun_runtime_unknown" => push_cli_next_action(
            actions,
            cli_next_action(
                "check_config",
                vec![argv(&["TabbyMew", "check", "--json"])],
                "validate the selected config before enabling TUN again",
            ),
        ),
        "system_proxy_error" | "system_proxy_unrecorded" => push_cli_next_action(
            actions,
            cli_next_action(
                "disable_system_proxy",
                vec![argv_with_state_dir(
                    &["TabbyMew", "system-proxy", "off", "--json"],
                    state_dir,
                )],
                "turn off the TabbyMew-matching system proxy target",
            ),
        ),
        "subscription_update_failed" | "subscriptions_status_error" => push_cli_next_action(
            actions,
            cli_next_action(
                "update_subscriptions",
                vec![argv_with_state_dir(
                    &["TabbyMew", "subscription", "update", "--all", "--json"],
                    state_dir,
                )],
                "retry all saved subscription updates and inspect per-subscription errors",
            ),
        ),
        _ => push_cli_next_action(
            actions,
            cli_next_action(
                "doctor",
                vec![argv_with_state_dir(
                    &["TabbyMew", "doctor", "--json"],
                    state_dir,
                )],
                "run the full local diagnostic report for stable issue codes",
            ),
        ),
    }
}

pub(super) fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_string()).collect()
}

pub(super) fn argv_with_state_dir(parts: &[&str], state_dir: Option<&Path>) -> Vec<String> {
    let mut command = argv(parts);
    if let Some(state_dir) = state_dir {
        command.push("--state-dir".to_string());
        command.push(state_dir.display().to_string());
    }
    command
}

pub(super) fn status_control_listen(
    listen: Option<String>,
    service: &ServiceStatus,
) -> Result<Option<std::net::SocketAddr>> {
    if let Some(listen) = listen {
        return control::parse_listen(&listen)
            .map(Some)
            .context("invalid control API listen address");
    }
    if !service.running {
        return Ok(None);
    }
    let listen = service
        .listen
        .as_deref()
        .unwrap_or(control::DEFAULT_CONTROL_LISTEN);
    control::parse_listen(listen)
        .map(Some)
        .context("invalid control API listen address from local state")
}

pub(super) async fn collect_control_status(
    listen: std::net::SocketAddr,
    timeout: Duration,
) -> ControlApiReport {
    let client = ControlClient::new(listen, timeout);
    let result: Result<(Value, Value, Value)> = async {
        let health = client.get_json("/health").await?;
        let config = client.get_json("/config").await?;
        let counters = client.get_json("/counters").await?;
        Ok((health, config, counters))
    }
    .await;

    match result {
        Ok((health, config, counters)) => ControlApiReport {
            listen: listen.to_string(),
            healthy: true,
            health: Some(health),
            config: Some(config),
            counters: Some(counters),
            error_code: None,
            error: None,
        },
        Err(err) => {
            let error = format!("{err:#}");
            ControlApiReport {
                listen: listen.to_string(),
                healthy: false,
                health: None,
                config: None,
                counters: None,
                error_code: Some(classify_user_error(&error).to_string()),
                error: Some(error),
            }
        }
    }
}

pub(super) async fn collect_control_snapshot_for_report(
    report: &StatusReport,
    timeout: Duration,
) -> Option<Value> {
    let control = report.control_api.as_ref()?;
    if !control.healthy {
        return None;
    }
    let listen = control::parse_listen(&control.listen).ok()?;
    ControlClient::new(listen, timeout)
        .get_json("/control/api/status")
        .await
        .ok()
}

pub(super) fn record_process_lifecycle_event(
    log_file: Option<&Path>,
    state: &ProcessState,
    event: &str,
    mut fields: Vec<(&'static str, String)>,
) {
    fields.push(("pid", state.pid.to_string()));
    fields.push(("started_at_unix", state.started_at_unix.to_string()));
    fields.push(("config", state.config.display().to_string()));
    if let Some(listen) = &state.listen {
        fields.push(("control_listen", listen.clone()));
    }
    record_lifecycle_event(log_file, event, fields);
}

pub(super) fn record_service_lifecycle_event(
    service: &ServiceStatus,
    event: &str,
    mut fields: Vec<(&'static str, String)>,
) {
    fields.push(("status", service.status.as_str().to_string()));
    fields.push(("state_file", service.state_file.display().to_string()));
    if let Some(pid) = service.pid {
        fields.push(("pid", pid.to_string()));
    }
    if let Some(listen) = &service.listen {
        fields.push(("control_listen", listen.clone()));
    }
    record_lifecycle_event(service_lifecycle_log_path(service), event, fields);
}

pub(super) fn record_lifecycle_event(
    log_file: Option<&Path>,
    event: &str,
    fields: Vec<(&'static str, String)>,
) {
    let Some(log_file) = log_file else {
        return;
    };
    process_manager::append_lifecycle_event_best_effort(log_file, event, &fields);
}

pub(super) fn service_lifecycle_log_path(service: &ServiceStatus) -> Option<&Path> {
    let log = service.log.as_deref()?;
    owned_lifecycle_log_path(&service.state_dir, log)
}

pub(super) fn owned_lifecycle_log_path<'a>(state_dir: &Path, log: &'a Path) -> Option<&'a Path> {
    if path_is_under(log, state_dir) {
        return Some(log);
    }
    None
}

pub(super) fn path_is_under(path: &Path, base: &Path) -> bool {
    if path.starts_with(base) {
        return true;
    }
    if base.is_absolute() {
        return false;
    }
    env::current_dir()
        .map(|current_dir| path.starts_with(current_dir.join(base)))
        .unwrap_or(false)
}
