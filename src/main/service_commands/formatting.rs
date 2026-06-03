use super::*;

pub(super) fn print_status_report(mut writer: impl Write, report: &StatusReport) -> Result<()> {
    let service = &report.service;
    writeln!(writer, "TabbyMew status: {}", service.status.as_str())?;
    if let Some(pid) = service.pid {
        writeln!(writer, "  pid: {pid}")?;
    }
    if let Some(memory) = service.memory_rss_bytes {
        writeln!(writer, "  memory: {}", format_memory_bytes(memory))?;
    }
    if let Some(age) = service.heartbeat_age_seconds {
        writeln!(
            writer,
            "  heartbeat: {}s{}",
            age,
            if service.heartbeat_stale {
                " (stale)"
            } else {
                ""
            }
        )?;
    }
    writeln!(writer, "  state: {}", service.state_file.display())?;
    if service.runtime_state_file_exists {
        writeln!(
            writer,
            "  runtime state: {}",
            service.runtime_state_file.display()
        )?;
    }
    if let Some(log) = &service.log {
        writeln!(writer, "  log: {}", log.display())?;
    }
    if let Some(listen) = &service.listen {
        writeln!(writer, "  control api: http://{listen}")?;
    }
    if service.needs_cleanup() {
        writeln!(
            writer,
            "  cleanup needed: {}",
            service.cleanup_items.join(", ")
        )?;
    }
    if let Some(error) = &service.state_error {
        writeln!(writer, "  state error: {error}")?;
    }
    if let Some(error) = &service.preference_error {
        writeln!(writer, "  preferences error: {error}")?;
    }
    if !report.issues.is_empty() {
        writeln!(
            writer,
            "  issue codes: {}",
            report
                .issues
                .iter()
                .map(|issue| issue.code.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )?;
    }
    print_next_actions(&mut writer, &report.next_actions)?;

    let Some(control_api) = &report.control_api else {
        return Ok(());
    };
    writeln!(writer, "api: http://{}", control_api.listen)?;
    if let Some(error) = &control_api.error {
        writeln!(writer, "  error: {error}")?;
        return Ok(());
    }
    let Some(health) = control_api.health.as_ref() else {
        return Ok(());
    };
    let Some(config) = control_api.config.as_ref() else {
        return Ok(());
    };
    let Some(counters) = control_api.counters.as_ref() else {
        return Ok(());
    };
    writeln!(
        writer,
        "  service: {}",
        value_str(health, &["service"]).unwrap_or("unknown")
    )?;
    writeln!(
        writer,
        "  uptime: {}",
        format_duration(value_u64(health, &["uptime_seconds"]).unwrap_or_default())
    )?;
    writeln!(
        writer,
        "  log: {}",
        value_str(config, &["log_level"]).unwrap_or("unknown")
    )?;
    writeln!(
        writer,
        "  dns: {}",
        value_str(config, &["dns"]).unwrap_or("unknown")
    )?;
    writeln!(
        writer,
        "  final outbound: {}",
        value_str(config, &["route", "final_outbound"]).unwrap_or("unknown")
    )?;
    writeln!(
        writer,
        "  route selections: total={} tcp={} udp={}",
        value_u64(counters, &["route_selections_total"]).unwrap_or_default(),
        value_u64(counters, &["route_selections_tcp"]).unwrap_or_default(),
        value_u64(counters, &["route_selections_udp"]).unwrap_or_default()
    )?;
    if let Some(lines) = config.get("summary").and_then(Value::as_array) {
        writeln!(writer, "summary:")?;
        for line in lines.iter().filter_map(Value::as_str) {
            writeln!(writer, "  {line}")?;
        }
    }
    Ok(())
}

pub(super) fn on_off(enabled: bool) -> &'static str {
    if enabled { "on" } else { "off" }
}

pub(super) fn classify_control_api_report_error(report: &ControlApiReport) -> &'static str {
    report
        .error
        .as_deref()
        .map(classify_user_error)
        .unwrap_or("control_api_unhealthy")
}

pub(super) fn classify_user_error(message: &str) -> &'static str {
    let message = message.to_ascii_lowercase();
    let mentions_tun = message.contains("tun") || message.contains("wintun");
    if message.contains("requires administrator")
        || message.contains("requires root")
        || message.contains("requires_permission")
        || (mentions_tun
            && (message.contains("permission denied")
                || message.contains("access denied")
                || message.contains("0x00000005")))
    {
        "tun_requires_permission"
    } else if message.contains("not running") || message.contains("no local state file") {
        "service_not_running"
    } else if message.contains("timed out") || message.contains("timeout") {
        "operation_timeout"
    } else if message.contains("connection refused")
        || message.contains("connection reset")
        || message.contains("control api is unhealthy")
        || message.contains("failed to connect")
    {
        "control_api_unreachable"
    } else if message.contains("token") {
        "control_token_unavailable"
    } else if message.contains("system proxy") {
        "system_proxy_error"
    } else if message.contains("tun") {
        "tun_error"
    } else if message.contains("subscription") {
        "subscription_error"
    } else if message.contains("route") || message.contains("routing") {
        "routing_error"
    } else {
        "operation_failed"
    }
}

pub(super) fn user_error_suggestion(error_code: &str) -> &'static str {
    match error_code {
        "service_not_running" => "Start or restart TabbyMew before retrying this operation.",
        "control_api_unreachable" => {
            "Run `TabbyMew doctor` and inspect recent logs before restarting."
        }
        "control_token_unavailable" => "Restart the service with the current TabbyMew binary.",
        "tun_requires_permission" => {
            "Authorize Administrator/root permission when enabling TUN, or turn TUN off."
        }
        "system_proxy_error" => "Check whether another application owns the system proxy settings.",
        "operation_timeout" => "Retry with a larger timeout or inspect the service log.",
        "subscription_error" => "Check the subscription URL, network path, and recent logs.",
        "routing_error" => "Check route mode, policy groups, and custom rules.",
        _ => "Run `TabbyMew doctor` for a full local diagnostic report.",
    }
}

pub(super) fn format_memory_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;

    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / MIB)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / KIB)
    } else {
        format!("{bytes} B")
    }
}

pub(super) fn print_cleanup_report(mut writer: impl Write, report: &CleanupReport) -> Result<()> {
    writeln!(
        writer,
        "TabbyMew cleanup: {}",
        if report.ok { "ok" } else { "issues found" }
    )?;
    writeln!(writer, "  before: {}", report.before.status.as_str())?;
    writeln!(writer, "  after: {}", report.after.status.as_str())?;
    writeln!(
        writer,
        "  before cleanup: {}",
        format_cleanup_state_summary(&report.before_summary)
    )?;
    writeln!(
        writer,
        "  after cleanup: {}",
        format_cleanup_state_summary(&report.after_summary)
    )?;
    if report.actions.is_empty() {
        writeln!(writer, "  actions: none")?;
    } else {
        writeln!(writer, "actions:")?;
        for action in &report.actions {
            let code = action
                .error_code
                .map(|code| format!(" code={code}"))
                .unwrap_or_default();
            writeln!(
                writer,
                "  {} {}{}: {}",
                if action.ok { "ok" } else { "fail" },
                action.name,
                code,
                action.message
            )?;
        }
    }
    for error in &report.errors {
        writeln!(writer, "error: {error}")?;
    }
    print_next_actions(&mut writer, &report.next_actions)?;
    Ok(())
}

pub(super) fn format_cleanup_state_summary(summary: &CleanupStateSummary) -> String {
    let cleanup = if summary.cleanup_items.is_empty() {
        "none".to_string()
    } else {
        summary.cleanup_items.join(",")
    };
    let mut parts = vec![
        format!("service={}", summary.service_status),
        format!("cleanup={cleanup}"),
        format!("state_file={}", on_off(summary.state_file_exists)),
        format!(
            "runtime_state_file={}",
            on_off(summary.runtime_state_file_exists)
        ),
        format!(
            "system_proxy_record={}",
            on_off(summary.managed_system_proxy_recorded)
        ),
    ];
    if let Some(system_proxy) = &summary.system_proxy {
        parts.push(format!(
            "system_proxy={}",
            format_cleanup_system_proxy_summary(system_proxy)
        ));
    }
    parts.join(" ")
}

pub(super) fn format_cleanup_system_proxy_summary(summary: &CleanupSystemProxySummary) -> String {
    let status = &summary.status;
    let state = if status.managed {
        "managed"
    } else if status.matches_target {
        "unrecorded_match"
    } else if status.enabled {
        "other_target"
    } else {
        "off"
    };
    format!(
        "{state}@{} recorded={}",
        summary.candidate_source,
        on_off(status.target_recorded)
    )
}

pub(super) fn print_doctor_report(mut writer: impl Write, report: &DoctorReport) -> Result<()> {
    writeln!(
        writer,
        "TabbyMew doctor: {}",
        if report.ok { "ok" } else { "issues found" }
    )?;
    writeln!(writer, "  service: {}", report.service.status.as_str())?;
    writeln!(writer, "checks:")?;
    for check in &report.checks {
        let code = check
            .error_code
            .map(|code| format!(" code={code}"))
            .unwrap_or_default();
        writeln!(
            writer,
            "  {} {} [{}{}]: {}",
            if check.ok { "ok" } else { "fail" },
            check.name,
            check.severity,
            code,
            check.message
        )?;
    }
    if !report.recommendations.is_empty() {
        writeln!(writer, "recommendations:")?;
        for recommendation in &report.recommendations {
            writeln!(writer, "  - {recommendation}")?;
        }
    }
    print_next_actions(&mut writer, &report.next_actions)?;
    Ok(())
}

pub(super) fn print_next_actions(
    writer: &mut impl Write,
    actions: &[CliNextAction],
) -> Result<()> {
    if actions.is_empty() {
        return Ok(());
    }
    writeln!(writer, "next actions:")?;
    for action in actions {
        writeln!(
            writer,
            "  - {}: {}",
            action.code,
            format_next_action_commands(action)
        )?;
    }
    Ok(())
}

pub(super) fn format_next_action_commands(action: &CliNextAction) -> String {
    action
        .commands
        .iter()
        .map(|command| command.join(" "))
        .collect::<Vec<_>>()
        .join(" && ")
}

pub(super) fn value_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

pub(super) fn value_u64(value: &Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_u64()
}

pub(super) fn value_bool(value: &Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

pub(super) fn value_array<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Vec<Value>> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_array()
}

pub(super) fn value_string_array(value: &Value, path: &[&str]) -> Vec<String> {
    value_array(value, path)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn value_array_len(value: &Value, path: &[&str]) -> Option<usize> {
    value_array(value, path).map(Vec::len)
}

pub(super) fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

pub(super) fn print_import_report(
    mut writer: impl Write,
    result: &subscription::ImportResult,
    input: &Path,
    output: Option<&Path>,
) -> Result<()> {
    match output {
        Some(output) => writeln!(
            writer,
            "imported {} outbound(s) from {} into {}",
            result.imported,
            input.display(),
            output.display()
        )?,
        None => writeln!(
            writer,
            "imported {} outbound(s) from {}",
            result.imported,
            input.display()
        )?,
    }

    writeln!(writer, "protocols:")?;
    for (protocol, count) in result.protocol_counts() {
        writeln!(writer, "  {protocol}: {count}")?;
    }
    writeln!(
        writer,
        "routing: final={}, policy_groups={}, rules={}",
        result.config.route.final_outbound,
        result.config.policy_groups.len(),
        result.config.route.rules.len()
    )?;

    if result.warnings.is_empty() {
        writeln!(writer, "warnings: none")?;
    } else {
        writeln!(writer, "warnings: {}", result.warnings.len())?;
        for warning in &result.warnings {
            writeln!(writer, "  - {warning}")?;
        }
    }

    Ok(())
}

pub(super) fn init_logging(level: &str, log_file: Option<&Path>) -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let timer = ChronoLocal::new("%Y-%m-%d %H:%M:%S".to_string());

    match log_file {
        Some(log_file) => {
            if let Some(parent) = log_file
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .filter(|parent| !parent.exists())
            {
                fs_security::create_private_dir_all(parent)
                    .with_context(|| format!("failed to create log dir {}", parent.display()))?;
            }
            let file = fs_security::open_private_append(log_file)
                .with_context(|| format!("failed to open log file {}", log_file.display()))?;
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_timer(timer)
                .with_ansi(false)
                .with_target(false)
                .with_writer(Mutex::new(file))
                .try_init();
        }
        None => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_timer(timer)
                .with_ansi(false)
                .with_target(false)
                .try_init();
        }
    }
    Ok(())
}
