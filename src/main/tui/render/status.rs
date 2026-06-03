use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DashboardStatusTone {
    Good,
    Warning,
    Bad,
    Muted,
    Accent,
}

pub(super) fn dashboard_status_row_tone(label: &str, value: &str) -> Option<DashboardStatusTone> {
    match label {
        "State" => Some(service_text_dashboard_status_tone(value)),
        "Proxy" | "LAN Proxy" | "System Proxy" => Some(on_off_dashboard_status_tone(value)),
        "TUN" => Some(tun_dashboard_status_tone(value)),
        "Route Mode" | "Routing" => Some(DashboardStatusTone::Accent),
        "Memory" if value != "-" => Some(DashboardStatusTone::Accent),
        "Issues" if value == "none" => Some(DashboardStatusTone::Muted),
        "Issues" => Some(DashboardStatusTone::Warning),
        _ => None,
    }
}

pub(super) fn service_text_dashboard_status_tone(value: &str) -> DashboardStatusTone {
    let value = value.to_ascii_lowercase();
    if value.contains("stale") || value.contains("failed") || value.contains("error") {
        DashboardStatusTone::Bad
    } else if value.contains("cleanup") || value.contains("unknown") {
        DashboardStatusTone::Warning
    } else if value.starts_with("running") {
        DashboardStatusTone::Good
    } else if value.starts_with("stopped") || value == "-" {
        DashboardStatusTone::Muted
    } else {
        DashboardStatusTone::Accent
    }
}

pub(super) fn on_off_dashboard_status_tone(value: &str) -> DashboardStatusTone {
    let value = value.to_ascii_lowercase();
    if value.contains("failed")
        || value.contains("stale")
        || value.contains("unhealthy")
        || value.contains("error")
    {
        DashboardStatusTone::Bad
    } else if value.contains("requires")
        || value.contains("cleanup")
        || value.contains("unknown")
        || value.contains("unmanaged")
        || value.contains("unrecorded")
    {
        DashboardStatusTone::Warning
    } else if value.starts_with("on") {
        DashboardStatusTone::Good
    } else if value.starts_with("off") || value == "-" {
        DashboardStatusTone::Muted
    } else {
        DashboardStatusTone::Accent
    }
}

pub(super) fn tun_dashboard_status_tone(value: &str) -> DashboardStatusTone {
    if value.to_ascii_lowercase().starts_with("on") {
        DashboardStatusTone::Good
    } else {
        DashboardStatusTone::Muted
    }
}

pub(super) fn dashboard_status_label_style(tone: Option<DashboardStatusTone>) -> Style {
    match tone {
        Some(DashboardStatusTone::Muted) | None => Style::default().fg(Color::DarkGray),
        Some(_) => Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    }
}

pub(super) fn dashboard_status_value_style(tone: Option<DashboardStatusTone>) -> Style {
    tone.map(dashboard_status_tone_style).unwrap_or_default()
}

pub(super) fn dashboard_status_tone_style(tone: DashboardStatusTone) -> Style {
    let color = match tone {
        DashboardStatusTone::Good => Color::Green,
        DashboardStatusTone::Warning => Color::Yellow,
        DashboardStatusTone::Bad => Color::Red,
        DashboardStatusTone::Muted => Color::DarkGray,
        DashboardStatusTone::Accent => Color::Cyan,
    };
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

#[derive(Debug)]
pub(super) struct TuiStatusSummary {
    pub(super) service_state: String,
    pub(super) pid: String,
    pub(super) memory: String,
    pub(super) uptime: String,
    pub(super) control_state: String,
    pub(super) control_error: Option<String>,
    pub(super) active_config: String,
    pub(super) log: String,
    pub(super) proxy: String,
    pub(super) lan_proxy: String,
    pub(super) route_mode: String,
    pub(super) final_outbound: String,
    pub(super) global_outbound: String,
    pub(super) policy_groups: String,
    pub(super) route_rules: String,
    pub(super) dns: String,
    pub(super) route_selections: String,
    pub(super) system_proxy: String,
    pub(super) tun: String,
    pub(super) tun_detail: String,
    pub(super) subscriptions: String,
    pub(super) state_file: String,
    pub(super) preferences_file: String,
    pub(super) cleanup_items: Vec<String>,
    pub(super) state_error: Option<String>,
    pub(super) preference_error: Option<String>,
}

pub(super) fn tui_status_summary(report: &StatusReport, control_snapshot: Option<&Value>) -> TuiStatusSummary {
    let service = &report.service;
    let service_state = if service.needs_cleanup() {
        format!("{} (cleanup needed)", service.status.as_str())
    } else {
        service.status.as_str().to_string()
    };
    let control_state = report
        .control_api
        .as_ref()
        .map(|control| {
            if control.healthy {
                format!("healthy at http://{}", control.listen)
            } else {
                format!("unhealthy at http://{}", control.listen)
            }
        })
        .unwrap_or_else(|| "not available".to_string());
    let control_error = report
        .control_api
        .as_ref()
        .and_then(|control| control.error.clone());
    let uptime = report
        .control_api
        .as_ref()
        .and_then(|control| control.health.as_ref())
        .and_then(|health| value_u64(health, &["uptime_seconds"]))
        .map(format_duration)
        .unwrap_or_else(|| "-".to_string());
    let final_outbound = report
        .control_api
        .as_ref()
        .and_then(|control| control.config.as_ref())
        .and_then(|config| value_str(config, &["route", "final_outbound"]))
        .map(str::to_string)
        .unwrap_or_else(|| "-".to_string());
    let dns = report
        .control_api
        .as_ref()
        .and_then(|control| control.config.as_ref())
        .and_then(|config| value_str(config, &["dns"]))
        .map(str::to_string)
        .unwrap_or_else(|| "-".to_string());
    let route_selections = report
        .control_api
        .as_ref()
        .and_then(|control| control.counters.as_ref())
        .and_then(|counters| value_u64(counters, &["route_selections_total"]))
        .unwrap_or_default()
        .to_string();
    let proxy = format_tui_proxy_state(control_snapshot);
    let lan_proxy = format_tui_lan_proxy_state(control_snapshot);
    let route_mode = control_snapshot
        .and_then(|value| value_str(value, &["routing", "mode"]))
        .unwrap_or("-")
        .to_string();
    let global_outbound = control_snapshot
        .and_then(|value| value_str(value, &["routing", "global_outbound"]))
        .unwrap_or("-")
        .to_string();
    let policy_groups = format_tui_policy_groups(control_snapshot);
    let route_rules = format_tui_route_rules(control_snapshot);
    let tun = format_tui_tun_state(control_snapshot);
    let tun_detail = control_snapshot
        .and_then(|value| value_str(value, &["proxy", "tun_detail"]))
        .unwrap_or("-")
        .to_string();
    let system_proxy = format_tui_system_proxy_state(control_snapshot);
    let subscriptions = control_snapshot
        .and_then(|value| {
            value
                .get("subscriptions")?
                .get("subscriptions")?
                .as_array()
                .map(Vec::len)
        })
        .map(|count| count.to_string())
        .unwrap_or_else(|| "-".to_string());
    let active_config = control_snapshot
        .and_then(|value| value_str(value, &["process", "config_path"]))
        .map(str::to_string)
        .or_else(|| {
            service
                .config
                .as_ref()
                .map(|path| path.display().to_string())
        })
        .unwrap_or_else(|| "-".to_string());

    TuiStatusSummary {
        service_state,
        pid: service
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".to_string()),
        memory: service
            .memory_rss_bytes
            .map(format_memory_bytes)
            .unwrap_or_else(|| "-".to_string()),
        uptime,
        control_state,
        control_error,
        active_config,
        log: service
            .log
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_string()),
        proxy,
        lan_proxy,
        route_mode,
        final_outbound,
        global_outbound,
        policy_groups,
        route_rules,
        dns,
        route_selections,
        system_proxy,
        tun,
        tun_detail,
        subscriptions,
        state_file: service.state_file.display().to_string(),
        preferences_file: service.preferences_file.display().to_string(),
        cleanup_items: service.cleanup_items.clone(),
        state_error: service.state_error.clone(),
        preference_error: service.preference_error.clone(),
    }
}

pub(super) fn format_tui_proxy_state(control_snapshot: Option<&Value>) -> String {
    let Some(control_snapshot) = control_snapshot else {
        return "-".to_string();
    };
    let state = value_bool(control_snapshot, &["proxy", "enabled"])
        .map(on_off)
        .unwrap_or("-");
    let listeners = tui_proxy_listener_values(control_snapshot, "effective_listeners")
        .or_else(|| tui_proxy_listener_values(control_snapshot, "local_listeners"))
        .unwrap_or_else(|| tui_inbound_listener_values(control_snapshot));
    format_tui_state_with_listeners(state, &listeners)
}

pub(super) fn format_tui_lan_proxy_state(control_snapshot: Option<&Value>) -> String {
    let Some(control_snapshot) = control_snapshot else {
        return "-".to_string();
    };
    let enabled = control_snapshot_lan_proxy_enabled(Some(control_snapshot));
    let state = enabled.map(on_off).unwrap_or("-");
    let available =
        value_bool(control_snapshot, &["lan_proxy", "available"]).unwrap_or_else(|| {
            value_u64(control_snapshot, &["proxy", "configured_inbounds"]).unwrap_or_default() > 0
        });
    if !available {
        return format!("{state} (unavailable)");
    }

    match enabled {
        Some(true) => {
            let listeners = tui_proxy_listener_values(control_snapshot, "effective_listeners")
                .or_else(|| tui_proxy_listener_values(control_snapshot, "lan_listeners"))
                .unwrap_or_default();
            format_tui_state_with_listeners(state, &listeners)
        }
        Some(false) => {
            let listeners = tui_proxy_listener_values(control_snapshot, "local_listeners")
                .or_else(|| tui_proxy_listener_values(control_snapshot, "effective_listeners"))
                .unwrap_or_else(|| tui_inbound_listener_values(control_snapshot));
            if listeners.is_empty() {
                format!("{state} local-only")
            } else {
                format!("{state} local-only {}", summarize_tui_listeners(&listeners))
            }
        }
        None => state.to_string(),
    }
}

pub(super) fn format_tui_system_proxy_state(control_snapshot: Option<&Value>) -> String {
    let Some(control_snapshot) = control_snapshot else {
        return "-".to_string();
    };
    let enabled = value_bool(control_snapshot, &["system_proxy", "enabled"]);
    let managed = value_bool(control_snapshot, &["system_proxy", "managed"]);
    let matches_target = value_bool(control_snapshot, &["system_proxy", "matches_target"]);
    let target_recorded = value_bool(control_snapshot, &["system_proxy", "target_recorded"]);
    match (enabled, managed, matches_target, target_recorded) {
        (Some(true), Some(true), _, _) => "on (managed)".to_string(),
        (Some(true), Some(false), Some(true), Some(false)) => "on (unrecorded)".to_string(),
        (Some(true), Some(false), _, _) => "off (unmanaged target on)".to_string(),
        (Some(false), Some(false), _, _) | (Some(false), Some(true), _, _) => "off".to_string(),
        (Some(true), None, _, _) => "on (unknown)".to_string(),
        (Some(false), None, _, _) => "off (unknown)".to_string(),
        _ => "-".to_string(),
    }
}

pub(super) fn format_tui_state_with_listeners(state: &str, listeners: &[String]) -> String {
    if listeners.is_empty() {
        state.to_string()
    } else {
        format!("{state} {}", summarize_tui_listeners(listeners))
    }
}

pub(super) fn tui_proxy_listener_values(control_snapshot: &Value, key: &str) -> Option<Vec<String>> {
    let listeners = value_string_array(control_snapshot, &["proxy", key]);
    (!listeners.is_empty()).then_some(listeners)
}

pub(super) fn tui_inbound_listener_values(control_snapshot: &Value) -> Vec<String> {
    value_array(control_snapshot, &["inbounds", "items"])
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(listener_from_inbound_summary)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub(super) fn listener_from_inbound_summary(summary: &str) -> Option<String> {
    let (_, address) = summary.split_once('@')?;
    address.split_whitespace().next().map(str::to_string)
}

pub(super) fn summarize_tui_listeners(listeners: &[String]) -> String {
    let shown = listeners.iter().take(2).cloned().collect::<Vec<_>>();
    match listeners.len().saturating_sub(shown.len()) {
        0 => shown.join(", "),
        hidden => format!("{} +{hidden}", shown.join(", ")),
    }
}

pub(super) fn format_tui_policy_groups(control_snapshot: Option<&Value>) -> String {
    let Some(groups) =
        control_snapshot.and_then(|value| value_array(value, &["routing", "policy_groups"]))
    else {
        return "-".to_string();
    };
    let selected = groups
        .iter()
        .filter(|group| value_str(group, &["selected"]).is_some_and(|value| !value.is_empty()))
        .count();
    format!("{} groups, {} selected", groups.len(), selected)
}

pub(super) fn format_tui_route_rules(control_snapshot: Option<&Value>) -> String {
    let Some(items) =
        control_snapshot.and_then(|value| value_array(value, &["rules", "rule_items"]))
    else {
        return "-".to_string();
    };
    let custom = items
        .iter()
        .filter(|item| value_str(item, &["source"]) == Some("custom"))
        .count();
    let subscription = items
        .iter()
        .filter(|item| value_str(item, &["source"]) == Some("subscription"))
        .count();
    format!("{custom} custom, {subscription} subscription")
}
