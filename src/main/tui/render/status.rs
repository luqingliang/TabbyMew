use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DashboardStatusTone {
    Good,
    Warning,
    Bad,
    Muted,
    Accent,
}

pub(crate) fn dashboard_status_row_tone(label: &str, value: &str) -> Option<DashboardStatusTone> {
    match label {
        "State" => Some(service_text_dashboard_status_tone(value)),
        "Proxy" | "LAN Proxy" | "System Proxy" => Some(on_off_dashboard_status_tone(value)),
        "TUN" => Some(tun_dashboard_status_tone(value)),
        "Route Mode" | "Routing" => Some(DashboardStatusTone::Accent),
        "Memory" if value != "-" => Some(DashboardStatusTone::Accent),
        "Traffic" if value != "-" => Some(DashboardStatusTone::Accent),
        "Issues" if value == "none" => Some(DashboardStatusTone::Muted),
        "Issues" => Some(DashboardStatusTone::Warning),
        _ => None,
    }
}

pub(crate) fn service_text_dashboard_status_tone(value: &str) -> DashboardStatusTone {
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

pub(crate) fn on_off_dashboard_status_tone(value: &str) -> DashboardStatusTone {
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

pub(crate) fn tun_dashboard_status_tone(value: &str) -> DashboardStatusTone {
    if value.to_ascii_lowercase().starts_with("on") {
        DashboardStatusTone::Good
    } else {
        DashboardStatusTone::Muted
    }
}

pub(crate) fn dashboard_status_label_style(tone: Option<DashboardStatusTone>) -> Style {
    match tone {
        Some(DashboardStatusTone::Muted) | None => Style::default().fg(Color::DarkGray),
        Some(_) => Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    }
}

pub(crate) fn dashboard_status_value_style(tone: Option<DashboardStatusTone>) -> Style {
    tone.map(dashboard_status_tone_style).unwrap_or_default()
}

pub(crate) fn dashboard_status_tone_style(tone: DashboardStatusTone) -> Style {
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
pub(crate) struct TuiStatusSummary {
    pub(crate) service_state: String,
    pub(crate) pid: String,
    pub(crate) memory: String,
    pub(crate) uptime: String,
    pub(crate) control_state: String,
    pub(crate) control_error: Option<String>,
    pub(crate) active_config: String,
    pub(crate) log: String,
    pub(crate) proxy: String,
    pub(crate) lan_proxy: String,
    pub(crate) route_mode: String,
    pub(crate) final_outbound: String,
    pub(crate) global_outbound: String,
    pub(crate) policy_groups: String,
    pub(crate) route_rules: String,
    pub(crate) dns: String,
    pub(crate) traffic: String,
    pub(crate) system_proxy: String,
    pub(crate) tun: String,
    pub(crate) tun_detail: String,
    pub(crate) subscriptions: String,
    pub(crate) state_file: String,
    pub(crate) preferences_file: String,
    pub(crate) cleanup_items: Vec<String>,
    pub(crate) state_error: Option<String>,
    pub(crate) preference_error: Option<String>,
}

pub(crate) fn tui_status_summary(
    report: &StatusReport,
    control_snapshot: Option<&Value>,
    traffic_speed: TuiTrafficSpeed,
) -> TuiStatusSummary {
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
    let traffic = format_tui_traffic(report, control_snapshot, traffic_speed);
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
    let policy_groups = format_policy_groups(control_snapshot);
    let route_rules = format_tui_route_rules(control_snapshot);
    let tun = format_control_snapshot_tun_state(control_snapshot);
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
        traffic,
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

pub(crate) fn format_tui_traffic(
    report: &StatusReport,
    control_snapshot: Option<&Value>,
    traffic_speed: TuiTrafficSpeed,
) -> String {
    let counters = control_snapshot
        .and_then(|value| value.get("counters"))
        .or_else(|| {
            report
                .control_api
                .as_ref()
                .and_then(|control| control.counters.as_ref())
        });
    let Some(counters) = counters else {
        return "-".to_string();
    };
    let Some(upload) = value_u64(counters, &["proxied_upload_bytes"]) else {
        return "-".to_string();
    };
    let Some(download) = value_u64(counters, &["proxied_download_bytes"]) else {
        return "-".to_string();
    };
    format!(
        "U {} @ {}  D {} @ {}",
        format_traffic_bytes(upload),
        format_traffic_speed(traffic_speed.upload_bytes_per_second),
        format_traffic_bytes(download),
        format_traffic_speed(traffic_speed.download_bytes_per_second),
    )
}

pub(crate) fn format_traffic_speed(bytes_per_second: Option<u64>) -> String {
    bytes_per_second
        .map(|bytes| format!("{}/s", format_traffic_bytes(bytes)))
        .unwrap_or_else(|| "-/s".to_string())
}

pub(crate) fn format_traffic_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * KIB;
    const GIB: f64 = 1024.0 * MIB;
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", bytes as f64 / GIB)
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / MIB)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / KIB)
    } else {
        format!("{bytes} B")
    }
}

pub(crate) fn format_tui_proxy_state(control_snapshot: Option<&Value>) -> String {
    let Some(control_snapshot) = control_snapshot else {
        return "-".to_string();
    };
    let state = value_bool(control_snapshot, &["proxy", "enabled"])
        .map(on_off)
        .unwrap_or("-");
    let listeners = proxy_listener_values(control_snapshot, "effective_listeners")
        .or_else(|| proxy_listener_values(control_snapshot, "local_listeners"))
        .unwrap_or_else(|| inbound_listener_values(control_snapshot));
    format_tui_state_with_listeners(state, &listeners)
}

pub(crate) fn format_tui_lan_proxy_state(control_snapshot: Option<&Value>) -> String {
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
            let listeners = proxy_listener_values(control_snapshot, "effective_listeners")
                .or_else(|| proxy_listener_values(control_snapshot, "lan_listeners"))
                .unwrap_or_default();
            format_tui_state_with_listeners(state, &listeners)
        }
        Some(false) => {
            let listeners = proxy_listener_values(control_snapshot, "local_listeners")
                .or_else(|| proxy_listener_values(control_snapshot, "effective_listeners"))
                .unwrap_or_else(|| inbound_listener_values(control_snapshot));
            if listeners.is_empty() {
                format!("{state} local-only")
            } else {
                format!("{state} local-only {}", summarize_listeners(&listeners))
            }
        }
        None => state.to_string(),
    }
}

pub(crate) fn format_tui_system_proxy_state(control_snapshot: Option<&Value>) -> String {
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

pub(crate) fn format_tui_state_with_listeners(state: &str, listeners: &[String]) -> String {
    if listeners.is_empty() {
        state.to_string()
    } else {
        format!("{state} {}", summarize_listeners(listeners))
    }
}

pub(crate) fn format_policy_groups(control_snapshot: Option<&Value>) -> String {
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

pub(crate) fn format_tui_route_rules(control_snapshot: Option<&Value>) -> String {
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
