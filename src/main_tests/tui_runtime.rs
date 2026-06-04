use super::*;

#[test]
fn dashboard_log_tail_reads_service_log() -> Result<()> {
    let dir = env::temp_dir().join(format!(
        "tabbymew-dashboard-log-test-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    let log = dir.join("tabbymew.log");
    fs::write(&log, "first\nsecond\nthird\n")?;
    let session = ShellSession {
        config: None,
        state_dir: dir.clone(),
        timeout: Duration::from_secs(1),
    };
    let report = StatusReport::new(
        ServiceStatus {
            status: ServiceStatusKind::Running,
            running: true,
            stale: false,
            pid: Some(42),
            memory_rss_bytes: None,
            config: None,
            log: Some(log),
            listen: None,
            started_at_unix: None,
            state_dir: dir.clone(),
            state_file: dir.join("tabbymew-state.json"),
            runtime_state_file: dir.join("tabbymew-runtime.json"),
            preferences_file: dir.join("tabbymew-preferences.json"),
            active_state_file: Some(dir.join("tabbymew-state.json")),
            state_source: Some("managed".to_string()),
            state_file_exists: true,
            runtime_state_file_exists: false,
            heartbeat_at_unix: Some(1),
            heartbeat_age_seconds: Some(1),
            heartbeat_stale: false,
            managed_system_proxy_recorded: false,
            cleanup_items: Vec::new(),
            state_error: None,
            preference_error: None,
        },
        None,
    );

    assert_eq!(
        tui_dashboard_log_tail(&session, &report, 2),
        "second\nthird\n"
    );

    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn simplifies_tui_log_dates_for_display_only() {
    let raw = concat!(
        "2026-05-30 11:38:55  WARN connection failed destination=google.com outbound=proxy\n",
        "2026-05-30 11:38:56  INFO connection routed destination=example.com outbound=proxy\n",
        "2026-05-30 11:39:03 INFO lifecycle event=start\n",
        "plain line without timestamp\n",
    );

    assert_eq!(
        simplify_tui_log_tail(raw),
        concat!(
            "11:38:55 WARN conn failed google.com =>proxy\n",
            "11:38:56 INFO conn example.com =>proxy\n",
            "11:39:03 INFO lifecycle event=start\n",
            "plain line without timestamp\n",
        )
    );
}

#[test]
fn tui_tun_summary_keeps_permission_status_as_suffix() {
    let control_snapshot = serde_json::json!({
        "proxy": {
            "tun_enabled": true,
            "tun_status": "requires_permission"
        }
    });

    assert_eq!(
        format_control_snapshot_tun_state(Some(&control_snapshot)),
        "on (requires_permission)"
    );

    let control_snapshot = serde_json::json!({
        "proxy": {
            "tun_enabled": false,
            "tun_status": "requires_permission"
        }
    });

    assert_eq!(
        format_control_snapshot_tun_state(Some(&control_snapshot)),
        "off (requires_permission)"
    );
}

#[test]
fn tui_tun_switch_output_uses_user_facing_state() {
    let snapshot = serde_json::json!({
        "tun_enabled": true,
        "tun_status": "requires_permission",
        "configured_tun_inbounds": 1,
        "tun_detail": "TUN needs privileged setup",
    });

    let output = format_tun_switch_output(&snapshot, true);

    assert!(output.contains("enabled: on\n"));
    assert!(output.contains("status: on (requires_permission)\n"));
    assert!(!output.contains("status: requires_permission\n"));
}

#[test]
fn tui_system_proxy_switch_output_summarizes_status() {
    let snapshot = serde_json::json!({
        "platform": "macos",
        "supported": true,
        "enabled": true,
        "managed": true,
        "matches_target": true,
        "target_recorded": true,
        "target": {
            "source": "hybrid",
            "http": {
                "host": "127.0.0.1",
                "port": 7890,
                "address": "127.0.0.1:7890"
            },
            "https": {
                "host": "127.0.0.1",
                "port": 7890,
                "address": "127.0.0.1:7890"
            },
            "socks": null
        }
    });

    let control_snapshot = serde_json::json!({
        "system_proxy": {
            "enabled": true,
            "managed": true,
            "matches_target": true,
            "target_recorded": true
        }
    });
    let output = format_system_proxy_switch_output(&snapshot, true);

    assert_eq!(
        control_snapshot_system_proxy_enabled(Some(&control_snapshot)),
        Some(true)
    );
    assert_eq!(
        format_tui_system_proxy_state(Some(&control_snapshot)),
        "on (managed)"
    );
    assert!(output.contains("requested: enable\n"));
    assert!(output.contains("enabled: on\n"));
    assert!(output.contains("supported: on\n"));
    assert!(output.contains("managed: on\n"));
    assert!(output.contains("target recorded: on\n"));
    assert!(output.contains("matches target: on\n"));
    assert!(output.contains("platform: macos\n"));
    assert!(output.contains("target: hybrid: http=127.0.0.1:7890, https=127.0.0.1:7890\n"));
}

#[test]
fn tui_system_proxy_unrecorded_match_is_visible() {
    let control_snapshot = serde_json::json!({
        "system_proxy": {
            "enabled": true,
            "managed": false,
            "matches_target": true,
            "target_recorded": false
        }
    });

    assert_eq!(
        control_snapshot_system_proxy_enabled(Some(&control_snapshot)),
        Some(true)
    );
    assert_eq!(
        format_tui_system_proxy_state(Some(&control_snapshot)),
        "on (unrecorded)"
    );
    assert_eq!(
        dashboard_status_row_tone("System Proxy", "on (unrecorded)"),
        Some(DashboardStatusTone::Warning)
    );
}

#[test]
fn tui_system_proxy_unmanaged_state_is_not_treated_as_enabled() {
    let control_snapshot = serde_json::json!({
        "system_proxy": {
            "enabled": true,
            "managed": false,
            "matches_target": false,
            "target_recorded": false
        }
    });

    assert_eq!(
        control_snapshot_system_proxy_enabled(Some(&control_snapshot)),
        Some(false)
    );
    assert_eq!(
        format_tui_system_proxy_state(Some(&control_snapshot)),
        "off (unmanaged target on)"
    );
    assert_eq!(
        dashboard_status_row_tone("System Proxy", "off (unmanaged target on)"),
        Some(DashboardStatusTone::Warning)
    );
}

#[test]
fn tui_lan_proxy_switch_output_summarizes_status() {
    let snapshot = serde_json::json!({
        "enabled": true,
        "available": true,
        "detail": "LAN devices can connect to the local proxy port"
    });
    let control_snapshot = serde_json::json!({
        "proxy": {
            "lan_enabled": true,
            "effective_listeners": ["hybrid 0.0.0.0:17890"],
            "local_listeners": ["hybrid 127.0.0.1:17890"]
        },
        "lan_proxy": {
            "enabled": true
        }
    });
    let output = format_lan_proxy_switch_output(&snapshot, true, Some(&control_snapshot));

    assert_eq!(
        control_snapshot_lan_proxy_enabled(Some(&control_snapshot)),
        Some(true)
    );
    assert!(output.contains("requested: enable\n"));
    assert!(output.contains("enabled: on\n"));
    assert!(output.contains("available: on\n"));
    assert!(output.contains("listeners: hybrid 0.0.0.0:17890\n"));
    assert!(output.contains("detail: LAN devices can connect to the local proxy port\n"));
}
