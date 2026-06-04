use super::*;

#[test]
fn tui_status_summary_includes_core_sections() {
    let report = StatusReport::new(
        ServiceStatus {
            status: ServiceStatusKind::Running,
            running: true,
            stale: false,
            pid: Some(42),
            memory_rss_bytes: Some(44 * 1024 * 1024),
            config: Some(PathBuf::from("/tmp/config.json")),
            log: Some(PathBuf::from("/tmp/tabbymew.log")),
            listen: Some("127.0.0.1:9090".to_string()),
            started_at_unix: Some(1),
            state_dir: PathBuf::from("/tmp/tabbymew-state"),
            state_file: PathBuf::from("/tmp/tabbymew-state/tabbymew-state.json"),
            runtime_state_file: PathBuf::from("/tmp/tabbymew-state/tabbymew-runtime.json"),
            preferences_file: PathBuf::from("/tmp/tabbymew-state/tabbymew-preferences.json"),
            active_state_file: Some(PathBuf::from("/tmp/tabbymew-state/tabbymew-state.json")),
            state_source: Some("managed".to_string()),
            state_file_exists: true,
            runtime_state_file_exists: false,
            heartbeat_at_unix: Some(1),
            heartbeat_age_seconds: Some(2),
            heartbeat_stale: false,
            managed_system_proxy_recorded: false,
            cleanup_items: Vec::new(),
            state_error: None,
            preference_error: None,
        },
        Some(ControlApiReport {
            listen: "127.0.0.1:9090".to_string(),
            healthy: true,
            health: Some(serde_json::json!({
                "service": "TabbyMew",
                "uptime_seconds": 3,
            })),
            config: Some(serde_json::json!({
                "dns": "enabled",
                "route": { "final_outbound": "Proxy" },
            })),
            counters: Some(serde_json::json!({
                "route_selections_total": 7,
            })),
            error_code: None,
            error: None,
        }),
    );
    let control_snapshot = serde_json::json!({
        "proxy": {
            "enabled": true,
            "lan_enabled": false,
            "local_listeners": ["hybrid 127.0.0.1:17890"],
            "lan_listeners": ["hybrid 0.0.0.0:17890"],
            "effective_listeners": ["hybrid 127.0.0.1:17890"],
            "tun_enabled": true,
            "tun_status": "running",
            "tun_auto_route": true,
            "tun_ipv6_enabled": false,
            "tun_dns_mode": "virtual",
            "tun_dns_addr": null,
            "tun_configured_bypass_count": 5,
            "tun_proxy_bypass_sources": 2,
            "tun_egress_interface": "en0",
            "tun_bound_interface": "en0",
            "tun_watchdog_restarts": 1,
            "tun_last_watchdog_reason": "runtime timer gap after sleep/wake (900s)",
            "tun_requires_privilege": true,
            "tun_privilege_verified": true,
            "tun_warnings": [],
            "tun_detail": "TUN mode is ready"
        },
        "system_proxy": {
            "enabled": true,
            "managed": true,
            "matches_target": true,
            "target_recorded": true
        },
        "lan_proxy": {
            "enabled": false,
            "available": true,
            "detail": "only this computer can connect to the local proxy port"
        },
        "subscriptions": {
            "subscriptions": [{ "name": "sub" }]
        },
        "routing": {
            "mode": "rule",
            "global_outbound": "Proxy",
            "global_targets": ["Proxy", "direct", "block"],
            "policy_groups": [
                { "tag": "Proxy", "selected": "node-a" },
                { "tag": "Fallback", "selected": "node-b" }
            ]
        },
        "rules": {
            "rule_items": [
                { "source": "custom", "summary": "domain=example.com -> Proxy" },
                { "source": "subscription", "summary": "domain_suffix=local -> direct" },
                { "source": "subscription", "summary": "domain_keyword=ads -> block" }
            ]
        },
        "process": {
            "config_path": "/tmp/config.json"
        }
    });
    let summary = tui_status_summary(&report, Some(&control_snapshot));

    assert_eq!(summary.service_state, "running");
    assert_eq!(summary.control_state, "healthy at http://127.0.0.1:9090");
    assert_eq!(summary.memory, "44.0 MiB");
    assert_eq!(summary.route_mode, "rule");
    assert_eq!(summary.global_outbound, "Proxy");
    assert_eq!(summary.proxy, "on hybrid 127.0.0.1:17890");
    assert_eq!(summary.lan_proxy, "off local-only hybrid 127.0.0.1:17890");
    assert_eq!(summary.policy_groups, "2 groups, 2 selected");
    assert_eq!(summary.route_rules, "1 custom, 2 subscription");
    assert_eq!(summary.system_proxy, "on (managed)");
    assert_eq!(summary.tun, "on");
    assert_eq!(summary.subscriptions, "1");

    assert_eq!(
        dashboard_status_row_tone("State", &summary.service_state),
        Some(DashboardStatusTone::Good)
    );
    assert_eq!(
        dashboard_status_row_tone("Control API", &summary.control_state),
        None
    );
    assert_eq!(
        dashboard_status_row_tone("Proxy", &summary.proxy),
        Some(DashboardStatusTone::Good)
    );
    assert_eq!(
        dashboard_status_row_tone("System Proxy", &summary.system_proxy),
        Some(DashboardStatusTone::Good)
    );
    assert_eq!(
        dashboard_status_row_tone("TUN", &summary.tun),
        Some(DashboardStatusTone::Good)
    );
    assert_eq!(
        dashboard_status_row_tone("Route Mode", &summary.route_mode),
        Some(DashboardStatusTone::Accent)
    );
    assert_eq!(
        dashboard_status_row_tone("Memory", &summary.memory),
        Some(DashboardStatusTone::Accent)
    );
    assert_eq!(
        on_off_dashboard_status_tone("off (requires_permission)"),
        DashboardStatusTone::Warning
    );
    assert_eq!(
        dashboard_status_row_tone("TUN", "off (requires_permission)"),
        Some(DashboardStatusTone::Muted)
    );
    assert_eq!(
        dashboard_status_row_tone("TUN", "on (requires_permission)"),
        Some(DashboardStatusTone::Good)
    );
    assert_eq!(
        dashboard_status_row_tone("Config", "/tmp/config.json"),
        None
    );

    assert!(
        format_cli_route_mode_status(&control_snapshot)
            .unwrap()
            .contains("route mode: rule")
    );
    assert!(
        format_cli_global_status(&control_snapshot)
            .unwrap()
            .contains("global target: Proxy")
    );
    assert!(format_cli_policy_groups(&policy_groups(Some(&control_snapshot))).contains("Proxy"));
    assert!(format_cli_tun_status(control_snapshot.get("proxy").unwrap()).contains("status: on"));
    assert!(
        format_cli_tun_status(control_snapshot.get("proxy").unwrap()).contains("auto route: on")
    );
    assert!(
        format_cli_tun_status(control_snapshot.get("proxy").unwrap())
            .contains("egress interface: en0")
    );
    assert!(
        format_cli_tun_status(control_snapshot.get("proxy").unwrap())
            .contains("watchdog restarts: 1")
    );
    assert!(
        format_cli_system_proxy_status(control_snapshot.get("system_proxy").unwrap())
            .contains("enabled: on")
    );
    assert!(
        format_cli_system_proxy_status(control_snapshot.get("system_proxy").unwrap())
            .contains("target recorded: on")
    );
    assert!(
        format_cli_system_proxy_status(control_snapshot.get("system_proxy").unwrap())
            .contains("matches target: on")
    );
}

#[test]
fn formats_memory_bytes_for_status_display() {
    assert_eq!(format_memory_bytes(512), "512 B");
    assert_eq!(format_memory_bytes(1536), "1.5 KiB");
    assert_eq!(format_memory_bytes(44 * 1024 * 1024), "44.0 MiB");
}

#[test]
fn wait_state_helpers_are_stable_for_cli_json() {
    let tun_running = serde_json::json!({
        "proxy": {
            "tun_enabled": true,
            "tun_status": "running"
        }
    });
    let tun_permission = serde_json::json!({
        "proxy": {
            "tun_enabled": true,
            "tun_status": "requires_permission"
        }
    });
    let system_proxy_managed = serde_json::json!({
        "enabled": true,
        "managed": true,
        "matches_target": true,
        "target_recorded": true
    });
    let system_proxy_unrecorded = serde_json::json!({
        "enabled": true,
        "managed": false,
        "matches_target": true,
        "target_recorded": false
    });
    let system_proxy_unmanaged = serde_json::json!({
        "enabled": true,
        "managed": false,
        "matches_target": false,
        "target_recorded": false
    });

    assert_eq!(tun_wait_current(&tun_running), "on");
    assert_eq!(tun_wait_current(&tun_permission), "on_requires_permission");
    assert_eq!(system_proxy_wait_current(&system_proxy_managed), "on");
    assert_eq!(
        system_proxy_wait_current(&system_proxy_unrecorded),
        "on_unrecorded"
    );
    assert_eq!(
        system_proxy_wait_current(&system_proxy_unmanaged),
        "on_unmanaged"
    );

    let report = wait_report(
        false,
        WaitTarget::Tun,
        WaitDesired::On,
        "on_requires_permission".to_string(),
        125,
        Some("tun_not_ready"),
    );
    assert_eq!(report.schema_version, CLI_JSON_SCHEMA_VERSION);
    assert_eq!(report.target, "tun");
    assert_eq!(report.desired, "on");
    assert_eq!(report.error_code, Some("tun_not_ready"));
    assert!(report.message.contains("current: on_requires_permission"));
    assert!(
        report
            .next_actions
            .iter()
            .any(|action| action.code == "doctor")
    );
}

#[test]
fn tui_error_output_includes_code_and_suggestion() {
    let mut app = test_tui_app();
    open_tui_error(
        &mut app,
        "TUN",
        anyhow::anyhow!("TUN auto route requires administrator/root privileges"),
    );
    assert_eq!(app.mode, TuiMode::Output);
    assert!(app.output.contains("error_code: tun_requires_permission"));
    assert!(app.output.contains("suggestion:"));
}

#[test]
fn wintun_access_denied_is_classified_as_permission_error() {
    let message = "tun2proxy failed: WintunCreateAdapter failed \"Failed to take device installation mutex (Code 0x00000005)\"";

    assert_eq!(classify_user_error(message), "tun_requires_permission");
    assert!(user_error_suggestion("tun_requires_permission").contains("Administrator"));
}

#[tokio::test]
async fn tui_refresh_status_is_safe_without_independent_runtime() -> Result<()> {
    let mut app = test_tui_app();
    fs::create_dir_all(&app.session.state_dir)?;
    app.refresh_status().await?;
    assert_eq!(app.status.service.status, ServiceStatusKind::Stopped);
    assert_eq!(app.control_snapshot, None);
    Ok(())
}
