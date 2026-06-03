use super::*;

#[test]
fn doctor_runtime_checks_report_actionable_codes() {
    let control_snapshot = serde_json::json!({
        "proxy": {
            "tun_enabled": true,
            "tun_status": "requires_permission",
            "tun_auto_route": true,
            "tun_configured_bypass_count": 5,
            "tun_proxy_bypass_sources": 1,
            "tun_requires_privilege": true,
            "tun_privilege_verified": false,
            "tun_warnings": [],
            "configured_tun_inbounds": 1
        },
        "system_proxy": {
            "enabled": true,
            "managed": false,
            "matches_target": false,
            "target_recorded": false
        },
        "subscriptions": {
            "subscriptions": [
                {
                    "name": "main",
                    "last_error": "fetch timed out"
                }
            ]
        },
        "routing": {
            "mode": "rule",
            "direct_outbound": "direct",
            "policy_groups": []
        },
        "rules": {
            "final_outbound": "Proxy"
        }
    });
    let mut checks = Vec::new();
    let mut recommendations = Vec::new();
    add_doctor_runtime_checks(&control_snapshot, &mut checks, &mut recommendations);

    assert!(checks.iter().any(|check| {
        check.name == "tun" && check.error_code == Some("tun_requires_permission")
    }));
    assert!(checks.iter().any(|check| {
        check.name == "system_proxy" && check.error_code == Some("system_proxy_unmanaged")
    }));
    assert!(
        checks
            .iter()
            .any(|check| check.name == "routing" && check.ok)
    );
    assert!(checks.iter().any(|check| {
        check.name == "subscriptions" && check.error_code == Some("subscription_update_failed")
    }));
    assert!(!recommendations.is_empty());

    let issues = doctor_report_issues(&checks);
    let actions = next_actions_for_issues(&issues);
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == "tun_requires_permission")
    );
    assert!(actions.iter().any(|action| action.code == "disable_tun"));
    assert!(
        actions
            .iter()
            .any(|action| action.code == "update_subscriptions")
    );
}

#[test]
fn doctor_system_proxy_reports_unrecorded_tabbymew_target() {
    let control_snapshot = serde_json::json!({
        "system_proxy": {
            "enabled": true,
            "managed": false,
            "matches_target": true,
            "target_recorded": false
        }
    });
    let mut checks = Vec::new();
    let mut recommendations = Vec::new();

    add_doctor_system_proxy_check(&control_snapshot, &mut checks, &mut recommendations);

    assert!(checks.iter().any(|check| {
        check.name == "system_proxy" && check.error_code == Some("system_proxy_unrecorded")
    }));
    assert!(
        recommendations.iter().any(|recommendation| {
            recommendation.contains("enable it again to record ownership")
        })
    );
}

#[test]
fn doctor_tun_checks_report_route_diagnostics() {
    let control_snapshot = serde_json::json!({
        "proxy": {
            "tun_enabled": true,
            "tun_status": "running",
            "tun_auto_route": true,
            "tun_dns_mode": "virtual",
            "tun_configured_bypass_count": 0,
            "tun_proxy_bypass_sources": 0,
            "tun_warnings": ["TUN bypass resolver timed out for outbound proxy"],
            "configured_tun_inbounds": 1
        },
        "system_proxy": {
            "enabled": false,
            "managed": false
        },
        "subscriptions": {
            "subscriptions": []
        },
        "routing": {
            "mode": "rule",
            "direct_outbound": "direct",
            "policy_groups": []
        },
        "rules": {
            "final_outbound": "Proxy"
        }
    });
    let mut checks = Vec::new();
    let mut recommendations = Vec::new();
    add_doctor_runtime_checks(&control_snapshot, &mut checks, &mut recommendations);

    assert!(
        checks
            .iter()
            .any(|check| check.error_code == Some("tun_bypass_empty"))
    );
    assert!(
        checks
            .iter()
            .any(|check| { check.error_code == Some("tun_egress_binding_missing") })
    );
    assert!(
        checks
            .iter()
            .any(|check| check.error_code == Some("tun_proxy_bypass_missing"))
    );
    assert!(
        checks
            .iter()
            .any(|check| check.error_code == Some("tun_startup_warnings"))
    );
    assert!(!recommendations.is_empty());
}

#[test]
fn doctor_tun_checks_expect_egress_binding_on_windows() {
    let control_snapshot = serde_json::json!({
        "proxy": {
            "tun_enabled": true,
            "tun_status": "running",
            "tun_auto_route": true,
            "tun_platform": "windows",
            "tun_dns_mode": "virtual",
            "tun_configured_bypass_count": 1,
            "tun_proxy_bypass_sources": 1,
            "tun_warnings": [],
            "configured_tun_inbounds": 1
        },
        "system_proxy": {
            "enabled": false,
            "managed": false
        },
        "subscriptions": {
            "subscriptions": []
        },
        "routing": {
            "mode": "rule",
            "direct_outbound": "direct",
            "policy_groups": []
        },
        "rules": {
            "final_outbound": "Proxy"
        }
    });
    let mut checks = Vec::new();
    let mut recommendations = Vec::new();
    add_doctor_runtime_checks(&control_snapshot, &mut checks, &mut recommendations);

    assert!(
        checks
            .iter()
            .any(|check| check.error_code == Some("tun_egress_binding_missing"))
    );
}

#[test]
fn doctor_tun_checks_report_recovery_and_binding_diagnostics() {
    let control_snapshot = serde_json::json!({
        "proxy": {
            "tun_desired_enabled": true,
            "tun_enabled": false,
            "tun_status": "failed",
            "tun_auto_route": true,
            "tun_configured_bypass_count": 1,
            "tun_proxy_bypass_sources": 1,
            "tun_warnings": [],
            "configured_tun_inbounds": 1
        }
    });
    let mut checks = Vec::new();
    let mut recommendations = Vec::new();
    add_doctor_tun_check(&control_snapshot, &mut checks, &mut recommendations);

    assert!(checks.iter().any(|check| {
        check.name == "tun_recovery" && check.error_code == Some("tun_listener_stopped")
    }));
    assert!(!recommendations.is_empty());

    let control_snapshot = serde_json::json!({
        "proxy": {
            "tun_enabled": true,
            "tun_status": "running",
            "tun_auto_route": true,
            "tun_platform": "macos",
            "tun_dns_mode": "virtual",
            "tun_configured_bypass_count": 1,
            "tun_proxy_bypass_sources": 1,
            "tun_egress_interface": "en0",
            "tun_bound_interface": "en7",
            "tun_watchdog_restarts": 2,
            "tun_last_watchdog_reason": "TUN egress binding drifted from en0 to en7",
            "tun_warnings": [],
            "configured_tun_inbounds": 1
        }
    });
    let mut checks = Vec::new();
    let mut recommendations = Vec::new();
    add_doctor_tun_check(&control_snapshot, &mut checks, &mut recommendations);

    assert!(
        checks
            .iter()
            .any(|check| check.error_code == Some("tun_egress_binding_drift"))
    );
    assert!(
        checks
            .iter()
            .any(|check| check.name == "tun_watchdog" && check.ok)
    );
    assert!(!recommendations.is_empty());

    let control_snapshot = serde_json::json!({
        "proxy": {
            "tun_enabled": true,
            "tun_status": "running",
            "tun_auto_route": true,
            "tun_platform": "linux",
            "tun_dns_mode": "virtual",
            "tun_configured_bypass_count": 1,
            "tun_proxy_bypass_sources": 1,
            "tun_egress_interface": "eth0",
            "tun_bound_interface": "eth1",
            "tun_watchdog_restarts": 0,
            "tun_warnings": [],
            "configured_tun_inbounds": 1
        }
    });
    let mut checks = Vec::new();
    let mut recommendations = Vec::new();
    add_doctor_tun_check(&control_snapshot, &mut checks, &mut recommendations);

    assert!(
        !checks
            .iter()
            .any(|check| check.error_code == Some("tun_egress_binding_drift"))
    );
}

#[test]
fn doctor_heartbeat_check_reports_stale_runtime_state() {
    let service = ServiceStatus {
        status: ServiceStatusKind::Running,
        running: true,
        stale: false,
        pid: Some(42),
        memory_rss_bytes: None,
        config: None,
        log: None,
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
        heartbeat_age_seconds: Some(process_manager::STALE_HEARTBEAT_AFTER_SECS + 1),
        heartbeat_stale: true,
        managed_system_proxy_recorded: false,
        cleanup_items: Vec::new(),
        state_error: None,
        preference_error: None,
    };
    let mut checks = Vec::new();
    let mut recommendations = Vec::new();

    add_doctor_heartbeat_check(&service, &mut checks, &mut recommendations);

    assert!(checks.iter().any(|check| {
        check.name == "runtime_heartbeat" && check.error_code == Some("runtime_heartbeat_stale")
    }));
    assert!(!recommendations.is_empty());
}

#[test]
fn status_report_exposes_cleanup_issues_and_actions() {
    let service = ServiceStatus {
        status: ServiceStatusKind::Stopped,
        running: false,
        stale: false,
        pid: None,
        memory_rss_bytes: None,
        config: None,
        log: None,
        listen: None,
        started_at_unix: None,
        state_dir: PathBuf::from("/tmp/tabbymew-state"),
        state_file: PathBuf::from("/tmp/tabbymew-state/tabbymew-state.json"),
        runtime_state_file: PathBuf::from("/tmp/tabbymew-state/tabbymew-runtime.json"),
        preferences_file: PathBuf::from("/tmp/tabbymew-state/tabbymew-preferences.json"),
        active_state_file: None,
        state_source: None,
        state_file_exists: false,
        runtime_state_file_exists: false,
        heartbeat_at_unix: None,
        heartbeat_age_seconds: None,
        heartbeat_stale: false,
        managed_system_proxy_recorded: true,
        cleanup_items: vec!["managed_system_proxy".to_string()],
        state_error: None,
        preference_error: None,
    };

    let report = StatusReport::new(service, None);

    assert_eq!(report.schema_version, CLI_JSON_SCHEMA_VERSION);
    assert!(!report.ok);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "managed_system_proxy")
    );
    assert!(
        report
            .next_actions
            .iter()
            .any(|action| action.code == "cleanup"
                && action.commands
                    == vec![vec![
                        "TabbyMew",
                        "cleanup",
                        "--json",
                        "--state-dir",
                        "/tmp/tabbymew-state"
                    ]])
    );
}
