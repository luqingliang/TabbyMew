use super::*;

#[test]
fn status_report_treats_clean_stopped_service_as_ok() -> Result<()> {
    let dir = env::temp_dir().join(format!(
        "tabbymew-status-report-test-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;

    let report = StatusReport::new(process_manager::service_status(&dir), None);

    assert!(report.ok);
    assert_eq!(report.service.status, ServiceStatusKind::Stopped);

    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn cleanup_removes_stale_runtime_state_file() -> Result<()> {
    let dir = env::temp_dir().join(format!(
        "tabbymew-runtime-cleanup-test-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    let runtime_state = process_manager::runtime_state_file(&dir);
    process_manager::save_state_file(
        &runtime_state,
        &ProcessState {
            pid: 0,
            config: dir.join("config.json"),
            log: dir.join("logs").join("tabbymew.log"),
            listen: Some("127.0.0.1:9090".to_string()),
            control_token: None,
            started_at_unix: 42,
            heartbeat_at_unix: Some(42),
        },
    )?;

    let report = cleanup_service_state(&dir)?;

    assert!(report.ok);
    assert!(!runtime_state.exists());
    assert!(
        report
            .actions
            .iter()
            .any(|action| { action.name == "runtime_state_file" && action.ok })
    );

    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn cleanup_candidate_uses_active_config_when_proxy_record_is_missing() -> Result<()> {
    let dir = env::temp_dir().join(format!(
        "tabbymew-cleanup-active-config-candidate-test-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    let config_path = dir.join("active.json");
    fs::write(&config_path, Config::default_local_json()?)?;
    process_manager::save_preferences(
        process_manager::preferences_path(&dir),
        &process_manager::RuntimePreferences {
            active_config: Some(config_path),
            ..process_manager::RuntimePreferences::default()
        },
    )?;

    let service = process_manager::service_status(&dir);
    let candidate = system_proxy_cleanup_candidate(&dir, &service).context("expected candidate")?;

    assert!(!candidate.target_recorded);
    assert_eq!(candidate.source, "preferences.active_config");
    assert!(
        candidate
            .target
            .source
            .contains("hybrid:hybrid-in@127.0.0.1:17890")
    );

    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn cleanup_disables_unrecorded_system_proxy_from_active_config() -> Result<()> {
    let dir = env::temp_dir().join(format!(
        "tabbymew-cleanup-unrecorded-system-proxy-test-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    let config_path = dir.join("active.json");
    fs::write(&config_path, Config::default_local_json()?)?;
    process_manager::save_preferences(
        process_manager::preferences_path(&dir),
        &process_manager::RuntimePreferences {
            active_config: Some(config_path),
            ..process_manager::RuntimePreferences::default()
        },
    )?;
    let disabled = std::cell::Cell::new(false);
    let status = |target: Option<&system_proxy::SystemProxyTarget>| {
        fake_system_proxy_status(target, !disabled.get())
    };
    let disable = |target: Option<&system_proxy::SystemProxyTarget>| {
        disabled.set(true);
        Ok(fake_system_proxy_status(target, false))
    };

    let report = cleanup_service_state_with_system_proxy(&dir, &status, &disable)?;

    assert!(report.ok);
    assert!(disabled.get());
    assert!(
        report
            .actions
            .iter()
            .any(|action| action.name == "system_proxy_unrecorded" && action.ok)
    );
    assert!(
        report
            .before_summary
            .system_proxy
            .as_ref()
            .is_some_and(|summary| summary.status.matches_target)
    );
    assert!(
        report
            .after_summary
            .system_proxy
            .as_ref()
            .is_some_and(|summary| !summary.status.matches_target)
    );

    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn cleanup_clears_stale_system_proxy_record_without_disabling_other_targets() -> Result<()> {
    let dir = env::temp_dir().join(format!(
        "tabbymew-cleanup-stale-system-proxy-record-test-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    let target = fake_system_proxy_target();
    process_manager::save_preferences(
        process_manager::preferences_path(&dir),
        &process_manager::RuntimePreferences {
            system_proxy_target: Some(target),
            ..process_manager::RuntimePreferences::default()
        },
    )?;
    let disable_called = std::cell::Cell::new(false);
    let status =
        |target: Option<&system_proxy::SystemProxyTarget>| fake_system_proxy_status(target, false);
    let disable = |target: Option<&system_proxy::SystemProxyTarget>| {
        disable_called.set(true);
        Ok(fake_system_proxy_status(target, false))
    };

    let report = cleanup_service_state_with_system_proxy(&dir, &status, &disable)?;
    let preferences = process_manager::load_preferences(process_manager::preferences_path(&dir))?;

    assert!(report.ok);
    assert!(!disable_called.get());
    assert_eq!(preferences.system_proxy_target, None);
    assert!(
        report
            .actions
            .iter()
            .any(|action| action.name == "system_proxy" && action.ok)
    );

    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn lifecycle_log_path_must_be_owned_by_state_dir() {
    let state_dir = Path::new("/tmp/tabbymew-state");
    let owned = Path::new("/tmp/tabbymew-state/logs/tabbymew.log");
    let outside = Path::new("/tmp/other.log");

    assert_eq!(owned_lifecycle_log_path(state_dir, owned), Some(owned));
    assert_eq!(owned_lifecycle_log_path(state_dir, outside), None);
}

fn fake_system_proxy_status(
    target: Option<&system_proxy::SystemProxyTarget>,
    matches_target: bool,
) -> system_proxy::SystemProxyStatus {
    system_proxy::SystemProxyStatus {
        platform: "test",
        supported: true,
        enabled: matches_target,
        managed: matches_target,
        matches_target,
        target_recorded: false,
        protocol: system_proxy::SystemProxyProtocol::Auto,
        target: target.cloned(),
        error: None,
    }
}

fn fake_system_proxy_target() -> system_proxy::SystemProxyTarget {
    let endpoint = system_proxy::SystemProxyEndpoint {
        host: "127.0.0.1".to_string(),
        port: 17890,
        address: "127.0.0.1:17890".to_string(),
    };
    system_proxy::SystemProxyTarget {
        source: "hybrid:hybrid-in@127.0.0.1:17890 auth=off".to_string(),
        http: Some(endpoint.clone()),
        https: Some(endpoint.clone()),
        socks: Some(endpoint),
    }
}
