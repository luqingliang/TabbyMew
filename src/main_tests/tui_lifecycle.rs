use super::*;

#[test]
fn tui_stop_confirmation_requires_second_ctrl_c_trigger() {
    let mut app = test_tui_app();

    confirm_or_request_tui_stop(&mut app);

    assert_eq!(app.exit_action, None);
    assert_eq!(
        app.exit_confirmation
            .map(|confirmation| confirmation.action),
        Some(TuiExitAction::StopService)
    );
    assert!(app.last_message.contains("confirm stop"));

    confirm_or_request_tui_stop(&mut app);

    assert_eq!(app.exit_action, Some(TuiExitAction::StopService));
}

#[test]
fn tui_stop_confirmation_can_cancel_and_expire() {
    let mut app = test_tui_app();
    confirm_or_request_tui_stop(&mut app);

    assert!(cancel_tui_exit_confirmation(&mut app));
    assert_eq!(app.exit_action, None);
    assert!(app.exit_confirmation.is_none());
    assert_eq!(app.last_message, "stop service cancelled");

    confirm_or_request_tui_stop(&mut app);
    app.exit_confirmation = Some(TuiExitConfirmation {
        action: TuiExitAction::StopService,
        started: Instant::now()
            .checked_sub(TUI_EXIT_CONFIRMATION_TIMEOUT + Duration::from_secs(1))
            .expect("valid expired instant"),
    });

    assert!(expire_tui_exit_confirmation(&mut app));
    assert_eq!(app.exit_action, None);
    assert!(app.exit_confirmation.is_none());
    assert_eq!(app.last_message, "stop service confirmation expired");

    confirm_or_request_tui_stop(&mut app);

    assert_eq!(app.exit_action, None);
}

#[test]
fn tui_detach_confirmation_requires_second_q_trigger() {
    let mut app = test_tui_app();

    confirm_or_request_tui_detach(&mut app);

    assert_eq!(app.exit_action, None);
    assert_eq!(
        app.exit_confirmation
            .map(|confirmation| confirmation.action),
        Some(TuiExitAction::Detach)
    );
    assert!(app.last_message.contains("confirm detach"));

    confirm_or_request_tui_detach(&mut app);

    assert_eq!(app.exit_action, Some(TuiExitAction::Detach));
    assert!(app.exit_confirmation.is_none());
    assert_eq!(app.last_message, "detaching TUI; service keeps running");
    assert!(!should_shutdown_service_after_tui(
        app.exit_action,
        false,
        true
    ));
    assert!(should_shutdown_service_after_tui(
        app.exit_action,
        true,
        true
    ));
    assert!(!should_shutdown_service_after_tui(
        app.exit_action,
        true,
        false
    ));
    assert!(should_shutdown_service_after_tui(
        Some(TuiExitAction::StopService),
        false,
        false
    ));
    assert!(!should_shutdown_service_after_tui(None, false, true));
    assert!(should_shutdown_service_after_tui(None, true, true));
}

#[tokio::test]
async fn tui_q_key_requires_confirmation_before_detach() -> Result<()> {
    let mut app = test_tui_app();
    let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);

    handle_tui_key(&mut app, key).await?;

    assert_eq!(app.exit_action, None);
    assert_eq!(
        app.exit_confirmation
            .map(|confirmation| confirmation.action),
        Some(TuiExitAction::Detach)
    );
    assert!(app.last_message.contains("confirm detach"));

    handle_tui_key(&mut app, key).await?;

    assert_eq!(app.exit_action, Some(TuiExitAction::Detach));
    assert!(app.exit_confirmation.is_none());
    Ok(())
}

#[tokio::test]
async fn tui_startup_message_reports_running_service_without_control_api() {
    let app = test_tui_app();
    let mut status = app.status.service.clone();
    status.status = ServiceStatusKind::Running;
    status.running = true;
    status.pid = Some(42);
    status.listen = None;

    let message = tui_running_service_startup_message(&status, Duration::from_millis(1)).await;

    assert!(message.contains("pid 42 is running"));
    assert!(message.contains("no control API listen address"));
    assert!(message.contains("/restart"));
    assert!(message.contains("TabbyMew doctor"));
    assert!(message.contains("Press q to detach"));
}

#[tokio::test]
async fn tui_startup_adopts_running_runtime_state() -> Result<()> {
    let dir = env::temp_dir().join(format!(
        "tabbymew-tui-adopt-runtime-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&dir)?;
    let config: Config = serde_json::from_str(&Config::default_local_json()?)?;
    let control_state = control::ControlState::new(
        config.summary(),
        std::sync::Arc::new(control::RuntimeMetrics::new()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let listen = listener.local_addr()?;
    let task = tokio::spawn(control::serve_listener(listener, control_state));
    let runtime_state_file = process_manager::runtime_state_file(&dir);
    let runtime_state = ProcessState {
        pid: std::process::id(),
        config: dir.join("config.json"),
        log: dir.join("tabbymew.log"),
        listen: Some(listen.to_string()),
        control_token: Some("runtime-token".to_string()),
        started_at_unix: 42,
        heartbeat_at_unix: Some(42),
    };
    process_manager::save_state_file(&runtime_state_file, &runtime_state)?;
    let session = ShellSession {
        config: None,
        state_dir: dir.clone(),
        timeout: Duration::from_secs(1),
    };

    let startup = ensure_tui_service_running(&session).await?;

    assert_eq!(startup.kind, TuiServiceStartupKind::AdoptedRuntime);
    assert!(
        startup
            .message
            .contains("Adopted independent TabbyMew service")
    );
    let managed_state = process_manager::load_state(process_manager::paths(&dir, None).state_file)?;
    assert_eq!(managed_state.pid, std::process::id());
    assert_eq!(
        managed_state.control_token.as_deref(),
        Some("runtime-token")
    );

    task.abort();
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn tui_dashboard_state_line_shows_version_instead_of_refresh_age() {
    let app = test_tui_app();
    let line = tui_dashboard_state_line(&app);

    assert!(line.contains("version: "));
    assert!(line.contains(env!("CARGO_PKG_VERSION")));
    assert!(!line.contains("refreshed:"));
}

#[test]
fn tui_direct_detach_key_is_disabled_in_command_palette() {
    let mut app = test_tui_app();
    let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);

    assert!(is_direct_tui_detach_key(&app, key));

    app.mode = TuiMode::CommandPalette;
    app.command_query = "q".to_string();
    app.selected_command = 1;

    assert!(!is_direct_tui_detach_key(&app, key));

    app.mode = TuiMode::RouteRules;
    assert!(!is_direct_tui_detach_key(&app, key));
    assert!(is_tui_text_key(key));

    app.mode = TuiMode::CommandPalette;
    confirm_or_request_tui_stop(&mut app);

    assert_eq!(app.mode, TuiMode::Dashboard);
    assert!(app.command_query.is_empty());
    assert_eq!(app.selected_command, 0);
}

#[test]
fn tui_policy_group_delay_key_uses_ctrl_t() {
    assert!(is_tui_policy_group_delay_key(KeyEvent::new(
        KeyCode::Char('t'),
        KeyModifiers::CONTROL,
    )));
    assert!(is_tui_policy_group_delay_key(KeyEvent::new(
        KeyCode::Char('T'),
        KeyModifiers::CONTROL | KeyModifiers::SHIFT,
    )));
    assert!(!is_tui_policy_group_delay_key(KeyEvent::new(
        KeyCode::Char('t'),
        KeyModifiers::NONE,
    )));
    assert!(!is_tui_policy_group_delay_key(KeyEvent::new(
        KeyCode::F(5),
        KeyModifiers::NONE,
    )));
}
