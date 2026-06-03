use super::*;

pub(super) fn enter_tui() -> Result<TuiTerminal> {
    enable_raw_mode().context("failed to enable terminal raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    Terminal::new(CrosstermBackend::new(stdout)).context("failed to create terminal")
}

pub(super) fn exit_tui(terminal: &mut TuiTerminal) -> Result<()> {
    disable_raw_mode().context("failed to disable terminal raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal
        .show_cursor()
        .context("failed to show terminal cursor")
}

pub(super) fn finish_tui_session(
    tui_result: Result<()>,
    terminal_result: Result<()>,
    shutdown_result: Option<Result<String>>,
) -> Result<()> {
    let shutdown_result = shutdown_result.unwrap_or_else(|| Ok(String::new()));
    match (tui_result, terminal_result, shutdown_result) {
        (Ok(()), Ok(()), Ok(_)) => Ok(()),
        (Err(err), Ok(()), Ok(_)) => Err(err),
        (Ok(()), Err(err), Ok(_)) => Err(err),
        (Ok(()), Ok(()), Err(err)) => Err(err).context("failed to stop TabbyMew service on exit"),
        (Err(err), Err(terminal_err), Ok(_)) => Err(err).context(format!(
            "failed to restore terminal after TUI error: {terminal_err:#}"
        )),
        (Err(err), Ok(()), Err(shutdown_err)) => Err(err).context(format!(
            "failed to stop TabbyMew service after TUI error: {shutdown_err:#}"
        )),
        (Ok(()), Err(terminal_err), Err(shutdown_err)) => Err(terminal_err).context(format!(
            "failed to stop TabbyMew service after terminal restore error: {shutdown_err:#}"
        )),
        (Err(err), Err(terminal_err), Err(shutdown_err)) => Err(err).context(format!(
            "terminal restore failed: {terminal_err:#}; service stop failed: {shutdown_err:#}"
        )),
    }
}

pub(super) fn should_shutdown_service_after_tui(
    exit_action: Option<TuiExitAction>,
    tui_failed: bool,
    service_started_by_tui: bool,
) -> bool {
    exit_action == Some(TuiExitAction::StopService) || (tui_failed && service_started_by_tui)
}

pub(super) async fn run_tui_loop(terminal: &mut TuiTerminal, app: &mut TuiApp) -> Result<()> {
    let mut dirty = true;
    loop {
        if drain_tui_policy_group_delay_updates(app) {
            dirty = true;
        }
        if dirty {
            terminal
                .draw(|frame| draw_tui(frame, app))
                .context("failed to draw terminal UI")?;
            dirty = false;
        }
        if app.exit_action.is_some() {
            break;
        }
        if expire_tui_exit_confirmation(app) {
            dirty = true;
            continue;
        }
        if app.mode == TuiMode::Dashboard && app.last_refresh.elapsed() >= Duration::from_secs(2) {
            if let Err(err) = app.refresh_status().await {
                app.last_message = format!("refresh failed: {err:#}");
            }
            dirty = true;
            continue;
        }
        if !event::poll(tui_poll_timeout(app)).context("failed to poll terminal events")? {
            continue;
        }
        match event::read().context("failed to read terminal event")? {
            Event::Key(key) => {
                handle_tui_key(app, key).await?;
                dirty = true;
            }
            Event::Resize(_, _) => dirty = true,
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn tui_poll_timeout(app: &TuiApp) -> Duration {
    const MAX_POLL: Duration = Duration::from_millis(250);
    const REFRESH_INTERVAL: Duration = Duration::from_secs(2);

    if app.mode == TuiMode::Dashboard {
        REFRESH_INTERVAL
            .saturating_sub(app.last_refresh.elapsed())
            .min(MAX_POLL)
    } else {
        MAX_POLL
    }
}

pub(super) async fn handle_tui_key(app: &mut TuiApp, key: KeyEvent) -> Result<()> {
    if key.kind == KeyEventKind::Release {
        return Ok(());
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
        confirm_or_request_tui_stop(app);
        return Ok(());
    }
    if is_direct_tui_detach_key(app, key) {
        confirm_or_request_tui_detach(app);
        return Ok(());
    }
    if matches!(key.code, KeyCode::Esc) && cancel_tui_exit_confirmation(app) {
        return Ok(());
    }
    cancel_tui_exit_confirmation(app);

    match app.mode {
        TuiMode::Dashboard | TuiMode::Output => handle_tui_normal_key(app, key).await,
        TuiMode::CommandPalette => handle_tui_palette_key(app, key).await,
        TuiMode::RouteModeSelector => handle_tui_route_mode_selector_key(app, key).await,
        TuiMode::GlobalTargetSelector => handle_tui_global_target_selector_key(app, key).await,
        TuiMode::PolicyGroupListSelector => handle_tui_policy_group_list_selector_key(app, key).await,
        TuiMode::PolicyGroupSelector => handle_tui_policy_group_selector_key(app, key).await,
        TuiMode::RouteRules => handle_tui_route_rules_key(app, key).await,
        TuiMode::RouteRuleActions => handle_tui_route_rule_actions_key(app, key).await,
        TuiMode::RouteRuleAdd => handle_tui_route_rule_add_key(app, key).await,
        TuiMode::RouteRuleTargetSelector => {
            handle_tui_route_rule_target_selector_key(app, key).await
        }
        TuiMode::Subscriptions => handle_tui_subscriptions_key(app, key).await,
        TuiMode::SubscriptionActions => handle_tui_subscription_actions_key(app, key).await,
        TuiMode::SubscriptionAdd => handle_tui_subscription_add_key(app, key).await,
    }
}

pub(super) fn is_direct_tui_detach_key(app: &TuiApp, key: KeyEvent) -> bool {
    matches!(app.mode, TuiMode::Dashboard | TuiMode::Output)
        && key.modifiers.is_empty()
        && matches!(key.code, KeyCode::Char('q'))
}

pub(super) fn is_tui_text_key(key: KeyEvent) -> bool {
    key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT
}

pub(super) fn is_tui_policy_group_delay_key(key: KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('t') | KeyCode::Char('T'))
}

pub(super) fn confirm_or_request_tui_detach(app: &mut TuiApp) {
    confirm_or_request_tui_exit_action(app, TuiExitAction::Detach);
}

pub(super) fn confirm_or_request_tui_stop(app: &mut TuiApp) {
    confirm_or_request_tui_exit_action(app, TuiExitAction::StopService);
}

pub(super) fn confirm_or_request_tui_exit_action(app: &mut TuiApp, action: TuiExitAction) {
    if tui_exit_confirmation_active_for(app, action) {
        app.exit_action = Some(action);
        app.exit_confirmation = None;
        app.last_message = match action {
            TuiExitAction::Detach => "detaching TUI; service keeps running".to_string(),
            TuiExitAction::StopService => "quitting and stopping service".to_string(),
        };
        return;
    }

    app.exit_confirmation = Some(TuiExitConfirmation {
        action,
        started: Instant::now(),
    });
    if app.mode == TuiMode::CommandPalette {
        app.mode = TuiMode::Dashboard;
        app.command_query.clear();
        app.selected_command = 0;
    }
    app.last_message = tui_exit_confirmation_message(action);
}

pub(super) fn tui_exit_confirmation_message(action: TuiExitAction) -> String {
    match action {
        TuiExitAction::Detach => format!(
            "confirm detach: press q again within {}s to close TUI and keep service running; Esc cancels",
            TUI_EXIT_CONFIRMATION_TIMEOUT.as_secs()
        ),
        TuiExitAction::StopService => format!(
            "confirm stop: press Ctrl+C again within {}s to stop service; Esc cancels",
            TUI_EXIT_CONFIRMATION_TIMEOUT.as_secs()
        ),
    }
}

pub(super) fn cancel_tui_exit_confirmation(app: &mut TuiApp) -> bool {
    if let Some(confirmation) = app.exit_confirmation.take() {
        app.last_message = format!("{} cancelled", confirmation.action.label());
        true
    } else {
        false
    }
}

pub(super) fn expire_tui_exit_confirmation(app: &mut TuiApp) -> bool {
    let Some(confirmation) = app.exit_confirmation else {
        return false;
    };
    if confirmation.started.elapsed() <= TUI_EXIT_CONFIRMATION_TIMEOUT {
        return false;
    }

    app.exit_confirmation = None;
    app.last_message = format!("{} confirmation expired", confirmation.action.label());
    true
}

pub(super) fn tui_exit_confirmation_active_for(app: &TuiApp, action: TuiExitAction) -> bool {
    app.exit_confirmation.is_some_and(|confirmation| {
        confirmation.action == action
            && confirmation.started.elapsed() <= TUI_EXIT_CONFIRMATION_TIMEOUT
    })
}
