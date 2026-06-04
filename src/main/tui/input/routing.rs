use super::*;

pub(crate) async fn handle_tui_route_mode_selector_key(
    app: &mut TuiApp,
    key: KeyEvent,
) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            app.mode = TuiMode::Dashboard;
            app.last_message = "route mode selection cancelled".to_string();
        }
        KeyCode::Up => {
            app.route_mode_selection = app.route_mode_selection.saturating_sub(1);
        }
        KeyCode::Down => {
            app.route_mode_selection =
                (app.route_mode_selection + 1).min(route_mode_options().len() - 1);
        }
        KeyCode::Char('1') => app.route_mode_selection = 0,
        KeyCode::Char('2') => app.route_mode_selection = 1,
        KeyCode::Char('3') => app.route_mode_selection = 2,
        KeyCode::Enter => {
            let mode = route_mode_options()[app.route_mode_selection].mode;
            match tui_set_route_mode(app, mode).await {
                Ok(text) => {
                    app.output_title = "Route Mode".to_string();
                    app.output = text;
                    app.output_scroll = 0;
                    app.last_message = format!("route mode set to {}", mode.as_str());
                    app.mode = TuiMode::Output;
                }
                Err(err) => {
                    open_tui_error(app, "Route Mode", err);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) async fn handle_tui_global_target_selector_key(
    app: &mut TuiApp,
    key: KeyEvent,
) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            app.mode = TuiMode::Dashboard;
            app.last_message = "global target selection cancelled".to_string();
        }
        KeyCode::Backspace => {
            app.global_target_query.pop();
            app.clamp_global_target_selection();
        }
        KeyCode::Up => {
            app.selected_global_target = app.selected_global_target.saturating_sub(1);
        }
        KeyCode::Down => {
            let len = app.filtered_global_targets().len();
            if len > 0 {
                app.selected_global_target = (app.selected_global_target + 1).min(len - 1);
            }
        }
        KeyCode::Enter => {
            let targets = app.filtered_global_targets();
            if let Some(target) = targets.get(app.selected_global_target) {
                let target = target.clone();
                match tui_set_global_target(app, &target).await {
                    Ok(text) => {
                        app.output_title = "Global Target".to_string();
                        app.output = text;
                        app.output_scroll = 0;
                        app.last_message = format!("global target set to {target}");
                        app.mode = TuiMode::Output;
                    }
                    Err(err) => {
                        open_tui_error(app, "Global Target", err);
                    }
                }
            }
        }
        KeyCode::Char('/') if app.global_target_query.is_empty() => {}
        KeyCode::Char(value) => {
            app.global_target_query.push(value);
            app.clamp_global_target_selection();
        }
        _ => {}
    }
    Ok(())
}
