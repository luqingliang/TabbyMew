use super::*;

pub(crate) async fn handle_tui_route_rules_key(app: &mut TuiApp, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            app.mode = TuiMode::Dashboard;
            app.last_message = "route rules closed".to_string();
        }
        KeyCode::Backspace => {
            app.route_rule_query.pop();
            app.clamp_route_rule_selection();
        }
        KeyCode::Up => {
            app.selected_route_rule = app.selected_route_rule.saturating_sub(1);
        }
        KeyCode::Down => {
            let len = app.filtered_route_rules().len();
            if len > 0 {
                app.selected_route_rule = (app.selected_route_rule + 1).min(len - 1);
            }
        }
        KeyCode::PageUp => {
            app.selected_route_rule = app.selected_route_rule.saturating_sub(10);
        }
        KeyCode::PageDown => {
            let len = app.filtered_route_rules().len();
            if len > 0 {
                app.selected_route_rule = (app.selected_route_rule + 10).min(len - 1);
            }
        }
        KeyCode::Home => {
            app.selected_route_rule = 0;
        }
        KeyCode::End => {
            let len = app.filtered_route_rules().len();
            if len > 0 {
                app.selected_route_rule = len - 1;
            }
        }
        KeyCode::Char('+') if is_tui_text_key(key) => {
            open_tui_route_rule_add(app);
        }
        KeyCode::Enter => {
            if let Err(err) = open_tui_route_rule_actions(app) {
                app.last_message = format!("route rule action unavailable: {err:#}");
            }
        }
        KeyCode::F(5) => match tui_reload_route_rules(app).await {
            Ok(_) => {
                app.clamp_route_rule_selection();
                app.mode = TuiMode::RouteRules;
                app.last_message = "route rules reloaded".to_string();
            }
            Err(err) => {
                open_tui_error(app, "Route Rules", err);
            }
        },
        KeyCode::Char('/') if app.route_rule_query.is_empty() && is_tui_text_key(key) => {}
        KeyCode::Char(value) if is_tui_text_key(key) => {
            app.route_rule_query.push(value);
            app.clamp_route_rule_selection();
        }
        _ => {}
    }
    Ok(())
}

pub(crate) async fn handle_tui_route_rule_actions_key(
    app: &mut TuiApp,
    key: KeyEvent,
) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            app.mode = TuiMode::RouteRules;
            app.last_message = "custom route rule action cancelled".to_string();
        }
        KeyCode::Up | KeyCode::Left => {
            app.selected_route_rule_action = app.selected_route_rule_action.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Right => {
            let len = tui_route_rule_actions().len();
            if len > 0 {
                app.selected_route_rule_action = (app.selected_route_rule_action + 1).min(len - 1);
            }
        }
        KeyCode::Enter => match selected_tui_route_rule_action(app) {
            Some(TuiRouteRuleAction::Edit) => match open_tui_route_rule_edit(app) {
                Ok(()) => {}
                Err(err) => {
                    open_tui_error(app, "Route Rule Edit", err);
                }
            },
            Some(TuiRouteRuleAction::Delete) => match remove_selected_tui_route_rule(app).await {
                Ok(()) => {
                    app.clamp_route_rule_selection();
                    app.mode = TuiMode::RouteRules;
                    app.last_message = "custom route rule removed".to_string();
                }
                Err(err) => {
                    open_tui_error(app, "Route Rule Delete", err);
                }
            },
            None => {}
        },
        _ => {}
    }
    Ok(())
}

pub(crate) async fn handle_tui_route_rule_add_key(app: &mut TuiApp, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            reset_tui_route_rule_add_form(app);
            app.mode = TuiMode::RouteRules;
            app.last_message = "custom route rule add cancelled".to_string();
        }
        KeyCode::Tab => {
            app.route_rule_add_field = (app.route_rule_add_field + 1) % TUI_ROUTE_RULE_ADD_FIELDS;
        }
        KeyCode::BackTab => {
            app.route_rule_add_field = (app.route_rule_add_field + TUI_ROUTE_RULE_ADD_FIELDS - 1)
                % TUI_ROUTE_RULE_ADD_FIELDS;
        }
        KeyCode::Backspace => {
            if app.route_rule_add_field == TUI_ROUTE_RULE_ADD_CONTENT_FIELD {
                app.route_rule_add_content.pop();
            }
        }
        KeyCode::Left | KeyCode::Up => {
            change_tui_route_rule_add_selection(app, -1);
        }
        KeyCode::Right | KeyCode::Down => {
            change_tui_route_rule_add_selection(app, 1);
        }
        KeyCode::Enter => {
            if app.route_rule_add_field == TUI_ROUTE_RULE_ADD_TARGET_FIELD {
                if let Err(err) = open_tui_route_rule_target_selector(app) {
                    open_tui_error(app, "Route Target", err);
                }
            } else {
                match tui_add_route_rule_from_form(app).await {
                    Ok(_) => {
                        reset_tui_route_rule_add_form(app);
                        app.route_rule_query = "custom".to_string();
                        app.selected_route_rule = 0;
                        app.clamp_route_rule_selection();
                        app.mode = TuiMode::RouteRules;
                        app.last_message = "custom route rule saved".to_string();
                    }
                    Err(err) => {
                        open_tui_error(app, "Route Rules", err);
                    }
                }
            }
        }
        KeyCode::Char(value)
            if is_tui_text_key(key)
                && app.route_rule_add_field == TUI_ROUTE_RULE_ADD_CONTENT_FIELD =>
        {
            app.route_rule_add_content.push(value);
        }
        _ => {}
    }
    Ok(())
}

pub(crate) async fn handle_tui_route_rule_target_selector_key(
    app: &mut TuiApp,
    key: KeyEvent,
) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            app.mode = TuiMode::RouteRuleAdd;
            app.route_rule_add_field = TUI_ROUTE_RULE_ADD_TARGET_FIELD;
            app.last_message = "route target selection cancelled".to_string();
        }
        KeyCode::Backspace => {
            app.route_rule_target_query.pop();
            app.clamp_route_rule_target_selection();
        }
        KeyCode::Up => {
            app.selected_route_rule_target_candidate =
                app.selected_route_rule_target_candidate.saturating_sub(1);
        }
        KeyCode::Down => {
            let len = app.filtered_route_rule_targets().len();
            if len > 0 {
                app.selected_route_rule_target_candidate =
                    (app.selected_route_rule_target_candidate + 1).min(len - 1);
            }
        }
        KeyCode::Enter => {
            let targets = app.filtered_route_rule_targets();
            if let Some(target) = targets.get(app.selected_route_rule_target_candidate) {
                let target = target.clone();
                let all_targets = tui_route_rule_targets(app.control_snapshot.as_ref());
                app.selected_route_rule_target = all_targets
                    .iter()
                    .position(|candidate| candidate == &target)
                    .unwrap_or_default();
                app.route_rule_target_query.clear();
                app.selected_route_rule_target_candidate = app.selected_route_rule_target;
                app.route_rule_add_field = TUI_ROUTE_RULE_ADD_CONTENT_FIELD;
                app.mode = TuiMode::RouteRuleAdd;
                app.last_message = format!("route target set to {target}; press Enter to save");
            }
        }
        KeyCode::Char('/') if app.route_rule_target_query.is_empty() => {}
        KeyCode::Char(value) if is_tui_text_key(key) => {
            app.route_rule_target_query.push(value);
            app.clamp_route_rule_target_selection();
        }
        _ => {}
    }
    Ok(())
}
