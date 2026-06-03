use super::*;

pub(super) async fn handle_tui_policy_group_list_selector_key(app: &mut TuiApp, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            cancel_tui_policy_group_delay(app);
            app.mode = TuiMode::Dashboard;
            app.last_message = "policy group selection cancelled".to_string();
        }
        KeyCode::Backspace => {
            app.policy_group_query.pop();
            app.clamp_policy_group_selection();
        }
        KeyCode::Up => {
            app.selected_policy_group = app.selected_policy_group.saturating_sub(1);
        }
        KeyCode::Down => {
            let len = app.filtered_policy_groups().len();
            if len > 0 {
                app.selected_policy_group = (app.selected_policy_group + 1).min(len - 1);
            }
        }
        KeyCode::Enter => {
            if let Err(err) = open_selected_tui_policy_group(app) {
                open_tui_error(app, "Policy Groups", err);
            }
        }
        KeyCode::Char('/') if app.policy_group_query.is_empty() => {}
        KeyCode::Char(value) => {
            app.policy_group_query.push(value);
            app.clamp_policy_group_selection();
        }
        _ => {}
    }
    Ok(())
}

pub(super) async fn handle_tui_policy_group_selector_key(app: &mut TuiApp, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            cancel_tui_policy_group_delay(app);
            app.mode = TuiMode::Dashboard;
            app.last_message = "policy group selection cancelled".to_string();
        }
        KeyCode::Backspace => {
            app.policy_group_outbound_query.pop();
            app.clamp_policy_group_outbound_selection();
        }
        KeyCode::Up => {
            app.selected_policy_group_outbound = app.selected_policy_group_outbound.saturating_sub(1);
        }
        KeyCode::Down => {
            let len = app.filtered_policy_group_outbounds().len();
            if len > 0 {
                app.selected_policy_group_outbound =
                    (app.selected_policy_group_outbound + 1).min(len - 1);
            }
        }
        _ if is_tui_policy_group_delay_key(key) => {
            let Some(group) = app.selected_policy_group_tag.clone() else {
                return Ok(());
            };
            match tui_start_policy_group_delay(app, &group).await {
                Ok(total) => {
                    app.mode = TuiMode::PolicyGroupSelector;
                    app.clamp_policy_group_outbound_selection();
                    app.last_message = format!("testing delays for policy group {group}: 0/{total}");
                }
                Err(err) => {
                    open_tui_error(app, "Policy Group Delay", err);
                }
            }
        }
        KeyCode::Enter => {
            let Some(group) = app.selected_policy_group_tag.clone() else {
                return Ok(());
            };
            let outbounds = app.filtered_policy_group_outbounds();
            if let Some(outbound) = outbounds.get(app.selected_policy_group_outbound) {
                let outbound = outbound.clone();
                match tui_select_policy_group_outbound(app, &group, &outbound).await {
                    Ok(_) => {
                        cancel_tui_policy_group_delay(app);
                        match return_to_tui_policy_group_list(app, &group) {
                            Ok(()) => {
                                app.last_message = format!("{group} selected {outbound}");
                            }
                            Err(err) => {
                                open_tui_error(app, "Policy Groups", err);
                            }
                        }
                    }
                    Err(err) => {
                        cancel_tui_policy_group_delay(app);
                        open_tui_error(app, "Policy Group", err);
                    }
                }
            }
        }
        KeyCode::Char('/') if app.policy_group_outbound_query.is_empty() => {}
        KeyCode::Char(value) => {
            app.policy_group_outbound_query.push(value);
            app.clamp_policy_group_outbound_selection();
        }
        _ => {}
    }
    Ok(())
}
