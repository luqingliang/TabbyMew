use super::*;

pub(super) async fn handle_tui_subscriptions_key(app: &mut TuiApp, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            app.mode = TuiMode::Dashboard;
            app.last_message = "subscriptions closed".to_string();
        }
        KeyCode::Backspace => {
            app.subscription_query.pop();
            app.clamp_subscription_selection();
        }
        KeyCode::Up => {
            app.selected_subscription = app.selected_subscription.saturating_sub(1);
        }
        KeyCode::Down => {
            let len = app.filtered_subscriptions().len();
            if len > 0 {
                app.selected_subscription = (app.selected_subscription + 1).min(len - 1);
            }
        }
        KeyCode::PageUp => {
            app.selected_subscription = app.selected_subscription.saturating_sub(10);
        }
        KeyCode::PageDown => {
            let len = app.filtered_subscriptions().len();
            if len > 0 {
                app.selected_subscription = (app.selected_subscription + 10).min(len - 1);
            }
        }
        KeyCode::Home => {
            app.selected_subscription = 0;
        }
        KeyCode::End => {
            let len = app.filtered_subscriptions().len();
            if len > 0 {
                app.selected_subscription = len - 1;
            }
        }
        KeyCode::Char('+') if is_tui_text_key(key) => {
            open_tui_subscription_add(app);
        }
        KeyCode::Char('u') if is_tui_text_key(key) => {
            match tui_refresh_all_subscriptions(app).await {
                Ok(output) => {
                    app.output_title = "Subscriptions Update".to_string();
                    app.output = output;
                    app.output_scroll = 0;
                    app.mode = TuiMode::Output;
                    app.last_message = "subscriptions updated".to_string();
                }
                Err(err) => {
                    open_tui_error(app, "Subscriptions Update", err);
                }
            }
        }
        KeyCode::Enter => {
            if let Err(err) = open_tui_subscription_actions(app) {
                app.last_message = format!("subscription action unavailable: {err:#}");
            }
        }
        KeyCode::F(5) => match app.refresh_status().await {
            Ok(()) => {
                app.clamp_subscription_selection();
                app.mode = TuiMode::Subscriptions;
                app.last_message = "subscriptions refreshed".to_string();
            }
            Err(err) => {
                open_tui_error(app, "Subscriptions", err);
            }
        },
        KeyCode::Char('/') if app.subscription_query.is_empty() && is_tui_text_key(key) => {}
        KeyCode::Char(value) if is_tui_text_key(key) => {
            app.subscription_query.push(value);
            app.clamp_subscription_selection();
        }
        _ => {}
    }
    Ok(())
}

pub(super) async fn handle_tui_subscription_actions_key(app: &mut TuiApp, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            app.mode = TuiMode::Subscriptions;
            app.last_message = "subscription action cancelled".to_string();
        }
        KeyCode::Up | KeyCode::Left => {
            app.selected_subscription_action = app.selected_subscription_action.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Right => {
            let len = tui_subscription_actions().len();
            if len > 0 {
                app.selected_subscription_action =
                    (app.selected_subscription_action + 1).min(len - 1);
            }
        }
        KeyCode::Enter => match selected_tui_subscription_action(app) {
            Some(TuiSubscriptionAction::Activate) => {
                match apply_selected_tui_subscription_action(app, TuiSubscriptionAction::Activate)
                    .await
                {
                    Ok(message) => {
                        app.clamp_subscription_selection();
                        app.mode = TuiMode::Subscriptions;
                        app.last_message = message;
                    }
                    Err(err) => open_tui_subscription_error(app, "Subscription Activate", err),
                }
            }
            Some(TuiSubscriptionAction::Refresh) => {
                match apply_selected_tui_subscription_action(app, TuiSubscriptionAction::Refresh)
                    .await
                {
                    Ok(message) => {
                        app.clamp_subscription_selection();
                        app.mode = TuiMode::Subscriptions;
                        app.last_message = message;
                    }
                    Err(err) => open_tui_subscription_error(app, "Subscription Refresh", err),
                }
            }
            Some(TuiSubscriptionAction::ToggleAutoUpdate) => {
                match apply_selected_tui_subscription_action(
                    app,
                    TuiSubscriptionAction::ToggleAutoUpdate,
                )
                .await
                {
                    Ok(message) => {
                        app.clamp_subscription_selection();
                        app.mode = TuiMode::Subscriptions;
                        app.last_message = message;
                    }
                    Err(err) => open_tui_subscription_error(app, "Subscription Settings", err),
                }
            }
            Some(TuiSubscriptionAction::Delete) => {
                match apply_selected_tui_subscription_action(app, TuiSubscriptionAction::Delete)
                    .await
                {
                    Ok(message) => {
                        app.clamp_subscription_selection();
                        app.mode = TuiMode::Subscriptions;
                        app.last_message = message;
                    }
                    Err(err) => open_tui_subscription_error(app, "Subscription Delete", err),
                }
            }
            None => {}
        },
        _ => {}
    }
    Ok(())
}

pub(super) async fn handle_tui_subscription_add_key(app: &mut TuiApp, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            reset_tui_subscription_add_form(app);
            app.mode = TuiMode::Subscriptions;
            app.last_message = "subscription add cancelled".to_string();
        }
        KeyCode::Tab => {
            app.subscription_add_field =
                (app.subscription_add_field + 1) % TUI_SUBSCRIPTION_ADD_FIELDS;
        }
        KeyCode::BackTab => {
            app.subscription_add_field = (app.subscription_add_field + TUI_SUBSCRIPTION_ADD_FIELDS
                - 1)
                % TUI_SUBSCRIPTION_ADD_FIELDS;
        }
        KeyCode::Backspace => match app.subscription_add_field {
            TUI_SUBSCRIPTION_ADD_NAME_FIELD => {
                app.subscription_add_name.pop();
            }
            TUI_SUBSCRIPTION_ADD_URL_FIELD => {
                app.subscription_add_url.pop();
            }
            _ => {}
        },
        KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down
            if app.subscription_add_field == TUI_SUBSCRIPTION_ADD_AUTO_UPDATE_FIELD =>
        {
            app.subscription_add_auto_update = !app.subscription_add_auto_update;
        }
        KeyCode::Enter => match tui_add_subscription_from_form(app).await {
            Ok(message) => {
                reset_tui_subscription_add_form(app);
                app.subscription_query.clear();
                app.selected_subscription = 0;
                app.clamp_subscription_selection();
                app.mode = TuiMode::Subscriptions;
                app.last_message = message;
            }
            Err(err) => open_tui_subscription_error(app, "Subscription Add", err),
        },
        KeyCode::Char(value) if is_tui_text_key(key) => match app.subscription_add_field {
            TUI_SUBSCRIPTION_ADD_NAME_FIELD => app.subscription_add_name.push(value),
            TUI_SUBSCRIPTION_ADD_URL_FIELD => app.subscription_add_url.push(value),
            _ => {}
        },
        _ => {}
    }
    Ok(())
}
