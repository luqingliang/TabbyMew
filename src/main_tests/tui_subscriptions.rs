use super::*;

#[test]
fn parses_and_formats_tui_subscriptions() -> Result<()> {
    let control_snapshot = serde_json::json!({
        "subscriptions": {
            "store": "/tmp/tabbymew-subscriptions.json",
            "active": "main",
            "subscriptions": [
                {
                    "name": "main",
                    "source": "remote",
                    "url": "https://example.com/sub?token=redacted",
                    "output": "/tmp/main.json",
                    "auto_update": true,
                    "imported": 3,
                    "warnings": 1,
                    "last_success_unix": 10,
                    "next_update_unix": 20,
                    "last_error": null,
                    "last_final_url": "https://example.com/sub?token=redacted"
                },
                {
                    "name": "file",
                    "source": "uploaded_file",
                    "url": "uploaded-file://local.yaml",
                    "output": "/tmp/file.json",
                    "auto_update": false,
                    "imported": 2,
                    "warnings": 0,
                    "last_error": "parse failed"
                }
            ]
        }
    });

    let items = tui_subscription_items(Some(&control_snapshot));
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].name, "main");
    assert!(items[0].active);
    assert!(items[0].refreshable);
    assert_eq!(items[0].imported, "3");
    assert_eq!(items[0].last_success, "unix 10");
    assert_eq!(items[0].next_update, "unix 20");
    assert_eq!(items[0].status, "active");
    assert_eq!(items[1].status, "error");
    assert_eq!(items[1].next_update, "disabled");
    assert!(!items[1].refreshable);

    let filtered = filtered_tui_subscription_items(Some(&control_snapshot), "parse");
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "file");

    let detail = format_tui_subscription_detail(&items[0]);
    assert!(detail.contains("imported=3"));
    assert!(detail.contains("last_success=unix 10"));
    assert!(detail.contains("/tmp/main.json"));

    let mut app = test_tui_app();
    app.control_snapshot = Some(control_snapshot);
    open_tui_subscriptions(&mut app, "main");
    assert_eq!(app.mode, TuiMode::Subscriptions);
    assert_eq!(app.filtered_subscriptions().len(), 1);
    open_tui_subscription_actions(&mut app)?;
    assert_eq!(app.mode, TuiMode::SubscriptionActions);
    assert_eq!(
        selected_tui_subscription_action(&app),
        Some(TuiSubscriptionAction::Activate)
    );
    assert_eq!(
        subscription_action_label(
            TuiSubscriptionAction::ToggleAutoUpdate,
            selected_tui_subscription_item(&app).as_ref()
        ),
        "Disable Auto"
    );

    open_tui_subscription_add(&mut app);
    assert_eq!(app.mode, TuiMode::SubscriptionAdd);
    assert_eq!(app.subscription_add_field, TUI_SUBSCRIPTION_ADD_NAME_FIELD);
    assert!(app.subscription_add_auto_update);
    Ok(())
}

#[test]
fn formats_tui_subscription_operation_results() {
    let add = serde_json::json!({
        "name": "main",
        "imported": 3,
        "warnings": ["skipped one unsupported node"]
    });
    assert_eq!(
        format_tui_subscription_apply_report(&add),
        "subscription main added (3 imported, 1 warnings)"
    );

    let refresh = serde_json::json!([
        {
            "name": "main",
            "ok": true,
            "report": {
                "imported": 4,
                "warnings": []
            }
        },
        {
            "name": "file",
            "ok": false,
            "error": "subscription file cannot be refreshed"
        }
    ]);
    let output = format_tui_subscription_refresh_outcomes(&refresh);
    assert!(output.contains("main: ok imported=4 warnings=0"));
    assert!(output.contains("file: failed subscription file cannot be refreshed"));
    assert!(subscription_refresh_has_failure(&refresh));
    assert_eq!(
        first_tui_subscription_refresh_message(&refresh).as_deref(),
        Some("subscription main updated (4 imported, 0 warnings)")
    );
}
