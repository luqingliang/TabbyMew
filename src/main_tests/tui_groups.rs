use super::*;

#[test]
fn parses_tui_policy_group_selection() -> Result<()> {
    let control_snapshot = serde_json::json!({
        "routing": {
            "policy_groups": [
                {
                    "tag": "Proxy",
                    "kind": "select",
                    "selected": "Hong Kong 01",
                    "outbounds": ["Hong Kong 01", "Japan 01"]
                },
                {
                    "tag": "Fallback",
                    "kind": "select",
                    "selected": "direct",
                    "outbounds": ["direct", "block"]
                }
            ]
        }
    });

    let group_only = parse_policy_group_selection(Some(&control_snapshot), "Proxy")?;
    assert_eq!(group_only.group.tag, "Proxy");
    assert!(group_only.outbound.is_none());

    let selection = parse_policy_group_selection(Some(&control_snapshot), "Proxy Japan")?;
    assert_eq!(selection.group.tag, "Proxy");
    assert_eq!(selection.outbound.as_deref(), Some("Japan 01"));
    assert_eq!(
        filtered_policy_group_outbounds(Some(&control_snapshot), Some("Proxy"), "hong"),
        vec!["Hong Kong 01".to_string()]
    );
    assert_eq!(
        current_policy_group_outbound(Some(&control_snapshot), "Fallback").as_deref(),
        Some("direct")
    );
    Ok(())
}

#[test]
fn opens_tui_policy_group_list_before_outbound_selector() -> Result<()> {
    let control_snapshot = serde_json::json!({
        "routing": {
            "policy_groups": [
                {
                    "tag": "Proxy",
                    "kind": "select",
                    "selected": "Hong Kong 01",
                    "outbounds": ["Hong Kong 01", "Japan 01"]
                },
                {
                    "tag": "Fallback",
                    "kind": "select",
                    "selected": "direct",
                    "outbounds": ["direct", "block"]
                }
            ]
        }
    });

    let groups = filtered_policy_groups(Some(&control_snapshot), "hong");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].tag, "Proxy");

    let mut app = test_tui_app();
    app.control_snapshot = Some(control_snapshot);
    app.selected_policy_group_tag = Some("Fallback".to_string());
    open_tui_policy_group_list_selector(&mut app)?;

    assert_eq!(app.mode, TuiMode::PolicyGroupListSelector);
    assert_eq!(app.selected_policy_group, 1);
    assert_eq!(app.last_message, "select a policy group");

    app.policy_group_delay_group = Some("Fallback".to_string());
    app.policy_group_delay_results = vec![TuiPolicyGroupDelayResult {
        outbound: "direct".to_string(),
        resolved_outbound: Some("direct".to_string()),
        latency_ms: Some(7),
        status_code: Some(204),
        error: None,
    }];
    app.policy_group_query = "proxy".to_string();
    app.selected_policy_group = 0;
    open_selected_tui_policy_group(&mut app)?;

    assert_eq!(app.mode, TuiMode::PolicyGroupSelector);
    assert_eq!(app.selected_policy_group_tag.as_deref(), Some("Proxy"));
    assert_eq!(app.selected_policy_group_outbound, 0);
    assert!(app.policy_group_delay_group.is_none());
    assert!(app.policy_group_delay_results.is_empty());

    app.policy_group_query = "fallback".to_string();
    app.selected_policy_group_outbound = 1;
    return_to_tui_policy_group_list(&mut app, "Proxy")?;

    assert_eq!(app.mode, TuiMode::PolicyGroupListSelector);
    assert!(app.policy_group_query.is_empty());
    assert_eq!(app.selected_policy_group, 0);
    assert_eq!(app.selected_policy_group_tag.as_deref(), Some("Proxy"));
    assert_eq!(app.selected_policy_group_outbound, 0);
    Ok(())
}

#[test]
fn parses_tui_policy_group_delay_results_for_selector() {
    let response = serde_json::json!({
        "group": "Proxy",
        "url": "http://www.gstatic.com/generate_204",
        "timeout_ms": 15_000,
        "results": [
            {
                "outbound": "direct",
                "resolved_outbound": "direct",
                "latency_ms": 42,
                "status_code": 204,
                "error": null
            },
            {
                "outbound": "block",
                "resolved_outbound": "block",
                "latency_ms": null,
                "status_code": null,
                "error": "timeout"
            },
            {
                "outbound": "bad",
                "resolved_outbound": null,
                "latency_ms": null,
                "status_code": null,
                "error": "connection failed"
            }
        ]
    });

    let results = tui_policy_group_delay_results(&response);

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].outbound, "direct");
    assert_eq!(results[0].resolved_outbound.as_deref(), Some("direct"));
    assert_eq!(results[0].latency_ms, Some(42));
    assert_eq!(results[0].status_code, Some(204));
    assert_eq!(results[1].error.as_deref(), Some("timeout"));
    assert_eq!(format_tui_policy_group_delay(results.first()), "42 ms");
    assert_eq!(format_tui_policy_group_delay(results.get(1)), "timeout");
    assert_eq!(format_tui_policy_group_delay(results.get(2)), "failed");
    assert_eq!(format_tui_policy_group_delay(None), "-");

    let mut app = test_tui_app();
    app.policy_group_delay_group = Some("Proxy".to_string());
    app.policy_group_delay_results = results;

    assert_eq!(
        tui_policy_group_delay_for(&app, "Proxy", "direct").and_then(|result| result.latency_ms),
        Some(42)
    );
    assert!(tui_policy_group_delay_for(&app, "Fallback", "direct").is_none());
}

#[test]
fn colors_tui_policy_group_delay_results_by_latency() {
    fn result(latency_ms: Option<u64>, error: Option<&str>) -> TuiPolicyGroupDelayResult {
        TuiPolicyGroupDelayResult {
            outbound: "node".to_string(),
            resolved_outbound: Some("node".to_string()),
            latency_ms,
            status_code: latency_ms.map(|_| 204),
            error: error.map(str::to_string),
        }
    }

    let green = result(Some(300), None);
    let yellow_low = result(Some(301), None);
    let yellow_high = result(Some(500), None);
    let orange_low = result(Some(501), None);
    let orange_high = result(Some(1_000), None);
    let red_slow = result(Some(1_001), None);
    let red_error = result(None, Some("connection failed"));

    assert_eq!(
        tui_policy_group_delay_color(Some(&green)),
        Some(Color::Green)
    );
    assert_eq!(
        tui_policy_group_delay_color(Some(&yellow_low)),
        Some(Color::Yellow)
    );
    assert_eq!(
        tui_policy_group_delay_color(Some(&yellow_high)),
        Some(Color::Yellow)
    );
    assert_eq!(
        tui_policy_group_delay_color(Some(&orange_low)),
        Some(Color::Rgb(255, 165, 0))
    );
    assert_eq!(
        tui_policy_group_delay_color(Some(&orange_high)),
        Some(Color::Rgb(255, 165, 0))
    );
    assert_eq!(
        tui_policy_group_delay_color(Some(&red_slow)),
        Some(Color::Red)
    );
    assert_eq!(
        tui_policy_group_delay_color(Some(&red_error)),
        Some(Color::Red)
    );
    assert_eq!(tui_policy_group_delay_color(None), None);
}

#[test]
fn drains_tui_policy_group_delay_updates_progressively() {
    let mut app = test_tui_app();
    let (sender, receiver) = mpsc::unbounded_channel();
    app.policy_group_delay_group = Some("Proxy".to_string());
    app.policy_group_delay_run = Some(TuiPolicyGroupDelayRun {
        id: 7,
        group: "Proxy".to_string(),
        total: 2,
        completed: 0,
        tasks: Vec::new(),
    });
    app.policy_group_delay_updates = Some(receiver);

    sender
        .send(TuiPolicyGroupDelayUpdate {
            run_id: 7,
            group: "Proxy".to_string(),
            result: TuiPolicyGroupDelayResult {
                outbound: "Hong Kong 01".to_string(),
                resolved_outbound: Some("Hong Kong 01".to_string()),
                latency_ms: Some(88),
                status_code: Some(204),
                error: None,
            },
        })
        .expect("send first delay update");

    assert!(drain_tui_policy_group_delay_updates(&mut app));
    assert_eq!(app.policy_group_delay_results.len(), 1);
    assert_eq!(
        app.policy_group_delay_run.as_ref().map(|run| run.completed),
        Some(1)
    );
    assert!(app.policy_group_delay_updates.is_some());
    assert!(app.last_message.contains("1/2"));

    sender
        .send(TuiPolicyGroupDelayUpdate {
            run_id: 7,
            group: "Proxy".to_string(),
            result: TuiPolicyGroupDelayResult {
                outbound: "Japan 01".to_string(),
                resolved_outbound: Some("Japan 01".to_string()),
                latency_ms: Some(520),
                status_code: Some(204),
                error: None,
            },
        })
        .expect("send second delay update");

    assert!(drain_tui_policy_group_delay_updates(&mut app));
    assert_eq!(app.policy_group_delay_results.len(), 2);
    assert!(app.policy_group_delay_run.is_none());
    assert!(app.policy_group_delay_updates.is_none());
    assert_eq!(
        app.last_message,
        "tested 2 outbounds for policy group Proxy"
    );
}

#[tokio::test]
async fn leaving_tui_policy_group_selector_cancels_delay_run() -> Result<()> {
    let mut app = test_tui_app();
    let (_sender, receiver) = mpsc::unbounded_channel();
    app.mode = TuiMode::PolicyGroupSelector;
    app.policy_group_delay_group = Some("Proxy".to_string());
    app.policy_group_delay_run = Some(TuiPolicyGroupDelayRun {
        id: 9,
        group: "Proxy".to_string(),
        total: 2,
        completed: 1,
        tasks: Vec::new(),
    });
    app.policy_group_delay_updates = Some(receiver);

    handle_tui_policy_group_selector_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .await?;

    assert_eq!(app.mode, TuiMode::Dashboard);
    assert!(app.policy_group_delay_run.is_none());
    assert!(app.policy_group_delay_updates.is_none());
    assert_eq!(app.last_message, "policy group selection cancelled");
    Ok(())
}
