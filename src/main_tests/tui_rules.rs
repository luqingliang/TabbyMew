use super::*;

#[test]
fn resolves_tui_global_targets_from_exact_or_unique_filter() -> Result<()> {
    let control_snapshot = serde_json::json!({
        "routing": {
            "global_outbound": "Proxy",
            "global_targets": ["Proxy", "Hong Kong Node", "direct"]
        }
    });

    assert_eq!(
        resolve_tui_global_target(Some(&control_snapshot), "Hong Kong Node")?,
        "Hong Kong Node"
    );
    assert_eq!(
        resolve_tui_global_target(Some(&control_snapshot), "hong kong")?,
        "Hong Kong Node"
    );
    assert_eq!(
        filtered_tui_global_targets(Some(&control_snapshot), "pro"),
        vec!["Proxy".to_string()]
    );
    assert!(resolve_tui_global_target(Some(&control_snapshot), "missing").is_err());
    Ok(())
}

#[test]
fn parses_and_formats_tui_route_rule_commands() -> Result<()> {
    let control_snapshot = serde_json::json!({
        "routing": {
            "global_targets": ["Proxy", "Fallback", "Hong Kong 01", "Japan 01", "direct", "block"],
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
        },
        "rules": {
            "final_outbound": "direct",
            "resolve_ip_cidr": false,
            "rule_items": [
                {
                    "source": "custom",
                    "id": "custom-1",
                    "summary": "domain_suffix=example.com -> Fallback",
                    "rule": {
                        "domain_suffix": ["example.com"],
                        "outbound": "Fallback"
                    }
                },
                {
                    "source": "subscription",
                    "summary": "domain_keyword=ads -> block"
                }
            ]
        }
    });
    let output = format_tui_route_rules_output(Some(&control_snapshot), "custom-1");
    assert!(output.contains("1 visible / 2 total"));
    assert!(output.contains("custom-1"));
    assert!(output.contains("Domain Suffix"));
    assert!(output.contains("example.com"));
    assert!(output.contains("Fallback"));
    let items = tui_route_rule_items(Some(&control_snapshot));
    assert_eq!(items[0].match_type, "domain_suffix");
    assert_eq!(items[0].match_kind, "Domain Suffix");
    assert_eq!(items[0].match_content, "example.com");
    assert_eq!(items[0].outbound, "Fallback");
    let visible = filtered_tui_route_rule_items(Some(&control_snapshot), "ads");
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].source, "subscription");
    assert_eq!(visible[0].match_type, "domain_keyword");
    assert_eq!(visible[0].match_kind, "Domain Keyword");
    assert_eq!(visible[0].match_content, "ads");
    assert_eq!(visible[0].outbound, "block");
    assert_eq!(
        resolve_tui_custom_route_rule_id(Some(&control_snapshot), "1")?,
        "custom-1"
    );
    let structured = structured_rules_list_json(Some(&control_snapshot), "custom");
    assert_eq!(structured["visible"], 1);
    assert_eq!(structured["total"], 2);
    assert_eq!(structured["custom"], 1);
    assert_eq!(structured["subscription"], 1);
    assert_eq!(structured["rules"][0]["id"], "custom-1");
    assert_eq!(structured["rules"][0]["match_type"], "domain_suffix");
    assert_eq!(structured["rules"][0]["match_kind"], "Domain Suffix");
    assert_eq!(structured["rules"][0]["match_content"], "example.com");
    assert_eq!(structured["rules"][0]["outbound"], "Fallback");

    let rule = parse_tui_custom_route_rule(
        "domain_suffix=example.com,example.org network=tcp port=443 -> Proxy Node",
    )?;
    assert_eq!(rule["domain_suffix"][0], "example.com");
    assert_eq!(rule["domain_suffix"][1], "example.org");
    assert_eq!(rule["network"][0], "tcp");
    assert_eq!(rule["port"][0], 443);
    assert_eq!(rule["outbound"], "Proxy Node");
    assert!(parse_tui_custom_route_rule("outbound=direct").is_err());

    let mut app = test_tui_app();
    app.control_snapshot = Some(control_snapshot);
    open_tui_route_rules(&mut app, "custom");
    assert_eq!(app.mode, TuiMode::RouteRules);
    assert_eq!(app.route_rule_query, "custom");
    assert_eq!(app.filtered_route_rules().len(), 1);

    open_tui_route_rule_actions(&mut app)?;
    assert_eq!(app.mode, TuiMode::RouteRuleActions);
    assert_eq!(
        selected_tui_route_rule_action(&app),
        Some(TuiRouteRuleAction::Edit)
    );
    open_tui_route_rule_edit(&mut app)?;
    assert_eq!(app.mode, TuiMode::RouteRuleAdd);
    assert_eq!(app.route_rule_form_id.as_deref(), Some("custom-1"));
    assert_eq!(app.route_rule_add_content, "example.com");
    assert_eq!(
        selected_tui_route_rule_target(&app).as_deref(),
        Some("Fallback")
    );

    open_tui_route_rule_add(&mut app);
    assert_eq!(app.mode, TuiMode::RouteRuleAdd);
    assert!(app.route_rule_form_id.is_none());
    assert_eq!(app.route_rule_add_field, TUI_ROUTE_RULE_ADD_CONTENT_FIELD);
    assert!(tui_route_rule_targets(app.control_snapshot.as_ref()).contains(&"direct".to_string()));
    assert!(
        filtered_tui_route_rule_targets(app.control_snapshot.as_ref(), "hong")
            .contains(&"Hong Kong 01".to_string())
    );
    app.route_rule_add_content = "example.net".to_string();
    app.selected_route_rule_target = tui_route_rule_targets(app.control_snapshot.as_ref())
        .iter()
        .position(|target| target == "direct")
        .context("direct target missing")?;
    let form_rule = build_tui_custom_route_rule_from_form(&app)?;
    assert_eq!(form_rule["domain_suffix"][0], "example.net");
    assert_eq!(form_rule["outbound"], "direct");

    app.route_rule_add_field = TUI_ROUTE_RULE_ADD_TARGET_FIELD;
    open_tui_route_rule_target_selector(&mut app)?;
    assert_eq!(app.mode, TuiMode::RouteRuleTargetSelector);
    app.route_rule_target_query = "hong".to_string();
    app.clamp_route_rule_target_selection();
    assert_eq!(
        app.filtered_route_rule_targets(),
        vec!["Hong Kong 01".to_string()]
    );

    app.route_rule_add_field = TUI_ROUTE_RULE_ADD_MATCH_FIELD;
    change_tui_route_rule_add_selection(&mut app, 1);
    let form_rule = build_tui_custom_route_rule_from_form(&app)?;
    assert_eq!(form_rule["domain"][0], "example.net");
    Ok(())
}

#[test]
fn builds_cli_custom_route_rules_and_formats_route_tests() -> Result<()> {
    let rule = build_cli_custom_route_rule("domain-suffix", "example.com,example.org", "Proxy")?;
    assert_eq!(rule["domain_suffix"][0], "example.com");
    assert_eq!(rule["domain_suffix"][1], "example.org");
    assert_eq!(rule["outbound"], "Proxy");
    assert!(build_cli_custom_route_rule("network", "tcp", "Proxy").is_err());
    assert!(build_cli_custom_route_rule("domain", "", "Proxy").is_err());

    let response = serde_json::json!({
        "destination": "example.com:443",
        "network": "tcp",
        "inbound": "cli",
        "mode": "rule",
        "route_target": "Proxy",
        "outbound": "Hong Kong 01",
        "rule_index": 0,
        "rule": {
            "source": "custom",
            "id": "custom-1",
            "summary": "domain_suffix=example.com -> Proxy",
            "rule": {
                "domain_suffix": ["example.com"],
                "outbound": "Proxy"
            }
        }
    });
    let output = format_rules_route_test_output(&response);
    assert!(output.contains("destination: example.com:443"));
    assert!(output.contains("mode: rule"));
    assert!(output.contains("outbound: Hong Kong 01"));
    assert!(output.contains("rule: custom custom-1 Domain Suffix example.com => Proxy"));
    Ok(())
}
