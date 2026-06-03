use super::*;

pub(super) fn open_tui_route_rules(app: &mut TuiApp, query: &str) {
    app.route_rule_query = query.trim().to_string();
    app.selected_route_rule = 0;
    app.clamp_route_rule_selection();
    reset_tui_route_rule_add_form(app);
    app.mode = TuiMode::RouteRules;
    app.last_message = "search route rules or press + to add a custom rule".to_string();
}

pub(super) fn open_tui_route_rule_add(app: &mut TuiApp) {
    reset_tui_route_rule_add_form(app);
    app.clamp_route_rule_add_selection();
    app.mode = TuiMode::RouteRuleAdd;
    app.last_message = "enter match content, choose rule and route target".to_string();
}

pub(super) fn reset_tui_route_rule_add_form(app: &mut TuiApp) {
    app.route_rule_form_id = None;
    app.route_rule_add_field = TUI_ROUTE_RULE_ADD_CONTENT_FIELD;
    app.route_rule_add_content.clear();
    app.route_rule_target_query.clear();
    app.selected_route_rule_target_candidate = app.selected_route_rule_target;
}

pub(super) fn open_tui_route_rule_actions(app: &mut TuiApp) -> Result<()> {
    let item = selected_tui_route_rule_item(app).context("no route rule selected")?;
    if item.source != "custom" {
        bail!("only custom route rules have edit/delete actions");
    }
    if item.id.is_none() {
        bail!("selected custom rule has no id");
    }
    app.selected_route_rule_action = 0;
    app.clamp_route_rule_action_selection();
    app.mode = TuiMode::RouteRuleActions;
    app.last_message = "choose a custom route rule action".to_string();
    Ok(())
}

pub(super) fn change_tui_route_rule_add_selection(app: &mut TuiApp, delta: isize) {
    match app.route_rule_add_field {
        TUI_ROUTE_RULE_ADD_MATCH_FIELD => {
            app.selected_route_rule_match_kind = shift_index(
                app.selected_route_rule_match_kind,
                tui_route_rule_match_kinds().len(),
                delta,
            );
        }
        TUI_ROUTE_RULE_ADD_TARGET_FIELD => {}
        _ => {}
    }
    app.clamp_route_rule_add_selection();
}

pub(super) fn shift_index(current: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    if delta.is_negative() {
        current.saturating_sub(delta.unsigned_abs()).min(len - 1)
    } else {
        current.saturating_add(delta as usize).min(len - 1)
    }
}

pub(super) fn selected_tui_route_rule_match_kind(app: &TuiApp) -> TuiRouteRuleMatchKind {
    tui_route_rule_match_kinds()[app
        .selected_route_rule_match_kind
        .min(tui_route_rule_match_kinds().len() - 1)]
}

pub(super) fn tui_route_rule_targets(control_snapshot: Option<&Value>) -> Vec<String> {
    tui_global_targets(control_snapshot)
}

pub(super) fn filtered_tui_route_rule_targets(control_snapshot: Option<&Value>, query: &str) -> Vec<String> {
    filtered_tui_global_targets(control_snapshot, query)
}

pub(super) fn selected_tui_route_rule_target(app: &TuiApp) -> Option<String> {
    let targets = tui_route_rule_targets(app.control_snapshot.as_ref());
    targets.get(app.selected_route_rule_target).cloned()
}

pub(super) fn open_tui_route_rule_target_selector(app: &mut TuiApp) -> Result<()> {
    let targets = tui_route_rule_targets(app.control_snapshot.as_ref());
    if targets.is_empty() {
        bail!("route targets are not available; run /restart and check the active config");
    }
    app.route_rule_target_query.clear();
    app.selected_route_rule_target_candidate =
        app.selected_route_rule_target.min(targets.len() - 1);
    app.mode = TuiMode::RouteRuleTargetSelector;
    app.last_message = "select a route target for this custom rule".to_string();
    Ok(())
}

pub(super) fn selected_tui_route_rule_item(app: &TuiApp) -> Option<TuiRouteRuleItem> {
    app.filtered_route_rules()
        .get(app.selected_route_rule)
        .cloned()
}

pub(super) fn selected_tui_route_rule_action(app: &TuiApp) -> Option<TuiRouteRuleAction> {
    tui_route_rule_actions()
        .get(app.selected_route_rule_action)
        .map(|option| option.action)
}

pub(super) fn open_tui_route_rule_edit(app: &mut TuiApp) -> Result<()> {
    let item = selected_tui_route_rule_item(app).context("no route rule selected")?;
    if item.source != "custom" {
        bail!("only custom route rules can be edited");
    }
    let id = item.id.context("selected custom rule has no id")?;
    let rule = item
        .rule
        .context("selected custom rule has no editable body")?;
    let (kind, content) = editable_tui_route_rule_match(&rule)?;
    let outbound =
        value_str(&rule, &["outbound"]).context("selected custom rule has no outbound")?;
    let targets = tui_route_rule_targets(app.control_snapshot.as_ref());
    let target_index = targets
        .iter()
        .position(|target| target == outbound)
        .with_context(|| {
            format!("selected custom rule outbound `{outbound}` is not a route target")
        })?;

    reset_tui_route_rule_add_form(app);
    app.route_rule_form_id = Some(id);
    app.route_rule_add_content = content;
    app.selected_route_rule_match_kind = kind;
    app.selected_route_rule_target = target_index;
    app.selected_route_rule_target_candidate = target_index;
    app.clamp_route_rule_add_selection();
    app.mode = TuiMode::RouteRuleAdd;
    app.last_message = "edit match content, rule, and route target".to_string();
    Ok(())
}

pub(super) fn editable_tui_route_rule_match(rule: &Value) -> Result<(usize, String)> {
    let unsupported = [
        "inbound",
        "network",
        "domain_set",
        "domain_suffix_set",
        "domain_keyword_set",
        "process_name",
        "geoip",
        "ip_cidr_set",
        "port",
        "port_range",
    ]
    .into_iter()
    .filter(|key| value_array(rule, &[*key]).is_some_and(|values| !values.is_empty()))
    .collect::<Vec<_>>();
    if !unsupported.is_empty() {
        bail!(
            "selected custom rule uses unsupported fields for form editing: {}",
            unsupported.join(", ")
        );
    }

    let matches = tui_route_rule_match_kinds()
        .iter()
        .enumerate()
        .filter_map(|(index, kind)| {
            let values = value_array(rule, &[kind.key])?;
            let values = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
            (!values.is_empty()).then_some((index, values.join(",")))
        })
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [(index, content)] => Ok((*index, content.clone())),
        [] => bail!("selected custom rule has no editable match content"),
        _ => bail!("selected custom rule has multiple match fields; use /rules add/remove CLI"),
    }
}
