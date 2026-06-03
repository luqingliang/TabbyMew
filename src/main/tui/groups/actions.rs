use super::*;

pub(super) fn open_tui_policy_group_list_selector(app: &mut TuiApp) -> Result<()> {
    let groups = tui_policy_groups(app.control_snapshot.as_ref());
    if groups.is_empty() {
        bail!("policy groups are not available; run /restart and check the active config");
    }
    app.policy_group_query.clear();
    app.selected_policy_group = app
        .selected_policy_group_tag
        .as_deref()
        .and_then(|tag| groups.iter().position(|group| group.tag == tag))
        .unwrap_or_default();
    app.mode = TuiMode::PolicyGroupListSelector;
    app.last_message = "select a policy group".to_string();
    Ok(())
}

pub(super) fn open_selected_tui_policy_group(app: &mut TuiApp) -> Result<()> {
    let groups = app.filtered_policy_groups();
    let group = groups
        .get(app.selected_policy_group)
        .cloned()
        .context("no policy group selected")?;
    open_tui_policy_group_selector(app, &group)
}

pub(super) fn return_to_tui_policy_group_list(app: &mut TuiApp, selected_group: &str) -> Result<()> {
    let mut groups = app.filtered_policy_groups();
    if groups.iter().all(|group| group.tag != selected_group) {
        app.policy_group_query.clear();
        groups = app.filtered_policy_groups();
    }
    if groups.is_empty() {
        bail!("policy groups are not available after refreshing runtime status");
    }
    app.selected_policy_group = groups
        .iter()
        .position(|group| group.tag == selected_group)
        .with_context(|| format!("policy group `{selected_group}` is no longer available"))?;
    app.selected_policy_group_tag = Some(selected_group.to_string());
    app.policy_group_outbound_query.clear();
    app.selected_policy_group_outbound = 0;
    app.mode = TuiMode::PolicyGroupListSelector;
    Ok(())
}

pub(super) fn open_tui_policy_group_selector(app: &mut TuiApp, group: &TuiPolicyGroup) -> Result<()> {
    if group.outbounds.is_empty() {
        bail!("policy group `{}` has no selectable outbounds", group.tag);
    }
    if app.policy_group_delay_group.as_deref() != Some(group.tag.as_str()) {
        cancel_tui_policy_group_delay(app);
        app.policy_group_delay_group = None;
        app.policy_group_delay_results.clear();
    }
    app.selected_policy_group_tag = Some(group.tag.clone());
    app.policy_group_outbound_query.clear();
    app.selected_policy_group_outbound = group
        .outbounds
        .iter()
        .position(|outbound| outbound == &group.selected)
        .unwrap_or_default();
    app.mode = TuiMode::PolicyGroupSelector;
    app.last_message = format!("select an outbound for policy group {}", group.tag);
    Ok(())
}
pub(super) async fn tui_select_policy_group_outbound(
    app: &mut TuiApp,
    group: &str,
    outbound: &str,
) -> Result<String> {
    app.refresh_status().await?;
    let before_mode = current_tui_route_mode(app.control_snapshot.as_ref());
    let control = app.status.control_api.as_ref().context(
        "TabbyMew service is not running; run /restart before selecting policy group outbound",
    )?;
    if !control.healthy {
        bail!(
            "control API is unhealthy at http://{}: {}",
            control.listen,
            control.error.as_deref().unwrap_or("unknown error")
        );
    }
    let listen = control::parse_listen(&control.listen)
        .context("invalid control API listen address from local state")?;
    let client = ControlClient::new(listen, app.session.timeout);
    let token = tui_control_token(&app.session)?;
    let response = client
        .post_json(
            "/control/api/policy-groups/select",
            &token,
            &serde_json::json!({ "group": group, "outbound": outbound }),
        )
        .await?;
    app.refresh_status().await?;
    Ok(format_policy_group_selection_output(
        &response,
        group,
        outbound,
        before_mode,
        current_tui_route_mode(app.control_snapshot.as_ref()),
    ))
}

pub(super) fn format_policy_group_selection_output(
    response: &Value,
    group: &str,
    requested_outbound: &str,
    before_mode: Option<router::RouteMode>,
    after_mode: Option<router::RouteMode>,
) -> String {
    let selected = value_array(response, &["policy_groups"])
        .and_then(|groups| {
            groups.iter().find_map(|item| {
                (value_str(item, &["tag"]) == Some(group))
                    .then(|| value_str(item, &["selected"]))
                    .flatten()
            })
        })
        .unwrap_or(requested_outbound);
    let mode = value_str(response, &["mode"])
        .map(str::to_string)
        .or_else(|| after_mode.map(|mode| mode.as_str().to_string()))
        .unwrap_or_else(|| "-".to_string());
    let mode_note = match (before_mode, after_mode) {
        (Some(before), Some(after)) if before == after => {
            format!("unchanged ({})", after.as_str())
        }
        (Some(before), Some(after)) => format!("changed {} -> {}", before.as_str(), after.as_str()),
        _ => mode,
    };
    format!("policy group: {group}\nselected: {selected}\nroute mode: {mode_note}\n")
}
