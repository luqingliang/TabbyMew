use super::*;

#[derive(Debug, Clone, Copy)]
pub(super) struct RouteModeOption {
    pub(super) mode: router::RouteMode,
    pub(super) name: &'static str,
    pub(super) summary: &'static str,
}

pub(super) fn route_mode_options() -> &'static [RouteModeOption] {
    const OPTIONS: &[RouteModeOption] = &[
        RouteModeOption {
            mode: router::RouteMode::Rule,
            name: "rule",
            summary: "Use routing rules and proxy-group selections.",
        },
        RouteModeOption {
            mode: router::RouteMode::Global,
            name: "global",
            summary: "Send traffic to one global outbound or group.",
        },
        RouteModeOption {
            mode: router::RouteMode::Direct,
            name: "direct",
            summary: "Bypass proxy when a direct outbound exists.",
        },
    ];
    OPTIONS
}

pub(super) fn open_tui_route_mode_selector(app: &mut TuiApp) {
    let current =
        current_tui_route_mode(app.control_snapshot.as_ref()).unwrap_or(router::RouteMode::Rule);
    app.route_mode_selection = route_mode_options()
        .iter()
        .position(|option| option.mode == current)
        .unwrap_or_default();
    app.mode = TuiMode::RouteModeSelector;
    app.last_message = "select a route mode with Up/Down and press Enter".to_string();
}

pub(super) fn current_tui_route_mode(control_snapshot: Option<&Value>) -> Option<router::RouteMode> {
    control_snapshot
        .and_then(|value| value_str(value, &["routing", "mode"]))
        .and_then(router::RouteMode::parse)
}

pub(super) fn open_tui_global_target_selector(app: &mut TuiApp) -> Result<()> {
    if tui_global_targets(app.control_snapshot.as_ref()).is_empty() {
        bail!("global targets are not available; run /restart and check the active config");
    }
    app.global_target_query.clear();
    let current = current_tui_global_target(app.control_snapshot.as_ref());
    app.selected_global_target = app
        .filtered_global_targets()
        .iter()
        .position(|target| Some(target.as_str()) == current.as_deref())
        .unwrap_or_default();
    app.mode = TuiMode::GlobalTargetSelector;
    app.last_message =
        "select the target used by global mode; current route mode is unchanged".to_string();
    Ok(())
}

pub(super) fn current_tui_global_target(control_snapshot: Option<&Value>) -> Option<String> {
    control_snapshot
        .and_then(|value| value_str(value, &["routing", "global_outbound"]))
        .map(str::to_string)
}

pub(super) fn tui_global_targets(control_snapshot: Option<&Value>) -> Vec<String> {
    control_snapshot
        .and_then(|value| value_array(value, &["routing", "global_targets"]))
        .map(|targets| {
            targets
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn filtered_tui_global_targets(control_snapshot: Option<&Value>, query: &str) -> Vec<String> {
    let query = query.trim().to_ascii_lowercase();
    tui_global_targets(control_snapshot)
        .into_iter()
        .filter(|target| query.is_empty() || target.to_ascii_lowercase().contains(&query))
        .collect()
}

pub(super) fn resolve_tui_global_target(control_snapshot: Option<&Value>, input: &str) -> Result<String> {
    let input = input.trim();
    if input.is_empty() {
        bail!("global target is required");
    }
    let targets = tui_global_targets(control_snapshot);
    if targets.is_empty() {
        bail!("global targets are not available; run /restart and check the active config");
    }
    if let Some(target) = targets.iter().find(|target| target.as_str() == input) {
        return Ok(target.clone());
    }
    if let Some(target) = targets
        .iter()
        .find(|target| target.eq_ignore_ascii_case(input))
    {
        return Ok(target.clone());
    }

    let query = input.to_ascii_lowercase();
    let matches = targets
        .iter()
        .filter(|target| target.to_ascii_lowercase().contains(&query))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [target] => Ok((*target).clone()),
        [] => bail!("global target `{input}` is not defined"),
        _ => bail!("global target `{input}` is ambiguous; refine the target name"),
    }
}

pub(super) fn parse_tui_route_mode(args: &str) -> Result<router::RouteMode> {
    let mut parts = args.split_whitespace();
    let mode = parts.next().context("route mode is required")?;
    if parts.next().is_some() {
        bail!("route mode accepts one value: rule, global, or direct");
    }
    match mode.to_ascii_lowercase().as_str() {
        "r" | "rule" => Ok(router::RouteMode::Rule),
        "g" | "global" => Ok(router::RouteMode::Global),
        "d" | "direct" => Ok(router::RouteMode::Direct),
        _ => bail!("unknown route mode `{mode}`; expected rule, global, or direct"),
    }
}

pub(super) async fn tui_set_route_mode(app: &mut TuiApp, mode: router::RouteMode) -> Result<String> {
    app.refresh_status().await?;
    let control = app
        .status
        .control_api
        .as_ref()
        .context("TabbyMew service is not running; run /restart before switching route mode")?;
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
            "/control/api/route-mode",
            &token,
            &serde_json::json!({ "mode": mode.as_str() }),
        )
        .await?;
    app.refresh_status().await?;
    Ok(format_route_mode_switch_output(&response, mode))
}

pub(super) fn format_route_mode_switch_output(response: &Value, requested: router::RouteMode) -> String {
    let mode = value_str(response, &["mode"]).unwrap_or_else(|| requested.as_str());
    let global = value_str(response, &["global_outbound"]).unwrap_or("-");
    let direct = value_str(response, &["direct_outbound"]).unwrap_or("-");
    let groups = value_array_len(response, &["policy_groups"]).unwrap_or_default();
    format!(
        "route mode: {mode}\nglobal target: {global}\ndirect outbound: {direct}\npolicy groups: {groups}\n"
    )
}

pub(super) async fn tui_set_global_target(app: &mut TuiApp, target: &str) -> Result<String> {
    app.refresh_status().await?;
    let before_mode = current_tui_route_mode(app.control_snapshot.as_ref());
    let control =
        app.status.control_api.as_ref().context(
            "TabbyMew service is not running; run /restart before setting global target",
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
            "/control/api/global-target",
            &token,
            &serde_json::json!({ "target": target }),
        )
        .await?;
    app.refresh_status().await?;
    Ok(format_global_target_switch_output(
        &response,
        target,
        before_mode,
        current_tui_route_mode(app.control_snapshot.as_ref()),
    ))
}

pub(super) fn format_global_target_switch_output(
    response: &Value,
    requested: &str,
    before_mode: Option<router::RouteMode>,
    after_mode: Option<router::RouteMode>,
) -> String {
    let target = value_str(response, &["global_outbound"]).unwrap_or(requested);
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
    format!("global target: {target}\nroute mode: {mode_note}\n")
}

pub(super) async fn tui_set_tun_enabled(app: &mut TuiApp, enabled: bool) -> Result<String> {
    app.refresh_status().await?;
    let control = app
        .status
        .control_api
        .as_ref()
        .context("TabbyMew service is not running; run /restart before switching TUN")?;
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
            "/control/api/tun",
            &token,
            &serde_json::json!({ "enabled": enabled }),
        )
        .await?;
    app.refresh_status().await?;
    Ok(format_tun_switch_output(&response, enabled))
}

pub(super) async fn tui_set_system_proxy_enabled(app: &mut TuiApp, enabled: bool) -> Result<String> {
    let response = tui_post_control_json_with_timeout(
        app,
        "/control/api/system-proxy",
        serde_json::json!({ "enabled": enabled }),
        if enabled {
            "enabling system proxy"
        } else {
            "disabling system proxy"
        },
        app.session.timeout.max(Duration::from_secs(60)),
    )
    .await?;
    app.refresh_status().await?;
    let snapshot = app
        .control_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.get("system_proxy"))
        .unwrap_or(&response);
    Ok(format_system_proxy_switch_output(snapshot, enabled))
}

pub(super) async fn tui_set_lan_proxy_enabled(app: &mut TuiApp, enabled: bool) -> Result<String> {
    let response = tui_post_control_json_with_timeout(
        app,
        "/control/api/lan-proxy",
        serde_json::json!({ "enabled": enabled }),
        if enabled {
            "enabling LAN proxy"
        } else {
            "disabling LAN proxy"
        },
        app.session.timeout.max(Duration::from_secs(60)),
    )
    .await?;
    Ok(format_lan_proxy_switch_output(
        &response,
        enabled,
        app.control_snapshot.as_ref(),
    ))
}
