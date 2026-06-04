use super::*;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RouteModeOption {
    pub(crate) mode: router::RouteMode,
    pub(crate) name: &'static str,
    pub(crate) summary: &'static str,
}

pub(crate) fn route_mode_options() -> &'static [RouteModeOption] {
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

pub(crate) fn open_tui_route_mode_selector(app: &mut TuiApp) {
    let current =
        current_route_mode(app.control_snapshot.as_ref()).unwrap_or(router::RouteMode::Rule);
    app.route_mode_selection = route_mode_options()
        .iter()
        .position(|option| option.mode == current)
        .unwrap_or_default();
    app.mode = TuiMode::RouteModeSelector;
    app.last_message = "select a route mode with Up/Down and press Enter".to_string();
}

pub(crate) fn open_tui_global_target_selector(app: &mut TuiApp) -> Result<()> {
    if global_targets(app.control_snapshot.as_ref()).is_empty() {
        bail!("global targets are not available; run /restart and check the active config");
    }
    app.global_target_query.clear();
    let current = current_global_target(app.control_snapshot.as_ref());
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

pub(crate) async fn tui_set_route_mode(
    app: &mut TuiApp,
    mode: router::RouteMode,
) -> Result<String> {
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

pub(crate) async fn tui_set_global_target(app: &mut TuiApp, target: &str) -> Result<String> {
    app.refresh_status().await?;
    let before_mode = current_route_mode(app.control_snapshot.as_ref());
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
        current_route_mode(app.control_snapshot.as_ref()),
    ))
}

pub(crate) async fn tui_set_tun_enabled(app: &mut TuiApp, enabled: bool) -> Result<String> {
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

pub(crate) async fn tui_set_system_proxy_enabled(
    app: &mut TuiApp,
    enabled: bool,
) -> Result<String> {
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

pub(crate) async fn tui_set_lan_proxy_enabled(app: &mut TuiApp, enabled: bool) -> Result<String> {
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
