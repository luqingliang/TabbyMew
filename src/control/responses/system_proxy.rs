fn system_proxy_response(state: &ControlState) -> system_proxy::SystemProxyStatus {
    let active = state.active_config();
    let protocol = load_system_proxy_protocol(state);
    let recorded_target = load_managed_system_proxy_target(state);
    let target_recorded = recorded_target.is_some();
    let target = recorded_target.or_else(|| {
        system_proxy::target_from_inbounds_with_protocol(&active.summary.inbounds, protocol)
    });
    if target_recorded {
        match system_proxy::reapply_target_if_needed(target.as_ref()) {
            Ok(true) => info!("reapplied system proxy target with canonical settings"),
            Ok(false) => {}
            Err(err) => warn!(
                error = %err,
                "failed to reapply system proxy target with canonical settings"
            ),
        }
    }
    system_proxy::status_for_target(target.as_ref())
        .with_protocol(protocol)
        .with_target_recorded(target_recorded)
}

fn system_proxy_switch_response(
    state: &ControlState,
    body: &[u8],
) -> Result<system_proxy::SystemProxyStatus> {
    let request: ProxySwitchRequest =
        serde_json::from_slice(body).context("system proxy switch request body must be JSON")?;
    let active = state.active_config();
    let requested_protocol = request.protocol;
    let protocol = requested_protocol.unwrap_or_else(|| load_system_proxy_protocol(state));
    if request.enabled {
        let status = system_proxy::switch_with_protocol(
            &active.summary.inbounds,
            protocol,
            system_proxy::SystemProxySwitch::Enable,
        )?;
        if requested_protocol.is_some() {
            persist_system_proxy_protocol(state, protocol);
        }
        let target_recorded = persist_enabled_system_proxy_target(state, &status);
        Ok(status
            .with_protocol(protocol)
            .with_target_recorded(target_recorded))
    } else {
        if requested_protocol.is_some() {
            persist_system_proxy_protocol(state, protocol);
        }
        let recorded_target = load_managed_system_proxy_target(state);
        let target = recorded_target.or_else(|| {
            system_proxy::target_from_inbounds_with_protocol(&active.summary.inbounds, protocol)
        });
        let status = system_proxy::disable_target_without_prompt(target.as_ref())?;
        persist_system_proxy_enabled_preference(state, false);
        clear_managed_system_proxy_target(state);
        Ok(status
            .with_protocol(protocol)
            .with_target_recorded(false))
    }
}

async fn apply_system_proxy_after_config_change(
    state: &ControlState,
    new_active: &ActiveConfig,
) -> Result<()> {
    let Some(old_target) = load_managed_system_proxy_target(state) else {
        if !load_system_proxy_enabled_preference(state) {
            return Ok(());
        }
        let protocol = load_system_proxy_protocol(state);
        let Some(new_target) =
            system_proxy::target_from_inbounds_with_protocol(&new_active.summary.inbounds, protocol)
        else {
            return Ok(());
        };
        let status =
            system_proxy::switch_target(Some(&new_target), system_proxy::SystemProxySwitch::Enable)?;
        if status.matches_target {
            persist_managed_system_proxy_target(state, &new_target);
        }
        return Ok(());
    };
    if !system_proxy::status_for_target(Some(&old_target)).managed {
        clear_managed_system_proxy_target(state);
        return Ok(());
    }

    let protocol = load_system_proxy_protocol(state);
    let Some(new_target) =
        system_proxy::target_from_inbounds_with_protocol(&new_active.summary.inbounds, protocol)
    else {
        let status = system_proxy::disable_target_without_prompt(Some(&old_target))?;
        if !status.managed {
            clear_managed_system_proxy_target(state);
        }
        return Ok(());
    };
    if new_target == old_target {
        return Ok(());
    }

    let status =
        system_proxy::switch_target(Some(&new_target), system_proxy::SystemProxySwitch::Enable)?;
    if status.matches_target {
        persist_managed_system_proxy_target(state, &new_target);
    }
    Ok(())
}

async fn tun_switch_response(state: &ControlState, body: &[u8]) -> Result<ProxyRuntimeSnapshot> {
    let request: ProxySwitchRequest =
        serde_json::from_slice(body).context("TUN switch request body must be JSON")?;
    let active = state.active_config();
    let runtime = active
        .proxy_runtime
        .as_ref()
        .context("proxy runtime is not available")?;
    let snapshot = runtime.set_tun_enabled(request.enabled).await?;
    persist_tun_preference(state, snapshot.tun_enabled);
    Ok(snapshot)
}

async fn lan_proxy_switch_response(state: &ControlState, body: &[u8]) -> Result<LanProxyResponse> {
    let request: ProxySwitchRequest =
        serde_json::from_slice(body).context("LAN proxy switch request body must be JSON")?;
    let active = state.active_config();
    let runtime = active
        .proxy_runtime
        .as_ref()
        .context("proxy runtime is not available")?;
    let snapshot = runtime.set_lan_enabled(request.enabled).await?;
    persist_lan_proxy_preference(state, snapshot.lan_enabled);
    Ok(LanProxyResponse {
        enabled: snapshot.lan_enabled,
        available: snapshot.configured_inbounds > 0,
        detail: lan_proxy_detail(snapshot.lan_enabled, snapshot.configured_inbounds > 0),
    })
}
