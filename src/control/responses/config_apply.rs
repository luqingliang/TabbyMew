fn import_response(body: &[u8]) -> Result<ImportResponse> {
    let request: ImportRequest =
        serde_json::from_slice(body).context("control API import request body must be JSON")?;
    let result = subscription::import_from_text(
        &request.input,
        subscription::ImportOptions {
            inbound_tag: request.inbound_tag,
            listen: request.listen,
            listen_port: request.listen_port,
        },
    )?;
    validate_imported_config(&result.config)?;
    let protocols = result
        .protocol_counts()
        .into_iter()
        .map(|(protocol, count)| (protocol.to_string(), count))
        .collect();
    Ok(ImportResponse {
        imported: result.imported,
        protocols,
        warnings: result.warnings,
        config: result.config,
    })
}

fn validate_imported_config(config: &Config) -> Result<()> {
    config
        .validate()
        .context("imported configuration validation failed")?;
    outbound::validate_configs(&config.outbounds).context("imported outbound validation failed")?;
    if let Some(dns) = config.dns.as_ref() {
        router::Router::from_config_with_policy_groups_dns(
            &config.outbounds,
            &config.policy_groups,
            &config.route,
            Some(dns),
        )
        .context("imported router validation failed")?;
    } else {
        router::Router::from_config_with_policy_groups(
            &config.outbounds,
            &config.policy_groups,
            &config.route,
        )
        .context("imported router validation failed")?;
    }
    inbound::validate_configs(&config.inbounds).context("imported inbound validation failed")?;
    Ok(())
}

fn validate_preview_config(config: &Config, config_base_dir: Option<&Path>) -> Result<()> {
    config
        .validate()
        .context("configuration validation failed")?;
    outbound::validate_configs(&config.outbounds).context("outbound validation failed")?;
    build_router(config, config_base_dir, None).context("router validation failed")?;
    inbound::validate_configs(&config.inbounds).context("inbound validation failed")?;
    Ok(())
}

fn build_active_config_from_config(
    config_path: Option<PathBuf>,
    config: &Config,
    config_base_dir: Option<&Path>,
    metrics: Arc<RuntimeMetrics>,
) -> Result<ActiveConfig> {
    let store_path = config_path
        .as_deref()
        .and_then(custom_route_rules_path_for_subscription_config);
    build_active_config_from_config_with_store(
        config_path,
        config,
        config_base_dir,
        metrics,
        store_path.as_deref(),
    )
}

fn build_active_config_from_config_with_store(
    config_path: Option<PathBuf>,
    config: &Config,
    config_base_dir: Option<&Path>,
    metrics: Arc<RuntimeMetrics>,
    custom_rules_store_path: Option<&Path>,
) -> Result<ActiveConfig> {
    let custom_route_rules =
        custom_route_rules_for_config_path(config_path.as_deref(), custom_rules_store_path)?;
    let effective_config = config_with_custom_route_rules(config, &custom_route_rules);
    effective_config
        .validate()
        .context("configuration validation failed")?;
    outbound::validate_configs(&effective_config.outbounds)
        .context("outbound validation failed")?;
    let router = build_router(&effective_config, config_base_dir, Some(metrics))
        .context("router validation failed")?;
    inbound::validate_configs(&effective_config.inbounds).context("inbound validation failed")?;
    let proxy_runtime = Arc::new(ProxyRuntime::new_with_outbounds(
        effective_config.inbounds.clone(),
        router.clone(),
        &effective_config.outbounds,
    ));
    Ok(ActiveConfig::with_runtime(
        config_path,
        &effective_config,
        custom_route_rules,
        config.summary().route_rules,
        router,
        proxy_runtime,
    ))
}

fn build_router(
    config: &Config,
    config_base_dir: Option<&Path>,
    metrics: Option<Arc<RuntimeMetrics>>,
) -> Result<router::Router> {
    router::Router::from_config_with_policy_groups_dns_in_dir_and_metrics(
        &config.outbounds,
        &config.policy_groups,
        &config.route,
        config.dns.as_ref(),
        config_base_dir,
        metrics,
    )
}

fn config_base_dir(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn update_process_state_config(state: &ControlState, config_path: &Path) {
    if let Some(state_file) = state.control_api.state_file.as_ref() {
        let mut process_state = match crate::process_manager::load_state(state_file) {
            Ok(process_state) => process_state,
            Err(err) => {
                warn!(
                    state_file = %state_file.display(),
                    error = %err,
                    "failed to load process state after config activation"
                );
                persist_active_config_preference(state, config_path);
                return;
            }
        };
        process_state.config = config_path.to_path_buf();
        if let Err(err) = crate::process_manager::save_state_file(state_file, &process_state) {
            warn!(
                state_file = %state_file.display(),
                error = %err,
                "failed to update process state after config activation"
            );
        }
    }
    persist_active_config_preference(state, config_path);
}

fn persist_active_config_preference(state: &ControlState, config_path: &Path) {
    let Some(preferences_file) = preferences_file(state) else {
        return;
    };
    if let Err(err) = crate::process_manager::update_preferences(&preferences_file, |preferences| {
        preferences.active_config = Some(config_path.to_path_buf());
    }) {
        warn!(
            preferences = %preferences_file.display(),
            error = %err,
            "failed to persist active config preference"
        );
    }
}

fn persist_routing_preferences(state: &ControlState, snapshot: &router::RouterRuntimeSnapshot) {
    let Some(preferences_file) = preferences_file(state) else {
        return;
    };
    if let Err(err) = crate::process_manager::update_preferences(&preferences_file, |preferences| {
        preferences.route_mode = Some(snapshot.mode.as_str().to_string());
        preferences.global_outbound = Some(snapshot.global_outbound.clone());
        preferences.policy_group_selections = snapshot
            .policy_groups
            .iter()
            .map(|group| (group.tag.clone(), group.selected.clone()))
            .collect();
    }) {
        warn!(
            preferences = %preferences_file.display(),
            error = %err,
            "failed to persist routing preferences"
        );
    }
}

fn persist_lan_proxy_preference(state: &ControlState, enabled: bool) {
    let Some(preferences_file) = preferences_file(state) else {
        return;
    };
    if let Err(err) = crate::process_manager::update_preferences(&preferences_file, |preferences| {
        preferences.lan_proxy_enabled = enabled;
    }) {
        warn!(
            preferences = %preferences_file.display(),
            error = %err,
            "failed to persist LAN proxy preference"
        );
    }
}

fn load_managed_system_proxy_target(
    state: &ControlState,
) -> Option<system_proxy::SystemProxyTarget> {
    let preferences_file = preferences_file(state)?;
    crate::process_manager::load_preferences(preferences_file)
        .ok()
        .and_then(|preferences| preferences.system_proxy_target)
}

fn load_system_proxy_protocol(state: &ControlState) -> system_proxy::SystemProxyProtocol {
    let Some(preferences_file) = preferences_file(state) else {
        return system_proxy::SystemProxyProtocol::Auto;
    };
    crate::process_manager::load_preferences(preferences_file)
        .map(|preferences| preferences.system_proxy_protocol)
        .unwrap_or_default()
}

fn persist_system_proxy_protocol(
    state: &ControlState,
    protocol: system_proxy::SystemProxyProtocol,
) -> bool {
    let Some(preferences_file) = preferences_file(state) else {
        warn!("failed to persist system proxy protocol; no preferences file is available");
        return false;
    };
    match crate::process_manager::update_preferences(&preferences_file, |preferences| {
        preferences.system_proxy_protocol = protocol;
    }) {
        Ok(_) => {
            info!(
                preferences = %preferences_file.display(),
                protocol = protocol.as_str(),
                "persisted system proxy protocol"
            );
            true
        }
        Err(err) => {
            warn!(
                preferences = %preferences_file.display(),
                error = %err,
                "failed to persist system proxy protocol"
            );
            false
        }
    }
}

fn persist_managed_system_proxy_target(
    state: &ControlState,
    target: &system_proxy::SystemProxyTarget,
) -> bool {
    let Some(preferences_file) = preferences_file(state) else {
        warn!("failed to persist system proxy target; no preferences file is available");
        return false;
    };
    match crate::process_manager::update_preferences(&preferences_file, |preferences| {
        preferences.system_proxy_target = Some(target.clone());
    }) {
        Ok(_) => {
            info!(
                preferences = %preferences_file.display(),
                "persisted system proxy target"
            );
            true
        }
        Err(err) => {
            warn!(
                preferences = %preferences_file.display(),
                error = %err,
                "failed to persist system proxy target"
            );
            false
        }
    }
}

fn persist_enabled_system_proxy_target(
    state: &ControlState,
    status: &system_proxy::SystemProxyStatus,
) -> bool {
    let Some(target) = status.target.as_ref() else {
        return false;
    };
    persist_managed_system_proxy_target(state, target)
}

fn clear_managed_system_proxy_target(state: &ControlState) {
    let Some(preferences_file) = preferences_file(state) else {
        return;
    };
    if let Err(err) = crate::process_manager::update_preferences(&preferences_file, |preferences| {
        preferences.system_proxy_target = None;
    }) {
        warn!(
            preferences = %preferences_file.display(),
            error = %err,
            "failed to clear system proxy target"
        );
    }
}

async fn apply_proxy_preferences_or_inherit_current(
    state: &ControlState,
    current_proxy: Option<&Arc<ProxyRuntime>>,
    active: &ActiveConfig,
) {
    if let Some(preferences_file) = preferences_file(state)
        && let Ok(preferences) = crate::process_manager::load_preferences(&preferences_file)
    {
        apply_lan_proxy_enabled(active, preferences.lan_proxy_enabled).await;
        return;
    }
    if let Some(current_proxy) = current_proxy {
        let snapshot = current_proxy.snapshot().await;
        apply_lan_proxy_enabled(active, snapshot.lan_enabled).await;
    }
}

async fn apply_lan_proxy_enabled(active: &ActiveConfig, enabled: bool) {
    let Some(proxy) = active.proxy_runtime.as_ref() else {
        return;
    };
    if let Err(err) = proxy.set_lan_enabled(enabled).await {
        warn!(error = %err, "failed to apply LAN proxy preference");
    }
}

fn apply_saved_routing_preferences(state: &ControlState, active: &ActiveConfig) {
    let Some(preferences_file) = preferences_file(state) else {
        return;
    };
    let preferences = match crate::process_manager::load_preferences(&preferences_file) {
        Ok(preferences) => preferences,
        Err(err) => {
            warn!(
                preferences = %preferences_file.display(),
                error = %err,
                "failed to load routing preferences"
            );
            return;
        }
    };
    let Some(router) = active.router.as_ref() else {
        return;
    };
    let mode = preferences
        .route_mode
        .as_deref()
        .and_then(router::RouteMode::parse);
    let warnings = router.runtime().apply_preferences(
        mode,
        preferences.global_outbound.as_deref(),
        &preferences.policy_group_selections,
    );
    for warning in warnings {
        warn!(
            preferences = %preferences_file.display(),
            warning = %warning,
            "ignored routing preference"
        );
    }
}

fn preferences_file(state: &ControlState) -> Option<PathBuf> {
    state.control_api.state_file.as_ref().map(|path| {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        crate::process_manager::preferences_path(parent)
    })
}

fn json_body(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).context("failed to serialize control_api response")
}
