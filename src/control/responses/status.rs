async fn control_status_response(state: &ControlState) -> ControlStatusResponse {
    let active = state.active_config();
    let counters = state.metrics.snapshot();
    let proxy = match active.proxy_runtime.as_ref() {
        Some(runtime) => Some(runtime.snapshot().await),
        None => None,
    };
    let subscriptions =
        subscriptions_response(state)
            .await
            .unwrap_or_else(|err| ControlSubscriptionsResponse {
                store: state
                    .subscriptions
                    .as_ref()
                    .map(|runtime| runtime.store_path().display().to_string()),
                subscriptions: Vec::new(),
                active: None,
                active_config: path_to_string(state.active_config().config_path.as_ref()),
                error: Some(format!("{err:#}")),
                auto_update_running: state.subscriptions.is_some(),
            });
    ControlStatusResponse {
        health: HealthResponse {
            ok: true,
            service: "TabbyMew",
            uptime_seconds: counters.uptime_seconds,
        },
        config: config_response(&active.summary),
        inbounds: ListResponse {
            items: active.summary.inbounds.clone(),
        },
        outbounds: ListResponse {
            items: active.summary.outbounds.clone(),
        },
        rules: RouteSummaryResponse {
            final_outbound: active.summary.route_final.clone(),
            resolve_ip_cidr: active.summary.route_resolve_ip_cidr,
            rule_sets: active.summary.route_rule_sets.clone(),
            rules: active.summary.route_rules.clone(),
            rule_items: route_rule_items_response(&active),
        },
        routing: active
            .router
            .as_ref()
            .map(|router| router.runtime().snapshot()),
        proxy,
        lan_proxy: lan_proxy_response(state).await,
        system_proxy: system_proxy_response(state),
        counters,
        process: ControlProcessResponse {
            config_path: path_to_string(
                active
                    .config_path
                    .as_ref()
                    .or(state.control_api.config_path.as_ref()),
            ),
            log_file: path_to_string(state.control_api.log_file.as_ref()),
            state_file: path_to_string(state.control_api.state_file.as_ref()),
            can_read_logs: state.control_api.log_file.is_some(),
            can_stop: state.shutdown.is_some(),
        },
        subscriptions,
    }
}

async fn lan_proxy_response(state: &ControlState) -> LanProxyResponse {
    let active = state.active_config();
    let Some(runtime) = active.proxy_runtime.as_ref() else {
        return LanProxyResponse {
            enabled: false,
            available: false,
            detail: "proxy runtime is not available".to_string(),
        };
    };
    let snapshot = runtime.snapshot().await;
    let available = snapshot.configured_inbounds > 0;
    LanProxyResponse {
        enabled: snapshot.lan_enabled,
        available,
        detail: lan_proxy_detail(snapshot.lan_enabled, available),
    }
}

fn lan_proxy_detail(enabled: bool, available: bool) -> String {
    if !available {
        return "no local proxy listener is configured".to_string();
    }
    if enabled {
        "LAN devices can connect to the local proxy port".to_string()
    } else {
        "only this computer can connect to the local proxy port".to_string()
    }
}

async fn subscriptions_response(state: &ControlState) -> Result<ControlSubscriptionsResponse> {
    let Some(runtime) = state.subscriptions.as_ref() else {
        return Ok(ControlSubscriptionsResponse {
            store: None,
            subscriptions: Vec::new(),
            active: None,
            active_config: path_to_string(state.active_config().config_path.as_ref()),
            error: None,
            auto_update_running: false,
        });
    };
    let snapshot = runtime.snapshot().await?;
    let active_config = path_to_string(state.active_config().config_path.as_ref());
    let active = active_config
        .as_deref()
        .and_then(|path| active_subscription_name(path, &snapshot.subscriptions));
    Ok(ControlSubscriptionsResponse {
        store: Some(snapshot.store),
        subscriptions: snapshot.subscriptions,
        active,
        active_config,
        error: None,
        auto_update_running: true,
    })
}

async fn active_config_preview_response(
    state: &ControlState,
) -> Result<ActiveConfigPreviewResponse> {
    let active = state.active_config();
    let config_path = active
        .config_path
        .context("no active config path is available")?;
    let runtime = subscription_runtime(state)?;
    let snapshot = runtime.snapshot().await?;
    let config_path_text = config_path.display().to_string();
    let subscription = active_subscription_name(&config_path_text, &snapshot.subscriptions)
        .context("no active subscription config is selected")?;
    let config = Config::load(&config_path)
        .with_context(|| format!("failed to load active config {}", config_path.display()))?;
    let validation_error = validate_preview_config(&config, config_base_dir(&config_path))
        .err()
        .map(|err| format!("{err:#}"));
    let config = config_normalize::normalize_json(&config, true)
        .context("failed to normalize active subscription config")?;
    Ok(ActiveConfigPreviewResponse {
        subscription,
        config_path: config_path_text,
        redacted: true,
        validation_error,
        config,
    })
}

fn custom_route_rules_response(state: &ControlState) -> Result<CustomRouteRulesResponse> {
    let active = state.active_config();
    let store_path = custom_route_rules_path(state);
    let rules = custom_route_rules_for_active(state, &active)?
        .into_iter()
        .map(custom_route_rule_response)
        .collect();
    Ok(CustomRouteRulesResponse {
        active_config: path_to_string(active.config_path.as_ref()),
        store: store_path.map(|path| path.display().to_string()),
        rules,
    })
}

async fn custom_route_rule_upsert_response(
    state: &ControlState,
    body: &[u8],
) -> Result<ControlStatusResponse> {
    let request: CustomRouteRuleUpsertRequest =
        serde_json::from_slice(body).context("custom rule request body must be JSON")?;
    let active = state.active_config();
    let config_path = active
        .config_path
        .clone()
        .context("custom route rules require an active config path")?;
    let store_path = custom_route_rules_path(state)
        .context("custom route rules require an attached state file")?;
    let mut store = load_custom_route_rules_store(&store_path)?;
    let profile_key = profile_key_for_config_path(Some(&config_path));
    let profile = store.profiles.entry(profile_key).or_default();
    let rule = CustomRouteRule {
        id: request
            .id
            .unwrap_or_else(|| format!("custom-{}", csrf_token())),
        rule: request.rule,
    };
    validate_custom_route_rule(state, &rule.rule)?;
    if let Some(existing) = profile
        .rules
        .iter_mut()
        .find(|existing| existing.id == rule.id)
    {
        *existing = rule;
    } else {
        profile.rules.push(rule);
    }
    store.version = CUSTOM_ROUTE_RULES_VERSION;
    save_custom_route_rules_store(&store_path, &store)?;
    reload_active_config(state).await?;
    Ok(control_status_response(state).await)
}

async fn custom_route_rule_delete_response(
    state: &ControlState,
    body: &[u8],
) -> Result<ControlStatusResponse> {
    let request: CustomRouteRuleDeleteRequest =
        serde_json::from_slice(body).context("custom rule delete request body must be JSON")?;
    let active = state.active_config();
    let config_path = active
        .config_path
        .clone()
        .context("custom route rules require an active config path")?;
    let store_path = custom_route_rules_path(state)
        .context("custom route rules require an attached state file")?;
    let mut store = load_custom_route_rules_store(&store_path)?;
    let profile_key = profile_key_for_config_path(Some(&config_path));
    let profile = store.profiles.entry(profile_key).or_default();
    let before = profile.rules.len();
    profile.rules.retain(|rule| rule.id != request.id);
    if profile.rules.len() == before {
        bail!("custom route rule {} was not found", request.id);
    }
    store.version = CUSTOM_ROUTE_RULES_VERSION;
    save_custom_route_rules_store(&store_path, &store)?;
    reload_active_config(state).await?;
    Ok(control_status_response(state).await)
}

async fn route_rules_reload_response(state: &ControlState) -> Result<ControlStatusResponse> {
    reload_active_config(state).await?;
    Ok(control_status_response(state).await)
}

async fn route_test_response(state: &ControlState, body: &[u8]) -> Result<RouteTestResponse> {
    let request: RouteTestRequest =
        serde_json::from_slice(body).context("route test request body must be JSON")?;
    let active = state.active_config();
    let router = active
        .router
        .clone()
        .context("router runtime is not available")?;
    let destination = parse_route_test_destination(&request)?;
    let network = parse_route_test_network(request.network.as_deref())?;
    let inbound = request
        .inbound
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("rule-test")
        .to_string();
    let session = match network {
        Network::Tcp => Session::tcp(inbound.clone(), None, destination.clone()),
        Network::Udp => Session::udp(inbound.clone(), None, destination.clone()),
    };
    let decision = router.route_decision(&session).await?;
    let rule_items = route_rule_items_response(&active);
    let rule = decision
        .rule_index
        .and_then(|index| rule_items.get(index).cloned());

    Ok(RouteTestResponse {
        destination: destination.to_string(),
        network: network_label(network).to_string(),
        inbound,
        mode: decision.mode,
        route_target: decision.route_target,
        outbound: decision.outbound,
        rule_index: decision.rule_index,
        rule,
    })
}

fn parse_route_test_destination(request: &RouteTestRequest) -> Result<Destination> {
    let input = request.destination.trim();
    if input.is_empty() {
        bail!("route test destination is required");
    }
    if input.contains("://") {
        let url = Url::parse(input).context("route test destination URL is invalid")?;
        let host = url
            .host_str()
            .context("route test destination URL has no host")?;
        let port = request
            .port
            .or_else(|| url.port_or_known_default())
            .context("route test destination URL has no port")?;
        let address = match host.parse::<IpAddr>() {
            Ok(ip) => Address::Ip(ip),
            Err(_) => Address::Domain(host.to_string()),
        };
        return Ok(Destination::new(address, port));
    }
    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok(Destination::new(
            Address::Ip(ip),
            request.port.unwrap_or(443),
        ));
    }
    parse_authority(input, request.port.or(Some(443)))
        .context("route test destination must be a host, host:port, IP, IP:port, or URL")
}

fn parse_route_test_network(network: Option<&str>) -> Result<Network> {
    match network
        .unwrap_or("tcp")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "tcp" => Ok(Network::Tcp),
        "udp" => Ok(Network::Udp),
        other => bail!("route test network `{other}` is invalid; expected tcp or udp"),
    }
}

fn network_label(network: Network) -> &'static str {
    match network {
        Network::Tcp => "tcp",
        Network::Udp => "udp",
    }
}

async fn reload_active_config(state: &ControlState) -> Result<()> {
    let old_active = state.active_config();
    let config_path = old_active
        .config_path
        .clone()
        .context("active config path is not available")?;
    let config = Config::load(&config_path)
        .with_context(|| format!("failed to load active config {}", config_path.display()))?;
    let new_active = build_active_config_from_config_with_store(
        Some(config_path.clone()),
        &config,
        config_base_dir(&config_path),
        state.metrics.clone(),
        custom_route_rules_path(state).as_deref(),
    )
    .with_context(|| format!("failed to reload active config {}", config_path.display()))?;
    apply_saved_routing_preferences(state, &new_active);
    apply_proxy_preferences_or_inherit_current(
        state,
        old_active.proxy_runtime.as_ref(),
        &new_active,
    )
    .await;
    replace_active_config_preserving_proxy(state, old_active, new_active).await
}

async fn replace_active_config_preserving_proxy(
    state: &ControlState,
    old_active: ActiveConfig,
    new_active: ActiveConfig,
) -> Result<()> {
    let old_proxy = old_active.proxy_runtime.clone();
    let (old_proxy_enabled, old_tun_enabled) = match old_proxy.as_ref() {
        Some(proxy) => {
            let snapshot = proxy.snapshot().await;
            (snapshot.enabled, snapshot.tun_enabled)
        }
        None => (false, false),
    };

    if (old_proxy_enabled || old_tun_enabled)
        && let Some(proxy) = old_proxy.as_ref()
    {
        proxy
            .stop_all()
            .await
            .context("failed to stop current proxy listeners before reloading config")?;
    }

    if let Some(new_proxy) = new_active.proxy_runtime.as_ref() {
        if old_proxy_enabled && let Err(err) = new_proxy.start().await {
            restore_proxy_runtime(old_proxy.as_ref(), old_proxy_enabled, old_tun_enabled).await;
            return Err(err).context("failed to restart proxy listeners after reloading config");
        }
        if old_tun_enabled && let Err(err) = new_proxy.set_tun_enabled(true).await {
            restore_proxy_runtime(old_proxy.as_ref(), old_proxy_enabled, old_tun_enabled).await;
            return Err(err).context("failed to restart TUN listeners after reloading config");
        }
    }

    if let Err(err) = apply_system_proxy_after_config_change(state, &new_active).await {
        if let Some(new_proxy) = new_active.proxy_runtime.as_ref() {
            let _ = new_proxy.stop_all().await;
        }
        restore_proxy_runtime(old_proxy.as_ref(), old_proxy_enabled, old_tun_enabled).await;
        return Err(err).context("failed to update system proxy after reloading config");
    }

    state.replace_active_config(new_active);
    Ok(())
}

async fn restore_proxy_runtime(
    proxy: Option<&Arc<ProxyRuntime>>,
    restore_proxy: bool,
    restore_tun: bool,
) {
    let Some(proxy) = proxy else {
        return;
    };
    if restore_proxy && let Err(err) = proxy.start().await {
        warn!(error = %err, "failed to restore previous proxy listeners");
    }
    if restore_tun && let Err(err) = proxy.set_tun_enabled(true).await {
        warn!(error = %err, "failed to restore previous TUN listeners");
    }
}

fn custom_route_rules_path(state: &ControlState) -> Option<PathBuf> {
    custom_route_rules_path_for_control_api(&state.control_api)
}

fn custom_route_rules_path_for_control_api(control_api: &ControlApiState) -> Option<PathBuf> {
    if let Some(state_dir) = control_api.state_dir.as_ref() {
        return Some(custom_route_rules_path_for_state_dir(state_dir));
    }
    control_api
        .state_file
        .as_ref()
        .map(|path| custom_route_rules_path_for_state_file(path))
}

fn custom_route_rules_path_for_state_file(state_file: &Path) -> PathBuf {
    let parent = state_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    custom_route_rules_path_for_state_dir(parent)
}

fn custom_route_rules_for_active(
    state: &ControlState,
    active: &ActiveConfig,
) -> Result<Vec<CustomRouteRule>> {
    custom_route_rules_for_config_path(
        active.config_path.as_deref(),
        custom_route_rules_path(state).as_deref(),
    )
}

fn custom_route_rules_for_config_path(
    config_path: Option<&Path>,
    store_path: Option<&Path>,
) -> Result<Vec<CustomRouteRule>> {
    let Some(config_path) = config_path else {
        return Ok(Vec::new());
    };
    let Some(store_path) = store_path else {
        return Ok(Vec::new());
    };
    let store = load_custom_route_rules_store(store_path)?;
    let profile_key = profile_key_for_config_path(Some(config_path));
    Ok(store
        .profiles
        .get(&profile_key)
        .map(|profile| profile.rules.clone())
        .unwrap_or_default())
}

fn load_custom_route_rules_store(path: &Path) -> Result<CustomRouteRulesStore> {
    if !path.exists() {
        return Ok(CustomRouteRulesStore::default());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read custom route rules {}", path.display()))?;
    let mut store: CustomRouteRulesStore = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse custom route rules {}", path.display()))?;
    if store.version == 0 {
        store.version = CUSTOM_ROUTE_RULES_VERSION;
    }
    Ok(store)
}

fn save_custom_route_rules_store(path: &Path, store: &CustomRouteRulesStore) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        crate::fs_security::create_private_dir_all(parent).with_context(|| {
            format!(
                "failed to create custom route rules dir {}",
                parent.display()
            )
        })?;
    }
    let text =
        serde_json::to_string_pretty(store).context("failed to serialize custom route rules")?;
    crate::fs_security::write_private_file(path, format!("{text}\n"))
        .with_context(|| format!("failed to write custom route rules {}", path.display()))
}

fn validate_custom_route_rule(state: &ControlState, rule: &RouteRuleConfig) -> Result<()> {
    let active = state.active_config();
    let config_path = active
        .config_path
        .as_ref()
        .context("custom route rules require an active config path")?;
    let config = Config::load(config_path)
        .with_context(|| format!("failed to load active config {}", config_path.display()))?;
    let mut test_config = config.clone();
    let mut rules = vec![rule.clone()];
    rules.extend(test_config.route.rules);
    test_config.route.rules = rules;
    validate_preview_config(&test_config, config_base_dir(config_path))
}

fn profile_key_for_config_path(config_path: Option<&Path>) -> String {
    let Some(config_path) = config_path else {
        return "default".to_string();
    };
    fs::canonicalize(config_path)
        .unwrap_or_else(|_| config_path.to_path_buf())
        .display()
        .to_string()
}

fn custom_route_rule_response(rule: CustomRouteRule) -> CustomRouteRuleResponse {
    CustomRouteRuleResponse {
        id: rule.id,
        summary: route_rule_summary(&rule.rule),
        rule: rule.rule,
    }
}

fn route_rule_summary(rule: &RouteRuleConfig) -> String {
    let mut matches = Vec::new();
    push_string_match(&mut matches, "inbound", &rule.inbound);
    push_network_match(&mut matches, &rule.network);
    push_string_match(&mut matches, "domain", &rule.domain);
    push_string_match(&mut matches, "domain_set", &rule.domain_set);
    push_string_match(&mut matches, "domain_suffix", &rule.domain_suffix);
    push_string_match(
        &mut matches,
        "domain_suffix_set",
        &rule.domain_suffix_set,
    );
    push_string_match(&mut matches, "domain_keyword", &rule.domain_keyword);
    push_string_match(
        &mut matches,
        "domain_keyword_set",
        &rule.domain_keyword_set,
    );
    push_string_match(&mut matches, "ip_cidr", &rule.ip_cidr);
    push_string_match(&mut matches, "process_name", &rule.process_name);
    push_string_match(&mut matches, "geoip", &rule.geoip);
    push_string_match(&mut matches, "ip_cidr_set", &rule.ip_cidr_set);
    push_port_match(&mut matches, &rule.port);
    push_string_match(&mut matches, "port_range", &rule.port_range);
    let conditions = if matches.is_empty() {
        "any".to_string()
    } else {
        matches.join("; ")
    };
    format!("{conditions} -> {}", rule.outbound)
}

fn push_string_match(matches: &mut Vec<String>, key: &str, values: &[String]) {
    if !values.is_empty() {
        matches.push(format!("{key}={}", values.join("|")));
    }
}

fn push_network_match(matches: &mut Vec<String>, values: &[RouteNetwork]) {
    if !values.is_empty() {
        let values = values
            .iter()
            .map(|network| match network {
                RouteNetwork::Tcp => "tcp",
                RouteNetwork::Udp => "udp",
            })
            .collect::<Vec<_>>();
        matches.push(format!("network={}", values.join("|")));
    }
}

fn push_port_match(matches: &mut Vec<String>, values: &[u16]) {
    if !values.is_empty() {
        matches.push(format!(
            "port={}",
            values
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join("|")
        ));
    }
}

fn logs_response(state: &ControlState, request: &HttpRequest) -> LogsResponse {
    let lines = query_param(&request.query, "lines")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(80)
        .clamp(1, 1000);
    let Some(log_file) = state.control_api.log_file.as_ref() else {
        return LogsResponse {
            log_file: None,
            lines,
            available: false,
            error: Some("control API is not attached to a log file".to_string()),
            content: String::new(),
        };
    };

    match crate::process_manager::read_log_tail(log_file, lines) {
        Ok(content) => LogsResponse {
            log_file: Some(log_file.display().to_string()),
            lines,
            available: true,
            error: None,
            content,
        },
        Err(err) => LogsResponse {
            log_file: Some(log_file.display().to_string()),
            lines,
            available: false,
            error: Some(format!("{err:#}")),
            content: String::new(),
        },
    }
}
