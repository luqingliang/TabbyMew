async fn subscription_add_response(
    state: &ControlState,
    body: &[u8],
) -> Result<subscription_remote::SubscriptionApplyReport> {
    let request: ControlSubscriptionAddRequest =
        serde_json::from_slice(body).context("subscription add request body must be JSON")?;
    let runtime = subscription_runtime(state)?;
    subscription_remote::validate_name(&request.name)?;
    subscription_remote::validate_url(&request.url)?;
    let record = subscription_remote::SubscriptionRecord {
        output: runtime.output_path_for(&request.name)?,
        name: request.name,
        source: subscription_remote::SubscriptionSource::Remote,
        url: request.url,
        inbound_tag: request.inbound_tag,
        listen: request.listen,
        listen_port: request.listen_port,
        user_agent: request.user_agent,
        auto_update: request.auto_update,
        update_interval_seconds: subscription_remote::default_update_interval_seconds(),
        timeout_ms: subscription_remote::default_timeout_ms(),
        retries: subscription_remote::default_retries(),
        last_checked_unix: None,
        last_updated_unix: None,
        last_success_unix: None,
        next_update_unix: None,
        last_error: None,
        imported: None,
        warnings: Vec::new(),
        last_etag: None,
        last_modified: None,
        last_final_url: None,
    };
    let report = runtime
        .add(
            record,
            subscription_remote::SubscriptionRefreshOverrides::default(),
        )
        .await?;
    info!(
        subscription = %report.name,
        imported = report.imported,
        warnings = report.warnings.len(),
        "subscription added"
    );
    Ok(report)
}

async fn subscription_import_file_response(
    state: &ControlState,
    body: &[u8],
) -> Result<subscription_remote::SubscriptionApplyReport> {
    let request: ControlSubscriptionImportFileRequest = serde_json::from_slice(body)
        .context("subscription file import request body must be JSON")?;
    if request.input.trim().is_empty() {
        bail!("subscription file is empty");
    }
    let runtime = subscription_runtime(state)?;
    subscription_remote::validate_name(&request.name)?;
    let record = subscription_remote::SubscriptionRecord {
        output: runtime.output_path_for(&request.name)?,
        name: request.name,
        source: subscription_remote::SubscriptionSource::UploadedFile,
        url: subscription_remote::uploaded_file_url(request.filename.as_deref()),
        inbound_tag: request.inbound_tag,
        listen: request.listen,
        listen_port: request.listen_port,
        user_agent: subscription_remote::default_user_agent(),
        auto_update: false,
        update_interval_seconds: subscription_remote::default_update_interval_seconds(),
        timeout_ms: subscription_remote::default_timeout_ms(),
        retries: subscription_remote::default_retries(),
        last_checked_unix: None,
        last_updated_unix: None,
        last_success_unix: None,
        next_update_unix: None,
        last_error: None,
        imported: None,
        warnings: Vec::new(),
        last_etag: None,
        last_modified: None,
        last_final_url: None,
    };
    let report = runtime.import_uploaded(record, &request.input).await?;
    info!(
        subscription = %report.name,
        imported = report.imported,
        warnings = report.warnings.len(),
        "subscription file imported"
    );
    Ok(report)
}

async fn subscription_refresh_response(
    state: &ControlState,
    body: &[u8],
) -> Result<Vec<subscription_remote::SubscriptionRefreshOutcome>> {
    let request: ControlSubscriptionRefreshRequest =
        serde_json::from_slice(body).context("subscription refresh request body must be JSON")?;
    let runtime = subscription_runtime(state)?;
    if request.all && request.name.is_some() {
        bail!("subscription refresh accepts either name or all, not both");
    }
    if request.all {
        let outcomes = runtime
            .refresh_all(subscription_remote::SubscriptionRefreshOverrides::default())
            .await?;
        log_subscription_refresh_outcomes(&outcomes);
        return Ok(outcomes);
    }
    let name = request
        .name
        .as_deref()
        .context("subscription refresh requires name or all")?;
    let outcome = match runtime
        .refresh_one(
            name,
            subscription_remote::SubscriptionRefreshOverrides::default(),
        )
        .await
    {
        Ok(report) => subscription_remote::SubscriptionRefreshOutcome {
            name: name.to_string(),
            ok: true,
            report: Some(report),
            error: None,
        },
        Err(err) => subscription_remote::SubscriptionRefreshOutcome {
            name: name.to_string(),
            ok: false,
            report: None,
            error: Some(format!("{err:#}")),
        },
    };
    let outcomes = vec![outcome];
    log_subscription_refresh_outcomes(&outcomes);
    Ok(outcomes)
}

fn log_subscription_refresh_outcomes(outcomes: &[subscription_remote::SubscriptionRefreshOutcome]) {
    for outcome in outcomes {
        if outcome.ok {
            if let Some(report) = outcome.report.as_ref() {
                info!(
                    subscription = %outcome.name,
                    imported = report.imported,
                    warnings = report.warnings.len(),
                    "subscription refreshed"
                );
            } else {
                info!(subscription = %outcome.name, "subscription refreshed");
            }
        } else if let Some(error) = outcome.error.as_deref() {
            warn!(
                subscription = %outcome.name,
                error = %error,
                "subscription refresh failed"
            );
        }
    }
}

async fn subscription_activate_response(
    state: &ControlState,
    body: &[u8],
) -> Result<ControlStatusResponse> {
    let request: ControlSubscriptionNameRequest =
        serde_json::from_slice(body).context("subscription activate request body must be JSON")?;
    let runtime = subscription_runtime(state)?;
    let subscription = runtime.summary(&request.name).await?;
    let config_path = PathBuf::from(&subscription.output);
    let config = Config::load(&config_path).with_context(|| {
        format!(
            "failed to load subscription config {}",
            config_path.display()
        )
    })?;
    let new_active = build_active_config_from_config(
        Some(config_path.clone()),
        &config,
        config_base_dir(&config_path),
        state.metrics.clone(),
    )
    .with_context(|| {
        format!(
            "failed to prepare subscription config {}",
            config_path.display()
        )
    })?;
    apply_saved_routing_preferences(state, &new_active);

    let old_active = state.active_config();
    let old_proxy = old_active.proxy_runtime.clone();
    apply_proxy_preferences_or_inherit_current(state, old_proxy.as_ref(), &new_active).await;
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
            .context("failed to stop current proxy listeners before activating subscription")?;
    }

    if let Some(new_proxy) = new_active.proxy_runtime.as_ref() {
        if old_proxy_enabled && let Err(err) = new_proxy.start().await {
            restore_proxy_runtime(old_proxy.as_ref(), old_proxy_enabled, old_tun_enabled).await;
            bail!(
                "failed to activate subscription {} from {}: failed to start new proxy listeners: {err:#}; previous listeners restore was attempted",
                request.name,
                config_path.display()
            );
        }
        if old_tun_enabled && let Err(err) = new_proxy.set_tun_enabled(true).await {
            restore_proxy_runtime(old_proxy.as_ref(), old_proxy_enabled, old_tun_enabled).await;
            bail!(
                "failed to activate subscription {} from {}: failed to start new TUN listeners: {err:#}; previous listeners restore was attempted",
                request.name,
                config_path.display()
            );
        }
    }

    if let Err(err) = apply_system_proxy_after_config_change(state, &new_active).await {
        if let Some(new_proxy) = new_active.proxy_runtime.as_ref() {
            let _ = new_proxy.stop_all().await;
        }
        restore_proxy_runtime(old_proxy.as_ref(), old_proxy_enabled, old_tun_enabled).await;
        bail!(
            "failed to activate subscription {}: failed to update system proxy: {err:#}; previous listeners restore was attempted",
            request.name
        );
    }

    state.replace_active_config(new_active);
    update_process_state_config(state, &config_path);
    info!(
        subscription = %request.name,
        config = %config_path.display(),
        "subscription activated"
    );
    Ok(control_status_response(state).await)
}

async fn subscription_set_response(
    state: &ControlState,
    body: &[u8],
) -> Result<subscription_remote::SubscriptionSummary> {
    let request: ControlSubscriptionSetRequest =
        serde_json::from_slice(body).context("subscription set request body must be JSON")?;
    subscription_runtime(state)?
        .update_settings(
            &request.name,
            subscription_remote::SubscriptionSettingsPatch {
                auto_update: request.auto_update,
                ..subscription_remote::SubscriptionSettingsPatch::default()
            },
        )
        .await
}

async fn subscription_remove_response(
    state: &ControlState,
    body: &[u8],
) -> Result<subscription_remote::SubscriptionSummary> {
    let request: ControlSubscriptionNameRequest =
        serde_json::from_slice(body).context("subscription remove request body must be JSON")?;
    let summary = subscription_runtime(state)?.remove(&request.name).await?;
    info!(subscription = %summary.name, "subscription removed");
    Ok(summary)
}

fn subscription_runtime(state: &ControlState) -> Result<&subscription_remote::SubscriptionRuntime> {
    state
        .subscriptions
        .as_ref()
        .context("subscription runtime is not available")
}
