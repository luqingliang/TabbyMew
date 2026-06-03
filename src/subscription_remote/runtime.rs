#[derive(Debug, Clone)]
pub struct SubscriptionRuntime {
    store_path: PathBuf,
    lock: Arc<AsyncMutex<()>>,
}

impl SubscriptionRuntime {
    pub fn new(state_dir: impl AsRef<Path>) -> Self {
        Self::from_store_path(store_path(state_dir))
    }

    pub fn from_store_path(store_path: PathBuf) -> Self {
        Self {
            store_path,
            lock: Arc::new(AsyncMutex::new(())),
        }
    }

    pub fn store_path(&self) -> &Path {
        &self.store_path
    }

    pub fn output_path_for(&self, name: &str) -> Result<PathBuf> {
        subscription_output_path_for_store(&self.store_path, name)
    }

    pub async fn snapshot(&self) -> Result<SubscriptionStoreSnapshot> {
        let _guard = self.lock.lock().await;
        let store = load_store(&self.store_path)?;
        Ok(SubscriptionStoreSnapshot::from_store(
            &self.store_path,
            &store,
        ))
    }

    pub async fn summary(&self, name: &str) -> Result<SubscriptionSummary> {
        validate_name(name)?;
        let _guard = self.lock.lock().await;
        let store = load_store(&self.store_path)?;
        let record = store
            .subscriptions
            .get(name)
            .with_context(|| format!("subscription {name} is not defined"))?;
        Ok(SubscriptionSummary::from_record(record))
    }

    pub async fn add(
        &self,
        record: SubscriptionRecord,
        overrides: SubscriptionRefreshOverrides,
    ) -> Result<SubscriptionApplyReport> {
        let _guard = self.lock.lock().await;
        let mut store = load_store(&self.store_path)?;
        if store.subscriptions.contains_key(&record.name) {
            bail!("subscription {} already exists", record.name);
        }
        let mut record = record;
        record.output = self.output_path_for(&record.name)?;
        let applied = refresh_record(record, &overrides).await?;
        let report = applied.report();
        store
            .subscriptions
            .insert(applied.record.name.clone(), applied.record);
        save_store(&self.store_path, &store)?;
        Ok(report)
    }

    pub async fn import_uploaded(
        &self,
        record: SubscriptionRecord,
        text: &str,
    ) -> Result<SubscriptionApplyReport> {
        validate_name(&record.name)?;
        let _guard = self.lock.lock().await;
        let mut store = load_store(&self.store_path)?;
        if store.subscriptions.contains_key(&record.name) {
            bail!("subscription {} already exists", record.name);
        }
        let mut record = record;
        record.source = SubscriptionSource::UploadedFile;
        record.auto_update = false;
        record.next_update_unix = None;
        record.output = self.output_path_for(&record.name)?;
        let applied = import_record_text(record, text, None, None)
            .with_context(|| "failed to import uploaded subscription file")?;
        let report = applied.report();
        store
            .subscriptions
            .insert(applied.record.name.clone(), applied.record);
        save_store(&self.store_path, &store)?;
        Ok(report)
    }

    pub async fn remove(&self, name: &str) -> Result<SubscriptionSummary> {
        validate_name(name)?;
        let _guard = self.lock.lock().await;
        let mut store = load_store(&self.store_path)?;
        let record = store
            .subscriptions
            .remove(name)
            .with_context(|| format!("subscription {name} is not defined"))?;
        save_store(&self.store_path, &store)?;
        Ok(SubscriptionSummary::from_record(&record))
    }

    pub async fn update_settings(
        &self,
        name: &str,
        patch: SubscriptionSettingsPatch,
    ) -> Result<SubscriptionSummary> {
        validate_name(name)?;
        let _guard = self.lock.lock().await;
        let mut store = load_store(&self.store_path)?;
        let record = store
            .subscriptions
            .get_mut(name)
            .with_context(|| format!("subscription {name} is not defined"))?;
        apply_settings_patch(record, patch)?;
        let summary = SubscriptionSummary::from_record(record);
        save_store(&self.store_path, &store)?;
        Ok(summary)
    }

    pub async fn refresh_one(
        &self,
        name: &str,
        overrides: SubscriptionRefreshOverrides,
    ) -> Result<SubscriptionApplyReport> {
        validate_name(name)?;
        let _guard = self.lock.lock().await;
        let mut store = load_store(&self.store_path)?;
        let record = store
            .subscriptions
            .get(name)
            .cloned()
            .with_context(|| format!("subscription {name} is not defined"))?;
        match refresh_record(record, &overrides).await {
            Ok(applied) => {
                let report = applied.report();
                store
                    .subscriptions
                    .insert(applied.record.name.clone(), applied.record);
                save_store(&self.store_path, &store)?;
                Ok(report)
            }
            Err(err) => {
                let error = format!("{err:#}");
                if let Some(record) = store.subscriptions.get_mut(name) {
                    mark_refresh_failure(record, error.clone())?;
                }
                save_store(&self.store_path, &store)?;
                Err(anyhow!(error))
            }
        }
    }

    pub async fn refresh_all(
        &self,
        overrides: SubscriptionRefreshOverrides,
    ) -> Result<Vec<SubscriptionRefreshOutcome>> {
        let _guard = self.lock.lock().await;
        let mut store = load_store(&self.store_path)?;
        let names = store
            .subscriptions
            .iter()
            .filter(|(_, record)| record.source.can_refresh())
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        let mut outcomes = Vec::new();
        for name in names {
            let Some(record) = store.subscriptions.get(&name).cloned() else {
                continue;
            };
            match refresh_record(record, &overrides).await {
                Ok(applied) => {
                    let report = applied.report();
                    store
                        .subscriptions
                        .insert(applied.record.name.clone(), applied.record);
                    outcomes.push(SubscriptionRefreshOutcome {
                        name,
                        ok: true,
                        report: Some(report),
                        error: None,
                    });
                }
                Err(err) => {
                    let error = format!("{err:#}");
                    if let Some(record) = store.subscriptions.get_mut(&name) {
                        mark_refresh_failure(record, error.clone())?;
                    }
                    outcomes.push(SubscriptionRefreshOutcome {
                        name,
                        ok: false,
                        report: None,
                        error: Some(error),
                    });
                }
            }
        }
        save_store(&self.store_path, &store)?;
        Ok(outcomes)
    }

    pub async fn refresh_due(&self) -> Result<Vec<SubscriptionRefreshOutcome>> {
        let _guard = self.lock.lock().await;
        let mut store = load_store(&self.store_path)?;
        let now = unix_now();
        let names = store
            .subscriptions
            .iter()
            .filter(|(_, record)| record.is_due_for_auto_update(now))
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        let mut outcomes = Vec::new();
        for name in names {
            let Some(record) = store.subscriptions.get(&name).cloned() else {
                continue;
            };
            match refresh_record(record, &SubscriptionRefreshOverrides::default()).await {
                Ok(applied) => {
                    let report = applied.report();
                    store
                        .subscriptions
                        .insert(applied.record.name.clone(), applied.record);
                    outcomes.push(SubscriptionRefreshOutcome {
                        name,
                        ok: true,
                        report: Some(report),
                        error: None,
                    });
                }
                Err(err) => {
                    let error = format!("{err:#}");
                    if let Some(record) = store.subscriptions.get_mut(&name) {
                        mark_refresh_failure(record, error.clone())?;
                    }
                    outcomes.push(SubscriptionRefreshOutcome {
                        name,
                        ok: false,
                        report: None,
                        error: Some(error),
                    });
                }
            }
        }
        if !outcomes.is_empty() {
            save_store(&self.store_path, &store)?;
        }
        Ok(outcomes)
    }

    pub async fn next_auto_update_delay(&self) -> Result<Duration> {
        let _guard = self.lock.lock().await;
        let store = load_store(&self.store_path)?;
        Ok(next_auto_update_delay(&store, unix_now()))
    }
}

pub async fn run_auto_update_loop(
    runtime: SubscriptionRuntime,
    shutdown: Arc<tokio::sync::Notify>,
) {
    loop {
        match runtime.refresh_due().await {
            Ok(outcomes) => {
                for outcome in outcomes {
                    if outcome.ok {
                        if let Some(report) = outcome.report.as_ref() {
                            info!(
                                subscription = %outcome.name,
                                imported = report.imported,
                                warnings = report.warnings.len(),
                                "subscription auto-update completed"
                            );
                        } else {
                            info!(subscription = %outcome.name, "subscription auto-update completed");
                        }
                    } else if let Some(error) = outcome.error {
                        warn!(
                            subscription = %outcome.name,
                            error = %error,
                            "subscription auto-update failed"
                        );
                    }
                }
            }
            Err(err) => warn!(error = %err, "subscription auto-update scan failed"),
        }

        let delay = match runtime.next_auto_update_delay().await {
            Ok(delay) => delay,
            Err(err) => {
                warn!(error = %err, "failed to calculate next subscription auto-update delay");
                Duration::from_secs(MIN_UPDATE_INTERVAL_SECONDS)
            }
        };

        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = shutdown.notified() => break,
        }
    }
}

pub async fn refresh_record(
    mut record: SubscriptionRecord,
    overrides: &SubscriptionRefreshOverrides,
) -> Result<AppliedSubscription> {
    normalize_record_fields(&mut record)?;
    if !record.source.can_refresh() {
        bail!("subscription {} cannot be refreshed", record.name);
    }
    let timeout_ms = overrides.timeout_ms.unwrap_or(record.timeout_ms);
    validate_timeout_ms(timeout_ms)?;
    let retries = overrides.retries.unwrap_or(record.retries);
    let fetch = fetch_text(
        &record.url,
        &FetchOptions {
            timeout: Duration::from_millis(timeout_ms),
            retries,
            user_agent: record.user_agent.clone(),
        },
    )
    .await
    .with_context(|| format!("failed to fetch subscription {}", record.name))?;
    let mut applied = import_record_text(
        record,
        &fetch.body,
        Some(fetch.final_url.clone()),
        Some(fetch.bytes),
    )
    .with_context(|| "failed to apply fetched subscription")?;
    applied.record.last_etag = fetch.etag;
    applied.record.last_modified = fetch.last_modified;
    Ok(applied)
}

fn import_record_text(
    mut record: SubscriptionRecord,
    text: &str,
    final_url: Option<String>,
    fetched_bytes: Option<usize>,
) -> Result<AppliedSubscription> {
    normalize_record_fields(&mut record)?;
    let result = subscription::import_from_text(
        text,
        subscription::ImportOptions {
            inbound_tag: record.inbound_tag.clone(),
            listen: record.listen.clone(),
            listen_port: record.listen_port,
        },
    )
    .with_context(|| format!("failed to import subscription {}", record.name))?;
    validate_generated_config(&result.config)
        .with_context(|| format!("subscription {} produced an invalid config", record.name))?;
    write_imported_config(&record.output, &result.config).with_context(|| {
        format!(
            "failed to write subscription output {}",
            record.output.display()
        )
    })?;

    let now = unix_now();
    let final_url = final_url.unwrap_or_else(|| record.redacted_url());
    record.last_checked_unix = Some(now);
    record.last_updated_unix = Some(now);
    record.last_success_unix = Some(now);
    record.last_error = None;
    record.imported = Some(result.imported);
    record.warnings = result.warnings.clone();
    record.last_etag = None;
    record.last_modified = None;
    record.last_final_url = Some(final_url.clone());
    schedule_next_update(&mut record, now)?;
    Ok(AppliedSubscription {
        record,
        result,
        fetched_bytes: fetched_bytes.unwrap_or(text.len()),
        final_url,
    })
}

pub fn mark_refresh_failure(record: &mut SubscriptionRecord, error: String) -> Result<()> {
    let now = unix_now();
    record.last_checked_unix = Some(now);
    record.last_updated_unix = Some(now);
    record.last_error = Some(error);
    schedule_next_update(record, now)
}

pub fn write_imported_config(path: &Path, config: &Config) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        crate::fs_security::create_private_dir_all(parent)
            .with_context(|| format!("failed to create config output dir {}", parent.display()))?;
    }
    let output =
        serde_json::to_string_pretty(config).context("failed to serialize imported config")?;
    replace_file(path, &format!("{output}\n"))
}

pub fn validate_generated_config(config: &Config) -> Result<()> {
    config
        .validate()
        .context("configuration validation failed")?;
    outbound::validate_configs(&config.outbounds).context("outbound validation failed")?;
    if let Some(dns) = config.dns.as_ref() {
        router::Router::from_config_with_policy_groups_dns(
            &config.outbounds,
            &config.policy_groups,
            &config.route,
            Some(dns),
        )
        .context("router validation failed")?;
    } else {
        router::Router::from_config_with_policy_groups(
            &config.outbounds,
            &config.policy_groups,
            &config.route,
        )
        .context("router validation failed")?;
    }
    inbound::validate_configs(&config.inbounds).context("inbound validation failed")?;
    Ok(())
}

pub fn migrate_active_subscription_config_defaults(
    state_dir: &Path,
    config_path: &Path,
) -> Result<bool> {
    let store = load_store(store_path(state_dir))?;
    if !store
        .subscriptions
        .values()
        .any(|record| same_existing_path(&record.output, config_path))
    {
        return Ok(false);
    }
    ensure_subscription_config_runtime_defaults(config_path)
}

pub fn ensure_subscription_config_runtime_defaults(config_path: &Path) -> Result<bool> {
    let (mut config, legacy_fields_migrated) =
        load_subscription_config_for_migration(config_path).with_context(|| {
            format!(
                "failed to load subscription config {}",
                config_path.display()
            )
        })?;
    let default_tun_added = config.ensure_default_tun_inbound();
    if !legacy_fields_migrated && !default_tun_added {
        return Ok(false);
    }
    validate_generated_config(&config).with_context(|| {
        format!(
            "legacy subscription config {} became invalid after adding default TUN inbound",
            config_path.display()
        )
    })?;
    write_imported_config(config_path, &config).with_context(|| {
        format!(
            "failed to update legacy subscription config {}",
            config_path.display()
        )
    })?;
    info!(
        config = %config_path.display(),
        legacy_fields_migrated,
        default_tun_added,
        "migrated legacy subscription config"
    );
    Ok(true)
}

fn load_subscription_config_for_migration(config_path: &Path) -> Result<(Config, bool)> {
    let text = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read config {}", config_path.display()))?;
    let mut value: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse JSON config {}", config_path.display()))?;
    let legacy_fields_migrated = migrate_legacy_subscription_config_fields(&mut value);
    let config = serde_json::from_value(value)
        .with_context(|| format!("failed to parse JSON config {}", config_path.display()))?;
    Ok((config, legacy_fields_migrated))
}

fn migrate_legacy_subscription_config_fields(value: &mut serde_json::Value) -> bool {
    let mut changed = false;
    changed |= migrate_legacy_dns_config(value);
    changed |= migrate_legacy_inbounds(value);
    changed |= migrate_legacy_top_level_field(value, "proxy_groups", "policy_groups");
    changed |= migrate_legacy_top_level_field(value, "proxy-groups", "policy_groups");
    changed
}

fn migrate_legacy_inbounds(value: &mut serde_json::Value) -> bool {
    let Some(inbounds) = value.get_mut("inbounds").and_then(|value| value.as_array_mut()) else {
        return false;
    };

    let mut changed = false;
    for inbound in inbounds {
        let Some(inbound) = inbound.as_object_mut() else {
            continue;
        };
        if inbound.get("type").and_then(|value| value.as_str()) == Some("mixed") {
            inbound.insert(
                "type".to_string(),
                serde_json::Value::String("hybrid".to_string()),
            );
            changed = true;
        }
        changed |= migrate_legacy_object_field(inbound, "tcp_timeout", "tcp_timeout_seconds");
        changed |= migrate_legacy_object_field(inbound, "udp_timeout", "udp_timeout_seconds");
    }
    changed
}

fn migrate_legacy_dns_config(value: &mut serde_json::Value) -> bool {
    let Some(dns) = value.get_mut("dns") else {
        return false;
    };
    let Some(dns) = dns.as_object_mut() else {
        return false;
    };

    let mut changed = false;
    let legacy_nameservers = dns.remove("nameservers").or_else(|| dns.remove("nameserver"));
    if let Some(nameservers) = legacy_nameservers {
        changed = true;
        if !dns.contains_key("servers")
            && let Some(servers) = legacy_dns_servers(nameservers)
        {
            dns.insert("servers".to_string(), servers);
        }
    }

    for key in [
        "listen",
        "ipv6",
        "use_hosts",
        "use-hosts",
        "fake_ip_range",
        "fake-ip-range",
        "fake_ip_filter",
        "fake-ip-filter",
        "enhanced_mode",
        "enhanced-mode",
        "default_nameserver",
        "default-nameserver",
        "fallback",
        "fallback_filter",
        "fallback-filter",
        "nameserver_policy",
        "nameserver-policy",
    ] {
        changed |= dns.remove(key).is_some();
    }

    changed
}

fn legacy_dns_servers(value: serde_json::Value) -> Option<serde_json::Value> {
    let servers = value
        .as_array()?
        .iter()
        .filter_map(|server| server.as_str())
        .filter_map(legacy_dns_server)
        .map(serde_json::Value::String)
        .collect::<Vec<_>>();
    (!servers.is_empty()).then_some(serde_json::Value::Array(servers))
}

fn legacy_dns_server(server: &str) -> Option<String> {
    let server = server.trim();
    if server.is_empty() {
        return None;
    }
    if let Some(server) = server.strip_prefix("udp://") {
        return Some(server.to_string());
    }
    if server.contains("://") {
        return None;
    }
    Some(server.to_string())
}

fn migrate_legacy_object_field(
    object: &mut serde_json::Map<String, serde_json::Value>,
    legacy_key: &str,
    native_key: &str,
) -> bool {
    let Some(legacy_value) = object.remove(legacy_key) else {
        return false;
    };
    object.entry(native_key.to_string()).or_insert(legacy_value);
    true
}

fn migrate_legacy_top_level_field(
    value: &mut serde_json::Value,
    legacy_key: &str,
    native_key: &str,
) -> bool {
    let Some(root) = value.as_object_mut() else {
        return false;
    };
    let Some(legacy_value) = root.remove(legacy_key) else {
        return false;
    };
    root.entry(native_key.to_string()).or_insert(legacy_value);
    true
}

fn same_existing_path(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

pub fn validate_timeout_ms(timeout_ms: u64) -> Result<()> {
    if timeout_ms == 0 {
        bail!("timeout-ms must be greater than 0");
    }
    Ok(())
}

pub fn validate_update_interval_seconds(seconds: u64) -> Result<()> {
    if seconds < MIN_UPDATE_INTERVAL_SECONDS {
        bail!("update interval must be at least {MIN_UPDATE_INTERVAL_SECONDS} seconds");
    }
    Ok(())
}

pub fn validate_url(url: &str) -> Result<Url> {
    let url = Url::parse(url)
        .with_context(|| format!("subscription URL {} is invalid", redact_url(url)))?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => bail!("subscription URL scheme {scheme} is not supported"),
    }
    if url.host_str().is_none() {
        bail!("subscription URL is missing host");
    }
    Ok(url)
}

pub fn uploaded_file_url(file_name: Option<&str>) -> String {
    let file_name = file_name
        .and_then(|value| {
            value
                .rsplit(['/', '\\'])
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .unwrap_or("uploaded.yaml");
    let clean = file_name
        .chars()
        .filter(|ch| !ch.is_ascii_control())
        .collect::<String>();
    format!(
        "uploaded-file:{}",
        if clean.is_empty() {
            "uploaded.yaml"
        } else {
            clean.as_str()
        }
    )
}
