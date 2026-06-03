fn normalize_store(store: &mut SubscriptionStore, store_path: &Path) -> Result<()> {
    store.version = STORE_VERSION;
    for record in store.subscriptions.values_mut() {
        normalize_record(record, store_path)?;
    }
    Ok(())
}

fn normalize_record(record: &mut SubscriptionRecord, store_path: &Path) -> Result<()> {
    normalize_record_fields(record)?;
    let old_output = record.output.clone();
    let new_output = subscription_output_path_for_store(store_path, &record.name)?;
    migrate_existing_output(&old_output, &new_output)?;
    record.output = new_output;
    Ok(())
}

fn migrate_existing_output(old_output: &Path, new_output: &Path) -> Result<()> {
    if old_output == new_output || !old_output.exists() || new_output.exists() {
        return Ok(());
    }
    if let Some(parent) = new_output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        crate::fs_security::create_private_dir_all(parent)
            .with_context(|| format!("failed to create config output dir {}", parent.display()))?;
    }
    fs::copy(old_output, new_output).with_context(|| {
        format!(
            "failed to migrate subscription output {} to {}",
            old_output.display(),
            new_output.display()
        )
    })?;
    Ok(())
}

fn normalize_record_fields(record: &mut SubscriptionRecord) -> Result<()> {
    validate_name(&record.name)?;
    match record.source {
        SubscriptionSource::Remote => {
            validate_url(&record.url)?;
        }
        SubscriptionSource::UploadedFile => {
            if record.url.trim().is_empty() {
                record.url = uploaded_file_url(None);
            }
            record.auto_update = false;
        }
    }
    validate_timeout_ms(record.timeout_ms)?;
    if record.user_agent.is_empty() {
        record.user_agent = default_user_agent();
    }
    if record.update_interval_seconds == 0 {
        record.update_interval_seconds = default_update_interval_seconds();
    }
    validate_update_interval_seconds(record.update_interval_seconds)?;
    if !record.auto_update {
        record.next_update_unix = None;
    } else if record.next_update_unix.is_none() {
        record.next_update_unix = record.effective_next_update_unix();
    }
    Ok(())
}

fn apply_settings_patch(
    record: &mut SubscriptionRecord,
    patch: SubscriptionSettingsPatch,
) -> Result<()> {
    if let Some(timeout_ms) = patch.timeout_ms {
        validate_timeout_ms(timeout_ms)?;
        record.timeout_ms = timeout_ms;
    }
    if let Some(retries) = patch.retries {
        record.retries = retries;
    }
    if let Some(user_agent) = patch.user_agent {
        if user_agent.trim().is_empty() {
            bail!("user-agent must not be empty");
        }
        record.user_agent = user_agent;
    }
    if let Some(update_interval_seconds) = patch.update_interval_seconds {
        validate_update_interval_seconds(update_interval_seconds)?;
        record.update_interval_seconds = update_interval_seconds;
    }
    if let Some(auto_update) = patch.auto_update {
        if auto_update && !record.source.can_refresh() {
            bail!("subscription {} does not support auto-update", record.name);
        }
        record.auto_update = auto_update;
    }
    schedule_next_update(record, unix_now())
}

fn schedule_next_update(record: &mut SubscriptionRecord, now: u64) -> Result<()> {
    validate_update_interval_seconds(record.update_interval_seconds)?;
    record.next_update_unix = if record.auto_update {
        Some(now.saturating_add(record.update_interval_seconds))
    } else {
        None
    };
    Ok(())
}

fn subscription_output_path_for_store(store_path: &Path, name: &str) -> Result<PathBuf> {
    let state_dir = store_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("subscription store path must have a parent directory")?;
    subscription_output_path(state_dir, name)
}

fn next_auto_update_delay(store: &SubscriptionStore, now: u64) -> Duration {
    let next_due = store
        .subscriptions
        .values()
        .filter(|record| record.auto_update)
        .filter_map(SubscriptionRecord::effective_next_update_unix)
        .min();
    match next_due {
        Some(next_due) if next_due <= now => Duration::from_secs(0),
        Some(next_due) => Duration::from_secs(next_due.saturating_sub(now)),
        None => Duration::from_secs(MIN_UPDATE_INTERVAL_SECONDS),
    }
}

fn replace_file(path: &Path, contents: &str) -> Result<()> {
    crate::fs_security::replace_private_file(path, contents)
}
