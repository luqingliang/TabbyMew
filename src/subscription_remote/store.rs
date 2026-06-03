pub fn store_path(state_dir: impl AsRef<Path>) -> PathBuf {
    state_dir.as_ref().join(STORE_FILE)
}

pub fn subscription_output_path(state_dir: impl AsRef<Path>, name: &str) -> Result<PathBuf> {
    validate_name(name)?;
    Ok(state_dir
        .as_ref()
        .join(PROFILES_DIR)
        .join(SUBSCRIPTION_PROFILES_DIR)
        .join(format!("{name}.json")))
}

pub fn load_store(path: impl AsRef<Path>) -> Result<SubscriptionStore> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(SubscriptionStore::default());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read subscription store {}", path.display()))?;
    let mut store: SubscriptionStore = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse subscription store {}", path.display()))?;
    if store.version == 0 {
        store.version = STORE_VERSION;
    }
    normalize_store(&mut store, path)?;
    Ok(store)
}

pub fn save_store(path: impl AsRef<Path>, store: &SubscriptionStore) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        crate::fs_security::create_private_dir_all(parent).with_context(|| {
            format!(
                "failed to create subscription store dir {}",
                parent.display()
            )
        })?;
    }
    let text =
        serde_json::to_string_pretty(store).context("failed to serialize subscription store")?;
    replace_file(path, &format!("{text}\n"))
        .with_context(|| format!("failed to write subscription store {}", path.display()))
}

pub fn validate_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("subscription name is empty");
    }
    if name != name.trim() {
        bail!("subscription name must not contain leading or trailing whitespace");
    }
    if name == "." || name == ".." {
        bail!("subscription name must not be . or ..");
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("subscription name must contain only ASCII letters, digits, '-', '_', or '.'");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionStoreSnapshot {
    pub store: String,
    pub subscriptions: Vec<SubscriptionSummary>,
}

impl SubscriptionStoreSnapshot {
    pub fn from_store(path: &Path, store: &SubscriptionStore) -> Self {
        Self {
            store: path.display().to_string(),
            subscriptions: store
                .subscriptions
                .values()
                .map(SubscriptionSummary::from_record)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionSummary {
    pub name: String,
    pub source: SubscriptionSource,
    pub url: String,
    pub output: String,
    pub auto_update: bool,
    pub update_interval_seconds: u64,
    pub timeout_ms: u64,
    pub retries: u8,
    pub last_checked_unix: Option<u64>,
    pub last_updated_unix: Option<u64>,
    pub last_success_unix: Option<u64>,
    pub next_update_unix: Option<u64>,
    pub last_error: Option<String>,
    pub imported: Option<usize>,
    pub warnings: usize,
    pub last_etag: Option<String>,
    pub last_modified: Option<String>,
    pub last_final_url: Option<String>,
}

impl SubscriptionSummary {
    pub fn from_record(record: &SubscriptionRecord) -> Self {
        Self {
            name: record.name.clone(),
            source: record.source,
            url: record.redacted_url(),
            output: record.output.display().to_string(),
            auto_update: record.auto_update,
            update_interval_seconds: record.update_interval_seconds,
            timeout_ms: record.timeout_ms,
            retries: record.retries,
            last_checked_unix: record.last_checked_unix,
            last_updated_unix: record.last_updated_unix,
            last_success_unix: record.last_success_unix,
            next_update_unix: record.effective_next_update_unix(),
            last_error: record.last_error.clone(),
            imported: record.imported,
            warnings: record.warnings.len(),
            last_etag: record.last_etag.clone(),
            last_modified: record.last_modified.clone(),
            last_final_url: record.last_final_url.as_ref().map(|url| redact_url(url)),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionApplyReport {
    pub name: String,
    pub source: SubscriptionSource,
    pub url: String,
    pub output: String,
    pub fetched_bytes: usize,
    pub final_url: String,
    pub imported: usize,
    pub warnings: Vec<String>,
    pub route_final: String,
    pub policy_groups: usize,
    pub rules: usize,
    pub last_success_unix: Option<u64>,
    pub next_update_unix: Option<u64>,
}

#[derive(Debug)]
pub struct AppliedSubscription {
    pub record: SubscriptionRecord,
    pub result: subscription::ImportResult,
    pub fetched_bytes: usize,
    pub final_url: String,
}

impl AppliedSubscription {
    pub fn report(&self) -> SubscriptionApplyReport {
        SubscriptionApplyReport {
            name: self.record.name.clone(),
            source: self.record.source,
            url: self.record.redacted_url(),
            output: self.record.output.display().to_string(),
            fetched_bytes: self.fetched_bytes,
            final_url: match self.record.source {
                SubscriptionSource::Remote => redact_url(&self.final_url),
                SubscriptionSource::UploadedFile => self.final_url.clone(),
            },
            imported: self.result.imported,
            warnings: self.result.warnings.clone(),
            route_final: self.result.config.route.final_outbound.clone(),
            policy_groups: self.result.config.policy_groups.len(),
            rules: self.result.config.route.rules.len(),
            last_success_unix: self.record.last_success_unix,
            next_update_unix: self.record.effective_next_update_unix(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionRefreshOutcome {
    pub name: String,
    pub ok: bool,
    pub report: Option<SubscriptionApplyReport>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SubscriptionRefreshOverrides {
    pub timeout_ms: Option<u64>,
    pub retries: Option<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct SubscriptionSettingsPatch {
    pub auto_update: Option<bool>,
    pub update_interval_seconds: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub retries: Option<u8>,
    pub user_agent: Option<String>,
}
