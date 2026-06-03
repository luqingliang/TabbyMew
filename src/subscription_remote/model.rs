#[derive(Debug, Clone)]
pub struct FetchOptions {
    pub timeout: Duration,
    pub retries: u8,
    pub user_agent: String,
}

#[derive(Debug, Clone)]
pub struct FetchResult {
    pub final_url: String,
    pub body: String,
    pub bytes: usize,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionStore {
    pub version: u32,
    #[serde(default)]
    pub subscriptions: BTreeMap<String, SubscriptionRecord>,
}

impl Default for SubscriptionStore {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            subscriptions: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionRecord {
    pub name: String,
    #[serde(default)]
    pub source: SubscriptionSource,
    pub url: String,
    pub output: PathBuf,
    pub inbound_tag: String,
    pub listen: String,
    pub listen_port: u16,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    #[serde(default = "default_auto_update")]
    pub auto_update: bool,
    #[serde(default = "default_update_interval_seconds")]
    pub update_interval_seconds: u64,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_retries")]
    pub retries: u8,
    #[serde(default)]
    pub last_checked_unix: Option<u64>,
    #[serde(default)]
    pub last_updated_unix: Option<u64>,
    #[serde(default)]
    pub last_success_unix: Option<u64>,
    #[serde(default)]
    pub next_update_unix: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub imported: Option<usize>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub last_etag: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
    #[serde(default)]
    pub last_final_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionSource {
    #[default]
    Remote,
    UploadedFile,
}

impl SubscriptionSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Remote => "remote",
            Self::UploadedFile => "uploaded_file",
        }
    }

    fn can_refresh(self) -> bool {
        matches!(self, Self::Remote)
    }
}

impl SubscriptionRecord {
    pub fn redacted_url(&self) -> String {
        match self.source {
            SubscriptionSource::Remote => redact_url(&self.url),
            SubscriptionSource::UploadedFile => self.url.clone(),
        }
    }

    pub fn effective_next_update_unix(&self) -> Option<u64> {
        if !self.auto_update {
            return None;
        }
        self.next_update_unix.or_else(|| {
            self.last_success_unix
                .map(|last_success| last_success.saturating_add(self.update_interval_seconds))
        })
    }

    pub fn is_due_for_auto_update(&self, now: u64) -> bool {
        self.auto_update
            && self.source.can_refresh()
            && self
                .effective_next_update_unix()
                .is_none_or(|next| next <= now)
    }
}

pub fn default_user_agent() -> String {
    DEFAULT_USER_AGENT.to_string()
}

pub fn default_auto_update() -> bool {
    true
}

pub fn default_update_interval_seconds() -> u64 {
    DEFAULT_UPDATE_INTERVAL_SECONDS
}

pub fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

pub fn default_retries() -> u8 {
    DEFAULT_RETRIES
}
