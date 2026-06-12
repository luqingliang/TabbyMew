#[derive(Debug)]
pub struct RuntimeMetrics {
    started_at: Instant,
    next_tcp_connection_id: AtomicU64,
    active_tcp_connections_total: AtomicU64,
    active_tcp_connections_max: AtomicU64,
    tcp_connection_limit_reached_total: AtomicU64,
    route_selections_total: AtomicU64,
    route_tcp: AtomicU64,
    route_udp: AtomicU64,
    proxied_upload_bytes: AtomicU64,
    proxied_download_bytes: AtomicU64,
    active_tcp_connections: Mutex<BTreeMap<u64, ActiveTcpConnection>>,
    active_tcp_by_inbound: Mutex<BTreeMap<String, u64>>,
    active_tcp_by_outbound: Mutex<BTreeMap<String, u64>>,
    tcp_connection_limit_reached_by_context: Mutex<BTreeMap<String, u64>>,
    route_by_inbound: Mutex<BTreeMap<String, u64>>,
    route_by_outbound: Mutex<BTreeMap<String, u64>>,
}

#[derive(Debug)]
struct ActiveTcpConnection {
    started_at: Instant,
    inbound_tag: String,
    outbound_tag: Option<String>,
}

#[derive(Debug)]
pub struct TcpConnectionActivity {
    metrics: Arc<RuntimeMetrics>,
    id: u64,
}

impl RuntimeMetrics {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            next_tcp_connection_id: AtomicU64::new(1),
            active_tcp_connections_total: AtomicU64::new(0),
            active_tcp_connections_max: AtomicU64::new(0),
            tcp_connection_limit_reached_total: AtomicU64::new(0),
            route_selections_total: AtomicU64::new(0),
            route_tcp: AtomicU64::new(0),
            route_udp: AtomicU64::new(0),
            proxied_upload_bytes: AtomicU64::new(0),
            proxied_download_bytes: AtomicU64::new(0),
            active_tcp_connections: Mutex::new(BTreeMap::new()),
            active_tcp_by_inbound: Mutex::new(BTreeMap::new()),
            active_tcp_by_outbound: Mutex::new(BTreeMap::new()),
            tcp_connection_limit_reached_by_context: Mutex::new(BTreeMap::new()),
            route_by_inbound: Mutex::new(BTreeMap::new()),
            route_by_outbound: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn track_tcp_connection(self: &Arc<Self>, inbound_tag: &str) -> TcpConnectionActivity {
        let id = self.next_tcp_connection_id.fetch_add(1, Ordering::Relaxed);
        self.active_tcp_connections
            .lock()
            .expect("active_tcp_connections metrics mutex must not be poisoned")
            .insert(
                id,
                ActiveTcpConnection {
                    started_at: Instant::now(),
                    inbound_tag: inbound_tag.to_string(),
                    outbound_tag: None,
                },
            );
        increment_counter(&self.active_tcp_by_inbound, inbound_tag);
        let active = self
            .active_tcp_connections_total
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        update_atomic_max(&self.active_tcp_connections_max, active);

        TcpConnectionActivity {
            metrics: self.clone(),
            id,
        }
    }

    pub fn record_tcp_connection_limit_reached(&self, context: &str) {
        self.tcp_connection_limit_reached_total
            .fetch_add(1, Ordering::Relaxed);
        increment_counter(&self.tcp_connection_limit_reached_by_context, context);
    }

    pub fn record_route(&self, session: &Session, outbound_tag: &str) {
        self.route_selections_total.fetch_add(1, Ordering::Relaxed);
        match session.network {
            Network::Tcp => {
                self.route_tcp.fetch_add(1, Ordering::Relaxed);
            }
            Network::Udp => {
                self.route_udp.fetch_add(1, Ordering::Relaxed);
            }
        }

        increment_counter(&self.route_by_inbound, &session.inbound_tag);
        increment_counter(&self.route_by_outbound, outbound_tag);
    }

    fn record_tcp_connection_outbound(&self, id: u64, outbound_tag: &str) {
        let previous = {
            let mut active = self
                .active_tcp_connections
                .lock()
                .expect("active_tcp_connections metrics mutex must not be poisoned");
            let Some(connection) = active.get_mut(&id) else {
                return;
            };
            connection.outbound_tag.replace(outbound_tag.to_string())
        };
        if previous.as_deref() == Some(outbound_tag) {
            return;
        }
        if let Some(previous) = previous {
            decrement_counter(&self.active_tcp_by_outbound, &previous);
        }
        increment_counter(&self.active_tcp_by_outbound, outbound_tag);
    }

    fn finish_tcp_connection(&self, id: u64) {
        let Some(connection) = self
            .active_tcp_connections
            .lock()
            .expect("active_tcp_connections metrics mutex must not be poisoned")
            .remove(&id)
        else {
            return;
        };
        self.active_tcp_connections_total
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                Some(active.saturating_sub(1))
            })
            .ok();
        decrement_counter(&self.active_tcp_by_inbound, &connection.inbound_tag);
        if let Some(outbound_tag) = connection.outbound_tag {
            decrement_counter(&self.active_tcp_by_outbound, &outbound_tag);
        }
    }

    pub fn record_proxied_upload(&self, bytes: u64) {
        self.proxied_upload_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_proxied_download(&self, bytes: u64) {
        self.proxied_download_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> CountersSnapshot {
        let proxied_upload_bytes = self.proxied_upload_bytes.load(Ordering::Relaxed);
        let proxied_download_bytes = self.proxied_download_bytes.load(Ordering::Relaxed);
        let active_tcp_connection_oldest_age_seconds = self
            .active_tcp_connections
            .lock()
            .expect("active_tcp_connections metrics mutex must not be poisoned")
            .values()
            .map(|connection| connection.started_at.elapsed().as_secs())
            .max();
        CountersSnapshot {
            uptime_seconds: self.started_at.elapsed().as_secs(),
            active_tcp_connections_total: self
                .active_tcp_connections_total
                .load(Ordering::Relaxed),
            active_tcp_connections_max: self.active_tcp_connections_max.load(Ordering::Relaxed),
            active_tcp_connection_oldest_age_seconds,
            tcp_connection_limit_reached_total: self
                .tcp_connection_limit_reached_total
                .load(Ordering::Relaxed),
            route_selections_total: self.route_selections_total.load(Ordering::Relaxed),
            route_selections_tcp: self.route_tcp.load(Ordering::Relaxed),
            route_selections_udp: self.route_udp.load(Ordering::Relaxed),
            proxied_upload_bytes,
            proxied_download_bytes,
            proxied_total_bytes: proxied_upload_bytes.saturating_add(proxied_download_bytes),
            active_tcp_connections_by_inbound: self
                .active_tcp_by_inbound
                .lock()
                .expect("active_tcp_by_inbound metrics mutex must not be poisoned")
                .clone(),
            active_tcp_connections_by_outbound: self
                .active_tcp_by_outbound
                .lock()
                .expect("active_tcp_by_outbound metrics mutex must not be poisoned")
                .clone(),
            tcp_connection_limit_reached_by_context: self
                .tcp_connection_limit_reached_by_context
                .lock()
                .expect("tcp_connection_limit_reached_by_context metrics mutex must not be poisoned")
                .clone(),
            route_selections_by_inbound: self
                .route_by_inbound
                .lock()
                .expect("route_by_inbound metrics mutex must not be poisoned")
                .clone(),
            route_selections_by_outbound: self
                .route_by_outbound
                .lock()
                .expect("route_by_outbound metrics mutex must not be poisoned")
                .clone(),
        }
    }
}

impl TcpConnectionActivity {
    pub fn record_outbound(&self, outbound_tag: &str) {
        self.metrics
            .record_tcp_connection_outbound(self.id, outbound_tag);
    }
}

impl Drop for TcpConnectionActivity {
    fn drop(&mut self) {
        self.metrics.finish_tcp_connection(self.id);
    }
}

fn update_atomic_max(max: &AtomicU64, value: u64) {
    let mut current = max.load(Ordering::Relaxed);
    while value > current {
        match max.compare_exchange(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(next) => current = next,
        }
    }
}

fn decrement_counter(counters: &Mutex<BTreeMap<String, u64>>, key: &str) {
    let mut counters = counters
        .lock()
        .expect("runtime metrics mutex must not be poisoned");
    if let Some(value) = counters.get_mut(key) {
        *value = value.saturating_sub(1);
        if *value == 0 {
            counters.remove(key);
        }
    }
}

impl Default for RuntimeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CountersSnapshot {
    pub uptime_seconds: u64,
    pub active_tcp_connections_total: u64,
    pub active_tcp_connections_max: u64,
    pub active_tcp_connection_oldest_age_seconds: Option<u64>,
    pub tcp_connection_limit_reached_total: u64,
    pub route_selections_total: u64,
    pub route_selections_tcp: u64,
    pub route_selections_udp: u64,
    pub proxied_upload_bytes: u64,
    pub proxied_download_bytes: u64,
    pub proxied_total_bytes: u64,
    pub active_tcp_connections_by_inbound: BTreeMap<String, u64>,
    pub active_tcp_connections_by_outbound: BTreeMap<String, u64>,
    pub tcp_connection_limit_reached_by_context: BTreeMap<String, u64>,
    pub route_selections_by_inbound: BTreeMap<String, u64>,
    pub route_selections_by_outbound: BTreeMap<String, u64>,
}

#[derive(Clone)]
pub struct ControlState {
    active: Arc<RwLock<ActiveConfig>>,
    metrics: Arc<RuntimeMetrics>,
    control_api: Arc<ControlApiState>,
    shutdown: Option<Arc<Notify>>,
    subscriptions: Option<subscription_remote::SubscriptionRuntime>,
}

#[derive(Clone)]
struct ActiveConfig {
    config_path: Option<PathBuf>,
    summary: ConfigSummary,
    custom_route_rules: Vec<CustomRouteRule>,
    subscription_route_rules: Vec<String>,
    router: Option<router::Router>,
    proxy_runtime: Option<Arc<ProxyRuntime>>,
}

impl ActiveConfig {
    #[cfg(test)]
    fn summary_only(summary: ConfigSummary) -> Self {
        Self {
            config_path: None,
            subscription_route_rules: summary.route_rules.clone(),
            summary,
            custom_route_rules: Vec::new(),
            router: None,
            proxy_runtime: None,
        }
    }

    fn with_runtime(
        config_path: Option<PathBuf>,
        effective_config: &Config,
        custom_route_rules: Vec<CustomRouteRule>,
        subscription_route_rules: Vec<String>,
        router: router::Router,
        proxy_runtime: Arc<ProxyRuntime>,
    ) -> Self {
        Self {
            config_path,
            summary: effective_config.summary(),
            custom_route_rules,
            subscription_route_rules,
            router: Some(router),
            proxy_runtime: Some(proxy_runtime),
        }
    }
}

impl ControlState {
    #[cfg(test)]
    pub fn new(summary: ConfigSummary, metrics: Arc<RuntimeMetrics>) -> Self {
        Self {
            active: Arc::new(RwLock::new(ActiveConfig::summary_only(summary))),
            metrics,
            control_api: Arc::new(ControlApiState::default()),
            shutdown: None,
            subscriptions: None,
        }
    }

    #[cfg(test)]
    pub fn with_control_api(
        summary: ConfigSummary,
        metrics: Arc<RuntimeMetrics>,
        control_api: ControlApiState,
        shutdown: Arc<Notify>,
    ) -> Self {
        Self {
            active: Arc::new(RwLock::new(ActiveConfig::summary_only(summary))),
            metrics,
            control_api: Arc::new(control_api),
            shutdown: Some(shutdown),
            subscriptions: None,
        }
    }

    pub fn with_control_api_runtime(
        summary: ConfigSummary,
        metrics: Arc<RuntimeMetrics>,
        control_api: ControlApiState,
        router: router::Router,
        proxy_runtime: Arc<ProxyRuntime>,
        shutdown: Arc<Notify>,
        subscriptions: subscription_remote::SubscriptionRuntime,
    ) -> Self {
        let custom_route_rules = custom_route_rules_for_config_path(
            control_api.config_path.as_deref(),
            custom_route_rules_path_for_control_api(&control_api).as_deref(),
        )
        .unwrap_or_default();
        let subscription_route_rules = summary
            .route_rules
            .iter()
            .skip(custom_route_rules.len())
            .cloned()
            .collect();
        Self {
            active: Arc::new(RwLock::new(ActiveConfig {
                config_path: control_api.config_path.clone(),
                subscription_route_rules,
                summary,
                custom_route_rules,
                router: Some(router),
                proxy_runtime: Some(proxy_runtime),
            })),
            metrics,
            control_api: Arc::new(control_api),
            shutdown: Some(shutdown),
            subscriptions: Some(subscriptions),
        }
    }

    fn active_config(&self) -> ActiveConfig {
        self.active
            .read()
            .expect("active config lock must not be poisoned")
            .clone()
    }

    fn replace_active_config(&self, active: ActiveConfig) {
        *self
            .active
            .write()
            .expect("active config lock must not be poisoned") = active;
    }
}

#[derive(Debug, Clone)]
pub struct ControlApiState {
    pub config_path: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub state_file: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub token: String,
}

impl ControlApiState {
    pub fn new() -> Self {
        Self {
            config_path: None,
            log_file: None,
            state_file: None,
            state_dir: None,
            token: csrf_token(),
        }
    }
}

impl Default for ControlApiState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    service: &'static str,
    uptime_seconds: u64,
}

#[derive(Serialize)]
struct ConfigResponse {
    log_level: String,
    dns: String,
    route: RouteSummaryResponse,
    policy_groups: Vec<String>,
    services: Vec<String>,
    summary: Vec<String>,
}

#[derive(Serialize)]
struct RouteSummaryResponse {
    final_outbound: String,
    resolve_ip_cidr: bool,
    rule_sets: Vec<String>,
    rules: Vec<String>,
    rule_items: Vec<RouteRuleItemResponse>,
}

#[derive(Debug, Clone, Serialize)]
struct RouteRuleItemResponse {
    source: RouteRuleSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<RouteRuleConfig>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RouteRuleSource {
    Custom,
    Subscription,
}

#[derive(Serialize)]
struct ListResponse {
    items: Vec<String>,
}

#[derive(Serialize)]
struct IndexResponse {
    service: &'static str,
    endpoints: Vec<&'static str>,
}

#[derive(Serialize)]
struct ControlStatusResponse {
    health: HealthResponse,
    config: ConfigResponse,
    inbounds: ListResponse,
    outbounds: ListResponse,
    rules: RouteSummaryResponse,
    routing: Option<router::RouterRuntimeSnapshot>,
    proxy: Option<ProxyRuntimeSnapshot>,
    lan_proxy: LanProxyResponse,
    system_proxy: system_proxy::SystemProxyStatus,
    counters: CountersSnapshot,
    process: ControlProcessResponse,
    subscriptions: ControlSubscriptionsResponse,
}

#[derive(Serialize)]
struct LanProxyResponse {
    enabled: bool,
    available: bool,
    detail: String,
}

#[derive(Serialize)]
struct ControlProcessResponse {
    config_path: Option<String>,
    log_file: Option<String>,
    state_file: Option<String>,
    can_read_logs: bool,
    can_stop: bool,
}

#[derive(Serialize)]
struct LogsResponse {
    log_file: Option<String>,
    lines: usize,
    available: bool,
    error: Option<String>,
    content: String,
}

#[derive(Serialize)]
struct ImportResponse {
    imported: usize,
    protocols: BTreeMap<String, usize>,
    warnings: Vec<String>,
    config: Config,
}

#[derive(Serialize)]
struct ActiveConfigPreviewResponse {
    subscription: String,
    config_path: String,
    redacted: bool,
    validation_error: Option<String>,
    config: String,
}

#[derive(Serialize)]
struct ControlSubscriptionsResponse {
    store: Option<String>,
    subscriptions: Vec<subscription_remote::SubscriptionSummary>,
    active: Option<String>,
    active_config: Option<String>,
    error: Option<String>,
    auto_update_running: bool,
}

#[derive(Deserialize)]
struct ControlSubscriptionAddRequest {
    name: String,
    url: String,
    #[serde(default = "default_import_inbound_tag")]
    inbound_tag: String,
    #[serde(default = "default_import_listen")]
    listen: String,
    #[serde(default = "default_import_port")]
    listen_port: u16,
    #[serde(default = "subscription_remote::default_auto_update")]
    auto_update: bool,
    #[serde(default = "subscription_remote::default_user_agent")]
    user_agent: String,
}

#[derive(Deserialize)]
struct ControlSubscriptionImportFileRequest {
    name: String,
    filename: Option<String>,
    input: String,
    #[serde(default = "default_import_inbound_tag")]
    inbound_tag: String,
    #[serde(default = "default_import_listen")]
    listen: String,
    #[serde(default = "default_import_port")]
    listen_port: u16,
}

#[derive(Deserialize)]
struct ControlSubscriptionNameRequest {
    name: String,
}

#[derive(Deserialize)]
struct ControlSubscriptionRefreshRequest {
    name: Option<String>,
    #[serde(default)]
    all: bool,
}

#[derive(Deserialize)]
struct ControlSubscriptionSetRequest {
    name: String,
    auto_update: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CustomRouteRulesStore {
    version: u32,
    #[serde(default)]
    profiles: BTreeMap<String, CustomRouteRuleProfile>,
}

impl Default for CustomRouteRulesStore {
    fn default() -> Self {
        Self {
            version: CUSTOM_ROUTE_RULES_VERSION,
            profiles: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct CustomRouteRuleProfile {
    #[serde(default)]
    rules: Vec<CustomRouteRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CustomRouteRule {
    id: String,
    rule: RouteRuleConfig,
}

#[derive(Serialize)]
struct CustomRouteRulesResponse {
    active_config: Option<String>,
    store: Option<String>,
    rules: Vec<CustomRouteRuleResponse>,
}

#[derive(Serialize)]
struct CustomRouteRuleResponse {
    id: String,
    summary: String,
    rule: RouteRuleConfig,
}

#[derive(Deserialize)]
struct CustomRouteRuleUpsertRequest {
    id: Option<String>,
    rule: RouteRuleConfig,
}

#[derive(Deserialize)]
struct CustomRouteRuleDeleteRequest {
    id: String,
}

#[derive(Deserialize)]
struct RouteTestRequest {
    destination: String,
    port: Option<u16>,
    network: Option<String>,
    inbound: Option<String>,
}

#[derive(Serialize)]
struct RouteTestResponse {
    destination: String,
    network: String,
    inbound: String,
    mode: router::RouteMode,
    route_target: String,
    outbound: String,
    rule_index: Option<usize>,
    rule: Option<RouteRuleItemResponse>,
}

#[derive(Deserialize)]
struct ImportRequest {
    input: String,
    #[serde(default = "default_import_inbound_tag")]
    inbound_tag: String,
    #[serde(default = "default_import_listen")]
    listen: String,
    #[serde(default = "default_import_port")]
    listen_port: u16,
}

#[derive(Deserialize)]
struct RouteModeRequest {
    mode: router::RouteMode,
}

#[derive(Deserialize)]
struct GlobalTargetRequest {
    target: String,
}

#[derive(Deserialize)]
struct PolicyGroupSelectRequest {
    group: String,
    outbound: String,
}

#[derive(Deserialize)]
struct PolicyGroupDelayRequest {
    group: String,
    outbound: Option<String>,
    url: Option<String>,
    timeout_ms: Option<u64>,
}

#[derive(Serialize)]
struct PolicyGroupDelayResponse {
    group: String,
    url: String,
    timeout_ms: u64,
    results: Vec<PolicyGroupDelayResult>,
}

#[derive(Serialize)]
struct PolicyGroupDelayResult {
    outbound: String,
    resolved_outbound: Option<String>,
    latency_ms: Option<u64>,
    status_code: Option<u16>,
    error: Option<String>,
}

#[derive(Clone)]
struct UrlTestTarget {
    url: String,
    scheme: UrlTestScheme,
    host: String,
    host_header: String,
    destination: Destination,
    path: String,
}

#[derive(Clone, Copy)]
enum UrlTestScheme {
    Http,
    Https,
}

#[derive(Deserialize)]
struct ProxySwitchRequest {
    enabled: bool,
    #[serde(default)]
    protocol: Option<system_proxy::SystemProxyProtocol>,
}

#[derive(Serialize)]
struct StopResponse {
    stopping: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}
