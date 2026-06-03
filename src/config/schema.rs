use super::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_config_schema_version")]
    pub schema_version: u16,
    #[serde(default)]
    pub log: Option<LogConfig>,
    #[serde(default)]
    pub dns: Option<DnsConfig>,
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub policy_groups: Vec<PolicyGroupConfig>,
    #[serde(default)]
    pub route: RouteConfig,
    #[serde(default)]
    pub services: Option<ServicesConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSummary {
    pub log_level: String,
    pub dns: String,
    pub inbounds: Vec<String>,
    pub outbounds: Vec<String>,
    pub policy_groups: Vec<String>,
    pub route_final: String,
    pub route_rule_sets: Vec<String>,
    pub route_resolve_ip_cidr: bool,
    pub route_rules: Vec<String>,
    pub services: Vec<String>,
}

impl ConfigSummary {
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("log: level={}", self.log_level),
            format!("dns: {}", self.dns),
            format!(
                "inbounds: {}{}",
                self.inbounds.len(),
                format_summary_items(&self.inbounds)
            ),
            format!(
                "outbounds: {}{}",
                self.outbounds.len(),
                format_summary_items(&self.outbounds)
            ),
            format!(
                "policy_groups: {}{}",
                self.policy_groups.len(),
                format_summary_items(&self.policy_groups)
            ),
            format!(
                "route: final={}, rules={}, rule_sets={}, resolve_ip_cidr={}",
                self.route_final,
                self.route_rules.len(),
                self.route_rule_sets.len(),
                self.route_resolve_ip_cidr
            ),
        ];

        for (index, rule_set) in self.route_rule_sets.iter().enumerate() {
            lines.push(format!("route rule set {index}: {rule_set}"));
        }
        for (index, rule) in self.route_rules.iter().enumerate() {
            lines.push(format!("route rule {index}: {rule}"));
        }

        lines.push(format!("services: {}", self.services_label()));
        lines
    }

    pub fn services_label(&self) -> String {
        if self.services.is_empty() {
            "disabled".to_string()
        } else {
            self.services.join(", ")
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default)]
    pub servers: Vec<String>,
    #[serde(default = "default_dns_timeout_ms")]
    pub timeout_ms: u64,
}

pub(crate) const CONFIG_SCHEMA_VERSION: u16 = 2;

pub(crate) fn default_config_schema_version() -> u16 {
    CONFIG_SCHEMA_VERSION
}

pub(crate) fn default_dns_timeout_ms() -> u64 {
    3_000
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            timeout_ms: default_dns_timeout_ms(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServicesConfig {
    #[serde(default)]
    pub control_api: Option<ControlApiConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlApiConfig {
    pub listen: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum InboundConfig {
    Socks {
        tag: String,
        #[serde(default = "default_listen")]
        listen: String,
        listen_port: u16,
    },
    Http {
        tag: String,
        #[serde(default = "default_listen")]
        listen: String,
        listen_port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    Hybrid {
        tag: String,
        #[serde(default = "default_listen")]
        listen: String,
        listen_port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    Tun {
        tag: String,
        #[serde(default)]
        interface_name: Option<String>,
        #[serde(default = "default_tun_mtu")]
        mtu: u16,
        #[serde(default)]
        auto_route: bool,
        #[serde(default)]
        ipv6_enabled: bool,
        #[serde(default)]
        dns: TunDnsMode,
        #[serde(default)]
        dns_addr: Option<String>,
        #[serde(default)]
        bypass: Vec<String>,
        #[serde(default)]
        tcp_timeout_seconds: Option<u64>,
        #[serde(default)]
        udp_timeout_seconds: Option<u64>,
        #[serde(default)]
        max_sessions: Option<usize>,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TunDnsMode {
    Virtual,
    OverTcp,
    #[default]
    Direct,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OutboundConfig {
    Direct {
        tag: String,
    },
    Block {
        tag: String,
    },
    Socks {
        tag: String,
        server: String,
        server_port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    Http {
        tag: String,
        server: String,
        server_port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    Trojan {
        tag: String,
        server: String,
        server_port: u16,
        password: String,
        #[serde(default)]
        tls: TlsClientConfig,
    },
    #[serde(rename = "shadowsocks-2022")]
    Shadowsocks2022 {
        tag: String,
        server: String,
        server_port: u16,
        method: String,
        password: String,
    },
    Shadowsocks {
        tag: String,
        server: String,
        server_port: u16,
        method: String,
        password: String,
    },
    #[serde(rename = "anytls")]
    AnyTls {
        tag: String,
        server: String,
        server_port: u16,
        password: String,
        #[serde(default)]
        tls: TlsClientConfig,
        #[serde(default = "default_anytls_idle_session_check_interval_ms")]
        idle_session_check_interval_ms: u64,
        #[serde(default = "default_anytls_idle_session_timeout_ms")]
        idle_session_timeout_ms: u64,
        #[serde(default)]
        min_idle_session: usize,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyGroupConfig {
    #[serde(rename = "type")]
    pub kind: PolicyGroupKind,
    pub tag: String,
    #[serde(default, deserialize_with = "deserialize_one_or_many")]
    pub outbounds: Vec<String>,
    #[serde(default)]
    pub default: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyGroupKind {
    Select,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsClientConfig {
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
}

pub(crate) fn default_anytls_idle_session_check_interval_ms() -> u64 {
    30_000
}

pub(crate) fn default_anytls_idle_session_timeout_ms() -> u64 {
    30_000
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    #[serde(default = "default_final_outbound", rename = "final")]
    pub final_outbound: String,
    #[serde(default)]
    pub resolve_ip_cidr: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rule_sets: BTreeMap<String, RouteRuleSetConfig>,
    #[serde(default)]
    pub rules: Vec<RouteRuleConfig>,
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            final_outbound: default_final_outbound(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::new(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRuleSetConfig {
    #[serde(rename = "type")]
    pub kind: RouteRuleSetKind,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteRuleSetKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRuleConfig {
    #[serde(default, deserialize_with = "deserialize_one_or_many")]
    pub inbound: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_one_or_many")]
    pub network: Vec<RouteNetwork>,
    #[serde(default, deserialize_with = "deserialize_one_or_many")]
    pub domain: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub domain_set: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_one_or_many")]
    pub domain_suffix: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub domain_suffix_set: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_one_or_many")]
    pub domain_keyword: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub domain_keyword_set: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_one_or_many")]
    pub ip_cidr: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub process_name: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub geoip: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ip_cidr_set: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_one_or_many")]
    pub port: Vec<u16>,
    #[serde(default, deserialize_with = "deserialize_one_or_many")]
    pub port_range: Vec<String>,
    pub outbound: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteNetwork {
    Tcp,
    Udp,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

pub(crate) fn parse_duration_ms_literal(value: &str) -> Result<u64> {
    let value = value.trim();
    if value.is_empty() {
        bail!("duration is empty");
    }

    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000)
    } else {
        (value, 1)
    };

    let number = number
        .trim()
        .parse::<u64>()
        .context("duration value is not a valid integer")?;
    number
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("duration is too large"))
}

fn deserialize_one_or_many<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(match OneOrMany::<T>::deserialize(deserializer)? {
        OneOrMany::One(item) => vec![item],
        OneOrMany::Many(items) => items,
    })
}
