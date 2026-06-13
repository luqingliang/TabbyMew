use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    config::{
        DnsConfig, OutboundConfig, PolicyGroupConfig, PolicyGroupKind, RouteConfig, RouteNetwork,
        RouteRuleConfig, RouteRuleSetConfig, RouteRuleSetKind,
    },
    control::{RuntimeMetrics, destination_log_label},
    net::{address::Address, cidr::IpCidr, dns::DnsResolver, stream::AnyStream},
    outbound::{self, Outbound},
    session::{Network, Session},
};

#[derive(Clone)]
pub struct Router {
    inner: Arc<RouterInner>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteDecision {
    pub mode: RouteMode,
    pub route_target: String,
    pub outbound: String,
    pub rule_index: Option<usize>,
}

struct RouterInner {
    outbounds: HashMap<String, Arc<dyn Outbound>>,
    route: RouteConfig,
    dns: Option<Arc<DnsResolver>>,
    metrics: Option<Arc<RuntimeMetrics>>,
    runtime: Arc<RouterRuntime>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    #[default]
    Rule,
    Global,
    Direct,
}

impl RouteMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Global => "global",
            Self::Direct => "direct",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "rule" => Some(Self::Rule),
            "global" => Some(Self::Global),
            "direct" => Some(Self::Direct),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct RouterRuntime {
    mode: std::sync::Mutex<RouteMode>,
    direct_outbound: Option<String>,
    global_outbound: std::sync::Mutex<String>,
    global_targets: Vec<String>,
    groups: BTreeMap<String, PolicyGroupRuntime>,
    selections: std::sync::Mutex<BTreeMap<String, String>>,
}

#[derive(Debug, Clone)]
struct PolicyGroupRuntime {
    kind: PolicyGroupKind,
    outbounds: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouterRuntimeSnapshot {
    pub mode: RouteMode,
    pub available_modes: Vec<RouteMode>,
    pub direct_outbound: Option<String>,
    pub global_outbound: String,
    pub global_targets: Vec<String>,
    pub policy_groups: Vec<PolicyGroupSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyGroupSnapshot {
    pub tag: String,
    pub kind: &'static str,
    pub outbounds: Vec<String>,
    pub selected: String,
}

impl RouterRuntime {
    fn new(
        outbound_tags: &HashSet<String>,
        direct_outbound: Option<String>,
        route: &RouteConfig,
        policy_groups: &[PolicyGroupConfig],
    ) -> Result<Self> {
        let group_tags = policy_groups
            .iter()
            .map(|group| group.tag.as_str())
            .collect::<HashSet<_>>();
        let route_targets = outbound_tags
            .iter()
            .map(String::as_str)
            .chain(group_tags.iter().copied())
            .collect::<HashSet<_>>();
        let global_targets = outbound_tags
            .iter()
            .map(String::as_str)
            .chain(group_tags.iter().copied())
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if !route_targets.contains(route.final_outbound.as_str()) {
            anyhow::bail!("final outbound {} is not defined", route.final_outbound);
        }
        for rule in &route.rules {
            if !route_targets.contains(rule.outbound.as_str()) {
                anyhow::bail!("route rule outbound {} is not defined", rule.outbound);
            }
        }

        let mut groups = BTreeMap::new();
        let mut selections = BTreeMap::new();
        for group in policy_groups {
            for outbound in &group.outbounds {
                if !route_targets.contains(outbound.as_str()) {
                    anyhow::bail!(
                        "policy group {} outbound {} is not defined",
                        group.tag,
                        outbound
                    );
                }
            }
            let selected = group
                .default
                .clone()
                .unwrap_or_else(|| group.outbounds[0].clone());
            if !group.outbounds.iter().any(|outbound| outbound == &selected) {
                anyhow::bail!(
                    "policy group {} default {} is not listed in outbounds",
                    group.tag,
                    selected
                );
            }
            selections.insert(group.tag.clone(), selected);
            groups.insert(
                group.tag.clone(),
                PolicyGroupRuntime {
                    kind: group.kind,
                    outbounds: group.outbounds.clone(),
                },
            );
        }

        validate_policy_group_cycles(&groups)?;

        Ok(Self {
            mode: std::sync::Mutex::new(RouteMode::Rule),
            direct_outbound,
            global_outbound: std::sync::Mutex::new(route.final_outbound.clone()),
            global_targets,
            groups,
            selections: std::sync::Mutex::new(selections),
        })
    }

    pub fn snapshot(&self) -> RouterRuntimeSnapshot {
        let mode = self.mode();
        let selections = self
            .selections
            .lock()
            .expect("policy group selections mutex must not be poisoned");
        let policy_groups = self
            .groups
            .iter()
            .map(|(tag, group)| PolicyGroupSnapshot {
                tag: tag.clone(),
                kind: policy_group_kind_label(group.kind),
                outbounds: group.outbounds.clone(),
                selected: selections
                    .get(tag)
                    .cloned()
                    .unwrap_or_else(|| group.outbounds[0].clone()),
            })
            .collect();
        RouterRuntimeSnapshot {
            mode,
            available_modes: self.available_modes(),
            direct_outbound: self.direct_outbound.clone(),
            global_outbound: self.global_target(),
            global_targets: self.global_targets.clone(),
            policy_groups,
        }
    }

    pub fn mode(&self) -> RouteMode {
        *self
            .mode
            .lock()
            .expect("route mode mutex must not be poisoned")
    }

    pub fn set_mode(&self, mode: RouteMode) -> Result<RouterRuntimeSnapshot> {
        if mode == RouteMode::Direct && self.direct_outbound.is_none() {
            anyhow::bail!("direct mode requires a direct outbound");
        }
        *self
            .mode
            .lock()
            .expect("route mode mutex must not be poisoned") = mode;
        Ok(self.snapshot())
    }

    pub fn set_policy_group(
        &self,
        group_tag: &str,
        outbound_tag: &str,
    ) -> Result<RouterRuntimeSnapshot> {
        let group = self
            .groups
            .get(group_tag)
            .with_context(|| format!("policy group {group_tag} is not defined"))?;
        if !group
            .outbounds
            .iter()
            .any(|outbound| outbound == outbound_tag)
        {
            anyhow::bail!("policy group {group_tag} does not contain outbound {outbound_tag}");
        }
        self.selections
            .lock()
            .expect("policy group selections mutex must not be poisoned")
            .insert(group_tag.to_string(), outbound_tag.to_string());
        Ok(self.snapshot())
    }

    pub fn set_global_target(&self, target: &str) -> Result<RouterRuntimeSnapshot> {
        if !self
            .global_targets
            .iter()
            .any(|global_target| global_target == target)
        {
            anyhow::bail!("global target {target} is not defined");
        }
        *self
            .global_outbound
            .lock()
            .expect("global outbound mutex must not be poisoned") = target.to_string();
        Ok(self.snapshot())
    }

    pub fn apply_preferences(
        &self,
        mode: Option<RouteMode>,
        global_outbound: Option<&str>,
        policy_group_selections: &BTreeMap<String, String>,
    ) -> Vec<String> {
        let mut warnings = Vec::new();

        if let Some(target) = global_outbound {
            if self
                .global_targets
                .iter()
                .any(|global_target| global_target == target)
            {
                *self
                    .global_outbound
                    .lock()
                    .expect("global outbound mutex must not be poisoned") = target.to_string();
            } else {
                warnings.push(format!("saved global target {target} is not defined"));
            }
        }

        {
            let mut selections = self
                .selections
                .lock()
                .expect("policy group selections mutex must not be poisoned");
            for (group_tag, outbound_tag) in policy_group_selections {
                let Some(group) = self.groups.get(group_tag) else {
                    warnings.push(format!("saved policy group {group_tag} is not defined"));
                    continue;
                };
                if group
                    .outbounds
                    .iter()
                    .any(|outbound| outbound == outbound_tag)
                {
                    selections.insert(group_tag.clone(), outbound_tag.clone());
                } else {
                    warnings.push(format!(
                        "saved policy group {group_tag} selection {outbound_tag} is not defined"
                    ));
                }
            }
        }

        if let Some(mode) = mode {
            if mode == RouteMode::Direct && self.direct_outbound.is_none() {
                warnings.push("saved direct route mode requires a direct outbound".to_string());
            } else {
                *self
                    .mode
                    .lock()
                    .expect("route mode mutex must not be poisoned") = mode;
            }
        }

        warnings
    }

    fn available_modes(&self) -> Vec<RouteMode> {
        let mut modes = vec![RouteMode::Rule, RouteMode::Global];
        if self.direct_outbound.is_some() {
            modes.push(RouteMode::Direct);
        }
        modes
    }

    fn direct_target(&self) -> Result<&str> {
        self.direct_outbound
            .as_deref()
            .context("direct mode requires a direct outbound")
    }

    fn global_target(&self) -> String {
        self.global_outbound
            .lock()
            .expect("global outbound mutex must not be poisoned")
            .clone()
    }

    fn policy_group_outbounds(&self, group_tag: &str) -> Result<Vec<String>> {
        self.groups
            .get(group_tag)
            .map(|group| group.outbounds.clone())
            .with_context(|| format!("policy group {group_tag} is not defined"))
    }

    fn resolve_target(&self, target: &str) -> Result<String> {
        let selections = self
            .selections
            .lock()
            .expect("policy group selections mutex must not be poisoned");
        let mut current = target;
        let mut seen = HashSet::new();
        loop {
            if !seen.insert(current.to_string()) {
                anyhow::bail!("policy group cycle includes {current}");
            }
            let Some(group) = self.groups.get(current) else {
                return Ok(current.to_string());
            };
            current = selections
                .get(current)
                .map(String::as_str)
                .unwrap_or_else(|| group.outbounds[0].as_str());
        }
    }
}

fn validate_policy_group_cycles(groups: &BTreeMap<String, PolicyGroupRuntime>) -> Result<()> {
    fn visit<'a>(
        tag: &'a str,
        groups: &'a BTreeMap<String, PolicyGroupRuntime>,
        visiting: &mut HashSet<&'a str>,
        visited: &mut HashSet<&'a str>,
    ) -> Result<()> {
        if visited.contains(tag) {
            return Ok(());
        }
        if !visiting.insert(tag) {
            anyhow::bail!("policy group cycle includes {tag}");
        }
        if let Some(group) = groups.get(tag) {
            for outbound in &group.outbounds {
                if groups.contains_key(outbound) {
                    visit(outbound, groups, visiting, visited)?;
                }
            }
        }
        visiting.remove(tag);
        visited.insert(tag);
        Ok(())
    }

    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for tag in groups.keys() {
        visit(tag, groups, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn policy_group_kind_label(kind: PolicyGroupKind) -> &'static str {
    match kind {
        PolicyGroupKind::Select => "select",
    }
}

#[allow(dead_code)]
impl Router {
    pub fn from_config(outbound_configs: &[OutboundConfig], route: &RouteConfig) -> Result<Self> {
        Self::from_config_with_policy_groups(outbound_configs, &[], route)
    }

    pub fn from_config_with_policy_groups(
        outbound_configs: &[OutboundConfig],
        policy_groups: &[PolicyGroupConfig],
        route: &RouteConfig,
    ) -> Result<Self> {
        Self::from_config_with_policy_groups_dns_in_dir(
            outbound_configs,
            policy_groups,
            route,
            None,
            None,
        )
    }

    pub fn from_config_in_dir(
        outbound_configs: &[OutboundConfig],
        route: &RouteConfig,
        base_dir: Option<&Path>,
    ) -> Result<Self> {
        Self::from_config_with_dns_in_dir(outbound_configs, route, None, base_dir)
    }

    pub fn from_config_with_dns(
        outbound_configs: &[OutboundConfig],
        route: &RouteConfig,
        dns: Option<&DnsConfig>,
    ) -> Result<Self> {
        Self::from_config_with_dns_in_dir(outbound_configs, route, dns, None)
    }

    pub fn from_config_with_policy_groups_dns(
        outbound_configs: &[OutboundConfig],
        policy_groups: &[PolicyGroupConfig],
        route: &RouteConfig,
        dns: Option<&DnsConfig>,
    ) -> Result<Self> {
        Self::from_config_with_policy_groups_dns_in_dir(
            outbound_configs,
            policy_groups,
            route,
            dns,
            None,
        )
    }

    pub fn from_config_with_dns_in_dir(
        outbound_configs: &[OutboundConfig],
        route: &RouteConfig,
        dns: Option<&DnsConfig>,
        base_dir: Option<&Path>,
    ) -> Result<Self> {
        Self::from_config_with_dns_in_dir_and_metrics(outbound_configs, route, dns, base_dir, None)
    }

    pub fn from_config_with_policy_groups_dns_in_dir(
        outbound_configs: &[OutboundConfig],
        policy_groups: &[PolicyGroupConfig],
        route: &RouteConfig,
        dns: Option<&DnsConfig>,
        base_dir: Option<&Path>,
    ) -> Result<Self> {
        Self::from_config_with_policy_groups_dns_in_dir_and_metrics(
            outbound_configs,
            policy_groups,
            route,
            dns,
            base_dir,
            None,
        )
    }

    pub fn from_config_with_dns_in_dir_and_metrics(
        outbound_configs: &[OutboundConfig],
        route: &RouteConfig,
        dns: Option<&DnsConfig>,
        base_dir: Option<&Path>,
        metrics: Option<Arc<RuntimeMetrics>>,
    ) -> Result<Self> {
        Self::from_config_with_policy_groups_dns_in_dir_and_metrics(
            outbound_configs,
            &[],
            route,
            dns,
            base_dir,
            metrics,
        )
    }

    pub fn from_config_with_policy_groups_dns_in_dir_and_metrics(
        outbound_configs: &[OutboundConfig],
        policy_groups: &[PolicyGroupConfig],
        route: &RouteConfig,
        dns: Option<&DnsConfig>,
        base_dir: Option<&Path>,
        metrics: Option<Arc<RuntimeMetrics>>,
    ) -> Result<Self> {
        let dns = dns
            .map(|dns| DnsResolver::from_servers(&dns.servers, dns.timeout_ms))
            .transpose()?
            .flatten()
            .map(Arc::new);
        let route = expand_route_rule_sets(route, base_dir)?;
        let mut outbounds = HashMap::new();
        let mut outbound_tags = HashSet::new();
        let mut direct_outbound = None;
        for config in outbound_configs {
            let outbound = outbound::build_with_dns(config, dns.clone())?;
            outbound_tags.insert(outbound.tag().to_string());
            if direct_outbound.is_none() && matches!(config, OutboundConfig::Direct { .. }) {
                direct_outbound = Some(outbound.tag().to_string());
            }
            outbounds.insert(outbound.tag().to_string(), outbound);
        }
        let runtime = Arc::new(RouterRuntime::new(
            &outbound_tags,
            direct_outbound,
            &route,
            policy_groups,
        )?);

        Ok(Self {
            inner: Arc::new(RouterInner {
                outbounds,
                route,
                dns,
                metrics,
                runtime,
            }),
        })
    }

    pub fn runtime(&self) -> Arc<RouterRuntime> {
        self.inner.runtime.clone()
    }

    pub fn policy_group_outbounds(&self, group_tag: &str) -> Result<Vec<String>> {
        self.inner.runtime.policy_group_outbounds(group_tag)
    }

    pub fn resolve_route_target(&self, target: &str) -> Result<String> {
        self.inner.runtime.resolve_target(target)
    }

    pub async fn connect_outbound(
        &self,
        outbound_tag: &str,
        session: &Session,
    ) -> Result<AnyStream> {
        let outbound = self
            .inner
            .outbounds
            .get(outbound_tag)
            .cloned()
            .with_context(|| format!("outbound {outbound_tag} not found"))?;
        outbound.connect(session).await
    }

    pub async fn route_decision(&self, session: &Session) -> Result<RouteDecision> {
        let mode = self.inner.runtime.mode();
        let mut matched_rule_index = None;

        let route_target = match mode {
            RouteMode::Rule => {
                let mut resolved_ips = None;
                for (index, rule) in self.inner.route.rules.iter().enumerate() {
                    if matches_rule(rule, session) {
                        matched_rule_index = Some(index);
                        break;
                    }

                    if self.should_try_resolved_ip_cidr(rule, session) {
                        if resolved_ips.is_none() {
                            resolved_ips = Some(self.resolve_session_ips(session).await?);
                        }
                        if matches_rule_with_resolved_ips(rule, session, resolved_ips.as_deref()) {
                            matched_rule_index = Some(index);
                            break;
                        }
                    }
                }
                matched_rule_index
                    .and_then(|index| self.inner.route.rules.get(index))
                    .map(|rule| rule.outbound.as_str())
                    .unwrap_or(self.inner.route.final_outbound.as_str())
                    .to_string()
            }
            RouteMode::Global => self.inner.runtime.global_target(),
            RouteMode::Direct => self.inner.runtime.direct_target()?.to_string(),
        };
        let outbound_tag = self.inner.runtime.resolve_target(&route_target)?;
        debug!(
            inbound = %session.inbound_tag,
            network = ?session.network,
            destination = %destination_log_label(&session.destination),
            mode = mode.as_str(),
            route_target = %route_target,
            outbound = %outbound_tag,
            rule_index = matched_rule_index,
            "route selected outbound"
        );
        Ok(RouteDecision {
            mode,
            route_target,
            outbound: outbound_tag,
            rule_index: matched_rule_index,
        })
    }

    pub async fn pick(&self, session: &Session) -> Result<Arc<dyn Outbound>> {
        let decision = self.route_decision(session).await?;

        let outbound = self
            .inner
            .outbounds
            .get(&decision.outbound)
            .cloned()
            .with_context(|| format!("outbound {} not found", decision.outbound))?;
        if let Some(metrics) = &self.inner.metrics {
            metrics.record_route(session, &decision.outbound);
        }
        debug!(
            inbound = %session.inbound_tag,
            network = ?session.network,
            destination = %destination_log_label(&session.destination),
            outbound = %decision.outbound,
            "connection route accounted"
        );
        Ok(outbound)
    }

    pub fn proxied_traffic_metrics(&self, outbound: &dyn Outbound) -> Option<Arc<RuntimeMetrics>> {
        if outbound.counts_as_proxied_traffic() {
            self.inner.metrics.clone()
        } else {
            None
        }
    }

    pub fn runtime_metrics(&self) -> Option<Arc<RuntimeMetrics>> {
        self.inner.metrics.clone()
    }

    pub(crate) fn dns_resolver(&self) -> Option<Arc<DnsResolver>> {
        self.inner.dns.clone()
    }

    pub(crate) async fn clear_dns_cache(&self) -> Option<usize> {
        let dns = self.inner.dns.as_ref()?;
        Some(dns.clear_cache().await)
    }

    fn should_try_resolved_ip_cidr(&self, rule: &RouteRuleConfig, session: &Session) -> bool {
        self.inner.route.resolve_ip_cidr
            && !rule.ip_cidr.is_empty()
            && matches!(session.destination.address, Address::Domain(_))
            && matches_session_fields(rule, session)
    }

    async fn resolve_session_ips(&self, session: &Session) -> Result<Vec<IpAddr>> {
        let Address::Domain(domain) = &session.destination.address else {
            return Ok(Vec::new());
        };
        let dns = self
            .inner
            .dns
            .as_ref()
            .context("route resolve_ip_cidr requires configured DNS resolver")?;
        let addrs = dns
            .lookup(domain, session.destination.port)
            .await
            .with_context(|| {
                format!(
                    "failed to resolve {} for route ip_cidr matching",
                    session.destination
                )
            })?;
        session.cache_resolved_destination(addrs.clone());
        let ips = addrs.into_iter().map(|addr| addr.ip()).collect::<Vec<_>>();
        debug!(
            destination = %session.destination,
            resolved_ips = ?ips,
            "route resolved domain for ip_cidr matching"
        );
        Ok(ips)
    }
}

#[derive(Debug)]
struct LoadedRouteRuleSet {
    kind: RouteRuleSetKind,
    values: Vec<String>,
}

fn expand_route_rule_sets(route: &RouteConfig, base_dir: Option<&Path>) -> Result<RouteConfig> {
    if route.rule_sets.is_empty() {
        return Ok(route.clone());
    }

    let rule_sets = load_route_rule_sets(&route.rule_sets, base_dir)?;
    let mut route = route.clone();
    for rule in &mut route.rules {
        append_rule_set_values(
            "domain_set",
            &rule.domain_set.clone(),
            RouteRuleSetKind::Domain,
            &rule_sets,
            &mut rule.domain,
        )?;
        append_rule_set_values(
            "domain_suffix_set",
            &rule.domain_suffix_set.clone(),
            RouteRuleSetKind::DomainSuffix,
            &rule_sets,
            &mut rule.domain_suffix,
        )?;
        append_rule_set_values(
            "domain_keyword_set",
            &rule.domain_keyword_set.clone(),
            RouteRuleSetKind::DomainKeyword,
            &rule_sets,
            &mut rule.domain_keyword,
        )?;
        append_rule_set_values(
            "ip_cidr_set",
            &rule.ip_cidr_set.clone(),
            RouteRuleSetKind::IpCidr,
            &rule_sets,
            &mut rule.ip_cidr,
        )?;
    }

    Ok(route)
}

fn load_route_rule_sets(
    rule_sets: &BTreeMap<String, RouteRuleSetConfig>,
    base_dir: Option<&Path>,
) -> Result<HashMap<String, LoadedRouteRuleSet>> {
    let mut loaded = HashMap::new();
    for (tag, rule_set) in rule_sets {
        let path = resolve_rule_set_path(&rule_set.path, base_dir);
        let text = fs::read_to_string(&path).with_context(|| {
            format!(
                "failed to read route rule set {tag} from {}",
                path.display()
            )
        })?;
        let values = parse_rule_set_values(tag, rule_set.kind, &text)
            .with_context(|| format!("failed to load route rule set {tag}"))?;
        if values.is_empty() {
            anyhow::bail!("route rule set {tag} from {} has no rules", path.display());
        }
        loaded.insert(
            tag.clone(),
            LoadedRouteRuleSet {
                kind: rule_set.kind,
                values,
            },
        );
    }
    Ok(loaded)
}

fn resolve_rule_set_path(path: &Path, base_dir: Option<&Path>) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else if let Some(base_dir) = base_dir {
        base_dir.join(path)
    } else {
        path.to_path_buf()
    }
}

fn parse_rule_set_values(tag: &str, kind: RouteRuleSetKind, text: &str) -> Result<Vec<String>> {
    let mut values = Vec::new();
    let mut seen = HashSet::new();
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        let value = parse_rule_set_value(tag, kind, line_number, value)?;
        if seen.insert(value.clone()) {
            values.push(value);
        }
    }
    Ok(values)
}

fn parse_rule_set_value(
    tag: &str,
    kind: RouteRuleSetKind,
    line_number: usize,
    value: &str,
) -> Result<String> {
    match kind {
        RouteRuleSetKind::Domain => {
            let value = normalize_domain(value);
            if value.is_empty() {
                anyhow::bail!("route rule set {tag} line {line_number} contains an empty domain");
            }
            Ok(value)
        }
        RouteRuleSetKind::DomainSuffix => {
            let value = normalize_domain_suffix(value);
            if value.is_empty() {
                anyhow::bail!(
                    "route rule set {tag} line {line_number} contains an empty domain suffix"
                );
            }
            Ok(value)
        }
        RouteRuleSetKind::DomainKeyword => {
            let value = value.trim().to_ascii_lowercase();
            if value.is_empty() {
                anyhow::bail!(
                    "route rule set {tag} line {line_number} contains an empty domain keyword"
                );
            }
            Ok(value)
        }
        RouteRuleSetKind::IpCidr => {
            let value = value.trim().to_string();
            IpCidr::parse(&value).with_context(|| {
                format!("route rule set {tag} line {line_number} ip_cidr {value} is invalid")
            })?;
            Ok(value)
        }
    }
}

fn append_rule_set_values(
    field: &str,
    rule_set_refs: &[String],
    expected_kind: RouteRuleSetKind,
    rule_sets: &HashMap<String, LoadedRouteRuleSet>,
    target: &mut Vec<String>,
) -> Result<()> {
    if rule_set_refs.is_empty() {
        return Ok(());
    }

    let mut seen = target.iter().cloned().collect::<HashSet<_>>();
    for rule_set_ref in rule_set_refs {
        let Some(rule_set) = rule_sets.get(rule_set_ref) else {
            anyhow::bail!("route rule {field} {rule_set_ref} is not defined");
        };
        if rule_set.kind != expected_kind {
            anyhow::bail!(
                "route rule {field} {rule_set_ref} references a {} rule set",
                route_rule_set_kind_label(rule_set.kind)
            );
        }
        for value in &rule_set.values {
            if seen.insert(value.clone()) {
                target.push(value.clone());
            }
        }
    }
    Ok(())
}

fn route_rule_set_kind_label(kind: RouteRuleSetKind) -> &'static str {
    match kind {
        RouteRuleSetKind::Domain => "domain",
        RouteRuleSetKind::DomainSuffix => "domain-suffix",
        RouteRuleSetKind::DomainKeyword => "domain-keyword",
        RouteRuleSetKind::IpCidr => "ip-cidr",
    }
}

fn matches_rule(rule: &RouteRuleConfig, session: &Session) -> bool {
    matches_rule_with_resolved_ips(rule, session, None)
}

fn matches_rule_with_resolved_ips(
    rule: &RouteRuleConfig,
    session: &Session,
    resolved_ips: Option<&[IpAddr]>,
) -> bool {
    if !matches_session_fields(rule, session) {
        return false;
    }
    if has_runtime_unsupported_matcher(rule) {
        return false;
    }

    if !has_destination_matcher(rule) {
        return true;
    }

    matches_destination(rule, &session.destination.address, resolved_ips)
}

fn matches_session_fields(rule: &RouteRuleConfig, session: &Session) -> bool {
    if !rule.inbound.is_empty() && !rule.inbound.iter().any(|tag| tag == &session.inbound_tag) {
        return false;
    }

    if !rule.network.is_empty()
        && !rule
            .network
            .iter()
            .any(|network| matches_network(*network, session.network))
    {
        return false;
    }

    if has_port_matcher(rule) && !matches_port(rule, session.destination.port) {
        return false;
    }

    true
}

fn matches_destination(
    rule: &RouteRuleConfig,
    address: &Address,
    resolved_ips: Option<&[IpAddr]>,
) -> bool {
    match address {
        Address::Domain(domain) => {
            matches_domain(rule, domain)
                || resolved_ips.is_some_and(|ips| matches_ip_cidrs(rule, ips))
        }
        Address::Ip(address) => matches_ip_cidrs(rule, &[*address]),
    }
}

fn matches_domain(rule: &RouteRuleConfig, domain: &str) -> bool {
    let domain = normalize_domain(domain);
    rule.domain
        .iter()
        .any(|item| normalize_domain(item) == domain)
        || rule
            .domain_suffix
            .iter()
            .any(|suffix| matches_domain_suffix(&domain, suffix))
        || rule
            .domain_keyword
            .iter()
            .any(|keyword| domain.contains(&keyword.trim().to_ascii_lowercase()))
}

fn has_destination_matcher(rule: &RouteRuleConfig) -> bool {
    !rule.domain.is_empty()
        || !rule.domain_suffix.is_empty()
        || !rule.domain_keyword.is_empty()
        || !rule.ip_cidr.is_empty()
        || !rule.process_name.is_empty()
        || !rule.geoip.is_empty()
}

fn has_runtime_unsupported_matcher(rule: &RouteRuleConfig) -> bool {
    !rule.process_name.is_empty() || !rule.geoip.is_empty()
}

fn matches_ip_cidrs(rule: &RouteRuleConfig, ips: &[IpAddr]) -> bool {
    rule.ip_cidr.iter().any(|cidr| {
        IpCidr::parse(cidr)
            .map(|cidr| ips.iter().any(|ip| cidr.contains(*ip)))
            .unwrap_or(false)
    })
}

fn matches_network(rule_network: RouteNetwork, session_network: Network) -> bool {
    matches!(
        (rule_network, session_network),
        (RouteNetwork::Tcp, Network::Tcp) | (RouteNetwork::Udp, Network::Udp)
    )
}

fn has_port_matcher(rule: &RouteRuleConfig) -> bool {
    !rule.port.is_empty() || !rule.port_range.is_empty()
}

fn matches_port(rule: &RouteRuleConfig, port: u16) -> bool {
    rule.port.contains(&port)
        || rule
            .port_range
            .iter()
            .any(|range| matches_port_range(range, port))
}

fn matches_port_range(range: &str, port: u16) -> bool {
    parse_port_range(range)
        .map(|(start, end)| start <= port && port <= end)
        .unwrap_or(false)
}

fn parse_port_range(value: &str) -> Result<(u16, u16)> {
    let value = value.trim();
    let (start, end) = if let Some((start, end)) = value.split_once(':') {
        (parse_port(start)?, parse_port(end)?)
    } else if let Some((start, end)) = value.split_once('-') {
        (parse_port(start)?, parse_port(end)?)
    } else {
        let port = parse_port(value)?;
        (port, port)
    };

    if start > end {
        anyhow::bail!("start port {start} is greater than end port {end}");
    }
    Ok((start, end))
}

fn parse_port(value: &str) -> Result<u16> {
    let port = value.trim().parse::<u16>().context("invalid port")?;
    if port == 0 {
        anyhow::bail!("port must be greater than 0");
    }
    Ok(port)
}

fn matches_domain_suffix(domain: &str, suffix: &str) -> bool {
    let suffix = normalize_domain_suffix(suffix);
    if suffix.is_empty() {
        return false;
    }

    domain == suffix
        || domain
            .strip_suffix(&suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_domain_suffix(suffix: &str) -> String {
    suffix
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        net::address::{Address, Destination},
        session::Session,
    };
    use anyhow::Result;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::net::{TcpListener, UdpSocket};

    fn rule() -> RouteRuleConfig {
        RouteRuleConfig {
            inbound: Vec::new(),
            network: Vec::new(),
            domain: Vec::new(),
            domain_set: Vec::new(),
            domain_suffix: Vec::new(),
            domain_suffix_set: Vec::new(),
            domain_keyword: Vec::new(),
            domain_keyword_set: Vec::new(),
            ip_cidr: Vec::new(),
            process_name: Vec::new(),
            geoip: Vec::new(),
            ip_cidr_set: Vec::new(),
            port: Vec::new(),
            port_range: Vec::new(),
            outbound: "direct".to_string(),
        }
    }

    #[test]
    fn domain_suffix_respects_label_boundaries() {
        let rule = RouteRuleConfig {
            domain_suffix: vec!["example.com".to_string()],
            ..rule()
        };

        let matching = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("api.example.com".to_string()), 443),
        );
        let exact = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("example.com".to_string()), 443),
        );
        let non_matching = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("badexample.com".to_string()), 443),
        );

        assert!(matches_rule(&rule, &matching));
        assert!(matches_rule(&rule, &exact));
        assert!(!matches_rule(&rule, &non_matching));
    }

    #[test]
    fn domain_rules_are_case_insensitive() {
        let rule = RouteRuleConfig {
            domain: vec!["example.com".to_string()],
            domain_suffix: vec!["example.org".to_string()],
            ..rule()
        };

        let exact = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("Example.COM.".to_string()), 443),
        );
        let suffix = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("API.Example.ORG".to_string()), 443),
        );

        assert!(matches_rule(&rule, &exact));
        assert!(matches_rule(&rule, &suffix));
    }

    #[test]
    fn domain_keyword_rules_are_case_insensitive() {
        let rule = RouteRuleConfig {
            domain_keyword: vec!["Tracker".to_string()],
            ..rule()
        };
        let matching = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("cdn.tracker.example".to_string()), 443),
        );
        let non_matching = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("cdn.example".to_string()), 443),
        );

        assert!(matches_rule(&rule, &matching));
        assert!(!matches_rule(&rule, &non_matching));
    }

    #[test]
    fn ip_cidr_rules_match_ip_destinations() {
        let rule = RouteRuleConfig {
            ip_cidr: vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()],
            ..rule()
        };
        let ipv4 = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Ip("10.1.2.3".parse().unwrap()), 443),
        );
        let ipv6 = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Ip("2001:db8::1".parse().unwrap()), 443),
        );
        let non_matching = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Ip("192.0.2.1".parse().unwrap()), 443),
        );
        let domain = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("example.com".to_string()), 443),
        );

        assert!(matches_rule(&rule, &ipv4));
        assert!(matches_rule(&rule, &ipv6));
        assert!(!matches_rule(&rule, &non_matching));
        assert!(!matches_rule(&rule, &domain));
    }

    #[test]
    fn network_and_port_rules_are_conjunctive() {
        let rule = RouteRuleConfig {
            network: vec![RouteNetwork::Tcp],
            port: vec![443],
            domain_suffix: vec!["example.com".to_string()],
            ..rule()
        };
        let matching = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("api.example.com".to_string()), 443),
        );
        let wrong_network = Session::udp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("api.example.com".to_string()), 443),
        );
        let wrong_port = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("api.example.com".to_string()), 80),
        );

        assert!(matches_rule(&rule, &matching));
        assert!(!matches_rule(&rule, &wrong_network));
        assert!(!matches_rule(&rule, &wrong_port));
    }

    #[test]
    fn port_range_matches_destination_port() {
        let rule = RouteRuleConfig {
            port: vec![53],
            port_range: vec!["1000-2000".to_string()],
            ..rule()
        };
        let exact_port = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Ip("192.0.2.1".parse().unwrap()), 53),
        );
        let matching = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Ip("192.0.2.1".parse().unwrap()), 1500),
        );
        let non_matching = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Ip("192.0.2.1".parse().unwrap()), 999),
        );

        assert!(matches_rule(&rule, &exact_port));
        assert!(matches_rule(&rule, &matching));
        assert!(!matches_rule(&rule, &non_matching));
    }

    #[test]
    fn process_and_geoip_rules_require_runtime_context() {
        let process_rule = RouteRuleConfig {
            process_name: vec!["telegram-desktop".to_string()],
            ..rule()
        };
        let geoip_rule = RouteRuleConfig {
            geoip: vec!["CN".to_string()],
            ..rule()
        };
        let session = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("example.com".to_string()), 443),
        );

        assert!(!matches_rule(&process_rule, &session));
        assert!(!matches_rule(&geoip_rule, &session));
    }

    #[tokio::test]
    async fn rule_set_rules_match_and_preserve_rule_precedence() -> Result<()> {
        let dir = temp_rule_set_dir()?;
        std::fs::write(dir.join("exact.txt"), "example.com\n")?;
        std::fs::write(dir.join("suffix.txt"), "example.com\n")?;

        let mut rule_sets = BTreeMap::new();
        rule_sets.insert(
            "exact".to_string(),
            RouteRuleSetConfig {
                kind: RouteRuleSetKind::Domain,
                path: "exact.txt".into(),
            },
        );
        rule_sets.insert(
            "suffix".to_string(),
            RouteRuleSetConfig {
                kind: RouteRuleSetKind::DomainSuffix,
                path: "suffix.txt".into(),
            },
        );
        let route = RouteConfig {
            final_outbound: "block".to_string(),
            resolve_ip_cidr: false,
            rule_sets,
            rules: vec![
                RouteRuleConfig {
                    domain_set: vec!["exact".to_string()],
                    outbound: "direct".to_string(),
                    ..rule()
                },
                RouteRuleConfig {
                    domain_suffix_set: vec!["suffix".to_string()],
                    outbound: "block".to_string(),
                    ..rule()
                },
            ],
        };
        let router = Router::from_config_in_dir(&direct_block_outbounds(), &route, Some(&dir))?;

        let exact = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("example.com".to_string()), 443),
        );
        let suffix = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("api.example.com".to_string()), 443),
        );

        assert_eq!(router.pick(&exact).await?.tag(), "direct");
        assert_eq!(router.pick(&suffix).await?.tag(), "block");

        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn missing_rule_set_files_fail_router_build() {
        let route = RouteConfig {
            final_outbound: "direct".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::from([(
                "missing".to_string(),
                RouteRuleSetConfig {
                    kind: RouteRuleSetKind::Domain,
                    path: "missing.txt".into(),
                },
            )]),
            rules: vec![RouteRuleConfig {
                domain_set: vec!["missing".to_string()],
                outbound: "direct".to_string(),
                ..rule()
            }],
        };

        let err = match Router::from_config_in_dir(
            &direct_block_outbounds(),
            &route,
            Some(Path::new(".")),
        ) {
            Ok(_) => panic!("missing rule set file unexpectedly built a router"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("failed to read route rule set missing")
        );
    }

    #[test]
    fn invalid_rule_set_cidrs_fail_router_build() -> Result<()> {
        let dir = temp_rule_set_dir()?;
        std::fs::write(dir.join("private.txt"), "192.0.2.0/33\n")?;
        let route = RouteConfig {
            final_outbound: "direct".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::from([(
                "private".to_string(),
                RouteRuleSetConfig {
                    kind: RouteRuleSetKind::IpCidr,
                    path: "private.txt".into(),
                },
            )]),
            rules: vec![RouteRuleConfig {
                ip_cidr_set: vec!["private".to_string()],
                outbound: "direct".to_string(),
                ..rule()
            }],
        };

        let err = match Router::from_config_in_dir(&direct_block_outbounds(), &route, Some(&dir)) {
            Ok(_) => panic!("invalid rule set CIDR unexpectedly built a router"),
            Err(err) => err,
        };
        let text = format!("{err:#}");

        assert!(text.contains("route rule set private line 1 ip_cidr 192.0.2.0/33"));

        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[tokio::test]
    async fn rebuilding_router_reloads_local_rule_set_files() -> Result<()> {
        let dir = temp_rule_set_dir()?;
        let rule_set = dir.join("direct.txt");
        std::fs::write(&rule_set, "example.com\n")?;

        let route = RouteConfig {
            final_outbound: "block".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::from([(
                "direct-domains".to_string(),
                RouteRuleSetConfig {
                    kind: RouteRuleSetKind::Domain,
                    path: "direct.txt".into(),
                },
            )]),
            rules: vec![RouteRuleConfig {
                domain_set: vec!["direct-domains".to_string()],
                outbound: "direct".to_string(),
                ..rule()
            }],
        };
        let session = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("example.com".to_string()), 443),
        );
        let other = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("other.com".to_string()), 443),
        );

        let router = Router::from_config_in_dir(&direct_block_outbounds(), &route, Some(&dir))?;
        assert_eq!(router.pick(&session).await?.tag(), "direct");

        std::fs::write(&rule_set, "other.com\n")?;
        let router = Router::from_config_in_dir(&direct_block_outbounds(), &route, Some(&dir))?;
        assert_eq!(router.pick(&session).await?.tag(), "block");
        assert_eq!(router.pick(&other).await?.tag(), "direct");

        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[tokio::test]
    async fn resolved_ip_cidr_rules_match_domain_destinations() -> Result<()> {
        let dns_server = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let dns_addr = dns_server.local_addr()?;
        let dns_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = dns_server.recv_from(&mut buf).await?;
                let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
                let response = dns_response(&buf[..n], qtype == 1);
                dns_server.send_to(&response, peer).await?;
            }
            Ok::<_, anyhow::Error>(())
        });
        let dns = DnsConfig {
            servers: vec![dns_addr.to_string()],
            ..DnsConfig::default()
        };
        let route = RouteConfig {
            final_outbound: "direct".to_string(),
            resolve_ip_cidr: true,
            rule_sets: std::collections::BTreeMap::new(),
            rules: vec![RouteRuleConfig {
                ip_cidr: vec!["127.0.0.0/8".to_string()],
                outbound: "block".to_string(),
                ..rule()
            }],
        };
        let router = Router::from_config_with_dns(
            &[
                OutboundConfig::Direct {
                    tag: "direct".to_string(),
                },
                OutboundConfig::Block {
                    tag: "block".to_string(),
                },
            ],
            &route,
            Some(&dns),
        )?;
        let session = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("blocked.example".to_string()), 443),
        );

        let outbound = router.pick(&session).await?;
        dns_task.await??;

        assert_eq!(outbound.tag(), "block");
        Ok(())
    }

    #[tokio::test]
    async fn direct_connect_reuses_resolved_ip_cidr_lookup() -> Result<()> {
        let dns_server = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let dns_addr = dns_server.local_addr()?;
        let query_count = Arc::new(AtomicUsize::new(0));
        let server_query_count = query_count.clone();
        let dns_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, peer) = dns_server.recv_from(&mut buf).await.unwrap();
                server_query_count.fetch_add(1, Ordering::Relaxed);
                let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
                let response =
                    dns_response_with_ipv4(&buf[..n], qtype == 1, std::net::Ipv4Addr::LOCALHOST);
                dns_server.send_to(&response, peer).await.unwrap();
            }
        });
        let dns = DnsConfig {
            servers: vec![dns_addr.to_string()],
            ..DnsConfig::default()
        };
        let route = RouteConfig {
            final_outbound: "direct".to_string(),
            resolve_ip_cidr: true,
            rule_sets: BTreeMap::new(),
            rules: vec![RouteRuleConfig {
                ip_cidr: vec!["127.0.0.0/8".to_string()],
                outbound: "direct".to_string(),
                ..rule()
            }],
        };
        let router = Router::from_config_with_dns(
            &[OutboundConfig::Direct {
                tag: "direct".to_string(),
            }],
            &route,
            Some(&dns),
        )?;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        let accept_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await?;
            Ok::<_, anyhow::Error>(())
        });
        let session = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("reuse.example".to_string()), port),
        );

        let outbound = router.pick(&session).await?;
        let _stream = outbound.connect(&session).await?;
        accept_task.await??;
        dns_task.abort();

        assert_eq!(outbound.tag(), "direct");
        assert_eq!(query_count.load(Ordering::Relaxed), 2);
        Ok(())
    }

    #[tokio::test]
    async fn direct_udp_session_reuses_resolved_ip_cidr_lookup() -> Result<()> {
        let dns_server = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let dns_addr = dns_server.local_addr()?;
        let query_count = Arc::new(AtomicUsize::new(0));
        let server_query_count = query_count.clone();
        let dns_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, peer) = dns_server.recv_from(&mut buf).await.unwrap();
                server_query_count.fetch_add(1, Ordering::Relaxed);
                let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
                let response =
                    dns_response_with_ipv4(&buf[..n], qtype == 1, std::net::Ipv4Addr::LOCALHOST);
                dns_server.send_to(&response, peer).await.unwrap();
            }
        });
        let dns = DnsConfig {
            servers: vec![dns_addr.to_string()],
            ..DnsConfig::default()
        };
        let route = RouteConfig {
            final_outbound: "direct".to_string(),
            resolve_ip_cidr: true,
            rule_sets: BTreeMap::new(),
            rules: vec![RouteRuleConfig {
                ip_cidr: vec!["127.0.0.0/8".to_string()],
                outbound: "direct".to_string(),
                ..rule()
            }],
        };
        let router = Router::from_config_with_dns(
            &[OutboundConfig::Direct {
                tag: "direct".to_string(),
            }],
            &route,
            Some(&dns),
        )?;
        let session = Session::udp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("reuse.example".to_string()), 5353),
        );

        let outbound = router.pick(&session).await?;
        let _udp_session = outbound.udp_session(&session).await?;
        dns_task.abort();

        assert_eq!(outbound.tag(), "direct");
        assert_eq!(query_count.load(Ordering::Relaxed), 2);
        Ok(())
    }

    #[tokio::test]
    async fn select_policy_group_routes_to_selected_outbound() -> Result<()> {
        let route = RouteConfig {
            final_outbound: "Proxy".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::new(),
            rules: Vec::new(),
        };
        let groups = vec![PolicyGroupConfig {
            kind: PolicyGroupKind::Select,
            tag: "Proxy".to_string(),
            outbounds: vec!["block".to_string(), "direct".to_string()],
            default: Some("block".to_string()),
        }];
        let router =
            Router::from_config_with_policy_groups(&direct_block_outbounds(), &groups, &route)?;
        let session = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("example.com".to_string()), 443),
        );

        assert_eq!(router.pick(&session).await?.tag(), "block");
        router.runtime().set_policy_group("Proxy", "direct")?;
        assert_eq!(router.pick(&session).await?.tag(), "direct");
        let snapshot = router.runtime().set_global_target("block")?;
        assert_eq!(snapshot.mode, RouteMode::Rule);
        assert_eq!(snapshot.global_outbound, "block");
        assert_eq!(router.pick(&session).await?.tag(), "direct");
        router.runtime().set_mode(RouteMode::Global)?;
        assert_eq!(router.pick(&session).await?.tag(), "block");
        let snapshot = router.runtime().set_global_target("Proxy")?;
        assert_eq!(snapshot.mode, RouteMode::Global);
        assert_eq!(snapshot.global_outbound, "Proxy");
        assert_eq!(router.pick(&session).await?.tag(), "direct");
        Ok(())
    }

    #[tokio::test]
    async fn applies_saved_runtime_preferences() -> Result<()> {
        let route = RouteConfig {
            final_outbound: "Proxy".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::new(),
            rules: Vec::new(),
        };
        let groups = vec![PolicyGroupConfig {
            kind: PolicyGroupKind::Select,
            tag: "Proxy".to_string(),
            outbounds: vec!["block".to_string(), "direct".to_string()],
            default: Some("block".to_string()),
        }];
        let router =
            Router::from_config_with_policy_groups(&direct_block_outbounds(), &groups, &route)?;
        let mut selections = BTreeMap::new();
        selections.insert("Proxy".to_string(), "direct".to_string());

        let warnings =
            router
                .runtime()
                .apply_preferences(Some(RouteMode::Global), Some("Proxy"), &selections);
        let snapshot = router.runtime().snapshot();

        assert!(warnings.is_empty());
        assert_eq!(snapshot.mode, RouteMode::Global);
        assert_eq!(snapshot.global_outbound, "Proxy");
        assert_eq!(snapshot.policy_groups[0].selected, "direct");

        let session = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("example.com".to_string()), 443),
        );
        assert_eq!(router.pick(&session).await?.tag(), "direct");
        Ok(())
    }

    #[tokio::test]
    async fn route_mode_can_switch_between_rule_global_and_direct() -> Result<()> {
        let route = RouteConfig {
            final_outbound: "block".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::new(),
            rules: vec![RouteRuleConfig {
                domain_suffix: vec!["example.com".to_string()],
                outbound: "direct".to_string(),
                ..rule()
            }],
        };
        let router = Router::from_config(&direct_block_outbounds(), &route)?;
        let session = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("api.example.com".to_string()), 443),
        );

        let decision = router.route_decision(&session).await?;
        assert_eq!(decision.mode, RouteMode::Rule);
        assert_eq!(decision.route_target, "direct");
        assert_eq!(decision.outbound, "direct");
        assert_eq!(decision.rule_index, Some(0));
        assert_eq!(router.pick(&session).await?.tag(), "direct");
        router.runtime().set_mode(RouteMode::Global)?;
        let decision = router.route_decision(&session).await?;
        assert_eq!(decision.mode, RouteMode::Global);
        assert_eq!(decision.route_target, "block");
        assert_eq!(decision.outbound, "block");
        assert_eq!(decision.rule_index, None);
        assert_eq!(router.pick(&session).await?.tag(), "block");
        router.runtime().set_mode(RouteMode::Direct)?;
        let decision = router.route_decision(&session).await?;
        assert_eq!(decision.mode, RouteMode::Direct);
        assert_eq!(decision.route_target, "direct");
        assert_eq!(decision.outbound, "direct");
        assert_eq!(decision.rule_index, None);
        assert_eq!(router.pick(&session).await?.tag(), "direct");
        Ok(())
    }

    fn direct_block_outbounds() -> Vec<OutboundConfig> {
        vec![
            OutboundConfig::Direct {
                tag: "direct".to_string(),
            },
            OutboundConfig::Block {
                tag: "block".to_string(),
            },
        ]
    }

    fn temp_rule_set_dir() -> Result<PathBuf> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "tabbymew-route-rule-set-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn dns_response(query: &[u8], include_a_answer: bool) -> Vec<u8> {
        dns_response_with_ipv4(
            query,
            include_a_answer,
            std::net::Ipv4Addr::new(127, 0, 0, 7),
        )
    }

    fn dns_response_with_ipv4(
        query: &[u8],
        include_a_answer: bool,
        ipv4: std::net::Ipv4Addr,
    ) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&(include_a_answer as u16).to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);

        if include_a_answer {
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&60u32.to_be_bytes());
            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&ipv4.octets());
        }

        response
    }
}
