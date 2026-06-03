use super::*;

pub(super) fn validate_inbound(inbound: &InboundConfig) -> Result<()> {
    validate_tag("inbound", inbound.tag())?;
    match inbound {
        InboundConfig::Socks {
            tag,
            listen,
            listen_port,
        } => validate_listen(tag, listen, *listen_port),
        InboundConfig::Http {
            tag,
            listen,
            listen_port,
            username,
            password,
        }
        | InboundConfig::Hybrid {
            tag,
            listen,
            listen_port,
            username,
            password,
        } => {
            validate_listen(tag, listen, *listen_port)?;
            validate_auth_pair("HTTP inbound", tag, username, password)
        }
        InboundConfig::Tun {
            interface_name,
            bypass,
            tcp_timeout_seconds,
            udp_timeout_seconds,
            max_sessions,
            ..
        } => {
            if interface_name
                .as_deref()
                .is_some_and(|name| name.trim().is_empty())
            {
                bail!("TUN inbound {} has an empty interface_name", inbound.tag());
            }
            for cidr in bypass {
                IpCidr::parse(cidr).with_context(|| {
                    format!(
                        "TUN inbound {} bypass CIDR {cidr} is invalid",
                        inbound.tag()
                    )
                })?;
            }
            if tcp_timeout_seconds.is_some_and(|timeout| timeout == 0) {
                bail!(
                    "TUN inbound {} tcp_timeout_seconds must be greater than 0",
                    inbound.tag()
                );
            }
            if udp_timeout_seconds.is_some_and(|timeout| timeout == 0) {
                bail!(
                    "TUN inbound {} udp_timeout_seconds must be greater than 0",
                    inbound.tag()
                );
            }
            if max_sessions.is_some_and(|sessions| sessions == 0) {
                bail!(
                    "TUN inbound {} max_sessions must be greater than 0",
                    inbound.tag()
                );
            }
            Ok(())
        }
    }
}

pub(super) fn validate_dns(dns_config: &DnsConfig) -> Result<()> {
    dns::validate_servers(&dns_config.servers)?;
    if dns_config.timeout_ms == 0 {
        bail!("dns.timeout_ms must be greater than 0");
    }
    Ok(())
}
pub(super) fn validate_services(services: &ServicesConfig) -> Result<()> {
    if let Some(control_api) = &services.control_api {
        validate_control_api(control_api)?;
    }
    Ok(())
}

pub(super) fn validate_control_api(control_api: &ControlApiConfig) -> Result<()> {
    let addr = control_api
        .listen
        .trim()
        .parse::<SocketAddr>()
        .with_context(|| format!("control_api listen {} is invalid", control_api.listen))?;
    if addr.port() == 0 {
        bail!("control_api listen port must be greater than 0");
    }
    if !addr.ip().is_loopback() {
        bail!("control_api listen address must be loopback");
    }
    Ok(())
}

pub(super) fn validate_outbound(outbound: &OutboundConfig) -> Result<()> {
    validate_tag("outbound", outbound.tag())?;
    match outbound {
        OutboundConfig::Direct { .. } | OutboundConfig::Block { .. } => Ok(()),
        OutboundConfig::Socks {
            tag,
            server,
            server_port,
            username,
            password,
        } => {
            validate_server(tag, server, *server_port)?;
            validate_socks_auth(tag, username, password)
        }
        OutboundConfig::Http {
            tag,
            server,
            server_port,
            username,
            password,
        } => {
            validate_server(tag, server, *server_port)?;
            validate_auth_pair("HTTP outbound", tag, username, password)
        }
        OutboundConfig::Shadowsocks2022 {
            tag,
            server,
            server_port,
            ..
        }
        | OutboundConfig::Shadowsocks {
            tag,
            server,
            server_port,
            ..
        } => validate_server(tag, server, *server_port),
        OutboundConfig::Trojan {
            tag,
            server,
            server_port,
            password,
            tls,
        } => {
            validate_server(tag, server, *server_port)?;
            validate_required_secret(tag, "password", password)?;
            validate_tls(tag, tls)
        }
        OutboundConfig::AnyTls {
            tag,
            server,
            server_port,
            password,
            tls,
            idle_session_check_interval_ms,
            idle_session_timeout_ms,
            ..
        } => {
            validate_server(tag, server, *server_port)?;
            validate_required_secret(tag, "password", password)?;
            validate_tls(tag, tls)?;
            if *idle_session_check_interval_ms == 0 {
                bail!(
                    "outbound {tag} AnyTLS idle_session_check_interval_ms must be greater than 0"
                );
            }
            if *idle_session_timeout_ms == 0 {
                bail!("outbound {tag} AnyTLS idle_session_timeout_ms must be greater than 0");
            }
            Ok(())
        }
    }
}

pub(super) fn validate_policy_group(group: &PolicyGroupConfig) -> Result<()> {
    validate_tag("policy group", &group.tag)?;
    if group.outbounds.is_empty() {
        bail!(
            "policy group {} must contain at least one outbound",
            group.tag
        );
    }
    for outbound in &group.outbounds {
        if outbound.trim().is_empty() {
            bail!("policy group {} contains an empty outbound tag", group.tag);
        }
    }
    if let Some(default) = &group.default {
        if default.trim().is_empty() {
            bail!("policy group {} default is empty", group.tag);
        }
        if !group.outbounds.iter().any(|outbound| outbound == default) {
            bail!(
                "policy group {} default {} is not listed in outbounds",
                group.tag,
                default
            );
        }
    }
    Ok(())
}

pub(super) fn validate_policy_group_refs(
    groups: &[PolicyGroupConfig],
    route_target_tags: &HashSet<&str>,
) -> Result<()> {
    for group in groups {
        for outbound in &group.outbounds {
            if !route_target_tags.contains(outbound.as_str()) {
                bail!(
                    "policy group {} outbound {} is not defined",
                    group.tag,
                    outbound
                );
            }
        }
    }
    Ok(())
}

pub(super) fn validate_policy_group_cycles(groups: &[PolicyGroupConfig]) -> Result<()> {
    let members = groups
        .iter()
        .map(|group| (group.tag.as_str(), group.outbounds.as_slice()))
        .collect::<HashMap<_, _>>();
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for group in groups {
        visit_policy_group(&group.tag, &members, &mut visiting, &mut visited)?;
    }
    Ok(())
}

pub(super) fn visit_policy_group<'a>(
    tag: &'a str,
    members: &HashMap<&'a str, &'a [String]>,
    visiting: &mut HashSet<&'a str>,
    visited: &mut HashSet<&'a str>,
) -> Result<()> {
    if visited.contains(tag) {
        return Ok(());
    }
    if !visiting.insert(tag) {
        bail!("policy group cycle includes {tag}");
    }
    if let Some(outbounds) = members.get(tag) {
        for outbound in *outbounds {
            if members.contains_key(outbound.as_str()) {
                visit_policy_group(outbound, members, visiting, visited)?;
            }
        }
    }
    visiting.remove(tag);
    visited.insert(tag);
    Ok(())
}

pub(super) fn validate_route_rule(rule: &RouteRuleConfig) -> Result<()> {
    if rule.outbound.trim().is_empty() {
        bail!("route rule outbound is empty");
    }
    if !route_rule_has_match_condition(rule) {
        bail!("route rule needs at least one match condition");
    }
    for inbound in &rule.inbound {
        if inbound.trim().is_empty() {
            bail!("route rule inbound contains an empty tag");
        }
    }
    for port in &rule.port {
        if *port == 0 {
            bail!("route rule port must be greater than 0");
        }
    }
    for range in &rule.port_range {
        validate_port_range(range)
            .with_context(|| format!("route rule port_range {range} is invalid"))?;
    }
    for domain in &rule.domain {
        if domain.trim().trim_end_matches('.').is_empty() {
            bail!("route rule domain contains an empty value");
        }
    }
    for suffix in &rule.domain_suffix {
        if suffix
            .trim()
            .trim_start_matches('.')
            .trim_end_matches('.')
            .is_empty()
        {
            bail!("route rule domain_suffix contains an empty value");
        }
    }
    for keyword in &rule.domain_keyword {
        if keyword.trim().is_empty() {
            bail!("route rule domain_keyword contains an empty value");
        }
    }
    for cidr in &rule.ip_cidr {
        IpCidr::parse(cidr).with_context(|| format!("route rule ip_cidr {cidr} is invalid"))?;
    }
    for process_name in &rule.process_name {
        if process_name.trim().is_empty() {
            bail!("route rule process_name contains an empty value");
        }
    }
    for geoip in &rule.geoip {
        if geoip.trim().is_empty() {
            bail!("route rule geoip contains an empty value");
        }
    }
    Ok(())
}

pub(super) fn route_rule_has_match_condition(rule: &RouteRuleConfig) -> bool {
    !rule.inbound.is_empty()
        || !rule.network.is_empty()
        || !rule.domain.is_empty()
        || !rule.domain_set.is_empty()
        || !rule.domain_suffix.is_empty()
        || !rule.domain_suffix_set.is_empty()
        || !rule.domain_keyword.is_empty()
        || !rule.domain_keyword_set.is_empty()
        || !rule.ip_cidr.is_empty()
        || !rule.ip_cidr_set.is_empty()
        || !rule.process_name.is_empty()
        || !rule.geoip.is_empty()
        || !rule.port.is_empty()
        || !rule.port_range.is_empty()
}

pub(super) fn validate_route_rule_set(tag: &str, rule_set: &RouteRuleSetConfig) -> Result<()> {
    validate_tag("route rule set", tag)?;
    if rule_set.path.as_os_str().is_empty() {
        bail!("route rule set {tag} path is empty");
    }
    Ok(())
}

pub(super) fn validate_route_rule_set_refs(
    rule: &RouteRuleConfig,
    rule_sets: &BTreeMap<String, RouteRuleSetConfig>,
) -> Result<()> {
    validate_rule_set_refs(
        "domain_set",
        &rule.domain_set,
        rule_sets,
        RouteRuleSetKind::Domain,
    )?;
    validate_rule_set_refs(
        "domain_suffix_set",
        &rule.domain_suffix_set,
        rule_sets,
        RouteRuleSetKind::DomainSuffix,
    )?;
    validate_rule_set_refs(
        "domain_keyword_set",
        &rule.domain_keyword_set,
        rule_sets,
        RouteRuleSetKind::DomainKeyword,
    )?;
    validate_rule_set_refs(
        "ip_cidr_set",
        &rule.ip_cidr_set,
        rule_sets,
        RouteRuleSetKind::IpCidr,
    )
}

pub(super) fn validate_rule_set_refs(
    field: &str,
    refs: &[String],
    rule_sets: &BTreeMap<String, RouteRuleSetConfig>,
    expected_kind: RouteRuleSetKind,
) -> Result<()> {
    for rule_set_ref in refs {
        if rule_set_ref.trim().is_empty() {
            bail!("route rule {field} contains an empty rule set tag");
        }
        let Some(rule_set) = rule_sets.get(rule_set_ref) else {
            bail!("route rule {field} {rule_set_ref} is not defined");
        };
        if rule_set.kind != expected_kind {
            bail!(
                "route rule {field} {rule_set_ref} references a {} rule set",
                route_rule_set_kind_label(rule_set.kind)
            );
        }
    }
    Ok(())
}
