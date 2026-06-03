use super::*;

pub(super) fn dns_summary(dns: Option<&DnsConfig>) -> String {
    match dns {
        Some(dns) if !dns.servers.is_empty() => {
            format!(
                "servers={}, timeout={}ms",
                dns.servers.len(),
                dns.timeout_ms
            )
        }
        _ => "disabled".to_string(),
    }
}

pub(super) fn services_summary(services: Option<&ServicesConfig>) -> Vec<String> {
    let mut items = Vec::new();
    if let Some(control_api) = services.and_then(|services| services.control_api.as_ref()) {
        items.push(format!("control_api={}", control_api.listen));
    }
    items
}

pub(super) fn route_rule_set_summary(tag: &str, rule_set: &RouteRuleSetConfig) -> String {
    format!("{tag}:{}", route_rule_set_kind_label(rule_set.kind))
}

pub(super) fn route_rule_set_kind_label(kind: RouteRuleSetKind) -> &'static str {
    match kind {
        RouteRuleSetKind::Domain => "domain",
        RouteRuleSetKind::DomainSuffix => "domain-suffix",
        RouteRuleSetKind::DomainKeyword => "domain-keyword",
        RouteRuleSetKind::IpCidr => "ip-cidr",
    }
}

pub(super) fn policy_group_summary(group: &PolicyGroupConfig) -> String {
    format!(
        "{}:{} [{}] default={}",
        policy_group_kind_label(group.kind),
        group.tag,
        group.outbounds.join("|"),
        group.default.as_deref().unwrap_or("first")
    )
}

pub(super) fn policy_group_kind_label(kind: PolicyGroupKind) -> &'static str {
    match kind {
        PolicyGroupKind::Select => "select",
    }
}

pub(super) fn inbound_summary(inbound: &InboundConfig) -> String {
    match inbound {
        InboundConfig::Socks {
            tag,
            listen,
            listen_port,
        } => format!("socks:{tag}@{}", listen_summary(listen, *listen_port)),
        InboundConfig::Http {
            tag,
            listen,
            listen_port,
            username,
            password,
        } => format!(
            "http:{tag}@{} auth={}",
            listen_summary(listen, *listen_port),
            auth_summary(username, password)
        ),
        InboundConfig::Hybrid {
            tag,
            listen,
            listen_port,
            username,
            password,
        } => format!(
            "hybrid:{tag}@{} auth={}",
            listen_summary(listen, *listen_port),
            auth_summary(username, password)
        ),
        InboundConfig::Tun {
            tag,
            interface_name,
            mtu,
            auto_route,
            ipv6_enabled,
            dns,
            ..
        } => format!(
            "tun:{tag} interface={} mtu={mtu} auto_route={auto_route} ipv6={ipv6_enabled} dns={}",
            interface_name.as_deref().unwrap_or("auto"),
            tun_dns_summary(*dns)
        ),
    }
}

pub(super) fn outbound_summary(outbound: &OutboundConfig) -> String {
    match outbound {
        OutboundConfig::Direct { tag } => format!("direct:{tag}"),
        OutboundConfig::Block { tag } => format!("block:{tag}"),
        OutboundConfig::Socks {
            tag,
            server,
            server_port,
            username,
            password,
        } => format!(
            "socks:{tag}@{} auth={}",
            listen_summary(server, *server_port),
            auth_summary(username, password)
        ),
        OutboundConfig::Http {
            tag,
            server,
            server_port,
            username,
            password,
        } => format!(
            "http:{tag}@{} auth={}",
            listen_summary(server, *server_port),
            auth_summary(username, password)
        ),
        OutboundConfig::Trojan {
            tag,
            server,
            server_port,
            tls,
            ..
        } => format!(
            "trojan:{tag}@{} {}",
            listen_summary(server, *server_port),
            tls_summary(tls)
        ),
        OutboundConfig::Shadowsocks2022 {
            tag,
            server,
            server_port,
            method,
            ..
        } => format!(
            "shadowsocks-2022:{tag}@{} method={method}",
            listen_summary(server, *server_port)
        ),
        OutboundConfig::Shadowsocks {
            tag,
            server,
            server_port,
            method,
            ..
        } => format!(
            "shadowsocks:{tag}@{} method={method}",
            listen_summary(server, *server_port)
        ),
        OutboundConfig::AnyTls {
            tag,
            server,
            server_port,
            tls,
            idle_session_check_interval_ms,
            idle_session_timeout_ms,
            min_idle_session,
            ..
        } => format!(
            "anytls:{tag}@{} {} idle_check={}ms idle_timeout={}ms min_idle={}",
            listen_summary(server, *server_port),
            tls_summary(tls),
            idle_session_check_interval_ms,
            idle_session_timeout_ms,
            min_idle_session
        ),
    }
}

pub(super) fn route_rule_summary(rule: &RouteRuleConfig) -> String {
    let mut matches = Vec::new();
    push_string_match(&mut matches, "inbound", &rule.inbound);
    push_network_match(&mut matches, &rule.network);
    push_string_match(&mut matches, "domain", &rule.domain);
    push_string_match(&mut matches, "domain_set", &rule.domain_set);
    push_string_match(&mut matches, "domain_suffix", &rule.domain_suffix);
    push_string_match(&mut matches, "domain_suffix_set", &rule.domain_suffix_set);
    push_string_match(&mut matches, "domain_keyword", &rule.domain_keyword);
    push_string_match(&mut matches, "domain_keyword_set", &rule.domain_keyword_set);
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

pub(super) fn push_string_match(matches: &mut Vec<String>, key: &str, values: &[String]) {
    if !values.is_empty() {
        matches.push(format!("{key}={}", values.join("|")));
    }
}

pub(super) fn push_network_match(matches: &mut Vec<String>, values: &[RouteNetwork]) {
    if values.is_empty() {
        return;
    }

    let values = values
        .iter()
        .map(|network| match network {
            RouteNetwork::Tcp => "tcp",
            RouteNetwork::Udp => "udp",
        })
        .collect::<Vec<_>>()
        .join("|");
    matches.push(format!("network={values}"));
}

pub(super) fn push_port_match(matches: &mut Vec<String>, values: &[u16]) {
    if values.is_empty() {
        return;
    }

    let values = values
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join("|");
    matches.push(format!("port={values}"));
}

pub(super) fn format_summary_items(items: &[String]) -> String {
    if items.is_empty() {
        String::new()
    } else {
        format!(" [{}]", items.join(", "))
    }
}

pub(super) fn listen_summary(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

pub(super) fn auth_summary(username: &Option<String>, password: &Option<String>) -> &'static str {
    if username.is_some() && password.is_some() {
        "on"
    } else {
        "off"
    }
}

pub(super) fn tls_summary(tls: &TlsClientConfig) -> String {
    let alpn = if tls.alpn.is_empty() {
        "none".to_string()
    } else {
        tls.alpn.join("|")
    };
    match &tls.server_name {
        Some(server_name) => format!(
            "tls_server_name={server_name} tls_insecure={} alpn={alpn}",
            tls.insecure
        ),
        None => format!(
            "tls_server_name=default tls_insecure={} alpn={alpn}",
            tls.insecure
        ),
    }
}

pub(super) fn tun_dns_summary(dns: TunDnsMode) -> &'static str {
    match dns {
        TunDnsMode::Virtual => "virtual",
        TunDnsMode::OverTcp => "over-tcp",
        TunDnsMode::Direct => "direct",
    }
}
