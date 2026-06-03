fn looks_like_clash_yaml(text: &str) -> bool {
    text.lines()
        .map(str::trim_start)
        .any(|line| line == "proxies:" || line.starts_with("proxies:"))
}

fn apply_unique_tags(nodes: &mut [ImportedOutbound]) -> HashMap<String, String> {
    let mut used = HashSet::from(["direct".to_string(), "block".to_string()]);
    let mut mapped = HashMap::new();
    for (index, node) in nodes.iter_mut().enumerate() {
        let tag = reserve_unique_tag(&node.tag_seed, index + 1, &mut used);
        set_outbound_tag(&mut node.outbound, tag.clone());
        mapped.entry(node.tag_seed.clone()).or_insert(tag);
    }
    mapped
}

fn reserve_unique_tag(seed: &str, fallback_index: usize, used: &mut HashSet<String>) -> String {
    let base = tag_base(seed, fallback_index);
    let mut tag = base.clone();
    let mut suffix = 2usize;
    while used.contains(&tag) {
        tag = format!("{base}-{suffix}");
        suffix += 1;
    }
    used.insert(tag.clone());
    tag
}

fn translate_clash_proxy_groups(
    groups: &[ClashProxyGroup],
    outbound_name_map: &HashMap<String, String>,
    warnings: &mut Vec<String>,
) -> (Vec<PolicyGroupConfig>, HashMap<String, String>) {
    if groups.is_empty() {
        return (Vec::new(), HashMap::new());
    }

    let mut used_tags = outbound_name_map
        .values()
        .cloned()
        .chain(["direct".to_string(), "block".to_string()])
        .collect::<HashSet<_>>();
    let mut candidates = Vec::new();
    let mut candidate_group_map = HashMap::new();

    for (index, group) in groups.iter().enumerate() {
        let name = match group.name.as_deref().map(str::trim) {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => {
                warnings.push("skipped Clash proxy group with empty name".to_string());
                continue;
            }
        };
        let kind = group
            .kind
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if kind != "select" {
            warnings.push(format!(
                "skipped proxy group {name} because group type {} is not supported",
                if kind.is_empty() { "missing" } else { &kind }
            ));
            continue;
        }
        if group.proxies.is_empty() {
            warnings.push(format!(
                "skipped proxy group {name} because it does not contain proxies"
            ));
            continue;
        }

        let tag = reserve_unique_tag(&name, index + 1, &mut used_tags);
        candidate_group_map.insert(name.clone(), tag.clone());
        candidates.push((name, tag, group.proxies.clone()));
    }

    let mut translated = Vec::new();
    for (name, tag, proxies) in candidates {
        let mut outbounds = Vec::new();
        for target in proxies {
            match resolve_clash_target(&target, outbound_name_map, &candidate_group_map) {
                Some(outbound) if !outbounds.contains(&outbound) => outbounds.push(outbound),
                Some(_) => {}
                None => warnings.push(format!(
                    "skipped proxy group {name} member {target} because target is not imported"
                )),
            }
        }
        if outbounds.is_empty() {
            warnings.push(format!(
                "skipped proxy group {name} because it has no supported members"
            ));
            continue;
        }
        let default = outbounds.first().cloned();
        translated.push((
            name,
            PolicyGroupConfig {
                kind: PolicyGroupKind::Select,
                tag,
                outbounds,
                default,
            },
        ));
    }

    let concrete_targets = outbound_name_map
        .values()
        .cloned()
        .chain(["direct".to_string(), "block".to_string()])
        .collect::<HashSet<_>>();
    let mut changed = true;
    while changed {
        changed = false;
        let group_targets = translated
            .iter()
            .map(|(_, group)| group.tag.clone())
            .collect::<HashSet<_>>();
        for (_, group) in &mut translated {
            let before = group.outbounds.len();
            group.outbounds.retain(|target| {
                concrete_targets.contains(target) || group_targets.contains(target)
            });
            if group.outbounds.len() != before {
                changed = true;
            }
            if group
                .default
                .as_ref()
                .is_none_or(|default| !group.outbounds.contains(default))
            {
                group.default = group.outbounds.first().cloned();
            }
        }
        let before = translated.len();
        translated.retain(|(name, group)| {
            if group.outbounds.is_empty() {
                warnings.push(format!(
                    "skipped proxy group {name} because it only referenced skipped groups"
                ));
                false
            } else {
                true
            }
        });
        if translated.len() != before {
            changed = true;
        }
    }

    let group_name_map = translated
        .iter()
        .map(|(name, group)| (name.clone(), group.tag.clone()))
        .collect::<HashMap<_, _>>();
    let groups = translated
        .into_iter()
        .map(|(_, group)| group)
        .collect::<Vec<_>>();
    (groups, group_name_map)
}

fn normalize_clash_dns_server(server: String) -> Option<String> {
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

fn translate_clash_rules(
    rules: &[YamlValue],
    outbound_name_map: &HashMap<String, String>,
    group_name_map: &HashMap<String, String>,
    warnings: &mut Vec<String>,
) -> (Vec<RouteRuleConfig>, Option<String>) {
    let mut route_rules = Vec::new();
    let mut final_outbound = None;
    let mut saw_match = false;

    for (index, rule) in rules.iter().enumerate() {
        let Some(text) = yaml_string(Some(rule)).map(|text| text.trim().to_string()) else {
            warnings.push(format!(
                "skipped Clash rule {} because it is not a string",
                index + 1
            ));
            continue;
        };
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        if saw_match {
            warnings.push(format!("ignored Clash rule after MATCH: {text}"));
            continue;
        }

        let parts = text.split(',').map(str::trim).collect::<Vec<_>>();
        let kind = parts
            .first()
            .copied()
            .unwrap_or_default()
            .to_ascii_uppercase();
        match kind.as_str() {
            "MATCH" | "FINAL" => {
                saw_match = true;
                if parts.len() < 2 {
                    warnings.push(format!(
                        "skipped Clash rule {text} because target is missing"
                    ));
                    continue;
                }
                match resolve_clash_target(parts[1], outbound_name_map, group_name_map) {
                    Some(target) => {
                        final_outbound = Some(target);
                    }
                    None => warnings.push(format!(
                        "skipped Clash rule {text} because target {} is not imported",
                        parts[1]
                    )),
                }
            }
            "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "IP-CIDR" | "IP-CIDR6"
            | "PROCESS-NAME" | "GEOIP" => {
                if parts.len() < 3 {
                    warnings.push(format!(
                        "skipped Clash rule {text} because it is incomplete"
                    ));
                    continue;
                }
                let payload = parts[1];
                if payload.is_empty() {
                    warnings.push(format!("skipped Clash rule {text} because value is empty"));
                    continue;
                }
                let Some(outbound) =
                    resolve_clash_target(parts[2], outbound_name_map, group_name_map)
                else {
                    warnings.push(format!(
                        "skipped Clash rule {text} because target {} is not imported",
                        parts[2]
                    ));
                    continue;
                };

                let mut route_rule = empty_route_rule(outbound);
                match kind.as_str() {
                    "DOMAIN" => route_rule.domain.push(payload.to_string()),
                    "DOMAIN-SUFFIX" => route_rule.domain_suffix.push(payload.to_string()),
                    "DOMAIN-KEYWORD" => route_rule.domain_keyword.push(payload.to_string()),
                    "IP-CIDR" | "IP-CIDR6" => {
                        if let Err(err) = IpCidr::parse(payload) {
                            warnings.push(format!(
                                "skipped Clash rule {text} because CIDR {payload} is invalid: {err:#}"
                            ));
                            continue;
                        }
                        route_rule.ip_cidr.push(payload.to_string());
                    }
                    "PROCESS-NAME" => route_rule.process_name.push(payload.to_string()),
                    "GEOIP" => route_rule.geoip.push(payload.to_string()),
                    _ => unreachable!(),
                }
                route_rules.push(route_rule);
            }
            unsupported => warnings.push(format!(
                "skipped Clash rule {text} because rule type {unsupported} is not supported"
            )),
        }
    }

    (route_rules, final_outbound)
}

fn empty_route_rule(outbound: String) -> RouteRuleConfig {
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
        outbound,
    }
}

fn resolve_clash_target(
    target: &str,
    outbound_name_map: &HashMap<String, String>,
    group_name_map: &HashMap<String, String>,
) -> Option<String> {
    let target = target.trim();
    if target.eq_ignore_ascii_case("DIRECT") {
        return Some("direct".to_string());
    }
    if target.eq_ignore_ascii_case("REJECT")
        || target.eq_ignore_ascii_case("REJECT-DROP")
        || target.eq_ignore_ascii_case("DROP")
    {
        return Some("block".to_string());
    }
    outbound_name_map
        .get(target)
        .or_else(|| group_name_map.get(target))
        .cloned()
}

fn set_outbound_tag(outbound: &mut OutboundConfig, next_tag: String) {
    match outbound {
        OutboundConfig::Direct { tag }
        | OutboundConfig::Block { tag }
        | OutboundConfig::Socks { tag, .. }
        | OutboundConfig::Http { tag, .. }
        | OutboundConfig::Trojan { tag, .. }
        | OutboundConfig::Shadowsocks2022 { tag, .. }
        | OutboundConfig::Shadowsocks { tag, .. }
        | OutboundConfig::AnyTls { tag, .. } => *tag = next_tag,
    }
}

fn imported_protocol(outbound: &OutboundConfig) -> Option<&'static str> {
    match outbound {
        OutboundConfig::Socks { .. } => Some("socks"),
        OutboundConfig::Http { .. } => Some("http"),
        OutboundConfig::Trojan { .. } => Some("trojan"),
        OutboundConfig::Shadowsocks2022 { .. } => Some("shadowsocks-2022"),
        OutboundConfig::Shadowsocks { .. } => Some("shadowsocks"),
        OutboundConfig::AnyTls { .. } => Some("anytls"),
        OutboundConfig::Direct { .. } | OutboundConfig::Block { .. } => None,
    }
}

fn tag_base(seed: &str, fallback_index: usize) -> String {
    let tag = seed.trim();
    if tag.is_empty() {
        format!("node-{fallback_index}")
    } else {
        tag.to_string()
    }
}
