use super::*;

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        serde_json::from_str(&text)
            .with_context(|| format!("failed to parse JSON config {}", path.display()))
    }

    pub fn summary(&self) -> ConfigSummary {
        ConfigSummary {
            log_level: self
                .log
                .as_ref()
                .map(|log| log.level.clone())
                .unwrap_or_else(default_log_level),
            dns: dns_summary(self.dns.as_ref()),
            inbounds: self.inbounds.iter().map(inbound_summary).collect(),
            outbounds: self.outbounds.iter().map(outbound_summary).collect(),
            policy_groups: self
                .policy_groups
                .iter()
                .map(policy_group_summary)
                .collect(),
            route_final: self.route.final_outbound.clone(),
            route_rule_sets: self
                .route
                .rule_sets
                .iter()
                .map(|(tag, rule_set)| route_rule_set_summary(tag, rule_set))
                .collect(),
            route_resolve_ip_cidr: self.route.resolve_ip_cidr,
            route_rules: self.route.rules.iter().map(route_rule_summary).collect(),
            services: services_summary(self.services.as_ref()),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            bail!(
                "unsupported config schema_version {}; expected {}",
                self.schema_version,
                CONFIG_SCHEMA_VERSION
            );
        }
        if self.inbounds.is_empty() {
            bail!("at least one inbound is required");
        }
        if self.outbounds.is_empty() {
            bail!("at least one outbound is required");
        }
        if let Some(dns) = &self.dns {
            validate_dns(dns)?;
        }
        if let Some(services) = &self.services {
            validate_services(services)?;
        }
        if self.route.resolve_ip_cidr && self.dns.as_ref().is_none_or(|dns| dns.servers.is_empty())
        {
            bail!("route resolve_ip_cidr requires dns.servers");
        }

        let mut inbound_tags = std::collections::HashSet::new();
        for inbound in &self.inbounds {
            validate_inbound(inbound)?;
            if !inbound_tags.insert(inbound.tag()) {
                bail!("duplicate inbound tag {}", inbound.tag());
            }
        }

        let mut outbound_tags = std::collections::HashSet::new();
        for outbound in &self.outbounds {
            validate_outbound(outbound)?;
            if !outbound_tags.insert(outbound.tag()) {
                bail!("duplicate outbound tag {}", outbound.tag());
            }
        }
        let mut policy_group_tags = HashSet::new();
        for group in &self.policy_groups {
            validate_policy_group(group)?;
            if outbound_tags.contains(group.tag.as_str()) {
                bail!("policy group tag {} duplicates an outbound tag", group.tag);
            }
            if !policy_group_tags.insert(group.tag.as_str()) {
                bail!("duplicate policy group tag {}", group.tag);
            }
        }
        let route_target_tags = outbound_tags
            .iter()
            .copied()
            .chain(policy_group_tags.iter().copied())
            .collect::<HashSet<_>>();
        validate_policy_group_refs(&self.policy_groups, &route_target_tags)?;
        validate_policy_group_cycles(&self.policy_groups)?;
        if self.route.final_outbound.trim().is_empty() {
            bail!("final outbound is empty");
        }
        if !route_target_tags.contains(self.route.final_outbound.as_str()) {
            bail!(
                "final outbound {} is not defined",
                self.route.final_outbound
            );
        }
        for (tag, rule_set) in &self.route.rule_sets {
            validate_route_rule_set(tag, rule_set)?;
        }
        for rule in &self.route.rules {
            validate_route_rule(rule)?;
            validate_route_rule_set_refs(rule, &self.route.rule_sets)?;
            if !route_target_tags.contains(rule.outbound.as_str()) {
                bail!("route rule outbound {} is not defined", rule.outbound);
            }
            for inbound in &rule.inbound {
                if !inbound_tags.contains(inbound.as_str()) {
                    bail!("route rule inbound {} is not defined", inbound);
                }
            }
        }

        Ok(())
    }

    pub fn example_json() -> Result<String> {
        serde_json::to_string_pretty(&Self::example()).context("failed to serialize example config")
    }

    pub fn default_local_json() -> Result<String> {
        serde_json::to_string_pretty(&Self::default_local())
            .context("failed to serialize default local config")
    }

    pub fn default_local_inbound_tag() -> String {
        Self::default_local()
            .inbounds
            .iter()
            .find(|inbound| !matches!(inbound, InboundConfig::Tun { .. }))
            .map(|inbound| inbound.tag().to_string())
            .unwrap_or_else(|| "hybrid-in".to_string())
    }

    pub fn default_local_listen() -> String {
        match Self::default_local()
            .inbounds
            .iter()
            .find(|inbound| !matches!(inbound, InboundConfig::Tun { .. }))
        {
            Some(
                InboundConfig::Socks { listen, .. }
                | InboundConfig::Http { listen, .. }
                | InboundConfig::Hybrid { listen, .. },
            ) => listen.clone(),
            _ => default_listen(),
        }
    }

    pub fn default_local_listen_port() -> u16 {
        match Self::default_local()
            .inbounds
            .iter()
            .find(|inbound| !matches!(inbound, InboundConfig::Tun { .. }))
        {
            Some(
                InboundConfig::Socks { listen_port, .. }
                | InboundConfig::Http { listen_port, .. }
                | InboundConfig::Hybrid { listen_port, .. },
            ) => *listen_port,
            _ => 17890,
        }
    }

    fn example() -> Config {
        Config {
            schema_version: CONFIG_SCHEMA_VERSION,
            log: Some(LogConfig {
                level: default_log_level(),
            }),
            dns: None,
            inbounds: vec![InboundConfig::Hybrid {
                tag: "hybrid-in".to_string(),
                listen: default_listen(),
                listen_port: 7890,
                username: None,
                password: None,
            }],
            outbounds: vec![
                OutboundConfig::Direct {
                    tag: "direct".to_string(),
                },
                OutboundConfig::Block {
                    tag: "block".to_string(),
                },
            ],
            policy_groups: Vec::new(),
            route: RouteConfig::default(),
            services: None,
        }
    }

    pub fn default_tun_inbound() -> InboundConfig {
        Self::default_tun_inbound_with_tag("tun-in")
    }

    pub fn default_tun_inbound_with_tag(tag: impl Into<String>) -> InboundConfig {
        InboundConfig::Tun {
            tag: tag.into(),
            interface_name: None,
            mtu: default_tun_mtu(),
            auto_route: true,
            ipv6_enabled: false,
            dns: TunDnsMode::Virtual,
            dns_addr: None,
            bypass: default_tun_bypass(),
            tcp_timeout_seconds: Some(600),
            udp_timeout_seconds: Some(10),
            max_sessions: Some(1024),
        }
    }

    pub fn ensure_default_tun_inbound(&mut self) -> bool {
        if self
            .inbounds
            .iter()
            .any(|inbound| matches!(inbound, InboundConfig::Tun { .. }))
        {
            return false;
        }

        let existing_tags = self
            .inbounds
            .iter()
            .map(InboundConfig::tag)
            .collect::<HashSet<_>>();
        let tag = unique_default_tun_tag(&existing_tags);
        self.inbounds.push(Self::default_tun_inbound_with_tag(tag));
        true
    }

    fn default_local() -> Config {
        let mut config = Self::example();
        if let Some(InboundConfig::Hybrid { listen_port, .. }) = config.inbounds.first_mut() {
            *listen_port = 17890;
        }
        config.inbounds.push(Self::default_tun_inbound());
        config
    }
}

fn unique_default_tun_tag(existing_tags: &HashSet<&str>) -> String {
    for tag in ["tun-in", "tun-auto-in"] {
        if !existing_tags.contains(tag) {
            return tag.to_string();
        }
    }
    let mut index = 2usize;
    loop {
        let tag = format!("tun-in-{index}");
        if !existing_tags.contains(tag.as_str()) {
            return tag;
        }
        index += 1;
    }
}
