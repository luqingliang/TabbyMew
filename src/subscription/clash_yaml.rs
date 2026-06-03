fn import_clash_yaml(text: &str, warnings: &mut Vec<String>) -> Result<ImportedProfile> {
    let profile: ClashProfile = serde_yaml::from_str(text).context("failed to parse Clash YAML")?;
    let ClashProfile {
        proxies,
        dns,
        proxy_groups,
        rules,
    } = profile;
    let proxies = proxies.ok_or_else(|| anyhow!("Clash YAML does not contain a proxies list"))?;
    let proxy_groups = proxy_groups.unwrap_or_default();
    let rules = rules.unwrap_or_default();
    let mut outbounds = Vec::new();
    for proxy in proxies {
        match proxy.into_node() {
            Ok(ParsedNode::Imported(node)) => {
                warnings.extend(node.warnings.clone());
                outbounds.push(*node);
            }
            Ok(ParsedNode::Skipped(reason)) => warnings.push(reason),
            Err(err) => warnings.push(format!("skipped invalid Clash proxy: {err:#}")),
        }
    }
    Ok(ImportedProfile {
        outbounds,
        dns: dns.and_then(|dns| dns.into_config(warnings)),
        proxy_groups,
        rules,
    })
}

#[derive(Debug, Deserialize)]
struct ClashProfile {
    #[serde(default)]
    proxies: Option<Vec<ClashProxy>>,
    #[serde(default)]
    dns: Option<ClashDns>,
    #[serde(default, rename = "proxy-groups", alias = "proxy_groups")]
    proxy_groups: Option<Vec<ClashProxyGroup>>,
    #[serde(default)]
    rules: Option<Vec<YamlValue>>,
}

#[derive(Debug, Deserialize)]
struct ClashProxyGroup {
    name: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    proxies: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ClashDns {
    #[serde(default)]
    enable: Option<YamlValue>,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    ipv6: Option<YamlValue>,
    #[serde(default, rename = "use-hosts", alias = "use_hosts")]
    use_hosts: Option<YamlValue>,
    #[serde(default)]
    nameserver: Vec<String>,
    #[serde(default, rename = "fake-ip-range", alias = "fake_ip_range")]
    fake_ip_range: Option<String>,
    #[serde(default, rename = "fake-ip-filter", alias = "fake_ip_filter")]
    fake_ip_filter: Vec<String>,
}

impl ClashDns {
    fn into_config(self, warnings: &mut Vec<String>) -> Option<DnsConfig> {
        if yaml_bool(self.enable.as_ref()).is_some_and(|enabled| !enabled) {
            return None;
        }
        if self.listen.as_ref().is_some_and(|listen| !listen.trim().is_empty()) {
            warnings.push("ignored Clash dns.listen because native DNS does not run a DNS listener".to_string());
        }
        if self.ipv6.is_some() {
            warnings.push("ignored Clash dns.ipv6 because native DNS only controls configured upstream lookups".to_string());
        }
        if self.use_hosts.is_some() {
            warnings.push("ignored Clash dns.use-hosts because native DNS host-file lookup is not supported".to_string());
        }
        if self
            .fake_ip_range
            .as_ref()
            .is_some_and(|range| !range.trim().is_empty())
        {
            warnings.push("ignored Clash dns.fake-ip-range because native fake-IP DNS is not supported".to_string());
        }
        if self
            .fake_ip_filter
            .iter()
            .any(|filter| !filter.trim().is_empty())
        {
            warnings.push("ignored Clash dns.fake-ip-filter because native fake-IP DNS is not supported".to_string());
        }

        let mut servers = Vec::new();
        for server in self.nameserver {
            let server = server.trim().to_string();
            if server.is_empty() {
                continue;
            }
            match normalize_clash_dns_server(server.clone()) {
                Some(server) => servers.push(server),
                None => warnings.push(format!(
                    "skipped Clash DNS nameserver {server} because only UDP IP upstreams are supported"
                )),
            }
        }
        if servers.is_empty() {
            return None;
        }
        Some(DnsConfig {
            servers,
            timeout_ms: crate::config::default_dns_timeout_ms(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct ClashProxy {
    name: Option<String>,
    #[serde(rename = "type")]
    protocol: Option<String>,
    server: Option<String>,
    port: Option<YamlValue>,
    cipher: Option<String>,
    method: Option<String>,
    password: Option<YamlValue>,
    servername: Option<String>,
    sni: Option<String>,
    #[serde(rename = "skip-cert-verify")]
    skip_cert_verify: Option<YamlValue>,
    alpn: Option<YamlValue>,
    network: Option<String>,
    plugin: Option<YamlValue>,
    #[serde(rename = "plugin-opts")]
    plugin_opts: Option<YamlValue>,
    #[serde(rename = "ws-opts")]
    ws_opts: Option<YamlValue>,
    #[serde(rename = "grpc-opts")]
    grpc_opts: Option<YamlValue>,
    #[serde(rename = "h2-opts")]
    h2_opts: Option<YamlValue>,
    mux: Option<YamlValue>,
    #[serde(rename = "idle-session-check-interval", alias = "idle_session_check_interval")]
    idle_session_check_interval: Option<YamlValue>,
    #[serde(rename = "idle-session-timeout", alias = "idle_session_timeout")]
    idle_session_timeout: Option<YamlValue>,
    #[serde(rename = "min-idle-session", alias = "min_idle_session")]
    min_idle_session: Option<YamlValue>,
}

impl ClashProxy {
    fn into_node(self) -> Result<ParsedNode> {
        let protocol =
            required_string(self.protocol.clone(), "Clash proxy type")?.to_ascii_lowercase();
        let name = self.name.clone().unwrap_or_else(|| "unnamed".to_string());
        if self.has_unsupported_transport() {
            return Ok(ParsedNode::Skipped(format!(
                "skipped {name} because transport {} is not supported",
                self.network.as_deref().unwrap_or("non-tcp")
            )));
        }
        match protocol.as_str() {
            "ss" | "shadowsocks" => self.into_shadowsocks(protocol),
            "trojan" => self.into_trojan(),
            "anytls" => self.into_anytls(),
            other => Ok(ParsedNode::Skipped(format!(
                "skipped {name} because proxy type {other} is not supported"
            ))),
        }
    }

    fn into_shadowsocks(self, _protocol: String) -> Result<ParsedNode> {
        let name = self.name.clone().unwrap_or_else(|| "unnamed".to_string());
        let warnings = self.mux_warning();
        if self.plugin.is_some() || self.plugin_opts.is_some() {
            return Ok(ParsedNode::Skipped(format!(
                "skipped {name} because Shadowsocks plugin options are not supported"
            )));
        }
        let server = required_string(self.server, "Shadowsocks server")?;
        let server_port = yaml_port(self.port.as_ref()).context("Shadowsocks port is invalid")?;
        let method = self
            .method
            .or(self.cipher)
            .ok_or_else(|| anyhow!("Shadowsocks method is missing"))?;
        let Some(is_2022_method) = supported_shadowsocks_method(&method) else {
            return Ok(ParsedNode::Skipped(format!(
                "skipped {name} because Shadowsocks method {method} is not supported"
            )));
        };
        let password = yaml_string(self.password.as_ref())
            .ok_or_else(|| anyhow!("Shadowsocks password is missing"))?;
        let outbound = if is_2022_method {
            OutboundConfig::Shadowsocks2022 {
                tag: String::new(),
                server,
                server_port,
                method,
                password,
            }
        } else {
            OutboundConfig::Shadowsocks {
                tag: String::new(),
                server,
                server_port,
                method,
                password,
            }
        };
        Ok(ParsedNode::Imported(Box::new(ImportedOutbound {
            tag_seed: name,
            outbound,
            warnings,
        })))
    }

    fn into_trojan(self) -> Result<ParsedNode> {
        let warnings = self.mux_warning();
        let tag_seed = self.name.clone();
        let server = required_string(self.server, "Trojan server")?;
        let server_port = yaml_port(self.port.as_ref()).context("Trojan port is invalid")?;
        let password = yaml_string(self.password.as_ref())
            .ok_or_else(|| anyhow!("Trojan password is missing"))?;
        let tls = TlsClientConfig {
            server_name: self.servername.or(self.sni),
            insecure: yaml_bool(self.skip_cert_verify.as_ref()).unwrap_or(false),
            alpn: yaml_string_list(self.alpn.as_ref()),
        };
        Ok(ParsedNode::Imported(Box::new(ImportedOutbound {
            tag_seed: tag_seed.unwrap_or_else(|| format!("trojan-{server}")),
            outbound: OutboundConfig::Trojan {
                tag: String::new(),
                server,
                server_port,
                password,
                tls,
            },
            warnings,
        })))
    }

    fn into_anytls(self) -> Result<ParsedNode> {
        let warnings = Vec::new();
        let tag_seed = self.name.clone();
        let server = required_string(self.server, "AnyTLS server")?;
        let server_port = yaml_port(self.port.as_ref()).context("AnyTLS port is invalid")?;
        let password = yaml_string(self.password.as_ref())
            .ok_or_else(|| anyhow!("AnyTLS password is missing"))?;
        let tls = TlsClientConfig {
            server_name: self.servername.or(self.sni),
            insecure: yaml_bool(self.skip_cert_verify.as_ref()).unwrap_or(false),
            alpn: yaml_string_list(self.alpn.as_ref()),
        };
        Ok(ParsedNode::Imported(Box::new(ImportedOutbound {
            tag_seed: tag_seed.unwrap_or_else(|| format!("anytls-{server}")),
            outbound: OutboundConfig::AnyTls {
                tag: String::new(),
                server,
                server_port,
                password,
                tls,
                idle_session_check_interval_ms: yaml_duration_ms(
                    self.idle_session_check_interval.as_ref(),
                )?
                .unwrap_or_else(default_anytls_idle_session_check_interval_ms),
                idle_session_timeout_ms: yaml_duration_ms(self.idle_session_timeout.as_ref())?
                    .unwrap_or_else(default_anytls_idle_session_timeout_ms),
                min_idle_session: yaml_usize(self.min_idle_session.as_ref())?.unwrap_or_default(),
            },
            warnings,
        })))
    }

    fn has_unsupported_transport(&self) -> bool {
        let network = self.network.as_deref().unwrap_or("tcp");
        if network != "tcp" {
            return true;
        }
        self.ws_opts.is_some() || self.grpc_opts.is_some() || self.h2_opts.is_some()
    }

    fn mux_warning(&self) -> Vec<String> {
        if yaml_bool(self.mux.as_ref()).unwrap_or(false) {
            vec![format!(
                "ignored mux option for {} because multiplex is not supported yet",
                self.name.as_deref().unwrap_or("unnamed")
            )]
        } else {
            Vec::new()
        }
    }
}
