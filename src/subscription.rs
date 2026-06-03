use std::{
    collections::{BTreeMap, HashMap, HashSet},
    str::FromStr,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use serde_yaml::Value as YamlValue;
use shadowsocks::crypto::CipherKind;
use url::Url;

use crate::{
    config::{
        Config, DnsConfig, InboundConfig, LogConfig, OutboundConfig, PolicyGroupConfig,
        PolicyGroupKind, RouteConfig, RouteRuleConfig, TlsClientConfig,
        default_anytls_idle_session_check_interval_ms, default_anytls_idle_session_timeout_ms,
        parse_duration_ms_literal,
    },
    net::cidr::IpCidr,
};

#[derive(Debug, Clone)]
pub struct ImportOptions {
    pub inbound_tag: String,
    pub listen: String,
    pub listen_port: u16,
}

#[derive(Debug)]
pub struct ImportResult {
    pub config: Config,
    pub warnings: Vec<String>,
    pub imported: usize,
}

impl ImportResult {
    pub fn protocol_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for outbound in &self.config.outbounds {
            if let Some(protocol) = imported_protocol(outbound) {
                *counts.entry(protocol).or_insert(0) += 1;
            }
        }
        counts
    }
}

#[derive(Debug)]
struct ImportedOutbound {
    tag_seed: String,
    outbound: OutboundConfig,
    warnings: Vec<String>,
}

#[derive(Debug, Default)]
struct ImportedProfile {
    outbounds: Vec<ImportedOutbound>,
    dns: Option<DnsConfig>,
    proxy_groups: Vec<ClashProxyGroup>,
    rules: Vec<YamlValue>,
}

#[derive(Debug)]
enum ParsedNode {
    Imported(Box<ImportedOutbound>),
    Skipped(String),
}

pub fn import_from_text(text: &str, options: ImportOptions) -> Result<ImportResult> {
    let mut warnings = Vec::new();
    let mut imported = if looks_like_clash_yaml(text) {
        import_clash_yaml(text, &mut warnings)?
    } else {
        ImportedProfile {
            outbounds: import_share_link_text(text, &mut warnings)?,
            ..ImportedProfile::default()
        }
    };

    if imported.outbounds.is_empty() {
        if warnings.is_empty() {
            bail!("no supported nodes found in import input");
        }
        bail!(
            "no supported nodes found in import input; {}",
            warnings.join("; ")
        );
    }

    let outbound_name_map = apply_unique_tags(&mut imported.outbounds);
    let final_outbound = imported
        .outbounds
        .first()
        .map(|node| node.outbound.tag().to_string())
        .ok_or_else(|| anyhow!("no supported nodes found in import input"))?;

    let imported_count = imported.outbounds.len();
    let mut config_outbounds = imported
        .outbounds
        .into_iter()
        .map(|node| node.outbound)
        .collect::<Vec<_>>();
    let (policy_groups, group_name_map) =
        translate_clash_proxy_groups(&imported.proxy_groups, &outbound_name_map, &mut warnings);
    let (route_rules, clash_final_outbound) = translate_clash_rules(
        &imported.rules,
        &outbound_name_map,
        &group_name_map,
        &mut warnings,
    );
    let final_outbound = clash_final_outbound.unwrap_or(final_outbound);

    config_outbounds.push(OutboundConfig::Direct {
        tag: "direct".to_string(),
    });
    config_outbounds.push(OutboundConfig::Block {
        tag: "block".to_string(),
    });

    Ok(ImportResult {
        config: Config {
            schema_version: crate::config::CONFIG_SCHEMA_VERSION,
            log: Some(LogConfig {
                level: "info".to_string(),
            }),
            dns: imported.dns,
            inbounds: imported_inbounds(options),
            outbounds: config_outbounds,
            policy_groups,
            route: RouteConfig {
                final_outbound,
                resolve_ip_cidr: false,
                rule_sets: std::collections::BTreeMap::new(),
                rules: route_rules,
            },
            services: None,
        },
        warnings,
        imported: imported_count,
    })
}

fn imported_inbounds(options: ImportOptions) -> Vec<InboundConfig> {
    let tun_tag = if options.inbound_tag == "tun-in" {
        "tun-auto-in"
    } else {
        "tun-in"
    };
    vec![
        InboundConfig::Hybrid {
            tag: options.inbound_tag,
            listen: options.listen,
            listen_port: options.listen_port,
            username: None,
            password: None,
        },
        Config::default_tun_inbound_with_tag(tun_tag),
    ]
}

include!("subscription/share_links.rs");

include!("subscription/clash_yaml.rs");

include!("subscription/transform.rs");

include!("subscription/util.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound;

    fn options() -> ImportOptions {
        ImportOptions {
            inbound_tag: "hybrid-in".to_string(),
            listen: "127.0.0.1".to_string(),
            listen_port: 7890,
        }
    }

    fn assert_runtime_valid(config: &Config) {
        config.validate().unwrap();
        outbound::validate_configs(&config.outbounds).unwrap();
        crate::router::Router::from_config_with_policy_groups(
            &config.outbounds,
            &config.policy_groups,
            &config.route,
        )
        .unwrap();
    }

    fn assert_default_inbounds(config: &Config) {
        assert_eq!(config.inbounds.len(), 2);
        assert!(matches!(
            &config.inbounds[0],
            InboundConfig::Hybrid {
                tag,
                listen,
                listen_port,
                ..
            } if tag == "hybrid-in" && listen == "127.0.0.1" && *listen_port == 7890
        ));
        assert!(matches!(
            &config.inbounds[1],
            InboundConfig::Tun {
                tag,
                auto_route,
                dns,
                ..
            } if tag == "tun-in" && *auto_route && *dns == crate::config::TunDnsMode::Virtual
        ));
    }

    #[test]
    fn imports_plain_share_links() {
        let text = include_str!("../examples/subscription-links.txt");

        let result = import_from_text(text, options()).unwrap();
        assert_eq!(result.imported, 3);
        assert!(result.warnings.is_empty());
        assert_eq!(result.protocol_counts().get("shadowsocks"), Some(&1));
        assert_eq!(result.protocol_counts().get("trojan"), Some(&1));
        assert_eq!(result.protocol_counts().get("anytls"), Some(&1));
        assert_default_inbounds(&result.config);
        assert_runtime_valid(&result.config);
        assert_eq!(result.config.route.final_outbound, "ss-main");
    }

    #[test]
    fn imports_base64_subscription_text() {
        let links = "ss://YWVzLTEyOC1nY206ZXhhbXBsZS1wYXNzd29yZA==@example.com:8388#ss-main\n\
             trojan://example-password@trojan.example.com:443?sni=trojan.example.com#trojan-main\n";
        let encoded = general_purpose::STANDARD.encode(links);

        let result = import_from_text(&encoded, options()).unwrap();
        assert_eq!(result.imported, 2);
        assert_runtime_valid(&result.config);
    }

    #[test]
    fn imports_clash_yaml_and_skips_unsupported_nodes() {
        let text = include_str!("../examples/clash-profile.yaml");

        let result = import_from_text(text, options()).unwrap();
        assert_eq!(result.imported, 3);
        assert_eq!(result.warnings.len(), 2);
        assert_eq!(result.protocol_counts().get("shadowsocks-2022"), Some(&1));
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("transport ws"))
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("group type url-test"))
        );
        assert_eq!(result.config.policy_groups.len(), 1);
        assert_eq!(result.config.policy_groups[0].tag, "Proxy");
        assert_eq!(
            result.config.policy_groups[0].outbounds,
            vec!["ss-yaml", "trojan-yaml", "direct", "block"]
        );
        assert_eq!(result.config.route.final_outbound, "Proxy");
        assert_eq!(result.config.route.rules.len(), 4);
        assert_eq!(
            result.config.route.rules[0].domain_suffix,
            vec!["example.com"]
        );
        assert_eq!(result.config.route.rules[0].outbound, "Proxy");
        assert_eq!(result.config.route.rules[1].domain_keyword, vec!["ads"]);
        assert_eq!(result.config.route.rules[1].outbound, "block");
        assert_eq!(result.config.route.rules[2].ip_cidr, vec!["10.0.0.0/8"]);
        assert_eq!(result.config.route.rules[2].outbound, "direct");
        assert_eq!(result.config.route.rules[3].geoip, vec!["CN"]);
        assert_eq!(result.config.route.rules[3].outbound, "direct");
        assert_runtime_valid(&result.config);
    }

    #[test]
    fn imports_clash_tls_alpn() {
        let text = r#"
proxies:
  - name: trojan-main
    type: trojan
    server: trojan.example.com
    port: 443
    password: example-password
    sni: trojan.example.com
    alpn:
      - h2
      - http/1.1
"#;

        let result = import_from_text(text, options()).unwrap();
        assert_eq!(result.imported, 1);
        assert!(result.warnings.is_empty());

        let trojan_tls = result
            .config
            .outbounds
            .iter()
            .find_map(|outbound| match outbound {
                OutboundConfig::Trojan { tag, tls, .. } if tag == "trojan-main" => Some(tls),
                _ => None,
            })
            .unwrap();

        assert_eq!(
            trojan_tls.alpn,
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
        assert_runtime_valid(&result.config);
    }

    #[test]
    fn imports_anytls_session_reuse_settings() {
        let links = "anytls://example-password@anytls.example.com:443?sni=anytls.example.com&idle_session_check_interval=2s&idle_session_timeout=45000&min_idle_session=1&mux=true#anytls-main";

        let result = import_from_text(links, options()).unwrap();
        assert_eq!(result.imported, 1);
        assert!(result.warnings.is_empty());
        match result
            .config
            .outbounds
            .iter()
            .find(|outbound| outbound.tag() == "anytls-main")
        {
            Some(OutboundConfig::AnyTls {
                idle_session_check_interval_ms,
                idle_session_timeout_ms,
                min_idle_session,
                ..
            }) => {
                assert_eq!(*idle_session_check_interval_ms, 2_000);
                assert_eq!(*idle_session_timeout_ms, 45_000);
                assert_eq!(*min_idle_session, 1);
            }
            other => panic!("expected AnyTLS outbound, got {other:?}"),
        }
        assert_runtime_valid(&result.config);

        let yaml = r#"
proxies:
  - name: anytls-yaml
    type: anytls
    server: anytls.example.com
    port: 443
    password: example-password
    sni: anytls.example.com
    idle-session-check-interval: 3
    idle-session-timeout: 4s
    min-idle-session: 2
    mux: true
"#;
        let result = import_from_text(yaml, options()).unwrap();
        assert_eq!(result.imported, 1);
        assert!(result.warnings.is_empty());
        match result
            .config
            .outbounds
            .iter()
            .find(|outbound| outbound.tag() == "anytls-yaml")
        {
            Some(OutboundConfig::AnyTls {
                idle_session_check_interval_ms,
                idle_session_timeout_ms,
                min_idle_session,
                ..
            }) => {
                assert_eq!(*idle_session_check_interval_ms, 3_000);
                assert_eq!(*idle_session_timeout_ms, 4_000);
                assert_eq!(*min_idle_session, 2);
            }
            other => panic!("expected AnyTLS outbound, got {other:?}"),
        }
        assert_runtime_valid(&result.config);
    }

    #[test]
    fn imports_clash_dns_process_geoip_and_preserves_node_names() {
        let text = r#"
dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: false
  use-hosts: false
  nameserver:
    - 119.29.29.29
    - tls://223.5.5.5:853
  fake-ip-range: 198.18.0.1/15
  fake-ip-filter:
    - "*.lan"
proxies:
  - name: "🇭🇰 香港节点 1"
    type: trojan
    server: trojan.example.com
    port: 443
    password: example-password
    sni: trojan.example.com
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - "🇭🇰 香港节点 1"
rules:
  - PROCESS-NAME,telegram-desktop,Proxy
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
"#;

        let result = import_from_text(text, options()).unwrap();

        assert_eq!(
            result.warnings,
            vec![
                "ignored Clash dns.listen because native DNS does not run a DNS listener",
                "ignored Clash dns.ipv6 because native DNS only controls configured upstream lookups",
                "ignored Clash dns.use-hosts because native DNS host-file lookup is not supported",
                "ignored Clash dns.fake-ip-range because native fake-IP DNS is not supported",
                "ignored Clash dns.fake-ip-filter because native fake-IP DNS is not supported",
                "skipped Clash DNS nameserver tls://223.5.5.5:853 because only UDP IP upstreams are supported",
            ]
        );
        let dns = result.config.dns.as_ref().unwrap();
        assert_eq!(dns.servers, vec!["119.29.29.29".to_string()]);
        assert!(result.config.outbounds.iter().any(|outbound| matches!(
            outbound,
            OutboundConfig::Trojan { tag, .. } if tag == "🇭🇰 香港节点 1"
        )));
        assert_eq!(
            result.config.policy_groups[0].outbounds,
            vec!["🇭🇰 香港节点 1"]
        );
        assert_eq!(result.config.route.rules.len(), 2);
        assert_eq!(
            result.config.route.rules[0].process_name,
            vec!["telegram-desktop"]
        );
        assert_eq!(result.config.route.rules[0].outbound, "Proxy");
        assert_eq!(result.config.route.rules[1].geoip, vec!["CN"]);
        assert_eq!(result.config.route.rules[1].outbound, "direct");
        assert_eq!(result.config.route.final_outbound, "Proxy");
        assert_runtime_valid(&result.config);
    }

    #[test]
    fn omits_clash_dns_when_no_runtime_upstream_is_supported() {
        let text = r#"
dns:
  enable: true
  listen: 0.0.0.0:1053
  nameserver:
    - tls://223.5.5.5:853
proxies:
  - name: ss-main
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: example-password
"#;

        let result = import_from_text(text, options()).unwrap();

        assert!(result.config.dns.is_none());
        assert_eq!(
            result.warnings,
            vec![
                "ignored Clash dns.listen because native DNS does not run a DNS listener",
                "skipped Clash DNS nameserver tls://223.5.5.5:853 because only UDP IP upstreams are supported",
            ]
        );
        assert_runtime_valid(&result.config);
    }

    #[test]
    fn ignores_rules_after_match_even_when_target_is_skipped() {
        let text = r#"
proxies:
  - name: ss-main
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: example-password
rules:
  - MATCH,Missing
  - DOMAIN-SUFFIX,example.com,DIRECT
"#;

        let result = import_from_text(text, options()).unwrap();

        assert_eq!(result.config.route.final_outbound, "ss-main");
        assert!(result.config.route.rules.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("target Missing is not imported"))
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("ignored Clash rule after MATCH"))
        );
        assert_runtime_valid(&result.config);
    }

    #[test]
    fn warns_about_unsupported_share_link_schemes() {
        let text = "\
hysteria2://example-password@example.com:443#hy2
tuic://example-password@example.com:443#tuic
ss://YWVzLTEyOC1nY206ZXhhbXBsZS1wYXNzd29yZA==@example.com:8388#ss-main
";

        let result = import_from_text(text, options()).unwrap();
        assert_eq!(result.imported, 1);
        assert_eq!(result.warnings.len(), 2);
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("hysteria2"))
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("tuic"))
        );
        assert_runtime_valid(&result.config);
    }
}
