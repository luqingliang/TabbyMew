use anyhow::{Context, Result};

use crate::config::{Config, InboundConfig, OutboundConfig, TlsClientConfig};

const REDACTED: &str = "<redacted>";

pub fn normalize_json(config: &Config, redact_secrets: bool) -> Result<String> {
    let mut normalized = config.clone();
    if redact_secrets {
        redact_config(&mut normalized);
    }
    serde_json::to_string_pretty(&normalized).context("failed to serialize normalized config")
}

fn redact_config(config: &mut Config) {
    for inbound in &mut config.inbounds {
        redact_inbound(inbound);
    }
    for outbound in &mut config.outbounds {
        redact_outbound(outbound);
    }
    for rule_set in config.route.rule_sets.values_mut() {
        rule_set.path = REDACTED.into();
    }
}

fn redact_inbound(inbound: &mut InboundConfig) {
    match inbound {
        InboundConfig::Http {
            username, password, ..
        }
        | InboundConfig::Hybrid {
            username, password, ..
        } => {
            redact_option(username);
            redact_option(password);
        }
        InboundConfig::Socks { .. } | InboundConfig::Tun { .. } => {}
    }
}

fn redact_outbound(outbound: &mut OutboundConfig) {
    match outbound {
        OutboundConfig::Socks {
            username, password, ..
        }
        | OutboundConfig::Http {
            username, password, ..
        } => {
            redact_option(username);
            redact_option(password);
        }
        OutboundConfig::Trojan { password, tls, .. }
        | OutboundConfig::AnyTls { password, tls, .. } => {
            *password = REDACTED.to_string();
            redact_tls(tls);
        }
        OutboundConfig::Shadowsocks2022 { password, .. }
        | OutboundConfig::Shadowsocks { password, .. } => {
            *password = REDACTED.to_string();
        }
        OutboundConfig::Direct { .. } | OutboundConfig::Block { .. } => {}
    }
}

fn redact_option(value: &mut Option<String>) {
    if value.is_some() {
        *value = Some(REDACTED.to_string());
    }
}

fn redact_tls(_tls: &mut TlsClientConfig) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RouteConfig, TlsClientConfig};

    #[test]
    fn redacts_config_secrets_without_losing_shape() {
        let mut rule_sets = std::collections::BTreeMap::new();
        rule_sets.insert(
            "private".to_string(),
            crate::config::RouteRuleSetConfig {
                kind: crate::config::RouteRuleSetKind::IpCidr,
                path: "/Users/example/private-cidrs.txt".into(),
            },
        );
        let config = Config {
            schema_version: crate::config::CONFIG_SCHEMA_VERSION,
            log: None,
            dns: None,
            inbounds: vec![InboundConfig::Hybrid {
                tag: "hybrid-in".to_string(),
                listen: "127.0.0.1".to_string(),
                listen_port: 7890,
                username: Some("user".to_string()),
                password: Some("example-password".to_string()),
            }],
            outbounds: vec![
                OutboundConfig::Shadowsocks {
                    tag: "ss".to_string(),
                    server: "example.com".to_string(),
                    server_port: 8388,
                    method: "aes-128-gcm".to_string(),
                    password: "example-shadowsocks-password".to_string(),
                },
                OutboundConfig::Trojan {
                    tag: "trojan".to_string(),
                    server: "example.com".to_string(),
                    server_port: 443,
                    password: "example-trojan-password".to_string(),
                    tls: TlsClientConfig {
                        server_name: Some("www.example.com".to_string()),
                        insecure: false,
                        alpn: Vec::new(),
                    },
                },
            ],
            policy_groups: Vec::new(),
            route: RouteConfig {
                final_outbound: "ss".to_string(),
                resolve_ip_cidr: false,
                rule_sets,
                rules: Vec::new(),
            },
            services: None,
        };

        let normalized = normalize_json(&config, true).unwrap();
        assert!(normalized.contains(REDACTED));
        assert!(!normalized.contains("example-shadowsocks-password"));
        assert!(!normalized.contains("example-trojan-password"));
        assert!(!normalized.contains("/Users/example"));
    }

    #[test]
    fn can_keep_secrets_for_local_normalization() {
        let config = Config {
            schema_version: crate::config::CONFIG_SCHEMA_VERSION,
            log: None,
            dns: None,
            inbounds: vec![InboundConfig::Hybrid {
                tag: "hybrid-in".to_string(),
                listen: "127.0.0.1".to_string(),
                listen_port: 7890,
                username: None,
                password: None,
            }],
            outbounds: vec![OutboundConfig::Trojan {
                tag: "trojan".to_string(),
                server: "example.com".to_string(),
                server_port: 443,
                password: "example-password".to_string(),
                tls: TlsClientConfig::default(),
            }],
            policy_groups: Vec::new(),
            route: RouteConfig {
                final_outbound: "trojan".to_string(),
                resolve_ip_cidr: false,
                rule_sets: std::collections::BTreeMap::new(),
                rules: Vec::new(),
            },
            services: None,
        };

        let normalized = normalize_json(&config, false).unwrap();
        assert!(normalized.contains("example-password"));
    }
}
