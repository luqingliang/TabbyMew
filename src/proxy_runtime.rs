use std::time::Duration;

use anyhow::Result;
use serde::Serialize;
use tokio::{sync::Mutex, task::JoinSet};

use crate::{config::InboundConfig, router::Router};

mod lifecycle;
mod listeners;
mod snapshot;
mod tasks;
mod tun_bypass;

const TASK_CANCELLED: &str = "proxy listener task was cancelled";
const LAN_IPV4_LISTEN: &str = "0.0.0.0";
const LAN_IPV6_LISTEN: &str = "::";
const MAX_TUN_BYPASS_RESOLVES: usize = 16;
const TUN_BYPASS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TunRuntimeStatus {
    Unsupported,
    NotConfigured,
    RequiresPermission,
    RequiresConfiguration,
    Stopped,
    Running,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyRuntimeSnapshot {
    pub enabled: bool,
    pub tun_desired_enabled: bool,
    pub tun_enabled: bool,
    pub tun_status: TunRuntimeStatus,
    pub tun_supported: bool,
    pub tun_requires_privilege: bool,
    pub tun_privilege_verified: Option<bool>,
    pub tun_platform: &'static str,
    pub tun_detail: String,
    pub tun_warnings: Vec<String>,
    pub tun_auto_route: bool,
    pub tun_ipv6_enabled: bool,
    pub tun_dns_mode: Option<String>,
    pub tun_dns_addr: Option<String>,
    pub tun_configured_bypass_count: usize,
    pub tun_proxy_bypass_sources: usize,
    pub tun_egress_interface: Option<String>,
    pub tun_bound_interface: Option<String>,
    pub tun_watchdog_restarts: u64,
    pub tun_last_watchdog_reason: Option<String>,
    pub lan_enabled: bool,
    pub local_listeners: Vec<String>,
    pub lan_listeners: Vec<String>,
    pub effective_listeners: Vec<String>,
    pub configured_inbounds: usize,
    pub configured_tun_inbounds: usize,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TunBypassSource {
    tag: String,
    server: String,
    port: u16,
}

struct TunPreflightSnapshot {
    status: TunRuntimeStatus,
    supported: bool,
    requires_privilege: bool,
    privilege_verified: Option<bool>,
    platform: &'static str,
    detail: String,
}

struct TunConfigSummary {
    auto_route: bool,
    ipv6_enabled: bool,
    dns_mode: Option<String>,
    dns_addr: Option<String>,
    configured_bypass_count: usize,
}

pub struct ProxyRuntime {
    inbounds: Vec<InboundConfig>,
    tun_inbounds: Vec<InboundConfig>,
    tun_bypass_sources: Vec<TunBypassSource>,
    router: Router,
    inner: Mutex<ProxyRuntimeInner>,
    tun_inner: Mutex<ProxyRuntimeInner>,
    tun_operation: Mutex<()>,
    lan_enabled: Mutex<bool>,
}

struct ProxyRuntimeInner {
    desired_enabled: bool,
    enabled: bool,
    last_error: Option<String>,
    last_warnings: Vec<String>,
    tasks: JoinSet<Result<()>>,
    tun_egress_interface: Option<String>,
    watchdog_restarts: u64,
    last_watchdog_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{
        listeners::lan_listen_address,
        tun_bypass::{
            extend_tun_bypass, tun_bypass_cidr, tun_bypass_entry_count,
            tun_bypass_sources_from_outbounds, tun_dns_bypass_cidrs,
        },
    };
    use crate::{
        config::{InboundConfig, OutboundConfig, RouteConfig, TunDnsMode},
        net::dns::DnsResolver,
        router::Router,
    };
    use std::collections::BTreeMap;
    use tokio::task::JoinSet;

    #[test]
    fn lan_listen_rewrites_only_loopback_addresses() {
        assert_eq!(lan_listen_address("127.0.0.1"), "0.0.0.0");
        assert_eq!(lan_listen_address("::1"), "::");
        assert_eq!(lan_listen_address("192.168.1.8"), "192.168.1.8");
        assert_eq!(lan_listen_address("0.0.0.0"), "0.0.0.0");
    }

    #[tokio::test]
    async fn separates_regular_and_tun_inbound_state() -> Result<()> {
        let route = RouteConfig {
            final_outbound: "direct".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::new(),
            rules: Vec::new(),
        };
        let router = Router::from_config(
            &[OutboundConfig::Direct {
                tag: "direct".to_string(),
            }],
            &route,
        )?;
        let runtime = ProxyRuntime::new(
            vec![
                InboundConfig::Hybrid {
                    tag: "hybrid-in".to_string(),
                    listen: "127.0.0.1".to_string(),
                    listen_port: 0,
                    username: None,
                    password: None,
                },
                InboundConfig::Tun {
                    tag: "tun-in".to_string(),
                    interface_name: Some("tun-test".to_string()),
                    mtu: 1500,
                    auto_route: false,
                    ipv6_enabled: false,
                    dns: TunDnsMode::Direct,
                    dns_addr: None,
                    bypass: Vec::new(),
                    tcp_timeout_seconds: None,
                    udp_timeout_seconds: None,
                    max_sessions: None,
                },
            ],
            router,
        );

        let snapshot = runtime.snapshot().await;
        assert!(!snapshot.enabled);
        assert!(!snapshot.tun_enabled);
        assert!(!snapshot.lan_enabled);
        assert_eq!(snapshot.local_listeners, vec!["hybrid 127.0.0.1:0"]);
        assert_eq!(snapshot.lan_listeners, vec!["hybrid 0.0.0.0:0"]);
        assert_eq!(snapshot.effective_listeners, vec!["hybrid 127.0.0.1:0"]);
        assert_eq!(snapshot.configured_inbounds, 1);
        assert_eq!(snapshot.configured_tun_inbounds, 1);
        assert_eq!(snapshot.tun_status, TunRuntimeStatus::Stopped);

        let snapshot = runtime.set_lan_enabled(true).await?;
        assert!(snapshot.lan_enabled);
        assert_eq!(snapshot.effective_listeners, vec!["hybrid 0.0.0.0:0"]);

        let snapshot = runtime.start().await?;
        assert!(snapshot.enabled);
        assert!(!snapshot.tun_enabled);
        assert!(snapshot.lan_enabled);

        let snapshot = runtime.set_lan_enabled(false).await?;
        assert!(snapshot.enabled);
        assert!(!snapshot.lan_enabled);

        let snapshot = runtime.stop_all().await?;
        assert!(!snapshot.enabled);
        assert!(!snapshot.tun_enabled);
        let snapshot = runtime.snapshot().await;
        assert!(!snapshot.enabled);
        assert!(!snapshot.tun_enabled);

        let regular_only = ProxyRuntime::new(
            vec![InboundConfig::Hybrid {
                tag: "hybrid-in".to_string(),
                listen: "127.0.0.1".to_string(),
                listen_port: 0,
                username: None,
                password: None,
            }],
            Router::from_config(
                &[OutboundConfig::Direct {
                    tag: "direct".to_string(),
                }],
                &route,
            )?,
        );
        let snapshot = regular_only.start_all().await?;
        assert!(snapshot.enabled);
        assert!(!snapshot.tun_enabled);
        assert_eq!(snapshot.tun_status, TunRuntimeStatus::NotConfigured);
        regular_only.stop_all().await?;

        Ok(())
    }

    #[test]
    fn collects_proxy_servers_for_tun_bypass() {
        let sources = tun_bypass_sources_from_outbounds(&[
            OutboundConfig::Direct {
                tag: "direct".to_string(),
            },
            OutboundConfig::Socks {
                tag: "socks".to_string(),
                server: "198.51.100.10".to_string(),
                server_port: 1080,
                username: None,
                password: None,
            },
            OutboundConfig::Trojan {
                tag: "trojan".to_string(),
                server: "node.example.com".to_string(),
                server_port: 443,
                password: "example-password".to_string(),
                tls: crate::config::TlsClientConfig::default(),
            },
        ]);

        assert_eq!(sources.len(), 2);
        assert!(sources.iter().any(|source| source.tag == "socks"));
        assert!(
            sources
                .iter()
                .any(|source| source.server == "node.example.com")
        );
    }

    #[test]
    fn extend_tun_bypass_deduplicates_extra_cidrs() {
        let inbound = InboundConfig::Tun {
            tag: "tun-in".to_string(),
            interface_name: None,
            mtu: 1500,
            auto_route: true,
            ipv6_enabled: false,
            dns: TunDnsMode::Virtual,
            dns_addr: None,
            bypass: vec!["127.0.0.0/8".to_string(), "::1/128".to_string()],
            tcp_timeout_seconds: None,
            udp_timeout_seconds: None,
            max_sessions: None,
        };

        let extended = extend_tun_bypass(
            inbound,
            &[
                "127.0.0.0/8".to_string(),
                "198.51.100.10/32".to_string(),
                "ff00::/8".to_string(),
            ],
        );

        match extended {
            InboundConfig::Tun { bypass, .. } => {
                assert_eq!(bypass, vec!["127.0.0.0/8", "198.51.100.10/32"]);
            }
            other => panic!("unexpected inbound: {other:?}"),
        }
    }

    #[test]
    fn extend_tun_bypass_keeps_ipv6_cidrs_when_ipv6_enabled() {
        let inbound = InboundConfig::Tun {
            tag: "tun-in".to_string(),
            interface_name: None,
            mtu: 1500,
            auto_route: true,
            ipv6_enabled: true,
            dns: TunDnsMode::Virtual,
            dns_addr: None,
            bypass: vec!["127.0.0.0/8".to_string(), "::1/128".to_string()],
            tcp_timeout_seconds: None,
            udp_timeout_seconds: None,
            max_sessions: None,
        };

        let extended = extend_tun_bypass(inbound, &["ff00::/8".to_string()]);

        match extended {
            InboundConfig::Tun { bypass, .. } => {
                assert_eq!(bypass, vec!["127.0.0.0/8", "::1/128", "ff00::/8"]);
            }
            other => panic!("unexpected inbound: {other:?}"),
        }
    }

    #[test]
    fn tun_bypass_entry_count_counts_effective_unique_entries() {
        let inbounds = vec![
            InboundConfig::Tun {
                tag: "tun-a".to_string(),
                interface_name: None,
                mtu: 1500,
                auto_route: true,
                ipv6_enabled: false,
                dns: TunDnsMode::Virtual,
                dns_addr: None,
                bypass: vec!["127.0.0.0/8".to_string(), "10.0.0.0/8".to_string()],
                tcp_timeout_seconds: None,
                udp_timeout_seconds: None,
                max_sessions: None,
            },
            InboundConfig::Tun {
                tag: "tun-b".to_string(),
                interface_name: None,
                mtu: 1500,
                auto_route: true,
                ipv6_enabled: false,
                dns: TunDnsMode::Virtual,
                dns_addr: None,
                bypass: vec!["10.0.0.0/8".to_string(), "ff00::/8".to_string()],
                tcp_timeout_seconds: None,
                udp_timeout_seconds: None,
                max_sessions: None,
            },
        ];

        assert_eq!(tun_bypass_entry_count(&inbounds), 3);
    }

    #[tokio::test]
    async fn prepare_tun_inbounds_filters_ipv6_bypass_when_ipv6_is_disabled() -> Result<()> {
        let route = RouteConfig {
            final_outbound: "socks".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::new(),
            rules: Vec::new(),
        };
        let outbounds = vec![OutboundConfig::Socks {
            tag: "socks".to_string(),
            server: "198.51.100.10".to_string(),
            server_port: 1080,
            username: None,
            password: None,
        }];
        let router = Router::from_config(&outbounds, &route)?;
        let runtime = ProxyRuntime::new_with_outbounds(
            vec![InboundConfig::Tun {
                tag: "tun-in".to_string(),
                interface_name: None,
                mtu: 1500,
                auto_route: true,
                ipv6_enabled: false,
                dns: TunDnsMode::Virtual,
                dns_addr: None,
                bypass: vec!["127.0.0.0/8".to_string(), "::1/128".to_string()],
                tcp_timeout_seconds: None,
                udp_timeout_seconds: None,
                max_sessions: None,
            }],
            router,
            &outbounds,
        );

        let (prepared, _warnings) = runtime.prepare_tun_inbounds().await?;
        let InboundConfig::Tun { bypass, .. } = &prepared[0] else {
            panic!("unexpected inbound: {:?}", prepared[0]);
        };

        assert!(bypass.contains(&"127.0.0.0/8".to_string()));
        assert!(bypass.contains(&"224.0.0.0/4".to_string()));
        assert!(bypass.contains(&"198.51.100.10/32".to_string()));
        assert!(!bypass.contains(&"::1/128".to_string()));
        assert!(!bypass.contains(&"fe80::/10".to_string()));
        assert!(!bypass.contains(&"ff00::/8".to_string()));

        Ok(())
    }

    #[test]
    fn tun_dns_bypass_cidrs_include_configured_dns_servers() -> Result<()> {
        let dns = DnsResolver::from_servers(
            &[
                "9.9.9.9".to_string(),
                "[2001:4860:4860::8888]:53".to_string(),
            ],
            3_000,
        )?
        .unwrap();
        let tun_inbounds = vec![InboundConfig::Tun {
            tag: "tun-in".to_string(),
            interface_name: None,
            mtu: 1500,
            auto_route: true,
            ipv6_enabled: false,
            dns: TunDnsMode::Virtual,
            dns_addr: Some("8.8.4.4:53".to_string()),
            bypass: Vec::new(),
            tcp_timeout_seconds: None,
            udp_timeout_seconds: None,
            max_sessions: None,
        }];

        let cidrs = tun_dns_bypass_cidrs(Some(&dns), &tun_inbounds, false);

        assert!(cidrs.contains(&"9.9.9.9/32".to_string()));
        assert!(cidrs.contains(&"8.8.4.4/32".to_string()));
        assert!(!cidrs.contains(&"2001:4860:4860::8888/128".to_string()));
        Ok(())
    }

    #[test]
    fn tun_bypass_cidr_follows_ipv6_setting() {
        assert_eq!(
            tun_bypass_cidr("198.51.100.10".parse().unwrap(), false).as_deref(),
            Some("198.51.100.10/32")
        );
        assert_eq!(tun_bypass_cidr("2001:db8::1".parse().unwrap(), false), None);
        assert_eq!(
            tun_bypass_cidr("2001:db8::1".parse().unwrap(), true).as_deref(),
            Some("2001:db8::1/128")
        );
    }

    #[tokio::test]
    async fn tun_snapshot_reports_runtime_diagnostics() -> Result<()> {
        let route = RouteConfig {
            final_outbound: "socks".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::new(),
            rules: Vec::new(),
        };
        let outbounds = vec![
            OutboundConfig::Direct {
                tag: "direct".to_string(),
            },
            OutboundConfig::Socks {
                tag: "socks".to_string(),
                server: "198.51.100.10".to_string(),
                server_port: 1080,
                username: None,
                password: None,
            },
        ];
        let router = Router::from_config(&outbounds, &route)?;
        let runtime = ProxyRuntime::new_with_outbounds(
            vec![InboundConfig::Tun {
                tag: "tun-in".to_string(),
                interface_name: None,
                mtu: 1500,
                auto_route: true,
                ipv6_enabled: true,
                dns: TunDnsMode::OverTcp,
                dns_addr: Some("1.1.1.1:53".to_string()),
                bypass: vec![
                    "127.0.0.0/8".to_string(),
                    "127.0.0.0/8".to_string(),
                    "::1/128".to_string(),
                ],
                tcp_timeout_seconds: None,
                udp_timeout_seconds: None,
                max_sessions: None,
            }],
            router,
            &outbounds,
        );

        let snapshot = runtime.snapshot().await;

        assert!(snapshot.tun_auto_route);
        assert!(snapshot.tun_ipv6_enabled);
        assert_eq!(snapshot.tun_dns_mode.as_deref(), Some("over-tcp"));
        assert_eq!(snapshot.tun_dns_addr.as_deref(), Some("1.1.1.1:53"));
        assert_eq!(snapshot.tun_configured_bypass_count, 2);
        assert_eq!(snapshot.tun_proxy_bypass_sources, 1);
        assert!(snapshot.tun_egress_interface.is_none());

        Ok(())
    }

    #[test]
    fn tun_running_status_takes_precedence_over_permission_prompt() -> Result<()> {
        let route = RouteConfig {
            final_outbound: "socks".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::new(),
            rules: Vec::new(),
        };
        let outbounds = vec![
            OutboundConfig::Direct {
                tag: "direct".to_string(),
            },
            OutboundConfig::Socks {
                tag: "socks".to_string(),
                server: "198.51.100.10".to_string(),
                server_port: 1080,
                username: None,
                password: None,
            },
        ];
        let router = Router::from_config(&outbounds, &route)?;
        let runtime = ProxyRuntime::new_with_outbounds(
            vec![InboundConfig::Tun {
                tag: "tun-in".to_string(),
                interface_name: None,
                mtu: 1500,
                auto_route: true,
                ipv6_enabled: false,
                dns: TunDnsMode::Direct,
                dns_addr: None,
                bypass: vec!["127.0.0.0/8".to_string()],
                tcp_timeout_seconds: None,
                udp_timeout_seconds: None,
                max_sessions: None,
            }],
            router,
            &outbounds,
        );
        let inner = ProxyRuntimeInner {
            desired_enabled: true,
            enabled: true,
            last_error: None,
            last_warnings: Vec::new(),
            tasks: JoinSet::new(),
            tun_egress_interface: None,
            watchdog_restarts: 0,
            last_watchdog_reason: None,
        };

        let preflight = runtime.tun_preflight(&inner);

        assert_eq!(preflight.status, TunRuntimeStatus::Running);
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    #[test]
    fn unsupported_tun_egress_binding_is_startup_warning() -> Result<()> {
        let mut inner = ProxyRuntimeInner {
            desired_enabled: false,
            enabled: false,
            last_error: None,
            last_warnings: Vec::new(),
            tasks: JoinSet::new(),
            tun_egress_interface: None,
            watchdog_restarts: 0,
            last_watchdog_reason: None,
        };

        super::tasks::prepare_tun_egress_binding(&mut inner)?;

        assert!(inner.last_error.is_none());
        assert!(inner.tun_egress_interface.is_none());
        assert_eq!(
            inner.last_warnings,
            vec![crate::platform::TUN_EGRESS_BINDING_UNSUPPORTED_WARNING.to_string()]
        );

        Ok(())
    }

    #[tokio::test]
    async fn tun_auto_route_requires_proxy_outbound() -> Result<()> {
        let route = RouteConfig {
            final_outbound: "direct".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::new(),
            rules: Vec::new(),
        };
        let router = Router::from_config(
            &[OutboundConfig::Direct {
                tag: "direct".to_string(),
            }],
            &route,
        )?;
        let runtime = ProxyRuntime::new_with_outbounds(
            vec![InboundConfig::Tun {
                tag: "tun-in".to_string(),
                interface_name: None,
                mtu: 1500,
                auto_route: true,
                ipv6_enabled: false,
                dns: TunDnsMode::Virtual,
                dns_addr: None,
                bypass: Vec::new(),
                tcp_timeout_seconds: None,
                udp_timeout_seconds: None,
                max_sessions: None,
            }],
            router,
            &[OutboundConfig::Direct {
                tag: "direct".to_string(),
            }],
        );

        let snapshot = runtime.snapshot().await;
        assert_eq!(snapshot.tun_status, TunRuntimeStatus::RequiresConfiguration);
        assert!(snapshot.tun_auto_route);
        assert_eq!(snapshot.tun_proxy_bypass_sources, 0);
        assert!(
            snapshot
                .tun_detail
                .contains("requires at least one proxy outbound")
        );

        Ok(())
    }

    #[tokio::test]
    async fn tun_recovery_restart_is_noop_when_tun_is_off() -> Result<()> {
        let route = RouteConfig {
            final_outbound: "direct".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::new(),
            rules: Vec::new(),
        };
        let router = Router::from_config(
            &[OutboundConfig::Direct {
                tag: "direct".to_string(),
            }],
            &route,
        )?;
        let runtime = ProxyRuntime::new_with_outbounds(
            vec![InboundConfig::Tun {
                tag: "tun-in".to_string(),
                interface_name: None,
                mtu: 1500,
                auto_route: true,
                ipv6_enabled: false,
                dns: TunDnsMode::Virtual,
                dns_addr: None,
                bypass: Vec::new(),
                tcp_timeout_seconds: None,
                udp_timeout_seconds: None,
                max_sessions: None,
            }],
            router,
            &[OutboundConfig::Direct {
                tag: "direct".to_string(),
            }],
        );

        let snapshot = runtime.restart_tun_for_recovery("test gap").await?;

        assert!(!snapshot.tun_enabled);
        assert_eq!(snapshot.tun_watchdog_restarts, 0);
        assert_eq!(snapshot.tun_last_watchdog_reason, None);

        Ok(())
    }
}
