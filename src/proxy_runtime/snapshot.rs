use std::collections::BTreeSet;

use crate::{config::InboundConfig, inbound::tun, net::egress, platform};

use super::{
    ProxyRuntime, ProxyRuntimeInner, ProxyRuntimeSnapshot, TunConfigSummary, TunPreflightSnapshot,
    TunRuntimeStatus, listeners::listener_summaries, tasks::reap_finished,
};

impl ProxyRuntime {
    pub async fn snapshot(&self) -> ProxyRuntimeSnapshot {
        let mut inner = self.inner.lock().await;
        let mut tun_inner = self.tun_inner.lock().await;
        let lan_enabled = *self.lan_enabled.lock().await;
        reap_finished(&mut inner).await;
        reap_finished(&mut tun_inner).await;
        self.snapshot_locked(&inner, &tun_inner, lan_enabled)
    }

    fn snapshot_locked(
        &self,
        inner: &ProxyRuntimeInner,
        tun_inner: &ProxyRuntimeInner,
        lan_enabled: bool,
    ) -> ProxyRuntimeSnapshot {
        let tun = self.tun_preflight(tun_inner);
        let tun_config = self.tun_config_summary();
        let local_listeners = listener_summaries(&self.inbounds);
        let lan_listeners = listener_summaries(&self.regular_inbounds(true));
        let effective_listeners = if lan_enabled {
            lan_listeners.clone()
        } else {
            local_listeners.clone()
        };
        ProxyRuntimeSnapshot {
            enabled: inner.enabled,
            tun_desired_enabled: tun_inner.desired_enabled,
            tun_enabled: tun_inner.enabled,
            tun_status: tun.status,
            tun_supported: tun.supported,
            tun_requires_privilege: tun.requires_privilege,
            tun_privilege_verified: tun.privilege_verified,
            tun_platform: tun.platform,
            tun_detail: tun.detail,
            tun_warnings: tun_inner.last_warnings.clone(),
            tun_auto_route: tun_config.auto_route,
            tun_ipv6_enabled: tun_config.ipv6_enabled,
            tun_dns_mode: tun_config.dns_mode,
            tun_dns_addr: tun_config.dns_addr,
            tun_configured_bypass_count: tun_config.configured_bypass_count,
            tun_proxy_bypass_sources: self.tun_bypass_sources.len(),
            tun_egress_interface: tun_inner.tun_egress_interface.clone(),
            tun_bound_interface: egress::bound_interface_name(),
            tun_watchdog_restarts: tun_inner.watchdog_restarts,
            tun_last_watchdog_reason: tun_inner.last_watchdog_reason.clone(),
            lan_enabled,
            local_listeners,
            lan_listeners,
            effective_listeners,
            configured_inbounds: self.inbounds.len(),
            configured_tun_inbounds: self.tun_inbounds.len(),
            last_error: inner
                .last_error
                .clone()
                .or_else(|| tun_inner.last_error.clone()),
        }
    }

    pub(super) fn tun_preflight(&self, tun_inner: &ProxyRuntimeInner) -> TunPreflightSnapshot {
        if self.tun_inbounds.is_empty() {
            return TunPreflightSnapshot {
                status: TunRuntimeStatus::NotConfigured,
                supported: true,
                requires_privilege: false,
                privilege_verified: None,
                platform: platform::name(),
                detail: "no TUN inbounds are configured".to_string(),
            };
        }

        let mut supported = true;
        let mut requires_privilege = false;
        let mut privilege_verified = None;
        let mut tun_platform = platform::name();
        let mut permission_block = None;
        for inbound in &self.tun_inbounds {
            let Some(parts) = tun::TunConfigParts::from_inbound(inbound) else {
                continue;
            };
            let preflight = tun::preflight_config(parts);
            supported &= preflight.supported;
            requires_privilege |= preflight.requires_privilege;
            privilege_verified =
                merge_privilege_verified(privilege_verified, preflight.privilege_verified);
            tun_platform = preflight.platform;
            match preflight.status {
                tun::TunPreflightStatus::Ready => {}
                tun::TunPreflightStatus::RequiresPermission => {
                    permission_block = Some(TunPreflightSnapshot {
                        status: TunRuntimeStatus::RequiresPermission,
                        supported,
                        requires_privilege,
                        privilege_verified,
                        platform: tun_platform,
                        detail: preflight.detail,
                    });
                }
                tun::TunPreflightStatus::Unsupported => {
                    return TunPreflightSnapshot {
                        status: TunRuntimeStatus::Unsupported,
                        supported: false,
                        requires_privilege,
                        privilege_verified,
                        platform: tun_platform,
                        detail: preflight.detail,
                    };
                }
            }
        }

        if self.auto_route_enabled() && self.tun_bypass_sources.is_empty() {
            return TunPreflightSnapshot {
                status: TunRuntimeStatus::RequiresConfiguration,
                supported,
                requires_privilege,
                privilege_verified,
                platform: tun_platform,
                detail:
                    "TUN auto route requires at least one proxy outbound; direct-only configs cannot safely use TUN"
                        .to_string(),
            };
        }

        if tun_inner.enabled {
            return TunPreflightSnapshot {
                status: TunRuntimeStatus::Running,
                supported,
                requires_privilege,
                privilege_verified,
                platform: tun_platform,
                detail: "TUN mode is running".to_string(),
            };
        }

        if let Some(permission_block) = permission_block {
            return permission_block;
        }

        if let Some(error) = &tun_inner.last_error {
            return TunPreflightSnapshot {
                status: TunRuntimeStatus::Failed,
                supported,
                requires_privilege,
                privilege_verified,
                platform: tun_platform,
                detail: error.clone(),
            };
        }

        TunPreflightSnapshot {
            status: TunRuntimeStatus::Stopped,
            supported,
            requires_privilege,
            privilege_verified,
            platform: tun_platform,
            detail: "TUN mode is ready".to_string(),
        }
    }

    pub(super) fn auto_route_enabled(&self) -> bool {
        self.tun_inbounds.iter().any(|inbound| match inbound {
            InboundConfig::Tun { auto_route, .. } => *auto_route,
            _ => false,
        })
    }

    pub(super) fn tun_ipv6_enabled(&self) -> bool {
        self.tun_inbounds.iter().any(|inbound| match inbound {
            InboundConfig::Tun { ipv6_enabled, .. } => *ipv6_enabled,
            _ => false,
        })
    }

    pub(super) fn tun_config_summary(&self) -> TunConfigSummary {
        let mut auto_route = false;
        let mut ipv6_enabled = false;
        let mut dns_modes = BTreeSet::new();
        let mut dns_addrs = BTreeSet::new();
        let mut dns_addr_missing = false;
        let mut bypass_entries = BTreeSet::new();

        for inbound in &self.tun_inbounds {
            let InboundConfig::Tun {
                auto_route: inbound_auto_route,
                ipv6_enabled: inbound_ipv6_enabled,
                dns,
                dns_addr,
                bypass,
                ..
            } = inbound
            else {
                continue;
            };
            auto_route |= *inbound_auto_route;
            ipv6_enabled |= *inbound_ipv6_enabled;
            dns_modes.insert(tun_dns_mode_name(*dns).to_string());
            match dns_addr.as_deref().filter(|value| !value.is_empty()) {
                Some(dns_addr) => {
                    dns_addrs.insert(dns_addr.to_string());
                }
                None => dns_addr_missing = true,
            }
            for cidr in bypass {
                bypass_entries.insert(cidr.clone());
            }
        }

        TunConfigSummary {
            auto_route,
            ipv6_enabled,
            dns_mode: summarize_unique_strings(&dns_modes),
            dns_addr: summarize_unique_optional_strings(&dns_addrs, dns_addr_missing),
            configured_bypass_count: bypass_entries.len(),
        }
    }
}

fn merge_privilege_verified(current: Option<bool>, next: Option<bool>) -> Option<bool> {
    match (current, next) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), _) | (_, Some(true)) => Some(true),
        (None, None) => None,
    }
}

fn tun_dns_mode_name(dns: crate::config::TunDnsMode) -> &'static str {
    match dns {
        crate::config::TunDnsMode::Virtual => "virtual",
        crate::config::TunDnsMode::OverTcp => "over-tcp",
        crate::config::TunDnsMode::Direct => "direct",
    }
}

fn summarize_unique_strings(values: &BTreeSet<String>) -> Option<String> {
    match values.len() {
        0 => None,
        1 => values.iter().next().cloned(),
        _ => Some("hybrid".to_string()),
    }
}

fn summarize_unique_optional_strings(values: &BTreeSet<String>, missing: bool) -> Option<String> {
    if missing && !values.is_empty() {
        Some("hybrid".to_string())
    } else {
        summarize_unique_strings(values)
    }
}
