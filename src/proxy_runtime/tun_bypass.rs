use std::{
    collections::{BTreeSet, VecDeque},
    net::{IpAddr, SocketAddr},
};

use anyhow::{Result, bail};
use tokio::{net::lookup_host, task::JoinSet, time::timeout};
use tracing::{debug, info};

use crate::{
    config::{InboundConfig, OutboundConfig},
    net::{
        address::{Address, parse_authority},
        dns::DnsResolver,
    },
};

use super::{MAX_TUN_BYPASS_RESOLVES, ProxyRuntime, TUN_BYPASS_RESOLVE_TIMEOUT, TunBypassSource};

impl ProxyRuntime {
    pub(super) async fn prepare_tun_inbounds(&self) -> Result<(Vec<InboundConfig>, Vec<String>)> {
        if !self.auto_route_enabled() {
            return Ok((self.tun_inbounds.clone(), Vec::new()));
        }

        debug!(
            proxy_bypass_sources = self.tun_bypass_sources.len(),
            include_ipv6 = self.tun_ipv6_enabled(),
            "resolving TUN proxy bypass sources"
        );
        let dns = self.router.dns_resolver();
        let (resolved_bypass, warnings) = resolve_tun_bypass_sources(
            &self.tun_bypass_sources,
            self.tun_ipv6_enabled(),
            dns.as_deref(),
        )
        .await?;
        let dns_bypass =
            tun_dns_bypass_cidrs(dns.as_deref(), &self.tun_inbounds, self.tun_ipv6_enabled());
        let mut extra_bypass = resolved_bypass;
        extra_bypass.extend(dns_bypass);
        extra_bypass.extend(crate::config::tun_local_bypass_cidrs());
        extra_bypass.sort();
        extra_bypass.dedup();
        info!(
            resolved_bypass_count = extra_bypass.len(),
            warning_count = warnings.len(),
            "resolved TUN proxy bypass sources"
        );
        let mut prepared = Vec::with_capacity(self.tun_inbounds.len());
        for inbound in self.tun_inbounds.clone() {
            prepared.push(extend_tun_bypass(inbound, &extra_bypass));
        }
        Ok((prepared, warnings))
    }
}

pub(super) fn tun_bypass_entry_count(inbounds: &[InboundConfig]) -> usize {
    inbounds
        .iter()
        .filter_map(|inbound| match inbound {
            InboundConfig::Tun { bypass, .. } => Some(bypass),
            _ => None,
        })
        .flatten()
        .collect::<BTreeSet<_>>()
        .len()
}

pub(super) fn tun_bypass_sources_from_outbounds(
    outbounds: &[OutboundConfig],
) -> Vec<TunBypassSource> {
    let mut sources = outbounds
        .iter()
        .filter_map(|outbound| {
            let (server, port) = outbound_server(outbound)?;
            Some(TunBypassSource {
                tag: outbound.tag().to_string(),
                server: server.to_string(),
                port,
            })
        })
        .collect::<Vec<_>>();
    sources.sort();
    sources.dedup();
    sources
}

fn outbound_server(outbound: &OutboundConfig) -> Option<(&str, u16)> {
    match outbound {
        OutboundConfig::Direct { .. } | OutboundConfig::Block { .. } => None,
        OutboundConfig::Socks {
            server,
            server_port,
            ..
        }
        | OutboundConfig::Http {
            server,
            server_port,
            ..
        }
        | OutboundConfig::Trojan {
            server,
            server_port,
            ..
        }
        | OutboundConfig::Shadowsocks2022 {
            server,
            server_port,
            ..
        }
        | OutboundConfig::Shadowsocks {
            server,
            server_port,
            ..
        }
        | OutboundConfig::AnyTls {
            server,
            server_port,
            ..
        } => Some((server.as_str(), *server_port)),
    }
}

async fn resolve_tun_bypass_sources(
    sources: &[TunBypassSource],
    include_ipv6: bool,
    dns: Option<&DnsResolver>,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut cidrs = BTreeSet::new();
    let mut domain_sources = BTreeSet::new();
    for source in sources {
        match source.server.parse::<IpAddr>() {
            Ok(ip) => {
                if let Some(cidr) = tun_bypass_cidr(ip, include_ipv6) {
                    cidrs.insert(cidr);
                }
            }
            Err(_) => {
                domain_sources.insert(source.clone());
            }
        }
    }

    let mut pending = domain_sources.into_iter().collect::<VecDeque<_>>();
    let mut tasks = JoinSet::new();
    let mut warnings = Vec::new();
    while !pending.is_empty() || !tasks.is_empty() {
        while tasks.len() < MAX_TUN_BYPASS_RESOLVES {
            let Some(source) = pending.pop_front() else {
                break;
            };
            tasks.spawn(resolve_tun_bypass_source(source, dns.cloned()));
        }

        let Some(result) = tasks.join_next().await else {
            break;
        };
        match result {
            Ok(Ok(resolved)) => {
                for addr in resolved.addrs {
                    if let Some(cidr) = tun_bypass_cidr(addr.ip(), include_ipv6) {
                        cidrs.insert(cidr);
                    }
                }
            }
            Ok(Err(warning)) => warnings.push(warning),
            Err(err) => warnings.push(format!("TUN bypass resolver task failed: {err}")),
        }
    }

    if cidrs.is_empty() && !sources.is_empty() && !warnings.is_empty() {
        bail!("failed to resolve any proxy outbound server for TUN bypass");
    }

    Ok((cidrs.into_iter().collect(), warnings))
}

pub(super) fn tun_dns_bypass_cidrs(
    dns: Option<&DnsResolver>,
    tun_inbounds: &[InboundConfig],
    include_ipv6: bool,
) -> Vec<String> {
    let mut cidrs = BTreeSet::new();
    if let Some(dns) = dns {
        for server in dns.server_addrs() {
            if let Some(cidr) = tun_bypass_cidr(server.ip(), include_ipv6) {
                cidrs.insert(cidr);
            }
        }
    }
    for server in crate::net::timeout::tun_fallback_dns_server_addrs() {
        if let Some(cidr) = tun_bypass_cidr(server.ip(), include_ipv6) {
            cidrs.insert(cidr);
        }
    }
    for inbound in tun_inbounds {
        let InboundConfig::Tun { dns_addr, .. } = inbound else {
            continue;
        };
        let Some(ip) = dns_addr.as_deref().and_then(tun_dns_addr_ip) else {
            continue;
        };
        if let Some(cidr) = tun_bypass_cidr(ip, include_ipv6) {
            cidrs.insert(cidr);
        }
    }
    cidrs.into_iter().collect()
}

fn tun_dns_addr_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip);
    }
    let destination = parse_authority(value, Some(53)).ok()?;
    match destination.address {
        Address::Ip(ip) => Some(ip),
        Address::Domain(_) => None,
    }
}

struct ResolvedTunBypassSource {
    addrs: Vec<SocketAddr>,
}

async fn resolve_tun_bypass_source(
    source: TunBypassSource,
    dns: Option<DnsResolver>,
) -> std::result::Result<ResolvedTunBypassSource, String> {
    let addrs = match dns {
        Some(dns) => timeout(
            TUN_BYPASS_RESOLVE_TIMEOUT,
            dns.lookup(&source.server, source.port),
        )
        .await
        .map_err(|_| {
            format!(
                "TUN bypass resolver timed out for outbound {} ({})",
                source.tag, source.server
            )
        })?
        .map_err(|err| {
            format!(
                "TUN bypass resolver failed for outbound {} ({}): {err:#}",
                source.tag, source.server
            )
        })?,
        None => {
            let lookup = timeout(
                TUN_BYPASS_RESOLVE_TIMEOUT,
                lookup_host((source.server.as_str(), source.port)),
            )
            .await
            .map_err(|_| {
                format!(
                    "TUN bypass resolver timed out for outbound {} ({})",
                    source.tag, source.server
                )
            })?
            .map_err(|err| {
                format!(
                    "TUN bypass resolver failed for outbound {} ({}): {err}",
                    source.tag, source.server
                )
            })?;
            lookup.collect::<Vec<_>>()
        }
    };
    if addrs.is_empty() {
        return Err(format!(
            "TUN bypass resolver returned no address for outbound {} ({})",
            source.tag, source.server
        ));
    }
    Ok(ResolvedTunBypassSource { addrs })
}

pub(super) fn tun_bypass_cidr(ip: IpAddr, include_ipv6: bool) -> Option<String> {
    match ip {
        IpAddr::V4(ip) => Some(format!("{ip}/32")),
        IpAddr::V6(ip) if include_ipv6 => Some(format!("{ip}/128")),
        IpAddr::V6(_) => None,
    }
}

pub(super) fn extend_tun_bypass(inbound: InboundConfig, extra_bypass: &[String]) -> InboundConfig {
    match inbound {
        InboundConfig::Tun {
            tag,
            interface_name,
            mtu,
            auto_route,
            ipv6_enabled,
            dns,
            dns_addr,
            mut bypass,
            tcp_timeout_seconds,
            udp_timeout_seconds,
            max_sessions,
        } => {
            bypass.retain(|cidr| tun_bypass_allowed_for_ipv6(cidr, ipv6_enabled));
            let mut seen = bypass.iter().cloned().collect::<BTreeSet<_>>();
            for cidr in extra_bypass {
                if tun_bypass_allowed_for_ipv6(cidr, ipv6_enabled) && seen.insert(cidr.clone()) {
                    bypass.push(cidr.clone());
                }
            }
            InboundConfig::Tun {
                tag,
                interface_name,
                mtu,
                auto_route,
                ipv6_enabled,
                dns,
                dns_addr,
                bypass,
                tcp_timeout_seconds,
                udp_timeout_seconds,
                max_sessions,
            }
        }
        other => other,
    }
}

fn tun_bypass_allowed_for_ipv6(cidr: &str, include_ipv6: bool) -> bool {
    include_ipv6 || !tun_bypass_cidr_is_ipv6(cidr)
}

fn tun_bypass_cidr_is_ipv6(cidr: &str) -> bool {
    let address = cidr
        .split_once('/')
        .map_or(cidr, |(address, _prefix)| address)
        .trim();
    address.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6())
}
