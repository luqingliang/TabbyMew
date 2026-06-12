#[cfg(test)]
use std::time::Instant;
use std::{
    collections::{HashSet, VecDeque},
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::{
    net::{TcpStream, UdpSocket},
    task::JoinSet,
    time::sleep,
};
use tracing::debug;

use crate::{
    net::{
        address::{Address, Destination, destination_from_socket_addr},
        dns::{DnsResolver, is_tun_virtual_ip},
        egress,
        stream::{AnyStream, boxed},
        timeout,
        udp::{UdpOutboundSession, UdpPacket},
    },
    outbound::Outbound,
    session::Session,
};

pub struct DirectOutbound {
    tag: String,
    dns: Option<Arc<DnsResolver>>,
}

const HAPPY_EYEBALLS_DELAY_MS: u64 = 250;

type RaceConnectorFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send>>;
type RaceConnector<T> = Arc<dyn Fn(SocketAddr, String) -> RaceConnectorFuture<T> + Send + Sync>;

impl DirectOutbound {
    pub fn new(tag: String, dns: Option<Arc<DnsResolver>>) -> Self {
        Self { tag, dns }
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn counts_as_proxied_traffic(&self) -> bool {
        false
    }

    async fn connect(&self, session: &Session) -> Result<AnyStream> {
        let dest = &session.destination;
        debug!(outbound = %self.tag, destination = %dest, "direct TCP connecting");
        let stream = match &dest.address {
            Address::Ip(ip) => {
                let addr = SocketAddr::new(*ip, dest.port);
                ensure_direct_addr_supported(addr, session.rejects_local_direct_destinations())
                    .with_context(|| format!("failed to connect {dest} directly"))?;
                timeout::connect_socket(addr, &format!("connecting direct destination {dest}"))
                    .await
                    .with_context(|| format!("failed to connect {dest} directly"))?
            }
            Address::Domain(domain) => {
                if let Some(addrs) = session
                    .resolved_destination_addrs()
                    .and_then(usable_direct_addrs_only)
                {
                    let addrs = filter_tun_guarded_direct_addrs(
                        domain,
                        dest.port,
                        addrs,
                        session.rejects_local_direct_destinations(),
                    )?;
                    connect_happy_eyeballs(
                        addrs,
                        format!("connecting direct destination {domain}:{}", dest.port),
                        tcp_socket_connector(),
                    )
                    .await
                    .with_context(|| format!("failed to connect {dest} directly"))?
                } else if let Some(dns) = &self.dns {
                    connect_resolved(
                        dns,
                        domain,
                        dest.port,
                        session.rejects_local_direct_destinations(),
                    )
                    .await
                    .with_context(|| format!("failed to connect {dest} directly"))?
                } else {
                    connect_system_resolved(
                        domain,
                        dest.port,
                        session.rejects_local_direct_destinations(),
                    )
                    .await
                    .with_context(|| format!("failed to connect {dest} directly"))?
                }
            }
        };

        Ok(boxed(stream))
    }

    async fn udp_session(&self, session: &Session) -> Result<Box<dyn UdpOutboundSession>> {
        let resolved_destination = resolve_udp_destination(session, self.dns.as_ref()).await?;
        let bind_addr = udp_bind_addr(&session.destination, resolved_destination.as_ref());
        debug!(
            outbound = %self.tag,
            destination = %session.destination,
            bind = %bind_addr,
            resolved = ?resolved_destination.as_ref().map(|resolved| resolved.addr),
            "direct UDP session opening"
        );
        let remote_addr = resolved_destination
            .as_ref()
            .map(|destination| destination.addr)
            .or_else(|| match &session.destination.address {
                Address::Ip(ip) => Some(SocketAddr::new(*ip, session.destination.port)),
                Address::Domain(_) => None,
            });
        if let Some(remote_addr) = remote_addr {
            ensure_direct_addr_supported(remote_addr, session.rejects_local_direct_destinations())
                .with_context(|| {
                    format!(
                        "direct UDP destination {} is not usable",
                        session.destination
                    )
                })?;
        }
        let socket =
            timeout::bind_udp_socket_for_remote_addr(bind_addr, remote_addr, "direct UDP socket")
                .context("failed to prepare direct UDP socket")?;
        Ok(Box::new(DirectUdpSession {
            socket,
            resolved_destination,
        }))
    }
}

async fn connect_resolved(
    dns: &DnsResolver,
    domain: &str,
    port: u16,
    reject_local_direct_destinations: bool,
) -> std::io::Result<TcpStream> {
    let looked_up = dns
        .lookup(domain, port)
        .await
        .map_err(std::io::Error::other)?;
    let addrs = usable_direct_addrs_only(looked_up.clone())
        .ok_or_else(|| direct_no_usable_addrs_error(domain, port, &looked_up))?;
    let addrs =
        filter_tun_guarded_direct_addrs(domain, port, addrs, reject_local_direct_destinations)?;
    connect_happy_eyeballs(
        addrs,
        format!("connecting direct destination {domain}:{port}"),
        tcp_socket_connector(),
    )
    .await
}

async fn connect_system_resolved(
    domain: &str,
    port: u16,
    reject_local_direct_destinations: bool,
) -> std::io::Result<TcpStream> {
    let addrs = timeout::resolve_direct_host_with_dns(
        domain,
        port,
        None,
        &format!("resolving direct destination {domain}:{port}"),
    )
    .await
    .map_err(io::Error::other)?;
    let addrs = usable_direct_addrs_only(addrs.clone())
        .ok_or_else(|| direct_no_usable_addrs_error(domain, port, &addrs))?;
    let addrs =
        filter_tun_guarded_direct_addrs(domain, port, addrs, reject_local_direct_destinations)?;
    connect_happy_eyeballs(
        addrs,
        format!("connecting direct destination {domain}:{port}"),
        tcp_socket_connector(),
    )
    .await
}

fn tcp_socket_connector() -> RaceConnector<TcpStream> {
    Arc::new(|addr, stage| {
        Box::pin(async move {
            timeout::connect_socket(addr, &stage)
                .await
                .map_err(io::Error::other)
        })
    })
}

async fn connect_happy_eyeballs<T: Send + 'static>(
    addrs: Vec<SocketAddr>,
    stage: String,
    connector: RaceConnector<T>,
) -> io::Result<T> {
    let candidates = happy_eyeballs_candidates(addrs);
    if candidates.is_empty() {
        return Err(io::Error::other("DNS lookup returned no addresses"));
    }
    debug!(stage, candidates = ?candidates, "direct happy-eyeballs candidates");

    let mut attempts = JoinSet::new();
    for (index, addr) in candidates.into_iter().enumerate() {
        let connector = connector.clone();
        let attempt_stage = format!("{stage} via {addr}");
        attempts.spawn(async move {
            if index > 0 {
                sleep(happy_eyeballs_delay(index)).await;
            }
            connector(addr, attempt_stage).await
        });
    }

    let mut last_error = None;
    while let Some(result) = attempts.join_next().await {
        match result {
            Ok(Ok(stream)) => {
                attempts.abort_all();
                return Ok(stream);
            }
            Ok(Err(err)) => last_error = Some(err),
            Err(err) if err.is_cancelled() => {}
            Err(err) => last_error = Some(io::Error::other(err)),
        }
    }

    Err(last_error.unwrap_or_else(|| io::Error::other("all direct connection attempts failed")))
}

fn happy_eyeballs_candidates(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first) = addrs.first().copied() else {
        return Vec::new();
    };

    let mut seen = HashSet::new();
    let mut ipv4 = VecDeque::new();
    let mut ipv6 = VecDeque::new();
    for addr in addrs {
        if !seen.insert(addr) {
            continue;
        }
        if addr.is_ipv6() {
            ipv6.push_back(addr);
        } else {
            ipv4.push_back(addr);
        }
    }

    let prefer_ipv6 = first.is_ipv6();
    let mut ordered = Vec::with_capacity(ipv4.len() + ipv6.len());
    while !ipv4.is_empty() || !ipv6.is_empty() {
        if prefer_ipv6 {
            if let Some(addr) = ipv6.pop_front() {
                ordered.push(addr);
            }
            if let Some(addr) = ipv4.pop_front() {
                ordered.push(addr);
            }
        } else {
            if let Some(addr) = ipv4.pop_front() {
                ordered.push(addr);
            }
            if let Some(addr) = ipv6.pop_front() {
                ordered.push(addr);
            }
        }
    }
    ordered
}

fn happy_eyeballs_delay(index: usize) -> Duration {
    Duration::from_millis(HAPPY_EYEBALLS_DELAY_MS * index as u64)
}

async fn resolve_udp_destination(
    session: &Session,
    dns: Option<&Arc<DnsResolver>>,
) -> Result<Option<ResolvedUdpDestination>> {
    let destination = &session.destination;
    let Address::Domain(domain) = &destination.address else {
        return Ok(None);
    };

    let addr = if let Some(addrs) = session.resolved_destination_addrs() {
        first_usable_direct_addr_or_error(
            domain,
            destination.port,
            addrs,
            session.rejects_local_direct_destinations(),
        )?
    } else if let Some(dns) = dns {
        let looked_up = dns.lookup(domain, destination.port).await?;
        first_usable_direct_addr_or_error(
            domain,
            destination.port,
            looked_up,
            session.rejects_local_direct_destinations(),
        )?
    } else {
        let looked_up = timeout::resolve_direct_host_with_dns(
            domain,
            destination.port,
            None,
            &format!("resolving UDP destination {destination}"),
        )
        .await?;
        first_usable_direct_addr_or_error(
            domain,
            destination.port,
            looked_up,
            session.rejects_local_direct_destinations(),
        )?
    };
    ensure_direct_addr_supported(addr, session.rejects_local_direct_destinations())
        .with_context(|| format!("UDP destination {destination} did not resolve"))?;
    Ok(Some(ResolvedUdpDestination {
        destination: destination.clone(),
        addr,
    }))
}

fn first_usable_direct_addr_or_error(
    domain: &str,
    port: u16,
    addrs: Vec<SocketAddr>,
    reject_local_direct_destinations: bool,
) -> Result<SocketAddr> {
    let usable = usable_direct_addrs_only(addrs.clone())
        .with_context(|| direct_no_usable_addrs_error(domain, port, &addrs).to_string())?;
    filter_tun_guarded_direct_addrs(domain, port, usable, reject_local_direct_destinations)?
        .into_iter()
        .next()
        .with_context(|| format!("DNS lookup for {domain}:{port} returned no usable addresses"))
}

fn ensure_direct_addr_supported(
    addr: SocketAddr,
    reject_local_direct_destinations: bool,
) -> io::Result<()> {
    if is_tun_virtual_ip(addr.ip()) {
        return Err(io::Error::other(format!(
            "direct destination {addr} is a TUN fake-IP address; virtual DNS mapping may be stale or direct routing bypassed the TUN DNS mapper"
        )));
    }
    if reject_local_direct_destinations && crate::net::address::is_local_or_private_ip(addr.ip()) {
        return Err(io::Error::other(format!(
            "direct destination {addr} is local/private and was received from a protected TUN inbound"
        )));
    }
    if egress::remote_addr_supported(addr) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "direct destination {addr} is not usable through the bound egress interface"
        )))
    }
}

fn filter_tun_guarded_direct_addrs(
    domain: &str,
    port: u16,
    addrs: Vec<SocketAddr>,
    reject_local_direct_destinations: bool,
) -> io::Result<Vec<SocketAddr>> {
    if !reject_local_direct_destinations {
        return Ok(addrs);
    }
    let public_addrs = addrs
        .iter()
        .copied()
        .filter(|addr| !crate::net::address::is_local_or_private_ip(addr.ip()))
        .collect::<Vec<_>>();
    if public_addrs.is_empty() {
        Err(io::Error::other(format!(
            "direct destination {domain}:{port} resolved only to local/private addresses from a protected TUN inbound"
        )))
    } else {
        Ok(public_addrs)
    }
}

fn usable_direct_addrs_only(addrs: Vec<SocketAddr>) -> Option<Vec<SocketAddr>> {
    usable_direct_addrs_only_with(addrs, egress::remote_addr_supported)
}

fn usable_direct_addrs_only_with(
    addrs: Vec<SocketAddr>,
    mut supports_addr: impl FnMut(SocketAddr) -> bool,
) -> Option<Vec<SocketAddr>> {
    let addrs = addrs
        .into_iter()
        .filter(|addr| !is_tun_virtual_ip(addr.ip()))
        .filter(|addr| supports_addr(*addr))
        .collect::<Vec<_>>();
    (!addrs.is_empty()).then_some(addrs)
}

fn direct_no_usable_addrs_error(domain: &str, port: u16, addrs: &[SocketAddr]) -> io::Error {
    let fake_ips = addrs
        .iter()
        .filter(|addr| is_tun_virtual_ip(addr.ip()))
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if fake_ips.is_empty() {
        return io::Error::other(format!(
            "DNS lookup for {domain}:{port} returned no usable direct addresses"
        ));
    }

    io::Error::other(format!(
        "DNS lookup for {domain}:{port} returned no usable direct addresses; fake-IP candidates={}; virtual DNS mapping may be stale or direct routing bypassed the TUN DNS mapper",
        fake_ips.join(",")
    ))
}

fn udp_bind_addr(
    destination: &Destination,
    resolved_destination: Option<&ResolvedUdpDestination>,
) -> SocketAddr {
    match resolved_destination
        .map(|resolved| resolved.addr.ip())
        .or(match &destination.address {
            Address::Ip(ip) => Some(*ip),
            Address::Domain(_) => None,
        }) {
        Some(IpAddr::V6(_)) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
        Some(IpAddr::V4(_)) | None => {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        }
    }
}

struct ResolvedUdpDestination {
    destination: Destination,
    addr: SocketAddr,
}

struct DirectUdpSession {
    socket: UdpSocket,
    resolved_destination: Option<ResolvedUdpDestination>,
}

#[async_trait]
impl UdpOutboundSession for DirectUdpSession {
    async fn send(&self, destination: &Destination, data: &[u8]) -> Result<()> {
        if let Some(resolved) = self
            .resolved_destination
            .as_ref()
            .filter(|resolved| resolved.destination == *destination)
        {
            self.socket
                .send_to(data, resolved.addr)
                .await
                .with_context(|| format!("failed to send UDP packet to {destination}"))?;
            return Ok(());
        }

        match &destination.address {
            Address::Ip(ip) => {
                self.socket
                    .send_to(data, (*ip, destination.port))
                    .await
                    .with_context(|| format!("failed to send UDP packet to {destination}"))?;
            }
            Address::Domain(domain) => {
                self.socket
                    .send_to(data, (domain.as_str(), destination.port))
                    .await
                    .with_context(|| format!("failed to send UDP packet to {destination}"))?;
            }
        }
        Ok(())
    }

    async fn recv(&self) -> Result<UdpPacket> {
        let mut buf = vec![0u8; 64 * 1024];
        let (n, source) = self
            .socket
            .recv_from(&mut buf)
            .await
            .context("failed to receive UDP packet")?;
        buf.truncate(n);
        Ok(UdpPacket {
            source: destination_from_socket_addr(source),
            data: buf,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn direct_udp_bind_addr_follows_destination_family() {
        let ipv4 = Destination::new(Address::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53);
        let ipv6 = Destination::new(Address::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)), 53);
        let domain = Destination::new(Address::Domain("example.com".to_string()), 53);
        let resolved_ipv4 = ResolvedUdpDestination {
            destination: domain.clone(),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        };
        let resolved_ipv6 = ResolvedUdpDestination {
            destination: domain.clone(),
            addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53),
        };

        assert_eq!(
            udp_bind_addr(&ipv4, None),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        );
        assert_eq!(
            udp_bind_addr(&ipv6, None),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        );
        assert_eq!(
            udp_bind_addr(&domain, Some(&resolved_ipv4)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        );
        assert_eq!(
            udp_bind_addr(&domain, Some(&resolved_ipv6)),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        );
    }

    #[test]
    fn usable_direct_addrs_only_drops_tun_virtual_dns_pool() {
        let real = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443);
        let fake_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), 443);
        let fake_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 19, 255, 254)), 443);

        assert_eq!(
            usable_direct_addrs_only_with(vec![fake_a, real, fake_b], |_| true).unwrap(),
            vec![real]
        );
        assert!(usable_direct_addrs_only_with(vec![fake_a, fake_b], |_| true).is_none());
    }

    #[test]
    fn direct_fake_ip_errors_are_diagnostic() {
        let fake = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), 443);
        let err = ensure_direct_addr_supported(fake, false)
            .unwrap_err()
            .to_string();

        assert!(err.contains("fake-IP"));
        assert!(err.contains("virtual DNS mapping"));
    }

    #[test]
    fn protected_tun_direct_addresses_reject_local_private_targets() {
        let private = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 28, 10, 67)), 49735);
        let public = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);

        let err = ensure_direct_addr_supported(private, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("local/private"));
        assert!(ensure_direct_addr_supported(public, true).is_ok());
    }

    #[test]
    fn protected_tun_direct_addresses_filter_resolved_local_private_targets() {
        let private = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 28, 10, 67)), 49735);
        let public = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);

        assert_eq!(
            filter_tun_guarded_direct_addrs("example.com", 443, vec![private, public], true)
                .unwrap(),
            vec![public]
        );
        let err = filter_tun_guarded_direct_addrs("example.com", 443, vec![private], true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("local/private"));
    }

    #[test]
    fn no_usable_direct_address_error_mentions_fake_ip_candidates() {
        let fake = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), 443);
        let err = direct_no_usable_addrs_error("example.com", 443, &[fake]).to_string();

        assert!(err.contains("fake-IP candidates=198.18.0.1:443"));
        assert!(err.contains("virtual DNS mapping"));
    }

    #[test]
    fn usable_direct_addrs_only_drops_unsupported_address_families() {
        let ipv6 = SocketAddr::new("2001:db8::1".parse().unwrap(), 443);
        let ipv4 = SocketAddr::new("203.0.113.10".parse().unwrap(), 443);

        assert_eq!(
            usable_direct_addrs_only_with(vec![ipv6, ipv4], |addr| addr.is_ipv4()).unwrap(),
            vec![ipv4]
        );
        assert!(usable_direct_addrs_only_with(vec![ipv6], |addr| addr.is_ipv4()).is_none());
    }

    #[test]
    fn happy_eyeballs_candidates_interleave_address_families() {
        let v4a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443);
        let v4b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 443);
        let v6a = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
        let v6b = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            443,
        );

        let ordered = happy_eyeballs_candidates(vec![v4a, v4b, v6a, v6b, v4a]);

        assert_eq!(ordered, vec![v4a, v6a, v4b, v6b]);
    }

    #[tokio::test]
    async fn happy_eyeballs_second_candidate_can_win_before_slow_first() -> Result<()> {
        let slow = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
        let fast = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let connector: RaceConnector<SocketAddr> = Arc::new(move |addr, _stage| {
            Box::pin(async move {
                if addr == slow {
                    sleep(Duration::from_millis(600)).await;
                    return Ok(addr);
                }
                sleep(Duration::from_millis(10)).await;
                Ok(addr)
            })
        });

        let started = Instant::now();
        let winner =
            connect_happy_eyeballs(vec![slow, fast], "test direct".to_string(), connector).await?;

        assert_eq!(winner, fast);
        assert!(started.elapsed() < Duration::from_millis(500));
        Ok(())
    }

    #[tokio::test]
    async fn happy_eyeballs_same_family_candidates_are_also_staggered() -> Result<()> {
        let slow = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443);
        let fast = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)), 443);
        let connector: RaceConnector<SocketAddr> = Arc::new(move |addr, _stage| {
            Box::pin(async move {
                if addr == slow {
                    sleep(Duration::from_millis(600)).await;
                    return Ok(addr);
                }
                sleep(Duration::from_millis(10)).await;
                Ok(addr)
            })
        });

        let started = Instant::now();
        let winner =
            connect_happy_eyeballs(vec![slow, fast], "test direct".to_string(), connector).await?;

        assert_eq!(winner, fast);
        assert!(started.elapsed() < Duration::from_millis(500));
        Ok(())
    }
}
