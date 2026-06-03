#[cfg(test)]
use std::sync::{
    Mutex, MutexGuard,
    atomic::{AtomicU64, Ordering},
};
use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::OnceLock,
    time::Duration,
};

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket, lookup_host},
    time::timeout,
};

use crate::net::{dns::DnsResolver, egress, tcp};

const OUTBOUND_CONNECT_TIMEOUT_MS: u64 = 5_000;
const OUTBOUND_HANDSHAKE_TIMEOUT_MS: u64 = 5_000;
const TUN_FALLBACK_DNS_TIMEOUT_MS: u64 = 3_000;
const TUN_FALLBACK_DNS_SERVERS: &[&str] = &["119.29.29.29", "223.5.5.5", "1.1.1.1", "8.8.8.8"];

static TUN_FALLBACK_DNS: OnceLock<DnsResolver> = OnceLock::new();

fn outbound_connect_timeout() -> Duration {
    Duration::from_millis(connect_timeout_ms())
}

fn outbound_handshake_timeout() -> Duration {
    Duration::from_millis(handshake_timeout_ms())
}

pub async fn connect_tcp_with_dns(
    host: &str,
    port: u16,
    dns: Option<&DnsResolver>,
    stage: &str,
) -> Result<TcpStream> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return connect_socket(SocketAddr::new(ip, port), stage).await;
    }

    let addrs = resolve_host_with_dns(host, port, dns, stage).await?;

    let mut last_error = None;
    for addr in addrs {
        let attempt_stage = format!("{stage} via {addr}");
        match connect_socket(addr, &attempt_stage).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("{stage} resolved no addresses")))
}

pub async fn connect_socket(addr: SocketAddr, stage: &str) -> Result<TcpStream> {
    let timeout_duration = outbound_connect_timeout();
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .with_context(|| format!("{stage} failed to create TCP socket"))?;
    egress::bind_tcp_socket(&socket, addr)
        .with_context(|| format!("{stage} failed to bind egress interface"))?;
    let stream = timeout(timeout_duration, socket.connect(addr))
        .await
        .with_context(|| format!("{stage} timed out after {:?}", timeout_duration))?
        .with_context(|| format!("{stage} failed"))?;
    tcp::enable_nodelay(&stream, stage);
    Ok(stream)
}

pub fn bind_udp_socket_for_remote_addr(
    mut bind_addr: SocketAddr,
    remote_addr: Option<SocketAddr>,
    stage: &str,
) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(bind_addr),
        Type::DGRAM,
        Some(Protocol::UDP),
    )
    .map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("{stage} failed to create socket: {err}"),
        )
    })?;
    if let Some(remote_addr) = remote_addr {
        egress::bind_socket2_udp_socket(&socket, remote_addr).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("{stage} failed to bind egress interface: {err}"),
            )
        })?;
        if let Some(local_addr) = egress::local_bind_addr_for_remote(remote_addr) {
            bind_addr = local_addr;
        }
    }
    socket
        .bind(&SockAddr::from(bind_addr))
        .map_err(|err| io::Error::new(err.kind(), format!("{stage} failed to bind: {err}")))?;
    socket.set_nonblocking(true).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("{stage} failed to set nonblocking mode: {err}"),
        )
    })?;
    let socket = std::net::UdpSocket::from(socket);
    UdpSocket::from_std(socket).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("{stage} failed to create Tokio UDP socket: {err}"),
        )
    })
}

pub fn unspecified_udp_bind_addr(remote_addr: SocketAddr) -> SocketAddr {
    if remote_addr.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }
}

pub async fn resolve_host_with_dns(
    host: &str,
    port: u16,
    dns: Option<&DnsResolver>,
    stage: &str,
) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if let Some(dns) = dns {
        return dns
            .lookup(host, port)
            .await
            .with_context(|| format!("failed to resolve {host}:{port}"));
    }

    lookup_host((host, port))
        .await
        .with_context(|| format!("{stage} failed to resolve {host}:{port}"))
        .map(|addrs| addrs.collect())
}

pub async fn resolve_direct_host_with_dns(
    host: &str,
    port: u16,
    dns: Option<&DnsResolver>,
    stage: &str,
) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if let Some(dns) = dns {
        return dns
            .lookup(host, port)
            .await
            .with_context(|| format!("failed to resolve {host}:{port}"));
    }
    if egress::bound_interface_name().is_some() {
        return tun_fallback_dns_resolver()
            .lookup(host, port)
            .await
            .with_context(|| format!("{stage} failed to resolve {host}:{port} with TUN DNS"));
    }

    lookup_host((host, port))
        .await
        .with_context(|| format!("{stage} failed to resolve {host}:{port}"))
        .map(|addrs| addrs.collect())
}

fn tun_fallback_dns_resolver() -> &'static DnsResolver {
    TUN_FALLBACK_DNS.get_or_init(|| {
        let servers = TUN_FALLBACK_DNS_SERVERS
            .iter()
            .map(|server| (*server).to_string())
            .collect::<Vec<_>>();
        DnsResolver::from_servers(&servers, TUN_FALLBACK_DNS_TIMEOUT_MS)
            .expect("built-in TUN DNS fallback servers must be valid")
            .expect("built-in TUN DNS fallback servers must not be empty")
    })
}

pub fn tun_fallback_dns_server_addrs() -> Vec<SocketAddr> {
    tun_fallback_dns_resolver().server_addrs()
}

pub async fn with_handshake_timeout<T, F>(stage: &str, future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let timeout_duration = outbound_handshake_timeout();
    timeout(timeout_duration, future)
        .await
        .with_context(|| format!("{stage} timed out after {:?}", timeout_duration))?
}

#[cfg(test)]
static TEST_TIMEOUT_LOCK: Mutex<()> = Mutex::new(());
#[cfg(test)]
static TEST_CONNECT_TIMEOUT_MS: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static TEST_HANDSHAKE_TIMEOUT_MS: AtomicU64 = AtomicU64::new(0);

#[cfg(not(test))]
fn connect_timeout_ms() -> u64 {
    OUTBOUND_CONNECT_TIMEOUT_MS
}

#[cfg(test)]
fn connect_timeout_ms() -> u64 {
    match TEST_CONNECT_TIMEOUT_MS.load(Ordering::Relaxed) {
        0 => OUTBOUND_CONNECT_TIMEOUT_MS,
        override_ms => override_ms,
    }
}

#[cfg(not(test))]
fn handshake_timeout_ms() -> u64 {
    OUTBOUND_HANDSHAKE_TIMEOUT_MS
}

#[cfg(test)]
fn handshake_timeout_ms() -> u64 {
    match TEST_HANDSHAKE_TIMEOUT_MS.load(Ordering::Relaxed) {
        0 => OUTBOUND_HANDSHAKE_TIMEOUT_MS,
        override_ms => override_ms,
    }
}

#[cfg(test)]
pub struct TestTimeoutGuard {
    _lock: MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for TestTimeoutGuard {
    fn drop(&mut self) {
        TEST_CONNECT_TIMEOUT_MS.store(0, Ordering::Relaxed);
        TEST_HANDSHAKE_TIMEOUT_MS.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
pub fn override_test_timeouts(connect: Duration, handshake: Duration) -> TestTimeoutGuard {
    let lock = TEST_TIMEOUT_LOCK
        .lock()
        .expect("test timeout override mutex must not be poisoned");
    TEST_CONNECT_TIMEOUT_MS.store(connect.as_millis() as u64, Ordering::Relaxed);
    TEST_HANDSHAKE_TIMEOUT_MS.store(handshake.as_millis() as u64, Ordering::Relaxed);
    TestTimeoutGuard { _lock: lock }
}
