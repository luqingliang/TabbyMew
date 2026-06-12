use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    task::JoinHandle,
    time::Instant,
};
use tracing::{debug, info, warn};

use crate::{
    control::RuntimeMetrics,
    inbound::listen,
    net::{
        address::{
            Address, Destination, append_socks_destination, destination_from_socket_addr,
            is_local_or_private_ip, read_socks_destination, read_socks_destination_from_slice,
        },
        tcp,
        udp::{UdpOutboundSession, UdpPacket},
    },
    router::Router,
    session::Session,
};

const MAX_UDP_RELAY_SESSIONS: usize = 256;
const UDP_RELAY_SESSION_IDLE_TTL: Duration = Duration::from_secs(60);
const SOCKS4_MAX_STRING_LEN: usize = 1024;

pub async fn serve(tag: String, listen: String, listen_port: u16, router: Router) -> Result<()> {
    let addr = listen::socket_addr(&listen, listen_port)?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind SOCKS inbound {tag} on {addr}"))?;
    serve_listener(tag, listener, router).await
}

pub async fn serve_listener(tag: String, listener: TcpListener, router: Router) -> Result<()> {
    serve_listener_with_connection_limit(
        tag,
        listener,
        router,
        tcp::DEFAULT_MAX_INBOUND_CONNECTIONS,
    )
    .await
}

pub async fn serve_listener_with_connection_limit(
    tag: String,
    listener: TcpListener,
    router: Router,
    max_connections: usize,
) -> Result<()> {
    let addr = listener
        .local_addr()
        .context("failed to read SOCKS listener address")?;
    debug!(inbound = %tag, listen = %addr, "SOCKS inbound listening");

    let accept_context = format!("SOCKS inbound {tag}");
    let limiter = tcp::ConnectionLimiter::new(format!("SOCKS inbound {tag}"), max_connections);
    loop {
        let Some(connection_permit) = limiter.acquire().await else {
            return Ok(());
        };
        let (stream, source) = tcp::accept_with_backoff(&listener, &accept_context).await?;
        tcp::enable_nodelay(&stream, "SOCKS inbound accepted stream");
        let tag = tag.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            if let Err(err) = handle_tcp(tag, stream, Some(source), router).await {
                debug!(error = %err, "SOCKS connection closed");
            }
        });
    }
}

pub async fn serve_tun_listener_with_connection_limit(
    tag: String,
    listener: TcpListener,
    router: Router,
    max_connections: usize,
) -> Result<()> {
    let addr = listener
        .local_addr()
        .context("failed to read SOCKS listener address")?;
    debug!(inbound = %tag, listen = %addr, "SOCKS inbound listening");

    let accept_context = format!("SOCKS inbound {tag}");
    let limiter = tcp::ConnectionLimiter::new(format!("SOCKS inbound {tag}"), max_connections);
    loop {
        let (mut stream, source) = tcp::accept_with_backoff(&listener, &accept_context).await?;
        tcp::enable_nodelay(&stream, "SOCKS inbound accepted stream");
        let Some(connection_permit) = limiter.try_acquire() else {
            if let Some(metrics) = router.runtime_metrics() {
                metrics.record_tcp_connection_limit_reached(limiter.context());
            }
            let _ = stream.shutdown().await;
            continue;
        };
        let tag = tag.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            if let Err(err) = handle_tcp_with_options(tag, stream, Some(source), router, true).await
            {
                debug!(error = %err, "SOCKS connection closed");
            }
        });
    }
}

pub async fn handle_tcp(
    tag: String,
    inbound: TcpStream,
    source: Option<SocketAddr>,
    router: Router,
) -> Result<()> {
    handle_tcp_with_options(tag, inbound, source, router, false).await
}

async fn handle_tcp_with_options(
    tag: String,
    mut inbound: TcpStream,
    source: Option<SocketAddr>,
    router: Router,
    reject_local_direct_destinations: bool,
) -> Result<()> {
    let activity = router
        .runtime_metrics()
        .map(|metrics| metrics.track_tcp_connection(&tag));
    let request = read_socks_request(&mut inbound).await?;
    if request.version == SocksRequestVersion::V5 && request.command == 0x03 {
        return handle_udp_associate(tag, inbound, source, router).await;
    }
    if request.command != 0x01 {
        send_reply_for_version(&mut inbound, request.version, 0x07).await?;
        bail!("SOCKS command {:#x} is not implemented", request.command);
    }

    if reject_local_direct_destinations && is_local_or_private_destination(&request.destination) {
        warn!(
            destination = %request.destination,
            network = "tcp",
            "rejected local/private destination from protected TUN inbound"
        );
        let _ = send_reply_for_version(&mut inbound, request.version, 0x05).await;
        bail!(
            "local/private destination {} is rejected for protected TUN inbound",
            request.destination
        );
    }
    let session = Session::tcp(tag, source, request.destination.clone())
        .with_reject_local_direct_destinations(reject_local_direct_destinations);
    let outbound = match router.pick(&session).await {
        Ok(outbound) => outbound,
        Err(err) => {
            warn!(
                destination = %request.destination,
                network = "tcp",
                error = %format!("{err:#}"),
                "connection failed"
            );
            return Err(err);
        }
    };
    if let Some(activity) = &activity {
        activity.record_outbound(outbound.tag());
    }
    let mut outbound_stream = match outbound.connect(&session).await {
        Ok(stream) => stream,
        Err(err) => {
            warn!(
                destination = %request.destination,
                outbound = %outbound.tag(),
                network = "tcp",
                error = %format!("{err:#}"),
                "connection failed"
            );
            let _ = send_reply_for_version(&mut inbound, request.version, 0x05).await;
            return Err(err);
        }
    };

    info!(
        destination = %request.destination,
        outbound = %outbound.tag(),
        network = "tcp",
        "connection routed"
    );
    send_reply_for_version(&mut inbound, request.version, 0x00).await?;
    debug!(
        source = ?session.source,
        network = ?session.network,
        destination = %request.destination,
        outbound = %outbound.tag(),
        "SOCKS connection established"
    );
    relay_tcp_with_optional_traffic(
        &router,
        outbound.as_ref(),
        &mut inbound,
        &mut outbound_stream,
    )
    .await;
    Ok(())
}

fn is_local_or_private_destination(destination: &Destination) -> bool {
    matches!(&destination.address, Address::Ip(ip) if is_local_or_private_ip(*ip))
}

async fn relay_tcp_with_optional_traffic<L, R>(
    router: &Router,
    outbound: &dyn crate::outbound::Outbound,
    inbound: &mut L,
    outbound_stream: &mut R,
) where
    L: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if let Some(metrics) = router.proxied_traffic_metrics(outbound) {
        let upload_metrics = metrics.clone();
        let _ = tcp::relay_until_first_eof_with_counters(
            inbound,
            outbound_stream,
            move |bytes| upload_metrics.record_proxied_upload(bytes),
            move |bytes| metrics.record_proxied_download(bytes),
        )
        .await;
    } else {
        let _ = tcp::relay_until_first_eof(inbound, outbound_stream).await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocksRequestVersion {
    V4,
    V5,
}

struct SocksTcpRequest {
    version: SocksRequestVersion,
    command: u8,
    destination: Destination,
}

async fn read_socks_request(stream: &mut TcpStream) -> Result<SocksTcpRequest> {
    tokio::time::timeout(
        tcp::INBOUND_HANDSHAKE_TIMEOUT,
        read_socks_request_inner(stream),
    )
    .await
    .with_context(|| {
        format!(
            "timed out reading SOCKS request after {:?}",
            tcp::INBOUND_HANDSHAKE_TIMEOUT
        )
    })?
}

async fn read_socks_request_inner(inbound: &mut TcpStream) -> Result<SocksTcpRequest> {
    let version = inbound
        .read_u8()
        .await
        .context("failed to read SOCKS version")?;
    match version {
        0x04 => read_socks4_request_inner(inbound).await,
        0x05 => read_socks5_request_inner(inbound).await,
        _ => bail!("unsupported SOCKS version {version}"),
    }
}

async fn read_socks5_request_inner(inbound: &mut TcpStream) -> Result<SocksTcpRequest> {
    let method_count = inbound
        .read_u8()
        .await
        .context("failed to read SOCKS method count")? as usize;
    let mut methods = vec![0u8; method_count];
    inbound
        .read_exact(&mut methods)
        .await
        .context("failed to read SOCKS methods")?;
    if !methods.contains(&0x00) {
        inbound.write_all(&[0x05, 0xff]).await?;
        bail!("SOCKS client does not support no-auth");
    }
    inbound.write_all(&[0x05, 0x00]).await?;

    let mut header = [0u8; 3];
    inbound
        .read_exact(&mut header)
        .await
        .context("failed to read SOCKS request header")?;
    if header[0] != 0x05 {
        bail!("invalid SOCKS request version {}", header[0]);
    }
    let destination = read_socks_destination(inbound).await?;
    Ok(SocksTcpRequest {
        version: SocksRequestVersion::V5,
        command: header[1],
        destination,
    })
}

async fn read_socks4_request_inner(inbound: &mut TcpStream) -> Result<SocksTcpRequest> {
    let command = inbound
        .read_u8()
        .await
        .context("failed to read SOCKS4 command")?;
    let mut port = [0u8; 2];
    inbound
        .read_exact(&mut port)
        .await
        .context("failed to read SOCKS4 destination port")?;
    let port = u16::from_be_bytes(port);
    let mut ip = [0u8; 4];
    inbound
        .read_exact(&mut ip)
        .await
        .context("failed to read SOCKS4 destination address")?;
    let _user_id = read_socks4_string(inbound, "user id").await?;

    let address = if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
        let domain = read_socks4_string(inbound, "domain").await?;
        let domain = String::from_utf8(domain).context("SOCKS4a domain is not valid UTF-8")?;
        if domain.is_empty() {
            bail!("SOCKS4a domain is empty");
        }
        Address::Domain(domain)
    } else {
        Address::Ip(Ipv4Addr::from(ip).into())
    };

    Ok(SocksTcpRequest {
        version: SocksRequestVersion::V4,
        command,
        destination: Destination::new(address, port),
    })
}

async fn read_socks4_string(stream: &mut TcpStream, field: &str) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    loop {
        let byte = stream
            .read_u8()
            .await
            .with_context(|| format!("failed to read SOCKS4 {field}"))?;
        if byte == 0 {
            return Ok(value);
        }
        if value.len() >= SOCKS4_MAX_STRING_LEN {
            bail!("SOCKS4 {field} is too long");
        }
        value.push(byte);
    }
}

async fn send_reply_for_version(
    stream: &mut TcpStream,
    version: SocksRequestVersion,
    code: u8,
) -> Result<()> {
    match version {
        SocksRequestVersion::V4 => send_socks4_reply(stream, code).await,
        SocksRequestVersion::V5 => send_reply(stream, code).await,
    }
}

async fn send_reply(stream: &mut TcpStream, code: u8) -> Result<()> {
    let destination = Destination::new(
        crate::net::address::Address::Ip("0.0.0.0".parse().unwrap()),
        0,
    );
    send_reply_with_bound(stream, code, &destination).await
}

async fn send_reply_with_bound(
    stream: &mut TcpStream,
    code: u8,
    bound: &Destination,
) -> Result<()> {
    let mut reply = vec![0x05, code, 0x00];
    append_socks_destination(&mut reply, bound)?;
    stream
        .write_all(&reply)
        .await
        .context("failed to write SOCKS reply")
}

async fn send_socks4_reply(stream: &mut TcpStream, code: u8) -> Result<()> {
    let status = if code == 0x00 { 0x5a } else { 0x5b };
    stream
        .write_all(&[0x00, status, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await
        .context("failed to write SOCKS4 reply")
}

async fn handle_udp_associate(
    tag: String,
    mut control: TcpStream,
    source: Option<SocketAddr>,
    router: Router,
) -> Result<()> {
    let local_ip = control
        .local_addr()
        .context("failed to read SOCKS control local address")?
        .ip();
    let bind_addr = SocketAddr::new(local_ip, 0);
    let udp_socket = UdpSocket::bind(bind_addr)
        .await
        .context("failed to bind SOCKS UDP relay socket")?;
    let relay_addr = udp_socket
        .local_addr()
        .context("failed to read SOCKS UDP relay address")?;
    let relay_destination = destination_from_socket_addr(relay_addr);
    send_reply_with_bound(&mut control, 0x00, &relay_destination).await?;

    debug!(
        inbound = %tag,
        relay = %relay_addr,
        "SOCKS UDP associate established"
    );

    let udp_loop = serve_udp_relay(tag, udp_socket, source, router);
    let mut control_buf = [0u8; 1];
    tokio::select! {
        result = udp_loop => result,
        result = control.read(&mut control_buf) => {
            result.context("failed to read SOCKS UDP control connection")?;
            Ok(())
        }
    }
}

async fn serve_udp_relay(
    tag: String,
    socket: UdpSocket,
    tcp_source: Option<SocketAddr>,
    router: Router,
) -> Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut client_addr: Option<SocketAddr> = None;
    let mut sessions: HashMap<String, UdpRelaySession> = HashMap::new();
    let (response_tx, mut response_rx) = mpsc::channel::<UdpPacket>(128);
    let mut cleanup_interval = tokio::time::interval(UDP_RELAY_SESSION_IDLE_TTL);
    cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    cleanup_interval.tick().await;

    loop {
        tokio::select! {
            _ = cleanup_interval.tick() => {
                prune_udp_relay_sessions(&mut sessions);
            }
            received = socket.recv_from(&mut buf) => {
                prune_udp_relay_sessions(&mut sessions);
                let (n, source_addr) = received.context("failed to receive SOCKS UDP datagram")?;
                if !accept_udp_client(tcp_source, client_addr, source_addr) {
                    debug!(source = %source_addr, "ignored SOCKS UDP datagram from unexpected client");
                    continue;
                }
                client_addr.get_or_insert(source_addr);

                let packet = match parse_socks_udp_packet(&buf[..n]) {
                    Ok(packet) => packet,
                    Err(err) => {
                        debug!(error = %err, "ignored invalid SOCKS UDP datagram");
                        continue;
                    }
                };
                if is_local_discovery_udp_destination(&packet.destination) {
                    debug!(
                        destination = %packet.destination,
                        "ignored local discovery UDP datagram"
                    );
                    continue;
                }

                let session = Session::udp(tag.clone(), Some(source_addr), packet.destination.clone());
                let outbound = match router.pick(&session).await {
                    Ok(outbound) => outbound,
                    Err(err) => {
                        warn!(
                            destination = %packet.destination,
                            network = "udp",
                            error = %format!("{err:#}"),
                            "connection failed"
                        );
                        return Err(err);
                    }
                };
                let session_key = format!("{}|{}", outbound.tag(), packet.destination);
                let traffic_metrics = router.proxied_traffic_metrics(outbound.as_ref());
                let udp_session = match sessions.get(&session_key) {
                    Some(session) => session.session.clone(),
                    None => {
                        evict_udp_relay_session_if_needed(&mut sessions);
                        let created: Arc<dyn UdpOutboundSession> = match outbound.udp_session(&session).await {
                            Ok(session) => session.into(),
                            Err(err) => {
                                warn!(
                                    destination = %packet.destination,
                                    outbound = %outbound.tag(),
                                    network = "udp",
                                    error = %format!("{err:#}"),
                                    "connection failed"
                                );
                                return Err(err);
                            }
                        };
                        info!(
                            destination = %packet.destination,
                            outbound = %outbound.tag(),
                            network = "udp",
                            "connection routed"
                        );
                        let receiver = spawn_udp_receiver(
                            session_key.clone(),
                            created.clone(),
                            traffic_metrics.clone(),
                            response_tx.clone(),
                        );
                        sessions.insert(session_key.clone(), UdpRelaySession {
                            session: created.clone(),
                            receiver,
                            last_used: Instant::now(),
                        });
                        created
                    }
                };
                if let Some(session) = sessions.get_mut(&session_key) {
                    session.last_used = Instant::now();
                }

                if let Err(err) = udp_session.send(&packet.destination, &packet.data).await {
                    warn!(error = %err, destination = %packet.destination, outbound = %outbound.tag(), "failed to send outbound UDP packet");
                } else if let Some(metrics) = traffic_metrics {
                    metrics.record_proxied_upload(packet.data.len() as u64);
                }
            }
            response = response_rx.recv() => {
                let Some(response) = response else {
                    break;
                };
                let Some(client_addr) = client_addr else {
                    continue;
                };
                let packet = build_socks_udp_packet(&response.source, &response.data)?;
                socket
                    .send_to(&packet, client_addr)
                    .await
                    .context("failed to send SOCKS UDP response")?;
            }
        }
    }

    Ok(())
}

struct UdpRelaySession {
    session: Arc<dyn UdpOutboundSession>,
    receiver: JoinHandle<()>,
    last_used: Instant,
}

impl Drop for UdpRelaySession {
    fn drop(&mut self) {
        self.receiver.abort();
    }
}

fn prune_udp_relay_sessions(sessions: &mut HashMap<String, UdpRelaySession>) {
    let now = Instant::now();
    sessions.retain(|session_key, session| {
        let active = !session.receiver.is_finished()
            && now.duration_since(session.last_used) <= UDP_RELAY_SESSION_IDLE_TTL;
        if !active {
            debug!(session = %session_key, "SOCKS UDP relay session evicted");
        }
        active
    })
}

fn evict_udp_relay_session_if_needed(sessions: &mut HashMap<String, UdpRelaySession>) {
    if sessions.len() < MAX_UDP_RELAY_SESSIONS {
        return;
    }
    if let Some(oldest_key) = sessions
        .iter()
        .min_by_key(|(_, session)| session.last_used)
        .map(|(key, _)| key.clone())
    {
        sessions.remove(&oldest_key);
        warn!(
            session = %oldest_key,
            max = MAX_UDP_RELAY_SESSIONS,
            "SOCKS UDP relay session limit reached; evicted oldest session"
        );
    }
}

fn spawn_udp_receiver(
    session_key: String,
    session: Arc<dyn UdpOutboundSession>,
    traffic_metrics: Option<Arc<RuntimeMetrics>>,
    response_tx: mpsc::Sender<UdpPacket>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match session.recv().await {
                Ok(packet) => {
                    if let Some(metrics) = &traffic_metrics {
                        metrics.record_proxied_download(packet.data.len() as u64);
                    }
                    if response_tx.send(packet).await.is_err() {
                        break;
                    }
                }
                Err(err) => {
                    debug!(error = %err, session = %session_key, "UDP outbound receiver stopped");
                    break;
                }
            }
        }
    })
}

fn accept_udp_client(
    tcp_source: Option<SocketAddr>,
    client_addr: Option<SocketAddr>,
    packet_source: SocketAddr,
) -> bool {
    if let Some(client_addr) = client_addr {
        return client_addr == packet_source;
    }
    tcp_source.is_none_or(|tcp_source| tcp_source.ip() == packet_source.ip())
}

fn is_local_discovery_udp_destination(destination: &Destination) -> bool {
    match &destination.address {
        crate::net::address::Address::Ip(std::net::IpAddr::V4(ip)) => {
            ip.is_broadcast()
                || ip.is_multicast()
                || (is_netbios_discovery_port(destination.port)
                    && (ip.is_private() || ip.is_link_local()))
        }
        crate::net::address::Address::Ip(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.is_multicast()
        }
        crate::net::address::Address::Domain(_) => false,
    }
}

fn is_netbios_discovery_port(port: u16) -> bool {
    matches!(port, 137 | 138)
}

struct SocksUdpInboundPacket {
    destination: Destination,
    data: Vec<u8>,
}

fn parse_socks_udp_packet(packet: &[u8]) -> Result<SocksUdpInboundPacket> {
    if packet.len() < 3 {
        bail!("SOCKS UDP datagram is too short");
    }
    if packet[0] != 0 || packet[1] != 0 {
        bail!("SOCKS UDP RSV field is invalid");
    }
    if packet[2] != 0 {
        bail!("fragmented SOCKS UDP datagrams are not supported");
    }

    let (destination, offset) = read_socks_destination_from_slice(&packet[3..])?;
    Ok(SocksUdpInboundPacket {
        destination,
        data: packet[3 + offset..].to_vec(),
    })
}

fn build_socks_udp_packet(source: &Destination, data: &[u8]) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(3 + 256 + data.len());
    packet.extend_from_slice(&[0, 0, 0]);
    append_socks_destination(&mut packet, source)?;
    packet.extend_from_slice(data);
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{OutboundConfig, RouteConfig},
        net::address::Address,
    };

    #[test]
    fn parses_socks_udp_packet() {
        let destination = Destination::new(Address::Domain("example.com".to_string()), 53);
        let packet = build_socks_udp_packet(&destination, b"hello").unwrap();
        let parsed = parse_socks_udp_packet(&packet).unwrap();
        assert_eq!(parsed.destination, destination);
        assert_eq!(parsed.data, b"hello");
    }

    #[test]
    fn detects_local_discovery_udp_destinations() {
        assert!(is_local_discovery_udp_destination(&Destination::new(
            Address::Ip("ff02::fb".parse().unwrap()),
            5353,
        )));
        assert!(is_local_discovery_udp_destination(&Destination::new(
            Address::Ip("224.0.0.251".parse().unwrap()),
            5353,
        )));
        assert!(is_local_discovery_udp_destination(&Destination::new(
            Address::Ip("10.0.0.255".parse().unwrap()),
            137,
        )));
        assert!(is_local_discovery_udp_destination(&Destination::new(
            Address::Ip("192.168.1.255".parse().unwrap()),
            138,
        )));
        assert!(!is_local_discovery_udp_destination(&Destination::new(
            Address::Ip("169.254.1.10".parse().unwrap()),
            5355,
        )));
        assert!(!is_local_discovery_udp_destination(&Destination::new(
            Address::Ip("10.0.0.255".parse().unwrap()),
            123,
        )));
        assert!(!is_local_discovery_udp_destination(&Destination::new(
            Address::Ip("8.8.8.8".parse().unwrap()),
            53,
        )));
    }

    #[tokio::test]
    async fn proxies_socks_tcp_to_direct_outbound() -> Result<()> {
        let target_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let target_addr = target_listener.local_addr()?;
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let (proxy_addr, proxy_task) = spawn_socks_inbound(direct_router()).await?;
        let mut client = TcpStream::connect(proxy_addr).await?;
        socks_connect(&mut client, destination_from_socket_addr(target_addr)).await?;
        client.write_all(b"ping").await?;

        let mut response = [0u8; 4];
        client.read_exact(&mut response).await?;
        proxy_task.abort();
        target_task.await?;

        assert_eq!(&response, b"pong");
        Ok(())
    }

    #[tokio::test]
    async fn proxies_socks4_tcp_to_direct_outbound() -> Result<()> {
        let target_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let target_addr = target_listener.local_addr()?;
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let (proxy_addr, proxy_task) = spawn_socks_inbound(direct_router()).await?;
        let mut client = TcpStream::connect(proxy_addr).await?;
        socks4_connect_ip(&mut client, target_addr).await?;
        client.write_all(b"ping").await?;

        let mut response = [0u8; 4];
        client.read_exact(&mut response).await?;
        proxy_task.abort();
        target_task.await?;

        assert_eq!(&response, b"pong");
        Ok(())
    }

    #[tokio::test]
    async fn proxies_socks4a_domain_tcp_to_direct_outbound() -> Result<()> {
        let target_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let target_addr = target_listener.local_addr()?;
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let (proxy_addr, proxy_task) = spawn_socks_inbound(direct_router()).await?;
        let mut client = TcpStream::connect(proxy_addr).await?;
        socks4a_connect_domain(&mut client, "127.0.0.1", target_addr.port()).await?;
        client.write_all(b"ping").await?;

        let mut response = [0u8; 4];
        client.read_exact(&mut response).await?;
        proxy_task.abort();
        target_task.await?;

        assert_eq!(&response, b"pong");
        Ok(())
    }

    #[tokio::test]
    async fn reports_socks_connect_failure_for_block_outbound() -> Result<()> {
        let (proxy_addr, proxy_task) = spawn_socks_inbound(block_router()).await?;
        let mut client = TcpStream::connect(proxy_addr).await?;

        client.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut method_response = [0u8; 2];
        client.read_exact(&mut method_response).await?;
        assert_eq!(method_response, [0x05, 0x00]);

        let mut request = vec![0x05, 0x01, 0x00];
        append_socks_destination(
            &mut request,
            &Destination::new(Address::Ip("127.0.0.1".parse().unwrap()), 1),
        )?;
        client.write_all(&request).await?;

        let mut reply = [0u8; 3];
        client.read_exact(&mut reply).await?;
        let _bound = read_socks_destination(&mut client).await?;
        proxy_task.abort();

        assert_eq!(reply, [0x05, 0x05, 0x00]);
        Ok(())
    }

    #[tokio::test]
    async fn reports_socks4_connect_failure_for_block_outbound() -> Result<()> {
        let (proxy_addr, proxy_task) = spawn_socks_inbound(block_router()).await?;
        let mut client = TcpStream::connect(proxy_addr).await?;

        socks4_connect_ip_expect_status(&mut client, SocketAddr::from(([127, 0, 0, 1], 1)), 0x5b)
            .await?;
        proxy_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn tun_socks_listener_closes_new_connections_when_limit_is_full() -> Result<()> {
        let metrics = std::sync::Arc::new(RuntimeMetrics::new());
        let (proxy_addr, proxy_task) =
            spawn_tun_socks_inbound(direct_router_with_metrics(metrics.clone()), 1).await?;

        let _holder = TcpStream::connect(proxy_addr).await?;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut rejected = TcpStream::connect(proxy_addr).await?;
        rejected.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut buf = [0u8; 2];
        let n = tokio::time::timeout(Duration::from_secs(1), rejected.read(&mut buf)).await??;

        proxy_task.abort();

        assert_eq!(n, 0);
        assert_eq!(metrics.snapshot().tcp_connection_limit_reached_total, 1);
        Ok(())
    }

    #[tokio::test]
    async fn tun_socks_listener_rejects_local_private_tcp_destinations() -> Result<()> {
        let (proxy_addr, proxy_task) =
            spawn_tun_socks_inbound(direct_router(), tcp::DEFAULT_MAX_INBOUND_CONNECTIONS).await?;
        let mut client = TcpStream::connect(proxy_addr).await?;

        socks_connect_expect_status(
            &mut client,
            Destination::new(Address::Ip("10.28.10.67".parse().unwrap()), 49735),
            0x05,
        )
        .await?;
        proxy_task.abort();
        Ok(())
    }

    async fn socks_connect(client: &mut TcpStream, destination: Destination) -> Result<()> {
        socks_connect_expect_status(client, destination, 0x00).await
    }

    async fn socks_connect_expect_status(
        client: &mut TcpStream,
        destination: Destination,
        expected_status: u8,
    ) -> Result<()> {
        client.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut method_response = [0u8; 2];
        client.read_exact(&mut method_response).await?;
        assert_eq!(method_response, [0x05, 0x00]);

        let mut request = vec![0x05, 0x01, 0x00];
        append_socks_destination(&mut request, &destination)?;
        client.write_all(&request).await?;

        let mut reply = [0u8; 3];
        client.read_exact(&mut reply).await?;
        let _bound = read_socks_destination(client).await?;
        assert_eq!(reply, [0x05, expected_status, 0x00]);
        Ok(())
    }

    async fn socks4_connect_ip(client: &mut TcpStream, destination: SocketAddr) -> Result<()> {
        socks4_connect_ip_expect_status(client, destination, 0x5a).await
    }

    async fn socks4_connect_ip_expect_status(
        client: &mut TcpStream,
        destination: SocketAddr,
        expected_status: u8,
    ) -> Result<()> {
        let std::net::IpAddr::V4(ip) = destination.ip() else {
            bail!("SOCKS4 test destination must be IPv4");
        };
        let mut request = vec![0x04, 0x01];
        request.extend_from_slice(&destination.port().to_be_bytes());
        request.extend_from_slice(&ip.octets());
        request.push(0x00);
        client.write_all(&request).await?;
        read_socks4_reply(client, expected_status).await
    }

    async fn socks4a_connect_domain(client: &mut TcpStream, domain: &str, port: u16) -> Result<()> {
        let mut request = vec![0x04, 0x01];
        request.extend_from_slice(&port.to_be_bytes());
        request.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        request.push(0x00);
        request.extend_from_slice(domain.as_bytes());
        request.push(0x00);
        client.write_all(&request).await?;
        read_socks4_reply(client, 0x5a).await
    }

    async fn read_socks4_reply(client: &mut TcpStream, expected_status: u8) -> Result<()> {
        let mut reply = [0u8; 8];
        client.read_exact(&mut reply).await?;
        assert_eq!(reply[0], 0x00);
        assert_eq!(reply[1], expected_status);
        Ok(())
    }

    async fn spawn_socks_inbound(
        router: Router,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let _ = serve_listener("socks-in".to_string(), listener, router).await;
        });

        Ok((addr, task))
    }

    async fn spawn_tun_socks_inbound(
        router: Router,
        max_connections: usize,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let _ = serve_tun_listener_with_connection_limit(
                "tun-in".to_string(),
                listener,
                router,
                max_connections,
            )
            .await;
        });

        Ok((addr, task))
    }

    fn direct_router() -> Router {
        Router::from_config(
            &[OutboundConfig::Direct {
                tag: "direct".to_string(),
            }],
            &RouteConfig::default(),
        )
        .unwrap()
    }

    fn direct_router_with_metrics(metrics: std::sync::Arc<RuntimeMetrics>) -> Router {
        Router::from_config_with_dns_in_dir_and_metrics(
            &[OutboundConfig::Direct {
                tag: "direct".to_string(),
            }],
            &RouteConfig::default(),
            None,
            None,
            Some(metrics),
        )
        .unwrap()
    }

    fn block_router() -> Router {
        Router::from_config(
            &[OutboundConfig::Block {
                tag: "block".to_string(),
            }],
            &RouteConfig {
                final_outbound: "block".to_string(),
                resolve_ip_cidr: false,
                rule_sets: std::collections::BTreeMap::new(),
                rules: Vec::new(),
            },
        )
        .unwrap()
    }
}
