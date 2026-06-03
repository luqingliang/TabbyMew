use std::{
    io,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};

use anyhow::{Context as AnyhowContext, Result, bail};
use async_trait::async_trait;
use shadowsocks::{
    ProxyClientStream, ProxySocket, ServerConfig,
    config::ServerType,
    context::{Context, SharedContext},
    crypto::CipherKind,
    relay::{
        socks5::Address as SsAddress,
        udprelay::{DatagramReceive, DatagramSend, DatagramSocket, proxy_socket::UdpSocketType},
    },
};
use tokio::{
    io::ReadBuf,
    net::{TcpStream, UdpSocket},
};

use crate::{
    net::{
        address::{Address, Destination, destination_from_socket_addr},
        dns::DnsResolver,
        stream::{AnyStream, boxed},
        timeout,
        udp::{UdpOutboundSession, UdpPacket},
    },
    outbound::Outbound,
    session::Session,
};

#[derive(Debug, Clone, Copy)]
pub enum CipherProfile {
    Shadowsocks2022,
    ClassicAead,
}

pub struct ShadowsocksOutbound {
    tag: String,
    server: String,
    server_port: u16,
    server_config: Arc<ServerConfig>,
    context: SharedContext,
    dns: Option<Arc<DnsResolver>>,
}

impl ShadowsocksOutbound {
    pub fn new(
        tag: String,
        server: String,
        server_port: u16,
        method: String,
        password: String,
        profile: CipherProfile,
        dns: Option<Arc<DnsResolver>>,
    ) -> Result<Self> {
        let cipher = CipherKind::from_str(&method)
            .map_err(|_| anyhow::anyhow!("unsupported Shadowsocks cipher method {method}"))?;

        match profile {
            CipherProfile::Shadowsocks2022 if !cipher.is_aead_2022() => {
                bail!("shadowsocks-2022 outbound requires a 2022-* cipher method")
            }
            CipherProfile::ClassicAead if cipher.is_aead_2022() => {
                bail!("classic shadowsocks outbound cannot use a 2022 cipher method")
            }
            _ => {}
        }

        let server_config = ServerConfig::new((server.clone(), server_port), password, cipher)
            .context("invalid Shadowsocks server config")?;

        Ok(Self {
            tag,
            server,
            server_port,
            server_config: Arc::new(server_config),
            context: Context::new_shared(ServerType::Local),
            dns,
        })
    }
}

#[async_trait]
impl Outbound for ShadowsocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<AnyStream> {
        let target = match &session.destination.address {
            Address::Ip(ip) => {
                SsAddress::SocketAddress(SocketAddr::new(*ip, session.destination.port))
            }
            Address::Domain(domain) => {
                SsAddress::DomainNameAddress(domain.clone(), session.destination.port)
            }
        };

        let server = format!("{}:{}", self.server, self.server_port);
        let raw_stream = timeout::connect_tcp_with_dns(
            &self.server,
            self.server_port,
            self.dns.as_deref(),
            &format!("connecting Shadowsocks outbound server {server}"),
        )
        .await?;

        let stream: ProxyClientStream<TcpStream> = timeout::with_handshake_timeout(
            &format!(
                "Shadowsocks connect handshake to {} via {}",
                session.destination, server
            ),
            async {
                Ok(ProxyClientStream::from_stream(
                    self.context.clone(),
                    raw_stream,
                    self.server_config.as_ref(),
                    target,
                ))
            },
        )
        .await?;
        Ok(boxed(stream))
    }

    async fn udp_session(&self, _session: &Session) -> Result<Box<dyn UdpOutboundSession>> {
        let server = format!("{}:{}", self.server, self.server_port);
        let socket = self
            .connect_udp_socket(&server)
            .await
            .context("failed to connect Shadowsocks UDP socket")?;
        Ok(Box::new(ShadowsocksUdpSession { socket }))
    }
}

impl ShadowsocksOutbound {
    async fn connect_udp_socket(&self, server: &str) -> Result<ProxySocket<ProjectUdpSocket>> {
        let addrs = timeout::resolve_host_with_dns(
            &self.server,
            self.server_port,
            self.dns.as_deref(),
            &format!("resolving Shadowsocks UDP server {server}"),
        )
        .await?;

        let mut last_error = None;
        for addr in addrs {
            let attempt = timeout::with_handshake_timeout(
                &format!("Shadowsocks UDP handshake with {server} via {addr}"),
                async {
                    let socket = ProjectUdpSocket::connect(addr).await?;
                    Ok(ProxySocket::from_socket(
                        UdpSocketType::Client,
                        self.context.clone(),
                        self.server_config.as_ref(),
                        socket,
                    ))
                },
            )
            .await;

            match attempt {
                Ok(socket) => return Ok(socket),
                Err(err) => last_error = Some(err),
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("{server} resolved no addresses")))
    }
}

struct ProjectUdpSocket(UdpSocket);

impl ProjectUdpSocket {
    async fn connect(remote_addr: SocketAddr) -> Result<Self> {
        let bind_addr = timeout::unspecified_udp_bind_addr(remote_addr);
        let socket = timeout::bind_udp_socket_for_remote_addr(
            bind_addr,
            Some(remote_addr),
            &format!("connecting Shadowsocks UDP server {remote_addr}"),
        )?;
        socket
            .connect(remote_addr)
            .await
            .with_context(|| format!("failed to connect UDP socket to {remote_addr}"))?;
        Ok(Self(socket))
    }
}

impl DatagramSocket for ProjectUdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

impl DatagramReceive for ProjectUdpSocket {
    fn poll_recv(&self, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.0.poll_recv(cx, buf)
    }

    fn poll_recv_from(
        &self,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        self.0.poll_recv_from(cx, buf)
    }

    fn poll_recv_ready(&self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.0.poll_recv_ready(cx)
    }
}

impl DatagramSend for ProjectUdpSocket {
    fn poll_send(&self, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.0.poll_send(cx, buf)
    }

    fn poll_send_to(
        &self,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.0.poll_send_to(cx, buf, target)
    }

    fn poll_send_ready(&self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.0.poll_send_ready(cx)
    }
}

struct ShadowsocksUdpSession {
    socket: ProxySocket<ProjectUdpSocket>,
}

#[async_trait]
impl UdpOutboundSession for ShadowsocksUdpSession {
    async fn send(&self, destination: &Destination, data: &[u8]) -> Result<()> {
        let target = to_shadowsocks_address(destination);
        self.socket
            .send(&target, data)
            .await
            .with_context(|| format!("failed to send Shadowsocks UDP packet to {destination}"))?;
        Ok(())
    }

    async fn recv(&self) -> Result<UdpPacket> {
        let mut buf = vec![0u8; 64 * 1024];
        let (n, source, _packet_len) = self
            .socket
            .recv(&mut buf)
            .await
            .context("failed to receive Shadowsocks UDP packet")?;
        buf.truncate(n);
        Ok(UdpPacket {
            source: from_shadowsocks_address(source),
            data: buf,
        })
    }
}

fn to_shadowsocks_address(destination: &Destination) -> SsAddress {
    match &destination.address {
        Address::Ip(ip) => SsAddress::SocketAddress(SocketAddr::new(*ip, destination.port)),
        Address::Domain(domain) => SsAddress::DomainNameAddress(domain.clone(), destination.port),
    }
}

fn from_shadowsocks_address(address: SsAddress) -> Destination {
    match address {
        SsAddress::SocketAddress(addr) => destination_from_socket_addr(addr),
        SsAddress::DomainNameAddress(domain, port) => {
            Destination::new(Address::Domain(domain), port)
        }
    }
}
