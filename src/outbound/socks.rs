use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

use crate::{
    net::{
        address::{
            Address, Destination, append_socks_destination, read_socks_destination_from_slice,
        },
        dns::DnsResolver,
        stream::{AnyStream, boxed},
        timeout,
        udp::{UdpOutboundSession, UdpPacket},
    },
    outbound::Outbound,
    session::Session,
};

pub struct SocksOutbound {
    tag: String,
    server: String,
    server_port: u16,
    username: Option<String>,
    password: Option<String>,
    dns: Option<Arc<DnsResolver>>,
}

impl SocksOutbound {
    pub fn new(
        tag: String,
        server: String,
        server_port: u16,
        username: Option<String>,
        password: Option<String>,
        dns: Option<Arc<DnsResolver>>,
    ) -> Self {
        Self {
            tag,
            server,
            server_port,
            username,
            password,
            dns,
        }
    }

    async fn handshake(&self) -> Result<TcpStream> {
        let proxy_addr = format!("{}:{}", self.server, self.server_port);
        let mut stream = timeout::connect_tcp_with_dns(
            self.server.as_str(),
            self.server_port,
            self.dns.as_deref(),
            &format!("connecting SOCKS outbound {proxy_addr}"),
        )
        .await?;

        let use_auth = self.username.is_some() || self.password.is_some();
        timeout::with_handshake_timeout(&format!("SOCKS handshake with {proxy_addr}"), async {
            if use_auth {
                stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
            } else {
                stream.write_all(&[0x05, 0x01, 0x00]).await?;
            }
            stream.flush().await?;

            let mut resp = [0u8; 2];
            stream
                .read_exact(&mut resp)
                .await
                .context("failed to read SOCKS method response")?;
            if resp[0] != 0x05 {
                bail!("invalid SOCKS version in method response");
            }
            match resp[1] {
                0x00 => {}
                0x02 if use_auth => {
                    let username = self.username.as_deref().unwrap_or("");
                    let password = self.password.as_deref().unwrap_or("");
                    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
                        bail!("SOCKS username/password is too long");
                    }
                    let mut auth = Vec::with_capacity(3 + username.len() + password.len());
                    auth.push(0x01);
                    auth.push(username.len() as u8);
                    auth.extend_from_slice(username.as_bytes());
                    auth.push(password.len() as u8);
                    auth.extend_from_slice(password.as_bytes());
                    stream.write_all(&auth).await?;
                    stream.flush().await?;

                    let mut auth_resp = [0u8; 2];
                    stream
                        .read_exact(&mut auth_resp)
                        .await
                        .context("failed to read SOCKS auth response")?;
                    if auth_resp != [0x01, 0x00] {
                        bail!("SOCKS username/password authentication failed");
                    }
                }
                0xff => bail!("SOCKS outbound has no acceptable auth method"),
                other => bail!("SOCKS outbound selected unsupported auth method {other:#x}"),
            }
            Ok(())
        })
        .await?;

        Ok(stream)
    }
}

#[async_trait]
impl Outbound for SocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<AnyStream> {
        let mut stream = self.handshake().await?;

        let mut req = vec![0x05, 0x01, 0x00];
        append_socks_destination(&mut req, &session.destination)?;
        timeout::with_handshake_timeout(
            &format!(
                "SOCKS CONNECT handshake for {} via {}:{}",
                session.destination, self.server, self.server_port
            ),
            async {
                stream.write_all(&req).await?;
                stream.flush().await?;

                let mut header = [0u8; 3];
                stream
                    .read_exact(&mut header)
                    .await
                    .context("failed to read SOCKS connect response")?;
                if header[0] != 0x05 {
                    bail!("invalid SOCKS version in connect response");
                }
                if header[1] != 0x00 {
                    bail!("SOCKS outbound connect failed with code {:#x}", header[1]);
                }

                let _bound = crate::net::address::read_socks_destination(&mut stream).await?;
                Ok(())
            },
        )
        .await?;
        Ok(boxed(stream))
    }

    async fn udp_session(&self, _session: &Session) -> Result<Box<dyn UdpOutboundSession>> {
        let mut control = self.handshake().await?;
        let associate_dest = Destination::new(Address::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0);
        let mut req = vec![0x05, 0x03, 0x00];
        append_socks_destination(&mut req, &associate_dest)?;
        let relay = timeout::with_handshake_timeout(
            &format!(
                "SOCKS UDP associate handshake with {}:{}",
                self.server, self.server_port
            ),
            async {
                control.write_all(&req).await?;
                control.flush().await?;

                let mut header = [0u8; 3];
                control
                    .read_exact(&mut header)
                    .await
                    .context("failed to read SOCKS UDP associate response")?;
                if header[0] != 0x05 {
                    bail!("invalid SOCKS version in UDP associate response");
                }
                if header[1] != 0x00 {
                    bail!(
                        "SOCKS outbound UDP associate failed with code {:#x}",
                        header[1]
                    );
                }

                crate::net::address::read_socks_destination(&mut control).await
            },
        )
        .await?;
        let relay = resolve_udp_relay(&relay, &self.server, self.dns.as_deref()).await?;
        let bind_addr = timeout::unspecified_udp_bind_addr(relay);
        let socket = timeout::bind_udp_socket_for_remote_addr(
            bind_addr,
            Some(relay),
            "SOCKS outbound UDP socket",
        )
        .context("failed to prepare SOCKS outbound UDP socket")?;

        Ok(Box::new(SocksUdpSession {
            _control: control,
            socket,
            relay,
        }))
    }
}

struct SocksUdpSession {
    _control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
}

#[async_trait]
impl UdpOutboundSession for SocksUdpSession {
    async fn send(&self, destination: &Destination, data: &[u8]) -> Result<()> {
        let mut packet = Vec::with_capacity(3 + 256 + data.len());
        packet.extend_from_slice(&[0x00, 0x00, 0x00]);
        append_socks_destination(&mut packet, destination)?;
        packet.extend_from_slice(data);
        self.socket
            .send_to(&packet, self.relay)
            .await
            .with_context(|| format!("failed to send SOCKS UDP packet to {}", self.relay))?;
        Ok(())
    }

    async fn recv(&self) -> Result<UdpPacket> {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let (n, source) = self
                .socket
                .recv_from(&mut buf)
                .await
                .context("failed to receive SOCKS UDP packet")?;
            if source != self.relay || n < 3 || buf[2] != 0x00 {
                continue;
            }
            let (source, offset) = read_socks_destination_from_slice(&buf[3..n])?;
            return Ok(UdpPacket {
                source,
                data: buf[3 + offset..n].to_vec(),
            });
        }
    }
}

async fn resolve_udp_relay(
    relay: &Destination,
    server: &str,
    dns: Option<&DnsResolver>,
) -> Result<SocketAddr> {
    match &relay.address {
        Address::Ip(ip) if !ip.is_unspecified() => Ok(SocketAddr::new(*ip, relay.port)),
        Address::Ip(_) => {
            let addrs = resolve_relay_addrs(server, relay.port, dns).await?;
            addrs
                .into_iter()
                .next()
                .with_context(|| format!("SOCKS UDP relay {server} did not resolve"))
        }
        Address::Domain(domain) => {
            let addrs = resolve_relay_addrs(domain, relay.port, dns).await?;
            addrs
                .into_iter()
                .next()
                .with_context(|| format!("SOCKS UDP relay {domain} did not resolve"))
        }
    }
}

async fn resolve_relay_addrs(
    host: &str,
    port: u16,
    dns: Option<&DnsResolver>,
) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    timeout::resolve_host_with_dns(
        host,
        port,
        dns,
        &format!("resolving SOCKS UDP relay {host}"),
    )
    .await
    .with_context(|| format!("failed to resolve SOCKS UDP relay {host}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{address::Destination, timeout::override_test_timeouts};
    use crate::session::Session;
    use anyhow::Result;
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn socks_outbound_handshake_times_out_waiting_for_method_response() -> Result<()> {
        let _guard = override_test_timeouts(Duration::from_millis(200), Duration::from_millis(200));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let outbound = SocksOutbound::new(
            "socks-out".to_string(),
            "127.0.0.1".to_string(),
            addr.port(),
            None,
            None,
            None,
        );
        let session = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("example.com".to_string()), 443),
        );

        let err = match outbound.connect(&session).await {
            Ok(_) => panic!("SOCKS outbound connect unexpectedly succeeded"),
            Err(err) => err,
        };
        let text = format!("{err:#}");
        assert!(text.contains("SOCKS handshake"));
        assert!(text.contains("timed out"));

        server.abort();
        Ok(())
    }
}
