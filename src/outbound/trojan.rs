use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use sha2::{Digest, Sha224};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::Mutex,
};

use crate::{
    config::TlsClientConfig,
    net::{
        address::{Address, Destination, append_socks_destination, read_socks_destination},
        dns::DnsResolver,
        stream::{AnyStream, boxed},
        timeout, tls,
        udp::{UdpOutboundSession, UdpPacket},
    },
    outbound::Outbound,
    session::Session,
};

pub struct TrojanOutbound {
    tag: String,
    server: String,
    server_port: u16,
    password: String,
    tls: TlsClientConfig,
    dns: Option<Arc<DnsResolver>>,
}

impl TrojanOutbound {
    pub fn new(
        tag: String,
        server: String,
        server_port: u16,
        password: String,
        tls: TlsClientConfig,
        dns: Option<Arc<DnsResolver>>,
    ) -> Self {
        Self {
            tag,
            server,
            server_port,
            password,
            tls,
            dns,
        }
    }
}

#[async_trait]
impl Outbound for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<AnyStream> {
        let stream = self
            .connect_with_command(0x01, &session.destination)
            .await?;
        Ok(boxed(stream))
    }

    async fn udp_session(&self, _session: &Session) -> Result<Box<dyn UdpOutboundSession>> {
        let associate = Destination::new(Address::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0);
        let stream = self.connect_with_command(0x03, &associate).await?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(Box::new(TrojanUdpSession {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        }))
    }
}

impl TrojanOutbound {
    async fn connect_with_command(
        &self,
        command: u8,
        destination: &Destination,
    ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        let mut stream = tls::connect_tls_with_dns(
            &self.server,
            self.server_port,
            &self.tls,
            self.dns.as_deref(),
        )
        .await?;
        let mut request = self.auth_prefix();
        request.push(command);
        append_socks_destination(&mut request, destination)?;
        request.extend_from_slice(b"\r\n");
        timeout::with_handshake_timeout(
            &format!("Trojan request handshake for {destination}"),
            async {
                stream.write_all(&request).await?;
                stream.flush().await?;
                Ok(())
            },
        )
        .await?;
        Ok(stream)
    }

    fn auth_prefix(&self) -> Vec<u8> {
        let digest = Sha224::digest(self.password.as_bytes());
        let mut request = Vec::with_capacity(128);
        request.extend_from_slice(hex::encode(digest).as_bytes());
        request.extend_from_slice(b"\r\n");
        request
    }
}

struct TrojanUdpSession {
    reader: Mutex<ReadHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>,
    writer: Mutex<WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>,
}

#[async_trait]
impl UdpOutboundSession for TrojanUdpSession {
    async fn send(&self, destination: &Destination, data: &[u8]) -> Result<()> {
        if data.len() > u16::MAX as usize {
            bail!("Trojan UDP payload is too large");
        }

        let mut packet = Vec::with_capacity(256 + data.len());
        append_socks_destination(&mut packet, destination)?;
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(b"\r\n");
        packet.extend_from_slice(data);

        let mut writer = self.writer.lock().await;
        writer
            .write_all(&packet)
            .await
            .context("failed to write Trojan UDP packet")?;
        writer
            .flush()
            .await
            .context("failed to flush Trojan UDP packet")
    }

    async fn recv(&self) -> Result<UdpPacket> {
        let mut reader = self.reader.lock().await;
        let source = read_socks_destination(&mut *reader)
            .await
            .context("failed to read Trojan UDP source address")?;
        let length = reader
            .read_u16()
            .await
            .context("failed to read Trojan UDP payload length")? as usize;
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .await
            .context("failed to read Trojan UDP frame delimiter")?;
        if crlf != *b"\r\n" {
            bail!("invalid Trojan UDP frame delimiter");
        }
        let mut data = vec![0u8; length];
        reader
            .read_exact(&mut data)
            .await
            .context("failed to read Trojan UDP payload")?;
        Ok(UdpPacket { source, data })
    }
}
