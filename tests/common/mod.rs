#![allow(dead_code)]

use std::{
    fs::{self, File},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::TlsAcceptor;

pub const TARGETS: [TargetKind; 3] = [TargetKind::Ipv4, TargetKind::Domain, TargetKind::Ipv6];

#[derive(Debug, Clone, Copy)]
pub enum TargetKind {
    Ipv4,
    Domain,
    Ipv6,
}

impl TargetKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Domain => "domain",
            Self::Ipv6 => "ipv6",
        }
    }
}

#[derive(Debug, Clone)]
enum SocksTarget {
    Ipv4(Ipv4Addr, u16),
    Domain(&'static str, u16),
    Ipv6(Ipv6Addr, u16),
}

pub struct TlsFiles {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

pub fn find_tool(binary: &str, display_name: &str) -> Result<PathBuf> {
    let output = Command::new(binary)
        .arg("version")
        .output()
        .with_context(|| format!("{display_name} is required for this ignored interop test"))?;
    if !output.status.success() {
        bail!("{binary} version failed");
    }
    Ok(PathBuf::from(binary))
}

pub fn tool_version(tool: &Path, display_name: &str, fallback: &str) -> Result<String> {
    let output = Command::new(tool)
        .arg("version")
        .output()
        .with_context(|| format!("failed to execute {display_name} version"))?;
    if !output.status.success() {
        bail!("{display_name} version failed");
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().next().unwrap_or(fallback).to_string())
}

pub fn unused_tcp_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

pub fn write_json(path: &Path, value: &Value) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("failed to write JSON configuration to {}", path.display()))
}

pub fn print_process_logs(server_label: &str, server_log: &Path, tabby_log: &Path) {
    eprintln!("--- {server_label} log: {} ---", server_log.display());
    eprintln!("{}", fs::read_to_string(server_log).unwrap_or_default());
    eprintln!("--- TabbyMew log: {} ---", tabby_log.display());
    eprintln!("{}", fs::read_to_string(tabby_log).unwrap_or_default());
}

pub async fn wait_for_tcp(addr: SocketAddr) -> Result<()> {
    for _ in 0..100 {
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    }
    bail!("timed out waiting for {addr}")
}

pub async fn spawn_tls_handshake_target() -> Result<(u16, JoinHandle<()>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let acceptor = TlsAcceptor::from(Arc::new(tls_server_config()?));
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(stream).await;
            });
        }
    });
    Ok((port, task))
}

fn tls_server_config() -> Result<ServerConfig> {
    let (cert_pem, key_pem) = generated_test_tls_pem()?;
    let cert = CertificateDer::from_pem_slice(cert_pem.as_bytes())
        .context("failed to parse test TLS certificate")?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .context("failed to parse test TLS key")?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("failed to build test TLS server config")
}

fn generated_test_tls_pem() -> Result<(String, String)> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("failed to generate test TLS certificate")?;
    Ok((certified.cert.pem(), certified.signing_key.serialize_pem()))
}

pub async fn assert_tcp_target_round_trip(
    name: &str,
    socks_port: u16,
    target: TargetKind,
) -> Result<()> {
    let (target_address, echo) = spawn_tcp_echo(target).await?;
    let payload = format!("tabbymew-{name}-tcp-{}", target.label());

    let mut client = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    socks_connect(&mut client, &target_address).await?;
    client.write_all(payload.as_bytes()).await?;

    let mut response = vec![0u8; payload.len()];
    timeout(Duration::from_secs(5), client.read_exact(&mut response)).await??;
    assert_eq!(response, payload.as_bytes());
    echo.await??;
    Ok(())
}

pub async fn assert_udp_target_round_trip(
    name: &str,
    socks_port: u16,
    target: TargetKind,
) -> Result<()> {
    let (target_address, echo) = spawn_udp_echo(target).await?;
    let payload = format!("tabbymew-{name}-udp-{}", target.label());

    let mut control = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    let relay_addr = socks_udp_associate(&mut control).await?;
    let client = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let packet = build_socks_udp_packet(&target_address, payload.as_bytes())?;
    client.send_to(&packet, relay_addr).await?;

    let mut buf = [0u8; 2048];
    let (n, _) = timeout(Duration::from_secs(5), client.recv_from(&mut buf)).await??;
    assert_eq!(socks_udp_payload(&buf[..n])?, payload.as_bytes());
    echo.await??;
    Ok(())
}

async fn spawn_tcp_echo(target: TargetKind) -> Result<(SocksTarget, JoinHandle<Result<()>>)> {
    match target {
        TargetKind::Ipv4 => {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let port = listener.local_addr()?.port();
            Ok((
                SocksTarget::Ipv4(Ipv4Addr::LOCALHOST, port),
                tokio::spawn(serve_tcp_echo(listener)),
            ))
        }
        TargetKind::Ipv6 => {
            let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
            let port = listener.local_addr()?.port();
            Ok((
                SocksTarget::Ipv6(Ipv6Addr::LOCALHOST, port),
                tokio::spawn(serve_tcp_echo(listener)),
            ))
        }
        TargetKind::Domain => {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let port = listener.local_addr()?.port();
            Ok((
                SocksTarget::Domain("127.0.0.1", port),
                tokio::spawn(serve_tcp_echo(listener)),
            ))
        }
    }
}

async fn serve_tcp_echo(listener: TcpListener) -> Result<()> {
    let (mut stream, _) = listener.accept().await?;
    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
    stream.write_all(&buf[..n]).await?;
    Ok(())
}

async fn spawn_udp_echo(target: TargetKind) -> Result<(SocksTarget, JoinHandle<Result<()>>)> {
    match target {
        TargetKind::Ipv4 => {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let port = socket.local_addr()?.port();
            Ok((
                SocksTarget::Ipv4(Ipv4Addr::LOCALHOST, port),
                tokio::spawn(serve_udp_echo(socket)),
            ))
        }
        TargetKind::Ipv6 => {
            let socket = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await?;
            let port = socket.local_addr()?.port();
            Ok((
                SocksTarget::Ipv6(Ipv6Addr::LOCALHOST, port),
                tokio::spawn(serve_udp_echo(socket)),
            ))
        }
        TargetKind::Domain => {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let port = socket.local_addr()?.port();
            Ok((
                SocksTarget::Domain("127.0.0.1", port),
                tokio::spawn(serve_udp_echo(socket)),
            ))
        }
    }
}

async fn serve_udp_echo(socket: UdpSocket) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    let (n, peer) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await??;
    socket.send_to(&buf[..n], peer).await?;
    Ok(())
}

async fn socks_connect(stream: &mut TcpStream, target: &SocksTarget) -> Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    assert_eq!(response, [0x05, 0x00]);

    let mut request = Vec::with_capacity(64);
    request.extend_from_slice(&[0x05, 0x01, 0x00]);
    append_socks_target(&mut request, target)?;
    stream.write_all(&request).await?;
    let _ = read_socks_reply(stream).await?;
    Ok(())
}

async fn socks_udp_associate(stream: &mut TcpStream) -> Result<SocketAddr> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    assert_eq!(response, [0x05, 0x00]);

    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    read_socks_reply(stream).await
}

async fn read_socks_reply(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        bail!("unexpected SOCKS reply version {:#x}", head[0]);
    }
    if head[1] != 0x00 {
        bail!("SOCKS request failed with status {:#x}", head[1]);
    }
    let ip = match head[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            bail!(
                "SOCKS reply used domain address {}",
                String::from_utf8_lossy(&domain)
            );
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            IpAddr::V6(octets.into())
        }
        other => bail!("unexpected SOCKS reply address type {other:#x}"),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

fn build_socks_udp_packet(target: &SocksTarget, payload: &[u8]) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(10 + payload.len());
    packet.extend_from_slice(&[0x00, 0x00, 0x00]);
    append_socks_target(&mut packet, target)?;
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn append_socks_target(buf: &mut Vec<u8>, target: &SocksTarget) -> Result<()> {
    match target {
        SocksTarget::Ipv4(addr, port) => {
            buf.push(0x01);
            buf.extend_from_slice(&addr.octets());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        SocksTarget::Domain(domain, port) => {
            let len: u8 = domain
                .len()
                .try_into()
                .context("domain is too long for SOCKS packet")?;
            buf.push(0x03);
            buf.push(len);
            buf.extend_from_slice(domain.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        SocksTarget::Ipv6(addr, port) => {
            buf.push(0x04);
            buf.extend_from_slice(&addr.octets());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

fn socks_udp_payload(packet: &[u8]) -> Result<&[u8]> {
    if packet.len() < 10 {
        bail!("SOCKS UDP packet is too short");
    }
    if packet[2] != 0 {
        bail!("SOCKS UDP fragmentation is not supported");
    }
    let offset = match packet[3] {
        0x01 => 10,
        0x03 => {
            if packet.len() < 5 {
                bail!("SOCKS UDP domain packet is too short");
            }
            5 + packet[4] as usize + 2
        }
        0x04 => 22,
        other => bail!("unexpected SOCKS UDP address type {other:#x}"),
    };
    if packet.len() < offset {
        bail!("SOCKS UDP packet is truncated");
    }
    Ok(&packet[offset..])
}

pub struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    pub fn spawn(command: &mut Command, log_path: &Path) -> Result<Self> {
        let stdout = File::create(log_path)?;
        let stderr = stdout.try_clone()?;
        let child = command
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?;
        Ok(Self { child })
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> Result<Self> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{now}", std::process::id()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
