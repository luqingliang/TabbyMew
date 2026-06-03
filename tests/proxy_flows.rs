use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, LazyLock},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sha2::{Digest, Sha224};
use shadowsocks::{
    ProxyListener,
    config::{ServerConfig as ShadowsocksServerConfig, ServerType},
    context::Context as ShadowsocksContext,
    crypto::CipherKind,
    relay::{socks5::Address as ShadowsocksAddress, udprelay::ProxySocket},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::{Duration, sleep, timeout},
};
use tokio_rustls::TlsAcceptor;

const BASIC_USER_PASS: &str = "Basic dXNlcjpleGFtcGxlLXBhc3N3b3Jk";
static PROXY_FLOW_TEST_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProtocolDestination {
    address: ProtocolAddress,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProtocolAddress {
    Ip(IpAddr),
    Domain(String),
}

impl ProtocolDestination {
    fn domain(domain: &str, port: u16) -> Self {
        Self {
            address: ProtocolAddress::Domain(domain.to_string()),
            port,
        }
    }

    fn ip(ip: IpAddr, port: u16) -> Self {
        Self {
            address: ProtocolAddress::Ip(ip),
            port,
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn http_inbound_accepts_valid_basic_auth() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    assert_plain_http_auth_flow("http").await
}

#[tokio::test(flavor = "current_thread")]
async fn hybrid_inbound_accepts_valid_http_basic_auth() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    assert_plain_http_auth_flow("hybrid").await
}

#[tokio::test(flavor = "current_thread")]
async fn http_outbound_sends_basic_proxy_authorization() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    let mock_proxy = TcpListener::bind(("127.0.0.1", 0)).await?;
    let mock_proxy_addr = mock_proxy.local_addr()?;
    let mock_proxy_task = tokio::spawn(async move {
        let (mut stream, _) = mock_proxy.accept().await.unwrap();
        let head = String::from_utf8(read_http_head(&mut stream).await.unwrap()).unwrap();
        assert!(head.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(head.contains("Proxy-Authorization: Basic dXNlcjpleGFtcGxlLXBhc3N3b3Jk\r\n"));

        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let socks_port = unused_tcp_port()?;
    let config = write_config(
        "http-outbound-auth",
        &format!(
            r#"{{
  "log": {{"level": "error"}},
  "inbounds": [
    {{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": {socks_port}}}
  ],
  "outbounds": [
    {{
      "type": "http",
      "tag": "http-out",
      "server": "127.0.0.1",
      "server_port": {},
      "username": "user",
      "password": "example-password"
    }}
  ],
  "route": {{"final": "http-out", "rules": []}}
}}"#,
            mock_proxy_addr.port()
        ),
    )?;
    let _app = spawn_tabbymew(&config)?;
    wait_for_tcp(SocketAddr::from(([127, 0, 0, 1], socks_port))).await?;

    let mut client = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    socks_connect_domain(&mut client, "example.com", 443).await?;
    client.write_all(b"ping").await?;

    let mut response = [0u8; 4];
    client.read_exact(&mut response).await?;
    assert_eq!(&response, b"pong");
    mock_proxy_task.await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trojan_outbound_tcp_interops_with_tls_server() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    let password = "example-password";
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let mut stream = accept_tls(listener).await.unwrap();
        let destination = read_trojan_request(&mut stream, password, 0x01)
            .await
            .unwrap();
        assert_eq!(
            destination,
            ProtocolDestination::domain("trojan.example.test", 443)
        );
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let socks_port = unused_tcp_port()?;
    let config = write_config(
        "trojan-tcp",
        &format!(
            r#"{{
  "log": {{"level": "error"}},
  "inbounds": [
    {{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": {socks_port}}}
  ],
  "outbounds": [
    {{
      "type": "trojan",
      "tag": "trojan-out",
      "server": "127.0.0.1",
      "server_port": {},
      "password": "{password}",
      "tls": {{"server_name": "localhost", "insecure": true}}
    }}
  ],
  "route": {{"final": "trojan-out", "rules": []}}
}}"#,
            server_addr.port()
        ),
    )?;
    let _app = spawn_tabbymew(&config)?;
    wait_for_tcp(SocketAddr::from(([127, 0, 0, 1], socks_port))).await?;

    let mut client = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    socks_connect_domain(&mut client, "trojan.example.test", 443).await?;
    client.write_all(b"ping").await?;

    let mut response = [0u8; 4];
    client.read_exact(&mut response).await?;
    assert_eq!(&response, b"pong");
    server.await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trojan_outbound_udp_interops_with_tls_server() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    let password = "example-password";
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let mut stream = accept_tls(listener).await.unwrap();
        let associate = read_trojan_request(&mut stream, password, 0x03)
            .await
            .unwrap();
        assert_eq!(
            associate,
            ProtocolDestination::ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        );

        let destination = read_socks_destination_for_test(&mut stream).await.unwrap();
        assert_eq!(
            destination,
            ProtocolDestination::domain("udp.trojan.example.test", 5353)
        );
        let length = stream.read_u16().await.unwrap() as usize;
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await.unwrap();
        assert_eq!(&crlf, b"\r\n");
        let mut payload = vec![0u8; length];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, b"ping");

        write_socks_destination_for_test(&mut stream, &destination)
            .await
            .unwrap();
        stream.write_all(&4u16.to_be_bytes()).await.unwrap();
        stream.write_all(b"\r\n").await.unwrap();
        stream.write_all(b"pong").await.unwrap();
    });

    let socks_port = unused_tcp_port()?;
    let config = write_config(
        "trojan-udp",
        &format!(
            r#"{{
  "log": {{"level": "error"}},
  "inbounds": [
    {{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": {socks_port}}}
  ],
  "outbounds": [
    {{
      "type": "trojan",
      "tag": "trojan-out",
      "server": "127.0.0.1",
      "server_port": {},
      "password": "{password}",
      "tls": {{"server_name": "localhost", "insecure": true}}
    }}
  ],
  "route": {{"final": "trojan-out", "rules": []}}
}}"#,
            server_addr.port()
        ),
    )?;
    let _app = spawn_tabbymew(&config)?;
    wait_for_tcp(SocketAddr::from(([127, 0, 0, 1], socks_port))).await?;

    let mut control = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    let relay_addr = socks_udp_associate(&mut control).await?;
    let udp_client = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let packet = build_socks_udp_domain_packet("udp.trojan.example.test", 5353, b"ping")?;
    udp_client.send_to(&packet, relay_addr).await?;

    let mut response = [0u8; 512];
    let (n, _) = timeout(Duration::from_secs(3), udp_client.recv_from(&mut response)).await??;
    assert_eq!(socks_udp_payload(&response[..n])?, b"pong");
    server.await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn shadowsocks_outbound_tcp_interops_with_proxy_listener() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    assert_shadowsocks_tcp_round_trip("shadowsocks", "aes-128-gcm", "example-password").await
}

#[tokio::test(flavor = "current_thread")]
async fn shadowsocks_2022_outbound_tcp_interops_with_proxy_listener() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    assert_shadowsocks_tcp_round_trip(
        "shadowsocks-2022",
        "2022-blake3-aes-128-gcm",
        "AAAAAAAAAAAAAAAAAAAAAA==",
    )
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn shadowsocks_outbound_udp_interops_with_proxy_socket() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    assert_shadowsocks_udp_round_trip("shadowsocks", "aes-128-gcm", "example-password").await
}

#[tokio::test(flavor = "current_thread")]
async fn shadowsocks_outbound_tcp_uses_configured_dns_for_server_domain() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    let (dns_addr, dns_task) = spawn_dns_server(IpAddr::V4(Ipv4Addr::LOCALHOST)).await?;
    let result = assert_shadowsocks_tcp_round_trip_with_server(
        "shadowsocks",
        "aes-128-gcm",
        "example-password",
        "ss-server.example.test",
        Some(dns_addr),
    )
    .await;
    dns_task.abort();
    result
}

#[tokio::test(flavor = "current_thread")]
async fn shadowsocks_outbound_udp_uses_configured_dns_for_server_domain() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    let (dns_addr, dns_task) = spawn_dns_server(IpAddr::V4(Ipv4Addr::LOCALHOST)).await?;
    let result = assert_shadowsocks_udp_round_trip_with_server(
        "shadowsocks",
        "aes-128-gcm",
        "example-password",
        "ss-server.example.test",
        Some(dns_addr),
    )
    .await;
    dns_task.abort();
    result
}

#[tokio::test(flavor = "current_thread")]
async fn shadowsocks_2022_outbound_udp_interops_with_proxy_socket() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    assert_shadowsocks_udp_round_trip(
        "shadowsocks-2022",
        "2022-blake3-aes-128-gcm",
        "AAAAAAAAAAAAAAAAAAAAAA==",
    )
    .await
}

async fn assert_shadowsocks_udp_round_trip(
    outbound_type: &str,
    method: &str,
    password: &str,
) -> Result<()> {
    assert_shadowsocks_udp_round_trip_with_server(
        outbound_type,
        method,
        password,
        "127.0.0.1",
        None,
    )
    .await
}

async fn assert_shadowsocks_udp_round_trip_with_server(
    outbound_type: &str,
    method: &str,
    password: &str,
    server_host: &str,
    dns_addr: Option<SocketAddr>,
) -> Result<()> {
    let cipher = parse_shadowsocks_method(method)?;
    let config = ShadowsocksServerConfig::new(("127.0.0.1", 0), password, cipher)?;
    let context = ShadowsocksContext::new_shared(ServerType::Server);
    let socket = ProxySocket::bind(context, &config).await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        let (n, peer, destination, _) = socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(
            shadowsocks_address_to_destination(&destination),
            ProtocolDestination::domain("udp.ss.example.test", 5353)
        );
        socket.send_to(peer, &destination, b"pong").await.unwrap();
    });

    let socks_port = unused_tcp_port()?;
    let dns_config = dns_config_json(dns_addr);
    let config = write_config(
        &format!("{outbound_type}-udp"),
        &format!(
            r#"{{
  "log": {{"level": "error"}},
{dns_config}  "inbounds": [
    {{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": {socks_port}}}
  ],
  "outbounds": [
    {{
      "type": "{outbound_type}",
      "tag": "ss-out",
      "server": "{server_host}",
      "server_port": {},
      "method": "{method}",
      "password": "{password}"
    }}
  ],
  "route": {{"final": "ss-out", "rules": []}}
}}"#,
            server_addr.port()
        ),
    )?;
    let _app = spawn_tabbymew(&config)?;
    wait_for_tcp(SocketAddr::from(([127, 0, 0, 1], socks_port))).await?;

    let mut control = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    let relay_addr = socks_udp_associate(&mut control).await?;
    let udp_client = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let packet = build_socks_udp_domain_packet("udp.ss.example.test", 5353, b"ping")?;
    udp_client.send_to(&packet, relay_addr).await?;

    let mut response = [0u8; 512];
    let (n, _) = timeout(Duration::from_secs(3), udp_client.recv_from(&mut response)).await??;
    assert_eq!(socks_udp_payload(&response[..n])?, b"pong");
    server.await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn direct_outbound_uses_configured_dns_for_tcp_domains() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    let (dns_addr, dns_task) = spawn_dns_server(IpAddr::V4(Ipv4Addr::LOCALHOST)).await?;
    let target_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let target_addr = target_listener.local_addr()?;
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.unwrap();
        let head = String::from_utf8(read_http_head(&mut stream).await.unwrap()).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        head
    });

    let proxy_port = unused_tcp_port()?;
    let config = write_config(
        "direct-dns-tcp",
        &format!(
            r#"{{
  "log": {{"level": "error"}},
  "dns": {{"servers": ["{dns_addr}"]}},
  "inbounds": [
    {{"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": {proxy_port}}}
  ],
  "outbounds": [
    {{"type": "direct", "tag": "direct"}}
  ],
  "route": {{"final": "direct", "rules": []}}
}}"#
        ),
    )?;
    let _app = spawn_tabbymew(&config)?;
    wait_for_tcp(SocketAddr::from(([127, 0, 0, 1], proxy_port))).await?;

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    let request = format!(
        "GET http://example.test:{}/dns HTTP/1.1\r\nHost: example.test:{}\r\n\r\n",
        target_addr.port(),
        target_addr.port()
    );
    client.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    client.read_to_end(&mut response).await?;

    let target_head = target_task.await?;
    dns_task.abort();
    assert!(String::from_utf8(response)?.contains("\r\n\r\nok"));
    assert!(target_head.starts_with("GET /dns HTTP/1.1\r\n"));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn socks_udp_uses_configured_dns_for_domain_packets() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    let (dns_addr, dns_task) = spawn_dns_server(IpAddr::V4(Ipv4Addr::LOCALHOST)).await?;
    let target = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let target_addr = target.local_addr()?;
    let target_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (n, peer) = target.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        target.send_to(b"pong", peer).await.unwrap();
    });

    let socks_port = unused_tcp_port()?;
    let config = write_config(
        "direct-dns-udp",
        &format!(
            r#"{{
  "log": {{"level": "error"}},
  "dns": {{"servers": ["{dns_addr}"]}},
  "inbounds": [
    {{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": {socks_port}}}
  ],
  "outbounds": [
    {{"type": "direct", "tag": "direct"}}
  ],
  "route": {{"final": "direct", "rules": []}}
}}"#
        ),
    )?;
    let _app = spawn_tabbymew(&config)?;
    wait_for_tcp(SocketAddr::from(([127, 0, 0, 1], socks_port))).await?;

    let mut control = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    let relay_addr = socks_udp_associate(&mut control).await?;
    let udp_client = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let packet = build_socks_udp_domain_packet("udp.example.test", target_addr.port(), b"ping")?;
    udp_client.send_to(&packet, relay_addr).await?;

    let mut response = [0u8; 512];
    let (n, _) = timeout(Duration::from_secs(3), udp_client.recv_from(&mut response)).await??;
    let payload = socks_udp_payload(&response[..n])?;
    dns_task.abort();
    target_task.await?;
    assert_eq!(payload, b"pong");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn route_resolves_tcp_domain_for_ip_cidr_matching() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    let (dns_addr, dns_task) = spawn_dns_server(IpAddr::V4(Ipv4Addr::LOCALHOST)).await?;
    let proxy_port = unused_tcp_port()?;
    let config = write_config(
        "route-resolve-ip-cidr-tcp",
        &format!(
            r#"{{
  "log": {{"level": "error"}},
  "dns": {{"servers": ["{dns_addr}"]}},
  "inbounds": [
    {{"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": {proxy_port}}}
  ],
  "outbounds": [
    {{"type": "direct", "tag": "direct"}},
    {{"type": "block", "tag": "block"}}
  ],
  "route": {{
    "final": "direct",
    "resolve_ip_cidr": true,
    "rules": [
      {{"ip_cidr": ["127.0.0.0/8"], "outbound": "block"}}
    ]
  }}
}}"#
        ),
    )?;
    let _app = spawn_tabbymew(&config)?;
    wait_for_tcp(SocketAddr::from(([127, 0, 0, 1], proxy_port))).await?;

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    client
        .write_all(b"GET http://blocked.example:80/path HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
        .await?;
    let response = String::from_utf8(read_http_head(&mut client).await?)?;
    dns_task.abort();

    assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn route_resolves_udp_domain_for_ip_cidr_matching() -> Result<()> {
    let _guard = PROXY_FLOW_TEST_LOCK.lock().await;
    let (dns_addr, dns_task) = spawn_dns_server(IpAddr::V4(Ipv4Addr::LOCALHOST)).await?;
    let socks_port = unused_tcp_port()?;
    let config = write_config(
        "route-resolve-ip-cidr-udp",
        &format!(
            r#"{{
  "log": {{"level": "error"}},
  "dns": {{"servers": ["{dns_addr}"]}},
  "inbounds": [
    {{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": {socks_port}}}
  ],
  "outbounds": [
    {{"type": "direct", "tag": "direct"}},
    {{"type": "block", "tag": "block"}}
  ],
  "route": {{
    "final": "direct",
    "resolve_ip_cidr": true,
    "rules": [
      {{"ip_cidr": ["127.0.0.0/8"], "outbound": "block"}}
    ]
  }}
}}"#
        ),
    )?;
    let _app = spawn_tabbymew(&config)?;
    wait_for_tcp(SocketAddr::from(([127, 0, 0, 1], socks_port))).await?;

    let mut control = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    let relay_addr = socks_udp_associate(&mut control).await?;
    let udp_client = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let packet = build_socks_udp_domain_packet("blocked-udp.example", 53, b"ping")?;
    udp_client.send_to(&packet, relay_addr).await?;

    let mut response = [0u8; 512];
    let received = timeout(
        Duration::from_millis(500),
        udp_client.recv_from(&mut response),
    )
    .await;
    dns_task.abort();

    assert!(
        received.is_err(),
        "blocked UDP packet should not receive a response"
    );
    Ok(())
}

async fn assert_plain_http_auth_flow(inbound_type: &str) -> Result<()> {
    let target_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let target_addr = target_listener.local_addr()?;
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.unwrap();
        let head = String::from_utf8(read_http_head(&mut stream).await.unwrap()).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        head
    });

    let proxy_port = unused_tcp_port()?;
    let config = write_config(
        &format!("{inbound_type}-inbound-auth"),
        &format!(
            r#"{{
  "log": {{"level": "error"}},
  "inbounds": [
    {{
      "type": "{inbound_type}",
      "tag": "proxy-in",
      "listen": "127.0.0.1",
      "listen_port": {proxy_port},
      "username": "user",
      "password": "example-password"
    }}
  ],
  "outbounds": [
    {{"type": "direct", "tag": "direct"}}
  ],
  "route": {{"final": "direct", "rules": []}}
}}"#
        ),
    )?;
    let _app = spawn_tabbymew(&config)?;
    wait_for_tcp(SocketAddr::from(([127, 0, 0, 1], proxy_port))).await?;

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    let request = format!(
        "GET http://{target_addr}/path?q=1 HTTP/1.1\r\n\
         Host: {target_addr}\r\n\
         Proxy-Authorization: {BASIC_USER_PASS}\r\n\
         \r\n"
    );
    client.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    client.read_to_end(&mut response).await?;
    let target_head = target_task.await?;

    assert!(String::from_utf8(response)?.contains("\r\n\r\nok"));
    assert!(target_head.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
    assert!(!target_head.contains("Proxy-Authorization:"));
    Ok(())
}

async fn assert_shadowsocks_tcp_round_trip(
    outbound_type: &str,
    method: &str,
    password: &str,
) -> Result<()> {
    assert_shadowsocks_tcp_round_trip_with_server(
        outbound_type,
        method,
        password,
        "127.0.0.1",
        None,
    )
    .await
}

async fn assert_shadowsocks_tcp_round_trip_with_server(
    outbound_type: &str,
    method: &str,
    password: &str,
    server_host: &str,
    dns_addr: Option<SocketAddr>,
) -> Result<()> {
    let cipher = parse_shadowsocks_method(method)?;
    let server_config = ShadowsocksServerConfig::new(("127.0.0.1", 0), password, cipher)?;
    let context = ShadowsocksContext::new_shared(ServerType::Server);
    let listener = ProxyListener::bind(context, &server_config).await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let destination = stream.handshake().await.unwrap();
        assert_eq!(
            shadowsocks_address_to_destination(&destination),
            ProtocolDestination::domain("ss.example.test", 443)
        );
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let socks_port = unused_tcp_port()?;
    let dns_config = dns_config_json(dns_addr);
    let config = write_config(
        &format!("{outbound_type}-tcp"),
        &format!(
            r#"{{
  "log": {{"level": "error"}},
{dns_config}  "inbounds": [
    {{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": {socks_port}}}
  ],
  "outbounds": [
    {{
      "type": "{outbound_type}",
      "tag": "ss-out",
      "server": "{server_host}",
      "server_port": {},
      "method": "{method}",
      "password": "{password}"
    }}
  ],
  "route": {{"final": "ss-out", "rules": []}}
}}"#,
            server_addr.port()
        ),
    )?;
    let _app = spawn_tabbymew(&config)?;
    wait_for_tcp(SocketAddr::from(([127, 0, 0, 1], socks_port))).await?;

    let mut client = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    socks_connect_domain(&mut client, "ss.example.test", 443).await?;
    client.write_all(b"ping").await?;

    let mut response = [0u8; 4];
    client.read_exact(&mut response).await?;
    assert_eq!(&response, b"pong");
    server.await?;
    Ok(())
}

fn spawn_tabbymew(config: &Path) -> Result<ChildGuard> {
    let state_dir = config.with_extension("state");
    let log_file = config.with_extension("log");
    let control_port = unused_tcp_port()?;
    let child = Command::new(env!("CARGO_BIN_EXE_TabbyMew"))
        .arg("--config")
        .arg(config)
        .arg("run")
        .env("TABBYMEW_STATE_DIR", &state_dir)
        .env("TABBYMEW_LOG_FILE", &log_file)
        .env(
            "TABBYMEW_CONTROL_LISTEN",
            format!("127.0.0.1:{control_port}"),
        )
        .env_remove("TABBYMEW_STATE_FILE")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to start TabbyMew")?;
    Ok(ChildGuard { child })
}

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_config(name: &str, contents: &str) -> Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "tabbymew-{name}-{}-{nanos}.json",
        std::process::id()
    ));
    fs::write(&path, contents).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn dns_config_json(dns_addr: Option<SocketAddr>) -> String {
    dns_addr
        .map(|addr| format!(r#"  "dns": {{"servers": ["{addr}"]}},"#) + "\n")
        .unwrap_or_default()
}

fn unused_tcp_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

async fn wait_for_tcp(addr: SocketAddr) -> Result<()> {
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(20)).await;
    }
    bail!("timed out waiting for TabbyMew to listen on {addr}")
}

async fn accept_tls(listener: TcpListener) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
    let acceptor = TlsAcceptor::from(Arc::new(tls_server_config()?));
    let (stream, _) = listener.accept().await?;
    acceptor
        .accept(stream)
        .await
        .context("mock TLS server handshake failed")
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

async fn read_trojan_request<R>(
    stream: &mut R,
    password: &str,
    expected_command: u8,
) -> Result<ProtocolDestination>
where
    R: AsyncRead + Unpin,
{
    let expected_digest = hex::encode(Sha224::digest(password.as_bytes()));
    let mut digest = vec![0u8; expected_digest.len()];
    stream.read_exact(&mut digest).await?;
    assert_eq!(digest, expected_digest.as_bytes());
    let mut crlf = [0u8; 2];
    stream.read_exact(&mut crlf).await?;
    assert_eq!(&crlf, b"\r\n");

    let command = stream.read_u8().await?;
    assert_eq!(command, expected_command);
    let destination = read_socks_destination_for_test(stream).await?;
    stream.read_exact(&mut crlf).await?;
    assert_eq!(&crlf, b"\r\n");
    Ok(destination)
}

async fn read_socks_destination_for_test<R>(stream: &mut R) -> Result<ProtocolDestination>
where
    R: AsyncRead + Unpin,
{
    let atyp = stream.read_u8().await?;
    read_address_for_test(stream, atyp).await
}

async fn read_address_for_test<R>(stream: &mut R, atyp: u8) -> Result<ProtocolDestination>
where
    R: AsyncRead + Unpin,
{
    let address = match atyp {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            ProtocolAddress::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        0x03 => {
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            ProtocolAddress::Domain(String::from_utf8(domain)?)
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            ProtocolAddress::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        other => bail!("unexpected address type {other:#x}"),
    };
    let port = stream.read_u16().await?;
    Ok(ProtocolDestination { address, port })
}

async fn write_socks_destination_for_test<W>(
    stream: &mut W,
    destination: &ProtocolDestination,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    match &destination.address {
        ProtocolAddress::Ip(IpAddr::V4(addr)) => {
            stream.write_u8(0x01).await?;
            stream.write_all(&addr.octets()).await?;
        }
        ProtocolAddress::Domain(domain) => {
            stream.write_u8(0x03).await?;
            stream
                .write_u8(domain.len().try_into().context("domain is too long")?)
                .await?;
            stream.write_all(domain.as_bytes()).await?;
        }
        ProtocolAddress::Ip(IpAddr::V6(addr)) => {
            stream.write_u8(0x04).await?;
            stream.write_all(&addr.octets()).await?;
        }
    }
    stream.write_all(&destination.port.to_be_bytes()).await?;
    Ok(())
}

fn shadowsocks_address_to_destination(address: &ShadowsocksAddress) -> ProtocolDestination {
    match address {
        ShadowsocksAddress::SocketAddress(addr) => ProtocolDestination::ip(addr.ip(), addr.port()),
        ShadowsocksAddress::DomainNameAddress(domain, port) => {
            ProtocolDestination::domain(domain, *port)
        }
    }
}

fn parse_shadowsocks_method(method: &str) -> Result<CipherKind> {
    method
        .parse::<CipherKind>()
        .map_err(|err| anyhow::anyhow!("invalid Shadowsocks method {method}: {err:?}"))
}

async fn read_http_head(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while buf.len() < 64 * 1024 {
        stream.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
    }
    bail!("HTTP header is too large")
}

async fn socks_connect_domain(stream: &mut TcpStream, domain: &str, port: u16) -> Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method_response = [0u8; 2];
    stream.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00, 0x03];
    request.push(domain.len().try_into().context("domain is too long")?);
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0u8; 3];
    stream.read_exact(&mut reply).await?;
    read_socks_bound_addr(stream).await?;
    assert_eq!(reply, [0x05, 0x00, 0x00]);
    Ok(())
}

async fn socks_udp_associate(stream: &mut TcpStream) -> Result<SocketAddr> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method_response = [0u8; 2];
    stream.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);

    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut reply = [0u8; 3];
    stream.read_exact(&mut reply).await?;
    let relay = read_socks_bound_addr(stream).await?;
    assert_eq!(reply, [0x05, 0x00, 0x00]);
    Ok(relay)
}

async fn read_socks_bound_addr(stream: &mut TcpStream) -> Result<SocketAddr> {
    let atyp = stream.read_u8().await?;
    match atyp {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => bail!("unexpected SOCKS bound address type {other:#x}"),
    }
}

fn build_socks_udp_domain_packet(domain: &str, port: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let mut packet = vec![0, 0, 0, 0x03];
    packet.push(domain.len().try_into().context("domain is too long")?);
    packet.extend_from_slice(domain.as_bytes());
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn socks_udp_payload(packet: &[u8]) -> Result<&[u8]> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        bail!("invalid SOCKS UDP packet");
    }
    let mut offset = 4;
    match packet[3] {
        0x01 => offset += 4,
        0x03 => {
            let len = *packet
                .get(offset)
                .context("truncated SOCKS UDP domain length")? as usize;
            offset += 1 + len;
        }
        0x04 => offset += 16,
        other => bail!("unexpected SOCKS UDP address type {other:#x}"),
    }
    offset += 2;
    if offset > packet.len() {
        bail!("truncated SOCKS UDP packet");
    }
    Ok(&packet[offset..])
}

async fn spawn_dns_server(ip: IpAddr) -> Result<(SocketAddr, JoinHandle<()>)> {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let addr = socket.local_addr()?;
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let response = dns_response(&buf[..n], ip);
            let _ = socket.send_to(&response, peer).await;
        }
    });
    Ok((addr, task))
}

fn dns_response(query: &[u8], ip: IpAddr) -> Vec<u8> {
    let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
    let answer = match (qtype, ip) {
        (1, IpAddr::V4(ip)) => Some((1u16, ip.octets().to_vec())),
        (28, IpAddr::V6(ip)) => Some((28u16, ip.octets().to_vec())),
        _ => None,
    };

    let mut response = Vec::new();
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&0x8180u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&(answer.is_some() as u16).to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&query[12..]);

    if let Some((record_type, octets)) = answer {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&record_type.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&(octets.len() as u16).to_be_bytes());
        response.extend_from_slice(&octets);
    }

    response
}
