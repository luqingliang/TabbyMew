use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, info, warn};

use crate::{
    inbound::listen,
    net::{address::parse_authority, http_auth, tcp},
    router::Router,
    session::Session,
};

#[derive(Debug, Clone)]
pub struct HttpInboundAuth {
    username: String,
    password: String,
}

impl HttpInboundAuth {
    pub fn from_options(username: Option<String>, password: Option<String>) -> Option<Self> {
        Some(Self {
            username: username?,
            password: password?,
        })
    }
}

pub async fn serve(
    tag: String,
    listen: String,
    listen_port: u16,
    auth: Option<HttpInboundAuth>,
    router: Router,
) -> Result<()> {
    let addr = listen::socket_addr(&listen, listen_port)?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind HTTP inbound {tag} on {addr}"))?;
    debug!(inbound = %tag, listen = %addr, "HTTP inbound listening");

    let accept_context = format!("HTTP inbound {tag}");
    let limiter = tcp::ConnectionLimiter::new(
        format!("HTTP inbound {tag}"),
        tcp::DEFAULT_MAX_INBOUND_CONNECTIONS,
    );
    loop {
        let Some(connection_permit) = limiter.acquire().await else {
            return Ok(());
        };
        let (stream, source) = tcp::accept_with_backoff(&listener, &accept_context).await?;
        tcp::enable_nodelay(&stream, "HTTP inbound accepted stream");
        let tag = tag.clone();
        let auth = auth.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            if let Err(err) = handle_tcp(tag, stream, Some(source), auth, router).await {
                debug!(error = %err, "HTTP connection closed");
            }
        });
    }
}

pub async fn handle_tcp(
    tag: String,
    mut inbound: TcpStream,
    source: Option<std::net::SocketAddr>,
    auth: Option<HttpInboundAuth>,
    router: Router,
) -> Result<()> {
    let head = read_http_head(&mut inbound).await?;
    let head_text = std::str::from_utf8(&head).context("HTTP request header is not valid UTF-8")?;
    let mut lines = head_text.split("\r\n");
    let request_line = lines.next().context("empty HTTP request")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().context("HTTP request is missing method")?;
    let target = parts.next().context("HTTP request is missing target")?;
    let version = parts.next().unwrap_or("HTTP/1.1");

    if !is_authorized(head_text, auth.as_ref()) {
        warn!(inbound = %tag, "HTTP proxy authentication failed");
        inbound
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"TabbyMew\"\r\n\
                  Content-Length: 0\r\n\r\n",
            )
            .await?;
        return Ok(());
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let destination = parse_authority(target, None)?;
        let session = Session::tcp(tag, source, destination.clone());
        let outbound = match router.pick(&session).await {
            Ok(outbound) => outbound,
            Err(err) => {
                warn!(
                    destination = %destination,
                    network = "tcp",
                    error = %format!("{err:#}"),
                    "connection failed"
                );
                return Err(err);
            }
        };
        let mut outbound_stream = match outbound.connect(&session).await {
            Ok(stream) => stream,
            Err(err) => {
                warn!(
                    destination = %destination,
                    outbound = %outbound.tag(),
                    network = "tcp",
                    error = %format!("{err:#}"),
                    "connection failed"
                );
                let _ = inbound.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(err);
            }
        };

        info!(
            destination = %destination,
            outbound = %outbound.tag(),
            network = "tcp",
            "connection routed"
        );
        inbound
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        inbound.flush().await?;
        debug!(
            source = ?session.source,
            network = ?session.network,
            destination = %destination,
            outbound = %outbound.tag(),
            "HTTP CONNECT established"
        );
        relay_tcp_with_optional_traffic(
            &router,
            outbound.as_ref(),
            &mut inbound,
            &mut outbound_stream,
        )
        .await;
        return Ok(());
    }

    let (destination, rewritten) = rewrite_plain_http_request(method, target, version, head_text)?;
    let session = Session::tcp(tag, source, destination.clone());
    let outbound = match router.pick(&session).await {
        Ok(outbound) => outbound,
        Err(err) => {
            warn!(
                destination = %destination,
                network = "tcp",
                error = %format!("{err:#}"),
                "connection failed"
            );
            return Err(err);
        }
    };
    let mut outbound_stream = match outbound.connect(&session).await {
        Ok(stream) => stream,
        Err(err) => {
            warn!(
                destination = %destination,
                outbound = %outbound.tag(),
                network = "tcp",
                error = %format!("{err:#}"),
                "connection failed"
            );
            let _ = inbound.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Err(err);
        }
    };

    info!(
        destination = %destination,
        outbound = %outbound.tag(),
        network = "tcp",
        "connection routed"
    );
    outbound_stream.write_all(rewritten.as_bytes()).await?;
    if let Some(metrics) = router.proxied_traffic_metrics(outbound.as_ref()) {
        metrics.record_proxied_upload(rewritten.len() as u64);
    }
    outbound_stream.flush().await?;
    debug!(
        source = ?session.source,
        network = ?session.network,
        destination = %destination,
        outbound = %outbound.tag(),
        "plain HTTP proxy established"
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

async fn read_http_head(stream: &mut TcpStream) -> Result<Vec<u8>> {
    tokio::time::timeout(tcp::INBOUND_HANDSHAKE_TIMEOUT, read_http_head_inner(stream))
        .await
        .with_context(|| {
            format!(
                "timed out reading HTTP request header after {:?}",
                tcp::INBOUND_HANDSHAKE_TIMEOUT
            )
        })?
}

async fn read_http_head_inner(stream: &mut TcpStream) -> Result<Vec<u8>> {
    const MAX_HEAD: usize = 64 * 1024;
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];

    while buf.len() < MAX_HEAD {
        stream
            .read_exact(&mut byte)
            .await
            .context("failed to read HTTP request")?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
    }

    bail!("HTTP request header is too large")
}

fn rewrite_plain_http_request(
    method: &str,
    target: &str,
    version: &str,
    head_text: &str,
) -> Result<(crate::net::address::Destination, String)> {
    let (authority, path) = if let Some(rest) = strip_proxy_scheme(target) {
        split_absolute_uri(rest)
    } else {
        let host =
            find_header(head_text, "host").context("plain HTTP proxy request is missing Host")?;
        (host.to_string(), target.to_string())
    };

    let destination = parse_authority(&authority, Some(80))?;
    let websocket_upgrade = is_websocket_upgrade_request(head_text);
    let connection_headers = connection_header_tokens(head_text);
    let mut lines = head_text.split("\r\n");
    let _ = lines.next();
    let mut rewritten = format!("{method} {path} {version}\r\n");
    for line in lines {
        if line.is_empty() {
            rewritten.push_str("\r\n");
            break;
        }
        if should_strip_header(line, &connection_headers, websocket_upgrade) {
            continue;
        }
        rewritten.push_str(line);
        rewritten.push_str("\r\n");
    }

    Ok((destination, rewritten))
}

fn strip_proxy_scheme(target: &str) -> Option<&str> {
    for scheme in ["http://", "ws://"] {
        if let Some((prefix, rest)) = target.split_at_checked(scheme.len())
            && prefix.eq_ignore_ascii_case(scheme)
        {
            return Some(rest);
        }
    }
    None
}

fn split_absolute_uri(rest: &str) -> (String, String) {
    match rest.find(['/', '?']) {
        Some(index) if rest.as_bytes()[index] == b'?' => {
            (rest[..index].to_string(), format!("/{}", &rest[index..]))
        }
        Some(index) => (rest[..index].to_string(), rest[index..].to_string()),
        None => (rest.to_string(), "/".to_string()),
    }
}

fn find_header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    let wanted = format!("{name}:");
    head.split("\r\n").skip(1).find_map(|line| {
        let lower = line.to_ascii_lowercase();
        lower
            .strip_prefix(&wanted)
            .map(|_| line[wanted.len()..].trim())
    })
}

fn is_authorized(head: &str, auth: Option<&HttpInboundAuth>) -> bool {
    let Some(auth) = auth else {
        return true;
    };
    find_header(head, "proxy-authorization")
        .is_some_and(|value| http_auth::matches_basic_value(value, &auth.username, &auth.password))
}

fn connection_header_tokens(head: &str) -> HashSet<String> {
    head.split("\r\n")
        .skip(1)
        .filter_map(|line| header_name_value(line))
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

fn is_websocket_upgrade_request(head: &str) -> bool {
    find_header(head, "upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

fn should_strip_header(
    line: &str,
    connection_headers: &HashSet<String>,
    websocket_upgrade: bool,
) -> bool {
    let Some((name, _)) = header_name_value(line) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    if websocket_upgrade && matches!(name.as_str(), "connection" | "upgrade") {
        return false;
    }
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
    ) || connection_headers.contains(&name)
}

fn header_name_value(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once(':')?;
    Some((name.trim(), value.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{OutboundConfig, RouteConfig},
        net::address::Address,
        router::Router,
    };
    use tokio::task::JoinHandle;

    #[test]
    fn rewrites_absolute_uri_query_without_path() {
        let head = concat!(
            "GET http://example.com?x=1 HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "\r\n"
        );

        let (destination, rewritten) =
            rewrite_plain_http_request("GET", "http://example.com?x=1", "HTTP/1.1", head).unwrap();

        assert_eq!(
            destination.address,
            Address::Domain("example.com".to_string())
        );
        assert_eq!(destination.port, 80);
        assert!(rewritten.starts_with("GET /?x=1 HTTP/1.1\r\n"));
    }

    #[test]
    fn rewrites_absolute_uri_with_case_insensitive_scheme() {
        let head = concat!(
            "GET HTTP://example.com/path HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "\r\n"
        );

        let (destination, rewritten) =
            rewrite_plain_http_request("GET", "HTTP://example.com/path", "HTTP/1.1", head).unwrap();

        assert_eq!(
            destination.address,
            Address::Domain("example.com".to_string())
        );
        assert_eq!(rewritten, "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n");
    }

    #[test]
    fn strips_proxy_and_connection_headers() {
        let head = concat!(
            "GET http://example.com/path HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "Proxy-Authorization: Basic invalid-auth\r\n",
            "Proxy-Connection: keep-alive\r\n",
            "Connection: X-Hop\r\n",
            "X-Hop: remove-me\r\n",
            "Keep-Alive: timeout=5\r\n",
            "TE: trailers\r\n",
            "Trailer: X-Trailer\r\n",
            "User-Agent: TabbyMew\r\n",
            "\r\n"
        );

        let (_destination, rewritten) =
            rewrite_plain_http_request("GET", "http://example.com/path", "HTTP/1.1", head).unwrap();

        assert!(rewritten.contains("Host: example.com\r\n"));
        assert!(rewritten.contains("User-Agent: TabbyMew\r\n"));
        assert!(!rewritten.contains("Proxy-Authorization:"));
        assert!(!rewritten.contains("Proxy-Connection:"));
        assert!(!rewritten.contains("Connection:"));
        assert!(!rewritten.contains("X-Hop:"));
        assert!(!rewritten.contains("Keep-Alive:"));
        assert!(!rewritten.contains("TE:"));
        assert!(!rewritten.contains("Trailer:"));
    }

    #[test]
    fn preserves_upgrade_headers_for_plain_websocket_requests() {
        let head = concat!(
            "GET http://example.com/socket HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "Connection: Upgrade\r\n",
            "Upgrade: websocket\r\n",
            "Sec-WebSocket-Key: abc123\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "\r\n"
        );

        let (_destination, rewritten) =
            rewrite_plain_http_request("GET", "http://example.com/socket", "HTTP/1.1", head)
                .unwrap();

        assert!(rewritten.contains("Connection: Upgrade\r\n"));
        assert!(rewritten.contains("Upgrade: websocket\r\n"));
        assert!(rewritten.contains("Sec-WebSocket-Key: abc123\r\n"));
        assert!(rewritten.contains("Sec-WebSocket-Version: 13\r\n"));
    }

    #[test]
    fn rewrites_absolute_websocket_uri() {
        let head = concat!(
            "GET ws://example.com/socket?x=1 HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "Connection: Upgrade\r\n",
            "Upgrade: websocket\r\n",
            "\r\n"
        );

        let (destination, rewritten) =
            rewrite_plain_http_request("GET", "ws://example.com/socket?x=1", "HTTP/1.1", head)
                .unwrap();

        assert_eq!(
            destination.address,
            Address::Domain("example.com".to_string())
        );
        assert_eq!(destination.port, 80);
        assert!(rewritten.starts_with("GET /socket?x=1 HTTP/1.1\r\n"));
        assert!(rewritten.contains("Connection: Upgrade\r\n"));
        assert!(rewritten.contains("Upgrade: websocket\r\n"));
    }

    #[tokio::test]
    async fn proxies_plain_http_request_to_direct_outbound() -> Result<()> {
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

        let (proxy_addr, proxy_task) = spawn_http_inbound(direct_router()).await?;
        let mut client = TcpStream::connect(proxy_addr).await?;
        let request = format!(
            "GET http://{target_addr}/path?q=1 HTTP/1.1\r\n\
             Host: {target_addr}\r\n\
             Proxy-Authorization: Basic hidden\r\n\
             Connection: X-Hop\r\n\
             X-Hop: hidden\r\n\
             \r\n"
        );
        client.write_all(request.as_bytes()).await?;

        let mut response = Vec::new();
        client.read_to_end(&mut response).await?;
        let response = String::from_utf8(response)?;
        let target_head = target_task.await?;
        proxy_task.abort();

        assert!(response.contains("\r\n\r\nok"));
        assert!(target_head.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(target_head.contains(&format!("Host: {target_addr}\r\n")));
        assert!(!target_head.contains("Proxy-Authorization:"));
        assert!(!target_head.contains("Connection:"));
        assert!(!target_head.contains("X-Hop:"));
        Ok(())
    }

    #[tokio::test]
    async fn proxies_http_connect_to_direct_outbound() -> Result<()> {
        let target_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let target_addr = target_listener.local_addr()?;
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let (proxy_addr, proxy_task) = spawn_http_inbound(direct_router()).await?;
        let mut client = TcpStream::connect(proxy_addr).await?;
        client
            .write_all(format!("CONNECT {target_addr} HTTP/1.1\r\n\r\n").as_bytes())
            .await?;
        let response_head = String::from_utf8(read_http_head(&mut client).await?)?;
        assert!(response_head.starts_with("HTTP/1.1 200 Connection Established\r\n"));

        client.write_all(b"ping").await?;
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await?;
        proxy_task.abort();
        target_task.await?;

        assert_eq!(&response, b"pong");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_missing_http_proxy_authorization() -> Result<()> {
        let auth = HttpInboundAuth::from_options(
            Some("user".to_string()),
            Some("example-password".to_string()),
        );
        let (proxy_addr, proxy_task) = spawn_http_inbound_with_auth(direct_router(), auth).await?;
        let mut client = TcpStream::connect(proxy_addr).await?;
        client
            .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await?;

        let response_head = String::from_utf8(read_http_head(&mut client).await?)?;
        proxy_task.abort();

        assert!(response_head.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"));
        assert!(response_head.contains("Proxy-Authenticate: Basic realm=\"TabbyMew\"\r\n"));
        Ok(())
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

    async fn spawn_http_inbound(router: Router) -> Result<(std::net::SocketAddr, JoinHandle<()>)> {
        spawn_http_inbound_with_auth(router, None).await
    }

    async fn spawn_http_inbound_with_auth(
        router: Router,
        auth: Option<HttpInboundAuth>,
    ) -> Result<(std::net::SocketAddr, JoinHandle<()>)> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let (stream, source) = listener.accept().await.unwrap();
                let router = router.clone();
                let auth = auth.clone();
                tokio::spawn(async move {
                    let _ =
                        handle_tcp("http-in".to_string(), stream, Some(source), auth, router).await;
                });
            }
        });

        Ok((addr, task))
    }
}
