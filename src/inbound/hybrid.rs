use anyhow::{Context, Result, bail};
use tokio::net::{TcpListener, TcpStream};
use tracing::debug;

use crate::{inbound, inbound::http::HttpInboundAuth, inbound::listen, net::tcp, router::Router};

pub async fn serve(
    tag: String,
    listen: String,
    listen_port: u16,
    http_auth: Option<HttpInboundAuth>,
    router: Router,
) -> Result<()> {
    let addr = listen::socket_addr(&listen, listen_port)?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind hybrid inbound {tag} on {addr}"))?;
    debug!(inbound = %tag, listen = %addr, "hybrid inbound listening");

    let accept_context = format!("hybrid inbound {tag}");
    let limiter = tcp::ConnectionLimiter::new(
        format!("hybrid inbound {tag}"),
        tcp::DEFAULT_MAX_INBOUND_CONNECTIONS,
    );
    loop {
        let Some(connection_permit) = limiter.acquire().await else {
            return Ok(());
        };
        let (stream, source) = tcp::accept_with_backoff(&listener, &accept_context).await?;
        tcp::enable_nodelay(&stream, "hybrid inbound accepted stream");
        let tag = tag.clone();
        let http_auth = http_auth.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            if let Err(err) = handle_tcp(tag, stream, Some(source), http_auth, router).await {
                debug!(error = %err, "hybrid connection closed");
            }
        });
    }
}

async fn handle_tcp(
    tag: String,
    stream: TcpStream,
    source: Option<std::net::SocketAddr>,
    http_auth: Option<HttpInboundAuth>,
    router: Router,
) -> Result<()> {
    let mut first = [0u8; 1];
    let n = tokio::time::timeout(tcp::INBOUND_HANDSHAKE_TIMEOUT, stream.peek(&mut first))
        .await
        .with_context(|| {
            format!(
                "timed out peeking hybrid inbound stream after {:?}",
                tcp::INBOUND_HANDSHAKE_TIMEOUT
            )
        })?
        .context("failed to peek hybrid inbound stream")?;
    if n == 0 {
        bail!("empty hybrid inbound connection");
    }

    if matches!(first[0], 0x04 | 0x05) {
        inbound::socks::handle_tcp(tag, stream, source, router).await
    } else {
        inbound::http::handle_tcp(tag, stream, source, http_auth, router).await
    }
}
