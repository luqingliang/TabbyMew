use std::sync::Arc;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::debug;

use crate::{
    net::stream::{AnyStream, boxed},
    net::{dns::DnsResolver, http_auth, timeout},
    outbound::Outbound,
    session::Session,
};

pub struct HttpOutbound {
    tag: String,
    server: String,
    server_port: u16,
    username: Option<String>,
    password: Option<String>,
    dns: Option<Arc<DnsResolver>>,
}

impl HttpOutbound {
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
}

#[async_trait]
impl Outbound for HttpOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<AnyStream> {
        debug!(
            outbound = %self.tag,
            proxy = %format!("{}:{}", self.server, self.server_port),
            destination = %session.destination,
            authenticated = self.username.is_some(),
            "HTTP outbound CONNECT opening"
        );
        let proxy_addr = format!("{}:{}", self.server, self.server_port);
        let mut stream = timeout::connect_tcp_with_dns(
            self.server.as_str(),
            self.server_port,
            self.dns.as_deref(),
            &format!("connecting HTTP outbound {proxy_addr}"),
        )
        .await?;

        let request = self.connect_request(session);
        timeout::with_handshake_timeout(
            &format!("HTTP proxy CONNECT handshake with {proxy_addr}"),
            async {
                stream.write_all(request.as_bytes()).await?;
                stream.flush().await?;

                let response = read_http_head(&mut stream).await?;
                let status = response
                    .lines()
                    .next()
                    .context("empty HTTP proxy response")?;
                if !is_2xx_status(status) {
                    bail!("HTTP outbound CONNECT failed: {status}");
                }

                Ok(())
            },
        )
        .await?;

        Ok(boxed(stream))
    }
}

impl HttpOutbound {
    fn connect_request(&self, session: &Session) -> String {
        let mut request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: keep-alive\r\n",
            session.destination.authority(),
            session.destination.authority()
        );
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            request.push_str("Proxy-Authorization: ");
            request.push_str(&http_auth::basic_value(username, password));
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        request
    }
}

async fn read_http_head(stream: &mut TcpStream) -> Result<String> {
    const MAX_HEAD: usize = 64 * 1024;
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while buf.len() < MAX_HEAD {
        stream
            .read_exact(&mut byte)
            .await
            .context("failed to read HTTP proxy response")?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return String::from_utf8(buf).context("HTTP proxy response is not valid UTF-8");
        }
    }
    bail!("HTTP proxy response header is too large")
}

fn is_2xx_status(status: &str) -> bool {
    status
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .is_some_and(|code| (200..300).contains(&code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::timeout::override_test_timeouts;
    use crate::{
        net::address::{Address, Destination},
        session::Session,
    };
    use anyhow::Result;
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[test]
    fn connect_request_includes_proxy_authorization() {
        let outbound = HttpOutbound::new(
            "http-out".to_string(),
            "127.0.0.1".to_string(),
            8080,
            Some("user".to_string()),
            Some("example-password".to_string()),
            None,
        );
        let session = Session::tcp(
            "hybrid-in",
            None,
            Destination::new(Address::Domain("example.com".to_string()), 443),
        );

        let request = outbound.connect_request(&session);

        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpleGFtcGxlLXBhc3N3b3Jk\r\n"));
    }

    #[tokio::test]
    async fn http_outbound_connect_times_out_waiting_for_proxy_response() -> Result<()> {
        let _guard = override_test_timeouts(Duration::from_millis(200), Duration::from_millis(200));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let outbound = HttpOutbound::new(
            "http-out".to_string(),
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
            Ok(_) => panic!("HTTP outbound connect unexpectedly succeeded"),
            Err(err) => err,
        };
        let text = format!("{err:#}");
        assert!(text.contains("HTTP proxy CONNECT handshake"));
        assert!(text.contains("timed out"));

        server.abort();
        Ok(())
    }
}
