use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, bail};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

#[derive(Debug, Clone, Copy)]
pub struct ControlClient {
    listen: SocketAddr,
    timeout: Duration,
}

impl ControlClient {
    pub fn new(listen: SocketAddr, timeout: Duration) -> Self {
        Self { listen, timeout }
    }

    pub async fn get_json(&self, path: &str) -> Result<Value> {
        let response = self
            .get(path)
            .await
            .with_context(|| format!("failed to query control API {path}"))?;
        parse_json_response(&response)
    }

    pub async fn post_json(&self, path: &str, token: &str, body: &Value) -> Result<Value> {
        let response = self
            .post(path, token, body)
            .await
            .with_context(|| format!("failed to post control API {path}"))?;
        parse_json_response(&response)
    }

    async fn get(&self, path: &str) -> Result<String> {
        let path = validate_path(path)?;
        let mut stream = timeout(self.timeout, TcpStream::connect(self.listen))
            .await
            .context("timed out connecting to control API")?
            .with_context(|| format!("failed to connect control API at {}", self.listen))?;
        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {}\r\n\
             Accept: application/json\r\n\
             Connection: close\r\n\r\n",
            self.listen
        );
        timeout(self.timeout, stream.write_all(request.as_bytes()))
            .await
            .context("timed out writing control API request")?
            .context("failed to write control API request")?;

        let mut response = Vec::new();
        timeout(self.timeout, stream.read_to_end(&mut response))
            .await
            .context("timed out reading control API response")?
            .context("failed to read control API response")?;
        String::from_utf8(response).context("control API response is not valid UTF-8")
    }

    async fn post(&self, path: &str, token: &str, body: &Value) -> Result<String> {
        let path = validate_path(path)?;
        validate_header_value(token)?;
        let body = serde_json::to_vec(body).context("failed to serialize control API body")?;
        let mut stream = timeout(self.timeout, TcpStream::connect(self.listen))
            .await
            .context("timed out connecting to control API")?
            .with_context(|| format!("failed to connect control API at {}", self.listen))?;
        let request = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {}\r\n\
             Accept: application/json\r\n\
             Content-Type: application/json\r\n\
             X-TabbyMew-Control-Token: {token}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            self.listen,
            body.len()
        );
        timeout(self.timeout, stream.write_all(request.as_bytes()))
            .await
            .context("timed out writing control API request")?
            .context("failed to write control API request")?;
        timeout(self.timeout, stream.write_all(&body))
            .await
            .context("timed out writing control API body")?
            .context("failed to write control API body")?;

        let mut response = Vec::new();
        timeout(self.timeout, stream.read_to_end(&mut response))
            .await
            .context("timed out reading control API response")?
            .context("failed to read control API response")?;
        String::from_utf8(response).context("control API response is not valid UTF-8")
    }
}

fn validate_path(path: &str) -> Result<&str> {
    if path.is_empty() || !path.starts_with('/') {
        bail!("control API path must start with /");
    }
    if path
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        bail!("control API path must not contain spaces or control characters");
    }
    Ok(path)
}

fn validate_header_value(value: &str) -> Result<()> {
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        bail!("control API header value must not contain spaces or control characters");
    }
    Ok(())
}

fn parse_json_response(response: &str) -> Result<Value> {
    let (head, body) = response
        .split_once("\r\n\r\n")
        .context("control API response is missing HTTP headers")?;
    let status_line = head
        .lines()
        .next()
        .context("control API response is missing status line")?;
    let status = parse_status(status_line)?;
    if !(200..300).contains(&status) {
        bail!("control API returned HTTP {status}: {body}");
    }
    serde_json::from_str(body).context("control API response body is not JSON")
}

fn parse_status(status_line: &str) -> Result<u16> {
    let mut parts = status_line.split_whitespace();
    let version = parts
        .next()
        .context("control API status line is missing version")?;
    if version != "HTTP/1.1" {
        bail!("control API returned unsupported HTTP version {version}");
    }
    let status = parts
        .next()
        .context("control API status line is missing status code")?;
    status
        .parse::<u16>()
        .with_context(|| format!("control API status code {status} is invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::ConfigSummary,
        control::{ControlState, RuntimeMetrics, serve_listener},
    };
    use std::sync::Arc;
    use tokio::net::TcpListener;

    fn summary() -> ConfigSummary {
        ConfigSummary {
            log_level: "info".to_string(),
            dns: "disabled".to_string(),
            inbounds: vec!["hybrid:hybrid-in@127.0.0.1:7890 auth=off".to_string()],
            outbounds: vec!["direct:direct".to_string()],
            policy_groups: Vec::new(),
            route_final: "direct".to_string(),
            route_rule_sets: Vec::new(),
            route_resolve_ip_cidr: false,
            route_rules: Vec::new(),
            services: vec!["control_api=127.0.0.1:9090".to_string()],
        }
    }

    #[tokio::test]
    async fn gets_json_from_control_api() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let state = ControlState::new(summary(), Arc::new(RuntimeMetrics::new()));
        let task = tokio::spawn(serve_listener(listener, state));
        let client = ControlClient::new(addr, Duration::from_secs(1));

        let health = client.get_json("/health").await?;

        assert_eq!(health["ok"], true);
        assert_eq!(health["service"], "TabbyMew");

        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn reports_http_errors() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let state = ControlState::new(summary(), Arc::new(RuntimeMetrics::new()));
        let task = tokio::spawn(serve_listener(listener, state));
        let client = ControlClient::new(addr, Duration::from_secs(1));

        let err = client.get_json("/missing").await.unwrap_err();

        assert!(format!("{err:#}").contains("HTTP 404"));

        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn posts_json_with_control_token_header() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = Vec::new();
            let mut buffer = [0u8; 256];
            loop {
                let n = stream.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..n]);
                let text = String::from_utf8_lossy(&request);
                if text.contains("\r\n\r\n{\"enabled\":true}") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
                )
                .await?;
            String::from_utf8(request).context("request is not UTF-8")
        });
        let client = ControlClient::new(addr, Duration::from_secs(1));

        let response = client
            .post_json(
                "/control/api/tun",
                "test-token",
                &serde_json::json!({ "enabled": true }),
            )
            .await?;
        let request = task.await.context("test server task panicked")??;

        assert_eq!(response["ok"], true);
        assert!(request.starts_with("POST /control/api/tun HTTP/1.1"));
        assert!(request.contains("X-TabbyMew-Control-Token: test-token"));
        assert!(request.contains("Content-Type: application/json"));
        assert!(request.ends_with(r#"{"enabled":true}"#));
        Ok(())
    }

    #[test]
    fn rejects_invalid_paths() {
        assert!(validate_path("health").is_err());
        assert!(validate_path("/bad path").is_err());
        assert!(validate_path("/bad\r\nx").is_err());
    }

    #[test]
    fn rejects_invalid_header_values() {
        assert!(validate_header_value("good-token").is_ok());
        assert!(validate_header_value("bad token").is_err());
        assert!(validate_header_value("bad\r\ntoken").is_err());
    }
}
