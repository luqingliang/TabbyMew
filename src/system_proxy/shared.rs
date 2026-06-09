use super::*;

#[cfg(any(target_os = "macos", target_os = "windows", test))]
pub(super) fn system_proxy_status_error(
    target: Option<&SystemProxyTarget>,
    enabled: bool,
    managed: bool,
) -> Option<String> {
    if target.is_none() {
        Some(NO_LOCAL_SYSTEM_PROXY_TARGET.to_string())
    } else if enabled && !managed {
        Some(
            "system proxy is enabled for another target; enable again to apply TabbyMew"
                .to_string(),
        )
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
pub(super) fn run_command(program: &str, args: &[String]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {}", command_label(program, args)))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "{} failed with status {}{}",
            command_label(program, args),
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(target_os = "macos")]
pub(super) fn command_label(program: &str, args: &[String]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{program} {}", args.join(" "))
    }
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct MacProxyState {
    pub(super) http: Option<SystemProxyEndpoint>,
    pub(super) https: Option<SystemProxyEndpoint>,
    pub(super) socks: Option<SystemProxyEndpoint>,
}

#[cfg(any(target_os = "macos", test))]
impl MacProxyState {
    pub(super) fn enabled(&self) -> bool {
        self.http.is_some() || self.https.is_some() || self.socks.is_some()
    }

    pub(super) fn matches_target(&self, target: &SystemProxyTarget) -> bool {
        self.http == target.http && self.https == target.https && self.socks == target.socks
    }
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn parse_macos_proxy_state(output: &str) -> MacProxyState {
    let mut values = BTreeMap::new();
    for line in output.lines() {
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        values.insert(
            key.trim().to_string(),
            value.trim().trim_matches('"').to_string(),
        );
    }

    MacProxyState {
        http: parse_macos_proxy_endpoint(&values, "HTTP"),
        https: parse_macos_proxy_endpoint(&values, "HTTPS"),
        socks: parse_macos_proxy_endpoint(&values, "SOCKS"),
    }
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn parse_macos_proxy_endpoint(
    values: &BTreeMap<String, String>,
    prefix: &str,
) -> Option<SystemProxyEndpoint> {
    let enable = values.get(&format!("{prefix}Enable"))?;
    if !macos_proxy_enabled(enable) {
        return None;
    }
    let host = values.get(&format!("{prefix}Proxy"))?.trim();
    if host.is_empty() {
        return None;
    }
    let port = values.get(&format!("{prefix}Port"))?.parse::<u16>().ok()?;
    Some(SystemProxyEndpoint {
        host: host.to_string(),
        port,
        address: format_endpoint(host, port),
    })
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_proxy_enabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "yes" | "on" | "true"
    )
}

#[cfg(test)]
pub fn select_target(inbounds: &[String]) -> Option<SystemProxyTarget> {
    select_target_with_protocol(inbounds, SystemProxyProtocol::Auto)
}

pub fn select_target_with_protocol(
    inbounds: &[String],
    protocol: SystemProxyProtocol,
) -> Option<SystemProxyTarget> {
    let endpoints = inbounds
        .iter()
        .filter_map(|summary| parse_inbound_summary(summary))
        .collect::<Vec<_>>();

    if let Some(endpoint) = endpoints
        .iter()
        .find(|endpoint| endpoint.protocol == InboundProtocol::Hybrid && !endpoint.authenticated)
    {
        let http = matches!(
            protocol,
            SystemProxyProtocol::Auto | SystemProxyProtocol::HttpConnect
        )
        .then(|| endpoint.endpoint.clone());
        let socks = matches!(
            protocol,
            SystemProxyProtocol::Auto | SystemProxyProtocol::Socks
        )
        .then(|| endpoint.endpoint.clone());
        return Some(SystemProxyTarget {
            source: endpoint.source.clone(),
            http: http.clone(),
            https: http,
            socks,
        });
    }

    let http = endpoints
        .iter()
        .find(|endpoint| endpoint.supports_http_system_proxy());
    let socks = endpoints
        .iter()
        .find(|endpoint| endpoint.supports_socks_system_proxy());

    match protocol {
        SystemProxyProtocol::Socks => {
            return socks.map(|socks| SystemProxyTarget {
                source: socks.source.clone(),
                http: None,
                https: None,
                socks: Some(socks.endpoint.clone()),
            });
        }
        SystemProxyProtocol::HttpConnect => {
            return http.map(|http| SystemProxyTarget {
                source: http.source.clone(),
                http: Some(http.endpoint.clone()),
                https: Some(http.endpoint.clone()),
                socks: None,
            });
        }
        SystemProxyProtocol::Auto => {}
    }

    match (http, socks) {
        (Some(http), socks) => Some(SystemProxyTarget {
            source: match socks {
                Some(socks) => format!("{},{}", http.source, socks.source),
                None => http.source.clone(),
            },
            http: Some(http.endpoint.clone()),
            https: Some(http.endpoint.clone()),
            socks: socks.map(|endpoint| endpoint.endpoint.clone()),
        }),
        (None, Some(socks)) => Some(SystemProxyTarget {
            source: socks.source.clone(),
            http: None,
            https: None,
            socks: Some(socks.endpoint.clone()),
        }),
        (None, None) => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ParsedInboundEndpoint {
    protocol: InboundProtocol,
    source: String,
    authenticated: bool,
    endpoint: SystemProxyEndpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InboundProtocol {
    Hybrid,
    Http,
    Socks,
}

pub(super) fn parse_inbound_summary(summary: &str) -> Option<ParsedInboundEndpoint> {
    let (protocol, rest) = summary.split_once(':')?;
    let protocol = match protocol {
        "hybrid" => InboundProtocol::Hybrid,
        "http" => InboundProtocol::Http,
        "socks" => InboundProtocol::Socks,
        _ => return None,
    };
    let (_, after_tag) = rest.split_once('@')?;
    let address = after_tag.split_whitespace().next()?;
    let endpoint = parse_endpoint(address)?;
    let authenticated = has_enabled_auth(after_tag);
    Some(ParsedInboundEndpoint {
        protocol,
        source: summary.to_string(),
        authenticated,
        endpoint,
    })
}

pub(super) fn parse_endpoint(address: &str) -> Option<SystemProxyEndpoint> {
    let (host, port) = if let Some(rest) = address.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?.parse::<u16>().ok()?;
        (host.to_string(), port)
    } else {
        let (host, port) = address.rsplit_once(':')?;
        (host.to_string(), port.parse::<u16>().ok()?)
    };
    let host = system_proxy_host(&host);
    Some(SystemProxyEndpoint {
        address: format_endpoint(&host, port),
        host,
        port,
    })
}

impl ParsedInboundEndpoint {
    fn supports_http_system_proxy(&self) -> bool {
        matches!(
            self.protocol,
            InboundProtocol::Hybrid | InboundProtocol::Http
        ) && !self.authenticated
    }

    fn supports_socks_system_proxy(&self) -> bool {
        matches!(
            self.protocol,
            InboundProtocol::Hybrid | InboundProtocol::Socks
        )
    }
}

fn has_enabled_auth(summary_tail: &str) -> bool {
    summary_tail
        .split_whitespace()
        .any(|part| part.eq_ignore_ascii_case("auth=on"))
}

fn system_proxy_host(host: &str) -> String {
    match host {
        "0.0.0.0" => "127.0.0.1".to_string(),
        "::" => "::1".to_string(),
        _ => host.to_string(),
    }
}

pub(super) fn format_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
