use super::*;

pub(super) fn validate_port_range(value: &str) -> Result<(u16, u16)> {
    let value = value.trim();
    if value.is_empty() {
        bail!("empty port range");
    }

    let (start, end) = if let Some((start, end)) = value.split_once(':') {
        (parse_route_port(start)?, parse_route_port(end)?)
    } else if let Some((start, end)) = value.split_once('-') {
        (parse_route_port(start)?, parse_route_port(end)?)
    } else {
        let port = parse_route_port(value)?;
        (port, port)
    };

    if start > end {
        bail!("start port {start} is greater than end port {end}");
    }
    Ok((start, end))
}

pub(super) fn parse_route_port(value: &str) -> Result<u16> {
    let port = value
        .trim()
        .parse::<u16>()
        .context("port is not a valid u16")?;
    if port == 0 {
        bail!("port must be greater than 0");
    }
    Ok(port)
}

pub(super) fn validate_tag(kind: &str, tag: &str) -> Result<()> {
    if tag.trim().is_empty() {
        bail!("{kind} tag is empty");
    }
    Ok(())
}

pub(super) fn validate_listen(tag: &str, listen: &str, listen_port: u16) -> Result<()> {
    if listen_port == 0 {
        bail!("inbound {tag} listen_port must be greater than 0");
    }
    listen::socket_addr(listen, listen_port)
        .with_context(|| format!("inbound {tag} listen address is invalid"))?;
    Ok(())
}

pub(super) fn validate_server(tag: &str, server: &str, server_port: u16) -> Result<()> {
    if server.trim().is_empty() {
        bail!("outbound {tag} server is empty");
    }
    if server_port == 0 {
        bail!("outbound {tag} server_port must be greater than 0");
    }
    Ok(())
}

pub(super) fn validate_required_secret(tag: &str, field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("outbound {tag} {field} is empty");
    }
    Ok(())
}

pub(super) fn validate_socks_auth(
    tag: &str,
    username: &Option<String>,
    password: &Option<String>,
) -> Result<()> {
    validate_auth_pair("SOCKS outbound", tag, username, password)
}

pub(super) fn validate_auth_pair(
    label: &str,
    tag: &str,
    username: &Option<String>,
    password: &Option<String>,
) -> Result<()> {
    if username.is_some() != password.is_some() {
        bail!("{label} {tag} username and password must be provided together");
    }
    if username.as_deref().is_some_and(str::is_empty)
        || password.as_deref().is_some_and(str::is_empty)
    {
        bail!("{label} {tag} username/password cannot be empty");
    }
    Ok(())
}

pub(super) fn validate_tls(tag: &str, tls: &TlsClientConfig) -> Result<()> {
    if let Some(server_name) = &tls.server_name {
        if server_name.trim().is_empty() {
            bail!("outbound {tag} TLS server_name is empty");
        }
        ServerName::try_from(server_name.to_string())
            .with_context(|| format!("outbound {tag} TLS server_name is invalid"))?;
    }
    for protocol in &tls.alpn {
        if protocol.trim().is_empty() {
            bail!("outbound {tag} TLS alpn contains an empty protocol");
        }
        if !protocol.is_ascii() {
            bail!("outbound {tag} TLS alpn protocol must be ASCII");
        }
    }
    Ok(())
}

impl InboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Socks { tag, .. }
            | Self::Http { tag, .. }
            | Self::Hybrid { tag, .. }
            | Self::Tun { tag, .. } => tag,
        }
    }
}

impl OutboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Direct { tag }
            | Self::Block { tag }
            | Self::Socks { tag, .. }
            | Self::Http { tag, .. }
            | Self::Trojan { tag, .. }
            | Self::Shadowsocks2022 { tag, .. }
            | Self::Shadowsocks { tag, .. }
            | Self::AnyTls { tag, .. } => tag,
        }
    }
}

pub(super) fn default_log_level() -> String {
    "info".to_string()
}

pub(super) fn default_listen() -> String {
    "127.0.0.1".to_string()
}

pub(super) fn default_final_outbound() -> String {
    "direct".to_string()
}

pub(super) fn default_tun_mtu() -> u16 {
    1500
}

pub(crate) const TUN_LOCAL_BYPASS_CIDRS: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "::1/128",
    "fe80::/10",
    "ff00::/8",
];

pub(crate) fn tun_local_bypass_cidrs() -> Vec<String> {
    TUN_LOCAL_BYPASS_CIDRS
        .iter()
        .map(ToString::to_string)
        .collect()
}

pub(super) fn default_tun_bypass() -> Vec<String> {
    TUN_LOCAL_BYPASS_CIDRS
        .iter()
        .map(ToString::to_string)
        .collect()
}
