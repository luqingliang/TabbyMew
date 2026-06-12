use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Destination {
    pub address: Address,
    pub port: u16,
}

impl Destination {
    pub fn new(address: Address, port: u16) -> Self {
        Self { address, port }
    }

    pub fn host(&self) -> String {
        match &self.address {
            Address::Ip(IpAddr::V6(addr)) => format!("[{addr}]"),
            Address::Ip(addr) => addr.to_string(),
            Address::Domain(domain) => domain.clone(),
        }
    }

    pub fn authority(&self) -> String {
        format!("{}:{}", self.host(), self.port)
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.authority())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain(domain) => write!(f, "{domain}"),
        }
    }
}

pub fn is_local_or_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || is_ipv6_unique_local(ip)
                || is_ipv6_unicast_link_local(ip)
        }
    }
}

fn is_ipv6_unique_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_unicast_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

pub async fn read_socks_destination<R>(reader: &mut R) -> Result<Destination>
where
    R: AsyncRead + Unpin,
{
    let atyp = reader
        .read_u8()
        .await
        .context("failed to read address type")?;
    let address = match atyp {
        0x01 => {
            let mut buf = [0u8; 4];
            reader
                .read_exact(&mut buf)
                .await
                .context("failed to read IPv4 address")?;
            Address::Ip(IpAddr::V4(Ipv4Addr::from(buf)))
        }
        0x03 => {
            let len = reader
                .read_u8()
                .await
                .context("failed to read domain length")? as usize;
            let mut buf = vec![0u8; len];
            reader
                .read_exact(&mut buf)
                .await
                .context("failed to read domain")?;
            let domain = String::from_utf8(buf).context("domain is not valid UTF-8")?;
            Address::Domain(domain)
        }
        0x04 => {
            let mut buf = [0u8; 16];
            reader
                .read_exact(&mut buf)
                .await
                .context("failed to read IPv6 address")?;
            Address::Ip(IpAddr::V6(Ipv6Addr::from(buf)))
        }
        other => bail!("unsupported SOCKS address type {other:#x}"),
    };

    let port = reader.read_u16().await.context("failed to read port")?;
    Ok(Destination::new(address, port))
}

pub fn append_socks_destination(buf: &mut Vec<u8>, destination: &Destination) -> Result<()> {
    match &destination.address {
        Address::Ip(IpAddr::V4(addr)) => {
            buf.push(0x01);
            buf.extend_from_slice(&addr.octets());
        }
        Address::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.len() > u8::MAX as usize {
                bail!("domain is too long for SOCKS address: {domain}");
            }
            buf.push(0x03);
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
        }
        Address::Ip(IpAddr::V6(addr)) => {
            buf.push(0x04);
            buf.extend_from_slice(&addr.octets());
        }
    }
    buf.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

pub fn read_socks_destination_from_slice(buf: &[u8]) -> Result<(Destination, usize)> {
    if buf.is_empty() {
        bail!("missing SOCKS address type");
    }

    let atyp = buf[0];
    let mut offset = 1;
    let address = match atyp {
        0x01 => {
            if buf.len() < offset + 4 + 2 {
                bail!("truncated SOCKS IPv4 address");
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&buf[offset..offset + 4]);
            offset += 4;
            Address::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        0x03 => {
            if buf.len() < offset + 1 {
                bail!("truncated SOCKS domain length");
            }
            let len = buf[offset] as usize;
            offset += 1;
            if buf.len() < offset + len + 2 {
                bail!("truncated SOCKS domain address");
            }
            let domain = String::from_utf8(buf[offset..offset + len].to_vec())
                .context("SOCKS domain is not valid UTF-8")?;
            offset += len;
            Address::Domain(domain)
        }
        0x04 => {
            if buf.len() < offset + 16 + 2 {
                bail!("truncated SOCKS IPv6 address");
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[offset..offset + 16]);
            offset += 16;
            Address::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        other => bail!("unsupported SOCKS address type {other:#x}"),
    };

    let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    offset += 2;
    Ok((Destination::new(address, port), offset))
}

pub fn destination_from_socket_addr(addr: SocketAddr) -> Destination {
    Destination::new(Address::Ip(addr.ip()), addr.port())
}

pub fn parse_authority(authority: &str, default_port: Option<u16>) -> Result<Destination> {
    let authority = authority.trim();
    if authority.is_empty() {
        bail!("empty authority");
    }

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .context("missing closing bracket in IPv6 authority")?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = if let Some(port) = after.strip_prefix(':') {
            port.parse::<u16>().context("invalid port")?
        } else {
            default_port.context("authority is missing port")?
        };
        (host.to_string(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        let port = port.parse::<u16>().context("invalid port")?;
        (host.to_string(), port)
    } else {
        let port = default_port.context("authority is missing port")?;
        (authority.to_string(), port)
    };

    let address = match host.parse::<IpAddr>() {
        Ok(ip) => Address::Ip(ip),
        Err(_) => Address::Domain(host),
    };
    Ok(Destination::new(address, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_domain_and_bracket_ipv6_authorities() {
        let dest = parse_authority("example.com:443", None).unwrap();
        assert_eq!(dest.port, 443);
        assert_eq!(dest.address, Address::Domain("example.com".to_string()));

        let dest = parse_authority("[::1]:443", None).unwrap();
        assert_eq!(dest.port, 443);
        assert_eq!(dest.address, Address::Ip("::1".parse().unwrap()));
    }

    #[test]
    fn detects_local_or_private_ips() {
        for ip in [
            "127.0.0.1",
            "10.28.10.67",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.10",
            "224.0.0.251",
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fd00::1",
            "fe80::1",
            "ff02::fb",
            "::",
        ] {
            assert!(is_local_or_private_ip(ip.parse().unwrap()), "{ip}");
        }

        for ip in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
            assert!(!is_local_or_private_ip(ip.parse().unwrap()), "{ip}");
        }
    }
}
