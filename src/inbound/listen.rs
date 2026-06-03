use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};

pub fn socket_addr(listen: &str, listen_port: u16) -> Result<SocketAddr> {
    let ip = listen
        .trim()
        .parse::<IpAddr>()
        .with_context(|| format!("invalid listen address {listen}"))?;
    Ok(SocketAddr::new(ip, listen_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_ipv6_socket_addr() {
        let addr = socket_addr("::1", 7890).unwrap();

        assert_eq!(addr.to_string(), "[::1]:7890");
    }
}
