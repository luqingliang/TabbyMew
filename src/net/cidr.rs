use std::net::IpAddr;

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.is_empty() {
            bail!("empty IP CIDR");
        }

        let (address, prefix) = if let Some((address, prefix)) = value.split_once('/') {
            let address = address.trim();
            let prefix = prefix
                .trim()
                .parse::<u8>()
                .with_context(|| format!("invalid IP CIDR prefix in {value}"))?;
            (address, Some(prefix))
        } else {
            (value, None)
        };

        let network = address
            .parse::<IpAddr>()
            .with_context(|| format!("invalid IP CIDR address in {value}"))?;
        let max_prefix = max_prefix(network);
        let prefix = prefix.unwrap_or(max_prefix);
        if prefix > max_prefix {
            bail!("IP CIDR prefix {prefix} exceeds {max_prefix} in {value}");
        }

        Ok(Self { network, prefix })
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = ipv4_mask(self.prefix);
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = ipv6_mask(self.prefix);
                u128::from_be_bytes(network.octets()) & mask
                    == u128::from_be_bytes(address.octets()) & mask
            }
            _ => false,
        }
    }
}

fn max_prefix(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_matches_cidr_forms() {
        let cases = [
            ("192.0.2.0/24", "192.0.2.10", "192.0.3.10"),
            ("2001:db8::/32", "2001:db8::1", "2001:db9::1"),
            ("203.0.113.7", "203.0.113.7", "203.0.113.8"),
        ];

        for (cidr, matching, non_matching) in cases {
            let cidr = IpCidr::parse(cidr).unwrap();
            assert!(cidr.contains(matching.parse().unwrap()));
            assert!(!cidr.contains(non_matching.parse().unwrap()));
        }
    }

    #[test]
    fn rejects_too_large_prefix() {
        let err = IpCidr::parse("192.0.2.0/33").unwrap_err();

        assert!(err.to_string().contains("exceeds 32"));
    }
}
