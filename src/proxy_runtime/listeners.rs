use std::net::IpAddr;

use crate::config::InboundConfig;

use super::{LAN_IPV4_LISTEN, LAN_IPV6_LISTEN, ProxyRuntime};

impl ProxyRuntime {
    pub(super) fn regular_inbounds(&self, lan_enabled: bool) -> Vec<InboundConfig> {
        if lan_enabled {
            self.inbounds
                .iter()
                .cloned()
                .map(bind_inbound_to_lan)
                .collect()
        } else {
            self.inbounds.clone()
        }
    }
}

pub(super) fn bind_inbound_to_lan(inbound: InboundConfig) -> InboundConfig {
    match inbound {
        InboundConfig::Socks {
            tag,
            listen,
            listen_port,
        } => InboundConfig::Socks {
            tag,
            listen: lan_listen_address(&listen),
            listen_port,
        },
        InboundConfig::Http {
            tag,
            listen,
            listen_port,
            username,
            password,
        } => InboundConfig::Http {
            tag,
            listen: lan_listen_address(&listen),
            listen_port,
            username,
            password,
        },
        InboundConfig::Hybrid {
            tag,
            listen,
            listen_port,
            username,
            password,
        } => InboundConfig::Hybrid {
            tag,
            listen: lan_listen_address(&listen),
            listen_port,
            username,
            password,
        },
        InboundConfig::Tun { .. } => inbound,
    }
}

pub(super) fn listener_summaries(inbounds: &[InboundConfig]) -> Vec<String> {
    inbounds
        .iter()
        .filter_map(listener_summary)
        .collect::<Vec<_>>()
}

pub(super) fn listener_summary(inbound: &InboundConfig) -> Option<String> {
    match inbound {
        InboundConfig::Socks {
            listen,
            listen_port,
            ..
        } => Some(format!("socks {}", listen_address(listen, *listen_port))),
        InboundConfig::Http {
            listen,
            listen_port,
            ..
        } => Some(format!("http {}", listen_address(listen, *listen_port))),
        InboundConfig::Hybrid {
            listen,
            listen_port,
            ..
        } => Some(format!("hybrid {}", listen_address(listen, *listen_port))),
        InboundConfig::Tun { .. } => None,
    }
}

pub(super) fn listen_address(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

pub(super) fn lan_listen_address(listen: &str) -> String {
    match listen.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) if ip.is_loopback() => LAN_IPV4_LISTEN.to_string(),
        Ok(IpAddr::V6(ip)) if ip.is_loopback() => LAN_IPV6_LISTEN.to_string(),
        _ => listen.to_string(),
    }
}
