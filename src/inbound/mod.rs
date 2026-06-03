mod http;
mod hybrid;
pub(crate) mod listen;
mod socks;
pub(crate) mod tun;

use anyhow::{Context, Result};

use crate::{config::InboundConfig, router::Router};

pub async fn serve(config: InboundConfig, router: Router) -> Result<()> {
    match config {
        InboundConfig::Socks {
            tag,
            listen,
            listen_port,
        } => socks::serve(tag, listen, listen_port, router).await,
        InboundConfig::Http {
            tag,
            listen,
            listen_port,
            username,
            password,
        } => {
            http::serve(
                tag,
                listen,
                listen_port,
                http::HttpInboundAuth::from_options(username, password),
                router,
            )
            .await
        }
        InboundConfig::Hybrid {
            tag,
            listen,
            listen_port,
            username,
            password,
        } => {
            hybrid::serve(
                tag,
                listen,
                listen_port,
                http::HttpInboundAuth::from_options(username, password),
                router,
            )
            .await
        }
        InboundConfig::Tun {
            tag,
            interface_name,
            mtu,
            auto_route,
            ipv6_enabled,
            dns,
            dns_addr,
            bypass,
            tcp_timeout_seconds,
            udp_timeout_seconds,
            max_sessions,
        } => {
            tun::serve(tun::TunInboundOptions {
                tag,
                interface_name,
                mtu,
                auto_route,
                ipv6_enabled,
                dns,
                dns_addr,
                bypass,
                tcp_timeout_seconds,
                udp_timeout_seconds,
                max_sessions,
                router,
            })
            .await
        }
    }
}

pub fn validate_configs(configs: &[InboundConfig]) -> Result<()> {
    for config in configs {
        validate_config(config)?;
    }
    Ok(())
}

fn validate_config(config: &InboundConfig) -> Result<()> {
    match config {
        InboundConfig::Tun {
            tag,
            interface_name,
            mtu,
            auto_route,
            ipv6_enabled,
            dns,
            dns_addr,
            bypass,
            tcp_timeout_seconds,
            udp_timeout_seconds,
            max_sessions,
        } => tun::validate_config(tun::TunConfigParts {
            interface_name: interface_name.as_deref(),
            mtu: *mtu,
            auto_route: *auto_route,
            ipv6_enabled: *ipv6_enabled,
            dns: *dns,
            dns_addr: dns_addr.as_deref(),
            bypass,
            tcp_timeout_seconds: *tcp_timeout_seconds,
            udp_timeout_seconds: *udp_timeout_seconds,
            max_sessions: *max_sessions,
        })
        .with_context(|| format!("invalid TUN inbound {tag}")),
        _ => Ok(()),
    }
}
