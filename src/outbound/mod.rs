mod anytls;
mod block;
mod direct;
mod http;
mod shadowsocks;
mod socks;
mod trojan;

use std::sync::Arc;

use anyhow::{Result, bail};
use async_trait::async_trait;

use crate::{
    config::OutboundConfig,
    net::{dns::DnsResolver, stream::AnyStream, udp::UdpOutboundSession},
    session::Session,
};

#[async_trait]
pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    async fn connect(&self, session: &Session) -> Result<AnyStream>;
    async fn udp_session(&self, _session: &Session) -> Result<Box<dyn UdpOutboundSession>> {
        bail!("{} outbound does not support UDP", self.tag())
    }
}

pub fn build_with_dns(
    config: &OutboundConfig,
    dns: Option<Arc<DnsResolver>>,
) -> Result<Arc<dyn Outbound>> {
    let outbound: Arc<dyn Outbound> = match config {
        OutboundConfig::Direct { tag } => Arc::new(direct::DirectOutbound::new(tag.clone(), dns)),
        OutboundConfig::Block { tag } => Arc::new(block::BlockOutbound::new(tag.clone())),
        OutboundConfig::Socks {
            tag,
            server,
            server_port,
            username,
            password,
        } => Arc::new(socks::SocksOutbound::new(
            tag.clone(),
            server.clone(),
            *server_port,
            username.clone(),
            password.clone(),
            dns.clone(),
        )),
        OutboundConfig::Http {
            tag,
            server,
            server_port,
            username,
            password,
        } => Arc::new(http::HttpOutbound::new(
            tag.clone(),
            server.clone(),
            *server_port,
            username.clone(),
            password.clone(),
            dns.clone(),
        )),
        OutboundConfig::Trojan {
            tag,
            server,
            server_port,
            password,
            tls,
        } => Arc::new(trojan::TrojanOutbound::new(
            tag.clone(),
            server.clone(),
            *server_port,
            password.clone(),
            tls.clone(),
            dns.clone(),
        )),
        OutboundConfig::Shadowsocks2022 {
            tag,
            server,
            server_port,
            method,
            password,
        } => Arc::new(shadowsocks::ShadowsocksOutbound::new(
            tag.clone(),
            server.clone(),
            *server_port,
            method.clone(),
            password.clone(),
            shadowsocks::CipherProfile::Shadowsocks2022,
            dns.clone(),
        )?),
        OutboundConfig::Shadowsocks {
            tag,
            server,
            server_port,
            method,
            password,
        } => Arc::new(shadowsocks::ShadowsocksOutbound::new(
            tag.clone(),
            server.clone(),
            *server_port,
            method.clone(),
            password.clone(),
            shadowsocks::CipherProfile::ClassicAead,
            dns.clone(),
        )?),
        OutboundConfig::AnyTls {
            tag,
            server,
            server_port,
            password,
            tls,
            idle_session_check_interval_ms,
            idle_session_timeout_ms,
            min_idle_session,
        } => Arc::new(anytls::AnyTlsOutbound::new(anytls::AnyTlsOptions {
            tag: tag.clone(),
            server: server.clone(),
            server_port: *server_port,
            password: password.clone(),
            tls: tls.clone(),
            dns: dns.clone(),
            idle_session_check_interval_ms: *idle_session_check_interval_ms,
            idle_session_timeout_ms: *idle_session_timeout_ms,
            min_idle_session: *min_idle_session,
        })),
    };

    Ok(outbound)
}

pub fn validate_configs(_configs: &[OutboundConfig]) -> Result<()> {
    Ok(())
}
