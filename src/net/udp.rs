use async_trait::async_trait;

use anyhow::Result;

use crate::net::address::Destination;

#[derive(Debug, Clone)]
pub struct UdpPacket {
    pub source: Destination,
    pub data: Vec<u8>,
}

#[async_trait]
pub trait UdpOutboundSession: Send + Sync {
    async fn send(&self, destination: &Destination, data: &[u8]) -> Result<()>;
    async fn recv(&self) -> Result<UdpPacket>;
}
