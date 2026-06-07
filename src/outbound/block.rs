use anyhow::{Result, bail};
use async_trait::async_trait;

use crate::{
    net::{stream::AnyStream, udp::UdpOutboundSession},
    outbound::Outbound,
    session::Session,
};

pub struct BlockOutbound {
    tag: String,
}

impl BlockOutbound {
    pub fn new(tag: String) -> Self {
        Self { tag }
    }
}

#[async_trait]
impl Outbound for BlockOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn counts_as_proxied_traffic(&self) -> bool {
        false
    }

    async fn connect(&self, session: &Session) -> Result<AnyStream> {
        bail!("blocked connection to {}", session.destination)
    }

    async fn udp_session(&self, session: &Session) -> Result<Box<dyn UdpOutboundSession>> {
        bail!("blocked UDP session to {}", session.destination)
    }
}
