use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::net::address::Destination;

#[derive(Debug, Clone)]
pub struct Session {
    pub inbound_tag: String,
    pub source: Option<SocketAddr>,
    pub destination: Destination,
    pub network: Network,
    resolved_destination: Arc<Mutex<Option<ResolvedDestination>>>,
    reject_local_direct_destinations: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

impl Session {
    pub fn tcp(
        inbound_tag: impl Into<String>,
        source: Option<SocketAddr>,
        destination: Destination,
    ) -> Self {
        Self {
            inbound_tag: inbound_tag.into(),
            source,
            destination,
            network: Network::Tcp,
            resolved_destination: Arc::new(Mutex::new(None)),
            reject_local_direct_destinations: false,
        }
    }

    pub fn udp(
        inbound_tag: impl Into<String>,
        source: Option<SocketAddr>,
        destination: Destination,
    ) -> Self {
        Self {
            inbound_tag: inbound_tag.into(),
            source,
            destination,
            network: Network::Udp,
            resolved_destination: Arc::new(Mutex::new(None)),
            reject_local_direct_destinations: false,
        }
    }

    pub fn with_reject_local_direct_destinations(mut self, enabled: bool) -> Self {
        self.reject_local_direct_destinations = enabled;
        self
    }

    pub fn rejects_local_direct_destinations(&self) -> bool {
        self.reject_local_direct_destinations
    }

    pub fn resolved_destination_addrs(&self) -> Option<Vec<SocketAddr>> {
        self.resolution_cache()
            .as_ref()
            .filter(|resolved| resolved.destination == self.destination)
            .map(|resolved| resolved.addrs.clone())
    }

    pub fn cache_resolved_destination(&self, addrs: Vec<SocketAddr>) {
        if addrs.is_empty() {
            return;
        }
        *self.resolution_cache() = Some(ResolvedDestination {
            destination: self.destination.clone(),
            addrs,
        });
    }

    fn resolution_cache(&self) -> MutexGuard<'_, Option<ResolvedDestination>> {
        self.resolved_destination
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Debug, Clone)]
struct ResolvedDestination {
    destination: Destination,
    addrs: Vec<SocketAddr>,
}
