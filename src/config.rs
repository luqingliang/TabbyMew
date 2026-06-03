use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use rustls_pki_types::ServerName;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    inbound::listen,
    net::{cidr::IpCidr, dns},
};

mod defaults;
mod impls;
mod schema;
mod schema_report;
mod summary;
mod validation;

use self::{defaults::*, summary::*, validation::*};

pub(crate) use defaults::tun_local_bypass_cidrs;
pub use schema::*;
pub use schema_report::*;

#[cfg(test)]
mod tests;
