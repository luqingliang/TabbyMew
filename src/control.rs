use std::{
    collections::BTreeMap,
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use anyhow::{Context, Result, bail};
use percent_encoding::percent_decode_str;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    time::{Duration, timeout},
};
use tracing::{debug, info, warn};
use url::Url;

use crate::{
    config::{Config, ConfigSummary, RouteNetwork, RouteRuleConfig, TlsClientConfig},
    config_normalize, inbound,
    net::{
        address::{Address, Destination, parse_authority},
        tcp, tls,
    },
    outbound,
    proxy_runtime::{ProxyRuntime, ProxyRuntimeSnapshot},
    router,
    session::{Network, Session},
    subscription, subscription_remote, system_proxy,
};

pub const DEFAULT_CONTROL_LISTEN: &str = "127.0.0.1:9090";
pub const CONTROL_API_PREFIX: &str = "/control/api";
const LEGACY_CONSOLE_API_PREFIX: &str = "/console/api";
pub const CONTROL_TOKEN_HEADER: &str = "x-tabbymew-control-token";
const LEGACY_CONSOLE_TOKEN_HEADER: &str = "x-tabbymew-console-token";

#[cfg(not(test))]
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_millis(50);
const MAX_BODY: usize = 10 * 1024 * 1024;
const CUSTOM_ROUTE_RULES_VERSION: u32 = 1;
const CUSTOM_ROUTE_RULES_FILE: &str = "tabbymew-custom-route-rules.json";

include!("control/types.rs");

include!("control/server.rs");

include!("control/responses.rs");

include!("control/http.rs");

#[cfg(test)]
include!("control/tests.rs");
