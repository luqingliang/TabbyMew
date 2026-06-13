use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use tokio::{
    sync::{Mutex, Notify},
    time::{self, Instant},
};
use tracing::debug;

use crate::net::{
    address::{Address, parse_authority},
    egress,
};

static NEXT_QUERY_ID: AtomicU16 = AtomicU16::new(1);
const MAX_CACHE_ENTRIES: usize = 4096;
const MAX_IN_FLIGHT_LOOKUPS: usize = 1024;
const MAX_CACHE_TTL_SECS: u64 = 300;
const NEGATIVE_CACHE_TTL_SECS: u64 = 30;
const DNS_SERVER_FALLBACK_DELAY_MS: u64 = 150;

#[derive(Debug, Clone)]
pub struct DnsResolver {
    servers: Vec<SocketAddr>,
    timeout: Duration,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    in_flight: Arc<Mutex<HashMap<String, Arc<LookupFlight>>>>,
}

#[derive(Debug, Clone)]
struct LookupFlight {
    notify: Arc<Notify>,
    result: Arc<Mutex<Option<Result<DnsLookup, String>>>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    result: CacheValue,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
enum CacheValue {
    Positive(Vec<IpAddr>),
    Negative(String),
}

#[derive(Debug, Clone, Default)]
struct DnsLookup {
    records: Vec<DnsRecord>,
    cnames: Vec<CnameRecord>,
}

#[derive(Debug, Clone)]
struct DnsRecord {
    ip: IpAddr,
    ttl: u32,
}

#[derive(Debug, Clone)]
struct CnameRecord {
    name: String,
    ttl: u32,
}

impl DnsResolver {
    pub fn from_servers(servers: &[String], timeout_ms: u64) -> Result<Option<Self>> {
        if servers.is_empty() {
            return Ok(None);
        }
        if timeout_ms == 0 {
            bail!("DNS timeout_ms must be greater than 0");
        }

        let mut parsed = Vec::with_capacity(servers.len());
        for server in servers {
            parsed.push(parse_dns_server(server)?);
        }

        Ok(Some(Self {
            servers: parsed,
            timeout: Duration::from_millis(timeout_ms),
            cache: Arc::new(Mutex::new(HashMap::new())),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
        }))
    }

    pub async fn lookup(&self, domain: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let original_domain = normalize_domain(domain)?;
        let mut current_domain = original_domain.clone();
        let mut aliases: Vec<(String, u32)> = Vec::new();
        let mut visited = HashSet::new();

        for _ in 0..8 {
            if !visited.insert(current_domain.clone()) {
                bail!("DNS CNAME loop detected for {original_domain}");
            }

            match self.cached_lookup(&current_domain).await {
                Some(Ok(ips)) => return Ok(to_socket_addrs(ips, port)),
                Some(Err(err)) => return Err(err),
                None => {}
            }

            let lookup = self.lookup_with_singleflight(&current_domain).await?;
            if !lookup.records.is_empty() {
                let record_ttl = lookup
                    .records
                    .iter()
                    .map(|record| record.ttl)
                    .min()
                    .unwrap_or(0);
                let cname_ttl = lookup
                    .cnames
                    .iter()
                    .map(|cname| cname.ttl)
                    .min()
                    .unwrap_or(record_ttl);
                let ttl = record_ttl.min(cname_ttl);
                let ips = lookup
                    .records
                    .iter()
                    .map(|record| record.ip)
                    .collect::<Vec<_>>();

                self.cache_positive(current_domain.clone(), &ips, ttl).await;
                for (alias, alias_ttl) in aliases {
                    self.cache_positive(alias, &ips, alias_ttl.min(ttl)).await;
                }

                return Ok(to_socket_addrs(ips, port));
            }

            if let Some(cname) = lookup.cnames.first() {
                aliases.push((current_domain, cname.ttl));
                current_domain = normalize_domain(&cname.name)?;
                continue;
            }

            let negative = format!("DNS lookup for {original_domain} returned no addresses");
            self.cache_negative(current_domain.clone(), negative.clone())
                .await;
            bail!("DNS lookup for {original_domain} returned no addresses");
        }

        bail!("DNS CNAME chain for {original_domain} is too deep")
    }

    pub async fn lookup_fresh(&self, domain: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let original_domain = normalize_domain(domain)?;
        let mut current_domain = original_domain.clone();
        let mut visited = HashSet::new();

        for _ in 0..8 {
            if !visited.insert(current_domain.clone()) {
                bail!("DNS CNAME loop detected for {original_domain}");
            }

            let lookup = self.lookup_uncached(&current_domain).await?;
            if !lookup.records.is_empty() {
                let ips = lookup
                    .records
                    .iter()
                    .map(|record| record.ip)
                    .collect::<Vec<_>>();
                return Ok(to_socket_addrs(ips, port));
            }

            if let Some(cname) = lookup.cnames.first() {
                current_domain = normalize_domain(&cname.name)?;
                continue;
            }

            bail!("DNS lookup for {original_domain} returned no addresses");
        }

        bail!("DNS CNAME chain for {original_domain} is too deep")
    }

    pub fn server_addrs(&self) -> Vec<SocketAddr> {
        self.servers.clone()
    }

    pub async fn clear_cache(&self) -> usize {
        let mut cache = self.cache.lock().await;
        let removed = cache.len();
        cache.clear();
        removed
    }

    async fn lookup_with_singleflight(&self, domain: &str) -> Result<DnsLookup> {
        let flight = {
            let mut in_flight = self.in_flight.lock().await;
            if let Some(flight) = in_flight.get(domain) {
                flight.clone()
            } else {
                if in_flight.len() >= MAX_IN_FLIGHT_LOOKUPS {
                    bail!("DNS in-flight lookup limit reached");
                }
                let flight = Arc::new(LookupFlight {
                    notify: Arc::new(Notify::new()),
                    result: Arc::new(Mutex::new(None)),
                });
                in_flight.insert(domain.to_string(), flight.clone());
                let resolver = self.clone();
                let domain = domain.to_string();
                let task_flight = flight.clone();
                tokio::spawn(async move {
                    resolver.complete_lookup_flight(domain, task_flight).await;
                });
                flight
            }
        };

        loop {
            let notified = flight.notify.notified();
            if let Some(result) = flight.result.lock().await.clone() {
                return result.map_err(anyhow::Error::msg);
            }
            notified.await;
        }
    }

    async fn complete_lookup_flight(&self, domain: String, flight: Arc<LookupFlight>) {
        let result = self.lookup_uncached(&domain).await;
        match &result {
            Ok(lookup) if !lookup.records.is_empty() => {
                let record_ttl = lookup
                    .records
                    .iter()
                    .map(|record| record.ttl)
                    .min()
                    .unwrap_or(0);
                let cname_ttl = lookup
                    .cnames
                    .iter()
                    .map(|cname| cname.ttl)
                    .min()
                    .unwrap_or(record_ttl);
                let ttl = record_ttl.min(cname_ttl);
                let ips = lookup
                    .records
                    .iter()
                    .map(|record| record.ip)
                    .collect::<Vec<_>>();
                self.cache_positive(domain.clone(), &ips, ttl).await;
            }
            Ok(lookup) if lookup.cnames.is_empty() => {
                self.cache_negative(
                    domain.clone(),
                    format!("DNS lookup for {domain} returned no addresses"),
                )
                .await;
            }
            Err(err) => {
                self.cache_negative(domain.clone(), format!("{err:#}"))
                    .await;
            }
            Ok(_) => {}
        }
        {
            let mut shared = flight.result.lock().await;
            *shared = Some(match &result {
                Ok(lookup) => Ok(lookup.clone()),
                Err(err) => Err(err.to_string()),
            });
        }
        {
            let mut in_flight = self.in_flight.lock().await;
            in_flight.remove(&domain);
        }
        flight.notify.notify_waiters();
    }

    async fn lookup_uncached(&self, domain: &str) -> Result<DnsLookup> {
        let mut tasks = tokio::task::JoinSet::new();
        for (index, server) in self.servers.iter().copied().enumerate() {
            let resolver = self.clone();
            let domain = domain.to_string();
            tasks.spawn(async move {
                if index > 0 {
                    time::sleep(Duration::from_millis(
                        DNS_SERVER_FALLBACK_DELAY_MS * index as u64,
                    ))
                    .await;
                }
                (server, resolver.lookup_with_server(server, &domain).await)
            });
        }

        let mut last_error = None;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok((_, Ok(lookup))) if !lookup.records.is_empty() || !lookup.cnames.is_empty() => {
                    if dns_lookup_contains_tun_virtual_ip(&lookup) {
                        last_error = Some(anyhow::anyhow!(
                            "DNS server returned TUN virtual address for {domain}; DNS query was captured by TUN"
                        ));
                        continue;
                    }
                    tasks.abort_all();
                    return Ok(lookup);
                }
                Ok((_, Ok(_))) => {}
                Ok((server, Err(err))) => {
                    debug!(server = %server, domain, error = %err, "DNS query failed");
                    last_error = Some(err);
                }
                Err(err) => {
                    last_error = Some(anyhow::Error::new(err));
                }
            }
        }

        if let Some(err) = last_error {
            bail!("failed to resolve {domain}: {err:#}");
        }
        Ok(DnsLookup::default())
    }

    async fn lookup_with_server(&self, server: SocketAddr, domain: &str) -> Result<DnsLookup> {
        let (a_result, aaaa_result) = tokio::join!(
            query(server, domain, RecordType::A, self.timeout),
            query(server, domain, RecordType::Aaaa, self.timeout)
        );

        let mut lookup = DnsLookup::default();
        let mut errors = Vec::new();

        match a_result {
            Ok(result) => lookup.merge(result),
            Err(err) => errors.push(err),
        }
        match aaaa_result {
            Ok(result) => lookup.merge(result),
            Err(err) => errors.push(err),
        }

        if lookup.records.is_empty() && lookup.cnames.is_empty() && !errors.is_empty() {
            let details = errors
                .into_iter()
                .map(|err| err.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            bail!("DNS queries failed: {details}");
        }

        Ok(lookup)
    }

    async fn cached_lookup(&self, domain: &str) -> Option<Result<Vec<IpAddr>>> {
        let now = Instant::now();
        let mut cache = self.cache.lock().await;
        match cache.get(domain) {
            Some(entry) if entry.expires_at > now => Some(match &entry.result {
                CacheValue::Positive(ips) => Ok(ips.clone()),
                CacheValue::Negative(err) => Err(anyhow::anyhow!(err.clone())),
            }),
            Some(_) => {
                cache.remove(domain);
                None
            }
            None => None,
        }
    }

    async fn cache_positive(&self, domain: String, ips: &[IpAddr], ttl: u32) {
        if ttl == 0 || ips.is_empty() {
            return;
        }

        let now = Instant::now();
        let ttl = u64::from(ttl).min(MAX_CACHE_TTL_SECS);
        let mut cache = self.cache.lock().await;
        cache.retain(|_, entry| entry.expires_at > now);
        if !cache.contains_key(&domain)
            && cache.len() >= MAX_CACHE_ENTRIES
            && let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest_key);
        }

        cache.insert(
            domain,
            CacheEntry {
                result: CacheValue::Positive(ips.to_vec()),
                expires_at: now + Duration::from_secs(ttl),
            },
        );
    }

    async fn cache_negative(&self, domain: String, error: String) {
        self.cache_entry(
            domain,
            CacheValue::Negative(error),
            Duration::from_secs(NEGATIVE_CACHE_TTL_SECS),
        )
        .await;
    }

    async fn cache_entry(&self, domain: String, result: CacheValue, ttl: Duration) {
        let now = Instant::now();
        let mut cache = self.cache.lock().await;
        cache.retain(|_, entry| entry.expires_at > now);
        if !cache.contains_key(&domain)
            && cache.len() >= MAX_CACHE_ENTRIES
            && let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest_key);
        }
        cache.insert(
            domain,
            CacheEntry {
                result,
                expires_at: now + ttl,
            },
        );
    }
}

fn dns_lookup_contains_tun_virtual_ip(lookup: &DnsLookup) -> bool {
    egress::bound_interface_name().is_some()
        && lookup
            .records
            .iter()
            .any(|record| is_tun_virtual_ip(record.ip))
}

pub fn is_tun_virtual_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
        }
        IpAddr::V6(_) => false,
    }
}

impl DnsLookup {
    fn merge(&mut self, other: Self) {
        self.records.extend(other.records);
        self.cnames.extend(other.cnames);
    }
}

pub fn validate_servers(servers: &[String]) -> Result<()> {
    for server in servers {
        parse_dns_server(server)?;
    }
    Ok(())
}

fn parse_dns_server(server: &str) -> Result<SocketAddr> {
    if let Ok(ip) = server.trim().parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }

    let destination = parse_authority(server, Some(53))
        .with_context(|| format!("invalid DNS server {server}"))?;
    let Address::Ip(ip) = destination.address else {
        bail!("DNS server {server} must be an IP address");
    };
    Ok(SocketAddr::new(ip, destination.port))
}

fn normalize_domain(domain: &str) -> Result<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        bail!("domain is empty");
    }
    Ok(domain)
}

fn to_socket_addrs(ips: Vec<IpAddr>, port: u16) -> Vec<SocketAddr> {
    ips.into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect()
}

#[derive(Clone, Copy)]
enum RecordType {
    A,
    Aaaa,
}

impl RecordType {
    fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

async fn query(
    server: SocketAddr,
    domain: &str,
    record_type: RecordType,
    timeout_duration: Duration,
) -> Result<DnsLookup> {
    let bind_addr = crate::net::timeout::unspecified_udp_bind_addr(server);
    let socket = crate::net::timeout::bind_udp_socket_for_remote_addr(
        bind_addr,
        Some(server),
        "DNS UDP socket",
    )
    .context("failed to prepare DNS UDP socket")?;
    let query_id = NEXT_QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let query = build_query(query_id, domain, record_type)?;

    socket
        .send_to(&query, server)
        .await
        .with_context(|| format!("failed to send DNS query to {server}"))?;

    let mut response = [0u8; 1500];
    let (n, _) = time::timeout(timeout_duration, socket.recv_from(&mut response))
        .await
        .with_context(|| format!("DNS query timed out after {:?}", timeout_duration))?
        .context("failed to receive DNS response")?;
    parse_response(&response[..n], query_id, record_type)
}

fn build_query(id: u16, domain: &str, record_type: RecordType) -> Result<Vec<u8>> {
    let mut query = Vec::with_capacity(512);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());

    for label in domain.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            bail!("invalid DNS label in {domain}");
        }
        query.push(bytes.len() as u8);
        query.extend_from_slice(bytes);
    }
    query.push(0);
    query.extend_from_slice(&record_type.code().to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    Ok(query)
}

fn parse_response(buf: &[u8], expected_id: u16, record_type: RecordType) -> Result<DnsLookup> {
    if buf.len() < 12 {
        bail!("DNS response is too short");
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expected_id {
        bail!("DNS response id mismatch");
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        bail!("DNS response is not a response");
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        bail!("DNS response returned code {rcode}");
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut offset = 12;

    for _ in 0..qdcount {
        read_name(buf, &mut offset)?;
        offset = offset
            .checked_add(4)
            .context("DNS question offset overflow")?;
        if offset > buf.len() {
            bail!("DNS question is truncated");
        }
    }

    let mut lookup = DnsLookup::default();
    for _ in 0..ancount {
        read_name(buf, &mut offset)?;
        if offset + 10 > buf.len() {
            bail!("DNS answer is truncated");
        }
        let answer_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let class = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let ttl = u32::from_be_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        offset += 8;
        let rdlen = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
        offset += 2;
        if offset + rdlen > buf.len() {
            bail!("DNS answer data is truncated");
        }

        if class == 1 {
            match (answer_type, record_type, rdlen) {
                (1, RecordType::A, 4) => {
                    lookup.records.push(DnsRecord {
                        ip: IpAddr::V4(Ipv4Addr::new(
                            buf[offset],
                            buf[offset + 1],
                            buf[offset + 2],
                            buf[offset + 3],
                        )),
                        ttl,
                    });
                }
                (28, RecordType::Aaaa, 16) => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&buf[offset..offset + 16]);
                    lookup.records.push(DnsRecord {
                        ip: IpAddr::V6(Ipv6Addr::from(octets)),
                        ttl,
                    });
                }
                (5, _, _) => {
                    let mut cname_offset = offset;
                    let name = read_name_to_string(buf, &mut cname_offset)?;
                    lookup.cnames.push(CnameRecord { name, ttl });
                }
                _ => {}
            }
        }
        offset += rdlen;
    }

    Ok(lookup)
}

fn read_name(buf: &[u8], offset: &mut usize) -> Result<()> {
    read_name_to_string(buf, offset).map(|_| ())
}

fn read_name_to_string(buf: &[u8], offset: &mut usize) -> Result<String> {
    let mut labels = Vec::new();
    let mut cursor = *offset;
    let mut jumped = false;
    let mut jumps = 0;

    loop {
        if cursor >= buf.len() {
            bail!("DNS name is truncated");
        }
        let len = buf[cursor];
        if len & 0xc0 == 0xc0 {
            if cursor + 1 >= buf.len() {
                bail!("DNS compressed name is truncated");
            }
            let pointer = (((len & 0x3f) as usize) << 8) | buf[cursor + 1] as usize;
            if !jumped {
                *offset = cursor + 2;
            }
            cursor = pointer;
            jumped = true;
        } else if len == 0 {
            if !jumped {
                *offset = cursor + 1;
            }
            return Ok(labels.join("."));
        } else {
            if len & 0xc0 != 0 {
                bail!("unsupported DNS label encoding");
            }
            let start = cursor + 1;
            let end = start + len as usize;
            if end > buf.len() {
                bail!("DNS name is truncated");
            }
            let label =
                std::str::from_utf8(&buf[start..end]).context("DNS label is not valid UTF-8")?;
            labels.push(label.to_string());
            cursor = end;
            if !jumped {
                *offset = cursor;
            }
        }

        jumps += 1;
        if jumps > 128 {
            bail!("DNS name has too many labels");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
    };
    use tokio::net::UdpSocket;

    #[test]
    fn parses_dns_server_with_default_port() {
        let server = parse_dns_server("1.1.1.1").unwrap();

        assert_eq!(server, "1.1.1.1:53".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parses_bare_ipv6_dns_server_with_default_port() {
        let server = parse_dns_server("2001:4860:4860::8888").unwrap();

        assert_eq!(
            server,
            "[2001:4860:4860::8888]:53".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn builds_a_query() {
        let query = build_query(7, "example.com", RecordType::A).unwrap();

        assert_eq!(&query[0..2], &7u16.to_be_bytes());
        assert!(query.ends_with(&[0, 1, 0, 1]));
    }

    #[test]
    fn detects_tun_virtual_dns_pool() {
        assert!(is_tun_virtual_ip("198.18.0.1".parse().unwrap()));
        assert!(is_tun_virtual_ip("198.19.255.254".parse().unwrap()));
        assert!(!is_tun_virtual_ip("198.20.0.1".parse().unwrap()));
        assert!(!is_tun_virtual_ip("203.0.113.10".parse().unwrap()));
    }

    #[tokio::test]
    async fn resolves_using_configured_udp_server() -> Result<()> {
        let server = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
                let response = dns_response(&buf[..n], qtype == RecordType::A.code());
                server.send_to(&response, peer).await.unwrap();
            }
        });

        let resolver = DnsResolver::from_servers(&[server_addr.to_string()], 5_000)?.unwrap();
        let addrs = resolver.lookup("example.test", 8080).await?;
        server_task.await?;

        assert_eq!(addrs, vec!["127.0.0.7:8080".parse::<SocketAddr>().unwrap()]);
        Ok(())
    }

    #[tokio::test]
    async fn resolves_when_aaaa_query_fails_after_a_answer() -> Result<()> {
        let server = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
                let response = if qtype == RecordType::A.code() {
                    dns_response(&buf[..n], true)
                } else {
                    dns_error_response(&buf[..n], 3)
                };
                server.send_to(&response, peer).await.unwrap();
            }
        });

        let resolver = DnsResolver::from_servers(&[server_addr.to_string()], 5_000)?.unwrap();
        let addrs = resolver.lookup("example.test", 8080).await?;
        server_task.await?;

        assert_eq!(addrs, vec!["127.0.0.7:8080".parse::<SocketAddr>().unwrap()]);
        Ok(())
    }

    #[tokio::test]
    async fn caches_dns_answers_until_ttl_expires() -> Result<()> {
        let server = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let server_addr = server.local_addr()?;
        let query_count = Arc::new(AtomicUsize::new(0));
        let server_query_count = query_count.clone();
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                server_query_count.fetch_add(1, AtomicOrdering::Relaxed);
                let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
                let response = dns_response(&buf[..n], qtype == RecordType::A.code());
                server.send_to(&response, peer).await.unwrap();
            }
        });

        let resolver = DnsResolver::from_servers(&[server_addr.to_string()], 5_000)?.unwrap();
        let first = resolver.lookup("example.test", 8080).await?;
        let second = resolver.lookup("example.test", 9090).await?;
        server_task.abort();

        assert_eq!(first, vec!["127.0.0.7:8080".parse::<SocketAddr>().unwrap()]);
        assert_eq!(
            second,
            vec!["127.0.0.7:9090".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(query_count.load(AtomicOrdering::Relaxed), 2);
        Ok(())
    }

    #[tokio::test]
    async fn fresh_lookup_bypasses_cached_answers() -> Result<()> {
        let server = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
                let response = dns_response(&buf[..n], qtype == RecordType::A.code());
                server.send_to(&response, peer).await.unwrap();
            }
        });

        let resolver = DnsResolver::from_servers(&[server_addr.to_string()], 5_000)?.unwrap();
        let fake_ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2));
        resolver
            .cache_positive("example.test".to_string(), &[fake_ip], 60)
            .await;

        assert_eq!(
            resolver.lookup("example.test", 443).await?,
            vec![SocketAddr::new(fake_ip, 443)]
        );

        let fresh = resolver.lookup_fresh("example.test", 443).await?;
        server_task.await?;

        assert_eq!(fresh, vec!["127.0.0.7:443".parse::<SocketAddr>().unwrap()]);
        Ok(())
    }

    #[tokio::test]
    async fn clear_cache_removes_cached_answers() -> Result<()> {
        let resolver = DnsResolver::from_servers(&["127.0.0.1".to_string()], 5_000)?.unwrap();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        resolver
            .cache_positive("example.test".to_string(), &[ip], 60)
            .await;

        assert_eq!(resolver.clear_cache().await, 1);
        assert!(resolver.cached_lookup("example.test").await.is_none());
        assert_eq!(resolver.clear_cache().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn cache_enforces_ttl_cap_and_size_limit() -> Result<()> {
        let resolver = DnsResolver::from_servers(&["127.0.0.1".to_string()], 5_000)?.unwrap();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let now = Instant::now();

        resolver
            .cache_positive("ttl.example".to_string(), &[ip], 60 * 60)
            .await;
        {
            let cache = resolver.cache.lock().await;
            let entry = cache.get("ttl.example").context("missing cached entry")?;
            assert!(entry.expires_at <= now + Duration::from_secs(MAX_CACHE_TTL_SECS + 1));
            assert!(entry.expires_at > now);
        }

        for index in 0..=MAX_CACHE_ENTRIES {
            resolver
                .cache_positive(format!("host-{index}.example"), &[ip], 60)
                .await;
        }

        let cache = resolver.cache.lock().await;
        assert!(cache.len() <= MAX_CACHE_ENTRIES);
        Ok(())
    }

    #[tokio::test]
    async fn in_flight_lookup_limit_is_bounded() -> Result<()> {
        let resolver = DnsResolver::from_servers(&["127.0.0.1".to_string()], 5_000)?.unwrap();
        {
            let mut in_flight = resolver.in_flight.lock().await;
            for index in 0..MAX_IN_FLIGHT_LOOKUPS {
                in_flight.insert(
                    format!("host-{index}.example"),
                    Arc::new(LookupFlight {
                        notify: Arc::new(Notify::new()),
                        result: Arc::new(Mutex::new(None)),
                    }),
                );
            }
        }

        let err = resolver
            .lookup_with_singleflight("overflow.example")
            .await
            .unwrap_err();

        assert!(err.to_string().contains("in-flight lookup limit"));
        Ok(())
    }

    #[tokio::test]
    async fn follows_cname_records() -> Result<()> {
        let server = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                let (name, qtype) = dns_question(&buf[..n]).unwrap();
                let response = if name == "alias.test" {
                    dns_cname_response(&buf[..n], "target.test")
                } else {
                    dns_response(&buf[..n], qtype == RecordType::A.code())
                };
                server.send_to(&response, peer).await.unwrap();
            }
        });

        let resolver = DnsResolver::from_servers(&[server_addr.to_string()], 5_000)?.unwrap();
        let addrs = resolver.lookup("alias.test", 8080).await?;
        server_task.abort();

        assert_eq!(addrs, vec!["127.0.0.7:8080".parse::<SocketAddr>().unwrap()]);
        Ok(())
    }

    #[tokio::test]
    async fn inline_cname_answer_uses_shorter_cname_ttl() -> Result<()> {
        let server = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
                let response = if qtype == RecordType::A.code() {
                    dns_cname_and_a_response(&buf[..n], "target.test", 5, 60)
                } else {
                    dns_response(&buf[..n], false)
                };
                server.send_to(&response, peer).await.unwrap();
            }
        });

        let resolver = DnsResolver::from_servers(&[server_addr.to_string()], 5_000)?.unwrap();
        let now = Instant::now();
        let addrs = resolver.lookup("alias.test", 8080).await?;
        server_task.await?;

        let cache = resolver.cache.lock().await;
        let entry = cache
            .get("alias.test")
            .context("missing alias cache entry")?;
        assert_eq!(addrs, vec!["127.0.0.7:8080".parse::<SocketAddr>().unwrap()]);
        assert!(entry.expires_at <= now + Duration::from_secs(6));
        Ok(())
    }

    #[tokio::test]
    async fn negative_cache_avoids_immediate_repeat_queries() -> Result<()> {
        let server = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let server_addr = server.local_addr()?;
        let query_count = Arc::new(AtomicUsize::new(0));
        let server_query_count = query_count.clone();
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                server_query_count.fetch_add(1, AtomicOrdering::Relaxed);
                let response = dns_error_response(&buf[..n], 3);
                server.send_to(&response, peer).await.unwrap();
            }
        });

        let resolver = DnsResolver::from_servers(&[server_addr.to_string()], 5_000)?.unwrap();
        let first = resolver.lookup("missing.test", 8080).await.unwrap_err();
        let second = resolver.lookup("missing.test", 8080).await.unwrap_err();
        server_task.await?;

        assert!(first.to_string().contains("returned code 3"));
        assert!(second.to_string().contains("returned code 3"));
        assert_eq!(query_count.load(AtomicOrdering::Relaxed), 2);
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_lookups_share_single_in_flight_query() -> Result<()> {
        let server = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let server_addr = server.local_addr()?;
        let query_count = Arc::new(AtomicUsize::new(0));
        let server_query_count = query_count.clone();
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                server_query_count.fetch_add(1, AtomicOrdering::Relaxed);
                tokio::time::sleep(Duration::from_millis(50)).await;
                let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
                let response = dns_response(&buf[..n], qtype == RecordType::A.code());
                server.send_to(&response, peer).await.unwrap();
            }
        });

        let resolver =
            Arc::new(DnsResolver::from_servers(&[server_addr.to_string()], 5_000)?.unwrap());
        let first = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.lookup("shared.test", 8080).await })
        };
        let second = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.lookup("shared.test", 8080).await })
        };

        let first = first.await??;
        let second = second.await??;
        server_task.await?;

        assert_eq!(first, second);
        assert_eq!(query_count.load(AtomicOrdering::Relaxed), 2);
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_waiter_does_not_break_shared_lookup() -> Result<()> {
        let server = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let server_addr = server.local_addr()?;
        let query_count = Arc::new(AtomicUsize::new(0));
        let server_query_count = query_count.clone();
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                server_query_count.fetch_add(1, AtomicOrdering::Relaxed);
                tokio::time::sleep(Duration::from_millis(100)).await;
                let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
                let response = dns_response(&buf[..n], qtype == RecordType::A.code());
                server.send_to(&response, peer).await.unwrap();
            }
        });

        let resolver =
            Arc::new(DnsResolver::from_servers(&[server_addr.to_string()], 5_000)?.unwrap());
        let cancelled = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.lookup("cancelled.test", 8080).await })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        cancelled.abort();

        let survivor = resolver.lookup("cancelled.test", 8080).await?;
        server_task.await?;

        assert_eq!(
            survivor,
            vec!["127.0.0.7:8080".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(query_count.load(AtomicOrdering::Relaxed), 2);
        Ok(())
    }

    #[tokio::test]
    async fn falls_back_to_slower_next_server_when_first_times_out() -> Result<()> {
        let slow = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let slow_addr = slow.local_addr()?;
        let slow_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_n, _peer) = slow.recv_from(&mut buf).await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let fast = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let fast_addr = fast.local_addr()?;
        let fast_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = fast.recv_from(&mut buf).await.unwrap();
                let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
                let response = dns_response(&buf[..n], qtype == RecordType::A.code());
                fast.send_to(&response, peer).await.unwrap();
            }
        });

        let resolver =
            DnsResolver::from_servers(&[slow_addr.to_string(), fast_addr.to_string()], 300)?
                .unwrap();
        let addrs = resolver.lookup("fallback.test", 8080).await?;

        slow_task.abort();
        fast_task.await?;
        assert_eq!(addrs, vec!["127.0.0.7:8080".parse::<SocketAddr>().unwrap()]);
        Ok(())
    }

    fn dns_response(query: &[u8], include_a_answer: bool) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&(include_a_answer as u16).to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);

        if include_a_answer {
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&RecordType::A.code().to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&60u32.to_be_bytes());
            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&[127, 0, 0, 7]);
        }

        response
    }

    fn dns_error_response(query: &[u8], rcode: u16) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        response.extend_from_slice(&(0x8180u16 | rcode).to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response
    }

    fn dns_question(query: &[u8]) -> Result<(String, u16)> {
        let mut offset = 12;
        let name = read_name_to_string(query, &mut offset)?;
        if offset + 4 > query.len() {
            bail!("DNS question is truncated");
        }
        let qtype = u16::from_be_bytes([query[offset], query[offset + 1]]);
        Ok((name, qtype))
    }

    fn dns_cname_response(query: &[u8], cname: &str) -> Vec<u8> {
        let cname = encode_dns_name(cname);
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&5u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&(cname.len() as u16).to_be_bytes());
        response.extend_from_slice(&cname);
        response
    }

    fn dns_cname_and_a_response(query: &[u8], cname: &str, cname_ttl: u32, a_ttl: u32) -> Vec<u8> {
        let cname = encode_dns_name(cname);
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&2u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);

        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&5u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&cname_ttl.to_be_bytes());
        response.extend_from_slice(&(cname.len() as u16).to_be_bytes());
        response.extend_from_slice(&cname);

        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&RecordType::A.code().to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&a_ttl.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&[127, 0, 0, 7]);
        response
    }

    fn encode_dns_name(name: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        for label in name.split('.') {
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
        encoded.push(0);
        encoded
    }
}
