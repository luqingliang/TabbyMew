use std::{
    collections::HashMap,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use md5::Md5;
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    sync::{Mutex, mpsc, oneshot},
    time::MissedTickBehavior,
};
use tracing::{debug, warn};

use crate::{
    config::TlsClientConfig,
    net::{
        address::{Address, Destination, append_socks_destination},
        dns::DnsResolver,
        stream::{AnyStream, boxed},
        timeout, tls,
        udp::{UdpOutboundSession, UdpPacket},
    },
    outbound::Outbound,
    session::Session,
};

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const FIRST_STREAM_ID: u32 = 1;
const FRAME_HEADER_LEN: usize = 7;
const MAX_FRAME_DATA_LEN: usize = u16::MAX as usize;
const BRIDGE_BUFFER_SIZE: usize = 64 * 1024;
const WRITER_QUEUE_SIZE: usize = 128;

// The AnyTLS default padding scheme from the protocol document. Keep this
// exact byte sequence because its MD5 is advertised in cmdSettings.
const DEFAULT_PADDING_SCHEME_RAW: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
const DEFAULT_PADDING_MD5: &str = "75cff2ad89aadf5e257059ee571ebe11";

pub struct AnyTlsOptions {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub password: String,
    pub tls: TlsClientConfig,
    pub dns: Option<Arc<DnsResolver>>,
    pub idle_session_check_interval_ms: u64,
    pub idle_session_timeout_ms: u64,
    pub min_idle_session: usize,
}

pub struct AnyTlsOutbound {
    tag: String,
    client: Arc<AnyTlsClient>,
}

impl AnyTlsOutbound {
    pub fn new(options: AnyTlsOptions) -> Self {
        Self {
            tag: options.tag.clone(),
            client: Arc::new(AnyTlsClient::new(options)),
        }
    }
}

#[async_trait]
impl Outbound for AnyTlsOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<AnyStream> {
        self.client.open_stream(&session.destination).await
    }

    async fn udp_session(&self, session: &Session) -> Result<Box<dyn UdpOutboundSession>> {
        let magic_destination =
            Destination::new(Address::Domain("sp.v2.udp-over-tcp.arpa".to_string()), 0);
        let mut stream = self.client.open_stream(&magic_destination).await?;
        let mut request = Vec::with_capacity(256);
        request.push(0x01);
        append_socks_destination(&mut request, &session.destination)
            .context("failed to encode AnyTLS UoT destination")?;
        stream
            .write_all(&request)
            .await
            .context("failed to write AnyTLS UoT request")?;
        stream
            .flush()
            .await
            .context("failed to flush AnyTLS UoT request")?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(Box::new(AnyTlsUdpSession {
            destination: session.destination.clone(),
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        }))
    }
}

struct AnyTlsClient {
    server: String,
    server_port: u16,
    password: String,
    tls: TlsClientConfig,
    dns: Option<Arc<DnsResolver>>,
    sessions: Mutex<Vec<Arc<AnyTlsSession>>>,
    padding_scheme: Mutex<Arc<PaddingScheme>>,
    next_session_seq: AtomicU64,
    cleanup_started: AtomicBool,
    idle_session_check_interval: Duration,
    idle_session_timeout: Duration,
    min_idle_session: usize,
}

impl AnyTlsClient {
    fn new(options: AnyTlsOptions) -> Self {
        Self {
            server: options.server,
            server_port: options.server_port,
            password: options.password,
            tls: options.tls,
            dns: options.dns,
            sessions: Mutex::new(Vec::new()),
            padding_scheme: Mutex::new(Arc::new(PaddingScheme::default())),
            next_session_seq: AtomicU64::new(1),
            cleanup_started: AtomicBool::new(false),
            idle_session_check_interval: Duration::from_millis(
                options.idle_session_check_interval_ms,
            ),
            idle_session_timeout: Duration::from_millis(options.idle_session_timeout_ms),
            min_idle_session: options.min_idle_session,
        }
    }

    async fn open_stream(self: &Arc<Self>, destination: &Destination) -> Result<AnyStream> {
        self.ensure_cleanup_task();
        self.prune_idle_sessions().await;

        let session = match self.latest_reusable_session().await {
            Some(session) => session,
            None => self.create_session().await?,
        };

        match session.open_stream(destination).await {
            Ok(stream) => Ok(stream),
            Err(err) => {
                session.close();
                self.prune_closed_sessions().await;
                Err(err)
            }
        }
    }

    fn ensure_cleanup_task(self: &Arc<Self>) {
        if self
            .cleanup_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let client = Arc::downgrade(self);
        tokio::spawn(async move {
            let Some(client_ref) = client.upgrade() else {
                return;
            };
            let mut interval = tokio::time::interval(client_ref.idle_session_check_interval);
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            drop(client_ref);
            loop {
                interval.tick().await;
                let Some(client) = client.upgrade() else {
                    break;
                };
                client.prune_idle_sessions().await;
            }
        });
    }

    async fn create_session(self: &Arc<Self>) -> Result<Arc<AnyTlsSession>> {
        let mut stream = tls::connect_tls_with_dns(
            &self.server,
            self.server_port,
            &self.tls,
            self.dns.as_deref(),
        )
        .await?;
        let padding_scheme = self.padding_scheme.lock().await.clone();
        timeout::with_handshake_timeout("AnyTLS auth", async {
            write_auth(
                &mut stream,
                &self.password,
                padding_scheme.auth_padding_len(),
            )
            .await
            .context("failed to write AnyTLS auth")?;
            stream
                .flush()
                .await
                .context("failed to flush AnyTLS auth")?;
            Ok(())
        })
        .await?;

        let (tls_reader, tls_writer) = tokio::io::split(stream);
        let (tx, rx) = mpsc::channel::<WriterCommand>(WRITER_QUEUE_SIZE);
        let seq = self.next_session_seq.fetch_add(1, Ordering::SeqCst);
        let session = Arc::new(AnyTlsSession::new(seq, tx, padding_scheme));
        spawn_writer(session.clone(), tls_writer, rx);
        spawn_reader(self.clone(), session.clone(), tls_reader);

        self.sessions.lock().await.push(session.clone());
        Ok(session)
    }

    async fn latest_reusable_session(&self) -> Option<Arc<AnyTlsSession>> {
        let sessions = self.sessions.lock().await;
        sessions
            .iter()
            .filter(|session| session.is_reusable())
            .max_by_key(|session| session.seq)
            .cloned()
    }

    async fn update_padding_scheme(&self, raw: Vec<u8>) {
        match PaddingScheme::parse(raw) {
            Ok(scheme) => {
                let md5 = scheme.md5_hex.clone();
                *self.padding_scheme.lock().await = Arc::new(scheme);
                debug!(padding_md5 = %md5, "updated AnyTLS padding scheme");
            }
            Err(err) => {
                warn!(error = %err, "ignored invalid AnyTLS padding scheme update");
            }
        }
    }

    async fn prune_idle_sessions(&self) {
        let sessions = self.sessions.lock().await;
        let mut idle_sessions = sessions
            .iter()
            .filter(|session| session.is_idle())
            .cloned()
            .collect::<Vec<_>>();
        idle_sessions.sort_by_key(|session| std::cmp::Reverse(session.seq));

        let mut kept_idle = 0usize;
        for session in idle_sessions {
            kept_idle += 1;
            if kept_idle <= self.min_idle_session {
                continue;
            }
            if session.idle_elapsed().await >= self.idle_session_timeout {
                session.close();
            }
        }
        drop(sessions);
        self.prune_closed_sessions().await;
    }

    async fn prune_closed_sessions(&self) {
        self.sessions
            .lock()
            .await
            .retain(|session| session.is_alive());
    }
}

struct AnyTlsSession {
    seq: u64,
    tx: mpsc::Sender<WriterCommand>,
    streams: Mutex<HashMap<u32, StreamState>>,
    next_stream_id: AtomicU32,
    active_streams: AtomicUsize,
    alive: AtomicBool,
    first_stream: AtomicBool,
    idle_since: Mutex<Instant>,
    padding_scheme: Arc<PaddingScheme>,
}

impl AnyTlsSession {
    fn new(seq: u64, tx: mpsc::Sender<WriterCommand>, padding_scheme: Arc<PaddingScheme>) -> Self {
        Self {
            seq,
            tx,
            streams: Mutex::new(HashMap::new()),
            next_stream_id: AtomicU32::new(FIRST_STREAM_ID),
            active_streams: AtomicUsize::new(0),
            alive: AtomicBool::new(true),
            first_stream: AtomicBool::new(true),
            idle_since: Mutex::new(Instant::now()),
            padding_scheme,
        }
    }

    async fn open_stream(self: &Arc<Self>, destination: &Destination) -> Result<AnyStream> {
        if !self.is_alive() {
            bail!("AnyTLS session is closed");
        }
        self.active_streams.fetch_add(1, Ordering::SeqCst);
        let stream_id = self.next_stream_id.fetch_add(2, Ordering::SeqCst);
        if stream_id == 0 {
            self.active_streams.fetch_sub(1, Ordering::SeqCst);
            bail!("AnyTLS stream id space is exhausted");
        }

        let (client_side, bridge_side) = tokio::io::duplex(BRIDGE_BUFFER_SIZE);
        let (bridge_reader, bridge_writer) = tokio::io::split(bridge_side);
        let (synack_tx, synack_rx) = oneshot::channel();
        self.streams.lock().await.insert(
            stream_id,
            StreamState {
                writer: bridge_writer,
                synack: Some(synack_tx),
            },
        );

        let mut target = Vec::with_capacity(256);
        append_socks_destination(&mut target, destination)
            .context("failed to encode AnyTLS target address")?;

        let mut frames = Vec::with_capacity(3);
        if self.first_stream.swap(false, Ordering::SeqCst) {
            frames.push(FrameOut::new(
                CMD_SETTINGS,
                0,
                settings_payload_for_session(self),
            ));
        }
        frames.push(FrameOut::new(CMD_SYN, stream_id, Vec::new()));
        frames.push(FrameOut::new(CMD_PSH, stream_id, target));

        if self.tx.send(WriterCommand::Packet(frames)).await.is_err() {
            self.finish_stream(stream_id, Some("AnyTLS writer is closed".to_string()))
                .await;
            bail!("AnyTLS writer is closed");
        }

        spawn_upload_bridge(self.clone(), stream_id, bridge_reader);

        let synack_result =
            timeout::with_handshake_timeout(&format!("AnyTLS SYNACK for {destination}"), async {
                synack_rx
                    .await
                    .context("AnyTLS session closed before SYNACK")?
                    .map_err(anyhow::Error::msg)
            })
            .await;
        if let Err(err) = synack_result {
            self.finish_stream(stream_id, Some(err.to_string())).await;
            return Err(err);
        }

        Ok(boxed(client_side))
    }

    fn send_control(&self, command: u8, stream_id: u32, data: Vec<u8>) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx
                .send(WriterCommand::Packet(vec![FrameOut::new(
                    command, stream_id, data,
                )]))
                .await;
        });
    }

    async fn handle_synack(&self, stream_id: u32, data: Vec<u8>) {
        let result = if data.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "AnyTLS stream open failed: {}",
                String::from_utf8_lossy(&data)
            ))
        };
        let should_finish = result.is_err();
        {
            let mut streams = self.streams.lock().await;
            if let Some(stream) = streams.get_mut(&stream_id)
                && let Some(tx) = stream.synack.take()
            {
                let _ = tx.send(result);
            }
        }
        if should_finish {
            self.finish_stream(stream_id, None).await;
        }
    }

    async fn write_stream_data(&self, stream_id: u32, data: &[u8]) {
        let mut failed = false;
        {
            let mut streams = self.streams.lock().await;
            if let Some(stream) = streams.get_mut(&stream_id)
                && stream.writer.write_all(data).await.is_err()
            {
                failed = true;
            }
        }
        if failed {
            self.finish_stream(stream_id, Some("local stream reader closed".to_string()))
                .await;
        }
    }

    async fn finish_stream(&self, stream_id: u32, synack_error: Option<String>) {
        let stream = self.streams.lock().await.remove(&stream_id);
        if let Some(mut stream) = stream {
            if let Some(tx) = stream.synack.take() {
                let _ = tx.send(Err(synack_error
                    .unwrap_or_else(|| "AnyTLS stream closed before SYNACK".to_string())));
            }
            let _ = stream.writer.shutdown().await;
            if self.active_streams.fetch_sub(1, Ordering::SeqCst) <= 1 {
                *self.idle_since.lock().await = Instant::now();
            }
        }
    }

    async fn close_all_streams(&self) {
        let streams = std::mem::take(&mut *self.streams.lock().await);
        for (_, mut stream) in streams {
            if let Some(tx) = stream.synack {
                let _ = tx.send(Err("AnyTLS session closed".to_string()));
            }
            let _ = stream.writer.shutdown().await;
        }
        self.active_streams.store(0, Ordering::SeqCst);
        *self.idle_since.lock().await = Instant::now();
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    fn is_reusable(&self) -> bool {
        self.is_alive()
    }

    fn is_idle(&self) -> bool {
        self.is_alive() && self.active_streams.load(Ordering::SeqCst) == 0
    }

    async fn idle_elapsed(&self) -> Duration {
        if !self.is_idle() {
            return Duration::ZERO;
        }
        self.idle_since.lock().await.elapsed()
    }

    fn close(&self) {
        if self
            .alive
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let tx = self.tx.clone();
            tokio::spawn(async move {
                let _ = tx.send(WriterCommand::Close).await;
            });
        }
    }
}

fn settings_payload_for_session(session: &AnyTlsSession) -> Vec<u8> {
    format!(
        "v=2\nclient=TabbyMew/{}\npadding-md5={}",
        env!("CARGO_PKG_VERSION"),
        session.padding_scheme.md5_hex
    )
    .into_bytes()
}

struct StreamState {
    writer: WriteHalf<DuplexStream>,
    synack: Option<oneshot::Sender<std::result::Result<(), String>>>,
}

fn spawn_writer(
    session: Arc<AnyTlsSession>,
    mut tls_writer: WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    mut rx: mpsc::Receiver<WriterCommand>,
) {
    tokio::spawn(async move {
        let mut packet_index = 0u32;
        while let Some(command) = rx.recv().await {
            match command {
                WriterCommand::Packet(frames) => {
                    packet_index = packet_index.saturating_add(1);
                    if let Err(err) = write_packet(
                        &mut tls_writer,
                        &session.padding_scheme,
                        packet_index,
                        frames,
                    )
                    .await
                    {
                        debug!(error = %err, "AnyTLS writer stopped");
                        break;
                    }
                }
                WriterCommand::Close => break,
            }
        }
        session.alive.store(false, Ordering::SeqCst);
        let _ = tls_writer.shutdown().await;
    });
}

fn spawn_upload_bridge(
    session: Arc<AnyTlsSession>,
    stream_id: u32,
    mut bridge_reader: ReadHalf<DuplexStream>,
) {
    tokio::spawn(async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match bridge_reader.read(&mut buf).await {
                Ok(0) => {
                    let _ = session
                        .tx
                        .send(WriterCommand::Packet(vec![FrameOut::new(
                            CMD_FIN,
                            stream_id,
                            Vec::new(),
                        )]))
                        .await;
                    break;
                }
                Ok(n) => {
                    let frames = buf[..n]
                        .chunks(MAX_FRAME_DATA_LEN)
                        .map(|chunk| FrameOut::new(CMD_PSH, stream_id, chunk.to_vec()))
                        .collect::<Vec<_>>();
                    if session
                        .tx
                        .send(WriterCommand::Packet(frames))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(err) => {
                    debug!(error = %err, "AnyTLS upload bridge stopped");
                    let _ = session
                        .tx
                        .send(WriterCommand::Packet(vec![FrameOut::new(
                            CMD_FIN,
                            stream_id,
                            Vec::new(),
                        )]))
                        .await;
                    break;
                }
            }
        }
    });
}

fn spawn_reader(
    client: Arc<AnyTlsClient>,
    session: Arc<AnyTlsSession>,
    mut tls_reader: ReadHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
) {
    tokio::spawn(async move {
        loop {
            let frame = match read_frame(&mut tls_reader).await {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(err) => {
                    debug!(error = %err, "AnyTLS reader stopped");
                    break;
                }
            };

            match frame.command {
                CMD_PSH => {
                    session
                        .write_stream_data(frame.stream_id, &frame.data)
                        .await;
                }
                CMD_FIN => {
                    session.finish_stream(frame.stream_id, None).await;
                }
                CMD_SYNACK => {
                    session.handle_synack(frame.stream_id, frame.data).await;
                }
                CMD_WASTE | CMD_HEART_RESPONSE | CMD_SERVER_SETTINGS => {}
                CMD_HEART_REQUEST => {
                    session.send_control(CMD_HEART_RESPONSE, frame.stream_id, Vec::new());
                }
                CMD_UPDATE_PADDING_SCHEME => {
                    client.update_padding_scheme(frame.data).await;
                }
                CMD_ALERT => {
                    warn!(alert = %String::from_utf8_lossy(&frame.data), "AnyTLS alert");
                    break;
                }
                other => {
                    debug!(
                        command = other,
                        stream_id = frame.stream_id,
                        "ignored AnyTLS frame"
                    );
                }
            }
        }

        session.close();
        session.close_all_streams().await;
    });
}

struct AnyTlsUdpSession {
    destination: Destination,
    reader: Mutex<ReadHalf<AnyStream>>,
    writer: Mutex<WriteHalf<AnyStream>>,
}

#[async_trait]
impl UdpOutboundSession for AnyTlsUdpSession {
    async fn send(&self, destination: &Destination, data: &[u8]) -> Result<()> {
        if destination != &self.destination {
            bail!(
                "AnyTLS UoT session is bound to {}, got {}",
                self.destination,
                destination
            );
        }
        if data.len() > u16::MAX as usize {
            bail!("AnyTLS UoT payload is too large");
        }

        let mut writer = self.writer.lock().await;
        writer
            .write_all(&(data.len() as u16).to_be_bytes())
            .await
            .context("failed to write AnyTLS UoT packet length")?;
        writer
            .write_all(data)
            .await
            .context("failed to write AnyTLS UoT packet")?;
        writer
            .flush()
            .await
            .context("failed to flush AnyTLS UoT packet")
    }

    async fn recv(&self) -> Result<UdpPacket> {
        let mut reader = self.reader.lock().await;
        let length = reader
            .read_u16()
            .await
            .context("failed to read AnyTLS UoT packet length")? as usize;
        let mut data = vec![0u8; length];
        reader
            .read_exact(&mut data)
            .await
            .context("failed to read AnyTLS UoT packet")?;
        Ok(UdpPacket {
            source: self.destination.clone(),
            data,
        })
    }
}

async fn write_auth<W>(writer: &mut W, password: &str, padding_len: u16) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let digest = Sha256::digest(password.as_bytes());
    let mut auth = Vec::with_capacity(32 + 2 + padding_len as usize);
    auth.extend_from_slice(&digest);
    auth.extend_from_slice(&padding_len.to_be_bytes());
    auth.extend_from_slice(&random_bytes(padding_len as usize));
    writer.write_all(&auth).await
}

async fn write_packet<W>(
    writer: &mut W,
    padding_scheme: &PaddingScheme,
    packet_index: u32,
    frames: Vec<FrameOut>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut raw = Vec::with_capacity(256);
    for frame in frames {
        append_frame(&mut raw, frame.command, frame.stream_id, &frame.data)
            .map_err(io::Error::other)?;
    }

    let packets = padding_scheme
        .apply_packet(packet_index, raw)
        .map_err(io::Error::other)?;
    for packet in packets {
        writer.write_all(&packet).await?;
        writer.flush().await?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct PaddingScheme {
    md5_hex: String,
    stop: Option<u32>,
    rules: HashMap<u32, Vec<PaddingAction>>,
}

impl PaddingScheme {
    fn default() -> Self {
        let scheme = Self::parse(DEFAULT_PADDING_SCHEME_RAW.as_bytes())
            .expect("built-in AnyTLS padding scheme must be valid");
        debug_assert_eq!(scheme.md5_hex, DEFAULT_PADDING_MD5);
        scheme
    }

    fn parse(raw: impl AsRef<[u8]>) -> Result<Self> {
        let raw = raw.as_ref();
        let text = std::str::from_utf8(raw).context("AnyTLS padding scheme must be valid UTF-8")?;
        let mut stop = None;
        let mut rules = HashMap::new();

        for (line_index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| {
                anyhow!(
                    "AnyTLS padding scheme line {} is missing '='",
                    line_index + 1
                )
            })?;
            let key = key.trim();
            let value = value.trim();
            if key == "stop" {
                stop = Some(value.parse::<u32>().with_context(|| {
                    format!(
                        "AnyTLS padding scheme line {} has invalid stop value",
                        line_index + 1
                    )
                })?);
                continue;
            }

            let packet = key.parse::<u32>().with_context(|| {
                format!(
                    "AnyTLS padding scheme line {} has invalid packet index",
                    line_index + 1
                )
            })?;
            let mut actions = Vec::new();
            for item in value.split(',') {
                let item = item.trim();
                if item.eq_ignore_ascii_case("c") {
                    actions.push(PaddingAction::Check);
                    continue;
                }
                let (min, max) = item.split_once('-').ok_or_else(|| {
                    anyhow!(
                        "AnyTLS padding scheme line {} has invalid size range",
                        line_index + 1
                    )
                })?;
                let min = min.trim().parse::<usize>().with_context(|| {
                    format!(
                        "AnyTLS padding scheme line {} has invalid minimum size",
                        line_index + 1
                    )
                })?;
                let max = max.trim().parse::<usize>().with_context(|| {
                    format!(
                        "AnyTLS padding scheme line {} has invalid maximum size",
                        line_index + 1
                    )
                })?;
                if min == 0 || min > max {
                    bail!(
                        "AnyTLS padding scheme line {} has invalid size range {min}-{max}",
                        line_index + 1
                    );
                }
                if max > MAX_FRAME_DATA_LEN {
                    bail!(
                        "AnyTLS padding scheme line {} size range is too large",
                        line_index + 1
                    );
                }
                if packet != 0 && max < FRAME_HEADER_LEN {
                    bail!(
                        "AnyTLS padding scheme line {} packet size must allow a frame header",
                        line_index + 1
                    );
                }
                actions.push(PaddingAction::Size { min, max });
            }
            rules.insert(packet, actions);
        }

        let md5_hex = hex::encode(Md5::digest(raw));
        Ok(Self {
            md5_hex,
            stop,
            rules,
        })
    }

    fn auth_padding_len(&self) -> u16 {
        self.rules
            .get(&0)
            .and_then(|actions| {
                actions.iter().find_map(|action| match action {
                    PaddingAction::Size { min, max } => Some(random_range(*min, *max)),
                    PaddingAction::Check => None,
                })
            })
            .unwrap_or(0)
            .min(u16::MAX as usize) as u16
    }

    fn apply_packet(&self, packet_index: u32, raw: Vec<u8>) -> Result<Vec<Vec<u8>>> {
        if self
            .stop
            .is_some_and(|stop| stop > 0 && packet_index > stop)
        {
            return Ok(vec![raw]);
        }
        let Some(actions) = self.rules.get(&packet_index) else {
            return Ok(vec![raw]);
        };

        let mut packets = Vec::new();
        let mut offset = 0usize;
        for action in actions {
            match action {
                PaddingAction::Check => {
                    if offset >= raw.len() {
                        return Ok(packets);
                    }
                }
                PaddingAction::Size { min, max } => {
                    let remaining = raw.len().saturating_sub(offset);
                    let target = adjusted_packet_target(random_range(*min, *max), remaining, *max);
                    let take = remaining.min(target);
                    let mut packet = raw[offset..offset + take].to_vec();
                    offset += take;
                    pad_packet_to_target(&mut packet, target)?;
                    packets.push(packet);
                }
            }
        }

        if offset < raw.len() {
            packets.push(raw[offset..].to_vec());
        }
        Ok(packets)
    }
}

#[derive(Debug, Clone, Copy)]
enum PaddingAction {
    Size { min: usize, max: usize },
    Check,
}

fn adjusted_packet_target(target: usize, remaining: usize, max: usize) -> usize {
    if remaining < target && target - remaining > 0 && target - remaining < FRAME_HEADER_LEN {
        let adjusted = remaining.saturating_add(FRAME_HEADER_LEN);
        if adjusted <= max {
            return adjusted;
        }
        if remaining > 0 {
            return remaining;
        }
    }
    target
}

fn pad_packet_to_target(packet: &mut Vec<u8>, target: usize) -> Result<()> {
    if packet.len() >= target {
        return Ok(());
    }
    let padding_len = target - packet.len();
    if padding_len < FRAME_HEADER_LEN {
        return Ok(());
    }
    let data_len = padding_len - FRAME_HEADER_LEN;
    append_frame(packet, CMD_WASTE, 0, &random_bytes(data_len))
}

fn random_range(min: usize, max: usize) -> usize {
    if min == max {
        min
    } else {
        rand::thread_rng().gen_range(min..=max)
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

async fn read_frame<R>(reader: &mut R) -> io::Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }

    let command = header[0];
    let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let data_len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0u8; data_len];
    if data_len > 0 {
        reader.read_exact(&mut data).await?;
    }

    Ok(Some(Frame {
        command,
        stream_id,
        data,
    }))
}

fn append_frame(buf: &mut Vec<u8>, command: u8, stream_id: u32, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FRAME_DATA_LEN {
        anyhow::bail!("AnyTLS frame data is too large");
    }

    buf.push(command);
    buf.extend_from_slice(&stream_id.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    Ok(())
}

struct Frame {
    command: u8,
    stream_id: u32,
    data: Vec<u8>,
}

struct FrameOut {
    command: u8,
    stream_id: u32,
    data: Vec<u8>,
}

impl FrameOut {
    fn new(command: u8, stream_id: u32, data: Vec<u8>) -> Self {
        Self {
            command,
            stream_id,
            data,
        }
    }
}

enum WriterCommand {
    Packet(Vec<FrameOut>),
    Close,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_anytls_frame() {
        let mut buf = Vec::new();
        append_frame(&mut buf, CMD_SYN, 7, b"").unwrap();
        assert_eq!(buf, vec![CMD_SYN, 0, 0, 0, 7, 0, 0]);
    }

    #[test]
    fn parses_default_padding_scheme_md5_and_auth_padding() {
        let scheme = PaddingScheme::default();
        assert_eq!(scheme.md5_hex, DEFAULT_PADDING_MD5);
        assert_eq!(scheme.auth_padding_len(), 30);
    }

    #[test]
    fn applies_padding_scheme_with_checkpoints() {
        let scheme = PaddingScheme::parse(b"stop=3\n1=20-20,c,20-20\n2=8-8").unwrap();
        let packets = scheme.apply_packet(1, b"hello".to_vec()).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].len(), 20);
        assert_eq!(&packets[0][..5], b"hello");

        let packets = scheme
            .apply_packet(2, b"abcdefghijklmnop".to_vec())
            .unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].len(), 8);
        assert_eq!(&packets[1], b"ijklmnop");

        let packets = scheme.apply_packet(4, b"plain".to_vec()).unwrap();
        assert_eq!(packets, vec![b"plain".to_vec()]);
    }

    #[test]
    fn rejects_excessive_padding_scheme_sizes() {
        let err = PaddingScheme::parse(b"1=1-70000").unwrap_err();
        assert!(err.to_string().contains("size range is too large"));
    }

    #[tokio::test]
    async fn updates_client_padding_scheme() {
        let client = AnyTlsClient::new(AnyTlsOptions {
            tag: "anytls".to_string(),
            server: "127.0.0.1".to_string(),
            server_port: 443,
            password: "example-password".to_string(),
            tls: TlsClientConfig::default(),
            dns: None,
            idle_session_check_interval_ms: 30_000,
            idle_session_timeout_ms: 30_000,
            min_idle_session: 0,
        });
        client.update_padding_scheme(b"0=1-1\n1=8-8".to_vec()).await;
        let scheme = client.padding_scheme.lock().await.clone();
        assert_eq!(scheme.auth_padding_len(), 1);
        assert_ne!(scheme.md5_hex, DEFAULT_PADDING_MD5);
    }

    #[tokio::test]
    async fn session_pool_reuses_latest_alive_session_and_prunes_idle() {
        let client = AnyTlsClient::new(AnyTlsOptions {
            tag: "anytls".to_string(),
            server: "127.0.0.1".to_string(),
            server_port: 443,
            password: "example-password".to_string(),
            tls: TlsClientConfig::default(),
            dns: None,
            idle_session_check_interval_ms: 1,
            idle_session_timeout_ms: 1,
            min_idle_session: 1,
        });
        let padding = client.padding_scheme.lock().await.clone();
        let (older_tx, _older_rx) = mpsc::channel(1);
        let older = Arc::new(AnyTlsSession::new(1, older_tx, padding.clone()));
        let (newer_tx, _newer_rx) = mpsc::channel(1);
        let newer = Arc::new(AnyTlsSession::new(2, newer_tx, padding));

        *older.idle_since.lock().await = Instant::now() - Duration::from_secs(1);
        *newer.idle_since.lock().await = Instant::now() - Duration::from_secs(1);
        client
            .sessions
            .lock()
            .await
            .extend([older.clone(), newer.clone()]);

        let reusable = client.latest_reusable_session().await.unwrap();
        assert_eq!(reusable.seq, 2);

        client.prune_idle_sessions().await;
        assert!(!older.is_alive());
        assert!(newer.is_alive());
        assert_eq!(client.sessions.lock().await.len(), 1);
    }
}
