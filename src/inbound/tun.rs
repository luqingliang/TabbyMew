#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::collections::BTreeMap;
use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use clap::Parser;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use rand::RngCore;
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "macos", target_os = "windows", test))]
use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::sync::{Arc, OnceLock};
#[cfg(target_os = "macos")]
use tokio::process::Command;
#[cfg(target_os = "windows")]
use tokio::time::sleep;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, oneshot, watch},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tracing::debug;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use tracing::{info, warn};
use tun2proxy::{Args as Tun2ProxyArgs, CancellationToken};

#[cfg(any(target_os = "macos", target_os = "windows"))]
use crate::fs_security;
use crate::{
    config::TunDnsMode, inbound::socks, net::tcp, platform, resource_limits, router::Router,
};

pub struct TunInboundOptions {
    pub tag: String,
    pub interface_name: Option<String>,
    pub mtu: u16,
    pub auto_route: bool,
    pub ipv6_enabled: bool,
    pub dns: TunDnsMode,
    pub dns_addr: Option<String>,
    pub bypass: Vec<String>,
    pub tcp_timeout_seconds: Option<u64>,
    pub udp_timeout_seconds: Option<u64>,
    pub max_sessions: Option<usize>,
    pub router: Router,
}

#[derive(Debug, clap::Args)]
pub struct PrivilegedTunHelperCommand {
    #[arg(long)]
    pub(crate) control: SocketAddr,

    #[arg(long)]
    pub(crate) token_file: PathBuf,
}

pub async fn serve(options: TunInboundOptions) -> Result<()> {
    ensure_startable(TunConfigParts::from_options(&options))?;

    let socks_listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("failed to bind internal TUN SOCKS listener")?;
    let socks_addr = socks_listener
        .local_addr()
        .context("failed to read internal TUN SOCKS listener address")?;
    let socks_tag = options.tag.clone();

    let argv = build_argv(&options, socks_addr)?;
    let args = parse_tun2proxy_args(argv.clone())?;
    let shutdown = CancellationToken::new();
    let mut tasks = JoinSet::new();
    tasks.spawn(socks::serve_tun_listener_with_connection_limit(
        socks_tag,
        socks_listener,
        options.router.clone(),
        options
            .max_sessions
            .unwrap_or(tcp::DEFAULT_MAX_INBOUND_CONNECTIONS),
    ));
    tasks.spawn(run_tun2proxy_for_current_context(
        args,
        argv,
        options.mtu,
        options.auto_route,
        shutdown.clone(),
    ));

    debug!(
        inbound = %options.tag,
        interface = options.interface_name.as_deref().unwrap_or("<auto>"),
        mtu = options.mtu,
        auto_route = options.auto_route,
        internal_socks = %socks_addr,
        "TUN inbound starting"
    );

    let result = match tasks.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(err)) => Err(err).context("TUN inbound task panicked"),
        None => Ok(()),
    };

    shutdown.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    tokio::time::sleep(Duration::from_millis(50)).await;
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TunPreflightStatus {
    Ready,
    RequiresPermission,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TunPreflight {
    pub status: TunPreflightStatus,
    pub supported: bool,
    pub requires_privilege: bool,
    pub privilege_verified: Option<bool>,
    pub platform: &'static str,
    pub detail: String,
}

#[derive(Clone, Copy)]
pub(crate) struct TunConfigParts<'a> {
    pub interface_name: Option<&'a str>,
    pub mtu: u16,
    pub auto_route: bool,
    pub ipv6_enabled: bool,
    pub dns: TunDnsMode,
    pub dns_addr: Option<&'a str>,
    pub bypass: &'a [String],
    pub tcp_timeout_seconds: Option<u64>,
    pub udp_timeout_seconds: Option<u64>,
    pub max_sessions: Option<usize>,
}

impl<'a> TunConfigParts<'a> {
    pub(crate) fn from_inbound(config: &'a crate::config::InboundConfig) -> Option<Self> {
        match config {
            crate::config::InboundConfig::Tun {
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
                ..
            } => Some(Self {
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
            }),
            _ => None,
        }
    }

    fn from_options(options: &'a TunInboundOptions) -> Self {
        Self {
            interface_name: options.interface_name.as_deref(),
            mtu: options.mtu,
            auto_route: options.auto_route,
            ipv6_enabled: options.ipv6_enabled,
            dns: options.dns,
            dns_addr: options.dns_addr.as_deref(),
            bypass: &options.bypass,
            tcp_timeout_seconds: options.tcp_timeout_seconds,
            udp_timeout_seconds: options.udp_timeout_seconds,
            max_sessions: options.max_sessions,
        }
    }
}

pub(crate) fn validate_config(parts: TunConfigParts<'_>) -> Result<()> {
    let socks_addr = SocketAddr::from(([127, 0, 0, 1], 1080));
    build_args_from_parts(parts, socks_addr).map(|_| ())
}

pub(crate) fn preflight_config(parts: TunConfigParts<'_>) -> TunPreflight {
    preflight_config_with_privilege(parts, current_privilege_verified())
}

pub(crate) fn preflight_config_with_privilege(
    parts: TunConfigParts<'_>,
    privilege_verified: Option<bool>,
) -> TunPreflight {
    if !platform::tun_supported() {
        return TunPreflight {
            status: TunPreflightStatus::Unsupported,
            supported: false,
            requires_privilege: false,
            privilege_verified,
            platform: platform::name(),
            detail: format!("TUN mode is not supported on {}", platform::name()),
        };
    }

    let requires_privilege = platform::tun_requires_privilege(parts.auto_route);
    if requires_privilege && privilege_verified == Some(false) {
        return TunPreflight {
            status: TunPreflightStatus::RequiresPermission,
            supported: true,
            requires_privilege,
            privilege_verified,
            platform: platform::name(),
            detail: platform::tun_requires_permission_detail(),
        };
    }

    let detail = if requires_privilege {
        match privilege_verified {
            Some(true) => format!(
                "TUN mode is ready; auto route has administrator/root privileges on {}",
                platform::name()
            ),
            None => format!(
                "TUN mode is ready; {} must allow administrator/root privileges for auto route",
                platform::name()
            ),
            Some(false) => unreachable!("requires-permission case returned above"),
        }
    } else {
        format!("TUN mode is ready on {}", platform::name())
    };

    TunPreflight {
        status: TunPreflightStatus::Ready,
        supported: true,
        requires_privilege,
        privilege_verified,
        platform: platform::name(),
        detail,
    }
}

fn ensure_startable(parts: TunConfigParts<'_>) -> Result<()> {
    validate_config(parts)?;
    let preflight = preflight_config(parts);
    match preflight.status {
        TunPreflightStatus::Ready => Ok(()),
        TunPreflightStatus::RequiresPermission if can_start_with_privileged_helper() => Ok(()),
        TunPreflightStatus::RequiresPermission | TunPreflightStatus::Unsupported => {
            bail!("{}", preflight.detail)
        }
    }
}

pub(crate) fn can_start_with_privileged_helper() -> bool {
    platform::tun_privileged_helper_supported()
}

async fn run_tun2proxy_for_current_context(
    args: Tun2ProxyArgs,
    argv: Vec<String>,
    mtu: u16,
    _auto_route: bool,
    shutdown: CancellationToken,
) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        if _auto_route && current_privilege_verified() == Some(false) {
            return run_macos_privileged_helper(argv, mtu, shutdown).await;
        }
    }
    #[cfg(target_os = "windows")]
    {
        if current_privilege_verified() != Some(true) {
            return run_windows_privileged_helper(argv, mtu, shutdown).await;
        }
    }

    let _ = argv;
    run_tun2proxy(args, mtu, shutdown).await
}

async fn run_tun2proxy(args: Tun2ProxyArgs, mtu: u16, shutdown: CancellationToken) -> Result<()> {
    tun2proxy::general_run_async(args, mtu, platform::tun_packet_information(), shutdown)
        .await
        .map(|_| ())
        .map_err(|err| anyhow::anyhow!("tun2proxy failed: {}", format_tun2proxy_error(err)))
}

fn format_tun2proxy_error(err: impl std::fmt::Display) -> String {
    format_tun2proxy_error_for_platform(
        err.to_string(),
        platform::current() == platform::Platform::Windows,
    )
}

fn format_tun2proxy_error_for_platform(message: String, windows: bool) -> String {
    if windows && message.contains("LoadLibraryExW") {
        format!(
            "{message}; failed to load wintun.dll. Keep wintun.dll in the same directory as TabbyMew.exe, or use the full Windows release artifact"
        )
    } else if windows && is_windows_wintun_access_denied(&message) {
        format!(
            "{message}; Windows TUN adapter creation requires Administrator privileges. Authorize the Windows UAC prompt or retry from an Administrator session"
        )
    } else {
        message
    }
}

fn is_windows_wintun_access_denied(message: &str) -> bool {
    message.contains("WintunCreateAdapter")
        && (message.contains("0x00000005")
            || message.contains("Access is denied")
            || message.contains("access denied"))
}

pub async fn run_privileged_helper_command(command: PrivilegedTunHelperCommand) -> Result<()> {
    if current_privilege_verified() == Some(false) {
        bail!("privileged TUN helper must run as administrator/root");
    }
    let startup_limit = privileged_helper_resource_limit_output("privileged TUN helper started");

    let token = fs::read_to_string(&command.token_file).with_context(|| {
        format!(
            "failed to read TUN helper control token file {}",
            command.token_file.display()
        )
    })?;
    let token = token.trim();
    if token.is_empty() {
        bail!("TUN helper control token file is empty");
    }
    let mut control = TcpStream::connect(command.control)
        .await
        .with_context(|| format!("failed to connect TUN helper control {}", command.control))?;
    control
        .write_all(format!("{token}\n").as_bytes())
        .await
        .context("failed to write TUN helper control token")?;
    write_privileged_helper_output(&mut control, &startup_limit).await?;

    run_privileged_helper_command_loop(control).await
}

#[derive(Debug, Serialize, Deserialize)]
struct PrivilegedTunHelperEnvelope {
    id: u64,
    #[serde(flatten)]
    command: PrivilegedTunHelperCommandKind,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum PrivilegedTunHelperCommandKind {
    Start {
        mtu: u16,
        tun2proxy_args: Vec<String>,
    },
    Stop,
    FlushDns,
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PrivilegedTunHelperOutput {
    Response {
        id: u64,
        ok: bool,
        error: Option<String>,
    },
    Event {
        event: PrivilegedTunHelperEvent,
        error: Option<String>,
    },
    ResourceLimit {
        context: String,
        soft: String,
        hard: String,
        open_files: Option<usize>,
        changed: bool,
        previous_soft: Option<String>,
        error: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PrivilegedTunHelperEvent {
    TunStopped,
}

struct PrivilegedTunRunner {
    shutdown: CancellationToken,
    task: JoinHandle<Result<()>>,
}

enum PrivilegedTunHelperLoopEvent {
    Command(Option<PrivilegedTunHelperEnvelope>),
    RunnerFinished(std::result::Result<Result<()>, tokio::task::JoinError>),
}

async fn run_privileged_helper_command_loop(control: TcpStream) -> Result<()> {
    let (read_half, mut writer) = control.into_split();
    let mut reader = BufReader::new(read_half);
    let mut active: Option<PrivilegedTunRunner> = None;

    loop {
        let event = read_privileged_helper_loop_event(&mut reader, active.as_mut()).await?;
        match event {
            PrivilegedTunHelperLoopEvent::Command(Some(command)) => {
                let shutdown = handle_privileged_helper_command(command, &mut active, &mut writer)
                    .await
                    .context("failed to handle privileged TUN helper command")?;
                if shutdown {
                    return Ok(());
                }
            }
            PrivilegedTunHelperLoopEvent::Command(None) => {
                stop_privileged_tun_runner(&mut active)
                    .await
                    .context("failed to stop privileged TUN after control connection closed")?;
                return Ok(());
            }
            PrivilegedTunHelperLoopEvent::RunnerFinished(result) => {
                active = None;
                let error = privileged_tun_runner_result_error(result);
                write_privileged_helper_output(
                    &mut writer,
                    &PrivilegedTunHelperOutput::Event {
                        event: PrivilegedTunHelperEvent::TunStopped,
                        error,
                    },
                )
                .await?;
            }
        }
    }
}

async fn read_privileged_helper_loop_event(
    reader: &mut BufReader<OwnedReadHalf>,
    active: Option<&mut PrivilegedTunRunner>,
) -> Result<PrivilegedTunHelperLoopEvent> {
    if let Some(active) = active {
        tokio::select! {
            command = read_privileged_helper_command(reader) => {
                command.map(PrivilegedTunHelperLoopEvent::Command)
            }
            result = &mut active.task => {
                Ok(PrivilegedTunHelperLoopEvent::RunnerFinished(result))
            }
        }
    } else {
        read_privileged_helper_command(reader)
            .await
            .map(PrivilegedTunHelperLoopEvent::Command)
    }
}

async fn read_privileged_helper_command(
    reader: &mut BufReader<OwnedReadHalf>,
) -> Result<Option<PrivilegedTunHelperEnvelope>> {
    let mut line = String::new();
    let bytes = reader
        .read_line(&mut line)
        .await
        .context("failed to read privileged TUN helper command")?;
    if bytes == 0 {
        return Ok(None);
    }
    let command = serde_json::from_str(line.trim_end())
        .context("failed to parse privileged TUN helper command")?;
    Ok(Some(command))
}

async fn handle_privileged_helper_command(
    envelope: PrivilegedTunHelperEnvelope,
    active: &mut Option<PrivilegedTunRunner>,
    writer: &mut OwnedWriteHalf,
) -> Result<bool> {
    let result = match envelope.command {
        PrivilegedTunHelperCommandKind::Start {
            mtu,
            tun2proxy_args,
        } => {
            write_privileged_helper_output(
                writer,
                &privileged_helper_resource_limit_output("privileged TUN runner starting"),
            )
            .await?;
            start_privileged_tun_runner(active, tun2proxy_args, mtu).await
        }
        PrivilegedTunHelperCommandKind::Stop => {
            let result = stop_privileged_tun_runner(active).await;
            write_privileged_helper_output(
                writer,
                &privileged_helper_resource_limit_output("privileged TUN runner stopped"),
            )
            .await?;
            result
        }
        PrivilegedTunHelperCommandKind::FlushDns => {
            platform::flush_system_dns_cache().await.map(|_| ())
        }
        PrivilegedTunHelperCommandKind::Shutdown => {
            let result = stop_privileged_tun_runner(active).await;
            write_privileged_helper_output(
                writer,
                &privileged_helper_resource_limit_output("privileged TUN helper shutting down"),
            )
            .await?;
            write_privileged_helper_response(writer, envelope.id, result).await?;
            return Ok(true);
        }
    };
    write_privileged_helper_response(writer, envelope.id, result).await?;
    Ok(false)
}

async fn start_privileged_tun_runner(
    active: &mut Option<PrivilegedTunRunner>,
    tun2proxy_args: Vec<String>,
    mtu: u16,
) -> Result<()> {
    if active.is_some() {
        bail!("privileged TUN helper already has an active TUN runner");
    }

    let args = parse_tun2proxy_args(tun2proxy_args)?;
    let shutdown = CancellationToken::new();
    let mut task = tokio::spawn(run_tun2proxy(args, mtu, shutdown.clone()));
    match timeout(Duration::from_millis(100), &mut task).await {
        Ok(result) => match result {
            Ok(Ok(())) => bail!("privileged TUN runner exited during startup"),
            Ok(Err(err)) => Err(err).context("privileged TUN runner failed during startup"),
            Err(err) => Err(err).context("privileged TUN runner task panicked during startup"),
        },
        Err(_) => {
            *active = Some(PrivilegedTunRunner { shutdown, task });
            Ok(())
        }
    }
}

async fn stop_privileged_tun_runner(active: &mut Option<PrivilegedTunRunner>) -> Result<()> {
    let Some(mut runner) = active.take() else {
        return Ok(());
    };

    runner.shutdown.cancel();
    match timeout(Duration::from_secs(5), &mut runner.task).await {
        Ok(result) => match result {
            Ok(result) => result,
            Err(err) => Err(err).context("privileged TUN runner task panicked during shutdown"),
        },
        Err(_) => {
            runner.task.abort();
            let _ = timeout(Duration::from_secs(1), &mut runner.task).await;
            bail!("timed out waiting for privileged TUN runner shutdown");
        }
    }
}

fn privileged_tun_runner_result_error(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Option<String> {
    match result {
        Ok(Ok(())) => None,
        Ok(Err(err)) => Some(format!("{err:#}")),
        Err(err) => Some(format!("privileged TUN runner task panicked: {err}")),
    }
}

async fn write_privileged_helper_response(
    writer: &mut OwnedWriteHalf,
    id: u64,
    result: Result<()>,
) -> Result<()> {
    let output = match result {
        Ok(()) => PrivilegedTunHelperOutput::Response {
            id,
            ok: true,
            error: None,
        },
        Err(err) => PrivilegedTunHelperOutput::Response {
            id,
            ok: false,
            error: Some(format!("{err:#}")),
        },
    };
    write_privileged_helper_output(writer, &output).await
}

async fn write_privileged_helper_output<W>(
    writer: &mut W,
    output: &PrivilegedTunHelperOutput,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut line =
        serde_json::to_vec(output).context("failed to encode privileged helper output")?;
    line.push(b'\n');
    writer
        .write_all(&line)
        .await
        .context("failed to write privileged helper output")
}

fn privileged_helper_resource_limit_output(
    context: impl Into<String>,
) -> PrivilegedTunHelperOutput {
    let context = context.into();
    match resource_limits::raise_nofile_soft_limit(resource_limits::DEFAULT_NOFILE_SOFT_LIMIT) {
        Ok(change) => match resource_limits::nofile_limit_snapshot() {
            Ok(snapshot) => PrivilegedTunHelperOutput::ResourceLimit {
                context,
                soft: snapshot.soft,
                hard: snapshot.hard,
                open_files: snapshot.open_files,
                changed: change.is_some(),
                previous_soft: change.map(|change| change.previous_soft),
                error: None,
            },
            Err(err) => PrivilegedTunHelperOutput::ResourceLimit {
                context,
                soft: "-".to_string(),
                hard: "-".to_string(),
                open_files: None,
                changed: change.is_some(),
                previous_soft: change.map(|change| change.previous_soft),
                error: Some(format!("{err:#}")),
            },
        },
        Err(err) => PrivilegedTunHelperOutput::ResourceLimit {
            context,
            soft: "-".to_string(),
            hard: "-".to_string(),
            open_files: None,
            changed: false,
            previous_soft: None,
            error: Some(format!("{err:#}")),
        },
    }
}

#[cfg(target_os = "macos")]
const MACOS_HELPER_AUTH_TIMEOUT: Duration = Duration::from_secs(120);

#[cfg(target_os = "windows")]
const WINDOWS_HELPER_AUTH_TIMEOUT: Duration = Duration::from_secs(120);

pub async fn shutdown_privileged_helper_session() {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        let mut cached = privileged_tun_helper_session_cache().lock().await;
        let Some(session) = cached.take() else {
            return;
        };
        match session.shutdown().await {
            Ok(()) => info!("privileged TUN helper session stopped"),
            Err(err) => warn!(error = %err, "failed to stop privileged TUN helper session"),
        }
    }
}

pub async fn flush_system_dns_cache_with_privileged_helper() -> Result<bool> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        let session = {
            let cached = privileged_tun_helper_session_cache().lock().await;
            cached
                .as_ref()
                .filter(|session| session.is_alive())
                .map(Arc::clone)
        };
        let Some(session) = session else {
            return Ok(false);
        };
        session.flush_dns().await?;
        Ok(true)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Ok(false)
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn privileged_tun_helper_session_cache()
-> &'static tokio::sync::Mutex<Option<Arc<PrivilegedTunHelperSession>>> {
    static CACHE: OnceLock<tokio::sync::Mutex<Option<Arc<PrivilegedTunHelperSession>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| tokio::sync::Mutex::new(None))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
struct PrivilegedTunHelperSession {
    platform: &'static str,
    requests: mpsc::UnboundedSender<PrivilegedTunHelperRequest>,
    run_exit: watch::Sender<Option<PrivilegedTunRunExit>>,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Debug, Clone)]
struct PrivilegedTunRunExit {
    error: Option<String>,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
enum PrivilegedTunHelperRequest {
    Start {
        argv: Vec<String>,
        mtu: u16,
        response: oneshot::Sender<Result<()>>,
    },
    Stop {
        response: Option<oneshot::Sender<Result<()>>>,
    },
    FlushDns {
        response: oneshot::Sender<Result<()>>,
    },
    Shutdown {
        response: Option<oneshot::Sender<Result<()>>>,
    },
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
struct PrivilegedTunRunLease {
    requests: mpsc::UnboundedSender<PrivilegedTunHelperRequest>,
    exit: watch::Receiver<Option<PrivilegedTunRunExit>>,
    stopped: bool,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl PrivilegedTunHelperSession {
    fn spawn(
        platform: &'static str,
        stream: TcpStream,
        process_exit: oneshot::Receiver<String>,
    ) -> Arc<Self> {
        let (requests, request_rx) = mpsc::unbounded_channel();
        let (run_exit, _) = watch::channel(None);
        let session = Arc::new(Self {
            platform,
            requests,
            run_exit,
        });
        tokio::spawn(run_privileged_helper_session_manager(
            platform,
            stream,
            request_rx,
            session.run_exit.clone(),
            process_exit,
        ));
        session
    }

    fn is_alive(&self) -> bool {
        !self.requests.is_closed()
    }

    async fn start_run(&self, argv: Vec<String>, mtu: u16) -> Result<PrivilegedTunRunLease> {
        let mut exit = self.run_exit.subscribe();
        let (response, response_rx) = oneshot::channel();
        self.requests
            .send(PrivilegedTunHelperRequest::Start {
                argv,
                mtu,
                response,
            })
            .with_context(|| {
                format!(
                    "{} privileged TUN helper session is not running",
                    self.platform
                )
            })?;
        response_rx.await.with_context(|| {
            format!(
                "{} privileged TUN helper session stopped before TUN start completed",
                self.platform
            )
        })??;
        if let Some(exit) = exit.borrow_and_update().clone() {
            exit.into_result()?;
            bail!("privileged TUN helper runner stopped before TUN start completed");
        }
        Ok(PrivilegedTunRunLease {
            requests: self.requests.clone(),
            exit,
            stopped: false,
        })
    }

    async fn shutdown(&self) -> Result<()> {
        let (response, response_rx) = oneshot::channel();
        self.requests
            .send(PrivilegedTunHelperRequest::Shutdown {
                response: Some(response),
            })
            .with_context(|| {
                format!(
                    "{} privileged TUN helper session is not running",
                    self.platform
                )
            })?;
        response_rx.await.with_context(|| {
            format!(
                "{} privileged TUN helper session stopped before shutdown completed",
                self.platform
            )
        })?
    }

    async fn flush_dns(&self) -> Result<()> {
        let (response, response_rx) = oneshot::channel();
        self.requests
            .send(PrivilegedTunHelperRequest::FlushDns { response })
            .with_context(|| {
                format!(
                    "{} privileged TUN helper session is not running",
                    self.platform
                )
            })?;
        response_rx.await.with_context(|| {
            format!(
                "{} privileged TUN helper session stopped before DNS flush completed",
                self.platform
            )
        })?
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl PrivilegedTunRunExit {
    fn into_result(self) -> Result<()> {
        match self.error {
            Some(error) => bail!("privileged TUN helper runner stopped: {error}"),
            None => Ok(()),
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl PrivilegedTunRunLease {
    async fn wait(mut self, shutdown: CancellationToken) -> Result<()> {
        if let Some(exit) = self.exit.borrow_and_update().clone() {
            self.stopped = true;
            return exit.into_result();
        }

        tokio::select! {
            _ = shutdown.cancelled() => self.stop().await,
            changed = self.exit.changed() => {
                changed.context("privileged TUN helper session stopped before reporting runner status")?;
                let Some(exit) = self.exit.borrow_and_update().clone() else {
                    bail!("privileged TUN helper reported an empty runner status");
                };
                self.stopped = true;
                exit.into_result()
            }
        }
    }

    async fn stop(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        let (response, response_rx) = oneshot::channel();
        self.requests
            .send(PrivilegedTunHelperRequest::Stop {
                response: Some(response),
            })
            .context("privileged TUN helper session is not running")?;
        let result = response_rx
            .await
            .context("privileged TUN helper session stopped before TUN stop completed")?;
        self.stopped = true;
        result
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl Drop for PrivilegedTunRunLease {
    fn drop(&mut self) {
        if self.stopped {
            return;
        }
        let _ = self
            .requests
            .send(PrivilegedTunHelperRequest::Stop { response: None });
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn run_session_scoped_privileged_helper(
    platform: &'static str,
    session: Arc<PrivilegedTunHelperSession>,
    argv: Vec<String>,
    mtu: u16,
    shutdown: CancellationToken,
) -> Result<()> {
    info!(platform, "starting TUN through privileged helper session");
    let lease = session.start_run(argv, mtu).await?;
    lease.wait(shutdown).await
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn ensure_privileged_tun_helper_session<F, Fut>(
    platform: &'static str,
    start: F,
) -> Result<Arc<PrivilegedTunHelperSession>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<Arc<PrivilegedTunHelperSession>>>,
{
    let mut cached = privileged_tun_helper_session_cache().lock().await;
    if let Some(session) = cached.as_ref() {
        if session.is_alive() {
            debug!(platform, "reusing privileged TUN helper session");
            return Ok(Arc::clone(session));
        }
        warn!(platform, "discarding stopped privileged TUN helper session");
        *cached = None;
    }

    let session = start().await?;
    *cached = Some(Arc::clone(&session));
    Ok(session)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn run_privileged_helper_session_manager(
    platform: &'static str,
    stream: TcpStream,
    mut requests: mpsc::UnboundedReceiver<PrivilegedTunHelperRequest>,
    run_exit: watch::Sender<Option<PrivilegedTunRunExit>>,
    mut process_exit: oneshot::Receiver<String>,
) {
    let (read_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut pending: BTreeMap<u64, oneshot::Sender<Result<()>>> = BTreeMap::new();
    let mut next_id = 1u64;
    let mut shutdown_after_response = None;

    loop {
        tokio::select! {
            request = requests.recv() => {
                let Some(request) = request else {
                    let _ = send_privileged_helper_command(
                        &mut writer,
                        next_id,
                        PrivilegedTunHelperCommandKind::Shutdown,
                    ).await;
                    break;
                };
                let id = next_id;
                next_id = next_id.saturating_add(1);
                if let Err(err) = handle_privileged_helper_manager_request(
                    platform,
                    request,
                    id,
                    &mut writer,
                    &mut pending,
                    &run_exit,
                    &mut shutdown_after_response,
                ).await {
                    warn!(platform, error = %err, "privileged TUN helper command failed");
                    fail_pending_privileged_helper_requests(&mut pending, format!("{err:#}"));
                    let _ = run_exit.send(Some(PrivilegedTunRunExit { error: Some(format!("{err:#}")) }));
                    break;
                }
            }
            output = read_privileged_helper_output(&mut reader) => {
                match output {
                    Ok(Some(output)) => {
                        let should_shutdown = handle_privileged_helper_manager_output(
                            output,
                            &mut pending,
                            &run_exit,
                            shutdown_after_response,
                        );
                        if should_shutdown {
                            break;
                        }
                    }
                    Ok(None) => {
                        let message = format!("{platform} privileged TUN helper control connection closed");
                        warn!(message = %message, "privileged TUN helper control connection closed");
                        fail_pending_privileged_helper_requests(&mut pending, message.clone());
                        let _ = run_exit.send(Some(PrivilegedTunRunExit { error: Some(message) }));
                        break;
                    }
                    Err(err) => {
                        let message = format!("failed to read {platform} privileged TUN helper output: {err:#}");
                        warn!(error = %err, platform, "privileged TUN helper output read failed");
                        fail_pending_privileged_helper_requests(&mut pending, message.clone());
                        let _ = run_exit.send(Some(PrivilegedTunRunExit { error: Some(message) }));
                        break;
                    }
                }
            }
            process = &mut process_exit => {
                let message = process.unwrap_or_else(|_| {
                    format!("{platform} privileged TUN helper process monitor stopped")
                });
                warn!(platform, message = %message, "privileged TUN helper process exited");
                fail_pending_privileged_helper_requests(&mut pending, message.clone());
                let _ = run_exit.send(Some(PrivilegedTunRunExit { error: Some(message) }));
                break;
            }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn handle_privileged_helper_manager_request(
    platform: &'static str,
    request: PrivilegedTunHelperRequest,
    id: u64,
    writer: &mut OwnedWriteHalf,
    pending: &mut BTreeMap<u64, oneshot::Sender<Result<()>>>,
    run_exit: &watch::Sender<Option<PrivilegedTunRunExit>>,
    shutdown_after_response: &mut Option<u64>,
) -> Result<()> {
    match request {
        PrivilegedTunHelperRequest::Start {
            argv,
            mtu,
            response,
        } => {
            let _ = run_exit.send(None);
            send_privileged_helper_command(
                writer,
                id,
                PrivilegedTunHelperCommandKind::Start {
                    mtu,
                    tun2proxy_args: argv,
                },
            )
            .await?;
            pending.insert(id, response);
            debug!(
                platform,
                request_id = id,
                "sent privileged TUN start command"
            );
        }
        PrivilegedTunHelperRequest::Stop { response } => {
            send_privileged_helper_command(writer, id, PrivilegedTunHelperCommandKind::Stop)
                .await?;
            if let Some(response) = response {
                pending.insert(id, response);
            }
            debug!(
                platform,
                request_id = id,
                "sent privileged TUN stop command"
            );
        }
        PrivilegedTunHelperRequest::FlushDns { response } => {
            send_privileged_helper_command(writer, id, PrivilegedTunHelperCommandKind::FlushDns)
                .await?;
            pending.insert(id, response);
            debug!(
                platform,
                request_id = id,
                "sent privileged TUN DNS flush command"
            );
        }
        PrivilegedTunHelperRequest::Shutdown { response } => {
            send_privileged_helper_command(writer, id, PrivilegedTunHelperCommandKind::Shutdown)
                .await?;
            if let Some(response) = response {
                pending.insert(id, response);
                *shutdown_after_response = Some(id);
            } else {
                *shutdown_after_response = Some(id);
            }
            debug!(
                platform,
                request_id = id,
                "sent privileged TUN helper shutdown command"
            );
        }
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn handle_privileged_helper_manager_output(
    output: PrivilegedTunHelperOutput,
    pending: &mut BTreeMap<u64, oneshot::Sender<Result<()>>>,
    run_exit: &watch::Sender<Option<PrivilegedTunRunExit>>,
    shutdown_after_response: Option<u64>,
) -> bool {
    match output {
        PrivilegedTunHelperOutput::Response { id, ok, error } => {
            if let Some(response) = pending.remove(&id) {
                let result = if ok {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "{}",
                        error.unwrap_or_else(|| "privileged TUN helper command failed".to_string())
                    ))
                };
                let _ = response.send(result);
            }
            shutdown_after_response == Some(id)
        }
        PrivilegedTunHelperOutput::Event { event, error } => {
            if matches!(event, PrivilegedTunHelperEvent::TunStopped) {
                let _ = run_exit.send(Some(PrivilegedTunRunExit { error }));
            }
            false
        }
        PrivilegedTunHelperOutput::ResourceLimit {
            context,
            soft,
            hard,
            open_files,
            changed,
            previous_soft,
            error,
        } => {
            match error {
                Some(error) => warn!(
                    context = %context,
                    error = %error,
                    "privileged TUN helper resource limit snapshot failed"
                ),
                None => info!(
                    context = %context,
                    soft = %soft,
                    hard = %hard,
                    open_files = ?open_files,
                    changed,
                    previous_soft = previous_soft.as_deref().unwrap_or("-"),
                    "privileged TUN helper resource limit"
                ),
            }
            false
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn send_privileged_helper_command(
    writer: &mut OwnedWriteHalf,
    id: u64,
    command: PrivilegedTunHelperCommandKind,
) -> Result<()> {
    let envelope = PrivilegedTunHelperEnvelope { id, command };
    let mut line =
        serde_json::to_vec(&envelope).context("failed to encode privileged helper command")?;
    line.push(b'\n');
    writer
        .write_all(&line)
        .await
        .context("failed to write privileged helper command")
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn read_privileged_helper_output(
    reader: &mut BufReader<OwnedReadHalf>,
) -> Result<Option<PrivilegedTunHelperOutput>> {
    let mut line = String::new();
    let bytes = reader
        .read_line(&mut line)
        .await
        .context("failed to read privileged helper output")?;
    if bytes == 0 {
        return Ok(None);
    }
    serde_json::from_str(line.trim_end())
        .map(Some)
        .context("failed to parse privileged helper output")
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn fail_pending_privileged_helper_requests(
    pending: &mut BTreeMap<u64, oneshot::Sender<Result<()>>>,
    message: String,
) {
    for (_, response) in std::mem::take(pending) {
        let _ = response.send(Err(anyhow::anyhow!("{}", message)));
    }
}

#[cfg(target_os = "macos")]
async fn run_macos_privileged_helper(
    argv: Vec<String>,
    mtu: u16,
    shutdown: CancellationToken,
) -> Result<()> {
    let session =
        ensure_privileged_tun_helper_session("macOS", start_macos_privileged_helper_session)
            .await?;
    run_session_scoped_privileged_helper("macOS", session, argv, mtu, shutdown).await
}

#[cfg(target_os = "macos")]
async fn start_macos_privileged_helper_session() -> Result<Arc<PrivilegedTunHelperSession>> {
    let mut token_file = HelperTokenFile::create()?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("failed to bind TUN helper control listener")?;
    let control_addr = listener
        .local_addr()
        .context("failed to read TUN helper control address")?;
    let script = macos_privileged_helper_script(control_addr, token_file.path())?;
    let mut child = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .kill_on_drop(true)
        .spawn()
        .context("failed to request macOS administrator authorization for TUN")?;

    let accept = timeout(MACOS_HELPER_AUTH_TIMEOUT, listener.accept());
    tokio::pin!(accept);
    let mut child_wait = Box::pin(child.wait());
    let (mut stream, _) = tokio::select! {
        result = &mut accept => {
            result
                .context("timed out waiting for macOS administrator authorization for TUN")?
                .context("failed to accept TUN helper control connection")?
        }
        result = &mut child_wait => {
            let status = result.context("failed to wait for macOS administrator authorization prompt")?;
            bail!("macOS privileged TUN helper exited before connecting ({status})");
        }
    };
    drop(child_wait);
    verify_helper_token(&mut stream, token_file.token()).await?;
    token_file.remove_best_effort();
    info!("macOS privileged TUN helper session connected");
    let (process_exit_tx, process_exit_rx) = oneshot::channel();
    tokio::spawn(async move {
        let message = match child.wait().await {
            Ok(status) => format!("macOS privileged TUN helper exited with {status}"),
            Err(err) => format!("failed to wait for macOS privileged TUN helper: {err}"),
        };
        let _ = process_exit_tx.send(message);
    });
    Ok(PrivilegedTunHelperSession::spawn(
        "macOS",
        stream,
        process_exit_rx,
    ))
}

#[cfg(target_os = "windows")]
async fn run_windows_privileged_helper(
    argv: Vec<String>,
    mtu: u16,
    shutdown: CancellationToken,
) -> Result<()> {
    let session =
        ensure_privileged_tun_helper_session("Windows", start_windows_privileged_helper_session)
            .await?;
    run_session_scoped_privileged_helper("Windows", session, argv, mtu, shutdown).await
}

#[cfg(target_os = "windows")]
async fn start_windows_privileged_helper_session() -> Result<Arc<PrivilegedTunHelperSession>> {
    let mut token_file = HelperTokenFile::create()?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("failed to bind TUN helper control listener")?;
    let control_addr = listener
        .local_addr()
        .context("failed to read TUN helper control address")?;
    let helper = windows_spawn_privileged_helper(control_addr, token_file.path())?;

    let accept = timeout(WINDOWS_HELPER_AUTH_TIMEOUT, listener.accept());
    tokio::pin!(accept);
    let mut helper_wait = Box::pin(windows_wait_process_exit(helper.handle()));
    let (mut stream, _) = tokio::select! {
        result = &mut accept => {
            result
                .context("timed out waiting for Windows Administrator authorization for TUN")?
                .context("failed to accept TUN helper control connection")?
        }
        result = &mut helper_wait => {
            let exit_code = result.context("failed to wait for Windows privileged TUN helper")?;
            bail!("Windows privileged TUN helper exited before connecting (exit code {exit_code})");
        }
    };
    drop(helper_wait);
    verify_helper_token(&mut stream, token_file.token()).await?;
    token_file.remove_best_effort();
    info!("Windows privileged TUN helper session connected");
    let handle = helper.into_handle();
    let (process_exit_tx, process_exit_rx) = oneshot::channel();
    tokio::spawn(async move {
        let message = match windows_wait_process_exit(handle).await {
            Ok(exit_code) => format!("Windows privileged TUN helper exited with code {exit_code}"),
            Err(err) => format!("failed to wait for Windows privileged TUN helper: {err}"),
        };
        unsafe {
            let _ = close_handle(handle);
        }
        let _ = process_exit_tx.send(message);
    });
    Ok(PrivilegedTunHelperSession::spawn(
        "Windows",
        stream,
        process_exit_rx,
    ))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn verify_helper_token(stream: &mut TcpStream, expected: &str) -> Result<()> {
    let mut token = Vec::new();
    let mut byte = [0u8; 1];
    while token.len() <= expected.len() {
        let read = timeout(Duration::from_secs(5), stream.read(&mut byte))
            .await
            .context("timed out waiting for TUN helper control token")?
            .context("failed to read TUN helper control token")?;
        if read == 0 {
            bail!("TUN helper control connection closed before authentication");
        }
        if byte[0] == b'\n' {
            let actual = String::from_utf8(token).context("TUN helper control token is invalid")?;
            if actual == expected {
                return Ok(());
            }
            bail!("TUN helper control token mismatch");
        }
        token.push(byte[0]);
    }
    bail!("TUN helper control token is too long");
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn random_helper_token() -> String {
    let mut token = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token);
    hex::encode(token)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
struct HelperTokenFile {
    path: PathBuf,
    token: String,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl HelperTokenFile {
    fn create() -> Result<Self> {
        let token = random_helper_token();
        let path = helper_token_path();
        fs_security::write_private_file(&path, format!("{token}\n")).with_context(|| {
            format!(
                "failed to write TUN helper control token file {}",
                path.display()
            )
        })?;
        Ok(Self { path, token })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn token(&self) -> &str {
        &self.token
    }

    fn remove_best_effort(&mut self) {
        if self.path.as_os_str().is_empty() {
            return;
        }
        let _ = fs::remove_file(&self.path);
        self.path = PathBuf::new();
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl Drop for HelperTokenFile {
    fn drop(&mut self) {
        self.remove_best_effort();
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn helper_token_path() -> PathBuf {
    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    std::env::temp_dir().join(format!(
        "tabbymew-tun-helper-{}-{}.token",
        std::process::id(),
        hex::encode(suffix)
    ))
}

#[cfg(target_os = "windows")]
fn windows_spawn_privileged_helper(
    control_addr: SocketAddr,
    token_file: &Path,
) -> Result<WindowsHelperProcess> {
    let exe = std::env::current_exe().context("failed to locate current executable")?;
    let exe = wide_null(&exe.display().to_string());
    let verb = wide_null("runas");
    let parameters = wide_null(&windows_helper_parameters(control_addr, token_file));
    let directory = std::env::current_exe().ok().and_then(|path| {
        path.parent()
            .map(|parent| wide_null(&parent.display().to_string()))
    });
    let directory_ptr = directory
        .as_ref()
        .map(|value| value.as_ptr())
        .unwrap_or(std::ptr::null());

    let mut info = ShellExecuteInfoW {
        cb_size: std::mem::size_of::<ShellExecuteInfoW>() as u32,
        f_mask: SEE_MASK_NOCLOSEPROCESS,
        hwnd: 0,
        lp_verb: verb.as_ptr(),
        lp_file: exe.as_ptr(),
        lp_parameters: parameters.as_ptr(),
        lp_directory: directory_ptr,
        n_show: SW_HIDE,
        h_inst_app: 0,
        lp_id_list: std::ptr::null_mut(),
        lp_class: std::ptr::null(),
        hkey_class: 0,
        dw_hot_key: 0,
        h_icon_or_monitor: 0,
        h_process: 0,
    };

    let ok = unsafe { shell_execute_ex_w(&mut info) };
    if ok == 0 {
        let error = windows_last_error();
        if error == ERROR_CANCELLED {
            bail!(
                "Windows TUN mode requires Administrator privileges; UAC authorization was cancelled"
            );
        }
        bail!(
            "failed to request Windows Administrator authorization for TUN (Windows error {error})"
        );
    }
    if info.h_process == 0 {
        bail!("failed to start Windows privileged TUN helper: process handle was not returned");
    }

    Ok(WindowsHelperProcess {
        handle: info.h_process,
    })
}

#[cfg(any(target_os = "windows", test))]
fn windows_helper_parameters(control_addr: SocketAddr, token_file: &Path) -> String {
    let command = vec![
        "internal-tun-helper".to_string(),
        "--control".to_string(),
        control_addr.to_string(),
        "--token-file".to_string(),
        token_file.display().to_string(),
    ];
    windows_command_line(&command)
}

#[cfg(any(target_os = "windows", test))]
fn windows_command_line(args: &[String]) -> String {
    args.iter()
        .map(|arg| windows_quote_command_line_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(any(target_os = "windows", test))]
fn windows_quote_command_line_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if !arg
        .bytes()
        .any(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'"'))
    {
        return arg.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                quoted.push(ch);
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(target_os = "windows")]
async fn windows_wait_process_exit(handle: WindowsHandle) -> Result<u32> {
    loop {
        match unsafe { wait_for_single_object(handle, 0) } {
            WAIT_OBJECT_0 => return windows_process_exit_code(handle),
            WAIT_TIMEOUT => sleep(Duration::from_millis(100)).await,
            WAIT_FAILED => bail!(
                "failed to wait for Windows privileged TUN helper (Windows error {})",
                windows_last_error()
            ),
            other => bail!("unexpected Windows wait result for privileged TUN helper: {other}"),
        }
    }
}

#[cfg(target_os = "windows")]
fn windows_process_exit_code(handle: WindowsHandle) -> Result<u32> {
    let mut exit_code = 0;
    let ok = unsafe { get_exit_code_process(handle, &mut exit_code) };
    if ok == 0 {
        bail!(
            "failed to read Windows privileged TUN helper exit code (Windows error {})",
            windows_last_error()
        );
    }
    Ok(exit_code)
}

#[cfg(target_os = "windows")]
fn windows_last_error() -> u32 {
    unsafe { get_last_error() }
}

#[cfg(target_os = "windows")]
struct WindowsHelperProcess {
    handle: WindowsHandle,
}

#[cfg(target_os = "windows")]
impl WindowsHelperProcess {
    fn handle(&self) -> WindowsHandle {
        self.handle
    }

    fn into_handle(mut self) -> WindowsHandle {
        let handle = self.handle;
        self.handle = 0;
        handle
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsHelperProcess {
    fn drop(&mut self) {
        if self.handle != 0 {
            unsafe {
                let _ = close_handle(self.handle);
            }
            self.handle = 0;
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_privileged_helper_script(control_addr: SocketAddr, token_file: &Path) -> Result<String> {
    let exe = std::env::current_exe().context("failed to locate current executable")?;
    let command = vec![
        exe.display().to_string(),
        "internal-tun-helper".to_string(),
        "--control".to_string(),
        control_addr.to_string(),
        "--token-file".to_string(),
        token_file.display().to_string(),
    ];
    Ok(format!(
        "do shell script {} with administrator privileges",
        applescript_string(&format!("exec {}", shell_join(&command)))
    ))
}

#[cfg(target_os = "macos")]
fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(target_os = "macos")]
fn shell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

#[cfg(target_os = "macos")]
fn applescript_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
fn build_args(options: &TunInboundOptions, socks_addr: SocketAddr) -> Result<Tun2ProxyArgs> {
    parse_tun2proxy_args(build_argv(options, socks_addr)?)
}

fn build_argv(options: &TunInboundOptions, socks_addr: SocketAddr) -> Result<Vec<String>> {
    build_argv_from_parts(
        TunArgsParts {
            interface_name: options.interface_name.as_deref(),
            mtu: options.mtu,
            auto_route: options.auto_route,
            ipv6_enabled: options.ipv6_enabled,
            dns: options.dns,
            dns_addr: options.dns_addr.as_deref(),
            bypass: &options.bypass,
            tcp_timeout_seconds: options.tcp_timeout_seconds,
            udp_timeout_seconds: options.udp_timeout_seconds,
            max_sessions: options.max_sessions,
        },
        socks_addr,
    )
}

type TunArgsParts<'a> = TunConfigParts<'a>;

fn build_args_from_parts(
    parts: TunConfigParts<'_>,
    socks_addr: SocketAddr,
) -> Result<Tun2ProxyArgs> {
    parse_tun2proxy_args(build_argv_from_parts(parts, socks_addr)?)
}

fn build_argv_from_parts(parts: TunConfigParts<'_>, socks_addr: SocketAddr) -> Result<Vec<String>> {
    if parts.mtu == 0 {
        bail!("TUN MTU must be greater than 0");
    }
    if parts
        .tcp_timeout_seconds
        .is_some_and(|timeout| timeout == 0)
    {
        bail!("TUN tcp_timeout_seconds must be greater than 0");
    }
    if parts
        .udp_timeout_seconds
        .is_some_and(|timeout| timeout == 0)
    {
        bail!("TUN udp_timeout_seconds must be greater than 0");
    }
    if parts.max_sessions.is_some_and(|sessions| sessions == 0) {
        bail!("TUN max_sessions must be greater than 0");
    }

    let mut argv = vec![
        "tun2proxy".to_string(),
        "--proxy".to_string(),
        format!("socks5://{socks_addr}"),
        "--dns".to_string(),
        dns_arg(parts.dns).to_string(),
    ];

    if let Some(interface_name) = parts.interface_name {
        argv.push("--tun".to_string());
        argv.push(interface_name.to_string());
    }
    if parts.auto_route {
        argv.push("--setup".to_string());
    }
    if parts.ipv6_enabled {
        argv.push("--ipv6-enabled".to_string());
    }
    if let Some(dns_addr) = parts.dns_addr {
        argv.push("--dns-addr".to_string());
        argv.push(dns_addr.to_string());
    }
    for bypass in parts.bypass {
        argv.push("--bypass".to_string());
        argv.push(bypass.clone());
    }
    if let Some(tcp_timeout_seconds) = parts.tcp_timeout_seconds {
        argv.push("--tcp-timeout".to_string());
        argv.push(tcp_timeout_seconds.to_string());
    }
    if let Some(udp_timeout_seconds) = parts.udp_timeout_seconds {
        argv.push("--udp-timeout".to_string());
        argv.push(udp_timeout_seconds.to_string());
    }
    if let Some(max_sessions) = parts.max_sessions {
        argv.push("--max-sessions".to_string());
        argv.push(max_sessions.to_string());
    }

    Ok(argv)
}

fn parse_tun2proxy_args(argv: Vec<String>) -> Result<Tun2ProxyArgs> {
    Tun2ProxyArgs::try_parse_from(argv).context("failed to build tun2proxy arguments")
}

fn dns_arg(dns: TunDnsMode) -> &'static str {
    match dns {
        TunDnsMode::Virtual => "virtual",
        TunDnsMode::OverTcp => "over-tcp",
        TunDnsMode::Direct => "direct",
    }
}

#[cfg(unix)]
fn current_privilege_verified() -> Option<bool> {
    Some(unsafe { libc::geteuid() == 0 })
}

#[cfg(target_os = "windows")]
fn current_privilege_verified() -> Option<bool> {
    windows_current_process_is_elevated()
}

#[cfg(all(not(unix), not(target_os = "windows")))]
fn current_privilege_verified() -> Option<bool> {
    None
}

#[cfg(target_os = "windows")]
fn windows_current_process_is_elevated() -> Option<bool> {
    let mut token = 0;
    let opened = unsafe { open_process_token(get_current_process(), TOKEN_QUERY, &mut token) };
    if opened == 0 || token == 0 {
        return None;
    }

    let mut elevation = WindowsTokenElevation {
        token_is_elevated: 0,
    };
    let mut returned_len = 0;
    let ok = unsafe {
        get_token_information(
            token,
            TOKEN_INFORMATION_CLASS_TOKEN_ELEVATION,
            &mut elevation as *mut WindowsTokenElevation as *mut std::ffi::c_void,
            std::mem::size_of::<WindowsTokenElevation>() as u32,
            &mut returned_len,
        )
    };
    unsafe {
        let _ = close_handle(token);
    }

    (ok != 0).then_some(elevation.token_is_elevated != 0)
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct WindowsTokenElevation {
    token_is_elevated: u32,
}

#[cfg(target_os = "windows")]
type WindowsHandle = isize;

#[cfg(target_os = "windows")]
const TOKEN_QUERY: u32 = 0x0008;
#[cfg(target_os = "windows")]
const TOKEN_INFORMATION_CLASS_TOKEN_ELEVATION: u32 = 20;
#[cfg(target_os = "windows")]
const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;
#[cfg(target_os = "windows")]
const SW_HIDE: i32 = 0;
#[cfg(target_os = "windows")]
const WAIT_OBJECT_0: u32 = 0;
#[cfg(target_os = "windows")]
const WAIT_TIMEOUT: u32 = 258;
#[cfg(target_os = "windows")]
const WAIT_FAILED: u32 = 0xFFFF_FFFF;
#[cfg(target_os = "windows")]
const ERROR_CANCELLED: u32 = 1223;

#[cfg(target_os = "windows")]
#[repr(C)]
struct ShellExecuteInfoW {
    cb_size: u32,
    f_mask: u32,
    hwnd: WindowsHandle,
    lp_verb: *const u16,
    lp_file: *const u16,
    lp_parameters: *const u16,
    lp_directory: *const u16,
    n_show: i32,
    h_inst_app: WindowsHandle,
    lp_id_list: *mut std::ffi::c_void,
    lp_class: *const u16,
    hkey_class: WindowsHandle,
    dw_hot_key: u32,
    h_icon_or_monitor: WindowsHandle,
    h_process: WindowsHandle,
}

#[cfg(target_os = "windows")]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
#[link(name = "advapi32")]
unsafe extern "system" {
    #[link_name = "OpenProcessToken"]
    fn open_process_token(
        process_handle: WindowsHandle,
        desired_access: u32,
        token_handle: *mut WindowsHandle,
    ) -> i32;

    #[link_name = "GetTokenInformation"]
    fn get_token_information(
        token_handle: WindowsHandle,
        token_information_class: u32,
        token_information: *mut std::ffi::c_void,
        token_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "GetCurrentProcess"]
    fn get_current_process() -> WindowsHandle;

    #[link_name = "CloseHandle"]
    fn close_handle(object: WindowsHandle) -> i32;

    #[link_name = "WaitForSingleObject"]
    fn wait_for_single_object(handle: WindowsHandle, milliseconds: u32) -> u32;

    #[link_name = "GetExitCodeProcess"]
    fn get_exit_code_process(handle: WindowsHandle, exit_code: *mut u32) -> i32;

    #[link_name = "GetLastError"]
    fn get_last_error() -> u32;
}

#[cfg(target_os = "windows")]
#[link(name = "shell32")]
unsafe extern "system" {
    #[link_name = "ShellExecuteExW"]
    fn shell_execute_ex_w(info: *mut ShellExecuteInfoW) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{OutboundConfig, RouteConfig},
        router::Router,
    };

    #[test]
    fn builds_tun2proxy_args() {
        let router = Router::from_config(
            &[OutboundConfig::Direct {
                tag: "direct".to_string(),
            }],
            &RouteConfig::default(),
        )
        .unwrap();
        let options = TunInboundOptions {
            tag: "tun-in".to_string(),
            interface_name: None,
            mtu: 1500,
            auto_route: true,
            ipv6_enabled: false,
            dns: TunDnsMode::OverTcp,
            dns_addr: Some("8.8.8.8".to_string()),
            bypass: vec!["127.0.0.0/8".to_string()],
            tcp_timeout_seconds: Some(300),
            udp_timeout_seconds: Some(20),
            max_sessions: Some(1024),
            router,
        };

        build_args(&options, "127.0.0.1:1080".parse().unwrap()).unwrap();
    }

    #[test]
    fn validates_tun_mtu() {
        let err = validate_config(TunConfigParts {
            interface_name: None,
            mtu: 0,
            auto_route: false,
            ipv6_enabled: false,
            dns: TunDnsMode::Direct,
            dns_addr: None,
            bypass: &[],
            tcp_timeout_seconds: None,
            udp_timeout_seconds: None,
            max_sessions: None,
        })
        .unwrap_err();

        assert!(err.to_string().contains("TUN MTU must be greater than 0"));
    }

    #[test]
    fn tun_packet_information_matches_platform() {
        assert_eq!(
            platform::tun_packet_information(),
            platform::current() == platform::Platform::Macos
        );
    }

    #[test]
    fn windows_tun2proxy_load_library_error_explains_wintun_dll() {
        let message =
            format_tun2proxy_error_for_platform("LoadLibraryExW failed".to_string(), true);

        assert!(message.contains("wintun.dll"));
        assert!(message.contains("same directory as TabbyMew.exe"));
    }

    #[test]
    fn windows_tun2proxy_adapter_access_denied_explains_administrator() {
        let message = format_tun2proxy_error_for_platform(
            "WintunCreateAdapter failed \"Failed to take device installation mutex (Code 0x00000005)\"".to_string(),
            true,
        );

        assert!(message.contains("Administrator"));
        assert!(message.contains("UAC prompt"));
    }

    #[test]
    fn windows_tun_requires_privilege_even_without_auto_route() {
        assert!(platform::tun_requires_privilege_for_platform(
            false, true, "windows"
        ));
        assert!(!platform::tun_requires_privilege_for_platform(
            false, true, "macos"
        ));
        assert!(platform::tun_requires_privilege_for_platform(
            true, true, "macos"
        ));
        assert!(!platform::tun_requires_privilege_for_platform(
            true, false, "windows"
        ));
    }

    #[test]
    fn preflight_reports_missing_privilege_for_auto_route() {
        let preflight = preflight_config_with_privilege(
            TunConfigParts {
                interface_name: None,
                mtu: 1500,
                auto_route: true,
                ipv6_enabled: false,
                dns: TunDnsMode::Virtual,
                dns_addr: None,
                bypass: &[],
                tcp_timeout_seconds: None,
                udp_timeout_seconds: None,
                max_sessions: None,
            },
            Some(false),
        );

        if platform::tun_supported() {
            assert_eq!(preflight.status, TunPreflightStatus::RequiresPermission);
            assert!(preflight.supported);
            assert!(preflight.requires_privilege);
        } else {
            assert_eq!(preflight.status, TunPreflightStatus::Unsupported);
            assert!(!preflight.supported);
        }
    }

    #[test]
    fn privileged_helper_support_matches_platform_prompt_support() {
        assert_eq!(
            can_start_with_privileged_helper(),
            platform::tun_privileged_helper_supported()
        );
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn helper_token_file_keeps_token_out_of_arguments() -> Result<()> {
        let mut token_file = HelperTokenFile::create()?;
        let path = token_file.path().to_path_buf();
        let token = token_file.token().to_string();

        assert_eq!(fs::read_to_string(&path)?.trim(), token);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        }

        token_file.remove_best_effort();
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn windows_helper_parameters_only_start_session() {
        let params = windows_helper_parameters(
            "127.0.0.1:12345".parse().unwrap(),
            Path::new("C:\\Temp\\helper-auth.txt"),
        );

        assert!(params.starts_with("internal-tun-helper --control 127.0.0.1:12345"));
        assert!(params.contains("--token-file C:\\Temp\\helper-auth.txt"));
        assert!(!params.contains("--token "));
        assert!(!params.contains("--mtu"));
        assert!(!params.contains("tun2proxy"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_privileged_helper_script_only_starts_session() {
        assert_eq!(
            shell_quote("quote'and\"slash\\"),
            "'quote'\\''and\"slash\\'"
        );
        assert_eq!(applescript_string("a\"b\\c"), "\"a\\\"b\\\\c\"");

        let script = macos_privileged_helper_script(
            "127.0.0.1:12345".parse().unwrap(),
            Path::new("/tmp/helper-auth.txt"),
        )
        .unwrap();

        assert!(script.contains("with administrator privileges"));
        assert!(script.contains("--token-file"));
        assert!(!script.contains("--token "));
        assert!(!script.contains("--mtu"));
        assert!(!script.contains("tun2proxy"));
        assert!(script.contains("internal-tun-helper"));
    }

    #[test]
    fn privileged_helper_start_command_carries_tun_arguments() {
        let envelope = PrivilegedTunHelperEnvelope {
            id: 7,
            command: PrivilegedTunHelperCommandKind::Start {
                mtu: 1500,
                tun2proxy_args: vec![
                    "tun2proxy".to_string(),
                    "--proxy".to_string(),
                    "socks5://127.0.0.1:1080".to_string(),
                    "--bypass".to_string(),
                    "quote'and\"slash\\".to_string(),
                ],
            },
        };

        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("\"command\":\"start\""));
        assert!(json.contains("\"mtu\":1500"));
        assert!(json.contains("tun2proxy"));

        let decoded: PrivilegedTunHelperEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, 7);
        match decoded.command {
            PrivilegedTunHelperCommandKind::Start {
                mtu,
                tun2proxy_args,
            } => {
                assert_eq!(mtu, 1500);
                assert_eq!(tun2proxy_args[0], "tun2proxy");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn privileged_helper_flush_dns_command_is_machine_readable() {
        let envelope = PrivilegedTunHelperEnvelope {
            id: 8,
            command: PrivilegedTunHelperCommandKind::FlushDns,
        };

        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("\"command\":\"flush_dns\""));

        let decoded: PrivilegedTunHelperEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, 8);
        assert!(matches!(
            decoded.command,
            PrivilegedTunHelperCommandKind::FlushDns
        ));
    }

    #[test]
    fn privileged_helper_resource_limit_output_is_machine_readable() {
        let output = privileged_helper_resource_limit_output("test resource snapshot");
        let json = serde_json::to_string(&output).unwrap();

        assert!(json.contains("\"type\":\"resource_limit\""));
        assert!(json.contains("\"context\":\"test resource snapshot\""));

        let decoded: PrivilegedTunHelperOutput = serde_json::from_str(&json).unwrap();
        match decoded {
            PrivilegedTunHelperOutput::ResourceLimit { context, .. } => {
                assert_eq!(context, "test resource snapshot");
            }
            other => panic!("unexpected output: {other:?}"),
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[tokio::test]
    async fn privileged_helper_session_drop_sends_stop_without_reauth() -> Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let client = TcpStream::connect(addr).await?;
        let (server, _) = listener.accept().await?;
        let (_process_exit_tx, process_exit_rx) = oneshot::channel();
        let session = PrivilegedTunHelperSession::spawn("test", client, process_exit_rx);

        let fake_helper = tokio::spawn(async move {
            let (read_half, mut writer) = server.into_split();
            let mut reader = BufReader::new(read_half);
            let start = read_test_helper_command(&mut reader).await?;
            assert_eq!(start.id, 1);
            match start.command {
                PrivilegedTunHelperCommandKind::Start {
                    mtu,
                    tun2proxy_args,
                } => {
                    assert_eq!(mtu, 1500);
                    assert_eq!(tun2proxy_args[0], "tun2proxy");
                }
                other => panic!("unexpected command: {other:?}"),
            }
            write_privileged_helper_output(
                &mut writer,
                &PrivilegedTunHelperOutput::Response {
                    id: start.id,
                    ok: true,
                    error: None,
                },
            )
            .await?;

            let stop = read_test_helper_command(&mut reader).await?;
            assert_eq!(stop.id, 2);
            assert!(matches!(stop.command, PrivilegedTunHelperCommandKind::Stop));
            write_privileged_helper_output(
                &mut writer,
                &PrivilegedTunHelperOutput::Response {
                    id: stop.id,
                    ok: true,
                    error: None,
                },
            )
            .await?;
            Ok::<(), anyhow::Error>(())
        });

        let lease = session
            .start_run(
                vec![
                    "tun2proxy".to_string(),
                    "--proxy".to_string(),
                    "socks5://127.0.0.1:1080".to_string(),
                ],
                1500,
            )
            .await?;
        drop(lease);
        fake_helper.await??;
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[tokio::test]
    async fn privileged_helper_session_can_flush_dns_without_reauth() -> Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let client = TcpStream::connect(addr).await?;
        let (server, _) = listener.accept().await?;
        let (_process_exit_tx, process_exit_rx) = oneshot::channel();
        let session = PrivilegedTunHelperSession::spawn("test", client, process_exit_rx);

        let fake_helper = tokio::spawn(async move {
            let (read_half, mut writer) = server.into_split();
            let mut reader = BufReader::new(read_half);
            let flush = read_test_helper_command(&mut reader).await?;
            assert_eq!(flush.id, 1);
            assert!(matches!(
                flush.command,
                PrivilegedTunHelperCommandKind::FlushDns
            ));
            write_privileged_helper_output(
                &mut writer,
                &PrivilegedTunHelperOutput::Response {
                    id: flush.id,
                    ok: true,
                    error: None,
                },
            )
            .await?;
            Ok::<(), anyhow::Error>(())
        });

        session.flush_dns().await?;
        fake_helper.await??;
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    async fn read_test_helper_command(
        reader: &mut BufReader<OwnedReadHalf>,
    ) -> Result<PrivilegedTunHelperEnvelope> {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        serde_json::from_str(line.trim_end()).context("test helper command must be JSON")
    }

    #[test]
    fn preflight_allows_manual_route_without_privilege() {
        let preflight = preflight_config_with_privilege(
            TunConfigParts {
                interface_name: None,
                mtu: 1500,
                auto_route: false,
                ipv6_enabled: false,
                dns: TunDnsMode::Direct,
                dns_addr: None,
                bypass: &[],
                tcp_timeout_seconds: None,
                udp_timeout_seconds: None,
                max_sessions: None,
            },
            Some(false),
        );

        if platform::tun_supported() {
            if platform::current() == platform::Platform::Windows {
                assert_eq!(preflight.status, TunPreflightStatus::RequiresPermission);
                assert!(preflight.requires_privilege);
            } else {
                assert_eq!(preflight.status, TunPreflightStatus::Ready);
                assert!(!preflight.requires_privilege);
            }
        } else {
            assert_eq!(preflight.status, TunPreflightStatus::Unsupported);
        }
    }
}
