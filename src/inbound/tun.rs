use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use clap::Parser;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use rand::RngCore;
#[cfg(any(target_os = "macos", target_os = "windows", test))]
use std::path::Path;
#[cfg(target_os = "macos")]
use tokio::process::Command;
#[cfg(target_os = "windows")]
use tokio::time::sleep;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};
use tracing::debug;
use tun2proxy::{Args as Tun2ProxyArgs, CancellationToken};

#[cfg(any(target_os = "macos", target_os = "windows"))]
use crate::fs_security;
use crate::{config::TunDnsMode, inbound::socks, platform, router::Router};

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

    #[arg(long)]
    pub(crate) mtu: u16,

    #[arg(last = true, required = true)]
    pub(crate) tun2proxy_args: Vec<String>,
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
    tasks.spawn(socks::serve_listener(
        socks_tag,
        socks_listener,
        options.router.clone(),
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
            return run_macos_privileged_helper(argv, mtu).await;
        }
    }
    #[cfg(target_os = "windows")]
    {
        if current_privilege_verified() != Some(true) {
            return run_windows_privileged_helper(argv, mtu).await;
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

    let args = parse_tun2proxy_args(command.tun2proxy_args)?;
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

    let shutdown = CancellationToken::new();
    let mut monitor = tokio::spawn(monitor_parent_control(control, shutdown.clone()));
    let mut runner = tokio::spawn(run_tun2proxy(args, command.mtu, shutdown.clone()));
    tokio::select! {
        result = &mut runner => {
            shutdown.cancel();
            monitor.abort();
            match result {
                Ok(result) => result,
                Err(err) => Err(err).context("privileged TUN helper task panicked"),
            }
        }
        result = &mut monitor => {
            shutdown.cancel();
            let control_result = match result {
                Ok(result) => result,
                Err(err) => Err(err).context("TUN helper control monitor panicked"),
            };
            control_result?;
            match timeout(Duration::from_secs(5), &mut runner).await {
                Ok(Ok(result)) => result,
                Ok(Err(err)) => Err(err).context("privileged TUN helper task panicked"),
                Err(_) => {
                    runner.abort();
                    bail!("timed out waiting for privileged TUN helper shutdown");
                }
            }
        }
    }
}

async fn monitor_parent_control(mut control: TcpStream, shutdown: CancellationToken) -> Result<()> {
    let mut buffer = [0u8; 1];
    loop {
        if control
            .read(&mut buffer)
            .await
            .context("failed to read TUN helper control connection")?
            == 0
        {
            shutdown.cancel();
            return Ok(());
        }
    }
}

#[cfg(target_os = "macos")]
const MACOS_HELPER_AUTH_TIMEOUT: Duration = Duration::from_secs(120);

#[cfg(target_os = "windows")]
const WINDOWS_HELPER_AUTH_TIMEOUT: Duration = Duration::from_secs(120);

#[cfg(target_os = "macos")]
async fn run_macos_privileged_helper(argv: Vec<String>, mtu: u16) -> Result<()> {
    let mut token_file = HelperTokenFile::create()?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("failed to bind TUN helper control listener")?;
    let control_addr = listener
        .local_addr()
        .context("failed to read TUN helper control address")?;
    let script = macos_privileged_helper_script(&argv, mtu, control_addr, token_file.path())?;
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
    debug!("macOS privileged TUN helper connected");

    let mut child_wait = Box::pin(child.wait());
    let mut helper_monitor = Box::pin(monitor_privileged_helper(stream, "macOS"));
    tokio::select! {
        result = &mut helper_monitor => {
            let _ = timeout(Duration::from_secs(1), &mut child_wait).await;
            result
        }
        result = &mut child_wait => {
            let status = result.context("failed to wait for macOS privileged TUN helper")?;
            if status.success() {
                Ok(())
            } else {
                bail!("macOS privileged TUN helper exited with {status}");
            }
        }
    }
}

#[cfg(target_os = "windows")]
async fn run_windows_privileged_helper(argv: Vec<String>, mtu: u16) -> Result<()> {
    let mut token_file = HelperTokenFile::create()?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("failed to bind TUN helper control listener")?;
    let control_addr = listener
        .local_addr()
        .context("failed to read TUN helper control address")?;
    let helper = windows_spawn_privileged_helper(&argv, mtu, control_addr, token_file.path())?;

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
    debug!("Windows privileged TUN helper connected");

    let mut helper_wait = Box::pin(windows_wait_process_exit(helper.handle()));
    let mut helper_monitor = Box::pin(monitor_privileged_helper(stream, "Windows"));
    tokio::select! {
        result = &mut helper_monitor => {
            let _ = timeout(Duration::from_secs(1), &mut helper_wait).await;
            result
        }
        result = &mut helper_wait => {
            let exit_code = result.context("failed to wait for Windows privileged TUN helper")?;
            if exit_code == 0 {
                Ok(())
            } else {
                bail!("Windows privileged TUN helper exited with code {exit_code}");
            }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn monitor_privileged_helper(mut stream: TcpStream, platform: &str) -> Result<()> {
    let mut buffer = [0u8; 1];
    loop {
        if stream.read(&mut buffer).await.with_context(|| {
            format!("failed to read {platform} privileged TUN helper control connection")
        })? == 0
        {
            bail!("{platform} privileged TUN helper stopped");
        }
    }
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
    argv: &[String],
    mtu: u16,
    control_addr: SocketAddr,
    token_file: &Path,
) -> Result<WindowsHelperProcess> {
    let exe = std::env::current_exe().context("failed to locate current executable")?;
    let exe = wide_null(&exe.display().to_string());
    let verb = wide_null("runas");
    let parameters = wide_null(&windows_helper_parameters(
        argv,
        mtu,
        control_addr,
        token_file,
    ));
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
fn windows_helper_parameters(
    argv: &[String],
    mtu: u16,
    control_addr: SocketAddr,
    token_file: &Path,
) -> String {
    let mut command = vec![
        "internal-tun-helper".to_string(),
        "--control".to_string(),
        control_addr.to_string(),
        "--token-file".to_string(),
        token_file.display().to_string(),
        "--mtu".to_string(),
        mtu.to_string(),
        "--".to_string(),
    ];
    command.extend(argv.iter().cloned());
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
fn macos_privileged_helper_script(
    argv: &[String],
    mtu: u16,
    control_addr: SocketAddr,
    token_file: &Path,
) -> Result<String> {
    let exe = std::env::current_exe().context("failed to locate current executable")?;
    let mut command = vec![
        exe.display().to_string(),
        "internal-tun-helper".to_string(),
        "--control".to_string(),
        control_addr.to_string(),
        "--token-file".to_string(),
        token_file.display().to_string(),
        "--mtu".to_string(),
        mtu.to_string(),
        "--".to_string(),
    ];
    command.extend(argv.iter().cloned());
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
    fn windows_helper_parameters_quote_tun_arguments() {
        let params = windows_helper_parameters(
            &[
                "tun2proxy".to_string(),
                "--proxy".to_string(),
                "socks5://127.0.0.1:1080".to_string(),
                "--bypass".to_string(),
                "C:\\Program Files\\Proxy Rules".to_string(),
                "--tun".to_string(),
                "Tabby \"Mew\"".to_string(),
            ],
            1500,
            "127.0.0.1:12345".parse().unwrap(),
            Path::new("C:\\Temp\\helper-auth.txt"),
        );

        assert!(params.starts_with("internal-tun-helper --control 127.0.0.1:12345"));
        assert!(params.contains("--token-file C:\\Temp\\helper-auth.txt"));
        assert!(!params.contains("--token "));
        assert!(params.contains("--mtu 1500 -- tun2proxy"));
        assert!(params.contains("\"C:\\Program Files\\Proxy Rules\""));
        assert!(params.contains("\"Tabby \\\"Mew\\\"\""));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_privileged_helper_script_quotes_shell_and_applescript() {
        assert_eq!(
            shell_quote("quote'and\"slash\\"),
            "'quote'\\''and\"slash\\'"
        );
        assert_eq!(applescript_string("a\"b\\c"), "\"a\\\"b\\\\c\"");

        let script = macos_privileged_helper_script(
            &[
                "tun2proxy".to_string(),
                "--proxy".to_string(),
                "socks5://127.0.0.1:1080".to_string(),
                "--bypass".to_string(),
                "quote'and\"slash\\".to_string(),
            ],
            1500,
            "127.0.0.1:12345".parse().unwrap(),
            Path::new("/tmp/helper-auth.txt"),
        )
        .unwrap();

        assert!(script.contains("with administrator privileges"));
        assert!(script.contains("--token-file"));
        assert!(!script.contains("--token "));
        assert!(script.contains("quote"));
        assert!(script.contains("slash"));
        assert!(script.contains("internal-tun-helper"));
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
