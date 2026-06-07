use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use tokio::{signal, sync::Notify, task::JoinSet, time};
use tracing::{error, info, warn};

use crate::{
    config::Config,
    control::{self, ControlApiState, ControlState, RuntimeMetrics},
    platform, process_manager,
    proxy_runtime::{ProxyRuntime, ProxyRuntimeSnapshot, TunRuntimeStatus},
    resource_limits,
    router::{RouteMode, Router},
    subscription_remote::{self, SubscriptionRuntime},
    system_proxy,
};

const RUNTIME_STATE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const TUN_WATCHDOG_INTERVAL: Duration = Duration::from_secs(15);
const TUN_WATCHDOG_RESUME_GAP: Duration = Duration::from_secs(120);
const TUN_WATCHDOG_RECOVERY_COOLDOWN: Duration = Duration::from_secs(60);
const TUN_WATCHDOG_FAST_RECOVERY_COOLDOWN: Duration = TUN_WATCHDOG_INTERVAL;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TunWatchdogRecoveryAttempt {
    at: u64,
    cooldown: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub config_path: Option<PathBuf>,
    pub control_listen: Option<String>,
    pub log_file: Option<PathBuf>,
    pub state_file: Option<PathBuf>,
    pub state_dir: PathBuf,
}

pub async fn run(
    config: Config,
    config_base_dir: Option<PathBuf>,
    options: RunOptions,
) -> Result<()> {
    let config = control::apply_custom_route_rules_from_state_dir(
        &config,
        options.config_path.as_deref(),
        &options.state_dir,
    )?;
    let summary = config.summary();
    info!(
        state_dir = %options.state_dir.display(),
        config = %options
            .config_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string()),
        log_file = %options
            .log_file
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string()),
        state_file = %options
            .state_file
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string()),
        inbounds = config.inbounds.len(),
        outbounds = config.outbounds.len(),
        policy_groups = config.policy_groups.len(),
        "runtime starting"
    );
    let metrics = Arc::new(RuntimeMetrics::new());
    let shutdown = Arc::new(Notify::new());

    raise_runtime_resource_limits();

    let router = build_router(&config, config_base_dir.as_deref(), metrics.clone())?;
    apply_saved_routing_preferences(&options, &router);
    let proxy_runtime = Arc::new(ProxyRuntime::new_with_outbounds(
        config.inbounds.clone(),
        router.clone(),
        &config.outbounds,
    ));
    apply_saved_proxy_preferences(&options, &proxy_runtime).await;
    let subscription_runtime = SubscriptionRuntime::new(&options.state_dir);
    let mut tasks = JoinSet::new();

    let control_endpoint = spawn_control_api(
        &mut tasks,
        ControlApiContext {
            runtime_config: &config,
            summary: summary.clone(),
            metrics: metrics.clone(),
            router: router.clone(),
            proxy_runtime: proxy_runtime.clone(),
            shutdown: shutdown.clone(),
            options: &options,
            subscription_runtime: subscription_runtime.clone(),
        },
    )
    .await?;
    spawn_runtime_state_heartbeat(&mut tasks, &options, shutdown.clone());
    spawn_subscription_auto_update(&mut tasks, subscription_runtime, shutdown.clone());
    spawn_tun_watchdog(&mut tasks, proxy_runtime.clone(), shutdown.clone());

    let proxy_snapshot = proxy_runtime.snapshot().await;
    if proxy_snapshot.configured_inbounds > 0 {
        proxy_runtime.start().await?;
    }

    write_runtime_state(&control_endpoint, &options);
    info!(
        control_api = %control_endpoint.addr,
        proxy_inbounds = proxy_snapshot.configured_inbounds,
        "runtime ready"
    );

    let result = tokio::select! {
        result = tasks.join_next() => {
            match result {
                Some(Ok(Ok(()))) => Ok(()),
                Some(Ok(Err(err))) => {
                    error!(error = %err, "runtime task stopped");
                    Err(err)
                }
                Some(Err(err)) => Err(err).context("runtime task panicked"),
                None => Ok(()),
            }
        }
        _ = shutdown.notified() => {
            info!("shutdown requested from control API");
            Ok(())
        }
        result = shutdown_signal() => {
            let reason = result?;
            info!(reason, "shutdown requested");
            Ok(())
        }
    };

    info!("runtime cleanup started");
    cleanup_system_proxy(&options, &summary.inbounds);

    match proxy_runtime.stop_all().await {
        Ok(snapshot) => info!(
            enabled = snapshot.enabled,
            tun_enabled = snapshot.tun_enabled,
            lan_enabled = snapshot.lan_enabled,
            "proxy listeners stopped"
        ),
        Err(err) => warn!(error = %err, "failed to stop proxy listeners"),
    }
    crate::inbound::tun::shutdown_privileged_helper_session().await;
    system_proxy::clear_session_authorization();
    info!("cleared session authorization cache");

    remove_runtime_state_for_current_process(&options);
    info!("runtime cleanup completed");

    result
}

fn remove_runtime_state_for_current_process(options: &RunOptions) {
    let state_file = runtime_state_file(options);
    let pid = std::process::id();
    match process_manager::load_state(&state_file) {
        Ok(state) if state.pid != pid => {
            warn!(
                state_file = %state_file.display(),
                recorded_pid = state.pid,
                pid,
                "kept process state owned by a different runtime"
            );
        }
        Ok(_) => match process_manager::remove_state_file(&state_file) {
            Ok(()) => info!(state_file = %state_file.display(), "removed process state"),
            Err(err) => warn!(
                state_file = %state_file.display(),
                error = %err,
                "failed to remove process state"
            ),
        },
        Err(err) if state_file.exists() => warn!(
            state_file = %state_file.display(),
            error = %err,
            "failed to inspect process state before cleanup"
        ),
        Err(_) => {}
    }
}

fn spawn_runtime_state_heartbeat(
    tasks: &mut JoinSet<Result<()>>,
    options: &RunOptions,
    shutdown: Arc<Notify>,
) {
    let options = options.clone();
    tasks.spawn(async move {
        run_runtime_state_heartbeat(options, shutdown).await;
        Ok(())
    });
}

fn spawn_tun_watchdog(
    tasks: &mut JoinSet<Result<()>>,
    proxy_runtime: Arc<ProxyRuntime>,
    shutdown: Arc<Notify>,
) {
    tasks.spawn(async move {
        run_tun_watchdog(proxy_runtime, shutdown).await;
        Ok(())
    });
}

async fn run_tun_watchdog(proxy_runtime: Arc<ProxyRuntime>, shutdown: Arc<Notify>) {
    let mut interval = time::interval(TUN_WATCHDOG_INTERVAL);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let mut last_tick = unix_now();
    let mut last_recovery_attempt: Option<TunWatchdogRecoveryAttempt> = None;
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                return;
            }
            _ = interval.tick() => {
                let now = unix_now();
                let elapsed = now.saturating_sub(last_tick);
                last_tick = now;

                let snapshot = proxy_runtime.snapshot().await;
                let Some(reason) = tun_watchdog_recovery_reason(&snapshot, elapsed) else {
                    continue;
                };
                if !should_attempt_tun_watchdog_recovery(last_recovery_attempt, now) {
                    let cooldown = last_recovery_attempt
                        .map(|attempt| attempt.cooldown)
                        .unwrap_or(TUN_WATCHDOG_RECOVERY_COOLDOWN);
                    warn!(
                        reason = %reason,
                        elapsed_seconds = elapsed,
                        cooldown_seconds = cooldown.as_secs(),
                        "skipped TUN recovery condition during cooldown"
                    );
                    continue;
                }

                warn!(
                    reason = %reason,
                    elapsed_seconds = elapsed,
                    desired_enabled = snapshot.tun_desired_enabled,
                    enabled = snapshot.tun_enabled,
                    tun_status = ?snapshot.tun_status,
                    egress_interface = snapshot.tun_egress_interface.as_deref().unwrap_or("-"),
                    bound_interface = snapshot.tun_bound_interface.as_deref().unwrap_or("-"),
                    "detected TUN recovery condition"
                );
                let recovery = proxy_runtime.restart_tun_for_recovery(reason).await;
                let cooldown = match recovery.as_ref() {
                    Ok(_) => TUN_WATCHDOG_RECOVERY_COOLDOWN,
                    Err(err) => tun_watchdog_recovery_cooldown_for_error(err),
                };
                last_recovery_attempt = Some(TunWatchdogRecoveryAttempt { at: now, cooldown });
                if let Err(err) = recovery {
                    warn!(
                        elapsed_seconds = elapsed,
                        retry_cooldown_seconds = cooldown.as_secs(),
                        error = %err,
                        "failed to recover TUN after runtime timer gap"
                    );
                }
            }
        }
    }
}

fn tun_watchdog_recovery_reason(
    snapshot: &ProxyRuntimeSnapshot,
    elapsed_seconds: u64,
) -> Option<String> {
    if snapshot.tun_desired_enabled && !snapshot.tun_enabled {
        return Some("TUN listener stopped unexpectedly while desired on".to_string());
    }
    if !(snapshot.tun_enabled && snapshot.tun_auto_route) {
        return None;
    }
    if should_restart_tun_after_watchdog_gap(elapsed_seconds) {
        return Some(format!(
            "runtime timer gap after sleep/wake ({elapsed_seconds}s)"
        ));
    }
    if snapshot.tun_status != TunRuntimeStatus::Running {
        return Some(format!(
            "TUN enabled but runtime status is {:?}",
            snapshot.tun_status
        ));
    }
    tun_egress_binding_recovery_reason(snapshot)
}

fn tun_egress_binding_recovery_reason(snapshot: &ProxyRuntimeSnapshot) -> Option<String> {
    if !platform::tun_egress_binding_supported_for_name(snapshot.tun_platform) {
        return None;
    }
    let Some(expected) = snapshot.tun_egress_interface.as_deref() else {
        return Some("TUN auto route is missing a captured egress interface".to_string());
    };
    match snapshot.tun_bound_interface.as_deref() {
        Some(bound) if bound == expected => None,
        Some(bound) => Some(format!(
            "TUN egress binding drifted from {expected} to {bound}"
        )),
        None => Some(format!("TUN egress binding for {expected} is missing")),
    }
}

fn should_restart_tun_after_watchdog_gap(elapsed_seconds: u64) -> bool {
    elapsed_seconds >= TUN_WATCHDOG_RESUME_GAP.as_secs()
}

fn should_attempt_tun_watchdog_recovery(
    last_attempt: Option<TunWatchdogRecoveryAttempt>,
    now: u64,
) -> bool {
    last_attempt.is_none_or(|last_attempt| {
        now.saturating_sub(last_attempt.at) >= last_attempt.cooldown.as_secs()
    })
}

fn tun_watchdog_recovery_cooldown_for_error(err: &anyhow::Error) -> Duration {
    if is_fd_exhaustion_error_message(&format!("{err:#}")) {
        TUN_WATCHDOG_FAST_RECOVERY_COOLDOWN
    } else {
        TUN_WATCHDOG_RECOVERY_COOLDOWN
    }
}

fn is_fd_exhaustion_error_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("too many open files")
        || message.contains("os error 24")
        || message.contains("os error 23")
        || message.contains("emfile")
        || message.contains("enfile")
}

async fn run_runtime_state_heartbeat(options: RunOptions, shutdown: Arc<Notify>) {
    let state_file = runtime_state_file(&options);
    let pid = std::process::id();
    let mut interval = time::interval(RUNTIME_STATE_HEARTBEAT_INTERVAL);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                return;
            }
            _ = interval.tick() => {
                match process_manager::touch_state_heartbeat(&state_file, pid, unix_now()) {
                    Ok(true) => {}
                    Ok(false) => {
                        warn!(
                            state_file = %state_file.display(),
                            pid,
                            "skipped runtime state heartbeat because state is owned by another process"
                        );
                    }
                    Err(err) if state_file.exists() => {
                        warn!(
                            state_file = %state_file.display(),
                            error = %err,
                            "failed to update runtime state heartbeat"
                        );
                    }
                    Err(_) => {}
                }
            }
        }
    }
}

fn cleanup_system_proxy(options: &RunOptions, inbounds: &[String]) {
    let Some((target, target_recorded)) = system_proxy_cleanup_target(options, inbounds) else {
        info!("skipped system proxy cleanup; no recorded target or local proxy target");
        return;
    };

    if target_recorded {
        if disable_system_proxy_cleanup_target(&target, true) {
            clear_managed_system_proxy_preference(options);
        }
        return;
    }

    info!("checking unrecorded system proxy cleanup candidate");
    disable_system_proxy_cleanup_target(&target, false);
}

fn system_proxy_cleanup_target(
    options: &RunOptions,
    inbounds: &[String],
) -> Option<(system_proxy::SystemProxyTarget, bool)> {
    recorded_managed_system_proxy_target(options)
        .map(|target| (target, true))
        .or_else(|| system_proxy::target_from_inbounds(inbounds).map(|target| (target, false)))
}

fn disable_system_proxy_cleanup_target(
    target: &system_proxy::SystemProxyTarget,
    target_recorded: bool,
) -> bool {
    match system_proxy::disable_target_without_prompt(Some(target)) {
        Ok(status) => {
            info!(
                target_recorded,
                supported = status.supported,
                enabled = status.enabled,
                managed = status.managed,
                matches_target = status.matches_target,
                "checked system proxy cleanup"
            );
            true
        }
        Err(err) => {
            warn!(
                target_recorded,
                error = %err,
                "failed to disable system proxy without prompting"
            );
            false
        }
    }
}

fn recorded_managed_system_proxy_target(
    options: &RunOptions,
) -> Option<system_proxy::SystemProxyTarget> {
    let preferences_path = process_manager::preferences_path(&options.state_dir);
    match process_manager::load_preferences(&preferences_path) {
        Ok(preferences) => preferences.system_proxy_target,
        Err(err) => {
            warn!(
                preferences = %preferences_path.display(),
                error = %err,
                "failed to load system proxy preference"
            );
            None
        }
    }
}

fn clear_managed_system_proxy_preference(options: &RunOptions) {
    let preferences_path = process_manager::preferences_path(&options.state_dir);
    match process_manager::update_preferences(&preferences_path, |preferences| {
        preferences.system_proxy_target = None;
    }) {
        Ok(_) => info!(
            preferences = %preferences_path.display(),
            "cleared managed system proxy preference"
        ),
        Err(err) => warn!(
            preferences = %preferences_path.display(),
            error = %err,
            "failed to clear system proxy preference"
        ),
    }
}

fn raise_runtime_resource_limits() {
    match resource_limits::raise_nofile_soft_limit(resource_limits::DEFAULT_NOFILE_SOFT_LIMIT) {
        Ok(Some(limit)) => {
            let snapshot = resource_limits::nofile_limit_snapshot().ok();
            info!(
                previous_soft = %limit.previous_soft,
                soft = snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.soft.as_str())
                    .unwrap_or(limit.soft.as_str()),
                hard = snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.hard.as_str())
                    .unwrap_or(limit.hard.as_str()),
                open_files = ?snapshot.as_ref().and_then(|snapshot| snapshot.open_files),
                "raised file descriptor limit"
            );
        }
        Ok(None) => {
            let snapshot = resource_limits::nofile_limit_snapshot().ok();
            info!(
                soft = snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.soft.as_str())
                    .unwrap_or("-"),
                hard = snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.hard.as_str())
                    .unwrap_or("-"),
                open_files = ?snapshot.as_ref().and_then(|snapshot| snapshot.open_files),
                "file descriptor limit ready"
            );
        }
        Err(err) => {
            let snapshot = resource_limits::nofile_limit_snapshot().ok();
            warn!(
                error = %err,
                soft = snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.soft.as_str())
                    .unwrap_or("-"),
                hard = snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.hard.as_str())
                    .unwrap_or("-"),
                open_files = ?snapshot.as_ref().and_then(|snapshot| snapshot.open_files),
                "failed to raise file descriptor limit"
            );
        }
    }
}

async fn shutdown_signal() -> Result<&'static str> {
    #[cfg(unix)]
    {
        let mut terminate = signal::unix::signal(signal::unix::SignalKind::terminate())
            .context("failed to install SIGTERM handler")?;
        tokio::select! {
            result = signal::ctrl_c() => {
                result.context("failed to wait for ctrl-c")?;
                Ok("ctrl-c")
            }
            _ = terminate.recv() => Ok("sigterm"),
        }
    }

    #[cfg(not(unix))]
    {
        signal::ctrl_c()
            .await
            .context("failed to wait for ctrl-c")?;
        Ok("ctrl-c")
    }
}

fn build_router(
    config: &Config,
    config_base_dir: Option<&Path>,
    metrics: Arc<RuntimeMetrics>,
) -> Result<Router> {
    if let Some(dns) = config.dns.as_ref() {
        Router::from_config_with_policy_groups_dns_in_dir_and_metrics(
            &config.outbounds,
            &config.policy_groups,
            &config.route,
            Some(dns),
            config_base_dir,
            Some(metrics),
        )
    } else {
        Router::from_config_with_policy_groups_dns_in_dir_and_metrics(
            &config.outbounds,
            &config.policy_groups,
            &config.route,
            None,
            config_base_dir,
            Some(metrics),
        )
    }
}

fn apply_saved_routing_preferences(options: &RunOptions, router: &Router) {
    let preferences_path = process_manager::preferences_path(&options.state_dir);
    let preferences = match process_manager::load_preferences(&preferences_path) {
        Ok(preferences) => preferences,
        Err(err) => {
            warn!(
                preferences = %preferences_path.display(),
                error = %err,
                "failed to load runtime preferences"
            );
            return;
        }
    };
    let mode = preferences.route_mode.as_deref().and_then(RouteMode::parse);
    let warnings = router.runtime().apply_preferences(
        mode,
        preferences.global_outbound.as_deref(),
        &preferences.policy_group_selections,
    );
    for warning in warnings {
        warn!(preferences = %preferences_path.display(), warning = %warning, "ignored runtime preference");
    }
}

async fn apply_saved_proxy_preferences(options: &RunOptions, proxy_runtime: &ProxyRuntime) {
    let preferences_path = process_manager::preferences_path(&options.state_dir);
    let preferences = match process_manager::load_preferences(&preferences_path) {
        Ok(preferences) => preferences,
        Err(err) => {
            warn!(
                preferences = %preferences_path.display(),
                error = %err,
                "failed to load proxy preferences"
            );
            return;
        }
    };
    if let Err(err) = proxy_runtime
        .set_lan_enabled(preferences.lan_proxy_enabled)
        .await
    {
        warn!(
            preferences = %preferences_path.display(),
            error = %err,
            "failed to apply proxy preferences"
        );
    }
}

struct ControlApiContext<'a> {
    runtime_config: &'a Config,
    summary: crate::config::ConfigSummary,
    metrics: Arc<RuntimeMetrics>,
    router: Router,
    proxy_runtime: Arc<ProxyRuntime>,
    shutdown: Arc<Notify>,
    options: &'a RunOptions,
    subscription_runtime: SubscriptionRuntime,
}

struct ControlApiEndpoint {
    addr: SocketAddr,
    control_token: String,
}

async fn spawn_control_api(
    tasks: &mut JoinSet<Result<()>>,
    context: ControlApiContext<'_>,
) -> Result<ControlApiEndpoint> {
    let control_api = context
        .runtime_config
        .services
        .as_ref()
        .and_then(|services| services.control_api.clone());
    let listener = match control_api {
        Some(config) => control::bind(&config.listen).await?,
        None => match context.options.control_listen.as_deref() {
            Some(listen) => control::bind(listen).await?,
            None => control::bind_default_control().await?,
        },
    };
    let addr = listener
        .local_addr()
        .context("failed to read control API listener address")?;
    let mut control_api = ControlApiState::new();
    let control_token = control_api.token.clone();
    control_api.config_path = context.options.config_path.clone();
    control_api.log_file = context.options.log_file.clone();
    control_api.state_file = context.options.state_file.clone();
    control_api.state_dir = Some(context.options.state_dir.clone());
    let state = ControlState::with_control_api_runtime(
        context.summary,
        context.metrics,
        control_api,
        context.router,
        context.proxy_runtime,
        context.shutdown,
        context.subscription_runtime,
    );
    tasks.spawn(async move { control::serve_listener(listener, state).await });
    Ok(ControlApiEndpoint {
        addr,
        control_token,
    })
}

fn spawn_subscription_auto_update(
    tasks: &mut JoinSet<Result<()>>,
    runtime: SubscriptionRuntime,
    shutdown: Arc<Notify>,
) {
    tasks.spawn(async move {
        subscription_remote::run_auto_update_loop(runtime, shutdown).await;
        Ok(())
    });
}

fn write_runtime_state(endpoint: &ControlApiEndpoint, options: &RunOptions) {
    let state_file = runtime_state_file(options);
    let pid = std::process::id();
    if let Ok(existing) = process_manager::load_state(&state_file)
        && existing.pid != pid
        && process_manager::is_process_running(existing.pid)
    {
        warn!(
            state_file = %state_file.display(),
            existing_pid = existing.pid,
            pid,
            "refusing to replace live process state"
        );
        return;
    }
    let now = unix_now();
    let state = process_manager::ProcessState {
        pid,
        config: options.config_path.clone().unwrap_or_default(),
        log: options.log_file.clone().unwrap_or_default(),
        listen: Some(endpoint.addr.to_string()),
        control_token: Some(endpoint.control_token.clone()),
        started_at_unix: now,
        heartbeat_at_unix: Some(now),
    };
    if let Err(err) = process_manager::save_state_file(&state_file, &state) {
        warn!(state_file = %state_file.display(), error = %err, "failed to write process state");
    }
}

fn runtime_state_file(options: &RunOptions) -> PathBuf {
    options
        .state_file
        .clone()
        .unwrap_or_else(|| process_manager::runtime_state_file(&options.state_dir))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_run_options(state_dir: PathBuf) -> RunOptions {
        RunOptions {
            config_path: None,
            control_listen: None,
            log_file: None,
            state_file: None,
            state_dir,
        }
    }

    fn test_system_proxy_target() -> system_proxy::SystemProxyTarget {
        system_proxy::SystemProxyTarget {
            source: "http".to_string(),
            http: Some(system_proxy::SystemProxyEndpoint {
                host: "127.0.0.1".to_string(),
                port: 60056,
                address: "127.0.0.1:60056".to_string(),
            }),
            https: None,
            socks: None,
        }
    }

    #[test]
    fn runtime_cleanup_target_prefers_recorded_system_proxy_target() -> Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "tabbymew-app-cleanup-target-test-{}",
            std::process::id()
        ));
        let options = test_run_options(dir.clone());

        assert!(recorded_managed_system_proxy_target(&options).is_none());

        let target = test_system_proxy_target();
        process_manager::save_preferences(
            process_manager::preferences_path(&dir),
            &process_manager::RuntimePreferences {
                system_proxy_target: Some(target.clone()),
                ..process_manager::RuntimePreferences::default()
            },
        )?;

        assert_eq!(recorded_managed_system_proxy_target(&options), Some(target));
        let selected = system_proxy_cleanup_target(
            &options,
            &["hybrid:hybrid-in@127.0.0.1:17890 auth=off".to_string()],
        );
        assert_eq!(selected, Some((test_system_proxy_target(), true)));

        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn runtime_cleanup_uses_unrecorded_local_proxy_target() -> Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "tabbymew-app-cleanup-unrecorded-target-test-{}",
            std::process::id()
        ));
        let options = test_run_options(dir.clone());

        let selected = system_proxy_cleanup_target(
            &options,
            &["hybrid:hybrid-in@127.0.0.1:17890 auth=off".to_string()],
        );

        let (target, target_recorded) = selected.context("expected local proxy target")?;
        assert!(!target_recorded);
        assert_eq!(target.source, "hybrid:hybrid-in@127.0.0.1:17890 auth=off");
        assert_eq!(
            target
                .http
                .as_ref()
                .map(|endpoint| endpoint.address.as_str()),
            Some("127.0.0.1:17890")
        );
        assert_eq!(
            target
                .socks
                .as_ref()
                .map(|endpoint| endpoint.address.as_str()),
            Some("127.0.0.1:17890")
        );

        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn tun_watchdog_restart_threshold_requires_resume_sized_gap() {
        assert!(!should_restart_tun_after_watchdog_gap(119));
        assert!(should_restart_tun_after_watchdog_gap(120));
    }

    #[test]
    fn tun_watchdog_reports_recovery_reasons() {
        for case in [
            (
                test_tun_snapshot(
                    true,
                    false,
                    true,
                    TunRuntimeStatus::Failed,
                    Some("en0"),
                    Some("en0"),
                ),
                15,
                "desired on",
            ),
            (
                test_tun_snapshot(
                    true,
                    true,
                    true,
                    TunRuntimeStatus::Running,
                    Some("en0"),
                    Some("en0"),
                ),
                180,
                "sleep/wake",
            ),
            (
                test_tun_snapshot(
                    true,
                    true,
                    true,
                    TunRuntimeStatus::Running,
                    Some("en0"),
                    Some("en7"),
                ),
                15,
                "drifted",
            ),
        ] {
            let (snapshot, elapsed_seconds, expected_reason) = case;
            assert!(
                tun_watchdog_recovery_reason(&snapshot, elapsed_seconds)
                    .unwrap()
                    .contains(expected_reason)
            );
        }
    }

    #[test]
    fn tun_watchdog_recovery_attempts_are_rate_limited() {
        assert!(should_attempt_tun_watchdog_recovery(None, 100));
        assert!(!should_attempt_tun_watchdog_recovery(
            Some(TunWatchdogRecoveryAttempt {
                at: 100,
                cooldown: TUN_WATCHDOG_RECOVERY_COOLDOWN,
            }),
            130,
        ));
        assert!(should_attempt_tun_watchdog_recovery(
            Some(TunWatchdogRecoveryAttempt {
                at: 100,
                cooldown: TUN_WATCHDOG_RECOVERY_COOLDOWN,
            }),
            160,
        ));
    }

    #[test]
    fn tun_watchdog_fd_exhaustion_uses_fast_retry_cooldown() {
        let err = anyhow::anyhow!(
            "failed to start TUN listeners: tun2proxy failed: Too many open files (os error 24)"
        );
        assert_eq!(
            tun_watchdog_recovery_cooldown_for_error(&err),
            TUN_WATCHDOG_FAST_RECOVERY_COOLDOWN
        );
        assert!(should_attempt_tun_watchdog_recovery(
            Some(TunWatchdogRecoveryAttempt {
                at: 100,
                cooldown: TUN_WATCHDOG_FAST_RECOVERY_COOLDOWN,
            }),
            115,
        ));

        let err = anyhow::anyhow!("failed to capture current network interface");
        assert_eq!(
            tun_watchdog_recovery_cooldown_for_error(&err),
            TUN_WATCHDOG_RECOVERY_COOLDOWN
        );
    }

    fn test_tun_snapshot(
        desired_enabled: bool,
        enabled: bool,
        auto_route: bool,
        status: TunRuntimeStatus,
        egress_interface: Option<&str>,
        bound_interface: Option<&str>,
    ) -> ProxyRuntimeSnapshot {
        ProxyRuntimeSnapshot {
            enabled: true,
            tun_desired_enabled: desired_enabled,
            tun_enabled: enabled,
            tun_status: status,
            tun_supported: true,
            tun_requires_privilege: true,
            tun_privilege_verified: Some(true),
            tun_platform: "macos",
            tun_detail: "test".to_string(),
            tun_warnings: Vec::new(),
            tun_auto_route: auto_route,
            tun_ipv6_enabled: false,
            tun_dns_mode: Some("virtual".to_string()),
            tun_dns_addr: None,
            tun_configured_bypass_count: 1,
            tun_proxy_bypass_sources: 1,
            tun_egress_interface: egress_interface.map(str::to_string),
            tun_bound_interface: bound_interface.map(str::to_string),
            tun_watchdog_restarts: 0,
            tun_last_watchdog_reason: None,
            lan_enabled: false,
            local_listeners: Vec::new(),
            lan_listeners: Vec::new(),
            effective_listeners: Vec::new(),
            configured_inbounds: 1,
            configured_tun_inbounds: 1,
            last_error: None,
        }
    }
}
