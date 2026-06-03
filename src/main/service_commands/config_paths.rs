use super::*;

pub(super) fn resolve_control_listen(
    config_path: &Path,
    listen: Option<String>,
    state_dir: Option<PathBuf>,
) -> Result<std::net::SocketAddr> {
    let listen = match listen {
        Some(listen) => listen,
        None => control_listen_from_config(config_path)?
            .or_else(|| control_listen_from_state(state_dir))
            .unwrap_or_else(|| control::DEFAULT_CONTROL_LISTEN.to_string()),
    };
    control::parse_listen(&listen).context("invalid control API listen address")
}

pub(super) fn resolve_config_path(config: Option<&PathBuf>) -> Result<PathBuf> {
    match config {
        Some(path) => Ok(path.clone()),
        None => ensure_default_config(),
    }
}

pub(super) fn resolve_launch_config_path(config: Option<&PathBuf>, state_dir: &Path) -> Result<PathBuf> {
    resolve_launch_config_path_with_fallback(config, state_dir, ensure_default_config)
}

pub(super) fn resolve_launch_config_path_with_fallback(
    config: Option<&PathBuf>,
    state_dir: &Path,
    fallback: impl Fn() -> Result<PathBuf>,
) -> Result<PathBuf> {
    if let Some(path) = config {
        return Ok(path.clone());
    }
    let preferences_path = process_manager::preferences_path(state_dir);
    let preferences = match process_manager::load_preferences(&preferences_path) {
        Ok(preferences) => preferences,
        Err(err) => {
            eprintln!(
                "warning: failed to load runtime preferences {}; using default config: {err:#}",
                preferences_path.display()
            );
            return fallback();
        }
    };
    if let Some(active_config) = preferences
        .active_config
        .filter(|active_config| active_config.exists())
    {
        return Ok(active_config);
    }
    fallback()
}

pub(super) fn ensure_default_config() -> Result<PathBuf> {
    let path = process_manager::default_config_path();
    if path.exists() {
        return Ok(path);
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs_security::create_private_dir_all(parent)
            .with_context(|| format!("failed to create config dir {}", parent.display()))?;
    }
    let text = Config::default_local_json()?;
    fs_security::write_private_file(&path, format!("{text}\n"))
        .with_context(|| format!("failed to write default config {}", path.display()))?;
    Ok(path)
}

pub(super) fn control_listen_from_config(config_path: &Path) -> Result<Option<String>> {
    Ok(Config::load(config_path)
        .with_context(|| {
            format!(
                "failed to load config {} for control API listen; pass --listen",
                config_path.display()
            )
        })?
        .services
        .and_then(|services| services.control_api)
        .map(|control_api| control_api.listen))
}

pub(super) fn control_listen_from_state(state_dir: Option<PathBuf>) -> Option<String> {
    let state_dir = state_dir.unwrap_or_else(process_manager::default_state_dir);
    let paths = process_manager::paths(state_dir, None);
    let state = process_manager::load_state(&paths.state_file).ok()?;
    if process_manager::is_process_running(state.pid) {
        state.listen
    } else {
        None
    }
}

#[derive(Debug)]
pub(super) struct RunPaths {
    pub(super) state_file: Option<PathBuf>,
    pub(super) state_dir: PathBuf,
    pub(super) log_file: Option<PathBuf>,
}

pub(super) fn resolve_run_paths(
    default_state_dir: PathBuf,
    state_file: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    log_file: Option<PathBuf>,
) -> Result<RunPaths> {
    let state_dir = state_dir
        .or_else(|| {
            state_file
                .as_ref()
                .and_then(|path| path.parent().map(Path::to_path_buf))
        })
        .unwrap_or(default_state_dir);
    let log_file = match log_file {
        Some(path) => Some(path),
        None => Some(process_manager::new_session_log_file(&state_dir)?),
    };
    Ok(RunPaths {
        state_file,
        state_dir,
        log_file,
    })
}

pub(super) fn timeout_duration(timeout_ms: u64) -> Result<Duration> {
    named_duration("timeout-ms", timeout_ms)
}

pub(super) fn named_duration(name: &str, value_ms: u64) -> Result<Duration> {
    if value_ms == 0 {
        bail!("{name} must be greater than 0");
    }
    Ok(Duration::from_millis(value_ms))
}

pub(super) fn validate_runtime_config(config: &Config, config_base_dir: Option<&Path>) -> Result<()> {
    config
        .validate()
        .context("configuration validation failed")?;
    outbound::validate_configs(&config.outbounds).context("outbound validation failed")?;
    build_router(config, config_base_dir).context("router validation failed")?;
    inbound::validate_configs(&config.inbounds).context("inbound validation failed")?;
    Ok(())
}

pub(super) fn build_router(config: &Config, config_base_dir: Option<&Path>) -> Result<router::Router> {
    match (config.dns.as_ref(), config_base_dir) {
        (Some(dns), Some(config_base_dir)) => {
            router::Router::from_config_with_policy_groups_dns_in_dir(
                &config.outbounds,
                &config.policy_groups,
                &config.route,
                Some(dns),
                Some(config_base_dir),
            )
        }
        (Some(dns), None) => router::Router::from_config_with_policy_groups_dns(
            &config.outbounds,
            &config.policy_groups,
            &config.route,
            Some(dns),
        ),
        (None, Some(config_base_dir)) => router::Router::from_config_with_policy_groups_dns_in_dir(
            &config.outbounds,
            &config.policy_groups,
            &config.route,
            None,
            Some(config_base_dir),
        ),
        (None, None) => router::Router::from_config_with_policy_groups(
            &config.outbounds,
            &config.policy_groups,
            &config.route,
        ),
    }
}

pub(super) fn config_base_dir(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

pub(super) fn print_check_report(path: &Path, config: &Config) {
    println!("configuration ok: {}", path.display());
    println!("validation: config references ok, outbounds ok, router ok, inbounds ok");
    for line in config.summary().lines() {
        println!("  {line}");
    }
}
