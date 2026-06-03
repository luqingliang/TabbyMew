use std::{
    env, fs,
    net::TcpListener,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};

use crate::platform;

use super::{
    DEFAULT_CONFIG_FILE, DEFAULT_LOG_DIR, DEFAULT_LOG_FILE, PREFERENCES_FILE, ProcessPaths,
    RUNTIME_STATE_FILE, STATE_FILE,
};

pub fn default_state_dir() -> PathBuf {
    if let Some(state_dir) = env::var_os("TABBYMEW_STATE_DIR") {
        return PathBuf::from(state_dir);
    }
    platform::default_state_dir().unwrap_or_else(|| PathBuf::from(".tabbymew"))
}

pub fn default_config_path() -> PathBuf {
    default_state_dir().join(DEFAULT_CONFIG_FILE)
}

pub fn paths(state_dir: impl AsRef<Path>, log: Option<&Path>) -> ProcessPaths {
    let state_dir = state_dir.as_ref().to_path_buf();
    let state_file = state_dir.join(STATE_FILE);
    let log_file = log
        .map(Path::to_path_buf)
        .unwrap_or_else(|| state_dir.join(DEFAULT_LOG_DIR).join(DEFAULT_LOG_FILE));
    ProcessPaths {
        state_dir,
        state_file,
        log_file,
    }
}

pub fn preferences_path(state_dir: impl AsRef<Path>) -> PathBuf {
    state_dir.as_ref().join(PREFERENCES_FILE)
}

pub fn runtime_state_file(state_dir: impl AsRef<Path>) -> PathBuf {
    state_dir.as_ref().join(RUNTIME_STATE_FILE)
}

pub(super) fn absolute_existing_path(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path).with_context(|| format!("failed to canonicalize {}", path.display()))
}

pub(super) fn absolute_output_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()
            .context("failed to read current directory")?
            .join(path))
    }
}

pub(super) fn allocate_loopback_listen() -> Result<String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .context("failed to reserve a loopback control API listen address")?;
    Ok(listener
        .local_addr()
        .context("failed to read reserved control API listen address")?
        .to_string())
}

pub(super) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn unix_now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
