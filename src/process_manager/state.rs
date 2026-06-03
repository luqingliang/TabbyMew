use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

use crate::fs_security;

use super::{ProcessState, lifecycle::is_process_running};

pub fn load_state(state_file: impl AsRef<Path>) -> Result<ProcessState> {
    let state_file = state_file.as_ref();
    let text = fs::read_to_string(state_file)
        .with_context(|| format!("failed to read state file {}", state_file.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("failed to parse state file {}", state_file.display()))
}

pub fn remove_state_file(state_file: impl AsRef<Path>) -> Result<()> {
    let state_file = state_file.as_ref();
    match fs::remove_file(state_file) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", state_file.display())),
    }
}

pub fn save_state_file(state_file: impl AsRef<Path>, state: &ProcessState) -> Result<()> {
    let state_file = state_file.as_ref();
    if let Some(parent) = state_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs_security::create_private_dir_all(parent)
            .with_context(|| format!("failed to create state dir {}", parent.display()))?;
    }
    save_state(state_file, state)
}

pub fn touch_state_heartbeat(state_file: impl AsRef<Path>, pid: u32, now: u64) -> Result<bool> {
    let state_file = state_file.as_ref();
    let mut state = load_state(state_file)?;
    if state.pid != pid {
        return Ok(false);
    }
    state.heartbeat_at_unix = Some(now);
    save_state_file(state_file, &state)?;
    Ok(true)
}

pub(super) fn save_state(state_file: &Path, state: &ProcessState) -> Result<()> {
    let text = serde_json::to_string_pretty(state).context("failed to serialize process state")?;
    fs_security::write_private_file(state_file, format!("{text}\n"))
        .with_context(|| format!("failed to write state file {}", state_file.display()))
}

pub(super) struct InspectedStateFile {
    pub(super) source: &'static str,
    pub(super) path: PathBuf,
    pub(super) exists: bool,
    pub(super) state: Result<ProcessState>,
    pub(super) running: Option<bool>,
}

pub(super) struct RemovedStaleState {
    pub(super) source: &'static str,
    pub(super) path: PathBuf,
    pub(super) pid: Option<u32>,
}

impl InspectedStateFile {
    pub(super) fn needs_cleanup(&self) -> bool {
        self.exists && (self.state.is_err() || self.running == Some(false))
    }
}

pub(super) fn inspect_state_file(path: &Path, source: &'static str) -> InspectedStateFile {
    let exists = path.exists();
    let state = load_state(path);
    let running = state
        .as_ref()
        .ok()
        .map(|state| is_process_running(state.pid));
    InspectedStateFile {
        source,
        path: path.to_path_buf(),
        exists,
        state,
        running,
    }
}

pub(super) fn remove_stale_or_reject_live_states(
    state_files: &[(&'static str, &Path)],
) -> Result<Vec<RemovedStaleState>> {
    let mut removed = Vec::new();
    for &(source, state_file) in state_files {
        match load_state(state_file) {
            Ok(existing) if is_process_running(existing.pid) => bail!(
                "TabbyMew already appears to be running with pid {} ({} state: {})",
                existing.pid,
                source,
                state_file.display()
            ),
            Ok(existing) => {
                remove_state_file(state_file)?;
                removed.push(RemovedStaleState {
                    source,
                    path: state_file.to_path_buf(),
                    pid: Some(existing.pid),
                });
            }
            Err(_) if state_file.exists() => {
                remove_state_file(state_file)?;
                removed.push(RemovedStaleState {
                    source,
                    path: state_file.to_path_buf(),
                    pid: None,
                });
            }
            Err(_) => {}
        }
    }
    Ok(removed)
}
