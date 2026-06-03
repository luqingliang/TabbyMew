use std::path::Path;

use super::{
    STALE_HEARTBEAT_AFTER_SECS, ServiceStatus, ServiceStatusKind,
    lifecycle::process_memory_rss_bytes,
    paths::{paths, preferences_path, runtime_state_file, unix_now},
    preferences::load_preferences,
    state::inspect_state_file,
};

pub fn service_status(state_dir: impl AsRef<Path>) -> ServiceStatus {
    let paths = paths(state_dir, None);
    let runtime_state_file = runtime_state_file(&paths.state_dir);
    let preferences_file = preferences_path(&paths.state_dir);
    let mut cleanup_items = Vec::new();
    let mut state_error = None;
    let mut preference_error = None;
    let mut pid = None;
    let mut memory_rss_bytes = None;
    let mut config = None;
    let mut log = None;
    let mut listen = None;
    let mut started_at_unix = None;
    let mut heartbeat_at_unix = None;
    let mut active_state_file = None;
    let mut state_source = None;
    let state_file_exists = paths.state_file.exists();
    let runtime_state_file_exists = runtime_state_file.exists();

    let managed_state = inspect_state_file(&paths.state_file, "managed");
    let runtime_state = inspect_state_file(&runtime_state_file, "runtime");

    if managed_state.needs_cleanup() {
        cleanup_items.push("stale_state_file".to_string());
    }
    if runtime_state.needs_cleanup() {
        cleanup_items.push("stale_runtime_state_file".to_string());
    }

    let selected = if managed_state.running == Some(true) {
        &managed_state
    } else if runtime_state.running == Some(true) {
        &runtime_state
    } else if managed_state.exists {
        &managed_state
    } else if runtime_state.exists {
        &runtime_state
    } else {
        &managed_state
    };

    let status = if selected.exists {
        match selected.state.as_ref() {
            Ok(state) => {
                pid = Some(state.pid);
                config = Some(state.config.clone());
                log = Some(state.log.clone());
                listen = state.listen.clone();
                started_at_unix = Some(state.started_at_unix);
                heartbeat_at_unix = state.heartbeat_at_unix.or(Some(state.started_at_unix));
                active_state_file = Some(selected.path.clone());
                state_source = Some(selected.source.to_string());
                let running = selected.running.unwrap_or(false);
                if running {
                    memory_rss_bytes = process_memory_rss_bytes(state.pid);
                    ServiceStatusKind::Running
                } else {
                    ServiceStatusKind::Stale
                }
            }
            Err(err) => {
                state_error = Some(format!("{err:#}"));
                ServiceStatusKind::Stale
            }
        }
    } else {
        ServiceStatusKind::Stopped
    };

    let managed_system_proxy_recorded = match load_preferences(&preferences_file) {
        Ok(preferences) => preferences.system_proxy_target.is_some(),
        Err(err) => {
            if preferences_file.exists() {
                preference_error = Some(format!("{err:#}"));
            }
            false
        }
    };

    let now = unix_now();
    let heartbeat_age_seconds = heartbeat_at_unix.map(|heartbeat| now.saturating_sub(heartbeat));
    let heartbeat_stale = status == ServiceStatusKind::Running
        && heartbeat_age_seconds.is_some_and(|age| age > STALE_HEARTBEAT_AFTER_SECS);
    if managed_system_proxy_recorded && status != ServiceStatusKind::Running {
        cleanup_items.push("managed_system_proxy".to_string());
    }

    ServiceStatus {
        status,
        running: status == ServiceStatusKind::Running,
        stale: status == ServiceStatusKind::Stale,
        pid,
        memory_rss_bytes,
        config,
        log,
        listen,
        started_at_unix,
        state_dir: paths.state_dir,
        state_file: paths.state_file,
        runtime_state_file,
        preferences_file,
        active_state_file,
        state_source,
        state_file_exists,
        runtime_state_file_exists,
        heartbeat_at_unix,
        heartbeat_age_seconds,
        heartbeat_stale,
        managed_system_proxy_recorded,
        cleanup_items,
        state_error,
        preference_error,
    }
}
