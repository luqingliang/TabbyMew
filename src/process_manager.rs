use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::system_proxy::{SystemProxyProtocol, SystemProxyTarget};

mod lifecycle;
mod logs;
mod paths;
mod preferences;
mod state;
mod status;

pub use lifecycle::{is_process_running, start, stop, wait_for_exit};
pub use logs::{append_lifecycle_event_best_effort, new_session_log_file, read_log_tail};
pub use paths::{
    default_config_path, default_state_dir, paths, preferences_path, runtime_state_file,
};
pub use preferences::{load_preferences, save_preferences, update_preferences};
pub use state::{load_state, remove_state_file, save_state_file, touch_state_heartbeat};
pub use status::service_status;

pub fn append_lifecycle_event(
    log_file: impl AsRef<Path>,
    event: &str,
    fields: &[(&str, String)],
) -> Result<()> {
    logs::append_lifecycle_event(log_file, event, fields)
}

const STATE_FILE: &str = "tabbymew-state.json";
const RUNTIME_STATE_FILE: &str = "tabbymew-runtime.json";
const PREFERENCES_FILE: &str = "tabbymew-preferences.json";
const PREFERENCES_VERSION: u32 = 2;
const DEFAULT_LOG_DIR: &str = "logs";
const DEFAULT_LOG_FILE: &str = "tabbymew.log";
const SESSION_LOG_PREFIX: &str = "tabbymew-";
const SESSION_LOG_SUFFIX: &str = ".log";
const DEFAULT_CONFIG_FILE: &str = "tabbymew-config.json";
const MAX_LOG_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_LOG_ARCHIVES: usize = 4;
const MAX_SESSION_LOG_FILES: usize = 32;
const LOG_TAIL_BLOCK_BYTES: u64 = 8 * 1024;
const MAX_LOG_TAIL_BYTES: u64 = 1024 * 1024;
pub const STALE_HEARTBEAT_AFTER_SECS: u64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessState {
    pub pid: u32,
    pub config: PathBuf,
    pub log: PathBuf,
    pub listen: Option<String>,
    #[serde(
        default,
        alias = "console_token",
        skip_serializing_if = "Option::is_none"
    )]
    pub control_token: Option<String>,
    pub started_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_at_unix: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ProcessPaths {
    pub state_dir: PathBuf,
    pub state_file: PathBuf,
    pub log_file: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatusKind {
    Running,
    Stopped,
    Stale,
}

impl ServiceStatusKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceStatus {
    pub status: ServiceStatusKind,
    pub running: bool,
    pub stale: bool,
    pub pid: Option<u32>,
    pub memory_rss_bytes: Option<u64>,
    pub config: Option<PathBuf>,
    pub log: Option<PathBuf>,
    pub listen: Option<String>,
    pub started_at_unix: Option<u64>,
    pub state_dir: PathBuf,
    pub state_file: PathBuf,
    pub runtime_state_file: PathBuf,
    pub preferences_file: PathBuf,
    pub active_state_file: Option<PathBuf>,
    pub state_source: Option<String>,
    pub state_file_exists: bool,
    pub runtime_state_file_exists: bool,
    pub heartbeat_at_unix: Option<u64>,
    pub heartbeat_age_seconds: Option<u64>,
    pub heartbeat_stale: bool,
    pub managed_system_proxy_recorded: bool,
    pub cleanup_items: Vec<String>,
    pub state_error: Option<String>,
    pub preference_error: Option<String>,
}

impl ServiceStatus {
    pub fn needs_cleanup(&self) -> bool {
        !self.cleanup_items.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct StartOptions {
    pub config: PathBuf,
    pub state_dir: PathBuf,
    pub log: Option<PathBuf>,
    pub control_listen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimePreferences {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub active_config: Option<PathBuf>,
    #[serde(default)]
    pub lan_proxy_enabled: bool,
    #[serde(default)]
    pub route_mode: Option<String>,
    #[serde(default)]
    pub global_outbound: Option<String>,
    #[serde(default)]
    pub policy_group_selections: BTreeMap<String, String>,
    #[serde(default)]
    pub system_proxy_target: Option<SystemProxyTarget>,
    #[serde(default)]
    pub system_proxy_protocol: SystemProxyProtocol,
}

impl Default for RuntimePreferences {
    fn default() -> Self {
        Self {
            version: PREFERENCES_VERSION,
            active_config: None,
            lan_proxy_enabled: false,
            route_mode: None,
            global_outbound: None,
            policy_group_selections: BTreeMap::new(),
            system_proxy_target: None,
            system_proxy_protocol: SystemProxyProtocol::Auto,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{
        logs::{
            is_session_log_file, prune_session_logs, rotate_log_if_needed, rotated_log_path,
            tail_lines,
        },
        paths::unix_now,
        state::save_state,
    };
    use anyhow::{Context, Result};
    use std::{
        env, fs,
        path::{Path, PathBuf},
        process::Command,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use crate::system_proxy::{SystemProxyProtocol, SystemProxyTarget};

    #[test]
    fn tails_requested_lines() {
        assert_eq!(tail_lines("a\nb\nc\n", 2), "b\nc\n");
        assert_eq!(tail_lines("a\nb\nc", 2), "b\nc");
        assert_eq!(tail_lines("a\n", 10), "a\n");
        assert_eq!(tail_lines("a\n", 0), "");
    }

    #[test]
    fn reads_log_tail_without_full_file_contract() -> Result<()> {
        let dir = temp_test_dir("tabbymew-log-tail-test")?;
        let path = dir.join("tabbymew.log");
        fs::write(&path, "first\nsecond\nthird\n")?;

        assert_eq!(read_log_tail(&path, 2)?, "second\nthird\n");

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn lifecycle_event_log_sanitizes_and_appends_fields() -> Result<()> {
        let dir = temp_test_dir("tabbymew-lifecycle-log-test")?;
        let path = dir.join("tabbymew.log");

        append_lifecycle_event(
            &path,
            "cleanup\nstarted",
            &[
                ("pid", "123".to_string()),
                ("error", "line one\nline two".to_string()),
            ],
        )?;

        let text = fs::read_to_string(&path)?;
        assert!(text.contains("INFO lifecycle event=\"cleanup started\""));
        assert!(text.contains("pid=\"123\""));
        assert!(text.contains("error=\"line one line two\""));

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn default_paths_keep_logs_under_dedicated_log_dir() -> Result<()> {
        let dir = temp_test_dir("tabbymew-paths-test")?;
        let paths = paths(&dir, None);

        assert_eq!(
            paths.log_file,
            dir.join(DEFAULT_LOG_DIR).join(DEFAULT_LOG_FILE)
        );
        assert_eq!(runtime_state_file(&dir), dir.join(RUNTIME_STATE_FILE));

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn new_session_log_file_uses_unique_file_under_log_dir() -> Result<()> {
        let dir = temp_test_dir("tabbymew-session-log-path-test")?;
        let expected_log_dir = dir.join(DEFAULT_LOG_DIR);
        let first = new_session_log_file(&dir)?;
        let second = new_session_log_file(&dir)?;

        assert_ne!(first, second);
        assert_eq!(first.parent(), Some(expected_log_dir.as_path()));
        assert_eq!(second.parent(), Some(expected_log_dir.as_path()));
        assert!(is_session_log_file(&first));
        assert!(is_session_log_file(&second));

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn prunes_old_session_logs_without_touching_other_files() -> Result<()> {
        let dir = temp_test_dir("tabbymew-session-log-prune-test")?;
        let logs = dir.join(DEFAULT_LOG_DIR);
        fs::create_dir_all(&logs)?;
        fs::write(logs.join("keep.txt"), "not a session log")?;
        for index in 0..5 {
            fs::write(
                logs.join(format!(
                    "{SESSION_LOG_PREFIX}{index:03}{SESSION_LOG_SUFFIX}"
                )),
                format!("log {index}"),
            )?;
        }

        prune_session_logs(&logs, 2)?;

        let remaining = fs::read_dir(&logs)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| is_session_log_file(path))
            .collect::<Vec<_>>();
        assert_eq!(remaining.len(), 2);
        assert!(logs.join("keep.txt").exists());

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn rotates_large_log_files() -> Result<()> {
        let dir = temp_test_dir("tabbymew-log-rotate-test")?;
        let path = dir.join("tabbymew.log");
        fs::write(&path, "old archive")?;
        fs::write(rotated_log_path(&path, 1), "older archive")?;
        fs::OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_len(MAX_LOG_FILE_BYTES + 1)?;

        rotate_log_if_needed(&path)?;

        assert!(!path.exists());
        assert!(rotated_log_path(&path, 1).exists());
        assert!(rotated_log_path(&path, 2).exists());

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn state_round_trips() -> Result<()> {
        let dir = env::temp_dir().join(format!(
            "tabbymew-state-test-{}-{}",
            std::process::id(),
            unix_now()
        ));
        fs::create_dir_all(&dir)?;
        let state_file = dir.join(STATE_FILE);
        let state = ProcessState {
            pid: 123,
            config: PathBuf::from("/tmp/config.json"),
            log: PathBuf::from("/tmp/tabbymew.log"),
            listen: Some("127.0.0.1:9090".to_string()),
            control_token: Some("test-token".to_string()),
            started_at_unix: 42,
            heartbeat_at_unix: Some(43),
        };

        save_state(&state_file, &state)?;
        let loaded = load_state(&state_file)?;

        assert_eq!(loaded.pid, 123);
        assert_eq!(loaded.listen.as_deref(), Some("127.0.0.1:9090"));
        assert_eq!(loaded.control_token.as_deref(), Some("test-token"));
        assert_eq!(loaded.heartbeat_at_unix, Some(43));

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn state_and_preferences_files_are_private() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_test_dir("tabbymew-private-runtime-files-test")?;
        let paths = paths(&dir, None);
        let state = ProcessState {
            pid: 123,
            config: dir.join("config.json"),
            log: dir.join("tabbymew.log"),
            listen: Some("127.0.0.1:9090".to_string()),
            control_token: Some("test-token".to_string()),
            started_at_unix: 42,
            heartbeat_at_unix: Some(43),
        };

        save_state_file(&paths.state_file, &state)?;
        save_preferences(
            preferences_path(&dir),
            &RuntimePreferences {
                active_config: Some(dir.join("profile.json")),
                ..RuntimePreferences::default()
            },
        )?;

        assert_eq!(fs::metadata(&dir)?.permissions().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(&paths.state_file)?.permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(preferences_path(&dir))?.permissions().mode() & 0o777,
            0o600
        );

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn state_loads_legacy_fields_for_backward_compatibility() -> Result<()> {
        let dir = temp_test_dir("tabbymew-state-backward-compat-test")?;
        let state_file = dir.join(STATE_FILE);
        fs::write(
            &state_file,
            r#"{
  "pid": 123,
  "config": "/tmp/config.json",
  "log": "/tmp/tabbymew.log",
  "listen": "127.0.0.1:9090",
  "started_at_unix": 42
}
"#,
        )?;

        let loaded = load_state(&state_file)?;

        assert_eq!(loaded.pid, 123);
        assert_eq!(loaded.control_token, None);
        assert_eq!(loaded.heartbeat_at_unix, None);

        fs::remove_dir_all(dir)?;

        let dir = temp_test_dir("tabbymew-state-legacy-token-test")?;
        let state_file = dir.join(STATE_FILE);
        fs::write(
            &state_file,
            r#"{
  "pid": 123,
  "config": "/tmp/config.json",
  "log": "/tmp/tabbymew.log",
  "listen": "127.0.0.1:9090",
  "console_token": "legacy-token",
  "started_at_unix": 42
}
"#,
        )?;

        let loaded = load_state(&state_file)?;

        assert_eq!(loaded.control_token.as_deref(), Some("legacy-token"));

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn service_status_reports_stopped_without_state() -> Result<()> {
        let dir = temp_test_dir("tabbymew-service-status-stopped-test")?;

        let status = service_status(&dir);

        assert_eq!(status.status, ServiceStatusKind::Stopped);
        assert!(!status.running);
        assert!(!status.needs_cleanup());

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn service_status_reports_stale_dead_pid() -> Result<()> {
        let dir = temp_test_dir("tabbymew-service-status-stale-test")?;
        let state = ProcessState {
            pid: 0,
            config: dir.join("config.json"),
            log: dir.join("tabbymew.log"),
            listen: Some("127.0.0.1:9090".to_string()),
            control_token: None,
            started_at_unix: 42,
            heartbeat_at_unix: Some(42),
        };
        let state_file = paths(&dir, None).state_file;
        save_state_file(&state_file, &state)?;

        let status = service_status(&dir);

        assert_eq!(status.status, ServiceStatusKind::Stale);
        assert_eq!(status.pid, Some(0));
        assert!(status.stale);
        assert!(
            status
                .cleanup_items
                .contains(&"stale_state_file".to_string())
        );

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn service_status_reports_memory_for_running_process() -> Result<()> {
        let dir = temp_test_dir("tabbymew-service-status-memory-test")?;
        let state = ProcessState {
            pid: std::process::id(),
            config: dir.join("config.json"),
            log: dir.join("tabbymew.log"),
            listen: Some("127.0.0.1:9090".to_string()),
            control_token: None,
            started_at_unix: 42,
            heartbeat_at_unix: Some(unix_now()),
        };
        let state_file = paths(&dir, None).state_file;
        save_state_file(&state_file, &state)?;

        let status = service_status(&dir);

        assert_eq!(status.status, ServiceStatusKind::Running);
        assert!(status.memory_rss_bytes.is_some_and(|memory| memory > 0));

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn service_status_uses_running_runtime_state_when_managed_state_is_absent() -> Result<()> {
        let dir = temp_test_dir("tabbymew-runtime-state-status-test")?;
        let state = ProcessState {
            pid: std::process::id(),
            config: dir.join("config.json"),
            log: dir.join("tabbymew.log"),
            listen: Some("127.0.0.1:9090".to_string()),
            control_token: None,
            started_at_unix: 42,
            heartbeat_at_unix: Some(unix_now()),
        };
        save_state_file(runtime_state_file(&dir), &state)?;

        let status = service_status(&dir);

        assert_eq!(status.status, ServiceStatusKind::Running);
        assert_eq!(status.state_source.as_deref(), Some("runtime"));
        assert!(status.runtime_state_file_exists);
        assert!(!status.state_file_exists);
        assert!(!status.heartbeat_stale);

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn start_rejects_running_runtime_state() -> Result<()> {
        let dir = temp_test_dir("tabbymew-start-runtime-state-test")?;
        let runtime_state = ProcessState {
            pid: std::process::id(),
            config: dir.join("config.json"),
            log: dir.join("tabbymew.log"),
            listen: Some("127.0.0.1:9090".to_string()),
            control_token: Some("runtime-token".to_string()),
            started_at_unix: 42,
            heartbeat_at_unix: Some(unix_now()),
        };
        let runtime_state_file = runtime_state_file(&dir);
        save_state_file(&runtime_state_file, &runtime_state)?;

        let err = start(StartOptions {
            config: dir.join("missing-config.json"),
            state_dir: dir.clone(),
            log: None,
            control_listen: None,
        })
        .unwrap_err();

        let error = format!("{err:#}");
        assert!(error.contains("already appears to be running"));
        assert!(error.contains("runtime state"));
        assert!(runtime_state_file.exists());

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn service_status_prefers_running_runtime_state_over_stale_managed_state() -> Result<()> {
        let dir = temp_test_dir("tabbymew-runtime-state-adoption-test")?;
        save_state_file(
            paths(&dir, None).state_file,
            &ProcessState {
                pid: 0,
                config: dir.join("stale-config.json"),
                log: dir.join("stale.log"),
                listen: Some("127.0.0.1:9090".to_string()),
                control_token: None,
                started_at_unix: 1,
                heartbeat_at_unix: Some(1),
            },
        )?;
        save_state_file(
            runtime_state_file(&dir),
            &ProcessState {
                pid: std::process::id(),
                config: dir.join("runtime-config.json"),
                log: dir.join("runtime.log"),
                listen: Some("127.0.0.1:9091".to_string()),
                control_token: None,
                started_at_unix: 42,
                heartbeat_at_unix: Some(unix_now()),
            },
        )?;

        let status = service_status(&dir);

        assert_eq!(status.status, ServiceStatusKind::Running);
        assert_eq!(status.state_source.as_deref(), Some("runtime"));
        assert_eq!(status.pid, Some(std::process::id()));
        assert_eq!(status.listen.as_deref(), Some("127.0.0.1:9091"));
        assert!(
            status
                .cleanup_items
                .contains(&"stale_state_file".to_string())
        );

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn service_status_marks_stale_runtime_state_for_cleanup() -> Result<()> {
        let dir = temp_test_dir("tabbymew-runtime-state-stale-test")?;
        let state = ProcessState {
            pid: 0,
            config: dir.join("config.json"),
            log: dir.join("tabbymew.log"),
            listen: Some("127.0.0.1:9090".to_string()),
            control_token: None,
            started_at_unix: 42,
            heartbeat_at_unix: Some(42),
        };
        save_state_file(runtime_state_file(&dir), &state)?;

        let status = service_status(&dir);

        assert_eq!(status.status, ServiceStatusKind::Stale);
        assert!(
            status
                .cleanup_items
                .contains(&"stale_runtime_state_file".to_string())
        );
        assert!(
            !status
                .cleanup_items
                .contains(&"stale_state_file".to_string())
        );

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn touch_state_heartbeat_updates_only_owned_state() -> Result<()> {
        let dir = temp_test_dir("tabbymew-heartbeat-test")?;
        let state_file = paths(&dir, None).state_file;
        let state = ProcessState {
            pid: 123,
            config: dir.join("config.json"),
            log: dir.join("tabbymew.log"),
            listen: Some("127.0.0.1:9090".to_string()),
            control_token: None,
            started_at_unix: 42,
            heartbeat_at_unix: Some(42),
        };
        save_state_file(&state_file, &state)?;

        assert!(!touch_state_heartbeat(&state_file, 456, 100)?);
        assert_eq!(load_state(&state_file)?.heartbeat_at_unix, Some(42));
        assert!(touch_state_heartbeat(&state_file, 123, 100)?);
        assert_eq!(load_state(&state_file)?.heartbeat_at_unix, Some(100));

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn service_status_reports_stale_heartbeat_for_running_process() -> Result<()> {
        let dir = temp_test_dir("tabbymew-stale-heartbeat-test")?;
        let state = ProcessState {
            pid: std::process::id(),
            config: dir.join("config.json"),
            log: dir.join("tabbymew.log"),
            listen: Some("127.0.0.1:9090".to_string()),
            control_token: None,
            started_at_unix: 1,
            heartbeat_at_unix: Some(1),
        };
        save_state_file(paths(&dir, None).state_file, &state)?;

        let status = service_status(&dir);

        assert_eq!(status.status, ServiceStatusKind::Running);
        assert!(status.heartbeat_stale);
        assert!(status.heartbeat_age_seconds.is_some_and(|age| age > 120));

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn service_status_marks_stopped_managed_system_proxy_for_cleanup() -> Result<()> {
        let dir = temp_test_dir("tabbymew-service-status-system-proxy-test")?;
        save_preferences(
            preferences_path(&dir),
            &RuntimePreferences {
                system_proxy_target: Some(SystemProxyTarget {
                    source: "hybrid:hybrid-in@127.0.0.1:7890".to_string(),
                    http: None,
                    https: None,
                    socks: None,
                }),
                ..RuntimePreferences::default()
            },
        )?;

        let status = service_status(&dir);

        assert_eq!(status.status, ServiceStatusKind::Stopped);
        assert!(status.managed_system_proxy_recorded);
        assert!(status.needs_cleanup());
        assert!(
            status
                .cleanup_items
                .contains(&"managed_system_proxy".to_string())
        );

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn runtime_preferences_round_trip_and_update() -> Result<()> {
        let dir = env::temp_dir().join(format!(
            "tabbymew-preferences-test-{}-{}",
            std::process::id(),
            unix_now()
        ));
        fs::create_dir_all(&dir)?;
        let path = preferences_path(&dir);

        let mut preferences = RuntimePreferences {
            active_config: Some(PathBuf::from("/tmp/subscription.json")),
            lan_proxy_enabled: true,
            route_mode: Some("global".to_string()),
            global_outbound: Some("Proxy".to_string()),
            system_proxy_protocol: SystemProxyProtocol::Socks,
            system_proxy_target: Some(SystemProxyTarget {
                source: "hybrid:hybrid-in@127.0.0.1:7890".to_string(),
                http: None,
                https: None,
                socks: None,
            }),
            ..RuntimePreferences::default()
        };
        preferences
            .policy_group_selections
            .insert("Proxy".to_string(), "HK".to_string());
        save_preferences(&path, &preferences)?;

        let loaded = load_preferences(&path)?;
        assert_eq!(
            loaded.active_config.as_deref(),
            Some(Path::new("/tmp/subscription.json"))
        );
        assert!(loaded.lan_proxy_enabled);
        assert_eq!(loaded.route_mode.as_deref(), Some("global"));
        assert_eq!(
            loaded
                .policy_group_selections
                .get("Proxy")
                .map(String::as_str),
            Some("HK")
        );
        assert_eq!(
            loaded
                .system_proxy_target
                .as_ref()
                .map(|target| target.source.as_str()),
            Some("hybrid:hybrid-in@127.0.0.1:7890")
        );
        assert_eq!(loaded.system_proxy_protocol, SystemProxyProtocol::Socks);

        let updated = update_preferences(&path, |preferences| {
            preferences.lan_proxy_enabled = false;
            preferences.global_outbound = Some("direct".to_string());
            preferences.system_proxy_protocol = SystemProxyProtocol::HttpConnect;
        })?;
        assert!(!updated.lan_proxy_enabled);
        assert_eq!(updated.global_outbound.as_deref(), Some("direct"));
        assert_eq!(
            updated.system_proxy_protocol,
            SystemProxyProtocol::HttpConnect
        );

        fs::write(&path, "{not valid runtime preferences}\n")?;
        let repaired = update_preferences(&path, |preferences| {
            preferences.route_mode = Some("direct".to_string());
        })?;
        assert_eq!(repaired.route_mode.as_deref(), Some("direct"));
        assert_eq!(
            load_preferences(&path)?.route_mode.as_deref(),
            Some("direct")
        );

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn stop_reaps_child_process_without_waiting_for_timeout() -> Result<()> {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .context("failed to start test child process")?;
        let started = std::time::Instant::now();

        let result = stop(child.id(), false, Duration::from_secs(5));
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let stopped = result?;

        assert!(stopped);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "stop waited too long for a direct child process to exit"
        );
        Ok(())
    }

    fn temp_test_dir(prefix: &str) -> Result<PathBuf> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}
