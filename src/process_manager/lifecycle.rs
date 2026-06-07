use std::{
    env,
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, bail};
use sysinfo::{Pid, ProcessesToUpdate, System};

use crate::{config::Config, fs_security};

use super::{
    ProcessState, StartOptions,
    logs::{
        append_lifecycle_event_best_effort, append_log_separator, new_session_log_file,
        rotate_log_if_needed,
    },
    paths::{
        absolute_existing_path, absolute_output_path, allocate_loopback_listen, paths,
        runtime_state_file, unix_now,
    },
    state::{load_state, remove_stale_or_reject_live_states, save_state},
};

pub fn start(options: StartOptions) -> Result<ProcessState> {
    let paths = paths(&options.state_dir, options.log.as_deref());
    let runtime_state_file = runtime_state_file(&paths.state_dir);
    fs_security::create_private_dir_all(&paths.state_dir)
        .with_context(|| format!("failed to create state dir {}", paths.state_dir.display()))?;
    let removed_stale_states = remove_stale_or_reject_live_states(&[
        ("managed", paths.state_file.as_path()),
        ("runtime", runtime_state_file.as_path()),
    ])?;

    let config = absolute_existing_path(&options.config)
        .with_context(|| format!("failed to resolve config {}", options.config.display()))?;
    let config_for_summary = Config::load(&config)?;
    let log_file = match options.log.as_deref() {
        Some(log) => absolute_output_path(log)?,
        None => new_session_log_file(&paths.state_dir)?,
    };
    if let Some(parent) = log_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .filter(|parent| !parent.exists())
    {
        fs_security::create_private_dir_all(parent)
            .with_context(|| format!("failed to create log dir {}", parent.display()))?;
    }
    let configured_listen = config_for_summary
        .services
        .clone()
        .and_then(|services| services.control_api)
        .map(|control_api| control_api.listen);
    let control_listen = if let Some(listen) = configured_listen {
        listen
    } else if let Some(listen) = options.control_listen.clone() {
        listen
    } else {
        allocate_loopback_listen()?
    };
    let executable = env::current_exe().context("failed to resolve current executable")?;
    rotate_log_if_needed(&log_file)?;
    append_log_separator(&log_file)?;
    append_lifecycle_event_best_effort(
        &log_file,
        "start_requested",
        &[
            ("state_dir", paths.state_dir.display().to_string()),
            ("state_file", paths.state_file.display().to_string()),
            ("config", config.display().to_string()),
            ("control_listen", control_listen.clone()),
        ],
    );
    for removed in removed_stale_states {
        append_lifecycle_event_best_effort(
            &log_file,
            "stale_state_removed_before_start",
            &[
                ("source", removed.source.to_string()),
                (
                    "pid",
                    removed
                        .pid
                        .map(|pid| pid.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                ),
                ("state_file", removed.path.display().to_string()),
            ],
        );
    }
    let stdout = fs_security::open_private_append(&log_file)
        .with_context(|| format!("failed to open log file {}", log_file.display()))?;
    let stderr = fs_security::open_private_append(&log_file)
        .with_context(|| format!("failed to open log file {}", log_file.display()))?;

    let mut command = Command::new(&executable);
    command
        .arg("--config")
        .arg(&config)
        .env("TABBYMEW_CONTROL_LISTEN", &control_listen)
        .env("TABBYMEW_STATE_DIR", &paths.state_dir)
        .env("TABBYMEW_LOG_FILE", &log_file)
        .env("TABBYMEW_STATE_FILE", &paths.state_file)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    command.arg("run");
    configure_background_process(&mut command);
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start {}", executable.display()))?;

    thread::sleep(Duration::from_millis(250));
    if let Some(status) = child
        .try_wait()
        .context("failed to check started TabbyMew process")?
    {
        append_lifecycle_event_best_effort(
            &log_file,
            "start_failed",
            &[("exit_status", status.to_string())],
        );
        bail!(
            "TabbyMew exited during startup with status {status}; see {}",
            log_file.display()
        );
    }

    let now = unix_now();
    let mut state = ProcessState {
        pid: child.id(),
        config,
        log: log_file.clone(),
        listen: Some(control_listen),
        control_token: None,
        started_at_unix: now,
        heartbeat_at_unix: Some(now),
    };
    if let Ok(existing) = load_state(&paths.state_file)
        && existing.pid == state.pid
    {
        state.listen = existing.listen.or(state.listen);
        state.control_token = existing.control_token;
    }
    if let Err(err) = save_state(&paths.state_file, &state) {
        append_lifecycle_event_best_effort(
            &log_file,
            "start_failed",
            &[("error", format!("{err:#}"))],
        );
        let _ = child.kill();
        return Err(err);
    }
    append_lifecycle_event_best_effort(
        &log_file,
        "start_spawned",
        &[
            ("pid", state.pid.to_string()),
            ("state_file", paths.state_file.display().to_string()),
            (
                "control_listen",
                state.listen.clone().unwrap_or_else(|| "none".to_string()),
            ),
        ],
    );
    Ok(state)
}

pub fn stop(pid: u32, force: bool, timeout: Duration) -> Result<bool> {
    if !is_process_running(pid) {
        return Ok(false);
    }
    terminate_process(pid, force)?;
    match wait_for_exit(pid, timeout) {
        Ok(stopped) => Ok(stopped),
        Err(_) if force => bail!("process {pid} is still running after force stop"),
        Err(_) => bail!("process {pid} is still running; retry with --force"),
    }
}

pub fn wait_for_exit(pid: u32, timeout: Duration) -> Result<bool> {
    if !is_process_running(pid) {
        return Ok(false);
    }
    let deadline = SystemTime::now() + timeout;
    while SystemTime::now() < deadline {
        if try_reap_exited_child(pid) || !is_process_running(pid) {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("process {pid} is still running after waiting for graceful stop")
}

pub fn is_process_running(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    process_exists(pid)
}

pub(super) fn process_memory_rss_bytes(pid: u32) -> Option<u64> {
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).map(|process| process.memory())
}

#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return true;
    }
    matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    )
}

#[cfg(windows)]
fn process_exists(pid: u32) -> bool {
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).is_some()
}

#[cfg(unix)]
fn configure_background_process(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    // A separate session prevents the background service from receiving the
    // controlling terminal's hangup when the launching shell/window closes.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
}

#[cfg(windows)]
fn configure_background_process(command: &mut Command) {
    use std::os::windows::process::CommandExt;

    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
}

#[cfg(unix)]
fn terminate_process(pid: u32, force: bool) -> Result<()> {
    let signal = if force { "-KILL" } else { "-TERM" };
    let status = Command::new("kill")
        .arg(signal)
        .arg(pid.to_string())
        .status()
        .context("failed to execute kill")?;
    if status.success() {
        Ok(())
    } else {
        bail!("kill {signal} {pid} failed with status {status}")
    }
}

#[cfg(unix)]
fn try_reap_exited_child(pid: u32) -> bool {
    let mut status = 0;
    let result = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
    result == pid as libc::pid_t
}

#[cfg(windows)]
fn try_reap_exited_child(_pid: u32) -> bool {
    false
}

#[cfg(windows)]
fn terminate_process(pid: u32, force: bool) -> Result<()> {
    let mut command = Command::new("taskkill");
    command.args(["/PID", &pid.to_string(), "/T"]);
    if force {
        command.arg("/F");
    }
    let status = command.status().context("failed to execute taskkill")?;
    if status.success() {
        Ok(())
    } else {
        bail!("taskkill for pid {pid} failed with status {status}")
    }
}
