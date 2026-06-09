use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

#[cfg(windows)]
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::{fs_security, platform, process_manager};

const AUTOSTART_SCHEMA_VERSION: u16 = 1;
const MACOS_LAUNCH_AGENT_LABEL: &str = "com.tabbymew.autostart";
const WINDOWS_RUN_VALUE: &str = "TabbyMew";
const WINDOWS_RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AutostartAction {
    Status,
    Enable,
    Disable,
    Toggle,
}

#[derive(Debug, Clone)]
pub(crate) struct AutostartOptions {
    pub(crate) state_dir: PathBuf,
    pub(crate) config: Option<PathBuf>,
    pub(crate) executable: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AutostartReport {
    pub(crate) schema_version: u16,
    pub(crate) ok: bool,
    pub(crate) status: String,
    pub(crate) message: String,
    pub(crate) enabled: bool,
    pub(crate) supported: bool,
    pub(crate) synced: bool,
    pub(crate) platform: String,
    pub(crate) state_dir: PathBuf,
    pub(crate) preferences_file: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) config: Option<PathBuf>,
    pub(crate) entry: AutostartEntryReport,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AutostartEntryReport {
    pub(crate) kind: String,
    pub(crate) installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) command: Option<String>,
}

#[derive(Debug, Clone)]
struct PlatformEntryStatus {
    supported: bool,
    kind: &'static str,
    installed: bool,
    location: Option<String>,
    command: Option<String>,
}

pub(crate) fn parse_action(
    action: Option<&str>,
    default: AutostartAction,
) -> Result<AutostartAction> {
    match action.map(str::trim).filter(|action| !action.is_empty()) {
        None => Ok(default),
        Some("status") => Ok(AutostartAction::Status),
        Some("on" | "enable" | "enabled" | "start") => Ok(AutostartAction::Enable),
        Some("off" | "disable" | "disabled" | "stop") => Ok(AutostartAction::Disable),
        Some("toggle" | "switch") => Ok(AutostartAction::Toggle),
        Some(other) => {
            bail!("unknown autostart action `{other}`; expected status, on, off, or toggle")
        }
    }
}

pub(crate) fn apply(action: AutostartAction, options: AutostartOptions) -> Result<AutostartReport> {
    let preferences_file = process_manager::preferences_path(&options.state_dir);
    let preferences = process_manager::load_preferences(&preferences_file)
        .with_context(|| format!("failed to load {}", preferences_file.display()))?;
    let target_enabled = match action {
        AutostartAction::Status => preferences.autostart_enabled,
        AutostartAction::Enable => true,
        AutostartAction::Disable => false,
        AutostartAction::Toggle => !preferences.autostart_enabled,
    };

    match action {
        AutostartAction::Status => {}
        AutostartAction::Enable | AutostartAction::Toggle if target_enabled => {
            let config = options
                .config
                .as_ref()
                .context("autostart enable requires a config path")?;
            install_platform_entry(&options.executable, &options.state_dir)?;
            if let Err(err) =
                process_manager::update_preferences(&preferences_file, |preferences| {
                    preferences.active_config = Some(config.clone());
                    preferences.autostart_enabled = true;
                })
            {
                let _ = remove_platform_entry();
                return Err(err).with_context(|| {
                    format!(
                        "failed to save autostart preference {}; removed platform entry",
                        preferences_file.display()
                    )
                });
            }
        }
        AutostartAction::Disable | AutostartAction::Toggle => {
            if platform_autostart_supported() {
                remove_platform_entry()?;
            }
            process_manager::update_preferences(&preferences_file, |preferences| {
                preferences.autostart_enabled = false;
            })?;
        }
        AutostartAction::Enable => unreachable!("enable target is always enabled"),
    }

    report(&options.state_dir, options.config)
}

pub(crate) fn report(state_dir: &Path, config: Option<PathBuf>) -> Result<AutostartReport> {
    let preferences_file = process_manager::preferences_path(state_dir);
    let preferences = process_manager::load_preferences(&preferences_file)
        .with_context(|| format!("failed to load {}", preferences_file.display()))?;
    let entry = platform_entry_status()?;
    let enabled = preferences.autostart_enabled;
    let synced = if entry.supported {
        enabled == entry.installed
    } else {
        !enabled
    };
    let status = autostart_status(enabled, &entry);
    let message = autostart_message(enabled, &entry);
    Ok(AutostartReport {
        schema_version: AUTOSTART_SCHEMA_VERSION,
        ok: synced,
        status,
        message,
        enabled,
        supported: entry.supported,
        synced,
        platform: platform::name().to_string(),
        state_dir: state_dir.to_path_buf(),
        preferences_file,
        config,
        entry: AutostartEntryReport {
            kind: entry.kind.to_string(),
            installed: entry.installed,
            location: entry.location,
            command: entry.command,
        },
    })
}

pub(crate) fn format_report(report: &AutostartReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("autostart: {}\n", report.status));
    output.push_str(&format!("  message: {}\n", report.message));
    output.push_str(&format!("  platform: {}\n", report.platform));
    output.push_str(&format!("  supported: {}\n", on_off(report.supported)));
    output.push_str(&format!("  saved switch: {}\n", on_off(report.enabled)));
    output.push_str(&format!(
        "  platform entry: {}\n",
        on_off(report.entry.installed)
    ));
    output.push_str(&format!("  synced: {}\n", on_off(report.synced)));
    output.push_str(&format!("  state dir: {}\n", report.state_dir.display()));
    output.push_str(&format!(
        "  preferences: {}\n",
        report.preferences_file.display()
    ));
    if let Some(config) = &report.config {
        output.push_str(&format!("  config: {}\n", config.display()));
    }
    if let Some(location) = &report.entry.location {
        output.push_str(&format!("  entry: {location}\n"));
    }
    if let Some(command) = &report.entry.command {
        output.push_str(&format!("  command: {command}\n"));
    }
    output
}

pub(crate) fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()
            .context("failed to read current directory")?
            .join(path))
    }
}

pub(crate) fn action_needs_config(action: AutostartAction, state_dir: &Path) -> Result<bool> {
    match action {
        AutostartAction::Enable => Ok(true),
        AutostartAction::Toggle => {
            let preferences_file = process_manager::preferences_path(state_dir);
            let preferences = process_manager::load_preferences(&preferences_file)
                .with_context(|| format!("failed to load {}", preferences_file.display()))?;
            Ok(!preferences.autostart_enabled)
        }
        AutostartAction::Status | AutostartAction::Disable => Ok(false),
    }
}

fn autostart_status(enabled: bool, entry: &PlatformEntryStatus) -> String {
    if !entry.supported {
        return if enabled {
            "unsupported_enabled".to_string()
        } else {
            "unsupported".to_string()
        };
    }
    match (enabled, entry.installed) {
        (true, true) => "enabled".to_string(),
        (false, false) => "disabled".to_string(),
        (true, false) => "repair_needed".to_string(),
        (false, true) => "disable_needed".to_string(),
    }
}

fn autostart_message(enabled: bool, entry: &PlatformEntryStatus) -> String {
    if !entry.supported {
        return if enabled {
            format!(
                "autostart is saved as enabled, but {} does not support an autostart backend",
                platform::name()
            )
        } else {
            format!(
                "autostart is disabled; {} does not support an autostart backend",
                platform::name()
            )
        };
    }
    match (enabled, entry.installed) {
        (true, true) => "autostart is enabled".to_string(),
        (false, false) => "autostart is disabled".to_string(),
        (true, false) => {
            "autostart is saved as enabled, but the platform entry is missing".to_string()
        }
        (false, true) => {
            "autostart is saved as disabled, but the platform entry is still installed".to_string()
        }
    }
}

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

fn install_platform_entry(executable: &Path, state_dir: &Path) -> Result<()> {
    if !platform_autostart_supported() {
        bail!("{} autostart is not supported", platform::name());
    }
    match platform::current() {
        platform::Platform::Macos => install_macos_launch_agent(executable, state_dir),
        platform::Platform::Windows => install_windows_run_entry(executable, state_dir),
        platform::Platform::Linux | platform::Platform::Unsupported => {
            bail!("{} autostart is not supported", platform::name())
        }
    }
}

fn remove_platform_entry() -> Result<()> {
    if !platform_autostart_supported() {
        bail!("{} autostart is not supported", platform::name());
    }
    match platform::current() {
        platform::Platform::Macos => remove_macos_launch_agent(),
        platform::Platform::Windows => remove_windows_run_entry(),
        platform::Platform::Linux | platform::Platform::Unsupported => {
            bail!("{} autostart is not supported", platform::name())
        }
    }
}

fn platform_entry_status() -> Result<PlatformEntryStatus> {
    match platform::current() {
        platform::Platform::Macos => macos_launch_agent_status(),
        platform::Platform::Windows => windows_run_entry_status(),
        platform::Platform::Linux => Ok(PlatformEntryStatus {
            supported: false,
            kind: "linux_development_only",
            installed: false,
            location: None,
            command: None,
        }),
        platform::Platform::Unsupported => Ok(PlatformEntryStatus {
            supported: false,
            kind: "unsupported",
            installed: false,
            location: None,
            command: None,
        }),
    }
}

fn platform_autostart_supported() -> bool {
    matches!(
        platform::current(),
        platform::Platform::Macos | platform::Platform::Windows
    )
}

fn program_arguments(executable: &Path, state_dir: &Path) -> Vec<String> {
    vec![
        executable.display().to_string(),
        "start".to_string(),
        "--state-dir".to_string(),
        state_dir.display().to_string(),
    ]
}

fn install_macos_launch_agent(executable: &Path, state_dir: &Path) -> Result<()> {
    let path = macos_launch_agent_path()?;
    if let Some(parent) = path.parent() {
        fs_security::create_private_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let logs_dir = state_dir.join("logs");
    fs_security::create_private_dir_all(&logs_dir)
        .with_context(|| format!("failed to create {}", logs_dir.display()))?;
    fs_security::write_private_file(
        &path,
        macos_launch_agent_plist(
            &program_arguments(executable, state_dir),
            &logs_dir.join("autostart-launchagent.log"),
        ),
    )
    .with_context(|| format!("failed to write {}", path.display()))
}

fn remove_macos_launch_agent() -> Result<()> {
    remove_file_if_exists(macos_launch_agent_path()?)
}

fn macos_launch_agent_status() -> Result<PlatformEntryStatus> {
    let path = macos_launch_agent_path()?;
    let command = fs::read_to_string(&path)
        .ok()
        .and_then(|text| macos_program_arguments_summary(&text));
    Ok(PlatformEntryStatus {
        supported: true,
        kind: "macos_launch_agent",
        installed: path.exists(),
        location: Some(path.display().to_string()),
        command,
    })
}

fn macos_launch_agent_path() -> Result<PathBuf> {
    let home = env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{MACOS_LAUNCH_AGENT_LABEL}.plist")))
}

fn macos_launch_agent_plist(args: &[String], log_path: &Path) -> String {
    let mut plist = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
"#,
    );
    plist.push_str(&format!(
        "  <string>{}</string>\n",
        escape_xml(MACOS_LAUNCH_AGENT_LABEL)
    ));
    plist.push_str("  <key>ProgramArguments</key>\n  <array>\n");
    for arg in args {
        plist.push_str(&format!("    <string>{}</string>\n", escape_xml(arg)));
    }
    plist.push_str("  </array>\n");
    plist.push_str("  <key>RunAtLoad</key>\n  <true/>\n");
    plist.push_str(&format!(
        "  <key>StandardOutPath</key>\n  <string>{}</string>\n",
        escape_xml(&log_path.display().to_string())
    ));
    plist.push_str(&format!(
        "  <key>StandardErrorPath</key>\n  <string>{}</string>\n",
        escape_xml(&log_path.display().to_string())
    ));
    plist.push_str("</dict>\n</plist>\n");
    plist
}

fn macos_program_arguments_summary(plist: &str) -> Option<String> {
    let mut in_program_arguments = false;
    let mut args = Vec::new();
    for line in plist.lines().map(str::trim) {
        match line {
            "<array>" => in_program_arguments = true,
            "</array>" if in_program_arguments => break,
            _ if in_program_arguments => {
                if let Some(value) = line
                    .strip_prefix("<string>")
                    .and_then(|line| line.strip_suffix("</string>"))
                {
                    args.push(unescape_xml(value));
                }
            }
            _ => {}
        }
    }
    (!args.is_empty()).then(|| args.join(" "))
}

#[cfg(windows)]
fn install_windows_run_entry(executable: &Path, state_dir: &Path) -> Result<()> {
    let command = windows_run_command_line(&program_arguments(executable, state_dir));
    let status = Command::new("reg")
        .args([
            "add",
            WINDOWS_RUN_KEY,
            "/v",
            WINDOWS_RUN_VALUE,
            "/t",
            "REG_SZ",
            "/d",
            &command,
            "/f",
        ])
        .status()
        .context("failed to execute reg.exe")?;
    if status.success() {
        Ok(())
    } else {
        bail!("reg add failed with status {status}")
    }
}

#[cfg(not(windows))]
fn install_windows_run_entry(_executable: &Path, _state_dir: &Path) -> Result<()> {
    bail!("Windows autostart can only be installed on Windows")
}

#[cfg(windows)]
fn remove_windows_run_entry() -> Result<()> {
    if !windows_run_entry_status()?.installed {
        return Ok(());
    }
    let status = Command::new("reg")
        .args(["delete", WINDOWS_RUN_KEY, "/v", WINDOWS_RUN_VALUE, "/f"])
        .status()
        .context("failed to execute reg.exe")?;
    if status.success() {
        Ok(())
    } else {
        bail!("reg delete failed with status {status}")
    }
}

#[cfg(not(windows))]
fn remove_windows_run_entry() -> Result<()> {
    bail!("Windows autostart can only be removed on Windows")
}

#[cfg(windows)]
fn windows_run_entry_status() -> Result<PlatformEntryStatus> {
    let output = Command::new("reg")
        .args(["query", WINDOWS_RUN_KEY, "/v", WINDOWS_RUN_VALUE])
        .output()
        .context("failed to execute reg.exe")?;
    let command = if output.status.success() {
        parse_windows_reg_query(&String::from_utf8_lossy(&output.stdout))
    } else {
        None
    };
    Ok(PlatformEntryStatus {
        supported: true,
        kind: "windows_run_registry",
        installed: command.is_some(),
        location: Some(format!(r"{WINDOWS_RUN_KEY}\{WINDOWS_RUN_VALUE}")),
        command,
    })
}

#[cfg(not(windows))]
fn windows_run_entry_status() -> Result<PlatformEntryStatus> {
    Ok(PlatformEntryStatus {
        supported: true,
        kind: "windows_run_registry",
        installed: false,
        location: Some(format!(r"{WINDOWS_RUN_KEY}\{WINDOWS_RUN_VALUE}")),
        command: None,
    })
}

#[cfg(windows)]
fn parse_windows_reg_query(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let line = line.trim();
        if !line.starts_with(WINDOWS_RUN_VALUE) {
            return None;
        }
        let (_, rest) = line.split_once("REG_SZ")?;
        Some(rest.trim().to_string())
    })
}

#[cfg(any(windows, test))]
fn windows_run_command_line(args: &[String]) -> String {
    args.iter()
        .map(|arg| quote_windows_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(any(windows, test))]
fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty()
        && !arg
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, '"' | '\\'))
    {
        return arg.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0;
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
                quoted.push(ch);
                backslashes = 0;
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

fn escape_xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn unescape_xml(text: &str) -> String {
    text.replace("&apos;", "'")
        .replace("&quot;", "\"")
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&")
}

fn remove_file_if_exists(path: PathBuf) -> Result<()> {
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_plist_escapes_program_arguments() {
        let plist = macos_launch_agent_plist(
            &[
                "/Applications/Tabby&Mew.app/TabbyMew".to_string(),
                "start".to_string(),
                "--state-dir".to_string(),
                "/tmp/a < b".to_string(),
            ],
            Path::new("/tmp/tabbymew.log"),
        );

        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("/Applications/Tabby&amp;Mew.app/TabbyMew"));
        assert!(plist.contains("/tmp/a &lt; b"));
        assert_eq!(
            macos_program_arguments_summary(&plist).as_deref(),
            Some("/Applications/Tabby&Mew.app/TabbyMew start --state-dir /tmp/a < b")
        );
    }

    #[test]
    fn windows_command_line_quotes_spaces_and_backslashes() {
        let command = windows_run_command_line(&[
            r"C:\Program Files\TabbyMew\TabbyMew.exe".to_string(),
            "start".to_string(),
            "--state-dir".to_string(),
            r"C:\Users\me\Tabby Mew".to_string(),
        ]);

        assert_eq!(
            command,
            r#""C:\Program Files\TabbyMew\TabbyMew.exe" start --state-dir "C:\Users\me\Tabby Mew""#
        );
    }

    #[test]
    fn autostart_status_reports_saved_default_as_disabled() {
        let entry = PlatformEntryStatus {
            supported: true,
            kind: "test",
            installed: false,
            location: None,
            command: None,
        };

        assert_eq!(autostart_status(false, &entry), "disabled");
        assert_eq!(autostart_message(false, &entry), "autostart is disabled");
    }

    #[test]
    fn autostart_backend_support_matches_product_targets() {
        let supported = platform_autostart_supported();
        if matches!(
            platform::current(),
            platform::Platform::Macos | platform::Platform::Windows
        ) {
            assert!(supported);
        } else {
            assert!(!supported);
        }
    }
}
