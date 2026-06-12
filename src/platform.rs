use std::{env, path::PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Macos,
    Windows,
    Linux,
    Unsupported,
}

#[cfg(target_os = "macos")]
pub const CURRENT: Platform = Platform::Macos;
#[cfg(target_os = "windows")]
pub const CURRENT: Platform = Platform::Windows;
#[cfg(target_os = "linux")]
pub const CURRENT: Platform = Platform::Linux;
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub const CURRENT: Platform = Platform::Unsupported;

pub const TUN_EGRESS_BINDING_UNSUPPORTED_WARNING: &str = "egress interface binding is not implemented on this platform; TUN will rely on proxy server bypass rules";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemDnsFlushCommand {
    pub program: &'static str,
    pub args: &'static [&'static str],
}

const WINDOWS_DNS_FLUSH_COMMANDS: &[SystemDnsFlushCommand] = &[SystemDnsFlushCommand {
    program: "ipconfig",
    args: &["/flushdns"],
}];

const MACOS_DNS_FLUSH_COMMANDS: &[SystemDnsFlushCommand] = &[
    SystemDnsFlushCommand {
        program: "dscacheutil",
        args: &["-flushcache"],
    },
    SystemDnsFlushCommand {
        program: "killall",
        args: &["-HUP", "mDNSResponder"],
    },
];

impl Platform {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "macos" | "darwin" => Some(Self::Macos),
            "windows" | "win32" => Some(Self::Windows),
            "linux" => Some(Self::Linux),
            "unsupported" | "unknown" | "other" => Some(Self::Unsupported),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Unsupported => "unsupported",
        }
    }

    pub const fn supports_system_proxy(self) -> bool {
        matches!(self, Self::Macos | Self::Windows)
    }

    pub const fn supports_tun(self) -> bool {
        matches!(self, Self::Macos | Self::Windows | Self::Linux)
    }

    pub const fn supports_tun_privileged_helper(self) -> bool {
        matches!(self, Self::Macos | Self::Windows)
    }

    pub const fn supports_tun_egress_binding(self) -> bool {
        matches!(self, Self::Macos | Self::Windows)
    }

    pub const fn uses_tun_packet_information(self) -> bool {
        matches!(self, Self::Macos)
    }

    pub const fn tun_requires_privilege(self, auto_route: bool) -> bool {
        self.supports_tun() && (matches!(self, Self::Windows) || auto_route)
    }

    pub fn tun_requires_permission_detail(self) -> String {
        match self {
            Self::Macos => {
                "TUN auto route needs macOS administrator authorization; Start TUN will prompt for permission"
                    .to_string()
            }
            Self::Windows => {
                "Windows TUN mode requires Administrator privileges to create the Wintun adapter"
                    .to_string()
            }
            other => format!(
                "TUN auto route requires administrator/root privileges on {}",
                other.name()
            ),
        }
    }
}

pub const fn current() -> Platform {
    CURRENT
}

pub fn name() -> &'static str {
    current().name()
}

pub fn default_state_dir() -> Option<PathBuf> {
    match current() {
        Platform::Windows => env::var_os("APPDATA")
            .map(|path| PathBuf::from(path).join("TabbyMew"))
            .or_else(|| {
                env::var_os("USERPROFILE").map(|path| PathBuf::from(path).join(".tabbymew"))
            }),
        Platform::Macos | Platform::Linux | Platform::Unsupported => {
            env::var_os("HOME").map(|path| PathBuf::from(path).join(".tabbymew"))
        }
    }
}

#[cfg_attr(any(target_os = "macos", target_os = "windows"), allow(dead_code))]
pub fn system_proxy_supported() -> bool {
    current().supports_system_proxy()
}

#[cfg_attr(any(target_os = "macos", target_os = "windows"), allow(dead_code))]
pub fn system_proxy_unsupported_message() -> String {
    format!("{} system proxy backend is not implemented yet", name())
}

pub fn tun_supported() -> bool {
    current().supports_tun()
}

pub fn tun_privileged_helper_supported() -> bool {
    current().supports_tun_privileged_helper()
}

pub fn tun_egress_binding_supported() -> bool {
    current().supports_tun_egress_binding()
}

pub fn tun_egress_binding_supported_for_name(name: &str) -> bool {
    Platform::from_name(name)
        .map(|platform| platform.supports_tun_egress_binding())
        .unwrap_or(false)
}

pub fn tun_egress_binding_expected_for_snapshot(platform: Option<&str>) -> bool {
    platform
        .map(tun_egress_binding_supported_for_name)
        .unwrap_or(true)
}

pub fn tun_packet_information() -> bool {
    current().uses_tun_packet_information()
}

pub fn tun_requires_privilege(auto_route: bool) -> bool {
    current().tun_requires_privilege(auto_route)
}

#[cfg(test)]
pub fn tun_requires_privilege_for_platform(
    auto_route: bool,
    supported: bool,
    platform: &str,
) -> bool {
    supported
        && Platform::from_name(platform)
            .map(|platform| platform.tun_requires_privilege(auto_route))
            .unwrap_or(auto_route)
}

pub fn tun_requires_permission_detail() -> String {
    current().tun_requires_permission_detail()
}

pub fn windows_tun_runtime_dll_required() -> bool {
    current() == Platform::Windows
}

pub fn system_dns_flush_commands_for_platform(
    platform: Platform,
) -> &'static [SystemDnsFlushCommand] {
    match platform {
        Platform::Windows => WINDOWS_DNS_FLUSH_COMMANDS,
        Platform::Macos => MACOS_DNS_FLUSH_COMMANDS,
        Platform::Linux | Platform::Unsupported => &[],
    }
}

pub async fn flush_system_dns_cache() -> anyhow::Result<bool> {
    let commands = system_dns_flush_commands_for_platform(current());
    if commands.is_empty() {
        return Ok(false);
    }
    run_system_dns_flush_commands(commands).await?;
    Ok(true)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn run_system_dns_flush_commands(commands: &[SystemDnsFlushCommand]) -> anyhow::Result<()> {
    use anyhow::{Context, bail};
    use std::time::Duration;
    use tokio::process::Command;

    let command_timeout = Duration::from_secs(5);
    for command in commands {
        let mut process = Command::new(command.program);
        process.kill_on_drop(true);
        let output_future = process.args(command.args).output();
        let output = tokio::time::timeout(command_timeout, output_future)
            .await
            .with_context(|| {
                format!(
                    "{} timed out after {:?}",
                    system_dns_flush_command_label(command),
                    command_timeout
                )
            })?
            .with_context(|| {
                format!("failed to run {}", system_dns_flush_command_label(command))
            })?;
        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            };
            bail!(
                "{} exited with status {}{}",
                system_dns_flush_command_label(command),
                output.status,
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            );
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
async fn run_system_dns_flush_commands(_commands: &[SystemDnsFlushCommand]) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn system_dns_flush_command_label(command: &SystemDnsFlushCommand) -> String {
    std::iter::once(command.program)
        .chain(command.args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_capability_matrix_is_explicit() {
        assert!(Platform::Macos.supports_system_proxy());
        assert!(Platform::Windows.supports_system_proxy());
        assert!(!Platform::Linux.supports_system_proxy());

        assert!(Platform::Macos.supports_tun());
        assert!(Platform::Windows.supports_tun());
        assert!(Platform::Linux.supports_tun());
        assert!(!Platform::Unsupported.supports_tun());

        assert!(Platform::Macos.supports_tun_egress_binding());
        assert!(Platform::Windows.supports_tun_egress_binding());
        assert!(!Platform::Linux.supports_tun_egress_binding());
    }

    #[test]
    fn tun_privilege_rules_are_platform_specific() {
        assert!(Platform::Windows.tun_requires_privilege(false));
        assert!(Platform::Windows.tun_requires_privilege(true));
        assert!(!Platform::Macos.tun_requires_privilege(false));
        assert!(Platform::Macos.tun_requires_privilege(true));
        assert!(!Platform::Linux.tun_requires_privilege(false));
        assert!(Platform::Linux.tun_requires_privilege(true));
    }

    #[test]
    fn snapshot_binding_expectation_handles_unknown_values() {
        assert!(tun_egress_binding_expected_for_snapshot(None));
        assert!(tun_egress_binding_expected_for_snapshot(Some("macos")));
        assert!(tun_egress_binding_expected_for_snapshot(Some("windows")));
        assert!(!tun_egress_binding_expected_for_snapshot(Some("linux")));
        assert!(!tun_egress_binding_expected_for_snapshot(Some("other-os")));
    }

    #[test]
    fn system_dns_flush_commands_match_product_platforms() {
        assert_eq!(
            system_dns_flush_commands_for_platform(Platform::Windows),
            &[SystemDnsFlushCommand {
                program: "ipconfig",
                args: &["/flushdns"],
            }]
        );
        assert_eq!(
            system_dns_flush_commands_for_platform(Platform::Macos),
            &[
                SystemDnsFlushCommand {
                    program: "dscacheutil",
                    args: &["-flushcache"],
                },
                SystemDnsFlushCommand {
                    program: "killall",
                    args: &["-HUP", "mDNSResponder"],
                },
            ]
        );
        assert!(system_dns_flush_commands_for_platform(Platform::Linux).is_empty());
        assert!(system_dns_flush_commands_for_platform(Platform::Unsupported).is_empty());
    }
}
