use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SystemProxyStatus {
    pub platform: &'static str,
    pub supported: bool,
    pub enabled: bool,
    pub managed: bool,
    pub matches_target: bool,
    pub target_recorded: bool,
    pub protocol: SystemProxyProtocol,
    pub target: Option<SystemProxyTarget>,
    pub error: Option<String>,
}

impl SystemProxyStatus {
    pub fn with_target_recorded(mut self, target_recorded: bool) -> Self {
        self.target_recorded = target_recorded;
        self.managed = target_recorded && self.matches_target;
        self
    }

    pub fn with_protocol(mut self, protocol: SystemProxyProtocol) -> Self {
        self.protocol = protocol;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemProxyTarget {
    pub source: String,
    pub http: Option<SystemProxyEndpoint>,
    pub https: Option<SystemProxyEndpoint>,
    pub socks: Option<SystemProxyEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemProxyEndpoint {
    pub host: String,
    pub port: u16,
    pub address: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemProxyProtocol {
    #[default]
    Auto,
    Socks,
    HttpConnect,
}

impl SystemProxyProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Socks => "socks",
            Self::HttpConnect => "http-connect",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "Auto",
            Self::Socks => "SOCKS",
            Self::HttpConnect => "HTTP CONNECT",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" | "automatic" | "a" => Some(Self::Auto),
            "socks" | "socks5" | "s" => Some(Self::Socks),
            "http-connect" | "http_connect" | "http" | "connect" | "h" => Some(Self::HttpConnect),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemProxySwitch {
    Enable,
    Disable,
}

pub fn status_for_target(target: Option<&SystemProxyTarget>) -> SystemProxyStatus {
    #[cfg(target_os = "macos")]
    {
        macos_status_with_runner(target, &run_command)
    }

    #[cfg(target_os = "windows")]
    {
        windows_status_with_reader(target, &windows_read_proxy_state)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        unsupported_status(target.cloned())
    }
}

pub fn switch_with_protocol(
    inbounds: &[String],
    protocol: SystemProxyProtocol,
    switch: SystemProxySwitch,
) -> Result<SystemProxyStatus> {
    let target = select_target_with_protocol(inbounds, protocol);
    switch_target(target.as_ref(), switch)
}

pub fn switch_target(
    target: Option<&SystemProxyTarget>,
    switch: SystemProxySwitch,
) -> Result<SystemProxyStatus> {
    if matches!(switch, SystemProxySwitch::Enable) && target.is_none() {
        bail!(NO_LOCAL_SYSTEM_PROXY_TARGET);
    }

    #[cfg(target_os = "macos")]
    {
        macos_switch(target, switch)
    }

    #[cfg(target_os = "windows")]
    {
        windows_switch_with_reader(
            target,
            switch,
            &windows_read_proxy_state,
            &|target, switch| windows_apply_system_proxy(target, switch),
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if matches!(switch, SystemProxySwitch::Disable) {
            return Ok(unsupported_status(target.cloned()));
        }
        bail!("{}", platform::system_proxy_unsupported_message());
    }
}

pub fn disable_target_without_prompt(
    target: Option<&SystemProxyTarget>,
) -> Result<SystemProxyStatus> {
    #[cfg(target_os = "macos")]
    {
        macos_disable_managed_without_prompt(target)
    }

    #[cfg(target_os = "windows")]
    {
        windows_switch_with_reader(
            target,
            SystemProxySwitch::Disable,
            &windows_read_proxy_state,
            &|target, switch| windows_apply_system_proxy(target, switch),
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        switch_target(target, SystemProxySwitch::Disable)
    }
}

pub fn target_from_inbounds(inbounds: &[String]) -> Option<SystemProxyTarget> {
    target_from_inbounds_with_protocol(inbounds, SystemProxyProtocol::Auto)
}

pub fn target_from_inbounds_with_protocol(
    inbounds: &[String],
    protocol: SystemProxyProtocol,
) -> Option<SystemProxyTarget> {
    select_target_with_protocol(inbounds, protocol)
}

pub fn clear_session_authorization() {
    #[cfg(target_os = "macos")]
    macos_clear_cached_authorization();
}

pub fn reapply_target_if_needed(target: Option<&SystemProxyTarget>) -> Result<bool> {
    #[cfg(target_os = "windows")]
    {
        let Some(target) = target else {
            return Ok(false);
        };
        let state = windows_read_proxy_state()?;
        if state.needs_canonical_rewrite(target) {
            windows_apply_system_proxy(Some(target), SystemProxySwitch::Enable)?;
            return Ok(true);
        }
        Ok(false)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = target;
        Ok(false)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn unsupported_status(target: Option<SystemProxyTarget>) -> SystemProxyStatus {
    let error = if target.is_none() {
        NO_LOCAL_SYSTEM_PROXY_TARGET.to_string()
    } else {
        platform::system_proxy_unsupported_message()
    };

    SystemProxyStatus {
        platform: platform::name(),
        supported: platform::system_proxy_supported(),
        enabled: false,
        managed: false,
        matches_target: false,
        target_recorded: false,
        protocol: SystemProxyProtocol::Auto,
        target,
        error: Some(error),
    }
}
