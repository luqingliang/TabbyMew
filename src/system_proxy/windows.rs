use super::*;

#[cfg(any(target_os = "windows", test))]
pub(super) fn windows_status_with_reader(
    target: Option<&SystemProxyTarget>,
    read: &WindowsProxyReader<'_>,
) -> SystemProxyStatus {
    match read() {
        Ok(state) => windows_status_from_state(target, state),
        Err(err) => SystemProxyStatus {
            platform: platform::Platform::Windows.name(),
            supported: platform::Platform::Windows.supports_system_proxy(),
            enabled: false,
            managed: false,
            matches_target: false,
            target_recorded: false,
            protocol: SystemProxyProtocol::Auto,
            target: target.cloned(),
            error: Some(format!("failed to read Windows system proxy: {err}")),
        },
    }
}

#[cfg(any(target_os = "windows", test))]
pub(super) fn windows_status_from_state(
    target: Option<&SystemProxyTarget>,
    state: WindowsProxyState,
) -> SystemProxyStatus {
    let enabled = state.enabled;
    let matches_target = enabled && target.is_some_and(|target| state.matches_target(target));
    let error = system_proxy_status_error(target, enabled, matches_target);

    SystemProxyStatus {
        platform: platform::Platform::Windows.name(),
        supported: platform::Platform::Windows.supports_system_proxy(),
        enabled,
        managed: matches_target,
        matches_target,
        target_recorded: false,
        protocol: SystemProxyProtocol::Auto,
        target: target.cloned(),
        error,
    }
}

#[cfg(any(target_os = "windows", test))]
pub(super) fn windows_switch_with_reader(
    target: Option<&SystemProxyTarget>,
    switch: SystemProxySwitch,
    read: &WindowsProxyReader<'_>,
    apply: &WindowsProxyApplier<'_>,
) -> Result<SystemProxyStatus> {
    if matches!(switch, SystemProxySwitch::Enable) && target.is_none() {
        bail!(NO_LOCAL_SYSTEM_PROXY_TARGET);
    }

    if matches!(switch, SystemProxySwitch::Disable) {
        let before = windows_status_with_reader(target, read);
        if !before.managed {
            return Ok(before);
        }
    }

    apply(target, switch)?;
    Ok(windows_status_with_reader(target, read))
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct WindowsProxyState {
    pub(super) enabled: bool,
    pub(super) proxy_server: String,
    pub(super) http: Option<SystemProxyEndpoint>,
    pub(super) https: Option<SystemProxyEndpoint>,
    pub(super) socks: Option<SystemProxyEndpoint>,
}

#[cfg(any(target_os = "windows", test))]
impl WindowsProxyState {
    pub(super) fn from_registry_values(
        proxy_enable: Option<u32>,
        proxy_server: Option<String>,
    ) -> Self {
        let proxy_server = proxy_server.unwrap_or_default();
        let endpoints = parse_windows_proxy_server(&proxy_server);
        Self {
            enabled: proxy_enable.unwrap_or_default() != 0,
            proxy_server,
            http: endpoints.http,
            https: endpoints.https,
            socks: endpoints.socks,
        }
    }

    pub(super) fn matches_target(&self, target: &SystemProxyTarget) -> bool {
        self.http == target.http && self.https == target.https && self.socks == target.socks
    }

    pub(super) fn needs_canonical_rewrite(&self, target: &SystemProxyTarget) -> bool {
        self.enabled
            && self.matches_target(target)
            && self.proxy_server.trim() != windows_proxy_server_value(target)
    }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct WindowsProxyEndpoints {
    pub(super) http: Option<SystemProxyEndpoint>,
    pub(super) https: Option<SystemProxyEndpoint>,
    pub(super) socks: Option<SystemProxyEndpoint>,
}

#[cfg(any(target_os = "windows", test))]
pub(super) fn parse_windows_proxy_server(proxy_server: &str) -> WindowsProxyEndpoints {
    let mut endpoints = WindowsProxyEndpoints::default();
    let proxy_server = proxy_server.trim();
    if proxy_server.is_empty() {
        return endpoints;
    }

    let mut saw_protocol_value = false;
    for item in proxy_server.split(';') {
        let item = item.trim();
        let Some((protocol, address)) = item.split_once('=') else {
            continue;
        };
        saw_protocol_value = true;
        let Some(endpoint) = parse_endpoint(strip_windows_proxy_uri_scheme(address.trim())) else {
            continue;
        };
        match protocol.trim().to_ascii_lowercase().as_str() {
            "http" => endpoints.http = Some(endpoint),
            "https" => endpoints.https = Some(endpoint),
            "socks" => endpoints.socks = Some(endpoint),
            _ => {}
        }
    }

    if saw_protocol_value {
        return endpoints;
    }

    if let Some(endpoint) = parse_endpoint(strip_windows_proxy_uri_scheme(proxy_server)) {
        endpoints.http = Some(endpoint.clone());
        endpoints.https = Some(endpoint);
    }
    endpoints
}

#[cfg(any(target_os = "windows", test))]
pub(super) fn strip_windows_proxy_uri_scheme(address: &str) -> &str {
    let lowercase = address.to_ascii_lowercase();
    for scheme in ["socks5://", "socks4://", "socks://", "https://", "http://"] {
        if lowercase.starts_with(scheme) {
            return &address[scheme.len()..];
        }
    }
    address
}

#[cfg(any(target_os = "windows", test))]
pub(super) fn windows_proxy_server_value(target: &SystemProxyTarget) -> String {
    let mut parts = Vec::new();
    if let Some(endpoint) = target.http.as_ref() {
        parts.push(format!("http={}", endpoint.address));
    }
    if let Some(endpoint) = target.https.as_ref() {
        parts.push(format!("https={}", endpoint.address));
    }
    if let Some(endpoint) = target.socks.as_ref() {
        parts.push(format!("socks={}", windows_socks_proxy_value(endpoint)));
    }
    parts.join(";")
}

#[cfg(any(target_os = "windows", test))]
pub(super) fn windows_socks_proxy_value(endpoint: &SystemProxyEndpoint) -> String {
    format!("socks5://{}", endpoint.address)
}

#[cfg(target_os = "windows")]
pub(super) fn windows_read_proxy_state() -> Result<WindowsProxyState> {
    let Some(key) = WindowsRegistryKey::open_internet_settings()? else {
        return Ok(WindowsProxyState::default());
    };
    Ok(WindowsProxyState::from_registry_values(
        key.query_dword("ProxyEnable")?,
        key.query_string("ProxyServer")?,
    ))
}

#[cfg(target_os = "windows")]
pub(super) fn windows_apply_system_proxy(
    target: Option<&SystemProxyTarget>,
    switch: SystemProxySwitch,
) -> Result<()> {
    let key = WindowsRegistryKey::create_internet_settings()?;
    match switch {
        SystemProxySwitch::Enable => {
            let target = target.expect("target checked");
            let proxy_server = windows_proxy_server_value(target);
            if proxy_server.is_empty() {
                bail!(NO_LOCAL_SYSTEM_PROXY_TARGET);
            }
            key.set_dword("ProxyEnable", 1)?;
            key.set_string("ProxyServer", &proxy_server)?;
            key.set_string("ProxyOverride", WINDOWS_PROXY_OVERRIDE)?;
        }
        SystemProxySwitch::Disable => {
            key.set_dword("ProxyEnable", 0)?;
        }
    }
    windows_refresh_internet_settings()
}

#[cfg(target_os = "windows")]
pub(super) struct WindowsRegistryKey {
    handle: Hkey,
}

#[cfg(target_os = "windows")]
impl WindowsRegistryKey {
    fn open_internet_settings() -> Result<Option<Self>> {
        let mut handle = 0;
        let path = wide_null(WINDOWS_INTERNET_SETTINGS_KEY);
        let status = unsafe {
            reg_open_key_ex_w(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut handle,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        windows_status(status, "open Windows Internet Settings registry key")?;
        Ok(Some(Self { handle }))
    }

    fn create_internet_settings() -> Result<Self> {
        let mut handle = 0;
        let mut disposition = 0;
        let path = wide_null(WINDOWS_INTERNET_SETTINGS_KEY);
        let status = unsafe {
            reg_create_key_ex_w(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                std::ptr::null_mut(),
                REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                std::ptr::null_mut(),
                &mut handle,
                &mut disposition,
            )
        };
        windows_status(status, "create Windows Internet Settings registry key")?;
        Ok(Self { handle })
    }

    fn query_dword(&self, name: &str) -> Result<Option<u32>> {
        let name = wide_null(name);
        let mut value_type = 0;
        let mut value = 0u32;
        let mut value_len = std::mem::size_of::<u32>() as u32;
        let status = unsafe {
            reg_query_value_ex_w(
                self.handle,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut value_type,
                &mut value as *mut u32 as *mut u8,
                &mut value_len,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        windows_status(status, "read Windows proxy DWORD registry value")?;
        if value_type != REG_DWORD || value_len != std::mem::size_of::<u32>() as u32 {
            return Ok(None);
        }
        Ok(Some(value))
    }

    fn query_string(&self, name: &str) -> Result<Option<String>> {
        let name = wide_null(name);
        let mut value_type = 0;
        let mut value_len = 0u32;
        let status = unsafe {
            reg_query_value_ex_w(
                self.handle,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut value_type,
                std::ptr::null_mut(),
                &mut value_len,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        windows_status(status, "measure Windows proxy string registry value")?;
        if value_type != REG_SZ && value_type != REG_EXPAND_SZ {
            return Ok(None);
        }
        if value_len == 0 {
            return Ok(Some(String::new()));
        }

        let mut bytes = vec![0u8; value_len as usize];
        let status = unsafe {
            reg_query_value_ex_w(
                self.handle,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut value_type,
                bytes.as_mut_ptr(),
                &mut value_len,
            )
        };
        windows_status(status, "read Windows proxy string registry value")?;
        Ok(Some(wide_bytes_to_string(&bytes[..value_len as usize])))
    }

    fn set_dword(&self, name: &str, value: u32) -> Result<()> {
        let name = wide_null(name);
        let status = unsafe {
            reg_set_value_ex_w(
                self.handle,
                name.as_ptr(),
                0,
                REG_DWORD,
                &value as *const u32 as *const u8,
                std::mem::size_of::<u32>() as u32,
            )
        };
        windows_status(status, "write Windows proxy DWORD registry value")
    }

    fn set_string(&self, name: &str, value: &str) -> Result<()> {
        let name = wide_null(name);
        let value = wide_null(value);
        let status = unsafe {
            reg_set_value_ex_w(
                self.handle,
                name.as_ptr(),
                0,
                REG_SZ,
                value.as_ptr() as *const u8,
                (value.len() * std::mem::size_of::<u16>()) as u32,
            )
        };
        windows_status(status, "write Windows proxy string registry value")
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsRegistryKey {
    fn drop(&mut self) {
        unsafe {
            let _ = reg_close_key(self.handle);
        }
    }
}

#[cfg(target_os = "windows")]
pub(super) fn windows_refresh_internet_settings() -> Result<()> {
    let changed = unsafe {
        internet_set_option_w(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        )
    };
    if changed == 0 {
        bail!("failed to notify Windows that Internet Settings changed");
    }
    let refreshed = unsafe {
        internet_set_option_w(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        )
    };
    if refreshed == 0 {
        bail!("failed to refresh Windows Internet Settings");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub(super) fn windows_status(status: Lstatus, action: &str) -> Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        bail!("{action}: Windows error {status}")
    }
}

#[cfg(target_os = "windows")]
pub(super) fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
pub(super) fn wide_bytes_to_string(bytes: &[u8]) -> String {
    let mut words = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        words.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    if let Some(end) = words.iter().position(|word| *word == 0) {
        words.truncate(end);
    }
    String::from_utf16_lossy(&words)
}

#[cfg(target_os = "windows")]
pub(super) type Hkey = isize;
#[cfg(target_os = "windows")]
pub(super) type Lstatus = i32;

#[cfg(target_os = "windows")]
pub(super) const HKEY_CURRENT_USER: Hkey = 0x80000001u32 as i32 as isize;
#[cfg(target_os = "windows")]
pub(super) const WINDOWS_INTERNET_SETTINGS_KEY: &str =
    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
#[cfg(target_os = "windows")]
pub(super) const ERROR_SUCCESS: Lstatus = 0;
#[cfg(target_os = "windows")]
pub(super) const ERROR_FILE_NOT_FOUND: Lstatus = 2;
#[cfg(target_os = "windows")]
pub(super) const KEY_QUERY_VALUE: u32 = 0x0001;
#[cfg(target_os = "windows")]
pub(super) const KEY_SET_VALUE: u32 = 0x0002;
#[cfg(target_os = "windows")]
pub(super) const REG_OPTION_NON_VOLATILE: u32 = 0;
#[cfg(target_os = "windows")]
pub(super) const REG_SZ: u32 = 1;
#[cfg(target_os = "windows")]
pub(super) const REG_EXPAND_SZ: u32 = 2;
#[cfg(target_os = "windows")]
pub(super) const REG_DWORD: u32 = 4;
#[cfg(target_os = "windows")]
pub(super) const INTERNET_OPTION_REFRESH: u32 = 37;
#[cfg(target_os = "windows")]
pub(super) const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;

#[cfg(target_os = "windows")]
#[link(name = "advapi32")]
unsafe extern "system" {
    #[link_name = "RegOpenKeyExW"]
    fn reg_open_key_ex_w(
        h_key: Hkey,
        sub_key: *const u16,
        options: u32,
        desired: u32,
        result: *mut Hkey,
    ) -> Lstatus;

    #[link_name = "RegCreateKeyExW"]
    fn reg_create_key_ex_w(
        h_key: Hkey,
        sub_key: *const u16,
        reserved: u32,
        class: *mut u16,
        options: u32,
        desired: u32,
        security_attributes: *mut std::ffi::c_void,
        result: *mut Hkey,
        disposition: *mut u32,
    ) -> Lstatus;

    #[link_name = "RegQueryValueExW"]
    fn reg_query_value_ex_w(
        h_key: Hkey,
        value_name: *const u16,
        reserved: *mut u32,
        value_type: *mut u32,
        data: *mut u8,
        data_len: *mut u32,
    ) -> Lstatus;

    #[link_name = "RegSetValueExW"]
    fn reg_set_value_ex_w(
        h_key: Hkey,
        value_name: *const u16,
        reserved: u32,
        value_type: u32,
        data: *const u8,
        data_len: u32,
    ) -> Lstatus;

    #[link_name = "RegCloseKey"]
    fn reg_close_key(h_key: Hkey) -> Lstatus;
}

#[cfg(target_os = "windows")]
#[link(name = "wininet")]
unsafe extern "system" {
    #[link_name = "InternetSetOptionW"]
    fn internet_set_option_w(
        internet: *mut std::ffi::c_void,
        option: u32,
        buffer: *mut std::ffi::c_void,
        buffer_len: u32,
    ) -> i32;
}
