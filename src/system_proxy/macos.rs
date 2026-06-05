use super::*;

pub(super) fn macos_status_with_runner(
    target: Option<&SystemProxyTarget>,
    run: &CommandRunner<'_>,
) -> SystemProxyStatus {
    let proxy_state = match run(MACOS_SCUTIL, &[String::from("--proxy")]) {
        Ok(output) => parse_macos_proxy_state(&output),
        Err(err) => {
            return SystemProxyStatus {
                platform: platform::Platform::Macos.name(),
                supported: platform::Platform::Macos.supports_system_proxy(),
                enabled: false,
                managed: false,
                matches_target: false,
                target_recorded: false,
                protocol: SystemProxyProtocol::Auto,
                target: target.cloned(),
                error: Some(format!("failed to read macOS system proxy: {err}")),
            };
        }
    };
    let enabled = proxy_state.enabled();
    let matches_target = target.is_some_and(|target| proxy_state.matches_target(target));
    let error = system_proxy_status_error(target, enabled, matches_target);

    SystemProxyStatus {
        platform: platform::Platform::Macos.name(),
        supported: platform::Platform::Macos.supports_system_proxy(),
        enabled,
        managed: matches_target,
        matches_target,
        target_recorded: false,
        protocol: SystemProxyProtocol::Auto,
        target: target.cloned(),
        error,
    }
}

#[cfg(target_os = "macos")]
pub(super) fn macos_switch(
    target: Option<&SystemProxyTarget>,
    switch: SystemProxySwitch,
) -> Result<SystemProxyStatus> {
    macos_switch_with_runner(target, switch, &run_command, &|target, switch| {
        macos_apply_system_configuration_with_session_authorization(
            target,
            switch,
            macos_authorization_is_cached(),
            &macos_apply_system_configuration,
            &macos_apply_system_configuration_authorized,
        )
    })
}

#[cfg(target_os = "macos")]
pub(super) fn macos_disable_managed_without_prompt(
    target: Option<&SystemProxyTarget>,
) -> Result<SystemProxyStatus> {
    macos_disable_managed_without_prompt_with_runner(target, &run_command, &|target, switch| {
        macos_apply_system_configuration_with_session_authorization(
            target,
            switch,
            macos_authorization_is_cached(),
            &macos_apply_system_configuration,
            &macos_apply_system_configuration_authorized_without_prompt,
        )
    })
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_disable_managed_without_prompt_with_runner(
    target: Option<&SystemProxyTarget>,
    run: &CommandRunner<'_>,
    apply_without_prompt: &SystemProxyApplier<'_>,
) -> Result<SystemProxyStatus> {
    macos_switch_with_runner(
        target,
        SystemProxySwitch::Disable,
        run,
        apply_without_prompt,
    )
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_switch_with_runner(
    target: Option<&SystemProxyTarget>,
    switch: SystemProxySwitch,
    run: &CommandRunner<'_>,
    apply: &SystemProxyApplier<'_>,
) -> Result<SystemProxyStatus> {
    if matches!(switch, SystemProxySwitch::Enable) && target.is_none() {
        bail!(NO_LOCAL_SYSTEM_PROXY_TARGET);
    }

    if matches!(switch, SystemProxySwitch::Disable) {
        let before = macos_status_with_runner(target, run);
        if !before.managed {
            return Ok(before);
        }
    }

    apply(target, switch)?;
    Ok(macos_status_with_runner(target, run))
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_apply_system_configuration_with_session_authorization(
    target: Option<&SystemProxyTarget>,
    switch: SystemProxySwitch,
    has_cached_authorization: bool,
    apply_without_authorization: &SystemProxyApplier<'_>,
    apply_with_authorization: &SystemProxyApplier<'_>,
) -> Result<()> {
    if has_cached_authorization {
        tracing::debug!(
            action = ?switch,
            "macOS system proxy authorization cache hit; reusing session authorization"
        );
        return apply_with_authorization(target, switch)
            .context("failed to write macOS network preferences with cached authorization");
    }

    match apply_without_authorization(target, switch) {
        Ok(()) => {
            tracing::debug!(
                action = ?switch,
                "macOS system proxy preferences updated without authorization"
            );
            Ok(())
        }
        Err(err) => {
            tracing::debug!(
                action = ?switch,
                error = %err,
                "macOS system proxy authorization cache miss; requesting session authorization"
            );
            apply_with_authorization(target, switch).with_context(|| {
                format!("failed to write macOS network preferences without authorization: {err}")
            })
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) fn macos_apply_system_configuration(
    target: Option<&SystemProxyTarget>,
    switch: SystemProxySwitch,
) -> Result<()> {
    use system_configuration::{core_foundation::string::CFString, preferences::SCPreferences};

    let prefs = SCPreferences::default(&CFString::new("TabbyMew"));
    macos_apply_system_configuration_with_preferences(&prefs, target, switch)
}

#[cfg(target_os = "macos")]
pub(super) fn macos_apply_system_configuration_authorized(
    target: Option<&SystemProxyTarget>,
    switch: SystemProxySwitch,
) -> Result<()> {
    let mut cache = macos_authorization_cache()
        .lock()
        .map_err(|_| anyhow::anyhow!("macOS administrator authorization cache is poisoned"))?;
    let had_cached_authorization = cache.is_some();

    match macos_apply_system_configuration_with_cached_authorization(
        &mut cache,
        target,
        switch,
        MacAuthorizationInteraction::Allowed,
    ) {
        Ok(()) => Ok(()),
        Err(err) if had_cached_authorization => {
            *cache = None;
            macos_apply_system_configuration_with_cached_authorization(
                &mut cache,
                target,
                switch,
                MacAuthorizationInteraction::Allowed,
            )
                .with_context(|| {
                    format!("cached macOS administrator authorization failed; reauthorization did not recover: {err}")
                })
        }
        Err(err) => Err(err),
    }
}

#[cfg(target_os = "macos")]
pub(super) fn macos_apply_system_configuration_authorized_without_prompt(
    target: Option<&SystemProxyTarget>,
    switch: SystemProxySwitch,
) -> Result<()> {
    let mut cache = macos_authorization_cache()
        .lock()
        .map_err(|_| anyhow::anyhow!("macOS administrator authorization cache is poisoned"))?;
    let had_cached_authorization = cache.is_some();

    match macos_apply_system_configuration_with_cached_authorization(
        &mut cache,
        target,
        switch,
        MacAuthorizationInteraction::Disallowed,
    ) {
        Ok(()) => Ok(()),
        Err(err) if had_cached_authorization => {
            *cache = None;
            macos_apply_system_configuration_with_cached_authorization(
                &mut cache,
                target,
                switch,
                MacAuthorizationInteraction::Disallowed,
            )
            .with_context(|| {
                format!("cached macOS administrator authorization failed; noninteractive reauthorization did not recover: {err}")
            })
        }
        Err(err) => Err(err),
    }
}

#[cfg(target_os = "macos")]
pub(super) fn macos_apply_system_configuration_with_cached_authorization(
    cache: &mut Option<MacAuthorization>,
    target: Option<&SystemProxyTarget>,
    switch: SystemProxySwitch,
    interaction: MacAuthorizationInteraction,
) -> Result<()> {
    if cache.is_none() {
        *cache = Some(MacAuthorization::new(interaction)?);
    }
    let authorization = cache
        .as_ref()
        .expect("macOS authorization cache must be initialized");
    let authorized = MacAuthorizedPreferences::new(authorization)?;
    macos_apply_system_configuration_with_preferences(&authorized.prefs, target, switch)
}

#[cfg(target_os = "macos")]
pub(super) fn macos_authorization_cache() -> &'static Mutex<Option<MacAuthorization>> {
    static CACHE: OnceLock<Mutex<Option<MacAuthorization>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

#[cfg(target_os = "macos")]
pub(super) fn macos_authorization_is_cached() -> bool {
    macos_authorization_cache()
        .lock()
        .map(|cache| cache.is_some())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
pub(super) fn macos_clear_cached_authorization() {
    if let Ok(mut cache) = macos_authorization_cache().lock() {
        *cache = None;
    }
}

#[cfg(target_os = "macos")]
pub(super) fn macos_apply_system_configuration_with_preferences(
    prefs: &system_configuration::preferences::SCPreferences,
    target: Option<&SystemProxyTarget>,
    switch: SystemProxySwitch,
) -> Result<()> {
    use system_configuration::{
        core_foundation::base::TCFType,
        network_configuration::SCNetworkService,
        sys::{
            network_configuration::{
                SCNetworkProtocolSetConfiguration, SCNetworkProtocolSetEnabled,
                SCNetworkServiceAddProtocolType, SCNetworkServiceCopyProtocol,
                SCNetworkServiceGetEnabled,
            },
            preferences::{
                SCPreferencesApplyChanges, SCPreferencesCommitChanges, SCPreferencesLock,
                SCPreferencesUnlock,
            },
            schema_definitions::kSCEntNetProxies,
        },
    };

    let prefs_ref = prefs.as_concrete_TypeRef();
    if unsafe { SCPreferencesLock(prefs_ref, 1) } == 0 {
        bail!("failed to lock macOS network preferences");
    }

    let result = (|| {
        let services = SCNetworkService::get_services(prefs);
        let mut configured_services = 0usize;
        for service in services.iter() {
            let service_ref = service.as_concrete_TypeRef();
            if unsafe { SCNetworkServiceGetEnabled(service_ref) } == 0 {
                continue;
            }

            let protocol_type = unsafe { kSCEntNetProxies };
            let mut protocol = unsafe { SCNetworkServiceCopyProtocol(service_ref, protocol_type) };
            if protocol.is_null() {
                if unsafe { SCNetworkServiceAddProtocolType(service_ref, protocol_type) } == 0 {
                    bail!("failed to add macOS proxy protocol to a network service");
                }
                protocol = unsafe { SCNetworkServiceCopyProtocol(service_ref, protocol_type) };
            }
            if protocol.is_null() {
                bail!("failed to load macOS proxy protocol for a network service");
            }

            let config = match switch {
                SystemProxySwitch::Enable => {
                    macos_proxy_config_dictionary(protocol, target.expect("target checked"))
                }
                SystemProxySwitch::Disable => macos_disabled_proxy_config_dictionary(protocol),
            };

            if unsafe { SCNetworkProtocolSetConfiguration(protocol, config.as_concrete_TypeRef()) }
                == 0
            {
                bail!("failed to set macOS proxy configuration");
            }
            if unsafe { SCNetworkProtocolSetEnabled(protocol, 1) } == 0 {
                bail!("failed to enable macOS proxy protocol");
            }
            configured_services += 1;
        }

        if configured_services == 0 {
            bail!("no enabled macOS network services were found");
        }
        if unsafe { SCPreferencesCommitChanges(prefs_ref) } == 0 {
            bail!("failed to commit macOS network preferences");
        }
        if unsafe { SCPreferencesApplyChanges(prefs_ref) } == 0 {
            bail!("failed to apply macOS network preferences");
        }
        Ok(())
    })();

    unsafe {
        SCPreferencesUnlock(prefs_ref);
    }

    result
}

#[cfg(target_os = "macos")]
pub(super) struct MacAuthorizedPreferences {
    prefs: system_configuration::preferences::SCPreferences,
}

#[cfg(target_os = "macos")]
impl MacAuthorizedPreferences {
    fn new(authorization: &MacAuthorization) -> Result<Self> {
        use std::ptr;

        use system_configuration::{
            core_foundation::{base::TCFType, string::CFString},
            preferences::SCPreferences,
            sys::preferences::SCPreferencesCreateWithAuthorization,
        };

        let name = CFString::new("TabbyMew");
        let prefs_ref = unsafe {
            SCPreferencesCreateWithAuthorization(
                ptr::null(),
                name.as_concrete_TypeRef(),
                ptr::null(),
                authorization.0,
            )
        };
        if prefs_ref.is_null() {
            bail!("failed to create authorized macOS network preferences");
        }

        Ok(Self {
            prefs: unsafe { SCPreferences::wrap_under_create_rule(prefs_ref) },
        })
    }
}

#[cfg(target_os = "macos")]
pub(super) struct MacAuthorization(system_configuration::sys::preferences::AuthorizationRef);

#[cfg(target_os = "macos")]
// The authorization handle is only accessed while protected by the global mutex.
unsafe impl Send for MacAuthorization {}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MacAuthorizationInteraction {
    Allowed,
    Disallowed,
}

#[cfg(target_os = "macos")]
impl MacAuthorization {
    fn new(interaction: MacAuthorizationInteraction) -> Result<Self> {
        use std::{ffi::c_void, os::raw::c_char, ptr};

        const AUTHORIZATION_FLAG_INTERACTION_ALLOWED: AuthorizationFlags = 1 << 0;
        const AUTHORIZATION_FLAG_EXTEND_RIGHTS: AuthorizationFlags = 1 << 1;
        const NETWORK_PREFERENCES_RIGHT: &[u8] = b"system.preferences.network\0";
        const SYSTEM_CONFIGURATION_NETWORK_RIGHT: &[u8] =
            b"system.services.systemconfiguration.network\0";

        let mut authorization = ptr::null();
        let mut right_items = [
            AuthorizationItem {
                name: NETWORK_PREFERENCES_RIGHT.as_ptr().cast::<c_char>(),
                value_length: 0,
                value: ptr::null_mut::<c_void>(),
                flags: 0,
            },
            AuthorizationItem {
                name: SYSTEM_CONFIGURATION_NETWORK_RIGHT.as_ptr().cast::<c_char>(),
                value_length: 0,
                value: ptr::null_mut::<c_void>(),
                flags: 0,
            },
        ];
        let rights = AuthorizationRights {
            count: right_items.len() as u32,
            items: right_items.as_mut_ptr(),
        };
        let mut flags = AUTHORIZATION_FLAG_EXTEND_RIGHTS;
        if matches!(interaction, MacAuthorizationInteraction::Allowed) {
            flags |= AUTHORIZATION_FLAG_INTERACTION_ALLOWED;
        }
        let status =
            unsafe { AuthorizationCreate(&rights, ptr::null(), flags, &mut authorization) };
        if status != 0 {
            bail!(
                "failed to request macOS administrator authorization ({interaction:?}): OSStatus {status}"
            );
        }
        if authorization.is_null() {
            bail!("macOS administrator authorization returned an empty handle");
        }

        Ok(Self(authorization))
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacAuthorization {
    fn drop(&mut self) {
        const AUTHORIZATION_FLAG_DESTROY_RIGHTS: AuthorizationFlags = 1 << 3;
        unsafe {
            let _ = AuthorizationFree(self.0, AUTHORIZATION_FLAG_DESTROY_RIGHTS);
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) type AuthorizationFlags = u32;

#[cfg(target_os = "macos")]
pub(super) type OsStatus = i32;

#[cfg(target_os = "macos")]
#[repr(C)]
pub(super) struct AuthorizationItem {
    name: *const std::os::raw::c_char,
    value_length: usize,
    value: *mut std::ffi::c_void,
    flags: u32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
pub(super) struct AuthorizationItemSet {
    count: u32,
    items: *mut AuthorizationItem,
}

#[cfg(target_os = "macos")]
pub(super) type AuthorizationRights = AuthorizationItemSet;

#[cfg(target_os = "macos")]
pub(super) type AuthorizationEnvironment = AuthorizationItemSet;

#[cfg(target_os = "macos")]
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn AuthorizationCreate(
        rights: *const AuthorizationRights,
        environment: *const AuthorizationEnvironment,
        flags: AuthorizationFlags,
        authorization: *mut system_configuration::sys::preferences::AuthorizationRef,
    ) -> OsStatus;

    fn AuthorizationFree(
        authorization: system_configuration::sys::preferences::AuthorizationRef,
        flags: AuthorizationFlags,
    ) -> OsStatus;
}

#[cfg(target_os = "macos")]
pub(super) fn macos_proxy_config_dictionary(
    protocol: system_configuration::sys::network_configuration::SCNetworkProtocolRef,
    target: &SystemProxyTarget,
) -> system_configuration::core_foundation::dictionary::CFDictionary<
    system_configuration::core_foundation::string::CFString,
    system_configuration::core_foundation::base::CFType,
> {
    use system_configuration::sys::schema_definitions::{
        kSCPropNetProxiesHTTPEnable, kSCPropNetProxiesHTTPPort, kSCPropNetProxiesHTTPProxy,
        kSCPropNetProxiesHTTPSEnable, kSCPropNetProxiesHTTPSPort, kSCPropNetProxiesHTTPSProxy,
        kSCPropNetProxiesSOCKSEnable, kSCPropNetProxiesSOCKSPort, kSCPropNetProxiesSOCKSProxy,
    };

    let mut config = macos_existing_proxy_config(protocol);
    macos_set_proxy_fields(
        &mut config,
        unsafe { kSCPropNetProxiesHTTPEnable },
        unsafe { kSCPropNetProxiesHTTPProxy },
        unsafe { kSCPropNetProxiesHTTPPort },
        target.http.as_ref(),
    );
    macos_set_proxy_fields(
        &mut config,
        unsafe { kSCPropNetProxiesHTTPSEnable },
        unsafe { kSCPropNetProxiesHTTPSProxy },
        unsafe { kSCPropNetProxiesHTTPSPort },
        target.https.as_ref(),
    );
    macos_set_proxy_fields(
        &mut config,
        unsafe { kSCPropNetProxiesSOCKSEnable },
        unsafe { kSCPropNetProxiesSOCKSProxy },
        unsafe { kSCPropNetProxiesSOCKSPort },
        target.socks.as_ref(),
    );
    config.to_immutable()
}

#[cfg(target_os = "macos")]
pub(super) fn macos_disabled_proxy_config_dictionary(
    protocol: system_configuration::sys::network_configuration::SCNetworkProtocolRef,
) -> system_configuration::core_foundation::dictionary::CFDictionary<
    system_configuration::core_foundation::string::CFString,
    system_configuration::core_foundation::base::CFType,
> {
    use system_configuration::sys::schema_definitions::{
        kSCPropNetProxiesHTTPEnable, kSCPropNetProxiesHTTPPort, kSCPropNetProxiesHTTPProxy,
        kSCPropNetProxiesHTTPSEnable, kSCPropNetProxiesHTTPSPort, kSCPropNetProxiesHTTPSProxy,
        kSCPropNetProxiesSOCKSEnable, kSCPropNetProxiesSOCKSPort, kSCPropNetProxiesSOCKSProxy,
    };

    let mut config = macos_existing_proxy_config(protocol);
    macos_set_proxy_fields(
        &mut config,
        unsafe { kSCPropNetProxiesHTTPEnable },
        unsafe { kSCPropNetProxiesHTTPProxy },
        unsafe { kSCPropNetProxiesHTTPPort },
        None,
    );
    macos_set_proxy_fields(
        &mut config,
        unsafe { kSCPropNetProxiesHTTPSEnable },
        unsafe { kSCPropNetProxiesHTTPSProxy },
        unsafe { kSCPropNetProxiesHTTPSPort },
        None,
    );
    macos_set_proxy_fields(
        &mut config,
        unsafe { kSCPropNetProxiesSOCKSEnable },
        unsafe { kSCPropNetProxiesSOCKSProxy },
        unsafe { kSCPropNetProxiesSOCKSPort },
        None,
    );
    config.to_immutable()
}

#[cfg(target_os = "macos")]
pub(super) fn macos_existing_proxy_config(
    protocol: system_configuration::sys::network_configuration::SCNetworkProtocolRef,
) -> system_configuration::core_foundation::dictionary::CFMutableDictionary<
    system_configuration::core_foundation::string::CFString,
    system_configuration::core_foundation::base::CFType,
> {
    use system_configuration::{
        core_foundation::{
            base::{CFType, TCFType},
            dictionary::{CFDictionary, CFMutableDictionary},
            string::CFString,
        },
        sys::network_configuration::SCNetworkProtocolGetConfiguration,
    };

    let config_ref = unsafe { SCNetworkProtocolGetConfiguration(protocol) };
    if config_ref.is_null() {
        CFMutableDictionary::<CFString, CFType>::new()
    } else {
        let config = unsafe { CFDictionary::<CFString, CFType>::wrap_under_get_rule(config_ref) };
        CFMutableDictionary::from(&config)
    }
}

#[cfg(target_os = "macos")]
pub(super) fn macos_set_proxy_fields(
    config: &mut system_configuration::core_foundation::dictionary::CFMutableDictionary<
        system_configuration::core_foundation::string::CFString,
        system_configuration::core_foundation::base::CFType,
    >,
    enable_key: system_configuration::core_foundation::string::CFStringRef,
    proxy_key: system_configuration::core_foundation::string::CFStringRef,
    port_key: system_configuration::core_foundation::string::CFStringRef,
    endpoint: Option<&SystemProxyEndpoint>,
) {
    use system_configuration::core_foundation::{
        base::TCFType, number::CFNumber, string::CFString,
    };

    let enable_key = unsafe { CFString::wrap_under_get_rule(enable_key) };
    let proxy_key = unsafe { CFString::wrap_under_get_rule(proxy_key) };
    let port_key = unsafe { CFString::wrap_under_get_rule(port_key) };
    match endpoint {
        Some(endpoint) => {
            config.set(enable_key, CFNumber::from(1).into_CFType());
            config.set(proxy_key, CFString::new(&endpoint.host).into_CFType());
            config.set(
                port_key,
                CFNumber::from(i32::from(endpoint.port)).into_CFType(),
            );
        }
        None => {
            config.set(enable_key, CFNumber::from(0).into_CFType());
            config.remove(proxy_key);
            config.remove(port_key);
        }
    }
}
