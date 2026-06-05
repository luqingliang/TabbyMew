use super::*;
use anyhow::anyhow;
use std::cell::Cell;

#[test]
fn selects_system_proxy_targets_from_listener_summaries() {
    let target = select_target(&[
        "socks:socks-in@127.0.0.1:1080".to_string(),
        "hybrid:hybrid-in@127.0.0.1:17890 auth=off".to_string(),
    ])
    .unwrap();

    assert_eq!(target.source, "hybrid:hybrid-in@127.0.0.1:17890 auth=off");
    assert_eq!(target.http.as_ref().unwrap().address, "127.0.0.1:17890");
    assert_eq!(target.https.as_ref().unwrap().address, "127.0.0.1:17890");
    assert_eq!(target.socks.as_ref().unwrap().address, "127.0.0.1:17890");

    let target = select_target(&[
        "http:http-in@127.0.0.1:8080 auth=off".to_string(),
        "socks:socks-in@127.0.0.1:1080".to_string(),
    ])
    .unwrap();

    assert_eq!(target.http.as_ref().unwrap().address, "127.0.0.1:8080");
    assert_eq!(target.https.as_ref().unwrap().address, "127.0.0.1:8080");
    assert_eq!(target.socks.as_ref().unwrap().address, "127.0.0.1:1080");

    let target = select_target(&["http:http-in@127.0.0.1:8080 auth=off".to_string()]).unwrap();

    assert_eq!(target.source, "http:http-in@127.0.0.1:8080 auth=off");
    assert_eq!(target.http.as_ref().unwrap().address, "127.0.0.1:8080");
    assert_eq!(target.https.as_ref().unwrap().address, "127.0.0.1:8080");
    assert_eq!(target.socks, None);

    let target = select_target(&["socks:socks-in@127.0.0.1:1080".to_string()]).unwrap();

    assert_eq!(target.source, "socks:socks-in@127.0.0.1:1080");
    assert_eq!(target.http, None);
    assert_eq!(target.https, None);
    assert_eq!(target.socks.as_ref().unwrap().address, "127.0.0.1:1080");

    let target = select_target(&["hybrid:hybrid-in@[::1]:17890 auth=off".to_string()]).unwrap();

    assert_eq!(target.http.as_ref().unwrap().host, "::1");
    assert_eq!(target.http.as_ref().unwrap().address, "[::1]:17890");

    assert!(select_target(&["tun:tun-in interface=auto mtu=1500".to_string()]).is_none());

    assert!(
        select_target(&[
            "direct:direct".to_string(),
            "block:block".to_string(),
            "hybrid:missing-address".to_string(),
        ])
        .is_none()
    );
}

#[test]
fn selects_system_proxy_targets_by_protocol() {
    let hybrid = ["hybrid:hybrid-in@127.0.0.1:17890 auth=off".to_string()];
    let target = select_target_with_protocol(&hybrid, SystemProxyProtocol::Socks).unwrap();
    assert_eq!(target.http, None);
    assert_eq!(target.https, None);
    assert_eq!(target.socks.as_ref().unwrap().address, "127.0.0.1:17890");

    let target = select_target_with_protocol(&hybrid, SystemProxyProtocol::HttpConnect).unwrap();
    assert_eq!(target.http.as_ref().unwrap().address, "127.0.0.1:17890");
    assert_eq!(target.https.as_ref().unwrap().address, "127.0.0.1:17890");
    assert_eq!(target.socks, None);

    let separate = [
        "http:http-in@127.0.0.1:8080 auth=off".to_string(),
        "socks:socks-in@127.0.0.1:1080".to_string(),
    ];
    let target = select_target_with_protocol(&separate, SystemProxyProtocol::Socks).unwrap();
    assert_eq!(target.source, "socks:socks-in@127.0.0.1:1080");
    assert_eq!(target.http, None);
    assert_eq!(target.socks.as_ref().unwrap().address, "127.0.0.1:1080");

    let target = select_target_with_protocol(&separate, SystemProxyProtocol::HttpConnect).unwrap();
    assert_eq!(target.source, "http:http-in@127.0.0.1:8080 auth=off");
    assert_eq!(target.http.as_ref().unwrap().address, "127.0.0.1:8080");
    assert_eq!(target.socks, None);

    assert!(
        select_target_with_protocol(
            &["http:http-in@127.0.0.1:8080 auth=off".to_string()],
            SystemProxyProtocol::Socks
        )
        .is_none()
    );
}

#[test]
fn parses_macos_scutil_proxy_state() {
    let state = parse_macos_proxy_state(&macos_scutil_output(
        Some(("127.0.0.1", 7890)),
        Some(("127.0.0.1", 7890)),
        Some(("::1", 1080)),
    ));

    assert_eq!(state.http.as_ref().unwrap().address, "127.0.0.1:7890");
    assert_eq!(state.https.as_ref().unwrap().address, "127.0.0.1:7890");
    assert_eq!(state.socks.as_ref().unwrap().address, "[::1]:1080");
}

#[test]
fn macos_status_reports_managed_target() {
    let target = hybrid_target();
    let runner = |_program: &str, _args: &[String]| {
        Ok(macos_scutil_output(
            Some(("127.0.0.1", 17890)),
            Some(("127.0.0.1", 17890)),
            Some(("127.0.0.1", 17890)),
        ))
    };

    let status = macos_status_with_runner(Some(&target), &runner);

    assert!(status.supported);
    assert!(status.enabled);
    assert!(status.managed);
    assert!(status.matches_target);
    assert!(!status.target_recorded);
    assert_eq!(status.error, None);
}

#[test]
fn recorded_ownership_requires_matching_target() {
    let target = hybrid_target();
    let runner = |_program: &str, _args: &[String]| {
        Ok(macos_scutil_output(
            Some(("127.0.0.1", 17890)),
            Some(("127.0.0.1", 17890)),
            Some(("127.0.0.1", 17890)),
        ))
    };

    let unrecorded = macos_status_with_runner(Some(&target), &runner);
    let recorded = unrecorded.clone().with_target_recorded(true);
    let still_unrecorded = unrecorded.with_target_recorded(false);

    assert!(recorded.managed);
    assert!(recorded.matches_target);
    assert!(recorded.target_recorded);
    assert!(!still_unrecorded.managed);
    assert!(still_unrecorded.matches_target);
    assert!(!still_unrecorded.target_recorded);
}

#[test]
fn macos_status_reports_no_local_target() {
    let runner = |_program: &str, _args: &[String]| {
        Ok(macos_scutil_output(Some(("127.0.0.1", 8080)), None, None))
    };

    let status = macos_status_with_runner(None, &runner);

    assert!(status.supported);
    assert!(status.enabled);
    assert!(!status.managed);
    assert!(!status.matches_target);
    assert!(!status.target_recorded);
    assert_eq!(status.target, None);
    assert_eq!(status.error.as_deref(), Some(NO_LOCAL_SYSTEM_PROXY_TARGET));
}

#[test]
fn macos_status_reports_read_errors() {
    let target = hybrid_target();
    let runner = |_program: &str, _args: &[String]| Err(anyhow!("scutil failed"));

    let status = macos_status_with_runner(Some(&target), &runner);

    assert!(status.supported);
    assert!(!status.enabled);
    assert!(!status.managed);
    assert_eq!(status.target, Some(target));
    assert!(
        status
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("failed to read macOS system proxy: scutil failed")
    );
}

#[test]
fn macos_status_reports_other_target_as_unmanaged() {
    let target = hybrid_target();
    let runner = |_program: &str, _args: &[String]| {
        Ok(macos_scutil_output(
            Some(("127.0.0.1", 8080)),
            Some(("127.0.0.1", 8080)),
            None,
        ))
    };

    let status = macos_status_with_runner(Some(&target), &runner);

    assert!(status.enabled);
    assert!(!status.managed);
    assert!(!status.matches_target);
    assert!(
        status
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("another target")
    );
}

#[test]
fn macos_disable_skips_unmanaged_proxy() -> Result<()> {
    let target = hybrid_target();
    let applied = Cell::new(false);
    let runner = |_program: &str, _args: &[String]| {
        Ok(macos_scutil_output(
            Some(("127.0.0.1", 8080)),
            Some(("127.0.0.1", 8080)),
            None,
        ))
    };
    let applier = |_target: Option<&SystemProxyTarget>, _switch: SystemProxySwitch| {
        applied.set(true);
        Ok(())
    };

    let status =
        macos_switch_with_runner(Some(&target), SystemProxySwitch::Disable, &runner, &applier)?;

    assert!(!applied.get());
    assert!(status.enabled);
    assert!(!status.managed);
    assert!(
        status
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("another target")
    );
    Ok(())
}

#[test]
fn macos_disable_without_target_does_not_apply() -> Result<()> {
    let applied = Cell::new(false);
    let runner = |_program: &str, _args: &[String]| {
        Ok(macos_scutil_output(Some(("127.0.0.1", 8080)), None, None))
    };
    let applier = |_target: Option<&SystemProxyTarget>, _switch: SystemProxySwitch| {
        applied.set(true);
        Ok(())
    };

    let status = macos_switch_with_runner(None, SystemProxySwitch::Disable, &runner, &applier)?;

    assert!(!applied.get());
    assert!(status.enabled);
    assert!(!status.managed);
    assert_eq!(status.error.as_deref(), Some(NO_LOCAL_SYSTEM_PROXY_TARGET));
    Ok(())
}

#[test]
fn macos_disable_managed_proxy_applies() -> Result<()> {
    let target = hybrid_target();
    let applied = Cell::new(false);
    let runner = |_program: &str, _args: &[String]| {
        if applied.get() {
            Ok(macos_scutil_output(None, None, None))
        } else {
            Ok(macos_scutil_output(
                Some(("127.0.0.1", 17890)),
                Some(("127.0.0.1", 17890)),
                Some(("127.0.0.1", 17890)),
            ))
        }
    };
    let applier = |applied_target: Option<&SystemProxyTarget>, switch: SystemProxySwitch| {
        assert_eq!(applied_target, Some(&target));
        assert_eq!(switch, SystemProxySwitch::Disable);
        applied.set(true);
        Ok(())
    };

    let status =
        macos_switch_with_runner(Some(&target), SystemProxySwitch::Disable, &runner, &applier)?;

    assert!(applied.get());
    assert!(!status.enabled);
    assert!(!status.managed);
    assert_eq!(status.error, None);
    Ok(())
}

#[test]
fn macos_disable_managed_without_prompt_uses_supplied_applier() -> Result<()> {
    let target = hybrid_target();
    let applied = Cell::new(false);
    let runner = |_program: &str, _args: &[String]| {
        if applied.get() {
            Ok(macos_scutil_output(None, None, None))
        } else {
            Ok(macos_scutil_output(
                Some(("127.0.0.1", 17890)),
                Some(("127.0.0.1", 17890)),
                Some(("127.0.0.1", 17890)),
            ))
        }
    };
    let applier = |applied_target: Option<&SystemProxyTarget>, switch: SystemProxySwitch| {
        assert_eq!(applied_target, Some(&target));
        assert_eq!(switch, SystemProxySwitch::Disable);
        applied.set(true);
        Ok(())
    };

    let status =
        macos_disable_managed_without_prompt_with_runner(Some(&target), &runner, &applier)?;

    assert!(applied.get());
    assert!(!status.enabled);
    assert!(!status.managed);
    assert_eq!(status.error, None);
    Ok(())
}

#[test]
fn macos_disable_managed_without_prompt_skips_unmanaged_proxy() -> Result<()> {
    let target = hybrid_target();
    let applied = Cell::new(false);
    let runner = |_program: &str, _args: &[String]| {
        Ok(macos_scutil_output(
            Some(("127.0.0.1", 8080)),
            Some(("127.0.0.1", 8080)),
            None,
        ))
    };
    let applier = |_target: Option<&SystemProxyTarget>, _switch: SystemProxySwitch| {
        applied.set(true);
        Ok(())
    };

    let status =
        macos_disable_managed_without_prompt_with_runner(Some(&target), &runner, &applier)?;

    assert!(!applied.get());
    assert!(status.enabled);
    assert!(!status.managed);
    assert!(
        status
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("another target")
    );
    Ok(())
}

#[test]
fn macos_session_authorization_reuses_cached_authorization_first() -> Result<()> {
    let target = hybrid_target();
    let unauthorized_calls = Cell::new(0usize);
    let authorized_calls = Cell::new(0usize);
    let apply_without_authorization =
        |_target: Option<&SystemProxyTarget>, _switch: SystemProxySwitch| {
            unauthorized_calls.set(unauthorized_calls.get() + 1);
            Ok(())
        };
    let apply_with_authorization = |applied_target: Option<&SystemProxyTarget>,
                                    switch: SystemProxySwitch| {
        assert_eq!(applied_target, Some(&target));
        assert_eq!(switch, SystemProxySwitch::Enable);
        authorized_calls.set(authorized_calls.get() + 1);
        Ok(())
    };

    macos_apply_system_configuration_with_session_authorization(
        Some(&target),
        SystemProxySwitch::Enable,
        true,
        &apply_without_authorization,
        &apply_with_authorization,
    )?;

    assert_eq!(unauthorized_calls.get(), 0);
    assert_eq!(authorized_calls.get(), 1);
    Ok(())
}

#[test]
fn macos_session_authorization_tries_plain_write_before_prompting() -> Result<()> {
    let target = hybrid_target();
    let unauthorized_calls = Cell::new(0usize);
    let authorized_calls = Cell::new(0usize);
    let apply_without_authorization =
        |applied_target: Option<&SystemProxyTarget>, switch: SystemProxySwitch| {
            assert_eq!(applied_target, Some(&target));
            assert_eq!(switch, SystemProxySwitch::Enable);
            unauthorized_calls.set(unauthorized_calls.get() + 1);
            Ok(())
        };
    let apply_with_authorization = |_target: Option<&SystemProxyTarget>,
                                    _switch: SystemProxySwitch| {
        authorized_calls.set(authorized_calls.get() + 1);
        Ok(())
    };

    macos_apply_system_configuration_with_session_authorization(
        Some(&target),
        SystemProxySwitch::Enable,
        false,
        &apply_without_authorization,
        &apply_with_authorization,
    )?;

    assert_eq!(unauthorized_calls.get(), 1);
    assert_eq!(authorized_calls.get(), 0);
    Ok(())
}

#[test]
fn macos_session_authorization_prompts_after_plain_write_fails() -> Result<()> {
    let target = hybrid_target();
    let unauthorized_calls = Cell::new(0usize);
    let authorized_calls = Cell::new(0usize);
    let apply_without_authorization =
        |applied_target: Option<&SystemProxyTarget>, switch: SystemProxySwitch| {
            assert_eq!(applied_target, Some(&target));
            assert_eq!(switch, SystemProxySwitch::Enable);
            unauthorized_calls.set(unauthorized_calls.get() + 1);
            Err(anyhow!("network preferences are locked"))
        };
    let apply_with_authorization = |applied_target: Option<&SystemProxyTarget>,
                                    switch: SystemProxySwitch| {
        assert_eq!(applied_target, Some(&target));
        assert_eq!(switch, SystemProxySwitch::Enable);
        authorized_calls.set(authorized_calls.get() + 1);
        Ok(())
    };

    macos_apply_system_configuration_with_session_authorization(
        Some(&target),
        SystemProxySwitch::Enable,
        false,
        &apply_without_authorization,
        &apply_with_authorization,
    )?;

    assert_eq!(unauthorized_calls.get(), 1);
    assert_eq!(authorized_calls.get(), 1);
    Ok(())
}

#[test]
fn macos_enable_applies_over_unmanaged_proxy() -> Result<()> {
    let target = hybrid_target();
    let applied = Cell::new(false);
    let runner = |_program: &str, _args: &[String]| {
        if applied.get() {
            Ok(macos_scutil_output(
                Some(("127.0.0.1", 17890)),
                Some(("127.0.0.1", 17890)),
                Some(("127.0.0.1", 17890)),
            ))
        } else {
            Ok(macos_scutil_output(
                Some(("127.0.0.1", 8080)),
                Some(("127.0.0.1", 8080)),
                None,
            ))
        }
    };
    let applier = |applied_target: Option<&SystemProxyTarget>, switch: SystemProxySwitch| {
        assert_eq!(applied_target, Some(&target));
        assert_eq!(switch, SystemProxySwitch::Enable);
        applied.set(true);
        Ok(())
    };

    let status =
        macos_switch_with_runner(Some(&target), SystemProxySwitch::Enable, &runner, &applier)?;

    assert!(applied.get());
    assert!(status.enabled);
    assert!(status.managed);
    assert_eq!(status.error, None);
    Ok(())
}

#[test]
fn parses_windows_protocol_proxy_server() {
    let state = WindowsProxyState::from_registry_values(
        Some(1),
        Some(
            "http=http://127.0.0.1:7890;https=https://127.0.0.1:7891;socks=socks5://[::1]:1080"
                .to_string(),
        ),
    );

    assert!(state.enabled);
    assert_eq!(state.http.as_ref().unwrap().address, "127.0.0.1:7890");
    assert_eq!(state.https.as_ref().unwrap().address, "127.0.0.1:7891");
    assert_eq!(state.socks.as_ref().unwrap().address, "[::1]:1080");

    let legacy = parse_windows_proxy_server("socks=127.0.0.1:1080");
    assert_eq!(legacy.socks.as_ref().unwrap().address, "127.0.0.1:1080");
}

#[test]
fn parses_windows_single_proxy_server_as_http_and_https() {
    let endpoints = parse_windows_proxy_server("http://127.0.0.1:7890");

    assert_eq!(endpoints.http.as_ref().unwrap().address, "127.0.0.1:7890");
    assert_eq!(endpoints.https.as_ref().unwrap().address, "127.0.0.1:7890");
    assert_eq!(endpoints.socks, None);
}

#[test]
fn builds_windows_proxy_server_from_hybrid_target() {
    let target = hybrid_target();

    assert_eq!(
        windows_proxy_server_value(&target),
        "http=127.0.0.1:17890;https=127.0.0.1:17890;socks=socks5://127.0.0.1:17890"
    );
}

#[test]
fn windows_legacy_socks_proxy_server_needs_canonical_rewrite() {
    let target = hybrid_target();
    let legacy = WindowsProxyState::from_registry_values(
        Some(1),
        Some("http=127.0.0.1:17890;https=127.0.0.1:17890;socks=127.0.0.1:17890".to_string()),
    );
    let canonical =
        WindowsProxyState::from_registry_values(Some(1), Some(windows_proxy_server_value(&target)));

    assert!(legacy.matches_target(&target));
    assert!(legacy.needs_canonical_rewrite(&target));
    assert!(canonical.matches_target(&target));
    assert!(!canonical.needs_canonical_rewrite(&target));
}

#[test]
fn windows_status_reports_managed_target() {
    let target = hybrid_target();
    let state =
        WindowsProxyState::from_registry_values(Some(1), Some(windows_proxy_server_value(&target)));

    let status = windows_status_from_state(Some(&target), state);

    assert!(status.supported);
    assert!(status.enabled);
    assert!(status.managed);
    assert!(status.matches_target);
    assert!(!status.target_recorded);
    assert_eq!(status.error, None);
}

#[test]
fn windows_status_reports_other_target_as_unmanaged() {
    let target = hybrid_target();
    let state = WindowsProxyState::from_registry_values(
        Some(1),
        Some("http=127.0.0.1:8080;https=127.0.0.1:8080".to_string()),
    );

    let status = windows_status_from_state(Some(&target), state);

    assert!(status.enabled);
    assert!(!status.managed);
    assert!(!status.matches_target);
    assert!(
        status
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("another target")
    );
}

#[test]
fn windows_status_reports_read_errors() {
    let target = hybrid_target();
    let reader = || Err(anyhow!("registry failed"));

    let status = windows_status_with_reader(Some(&target), &reader);

    assert!(status.supported);
    assert!(!status.enabled);
    assert!(!status.managed);
    assert_eq!(status.target, Some(target));
    assert!(
        status
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("failed to read Windows system proxy: registry failed")
    );
}

#[test]
fn windows_disable_skips_unmanaged_proxy() -> Result<()> {
    let target = hybrid_target();
    let applied = Cell::new(false);
    let reader = || {
        Ok(WindowsProxyState::from_registry_values(
            Some(1),
            Some("http=127.0.0.1:8080;https=127.0.0.1:8080".to_string()),
        ))
    };
    let applier = |_target: Option<&SystemProxyTarget>, _switch: SystemProxySwitch| {
        applied.set(true);
        Ok(())
    };

    let status =
        windows_switch_with_reader(Some(&target), SystemProxySwitch::Disable, &reader, &applier)?;

    assert!(!applied.get());
    assert!(status.enabled);
    assert!(!status.managed);
    assert!(
        status
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("another target")
    );
    Ok(())
}

#[test]
fn windows_disable_managed_proxy_applies() -> Result<()> {
    let target = hybrid_target();
    let applied = Cell::new(false);
    let reader = || {
        if applied.get() {
            Ok(WindowsProxyState::from_registry_values(
                Some(0),
                Some(windows_proxy_server_value(&target)),
            ))
        } else {
            Ok(WindowsProxyState::from_registry_values(
                Some(1),
                Some(windows_proxy_server_value(&target)),
            ))
        }
    };
    let applier = |applied_target: Option<&SystemProxyTarget>, switch: SystemProxySwitch| {
        assert_eq!(applied_target, Some(&target));
        assert_eq!(switch, SystemProxySwitch::Disable);
        applied.set(true);
        Ok(())
    };

    let status =
        windows_switch_with_reader(Some(&target), SystemProxySwitch::Disable, &reader, &applier)?;

    assert!(applied.get());
    assert!(!status.enabled);
    assert!(!status.managed);
    assert_eq!(status.error, None);
    Ok(())
}

#[test]
fn windows_enable_applies_over_unmanaged_proxy() -> Result<()> {
    let target = hybrid_target();
    let applied = Cell::new(false);
    let reader = || {
        if applied.get() {
            Ok(WindowsProxyState::from_registry_values(
                Some(1),
                Some(windows_proxy_server_value(&target)),
            ))
        } else {
            Ok(WindowsProxyState::from_registry_values(
                Some(1),
                Some("http=127.0.0.1:8080;https=127.0.0.1:8080".to_string()),
            ))
        }
    };
    let applier = |applied_target: Option<&SystemProxyTarget>, switch: SystemProxySwitch| {
        assert_eq!(applied_target, Some(&target));
        assert_eq!(switch, SystemProxySwitch::Enable);
        applied.set(true);
        Ok(())
    };

    let status =
        windows_switch_with_reader(Some(&target), SystemProxySwitch::Enable, &reader, &applier)?;

    assert!(applied.get());
    assert!(status.enabled);
    assert!(status.managed);
    assert_eq!(status.error, None);
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[test]
fn enable_reports_unimplemented_backend_on_unsupported_platforms() {
    let err = switch_with_protocol(
        &["hybrid:hybrid-in@127.0.0.1:17890 auth=off".to_string()],
        SystemProxyProtocol::Auto,
        SystemProxySwitch::Enable,
    )
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("system proxy backend is not implemented yet")
    );
}

fn hybrid_target() -> SystemProxyTarget {
    let endpoint = SystemProxyEndpoint {
        host: "127.0.0.1".to_string(),
        port: 17890,
        address: "127.0.0.1:17890".to_string(),
    };
    SystemProxyTarget {
        source: "hybrid:hybrid-in@127.0.0.1:17890 auth=off".to_string(),
        http: Some(endpoint.clone()),
        https: Some(endpoint.clone()),
        socks: Some(endpoint),
    }
}

fn macos_scutil_output(
    http: Option<(&str, u16)>,
    https: Option<(&str, u16)>,
    socks: Option<(&str, u16)>,
) -> String {
    let mut output = String::from("<dictionary> {\n");
    push_scutil_proxy(&mut output, "HTTP", http);
    push_scutil_proxy(&mut output, "HTTPS", https);
    push_scutil_proxy(&mut output, "SOCKS", socks);
    output.push_str("}\n");
    output
}

fn push_scutil_proxy(output: &mut String, prefix: &str, endpoint: Option<(&str, u16)>) {
    match endpoint {
        Some((host, port)) => {
            output.push_str(&format!("  {prefix}Enable : 1\n"));
            output.push_str(&format!("  {prefix}Proxy : {host}\n"));
            output.push_str(&format!("  {prefix}Port : {port}\n"));
        }
        None => {
            output.push_str(&format!("  {prefix}Enable : 0\n"));
        }
    }
}
