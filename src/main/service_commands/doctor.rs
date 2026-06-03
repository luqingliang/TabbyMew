use super::*;

pub(super) fn doctor_check(
    name: &'static str,
    ok: bool,
    severity: &'static str,
    error_code: Option<&'static str>,
    message: impl Into<String>,
) -> DoctorCheck {
    DoctorCheck {
        name,
        ok,
        severity,
        error_code,
        message: message.into(),
    }
}

pub(super) async fn doctor_service_state(state_dir: &Path, timeout: Duration) -> DoctorReport {
    let service = process_manager::service_status(state_dir);
    let mut checks = Vec::new();
    let mut recommendations = Vec::new();

    checks.push(doctor_check(
        "service_state",
        !service.stale,
        if service.stale { "error" } else { "info" },
        service.stale.then_some("stale_state_file"),
        match service.status {
            ServiceStatusKind::Running => format!(
                "service is running with pid {}",
                service
                    .pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ),
            ServiceStatusKind::Stopped => "service is stopped".to_string(),
            ServiceStatusKind::Stale => "state file exists but process is not running".to_string(),
        },
    ));

    checks.push(doctor_check(
        "state_file",
        service.state_error.is_none(),
        if service.state_error.is_some() {
            "error"
        } else {
            "info"
        },
        service
            .state_error
            .is_some()
            .then_some("state_file_unreadable"),
        service
            .state_error
            .clone()
            .unwrap_or_else(|| format!("state file: {}", service.state_file.display())),
    ));

    checks.push(doctor_check(
        "preferences",
        service.preference_error.is_none(),
        if service.preference_error.is_some() {
            "error"
        } else {
            "info"
        },
        service
            .preference_error
            .is_some()
            .then_some("preferences_unreadable"),
        service
            .preference_error
            .clone()
            .unwrap_or_else(|| format!("preferences: {}", service.preferences_file.display())),
    ));

    let log_ok = service
        .log
        .as_ref()
        .is_none_or(|log| !service.state_file_exists || log.exists());
    checks.push(doctor_check(
        "log_file",
        log_ok,
        if log_ok { "info" } else { "warning" },
        (!log_ok).then_some("log_file_missing"),
        service
            .log
            .as_ref()
            .map(|log| format!("log file: {}", log.display()))
            .unwrap_or_else(|| "no log file is recorded".to_string()),
    ));

    add_doctor_cleanup_checks(&service, &mut checks, &mut recommendations);

    add_doctor_heartbeat_check(&service, &mut checks, &mut recommendations);

    let control_api = match status_control_listen(None, &service) {
        Ok(Some(listen)) => Some(collect_control_status(listen, timeout).await),
        Ok(None) => None,
        Err(err) => {
            checks.push(DoctorCheck {
                name: "control_api",
                ok: false,
                severity: "error",
                error_code: Some("invalid_control_listen"),
                message: format!("{err:#}"),
            });
            None
        }
    };
    if service.running {
        match &control_api {
            Some(control_api) if control_api.healthy => checks.push(doctor_check(
                "control_api",
                true,
                "info",
                None,
                format!("control API is healthy at http://{}", control_api.listen),
            )),
            Some(control_api) => {
                checks.push(doctor_check(
                    "control_api",
                    false,
                    "error",
                    Some(classify_control_api_report_error(control_api)),
                    control_api.error.clone().unwrap_or_else(|| {
                        format!("control API is unhealthy at http://{}", control_api.listen)
                    }),
                ));
                recommendations.push("inspect `TabbyMew logs` before restarting".to_string());
            }
            None => checks.push(doctor_check(
                "control_api",
                false,
                "error",
                Some("control_api_missing"),
                "service is running but no control API listen address is available",
            )),
        }
    } else if control_api.is_none() {
        checks.push(doctor_check(
            "control_api",
            true,
            "info",
            None,
            "service is not running; control API is not expected",
        ));
    }

    let runtime_status = collect_doctor_runtime_status(control_api.as_ref(), timeout).await;
    match (&service.status, runtime_status.as_ref()) {
        (ServiceStatusKind::Running, Some(_)) => checks.push(doctor_check(
            "runtime_status",
            true,
            "info",
            None,
            "runtime status endpoint is available",
        )),
        (ServiceStatusKind::Running, None) => {
            checks.push(doctor_check(
                "runtime_status",
                false,
                "error",
                Some("runtime_status_unavailable"),
                "runtime status endpoint is unavailable",
            ));
            recommendations.push(
                "run `TabbyMew restart` from the TUI or `TabbyMew stop && TabbyMew start`"
                    .to_string(),
            );
        }
        (_, _) => checks.push(doctor_check(
            "runtime_status",
            true,
            "info",
            None,
            "service is not running; runtime status is not expected",
        )),
    }
    if let Some(control_snapshot) = runtime_status.as_ref() {
        add_doctor_runtime_checks(control_snapshot, &mut checks, &mut recommendations);
    } else {
        add_doctor_stopped_system_proxy_residue_check(
            state_dir,
            &service,
            &mut checks,
            &mut recommendations,
        );
    }

    let issues = doctor_report_issues(&checks);
    let next_actions = next_actions_for_issues_with_state_dir(&issues, Some(&service.state_dir));
    let ok = checks.iter().all(|check| check.ok);
    if !ok {
        let failed_checks = checks
            .iter()
            .filter(|check| !check.ok)
            .map(|check| check.name)
            .collect::<Vec<_>>()
            .join(",");
        let issue_codes = issues
            .iter()
            .map(|issue| issue.code.as_str())
            .collect::<Vec<_>>()
            .join(",");
        record_service_lifecycle_event(
            &service,
            "doctor_issues",
            vec![
                ("failed_checks", failed_checks),
                ("issue_codes", issue_codes),
            ],
        );
    }
    DoctorReport {
        schema_version: CLI_JSON_SCHEMA_VERSION,
        ok,
        service,
        control_api,
        checks,
        issues,
        recommendations,
        next_actions,
    }
}

pub(super) async fn collect_doctor_runtime_status(
    control_api: Option<&ControlApiReport>,
    timeout: Duration,
) -> Option<Value> {
    let control_api = control_api?;
    if !control_api.healthy {
        return None;
    }
    let listen = control::parse_listen(&control_api.listen).ok()?;
    ControlClient::new(listen, timeout)
        .get_json("/control/api/status")
        .await
        .ok()
}

pub(super) fn add_doctor_runtime_checks(
    control_snapshot: &Value,
    checks: &mut Vec<DoctorCheck>,
    recommendations: &mut Vec<String>,
) {
    add_doctor_system_proxy_check(control_snapshot, checks, recommendations);
    add_doctor_tun_check(control_snapshot, checks, recommendations);
    add_doctor_routing_check(control_snapshot, checks);
    add_doctor_subscription_check(control_snapshot, checks, recommendations);
}

pub(super) fn add_doctor_cleanup_checks(
    service: &ServiceStatus,
    checks: &mut Vec<DoctorCheck>,
    recommendations: &mut Vec<String>,
) {
    if !service.needs_cleanup() {
        checks.push(doctor_check(
            "cleanup",
            true,
            "info",
            None,
            "no stale TabbyMew-owned runtime state is recorded",
        ));
        return;
    }

    for item in &service.cleanup_items {
        let (name, code, message) = match item.as_str() {
            "stale_state_file" => (
                "cleanup_state_file",
                "stale_state_file",
                "managed state file is stale or unreadable",
            ),
            "stale_runtime_state_file" => (
                "cleanup_runtime_state_file",
                "stale_runtime_state_file",
                "runtime state file is stale; previous TUN/DNS/route runtime ownership cannot be trusted",
            ),
            "managed_system_proxy" => (
                "cleanup_system_proxy",
                "managed_system_proxy",
                "system proxy ownership record exists while TabbyMew is not running",
            ),
            _ => ("cleanup", "cleanup_required", "cleanup is required"),
        };
        checks.push(doctor_check(name, false, "warning", Some(code), message));
    }
    push_recommendation(recommendations, "run `TabbyMew cleanup`");
}

pub(super) fn add_doctor_stopped_system_proxy_residue_check(
    state_dir: &Path,
    service: &ServiceStatus,
    checks: &mut Vec<DoctorCheck>,
    recommendations: &mut Vec<String>,
) {
    if service.running {
        return;
    }
    let Some(candidate) = system_proxy_cleanup_candidate(state_dir, service) else {
        checks.push(doctor_check(
            "system_proxy_residue",
            true,
            "info",
            None,
            "no stopped TabbyMew system proxy cleanup candidate is recorded",
        ));
        return;
    };
    let status = system_proxy::status_for_target(Some(&candidate.target))
        .with_target_recorded(candidate.target_recorded);
    if status.matches_target {
        let (code, message) = if candidate.target_recorded {
            (
                "managed_system_proxy_residue",
                "stopped TabbyMew still owns the current system proxy target",
            )
        } else {
            (
                "system_proxy_unrecorded_residue",
                "system proxy points to a TabbyMew config target but has no ownership record",
            )
        };
        checks.push(doctor_check(
            "system_proxy_residue",
            false,
            "warning",
            Some(code),
            format!("{message}; candidate={}", candidate.source),
        ));
        push_recommendation(recommendations, "run `TabbyMew cleanup`");
    } else if candidate.target_recorded {
        checks.push(doctor_check(
            "system_proxy_residue",
            false,
            "warning",
            Some("managed_system_proxy_record_stale"),
            "system proxy ownership record is stale; OS proxy no longer matches TabbyMew",
        ));
        push_recommendation(recommendations, "run `TabbyMew cleanup`");
    } else {
        checks.push(doctor_check(
            "system_proxy_residue",
            true,
            "info",
            None,
            "no stopped TabbyMew system proxy residue detected",
        ));
    }
}

pub(super) fn push_recommendation(recommendations: &mut Vec<String>, recommendation: &str) {
    if !recommendations
        .iter()
        .any(|existing| existing == recommendation)
    {
        recommendations.push(recommendation.to_string());
    }
}

pub(super) fn add_doctor_heartbeat_check(
    service: &ServiceStatus,
    checks: &mut Vec<DoctorCheck>,
    recommendations: &mut Vec<String>,
) {
    if !service.running {
        checks.push(doctor_check(
            "runtime_heartbeat",
            true,
            "info",
            None,
            "service is not running; runtime heartbeat is not expected",
        ));
        return;
    }

    match service.heartbeat_age_seconds {
        Some(age) if service.heartbeat_stale => {
            checks.push(doctor_check(
                "runtime_heartbeat",
                false,
                "warning",
                Some("runtime_heartbeat_stale"),
                format!(
                    "runtime heartbeat is {age}s old; expected <= {}s",
                    process_manager::STALE_HEARTBEAT_AFTER_SECS
                ),
            ));
            recommendations.push(
                "run `TabbyMew doctor` again after a few seconds; restart if the heartbeat stays stale"
                    .to_string(),
            );
        }
        Some(age) => checks.push(doctor_check(
            "runtime_heartbeat",
            true,
            "info",
            None,
            format!("runtime heartbeat is fresh ({age}s old)"),
        )),
        None => {
            checks.push(doctor_check(
                "runtime_heartbeat",
                false,
                "warning",
                Some("runtime_heartbeat_missing"),
                "runtime state has no heartbeat; restart TabbyMew with the current binary",
            ));
            recommendations
                .push("restart TabbyMew to enable runtime heartbeat diagnostics".to_string());
        }
    }
}

pub(super) fn add_doctor_system_proxy_check(
    control_snapshot: &Value,
    checks: &mut Vec<DoctorCheck>,
    recommendations: &mut Vec<String>,
) {
    let Some(system_proxy) = control_snapshot.get("system_proxy") else {
        checks.push(doctor_check(
            "system_proxy",
            false,
            "warning",
            Some("system_proxy_status_unavailable"),
            "system proxy status is unavailable",
        ));
        return;
    };
    if let Some(error) = value_str(system_proxy, &["error"]).filter(|value| !value.is_empty()) {
        checks.push(doctor_check(
            "system_proxy",
            false,
            "warning",
            Some("system_proxy_error"),
            format!("system proxy status error: {error}"),
        ));
        recommendations.push("inspect system proxy state before enabling it again".to_string());
        return;
    }
    let enabled = value_bool(system_proxy, &["enabled"]);
    let managed = value_bool(system_proxy, &["managed"]);
    let matches_target = value_bool(system_proxy, &["matches_target"]);
    let target_recorded = value_bool(system_proxy, &["target_recorded"]);
    match (enabled, managed, matches_target, target_recorded) {
        (Some(true), Some(true), _, _) => checks.push(doctor_check(
            "system_proxy",
            true,
            "info",
            None,
            "TabbyMew-managed system proxy is on",
        )),
        (Some(true), Some(false), Some(true), Some(false)) => {
            checks.push(doctor_check(
                "system_proxy",
                true,
                "warning",
                Some("system_proxy_unrecorded"),
                "system proxy points to TabbyMew but has no ownership record",
            ));
            recommendations.push(
                "turn system proxy off from TabbyMew before exit, or enable it again to record ownership"
                    .to_string(),
            );
        }
        (Some(true), Some(false), _, _) => checks.push(doctor_check(
            "system_proxy",
            true,
            "warning",
            Some("system_proxy_unmanaged"),
            "system proxy is on but not managed by TabbyMew",
        )),
        (Some(false), _, _, _) => checks.push(doctor_check(
            "system_proxy",
            true,
            "info",
            None,
            "system proxy is off",
        )),
        _ => checks.push(doctor_check(
            "system_proxy",
            false,
            "warning",
            Some("system_proxy_status_unavailable"),
            "system proxy status is incomplete",
        )),
    }
}

pub(super) fn add_doctor_tun_check(
    control_snapshot: &Value,
    checks: &mut Vec<DoctorCheck>,
    recommendations: &mut Vec<String>,
) {
    let configured =
        value_u64(control_snapshot, &["proxy", "configured_tun_inbounds"]).unwrap_or_default();
    if configured == 0 {
        checks.push(doctor_check(
            "tun",
            true,
            "info",
            None,
            "no TUN inbound is configured",
        ));
        return;
    }

    add_doctor_tun_runtime_file_check(checks, recommendations);

    let enabled = value_bool(control_snapshot, &["proxy", "tun_enabled"]);
    let desired_enabled =
        value_bool(control_snapshot, &["proxy", "tun_desired_enabled"]).unwrap_or(false);
    let status = value_str(control_snapshot, &["proxy", "tun_status"]).unwrap_or("-");
    let auto_route = value_bool(control_snapshot, &["proxy", "tun_auto_route"]).unwrap_or(false);
    let configured_bypass_count =
        value_u64(control_snapshot, &["proxy", "tun_configured_bypass_count"]).unwrap_or_default();
    let proxy_bypass_sources =
        value_u64(control_snapshot, &["proxy", "tun_proxy_bypass_sources"]).unwrap_or_default();
    let warning_count =
        value_array_len(control_snapshot, &["proxy", "tun_warnings"]).unwrap_or_default();
    if desired_enabled && enabled == Some(false) {
        checks.push(doctor_check(
            "tun_recovery",
            false,
            "warning",
            Some("tun_listener_stopped"),
            "TUN is desired on but the listener is not running; watchdog should retry recovery",
        ));
        recommendations.push(
            "inspect recent logs and run `TabbyMew tun off` if TUN should stay off".to_string(),
        );
        return;
    }
    match (enabled, status) {
        (Some(true), "running") => checks.push(doctor_check(
            "tun",
            true,
            "info",
            None,
            format_tun_running_doctor_message(control_snapshot),
        )),
        (Some(true), "requires_permission") => {
            checks.push(doctor_check(
                "tun",
                false,
                "warning",
                Some("tun_requires_permission"),
                "TUN is enabled but requires administrator/root permission",
            ));
            recommendations
                .push("grant permission when enabling TUN, or run without TUN".to_string());
        }
        (Some(true), "requires_configuration") => {
            checks.push(doctor_check(
                "tun",
                false,
                "warning",
                Some("tun_requires_configuration"),
                value_str(control_snapshot, &["proxy", "tun_detail"])
                    .unwrap_or("TUN configuration is incomplete")
                    .to_string(),
            ));
            recommendations.push(
                "configure at least one proxy outbound before enabling TUN auto route".to_string(),
            );
        }
        (Some(true), "failed") => {
            checks.push(doctor_check(
                "tun",
                false,
                "warning",
                Some("tun_failed"),
                value_str(control_snapshot, &["proxy", "tun_detail"])
                    .unwrap_or("TUN failed")
                    .to_string(),
            ));
            recommendations.push("inspect recent logs, then retry `TabbyMew tun on`".to_string());
        }
        (Some(true), other) => {
            checks.push(doctor_check(
                "tun",
                false,
                "warning",
                Some("tun_not_running"),
                format!("TUN is enabled but runtime status is {other}"),
            ));
            recommendations.push("inspect logs before toggling TUN again".to_string());
        }
        (Some(false), _) => {
            let message = if value_bool(control_snapshot, &["proxy", "tun_requires_privilege"])
                == Some(true)
                && value_bool(control_snapshot, &["proxy", "tun_privilege_verified"]) == Some(false)
            {
                "TUN is configured and currently off; enabling auto route will require administrator/root permission"
            } else {
                "TUN is configured and currently off"
            };
            checks.push(doctor_check("tun", true, "info", None, message));
        }
        _ => checks.push(doctor_check(
            "tun",
            false,
            "warning",
            Some("tun_status_unavailable"),
            "TUN status is incomplete",
        )),
    }

    if auto_route && configured_bypass_count == 0 {
        checks.push(doctor_check(
            "tun_bypass",
            false,
            "warning",
            Some("tun_bypass_empty"),
            "TUN auto route has no configured bypass CIDRs; local networks may be captured",
        ));
        recommendations.push(
            "add local/private CIDR bypass entries before using TUN auto route broadly".to_string(),
        );
    }
    if enabled == Some(true) && status == "running" && auto_route {
        if value_str(control_snapshot, &["proxy", "tun_egress_interface"]).is_none()
            && tun_egress_binding_expected(control_snapshot)
        {
            checks.push(doctor_check(
                "tun_route",
                false,
                "warning",
                Some("tun_egress_binding_missing"),
                "TUN auto route is running without a captured pre-TUN egress interface",
            ));
            recommendations.push(
                "restart TUN and inspect logs if outbound proxy connections loop into TUN"
                    .to_string(),
            );
        }
        if tun_egress_binding_expected(control_snapshot)
            && let (Some(egress), Some(bound)) = (
                value_str(control_snapshot, &["proxy", "tun_egress_interface"]),
                value_str(control_snapshot, &["proxy", "tun_bound_interface"]),
            )
            && egress != bound
        {
            checks.push(doctor_check(
                "tun_route",
                false,
                "warning",
                Some("tun_egress_binding_drift"),
                format!("TUN outbound egress binding drifted from {egress} to {bound}"),
            ));
            recommendations.push(
                "restart TUN so outbound proxy connections bind to the current pre-TUN interface"
                    .to_string(),
            );
        }
        if proxy_bypass_sources == 0 {
            checks.push(doctor_check(
                "tun_route",
                false,
                "warning",
                Some("tun_proxy_bypass_missing"),
                "TUN auto route is running without proxy outbound bypass sources",
            ));
            recommendations.push(
                "configure proxy outbounds so TUN can bypass the proxy server addresses"
                    .to_string(),
            );
        }
    }
    if warning_count > 0 {
        checks.push(doctor_check(
            "tun_bypass",
            false,
            "warning",
            Some("tun_startup_warnings"),
            format!("TUN startup recorded {warning_count} warning(s)"),
        ));
        recommendations.push("inspect recent TUN startup warnings in logs".to_string());
    }
    add_doctor_tun_watchdog_check(control_snapshot, checks);
}

pub(super) fn add_doctor_tun_watchdog_check(control_snapshot: &Value, checks: &mut Vec<DoctorCheck>) {
    let restarts =
        value_u64(control_snapshot, &["proxy", "tun_watchdog_restarts"]).unwrap_or_default();
    if restarts == 0 {
        checks.push(doctor_check(
            "tun_watchdog",
            true,
            "info",
            None,
            "TUN watchdog has not needed runtime recovery",
        ));
        return;
    }
    let reason = value_str(control_snapshot, &["proxy", "tun_last_watchdog_reason"]).unwrap_or("-");
    checks.push(doctor_check(
        "tun_watchdog",
        true,
        "info",
        None,
        format!(
            "TUN watchdog attempted runtime recovery {restarts} time(s); last reason: {reason}"
        ),
    ));
}

pub(super) fn add_doctor_tun_runtime_file_check(
    checks: &mut Vec<DoctorCheck>,
    recommendations: &mut Vec<String>,
) {
    if !platform::windows_tun_runtime_dll_required() {
        return;
    }

    let Some(exe_dir) = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
    else {
        checks.push(doctor_check(
            "tun_runtime",
            false,
            "warning",
            Some("wintun_runtime_unknown"),
            "could not locate the current executable directory to verify wintun.dll",
        ));
        recommendations.push(
            "keep wintun.dll in the same directory as TabbyMew.exe before enabling TUN".to_string(),
        );
        return;
    };

    let wintun_dll = exe_dir.join("wintun.dll");
    if wintun_dll.is_file() {
        checks.push(doctor_check(
            "tun_runtime",
            true,
            "info",
            None,
            "Windows TUN runtime DLL is present",
        ));
    } else {
        checks.push(doctor_check(
            "tun_runtime",
            false,
            "warning",
            Some("wintun_runtime_missing"),
            format!(
                "Windows TUN runtime DLL is missing: {}",
                wintun_dll.display()
            ),
        ));
        recommendations.push(
            "keep wintun.dll in the same directory as TabbyMew.exe, or use the full Windows release artifact"
                .to_string(),
        );
    }
}

pub(super) fn tun_egress_binding_expected(control_snapshot: &Value) -> bool {
    platform::tun_egress_binding_expected_for_snapshot(value_str(
        control_snapshot,
        &["proxy", "tun_platform"],
    ))
}

pub(super) fn format_tun_running_doctor_message(control_snapshot: &Value) -> String {
    let auto_route = value_bool(control_snapshot, &["proxy", "tun_auto_route"])
        .map(on_off)
        .unwrap_or("-");
    let dns = value_str(control_snapshot, &["proxy", "tun_dns_mode"]).unwrap_or("-");
    let egress = value_str(control_snapshot, &["proxy", "tun_egress_interface"]).unwrap_or("-");
    let bound = value_str(control_snapshot, &["proxy", "tun_bound_interface"]).unwrap_or("-");
    let watchdog_restarts =
        value_u64(control_snapshot, &["proxy", "tun_watchdog_restarts"]).unwrap_or_default();
    format!(
        "TUN is running; auto_route={auto_route} dns={dns} egress={egress} bound={bound} watchdog_restarts={watchdog_restarts}"
    )
}

pub(super) fn add_doctor_routing_check(control_snapshot: &Value, checks: &mut Vec<DoctorCheck>) {
    let Some(routing) = control_snapshot.get("routing") else {
        checks.push(doctor_check(
            "routing",
            false,
            "error",
            Some("routing_status_unavailable"),
            "routing status is unavailable",
        ));
        return;
    };
    let mode = value_str(routing, &["mode"]);
    let final_outbound = value_str(control_snapshot, &["rules", "final_outbound"])
        .or_else(|| value_str(routing, &["direct_outbound"]));
    let groups = value_array_len(routing, &["policy_groups"]).unwrap_or_default();
    if mode.is_some() && final_outbound.is_some() {
        checks.push(doctor_check(
            "routing",
            true,
            "info",
            None,
            format!(
                "routing mode={} final={} policy_groups={groups}",
                mode.unwrap_or("-"),
                final_outbound.unwrap_or("-")
            ),
        ));
    } else {
        checks.push(doctor_check(
            "routing",
            false,
            "error",
            Some("routing_status_incomplete"),
            "routing status is incomplete",
        ));
    }
}

pub(super) fn add_doctor_subscription_check(
    control_snapshot: &Value,
    checks: &mut Vec<DoctorCheck>,
    recommendations: &mut Vec<String>,
) {
    let Some(subscriptions) = control_snapshot.get("subscriptions") else {
        checks.push(doctor_check(
            "subscriptions",
            false,
            "warning",
            Some("subscriptions_status_unavailable"),
            "subscription status is unavailable",
        ));
        return;
    };
    if let Some(error) = value_str(subscriptions, &["error"]).filter(|value| !value.is_empty()) {
        checks.push(doctor_check(
            "subscriptions",
            false,
            "warning",
            Some("subscriptions_status_error"),
            format!("subscription status error: {error}"),
        ));
        recommendations.push("inspect subscription store and recent logs".to_string());
        return;
    }
    let failed = subscriptions
        .get("subscriptions")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| {
                    value_str(item, &["last_error"])
                        .filter(|value| !value.is_empty())
                        .is_some()
                })
                .count()
        })
        .unwrap_or_default();
    if failed > 0 {
        checks.push(doctor_check(
            "subscriptions",
            false,
            "warning",
            Some("subscription_update_failed"),
            format!("{failed} subscription(s) have a recorded update error"),
        ));
        recommendations
            .push("run `TabbyMew subscription update <name>` or inspect recent logs".to_string());
        return;
    }
    let total = value_array_len(subscriptions, &["subscriptions"]).unwrap_or_default();
    checks.push(doctor_check(
        "subscriptions",
        true,
        "info",
        None,
        format!("{total} subscription(s) tracked without recorded update errors"),
    ));
}
