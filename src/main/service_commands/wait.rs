use super::*;

pub(super) async fn run_wait_command(config: Option<&PathBuf>, command: WaitCommand) -> Result<()> {
    let target = parse_wait_target(&command.target)?;
    let desired = parse_wait_desired(target, command.state.as_deref())?;
    let state_dir = command
        .state_dir
        .clone()
        .unwrap_or_else(process_manager::default_state_dir);
    let timeout = named_duration("timeout-ms", command.timeout_ms)?;
    let interval = named_duration("interval-ms", command.interval_ms)?;
    let request_timeout = named_duration("request-timeout-ms", command.request_timeout_ms)?;
    let started = Instant::now();
    let mut last_report = evaluate_wait_state(
        config,
        &state_dir,
        command.listen.as_deref(),
        request_timeout,
        target,
        desired,
        0,
    )
    .await?;

    loop {
        if last_report.ok {
            print_wait_report(&last_report, command.json)?;
            return Ok(());
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            last_report.ok = false;
            last_report.waited_ms = elapsed.as_millis() as u64;
            last_report.error_code = Some("wait_timeout");
            last_report.message = format!(
                "timed out waiting for {} {} (current: {})",
                target.as_str(),
                desired.as_str(),
                last_report.current
            );
            last_report.next_actions = next_actions_for_issues(&[cli_issue(
                "wait_timeout",
                "error",
                last_report.message.clone(),
            )]);
            print_wait_report(&last_report, command.json)?;
            bail!("{}", last_report.message);
        }
        let sleep_for = interval.min(timeout.saturating_sub(elapsed));
        sleep(sleep_for).await;
        last_report = evaluate_wait_state(
            config,
            &state_dir,
            command.listen.as_deref(),
            request_timeout,
            target,
            desired,
            started.elapsed().as_millis() as u64,
        )
        .await?;
    }
}

pub(super) fn parse_wait_target(input: &str) -> Result<WaitTarget> {
    match input.trim().to_ascii_lowercase().as_str() {
        "service" | "svc" => Ok(WaitTarget::Service),
        "tun" => Ok(WaitTarget::Tun),
        "system-proxy" | "system_proxy" | "sysproxy" | "sp" => Ok(WaitTarget::SystemProxy),
        other => bail!("unknown wait target `{other}`; expected service, tun, or system-proxy"),
    }
}

pub(super) fn parse_wait_desired(target: WaitTarget, input: Option<&str>) -> Result<WaitDesired> {
    let normalized = input
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    match (target, normalized.as_deref()) {
        (WaitTarget::Service, None | Some("ready" | "running" | "up")) => Ok(WaitDesired::Ready),
        (WaitTarget::Service, Some("stopped" | "down" | "off")) => Ok(WaitDesired::Stopped),
        (WaitTarget::Service, Some(other)) => {
            bail!("unknown service wait state `{other}`; expected ready or stopped")
        }
        (WaitTarget::Tun | WaitTarget::SystemProxy, None | Some("on" | "enabled" | "ready")) => {
            Ok(WaitDesired::On)
        }
        (WaitTarget::Tun | WaitTarget::SystemProxy, Some("off" | "disabled" | "stopped")) => {
            Ok(WaitDesired::Off)
        }
        (WaitTarget::Tun, Some(other)) => {
            bail!("unknown TUN wait state `{other}`; expected on or off")
        }
        (WaitTarget::SystemProxy, Some(other)) => {
            bail!("unknown system proxy wait state `{other}`; expected on or off")
        }
    }
}

pub(super) async fn evaluate_wait_state(
    config: Option<&PathBuf>,
    state_dir: &Path,
    listen: Option<&str>,
    request_timeout: Duration,
    target: WaitTarget,
    desired: WaitDesired,
    waited_ms: u64,
) -> Result<WaitReport> {
    match target {
        WaitTarget::Service => {
            evaluate_service_wait_state(state_dir, listen, request_timeout, desired, waited_ms)
                .await
        }
        WaitTarget::Tun => {
            evaluate_tun_wait_state(
                config,
                state_dir,
                listen,
                request_timeout,
                desired,
                waited_ms,
            )
            .await
        }
        WaitTarget::SystemProxy => {
            evaluate_system_proxy_wait_state(
                config,
                state_dir,
                listen,
                request_timeout,
                desired,
                waited_ms,
            )
            .await
        }
    }
}

pub(super) async fn evaluate_service_wait_state(
    state_dir: &Path,
    listen: Option<&str>,
    request_timeout: Duration,
    desired: WaitDesired,
    waited_ms: u64,
) -> Result<WaitReport> {
    let listen = listen.map(str::to_string);
    let report = build_status_report(state_dir, listen, request_timeout).await?;
    let current = service_wait_current(&report);
    let ok = match desired {
        WaitDesired::Ready => current == "ready",
        WaitDesired::Stopped => current == "stopped",
        WaitDesired::On | WaitDesired::Off => unreachable!("service wait uses ready/stopped"),
    };
    Ok(wait_report(
        ok,
        WaitTarget::Service,
        desired,
        current,
        waited_ms,
        if ok {
            None
        } else {
            Some(service_wait_error_code(&report))
        },
    ))
}

pub(super) fn service_wait_current(report: &StatusReport) -> String {
    if report
        .control_api
        .as_ref()
        .is_some_and(|control| control.healthy)
    {
        return "ready".to_string();
    }
    if report.service.status == ServiceStatusKind::Stopped && report.service.needs_cleanup() {
        return "stopped_needs_cleanup".to_string();
    }
    if report.service.status == ServiceStatusKind::Stopped {
        return "stopped".to_string();
    }
    if report.service.status == ServiceStatusKind::Stale {
        return "stale".to_string();
    }
    match &report.control_api {
        Some(_) => "running_control_unhealthy".to_string(),
        None => "running_control_missing".to_string(),
    }
}

pub(super) fn service_wait_error_code(report: &StatusReport) -> &'static str {
    if report.service.status == ServiceStatusKind::Stale {
        "stale_state_file"
    } else if report.service.needs_cleanup() {
        "cleanup_required"
    } else if let Some(control) = &report.control_api {
        classify_control_api_report_error(control)
    } else if !report.service.running {
        "service_not_running"
    } else {
        "control_api_missing"
    }
}

pub(super) async fn evaluate_tun_wait_state(
    config: Option<&PathBuf>,
    state_dir: &Path,
    listen: Option<&str>,
    request_timeout: Duration,
    desired: WaitDesired,
    waited_ms: u64,
) -> Result<WaitReport> {
    let Some(client) =
        wait_runtime_control_client(config, state_dir, listen, request_timeout).await?
    else {
        return Ok(wait_report(
            false,
            WaitTarget::Tun,
            desired,
            "service_not_ready".to_string(),
            waited_ms,
            Some("service_not_ready"),
        ));
    };
    let snapshot = match client.get_json("/control/api/status").await {
        Ok(snapshot) => snapshot,
        Err(err) => {
            let error = format!("{err:#}");
            return Ok(wait_report(
                false,
                WaitTarget::Tun,
                desired,
                "runtime_status_unavailable".to_string(),
                waited_ms,
                Some(classify_user_error(&error)),
            ));
        }
    };
    let current = tun_wait_current(&snapshot);
    let ok = match desired {
        WaitDesired::On => current == "on",
        WaitDesired::Off => current == "off",
        WaitDesired::Ready | WaitDesired::Stopped => unreachable!("TUN wait uses on/off"),
    };
    Ok(wait_report(
        ok,
        WaitTarget::Tun,
        desired,
        current,
        waited_ms,
        (!ok).then_some("tun_not_ready"),
    ))
}

pub(super) fn tun_wait_current(snapshot: &Value) -> String {
    let enabled = value_bool(snapshot, &["proxy", "tun_enabled"]);
    let status = value_str(snapshot, &["proxy", "tun_status"]).unwrap_or("-");
    match (enabled, status) {
        (Some(true), "running") => "on".to_string(),
        (Some(true), "requires_permission") => "on_requires_permission".to_string(),
        (Some(true), other) => format!("on_{other}"),
        (Some(false), _) => "off".to_string(),
        _ => "unknown".to_string(),
    }
}

pub(super) async fn evaluate_system_proxy_wait_state(
    config: Option<&PathBuf>,
    state_dir: &Path,
    listen: Option<&str>,
    request_timeout: Duration,
    desired: WaitDesired,
    waited_ms: u64,
) -> Result<WaitReport> {
    let Some(client) =
        wait_runtime_control_client(config, state_dir, listen, request_timeout).await?
    else {
        return Ok(wait_report(
            false,
            WaitTarget::SystemProxy,
            desired,
            "service_not_ready".to_string(),
            waited_ms,
            Some("service_not_ready"),
        ));
    };
    let snapshot = match client.get_json("/control/api/system-proxy").await {
        Ok(snapshot) => snapshot,
        Err(err) => {
            let error = format!("{err:#}");
            return Ok(wait_report(
                false,
                WaitTarget::SystemProxy,
                desired,
                "system_proxy_status_unavailable".to_string(),
                waited_ms,
                Some(classify_user_error(&error)),
            ));
        }
    };
    let current = system_proxy_wait_current(&snapshot);
    let ok = match desired {
        WaitDesired::On => current == "on",
        WaitDesired::Off => current == "off",
        WaitDesired::Ready | WaitDesired::Stopped => {
            unreachable!("system proxy wait uses on/off")
        }
    };
    Ok(wait_report(
        ok,
        WaitTarget::SystemProxy,
        desired,
        current,
        waited_ms,
        (!ok).then_some("system_proxy_not_ready"),
    ))
}

pub(super) fn system_proxy_wait_current(snapshot: &Value) -> String {
    let enabled = value_bool(snapshot, &["enabled"]);
    let managed = value_bool(snapshot, &["managed"]);
    let matches_target = value_bool(snapshot, &["matches_target"]);
    let target_recorded = value_bool(snapshot, &["target_recorded"]);
    match (enabled, managed, matches_target, target_recorded) {
        (Some(true), Some(true), _, _) => "on".to_string(),
        (Some(true), Some(false), Some(true), Some(false)) => "on_unrecorded".to_string(),
        (Some(true), Some(false), _, _) => "on_unmanaged".to_string(),
        (Some(false), _, _, _) | (_, Some(false), _, _) => "off".to_string(),
        _ => "unknown".to_string(),
    }
}

pub(super) async fn wait_runtime_control_client(
    config: Option<&PathBuf>,
    state_dir: &Path,
    listen: Option<&str>,
    request_timeout: Duration,
) -> Result<Option<ControlClient>> {
    let status =
        build_status_report(state_dir, listen.map(str::to_string), request_timeout).await?;
    if let Some(control) = status
        .control_api
        .as_ref()
        .filter(|control| control.healthy)
    {
        let listen = control::parse_listen(&control.listen)
            .context("invalid control API listen address from local state")?;
        return Ok(Some(ControlClient::new(listen, request_timeout)));
    }
    if !status.service.running {
        return Ok(None);
    }
    if listen.is_none() {
        return Ok(None);
    }
    let control = RuntimeControlOptions {
        listen: listen.map(str::to_string),
        state_dir: Some(state_dir.to_path_buf()),
        timeout_ms: request_timeout.as_millis() as u64,
    };
    runtime_control_client(config, &control).map(Some)
}

pub(super) fn wait_report(
    ok: bool,
    target: WaitTarget,
    desired: WaitDesired,
    current: String,
    waited_ms: u64,
    error_code: Option<&'static str>,
) -> WaitReport {
    let message = if ok {
        format!(
            "{} reached {} after {}ms",
            target.as_str(),
            desired.as_str(),
            waited_ms
        )
    } else {
        format!(
            "waiting for {} {}; current: {}",
            target.as_str(),
            desired.as_str(),
            current
        )
    };
    let next_actions = error_code
        .map(|code| next_actions_for_issues(&[cli_issue(code, "warning", message.clone())]))
        .unwrap_or_default();
    WaitReport {
        schema_version: CLI_JSON_SCHEMA_VERSION,
        ok,
        target: target.as_str(),
        desired: desired.as_str(),
        current,
        waited_ms,
        error_code,
        message,
        next_actions,
    }
}

pub(super) fn print_wait_report(report: &WaitReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    let mut writer = io::stdout().lock();
    writeln!(
        writer,
        "TabbyMew wait {} {}: {}",
        report.target,
        report.desired,
        if report.ok { "ok" } else { "not ready" }
    )?;
    writeln!(writer, "  current: {}", report.current)?;
    writeln!(writer, "  waited: {}ms", report.waited_ms)?;
    if let Some(error_code) = report.error_code {
        writeln!(writer, "  error_code: {error_code}")?;
    }
    print_next_actions(&mut writer, &report.next_actions)?;
    Ok(())
}
