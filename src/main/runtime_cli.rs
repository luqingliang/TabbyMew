#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliSwitchAction {
    Status,
    On,
    Off,
    Toggle,
}

fn parse_cli_switch_action(action: Option<&str>, subject: &str) -> Result<CliSwitchAction> {
    match action.map(str::trim).filter(|action| !action.is_empty()) {
        None | Some("status") => Ok(CliSwitchAction::Status),
        Some("on" | "enable" | "enabled" | "start") => Ok(CliSwitchAction::On),
        Some("off" | "disable" | "disabled" | "stop") => Ok(CliSwitchAction::Off),
        Some("toggle" | "switch") => Ok(CliSwitchAction::Toggle),
        Some(other) => {
            bail!("unknown {subject} action `{other}`; expected status, on, off, or toggle")
        }
    }
}

async fn run_mode_command(config: Option<&PathBuf>, command: ModeCommand) -> Result<()> {
    match command.mode.as_deref() {
        Some(mode) => {
            let mode = parse_route_mode_arg(mode)?;
            let response = runtime_post_control_json(
                config,
                &command.control,
                "/control/api/route-mode",
                serde_json::json!({ "mode": mode.as_str() }),
            )
            .await?;
            if command.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                print!("{}", format_route_mode_switch_output(&response, mode));
            }
        }
        None => {
            let status =
                runtime_get_control_json(config, &command.control, "/control/api/status").await?;
            if command.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(routing_status(&status)?)?
                );
            } else {
                print!("{}", format_cli_route_mode_status(&status)?);
            }
        }
    }
    Ok(())
}

async fn run_global_command(config: Option<&PathBuf>, command: GlobalCommand) -> Result<()> {
    match command.target.as_deref() {
        Some(target) => {
            let status =
                runtime_get_control_json(config, &command.control, "/control/api/status").await?;
            let target = resolve_global_target(Some(&status), target)?;
            let response = runtime_post_control_json(
                config,
                &command.control,
                "/control/api/global-target",
                serde_json::json!({ "target": target }),
            )
            .await?;
            if command.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                print!(
                    "{}",
                    format_global_target_switch_output(&response, &target, None, None)
                );
            }
        }
        None => {
            let status =
                runtime_get_control_json(config, &command.control, "/control/api/status").await?;
            if command.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&cli_global_status_json(&status)?)?
                );
            } else {
                print!("{}", format_cli_global_status(&status)?);
            }
        }
    }
    Ok(())
}

async fn run_groups_command(config: Option<&PathBuf>, command: GroupsCommand) -> Result<()> {
    let status = runtime_get_control_json(config, &command.control, "/control/api/status").await?;
    match (command.group.as_deref(), command.outbound.as_deref()) {
        (Some(group), Some(outbound)) => {
            let group = resolve_cli_policy_group(&status, group)?;
            let outbound = resolve_policy_group_outbound(&group, outbound)?;
            let response = runtime_post_control_json(
                config,
                &command.control,
                "/control/api/policy-groups/select",
                serde_json::json!({ "group": group.tag, "outbound": outbound }),
            )
            .await?;
            if command.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                print!(
                    "{}",
                    format_policy_group_selection_output(
                        &response, &group.tag, &outbound, None, None,
                    )
                );
            }
        }
        (Some(group), None) => {
            let group = resolve_cli_policy_group(&status, group)?;
            if command.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&cli_policy_group_json(&group))?
                );
            } else {
                print!("{}", format_cli_policy_group(&group));
            }
        }
        (None, None) => {
            let groups = policy_groups(Some(&status));
            if command.json {
                let items = groups.iter().map(cli_policy_group_json).collect::<Vec<_>>();
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else {
                print!("{}", format_cli_policy_groups(&groups));
            }
        }
        (None, Some(_)) => unreachable!("clap positional parsing cannot set outbound first"),
    }
    Ok(())
}

async fn run_tun_command(config: Option<&PathBuf>, command: TunCommand) -> Result<()> {
    let action = parse_cli_switch_action(command.action.as_deref(), "TUN")?;
    match action {
        CliSwitchAction::Status => {
            let status =
                runtime_get_control_json(config, &command.control, "/control/api/status").await?;
            let proxy = status
                .get("proxy")
                .filter(|proxy| !proxy.is_null())
                .context("TUN status is not available; proxy runtime is not running")?;
            if command.json {
                println!("{}", serde_json::to_string_pretty(proxy)?);
            } else {
                print!("{}", format_cli_tun_status(proxy));
            }
        }
        CliSwitchAction::On | CliSwitchAction::Off | CliSwitchAction::Toggle => {
            let enabled = match action {
                CliSwitchAction::On => true,
                CliSwitchAction::Off => false,
                CliSwitchAction::Toggle => {
                    let status =
                        runtime_get_control_json(config, &command.control, "/control/api/status")
                            .await?;
                    !value_bool(&status, &["proxy", "tun_enabled"])
                        .context("TUN state is not available; proxy runtime is not running")?
                }
                CliSwitchAction::Status => unreachable!(),
            };
            let response = runtime_post_control_json(
                config,
                &command.control,
                "/control/api/tun",
                serde_json::json!({ "enabled": enabled }),
            )
            .await?;
            if command.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                print!("{}", format_tun_switch_output(&response, enabled));
            }
        }
    }
    Ok(())
}

async fn run_system_proxy_command(
    config: Option<&PathBuf>,
    command: SystemProxyCommand,
) -> Result<()> {
    let action = parse_cli_switch_action(command.action.as_deref(), "system proxy")?;
    match action {
        CliSwitchAction::Status => {
            let status =
                runtime_get_control_json(config, &command.control, "/control/api/system-proxy")
                    .await?;
            if command.json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                print!("{}", format_cli_system_proxy_status(&status));
            }
        }
        CliSwitchAction::On | CliSwitchAction::Off | CliSwitchAction::Toggle => {
            let enabled = match action {
                CliSwitchAction::On => true,
                CliSwitchAction::Off => false,
                CliSwitchAction::Toggle => {
                    let status = runtime_get_control_json(
                        config,
                        &command.control,
                        "/control/api/system-proxy",
                    )
                    .await?;
                    !value_bool(&status, &["enabled"])
                        .context("system proxy state is not available")?
                }
                CliSwitchAction::Status => unreachable!(),
            };
            let response = runtime_post_control_json(
                config,
                &command.control,
                "/control/api/system-proxy",
                serde_json::json!({ "enabled": enabled }),
            )
            .await?;
            if command.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                print!("{}", format_system_proxy_switch_output(&response, enabled));
            }
        }
    }
    Ok(())
}

async fn runtime_get_control_json(
    config: Option<&PathBuf>,
    control: &RuntimeControlOptions,
    path: &str,
) -> Result<Value> {
    runtime_control_client(config, control)?
        .get_json(path)
        .await
}

async fn runtime_post_control_json(
    config: Option<&PathBuf>,
    control: &RuntimeControlOptions,
    path: &str,
    body: Value,
) -> Result<Value> {
    let client = runtime_control_client(config, control)?;
    let token = control_token_for_state_dir(control.state_dir.as_deref())?;
    client.post_json(path, &token, &body).await
}

fn runtime_control_client(
    config: Option<&PathBuf>,
    control: &RuntimeControlOptions,
) -> Result<ControlClient> {
    let listen = resolve_runtime_control_listen(config, control)?;
    Ok(ControlClient::new(
        listen,
        timeout_duration(control.timeout_ms)?,
    ))
}

fn resolve_runtime_control_listen(
    config: Option<&PathBuf>,
    control: &RuntimeControlOptions,
) -> Result<std::net::SocketAddr> {
    if let Some(listen) = control.listen.as_ref() {
        return control::parse_listen(listen).context("invalid control API listen address");
    }
    if let Some(listen) = control_listen_from_state(control.state_dir.clone()) {
        return control::parse_listen(&listen)
            .context("invalid control API listen address from local state");
    }
    let config_path = resolve_config_path(config)?;
    resolve_control_listen(&config_path, None, control.state_dir.clone())
}

fn routing_status(status: &Value) -> Result<&Value> {
    status
        .get("routing")
        .filter(|routing| !routing.is_null())
        .context("routing runtime status is not available")
}

fn format_cli_route_mode_status(status: &Value) -> Result<String> {
    let routing = routing_status(status)?;
    let mode = value_str(routing, &["mode"]).unwrap_or("-");
    let global = value_str(routing, &["global_outbound"]).unwrap_or("-");
    let direct = value_str(routing, &["direct_outbound"]).unwrap_or("-");
    let groups = value_array_len(routing, &["policy_groups"]).unwrap_or_default();
    Ok(format!(
        "route mode: {mode}\nglobal target: {global}\ndirect outbound: {direct}\npolicy groups: {groups}\n"
    ))
}

fn cli_global_status_json(status: &Value) -> Result<Value> {
    let routing = routing_status(status)?;
    Ok(serde_json::json!({
        "mode": value_str(routing, &["mode"]),
        "global_outbound": value_str(routing, &["global_outbound"]),
        "global_targets": routing.get("global_targets").cloned().unwrap_or(Value::Array(Vec::new())),
    }))
}

fn format_cli_global_status(status: &Value) -> Result<String> {
    let routing = routing_status(status)?;
    let target = value_str(routing, &["global_outbound"]).unwrap_or("-");
    let targets = value_array_len(routing, &["global_targets"]).unwrap_or_default();
    Ok(format!(
        "global target: {target}\navailable targets: {targets}\n"
    ))
}

fn resolve_cli_policy_group(status: &Value, input: &str) -> Result<PolicyGroup> {
    let groups = policy_groups(Some(status));
    if groups.is_empty() {
        bail!("policy groups are not available; start TabbyMew and check the active config");
    }
    resolve_policy_group_with_remainder(&groups, input).map(|(group, _)| group)
}

fn cli_policy_group_json(group: &PolicyGroup) -> Value {
    serde_json::json!({
        "tag": group.tag,
        "kind": group.kind,
        "selected": group.selected,
        "outbounds": group.outbounds,
    })
}

fn format_cli_policy_groups(groups: &[PolicyGroup]) -> String {
    if groups.is_empty() {
        return "policy groups: none\n".to_string();
    }
    let mut output = format!("policy groups: {}\n", groups.len());
    for group in groups {
        output.push_str(&indent_text(&format_cli_policy_group(group)));
        output.push('\n');
    }
    output
}

fn format_cli_policy_group(group: &PolicyGroup) -> String {
    format!(
        "- {} [{}]\n  selected: {}\n  outbounds: {}\n",
        group.tag,
        group.kind,
        group.selected,
        if group.outbounds.is_empty() {
            "-".to_string()
        } else {
            group.outbounds.join(", ")
        }
    )
}

fn format_cli_tun_status(proxy: &Value) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "enabled: {}\n",
        value_bool(proxy, &["tun_enabled"])
            .map(on_off)
            .unwrap_or("-")
    ));
    output.push_str(&format!(
        "desired: {}\n",
        value_bool(proxy, &["tun_desired_enabled"])
            .map(on_off)
            .unwrap_or("-")
    ));
    output.push_str(&format!(
        "status: {}\n",
        format_tun_state(
            value_bool(proxy, &["tun_enabled"]),
            value_str(proxy, &["tun_status"]),
        )
    ));
    output.push_str(&format!(
        "configured inbounds: {}\n",
        value_u64(proxy, &["configured_tun_inbounds"])
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string())
    ));
    output.push_str(&format!(
        "auto route: {}\n",
        value_bool(proxy, &["tun_auto_route"])
            .map(on_off)
            .unwrap_or("-")
    ));
    output.push_str(&format!(
        "ipv6: {}\n",
        value_bool(proxy, &["tun_ipv6_enabled"])
            .map(on_off)
            .unwrap_or("-")
    ));
    output.push_str(&format!(
        "dns: {}\n",
        value_str(proxy, &["tun_dns_mode"]).unwrap_or("-")
    ));
    output.push_str(&format!(
        "dns address: {}\n",
        value_str(proxy, &["tun_dns_addr"]).unwrap_or("-")
    ));
    output.push_str(&format!(
        "configured bypass CIDRs: {}\n",
        value_u64(proxy, &["tun_configured_bypass_count"])
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string())
    ));
    output.push_str(&format!(
        "proxy bypass sources: {}\n",
        value_u64(proxy, &["tun_proxy_bypass_sources"])
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string())
    ));
    output.push_str(&format!(
        "egress interface: {}\n",
        value_str(proxy, &["tun_egress_interface"]).unwrap_or("-")
    ));
    output.push_str(&format!(
        "bound interface: {}\n",
        value_str(proxy, &["tun_bound_interface"]).unwrap_or("-")
    ));
    output.push_str(&format!(
        "privilege: {}\n",
        format_tun_privilege_status(proxy)
    ));
    output.push_str(&format!(
        "watchdog restarts: {}\n",
        value_u64(proxy, &["tun_watchdog_restarts"])
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string())
    ));
    output.push_str(&format!(
        "last watchdog reason: {}\n",
        value_str(proxy, &["tun_last_watchdog_reason"]).unwrap_or("-")
    ));
    output.push_str(&format!(
        "detail: {}\n",
        value_str(proxy, &["tun_detail"]).unwrap_or("-")
    ));
    if let Some(warnings) =
        value_array(proxy, &["tun_warnings"]).filter(|warnings| !warnings.is_empty())
    {
        output.push_str("warnings:\n");
        for warning in warnings.iter().filter_map(Value::as_str) {
            output.push_str("  - ");
            output.push_str(warning);
            output.push('\n');
        }
    }
    output
}

fn format_tun_privilege_status(proxy: &Value) -> String {
    let required = value_bool(proxy, &["tun_requires_privilege"]);
    let verified = value_bool(proxy, &["tun_privilege_verified"]);
    match (required, verified) {
        (Some(true), Some(true)) => "required, verified".to_string(),
        (Some(true), Some(false)) => "required, missing".to_string(),
        (Some(true), None) => "required, unknown".to_string(),
        (Some(false), Some(true)) => "not required, verified".to_string(),
        (Some(false), Some(false)) | (Some(false), None) => "not required".to_string(),
        (None, _) => "-".to_string(),
    }
}

fn format_cli_system_proxy_status(status: &Value) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "enabled: {}\n",
        value_bool(status, &["enabled"]).map(on_off).unwrap_or("-")
    ));
    output.push_str(&format!(
        "supported: {}\n",
        value_bool(status, &["supported"])
            .map(on_off)
            .unwrap_or("-")
    ));
    output.push_str(&format!(
        "managed: {}\n",
        value_bool(status, &["managed"]).map(on_off).unwrap_or("-")
    ));
    output.push_str(&format!(
        "target recorded: {}\n",
        value_bool(status, &["target_recorded"])
            .map(on_off)
            .unwrap_or("-")
    ));
    output.push_str(&format!(
        "matches target: {}\n",
        value_bool(status, &["matches_target"])
            .map(on_off)
            .unwrap_or("-")
    ));
    output.push_str(&format!(
        "platform: {}\n",
        value_str(status, &["platform"]).unwrap_or("-")
    ));
    output.push_str(&format!(
        "protocol: {}\n",
        format_system_proxy_protocol(status)
    ));
    output.push_str(&format!(
        "target: {}\n",
        format_system_proxy_target(status.get("target"))
    ));
    if let Some(error) = value_str(status, &["error"]) {
        output.push_str("error: ");
        output.push_str(error);
        output.push('\n');
    }
    output
}
