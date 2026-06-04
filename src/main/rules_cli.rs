async fn run_rules_command(config: Option<&PathBuf>, command: RulesCommand) -> Result<()> {
    match command.command {
        RulesSubcommand::List(command) => {
            let client = rules_control_client(config, &command.control)?;
            let response = client.get_json("/rules").await?;
            print_rules_list(&response, command.filter.as_deref(), command.json)
        }
        RulesSubcommand::Add(command) => {
            let rule =
                build_cli_custom_route_rule(&command.kind, &command.value, &command.outbound)?;
            let response = rules_post_json(
                config,
                &command.control,
                "/control/api/custom-rules/upsert",
                serde_json::json!({ "rule": rule }),
            )
            .await?;
            print_rules_mutation_result(&response, command.json)
        }
        RulesSubcommand::Edit(command) => {
            let rule = build_cli_custom_route_rule(
                &command.upsert.kind,
                &command.upsert.value,
                &command.upsert.outbound,
            )?;
            let response = rules_post_json(
                config,
                &command.upsert.control,
                "/control/api/custom-rules/upsert",
                serde_json::json!({ "id": command.id, "rule": rule }),
            )
            .await?;
            print_rules_mutation_result(&response, command.upsert.json)
        }
        RulesSubcommand::Remove(command) => {
            let response = rules_post_json(
                config,
                &command.control,
                "/control/api/custom-rules/delete",
                serde_json::json!({ "id": command.id }),
            )
            .await?;
            print_rules_mutation_result(&response, command.json)
        }
        RulesSubcommand::Reload(command) => {
            let response = rules_post_json(
                config,
                &command.control,
                "/control/api/rules/reload",
                serde_json::json!({}),
            )
            .await?;
            print_rules_mutation_result(&response, command.json)
        }
        RulesSubcommand::Test(command) => {
            let response = rules_post_json(
                config,
                &command.control,
                "/control/api/route-test",
                serde_json::json!({
                    "destination": command.destination,
                    "port": command.port,
                    "network": command.network,
                    "inbound": command.inbound,
                }),
            )
            .await?;
            if command.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                print!("{}", format_rules_route_test_output(&response));
            }
            Ok(())
        }
    }
}

fn rules_control_client(
    config: Option<&PathBuf>,
    control: &RulesControlOptions,
) -> Result<ControlClient> {
    let listen =
        resolve_rules_control_listen(config, control.listen.clone(), control.state_dir.clone())?;
    Ok(ControlClient::new(
        listen,
        timeout_duration(control.timeout_ms)?,
    ))
}

fn resolve_rules_control_listen(
    config: Option<&PathBuf>,
    listen: Option<String>,
    state_dir: Option<PathBuf>,
) -> Result<std::net::SocketAddr> {
    if let Some(listen) = listen {
        return control::parse_listen(&listen).context("invalid control API listen address");
    }
    if let Some(listen) = control_listen_from_state(state_dir.clone()) {
        return control::parse_listen(&listen)
            .context("invalid control API listen address from local state");
    }
    let config_path = resolve_config_path(config)?;
    resolve_control_listen(&config_path, None, state_dir)
}

async fn rules_post_json(
    config: Option<&PathBuf>,
    control: &RulesControlOptions,
    path: &str,
    body: Value,
) -> Result<Value> {
    let client = rules_control_client(config, control)?;
    let token = control_token_for_state_dir(control.state_dir.as_deref())?;
    client.post_json(path, &token, &body).await
}

fn control_token_for_state_dir(state_dir: Option<&Path>) -> Result<String> {
    let state_dir = state_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(process_manager::default_state_dir);
    control_token_from_state_dir(&state_dir)
}

fn control_token_from_state_dir(state_dir: &Path) -> Result<String> {
    let paths = process_manager::paths(state_dir, None);
    let runtime_state_file = process_manager::runtime_state_file(state_dir);
    for state_file in [&paths.state_file, &runtime_state_file] {
        if let Ok(state) = process_manager::load_state(state_file)
            && process_manager::is_process_running(state.pid)
            && let Some(token) = state.control_token.filter(|token| !token.is_empty())
        {
            return Ok(token);
        }
    }

    bail!(
        "control token is not available in {} or {}; wait for service readiness or restart TabbyMew with the current binary",
        paths.state_file.display(),
        runtime_state_file.display()
    )
}

fn build_cli_custom_route_rule(kind: &str, value: &str, outbound: &str) -> Result<Value> {
    let kind = normalize_route_rule_key(kind)?;
    if !matches!(
        kind,
        "domain_suffix" | "domain" | "domain_keyword" | "ip_cidr"
    ) {
        bail!(
            "unsupported rule kind `{kind}`; expected domain-suffix, domain, domain-keyword, or ip-cidr"
        );
    }
    if value.trim().is_empty() {
        bail!("rule match content is required");
    }
    let outbound = outbound.trim();
    if outbound.is_empty() {
        bail!("rule outbound is required");
    }
    let mut rule = Map::new();
    push_route_rule_values(&mut rule, kind, value)?;
    rule.insert("outbound".to_string(), Value::String(outbound.to_string()));
    Ok(Value::Object(rule))
}

fn print_rules_list(response: &Value, filter: Option<&str>, json: bool) -> Result<()> {
    let control_snapshot = serde_json::json!({ "rules": response });
    let filter = filter.unwrap_or("");
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&structured_rules_list_json(
                Some(&control_snapshot),
                filter
            ))?
        );
    } else {
        print!(
            "{}",
            format_route_rules_output(Some(&control_snapshot), filter)
        );
    }
    Ok(())
}

fn print_rules_mutation_result(response: &Value, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&structured_rules_list_json(Some(response), ""))?
        );
    } else {
        print!("{}", format_route_rules_output(Some(response), ""));
    }
    Ok(())
}

fn structured_rules_list_json(control_snapshot: Option<&Value>, filter: &str) -> Value {
    let filter = filter.trim();
    let items = route_rule_items(control_snapshot);
    let visible = filtered_route_rule_items(control_snapshot, filter);
    let custom = items.iter().filter(|item| item.source == "custom").count();
    let subscription = items
        .iter()
        .filter(|item| item.source == "subscription")
        .count();
    let rules = visible
        .iter()
        .map(|item| {
            let mut rule = Map::new();
            rule.insert("index".to_string(), Value::from(item.index));
            rule.insert("source".to_string(), Value::String(item.source.clone()));
            rule.insert(
                "id".to_string(),
                item.id
                    .as_ref()
                    .map(|id| Value::String(id.clone()))
                    .unwrap_or(Value::Null),
            );
            rule.insert(
                "match_type".to_string(),
                Value::String(item.match_type.clone()),
            );
            rule.insert(
                "match_kind".to_string(),
                Value::String(item.match_kind.clone()),
            );
            rule.insert(
                "match_content".to_string(),
                Value::String(item.match_content.clone()),
            );
            rule.insert("outbound".to_string(), Value::String(item.outbound.clone()));
            rule.insert("summary".to_string(), Value::String(item.summary.clone()));
            if let Some(body) = item.rule.clone() {
                rule.insert("rule".to_string(), body);
            }
            Value::Object(rule)
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "final_outbound": control_snapshot.and_then(|value| value_str(value, &["rules", "final_outbound"])),
        "resolve_ip_cidr": control_snapshot.and_then(|value| value_bool(value, &["rules", "resolve_ip_cidr"])),
        "filter": filter,
        "visible": visible.len(),
        "total": items.len(),
        "custom": custom,
        "subscription": subscription,
        "rules": rules,
    })
}

fn format_rules_route_test_output(response: &Value) -> String {
    let mut output = String::new();
    output.push_str("route test:\n");
    output.push_str(&format!(
        "  destination: {}\n",
        value_str(response, &["destination"]).unwrap_or("-")
    ));
    output.push_str(&format!(
        "  network: {}\n",
        value_str(response, &["network"]).unwrap_or("-")
    ));
    output.push_str(&format!(
        "  inbound: {}\n",
        value_str(response, &["inbound"]).unwrap_or("-")
    ));
    output.push_str(&format!(
        "  mode: {}\n",
        value_str(response, &["mode"]).unwrap_or("-")
    ));
    output.push_str(&format!(
        "  route target: {}\n",
        value_str(response, &["route_target"]).unwrap_or("-")
    ));
    output.push_str(&format!(
        "  outbound: {}\n",
        value_str(response, &["outbound"]).unwrap_or("-")
    ));
    output.push_str(&format!(
        "  rule index: {}\n",
        value_u64(response, &["rule_index"])
            .map(|index| index.to_string())
            .unwrap_or_else(|| "-".to_string())
    ));
    if let Some(rule) = response.get("rule") {
        let summary = value_str(rule, &["summary"]).unwrap_or("-");
        let display = route_rule_display(rule.get("rule"), summary);
        output.push_str(&format!(
            "  rule: {} {} {} {} => {}\n",
            value_str(rule, &["source"]).unwrap_or("-"),
            value_str(rule, &["id"]).unwrap_or("-"),
            display.match_kind,
            display.match_content,
            display.outbound
        ));
    } else {
        output.push_str("  rule: -\n");
    }
    output
}
