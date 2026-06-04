use super::*;

pub(crate) async fn tui_rules_command(app: &mut TuiApp, args: &str) -> Result<String> {
    let args = args.trim();
    let (verb, rest) = split_first_word(args);
    match verb {
        Some("add") => tui_add_route_rule(app, rest).await,
        Some("remove" | "delete" | "rm") => tui_remove_route_rule(app, rest).await,
        Some("reload") => tui_reload_route_rules(app).await,
        Some("help") => Ok(tui_rules_help_text()),
        _ => {
            app.refresh_status().await?;
            Ok(format_route_rules_output(
                app.control_snapshot.as_ref(),
                args,
            ))
        }
    }
}

pub(crate) fn tui_rules_help_text() -> String {
    [
        "/rules [filter]",
        "/rules add <match=value...> -> <outbound>",
        "/rules remove <custom-id|rule-number>",
        "/rules reload",
        "",
        "match keys: domain, domain_suffix, domain_keyword, ip_cidr, inbound, network, port, port_range",
        "examples:",
        "/rules add domain_suffix=example.com -> Proxy",
        "/rules add domain_keyword=ads network=tcp -> block",
    ]
    .join("\n")
}

pub(crate) fn split_first_word(input: &str) -> (Option<&str>, &str) {
    let input = input.trim();
    if input.is_empty() {
        return (None, "");
    }
    match input.find(char::is_whitespace) {
        Some(index) => (Some(&input[..index]), input[index..].trim()),
        None => (Some(input), ""),
    }
}

pub(crate) async fn tui_add_route_rule(app: &mut TuiApp, args: &str) -> Result<String> {
    let rule = parse_tui_custom_route_rule(args)?;
    tui_upsert_route_rule(app, None, rule).await
}

pub(crate) async fn tui_add_route_rule_from_form(app: &mut TuiApp) -> Result<String> {
    let rule = build_tui_custom_route_rule_from_form(app)?;
    tui_upsert_route_rule(app, app.route_rule_form_id.clone(), rule).await
}

pub(crate) async fn tui_upsert_route_rule(
    app: &mut TuiApp,
    id: Option<String>,
    rule: Value,
) -> Result<String> {
    let response = tui_post_control_json(
        app,
        "/control/api/custom-rules/upsert",
        serde_json::json!({ "id": id, "rule": rule }),
        "adding custom route rule",
    )
    .await?;
    Ok(format!(
        "custom route rule saved\n\n{}",
        format_route_rules_output(Some(&response), "custom")
    ))
}

pub(crate) fn build_tui_custom_route_rule_from_form(app: &TuiApp) -> Result<Value> {
    let content = app.route_rule_add_content.trim();
    if content.is_empty() {
        bail!("match content is required");
    }
    let match_kind = selected_tui_route_rule_match_kind(app);
    let outbound = selected_tui_route_rule_target(app)
        .context("route target is required; check the active config")?;
    let mut rule = Map::new();
    push_route_rule_values(&mut rule, match_kind.key, content)?;
    rule.insert("outbound".to_string(), Value::String(outbound));
    Ok(Value::Object(rule))
}

pub(crate) async fn tui_remove_route_rule(app: &mut TuiApp, args: &str) -> Result<String> {
    app.refresh_status().await?;
    let id = resolve_tui_custom_route_rule_id(app.control_snapshot.as_ref(), args.trim())?;
    let response = tui_post_control_json(
        app,
        "/control/api/custom-rules/delete",
        serde_json::json!({ "id": id }),
        "removing custom route rule",
    )
    .await?;
    Ok(format!(
        "custom route rule removed\n\n{}",
        format_route_rules_output(Some(&response), "")
    ))
}

pub(crate) async fn tui_reload_route_rules(app: &mut TuiApp) -> Result<String> {
    let response = tui_post_control_json(
        app,
        "/control/api/rules/reload",
        serde_json::json!({}),
        "reloading route rules",
    )
    .await?;
    Ok(format!(
        "route rules reloaded\n\n{}",
        format_route_rules_output(Some(&response), "")
    ))
}

pub(crate) fn parse_tui_custom_route_rule(args: &str) -> Result<Value> {
    let args = args.trim();
    if args.is_empty() {
        bail!("custom route rule is required; use /rules help for examples");
    }
    let (match_text, outbound_text) = split_rule_outbound(args);
    let mut rule = Map::new();
    let mut outbound = outbound_text
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let mut has_match = false;

    for token in match_text.split_whitespace() {
        let (key, value) = token
            .split_once('=')
            .with_context(|| format!("rule term `{token}` must use key=value"))?;
        let key = normalize_route_rule_key(key)?;
        if key == "outbound" {
            outbound = Some(value.trim());
            continue;
        }
        push_route_rule_values(&mut rule, key, value)?;
        has_match = true;
    }

    if !has_match {
        bail!("custom route rule needs at least one match condition");
    }
    let outbound =
        outbound.context("custom route rule outbound is required; append -> <outbound>")?;
    if outbound.is_empty() {
        bail!("custom route rule outbound is empty");
    }
    rule.insert("outbound".to_string(), Value::String(outbound.to_string()));
    Ok(Value::Object(rule))
}

pub(crate) fn split_rule_outbound(args: &str) -> (&str, Option<&str>) {
    args.split_once("->")
        .map(|(left, right)| (left.trim(), Some(right.trim())))
        .unwrap_or((args, None))
}

pub(crate) fn normalize_route_rule_key(key: &str) -> Result<&'static str> {
    match key.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "domain" => Ok("domain"),
        "domain_suffix" | "suffix" => Ok("domain_suffix"),
        "domain_keyword" | "keyword" => Ok("domain_keyword"),
        "ip_cidr" | "cidr" => Ok("ip_cidr"),
        "inbound" => Ok("inbound"),
        "network" => Ok("network"),
        "port" => Ok("port"),
        "port_range" | "range" => Ok("port_range"),
        "outbound" | "target" => Ok("outbound"),
        other => bail!("unsupported rule key `{other}`"),
    }
}

pub(crate) fn push_route_rule_values(
    rule: &mut Map<String, Value>,
    key: &str,
    value: &str,
) -> Result<()> {
    let values = split_route_rule_values(value)?;
    if values.is_empty() {
        bail!("rule key `{key}` has no values");
    }
    let array = rule
        .entry(key.to_string())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .context("rule value is not an array")?;
    match key {
        "port" => {
            for value in values {
                let port = value
                    .parse::<u16>()
                    .with_context(|| format!("rule port `{value}` is invalid"))?;
                array.push(Value::from(port));
            }
        }
        "network" => {
            for value in values {
                let network = match value.to_ascii_lowercase().as_str() {
                    "tcp" => "tcp",
                    "udp" => "udp",
                    other => bail!("rule network `{other}` is invalid; expected tcp or udp"),
                };
                array.push(Value::String(network.to_string()));
            }
        }
        _ => {
            for value in values {
                array.push(Value::String(value));
            }
        }
    }
    Ok(())
}

pub(crate) fn split_route_rule_values(value: &str) -> Result<Vec<String>> {
    let values = value
        .split([',', '|'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if values.is_empty() {
        bail!("rule value is empty");
    }
    Ok(values)
}

pub(crate) fn resolve_tui_custom_route_rule_id(
    control_snapshot: Option<&Value>,
    input: &str,
) -> Result<String> {
    let input = input.trim();
    if input.is_empty() {
        bail!("custom rule id or rule number is required");
    }
    let items = route_rule_items(control_snapshot)
        .into_iter()
        .filter(|item| item.source == "custom")
        .collect::<Vec<_>>();
    if let Some(item) = items.iter().find(|item| item.id.as_deref() == Some(input)) {
        return item.id.clone().context("custom rule has no id");
    }
    if let Ok(index) = input.parse::<usize>() {
        if let Some(item) = items.iter().find(|item| item.index == index) {
            return item.id.clone().context("custom rule has no id");
        }
        bail!("custom route rule number {index} was not found");
    }
    let input_lower = input.to_ascii_lowercase();
    let matches = items
        .iter()
        .filter(|item| {
            item.id
                .as_deref()
                .is_some_and(|id| id.to_ascii_lowercase().contains(&input_lower))
                || item.summary.to_ascii_lowercase().contains(&input_lower)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [item] => item.id.clone().context("custom rule has no id"),
        [] => bail!("custom route rule `{input}` was not found"),
        _ => bail!("custom route rule `{input}` is ambiguous; use the exact id or rule number"),
    }
}

pub(crate) async fn remove_selected_tui_route_rule(app: &mut TuiApp) -> Result<()> {
    let items = app.filtered_route_rules();
    let item = items
        .get(app.selected_route_rule)
        .context("no route rule selected")?;
    if item.source != "custom" {
        bail!("only custom route rules can be removed from the TUI");
    }
    let id = item.id.clone().context("selected custom rule has no id")?;
    tui_remove_route_rule(app, &id).await?;
    Ok(())
}

pub(crate) async fn tui_post_control_json(
    app: &mut TuiApp,
    path: &str,
    body: Value,
    action: &str,
) -> Result<Value> {
    tui_post_control_json_with_timeout(app, path, body, action, app.session.timeout).await
}

pub(crate) async fn tui_post_control_json_with_timeout(
    app: &mut TuiApp,
    path: &str,
    body: Value,
    action: &str,
    timeout: Duration,
) -> Result<Value> {
    app.refresh_status().await?;
    let control = app.status.control_api.as_ref().with_context(|| {
        format!("TabbyMew service is not running; run /restart before {action}")
    })?;
    if !control.healthy {
        bail!(
            "control API is unhealthy at http://{}: {}",
            control.listen,
            control.error.as_deref().unwrap_or("unknown error")
        );
    }
    let listen = control::parse_listen(&control.listen)
        .context("invalid control API listen address from local state")?;
    let client = ControlClient::new(listen, timeout);
    let token = tui_control_token(&app.session)?;
    let response = client.post_json(path, &token, &body).await?;
    app.refresh_status().await?;
    Ok(response)
}
