use super::*;

#[derive(Debug, Clone)]
pub(crate) struct PolicyGroup {
    pub(crate) tag: String,
    pub(crate) kind: String,
    pub(crate) outbounds: Vec<String>,
    pub(crate) selected: String,
}

#[derive(Debug, Clone)]
pub(crate) struct PolicyGroupSelection {
    pub(crate) group: PolicyGroup,
    pub(crate) outbound: Option<String>,
}

pub(crate) fn current_route_mode(control_snapshot: Option<&Value>) -> Option<router::RouteMode> {
    control_snapshot
        .and_then(|value| value_str(value, &["routing", "mode"]))
        .and_then(router::RouteMode::parse)
}

pub(crate) fn parse_route_mode_arg(args: &str) -> Result<router::RouteMode> {
    let mut parts = args.split_whitespace();
    let mode = parts.next().context("route mode is required")?;
    if parts.next().is_some() {
        bail!("route mode accepts one value: rule, global, or direct");
    }
    match mode.to_ascii_lowercase().as_str() {
        "r" | "rule" => Ok(router::RouteMode::Rule),
        "g" | "global" => Ok(router::RouteMode::Global),
        "d" | "direct" => Ok(router::RouteMode::Direct),
        _ => bail!("unknown route mode `{mode}`; expected rule, global, or direct"),
    }
}

pub(crate) fn current_global_target(control_snapshot: Option<&Value>) -> Option<String> {
    control_snapshot
        .and_then(|value| value_str(value, &["routing", "global_outbound"]))
        .map(str::to_string)
}

pub(crate) fn global_targets(control_snapshot: Option<&Value>) -> Vec<String> {
    control_snapshot
        .and_then(|value| value_array(value, &["routing", "global_targets"]))
        .map(|targets| {
            targets
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn filtered_global_targets(
    control_snapshot: Option<&Value>,
    query: &str,
) -> Vec<String> {
    let query = query.trim().to_ascii_lowercase();
    global_targets(control_snapshot)
        .into_iter()
        .filter(|target| query.is_empty() || target.to_ascii_lowercase().contains(&query))
        .collect()
}

pub(crate) fn resolve_global_target(
    control_snapshot: Option<&Value>,
    input: &str,
) -> Result<String> {
    let input = input.trim();
    if input.is_empty() {
        bail!("global target is required");
    }
    let targets = global_targets(control_snapshot);
    if targets.is_empty() {
        bail!("global targets are not available; run /restart and check the active config");
    }
    if let Some(target) = targets.iter().find(|target| target.as_str() == input) {
        return Ok(target.clone());
    }
    if let Some(target) = targets
        .iter()
        .find(|target| target.eq_ignore_ascii_case(input))
    {
        return Ok(target.clone());
    }

    let query = input.to_ascii_lowercase();
    let matches = targets
        .iter()
        .filter(|target| target.to_ascii_lowercase().contains(&query))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [target] => Ok((*target).clone()),
        [] => bail!("global target `{input}` is not defined"),
        _ => bail!("global target `{input}` is ambiguous; refine the target name"),
    }
}

pub(crate) fn policy_groups(control_snapshot: Option<&Value>) -> Vec<PolicyGroup> {
    control_snapshot
        .and_then(|value| value_array(value, &["routing", "policy_groups"]))
        .map(|groups| {
            groups
                .iter()
                .filter_map(|group| {
                    let tag = value_str(group, &["tag"])?.to_string();
                    let kind = value_str(group, &["kind"]).unwrap_or("-").to_string();
                    let selected = value_str(group, &["selected"]).unwrap_or("-").to_string();
                    let outbounds = value_array(group, &["outbounds"])
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default();
                    Some(PolicyGroup {
                        tag,
                        kind,
                        outbounds,
                        selected,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn filtered_policy_groups(
    control_snapshot: Option<&Value>,
    query: &str,
) -> Vec<PolicyGroup> {
    let query = query.trim().to_ascii_lowercase();
    policy_groups(control_snapshot)
        .into_iter()
        .filter(|group| {
            query.is_empty()
                || group.tag.to_ascii_lowercase().contains(&query)
                || group.kind.to_ascii_lowercase().contains(&query)
                || group.selected.to_ascii_lowercase().contains(&query)
        })
        .collect()
}

pub(crate) fn current_policy_group_outbound(
    control_snapshot: Option<&Value>,
    group_tag: &str,
) -> Option<String> {
    policy_groups(control_snapshot)
        .into_iter()
        .find(|group| group.tag == group_tag)
        .map(|group| group.selected)
}

pub(crate) fn filtered_policy_group_outbounds(
    control_snapshot: Option<&Value>,
    group_tag: Option<&str>,
    query: &str,
) -> Vec<String> {
    let Some(group_tag) = group_tag else {
        return Vec::new();
    };
    let query = query.trim().to_ascii_lowercase();
    policy_groups(control_snapshot)
        .into_iter()
        .find(|group| group.tag == group_tag)
        .map(|group| {
            group
                .outbounds
                .into_iter()
                .filter(|outbound| {
                    query.is_empty() || outbound.to_ascii_lowercase().contains(&query)
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn parse_policy_group_selection(
    control_snapshot: Option<&Value>,
    args: &str,
) -> Result<PolicyGroupSelection> {
    let args = args.trim();
    if args.is_empty() {
        bail!("policy group is required; use /groups to list available groups");
    }
    let groups = policy_groups(control_snapshot);
    if groups.is_empty() {
        bail!("policy groups are not available; run /restart and check the active config");
    }
    let (group, outbound_input) = resolve_policy_group_with_remainder(&groups, args)?;
    let outbound = match outbound_input {
        Some(input) if !input.trim().is_empty() => {
            Some(resolve_policy_group_outbound(&group, input.trim())?)
        }
        _ => None,
    };
    Ok(PolicyGroupSelection { group, outbound })
}

pub(crate) fn resolve_policy_group_with_remainder(
    groups: &[PolicyGroup],
    input: &str,
) -> Result<(PolicyGroup, Option<String>)> {
    if let Some(group) = groups.iter().find(|group| group.tag == input) {
        return Ok((group.clone(), None));
    }

    let mut prefix_matches = groups
        .iter()
        .filter_map(|group| {
            input
                .strip_prefix(group.tag.as_str())
                .and_then(|rest| {
                    rest.chars()
                        .next()
                        .filter(|ch| ch.is_whitespace())
                        .map(|_| rest)
                })
                .map(|rest| (group, rest.trim()))
        })
        .collect::<Vec<_>>();
    prefix_matches.sort_by_key(|(group, _)| std::cmp::Reverse(group.tag.len()));
    if let Some((group, rest)) = prefix_matches.first() {
        return Ok(((*group).clone(), Some((*rest).to_string())));
    }

    if let Some(group) = groups
        .iter()
        .find(|group| group.tag.eq_ignore_ascii_case(input))
    {
        return Ok((group.clone(), None));
    }
    let input_lower = input.to_ascii_lowercase();
    let matches = groups
        .iter()
        .filter(|group| group.tag.to_ascii_lowercase().contains(&input_lower))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [group] => Ok(((*group).clone(), None)),
        [] => bail!("policy group `{input}` is not defined"),
        _ => bail!("policy group `{input}` is ambiguous; refine the group name"),
    }
}

pub(crate) fn resolve_policy_group_outbound(group: &PolicyGroup, input: &str) -> Result<String> {
    if let Some(outbound) = group
        .outbounds
        .iter()
        .find(|outbound| outbound.as_str() == input)
    {
        return Ok(outbound.clone());
    }
    if let Some(outbound) = group
        .outbounds
        .iter()
        .find(|outbound| outbound.eq_ignore_ascii_case(input))
    {
        return Ok(outbound.clone());
    }
    let input_lower = input.to_ascii_lowercase();
    let matches = group
        .outbounds
        .iter()
        .filter(|outbound| outbound.to_ascii_lowercase().contains(&input_lower))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [outbound] => Ok((*outbound).clone()),
        [] => bail!(
            "outbound `{input}` is not defined in policy group `{}`",
            group.tag
        ),
        _ => bail!(
            "outbound `{input}` is ambiguous in policy group `{}`; refine the outbound name",
            group.tag
        ),
    }
}

pub(crate) fn format_route_mode_switch_output(
    response: &Value,
    requested: router::RouteMode,
) -> String {
    let mode = value_str(response, &["mode"]).unwrap_or_else(|| requested.as_str());
    let global = value_str(response, &["global_outbound"]).unwrap_or("-");
    let direct = value_str(response, &["direct_outbound"]).unwrap_or("-");
    let groups = value_array_len(response, &["policy_groups"]).unwrap_or_default();
    format!(
        "route mode: {mode}\nglobal target: {global}\ndirect outbound: {direct}\npolicy groups: {groups}\n"
    )
}

pub(crate) fn format_global_target_switch_output(
    response: &Value,
    requested: &str,
    before_mode: Option<router::RouteMode>,
    after_mode: Option<router::RouteMode>,
) -> String {
    let target = value_str(response, &["global_outbound"]).unwrap_or(requested);
    let mode = value_str(response, &["mode"])
        .map(str::to_string)
        .or_else(|| after_mode.map(|mode| mode.as_str().to_string()))
        .unwrap_or_else(|| "-".to_string());
    let mode_note = match (before_mode, after_mode) {
        (Some(before), Some(after)) if before == after => {
            format!("unchanged ({})", after.as_str())
        }
        (Some(before), Some(after)) => format!("changed {} -> {}", before.as_str(), after.as_str()),
        _ => mode,
    };
    format!("global target: {target}\nroute mode: {mode_note}\n")
}

pub(crate) fn control_snapshot_tun_enabled(control_snapshot: Option<&Value>) -> Option<bool> {
    control_snapshot.and_then(|value| value_bool(value, &["proxy", "tun_enabled"]))
}

pub(crate) fn control_snapshot_system_proxy_enabled(
    control_snapshot: Option<&Value>,
) -> Option<bool> {
    control_snapshot.and_then(|value| {
        let enabled = value_bool(value, &["system_proxy", "enabled"])?;
        let managed = value_bool(value, &["system_proxy", "managed"])?;
        let unrecorded_match = value_bool(value, &["system_proxy", "matches_target"]) == Some(true)
            && value_bool(value, &["system_proxy", "target_recorded"]) == Some(false);
        Some(enabled && (managed || unrecorded_match))
    })
}

pub(crate) fn control_snapshot_lan_proxy_enabled(control_snapshot: Option<&Value>) -> Option<bool> {
    control_snapshot.and_then(|value| {
        value_bool(value, &["lan_proxy", "enabled"])
            .or_else(|| value_bool(value, &["proxy", "lan_enabled"]))
    })
}

pub(crate) fn format_control_snapshot_tun_state(control_snapshot: Option<&Value>) -> String {
    let Some(control_snapshot) = control_snapshot else {
        return "-".to_string();
    };
    format_tun_state(
        value_bool(control_snapshot, &["proxy", "tun_enabled"]),
        value_str(control_snapshot, &["proxy", "tun_status"]),
    )
}

pub(crate) fn format_tun_state(enabled: Option<bool>, status: Option<&str>) -> String {
    let state = enabled
        .map(on_off)
        .or_else(|| tun_state_from_status(status))
        .unwrap_or("-");
    match status.filter(|status| tun_status_needs_suffix(status)) {
        Some(status) => format!("{state} ({status})"),
        None => state.to_string(),
    }
}

pub(crate) fn tun_state_from_status(status: Option<&str>) -> Option<&'static str> {
    match status {
        Some("running") => Some("on"),
        Some("stopped")
        | Some("not_configured")
        | Some("requires_permission")
        | Some("requires_configuration")
        | Some("unsupported")
        | Some("failed") => Some("off"),
        _ => None,
    }
}

pub(crate) fn tun_status_needs_suffix(status: &str) -> bool {
    !matches!(status, "running" | "stopped")
}

pub(crate) fn format_tun_switch_output(snapshot: &Value, requested_enabled: bool) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "requested: {}\n",
        if requested_enabled {
            "enable"
        } else {
            "disable"
        }
    ));
    output.push_str(&format!(
        "enabled: {}\n",
        snapshot
            .get("tun_enabled")
            .and_then(Value::as_bool)
            .map(on_off)
            .unwrap_or("-")
    ));
    output.push_str(&format!(
        "status: {}\n",
        format_tun_state(
            snapshot.get("tun_enabled").and_then(Value::as_bool),
            value_str(snapshot, &["tun_status"]),
        )
    ));
    output.push_str(&format!(
        "configured inbounds: {}\n",
        value_u64(snapshot, &["configured_tun_inbounds"])
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string())
    ));
    output.push_str(&format!(
        "detail: {}\n",
        value_str(snapshot, &["tun_detail"]).unwrap_or("-")
    ));
    if let Some(warnings) = snapshot.get("tun_warnings").and_then(Value::as_array)
        && !warnings.is_empty()
    {
        output.push_str("warnings:\n");
        for warning in warnings.iter().filter_map(Value::as_str) {
            output.push_str("  - ");
            output.push_str(warning);
            output.push('\n');
        }
    }
    if let Some(error) = value_str(snapshot, &["last_error"]) {
        output.push_str("last error: ");
        output.push_str(error);
        output.push('\n');
    }
    output
}

pub(crate) fn format_system_proxy_switch_output(
    snapshot: &Value,
    requested_enabled: bool,
) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "requested: {}\n",
        if requested_enabled {
            "enable"
        } else {
            "disable"
        }
    ));
    output.push_str(&format!(
        "enabled: {}\n",
        value_bool(snapshot, &["enabled"])
            .map(on_off)
            .unwrap_or("-")
    ));
    output.push_str(&format!(
        "supported: {}\n",
        value_bool(snapshot, &["supported"])
            .map(on_off)
            .unwrap_or("-")
    ));
    output.push_str(&format!(
        "managed: {}\n",
        value_bool(snapshot, &["managed"])
            .map(on_off)
            .unwrap_or("-")
    ));
    output.push_str(&format!(
        "target recorded: {}\n",
        value_bool(snapshot, &["target_recorded"])
            .map(on_off)
            .unwrap_or("-")
    ));
    output.push_str(&format!(
        "matches target: {}\n",
        value_bool(snapshot, &["matches_target"])
            .map(on_off)
            .unwrap_or("-")
    ));
    output.push_str(&format!(
        "platform: {}\n",
        value_str(snapshot, &["platform"]).unwrap_or("-")
    ));
    output.push_str(&format!(
        "protocol: {}\n",
        format_system_proxy_protocol(snapshot)
    ));
    output.push_str(&format!(
        "target: {}\n",
        format_system_proxy_target(snapshot.get("target"))
    ));
    if let Some(error) = value_str(snapshot, &["error"]) {
        output.push_str("error: ");
        output.push_str(error);
        output.push('\n');
    }
    output
}

pub(crate) fn format_lan_proxy_switch_output(
    snapshot: &Value,
    requested_enabled: bool,
    control_snapshot: Option<&Value>,
) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "requested: {}\n",
        if requested_enabled {
            "enable"
        } else {
            "disable"
        }
    ));
    output.push_str(&format!(
        "enabled: {}\n",
        value_bool(snapshot, &["enabled"])
            .map(on_off)
            .unwrap_or("-")
    ));
    output.push_str(&format!(
        "available: {}\n",
        value_bool(snapshot, &["available"])
            .map(on_off)
            .unwrap_or("-")
    ));
    if let Some(control_snapshot) = control_snapshot {
        let enabled = value_bool(snapshot, &["enabled"]).unwrap_or(requested_enabled);
        let listeners = if enabled {
            proxy_listener_values(control_snapshot, "effective_listeners")
                .or_else(|| proxy_listener_values(control_snapshot, "lan_listeners"))
        } else {
            proxy_listener_values(control_snapshot, "effective_listeners")
                .or_else(|| proxy_listener_values(control_snapshot, "local_listeners"))
        }
        .unwrap_or_else(|| inbound_listener_values(control_snapshot));
        output.push_str(&format!(
            "listeners: {}\n",
            if listeners.is_empty() {
                "-".to_string()
            } else {
                summarize_listeners(&listeners)
            }
        ));
    }
    output.push_str(&format!(
        "detail: {}\n",
        value_str(snapshot, &["detail"]).unwrap_or("-")
    ));
    output
}

pub(crate) fn format_system_proxy_target(target: Option<&Value>) -> String {
    let Some(target) = target else {
        return "-".to_string();
    };
    if target.is_null() {
        return "-".to_string();
    }

    let mut endpoints = Vec::new();
    for key in ["http", "https", "socks"] {
        if let Some(address) = value_str(target, &[key, "address"]) {
            endpoints.push(format!("{key}={address}"));
        }
    }
    let source = value_str(target, &["source"]);
    match (source, endpoints.is_empty()) {
        (Some(source), false) => format!("{source}: {}", endpoints.join(", ")),
        (Some(source), true) => source.to_string(),
        (None, false) => endpoints.join(", "),
        (None, true) => "-".to_string(),
    }
}

pub(crate) fn format_system_proxy_protocol(snapshot: &Value) -> String {
    value_str(snapshot, &["protocol"])
        .and_then(system_proxy::SystemProxyProtocol::parse)
        .map(|protocol| protocol.label().to_string())
        .or_else(|| value_str(snapshot, &["protocol"]).map(str::to_string))
        .unwrap_or_else(|| "-".to_string())
}

pub(crate) fn proxy_listener_values(control_snapshot: &Value, key: &str) -> Option<Vec<String>> {
    let listeners = value_string_array(control_snapshot, &["proxy", key]);
    (!listeners.is_empty()).then_some(listeners)
}

pub(crate) fn inbound_listener_values(control_snapshot: &Value) -> Vec<String> {
    value_array(control_snapshot, &["inbounds", "items"])
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(listener_from_inbound_summary)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub(crate) fn listener_from_inbound_summary(summary: &str) -> Option<String> {
    let (_, address) = summary.split_once('@')?;
    address.split_whitespace().next().map(str::to_string)
}

pub(crate) fn summarize_listeners(listeners: &[String]) -> String {
    let shown = listeners.iter().take(2).cloned().collect::<Vec<_>>();
    match listeners.len().saturating_sub(shown.len()) {
        0 => shown.join(", "),
        hidden => format!("{} +{hidden}", shown.join(", ")),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RouteRuleItem {
    pub(crate) index: usize,
    pub(crate) source: String,
    pub(crate) id: Option<String>,
    pub(crate) match_type: String,
    pub(crate) match_kind: String,
    pub(crate) match_content: String,
    pub(crate) outbound: String,
    pub(crate) summary: String,
    pub(crate) rule: Option<Value>,
}

#[derive(Debug, Clone)]
pub(crate) struct RouteRuleDisplay {
    pub(crate) match_type: String,
    pub(crate) match_kind: String,
    pub(crate) match_content: String,
    pub(crate) outbound: String,
}

pub(crate) fn route_rule_items(control_snapshot: Option<&Value>) -> Vec<RouteRuleItem> {
    control_snapshot
        .and_then(|value| value_array(value, &["rules", "rule_items"]))
        .map(|items| {
            items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let summary = value_str(item, &["summary"]).unwrap_or("-").to_string();
                    let rule = item.get("rule").cloned();
                    let display = route_rule_display(rule.as_ref(), &summary);
                    RouteRuleItem {
                        index: index + 1,
                        source: value_str(item, &["source"]).unwrap_or("-").to_string(),
                        id: value_str(item, &["id"]).map(str::to_string),
                        match_type: display.match_type,
                        match_kind: display.match_kind,
                        match_content: display.match_content,
                        outbound: display.outbound,
                        summary,
                        rule,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn route_rule_display(rule: Option<&Value>, summary: &str) -> RouteRuleDisplay {
    rule.and_then(route_rule_display_from_rule)
        .unwrap_or_else(|| route_rule_display_from_summary(summary))
}

pub(crate) fn route_rule_display_from_rule(rule: &Value) -> Option<RouteRuleDisplay> {
    let outbound = value_str(rule, &["outbound"]).unwrap_or("-").to_string();
    let matches = route_rule_display_fields()
        .iter()
        .filter_map(|field| {
            let values = value_array(rule, &[field.key])?;
            let values = values
                .iter()
                .filter_map(route_rule_value_display)
                .collect::<Vec<_>>();
            (!values.is_empty()).then_some((
                field.key.to_string(),
                field.label.to_string(),
                values.join(","),
            ))
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [(kind, label, content)] => Some(RouteRuleDisplay {
            match_type: kind.clone(),
            match_kind: label.clone(),
            match_content: content.clone(),
            outbound,
        }),
        [] => Some(RouteRuleDisplay {
            match_type: "any".to_string(),
            match_kind: "Any".to_string(),
            match_content: "-".to_string(),
            outbound,
        }),
        _ => Some(RouteRuleDisplay {
            match_type: "composite".to_string(),
            match_kind: "Composite".to_string(),
            match_content: matches
                .iter()
                .map(|(_, label, content)| format!("{label}={content}"))
                .collect::<Vec<_>>()
                .join("; "),
            outbound,
        }),
    }
}

pub(crate) fn route_rule_value_display(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_string)
        .or_else(|| value.as_u64().map(|value| value.to_string()))
}

pub(crate) fn route_rule_display_from_summary(summary: &str) -> RouteRuleDisplay {
    let (conditions, outbound) = summary
        .split_once(" -> ")
        .map(|(left, right)| (left.trim(), right.trim()))
        .unwrap_or((summary.trim(), "-"));
    if conditions.is_empty() || conditions == "any" {
        return RouteRuleDisplay {
            match_type: "any".to_string(),
            match_kind: "Any".to_string(),
            match_content: "-".to_string(),
            outbound: outbound.to_string(),
        };
    }
    let first = conditions.split(';').next().unwrap_or(conditions).trim();
    let (key, content) = first
        .split_once('=')
        .map(|(key, value)| (key.trim(), value.trim()))
        .unwrap_or(("Composite", first));
    let has_more = conditions.split(';').nth(1).is_some();
    RouteRuleDisplay {
        match_type: if has_more {
            "composite".to_string()
        } else {
            key.to_string()
        },
        match_kind: if has_more {
            "Composite".to_string()
        } else {
            route_rule_field_label(key).unwrap_or(key).to_string()
        },
        match_content: if has_more {
            conditions.to_string()
        } else if content.is_empty() {
            "-".to_string()
        } else {
            content.replace('|', ",")
        },
        outbound: outbound.to_string(),
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RouteRuleDisplayField {
    pub(crate) key: &'static str,
    pub(crate) label: &'static str,
}

pub(crate) fn route_rule_display_fields() -> &'static [RouteRuleDisplayField] {
    const FIELDS: &[RouteRuleDisplayField] = &[
        RouteRuleDisplayField {
            key: "domain_suffix",
            label: "Domain Suffix",
        },
        RouteRuleDisplayField {
            key: "domain",
            label: "Domain",
        },
        RouteRuleDisplayField {
            key: "domain_keyword",
            label: "Domain Keyword",
        },
        RouteRuleDisplayField {
            key: "ip_cidr",
            label: "IP CIDR",
        },
        RouteRuleDisplayField {
            key: "inbound",
            label: "Inbound",
        },
        RouteRuleDisplayField {
            key: "network",
            label: "Network",
        },
        RouteRuleDisplayField {
            key: "port",
            label: "Port",
        },
        RouteRuleDisplayField {
            key: "port_range",
            label: "Port Range",
        },
    ];
    FIELDS
}

pub(crate) fn route_rule_field_label(key: &str) -> Option<&'static str> {
    route_rule_display_fields()
        .iter()
        .find(|field| field.key == key)
        .map(|field| field.label)
}

pub(crate) fn filtered_route_rule_items(
    control_snapshot: Option<&Value>,
    query: &str,
) -> Vec<RouteRuleItem> {
    let query = query.trim().to_ascii_lowercase();
    route_rule_items(control_snapshot)
        .into_iter()
        .filter(|item| {
            query.is_empty()
                || item.source.to_ascii_lowercase().contains(&query)
                || item
                    .id
                    .as_deref()
                    .is_some_and(|id| id.to_ascii_lowercase().contains(&query))
                || item.match_type.to_ascii_lowercase().contains(&query)
                || item.match_kind.to_ascii_lowercase().contains(&query)
                || item.match_content.to_ascii_lowercase().contains(&query)
                || item.outbound.to_ascii_lowercase().contains(&query)
                || item.summary.to_ascii_lowercase().contains(&query)
        })
        .collect()
}

pub(crate) fn format_route_rules_output(control_snapshot: Option<&Value>, filter: &str) -> String {
    let filter = filter.trim();
    let final_outbound = control_snapshot
        .and_then(|value| value_str(value, &["rules", "final_outbound"]))
        .unwrap_or("-");
    let resolve_ip_cidr = control_snapshot
        .and_then(|value| value_bool(value, &["rules", "resolve_ip_cidr"]))
        .map(on_off)
        .unwrap_or("-");
    let items = route_rule_items(control_snapshot);
    let visible = filtered_route_rule_items(control_snapshot, filter);
    let custom = items.iter().filter(|item| item.source == "custom").count();
    let subscription = items
        .iter()
        .filter(|item| item.source == "subscription")
        .count();
    let mut output = format!(
        "route rules: {} visible / {} total ({custom} custom, {subscription} subscription)\n",
        visible.len(),
        items.len()
    );
    output.push_str(&format!("final outbound: {final_outbound}\n"));
    output.push_str(&format!("resolve ip_cidr: {resolve_ip_cidr}\n"));
    if !filter.is_empty() {
        output.push_str(&format!("filter: {filter}\n"));
    }
    if visible.is_empty() {
        output.push_str("rules: none\n");
        return output;
    }
    output.push_str("rules:\n");
    output.push_str(&format!(
        "{:>3}  {:<12} {:<20} {:<16} {:<28} {}\n",
        "#", "source", "id", "match", "content", "target"
    ));
    for item in &visible {
        output.push_str(&format!(
            "{:>3}. {:<12} {:<20} {:<16} {:<28} {}\n",
            item.index,
            item.source,
            item.id.as_deref().unwrap_or("-"),
            item.match_kind,
            item.match_content,
            item.outbound
        ));
    }
    output
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

pub(crate) fn format_policy_group_selection_output(
    response: &Value,
    group: &str,
    requested_outbound: &str,
    before_mode: Option<router::RouteMode>,
    after_mode: Option<router::RouteMode>,
) -> String {
    let selected = value_array(response, &["policy_groups"])
        .and_then(|items| {
            items.iter().find_map(|item| {
                (value_str(item, &["tag"]) == Some(group))
                    .then(|| value_str(item, &["selected"]))
                    .flatten()
            })
        })
        .unwrap_or(requested_outbound);
    let mode = value_str(response, &["mode"])
        .map(str::to_string)
        .or_else(|| after_mode.map(|mode| mode.as_str().to_string()))
        .unwrap_or_else(|| "-".to_string());
    let mode_note = match (before_mode, after_mode) {
        (Some(before), Some(after)) if before == after => {
            format!("unchanged ({})", after.as_str())
        }
        (Some(before), Some(after)) => format!("changed {} -> {}", before.as_str(), after.as_str()),
        _ => mode,
    };
    format!("policy group: {group}\nselected: {selected}\nroute mode: {mode_note}\n")
}

pub(crate) fn indent_text(text: &str) -> String {
    text.lines()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}
