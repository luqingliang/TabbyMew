use super::*;

pub(super) fn tui_route_rule_items(control_snapshot: Option<&Value>) -> Vec<TuiRouteRuleItem> {
    control_snapshot
        .and_then(|value| value_array(value, &["rules", "rule_items"]))
        .map(|items| {
            items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let summary = value_str(item, &["summary"]).unwrap_or("-").to_string();
                    let rule = item.get("rule").cloned();
                    let display = tui_route_rule_display(rule.as_ref(), &summary);
                    TuiRouteRuleItem {
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

pub(super) fn tui_route_rule_display(rule: Option<&Value>, summary: &str) -> TuiRouteRuleDisplay {
    rule.and_then(tui_route_rule_display_from_rule)
        .unwrap_or_else(|| tui_route_rule_display_from_summary(summary))
}

pub(super) fn tui_route_rule_display_from_rule(rule: &Value) -> Option<TuiRouteRuleDisplay> {
    let outbound = value_str(rule, &["outbound"]).unwrap_or("-").to_string();
    let matches = tui_route_rule_display_fields()
        .iter()
        .filter_map(|field| {
            let values = value_array(rule, &[field.key])?;
            let values = values
                .iter()
                .filter_map(tui_route_rule_value_display)
                .collect::<Vec<_>>();
            (!values.is_empty()).then_some((
                field.key.to_string(),
                field.label.to_string(),
                values.join(","),
            ))
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [(kind, label, content)] => Some(TuiRouteRuleDisplay {
            match_type: kind.clone(),
            match_kind: label.clone(),
            match_content: content.clone(),
            outbound,
        }),
        [] => Some(TuiRouteRuleDisplay {
            match_type: "any".to_string(),
            match_kind: "Any".to_string(),
            match_content: "-".to_string(),
            outbound,
        }),
        _ => Some(TuiRouteRuleDisplay {
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

pub(super) fn tui_route_rule_value_display(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_string)
        .or_else(|| value.as_u64().map(|value| value.to_string()))
}

pub(super) fn tui_route_rule_display_from_summary(summary: &str) -> TuiRouteRuleDisplay {
    let (conditions, outbound) = summary
        .split_once(" -> ")
        .map(|(left, right)| (left.trim(), right.trim()))
        .unwrap_or((summary.trim(), "-"));
    if conditions.is_empty() || conditions == "any" {
        return TuiRouteRuleDisplay {
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
    TuiRouteRuleDisplay {
        match_type: if has_more {
            "composite".to_string()
        } else {
            key.to_string()
        },
        match_kind: if has_more {
            "Composite".to_string()
        } else {
            tui_route_rule_field_label(key).unwrap_or(key).to_string()
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
pub(super) struct TuiRouteRuleDisplayField {
    key: &'static str,
    label: &'static str,
}

pub(super) fn tui_route_rule_display_fields() -> &'static [TuiRouteRuleDisplayField] {
    const FIELDS: &[TuiRouteRuleDisplayField] = &[
        TuiRouteRuleDisplayField {
            key: "domain_suffix",
            label: "Domain Suffix",
        },
        TuiRouteRuleDisplayField {
            key: "domain",
            label: "Domain",
        },
        TuiRouteRuleDisplayField {
            key: "domain_keyword",
            label: "Domain Keyword",
        },
        TuiRouteRuleDisplayField {
            key: "ip_cidr",
            label: "IP CIDR",
        },
        TuiRouteRuleDisplayField {
            key: "inbound",
            label: "Inbound",
        },
        TuiRouteRuleDisplayField {
            key: "network",
            label: "Network",
        },
        TuiRouteRuleDisplayField {
            key: "port",
            label: "Port",
        },
        TuiRouteRuleDisplayField {
            key: "port_range",
            label: "Port Range",
        },
    ];
    FIELDS
}

pub(super) fn tui_route_rule_field_label(key: &str) -> Option<&'static str> {
    tui_route_rule_display_fields()
        .iter()
        .find(|field| field.key == key)
        .map(|field| field.label)
}

pub(super) fn filtered_tui_route_rule_items(
    control_snapshot: Option<&Value>,
    query: &str,
) -> Vec<TuiRouteRuleItem> {
    let query = query.trim().to_ascii_lowercase();
    tui_route_rule_items(control_snapshot)
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

pub(super) fn format_tui_route_rules_output(control_snapshot: Option<&Value>, filter: &str) -> String {
    let filter = filter.trim();
    let final_outbound = control_snapshot
        .and_then(|value| value_str(value, &["rules", "final_outbound"]))
        .unwrap_or("-");
    let resolve_ip_cidr = control_snapshot
        .and_then(|value| value_bool(value, &["rules", "resolve_ip_cidr"]))
        .map(on_off)
        .unwrap_or("-");
    let items = tui_route_rule_items(control_snapshot);
    let visible = filtered_tui_route_rule_items(control_snapshot, filter);
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
