use super::*;

pub(super) fn tui_policy_groups(control_snapshot: Option<&Value>) -> Vec<TuiPolicyGroup> {
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
                    Some(TuiPolicyGroup {
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

pub(super) fn filtered_tui_policy_groups(control_snapshot: Option<&Value>, query: &str) -> Vec<TuiPolicyGroup> {
    let query = query.trim().to_ascii_lowercase();
    tui_policy_groups(control_snapshot)
        .into_iter()
        .filter(|group| {
            query.is_empty()
                || group.tag.to_ascii_lowercase().contains(&query)
                || group.kind.to_ascii_lowercase().contains(&query)
                || group.selected.to_ascii_lowercase().contains(&query)
        })
        .collect()
}

pub(super) fn current_tui_policy_group_outbound(
    control_snapshot: Option<&Value>,
    group_tag: &str,
) -> Option<String> {
    tui_policy_groups(control_snapshot)
        .into_iter()
        .find(|group| group.tag == group_tag)
        .map(|group| group.selected)
}

pub(super) fn filtered_tui_policy_group_outbounds(
    control_snapshot: Option<&Value>,
    group_tag: Option<&str>,
    query: &str,
) -> Vec<String> {
    let Some(group_tag) = group_tag else {
        return Vec::new();
    };
    let query = query.trim().to_ascii_lowercase();
    tui_policy_groups(control_snapshot)
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
pub(super) fn parse_tui_policy_group_selection(
    control_snapshot: Option<&Value>,
    args: &str,
) -> Result<TuiPolicyGroupSelection> {
    let args = args.trim();
    if args.is_empty() {
        bail!("policy group is required; use /groups to list available groups");
    }
    let groups = tui_policy_groups(control_snapshot);
    if groups.is_empty() {
        bail!("policy groups are not available; run /restart and check the active config");
    }
    let (group, outbound_input) = resolve_tui_policy_group_with_remainder(&groups, args)?;
    let outbound = match outbound_input {
        Some(input) if !input.trim().is_empty() => {
            Some(resolve_tui_policy_group_outbound(&group, input.trim())?)
        }
        _ => None,
    };
    Ok(TuiPolicyGroupSelection { group, outbound })
}

pub(super) fn resolve_tui_policy_group_with_remainder(
    groups: &[TuiPolicyGroup],
    input: &str,
) -> Result<(TuiPolicyGroup, Option<String>)> {
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

pub(super) fn resolve_tui_policy_group_outbound(group: &TuiPolicyGroup, input: &str) -> Result<String> {
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
