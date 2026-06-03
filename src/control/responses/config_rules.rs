fn config_response(summary: &ConfigSummary) -> ConfigResponse {
    ConfigResponse {
        log_level: summary.log_level.clone(),
        dns: summary.dns.clone(),
        route: RouteSummaryResponse {
            final_outbound: summary.route_final.clone(),
            resolve_ip_cidr: summary.route_resolve_ip_cidr,
            rule_sets: summary.route_rule_sets.clone(),
            rules: summary.route_rules.clone(),
            rule_items: subscription_rule_items(&summary.route_rules),
        },
        policy_groups: summary.policy_groups.clone(),
        services: summary.services.clone(),
        summary: summary.lines(),
    }
}

fn route_rule_items_response(active: &ActiveConfig) -> Vec<RouteRuleItemResponse> {
    let mut items = active
        .custom_route_rules
        .clone()
        .into_iter()
        .map(|rule| RouteRuleItemResponse {
            source: RouteRuleSource::Custom,
            id: Some(rule.id),
            summary: route_rule_summary(&rule.rule),
            rule: Some(rule.rule),
        })
        .collect::<Vec<_>>();
    items.extend(subscription_rule_items(&active.subscription_route_rules));
    items
}

fn subscription_rule_items(rules: &[String]) -> Vec<RouteRuleItemResponse> {
    rules
        .iter()
        .map(|summary| RouteRuleItemResponse {
            source: RouteRuleSource::Subscription,
            id: None,
            summary: summary.clone(),
            rule: None,
        })
        .collect()
}

pub fn custom_route_rules_path_for_state_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(CUSTOM_ROUTE_RULES_FILE)
}

fn custom_route_rules_path_for_subscription_config(config_path: &Path) -> Option<PathBuf> {
    let subscriptions_dir = config_path.parent()?;
    let profiles_dir = subscriptions_dir.parent()?;
    let state_dir = profiles_dir.parent()?;
    Some(custom_route_rules_path_for_state_dir(state_dir))
}

pub fn apply_custom_route_rules_from_state_dir(
    config: &Config,
    config_path: Option<&Path>,
    state_dir: &Path,
) -> Result<Config> {
    let path = custom_route_rules_path_for_state_dir(state_dir);
    let rules = custom_route_rules_for_config_path(config_path, Some(&path))?;
    Ok(config_with_custom_route_rules(config, &rules))
}

fn config_with_custom_route_rules(config: &Config, custom_rules: &[CustomRouteRule]) -> Config {
    if custom_rules.is_empty() {
        return config.clone();
    }
    let mut merged = config.clone();
    let mut rules = custom_rules
        .iter()
        .map(|custom| custom.rule.clone())
        .collect::<Vec<_>>();
    rules.extend(merged.route.rules);
    merged.route.rules = rules;
    merged
}
