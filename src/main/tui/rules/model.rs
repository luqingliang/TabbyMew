#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TuiRouteRuleAction {
    Edit,
    Delete,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TuiRouteRuleActionOption {
    pub(crate) action: TuiRouteRuleAction,
    pub(crate) label: &'static str,
    pub(crate) summary: &'static str,
}

pub(crate) fn tui_route_rule_actions() -> &'static [TuiRouteRuleActionOption] {
    const ACTIONS: &[TuiRouteRuleActionOption] = &[
        TuiRouteRuleActionOption {
            action: TuiRouteRuleAction::Edit,
            label: "Edit",
            summary: "Open this rule in the custom rule form.",
        },
        TuiRouteRuleActionOption {
            action: TuiRouteRuleAction::Delete,
            label: "Delete",
            summary: "Remove this custom rule.",
        },
    ];
    ACTIONS
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TuiRouteRuleMatchKind {
    pub(crate) key: &'static str,
    pub(crate) label: &'static str,
    pub(crate) summary: &'static str,
}

pub(crate) fn tui_route_rule_match_kinds() -> &'static [TuiRouteRuleMatchKind] {
    const KINDS: &[TuiRouteRuleMatchKind] = &[
        TuiRouteRuleMatchKind {
            key: "domain_suffix",
            label: "Domain Suffix",
            summary: "Match a domain suffix such as example.com.",
        },
        TuiRouteRuleMatchKind {
            key: "domain",
            label: "Domain",
            summary: "Match an exact domain.",
        },
        TuiRouteRuleMatchKind {
            key: "domain_keyword",
            label: "Domain Keyword",
            summary: "Match domains containing the keyword.",
        },
        TuiRouteRuleMatchKind {
            key: "ip_cidr",
            label: "IP CIDR",
            summary: "Match an IP range such as 10.0.0.0/8.",
        },
    ];
    KINDS
}
