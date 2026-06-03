use super::*;

#[derive(Debug, Clone)]
pub(super) struct TuiRouteRuleItem {
    pub(super) index: usize,
    pub(super) source: String,
    pub(super) id: Option<String>,
    pub(super) match_type: String,
    pub(super) match_kind: String,
    pub(super) match_content: String,
    pub(super) outbound: String,
    pub(super) summary: String,
    pub(super) rule: Option<Value>,
}

#[derive(Debug, Clone)]
pub(super) struct TuiRouteRuleDisplay {
    pub(super) match_type: String,
    pub(super) match_kind: String,
    pub(super) match_content: String,
    pub(super) outbound: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TuiRouteRuleAction {
    Edit,
    Delete,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct TuiRouteRuleActionOption {
    pub(super) action: TuiRouteRuleAction,
    pub(super) label: &'static str,
    pub(super) summary: &'static str,
}

pub(super) fn tui_route_rule_actions() -> &'static [TuiRouteRuleActionOption] {
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
pub(super) struct TuiRouteRuleMatchKind {
    pub(super) key: &'static str,
    pub(super) label: &'static str,
    pub(super) summary: &'static str,
}

pub(super) fn tui_route_rule_match_kinds() -> &'static [TuiRouteRuleMatchKind] {
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
