use super::*;

pub(crate) fn draw_tui(frame: &mut Frame<'_>, app: &mut TuiApp) {
    match app.mode {
        TuiMode::Output => draw_tui_output(frame, app),
        TuiMode::Dashboard
        | TuiMode::CommandPalette
        | TuiMode::RouteModeSelector
        | TuiMode::GlobalTargetSelector
        | TuiMode::PolicyGroupListSelector
        | TuiMode::PolicyGroupSelector
        | TuiMode::RouteRules
        | TuiMode::RouteRuleActions
        | TuiMode::RouteRuleAdd
        | TuiMode::RouteRuleTargetSelector
        | TuiMode::Subscriptions
        | TuiMode::SubscriptionActions
        | TuiMode::SubscriptionAdd => draw_tui_dashboard(frame, app),
    }
    if app.mode == TuiMode::CommandPalette {
        draw_tui_command_palette(frame, app);
    } else if app.mode == TuiMode::RouteModeSelector {
        draw_tui_route_mode_selector(frame, app);
    } else if app.mode == TuiMode::GlobalTargetSelector {
        draw_tui_global_target_selector(frame, app);
    } else if app.mode == TuiMode::PolicyGroupListSelector {
        draw_tui_policy_group_list_selector(frame, app);
    } else if app.mode == TuiMode::PolicyGroupSelector {
        draw_tui_policy_group_selector(frame, app);
    } else if matches!(
        app.mode,
        TuiMode::RouteRules
            | TuiMode::RouteRuleActions
            | TuiMode::RouteRuleAdd
            | TuiMode::RouteRuleTargetSelector
    ) {
        draw_tui_route_rules(frame, app);
        if app.mode == TuiMode::RouteRuleActions {
            draw_tui_route_rule_actions(frame, app);
        } else if matches!(
            app.mode,
            TuiMode::RouteRuleAdd | TuiMode::RouteRuleTargetSelector
        ) {
            draw_tui_route_rule_add(frame, app);
            if app.mode == TuiMode::RouteRuleTargetSelector {
                draw_tui_route_rule_target_selector(frame, app);
            }
        }
    } else if matches!(
        app.mode,
        TuiMode::Subscriptions | TuiMode::SubscriptionActions | TuiMode::SubscriptionAdd
    ) {
        draw_tui_subscriptions(frame, app);
        if app.mode == TuiMode::SubscriptionActions {
            draw_tui_subscription_actions(frame, app);
        } else if app.mode == TuiMode::SubscriptionAdd {
            draw_tui_subscription_add(frame, app);
        }
    }
}
