#[path = "tui/groups/actions.rs"]
mod group_actions;
#[path = "tui/groups/delay.rs"]
mod group_delay;
#[path = "tui/groups/model.rs"]
mod group_model;
#[path = "tui/groups/query.rs"]
mod group_query;
#[path = "tui/groups/runtime.rs"]
mod group_runtime;
#[path = "tui/input.rs"]
mod input;
#[path = "tui/input/groups.rs"]
mod input_groups;
#[path = "tui/input/normal.rs"]
mod input_normal;
#[path = "tui/input/palette.rs"]
mod input_palette;
#[path = "tui/input/routing.rs"]
mod input_routing;
#[path = "tui/input/rules.rs"]
mod input_rules;
#[path = "tui/input/subscriptions.rs"]
mod input_subscriptions;
#[path = "tui/render.rs"]
mod render;
#[path = "tui/render/dashboard.rs"]
mod render_dashboard;
#[path = "tui/render/groups.rs"]
mod render_groups;
#[path = "tui/render/output.rs"]
mod render_output;
#[path = "tui/render/palette.rs"]
mod render_palette;
#[path = "tui/render/routing.rs"]
mod render_routing;
#[path = "tui/render/rules.rs"]
mod render_rules;
#[path = "tui/render/shared.rs"]
mod render_shared;
#[path = "tui/render/status.rs"]
mod render_status;
#[path = "tui/render/subscriptions.rs"]
mod render_subscriptions;
#[path = "tui/rules/commands.rs"]
mod rule_commands;
#[path = "tui/rules/form.rs"]
mod rule_form;
#[path = "tui/rules/list.rs"]
mod rule_list;
#[path = "tui/rules/model.rs"]
mod rule_model;
#[path = "tui/service.rs"]
mod service;
#[path = "tui/state.rs"]
mod state;
#[path = "tui/terminal.rs"]
mod terminal;

use self::{
    group_actions::*, group_delay::*, group_model::*, group_query::*, group_runtime::*,
    input::*, input_groups::*, input_normal::*, input_palette::*, input_routing::*,
    input_rules::*, input_subscriptions::*, render::*, render_dashboard::*, render_groups::*,
    render_output::*, render_palette::*, render_routing::*, render_rules::*, render_shared::*,
    render_status::*, render_subscriptions::*, rule_commands::*, rule_form::*, rule_list::*,
    rule_model::*, service::*, state::*, terminal::*,
};
