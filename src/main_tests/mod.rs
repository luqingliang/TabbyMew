use super::*;

fn test_tui_app() -> TuiApp {
    let state_dir = env::temp_dir().join(format!("tabbymew-tui-test-{}", std::process::id()));
    let status = StatusReport::new(
        ServiceStatus {
            status: ServiceStatusKind::Stopped,
            running: false,
            stale: false,
            pid: None,
            memory_rss_bytes: None,
            config: None,
            log: None,
            listen: None,
            started_at_unix: None,
            state_dir: state_dir.clone(),
            state_file: state_dir.join("tabbymew-state.json"),
            runtime_state_file: state_dir.join("tabbymew-runtime.json"),
            preferences_file: state_dir.join("tabbymew-preferences.json"),
            active_state_file: None,
            state_source: None,
            state_file_exists: false,
            runtime_state_file_exists: false,
            heartbeat_at_unix: None,
            heartbeat_age_seconds: None,
            heartbeat_stale: false,
            managed_system_proxy_recorded: false,
            cleanup_items: Vec::new(),
            state_error: None,
            preference_error: None,
        },
        None,
    );
    TuiApp {
        session: ShellSession {
            config: None,
            state_dir,
            timeout: Duration::from_secs(1),
        },
        mode: TuiMode::Dashboard,
        status,
        control_snapshot: None,
        command_query: String::new(),
        selected_command: 0,
        route_mode_selection: 0,
        global_target_query: String::new(),
        selected_global_target: 0,
        policy_group_query: String::new(),
        selected_policy_group: 0,
        selected_policy_group_tag: None,
        policy_group_outbound_query: String::new(),
        selected_policy_group_outbound: 0,
        policy_group_delay_group: None,
        policy_group_delay_results: Vec::new(),
        policy_group_delay_run: None,
        policy_group_delay_next_run_id: 1,
        policy_group_delay_updates: None,
        route_rule_query: String::new(),
        selected_route_rule: 0,
        selected_route_rule_action: 0,
        route_rule_form_id: None,
        route_rule_add_field: 0,
        route_rule_add_content: String::new(),
        selected_route_rule_match_kind: 0,
        route_rule_target_query: String::new(),
        selected_route_rule_target: 0,
        selected_route_rule_target_candidate: 0,
        subscription_query: String::new(),
        selected_subscription: 0,
        selected_subscription_action: 0,
        subscription_add_field: 0,
        subscription_add_name: String::new(),
        subscription_add_url: String::new(),
        subscription_add_auto_update: true,
        output_title: "Status".to_string(),
        output: String::new(),
        output_scroll: 0,
        dashboard_log_tail: String::new(),
        traffic_sample: None,
        traffic_speed: TuiTrafficSpeed::default(),
        last_message: String::new(),
        last_refresh: Instant::now(),
        exit_confirmation: None,
        exit_action: None,
    }
}

mod cleanup;
mod cli_lifecycle;
mod cli_runtime;
mod control_tokens;
mod doctor;
mod lifecycle;
mod shell;
mod tui_groups;
mod tui_lifecycle;
mod tui_rules;
mod tui_runtime;
mod tui_status;
mod tui_subscriptions;
