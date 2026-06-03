use super::*;

#[derive(Clone)]
pub(super) struct ShellSession {
    pub(super) config: Option<PathBuf>,
    pub(super) state_dir: PathBuf,
    pub(super) timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TuiServiceStartupKind {
    Existing,
    AdoptedRuntime,
    Started,
}

impl TuiServiceStartupKind {
    pub(super) fn started_by_tui(self) -> bool {
        self == Self::Started
    }
}

#[derive(Debug)]
pub(super) struct TuiServiceStartup {
    pub(super) kind: TuiServiceStartupKind,
    pub(super) message: String,
}

#[derive(Debug)]
pub(super) struct ShellCommandSpec {
    pub(super) name: &'static str,
    pub(super) aliases: &'static [&'static str],
    pub(super) category: &'static str,
    pub(super) usage: &'static str,
    pub(super) summary: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TuiMode {
    Dashboard,
    CommandPalette,
    RouteModeSelector,
    GlobalTargetSelector,
    PolicyGroupListSelector,
    PolicyGroupSelector,
    RouteRules,
    RouteRuleActions,
    RouteRuleAdd,
    RouteRuleTargetSelector,
    Subscriptions,
    SubscriptionActions,
    SubscriptionAdd,
    Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TuiExitAction {
    Detach,
    StopService,
}

impl TuiExitAction {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Detach => "detach",
            Self::StopService => "stop service",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct TuiExitConfirmation {
    pub(super) action: TuiExitAction,
    pub(super) started: Instant,
}

pub(super) struct TuiApp {
    pub(super) session: ShellSession,
    pub(super) mode: TuiMode,
    pub(super) status: StatusReport,
    pub(super) control_snapshot: Option<Value>,
    pub(super) command_query: String,
    pub(super) selected_command: usize,
    pub(super) route_mode_selection: usize,
    pub(super) global_target_query: String,
    pub(super) selected_global_target: usize,
    pub(super) policy_group_query: String,
    pub(super) selected_policy_group: usize,
    pub(super) selected_policy_group_tag: Option<String>,
    pub(super) policy_group_outbound_query: String,
    pub(super) selected_policy_group_outbound: usize,
    pub(super) policy_group_delay_group: Option<String>,
    pub(super) policy_group_delay_results: Vec<TuiPolicyGroupDelayResult>,
    pub(super) policy_group_delay_run: Option<TuiPolicyGroupDelayRun>,
    pub(super) policy_group_delay_next_run_id: u64,
    pub(super) policy_group_delay_updates: Option<mpsc::UnboundedReceiver<TuiPolicyGroupDelayUpdate>>,
    pub(super) route_rule_query: String,
    pub(super) selected_route_rule: usize,
    pub(super) selected_route_rule_action: usize,
    pub(super) route_rule_form_id: Option<String>,
    pub(super) route_rule_add_field: usize,
    pub(super) route_rule_add_content: String,
    pub(super) selected_route_rule_match_kind: usize,
    pub(super) route_rule_target_query: String,
    pub(super) selected_route_rule_target: usize,
    pub(super) selected_route_rule_target_candidate: usize,
    pub(super) subscription_query: String,
    pub(super) selected_subscription: usize,
    pub(super) selected_subscription_action: usize,
    pub(super) subscription_add_field: usize,
    pub(super) subscription_add_name: String,
    pub(super) subscription_add_url: String,
    pub(super) subscription_add_auto_update: bool,
    pub(super) output_title: String,
    pub(super) output: String,
    pub(super) output_scroll: u16,
    pub(super) dashboard_log_tail: String,
    pub(super) last_message: String,
    pub(super) last_refresh: Instant,
    pub(super) exit_confirmation: Option<TuiExitConfirmation>,
    pub(super) exit_action: Option<TuiExitAction>,
}

pub(super) async fn run_interactive_shell(config: Option<PathBuf>, command: ShellCommand) -> Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        bail!("interactive shell requires a terminal; pass a subcommand for non-interactive use");
    }

    let session = ShellSession {
        config,
        state_dir: command
            .state_dir
            .unwrap_or_else(process_manager::default_state_dir),
        timeout: timeout_duration(command.timeout_ms)?,
    };
    let startup = match ensure_tui_service_running(&session).await {
        Ok(startup) => startup,
        Err(err) => {
            let _ = tui_shutdown_service(&session).await;
            return Err(err);
        }
    };
    let mut app = match TuiApp::new(session.clone(), startup.message).await {
        Ok(app) => app,
        Err(err) => {
            if startup.kind.started_by_tui() {
                let _ = tui_shutdown_service(&session).await;
            }
            return Err(err);
        }
    };
    let mut terminal = match enter_tui() {
        Ok(terminal) => terminal,
        Err(err) => {
            if startup.kind.started_by_tui() {
                let _ = tui_shutdown_service(&session).await;
            }
            return Err(err);
        }
    };
    let result = run_tui_loop(&mut terminal, &mut app).await;
    let exit_result = exit_tui(&mut terminal);
    let shutdown_result = if should_shutdown_service_after_tui(
        app.exit_action,
        result.is_err(),
        startup.kind.started_by_tui(),
    ) {
        Some(tui_shutdown_service(&app.session).await)
    } else {
        None
    };
    finish_tui_session(result, exit_result, shutdown_result)
}

impl TuiApp {
    pub(super) async fn new(session: ShellSession, startup_message: String) -> Result<Self> {
        let status = build_status_report(&session.state_dir, None, session.timeout).await?;
        let control_snapshot = collect_control_snapshot_for_report(&status, session.timeout).await;
        let dashboard_log_tail = tui_dashboard_log_tail(&session, &status, 80);
        Ok(Self {
            session,
            mode: TuiMode::Dashboard,
            status,
            control_snapshot,
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
            dashboard_log_tail,
            last_message: startup_message,
            last_refresh: Instant::now(),
            exit_confirmation: None,
            exit_action: None,
        })
    }

    pub(super) async fn refresh_status(&mut self) -> Result<()> {
        let mut status =
            build_status_report(&self.session.state_dir, None, self.session.timeout).await?;
        if !status.service.running
            && let Some(message) = adopt_independent_runtime(&self.session).await?
        {
            status =
                build_status_report(&self.session.state_dir, None, self.session.timeout).await?;
            self.last_message = message;
        }
        self.status = status;
        self.control_snapshot =
            collect_control_snapshot_for_report(&self.status, self.session.timeout).await;
        self.dashboard_log_tail = tui_dashboard_log_tail(&self.session, &self.status, 80);
        self.last_refresh = Instant::now();
        Ok(())
    }

    pub(super) fn filtered_commands(&self) -> Vec<&'static ShellCommandSpec> {
        filtered_shell_commands(&self.command_query)
    }

    pub(super) fn clamp_selection(&mut self) {
        let len = self.filtered_commands().len();
        if len == 0 {
            self.selected_command = 0;
        } else if self.selected_command >= len {
            self.selected_command = len - 1;
        }
    }

    pub(super) fn filtered_global_targets(&self) -> Vec<String> {
        filtered_tui_global_targets(self.control_snapshot.as_ref(), &self.global_target_query)
    }

    pub(super) fn clamp_global_target_selection(&mut self) {
        let len = self.filtered_global_targets().len();
        if len == 0 {
            self.selected_global_target = 0;
        } else if self.selected_global_target >= len {
            self.selected_global_target = len - 1;
        }
    }

    pub(super) fn filtered_policy_groups(&self) -> Vec<TuiPolicyGroup> {
        filtered_tui_policy_groups(self.control_snapshot.as_ref(), &self.policy_group_query)
    }

    pub(super) fn clamp_policy_group_selection(&mut self) {
        let len = self.filtered_policy_groups().len();
        if len == 0 {
            self.selected_policy_group = 0;
        } else if self.selected_policy_group >= len {
            self.selected_policy_group = len - 1;
        }
    }

    pub(super) fn filtered_policy_group_outbounds(&self) -> Vec<String> {
        filtered_tui_policy_group_outbounds(
            self.control_snapshot.as_ref(),
            self.selected_policy_group_tag.as_deref(),
            &self.policy_group_outbound_query,
        )
    }

    pub(super) fn clamp_policy_group_outbound_selection(&mut self) {
        let len = self.filtered_policy_group_outbounds().len();
        if len == 0 {
            self.selected_policy_group_outbound = 0;
        } else if self.selected_policy_group_outbound >= len {
            self.selected_policy_group_outbound = len - 1;
        }
    }

    pub(super) fn filtered_route_rules(&self) -> Vec<TuiRouteRuleItem> {
        filtered_tui_route_rule_items(self.control_snapshot.as_ref(), &self.route_rule_query)
    }

    pub(super) fn clamp_route_rule_selection(&mut self) {
        let len = self.filtered_route_rules().len();
        if len == 0 {
            self.selected_route_rule = 0;
        } else if self.selected_route_rule >= len {
            self.selected_route_rule = len - 1;
        }
    }

    pub(super) fn clamp_route_rule_add_selection(&mut self) {
        self.route_rule_add_field = self.route_rule_add_field.min(TUI_ROUTE_RULE_ADD_FIELDS - 1);
        let kinds = tui_route_rule_match_kinds().len();
        if self.selected_route_rule_match_kind >= kinds {
            self.selected_route_rule_match_kind = kinds.saturating_sub(1);
        }
        let targets = tui_route_rule_targets(self.control_snapshot.as_ref()).len();
        if targets == 0 {
            self.selected_route_rule_target = 0;
        } else if self.selected_route_rule_target >= targets {
            self.selected_route_rule_target = targets - 1;
        }
    }

    pub(super) fn filtered_route_rule_targets(&self) -> Vec<String> {
        filtered_tui_route_rule_targets(
            self.control_snapshot.as_ref(),
            &self.route_rule_target_query,
        )
    }

    pub(super) fn clamp_route_rule_target_selection(&mut self) {
        let len = self.filtered_route_rule_targets().len();
        if len == 0 {
            self.selected_route_rule_target_candidate = 0;
        } else if self.selected_route_rule_target_candidate >= len {
            self.selected_route_rule_target_candidate = len - 1;
        }
    }

    pub(super) fn clamp_route_rule_action_selection(&mut self) {
        let len = tui_route_rule_actions().len();
        if len == 0 {
            self.selected_route_rule_action = 0;
        } else if self.selected_route_rule_action >= len {
            self.selected_route_rule_action = len - 1;
        }
    }

    pub(super) fn filtered_subscriptions(&self) -> Vec<TuiSubscriptionItem> {
        filtered_tui_subscription_items(self.control_snapshot.as_ref(), &self.subscription_query)
    }

    pub(super) fn clamp_subscription_selection(&mut self) {
        let len = self.filtered_subscriptions().len();
        if len == 0 {
            self.selected_subscription = 0;
        } else if self.selected_subscription >= len {
            self.selected_subscription = len - 1;
        }
    }

    pub(super) fn clamp_subscription_action_selection(&mut self) {
        let len = tui_subscription_actions().len();
        if len == 0 {
            self.selected_subscription_action = 0;
        } else if self.selected_subscription_action >= len {
            self.selected_subscription_action = len - 1;
        }
    }

    pub(super) fn clamp_subscription_add_selection(&mut self) {
        self.subscription_add_field = self
            .subscription_add_field
            .min(TUI_SUBSCRIPTION_ADD_FIELDS - 1);
    }
}

pub(super) type TuiTerminal = Terminal<CrosstermBackend<io::Stdout>>;
