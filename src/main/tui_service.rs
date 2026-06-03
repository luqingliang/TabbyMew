async fn tui_start_service(session: &ShellSession) -> Result<String> {
    let cleanup_report = cleanup_service_state(&session.state_dir)?;
    if !cleanup_report.ok {
        let mut output = Vec::new();
        print_cleanup_report(&mut output, &cleanup_report)?;
        bail!(
            "failed to clean stale TabbyMew-owned runtime state before start\n{}",
            String::from_utf8_lossy(&output)
        );
    }

    let config_path = resolve_launch_config_path(session.config.as_ref(), &session.state_dir)?;
    warn_if_active_subscription_config_migration_fails(&session.state_dir, &config_path);
    let config = Config::load(&config_path)?;
    validate_runtime_config(&config, config_base_dir(&config_path))?;
    let state = process_manager::start(StartOptions {
        config: config_path,
        state_dir: session.state_dir.clone(),
        log: None,
        control_listen: None,
    })?;
    let mut output = Vec::new();
    print_start_report(&mut output, &state)?;
    Ok(String::from_utf8_lossy(&output).into_owned())
}

async fn tui_restart_service(session: &ShellSession) -> Result<String> {
    let mut output = String::new();
    output.push_str("stopping service:\n");
    output.push_str(&indent_text(&tui_shutdown_service(session).await?));
    output.push('\n');
    output.push_str("starting service:\n");
    output.push_str(&indent_text(&tui_start_service(session).await?));
    Ok(output)
}

async fn tui_shutdown_service(session: &ShellSession) -> Result<String> {
    match tui_stop_service(session, false).await {
        Ok(output) => Ok(output),
        Err(err) => {
            let graceful_error = format!("{err:#}");
            let forced = tui_stop_service(session, true).await?;
            Ok(format!(
                "graceful stop failed: {graceful_error}\nforced stop:\n{forced}"
            ))
        }
    }
}

async fn tui_stop_service(session: &ShellSession, force: bool) -> Result<String> {
    let paths = process_manager::paths(&session.state_dir, None);
    let state = match process_manager::load_state(&paths.state_file) {
        Ok(state) => state,
        Err(_) if !paths.state_file.exists() => {
            return Ok("TabbyMew is not running; no local state file found\n".to_string());
        }
        Err(err) => {
            process_manager::remove_state_file(&paths.state_file)?;
            return Ok(format!(
                "TabbyMew is not running; removed unreadable state file {} ({err:#})\n",
                paths.state_file.display()
            ));
        }
    };

    if !process_manager::is_process_running(state.pid) {
        let log_path = owned_lifecycle_log_path(&session.state_dir, &state.log);
        record_process_lifecycle_event(
            log_path,
            &state,
            "stale_state_removed_by_tui_stop",
            vec![("state_file", paths.state_file.display().to_string())],
        );
        process_manager::remove_state_file(&paths.state_file)?;
        return Ok(format!(
            "TabbyMew is not running; removed stale state for pid {}\n",
            state.pid
        ));
    }

    let log_path = owned_lifecycle_log_path(&session.state_dir, &state.log);
    record_process_lifecycle_event(
        log_path,
        &state,
        "tui_stop_requested",
        vec![
            ("force", force.to_string()),
            (
                "timeout_ms",
                tui_service_stop_timeout(session).as_millis().to_string(),
            ),
        ],
    );
    if !force && let Some(output) = try_tui_control_api_stop(session, &state, log_path).await? {
        process_manager::remove_state_file(&paths.state_file)?;
        return Ok(output);
    }
    match process_manager::stop(state.pid, force, tui_service_stop_timeout(session)) {
        Ok(stopped) => record_process_lifecycle_event(
            log_path,
            &state,
            "tui_stop_completed",
            vec![("terminated", stopped.to_string())],
        ),
        Err(err) => {
            record_process_lifecycle_event(
                log_path,
                &state,
                "tui_stop_failed",
                vec![("error", format!("{err:#}"))],
            );
            return Err(err);
        }
    }
    process_manager::remove_state_file(&paths.state_file)?;
    Ok(format!("stopped TabbyMew pid {}\n", state.pid))
}

async fn try_tui_control_api_stop(
    session: &ShellSession,
    state: &ProcessState,
    log_path: Option<&Path>,
) -> Result<Option<String>> {
    let (Some(listen), Some(token)) = (state.listen.as_deref(), state.control_token.as_deref())
    else {
        return Ok(None);
    };
    let listen = control::parse_listen(listen)
        .context("invalid control API listen address from local state")?;
    record_process_lifecycle_event(log_path, state, "tui_control_stop_requested", Vec::new());
    let client = ControlClient::new(listen, session.timeout);
    client
        .post_json("/control/api/stop", token, &serde_json::json!({}))
        .await?;
    let stopped = process_manager::wait_for_exit(state.pid, tui_service_stop_timeout(session))?;
    record_process_lifecycle_event(
        log_path,
        state,
        "tui_control_stop_completed",
        vec![("terminated", stopped.to_string())],
    );
    Ok(Some(format!(
        "stopped TabbyMew pid {} via control API\n",
        state.pid
    )))
}

fn tui_service_stop_timeout(session: &ShellSession) -> Duration {
    session.timeout.max(TUI_SERVICE_STOP_TIMEOUT)
}

fn indent_text(text: &str) -> String {
    text.lines()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn tui_log_tail(session: &ShellSession, lines: usize) -> Result<String> {
    let paths = process_manager::paths(&session.state_dir, None);
    let log_path = process_manager::load_state(&paths.state_file)
        .map(|state| state.log)
        .unwrap_or(paths.log_file);
    process_manager::read_log_tail(&log_path, lines)
}

fn tui_dashboard_log_tail(session: &ShellSession, report: &StatusReport, lines: usize) -> String {
    let paths = process_manager::paths(&session.state_dir, None);
    let log_path = report
        .service
        .log
        .clone()
        .or_else(|| {
            process_manager::load_state(&paths.state_file)
                .ok()
                .map(|state| state.log)
        })
        .unwrap_or(paths.log_file);
    match process_manager::read_log_tail(&log_path, lines) {
        Ok(text) if !text.trim().is_empty() => text,
        Ok(_) => "No log output yet.".to_string(),
        Err(_) if !log_path.exists() => format!("No log file yet: {}", log_path.display()),
        Err(err) => format!("failed to read log {}: {err:#}", log_path.display()),
    }
}

fn tui_check_config(session: &ShellSession) -> Result<String> {
    let config_path = resolve_launch_config_path(session.config.as_ref(), &session.state_dir)?;
    let config = Config::load(&config_path)?;
    validate_runtime_config(&config, config_base_dir(&config_path))?;
    let mut output = format!("configuration ok: {}\n", config_path.display());
    output.push_str("validation: config references ok, outbounds ok, router ok, inbounds ok\n");
    for line in config.summary().lines() {
        output.push_str("  ");
        output.push_str(&line);
        output.push('\n');
    }
    Ok(output)
}

#[derive(Debug, Clone)]
struct TuiSubscriptionItem {
    name: String,
    source: String,
    url: String,
    output: String,
    auto_update: bool,
    imported: String,
    last_success: String,
    next_update: String,
    warnings: u64,
    last_error: Option<String>,
    last_final_url: String,
    status: String,
    active: bool,
    refreshable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiSubscriptionAction {
    Activate,
    Refresh,
    ToggleAutoUpdate,
    Delete,
}

#[derive(Debug, Clone, Copy)]
struct TuiSubscriptionActionOption {
    action: TuiSubscriptionAction,
}

fn tui_subscription_actions() -> &'static [TuiSubscriptionActionOption] {
    const ACTIONS: &[TuiSubscriptionActionOption] = &[
        TuiSubscriptionActionOption {
            action: TuiSubscriptionAction::Activate,
        },
        TuiSubscriptionActionOption {
            action: TuiSubscriptionAction::Refresh,
        },
        TuiSubscriptionActionOption {
            action: TuiSubscriptionAction::ToggleAutoUpdate,
        },
        TuiSubscriptionActionOption {
            action: TuiSubscriptionAction::Delete,
        },
    ];
    ACTIONS
}

fn active_tui_subscription(control_snapshot: Option<&Value>) -> Option<&str> {
    control_snapshot.and_then(|value| value_str(value, &["subscriptions", "active"]))
}

fn tui_subscription_items(control_snapshot: Option<&Value>) -> Vec<TuiSubscriptionItem> {
    let active = active_tui_subscription(control_snapshot);
    control_snapshot
        .and_then(|value| value_array(value, &["subscriptions", "subscriptions"]))
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let name = value_str(item, &["name"])?.to_string();
                    let source = value_str(item, &["source"]).unwrap_or("-").to_string();
                    let auto_update = value_bool(item, &["auto_update"]).unwrap_or(false);
                    let imported = value_u64(item, &["imported"])
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    let last_success =
                        format_optional_unix(value_u64(item, &["last_success_unix"]));
                    let last_error = value_str(item, &["last_error"]).map(str::to_string);
                    let active = active == Some(name.as_str());
                    let warnings = value_u64(item, &["warnings"]).unwrap_or(0);
                    let status = if last_error.is_some() {
                        "error".to_string()
                    } else if active {
                        "active".to_string()
                    } else if value_u64(item, &["imported"]).is_some() {
                        "ready".to_string()
                    } else {
                        "pending".to_string()
                    };
                    Some(TuiSubscriptionItem {
                        name,
                        refreshable: source == "remote",
                        source,
                        url: value_str(item, &["url"]).unwrap_or("-").to_string(),
                        output: value_str(item, &["output"]).unwrap_or("-").to_string(),
                        auto_update,
                        imported,
                        last_success,
                        next_update: if auto_update {
                            format_optional_unix(value_u64(item, &["next_update_unix"]))
                        } else {
                            "disabled".to_string()
                        },
                        warnings,
                        last_error,
                        last_final_url: value_str(item, &["last_final_url"])
                            .unwrap_or("-")
                            .to_string(),
                        status,
                        active,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn filtered_tui_subscription_items(
    control_snapshot: Option<&Value>,
    query: &str,
) -> Vec<TuiSubscriptionItem> {
    let query = query.trim().to_ascii_lowercase();
    tui_subscription_items(control_snapshot)
        .into_iter()
        .filter(|item| {
            query.is_empty()
                || item.name.to_ascii_lowercase().contains(&query)
                || item.source.to_ascii_lowercase().contains(&query)
                || item.url.to_ascii_lowercase().contains(&query)
                || item.output.to_ascii_lowercase().contains(&query)
                || item.status.to_ascii_lowercase().contains(&query)
                || item
                    .last_error
                    .as_deref()
                    .is_some_and(|error| error.to_ascii_lowercase().contains(&query))
        })
        .collect()
}

fn format_optional_unix(value: Option<u64>) -> String {
    value
        .map(|value| format!("unix {value}"))
        .unwrap_or_else(|| "never".to_string())
}

fn format_tui_subscription_detail(item: &TuiSubscriptionItem) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "{}  source={}  active={}  auto_update={}\n",
        item.name,
        item.source,
        on_off(item.active),
        on_off(item.auto_update)
    ));
    output.push_str(&format!(
        "imported={}  warnings={}  last_success={}  next_update={}\n",
        item.imported, item.warnings, item.last_success, item.next_update
    ));
    output.push_str(&format!("url: {}\n", item.url));
    output.push_str(&format!("output: {}\n", item.output));
    output.push_str(&format!("last_final_url: {}\n", item.last_final_url));
    output.push_str(&format!(
        "last_error: {}\n",
        item.last_error.as_deref().unwrap_or("-")
    ));
    output
}

fn selected_tui_subscription_item(app: &TuiApp) -> Option<TuiSubscriptionItem> {
    app.filtered_subscriptions()
        .get(app.selected_subscription)
        .cloned()
}

fn selected_tui_subscription_action(app: &TuiApp) -> Option<TuiSubscriptionAction> {
    tui_subscription_actions()
        .get(app.selected_subscription_action)
        .map(|option| option.action)
}

fn subscription_action_label(
    action: TuiSubscriptionAction,
    item: Option<&TuiSubscriptionItem>,
) -> String {
    match action {
        TuiSubscriptionAction::Activate => "Activate".to_string(),
        TuiSubscriptionAction::Refresh => "Update".to_string(),
        TuiSubscriptionAction::ToggleAutoUpdate => {
            if item.is_some_and(|item| item.auto_update) {
                "Disable Auto".to_string()
            } else {
                "Enable Auto".to_string()
            }
        }
        TuiSubscriptionAction::Delete => "Delete".to_string(),
    }
}

fn subscription_action_summary(
    action: TuiSubscriptionAction,
    item: Option<&TuiSubscriptionItem>,
) -> String {
    match action {
        TuiSubscriptionAction::Activate => "Use this subscription config now.".to_string(),
        TuiSubscriptionAction::Refresh => match item {
            Some(item) if item.refreshable => {
                "Fetch and import the latest remote data.".to_string()
            }
            Some(_) => "Uploaded file subscriptions cannot be updated.".to_string(),
            None => "Fetch and import the latest remote data.".to_string(),
        },
        TuiSubscriptionAction::ToggleAutoUpdate => {
            "Switch automatic subscription updates.".to_string()
        }
        TuiSubscriptionAction::Delete => "Remove this subscription record.".to_string(),
    }
}

fn open_tui_subscriptions(app: &mut TuiApp, query: &str) {
    app.subscription_query = query.trim().to_string();
    app.selected_subscription = 0;
    app.clamp_subscription_selection();
    reset_tui_subscription_add_form(app);
    app.mode = TuiMode::Subscriptions;
    app.last_message = "select a subscription or press + to add one".to_string();
}

fn open_tui_subscription_actions(app: &mut TuiApp) -> Result<()> {
    selected_tui_subscription_item(app).context("no subscription selected")?;
    app.selected_subscription_action = 0;
    app.clamp_subscription_action_selection();
    app.mode = TuiMode::SubscriptionActions;
    app.last_message = "choose a subscription action".to_string();
    Ok(())
}

fn open_tui_subscription_add(app: &mut TuiApp) {
    reset_tui_subscription_add_form(app);
    app.clamp_subscription_add_selection();
    app.mode = TuiMode::SubscriptionAdd;
    app.last_message = "enter subscription name and URL".to_string();
}

fn reset_tui_subscription_add_form(app: &mut TuiApp) {
    app.subscription_add_field = TUI_SUBSCRIPTION_ADD_NAME_FIELD;
    app.subscription_add_name.clear();
    app.subscription_add_url.clear();
    app.subscription_add_auto_update = true;
}

fn open_tui_error(app: &mut TuiApp, title: &str, err: anyhow::Error) {
    let error = format!("{err:#}");
    let error_code = classify_user_error(&error);
    app.output_title = format!("{title} failed");
    app.output = format!(
        "error_code: {error_code}\nmessage: {error}\nsuggestion: {}\n",
        user_error_suggestion(error_code)
    );
    app.output_scroll = 0;
    app.last_message = format!("{} failed", title.to_ascii_lowercase());
    app.mode = TuiMode::Output;
}

fn open_tui_subscription_error(app: &mut TuiApp, title: &str, err: anyhow::Error) {
    open_tui_error(app, title, err);
}

async fn apply_selected_tui_subscription_action(
    app: &mut TuiApp,
    action: TuiSubscriptionAction,
) -> Result<String> {
    let item = selected_tui_subscription_item(app).context("no subscription selected")?;
    match action {
        TuiSubscriptionAction::Activate => tui_activate_subscription(app, &item.name).await,
        TuiSubscriptionAction::Refresh => {
            if !item.refreshable {
                bail!(
                    "subscription {} cannot be updated because it is not remote",
                    item.name
                );
            }
            tui_refresh_subscription(app, &item.name).await
        }
        TuiSubscriptionAction::ToggleAutoUpdate => {
            tui_set_subscription_auto_update(app, &item.name, !item.auto_update).await
        }
        TuiSubscriptionAction::Delete => tui_remove_subscription_from_tui(app, &item.name).await,
    }
}

async fn tui_activate_subscription(app: &mut TuiApp, name: &str) -> Result<String> {
    tui_subscription_post_control_json(
        app,
        "/control/api/subscriptions/activate",
        serde_json::json!({ "name": name }),
        "activating subscription",
    )
    .await?;
    Ok(format!("subscription {name} activated"))
}

async fn tui_refresh_subscription(app: &mut TuiApp, name: &str) -> Result<String> {
    let response = tui_subscription_post_control_json(
        app,
        "/control/api/subscriptions/refresh",
        serde_json::json!({ "name": name }),
        "updating subscription",
    )
    .await?;
    let output = format_tui_subscription_refresh_outcomes(&response);
    if subscription_refresh_has_failure(&response) {
        bail!("{output}");
    }
    Ok(first_tui_subscription_refresh_message(&response)
        .unwrap_or_else(|| format!("subscription {name} updated")))
}

async fn tui_refresh_all_subscriptions(app: &mut TuiApp) -> Result<String> {
    let response = tui_subscription_post_control_json(
        app,
        "/control/api/subscriptions/refresh",
        serde_json::json!({ "all": true }),
        "updating subscriptions",
    )
    .await?;
    Ok(format_tui_subscription_refresh_outcomes(&response))
}

async fn tui_set_subscription_auto_update(
    app: &mut TuiApp,
    name: &str,
    enabled: bool,
) -> Result<String> {
    tui_subscription_post_control_json(
        app,
        "/control/api/subscriptions/set",
        serde_json::json!({ "name": name, "auto_update": enabled }),
        "updating subscription settings",
    )
    .await?;
    Ok(format!(
        "subscription {name} auto update {}",
        on_off(enabled)
    ))
}

async fn tui_remove_subscription_from_tui(app: &mut TuiApp, name: &str) -> Result<String> {
    tui_subscription_post_control_json(
        app,
        "/control/api/subscriptions/remove",
        serde_json::json!({ "name": name }),
        "removing subscription",
    )
    .await?;
    Ok(format!("subscription {name} removed"))
}

async fn tui_add_subscription_from_form(app: &mut TuiApp) -> Result<String> {
    let name = app.subscription_add_name.trim();
    let url = app.subscription_add_url.trim();
    subscription_remote::validate_name(name)?;
    subscription_remote::validate_url(url)?;
    let response = tui_subscription_post_control_json(
        app,
        "/control/api/subscriptions/add",
        serde_json::json!({
            "name": name,
            "url": url,
            "auto_update": app.subscription_add_auto_update,
        }),
        "adding subscription",
    )
    .await?;
    Ok(format_tui_subscription_apply_report(&response))
}

async fn tui_subscription_post_control_json(
    app: &mut TuiApp,
    path: &str,
    body: Value,
    action: &str,
) -> Result<Value> {
    tui_post_control_json_with_timeout(
        app,
        path,
        body,
        action,
        app.session.timeout.max(Duration::from_secs(120)),
    )
    .await
}

fn format_tui_subscription_apply_report(response: &Value) -> String {
    let name = value_str(response, &["name"]).unwrap_or("-");
    let imported = value_u64(response, &["imported"])
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string());
    let warnings = value_array_len(response, &["warnings"]).unwrap_or(0);
    format!("subscription {name} added ({imported} imported, {warnings} warnings)")
}

fn format_tui_subscription_refresh_outcomes(response: &Value) -> String {
    let Some(outcomes) = response.as_array() else {
        return "subscription update returned an unexpected response".to_string();
    };
    if outcomes.is_empty() {
        return "subscriptions: none updated".to_string();
    }
    let mut output = format!("subscriptions updated: {}\n", outcomes.len());
    for outcome in outcomes {
        let name = value_str(outcome, &["name"]).unwrap_or("-");
        if value_bool(outcome, &["ok"]).unwrap_or(false) {
            let imported = outcome
                .get("report")
                .and_then(|report| value_u64(report, &["imported"]))
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string());
            let warnings = outcome
                .get("report")
                .and_then(|report| value_array_len(report, &["warnings"]))
                .map(|value| value.to_string())
                .unwrap_or_else(|| "0".to_string());
            output.push_str(&format!(
                "  {name}: ok imported={imported} warnings={warnings}\n"
            ));
        } else {
            output.push_str(&format!(
                "  {name}: failed {}\n",
                value_str(outcome, &["error"]).unwrap_or("unknown error")
            ));
        }
    }
    output
}

fn subscription_refresh_has_failure(response: &Value) -> bool {
    response.as_array().is_some_and(|outcomes| {
        outcomes
            .iter()
            .any(|outcome| value_bool(outcome, &["ok"]) == Some(false))
    })
}

fn first_tui_subscription_refresh_message(response: &Value) -> Option<String> {
    let outcome = response.as_array()?.first()?;
    let name = value_str(outcome, &["name"]).unwrap_or("-");
    let report = outcome.get("report")?;
    let imported = value_u64(report, &["imported"])
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string());
    let warnings = value_array_len(report, &["warnings"]).unwrap_or(0);
    Some(format!(
        "subscription {name} updated ({imported} imported, {warnings} warnings)"
    ))
}

fn shell_command_registry() -> &'static [ShellCommandSpec] {
    const COMMANDS: &[ShellCommandSpec] = &[
        ShellCommandSpec {
            name: "status",
            aliases: &["s"],
            category: "service",
            usage: "/status",
            summary: "Show the live service dashboard.",
        },
        ShellCommandSpec {
            name: "restart",
            aliases: &["reboot"],
            category: "service",
            usage: "/restart",
            summary: "Restart the managed proxy service.",
        },
        ShellCommandSpec {
            name: "mode",
            aliases: &["route-mode", "routing"],
            category: "routing",
            usage: "/mode [rule|global|direct]",
            summary: "Select the runtime proxy routing mode.",
        },
        ShellCommandSpec {
            name: "global",
            aliases: &["global-target", "target"],
            category: "routing",
            usage: "/global [target]",
            summary: "Select the outbound target used by global mode.",
        },
        ShellCommandSpec {
            name: "groups",
            aliases: &["policy-groups", "pgroups"],
            category: "routing",
            usage: "/groups [group] [outbound]",
            summary: "Open policy group selector or change a group outbound.",
        },
        ShellCommandSpec {
            name: "rules",
            aliases: &["route-rules"],
            category: "routing",
            usage: "/rules [filter|add|remove|reload]",
            summary: "Open route rule search or manage custom rules.",
        },
        ShellCommandSpec {
            name: "tun",
            aliases: &["t", "tun-toggle"],
            category: "network",
            usage: "/tun",
            summary: "Toggle TUN mode for the running service.",
        },
        ShellCommandSpec {
            name: "tun-on",
            aliases: &["tun-start"],
            category: "network",
            usage: "/tun-on",
            summary: "Enable TUN mode for the running service.",
        },
        ShellCommandSpec {
            name: "tun-off",
            aliases: &["tun-stop"],
            category: "network",
            usage: "/tun-off",
            summary: "Disable TUN mode for the running service.",
        },
        ShellCommandSpec {
            name: "lan-proxy",
            aliases: &["lan", "lp", "lan-proxy-toggle"],
            category: "network",
            usage: "/lan-proxy",
            summary: "Toggle LAN access to the local proxy listener.",
        },
        ShellCommandSpec {
            name: "lan-proxy-on",
            aliases: &["lan-on", "lp-on", "lan-proxy-start"],
            category: "network",
            usage: "/lan-proxy-on",
            summary: "Allow LAN devices to use the local proxy listener.",
        },
        ShellCommandSpec {
            name: "lan-proxy-off",
            aliases: &["lan-off", "lp-off", "lan-proxy-stop"],
            category: "network",
            usage: "/lan-proxy-off",
            summary: "Restrict the local proxy listener to this computer.",
        },
        ShellCommandSpec {
            name: "system-proxy",
            aliases: &["sp", "sysproxy", "system-proxy-toggle"],
            category: "network",
            usage: "/system-proxy",
            summary: "Toggle system proxy for the running service.",
        },
        ShellCommandSpec {
            name: "system-proxy-on",
            aliases: &["sp-on", "system-proxy-start"],
            category: "network",
            usage: "/system-proxy-on",
            summary: "Enable system proxy for the running service.",
        },
        ShellCommandSpec {
            name: "system-proxy-off",
            aliases: &["sp-off", "system-proxy-stop"],
            category: "network",
            usage: "/system-proxy-off",
            summary: "Disable system proxy for the running service.",
        },
        ShellCommandSpec {
            name: "cleanup",
            aliases: &["clean"],
            category: "service",
            usage: "/cleanup",
            summary: "Clean stale TabbyMew-owned runtime state.",
        },
        ShellCommandSpec {
            name: "doctor",
            aliases: &["diag"],
            category: "diagnostics",
            usage: "/doctor",
            summary: "Run local lifecycle and control API diagnostics.",
        },
        ShellCommandSpec {
            name: "logs",
            aliases: &["log"],
            category: "diagnostics",
            usage: "/logs",
            summary: "Show recent background service logs.",
        },
        ShellCommandSpec {
            name: "subscriptions",
            aliases: &["subs"],
            category: "configuration",
            usage: "/subscriptions [filter]",
            summary: "Open subscription manager.",
        },
        ShellCommandSpec {
            name: "check",
            aliases: &["validate"],
            category: "configuration",
            usage: "/check",
            summary: "Validate the active configuration.",
        },
        ShellCommandSpec {
            name: "help",
            aliases: &["h", "?"],
            category: "shell",
            usage: "/help",
            summary: "Show commands or filter the command menu.",
        },
        ShellCommandSpec {
            name: "detach",
            aliases: &["exit-ui", "close-ui", "q"],
            category: "shell",
            usage: "/detach",
            summary: "Exit the interactive shell and keep the service running.",
        },
        ShellCommandSpec {
            name: "quit",
            aliases: &["exit"],
            category: "shell",
            usage: "/quit",
            summary: "Exit the interactive shell and stop the service.",
        },
    ];
    COMMANDS
}

fn find_shell_command(name: &str) -> Option<&'static ShellCommandSpec> {
    shell_command_registry()
        .iter()
        .find(|command| command.name == name || command.aliases.contains(&name))
}

struct TuiCommandInvocation {
    command: &'static ShellCommandSpec,
    args: String,
}

fn selected_shell_invocation(app: &TuiApp) -> Option<TuiCommandInvocation> {
    let (name, args) = split_command_query(&app.command_query);
    exact_shell_command(name)
        .or_else(|| app.filtered_commands().get(app.selected_command).copied())
        .map(|command| TuiCommandInvocation {
            command,
            args: args.to_string(),
        })
}

fn exact_shell_command(query: &str) -> Option<&'static ShellCommandSpec> {
    let query = query.trim().trim_start_matches('/');
    if query.is_empty() {
        None
    } else {
        find_shell_command(query)
    }
}

fn filtered_shell_commands(query: &str) -> Vec<&'static ShellCommandSpec> {
    let query = command_query_name(query);
    let mut commands = shell_command_registry()
        .iter()
        .filter(|command| shell_command_visible(command))
        .filter(|command| query.is_empty() || shell_command_matches(command, query))
        .collect::<Vec<_>>();
    commands.sort_by_key(|command| shell_command_match_rank(command, query));
    commands
}

fn command_query_name(query: &str) -> &str {
    split_command_query(query).0
}

fn split_command_query(query: &str) -> (&str, &str) {
    let query = query.trim().trim_start_matches('/').trim_start();
    match query.find(char::is_whitespace) {
        Some(index) => (&query[..index], query[index..].trim()),
        None => (query, ""),
    }
}

fn command_help_text(query: Option<&str>) -> String {
    let query = query.map(str::trim).filter(|query| !query.is_empty());
    let commands = filtered_shell_commands(query.unwrap_or(""));
    let mut output = String::new();
    if let Some(query) = query {
        output.push_str(&format!("Commands matching `{query}`:\n"));
    } else {
        output.push_str("Command menu:\n");
    }
    if commands.is_empty() {
        output.push_str("  no matches\n");
        output.push_str("  type `/` to show all commands\n");
        return output;
    }

    let mut category = "";
    for command in commands {
        if command.category != category {
            category = command.category;
            output.push('\n');
            output.push_str(category);
            output.push_str(":\n");
        }
        output.push_str(&format!("  {:<48} {}\n", command.usage, command.summary));
    }
    output
}

fn shell_command_matches(command: &ShellCommandSpec, query: &str) -> bool {
    let query = query.to_ascii_lowercase();
    command.name.contains(&query)
        || command.category.contains(&query)
        || command.summary.to_ascii_lowercase().contains(&query)
        || command.aliases.iter().any(|alias| alias.contains(&query))
}

fn shell_command_match_rank(command: &ShellCommandSpec, query: &str) -> u8 {
    if query.is_empty() {
        return 0;
    }
    let query = query.to_ascii_lowercase();
    if command.name == query || command.aliases.iter().any(|alias| *alias == query) {
        0
    } else if command.name.starts_with(&query)
        || command
            .aliases
            .iter()
            .any(|alias| alias.starts_with(&query))
    {
        1
    } else if command.category.contains(&query) {
        2
    } else {
        3
    }
}

fn shell_command_visible(command: &ShellCommandSpec) -> bool {
    !matches!(
        command.name,
        "tun-on"
            | "tun-off"
            | "lan-proxy-on"
            | "lan-proxy-off"
            | "system-proxy-on"
            | "system-proxy-off"
    )
}
