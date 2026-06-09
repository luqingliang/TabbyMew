use super::*;

pub(crate) async fn execute_tui_command(
    app: &mut TuiApp,
    command: &ShellCommandSpec,
    args: &str,
) -> Result<()> {
    app.mode = TuiMode::Dashboard;
    app.command_query.clear();
    app.selected_command = 0;

    match command.name {
        "status" => {
            app.refresh_status().await?;
            app.output.clear();
            app.output_title = "Status".to_string();
            app.last_message = "status refreshed".to_string();
        }
        "restart" => {
            let text = tui_restart_service(&app.session).await?;
            app.refresh_status().await?;
            app.output_title = "Restart".to_string();
            app.output = text;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "mode" => {
            let args = args.trim();
            if args.is_empty() {
                app.refresh_status().await?;
                open_tui_route_mode_selector(app);
            } else {
                let mode = parse_route_mode_arg(args)?;
                let text = tui_set_route_mode(app, mode).await?;
                app.output_title = "Route Mode".to_string();
                app.output = text;
                app.output_scroll = 0;
                app.mode = TuiMode::Output;
            }
        }
        "global" => {
            let args = args.trim();
            app.refresh_status().await?;
            if args.is_empty() {
                open_tui_global_target_selector(app)?;
            } else {
                let target = resolve_global_target(app.control_snapshot.as_ref(), args)?;
                let text = tui_set_global_target(app, &target).await?;
                app.output_title = "Global Target".to_string();
                app.output = text;
                app.output_scroll = 0;
                app.mode = TuiMode::Output;
            }
        }
        "groups" => {
            let args = args.trim();
            app.refresh_status().await?;
            if args.is_empty() {
                open_tui_policy_group_list_selector(app)?;
            } else {
                let selection = parse_policy_group_selection(app.control_snapshot.as_ref(), args)?;
                match selection.outbound {
                    Some(outbound) => {
                        let text =
                            tui_select_policy_group_outbound(app, &selection.group.tag, &outbound)
                                .await?;
                        app.output_title = "Policy Group".to_string();
                        app.output = text;
                        app.output_scroll = 0;
                        app.mode = TuiMode::Output;
                    }
                    None => open_tui_policy_group_selector(app, &selection.group)?,
                }
            }
        }
        "rules" => {
            let args = args.trim();
            let (verb, _) = split_first_word(args);
            if matches!(
                verb,
                Some("add" | "remove" | "delete" | "rm" | "reload" | "help")
            ) {
                let text = tui_rules_command(app, args).await?;
                app.output_title = "Route Rules".to_string();
                app.output = text;
                app.output_scroll = 0;
                app.mode = TuiMode::Output;
            } else {
                app.refresh_status().await?;
                open_tui_route_rules(app, args);
            }
        }
        "tun" => {
            app.refresh_status().await?;
            let enabled = !control_snapshot_tun_enabled(app.control_snapshot.as_ref())
                .context("TUN state is not available; run /restart before switching TUN")?;
            let text = tui_set_tun_enabled(app, enabled).await?;
            app.output_title = "TUN".to_string();
            app.output = text;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "tun-on" => {
            let text = tui_set_tun_enabled(app, true).await?;
            app.output_title = "TUN On".to_string();
            app.output = text;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "tun-off" => {
            let text = tui_set_tun_enabled(app, false).await?;
            app.output_title = "TUN Off".to_string();
            app.output = text;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "lan-proxy" => {
            app.refresh_status().await?;
            let enabled = !control_snapshot_lan_proxy_enabled(app.control_snapshot.as_ref())
                .context(
                    "LAN Proxy state is not available; run /restart before switching LAN Proxy",
                )?;
            let text = tui_set_lan_proxy_enabled(app, enabled).await?;
            app.output_title = "LAN Proxy".to_string();
            app.output = text;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "lan-proxy-on" => {
            let text = tui_set_lan_proxy_enabled(app, true).await?;
            app.output_title = "LAN Proxy On".to_string();
            app.output = text;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "lan-proxy-off" => {
            let text = tui_set_lan_proxy_enabled(app, false).await?;
            app.output_title = "LAN Proxy Off".to_string();
            app.output = text;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "system-proxy" => {
            app.refresh_status().await?;
            let enabled = !control_snapshot_system_proxy_enabled(app.control_snapshot.as_ref())
                .context(
                    "system proxy state is not available; run /restart before switching system proxy",
                )?;
            let text = tui_set_system_proxy_enabled(app, enabled).await?;
            app.output_title = "System Proxy".to_string();
            app.output = text;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "system-proxy-on" => {
            let text = tui_set_system_proxy_enabled(app, true).await?;
            app.output_title = "System Proxy On".to_string();
            app.output = text;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "system-proxy-off" => {
            let text = tui_set_system_proxy_enabled(app, false).await?;
            app.output_title = "System Proxy Off".to_string();
            app.output = text;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "autostart" => {
            let action = parse_tui_autostart_action(args)?;
            let text = tui_autostart_command(&app.session, action)?;
            app.refresh_autostart_status();
            app.output_title = "Autostart".to_string();
            app.output = text;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "autostart-on" => {
            let text =
                tui_autostart_command(&app.session, crate::autostart::AutostartAction::Enable)?;
            app.refresh_autostart_status();
            app.output_title = "Autostart On".to_string();
            app.output = text;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "autostart-off" => {
            let text =
                tui_autostart_command(&app.session, crate::autostart::AutostartAction::Disable)?;
            app.refresh_autostart_status();
            app.output_title = "Autostart Off".to_string();
            app.output = text;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "cleanup" => {
            let report = cleanup_service_state(&app.session.state_dir)?;
            let mut output = Vec::new();
            print_cleanup_report(&mut output, &report)?;
            app.refresh_status().await?;
            app.output_title = "Cleanup".to_string();
            app.output = String::from_utf8_lossy(&output).into_owned();
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "doctor" => {
            let report = doctor_service_state(&app.session.state_dir, app.session.timeout).await;
            let mut output = Vec::new();
            print_doctor_report(&mut output, &report)?;
            app.output_title = "Doctor".to_string();
            app.output = String::from_utf8_lossy(&output).into_owned();
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "logs" => {
            app.output_title = "Logs".to_string();
            app.output = tui_log_tail(&app.session, 80)?;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "subscriptions" => {
            app.refresh_status().await?;
            open_tui_subscriptions(app, args.trim());
        }
        "check" => {
            app.output_title = "Config Check".to_string();
            app.output = tui_check_config(&app.session)?;
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "help" => {
            app.output_title = "Commands".to_string();
            app.output = command_help_text(None);
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        "detach" => app.exit_action = Some(TuiExitAction::Detach),
        "quit" => app.exit_action = Some(TuiExitAction::StopService),
        _ => unreachable!("all registered shell commands are handled"),
    }
    if should_record_executed_message(command, args, app.mode) {
        app.last_message = format!("executed /{}", command.name);
    }
    Ok(())
}

pub(crate) fn should_record_executed_message(
    command: &ShellCommandSpec,
    args: &str,
    mode: TuiMode,
) -> bool {
    !(matches!(command.name, "detach" | "quit")
        || matches!(command.name, "mode" | "global") && args.trim().is_empty()
        || matches!(command.name, "groups" | "rules" | "subscriptions") && mode != TuiMode::Output)
}
