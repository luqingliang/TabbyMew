use super::*;

pub(super) fn draw_tui_dashboard(frame: &mut Frame<'_>, app: &TuiApp) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(8),
            Constraint::Length(4),
        ])
        .split(area);
    let summary = tui_status_summary(&app.status, app.control_snapshot.as_ref());

    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                "TabbyMew",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                summary.service_state.clone(),
                service_status_style(&app.status.service),
            ),
            Span::raw("  "),
            Span::styled(
                if app.status.ok {
                    "healthy"
                } else {
                    "needs attention"
                },
                if app.status.ok {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::Yellow)
                },
            ),
        ]),
        Line::from(tui_dashboard_state_line(app)),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    if chunks[1].width < 84 {
        draw_tui_dashboard_narrow(
            frame,
            chunks[1],
            &summary,
            &app.status.service,
            &app.dashboard_log_tail,
        );
    } else {
        draw_tui_dashboard_wide(
            frame,
            chunks[1],
            &summary,
            &app.status.service,
            &app.dashboard_log_tail,
        );
    }

    let footer = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("/ ", Style::default().fg(Color::Cyan)),
            Span::raw("commands  "),
            Span::styled("/status ", Style::default().fg(Color::Cyan)),
            Span::raw("dashboard  "),
            Span::styled("r ", Style::default().fg(Color::Cyan)),
            Span::raw("refresh  "),
            Span::styled("? ", Style::default().fg(Color::Cyan)),
            Span::raw("help  "),
            Span::styled("q ", Style::default().fg(Color::Cyan)),
            Span::raw("detach  "),
            Span::styled("Ctrl+C ", Style::default().fg(Color::Cyan)),
            Span::raw("stop"),
        ]),
        Line::from(app.last_message.as_str()),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, chunks[2]);
}

pub(super) fn tui_dashboard_state_line(app: &TuiApp) -> String {
    format!(
        "state: {}  version: {}",
        app.session.state_dir.display(),
        env!("CARGO_PKG_VERSION")
    )
}

pub(super) fn draw_tui_dashboard_wide(
    frame: &mut Frame<'_>,
    area: Rect,
    summary: &TuiStatusSummary,
    service: &ServiceStatus,
    log_tail: &str,
) {
    let rows = split_dashboard_status_and_logs(area);
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(rows[0]);
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(6)])
        .split(columns[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(6)])
        .split(columns[1]);

    render_kv_table(
        frame,
        left[0],
        "Service",
        vec![
            ("State", summary.service_state.clone()),
            ("PID", summary.pid.clone()),
            ("Memory", summary.memory.clone()),
            ("Uptime", summary.uptime.clone()),
            ("Control API", summary.control_state.clone()),
            ("Config", summary.active_config.clone()),
            ("Log", summary.log.clone()),
        ],
        service_status_style(service),
    );
    render_diagnostics(frame, left[1], summary);
    render_kv_table(
        frame,
        right[0],
        "Runtime",
        vec![
            ("Proxy", summary.proxy.clone()),
            ("LAN Proxy", summary.lan_proxy.clone()),
            ("Route Mode", summary.route_mode.clone()),
            ("Rule Final", summary.final_outbound.clone()),
            ("Global Target", summary.global_outbound.clone()),
            ("Policy Groups", summary.policy_groups.clone()),
            ("Rules", summary.route_rules.clone()),
            ("DNS", summary.dns.clone()),
            ("Route Hits", summary.route_selections.clone()),
        ],
        Style::default().fg(Color::Cyan),
    );
    render_kv_table(
        frame,
        right[1],
        "System",
        vec![
            ("System Proxy", summary.system_proxy.clone()),
            ("TUN", summary.tun.clone()),
            ("TUN Detail", summary.tun_detail.clone()),
            ("Subscriptions", summary.subscriptions.clone()),
            ("State File", summary.state_file.clone()),
            ("Preferences", summary.preferences_file.clone()),
        ],
        Style::default().fg(Color::Magenta),
    );
    render_log_tail(frame, rows[1], log_tail);
}

pub(super) fn draw_tui_dashboard_narrow(
    frame: &mut Frame<'_>,
    area: Rect,
    summary: &TuiStatusSummary,
    service: &ServiceStatus,
    log_tail: &str,
) {
    let rows = split_dashboard_status_and_logs(area);
    render_kv_table(
        frame,
        rows[0],
        "Status",
        vec![
            ("State", summary.service_state.clone()),
            ("PID", summary.pid.clone()),
            ("Memory", summary.memory.clone()),
            ("Uptime", summary.uptime.clone()),
            ("Control API", summary.control_state.clone()),
            ("Proxy", summary.proxy.clone()),
            ("LAN Proxy", summary.lan_proxy.clone()),
            (
                "Routing",
                format!(
                    "{} rule={} global={}",
                    summary.route_mode, summary.final_outbound, summary.global_outbound
                ),
            ),
            ("Groups", summary.policy_groups.clone()),
            ("Rules", summary.route_rules.clone()),
            ("System Proxy", summary.system_proxy.clone()),
            ("TUN", summary.tun.clone()),
            ("Subscriptions", summary.subscriptions.clone()),
            ("Issues", diagnostic_inline(summary)),
        ],
        service_status_style(service),
    );
    render_log_tail(frame, rows[1], log_tail);
}
