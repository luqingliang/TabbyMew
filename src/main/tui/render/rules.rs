use super::*;

pub(super) fn draw_tui_route_rules(frame: &mut Frame<'_>, app: &TuiApp) {
    let area = centered_rect(90, 82, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Route Rules ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(4),
        ])
        .split(inner);
    let input = Paragraph::new(Line::from(vec![
        Span::styled("search ", Style::default().fg(Color::DarkGray)),
        Span::raw(app.route_rule_query.as_str()),
    ]))
    .block(Block::default().title(" Search ").borders(Borders::ALL));
    frame.render_widget(input, chunks[0]);

    let items = tui_route_rule_items(app.control_snapshot.as_ref());
    let visible = app.filtered_route_rules();
    let custom = items.iter().filter(|item| item.source == "custom").count();
    let subscription = items
        .iter()
        .filter(|item| item.source == "subscription")
        .count();
    let final_outbound = app
        .control_snapshot
        .as_ref()
        .and_then(|value| value_str(value, &["rules", "final_outbound"]))
        .unwrap_or("-");
    let resolve_ip_cidr = app
        .control_snapshot
        .as_ref()
        .and_then(|value| value_bool(value, &["rules", "resolve_ip_cidr"]))
        .map(on_off)
        .unwrap_or("-");
    let summary = Paragraph::new(Line::from(vec![
        Span::raw(format!("{} visible / {} total", visible.len(), items.len())),
        Span::raw(format!("  custom {custom}")),
        Span::raw(format!("  subscription {subscription}")),
        Span::raw(format!("  final {final_outbound}")),
        Span::raw(format!("  ip-cidr {resolve_ip_cidr}")),
    ]))
    .block(Block::default().title(" Summary ").borders(Borders::ALL));
    frame.render_widget(summary, chunks[1]);

    if visible.is_empty() {
        let text = if items.is_empty() {
            "No route rules are available."
        } else {
            "No route rules match this search."
        };
        let empty = Paragraph::new(text)
            .alignment(Alignment::Center)
            .block(Block::default().title(" Rules ").borders(Borders::ALL));
        frame.render_widget(empty, chunks[2]);
    } else {
        let rows = visible
            .iter()
            .map(|item| {
                Row::new(vec![
                    item.index.to_string(),
                    item.source.clone(),
                    item.id.clone().unwrap_or_else(|| "-".to_string()),
                    item.match_kind.clone(),
                    item.match_content.clone(),
                    item.outbound.clone(),
                ])
            })
            .collect::<Vec<_>>();
        let table = Table::new(
            rows,
            [
                Constraint::Length(5),
                Constraint::Length(12),
                Constraint::Length(18),
                Constraint::Length(16),
                Constraint::Min(22),
                Constraint::Min(16),
            ],
        )
        .header(
            Row::new(vec!["#", "Source", "ID", "Match", "Content", "Target"])
                .style(Style::default().fg(Color::DarkGray)),
        )
        .block(Block::default().title(" Rules ").borders(Borders::ALL))
        .row_highlight_style(
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" > ");
        let mut state = TableState::default();
        state.select(Some(app.selected_route_rule.min(visible.len() - 1)));
        frame.render_stateful_widget(table, chunks[2], &mut state);
    }

    let help = Paragraph::new(vec![
        Line::from("Type to search. Up/Down selects. + adds a custom rule."),
        Line::from("Enter opens custom rule actions. F5 reloads rules. Esc returns."),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[3]);
}

pub(super) fn draw_tui_route_rule_actions(frame: &mut Frame<'_>, app: &TuiApp) {
    let area = centered_rect(48, 30, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Custom Rule ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(4)])
        .split(inner);
    let actions = tui_route_rule_actions();
    let rows = actions
        .iter()
        .map(|action| Row::new(vec![action.label, action.summary]))
        .collect::<Vec<_>>();
    let table = Table::new(rows, [Constraint::Length(10), Constraint::Min(24)])
        .header(Row::new(vec!["Action", "Behavior"]).style(Style::default().fg(Color::DarkGray)))
        .block(Block::default().title(" Actions ").borders(Borders::ALL))
        .row_highlight_style(
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" > ");
    let mut state = TableState::default();
    state.select(Some(app.selected_route_rule_action.min(actions.len() - 1)));
    frame.render_stateful_widget(table, chunks[0], &mut state);

    let help = Paragraph::new(vec![
        Line::from("Up/Down selects. Enter applies the action."),
        Line::from("Esc returns to route rules."),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[1]);
}

pub(super) fn draw_tui_route_rule_add(frame: &mut Frame<'_>, app: &TuiApp) {
    let area = centered_rect(78, 38, frame.area());
    frame.render_widget(Clear, area);
    let title = if app.route_rule_form_id.is_some() {
        " Edit Custom Rule "
    } else {
        " Add Custom Rule "
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(4),
        ])
        .split(inner);

    let content = Paragraph::new(app.route_rule_add_content.as_str())
        .block(
            Block::default()
                .title(" Match Content ")
                .borders(Borders::ALL)
                .border_style(tui_route_rule_add_field_style(
                    app,
                    TUI_ROUTE_RULE_ADD_CONTENT_FIELD,
                )),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(content, chunks[0]);

    let match_kind = selected_tui_route_rule_match_kind(app);
    let match_rule = Paragraph::new(Line::from(vec![
        Span::styled(match_kind.label, Style::default().fg(Color::White)),
        Span::raw(format!("  {}  ", match_kind.key)),
        Span::styled(match_kind.summary, Style::default().fg(Color::DarkGray)),
    ]))
    .block(
        Block::default()
            .title(" Match Rule ")
            .borders(Borders::ALL)
            .border_style(tui_route_rule_add_field_style(
                app,
                TUI_ROUTE_RULE_ADD_MATCH_FIELD,
            )),
    );
    frame.render_widget(match_rule, chunks[1]);

    let route_target = selected_tui_route_rule_target(app)
        .unwrap_or_else(|| "No route targets available".to_string());
    let route_target = Paragraph::new(route_target)
        .block(
            Block::default()
                .title(" Route Target ")
                .borders(Borders::ALL)
                .border_style(tui_route_rule_add_field_style(
                    app,
                    TUI_ROUTE_RULE_ADD_TARGET_FIELD,
                )),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(route_target, chunks[2]);

    let help = Paragraph::new(vec![
        Line::from(
            "Tab switches fields. Arrows change match rule; Enter on target opens selector.",
        ),
        Line::from(if app.route_rule_form_id.is_some() {
            "Enter updates from other fields. Esc cancels."
        } else {
            "Enter saves from other fields. Esc cancels."
        }),
        Line::from(app.last_message.as_str()),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[3]);
}

pub(super) fn draw_tui_route_rule_target_selector(frame: &mut Frame<'_>, app: &TuiApp) {
    let area = centered_rect(72, 68, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Route Target ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(4),
        ])
        .split(inner);
    let input = Paragraph::new(Line::from(vec![
        Span::styled("filter ", Style::default().fg(Color::DarkGray)),
        Span::raw(app.route_rule_target_query.as_str()),
    ]))
    .block(Block::default().title(" Search ").borders(Borders::ALL));
    frame.render_widget(input, chunks[0]);

    let current = selected_tui_route_rule_target(app);
    let targets = app.filtered_route_rule_targets();
    if targets.is_empty() {
        let empty = Paragraph::new("No route targets match this search.")
            .alignment(Alignment::Center)
            .block(Block::default().title(" Targets ").borders(Borders::ALL));
        frame.render_widget(empty, chunks[1]);
    } else {
        let rows = targets
            .iter()
            .map(|target| {
                let marker = if current.as_deref() == Some(target.as_str()) {
                    "*"
                } else {
                    " "
                };
                Row::new(vec![marker.to_string(), target.clone()])
            })
            .collect::<Vec<_>>();
        let table = Table::new(rows, [Constraint::Length(3), Constraint::Min(24)])
            .header(Row::new(vec!["", "Target"]).style(Style::default().fg(Color::DarkGray)))
            .block(Block::default().title(" Targets ").borders(Borders::ALL))
            .row_highlight_style(
                Style::default()
                    .fg(Color::White)
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(" > ");
        let mut state = TableState::default();
        state.select(Some(app.selected_route_rule_target_candidate));
        frame.render_stateful_widget(table, chunks[1], &mut state);
    }

    let help = Paragraph::new(vec![
        Line::from("Type to filter. Up/Down selects. Enter uses this target for the custom rule."),
        Line::from("Esc returns to the custom rule form without changing the target."),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}

pub(super) fn tui_route_rule_add_field_style(app: &TuiApp, field: usize) -> Style {
    if app.route_rule_add_field == field {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}
