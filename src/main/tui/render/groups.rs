use super::*;

pub(crate) fn draw_tui_policy_group_list_selector(frame: &mut Frame<'_>, app: &TuiApp) {
    let area = centered_rect(78, 72, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Policy Groups ")
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
        Span::raw(app.policy_group_query.as_str()),
    ]))
    .block(Block::default().title(" Search ").borders(Borders::ALL));
    frame.render_widget(input, chunks[0]);

    let groups = app.filtered_policy_groups();
    if groups.is_empty() {
        let text = if policy_groups(app.control_snapshot.as_ref()).is_empty() {
            "No policy groups are available."
        } else {
            "No policy groups match this search."
        };
        let empty = Paragraph::new(text)
            .alignment(Alignment::Center)
            .block(Block::default().title(" Groups ").borders(Borders::ALL));
        frame.render_widget(empty, chunks[1]);
    } else {
        let rows = groups
            .iter()
            .map(|group| {
                Row::new(vec![
                    group.tag.clone(),
                    group.selected.clone(),
                    group.outbounds.len().to_string(),
                    group.kind.clone(),
                ])
            })
            .collect::<Vec<_>>();
        let table = Table::new(
            rows,
            [
                Constraint::Min(18),
                Constraint::Min(18),
                Constraint::Length(9),
                Constraint::Length(10),
            ],
        )
        .header(
            Row::new(vec!["Group", "Selected", "Outbounds", "Type"])
                .style(Style::default().fg(Color::DarkGray)),
        )
        .block(Block::default().title(" Groups ").borders(Borders::ALL))
        .row_highlight_style(
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" > ");
        let mut state = TableState::default();
        state.select(Some(app.selected_policy_group));
        frame.render_stateful_widget(table, chunks[1], &mut state);
    }

    let help = Paragraph::new(vec![
        Line::from("Type to filter. Up/Down selects a group. Enter opens its outbounds."),
        Line::from("Route mode is unchanged until an outbound is selected. Esc cancels."),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}

pub(crate) fn draw_tui_policy_group_selector(frame: &mut Frame<'_>, app: &TuiApp) {
    let area = centered_rect(76, 72, frame.area());
    frame.render_widget(Clear, area);
    let group = app
        .selected_policy_group_tag
        .as_deref()
        .unwrap_or("Policy Group");
    let block = Block::default()
        .title(format!(" Policy Group: {group} "))
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
        Span::raw(app.policy_group_outbound_query.as_str()),
    ]))
    .block(Block::default().title(" Search ").borders(Borders::ALL));
    frame.render_widget(input, chunks[0]);

    let current = current_policy_group_outbound(app.control_snapshot.as_ref(), group);
    let outbounds = app.filtered_policy_group_outbounds();
    if outbounds.is_empty() {
        let empty = Paragraph::new("No outbounds match this search.")
            .alignment(Alignment::Center)
            .block(Block::default().title(" Outbounds ").borders(Borders::ALL));
        frame.render_widget(empty, chunks[1]);
    } else {
        let rows = outbounds
            .iter()
            .map(|outbound| {
                let marker = if current.as_deref() == Some(outbound.as_str()) {
                    "*"
                } else {
                    " "
                };
                Row::new(vec![
                    Cell::from(marker.to_string()),
                    Cell::from(outbound.clone()),
                    tui_policy_group_delay_cell(tui_policy_group_delay_for(app, group, outbound)),
                ])
            })
            .collect::<Vec<_>>();
        let title = tui_policy_group_delay_table_title(app, group);
        let table = Table::new(
            rows,
            [
                Constraint::Length(3),
                Constraint::Min(24),
                Constraint::Length(12),
            ],
        )
        .header(Row::new(vec!["", "Outbound", "Delay"]).style(Style::default().fg(Color::DarkGray)))
        .block(Block::default().title(title).borders(Borders::ALL))
        .row_highlight_style(
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" > ");
        let mut state = TableState::default();
        state.select(Some(app.selected_policy_group_outbound));
        frame.render_stateful_widget(table, chunks[1], &mut state);
    }

    let help = Paragraph::new(vec![
        Line::from("Type to filter. Up/Down selects. Enter applies. Ctrl+t tests delays."),
        Line::from(
            "Route mode is unchanged; this affects rule/global targets that use this group.",
        ),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}
