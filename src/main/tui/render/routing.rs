use super::*;

pub(super) fn draw_tui_route_mode_selector(frame: &mut Frame<'_>, app: &TuiApp) {
    let area = centered_rect(62, 46, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Route Mode ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(4)])
        .split(inner);
    let current = current_tui_route_mode(app.control_snapshot.as_ref());
    let rows = route_mode_options()
        .iter()
        .map(|option| {
            let marker = if current == Some(option.mode) {
                "*"
            } else {
                " "
            };
            Row::new(vec![
                marker.to_string(),
                option.name.to_string(),
                option.summary.to_string(),
            ])
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(3),
            Constraint::Length(10),
            Constraint::Min(28),
        ],
    )
    .header(Row::new(vec!["", "Mode", "Behavior"]).style(Style::default().fg(Color::DarkGray)))
    .block(Block::default().title(" Modes ").borders(Borders::ALL))
    .row_highlight_style(
        Style::default()
            .fg(Color::White)
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(" > ");
    let mut state = TableState::default();
    state.select(Some(app.route_mode_selection));
    frame.render_stateful_widget(table, chunks[0], &mut state);

    let help = Paragraph::new(vec![
        Line::from("Up/Down selects. Enter applies immediately."),
        Line::from("Esc closes without changing routing state."),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[1]);
}

pub(super) fn draw_tui_global_target_selector(frame: &mut Frame<'_>, app: &TuiApp) {
    let area = centered_rect(72, 68, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Global Target ")
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
        Span::raw(app.global_target_query.as_str()),
    ]))
    .block(Block::default().title(" Search ").borders(Borders::ALL));
    frame.render_widget(input, chunks[0]);

    let current = current_tui_global_target(app.control_snapshot.as_ref());
    let targets = app.filtered_global_targets();
    if targets.is_empty() {
        let empty = Paragraph::new("No global targets match this search.")
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
        state.select(Some(app.selected_global_target));
        frame.render_stateful_widget(table, chunks[1], &mut state);
    }

    let help = Paragraph::new(vec![
        Line::from("Type to filter. Up/Down selects. Enter applies the target only."),
        Line::from("Route mode is unchanged; use /mode to switch modes. Esc cancels."),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}
