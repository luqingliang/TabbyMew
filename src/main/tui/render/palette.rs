use super::*;

pub(crate) fn draw_tui_command_palette(frame: &mut Frame<'_>, app: &TuiApp) {
    let area = centered_rect(76, 72, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Command Palette ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(4),
        ])
        .split(inner);

    let input = Paragraph::new(Line::from(vec![
        Span::styled("/", Style::default().fg(Color::Cyan)),
        Span::raw(app.command_query.as_str()),
    ]))
    .block(Block::default().title(" Search ").borders(Borders::ALL));
    frame.render_widget(input, chunks[0]);

    let commands = app.filtered_commands();
    if commands.is_empty() {
        let empty = Paragraph::new("No commands match this search.")
            .alignment(Alignment::Center)
            .block(Block::default().title(" Commands ").borders(Borders::ALL));
        frame.render_widget(empty, chunks[1]);
    } else {
        let rows = commands
            .iter()
            .map(|command| {
                Row::new(vec![
                    command.usage.to_string(),
                    command.category.to_string(),
                    command.summary.to_string(),
                ])
            })
            .collect::<Vec<_>>();
        let table = Table::new(
            rows,
            [
                Constraint::Length(28),
                Constraint::Length(16),
                Constraint::Min(20),
            ],
        )
        .header(
            Row::new(vec!["Command", "Area", "Action"]).style(Style::default().fg(Color::DarkGray)),
        )
        .block(Block::default().title(" Commands ").borders(Borders::ALL))
        .row_highlight_style(
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" > ");
        let mut state = TableState::default();
        state.select(Some(app.selected_command));
        frame.render_stateful_widget(table, chunks[1], &mut state);
    }

    let help = Paragraph::new(vec![
        Line::from("Type after / to filter. Enter runs the selected command."),
        Line::from("Esc closes the palette without changing service state."),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}
