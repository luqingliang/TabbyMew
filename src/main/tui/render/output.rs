use super::*;

pub(crate) fn draw_tui_output(frame: &mut Frame<'_>, app: &TuiApp) {
    let area = frame.area();
    frame.render_widget(Clear, area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(4),
        ])
        .split(area);
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            "TabbyMew",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(app.output_title.as_str(), Style::default().fg(Color::White)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let output = if app.output.trim().is_empty() {
        "No output.".to_string()
    } else {
        app.output.clone()
    };
    let body = Paragraph::new(output)
        .block(
            Block::default()
                .title(" Output ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.output_scroll, 0));
    frame.render_widget(body, chunks[1]);

    let footer = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Esc ", Style::default().fg(Color::Cyan)),
            Span::raw("dashboard  "),
            Span::styled("Up/Down ", Style::default().fg(Color::Cyan)),
            Span::raw("scroll  "),
            Span::styled("/ ", Style::default().fg(Color::Cyan)),
            Span::raw("commands  "),
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
