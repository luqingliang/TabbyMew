use super::*;

pub(crate) fn draw_tui_subscriptions(frame: &mut Frame<'_>, app: &TuiApp) {
    let area = centered_rect(92, 84, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Subscriptions ")
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
            Constraint::Length(7),
            Constraint::Length(4),
        ])
        .split(inner);
    let input = Paragraph::new(Line::from(vec![
        Span::styled("search ", Style::default().fg(Color::DarkGray)),
        Span::raw(app.subscription_query.as_str()),
    ]))
    .block(Block::default().title(" Search ").borders(Borders::ALL));
    frame.render_widget(input, chunks[0]);

    let items = tui_subscription_items(app.control_snapshot.as_ref());
    let visible = app.filtered_subscriptions();
    let active = active_tui_subscription(app.control_snapshot.as_ref()).unwrap_or("-");
    let auto_update = items.iter().filter(|item| item.auto_update).count();
    let failed = items
        .iter()
        .filter(|item| item.last_error.is_some())
        .count();
    let summary = Paragraph::new(Line::from(vec![
        Span::raw(format!("{} visible / {} total", visible.len(), items.len())),
        Span::raw(format!("  active {active}")),
        Span::raw(format!("  auto {auto_update}")),
        Span::raw(format!("  failed {failed}")),
    ]))
    .block(Block::default().title(" Summary ").borders(Borders::ALL));
    frame.render_widget(summary, chunks[1]);

    if visible.is_empty() {
        let text = if items.is_empty() {
            "No subscriptions are configured."
        } else {
            "No subscriptions match this search."
        };
        let empty = Paragraph::new(text).alignment(Alignment::Center).block(
            Block::default()
                .title(" Subscriptions ")
                .borders(Borders::ALL),
        );
        frame.render_widget(empty, chunks[2]);
    } else {
        let rows = visible
            .iter()
            .map(|item| {
                Row::new(vec![
                    if item.active { "*" } else { " " }.to_string(),
                    item.name.clone(),
                    item.source.clone(),
                    on_off(item.auto_update).to_string(),
                    item.imported.clone(),
                    item.last_success.clone(),
                    item.status.clone(),
                ])
            })
            .collect::<Vec<_>>();
        let table = Table::new(
            rows,
            [
                Constraint::Length(3),
                Constraint::Min(16),
                Constraint::Length(12),
                Constraint::Length(7),
                Constraint::Length(9),
                Constraint::Length(14),
                Constraint::Min(12),
            ],
        )
        .header(
            Row::new(vec![
                "", "Name", "Source", "Auto", "Imported", "Last OK", "Status",
            ])
            .style(Style::default().fg(Color::DarkGray)),
        )
        .block(Block::default().title(" Items ").borders(Borders::ALL))
        .row_highlight_style(
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" > ");
        let mut state = TableState::default();
        state.select(Some(app.selected_subscription.min(visible.len() - 1)));
        frame.render_stateful_widget(table, chunks[2], &mut state);
    }

    let detail = selected_tui_subscription_item(app)
        .map(|item| format_tui_subscription_detail(&item))
        .unwrap_or_else(|| "No subscription selected.".to_string());
    let detail = Paragraph::new(detail)
        .block(Block::default().title(" Details ").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(detail, chunks[3]);

    let help = Paragraph::new(vec![
        Line::from("Type to search. Up/Down selects. Enter opens actions. + adds a subscription."),
        Line::from("u updates all remote subscriptions. F5 reloads local state. Esc returns."),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[4]);
}

pub(crate) fn draw_tui_subscription_actions(frame: &mut Frame<'_>, app: &TuiApp) {
    let area = centered_rect(56, 36, frame.area());
    frame.render_widget(Clear, area);
    let title = selected_tui_subscription_item(app)
        .map(|item| format!(" Subscription: {} ", item.name))
        .unwrap_or_else(|| " Subscription ".to_string());
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(4)])
        .split(inner);
    let selected = selected_tui_subscription_item(app);
    let actions = tui_subscription_actions();
    let rows = actions
        .iter()
        .map(|action| {
            Row::new(vec![
                subscription_action_label(action.action, selected.as_ref()),
                subscription_action_summary(action.action, selected.as_ref()),
            ])
        })
        .collect::<Vec<_>>();
    let table = Table::new(rows, [Constraint::Length(16), Constraint::Min(24)])
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
    state.select(Some(
        app.selected_subscription_action.min(actions.len() - 1),
    ));
    frame.render_stateful_widget(table, chunks[0], &mut state);

    let help = Paragraph::new(vec![
        Line::from("Up/Down selects. Enter applies the action immediately."),
        Line::from("Esc returns to subscriptions."),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[1]);
}

pub(crate) fn draw_tui_subscription_add(frame: &mut Frame<'_>, app: &TuiApp) {
    let area = tui_subscription_add_area(frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Add Subscription ")
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
            Constraint::Min(4),
        ])
        .split(inner);

    let name = tui_subscription_add_input(
        app,
        " Name ",
        app.subscription_add_name.as_str(),
        TUI_SUBSCRIPTION_ADD_NAME_FIELD,
        chunks[0],
    );
    frame.render_widget(name, chunks[0]);

    let url = tui_subscription_add_input(
        app,
        " URL / File ",
        app.subscription_add_url.as_str(),
        TUI_SUBSCRIPTION_ADD_URL_FIELD,
        chunks[1],
    );
    frame.render_widget(url, chunks[1]);

    let auto_update = Paragraph::new(if app.subscription_add_auto_update {
        "enabled"
    } else {
        "disabled"
    })
    .block(
        Block::default()
            .title(" Auto Update ")
            .borders(Borders::ALL)
            .border_style(tui_subscription_add_field_style(
                app,
                TUI_SUBSCRIPTION_ADD_AUTO_UPDATE_FIELD,
            )),
    );
    frame.render_widget(auto_update, chunks[2]);

    let help = Paragraph::new(vec![
        Line::from("Tab switches fields. Left/Right toggles auto update."),
        Line::from("Enter imports URL or local file. Auto update applies to URL subscriptions."),
        Line::from(app.last_message.as_str()),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[3]);
}

pub(crate) fn tui_subscription_add_field_style(app: &TuiApp, field: usize) -> Style {
    if app.subscription_add_field == field {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

pub(crate) fn tui_subscription_add_area(area: Rect) -> Rect {
    centered_rect_with_min_size(78, 58, 54, 15, area)
}

fn centered_rect_with_min_size(
    width_percent: u16,
    height_percent: u16,
    min_width: u16,
    min_height: u16,
    area: Rect,
) -> Rect {
    let rect = centered_rect(width_percent, height_percent, area);
    let width = rect.width.max(min_width).min(area.width);
    let height = rect.height.max(min_height).min(area.height);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

fn tui_subscription_add_input(
    app: &TuiApp,
    title: &'static str,
    value: &str,
    field: usize,
    area: Rect,
) -> Paragraph<'static> {
    let text = visible_tui_subscription_input_value(value, tui_subscription_add_input_width(area))
        .into_owned();
    Paragraph::new(Line::from(Span::styled(
        text,
        Style::default().fg(Color::White),
    )))
    .block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(tui_subscription_add_field_style(app, field)),
    )
}

pub(crate) fn visible_tui_subscription_input_value(
    value: &str,
    width: u16,
) -> std::borrow::Cow<'_, str> {
    let width = usize::from(width);
    if width == 0 {
        return std::borrow::Cow::Borrowed("");
    }

    let value_len = value.chars().count();
    if value_len <= width {
        return std::borrow::Cow::Borrowed(value);
    }

    if width <= 3 {
        return std::borrow::Cow::Owned(tui_subscription_input_tail(value, width));
    }

    std::borrow::Cow::Owned(format!(
        "...{}",
        tui_subscription_input_tail(value, width - 3)
    ))
}

fn tui_subscription_add_input_width(area: Rect) -> u16 {
    area.width.saturating_sub(2)
}

fn tui_subscription_input_tail(value: &str, width: usize) -> String {
    let mut chars = value.chars().rev().take(width).collect::<Vec<_>>();
    chars.reverse();
    chars.into_iter().collect()
}
