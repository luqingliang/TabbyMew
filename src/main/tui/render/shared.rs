use super::*;

pub(super) fn render_kv_table(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &'static str,
    rows: Vec<(&'static str, String)>,
    border_style: Style,
) {
    let rows = rows
        .into_iter()
        .map(|(label, value)| {
            let tone = dashboard_status_row_tone(label, &value);
            Row::new(vec![
                Cell::from(label).style(dashboard_status_label_style(tone)),
                Cell::from(value).style(dashboard_status_value_style(tone)),
            ])
        })
        .collect::<Vec<_>>();
    let table = Table::new(rows, [Constraint::Length(17), Constraint::Min(10)])
        .block(
            Block::default()
                .title(format!(" {title} "))
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .column_spacing(1);
    frame.render_widget(table, area);
}

pub(super) fn split_dashboard_status_and_logs(area: Rect) -> std::rc::Rc<[Rect]> {
    let top_height = dashboard_status_height(area.height);
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(top_height), Constraint::Min(5)])
        .split(area)
}

pub(super) fn dashboard_status_height(height: u16) -> u16 {
    if height <= 12 {
        return height;
    }
    let room_for_logs = height.saturating_sub(6);
    room_for_logs.clamp(12, 17)
}

pub(super) fn render_log_tail(frame: &mut Frame<'_>, area: Rect, log_tail: &str) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    let text = if log_tail.trim().is_empty() {
        "No log output yet.".to_string()
    } else {
        simplify_tui_log_tail(log_tail)
    };
    let visible_lines = area.height.saturating_sub(2) as usize;
    let line_count = text.lines().count();
    let scroll = line_count.saturating_sub(visible_lines) as u16;
    let logs = Paragraph::new(text.as_str())
        .block(
            Block::default()
                .title(" Logs ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .scroll((scroll, 0));
    frame.render_widget(logs, area);
}

pub(super) fn simplify_tui_log_tail(log_tail: &str) -> String {
    let mut output = String::with_capacity(log_tail.len());
    for line in log_tail.lines() {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(simplify_tui_log_line(line).as_ref());
    }
    if log_tail.ends_with('\n') {
        output.push('\n');
    }
    output
}

pub(super) fn simplify_tui_log_line(line: &str) -> Cow<'_, str> {
    let line = if starts_with_date_time_prefix(line) {
        Cow::Borrowed(&line[11..])
    } else {
        Cow::Borrowed(line)
    };
    let line = compact_tui_time_level_spacing(line);
    simplify_tui_connection_log_line(line)
}

pub(super) fn compact_tui_time_level_spacing(line: Cow<'_, str>) -> Cow<'_, str> {
    let text = line.as_ref();
    if !starts_with_time_prefix(text) {
        return line;
    }
    let bytes = text.as_bytes();
    let mut index = 8;
    let mut whitespace_count = 0;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        whitespace_count += 1;
        index += 1;
    }
    if whitespace_count <= 1 {
        return line;
    }

    let mut output = String::with_capacity(text.len().saturating_sub(whitespace_count) + 1);
    output.push_str(&text[..8]);
    output.push(' ');
    output.push_str(&text[index..]);
    Cow::Owned(output)
}

pub(super) fn simplify_tui_connection_log_line(line: Cow<'_, str>) -> Cow<'_, str> {
    let text = line.as_ref();
    if !(text.contains("connection routed") || text.contains("connection failed")) {
        return line;
    }
    Cow::Owned(
        text.replace("connection routed", "conn")
            .replace("connection", "conn")
            .replace("destination=", "")
            .replace("outbound=", "=>"),
    )
}

pub(super) fn starts_with_time_prefix(line: &str) -> bool {
    let bytes = line.as_bytes();
    bytes.len() >= 8
        && bytes[0..2].iter().all(u8::is_ascii_digit)
        && bytes[2] == b':'
        && bytes[3..5].iter().all(u8::is_ascii_digit)
        && bytes[5] == b':'
        && bytes[6..8].iter().all(u8::is_ascii_digit)
}

pub(super) fn starts_with_date_time_prefix(line: &str) -> bool {
    let bytes = line.as_bytes();
    bytes.len() >= 19
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[10] == b' '
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[13] == b':'
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[16] == b':'
        && bytes[17..19].iter().all(u8::is_ascii_digit)
}

pub(super) fn render_diagnostics(frame: &mut Frame<'_>, area: Rect, summary: &TuiStatusSummary) {
    let mut items = Vec::new();
    if summary.cleanup_items.is_empty()
        && summary.control_error.is_none()
        && summary.state_error.is_none()
        && summary.preference_error.is_none()
    {
        items.push(ListItem::new("No cleanup or diagnostic issue detected."));
    }
    for item in &summary.cleanup_items {
        items.push(ListItem::new(Line::from(vec![
            Span::styled("cleanup ", Style::default().fg(Color::Yellow)),
            Span::raw(item.as_str()),
        ])));
    }
    if let Some(error) = &summary.control_error {
        items.push(ListItem::new(Line::from(vec![
            Span::styled("control ", Style::default().fg(Color::Red)),
            Span::raw(error.as_str()),
        ])));
    }
    if let Some(error) = &summary.state_error {
        items.push(ListItem::new(Line::from(vec![
            Span::styled("state ", Style::default().fg(Color::Red)),
            Span::raw(error.as_str()),
        ])));
    }
    if let Some(error) = &summary.preference_error {
        items.push(ListItem::new(Line::from(vec![
            Span::styled("preferences ", Style::default().fg(Color::Red)),
            Span::raw(error.as_str()),
        ])));
    }
    let list = List::new(items).block(
        Block::default()
            .title(" Diagnostics ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    frame.render_widget(list, area);
}

pub(super) fn diagnostic_inline(summary: &TuiStatusSummary) -> String {
    let mut items = summary.cleanup_items.clone();
    if summary.control_error.is_some() {
        items.push("control_api".to_string());
    }
    if summary.state_error.is_some() {
        items.push("state_file".to_string());
    }
    if summary.preference_error.is_some() {
        items.push("preferences_file".to_string());
    }
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

pub(super) fn centered_rect(width_percent: u16, height_percent: u16, area: Rect) -> Rect {
    let vertical_margin = (100u16.saturating_sub(height_percent)) / 2;
    let horizontal_margin = (100u16.saturating_sub(width_percent)) / 2;
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(vertical_margin),
            Constraint::Percentage(height_percent),
            Constraint::Percentage(vertical_margin),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(horizontal_margin),
            Constraint::Percentage(width_percent),
            Constraint::Percentage(horizontal_margin),
        ])
        .split(vertical[1])[1]
        .inner(Margin {
            vertical: 0,
            horizontal: 0,
        })
}

pub(super) fn service_status_style(service: &ServiceStatus) -> Style {
    if service.needs_cleanup() {
        return Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
    }
    match service.status {
        ServiceStatusKind::Running => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        ServiceStatusKind::Stopped => Style::default().fg(Color::DarkGray),
        ServiceStatusKind::Stale => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}
