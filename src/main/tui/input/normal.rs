use super::*;

pub(crate) async fn handle_tui_normal_key(app: &mut TuiApp, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Char('/') => {
            app.mode = TuiMode::CommandPalette;
            app.command_query.clear();
            app.selected_command = 0;
        }
        KeyCode::Char('r') | KeyCode::F(5) => {
            match app.refresh_status().await {
                Ok(()) => app.last_message = "status refreshed".to_string(),
                Err(err) => app.last_message = format!("refresh failed: {err:#}"),
            }
            app.mode = TuiMode::Dashboard;
        }
        KeyCode::Esc if app.mode == TuiMode::Output => app.mode = TuiMode::Dashboard,
        KeyCode::Up if app.mode == TuiMode::Output => {
            app.output_scroll = app.output_scroll.saturating_sub(1);
        }
        KeyCode::Down if app.mode == TuiMode::Output => {
            app.output_scroll = app.output_scroll.saturating_add(1);
        }
        KeyCode::PageUp if app.mode == TuiMode::Output => {
            app.output_scroll = app.output_scroll.saturating_sub(10);
        }
        KeyCode::PageDown if app.mode == TuiMode::Output => {
            app.output_scroll = app.output_scroll.saturating_add(10);
        }
        KeyCode::Home if app.mode == TuiMode::Output => {
            app.output_scroll = 0;
        }
        KeyCode::Char('?') => {
            app.output_title = "Commands".to_string();
            app.output = command_help_text(None);
            app.output_scroll = 0;
            app.mode = TuiMode::Output;
        }
        _ => {}
    }
    Ok(())
}
