use super::*;

pub(crate) async fn handle_tui_palette_key(app: &mut TuiApp, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => app.mode = TuiMode::Dashboard,
        KeyCode::Backspace => {
            app.command_query.pop();
            app.clamp_selection();
        }
        KeyCode::Up => {
            app.selected_command = app.selected_command.saturating_sub(1);
        }
        KeyCode::Down => {
            let len = app.filtered_commands().len();
            if len > 0 {
                app.selected_command = (app.selected_command + 1).min(len - 1);
            }
        }
        KeyCode::Enter => {
            if let Some(invocation) = selected_shell_invocation(app)
                && let Err(err) =
                    execute_tui_command(app, invocation.command, &invocation.args).await
            {
                open_tui_error(app, invocation.command.usage, err);
            }
        }
        KeyCode::Char('/') if app.command_query.is_empty() => {}
        KeyCode::Char(value) => {
            app.command_query.push(value);
            app.clamp_selection();
        }
        _ => {}
    }
    Ok(())
}
