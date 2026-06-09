use super::*;

pub(super) fn run_autostart_command(
    config: Option<&PathBuf>,
    command: AutostartCommand,
) -> Result<()> {
    let action = crate::autostart::parse_action(
        command.action.as_deref(),
        crate::autostart::AutostartAction::Status,
    )?;
    let state_dir = crate::autostart::absolute_path(
        &command
            .state_dir
            .unwrap_or_else(process_manager::default_state_dir),
    )?;
    let config = if crate::autostart::action_needs_config(action, &state_dir)? {
        Some(resolve_autostart_config_path(config, &state_dir)?)
    } else {
        None
    };
    let executable = crate::autostart::absolute_path(
        &env::current_exe().context("failed to resolve current executable")?,
    )?;
    let report = crate::autostart::apply(
        action,
        crate::autostart::AutostartOptions {
            state_dir,
            config,
            executable,
        },
    )?;
    if command.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", crate::autostart::format_report(&report));
    }
    Ok(())
}

fn resolve_autostart_config_path(config: Option<&PathBuf>, state_dir: &Path) -> Result<PathBuf> {
    let config_path = resolve_launch_config_path(config, state_dir)?;
    let config_model = Config::load(&config_path)?;
    validate_runtime_config(&config_model, config_base_dir(&config_path))?;
    fs::canonicalize(&config_path)
        .with_context(|| format!("failed to canonicalize config {}", config_path.display()))
}
