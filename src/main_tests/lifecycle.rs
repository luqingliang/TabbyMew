use super::*;

#[test]
fn launch_config_uses_saved_active_config_without_explicit_config() -> Result<()> {
    let dir = env::temp_dir().join(format!(
        "tabbymew-launch-config-test-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    let active_config = dir.join("active.json");
    fs::write(&active_config, "{}\n")?;
    process_manager::save_preferences(
        process_manager::preferences_path(&dir),
        &process_manager::RuntimePreferences {
            active_config: Some(active_config.clone()),
            ..process_manager::RuntimePreferences::default()
        },
    )?;

    assert_eq!(resolve_launch_config_path(None, &dir)?, active_config);

    let explicit_config = dir.join("explicit.json");
    assert_eq!(
        resolve_launch_config_path(Some(&explicit_config), &dir)?,
        explicit_config
    );

    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn launch_config_falls_back_when_preferences_are_invalid() -> Result<()> {
    let dir = env::temp_dir().join(format!(
        "tabbymew-launch-invalid-prefs-test-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    fs::write(
        process_manager::preferences_path(&dir),
        "{not valid runtime preferences}\n",
    )?;

    let fallback_config = dir.join("fallback.json");
    let config_path =
        resolve_launch_config_path_with_fallback(None, &dir, || Ok(fallback_config.clone()))?;
    assert_eq!(config_path, fallback_config);

    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn run_paths_do_not_create_managed_state_without_explicit_state_file() -> Result<()> {
    let dir = env::temp_dir().join(format!(
        "tabbymew-run-paths-unmanaged-test-{}",
        std::process::id()
    ));

    let paths = resolve_run_paths(dir.clone(), None, None, None)?;

    assert_eq!(paths.state_file, None);
    assert_eq!(paths.state_dir, dir);
    assert!(
        paths
            .log_file
            .as_ref()
            .is_some_and(|path| path.starts_with(paths.state_dir.join("logs")))
    );
    assert!(
        !process_manager::paths(&paths.state_dir, None)
            .state_file
            .exists()
    );

    let _ = fs::remove_dir_all(paths.state_dir);
    Ok(())
}

#[test]
fn run_paths_use_explicit_state_file_for_managed_start() -> Result<()> {
    let default_state_dir = env::temp_dir().join(format!(
        "tabbymew-run-paths-managed-default-test-{}",
        std::process::id()
    ));
    let explicit_state_file = env::temp_dir()
        .join(format!(
            "tabbymew-run-paths-managed-test-{}",
            std::process::id()
        ))
        .join("tabbymew-state.json");
    let explicit_log_file = explicit_state_file.with_extension("log");

    let paths = resolve_run_paths(
        default_state_dir,
        Some(explicit_state_file.clone()),
        None,
        Some(explicit_log_file.clone()),
    )?;

    assert_eq!(paths.state_file, Some(explicit_state_file.clone()));
    assert_eq!(
        paths.state_dir,
        explicit_state_file
            .parent()
            .expect("explicit state file has parent")
    );
    assert_eq!(paths.log_file, Some(explicit_log_file));

    Ok(())
}

#[test]
fn stop_state_loader_continues_after_unreadable_managed_state() -> Result<()> {
    let dir = env::temp_dir().join(format!(
        "tabbymew-stop-state-loader-test-{}",
        std::process::id()
    ));
    let paths = process_manager::paths(&dir, None);
    fs::create_dir_all(&dir)?;
    fs::write(&paths.state_file, "{not valid process state}\n")?;
    let runtime_state_file = process_manager::runtime_state_file(&dir);
    process_manager::save_state_file(
        &runtime_state_file,
        &ProcessState {
            pid: std::process::id(),
            config: dir.join("config.json"),
            log: dir.join("runtime.log"),
            listen: Some("127.0.0.1:9091".to_string()),
            control_token: None,
            started_at_unix: 42,
            heartbeat_at_unix: Some(42),
        },
    )?;

    let loaded = load_local_process_state_for_stop(&dir)?;

    assert!(!paths.state_file.exists());
    let (state, state_file) = loaded.context("runtime state should be loaded")?;
    assert_eq!(state.pid, std::process::id());
    assert_eq!(state_file, runtime_state_file);

    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn parses_hidden_internal_tun_helper_command() -> Result<()> {
    let cli = Cli::try_parse_from([
        "TabbyMew",
        "internal-tun-helper",
        "--control",
        "127.0.0.1:12345",
        "--token-file",
        "/tmp/tabbymew-helper-auth.txt",
    ])?;

    match cli.command {
        Some(Command::InternalTunHelper(command)) => {
            assert_eq!(
                command.token_file,
                PathBuf::from("/tmp/tabbymew-helper-auth.txt")
            );
        }
        other => panic!("unexpected command: {other:?}"),
    }
    Ok(())
}
