use super::*;

#[test]
fn reads_control_token_from_state_file() -> Result<()> {
    let dir = env::temp_dir().join(format!(
        "tabbymew-control-token-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let paths = process_manager::paths(&dir, None);
    let mut state = ProcessState {
        pid: std::process::id(),
        config: PathBuf::from("/tmp/config.json"),
        log: PathBuf::from("/tmp/tabbymew.log"),
        listen: Some("127.0.0.1:9090".to_string()),
        control_token: Some("test-token".to_string()),
        started_at_unix: 42,
        heartbeat_at_unix: Some(42),
    };

    process_manager::save_state_file(&paths.state_file, &state)?;
    assert_eq!(control_token_from_state_dir(&dir)?, "test-token");

    state.control_token = None;
    process_manager::save_state_file(&paths.state_file, &state)?;
    assert!(control_token_from_state_dir(&dir).is_err());

    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn reads_control_token_from_runtime_state_file() -> Result<()> {
    let dir = env::temp_dir().join(format!(
        "tabbymew-runtime-control-token-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let runtime_state_file = process_manager::runtime_state_file(&dir);
    let state = ProcessState {
        pid: std::process::id(),
        config: PathBuf::from("/tmp/config.json"),
        log: PathBuf::from("/tmp/tabbymew.log"),
        listen: Some("127.0.0.1:9090".to_string()),
        control_token: Some("runtime-token".to_string()),
        started_at_unix: 42,
        heartbeat_at_unix: Some(42),
    };

    process_manager::save_state_file(&runtime_state_file, &state)?;

    assert_eq!(control_token_from_state_dir(&dir)?, "runtime-token");

    fs::remove_dir_all(dir)?;
    Ok(())
}
