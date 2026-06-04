use super::*;

#[test]
fn parses_lifecycle_cleanup_and_doctor_commands() -> Result<()> {
    assert_eq!(
        ShellCommand::default().timeout_ms,
        DEFAULT_CONTROL_TIMEOUT_MS
    );

    let cli = Cli::try_parse_from(["TabbyMew", "shell"])?;
    match cli.command {
        Some(Command::Shell(command)) => {
            assert_eq!(command.timeout_ms, DEFAULT_CONTROL_TIMEOUT_MS);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "TabbyMew",
        "shell",
        "--state-dir",
        "/tmp/tabbymew-state",
        "--timeout-ms",
        "250",
    ])?;
    match cli.command {
        Some(Command::Shell(command)) => {
            assert_eq!(
                command.state_dir,
                Some(PathBuf::from("/tmp/tabbymew-state"))
            );
            assert_eq!(command.timeout_ms, 250);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "TabbyMew",
        "cleanup",
        "--state-dir",
        "/tmp/tabbymew-state",
        "--json",
    ])?;
    match cli.command {
        Some(Command::Cleanup(command)) => {
            assert_eq!(
                command.state_dir,
                Some(PathBuf::from("/tmp/tabbymew-state"))
            );
            assert!(command.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "TabbyMew",
        "doctor",
        "--state-dir",
        "/tmp/tabbymew-state",
        "--timeout-ms",
        "250",
        "--json",
    ])?;
    match cli.command {
        Some(Command::Doctor(command)) => {
            assert_eq!(
                command.state_dir,
                Some(PathBuf::from("/tmp/tabbymew-state"))
            );
            assert_eq!(command.timeout_ms, 250);
            assert!(command.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "TabbyMew",
        "wait",
        "--state-dir",
        "/tmp/tabbymew-state",
        "--timeout-ms",
        "5000",
        "--interval-ms",
        "100",
        "--request-timeout-ms",
        "250",
        "--json",
        "tun",
        "on",
    ])?;
    match cli.command {
        Some(Command::Wait(command)) => {
            assert_eq!(
                command.state_dir,
                Some(PathBuf::from("/tmp/tabbymew-state"))
            );
            assert_eq!(command.timeout_ms, 5000);
            assert_eq!(command.interval_ms, 100);
            assert_eq!(command.request_timeout_ms, 250);
            assert_eq!(command.target, "tun");
            assert_eq!(command.state.as_deref(), Some("on"));
            assert!(command.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    assert_eq!(parse_wait_target("system-proxy")?, WaitTarget::SystemProxy);
    assert_eq!(
        parse_wait_desired(WaitTarget::Service, Some("stopped"))?,
        WaitDesired::Stopped
    );
    assert!(parse_wait_desired(WaitTarget::Tun, Some("ready")).is_ok());
    Ok(())
}

#[test]
fn parses_agent_json_lifecycle_commands() -> Result<()> {
    let cli = Cli::try_parse_from([
        "TabbyMew",
        "start",
        "--state-dir",
        "/tmp/tabbymew-state",
        "--log",
        "/tmp/tabbymew.log",
        "--control-listen",
        "127.0.0.1:9090",
        "--json",
    ])?;
    match cli.command {
        Some(Command::Start(command)) => {
            assert_eq!(
                command.state_dir,
                Some(PathBuf::from("/tmp/tabbymew-state"))
            );
            assert_eq!(command.log, Some(PathBuf::from("/tmp/tabbymew.log")));
            assert_eq!(command.control_listen.as_deref(), Some("127.0.0.1:9090"));
            assert!(command.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "TabbyMew",
        "stop",
        "--state-dir",
        "/tmp/tabbymew-state",
        "--pid",
        "42",
        "--force",
        "--timeout-ms",
        "250",
        "--json",
    ])?;
    match cli.command {
        Some(Command::Stop(command)) => {
            assert_eq!(
                command.state_dir,
                Some(PathBuf::from("/tmp/tabbymew-state"))
            );
            assert_eq!(command.pid, Some(42));
            assert!(command.force);
            assert_eq!(command.timeout_ms, 250);
            assert!(command.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from(["TabbyMew", "check", "--json"])?;
    match cli.command {
        Some(Command::Check(command)) => assert!(command.json),
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from(["TabbyMew", "config", "schema"])?;
    match cli.command {
        Some(Command::Config(command)) => {
            assert!(matches!(command.command, ConfigSubcommand::Schema));
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "TabbyMew",
        "logs",
        "--state-dir",
        "/tmp/tabbymew-state",
        "--lines",
        "10",
        "--follow",
        "--json",
    ])?;
    match cli.command {
        Some(Command::Logs(command)) => {
            assert_eq!(
                command.state_dir,
                Some(PathBuf::from("/tmp/tabbymew-state"))
            );
            assert_eq!(command.lines, 10);
            assert!(command.follow);
            assert!(command.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "TabbyMew",
        "subscription",
        "import-file",
        "main",
        "examples/subscription-links.txt",
        "--state-dir",
        "/tmp/tabbymew-state",
        "--inbound-tag",
        "hybrid",
        "--listen",
        "0.0.0.0",
        "--listen-port",
        "17891",
        "--json",
    ])?;
    match cli.command {
        Some(Command::Subscription(command)) => match command.command {
            SubscriptionSubcommand::ImportFile(command) => {
                assert_eq!(command.name, "main");
                assert_eq!(
                    command.input,
                    PathBuf::from("examples/subscription-links.txt")
                );
                assert_eq!(
                    command.state_dir,
                    Some(PathBuf::from("/tmp/tabbymew-state"))
                );
                assert_eq!(command.inbound_tag, "hybrid");
                assert_eq!(command.listen.as_deref(), Some("0.0.0.0"));
                assert_eq!(command.listen_port, Some(17891));
                assert!(command.json);
            }
            other => panic!("unexpected subscription command: {other:?}"),
        },
        other => panic!("unexpected command: {other:?}"),
    }

    assert!(Cli::try_parse_from(["TabbyMew", "import"]).is_err());

    Ok(())
}

#[test]
fn cli_json_reports_keep_agent_fields() -> Result<()> {
    let config: Config = serde_json::from_str(&Config::default_local_json()?)?;
    let check = check_json_report(Path::new("config.json"), &config);
    assert_eq!(check.schema_version, CLI_JSON_SCHEMA_VERSION);
    assert!(check.ok);
    assert_eq!(check.status, "ok");
    assert_eq!(check.config, PathBuf::from("config.json"));
    assert!(!check.summary.is_empty());

    let state = ProcessState {
        pid: 42,
        config: PathBuf::from("config.json"),
        log: PathBuf::from("tabbymew.log"),
        listen: Some("127.0.0.1:9090".to_string()),
        control_token: None,
        started_at_unix: 10,
        heartbeat_at_unix: Some(11),
    };
    let start = start_json_report(
        &state,
        Path::new("state"),
        Path::new("state/tabbymew-state.json"),
        vec!["cleanup warning".to_string()],
    );
    assert_eq!(start.schema_version, CLI_JSON_SCHEMA_VERSION);
    assert_eq!(start.status, "started");
    assert_eq!(start.pid, 42);
    assert_eq!(start.warnings, vec!["cleanup warning"]);
    assert_eq!(
        start
            .control_api
            .as_ref()
            .map(|control_api| control_api.url.as_str()),
        Some("http://127.0.0.1:9090")
    );

    let stop = stop_json_report(StopJsonReportInput {
        ok: true,
        status: "stopped",
        message: "stopped TabbyMew pid 42".to_string(),
        pid: Some(42),
        state_dir: Path::new("state"),
        state_file: Path::new("state/tabbymew-state.json"),
        log_file: Some(Path::new("tabbymew.log")),
        removed_state_file: true,
        terminated: true,
    });
    assert_eq!(stop.schema_version, CLI_JSON_SCHEMA_VERSION);
    assert!(stop.ok);
    assert_eq!(stop.status, "stopped");
    assert!(stop.removed_state_file);
    assert!(stop.terminated);

    let logs = logs_json_report(Path::new("tabbymew.log"), 10, "one\ntwo\n".to_string());
    assert_eq!(logs.schema_version, CLI_JSON_SCHEMA_VERSION);
    assert_eq!(logs.status, "ok");
    assert_eq!(logs.lines, 10);
    assert_eq!(logs.line_count, 2);

    Ok(())
}
