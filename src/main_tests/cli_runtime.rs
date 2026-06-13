use super::*;

#[test]
fn parses_cli_rules_commands() -> Result<()> {
    let cli = Cli::try_parse_from([
        "TabbyMew",
        "rules",
        "list",
        "--filter",
        "ads",
        "--listen",
        "127.0.0.1:9090",
        "--timeout-ms",
        "250",
        "--json",
    ])?;
    match cli.command {
        Some(Command::Rules(command)) => match command.command {
            RulesSubcommand::List(command) => {
                assert_eq!(command.filter.as_deref(), Some("ads"));
                assert_eq!(command.control.listen.as_deref(), Some("127.0.0.1:9090"));
                assert_eq!(command.control.timeout_ms, 250);
                assert!(command.json);
            }
            other => panic!("unexpected rules command: {other:?}"),
        },
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "TabbyMew",
        "rules",
        "add",
        "--kind",
        "domain-suffix",
        "--value",
        "example.com",
        "--outbound",
        "Proxy",
        "--state-dir",
        "/tmp/tabbymew-state",
    ])?;
    match cli.command {
        Some(Command::Rules(command)) => match command.command {
            RulesSubcommand::Add(command) => {
                assert_eq!(command.kind, "domain-suffix");
                assert_eq!(command.value, "example.com");
                assert_eq!(command.outbound, "Proxy");
                assert_eq!(
                    command.control.state_dir,
                    Some(PathBuf::from("/tmp/tabbymew-state"))
                );
            }
            other => panic!("unexpected rules command: {other:?}"),
        },
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "TabbyMew",
        "rules",
        "edit",
        "custom-1",
        "--kind",
        "domain",
        "--value",
        "example.org",
        "--outbound",
        "Fallback",
        "--json",
    ])?;
    match cli.command {
        Some(Command::Rules(command)) => match command.command {
            RulesSubcommand::Edit(command) => {
                assert_eq!(command.id, "custom-1");
                assert_eq!(command.upsert.kind, "domain");
                assert_eq!(command.upsert.value, "example.org");
                assert_eq!(command.upsert.outbound, "Fallback");
                assert!(command.upsert.json);
            }
            other => panic!("unexpected rules command: {other:?}"),
        },
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from(["TabbyMew", "rules", "rm", "custom-1"])?;
    match cli.command {
        Some(Command::Rules(command)) => match command.command {
            RulesSubcommand::Remove(command) => assert_eq!(command.id, "custom-1"),
            other => panic!("unexpected rules command: {other:?}"),
        },
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from(["TabbyMew", "rules", "reload", "--json"])?;
    match cli.command {
        Some(Command::Rules(command)) => match command.command {
            RulesSubcommand::Reload(command) => assert!(command.json),
            other => panic!("unexpected rules command: {other:?}"),
        },
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "TabbyMew",
        "rules",
        "route-test",
        "https://example.com",
        "--port",
        "443",
        "--network",
        "tcp",
        "--inbound",
        "cli",
        "--json",
    ])?;
    match cli.command {
        Some(Command::Rules(command)) => match command.command {
            RulesSubcommand::Test(command) => {
                assert_eq!(command.destination, "https://example.com");
                assert_eq!(command.port, Some(443));
                assert_eq!(command.network.as_deref(), Some("tcp"));
                assert_eq!(command.inbound.as_deref(), Some("cli"));
                assert!(command.json);
            }
            other => panic!("unexpected rules command: {other:?}"),
        },
        other => panic!("unexpected command: {other:?}"),
    }

    Ok(())
}

#[test]
fn parses_cli_runtime_commands() -> Result<()> {
    let cli = Cli::try_parse_from([
        "TabbyMew",
        "mode",
        "global",
        "--listen",
        "127.0.0.1:9090",
        "--timeout-ms",
        "250",
        "--json",
    ])?;
    match cli.command {
        Some(Command::Mode(command)) => {
            assert_eq!(command.mode.as_deref(), Some("global"));
            assert_eq!(command.control.listen.as_deref(), Some("127.0.0.1:9090"));
            assert_eq!(command.control.timeout_ms, 250);
            assert!(command.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "TabbyMew",
        "global",
        "Proxy",
        "--state-dir",
        "/tmp/tabbymew-state",
        "--json",
    ])?;
    match cli.command {
        Some(Command::Global(command)) => {
            assert_eq!(command.target.as_deref(), Some("Proxy"));
            assert_eq!(
                command.control.state_dir,
                Some(PathBuf::from("/tmp/tabbymew-state"))
            );
            assert!(command.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from(["TabbyMew", "groups", "Proxy", "Hong Kong", "--json"])?;
    match cli.command {
        Some(Command::Groups(command)) => {
            assert_eq!(command.group.as_deref(), Some("Proxy"));
            assert_eq!(command.outbound.as_deref(), Some("Hong Kong"));
            assert!(command.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from(["TabbyMew", "tun", "toggle", "--json"])?;
    match cli.command {
        Some(Command::Tun(command)) => {
            assert_eq!(command.action.as_deref(), Some("toggle"));
            assert!(command.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from(["TabbyMew", "system-proxy", "off", "--json"])?;
    match cli.command {
        Some(Command::SystemProxy(command)) => {
            assert_eq!(command.action.as_deref(), Some("off"));
            assert!(command.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    assert_eq!(
        parse_cli_switch_action(None, "TUN")?,
        CliSwitchAction::Status
    );
    assert_eq!(
        parse_cli_switch_action(Some("enable"), "TUN")?,
        CliSwitchAction::On
    );
    assert!(parse_cli_switch_action(Some("bad"), "TUN").is_err());
    Ok(())
}

#[test]
fn tun_control_operation_timeout_keeps_authorization_window_open() {
    assert_eq!(
        tun_control_operation_timeout(Duration::from_millis(DEFAULT_CONTROL_TIMEOUT_MS)),
        TUN_CONTROL_OPERATION_TIMEOUT
    );
    assert_eq!(
        tun_control_operation_timeout(Duration::from_secs(180)),
        Duration::from_secs(180)
    );
}

#[test]
fn parses_cli_subscription_json_flags() -> Result<()> {
    let cli = Cli::try_parse_from([
        "TabbyMew",
        "subscription",
        "add",
        "main",
        "https://example.com/sub",
        "--json",
    ])?;
    match cli.command {
        Some(Command::Subscription(command)) => match command.command {
            SubscriptionSubcommand::Add(command) => assert!(command.json),
            other => panic!("unexpected subscription command: {other:?}"),
        },
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from(["TabbyMew", "subscriptions", "update", "--all", "--json"])?;
    match cli.command {
        Some(Command::Subscription(command)) => match command.command {
            SubscriptionSubcommand::Update(command) => {
                assert!(command.all);
                assert!(command.json);
            }
            other => panic!("unexpected subscription command: {other:?}"),
        },
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "TabbyMew",
        "subscription",
        "set",
        "main",
        "--auto-update",
        "--json",
    ])?;
    match cli.command {
        Some(Command::Subscription(command)) => match command.command {
            SubscriptionSubcommand::Set(command) => {
                assert!(command.auto_update);
                assert!(command.json);
            }
            other => panic!("unexpected subscription command: {other:?}"),
        },
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from(["TabbyMew", "subscription", "remove", "main", "--json"])?;
    match cli.command {
        Some(Command::Subscription(command)) => match command.command {
            SubscriptionSubcommand::Remove(command) => assert!(command.json),
            other => panic!("unexpected subscription command: {other:?}"),
        },
        other => panic!("unexpected command: {other:?}"),
    }
    Ok(())
}
