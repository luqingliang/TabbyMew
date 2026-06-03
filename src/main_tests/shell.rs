use super::*;

#[test]
fn shell_command_registry_supports_lookup_and_search() {
    assert_eq!(
        find_shell_command("status").map(|command| command.name),
        Some("status")
    );
    assert_eq!(
        find_shell_command("s").map(|command| command.name),
        Some("status")
    );
    assert!(shell_command_matches(
        find_shell_command("doctor").expect("doctor command"),
        "diag"
    ));
    assert_eq!(
        find_shell_command("restart").map(|command| command.name),
        Some("restart")
    );
    assert_eq!(
        find_shell_command("reboot").map(|command| command.name),
        Some("restart")
    );
    assert_eq!(
        find_shell_command("start").map(|command| command.name),
        None
    );
    assert_eq!(find_shell_command("stop").map(|command| command.name), None);
    assert_eq!(
        find_shell_command("tun").map(|command| command.name),
        Some("tun")
    );
    assert_eq!(
        find_shell_command("tun-stop").map(|command| command.name),
        Some("tun-off")
    );
    assert_eq!(
        find_shell_command("system-proxy").map(|command| command.name),
        Some("system-proxy")
    );
    assert_eq!(
        find_shell_command("sp").map(|command| command.name),
        Some("system-proxy")
    );
    assert_eq!(
        find_shell_command("sp-off").map(|command| command.name),
        Some("system-proxy-off")
    );
    assert_eq!(
        find_shell_command("detach").map(|command| command.name),
        Some("detach")
    );
    assert_eq!(
        find_shell_command("q").map(|command| command.name),
        Some("detach")
    );
    assert_eq!(
        find_shell_command("exit-ui").map(|command| command.name),
        Some("detach")
    );
    assert_eq!(
        find_shell_command("quit").map(|command| command.name),
        Some("quit")
    );
    assert_eq!(
        find_shell_command("exit").map(|command| command.name),
        Some("quit")
    );
    assert_eq!(
        find_shell_command("route-mode").map(|command| command.name),
        Some("mode")
    );
    assert_eq!(
        find_shell_command("global-target").map(|command| command.name),
        Some("global")
    );
    assert_eq!(
        find_shell_command("policy-groups").map(|command| command.name),
        Some("groups")
    );
    assert_eq!(
        find_shell_command("route-rules").map(|command| command.name),
        Some("rules")
    );
    assert_eq!(
        find_shell_command("test-rule").map(|command| command.name),
        None
    );
    assert_eq!(find_shell_command("rt").map(|command| command.name), None);
    assert_eq!(
        find_shell_command("proxy-group").map(|command| command.name),
        None
    );
    assert_eq!(
        exact_shell_command("/group").map(|command| command.name),
        None
    );
    assert_eq!(
        exact_shell_command("/tun-on").map(|command| command.name),
        Some("tun-on")
    );
    assert_eq!(
        exact_shell_command("/lan-proxy-on").map(|command| command.name),
        Some("lan-proxy-on")
    );
    assert_eq!(
        exact_shell_command("/system-proxy-on").map(|command| command.name),
        Some("system-proxy-on")
    );
    assert_eq!(
        filtered_shell_commands("/status")
            .first()
            .map(|command| command.name),
        Some("status")
    );
    let tun_commands = filtered_shell_commands("tun");
    assert_eq!(tun_commands.len(), 1);
    assert_eq!(tun_commands[0].name, "tun");
    let system_proxy_commands = filtered_shell_commands("system-proxy");
    assert_eq!(system_proxy_commands.len(), 1);
    assert_eq!(system_proxy_commands[0].name, "system-proxy");
    let lan_proxy_commands = filtered_shell_commands("lan-proxy");
    assert_eq!(lan_proxy_commands.len(), 1);
    assert_eq!(lan_proxy_commands[0].name, "lan-proxy");
    assert_eq!(
        filtered_shell_commands("/mode direct")
            .first()
            .map(|command| command.name),
        Some("mode")
    );
    assert_eq!(
        filtered_shell_commands("global")
            .first()
            .map(|command| command.name),
        Some("global")
    );
    assert_eq!(split_command_query("/mode rule"), ("mode", "rule"));
    assert_eq!(
        parse_tui_route_mode("global").unwrap(),
        router::RouteMode::Global
    );
    assert!(parse_tui_route_mode("global extra").is_err());
    assert_eq!(
        split_command_query("/global Hong Kong Node"),
        ("global", "Hong Kong Node")
    );
    assert_eq!(
        split_command_query("/groups Proxy Japan"),
        ("groups", "Proxy Japan")
    );
    assert!(command_help_text(None).contains("/restart"));
    assert!(command_help_text(None).contains("/mode [rule|global|direct]"));
    assert!(command_help_text(None).contains("/global [target]"));
    assert!(command_help_text(None).contains("/groups [group] [outbound]"));
    assert!(command_help_text(None).contains("/rules [filter|add|remove|reload]"));
    assert!(command_help_text(None).contains("/subscriptions [filter]"));
    assert!(command_help_text(None).contains("/lan-proxy"));
    assert!(command_help_text(None).contains("/system-proxy"));
    assert!(command_help_text(None).contains("/detach"));
    assert!(command_help_text(None).contains("/quit"));
    assert!(!command_help_text(None).contains("/rule-test"));
    assert!(!command_help_text(None).contains("/group <group> [outbound]"));
    assert!(!command_help_text(None).contains("/start"));
    assert!(!command_help_text(None).contains("/stop"));
    assert!(!command_help_text(None).contains("/tun-on"));
    assert!(!command_help_text(None).contains("/tun-off"));
    assert!(!command_help_text(None).contains("/lan-proxy-on"));
    assert!(!command_help_text(None).contains("/lan-proxy-off"));
    assert!(!command_help_text(None).contains("/system-proxy-on"));
    assert!(!command_help_text(None).contains("/system-proxy-off"));
    assert!(command_help_text(Some("diag")).contains("/doctor"));

    let groups = find_shell_command("groups").expect("groups command");
    assert!(!should_record_executed_message(
        groups,
        "",
        TuiMode::PolicyGroupListSelector
    ));
    assert!(!should_record_executed_message(
        groups,
        "Proxy",
        TuiMode::PolicyGroupSelector
    ));
    assert!(should_record_executed_message(
        groups,
        "Proxy Japan",
        TuiMode::Output
    ));

    let rules = find_shell_command("rules").expect("rules command");
    assert!(!should_record_executed_message(
        rules,
        "",
        TuiMode::RouteRules
    ));
    assert!(should_record_executed_message(
        rules,
        "add domain=example.com -> Proxy",
        TuiMode::Output
    ));

    let subscriptions = find_shell_command("subscriptions").expect("subscriptions command");
    assert!(!should_record_executed_message(
        subscriptions,
        "",
        TuiMode::Subscriptions
    ));
}
