use super::*;

fn base_config() -> Config {
    Config {
        schema_version: crate::config::CONFIG_SCHEMA_VERSION,
        log: None,
        dns: None,
        inbounds: vec![InboundConfig::Hybrid {
            tag: "hybrid-in".to_string(),
            listen: default_listen(),
            listen_port: 7890,
            username: None,
            password: None,
        }],
        outbounds: vec![OutboundConfig::Direct {
            tag: "direct".to_string(),
        }],
        policy_groups: Vec::new(),
        route: RouteConfig::default(),
        services: None,
    }
}

fn assert_config_error(config: Config, expected: &str) {
    let err = config.validate().unwrap_err();
    assert!(
        err.to_string().contains(expected),
        "expected validation error containing {expected:?}, got {err:#}"
    );
}

fn route_rule(outbound: &str) -> RouteRuleConfig {
    RouteRuleConfig {
        inbound: Vec::new(),
        network: Vec::new(),
        domain: Vec::new(),
        domain_set: Vec::new(),
        domain_suffix: Vec::new(),
        domain_suffix_set: Vec::new(),
        domain_keyword: Vec::new(),
        domain_keyword_set: Vec::new(),
        ip_cidr: Vec::new(),
        process_name: Vec::new(),
        geoip: Vec::new(),
        ip_cidr_set: Vec::new(),
        port: Vec::new(),
        port_range: Vec::new(),
        outbound: outbound.to_string(),
    }
}

#[test]
fn rejects_invalid_route_settings() {
    let mut config = base_config();
    config.route.rules.push(route_rule("direct"));
    assert_config_error(config, "route rule needs at least one match condition");

    let mut config = base_config();
    let mut rule = route_rule("direct");
    rule.inbound = vec!["missing-in".to_string()];
    config.route.rules.push(rule);
    assert_config_error(config, "route rule inbound missing-in is not defined");

    let mut config = base_config();
    let mut rule = route_rule("direct");
    rule.domain_suffix = vec![".".to_string()];
    config.route.rules.push(rule);
    assert_config_error(config, "route rule domain_suffix contains an empty value");

    let mut config = base_config();
    let mut rule = route_rule("direct");
    rule.ip_cidr = vec!["192.0.2.0/33".to_string()];
    config.route.rules.push(rule);
    assert_config_error(config, "route rule ip_cidr");

    let mut config = base_config();
    let mut rule = route_rule("direct");
    rule.port = vec![0];
    config.route.rules.push(rule);
    assert_config_error(config, "route rule port must be greater");

    let mut config = base_config();
    let mut rule = route_rule("direct");
    rule.port_range = vec!["2000-1000".to_string()];
    config.route.rules.push(rule);
    assert_config_error(config, "route rule port_range");

    let mut config = base_config();
    config.route.resolve_ip_cidr = true;
    assert_config_error(config, "route resolve_ip_cidr requires dns.servers");
}

#[test]
fn rejects_invalid_inbound_listen_address() {
    let mut config = base_config();
    config.inbounds = vec![InboundConfig::Hybrid {
        tag: "hybrid-in".to_string(),
        listen: "localhost".to_string(),
        listen_port: 7890,
        username: None,
        password: None,
    }];

    let err = config.validate().unwrap_err();

    assert!(
        err.to_string()
            .contains("inbound hybrid-in listen address is invalid")
    );
}

#[test]
fn accepts_ipv6_inbound_listen_address() {
    let mut config = base_config();
    config.inbounds = vec![InboundConfig::Hybrid {
        tag: "hybrid-in".to_string(),
        listen: "::1".to_string(),
        listen_port: 7890,
        username: None,
        password: None,
    }];

    config.validate().unwrap();
}

#[test]
fn rejects_zero_ports() {
    let mut config = base_config();
    config.outbounds = vec![OutboundConfig::Http {
        tag: "http-out".to_string(),
        server: "example.com".to_string(),
        server_port: 0,
        username: None,
        password: None,
    }];
    config.route.final_outbound = "http-out".to_string();

    let err = config.validate().unwrap_err();

    assert!(
        err.to_string()
            .contains("outbound http-out server_port must be greater than 0")
    );
}

#[test]
fn rejects_partial_outbound_auth() {
    for (outbound, final_outbound, expected) in [
        (
            OutboundConfig::Socks {
                tag: "socks-out".to_string(),
                server: "example.com".to_string(),
                server_port: 1080,
                username: Some("user".to_string()),
                password: None,
            },
            "socks-out",
            "username and password must be provided together",
        ),
        (
            OutboundConfig::Http {
                tag: "http-out".to_string(),
                server: "example.com".to_string(),
                server_port: 8080,
                username: Some("user".to_string()),
                password: None,
            },
            "http-out",
            "HTTP outbound http-out username and password must be provided together",
        ),
    ] {
        let mut config = base_config();
        config.outbounds = vec![outbound];
        config.route.final_outbound = final_outbound.to_string();

        assert_config_error(config, expected);
    }
}

#[test]
fn rejects_invalid_dns_server() {
    let mut config = base_config();
    config.dns = Some(DnsConfig {
        servers: vec!["dns.example.com".to_string()],
        ..DnsConfig::default()
    });

    let err = config.validate().unwrap_err();

    assert!(err.to_string().contains("must be an IP address"));
}

#[test]
fn rejects_invalid_tls_server_name() {
    let mut config = base_config();
    config.outbounds = vec![OutboundConfig::Trojan {
        tag: "trojan-out".to_string(),
        server: "example.com".to_string(),
        server_port: 443,
        password: "example-password".to_string(),
        tls: TlsClientConfig {
            server_name: Some("bad name".to_string()),
            insecure: false,
            alpn: Vec::new(),
        },
    }];
    config.route.final_outbound = "trojan-out".to_string();

    let err = config.validate().unwrap_err();

    assert!(
        err.to_string()
            .contains("outbound trojan-out TLS server_name is invalid")
    );
}

#[test]
fn parses_and_validates_anytls_session_reuse_settings() {
    let config: Config = serde_json::from_str(
        r#"{
  "outbounds": [
    {
      "type": "anytls",
      "tag": "anytls-out",
      "server": "example.com",
      "server_port": 443,
      "password": "example-password",
      "idle_session_check_interval_ms": 2000,
      "idle_session_timeout_ms": 60000,
      "min_idle_session": 2
    }
  ],
  "inbounds": [
    {"type": "hybrid", "tag": "hybrid-in", "listen": "127.0.0.1", "listen_port": 7890}
  ],
  "route": {"final": "anytls-out"}
}"#,
    )
    .unwrap();

    match &config.outbounds[0] {
        OutboundConfig::AnyTls {
            idle_session_check_interval_ms,
            idle_session_timeout_ms,
            min_idle_session,
            ..
        } => {
            assert_eq!(*idle_session_check_interval_ms, 2_000);
            assert_eq!(*idle_session_timeout_ms, 60_000);
            assert_eq!(*min_idle_session, 2);
        }
        other => panic!("expected AnyTLS outbound, got {other:?}"),
    }
    config.validate().unwrap();

    let mut invalid = config.clone();
    if let OutboundConfig::AnyTls {
        idle_session_timeout_ms,
        ..
    } = &mut invalid.outbounds[0]
    {
        *idle_session_timeout_ms = 0;
    }
    assert_config_error(invalid, "idle_session_timeout_ms must be greater than 0");
}

#[test]
fn rejects_duration_strings_in_native_anytls_config() {
    let err = serde_json::from_str::<Config>(
        r#"{
  "outbounds": [
    {
      "type": "anytls",
      "tag": "anytls-out",
      "server": "example.com",
      "server_port": 443,
      "password": "example-password",
      "idle_session_check_interval_ms": "2s"
    }
  ],
  "inbounds": [
    {"type": "hybrid", "tag": "hybrid-in", "listen_port": 7890}
  ],
  "route": {"final": "anytls-out"}
}"#,
    )
    .unwrap_err();

    assert!(err.to_string().contains("invalid type"));
}

#[test]
fn accepts_route_rule_set_refs_without_leaking_paths_in_summary() {
    let mut config = base_config();
    config.route.rule_sets.insert(
        "ads".to_string(),
        RouteRuleSetConfig {
            kind: RouteRuleSetKind::DomainKeyword,
            path: "/Users/example/private/ads.txt".into(),
        },
    );
    config.route.rules.push(RouteRuleConfig {
        inbound: Vec::new(),
        network: Vec::new(),
        domain: Vec::new(),
        domain_set: Vec::new(),
        domain_suffix: Vec::new(),
        domain_suffix_set: Vec::new(),
        domain_keyword: Vec::new(),
        domain_keyword_set: vec!["ads".to_string()],
        ip_cidr: Vec::new(),
        process_name: Vec::new(),
        geoip: Vec::new(),
        ip_cidr_set: Vec::new(),
        port: Vec::new(),
        port_range: Vec::new(),
        outbound: "direct".to_string(),
    });

    config.validate().unwrap();
    let summary = config.summary().lines().join("\n");

    assert!(summary.contains("rule_sets=1"));
    assert!(summary.contains("route rule set 0: ads:domain-keyword"));
    assert!(summary.contains("domain_keyword_set=ads -> direct"));
    assert!(!summary.contains("/Users/example"));
}

#[test]
fn rejects_missing_or_wrong_kind_route_rule_set_refs() {
    let mut config = base_config();
    config.route.rules.push(RouteRuleConfig {
        inbound: Vec::new(),
        network: Vec::new(),
        domain: Vec::new(),
        domain_set: vec!["missing".to_string()],
        domain_suffix: Vec::new(),
        domain_suffix_set: Vec::new(),
        domain_keyword: Vec::new(),
        domain_keyword_set: Vec::new(),
        ip_cidr: Vec::new(),
        process_name: Vec::new(),
        geoip: Vec::new(),
        ip_cidr_set: Vec::new(),
        port: Vec::new(),
        port_range: Vec::new(),
        outbound: "direct".to_string(),
    });
    let err = config.validate().unwrap_err();
    assert!(
        err.to_string()
            .contains("route rule domain_set missing is not defined")
    );

    let mut config = base_config();
    config.route.rule_sets.insert(
        "suffixes".to_string(),
        RouteRuleSetConfig {
            kind: RouteRuleSetKind::DomainSuffix,
            path: "suffixes.txt".into(),
        },
    );
    config.route.rules.push(RouteRuleConfig {
        inbound: Vec::new(),
        network: Vec::new(),
        domain: Vec::new(),
        domain_set: vec!["suffixes".to_string()],
        domain_suffix: Vec::new(),
        domain_suffix_set: Vec::new(),
        domain_keyword: Vec::new(),
        domain_keyword_set: Vec::new(),
        ip_cidr: Vec::new(),
        process_name: Vec::new(),
        geoip: Vec::new(),
        ip_cidr_set: Vec::new(),
        port: Vec::new(),
        port_range: Vec::new(),
        outbound: "direct".to_string(),
    });
    let err = config.validate().unwrap_err();
    assert!(
        err.to_string()
            .contains("route rule domain_set suffixes references a domain-suffix rule set")
    );
}

#[test]
fn parses_route_single_value_fields() {
    let config: Config = serde_json::from_str(
        r#"{
  "inbounds": [
    {"type": "hybrid", "tag": "hybrid-in", "listen_port": 7890}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "final": "direct",
    "rules": [
      {
        "inbound": "hybrid-in",
        "network": "tcp",
        "domain": "example.com",
        "domain_suffix": "example.org",
        "domain_keyword": "tracker",
        "ip_cidr": "10.0.0.0/8",
        "port": 443,
        "port_range": "1000-2000",
        "outbound": "direct"
      }
    ]
  }
}"#,
    )
    .unwrap();

    let rule = &config.route.rules[0];
    assert_eq!(rule.inbound, vec!["hybrid-in".to_string()]);
    assert_eq!(rule.network, vec![RouteNetwork::Tcp]);
    assert_eq!(rule.domain, vec!["example.com".to_string()]);
    assert_eq!(rule.domain_suffix, vec!["example.org".to_string()]);
    assert_eq!(rule.domain_keyword, vec!["tracker".to_string()]);
    assert_eq!(rule.ip_cidr, vec!["10.0.0.0/8".to_string()]);
    assert_eq!(rule.port, vec![443]);
    assert_eq!(rule.port_range, vec!["1000-2000".to_string()]);
    config.validate().unwrap();
}

#[test]
fn accepts_select_policy_group_route_targets() {
    let mut config = base_config();
    config.outbounds.push(OutboundConfig::Block {
        tag: "block".to_string(),
    });
    config.policy_groups.push(PolicyGroupConfig {
        kind: PolicyGroupKind::Select,
        tag: "Proxy".to_string(),
        outbounds: vec!["direct".to_string(), "block".to_string()],
        default: Some("direct".to_string()),
    });
    config.route.final_outbound = "Proxy".to_string();
    config.route.rules.push(RouteRuleConfig {
        domain_suffix: vec!["ads.example".to_string()],
        outbound: "Proxy".to_string(),
        ..RouteRuleConfig {
            inbound: Vec::new(),
            network: Vec::new(),
            domain: Vec::new(),
            domain_set: Vec::new(),
            domain_suffix: Vec::new(),
            domain_suffix_set: Vec::new(),
            domain_keyword: Vec::new(),
            domain_keyword_set: Vec::new(),
            ip_cidr: Vec::new(),
            process_name: Vec::new(),
            geoip: Vec::new(),
            ip_cidr_set: Vec::new(),
            port: Vec::new(),
            port_range: Vec::new(),
            outbound: "direct".to_string(),
        }
    });

    config.validate().unwrap();
    assert!(
        config
            .summary()
            .policy_groups
            .contains(&"select:Proxy [direct|block] default=direct".to_string())
    );
}

#[test]
fn rejects_unknown_native_config_fields() {
    let err = serde_json::from_str::<Config>(
        r#"{
  "schema_version": 1,
  "inbounds": [
    {"type": "hybrid", "tag": "hybrid-in", "listen_port": 7890}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final": "direct", "rules": []}
}"#,
    )
    .unwrap();
    assert_config_error(err, "unsupported config schema_version 1");

    let err = serde_json::from_str::<Config>(
        r#"{
  "inbounds": [
    {"type": "hybrid", "tag": "hybrid-in", "listen_port": 7890}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final": "direct", "rules": []},
  "unknown_top_level": true
}"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("unknown field"));
    assert!(err.to_string().contains("unknown_top_level"));

    let err = serde_json::from_str::<Config>(
        r#"{
  "inbounds": [
    {"type": "hybrid", "tag": "hybrid-in", "listen_port": 7890, "extra": true}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final": "direct", "rules": []}
}"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("unknown field"));
    assert!(err.to_string().contains("extra"));

    let err = serde_json::from_str::<Config>(
        r#"{
  "inbounds": [
    {"type": "hybrid", "tag": "hybrid-in", "listen_port": 7890}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final_outbound": "direct", "rules": []}
}"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("unknown field"));
    assert!(err.to_string().contains("final_outbound"));

    let err = serde_json::from_str::<Config>(
        r#"{
  "inbounds": [
    {"type": "hybrid", "tag": "hybrid-in", "listen_port": 7890}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ],
  "dns": {"nameservers": ["1.1.1.1"]},
  "route": {"final": "direct", "rules": []}
}"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("unknown field"));
    assert!(err.to_string().contains("nameservers"));
}

#[test]
fn rejects_clash_style_policy_group_aliases_in_native_config() {
    let err = serde_json::from_str::<Config>(
        r#"{
  "inbounds": [
    {"type": "hybrid", "tag": "hybrid-in", "listen_port": 7890}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ],
  "policy-groups": [
    {"type": "select", "name": "Proxy", "proxies": "direct"}
  ],
  "route": {"final": "Proxy", "rules": []}
}"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("unknown field"));
    assert!(err.to_string().contains("policy-groups"));

    let err = serde_json::from_str::<Config>(
        r#"{
  "inbounds": [
    {"type": "hybrid", "tag": "hybrid-in", "listen_port": 7890}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ],
  "policy_groups": [
    {"type": "select", "name": "Proxy", "proxies": "direct"}
  ],
  "route": {"final": "Proxy", "rules": []}
}"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("unknown field"));
    assert!(err.to_string().contains("name"));
}

#[test]
fn rejects_policy_group_cycles() {
    let mut config = base_config();
    config.policy_groups = vec![
        PolicyGroupConfig {
            kind: PolicyGroupKind::Select,
            tag: "A".to_string(),
            outbounds: vec!["B".to_string()],
            default: None,
        },
        PolicyGroupConfig {
            kind: PolicyGroupKind::Select,
            tag: "B".to_string(),
            outbounds: vec!["A".to_string()],
            default: None,
        },
    ];
    config.route.final_outbound = "A".to_string();

    let err = config.validate().unwrap_err();

    assert!(err.to_string().contains("policy group cycle"));
}

#[test]
fn rejects_null_route_list_fields() {
    let err = serde_json::from_str::<Config>(
        r#"{
  "inbounds": [
    {"type": "hybrid", "tag": "hybrid-in", "listen_port": 7890}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "final": "direct",
    "rules": [
      {
        "domain": null,
        "outbound": "direct"
      }
    ]
  }
}"#,
    )
    .unwrap_err();

    assert!(err.to_string().contains("data did not match any variant"));
}

#[test]
fn default_local_config_uses_non_clash_proxy_port() {
    let config: Config = serde_json::from_str(&Config::default_local_json().unwrap()).unwrap();

    assert_eq!(config.inbounds.len(), 2);
    match &config.inbounds[0] {
        InboundConfig::Hybrid {
            tag,
            listen,
            listen_port,
            ..
        } => {
            assert_eq!(tag, "hybrid-in");
            assert_eq!(listen, "127.0.0.1");
            assert_eq!(*listen_port, 17890);
        }
        other => panic!("unexpected default inbound: {other:?}"),
    }
    match &config.inbounds[1] {
        InboundConfig::Tun {
            tag,
            interface_name,
            auto_route,
            ipv6_enabled,
            dns,
            bypass,
            ..
        } => {
            assert_eq!(tag, "tun-in");
            assert_eq!(interface_name, &None);
            assert!(*auto_route);
            assert!(!*ipv6_enabled);
            assert_eq!(*dns, TunDnsMode::Virtual);
            assert!(bypass.iter().any(|cidr| cidr == "127.0.0.0/8"));
        }
        other => panic!("unexpected default TUN inbound: {other:?}"),
    }
    assert_eq!(Config::default_local_inbound_tag(), "hybrid-in");
    assert_eq!(Config::default_local_listen(), "127.0.0.1");
    assert_eq!(Config::default_local_listen_port(), 17890);
    config.validate().unwrap();
    crate::inbound::validate_configs(&config.inbounds).unwrap();
}

#[test]
fn ensure_default_tun_inbound_adds_missing_tun() {
    let mut config = base_config();

    assert!(config.ensure_default_tun_inbound());
    assert_eq!(config.inbounds.len(), 2);
    assert!(matches!(
        &config.inbounds[1],
        InboundConfig::Tun {
            tag,
            auto_route: true,
            dns: TunDnsMode::Virtual,
            ..
        } if tag == "tun-in"
    ));
    config.validate().unwrap();
}

#[test]
fn rejects_invalid_tun_bypass_cidr() {
    let mut config = base_config();
    config.inbounds.push(InboundConfig::Tun {
        tag: "tun-in".to_string(),
        interface_name: None,
        mtu: default_tun_mtu(),
        auto_route: true,
        ipv6_enabled: false,
        dns: TunDnsMode::Virtual,
        dns_addr: None,
        bypass: vec!["not-a-cidr".to_string()],
        tcp_timeout_seconds: None,
        udp_timeout_seconds: None,
        max_sessions: None,
    });

    let err = config.validate().unwrap_err();

    assert!(
        err.to_string()
            .contains("TUN inbound tun-in bypass CIDR not-a-cidr is invalid")
    );
}

#[test]
fn rejects_invalid_tun_numeric_limits() {
    for (tcp_timeout_seconds, udp_timeout_seconds, max_sessions, expected) in [
        (
            Some(0),
            None,
            None,
            "tcp_timeout_seconds must be greater than 0",
        ),
        (
            None,
            Some(0),
            None,
            "udp_timeout_seconds must be greater than 0",
        ),
        (None, None, Some(0), "max_sessions must be greater than 0"),
    ] {
        let mut config = base_config();
        config.inbounds.push(InboundConfig::Tun {
            tag: "tun-in".to_string(),
            interface_name: None,
            mtu: default_tun_mtu(),
            auto_route: true,
            ipv6_enabled: false,
            dns: TunDnsMode::Virtual,
            dns_addr: None,
            bypass: Vec::new(),
            tcp_timeout_seconds,
            udp_timeout_seconds,
            max_sessions,
        });

        assert_config_error(config, expected);
    }
}

#[test]
fn config_load_only_accepts_json() {
    let path = temp_config_path("tabbymew-config-toml-test", "config.toml");
    std::fs::write(
        &path,
        r#"
[[inbounds]]
type = "hybrid"
tag = "hybrid-in"
listen_port = 7890

[[outbounds]]
type = "direct"
tag = "direct"
"#,
    )
    .unwrap();

    let err = Config::load(&path).unwrap_err();

    assert!(err.to_string().contains("failed to parse JSON config"));
}

#[test]
fn exposes_machine_readable_config_schema() {
    let schema = config_schema_value();

    assert_eq!(schema["schema_version"], CONFIG_SCHEMA_VERSION);
    assert_eq!(schema["format"], "json");
    assert_eq!(schema["strict_unknown_fields"], true);
    assert!(
        schema["native_config"]["route_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "final")
    );
    assert!(
        schema["unit_fields"]["seconds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "inbounds[].tcp_timeout_seconds")
    );

    let text = config_schema_json().unwrap();
    assert!(text.contains("\"schema_version\""));
    assert!(text.contains("\"policy_groups\""));
}

fn temp_config_path(prefix: &str, file_name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(file_name)
}

#[test]
fn ensure_default_tun_inbound_keeps_existing_tun_and_avoids_tag_collision() {
    let mut config = base_config();
    config.inbounds[0] = InboundConfig::Hybrid {
        tag: "tun-in".to_string(),
        listen: "127.0.0.1".to_string(),
        listen_port: 7890,
        username: None,
        password: None,
    };

    assert!(config.ensure_default_tun_inbound());
    assert!(matches!(
        &config.inbounds[1],
        InboundConfig::Tun { tag, .. } if tag == "tun-auto-in"
    ));
    assert!(!config.ensure_default_tun_inbound());
    assert_eq!(config.inbounds.len(), 2);
    config.validate().unwrap();
}

#[test]
fn summary_describes_config_without_secrets() {
    let config: Config = serde_json::from_str(
        r#"{
  "log": {"level": "debug"},
  "dns": {"servers": ["1.1.1.1", "8.8.8.8:53"]},
  "inbounds": [
    {
      "type": "hybrid",
      "tag": "hybrid-in",
      "listen": "127.0.0.1",
      "listen_port": 7890,
      "username": "user",
      "password": "example-inbound-password"
    }
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"},
    {
      "type": "http",
      "tag": "http-out",
      "server": "127.0.0.1",
      "server_port": 8080,
      "username": "proxy-user",
      "password": "example-outbound-password"
    }
  ],
  "route": {
    "final": "direct",
    "resolve_ip_cidr": true,
    "rules": [
      {
        "network": "tcp",
        "domain_suffix": ["example.com"],
        "port": [443],
        "outbound": "block"
      }
    ]
  },
  "services": {
    "control_api": {"listen": "127.0.0.1:9090"}
  }
}"#,
    )
    .unwrap();

    let summary = config.summary();
    let lines = summary.lines();
    let text = lines.join("\n");

    assert_eq!(summary.log_level, "debug");
    assert_eq!(summary.dns, "servers=2, timeout=3000ms");
    assert!(summary.route_resolve_ip_cidr);
    assert!(text.contains("hybrid:hybrid-in@127.0.0.1:7890 auth=on"));
    assert!(text.contains("http:http-out@127.0.0.1:8080 auth=on"));
    assert!(text.contains("route: final=direct, rules=1, rule_sets=0, resolve_ip_cidr=true"));
    assert!(
        text.contains("route rule 0: network=tcp; domain_suffix=example.com; port=443 -> block")
    );
    assert!(text.contains("services: control_api=127.0.0.1:9090"));
    assert!(!text.contains("example-inbound-password"));
    assert!(!text.contains("example-outbound-password"));
}

#[test]
fn rejects_invalid_control_api_listen_address() {
    let mut config = base_config();
    config.services = Some(ServicesConfig {
        control_api: Some(ControlApiConfig {
            listen: "localhost:9090".to_string(),
        }),
    });

    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("control_api listen"));

    let mut config = base_config();
    config.services = Some(ServicesConfig {
        control_api: Some(ControlApiConfig {
            listen: "127.0.0.1:0".to_string(),
        }),
    });

    let err = config.validate().unwrap_err();
    assert!(
        err.to_string()
            .contains("control_api listen port must be greater than 0")
    );

    let mut config = base_config();
    config.services = Some(ServicesConfig {
        control_api: Some(ControlApiConfig {
            listen: "0.0.0.0:9090".to_string(),
        }),
    });

    let err = config.validate().unwrap_err();
    assert!(
        err.to_string()
            .contains("control_api listen address must be loopback")
    );
}
