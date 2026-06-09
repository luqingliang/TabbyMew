#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{
            ConfigSummary, InboundConfig, OutboundConfig, PolicyGroupConfig, PolicyGroupKind,
            RouteConfig, RouteRuleConfig,
        },
        net::address::{Address, Destination},
        router::{RouteMode, Router},
        session::Session,
    };
    use serde_json::Value;

    fn summary() -> ConfigSummary {
        ConfigSummary {
            log_level: "info".to_string(),
            dns: "disabled".to_string(),
            inbounds: vec!["hybrid:hybrid-in@127.0.0.1:7890 auth=on".to_string()],
            outbounds: vec!["http:http-out@127.0.0.1:8080 auth=on".to_string()],
            policy_groups: Vec::new(),
            route_final: "http-out".to_string(),
            route_rule_sets: vec!["private:ip-cidr".to_string()],
            route_resolve_ip_cidr: false,
            route_rules: vec!["domain_keyword_set=ads -> block".to_string()],
            services: vec!["control_api=127.0.0.1:9090".to_string()],
        }
    }

    #[tokio::test]
    async fn api_serves_read_only_json_without_secrets() -> Result<()> {
        let metrics = Arc::new(RuntimeMetrics::new());
        metrics.record_route(
            &Session::tcp(
                "hybrid-in",
                None,
                Destination::new(Address::Domain("example.com".to_string()), 443),
            ),
            "http-out",
        );
        metrics.record_proxied_upload(123);
        metrics.record_proxied_download(456);
        let state = ControlState::new(summary(), metrics);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(serve_listener(listener, state));

        let health = request_json(addr, "/health").await?;
        assert_eq!(health["ok"], true);
        assert_eq!(health["service"], "TabbyMew");

        let config = request_json(addr, "/config").await?;
        assert_eq!(config["route"]["final_outbound"], "http-out");
        assert_eq!(config["route"]["rule_sets"][0], "private:ip-cidr");
        assert_eq!(config["route"]["rule_items"][0]["source"], "subscription");
        let config_text = config.to_string();
        assert!(!config_text.contains("secret"));
        assert!(!config_text.contains("password"));

        let counters = request_json(addr, "/counters").await?;
        assert_eq!(counters["route_selections_total"], 1);
        assert_eq!(counters["route_selections_tcp"], 1);
        assert_eq!(counters["route_selections_by_inbound"]["hybrid-in"], 1);
        assert_eq!(counters["route_selections_by_outbound"]["http-out"], 1);
        assert_eq!(counters["proxied_upload_bytes"], 123);
        assert_eq!(counters["proxied_download_bytes"], 456);
        assert_eq!(counters["proxied_total_bytes"], 579);

        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn control_api_serves_runtime_status_and_logs() -> Result<()> {
        let metrics = Arc::new(RuntimeMetrics::new());
        let log_file = std::env::temp_dir().join(format!(
            "tabbymew-control-api-test-{}-{}.log",
            std::process::id(),
            csrf_token()
        ));
        std::fs::write(&log_file, "first\nsecond\n")?;
        let control_api = ControlApiState {
            log_file: Some(log_file.clone()),
            token: "test-token".to_string(),
            ..ControlApiState::default()
        };
        let state = ControlState::with_control_api(
            summary(),
            metrics,
            control_api,
            Arc::new(Notify::new()),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(serve_listener(listener, state));

        let status = request_json(addr, "/control/api/status").await?;
        assert_eq!(status["health"]["ok"], true);
        assert_eq!(status["process"]["can_read_logs"], true);
        assert!(status["system_proxy"]["platform"].as_str().is_some());
        assert!(status["system_proxy"]["supported"].as_bool().is_some());
        assert!(status["system_proxy"]["target"]["http"].is_null());
        assert!(status["system_proxy"]["target"]["https"].is_null());
        assert_eq!(
            status["system_proxy"]["target"]["socks"]["address"],
            "127.0.0.1:7890"
        );

        let system_proxy = request_json(addr, "/control/api/system-proxy").await?;
        assert!(system_proxy["supported"].as_bool().is_some());
        assert!(system_proxy["target"]["http"].is_null());
        assert_eq!(
            system_proxy["target"]["socks"]["address"],
            "127.0.0.1:7890"
        );

        let logs = request_json(addr, "/control/api/logs?lines=1").await?;
        assert_eq!(logs["available"], true);
        let log_file_text = log_file.display().to_string();
        assert_eq!(logs["log_file"].as_str(), Some(log_file_text.as_str()));
        assert_eq!(logs["content"], "second\n");

        std::fs::remove_file(&log_file)?;
        let missing_logs = request_json(addr, "/control/api/logs?lines=1").await?;
        assert_eq!(missing_logs["available"], false);
        assert_eq!(missing_logs["content"], "");
        assert!(
            missing_logs["error"]
                .as_str()
                .is_some_and(|error| error.contains("failed to read log file"))
        );

        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn control_api_post_requires_token_and_can_stop() -> Result<()> {
        let notify = Arc::new(Notify::new());
        let control_api = ControlApiState {
            token: "test-token".to_string(),
            ..ControlApiState::default()
        };
        let state = ControlState::with_control_api(
            summary(),
            Arc::new(RuntimeMetrics::new()),
            control_api,
            notify.clone(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(serve_listener(listener, state));

        let forbidden = request_raw(
            addr,
            "POST /control/api/stop HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n",
        )
        .await?;
        assert!(forbidden.starts_with("HTTP/1.1 403 Forbidden"));

        let notified = notify.notified();
        let accepted = request_raw(
            addr,
            "POST /control/api/stop HTTP/1.1\r\nHost: test\r\nX-TabbyMew-Control-Token: test-token\r\nContent-Length: 0\r\n\r\n",
        )
        .await?;
        assert!(accepted.starts_with("HTTP/1.1 200 OK"));
        tokio::time::timeout(Duration::from_secs(1), notified).await?;

        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn legacy_console_api_paths_remain_compatible() -> Result<()> {
        let notify = Arc::new(Notify::new());
        let control_api = ControlApiState {
            token: "test-token".to_string(),
            ..ControlApiState::default()
        };
        let state = ControlState::with_control_api(
            summary(),
            Arc::new(RuntimeMetrics::new()),
            control_api,
            notify.clone(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(serve_listener(listener, state));

        let status = request_json(addr, "/console/api/status").await?;
        assert_eq!(status["health"]["ok"], true);

        let notified = notify.notified();
        let accepted = request_raw(
            addr,
            "POST /console/api/stop HTTP/1.1\r\nHost: test\r\nX-TabbyMew-Console-Token: test-token\r\nContent-Length: 0\r\n\r\n",
        )
        .await?;
        assert!(accepted.starts_with("HTTP/1.1 200 OK"));
        tokio::time::timeout(Duration::from_secs(1), notified).await?;

        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn control_api_can_switch_route_mode_and_policy_group() -> Result<()> {
        let route = RouteConfig {
            final_outbound: "Proxy".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::new(),
            rules: vec![RouteRuleConfig {
                domain_suffix: vec!["example.com".to_string()],
                outbound: "direct".to_string(),
                inbound: Vec::new(),
                network: Vec::new(),
                domain: Vec::new(),
                domain_set: Vec::new(),
                domain_suffix_set: Vec::new(),
                domain_keyword: Vec::new(),
                domain_keyword_set: Vec::new(),
                ip_cidr: Vec::new(),
                process_name: Vec::new(),
                geoip: Vec::new(),
                ip_cidr_set: Vec::new(),
                port: Vec::new(),
                port_range: Vec::new(),
            }],
        };
        let groups = vec![PolicyGroupConfig {
            kind: PolicyGroupKind::Select,
            tag: "Proxy".to_string(),
            outbounds: vec!["block".to_string(), "direct".to_string()],
            default: Some("block".to_string()),
        }];
        let router = Router::from_config_with_policy_groups(
            &[
                OutboundConfig::Direct {
                    tag: "direct".to_string(),
                },
                OutboundConfig::Block {
                    tag: "block".to_string(),
                },
            ],
            &groups,
            &route,
        )?;
        let dir = std::env::temp_dir().join(format!(
            "tabbymew-control-api-routing-prefs-test-{}-{}",
            std::process::id(),
            csrf_token()
        ));
        std::fs::create_dir_all(&dir)?;
        let control_api = ControlApiState {
            token: "test-token".to_string(),
            state_file: Some(dir.join("tabbymew-state.json")),
            ..ControlApiState::default()
        };
        let state = ControlState::with_control_api_runtime(
            summary(),
            Arc::new(RuntimeMetrics::new()),
            control_api,
            router.clone(),
            test_proxy_runtime(&router),
            Arc::new(Notify::new()),
            temp_subscription_runtime(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(serve_listener(listener, state));

        let status = request_json(addr, "/control/api/status").await?;
        assert_eq!(status["routing"]["mode"], "rule");
        assert_eq!(status["routing"]["global_outbound"], "Proxy");
        assert!(
            status["routing"]["global_targets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|target| target == "Proxy")
        );
        assert_eq!(status["routing"]["policy_groups"][0]["selected"], "block");

        let mode = request_post_json(
            addr,
            "/control/api/route-mode",
            r#"{"mode":"direct"}"#,
            "test-token",
        )
        .await?;
        assert_eq!(mode["mode"], "direct");
        assert_eq!(router.runtime().snapshot().mode, RouteMode::Direct);

        let group = request_post_json(
            addr,
            "/control/api/policy-groups/select",
            r#"{"group":"Proxy","outbound":"direct"}"#,
            "test-token",
        )
        .await?;
        assert_eq!(group["mode"], "direct");
        assert_eq!(group["policy_groups"][0]["selected"], "direct");
        assert_eq!(router.runtime().snapshot().mode, RouteMode::Direct);

        let global = request_post_json(
            addr,
            "/control/api/global-target",
            r#"{"target":"block"}"#,
            "test-token",
        )
        .await?;
        assert_eq!(global["mode"], "direct");
        assert_eq!(global["global_outbound"], "block");
        assert_eq!(router.runtime().snapshot().mode, RouteMode::Direct);
        assert_eq!(router.runtime().snapshot().global_outbound, "block");

        let global_group = request_post_json(
            addr,
            "/control/api/global-target",
            r#"{"target":"Proxy"}"#,
            "test-token",
        )
        .await?;
        assert_eq!(global_group["global_outbound"], "Proxy");
        let preferences = crate::process_manager::load_preferences(
            crate::process_manager::preferences_path(&dir),
        )?;
        assert_eq!(preferences.route_mode.as_deref(), Some("direct"));
        assert_eq!(preferences.global_outbound.as_deref(), Some("Proxy"));
        assert_eq!(
            preferences
                .policy_group_selections
                .get("Proxy")
                .map(String::as_str),
            Some("direct")
        );

        task.abort();
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn control_api_can_toggle_lan_proxy_and_persist_preference() -> Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "tabbymew-lan-proxy-test-{}-{}",
            std::process::id(),
            csrf_token()
        ));
        std::fs::create_dir_all(&dir)?;
        let reserved = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_port = reserved.local_addr()?.port();
        drop(reserved);
        let config_path = dir.join("config.json");
        let config = Config {
            schema_version: crate::config::CONFIG_SCHEMA_VERSION,
            log: None,
            dns: None,
            inbounds: vec![InboundConfig::Hybrid {
                tag: "hybrid-in".to_string(),
                listen: "127.0.0.1".to_string(),
                listen_port: proxy_port,
                username: None,
                password: None,
            }],
            outbounds: vec![OutboundConfig::Direct {
                tag: "direct".to_string(),
            }],
            route: RouteConfig {
                final_outbound: "direct".to_string(),
                resolve_ip_cidr: false,
                rule_sets: BTreeMap::new(),
                rules: Vec::new(),
            },
            policy_groups: Vec::new(),
            services: None,
        };
        std::fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;
        let active = build_active_config_from_config(
            Some(config_path.clone()),
            &config,
            config_base_dir(&config_path),
            Arc::new(RuntimeMetrics::new()),
        )?;
        let router = active.router.clone().unwrap();
        let proxy_runtime = active.proxy_runtime.clone().unwrap();
        proxy_runtime.start().await?;
        let control_api = ControlApiState {
            config_path: Some(config_path),
            token: "test-token".to_string(),
            state_file: Some(dir.join("tabbymew-state.json")),
            state_dir: Some(dir.clone()),
            ..ControlApiState::default()
        };
        let state = ControlState::with_control_api_runtime(
            active.summary.clone(),
            Arc::new(RuntimeMetrics::new()),
            control_api,
            router,
            proxy_runtime.clone(),
            Arc::new(Notify::new()),
            subscription_remote::SubscriptionRuntime::new(&dir),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(serve_listener(listener, state));

        let initial = request_json(addr, "/control/api/status").await?;
        assert_eq!(initial["lan_proxy"]["enabled"], false);
        assert_eq!(initial["lan_proxy"]["available"], true);

        let enabled = request_post_json(
            addr,
            "/control/api/lan-proxy",
            r#"{"enabled":true}"#,
            "test-token",
        )
        .await?;
        assert_eq!(enabled["enabled"], true);
        assert!(proxy_runtime.snapshot().await.enabled);
        assert!(proxy_runtime.snapshot().await.lan_enabled);
        let preferences = crate::process_manager::load_preferences(
            crate::process_manager::preferences_path(&dir),
        )?;
        assert!(preferences.lan_proxy_enabled);

        let disabled = request_post_json(
            addr,
            "/control/api/lan-proxy",
            r#"{"enabled":false}"#,
            "test-token",
        )
        .await?;
        assert_eq!(disabled["enabled"], false);
        assert!(proxy_runtime.snapshot().await.enabled);
        assert!(!proxy_runtime.snapshot().await.lan_enabled);
        let preferences = crate::process_manager::load_preferences(
            crate::process_manager::preferences_path(&dir),
        )?;
        assert!(!preferences.lan_proxy_enabled);

        proxy_runtime.stop_all().await?;
        task.abort();
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn control_api_can_manage_custom_route_rules() -> Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "tabbymew-custom-rules-test-{}-{}",
            std::process::id(),
            csrf_token()
        ));
        std::fs::create_dir_all(&dir)?;
        let reserved = TcpListener::bind("127.0.0.1:0").await?;
        let listen_port = reserved.local_addr()?.port();
        drop(reserved);
        let config_path = subscription_remote::subscription_output_path(&dir, "flower")?;
        let other_config_path = subscription_remote::subscription_output_path(&dir, "other")?;
        let config = Config {
            schema_version: crate::config::CONFIG_SCHEMA_VERSION,
            log: None,
            dns: None,
            inbounds: vec![InboundConfig::Hybrid {
                tag: "hybrid-in".to_string(),
                listen: "127.0.0.1".to_string(),
                listen_port,
                username: None,
                password: None,
            }],
            outbounds: vec![
                OutboundConfig::Direct {
                    tag: "direct".to_string(),
                },
                OutboundConfig::Block {
                    tag: "block".to_string(),
                },
            ],
            route: RouteConfig {
                final_outbound: "direct".to_string(),
                resolve_ip_cidr: false,
                rule_sets: BTreeMap::new(),
                rules: vec![RouteRuleConfig {
                    domain_suffix: vec!["example.com".to_string()],
                    outbound: "direct".to_string(),
                    ..empty_route_rule()
                }],
            },
            policy_groups: Vec::new(),
            services: None,
        };
        let parent = config_path.parent().unwrap();
        std::fs::create_dir_all(parent)?;
        std::fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;
        std::fs::write(&other_config_path, serde_json::to_string_pretty(&config)?)?;

        let active = build_active_config_from_config(
            Some(config_path.clone()),
            &config,
            config_base_dir(&config_path),
            Arc::new(RuntimeMetrics::new()),
        )?;
        let router = active.router.clone().unwrap();
        let proxy_runtime = active.proxy_runtime.clone().unwrap();
        let control_api = ControlApiState {
            config_path: Some(config_path.clone()),
            token: "test-token".to_string(),
            state_file: Some(dir.join("tabbymew-state.json")),
            state_dir: Some(dir.clone()),
            ..ControlApiState::default()
        };
        let state = ControlState::with_control_api_runtime(
            active.summary.clone(),
            Arc::new(RuntimeMetrics::new()),
            control_api,
            router,
            proxy_runtime,
            Arc::new(Notify::new()),
            subscription_remote::SubscriptionRuntime::new(&dir),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(serve_listener(listener, state));

        let initial = request_json(addr, "/control/api/status").await?;
        assert_eq!(initial["rules"]["rule_items"][0]["source"], "subscription");

        let created = request_post_json(
            addr,
            "/control/api/custom-rules/upsert",
            &serde_json::json!({
                "rule": {
                    "domain_suffix": ["example.com"],
                    "outbound": "block"
                }
            })
            .to_string(),
            "test-token",
        )
        .await?;
        let custom = &created["rules"]["rule_items"][0];
        assert_eq!(custom["source"], "custom");
        assert!(custom.get("name").is_none());
        assert_eq!(custom["rule"]["domain_suffix"][0], "example.com");
        assert_eq!(custom["rule"]["outbound"], "block");
        assert!(
            created["config"]["route"]["rule_items"][0]
                .get("rule")
                .is_none()
        );
        assert!(
            custom["summary"]
                .as_str()
                .unwrap()
                .contains("domain_suffix=example.com -> block")
        );
        assert_eq!(created["rules"]["rule_items"][1]["source"], "subscription");
        let tested = request_post_json(
            addr,
            "/control/api/route-test",
            &serde_json::json!({
                "destination": "www.example.com",
                "port": 443,
                "network": "tcp",
                "inbound": "hybrid-in"
            })
            .to_string(),
            "test-token",
        )
        .await?;
        assert_eq!(tested["mode"], "rule");
        assert_eq!(tested["route_target"], "block");
        assert_eq!(tested["outbound"], "block");
        assert_eq!(tested["rule_index"], 0);
        assert_eq!(tested["rule"]["source"], "custom");
        assert_eq!(tested["rule"]["id"], custom["id"]);
        let id = custom["id"].as_str().unwrap();
        let other_active = build_active_config_from_config(
            Some(other_config_path.clone()),
            &config,
            config_base_dir(&other_config_path),
            Arc::new(RuntimeMetrics::new()),
        )?;
        assert_eq!(other_active.custom_route_rules.len(), 0);
        assert_eq!(other_active.summary.route_rules.len(), 1);

        let stored_text = std::fs::read_to_string(custom_route_rules_path_for_state_dir(&dir))?;
        assert!(!stored_text.contains("\"name\""));
        assert!(!std::fs::read_to_string(&config_path)?.contains("\"name\""));

        let edited = request_post_json(
            addr,
            "/control/api/custom-rules/upsert",
            &serde_json::json!({
                "id": id,
                "rule": {
                    "domain_keyword": ["example"],
                    "outbound": "block"
                }
            })
            .to_string(),
            "test-token",
        )
        .await?;
        assert!(edited["rules"]["rule_items"][0].get("name").is_none());
        assert!(
            edited["rules"]["rule_items"][0]["summary"]
                .as_str()
                .unwrap()
                .contains("domain_keyword=example -> block")
        );

        let deleted = request_post_json(
            addr,
            "/control/api/custom-rules/delete",
            &serde_json::json!({ "id": id }).to_string(),
            "test-token",
        )
        .await?;
        assert_eq!(deleted["rules"]["rule_items"][0]["source"], "subscription");
        let reloaded = request_post_json(
            addr,
            "/control/api/rules/reload",
            &serde_json::json!({}).to_string(),
            "test-token",
        )
        .await?;
        assert_eq!(reloaded["rules"]["rule_items"][0]["source"], "subscription");

        task.abort();
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn custom_route_rules_can_use_control_api_state_dir_without_state_file() -> Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "tabbymew-custom-rules-state-dir-test-{}-{}",
            std::process::id(),
            csrf_token()
        ));
        std::fs::create_dir_all(&dir)?;
        let reserved = TcpListener::bind("127.0.0.1:0").await?;
        let listen_port = reserved.local_addr()?.port();
        drop(reserved);
        let config_path = subscription_remote::subscription_output_path(&dir, "flower")?;
        let config = Config {
            schema_version: crate::config::CONFIG_SCHEMA_VERSION,
            log: None,
            dns: None,
            inbounds: vec![InboundConfig::Hybrid {
                tag: "hybrid-in".to_string(),
                listen: "127.0.0.1".to_string(),
                listen_port,
                username: None,
                password: None,
            }],
            outbounds: vec![
                OutboundConfig::Direct {
                    tag: "direct".to_string(),
                },
                OutboundConfig::Block {
                    tag: "block".to_string(),
                },
            ],
            route: RouteConfig {
                final_outbound: "direct".to_string(),
                resolve_ip_cidr: false,
                rule_sets: BTreeMap::new(),
                rules: Vec::new(),
            },
            policy_groups: Vec::new(),
            services: None,
        };
        let parent = config_path.parent().unwrap();
        std::fs::create_dir_all(parent)?;
        std::fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;

        let active = build_active_config_from_config(
            Some(config_path.clone()),
            &config,
            config_base_dir(&config_path),
            Arc::new(RuntimeMetrics::new()),
        )?;
        let router = active.router.clone().unwrap();
        let proxy_runtime = active.proxy_runtime.clone().unwrap();
        let control_api = ControlApiState {
            config_path: Some(config_path),
            token: "test-token".to_string(),
            state_dir: Some(dir.clone()),
            state_file: None,
            ..ControlApiState::default()
        };
        let state = ControlState::with_control_api_runtime(
            active.summary.clone(),
            Arc::new(RuntimeMetrics::new()),
            control_api,
            router,
            proxy_runtime,
            Arc::new(Notify::new()),
            subscription_remote::SubscriptionRuntime::new(&dir),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(serve_listener(listener, state));

        let created = request_post_json(
            addr,
            "/control/api/custom-rules/upsert",
            &serde_json::json!({
                "rule": {
                    "domain": ["api.qiuqiutoken.com"],
                    "outbound": "direct"
                }
            })
            .to_string(),
            "test-token",
        )
        .await?;
        assert_eq!(created["rules"]["rule_items"][0]["source"], "custom");
        assert_eq!(
            created["rules"]["rule_items"][0]["rule"]["domain"][0],
            "api.qiuqiutoken.com"
        );
        assert!(custom_route_rules_path_for_state_dir(&dir).exists());

        task.abort();
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn control_api_can_test_policy_group_delay() -> Result<()> {
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let target_addr = target.local_addr()?;
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /generate_204?test=1 HTTP/1.1"));
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let url = format!("http://{target_addr}/generate_204?test=1");

        let route = RouteConfig {
            final_outbound: "Proxy".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::new(),
            rules: Vec::new(),
        };
        let groups = vec![PolicyGroupConfig {
            kind: PolicyGroupKind::Select,
            tag: "Proxy".to_string(),
            outbounds: vec!["direct".to_string(), "block".to_string()],
            default: Some("direct".to_string()),
        }];
        let router = Router::from_config_with_policy_groups(
            &[
                OutboundConfig::Direct {
                    tag: "direct".to_string(),
                },
                OutboundConfig::Block {
                    tag: "block".to_string(),
                },
            ],
            &groups,
            &route,
        )?;
        let control_api = ControlApiState {
            token: "test-token".to_string(),
            ..ControlApiState::default()
        };
        let state = ControlState::with_control_api_runtime(
            summary(),
            Arc::new(RuntimeMetrics::new()),
            control_api,
            router.clone(),
            test_proxy_runtime(&router),
            Arc::new(Notify::new()),
            temp_subscription_runtime(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(serve_listener(listener, state));

        let delay = request_post_json(
            addr,
            "/control/api/policy-groups/delay",
            &serde_json::json!({
                "group": "Proxy",
                "outbound": "direct",
                "url": url.clone(),
                "timeout_ms": 20_000
            })
            .to_string(),
            "test-token",
        )
        .await?;
        assert_eq!(delay["group"], "Proxy");
        assert_eq!(delay["url"], url);
        assert_eq!(delay["timeout_ms"], 15_000);

        let results = delay["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        let direct = &results[0];
        assert_eq!(direct["outbound"], "direct");
        assert_eq!(direct["resolved_outbound"], "direct");
        assert!(direct["latency_ms"].as_u64().is_some());
        assert_eq!(direct["status_code"], 204);
        assert_eq!(direct["error"], Value::Null);

        let block_delay = request_post_json(
            addr,
            "/control/api/policy-groups/delay",
            &serde_json::json!({
                "group": "Proxy",
                "outbound": "block",
                "url": url
            })
            .to_string(),
            "test-token",
        )
        .await?;
        assert_eq!(block_delay["timeout_ms"], 15_000);
        let block_results = block_delay["results"].as_array().unwrap();
        assert_eq!(block_results.len(), 1);
        let block = &block_results[0];
        assert_eq!(block["outbound"], "block");
        assert_eq!(block["resolved_outbound"], "block");
        assert_eq!(block["latency_ms"], Value::Null);
        assert_eq!(block["status_code"], Value::Null);
        assert!(
            block["error"]
                .as_str()
                .unwrap()
                .contains("blocked connection")
        );

        target_task.await?;
        task.abort();
        Ok(())
    }

    #[test]
    fn control_api_preferences_file_supports_relative_state_file() {
        let control_api = ControlApiState {
            state_file: Some(PathBuf::from("tabbymew-state.json")),
            ..ControlApiState::default()
        };
        let state = ControlState::with_control_api(
            summary(),
            Arc::new(RuntimeMetrics::new()),
            control_api,
            Arc::new(Notify::new()),
        );

        assert_eq!(
            preferences_file(&state),
            Some(PathBuf::from(".").join("tabbymew-preferences.json"))
        );
    }

    #[test]
    fn enabled_system_proxy_target_is_recorded_even_before_status_matches() -> Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "tabbymew-control-system-proxy-record-test-{}-{}",
            std::process::id(),
            csrf_token()
        ));
        let control_api = ControlApiState {
            state_file: Some(dir.join("tabbymew-state.json")),
            ..ControlApiState::default()
        };
        let state = ControlState::with_control_api(
            summary(),
            Arc::new(RuntimeMetrics::new()),
            control_api,
            Arc::new(Notify::new()),
        );
        let target = system_proxy::SystemProxyTarget {
            source: "hybrid:hybrid-in@127.0.0.1:7890 auth=on".to_string(),
            http: Some(system_proxy::SystemProxyEndpoint {
                host: "127.0.0.1".to_string(),
                port: 7890,
                address: "127.0.0.1:7890".to_string(),
            }),
            https: Some(system_proxy::SystemProxyEndpoint {
                host: "127.0.0.1".to_string(),
                port: 7890,
                address: "127.0.0.1:7890".to_string(),
            }),
            socks: Some(system_proxy::SystemProxyEndpoint {
                host: "127.0.0.1".to_string(),
                port: 7890,
                address: "127.0.0.1:7890".to_string(),
            }),
        };
        let status = system_proxy::SystemProxyStatus {
            platform: "macos",
            supported: true,
            enabled: true,
            managed: false,
            matches_target: false,
            target_recorded: false,
            protocol: system_proxy::SystemProxyProtocol::Auto,
            target: Some(target.clone()),
            error: None,
        };

        assert!(persist_enabled_system_proxy_target(&state, &status));

        let preferences = crate::process_manager::load_preferences(
            crate::process_manager::preferences_path(&dir),
        )?;
        assert!(preferences.system_proxy_enabled);
        assert_eq!(preferences.system_proxy_target, Some(target));

        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn runtime_restore_switches_are_persisted() -> Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "tabbymew-control-restore-switch-test-{}-{}",
            std::process::id(),
            csrf_token()
        ));
        let control_api = ControlApiState {
            state_file: Some(dir.join("tabbymew-state.json")),
            ..ControlApiState::default()
        };
        let state = ControlState::with_control_api(
            summary(),
            Arc::new(RuntimeMetrics::new()),
            control_api,
            Arc::new(Notify::new()),
        );

        persist_tun_preference(&state, true);
        persist_system_proxy_enabled_preference(&state, true);
        let preferences = crate::process_manager::load_preferences(
            crate::process_manager::preferences_path(&dir),
        )?;
        assert!(preferences.tun_enabled);
        assert!(preferences.system_proxy_enabled);

        persist_tun_preference(&state, false);
        persist_system_proxy_enabled_preference(&state, false);
        let preferences = crate::process_manager::load_preferences(
            crate::process_manager::preferences_path(&dir),
        )?;
        assert!(!preferences.tun_enabled);
        assert!(!preferences.system_proxy_enabled);

        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[tokio::test]
    async fn control_api_reports_proxy_runtime_without_manual_switch() -> Result<()> {
        let reserved = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_port = reserved.local_addr()?.port();
        drop(reserved);

        let route = RouteConfig {
            final_outbound: "direct".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::new(),
            rules: Vec::new(),
        };
        let router = Router::from_config_with_policy_groups(
            &[OutboundConfig::Direct {
                tag: "direct".to_string(),
            }],
            &[],
            &route,
        )?;
        let proxy_runtime = Arc::new(ProxyRuntime::new(
            vec![InboundConfig::Hybrid {
                tag: "hybrid-in".to_string(),
                listen: "127.0.0.1".to_string(),
                listen_port: proxy_port,
                username: None,
                password: None,
            }],
            router.clone(),
        ));
        proxy_runtime.start().await?;
        let control_api = ControlApiState {
            token: "test-token".to_string(),
            ..ControlApiState::default()
        };
        let state = ControlState::with_control_api_runtime(
            summary(),
            Arc::new(RuntimeMetrics::new()),
            control_api,
            router.clone(),
            proxy_runtime.clone(),
            Arc::new(Notify::new()),
            temp_subscription_runtime(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(serve_listener(listener, state));

        let status = request_json(addr, "/control/api/status").await?;
        assert_eq!(status["proxy"]["enabled"], true);
        assert_eq!(status["proxy"]["tun_enabled"], false);
        assert_eq!(status["proxy"]["tun_status"], "not_configured");
        assert_eq!(
            status["proxy"]["tun_detail"],
            "no TUN inbounds are configured"
        );
        assert_eq!(status["proxy"]["configured_tun_inbounds"], 0);

        let stream = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
        drop(stream);

        let proxy_switch = request_raw(
            addr,
            "POST /control/api/proxy HTTP/1.1\r\nHost: test\r\nX-TabbyMew-Control-Token: test-token\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"enabled\":false}",
        )
        .await?;
        assert!(proxy_switch.starts_with("HTTP/1.1 404 Not Found"));

        let tun_request = "POST /control/api/tun HTTP/1.1\r\nHost: test\r\nX-TabbyMew-Control-Token: test-token\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"enabled\":true}";
        let tun = request_raw(addr, tun_request).await?;
        assert!(tun.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(tun.contains("no TUN inbounds are configured"));

        proxy_runtime.stop_all().await?;
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn control_api_can_manage_remote_subscriptions() -> Result<()> {
        let source = TcpListener::bind("127.0.0.1:0").await?;
        let source_addr = source.local_addr()?;
        let source_task = tokio::spawn(async move {
            let body = include_str!("../../examples/subscription-links.txt");
            for _ in 0..2 {
                let (mut stream, _) = source.accept().await.unwrap();
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    stream.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let dir = std::env::temp_dir().join(format!(
            "tabbymew-control-api-subscription-test-{}-{}",
            std::process::id(),
            csrf_token()
        ));
        std::fs::create_dir_all(&dir)?;
        let output = subscription_remote::subscription_output_path(&dir, "main")?;
        let file_output = subscription_remote::subscription_output_path(&dir, "file")?;
        let control_api = ControlApiState {
            token: "test-token".to_string(),
            state_file: Some(dir.join("tabbymew-state.json")),
            ..ControlApiState::default()
        };
        let route = RouteConfig {
            final_outbound: "direct".to_string(),
            resolve_ip_cidr: false,
            rule_sets: BTreeMap::new(),
            rules: Vec::new(),
        };
        let router = Router::from_config_with_policy_groups(
            &[OutboundConfig::Direct {
                tag: "direct".to_string(),
            }],
            &[],
            &route,
        )?;
        let runtime = subscription_remote::SubscriptionRuntime::new(&dir);
        let state = ControlState::with_control_api_runtime(
            summary(),
            Arc::new(RuntimeMetrics::new()),
            control_api,
            router.clone(),
            test_proxy_runtime(&router),
            Arc::new(Notify::new()),
            runtime,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(serve_listener(listener, state));

        let add = request_post_json(
            addr,
            "/control/api/subscriptions/add",
            &serde_json::json!({
                "name": "main",
                "url": format!("http://{source_addr}/subscription-links.txt?token=example-token"),
                "update_interval_seconds": 60,
                "timeout_ms": 1000,
                "retries": 0
            })
            .to_string(),
            "test-token",
        )
        .await?;
        assert_eq!(add["imported"], 3);
        assert!(output.exists());
        let generated: Value = serde_json::from_str(&std::fs::read_to_string(&output)?)?;
        assert_eq!(generated["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(generated["inbounds"][0]["listen_port"], 17890);
        assert_eq!(generated["inbounds"][1]["type"], "tun");
        assert_eq!(generated["inbounds"][1]["tag"], "tun-in");
        assert_eq!(generated["inbounds"][1]["dns"], "virtual");

        let subscriptions = request_json(addr, "/control/api/subscriptions").await?;
        assert_eq!(subscriptions["subscriptions"][0]["name"], "main");
        assert!(
            subscriptions["subscriptions"][0]["url"]
                .as_str()
                .unwrap()
                .contains("?redacted")
        );
        assert_eq!(
            subscriptions["subscriptions"][0]["update_interval_seconds"],
            subscription_remote::default_update_interval_seconds()
        );
        assert_eq!(
            subscriptions["subscriptions"][0]["timeout_ms"],
            subscription_remote::default_timeout_ms()
        );
        assert_eq!(
            subscriptions["subscriptions"][0]["retries"],
            subscription_remote::default_retries()
        );
        assert_eq!(subscriptions["active"], "main");

        let status = request_json(addr, "/control/api/status").await?;
        assert_eq!(status["subscriptions"]["active"], "main");
        assert_eq!(
            status["process"]["config_path"],
            output.display().to_string()
        );
        assert_eq!(status["config"]["route"]["final_outbound"], "ss-main");
        let preferences = crate::process_manager::load_preferences(
            crate::process_manager::preferences_path(&dir),
        )?;
        assert_eq!(preferences.active_config.as_deref(), Some(output.as_path()));

        let activated = request_post_json(
            addr,
            "/control/api/subscriptions/activate",
            r#"{"name":"main"}"#,
            "test-token",
        )
        .await?;
        assert_eq!(activated["subscriptions"]["active"], "main");
        assert_eq!(
            activated["process"]["config_path"],
            output.display().to_string()
        );
        let preferences = crate::process_manager::load_preferences(
            crate::process_manager::preferences_path(&dir),
        )?;
        assert_eq!(preferences.active_config.as_deref(), Some(output.as_path()));
        assert_eq!(activated["config"]["route"]["final_outbound"], "ss-main");
        assert!(
            activated["outbounds"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item.as_str().unwrap().contains("ss-main"))
        );

        let status = request_json(addr, "/control/api/status").await?;
        assert_eq!(status["subscriptions"]["active"], "main");
        assert_eq!(status["config"]["route"]["final_outbound"], "ss-main");

        let preview = request_json(addr, "/control/api/active-config").await?;
        assert_eq!(preview["subscription"], "main");
        assert_eq!(preview["config_path"], output.display().to_string());
        assert_eq!(preview["redacted"], true);
        assert_eq!(preview["validation_error"], Value::Null);
        let preview_config = preview["config"].as_str().unwrap();
        assert!(preview_config.contains("ss-main"));
        assert!(preview_config.contains("<redacted>"));
        assert!(!preview_config.contains("4b7d3c78-fd7b-45e9-9a53-1b0f5d3c6f28"));

        let set = request_post_json(
            addr,
            "/control/api/subscriptions/set",
            r#"{"name":"main","auto_update":false,"update_interval_seconds":120,"timeout_ms":1,"retries":0}"#,
            "test-token",
        )
        .await?;
        assert_eq!(set["auto_update"], false);
        assert_eq!(
            set["update_interval_seconds"],
            subscription_remote::default_update_interval_seconds()
        );
        assert_eq!(set["timeout_ms"], subscription_remote::default_timeout_ms());
        assert_eq!(set["retries"], subscription_remote::default_retries());

        let refresh = request_post_json(
            addr,
            "/control/api/subscriptions/refresh",
            r#"{"all":true}"#,
            "test-token",
        )
        .await?;
        assert_eq!(refresh[0]["ok"], true);

        let upload_yaml = r#"
proxies:
  - name: file-trojan
    type: trojan
    server: trojan.example.com
    port: 443
    password: example-password
    sni: trojan.example.com
rules:
  - MATCH,file-trojan
"#;
        let upload = request_post_json(
            addr,
            "/control/api/subscriptions/import-file",
            &serde_json::json!({
                "name": "file",
                "filename": "../Flower.yaml",
                "input": upload_yaml
            })
            .to_string(),
            "test-token",
        )
        .await?;
        assert_eq!(upload["source"], "uploaded_file");
        assert_eq!(upload["url"], "uploaded-file:Flower.yaml");
        assert_eq!(upload["imported"], 1);
        assert!(file_output.exists());

        let subscriptions = request_json(addr, "/control/api/subscriptions").await?;
        let file = subscriptions["subscriptions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == "file")
            .unwrap();
        assert_eq!(file["source"], "uploaded_file");
        assert_eq!(file["auto_update"], false);
        assert_eq!(file["next_update_unix"], Value::Null);
        assert_eq!(subscriptions["active"], "main");

        let activated_file = request_post_json(
            addr,
            "/control/api/subscriptions/activate",
            r#"{"name":"file"}"#,
            "test-token",
        )
        .await?;
        assert_eq!(activated_file["subscriptions"]["active"], "file");
        assert_eq!(
            activated_file["process"]["config_path"],
            file_output.display().to_string()
        );
        let preferences = crate::process_manager::load_preferences(
            crate::process_manager::preferences_path(&dir),
        )?;
        assert_eq!(
            preferences.active_config.as_deref(),
            Some(file_output.as_path())
        );
        assert_eq!(
            activated_file["config"]["route"]["final_outbound"],
            "file-trojan"
        );

        let removed = request_post_json(
            addr,
            "/control/api/subscriptions/remove",
            r#"{"name":"main"}"#,
            "test-token",
        )
        .await?;
        assert_eq!(removed["name"], "main");
        let removed_file = request_post_json(
            addr,
            "/control/api/subscriptions/remove",
            r#"{"name":"file"}"#,
            "test-token",
        )
        .await?;
        assert_eq!(removed_file["name"], "file");

        source_task.await?;
        task.abort();
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn bind_rejects_port_conflicts() -> Result<()> {
        let occupied = TcpListener::bind("127.0.0.1:0").await?;
        let addr = occupied.local_addr()?;

        let err = match bind(&addr.to_string()).await {
            Ok(_) => panic!("control_api unexpectedly bound an occupied port"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("failed to bind control_api"));
        Ok(())
    }

    #[test]
    fn parse_listen_rejects_invalid_addresses() {
        assert!(parse_listen("localhost:9090").is_err());
        assert!(parse_listen("127.0.0.1:0").is_err());
        assert!(parse_listen("0.0.0.0:9090").is_err());
        assert!(parse_listen("[::]:9090").is_err());
    }

    #[test]
    fn parse_route_test_destination_accepts_common_target_forms() -> Result<()> {
        let domain = parse_route_test_destination(&RouteTestRequest {
            destination: "example.com".to_string(),
            port: None,
            network: None,
            inbound: None,
        })?;
        assert_eq!(
            domain,
            Destination::new(Address::Domain("example.com".to_string()), 443)
        );

        let url = parse_route_test_destination(&RouteTestRequest {
            destination: "http://example.com/path".to_string(),
            port: None,
            network: None,
            inbound: None,
        })?;
        assert_eq!(
            url,
            Destination::new(Address::Domain("example.com".to_string()), 80)
        );

        let ipv6 = parse_route_test_destination(&RouteTestRequest {
            destination: "2001:db8::1".to_string(),
            port: Some(8443),
            network: None,
            inbound: None,
        })?;
        assert_eq!(
            ipv6,
            Destination::new(Address::Ip("2001:db8::1".parse()?), 8443)
        );
        Ok(())
    }

    async fn request_json(addr: SocketAddr, path: &str) -> Result<Value> {
        let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n\r\n");
        let response = request_raw(addr, &request).await?;
        let (_, body) = response
            .split_once("\r\n\r\n")
            .context("missing response body")?;
        serde_json::from_str(body).context("response body is not JSON")
    }

    fn temp_subscription_runtime() -> subscription_remote::SubscriptionRuntime {
        subscription_remote::SubscriptionRuntime::new(std::env::temp_dir().join(format!(
            "tabbymew-control-subscriptions-test-{}-{}",
            std::process::id(),
            csrf_token()
        )))
    }

    fn test_proxy_runtime(router: &Router) -> Arc<ProxyRuntime> {
        Arc::new(ProxyRuntime::new(
            vec![InboundConfig::Hybrid {
                tag: "hybrid-in".to_string(),
                listen: "127.0.0.1".to_string(),
                listen_port: 0,
                username: None,
                password: None,
            }],
            router.clone(),
        ))
    }

    fn empty_route_rule() -> RouteRuleConfig {
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
            outbound: "direct".to_string(),
        }
    }

    async fn request_post_json(
        addr: SocketAddr,
        path: &str,
        body: &str,
        token: &str,
    ) -> Result<Value> {
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nX-TabbyMew-Control-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = request_raw(addr, &request).await?;
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "unexpected response: {response}"
        );
        let (_, body) = response
            .split_once("\r\n\r\n")
            .context("missing response body")?;
        serde_json::from_str(body).context("response body is not JSON")
    }

    async fn request_raw(addr: SocketAddr, request: &str) -> Result<String> {
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(request.as_bytes()).await?;
        read_response(&mut stream).await
    }

    #[tokio::test]
    async fn api_times_out_incomplete_request_headers() -> Result<()> {
        let metrics = Arc::new(RuntimeMetrics::new());
        let state = ControlState::new(summary(), metrics);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(serve_listener(listener, state));

        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(b"GET /health HTTP/1.1\r\n").await?;
        let response = read_response(&mut stream).await?;

        assert!(response.starts_with("HTTP/1.1 408 Request Timeout"));
        assert!(response.contains(r#""request timeout""#));

        task.abort();
        Ok(())
    }

    async fn read_response(stream: &mut TcpStream) -> Result<String> {
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        String::from_utf8(response).context("response is not valid UTF-8")
    }
}
