pub fn parse_listen(listen: &str) -> Result<SocketAddr> {
    let addr = listen
        .trim()
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid control_api listen address {listen}"))?;
    if addr.port() == 0 {
        bail!("control_api listen port must be greater than 0");
    }
    if !addr.ip().is_loopback() {
        bail!("control_api listen address must be loopback");
    }
    Ok(addr)
}

pub async fn bind(listen: &str) -> Result<TcpListener> {
    let addr = parse_listen(listen)?;
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind control_api on {addr}"))
}

pub async fn bind_default_control() -> Result<TcpListener> {
    match bind(DEFAULT_CONTROL_LISTEN).await {
        Ok(listener) => Ok(listener),
        Err(err) => {
            debug!(
                error = %err,
                listen = DEFAULT_CONTROL_LISTEN,
                "default control API listen is unavailable; falling back to an ephemeral loopback port"
            );
            TcpListener::bind("127.0.0.1:0")
                .await
                .context("failed to bind control API on an ephemeral loopback port")
        }
    }
}

pub async fn serve_listener(listener: TcpListener, state: ControlState) -> Result<()> {
    let addr = listener
        .local_addr()
        .context("failed to read control_api listener address")?;
    info!(listen = %addr, "control API listening");

    let accept_context = format!("control API {addr}");
    let limiter = tcp::ConnectionLimiter::new(
        format!("control API {addr}"),
        tcp::DEFAULT_MAX_INBOUND_CONNECTIONS,
    );
    loop {
        let (stream, source) = tcp::accept_with_backoff(&listener, &accept_context).await?;
        let Some(connection_permit) = limiter.try_acquire() else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            if let Err(err) = handle_connection(stream, state).await {
                debug!(source = %source, error = %err, "control_api connection closed");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, state: ControlState) -> Result<()> {
    let head = match timeout(REQUEST_HEAD_TIMEOUT, read_http_head(&mut stream)).await {
        Ok(result) => result?,
        Err(_) => {
            let body = serde_json::to_vec(&ErrorResponse {
                error: "request timeout".to_string(),
            })?;
            write_json(&mut stream, 408, "Request Timeout", false, &body).await?;
            return Ok(());
        }
    };
    let head_text = std::str::from_utf8(&head).context("control_api request is not valid UTF-8")?;
    let request = parse_http_request(head_text)?;
    let body = read_request_body(&mut stream, &request).await?;

    if request.method != "GET" && request.method != "HEAD" && request.method != "POST" {
        let body = serde_json::to_vec(&ErrorResponse {
            error: "method not allowed".to_string(),
        })?;
        write_json(
            &mut stream,
            405,
            "Method Not Allowed",
            request.method == "HEAD",
            &body,
        )
        .await?;
        return Ok(());
    }

    if request.method == "POST" {
        handle_post(&mut stream, &state, &request, &body).await?;
        return Ok(());
    }

    handle_get(&mut stream, &state, &request).await
}

async fn handle_get(
    stream: &mut TcpStream,
    state: &ControlState,
    request: &HttpRequest,
) -> Result<()> {
    let head_only = request.method == "HEAD";
    let path = canonical_control_api_path(&request.path);

    let active = state.active_config();
    let response = match path.as_str() {
        "/" => json_body(&IndexResponse {
            service: "TabbyMew",
            endpoints: vec![
                "/health",
                "/config",
                "/inbounds",
                "/outbounds",
                "/policy-groups",
                "/rules",
                "/counters",
                "/control/api/status",
                "/control/api/subscriptions",
                "/control/api/subscriptions/activate",
                "/control/api/subscriptions/import-file",
                "/control/api/active-config",
                "/control/api/custom-rules",
                "/control/api/rules/reload",
                "/control/api/route-test",
                "/control/api/tun",
                "/control/api/lan-proxy",
                "/control/api/system-proxy",
                "/control/api/global-target",
                "/control/api/policy-groups/delay",
            ],
        })?,
        "/health" => json_body(&HealthResponse {
            ok: true,
            service: "TabbyMew",
            uptime_seconds: state.metrics.snapshot().uptime_seconds,
        })?,
        "/config" => json_body(&config_response(&active.summary))?,
        "/inbounds" => json_body(&ListResponse {
            items: active.summary.inbounds.clone(),
        })?,
        "/outbounds" => json_body(&ListResponse {
            items: active.summary.outbounds.clone(),
        })?,
        "/policy-groups" => json_body(&ListResponse {
            items: active.summary.policy_groups.clone(),
        })?,
        "/rules" => json_body(&RouteSummaryResponse {
            final_outbound: active.summary.route_final.clone(),
            resolve_ip_cidr: active.summary.route_resolve_ip_cidr,
            rule_sets: active.summary.route_rule_sets.clone(),
            rules: active.summary.route_rules.clone(),
            rule_items: route_rule_items_response(&active),
        })?,
        "/counters" | "/stats" => json_body(&state.metrics.snapshot())?,
        "/control/api/status" => json_body(&control_status_response(state).await)?,
        "/control/api/subscriptions" => match subscriptions_response(state).await {
            Ok(subscriptions) => json_body(&subscriptions)?,
            Err(err) => {
                write_error_json(stream, 500, "Internal Server Error", head_only, &err).await?;
                return Ok(());
            }
        },
        "/control/api/active-config" => match active_config_preview_response(state).await {
            Ok(preview) => json_body(&preview)?,
            Err(err) => {
                write_error_json(stream, 404, "Not Found", head_only, &err).await?;
                return Ok(());
            }
        },
        "/control/api/custom-rules" => match custom_route_rules_response(state) {
            Ok(rules) => json_body(&rules)?,
            Err(err) => {
                write_error_json(stream, 400, "Bad Request", head_only, &err).await?;
                return Ok(());
            }
        },
        "/control/api/system-proxy" => json_body(&system_proxy_response(state))?,
        "/control/api/lan-proxy" => json_body(&lan_proxy_response(state).await)?,
        "/control/api/logs" => json_body(&logs_response(state, request))?,
        _ => {
            let body = serde_json::to_vec(&ErrorResponse {
                error: "not found".to_string(),
            })?;
            write_json(stream, 404, "Not Found", head_only, &body).await?;
            return Ok(());
        }
    };

    write_json(stream, 200, "OK", head_only, &response).await
}

async fn handle_post(
    stream: &mut TcpStream,
    state: &ControlState,
    request: &HttpRequest,
    body: &[u8],
) -> Result<()> {
    if !control_token_matches(state, request) {
        let response = serde_json::to_vec(&ErrorResponse {
            error: "invalid control token".to_string(),
        })?;
        write_json(stream, 403, "Forbidden", false, &response).await?;
        return Ok(());
    }

    let path = canonical_control_api_path(&request.path);
    match path.as_str() {
        "/control/api/import" => match import_response(body) {
            Ok(import) => {
                let response = json_body(&import)?;
                write_json(stream, 200, "OK", false, &response).await
            }
            Err(err) => write_control_operation_error(stream, "import", &err).await,
        },
        "/control/api/route-mode" => match route_mode_response(state, body) {
            Ok(route) => {
                let response = json_body(&route)?;
                write_json(stream, 200, "OK", false, &response).await
            }
            Err(err) => write_control_operation_error(stream, "route_mode", &err).await,
        },
        "/control/api/global-target" => match global_target_response(state, body) {
            Ok(route) => {
                let response = json_body(&route)?;
                write_json(stream, 200, "OK", false, &response).await
            }
            Err(err) => write_control_operation_error(stream, "global_target", &err).await,
        },
        "/control/api/policy-groups/select" => match policy_group_select_response(state, body) {
            Ok(route) => {
                let response = json_body(&route)?;
                write_json(stream, 200, "OK", false, &response).await
            }
            Err(err) => write_control_operation_error(stream, "policy_group_select", &err).await,
        },
        "/control/api/policy-groups/delay" => match policy_group_delay_response(state, body).await {
            Ok(route) => {
                let response = json_body(&route)?;
                write_json(stream, 200, "OK", false, &response).await
            }
            Err(err) => write_control_operation_error(stream, "policy_group_delay", &err).await,
        },
        "/control/api/custom-rules/upsert" => {
            match custom_route_rule_upsert_response(state, body).await {
                Ok(status) => {
                    let response = json_body(&status)?;
                    write_json(stream, 200, "OK", false, &response).await
                }
                Err(err) => write_control_operation_error(stream, "custom_rule_upsert", &err).await,
            }
        }
        "/control/api/custom-rules/delete" => {
            match custom_route_rule_delete_response(state, body).await {
                Ok(status) => {
                    let response = json_body(&status)?;
                    write_json(stream, 200, "OK", false, &response).await
                }
                Err(err) => write_control_operation_error(stream, "custom_rule_delete", &err).await,
            }
        }
        "/control/api/rules/reload" => match route_rules_reload_response(state).await {
            Ok(status) => {
                let response = json_body(&status)?;
                write_json(stream, 200, "OK", false, &response).await
            }
            Err(err) => write_control_operation_error(stream, "rules_reload", &err).await,
        },
        "/control/api/route-test" => match route_test_response(state, body).await {
            Ok(route) => {
                let response = json_body(&route)?;
                write_json(stream, 200, "OK", false, &response).await
            }
            Err(err) => write_control_operation_error(stream, "route_test", &err).await,
        },
        "/control/api/tun" => match tun_switch_response(state, body).await {
            Ok(proxy) => {
                let response = json_body(&proxy)?;
                write_json(stream, 200, "OK", false, &response).await
            }
            Err(err) => write_control_operation_error(stream, "tun_switch", &err).await,
        },
        "/control/api/lan-proxy" => match lan_proxy_switch_response(state, body).await {
            Ok(status) => {
                let response = json_body(&status)?;
                write_json(stream, 200, "OK", false, &response).await
            }
            Err(err) => write_control_operation_error(stream, "lan_proxy_switch", &err).await,
        },
        "/control/api/system-proxy" => match system_proxy_switch_response(state, body) {
            Ok(status) => {
                let response = json_body(&status)?;
                write_json(stream, 200, "OK", false, &response).await
            }
            Err(err) => write_control_operation_error(stream, "system_proxy_switch", &err).await,
        },
        "/control/api/subscriptions/add" => match subscription_add_response(state, body).await {
            Ok(report) => {
                let response = json_body(&report)?;
                write_json(stream, 200, "OK", false, &response).await
            }
            Err(err) => write_control_operation_error(stream, "subscription_add", &err).await,
        },
        "/control/api/subscriptions/import-file" => {
            match subscription_import_file_response(state, body).await {
                Ok(report) => {
                    let response = json_body(&report)?;
                    write_json(stream, 200, "OK", false, &response).await
                }
                Err(err) => {
                    write_control_operation_error(stream, "subscription_import_file", &err).await
                }
            }
        }
        "/control/api/subscriptions/refresh" => {
            match subscription_refresh_response(state, body).await {
                Ok(outcome) => {
                    let response = json_body(&outcome)?;
                    write_json(stream, 200, "OK", false, &response).await
                }
                Err(err) => {
                    write_control_operation_error(stream, "subscription_refresh", &err).await
                }
            }
        }
        "/control/api/subscriptions/activate" => {
            match subscription_activate_response(state, body).await {
                Ok(status) => {
                    let response = json_body(&status)?;
                    write_json(stream, 200, "OK", false, &response).await
                }
                Err(err) => {
                    write_control_operation_error(stream, "subscription_activate", &err).await
                }
            }
        }
        "/control/api/subscriptions/set" => match subscription_set_response(state, body).await {
            Ok(summary) => {
                let response = json_body(&summary)?;
                write_json(stream, 200, "OK", false, &response).await
            }
            Err(err) => write_control_operation_error(stream, "subscription_set", &err).await,
        },
        "/control/api/subscriptions/remove" => {
            match subscription_remove_response(state, body).await {
                Ok(summary) => {
                    let response = json_body(&summary)?;
                    write_json(stream, 200, "OK", false, &response).await
                }
                Err(err) => {
                    write_control_operation_error(stream, "subscription_remove", &err).await
                }
            }
        }
        "/control/api/stop" => {
            let response = json_body(&StopResponse { stopping: true })?;
            write_json(stream, 200, "OK", false, &response).await?;
            if let Some(shutdown) = &state.shutdown {
                shutdown.notify_waiters();
            }
            Ok(())
        }
        _ => {
            let response = serde_json::to_vec(&ErrorResponse {
                error: "not found".to_string(),
            })?;
            write_json(stream, 404, "Not Found", false, &response).await
        }
    }
}

fn canonical_control_api_path(path: &str) -> String {
    if let Some(suffix) = path
        .strip_prefix(LEGACY_CONSOLE_API_PREFIX)
        .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'))
    {
        format!("{CONTROL_API_PREFIX}{suffix}")
    } else {
        path.to_string()
    }
}

async fn write_control_operation_error(
    stream: &mut TcpStream,
    operation: &'static str,
    err: &anyhow::Error,
) -> Result<()> {
    warn!(operation = %operation, error = %err, "control API operation failed");
    write_error_json(stream, 400, "Bad Request", false, err).await
}
