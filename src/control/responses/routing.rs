fn route_mode_response(state: &ControlState, body: &[u8]) -> Result<router::RouterRuntimeSnapshot> {
    let request: RouteModeRequest =
        serde_json::from_slice(body).context("route mode request body must be JSON")?;
    let snapshot = state
        .active_config()
        .router
        .as_ref()
        .context("router runtime is not available")?
        .runtime()
        .set_mode(request.mode)?;
    persist_routing_preferences(state, &snapshot);
    Ok(snapshot)
}

fn global_target_response(
    state: &ControlState,
    body: &[u8],
) -> Result<router::RouterRuntimeSnapshot> {
    let request: GlobalTargetRequest =
        serde_json::from_slice(body).context("global target request body must be JSON")?;
    let snapshot = state
        .active_config()
        .router
        .as_ref()
        .context("router runtime is not available")?
        .runtime()
        .set_global_target(&request.target)?;
    persist_routing_preferences(state, &snapshot);
    Ok(snapshot)
}

fn policy_group_select_response(
    state: &ControlState,
    body: &[u8],
) -> Result<router::RouterRuntimeSnapshot> {
    let request: PolicyGroupSelectRequest =
        serde_json::from_slice(body).context("policy group selection request body must be JSON")?;
    let snapshot = state
        .active_config()
        .router
        .as_ref()
        .context("router runtime is not available")?
        .runtime()
        .set_policy_group(&request.group, &request.outbound)?;
    persist_routing_preferences(state, &snapshot);
    Ok(snapshot)
}

async fn policy_group_delay_response(
    state: &ControlState,
    body: &[u8],
) -> Result<PolicyGroupDelayResponse> {
    let request: PolicyGroupDelayRequest =
        serde_json::from_slice(body).context("policy group delay request body must be JSON")?;
    let active = state.active_config();
    let router = active
        .router
        .as_ref()
        .context("router runtime is not available")?
        .clone();
    let group_outbounds = router.policy_group_outbounds(&request.group)?;
    let outbounds =
        policy_group_delay_outbounds(&request.group, &group_outbounds, request.outbound)?;
    let url = request.url.unwrap_or_else(default_policy_group_delay_url);
    let target = parse_url_test_target(&url)?;
    let timeout_ms = request
        .timeout_ms
        .unwrap_or_else(default_policy_group_delay_timeout_ms)
        .clamp(1, default_policy_group_delay_timeout_ms());
    let timeout_duration = Duration::from_millis(timeout_ms);

    let mut results = Vec::new();
    for outbound in outbounds {
        results.push(
            measure_policy_group_delay(router.clone(), outbound, target.clone(), timeout_duration)
                .await,
        );
    }

    Ok(PolicyGroupDelayResponse {
        group: request.group,
        url: target.url,
        timeout_ms,
        results,
    })
}

fn policy_group_delay_outbounds(
    group: &str,
    group_outbounds: &[String],
    requested_outbound: Option<String>,
) -> Result<Vec<String>> {
    match requested_outbound {
        Some(outbound) => {
            if !group_outbounds.iter().any(|item| item == &outbound) {
                bail!("policy group {group} does not contain outbound {outbound}");
            }
            Ok(vec![outbound])
        }
        None => Ok(group_outbounds.to_vec()),
    }
}

async fn measure_policy_group_delay(
    router: router::Router,
    outbound: String,
    target: UrlTestTarget,
    timeout_duration: Duration,
) -> PolicyGroupDelayResult {
    let resolved_outbound = match router.resolve_route_target(&outbound) {
        Ok(resolved) => resolved,
        Err(err) => {
            return PolicyGroupDelayResult {
                outbound,
                resolved_outbound: None,
                latency_ms: None,
                status_code: None,
                error: Some(format!("{err:#}")),
            };
        }
    };
    let started = Instant::now();
    let result = timeout(
        timeout_duration,
        run_url_test(router, &resolved_outbound, target),
    )
    .await;

    match result {
        Ok(Ok(status_code)) => PolicyGroupDelayResult {
            outbound,
            resolved_outbound: Some(resolved_outbound),
            latency_ms: Some(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
            status_code: Some(status_code),
            error: None,
        },
        Ok(Err(err)) => PolicyGroupDelayResult {
            outbound,
            resolved_outbound: Some(resolved_outbound),
            latency_ms: None,
            status_code: None,
            error: Some(format!("{err:#}")),
        },
        Err(_) => PolicyGroupDelayResult {
            outbound,
            resolved_outbound: Some(resolved_outbound),
            latency_ms: None,
            status_code: None,
            error: Some("timeout".to_string()),
        },
    }
}

async fn run_url_test(
    router: router::Router,
    outbound_tag: &str,
    target: UrlTestTarget,
) -> Result<u16> {
    let session = Session::tcp("control_api-url-test", None, target.destination.clone());
    let stream = router.connect_outbound(outbound_tag, &session).await?;
    let head = match target.scheme {
        UrlTestScheme::Http => {
            let mut stream = stream;
            write_url_test_request(&mut stream, &target).await?;
            read_url_test_head(&mut stream).await?
        }
        UrlTestScheme::Https => {
            let mut stream =
                tls::connect_tls_over_stream(stream, &target.host, &TlsClientConfig::default())
                    .await?;
            write_url_test_request(&mut stream, &target).await?;
            read_url_test_head(&mut stream).await?
        }
    };
    let status = parse_url_test_status(&head)?;
    if !(200..400).contains(&status) {
        bail!("URL test returned HTTP {status}");
    }
    Ok(status)
}

async fn write_url_test_request<S>(stream: &mut S, target: &UrlTestTarget) -> Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: TabbyMew/0.1 URLTest\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        target.path, target.host_header
    );
    stream
        .write_all(request.as_bytes())
        .await
        .context("failed to write URL test request")
}

async fn read_url_test_head<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin + ?Sized,
{
    const MAX_HEAD: usize = 64 * 1024;
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while head.len() < MAX_HEAD {
        stream
            .read_exact(&mut byte)
            .await
            .context("failed to read URL test response")?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
    bail!("URL test response header is too large")
}

fn parse_url_test_status(head: &[u8]) -> Result<u16> {
    let head = std::str::from_utf8(head).context("URL test response head is not UTF-8")?;
    let status_line = head
        .lines()
        .next()
        .context("URL test response is missing status line")?;
    if !status_line.starts_with("HTTP/") {
        bail!("URL test response has invalid status line");
    }
    status_line
        .split_whitespace()
        .nth(1)
        .context("URL test response is missing status code")?
        .parse::<u16>()
        .context("URL test response status code is invalid")
}

fn parse_url_test_target(value: &str) -> Result<UrlTestTarget> {
    let url = Url::parse(value).with_context(|| format!("URL test URL {value} is invalid"))?;
    let scheme = match url.scheme() {
        "http" => UrlTestScheme::Http,
        "https" => UrlTestScheme::Https,
        other => bail!("URL test scheme {other} is not supported"),
    };
    let host = url
        .host_str()
        .context("URL test URL is missing host")?
        .to_string();
    let port = url
        .port_or_known_default()
        .context("URL test URL is missing port")?;
    let address = match host.parse::<IpAddr>() {
        Ok(ip) => Address::Ip(ip),
        Err(_) => Address::Domain(host.clone()),
    };
    let path = match url.query() {
        Some(query) => format!("{}?{query}", empty_path_as_slash(url.path())),
        None => empty_path_as_slash(url.path()).to_string(),
    };
    let host_header = url_test_host_header(&url, &host);

    Ok(UrlTestTarget {
        url: url.to_string(),
        scheme,
        host,
        host_header,
        destination: Destination::new(address, port),
        path,
    })
}

fn empty_path_as_slash(path: &str) -> &str {
    if path.is_empty() { "/" } else { path }
}

fn url_test_host_header(url: &Url, host: &str) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}
