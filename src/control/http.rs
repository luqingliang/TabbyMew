struct HttpRequest {
    method: String,
    path: String,
    query: Option<String>,
    headers: BTreeMap<String, String>,
}

fn parse_http_request(head_text: &str) -> Result<HttpRequest> {
    let mut lines = head_text.split("\r\n");
    let request_line = lines.next().context("empty control_api request")?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .context("control_api request is missing method")?
        .to_string();
    let target = parts.next().context("control_api request is missing path")?;
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), Some(query.to_string())),
        None => (target.to_string(), None),
    };
    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
    })
}

async fn read_request_body(stream: &mut TcpStream, request: &HttpRequest) -> Result<Vec<u8>> {
    let length = match request.headers.get("content-length") {
        Some(value) => value
            .parse::<usize>()
            .with_context(|| format!("invalid content-length {value}"))?,
        None => 0,
    };
    if length > MAX_BODY {
        bail!("request body is too large");
    }
    let mut body = vec![0; length];
    if length > 0 {
        timeout(REQUEST_HEAD_TIMEOUT, stream.read_exact(&mut body))
            .await
            .context("timed out reading request body")?
            .context("failed to read request body")?;
    }
    Ok(body)
}

async fn read_http_head(stream: &mut TcpStream) -> Result<Vec<u8>> {
    const MAX_HEAD: usize = 16 * 1024;
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];

    while buf.len() < MAX_HEAD {
        stream
            .read_exact(&mut byte)
            .await
            .context("failed to read control_api request")?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
    }

    bail!("control_api request header is too large")
}

async fn write_json(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    head_only: bool,
    body: &[u8],
) -> Result<()> {
    write_response(stream, status, reason, head_only, "application/json", body).await
}

async fn write_error_json(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    head_only: bool,
    err: &anyhow::Error,
) -> Result<()> {
    let body = serde_json::to_vec(&ErrorResponse {
        error: format!("{err:#}"),
    })?;
    write_json(stream, status, reason, head_only, &body).await
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    head_only: bool,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    if !head_only {
        stream.write_all(body).await?;
    }
    Ok(())
}

fn increment_counter(counters: &Mutex<BTreeMap<String, u64>>, key: &str) {
    let mut counters = counters
        .lock()
        .expect("runtime metrics mutex must not be poisoned");
    *counters.entry(key.to_string()).or_insert(0) += 1;
}

fn control_token_matches(state: &ControlState, request: &HttpRequest) -> bool {
    request
        .headers
        .get(CONTROL_TOKEN_HEADER)
        .or_else(|| request.headers.get(LEGACY_CONSOLE_TOKEN_HEADER))
        .is_some_and(|token| token == &state.control_api.token)
}

fn query_param(query: &Option<String>, name: &str) -> Option<String> {
    let query = query.as_ref()?;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode_str(key).decode_utf8().ok()?.as_ref() == name {
            return percent_decode_str(value)
                .decode_utf8()
                .ok()
                .map(|v| v.into_owned());
        }
    }
    None
}

fn path_to_string(path: Option<&PathBuf>) -> Option<String> {
    path.map(|path| path.display().to_string())
}

fn active_subscription_name(
    active_config: &str,
    subscriptions: &[subscription_remote::SubscriptionSummary],
) -> Option<String> {
    let active_path = Path::new(active_config);
    subscriptions
        .iter()
        .find(|subscription| same_path(active_path, Path::new(&subscription.output)))
        .map(|subscription| subscription.name.clone())
}

fn same_path(left: &Path, right: &Path) -> bool {
    left == right
        || match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        }
}

fn csrf_token() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn default_import_inbound_tag() -> String {
    Config::default_local_inbound_tag()
}

fn default_import_listen() -> String {
    Config::default_local_listen()
}

fn default_import_port() -> u16 {
    Config::default_local_listen_port()
}

fn default_policy_group_delay_url() -> String {
    "http://www.gstatic.com/generate_204".to_string()
}

fn default_policy_group_delay_timeout_ms() -> u64 {
    15_000
}

pub fn destination_log_label(destination: &Destination) -> String {
    match &destination.address {
        Address::Domain(_) => format!("domain:<redacted>:{}", destination.port),
        Address::Ip(_) => format!("ip:<redacted>:{}", destination.port),
    }
}
