pub async fn fetch_text(url: &str, options: &FetchOptions) -> Result<FetchResult> {
    let mut last_error = None;
    for attempt in 0..=options.retries {
        match timeout(options.timeout, fetch_with_redirects(url, options)).await {
            Ok(Ok(result)) => return Ok(result),
            Ok(Err(err)) => last_error = Some(err),
            Err(_) => {
                last_error = Some(anyhow!(
                    "timed out fetching subscription {}",
                    redact_url(url)
                ))
            }
        }
        if attempt < options.retries {
            tokio::time::sleep(Duration::from_millis(150 * u64::from(attempt + 1))).await;
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("failed to fetch subscription {}", redact_url(url))))
}

async fn fetch_with_redirects(url: &str, options: &FetchOptions) -> Result<FetchResult> {
    let mut current = validate_url(url)?;
    for _ in 0..=MAX_REDIRECTS {
        let response = fetch_once(&current, options).await?;
        if response.is_redirect() {
            let location = response
                .header("location")
                .context("subscription redirect is missing Location header")?;
            current = current.join(location).with_context(|| {
                format!(
                    "subscription redirect Location {} is invalid",
                    redact_url(location)
                )
            })?;
            validate_url(current.as_str())?;
            continue;
        }
        return response.into_result(current);
    }
    bail!(
        "subscription {} exceeded redirect limit",
        redact_url(current.as_str())
    )
}

async fn fetch_once(url: &Url, options: &FetchOptions) -> Result<HttpResponse> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("subscription URL is missing host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("subscription URL is missing port"))?;
    let mut stream = connect(url.scheme(), host, port).await?;
    let path = match url.query() {
        Some(query) => format!("{}?{query}", empty_path_as_slash(url.path())),
        None => empty_path_as_slash(url.path()).to_string(),
    };
    let host_header = host_header(url, host);
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         User-Agent: {}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\r\n",
        sanitize_header_value(&options.user_agent)
    );
    stream
        .write_all(request.as_bytes())
        .await
        .context("failed to write subscription request")?;

    let bytes = read_limited(&mut stream).await?;
    parse_http_response(bytes)
}

trait AsyncStream: AsyncRead + AsyncWrite + Unpin {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin {}

async fn connect(scheme: &str, host: &str, port: u16) -> Result<Box<dyn AsyncStream + Send>> {
    match scheme {
        "http" => {
            let stream = crate::net::timeout::connect_tcp_with_dns(
                host,
                port,
                None,
                &format!("connecting subscription server {host}:{port}"),
            )
            .await
            .with_context(|| format!("failed to connect subscription server {host}:{port}"))?;
            Ok(Box::new(stream))
        }
        "https" => {
            let stream = tls::connect_tls(host, port, &TlsClientConfig::default()).await?;
            Ok(Box::new(stream))
        }
        _ => bail!("subscription URL scheme {scheme} is not supported"),
    }
}

async fn read_limited(stream: &mut (dyn AsyncStream + Send)) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = stream
            .read(&mut buffer)
            .await
            .context("failed to read subscription response")?;
        if read == 0 {
            return Ok(response);
        }
        if response.len() + read > MAX_SUBSCRIPTION_BYTES {
            bail!(
                "subscription response is larger than {} bytes",
                MAX_SUBSCRIPTION_BYTES
            );
        }
        response.extend_from_slice(&buffer[..read]);
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn is_redirect(&self) -> bool {
        matches!(self.status, 301 | 302 | 303 | 307 | 308)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    fn into_result(self, final_url: Url) -> Result<FetchResult> {
        if !(200..300).contains(&self.status) {
            bail!("subscription server returned HTTP {}", self.status);
        }
        let etag = self.header("etag").map(ToOwned::to_owned);
        let last_modified = self.header("last-modified").map(ToOwned::to_owned);
        let body = if self
            .header("transfer-encoding")
            .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
        {
            decode_chunked(&self.body)?
        } else {
            self.body
        };
        let bytes = body.len();
        let body = String::from_utf8(body).context("subscription response is not UTF-8")?;
        Ok(FetchResult {
            final_url: final_url.to_string(),
            body,
            bytes,
            etag,
            last_modified,
        })
    }
}

fn parse_http_response(response: Vec<u8>) -> Result<HttpResponse> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("subscription response is missing HTTP headers")?;
    let (head, body) = response.split_at(header_end + 4);
    let head = std::str::from_utf8(&head[..header_end])
        .context("subscription response headers are not UTF-8")?;
    let mut lines = head.lines();
    let status_line = lines
        .next()
        .context("subscription response is missing status line")?;
    let status = parse_status(status_line)?;
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    Ok(HttpResponse {
        status,
        headers,
        body: body.to_vec(),
    })
}

fn parse_status(status_line: &str) -> Result<u16> {
    let mut parts = status_line.split_whitespace();
    let version = parts
        .next()
        .context("subscription response status line is missing HTTP version")?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        bail!("subscription response returned unsupported HTTP version {version}");
    }
    parts
        .next()
        .context("subscription response status line is missing status code")?
        .parse::<u16>()
        .context("subscription response status code is invalid")
}

fn decode_chunked(body: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut index = 0usize;
    loop {
        let line_end = find_crlf(body, index).context("chunked response is missing chunk size")?;
        let size_text = std::str::from_utf8(&body[index..line_end])
            .context("chunked response chunk size is not UTF-8")?;
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .with_context(|| format!("chunked response chunk size {size_text} is invalid"))?;
        index = line_end + 2;
        if size == 0 {
            return Ok(output);
        }
        if index + size + 2 > body.len() {
            bail!("chunked response ended before chunk data completed");
        }
        output.extend_from_slice(&body[index..index + size]);
        index += size;
        if body.get(index..index + 2) != Some(b"\r\n") {
            bail!("chunked response chunk is missing trailing CRLF");
        }
        index += 2;
    }
}

fn find_crlf(bytes: &[u8], start: usize) -> Option<usize> {
    bytes
        .get(start..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}

pub fn redact_url(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return value.split('?').next().unwrap_or(value).to_string();
    };
    if !url.username().is_empty() {
        let _ = url.set_username("redacted");
    }
    if url.password().is_some() {
        let _ = url.set_password(Some("redacted"));
    }
    if url.query().is_some() {
        url.set_query(Some("redacted"));
    }
    if url.fragment().is_some() {
        url.set_fragment(Some("redacted"));
    }
    url.to_string()
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn empty_path_as_slash(path: &str) -> &str {
    if path.is_empty() { "/" } else { path }
}

fn host_header(url: &Url, host: &str) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_ascii_control())
        .collect::<String>()
}
