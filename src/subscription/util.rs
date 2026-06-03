fn split_fragment(value: &str) -> (&str, Option<String>) {
    match value.split_once('#') {
        Some((before, fragment)) => (before, Some(percent_decode(fragment))),
        None => (value, None),
    }
}

fn split_query(value: &str) -> (&str, Option<&str>) {
    match value.split_once('?') {
        Some((before, query)) => (before, Some(query)),
        None => (value, None),
    }
}

fn parse_query_pairs(query: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(query.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn query_map(url: &Url) -> HashMap<String, String> {
    url.query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn query_string(query: &HashMap<String, String>, key: &str) -> Option<String> {
    query
        .get(key)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn query_flag(query: &HashMap<String, String>, key: &str) -> Option<bool> {
    query
        .get(key)
        .and_then(|value| parse_bool_string(Some(value)))
}

fn query_duration_ms(query: &HashMap<String, String>, keys: &[&str]) -> Result<Option<u64>> {
    for key in keys {
        if let Some(value) = query_string(query, key) {
            return Ok(Some(parse_duration_ms_literal(&value).with_context(|| {
                format!("AnyTLS query parameter {key} is invalid")
            })?));
        }
    }
    Ok(None)
}

fn query_usize(query: &HashMap<String, String>, keys: &[&str]) -> Result<Option<usize>> {
    for key in keys {
        if let Some(value) = query_string(query, key) {
            return value
                .parse::<usize>()
                .with_context(|| format!("AnyTLS query parameter {key} is invalid"))
                .map(Some);
        }
    }
    Ok(None)
}

fn unsupported_transport_reason(query: &HashMap<String, String>) -> Option<String> {
    let transport = query
        .get("type")
        .or_else(|| query.get("network"))
        .or_else(|| query.get("net"))
        .map(String::as_str)
        .unwrap_or("tcp");
    if transport != "tcp" {
        return Some(format!("transport {transport} is not supported"));
    }
    None
}

fn tls_from_query(query: &HashMap<String, String>, server: &str) -> TlsClientConfig {
    TlsClientConfig {
        server_name: query_string(query, "sni")
            .or_else(|| query_string(query, "servername"))
            .or_else(|| query_string(query, "peer"))
            .filter(|name| name != server),
        insecure: query_flag(query, "allowInsecure")
            .or_else(|| query_flag(query, "skip-cert-verify"))
            .unwrap_or(false),
        alpn: query_string(query, "alpn")
            .map(|value| split_protocol_list(&value))
            .unwrap_or_default(),
    }
}

fn url_host(url: &Url) -> Result<String> {
    url.host_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("server host is missing"))
}

fn link_tag_label(url: &Url) -> String {
    url.fragment()
        .map(percent_decode)
        .filter(|tag| !tag.trim().is_empty())
        .unwrap_or_else(|| "unnamed".to_string())
}

fn tag_label(tag: Option<&str>) -> String {
    tag.filter(|tag| !tag.trim().is_empty())
        .unwrap_or("unnamed")
        .to_string()
}

fn decode_ss_credentials(value: &str) -> Result<String> {
    let decoded = percent_decode(value);
    if decoded.contains(':') {
        return Ok(decoded);
    }
    decode_base64_fragment(value).context("credentials are not plain method:password or base64")
}

fn split_credentials(value: &str) -> Result<(String, String)> {
    let (method, password) = value
        .split_once(':')
        .ok_or_else(|| anyhow!("missing ':' separator"))?;
    if method.is_empty() || password.is_empty() {
        bail!("method/password cannot be empty");
    }
    Ok((method.to_string(), password.to_string()))
}

fn parse_host_port(value: &str) -> Result<(String, u16)> {
    let value = value.trim().trim_end_matches('/');
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("IPv6 host is missing closing bracket"))?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("server port is missing"))?;
        (host.to_string(), port)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("server port is missing"))?;
        (host.to_string(), port)
    };
    if host.trim().is_empty() {
        bail!("server host is empty");
    }
    Ok((host, parse_port_string(port)?))
}

fn parse_port_string(value: &str) -> Result<u16> {
    let port = value.trim().parse::<u16>().context("port must be a u16")?;
    if port == 0 {
        bail!("port must be greater than 0");
    }
    Ok(port)
}

fn required_string(value: Option<String>, field: &str) -> Result<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("{field} is missing"))
}

fn decode_base64_text(value: &str) -> Option<String> {
    let compact = value.split_whitespace().collect::<String>();
    decode_base64_fragment(&compact).ok()
}

fn decode_base64_fragment(value: &str) -> Result<String> {
    let bytes = general_purpose::STANDARD
        .decode(value)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(value))
        .or_else(|_| general_purpose::URL_SAFE.decode(value))
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(value))
        .context("invalid base64")?;
    String::from_utf8(bytes).context("decoded base64 is not UTF-8")
}

fn percent_decode(value: &str) -> String {
    percent_decode_str(value).decode_utf8_lossy().into_owned()
}

fn supported_shadowsocks_method(method: &str) -> Option<bool> {
    CipherKind::from_str(method)
        .ok()
        .map(|cipher| cipher.is_aead_2022())
}

fn yaml_string(value: Option<&YamlValue>) -> Option<String> {
    match value? {
        YamlValue::String(value) => Some(value.clone()),
        YamlValue::Number(value) => Some(value.to_string()),
        YamlValue::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn yaml_string_list(value: Option<&YamlValue>) -> Vec<String> {
    match value {
        Some(YamlValue::Sequence(items)) => items
            .iter()
            .filter_map(|item| yaml_string(Some(item)))
            .flat_map(|item| split_protocol_list(&item))
            .collect(),
        Some(value) => yaml_string(Some(value))
            .map(|value| split_protocol_list(&value))
            .unwrap_or_default(),
        None => Vec::new(),
    }
}

fn split_protocol_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn yaml_u16(value: &YamlValue) -> Option<u16> {
    match value {
        YamlValue::Number(value) => value.as_u64().and_then(|value| u16::try_from(value).ok()),
        YamlValue::String(value) => value.parse::<u16>().ok(),
        _ => None,
    }
}

fn yaml_usize(value: Option<&YamlValue>) -> Result<Option<usize>> {
    match value {
        Some(YamlValue::Number(value)) => value
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| anyhow!("value is not a valid usize")),
        Some(YamlValue::String(value)) => value
            .trim()
            .parse::<usize>()
            .context("value is not a valid usize")
            .map(Some),
        Some(_) => bail!("value is not a valid usize"),
        None => Ok(None),
    }
}

fn yaml_duration_ms(value: Option<&YamlValue>) -> Result<Option<u64>> {
    match value {
        Some(YamlValue::Number(value)) => value
            .as_u64()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .map(Some)
            .ok_or_else(|| anyhow!("duration is not a valid number of seconds")),
        Some(YamlValue::String(value)) if value.trim().chars().all(|ch| ch.is_ascii_digit()) => {
            value
                .trim()
                .parse::<u64>()
                .ok()
                .and_then(|seconds| seconds.checked_mul(1_000))
                .map(Some)
                .ok_or_else(|| anyhow!("duration is not a valid number of seconds"))
        }
        Some(YamlValue::String(value)) => parse_duration_ms_literal(value)
            .context("duration is invalid")
            .map(Some),
        Some(_) => bail!("duration is invalid"),
        None => Ok(None),
    }
}

fn yaml_port(value: Option<&YamlValue>) -> Result<u16> {
    let port = value
        .and_then(yaml_u16)
        .ok_or_else(|| anyhow!("port is missing or invalid"))?;
    if port == 0 {
        bail!("port must be greater than 0");
    }
    Ok(port)
}

fn yaml_bool(value: Option<&YamlValue>) -> Option<bool> {
    match value? {
        YamlValue::Bool(value) => Some(*value),
        YamlValue::Number(value) => Some(value.as_u64()? != 0),
        YamlValue::String(value) => parse_bool_string(Some(value)),
        _ => None,
    }
}

fn parse_bool_string(value: Option<&str>) -> Option<bool> {
    match value?.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}
