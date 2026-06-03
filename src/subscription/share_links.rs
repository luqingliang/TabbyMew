fn import_share_link_text(text: &str, warnings: &mut Vec<String>) -> Result<Vec<ImportedOutbound>> {
    let mut candidates = share_link_candidates(text);
    if candidates.is_empty()
        && let Some(decoded) = decode_base64_text(text)
    {
        candidates = share_link_candidates(&decoded);
    }

    let mut outbounds = Vec::new();
    for candidate in candidates {
        match parse_share_link(&candidate) {
            Ok(ParsedNode::Imported(node)) => {
                warnings.extend(node.warnings.clone());
                outbounds.push(*node);
            }
            Ok(ParsedNode::Skipped(reason)) => warnings.push(reason),
            Err(err) => warnings.push(format!("skipped invalid share link: {err:#}")),
        }
    }
    Ok(outbounds)
}

fn share_link_candidates(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| share_link_scheme(line).is_some())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_share_link(link: &str) -> Result<ParsedNode> {
    let scheme = share_link_scheme(link).ok_or_else(|| anyhow!("missing share-link scheme"))?;
    match scheme.to_ascii_lowercase().as_str() {
        "ss" => parse_ss_link(link),
        "trojan" => parse_trojan_like_link(link, TrojanLikeProtocol::Trojan),
        "anytls" => parse_trojan_like_link(link, TrojanLikeProtocol::AnyTls),
        scheme => Ok(ParsedNode::Skipped(format!(
            "skipped unsupported share-link scheme {scheme}"
        ))),
    }
}

fn share_link_scheme(link: &str) -> Option<&str> {
    link.split_once("://").map(|(scheme, _)| scheme)
}

fn parse_ss_link(link: &str) -> Result<ParsedNode> {
    let body = link
        .strip_prefix("ss://")
        .ok_or_else(|| anyhow!("Shadowsocks link must start with ss://"))?;
    let (without_fragment, tag_seed) = split_fragment(body);
    let (authority, query) = split_query(without_fragment);
    let query = parse_query_pairs(query.unwrap_or_default());
    if query.contains_key("plugin") || query.contains_key("plugin-opts") {
        return Ok(ParsedNode::Skipped(format!(
            "skipped {} Shadowsocks node because plugin options are not supported",
            tag_label(tag_seed.as_deref())
        )));
    }

    let (method, password, server, server_port) =
        if let Some((userinfo, host_port)) = authority.rsplit_once('@') {
            let credentials = decode_ss_credentials(userinfo)
                .context("failed to decode Shadowsocks credentials")?;
            let (method, password) = split_credentials(&credentials)
                .context("Shadowsocks credentials must be method:password")?;
            let (server, server_port) =
                parse_host_port(host_port).context("failed to parse Shadowsocks server address")?;
            (method, password, server, server_port)
        } else {
            let decoded = decode_base64_fragment(authority)
                .context("Shadowsocks legacy link body must be base64")?;
            let (credentials, host_port) = decoded.rsplit_once('@').ok_or_else(|| {
                anyhow!("Shadowsocks legacy link must contain method:password@host:port")
            })?;
            let (method, password) = split_credentials(credentials)
                .context("Shadowsocks credentials must be method:password")?;
            let (server, server_port) =
                parse_host_port(host_port).context("failed to parse Shadowsocks server address")?;
            (method, password, server, server_port)
        };

    let tag_seed = tag_seed.unwrap_or_else(|| format!("ss-{server}"));
    let Some(is_2022_method) = supported_shadowsocks_method(&method) else {
        return Ok(ParsedNode::Skipped(format!(
            "skipped {} Shadowsocks node because method {method} is not supported",
            tag_seed
        )));
    };

    let outbound = if is_2022_method {
        OutboundConfig::Shadowsocks2022 {
            tag: String::new(),
            server,
            server_port,
            method,
            password,
        }
    } else {
        OutboundConfig::Shadowsocks {
            tag: String::new(),
            server,
            server_port,
            method,
            password,
        }
    };
    Ok(ParsedNode::Imported(Box::new(ImportedOutbound {
        tag_seed,
        outbound,
        warnings: Vec::new(),
    })))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrojanLikeProtocol {
    Trojan,
    AnyTls,
}

fn parse_trojan_like_link(link: &str, protocol: TrojanLikeProtocol) -> Result<ParsedNode> {
    let url = Url::parse(link).context("invalid URL")?;
    let query = query_map(&url);
    if let Some(reason) = unsupported_transport_reason(&query) {
        return Ok(ParsedNode::Skipped(format!(
            "skipped {} node because {reason}",
            link_tag_label(&url)
        )));
    }
    let mut warnings = Vec::new();

    let password = percent_decode(url.username());
    if password.is_empty() {
        bail!("password is empty");
    }
    let server = url_host(&url)?;
    let server_port = url
        .port()
        .ok_or_else(|| anyhow!("server port is missing"))?;
    let tls = tls_from_query(&query, &server);
    let tag_seed = url
        .fragment()
        .map(percent_decode)
        .filter(|tag| !tag.trim().is_empty())
        .unwrap_or_else(|| match protocol {
            TrojanLikeProtocol::Trojan => format!("trojan-{server}"),
            TrojanLikeProtocol::AnyTls => format!("anytls-{server}"),
        });
    if protocol == TrojanLikeProtocol::Trojan && query_flag(&query, "mux").unwrap_or(false) {
        warnings.push(format!(
            "ignored mux option for {} because multiplex is not supported yet",
            tag_seed
        ));
    }

    let outbound = match protocol {
        TrojanLikeProtocol::Trojan => OutboundConfig::Trojan {
            tag: String::new(),
            server,
            server_port,
            password,
            tls,
        },
        TrojanLikeProtocol::AnyTls => OutboundConfig::AnyTls {
            tag: String::new(),
            server,
            server_port,
            password,
            tls,
            idle_session_check_interval_ms: query_duration_ms(
                &query,
                &[
                    "idle_session_check_interval",
                    "idle-session-check-interval",
                    "idle_session_check_interval_ms",
                ],
            )?
            .unwrap_or_else(default_anytls_idle_session_check_interval_ms),
            idle_session_timeout_ms: query_duration_ms(
                &query,
                &[
                    "idle_session_timeout",
                    "idle-session-timeout",
                    "idle_session_timeout_ms",
                ],
            )?
            .unwrap_or_else(default_anytls_idle_session_timeout_ms),
            min_idle_session: query_usize(
                &query,
                &["min_idle_session", "min-idle-session"],
            )?
            .unwrap_or_default(),
        },
    };
    Ok(ParsedNode::Imported(Box::new(ImportedOutbound {
        tag_seed,
        outbound,
        warnings,
    })))
}
