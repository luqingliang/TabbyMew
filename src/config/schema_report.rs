use super::*;

pub fn config_schema_json() -> Result<String> {
    serde_json::to_string_pretty(&config_schema_value())
        .context("failed to serialize config schema")
}

pub fn config_schema_value() -> serde_json::Value {
    serde_json::json!({
        "schema_version": CONFIG_SCHEMA_VERSION,
        "format": "json",
        "strict_unknown_fields": true,
        "native_config": {
            "root_fields": [
                "schema_version",
                "log",
                "dns",
                "inbounds",
                "outbounds",
                "policy_groups",
                "route",
                "services"
            ],
            "dns_fields": ["servers", "timeout_ms"],
            "inbound_types": {
                "socks": ["tag", "listen", "listen_port"],
                "http": ["tag", "listen", "listen_port", "username", "password"],
                "hybrid": ["tag", "listen", "listen_port", "username", "password"],
                "tun": [
                    "tag",
                    "interface_name",
                    "mtu",
                    "auto_route",
                    "ipv6_enabled",
                    "dns",
                    "dns_addr",
                    "bypass",
                    "tcp_timeout_seconds",
                    "udp_timeout_seconds",
                    "max_sessions"
                ]
            },
            "outbound_types": {
                "direct": ["tag"],
                "block": ["tag"],
                "socks": ["tag", "server", "server_port", "username", "password"],
                "http": ["tag", "server", "server_port", "username", "password"],
                "trojan": ["tag", "server", "server_port", "password", "tls"],
                "shadowsocks": ["tag", "server", "server_port", "method", "password"],
                "shadowsocks-2022": ["tag", "server", "server_port", "method", "password"],
                "anytls": [
                    "tag",
                    "server",
                    "server_port",
                    "password",
                    "tls",
                    "idle_session_check_interval_ms",
                    "idle_session_timeout_ms",
                    "min_idle_session"
                ]
            },
            "policy_group_fields": ["type", "tag", "outbounds", "default"],
            "route_fields": ["final", "resolve_ip_cidr", "rule_sets", "rules"],
            "route_rule_match_fields": [
                "inbound",
                "network",
                "domain",
                "domain_set",
                "domain_suffix",
                "domain_suffix_set",
                "domain_keyword",
                "domain_keyword_set",
                "ip_cidr",
                "ip_cidr_set",
                "process_name",
                "geoip",
                "port",
                "port_range"
            ],
            "route_rule_target_field": "outbound",
            "tls_fields": ["server_name", "insecure", "alpn"]
        },
        "unit_fields": {
            "milliseconds": [
                "dns.timeout_ms",
                "outbounds[].idle_session_check_interval_ms",
                "outbounds[].idle_session_timeout_ms"
            ],
            "seconds": [
                "inbounds[].tcp_timeout_seconds",
                "inbounds[].udp_timeout_seconds"
            ]
        },
        "import_only_fields": {
            "clash_mihomo": [
                "proxy-groups",
                "proxy group name",
                "proxy group proxies",
                "dns.listen",
                "dns.ipv6",
                "dns.use-hosts",
                "dns.fake-ip-range",
                "dns.fake-ip-filter",
                "duration strings"
            ]
        }
    })
}
