# Clash and Mihomo Migration

This guide covers local and remote import paths for common Clash/Mihomo-style profiles. Remote subscription URLs can be saved, manually updated, automatically refreshed while TabbyMew is running, and managed from the CLI/TUI with validated last-good output files. Remote rule sets and advanced policy group behavior such as URL testing, fallback, and load balancing are not implemented yet. Select proxy groups, supported DNS fields, and common rules are imported from Clash/Mihomo profiles, and local file-backed route rule sets remain available for hand-written routing.

Clash/Mihomo profiles are import input, not native runtime configs. Run `import`
or `subscription add` first; the generated TabbyMew JSON uses strict native
field names such as `policy_groups`, `tag`, and `outbounds`.

## Basic Workflow

Import a local profile:

```bash
cargo run -- import --input examples/clash-profile.yaml --output /tmp/tabbymew-imported.json
```

Validate the generated config:

```bash
cargo run -- check --config /tmp/tabbymew-imported.json
```

Create a redacted copy for review or issue reports:

```bash
cargo run -- config normalize --config /tmp/tabbymew-imported.json --output /tmp/tabbymew-redacted.json
```

Run the generated config as a foreground service:

```bash
cargo run -- --config /tmp/tabbymew-imported.json run
```

Use `--show-secrets` only for local config cleanup when the normalized output should remain runnable.

## Remote Subscription URLs

Save a remote subscription and write the first validated generated config:

```bash
cargo run -- subscription add main 'https://example.com/subscription'
```

Update it later:

```bash
cargo run -- subscription update main
```

List or remove saved subscriptions:

```bash
cargo run -- subscription list
cargo run -- subscription set main --update-interval-seconds 43200
cargo run -- subscription set main --no-auto-update
cargo run -- subscription remove main
```

Remote subscriptions are persisted in `~/.tabbymew/tabbymew-subscriptions.json` by default. Generated subscription configs are written under `~/.tabbymew/profiles/subscriptions/<name>.json` by default. These files can contain subscription URLs and proxy credentials, so TabbyMew writes them with private file permissions where the platform supports it. Use `TABBYMEW_STATE_DIR` or `--state-dir` to isolate both the store and generated configs. `add` and `update` fetch HTTP/HTTPS URLs with timeout, retry, and redirect handling, then reuse the same importer and runtime validation as local files. New remote subscriptions auto-update every 86400 seconds by default while `run` or `start` is active. CLI/TUI subscription management can add remote subscriptions, refresh saved subscriptions, enable or disable automatic refresh, activate generated configs, and remove saved entries. The generated config is replaced only after fetch, import conversion, and validation all pass; failed updates record `last_error` and keep the previous generated config untouched. CLI output redacts query strings and URL credentials.

The last activated subscription config and runtime routing choices are persisted in `~/.tabbymew/tabbymew-preferences.json` by default. If `run` or `start` is launched later without an explicit `--config`, TabbyMew restores that generated config when it still exists, then reapplies saved route mode, global target, and policy group selections that still match the current config.

## Supported Proxy Entries

TabbyMew imports these Clash/Mihomo `proxies` entries when their transport is plain TCP:

| Clash/Mihomo type | TabbyMew outbound | Notes |
| --- | --- | --- |
| `ss` / `shadowsocks` | `shadowsocks` or `shadowsocks-2022` | AEAD and 2022 ciphers exposed by the `shadowsocks` crate. Plugin options are skipped. |
| `trojan` | `trojan` | TLS server name comes from `servername` or `sni`. |
| `anytls` | `anytls` | TLS server name comes from `servername` or `sni`; idle session fields are imported when present. |

The importer also supports share-link subscriptions containing `ss://`, `trojan://`, and `anytls://` lines, including base64-encoded line subscriptions.

## Supported Proxy Groups and Rules

TabbyMew imports Clash/Mihomo `proxy-groups` with `type: select`. Group members can reference imported proxy names, other imported select groups, `DIRECT`, `REJECT`, or `REJECT-DROP`. Unsupported group types such as `url-test`, `fallback`, `load-balance`, and `relay` are reported as warnings and skipped.

TabbyMew imports these string rules:

| Clash/Mihomo rule | TabbyMew route field |
| --- | --- |
| `DOMAIN,value,target` | `domain` |
| `DOMAIN-SUFFIX,value,target` | `domain_suffix` |
| `DOMAIN-KEYWORD,value,target` | `domain_keyword` |
| `IP-CIDR,value,target` | `ip_cidr` |
| `IP-CIDR6,value,target` | `ip_cidr` |
| `PROCESS-NAME,value,target` | `process_name` |
| `GEOIP,value,target` | `geoip` |
| `MATCH,target` / `FINAL,target` | `route.final` |

Rule targets can reference imported proxy names, imported select groups, `DIRECT`, `REJECT`, or `REJECT-DROP`. Rules after `MATCH`/`FINAL` are ignored with warnings to preserve Clash rule ordering semantics. `PROCESS-NAME` and `GEOIP` are preserved in generated configs for completeness; current route selection does not apply them until process and GeoIP runtime context is available.

## Skipped or Warning-Only Fields

The importer reports skipped nodes and warnings instead of silently claiming support for unsupported runtime behavior:

- Unsupported share-link schemes such as `hysteria2://`, `tuic://`, and `ssr://`.
- WebSocket, gRPC, H2, and other non-plain-TCP transports.
- Unsupported proxy group types such as `url-test`, `fallback`, `load-balance`, and `relay`.
- Unsupported rule types such as `GEOSITE`, `RULE-SET`, and provider-specific extensions.
- Shadowsocks `plugin` and `plugin-opts`.
- Multiplex options such as `mux`; plain non-mux connections are imported and the mux option is ignored.

## Output Shape

Imported configs use:

- One local `hybrid` inbound on the default local proxy address, currently `127.0.0.1:17890`, unless explicitly overridden from the CLI.
- Imported proxy nodes as outbounds with source names preserved as unique tags.
- Imported `select` proxy groups as native `policy_groups` when present.
- Imported rules as `route.rules` when present.
- Supported Clash `dns.nameserver` UDP IP upstreams as native `dns.servers`; unsupported DNS listener, fake-IP, hosts, and non-UDP upstream fields are reported as warnings and kept out of native configs.
- `MATCH`/`FINAL` as `route.final`; otherwise the first imported outbound is used as `route.final`.
- Built-in `direct` and `block` outbounds appended for later manual routing.

The generated config is plain TabbyMew JSON. After import, edit it directly or run `config normalize --show-secrets` for stable formatting without redaction.
Native config loading rejects unknown fields, so Clash/Mihomo keys such as
`proxy-groups`, proxy-group `name`, and proxy-group `proxies` are intentionally
limited to the import layer. Duration strings and Clash DNS compatibility fields
are also import-layer inputs; generated native JSON uses explicit `_ms` and
`_seconds` numeric fields.
