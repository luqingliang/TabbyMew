# TabbyMew

<p align="center">
  <img src="assets/app-icon.png" alt="TabbyMew application icon" width="240">
</p>

Language: English | [中文](README.zh-CN.md)

License: [Apache-2.0](LICENSE)

🦀 **TabbyMew** is a lightweight, efficient, Agent-friendly proxy application for
macOS and Windows. It keeps the core small, exposes deterministic CLI/TUI
controls, stores state in predictable files, and uses a strict native JSON
configuration format.

What it optimizes for:

- ⚡ **Lightweight runtime**: one Rust core service owns listeners, routing, TUN,
  system proxy, subscriptions, logs, and cleanup.
- 🧭 **Efficient control**: zero-argument TUI for humans, stable `--json` CLI
  reports for automation and Agents.
- 🤖 **Agent-friendly operations**: explicit command surfaces, stable issue
  codes, machine-readable diagnostics, and executable `next_actions`.
- 🖥️ **Cross-platform desktop target**: macOS and Windows are the primary
  supported platforms; Linux remains useful for development checks.

## Protocol Support

### Local Entry

| Type | TCP | UDP | Notes |
| --- | --- | --- | --- |
| SOCKS5 | ✅ | ✅ | TCP connect and UDP associate |
| HTTP CONNECT | ✅ | ❌ | Browser and system proxy friendly |
| Hybrid | ✅ | SOCKS | SOCKS5 and HTTP on one local port |
| TUN | ✅ | ✅ | Full-device routing with administrator/root privileges |

### Proxy Exit

| Type | TCP | UDP | Validation |
| --- | --- | --- | --- |
| Direct | ✅ | ✅ | Engineering tests |
| Block | 🚫 | 🚫 | Engineering tests |
| SOCKS | ✅ | ✅ | Engineering tests |
| HTTP CONNECT | ✅ | ❌ | Engineering tests |
| Shadowsocks | ✅ | ✅ | Engineering tests |
| Shadowsocks-2022 | ✅ | ✅ | Engineering tests |
| Trojan | ✅ | ✅ | Real-server validated |
| AnyTLS | ✅ | ✅ | Engineering tests |

### Future Protocols

| Type | Current status |
| --- | --- |
| VMess | Not supported yet |
| VLESS | Not supported yet |
| SSH | Not supported yet |

## Agent Index

| Need | Entry |
| --- | --- |
| Start interactive app | `cargo run --locked` |
| Start background service | `cargo run --locked -- start` |
| Stop background service | `cargo run --locked -- stop` |
| Machine status | `cargo run --locked -- status --json` |
| Full diagnostics | `cargo run --locked -- doctor --json` |
| Native config schema | `cargo run --locked -- config schema` |
| Validate config | `cargo run --locked -- check --config examples/config.json` |
| Public readiness audit | `./scripts/public-readiness-audit.sh` |
| Local validation gate | `./scripts/validate.sh` |
| Agent JSON contract | [`docs/agent-contract.md`](docs/agent-contract.md) |
| Release build | `cargo build --release` |
| macOS trial package | `./scripts/build-macos-release.sh` |
| Windows trial package | `./scripts/build-windows-release.sh` |

## Agent Contract

```yaml
project: TabbyMew
primary_targets:
  - macOS
  - Windows
development_target:
  - Linux
runtime_model:
  service: managed Rust core process
  human_ui: TUI
  automation_ui: CLI JSON
  internal_api: loopback Control API
config:
  format: strict JSON
  schema_version: 2
  unknown_fields: rejected
state_default_dir: ~/.tabbymew
release_binary: target/release/TabbyMew
agent_contract: docs/agent-contract.md
completion_gate:
  local: ./scripts/validate.sh
  release: cargo build --release
```

## Commands

```bash
# interactive TUI; starts or adopts the managed core service
cargo run --locked

# lifecycle
cargo run --locked -- start
cargo run --locked -- status --json
cargo run --locked -- wait service ready --json
cargo run --locked -- logs --lines 50
cargo run --locked -- stop

# routing
cargo run --locked -- mode rule --json
cargo run --locked -- mode global --json
cargo run --locked -- mode direct --json
cargo run --locked -- global direct --json
cargo run --locked -- groups --json

# runtime switches
cargo run --locked -- system-proxy status --json
cargo run --locked -- system-proxy on --json
cargo run --locked -- tun status --json
cargo run --locked -- tun on --json

# rules and subscriptions
cargo run --locked -- rules list --json
cargo run --locked -- subscription import-file local examples/clash-profile.yaml --json
cargo run --locked -- subscription list --json
cargo run --locked -- subscription update main --json

# diagnostics and cleanup
cargo run --locked -- doctor --json
cargo run --locked -- cleanup --json
```

## TUI Commands

```text
/status
/mode
/global
/groups
/rules
/subscriptions
/tun
/system-proxy
/doctor
/restart
```

```yaml
tui_exit:
  q: detach TUI after confirmation; core service keeps running
  ctrl_c: stop service after confirmation
```

## Config Schema

```yaml
native_config:
  format: json
  schema_version: 2
  root_fields:
    - schema_version
    - log
    - dns
    - inbounds
    - outbounds
    - policy_groups
    - route
    - services
  route_fields:
    - final
    - resolve_ip_cidr
    - rule_sets
    - rules
  service_fields:
    - control_api
```

```bash
cargo run --locked -- config schema
cargo run --locked -- check --config examples/config.json
cargo run --locked -- config normalize --config examples/config.json
```

## Capability Contract

```yaml
human_protocol_matrix: README.md#protocol-support
validation_records: docs/protocol-validation.md
native_config_type_values:
  inbounds:
    - socks
    - http
    - hybrid
    - tun
  outbounds:
    - direct
    - block
    - socks
    - http
    - shadowsocks
    - shadowsocks-2022
    - trojan
    - anytls
unsupported_protocols:
  runtime_placeholders: false
  future_directions:
    - vmess
    - vless
    - ssh
real_server_validated_outbounds:
  - trojan
```

## Routing

```yaml
route_modes:
  rule: custom rules first, then subscription/native rules, then route.final
  global: force selected global target
  direct: force direct outbound when available
route_targets:
  - outbound tag
  - policy group tag
policy_groups:
  type_supported:
    - select
  persisted_selection: true
rule_match_fields:
  - inbound
  - network
  - domain
  - domain_suffix
  - domain_keyword
  - domain_set
  - domain_suffix_set
  - domain_keyword_set
  - ip_cidr
  - ip_cidr_set
  - process_name
  - geoip
  - port
  - port_range
rule_sets:
  storage: local files
  example: examples/route-rule-sets.json
```

## State Files

```yaml
default_state_dir: ~/.tabbymew
files:
  config: ~/.tabbymew/tabbymew-config.json
  runtime_state: ~/.tabbymew/tabbymew-state.json
  preferences: ~/.tabbymew/tabbymew-preferences.json
  subscriptions: ~/.tabbymew/tabbymew-subscriptions.json
  logs: ~/.tabbymew/logs/
  generated_subscription_configs: ~/.tabbymew/profiles/subscriptions/
persisted_runtime_choices:
  - last activated subscription config
  - route mode
  - global target
  - policy group selections
  - LAN proxy switch
```

## Subscriptions And Import

```yaml
supported_inputs:
  share_links:
    - ss
    - trojan
    - anytls
  line_subscription:
    - plain text
    - base64
  yaml_import:
    format: Clash/Mihomo
    accepted_sections:
      - proxies
      - proxy-groups
      - rules
      - supported dns fields
generated_output:
  format: native TabbyMew JSON
  clash_mihomo_keys_in_native_config: rejected
```

```bash
cargo run --locked -- subscription import-file links examples/subscription-links.txt
cargo run --locked -- subscription import-file clash examples/clash-profile.yaml
cargo run --locked -- subscription add main 'https://example.com/subscription'
cargo run --locked -- subscription update main
cargo run --locked -- subscription list --json
```

Reference: [docs/clash-mihomo-migration.md](docs/clash-mihomo-migration.md)

## Control API

```yaml
scope: internal loopback API for CLI/TUI
default_listen: 127.0.0.1:9090
auth_header: X-TabbyMew-Control-Token
public_interface: no
```

```json
{
  "services": {
    "control_api": {
      "listen": "127.0.0.1:9090"
    }
  }
}
```

```yaml
read_only_endpoints:
  - GET /health
  - GET /config
  - GET /inbounds
  - GET /outbounds
  - GET /policy-groups
  - GET /rules
  - GET /counters
  - GET /control/api/subscriptions
  - GET /control/api/active-config
mutation_endpoints:
  - POST /control/api/mode
  - POST /control/api/global-target
  - POST /control/api/policy-groups/select
  - POST /control/api/tun
  - POST /control/api/system-proxy
  - POST /control/api/lan-proxy
```

## Validation

```bash
./scripts/validate.sh
```

```yaml
validate_sh_runs:
  - cargo fmt --all -- --check
  - cargo test --locked --all-targets --all-features -- --test-threads=1
  - cargo clippy --locked --all-targets --all-features -- -D warnings
  - cargo build --locked --release
  - example config checks
  - import checks
```

## Packaging

```bash
cargo build --release
./scripts/build-macos-release.sh
./scripts/build-windows-release.sh
```

```yaml
release_artifacts:
  local_binary: target/release/TabbyMew
  macos_binary: target/<macos-target>/release/TabbyMew
  windows_binary: target/<windows-target>/release/TabbyMew.exe
  windows_icon_resource: assets/app-icon.ico
  windows_tun_runtime_file: wintun.dll
  packaged_output_dir: target/release-artifacts/
```

Reference: [docs/install.md](docs/install.md)

## Examples

| File | Purpose |
| --- | --- |
| `examples/config.json` | minimal local hybrid proxy + direct route |
| `examples/auth-dns.json` | inbound auth + configured DNS |
| `examples/control-api.json` | explicit local Control API |
| `examples/http-outbound-auth.json` | authenticated HTTP CONNECT outbound |
| `examples/policy-groups.json` | selectable policy group |
| `examples/route-rules.json` | route matchers |
| `examples/route-resolve-ip-cidr.json` | DNS-backed IP CIDR matching |
| `examples/route-rule-sets.json` | local file-backed rule sets |
| `examples/tun.json` | TUN inbound |
| `examples/anytls-outbound.json` | AnyTLS outbound |
| `examples/clash-profile.yaml` | Clash/Mihomo import fixture |
| `examples/subscription-links.txt` | share-link import fixture |

## More Docs

```yaml
docs:
  cli: docs/cli.md
  install: docs/install.md
  fresh_machine_smoke: docs/fresh-machine-smoke.md
  platform_adapter: docs/platform.md
  protocol_validation: docs/protocol-validation.md
  release_checklist: docs/release-checklist.md
  changelog: CHANGELOG.md
  license: LICENSE
```
