# CLI Command Matrix

TabbyMew treats CLI/TUI as the primary user surface. Commands should stay
stable enough for humans, scripts, launch managers, and automation.

## Automation JSON Contract

Commands that document JSON support are safe for automation to call repeatedly.
Additive fields may appear over time, but existing stable fields should not be
renamed or removed without bumping `schema_version`.

The canonical agent-facing contract is maintained in
[`docs/agent-contract.md`](agent-contract.md). This command matrix documents the
current command surface that implements that contract.

Stable fields shared by first-class JSON reports:

- `schema_version`: integer contract version for the report shape.
- `ok`: boolean operation or diagnostic result where available.
- `status` / `message`: compact human-readable state where available.
- `error_code`: stable machine-readable failure code on command-specific
  errors.
- `issues`: machine-readable diagnostics, each with `code`, `severity`, and
  `message`. Warnings may appear even when `ok` is true.
- `next_actions`: executable suggestions for automation. Each action has a stable
  `code`, a human `description`, and ordered `commands`; each command is an
  argv array and should be executed without shell parsing. When the report is
  tied to a known state directory, suggested commands include that
  `--state-dir` so automation acts on the same service instance.

`TabbyMew status --json` is the fast health check. It reports service state,
control API health, cleanup requirements, heartbeat freshness, issue codes, and
safe next actions.

`TabbyMew doctor --json` is the full diagnostic entry point. It covers service
lifecycle, stale runtime state, cleanup candidates, control API reachability,
system proxy ownership, TUN runtime/permission/route state, routing, and
subscription update failures. Automation should prefer `issues[].code` and
`next_actions[].commands` over parsing `recommendations`.

`TabbyMew cleanup --json` is the conservative residue cleanup gate. It only
removes TabbyMew-owned stale files or TabbyMew-matching system proxy residue and
reports remaining issues plus next actions if cleanup cannot complete.

## Interactive

| Command | Purpose | JSON |
| --- | --- | --- |
| `TabbyMew` | Open the TUI and start or adopt the managed core service | no |
| `TabbyMew shell` | Open the TUI with explicit shell options | no |

Inside the TUI, `/` opens the command palette, `/status` returns to the runtime
dashboard, `q` detaches the TUI after confirmation, and `Ctrl+C` stops the
service after confirmation.

## Lifecycle and Diagnostics

| Command | Purpose | JSON |
| --- | --- | --- |
| `TabbyMew start` | Start a background core service and write a state file | yes |
| `TabbyMew stop` | Stop a background core service from state or PID | yes |
| `TabbyMew status` | Show service state and local control API health | yes |
| `TabbyMew wait service ready|stopped` | Wait for service readiness or stopped/clean state | yes |
| `TabbyMew wait tun on|off` | Wait for TUN runtime state | yes |
| `TabbyMew wait system-proxy on|off` | Wait for TabbyMew-managed system proxy state | yes |
| `TabbyMew doctor` | Diagnose lifecycle, cleanup, control API, TUN, system proxy, and routing state | yes |
| `TabbyMew cleanup` | Clean stale TabbyMew-owned runtime state and TabbyMew-matching system proxy residue | yes |
| `TabbyMew logs` | Read or follow the current background log | yes |
| `TabbyMew autostart [status|on|off|toggle]` | Get or switch user login autostart | yes |

## Runtime Controls

| Command | Purpose | JSON |
| --- | --- | --- |
| `TabbyMew mode [rule|global|direct]` | Get or set runtime route mode | yes |
| `TabbyMew global [target]` | Get or set the global-mode outbound target | yes |
| `TabbyMew groups [group] [outbound]` | List policy groups, inspect a group, or select a group outbound | yes |
| `TabbyMew tun [status|on|off|toggle]` | Get or switch TUN mode | yes |
| `TabbyMew system-proxy [status|on|off|toggle]` | Get or switch OS system proxy | yes |

All runtime controls accept `--listen`, `--state-dir`, and `--timeout-ms`.
`TabbyMew tun status` also reports TUN diagnostics such as auto-route, IPv6,
DNS mode/address, bypass counts, proxy bypass sources, privilege detection,
the captured egress interface when auto-route is running, and watchdog restart
history after sleep/wake recovery. The TUN watchdog also records whether TUN
is still desired after an unexpected listener exit, and can recover from
sleep/wake gaps or outbound egress binding drift.

## Login Autostart

TabbyMew never enables autostart by default. The saved switch lives in the
runtime preferences file under the selected state directory and defaults to
off:

```bash
TabbyMew autostart status
TabbyMew autostart on
TabbyMew autostart off
TabbyMew autostart toggle
```

`autostart on` validates the selected config, saves it as the active config,
persists the switch, and writes a user-login startup entry that runs
`TabbyMew start --state-dir <state-dir>`. `autostart off` removes that entry and
persists the switch as off. TUI users can run `/autostart
[status|on|off|toggle]`, `/autostart-on`, or `/autostart-off`.

Autostart restores the saved runtime preferences from the selected state
directory: active config, route mode, global outbound, policy group selections,
LAN proxy, TUN, and system proxy. On shutdown TabbyMew still cleans up live OS
state such as TUN listeners and the current system proxy target, but it keeps
the saved user intent so the next login/start can restore it. TUN restoration
may still require the normal macOS administrator authorization or Windows
Administrator approval.

Platform backends are per-user login entries on the supported desktop targets:
macOS LaunchAgent and Windows
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Linux is a development
environment only; `autostart status` reports it as unsupported there.

## Cleanup and Doctor Contract

`TabbyMew cleanup --json` reports both the full service state and compact
`before_summary` / `after_summary` objects. Cleanup actions include stable
`error_code` values when they fail, so automation does not need to parse human
text.

Cleanup is intentionally conservative:

- stale managed/runtime state files are removed only when their recorded
  process is not running
- recorded TabbyMew system proxy ownership is cleared when the service is no
  longer running
- if the ownership record was lost, cleanup may use the recorded active config
  to disable a system proxy only when the OS proxy exactly matches that
  TabbyMew local HTTP/SOCKS target
- unrelated system proxy targets are left untouched

`TabbyMew doctor --json` reports cleanup issues with actionable error codes
such as `stale_state_file`, `stale_runtime_state_file`,
`managed_system_proxy_residue`, and `system_proxy_unrecorded_residue`.
TUN stability diagnostics use error codes such as `tun_listener_stopped`,
`tun_egress_binding_missing`, and `tun_egress_binding_drift`.

## Routing Rules

| Command | Purpose | JSON |
| --- | --- | --- |
| `TabbyMew rules list` | List effective route rules | yes |
| `TabbyMew rules add` | Add a custom route rule | yes |
| `TabbyMew rules edit` | Edit a custom route rule | yes |
| `TabbyMew rules remove` | Remove a custom route rule | yes |
| `TabbyMew rules reload` | Reload route rules from disk/runtime state | yes |
| `TabbyMew rules test` | Test which route/outbound a destination uses | yes |

The TUI intentionally keeps route-test out of the command palette; it remains a
standard CLI/API diagnostic.

## Config and Subscriptions

| Command | Purpose | JSON |
| --- | --- | --- |
| `TabbyMew check` | Validate the selected config without starting listeners | yes |
| `TabbyMew config schema` | Print the native config schema contract | always |
| `TabbyMew config normalize` | Print stable pretty JSON with secrets redacted by default | no |
| `TabbyMew subscription add` | Fetch, import, validate, and save a remote subscription | yes |
| `TabbyMew subscription import-file` | Import, validate, and save a local subscription file | yes |
| `TabbyMew subscription list` | List saved subscriptions | yes |
| `TabbyMew subscription update` | Update one or all saved remote subscriptions | yes |
| `TabbyMew subscription set` | Update saved subscription settings | yes |
| `TabbyMew subscription remove` | Remove a saved subscription entry | yes |

## Control API

| Command | Purpose | JSON |
| --- | --- | --- |
| `TabbyMew api get <path>` | Query a read-only local control API endpoint | always |

The Control API is loopback-only product infrastructure for CLI/TUI and
diagnostics. It should not become the primary user interface.
