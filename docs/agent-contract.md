# Agent Contract

TabbyMew is designed to be controlled by agents through deterministic CLI
commands. The TUI is for humans; agents should prefer the standard CLI and JSON
reports.

## Stable Surfaces

- `TabbyMew status --json`: fast health check for service, Control API, cleanup
  state, and actionable recovery commands.
- `TabbyMew doctor --json`: full diagnostic report for lifecycle, Control API,
  system proxy, TUN, routing, and subscription health.
- `TabbyMew cleanup --json`: conservative cleanup gate for TabbyMew-owned stale
  files and TabbyMew-matching system proxy residue.
- `TabbyMew wait ... --json`: bounded polling for service, TUN, and system proxy
  state.
- Runtime controls with `--json`: `mode`, `global`, `groups`, `tun`,
  `system-proxy`, `rules`, and `subscription`.
- `TabbyMew autostart ... --json`: persistent user-login autostart switch and
  platform entry status.

## JSON Rules

First-class JSON reports must keep these fields stable once published:

- `schema_version`
- `ok`
- `status` or a command-specific stable state field
- `message` where the report represents one operation
- `error_code` for command-specific failures
- `issues[].code`
- `issues[].severity`
- `issues[].message`
- `next_actions[].code`
- `next_actions[].commands`
- `next_actions[].description`

Fields may be added without bumping `schema_version`. Existing stable fields
must not be renamed, removed, or change type without bumping `schema_version`.

Agents should treat human text as diagnostic context only. Prefer
`schema_version`, `ok`, `status`, `error_code`, `issues[].code`, and
`next_actions[].commands` for automation.

## Command Execution

Commands in `next_actions[].commands` are argv arrays. Agents should execute
them without shell parsing.

When a report is tied to a specific state directory, generated actions include
`--state-dir` so the follow-up command targets the same TabbyMew instance.

The loopback Control API is internal product infrastructure for CLI/TUI and
diagnostics. Agents should use the CLI contract unless a task explicitly
requires a raw Control API query.
