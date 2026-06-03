# Platform Adapter

Platform capability decisions live in `src/platform.rs`.

Keep platform checks there when the decision affects shared behavior, status
output, diagnostics, or runtime configuration. Keep `#[cfg(...)]` inside the
actual platform implementation files when the code calls OS-specific APIs.

## Desktop Targets

TabbyMew currently targets Windows and macOS as first-class desktop platforms.
Linux remains useful for development and tests, but Linux system proxy support
is not implemented yet.

| Capability | Windows | macOS | Linux |
| --- | --- | --- | --- |
| System Proxy | yes | yes | no |
| TUN inbound | yes | yes | yes |
| TUN privileged helper | yes | yes | no |
| TUN egress binding | yes | yes | no |
| TUN packet information | no | yes | no |
| `wintun.dll` runtime file | yes | no | no |

## Rules

- Use `platform::name()` for status snapshots and diagnostics.
- Use `platform::default_state_dir()` for default state location.
- Use `platform::system_proxy_supported()` before exposing System Proxy as a
  supported feature.
- Use `platform::tun_*` helpers for TUN capability, privilege, packet
  information, and egress binding decisions.
- Do not duplicate platform capability strings in Web, TUI, CLI, or runtime
  code.
