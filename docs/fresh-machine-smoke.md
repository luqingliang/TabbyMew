# Fresh-Machine Smoke Checklist

Use this checklist before publishing a release archive for a platform. Do not
use real subscription URLs, tokens, passwords, UUIDs, private keys, or public
test servers in committed notes.

## Common Checks

- Extract the archive under a temporary directory.
- Confirm `MANIFEST.txt` lists only the executable, required platform runtime
  files, docs, and examples.
- Run `TabbyMew --help`.
- Run `TabbyMew check --config examples/config.json`.
- Start the zero-argument TUI, open `/status`, press `q` twice, and confirm the
  core service keeps running.
- Reopen the TUI, press `Ctrl+C` twice, and confirm the core service stops.
- Run `TabbyMew start`, `TabbyMew wait service ready`, `TabbyMew status --json`,
  `TabbyMew logs --lines 20`, and `TabbyMew stop`.
- Run `TabbyMew cleanup --json` and `TabbyMew doctor --json`.
- Inspect logs for secrets and unexpected repeated warnings.
- Confirm no TabbyMew-owned runtime state remains except intentional logs,
  preferences, subscription stores, and generated profiles.

## macOS

- Confirm the binary starts without quarantine or document the local quarantine
  removal step used by the tester.
- Enable System Proxy from CLI or TUI, confirm macOS proxy state points at the
  local TabbyMew listener, then disable it and confirm previous unmanaged proxy
  settings were not modified.
- Enable TUN only from a session where administrator authorization is expected.
- With TUN on, verify browser traffic and terminal traffic can reach both a
  direct domestic site and a proxied remote site.
- Put the machine to sleep, wake it, and confirm TUN either continues to work
  or watchdog recovery is logged.
- Stop TabbyMew and confirm no TabbyMew-owned proxy, DNS, route, or TUN state
  remains.

## Linux

- Confirm the binary runs on the target distro and architecture.
- Run the background service lifecycle commands from a normal user shell.
- If testing TUN, run from a root-capable session and confirm permission errors
  are explicit when privileges are missing.
- With TUN on, verify browser traffic and terminal traffic can reach both a
  direct domestic site and a proxied remote site.
- Stop TabbyMew and confirm no TabbyMew-owned route, DNS, or TUN state remains.
- Optional launch-manager recipes must be disabled by default and removable
  without leaving a running TabbyMew process.

## Windows

- Confirm `TabbyMew.exe --help` runs from PowerShell.
- Run the background service lifecycle commands from a normal user PowerShell.
- Enable System Proxy from CLI or TUI, confirm Windows proxy state points at the
  local TabbyMew listener using a loopback address, then disable it and confirm
  previous unmanaged proxy settings were not modified.
- If testing TUN, run from an elevated session and confirm permission errors are
  explicit when privileges are missing.
- Stop TabbyMew and confirm no TabbyMew-owned proxy, DNS, route, or TUN state
  remains.
