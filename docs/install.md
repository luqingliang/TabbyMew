# Install and Packaging

TabbyMew is distributed as the executable plus minimum runtime support files,
CLI/install documentation, and example configs. Release archives are built under
`target/release-artifacts/` and do not include local runtime state, logs,
subscription stores, control tokens, or secrets.

## Build Primary Desktop Platforms

Windows and macOS are the primary desktop targets:

```bash
./scripts/build-macos-release.sh
./scripts/build-windows-release.sh
```

These scripts build with `cargo build --release --locked --target <triple>` and
then writes:

- `target/release-artifacts/tabbymew-<version>-<target>/`
- `target/release-artifacts/tabbymew-<version>-<target>.tar.gz`
- `target/release-artifacts/tabbymew-<version>-<target>.tar.gz.sha256`

Cross builds are opt-in through target variables:

```bash
TABBYMEW_MACOS_TARGET=aarch64-apple-darwin ./scripts/build-macos-release.sh
TABBYMEW_WINDOWS_TARGET=x86_64-pc-windows-gnu ./scripts/build-windows-release.sh
```

If the Rust target or linker is missing, the script fails before packaging and
prints the install command or missing tool.

## Archive Contents

Every archive contains only the files needed to install, inspect, and run sample
configurations:

- `TabbyMew` or `TabbyMew.exe`
- `wintun.dll` in Windows archives, required by TUN mode
- `LICENSE`
- `licenses/WINTUN-PREBUILT-BINARIES-LICENSE.txt` in Windows archives when
  `wintun.dll` is included
- `MANIFEST.txt`
- `docs/cli.md`
- `docs/install.md`
- `examples/`

Human-oriented project overview, changelog, release checklist, smoke checklist,
protocol validation notes, and migration notes stay in the Git repository and
are not copied into release archives.

Every archive explicitly excludes:

- `~/.tabbymew/` runtime state
- runtime logs
- Cargo build cache and incremental files
- Git metadata
- subscription URLs, tokens, passwords, UUIDs, and private keys

## Manual Install

Extract the archive and place the executable somewhere on `PATH`.

macOS/Linux:

```bash
tar -xzf target/release-artifacts/tabbymew-<version>-<target>.tar.gz
mkdir -p ~/.local/bin
install -m 0755 tabbymew-<version>-<target>/TabbyMew ~/.local/bin/TabbyMew
TabbyMew --help
```

Windows PowerShell:

```powershell
tar -xzf target\release-artifacts\tabbymew-<version>-<target>.tar.gz
.\tabbymew-<version>-<target>\TabbyMew.exe --help
```

For Windows TUN mode, keep `wintun.dll` next to `TabbyMew.exe`. TabbyMew can
start normally; enabling TUN launches a privileged helper and asks for
Administrator approval so Windows can create the Wintun adapter. Windows
archives also include `licenses/WINTUN-PREBUILT-BINARIES-LICENSE.txt` for that
runtime DLL.

When TUN auto-route starts on macOS or Windows, TabbyMew captures the pre-TUN
egress interface. On Windows it also records the interface source address.
TabbyMew binds its own outbound TCP/UDP sockets to that egress path to avoid
looping direct or proxy-server connections back into TUN.
While that binding is active, TabbyMew also avoids OS DNS for its own outbound
direct-target resolution and uses controlled UDP DNS sockets so virtual DNS
responses are not fed back into direct connections. Configured DNS servers are
added to the TUN bypass list, and TUN virtual DNS addresses are rejected if they
still leak into TabbyMew's own resolver path. Proxy server names keep the normal
resolver path so their addresses stay aligned with the TUN bypass list.

## Startup Modes

Zero-argument startup opens the interactive TUI and starts or adopts the managed
core service:

```bash
TabbyMew
```

Inside the TUI, `q` closes only the TUI after confirmation and leaves the core
service running. `Ctrl+C` stops the service after confirmation. Use
`TabbyMew stop` from another shell when a detached service should be stopped.

Background service mode is explicit:

```bash
TabbyMew start
TabbyMew wait service ready
TabbyMew status --json
TabbyMew logs --lines 50
TabbyMew stop
```

TabbyMew does not install auto-start entries by default. LaunchAgent, systemd,
or scheduled-task recipes should stay optional and must call normal CLI
commands such as `TabbyMew start` and `TabbyMew stop`.

## Cleanup and Rollback

TabbyMew-owned runtime files live under `~/.tabbymew/` on Unix-like systems or
`%APPDATA%\TabbyMew` on Windows unless `--state-dir` or `TABBYMEW_STATE_DIR`
is set.

Use these commands before uninstalling or after an interrupted run:

```bash
TabbyMew stop
TabbyMew cleanup --json
TabbyMew doctor --json
```

`cleanup` only removes TabbyMew-owned stale runtime state and managed system
proxy state. It must not disable unrelated user proxy settings.
