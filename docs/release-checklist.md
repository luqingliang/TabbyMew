# Release Checklist

This checklist is the release candidate gate for TabbyMew. Do not create a tagged release until every required item passes or is explicitly recorded as a known limitation.

## 1. Candidate Preparation

- Start from `main` with a clean worktree.
- Confirm `Cargo.toml` has the intended version.
- Update `CHANGELOG.md` for user-visible changes, compatibility notes, and known limitations. Formal release notes are generated from the matching changelog version section.
- Confirm the README support matrix matches the implementation.
- Confirm examples still avoid real endpoints and real secrets.
- Run `./scripts/public-readiness-audit.sh` before changing repository visibility or cutting a public release.

Version rules before `1.0.0`:

- Patch bump: bug fixes, test coverage, documentation, and release process changes.
- Minor bump: new inbound/outbound types, new config fields, protocol behavior changes, or compatibility changes.
- Major bump: reserved until the project declares a stable `1.0.0` contract.

## 2. Automated Smoke Gate

For release candidates, run the full release gate:

```bash
./scripts/release-gate.sh
```

The release gate requires a clean `main` worktree, an authenticated `gh` CLI,
`sing-box`, Xray, and v2ray-core. It checks that the GitHub `Release` workflow
passed for the exact `HEAD` commit, records available real-server
implementations, runs the local validation suite, and runs real-server
interoperability scripts. The current accepted real-server record only covers
Trojan; other protocols still need fresh recorded runs before they can be
described as real-server validated.

For local development, the validation suite can be run on its own:

```bash
./scripts/validate.sh
```

The script runs formatting checks, all tests with one test thread, clippy with
warnings denied, release build, validation for every `examples/*.json` config,
and subscription import checks. Platform packaging is a separate gate.

TUN smoke is intentionally separate from the default release gate because it
can change system routes/DNS. Run it only from a machine/session where
administrator or root permission is expected:

```bash
TABBYMEW_TUN_SMOKE=1 TABBYMEW_TUN_SMOKE_CONFIG=/path/to/tun-config.json ./scripts/tun-smoke.sh
```

On Windows shells, also set `TABBYMEW_TUN_SMOKE_ADMIN_CONFIRMED=1` after
confirming the shell is elevated.

CI must pass on the exact release commit. If CI fails before Rust checks start, rerun once and record the runner-side failure. If a Rust check fails, fix it before tagging. Do not bypass the release gate for a tagged release.

## 3. Real-Server Interop Gate

Run protocol interoperability against real server implementations such as sing-box, Xray, v2ray-core, or a Shadowsocks server. The local deterministic mocks in CI are not a substitute for this gate. At the moment, only Trojan has accepted real-server validation records; every other implemented protocol is considered engineering-tested until a fresh real-server run is recorded in `docs/protocol-validation.md`.

First record the available server implementations:

```bash
./scripts/interop-env.sh
```

Run the sing-box localhost interop suite:

```bash
./scripts/interop-sing-box.sh
```

Run the Xray localhost interop suite:

```bash
./scripts/interop-xray.sh
```

Run the v2ray-core localhost interop suite:

```bash
./scripts/interop-v2ray.sh
```

All four commands are included in `./scripts/release-gate.sh`; run them directly only when debugging interop failures.

Minimum release matrix to satisfy before claiming full protocol validation:

| Protocol | Current accepted status | Server implementation | Required TCP | Required UDP | Required notes |
| --- | --- | --- | --- | --- | --- |
| Trojan over TLS | Real-server validated | sing-box, Xray, or v2ray-core | Pass | Pass | TCP command, UDP associate, and large UDP payload behavior. |
| Shadowsocks | Engineering tests only | sing-box or Shadowsocks server | Pass | Pass | At least `aes-128-gcm`. |
| Shadowsocks 2022 | Engineering tests only | sing-box or Shadowsocks server | Pass | Pass | At least `2022-blake3-aes-128-gcm`. |
| AnyTLS | Engineering tests only | sing-box | Pass | Pass | TCP stream, UoT v2 UDP, idle session reuse, and padding-scheme update handling. |

Use localhost or private test endpoints. Public endpoints, passwords, private keys, and tokens must not be committed. Record implementation, version, transport, method/security, destination family, TCP result, UDP result, date, and notes in `docs/protocol-validation.md`.

## 4. Manual Runtime Checks

- Start `examples/config.json` and test local hybrid inbound with a SOCKS5 TCP request.
- Start `examples/auth-dns.json` and verify Basic auth and configured DNS behavior.
- Test SOCKS5 UDP associate through at least one UDP-capable outbound.
- If a release claims TUN support for a platform, run the TUN example on that platform with the required privileges.
- Check logs for secrets. Passwords must not appear in startup summaries or validation reports.
- Run the relevant fresh-machine smoke checklist in `docs/fresh-machine-smoke.md`.
- Confirm the release archive under `target/release-artifacts/` contains only
  the executable, required platform runtime files such as Windows `wintun.dll`,
  `LICENSE`, any required third-party license files such as
  `licenses/WINTUN-PREBUILT-BINARIES-LICENSE.txt`, `MANIFEST.txt`,
  `docs/cli.md`, `docs/install.md`, and `examples/`; it must not include local
  state, logs, Git metadata,
  subscription URLs, tokens, passwords, UUIDs, or private keys.

## 5. Platform Packaging

Build primary desktop platform artifacts under `target/release-artifacts/`:

```bash
./scripts/build-macos-release.sh
./scripts/build-windows-release.sh
```

Each script writes a staged directory, `.tar.gz` archive, and `.sha256`
checksum. Cross-target builds are opt-in through `TABBYMEW_MACOS_TARGET` and
`TABBYMEW_WINDOWS_TARGET`. The Windows packaging script also verifies that the
release executable has a PE resource section for the application icon.

## 6. Tagging

After all gates pass:

```bash
git status --short
./scripts/check-release-version.sh vX.Y.Z
./scripts/release-notes.sh vX.Y.Z
git tag -a vX.Y.Z -m "TabbyMew X.Y.Z"
git push origin main --tags
```

Do not tag from a dirty worktree. Do not tag a commit whose GitHub `Release`
workflow result is pending or failed. Do not leave the matching changelog
section marked `Unreleased`; `scripts/release-notes.sh` fails formal release
publishing when the version section is missing, empty, or still unreleased.

## 7. GitHub Release Automation

The GitHub `Release` workflow publishes two kinds of releases:

- Every successful push to `main` replaces the moving `snapshot-main`
  prerelease and uploads macOS and Windows archives plus `.sha256` checksums.
- Every pushed `vX.Y.Z` tag creates a formal GitHub Release. The tag must match
  the version in `Cargo.toml`; `scripts/check-release-version.sh` enforces this
  before publishing. The Release body is generated from the matching
  `CHANGELOG.md` section by `scripts/release-notes.sh`.

Formal release assets are built with the same platform scripts used locally:

```bash
./scripts/build-macos-release.sh
./scripts/build-windows-release.sh
```

The workflow uses `scripts/release-artifact.sh`, so Release assets follow the
same contents policy as local archives and exclude runtime state, logs, Git
metadata, subscription secrets, private keys, and build cache files.
