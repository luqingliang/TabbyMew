# Changelog

All notable user-facing changes should be recorded here before tagging a release.

TabbyMew uses SemVer-style `MAJOR.MINOR.PATCH` versions. Before `1.0.0`, minor versions may include compatibility changes; patch versions are reserved for fixes, documentation, tests, and release process updates.

The public changelog starts from the public repository migration. Work completed
before the migration is treated as the initial project baseline and is not
relisted in release notes.

## [Unreleased]

### Added

- Add persistent CLI/TUI controls for user-login autostart, disabled by default.
- Restore saved TUN and system proxy preferences when the background service starts.

## [0.1.23] - 2026-06-08

### Added

- Add proxied upload and download traffic counters to the runtime control API and CLI/TUI status surfaces.

### Changed

- Show proxied traffic in the wide TUI dashboard by merging runtime route final and global target details into one `Routing` row.

### Fixed

- Limit `open_fd_count` to Unix builds so Windows release builds do not warn about an unused non-Unix stub.

## [0.1.22] - 2026-06-07

### Changed

- Improve TUN sleep/wake recovery by waiting for a stable network state before restarting the TUN runtime.
- Add runtime resource telemetry around TUN recovery to make file descriptor and helper state easier to diagnose.

### Fixed

- Fix TUN recovery resource cleanup so repeated sleep/wake cycles do not leak runtime listeners or helper state.
- Fix `status --json` service reporting so healthy managed runtimes are not reported as stale.

## [0.1.21] - 2026-06-05

### Changed

- Reuse macOS system proxy authorization within a single TabbyMew runtime session to avoid repeated prompts.
- Use a session-scoped privileged TUN helper so TUN start and stop can reuse the same per-run authorization.
- Shut down the privileged TUN helper during runtime cleanup to avoid helper residue after exit.

### Fixed

- Fix cross-platform permission imports for Linux CI builds.
- Fix the TUN helper task handle import so test builds compile cleanly.

## [0.1.2] - 2026-06-05

### Added

- Add `subscription import-file` CLI support for importing and saving local subscription files.
- Add the TabbyMew application icon to the README.
- Embed the application icon in formal Windows release executables.
- Add an Agent Contract document for stable CLI/JSON automation surfaces.

### Changed

- Refine CLI, TUI, runtime, and service command module boundaries while preserving the public command behavior.
- Windows release packaging now verifies executable icon resources before producing the archive.

### Removed

- Remove the standalone `import` CLI command.
- Remove the Linux release packaging script from the formal release surface; macOS and Windows remain the release artifact targets.

## [0.1.1] - 2026-06-04

### Added

- Add Subscription in the TUI now accepts either a remote subscription URL or a local file path.
- Release notes generation from the matching `CHANGELOG.md` version section for future formal GitHub Releases.

### Changed

- New subscription imports now automatically become active when they are the only configured subscription.
- Add Subscription URL/File input rendering now keeps entered content visible in narrow TUI layouts.
- Release checklist now requires finalized changelog notes before tagging.

### Fixed

- Generated subscription profiles now keep the native DNS schema expected by the runtime.
- Command Palette Enter now always executes the selected command list item instead of an exact command name typed in the search field.

## [0.1.0] - 2026-06-03

### Added

- Public GitHub repository baseline after migration.
- Automated GitHub Release workflow for `main` snapshots and formal `v*` tags.
- Formal release version guard that requires the pushed tag to match the version in `Cargo.toml`.
- macOS and Windows release archives with generated manifests and SHA-256 checksums.

### Changed

- Release workflow official actions now use Node.js 24-compatible versions.
- Formal release assets are limited to macOS and Windows; Linux packaging remains available for development and CI-adjacent checks.
- Release gate now targets the `main` branch and the GitHub `Release` workflow.
- Release checklist now documents the automated snapshot and formal release flow.

### Removed

- Removed the redundant `scripts/smoke.sh` compatibility alias; release gate now calls `scripts/validate.sh` directly.
