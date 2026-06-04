# Public Repository Readiness

This checklist is the public-release gate for repository visibility changes.
Run it before making the GitHub repository public and before every public
release.

## Required Gate

```bash
./scripts/public-readiness-audit.sh
./scripts/validate.sh
cargo build --release
```

The audit checks the current working tree for common high-risk credential
signatures:

- GitHub, GitLab, Slack, OpenAI-style, AWS, and Google API tokens
- private key PEM headers
- secret-looking placeholders in public README, docs, and examples

The validation and release build confirm that public-facing examples, docs, and
code changes still compile and test locally.

Public docs and examples must not contain real subscription URLs, real proxy
servers, private node names, personal paths, access tokens, or reusable
credentials. Example credentials should use obvious `example-*` placeholders.

## History Policy

For a repository visibility migration, publish from a clean working tree in the
new public repository. Do not copy local runtime state, logs, generated
subscription profiles, or previous private-repository Git history.

Regex-based scans are not a cryptographic guarantee that the tree is clean. If
this repository has ever contained production credentials, rotate them before
publishing even if the audit passes.

## Public-Facing Repository Shape

Before making the repository public, keep these files aligned:

- `LICENSE`
- `README.md`
- `README.zh-CN.md`
- `docs/agent-contract.md`
- `docs/cli.md`
- `docs/install.md`
- `docs/protocol-validation.md`
- `docs/release-checklist.md`
- `examples/`
- `scripts/release-artifact.sh`

Release artifacts must not include local state under `~/.tabbymew/`, logs,
subscription stores, generated subscription configs, `.env` files, private
keys, or user-specific paths.
