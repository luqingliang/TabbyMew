#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

high_risk_current="$(mktemp)"
public_dummy_secrets="$(mktemp)"
trap 'rm -f "$high_risk_current" "$public_dummy_secrets"' EXIT

rg -n -i \
  -e 'ghp_[A-Za-z0-9_]{20,}' \
  -e 'github_pat_[A-Za-z0-9_]{20,}' \
  -e 'glpat-[A-Za-z0-9_-]{20,}' \
  -e 'xox[baprs]-[A-Za-z0-9-]{20,}' \
  -e 'sk-[A-Za-z0-9]{20,}' \
  -e 'AKIA[0-9A-Z]{16}' \
  -e 'AIza[0-9A-Za-z_-]{35}' \
  -e '-----BEGIN PRIVATE KEY-----' \
  -e '-----BEGIN RSA PRIVATE KEY-----' \
  -e '-----BEGIN OPENSSH PRIVATE KEY-----' \
  --glob '!target/**' \
  --glob '!Cargo.lock' \
  --glob '!scripts/public-readiness-audit.sh' \
  > "$high_risk_current" || true

rg -n \
  -e 'token=secret' \
  -e 'password: secret' \
  -e 'password: pass' \
  -e 'trojan://secret@' \
  -e 'anytls://secret@' \
  README.md README.zh-CN.md docs examples \
  > "$public_dummy_secrets" || true

failed=0

if [[ -s "$high_risk_current" ]]; then
  echo "Unclassified high-risk signatures in current files:" >&2
  cat "$high_risk_current" >&2
  failed=1
fi

if [[ -s "$public_dummy_secrets" ]]; then
  echo "Secret-looking placeholders in public docs/examples:" >&2
  cat "$public_dummy_secrets" >&2
  failed=1
fi

if [[ "$failed" -ne 0 ]]; then
  echo "public-readiness audit failed" >&2
  exit 1
fi

echo "public-readiness audit passed"
