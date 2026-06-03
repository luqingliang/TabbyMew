#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

section() {
  printf '\n==> %s\n' "$*"
}

run() {
  section "$*"
  "$@"
}

test_threads="${TABBYMEW_TEST_THREADS:-1}"

run cargo fmt --all -- --check
run cargo test --locked --all-targets --all-features -- --test-threads="$test_threads"
run cargo clippy --locked --all-targets --all-features -- -D warnings
run cargo build --locked --release

shopt -s nullglob
configs=(examples/*.json)
if ((${#configs[@]} == 0)); then
  echo "no example configs found under examples/" >&2
  exit 1
fi

for config in "${configs[@]}"; do
  run cargo run --locked -- check --config "$config"
done

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

run cargo run --locked -- import --input examples/subscription-links.txt --output "$tmpdir/imported-links.json"
run cargo run --locked -- check --config "$tmpdir/imported-links.json"
run cargo run --locked -- import --input examples/clash-profile.yaml --output "$tmpdir/imported-clash.json"
run cargo run --locked -- check --config "$tmpdir/imported-clash.json"
run cargo run --locked -- config normalize --config "$tmpdir/imported-clash.json" --output "$tmpdir/imported-clash.redacted.json"
run cargo run --locked -- config normalize --config "$tmpdir/imported-clash.json" --show-secrets --output "$tmpdir/imported-clash.full.json"

unsupported_configs=()
if [[ -d examples/unsupported ]]; then
  for config in examples/unsupported/*.json; do
    [[ -e "$config" ]] || continue
    unsupported_configs+=("$config")
  done
fi

if ((${#unsupported_configs[@]} > 0)); then
  for config in "${unsupported_configs[@]}"; do
    section "cargo run --locked -- check --config $config (expected failure)"
    if cargo run --locked -- check --config "$config"; then
      echo "unsupported example unexpectedly passed: $config" >&2
      exit 1
    fi
  done
fi
