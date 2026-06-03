#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

section() {
  printf '\n==> %s\n' "$*"
}

host_target() {
  rustc -vV | awk '/^host:/ {print $2}'
}

require_rust_target() {
  local target="$1"
  local host="$2"
  if [[ "$target" == "$host" ]]; then
    return 0
  fi
  if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup is required to verify cross target $target" >&2
    exit 1
  fi
  if ! rustup target list --installed | grep -qx "$target"; then
    echo "missing Rust target: $target" >&2
    echo "install it with: rustup target add $target" >&2
    exit 1
  fi
}

host="$(host_target)"
if [[ "$host" == *"-apple-darwin" ]]; then
  default_target="$host"
else
  default_target="aarch64-apple-darwin"
fi
target="${TABBYMEW_MACOS_TARGET:-$default_target}"
binary="target/${target}/release/TabbyMew"

section "Checking macOS Rust target"
if [[ "$target" != *"-apple-darwin" ]]; then
  echo "target does not look like macOS: $target" >&2
  exit 1
fi
require_rust_target "$target" "$host"

section "Building macOS release executable"
cargo build --release --locked --target "$target"

section "Packaging macOS release artifact"
./scripts/release-artifact.sh macos "$target" "$binary" TabbyMew
