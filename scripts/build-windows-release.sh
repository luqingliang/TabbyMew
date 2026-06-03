#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

section() {
  printf '\n==> %s\n' "$*"
}

host_target() {
  rustc -vV | awk '/^host:/ {print $2}'
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
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

windows_arch_dir() {
  local target="$1"
  case "$target" in
    x86_64-*-windows-*) echo "amd64" ;;
    i686-*-windows-* | i586-*-windows-*) echo "x86" ;;
    aarch64-*-windows-*) echo "arm64" ;;
    arm*-*-windows-*) echo "arm" ;;
    *)
      echo "unsupported Windows target architecture for Wintun: $target" >&2
      exit 1
      ;;
  esac
}

find_registry_wintun_dll() {
  local arch_dir="$1"
  local cargo_home="${CARGO_HOME:-$HOME/.cargo}"
  local registry_src="${cargo_home}/registry/src"

  if [[ ! -d "$registry_src" ]]; then
    return 0
  fi

  find "$registry_src" \
    -path "*/wintun-bindings-*/wintun/bin/${arch_dir}/wintun.dll" \
    -type f 2>/dev/null \
    | LC_ALL=C sort \
    | tail -n1
}

stage_wintun_dll() {
  local target="$1"
  local binary="$2"
  local binary_dir
  binary_dir="$(dirname "$binary")"
  local dst="${binary_dir}/wintun.dll"

  if [[ -f "$dst" ]]; then
    echo "wintun.dll already staged: $dst"
    return 0
  fi

  local src="${binary_dir}/examples/wintun.dll"
  if [[ ! -f "$src" ]]; then
    src="$(find_registry_wintun_dll "$(windows_arch_dir "$target")")"
  fi
  if [[ -z "$src" || ! -f "$src" ]]; then
    echo "failed to locate wintun.dll for $target" >&2
    exit 1
  fi

  cp "$src" "$dst"
  chmod 0644 "$dst"
  echo "staged wintun.dll: $dst"
}

host="$(host_target)"
if [[ "$host" == *"-windows-"* ]]; then
  default_target="$host"
else
  default_target="x86_64-pc-windows-gnu"
fi
target="${TABBYMEW_WINDOWS_TARGET:-$default_target}"
binary="target/${target}/release/TabbyMew.exe"

section "Checking Windows Rust target"
if [[ "$target" != *"-windows-"* ]]; then
  echo "target does not look like Windows: $target" >&2
  exit 1
fi
require_rust_target "$target" "$host"

if [[ "$target" == *"-gnu" && "$host" != *"-windows-"* ]]; then
  section "Checking MinGW linker"
  require_command x86_64-w64-mingw32-gcc
fi

section "Building Windows release executable"
cargo build --release --locked --target "$target"

section "Staging Wintun runtime DLL"
stage_wintun_dll "$target" "$binary"

section "Packaging Windows release artifact"
./scripts/release-artifact.sh windows "$target" "$binary" TabbyMew.exe
