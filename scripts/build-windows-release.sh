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

windows_tool_prefix() {
  local target="$1"
  case "$target" in
    x86_64-*-windows-*) echo "x86_64-w64-mingw32" ;;
    i686-*-windows-* | i586-*-windows-*) echo "i686-w64-mingw32" ;;
    *)
      echo "unsupported MinGW tool prefix for $target" >&2
      exit 1
      ;;
  esac
}

verify_windows_icon_resource() {
  local binary="$1"
  local python="python3"

  if ! command -v "$python" >/dev/null 2>&1; then
    python="python"
  fi
  require_command "$python"

  if ! "$python" - "$binary" <<'PY'
import struct
import sys

path = sys.argv[1]
data = open(path, "rb").read()
pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
if data[pe_offset : pe_offset + 4] != b"PE\0\0":
    raise SystemExit("not a PE executable")
section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
optional_header = pe_offset + 24
magic = struct.unpack_from("<H", data, optional_header)[0]
data_directory = optional_header + (112 if magic == 0x20B else 96)
resource_rva, resource_size = struct.unpack_from("<II", data, data_directory + 8 * 2)
if resource_rva == 0 or resource_size == 0:
    raise SystemExit("missing PE resource directory")
section_table = optional_header + optional_header_size
resource_section = None
for index in range(section_count):
    section = section_table + index * 40
    name = data[section : section + 8].rstrip(b"\0").decode("ascii", "replace")
    virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
        "<IIII", data, section + 8
    )
    if virtual_address <= resource_rva < virtual_address + max(virtual_size, raw_size):
        resource_section = (name, virtual_address, raw_pointer)
        break
if resource_section is None:
    raise SystemExit("missing PE .rsrc section")
base = resource_section[2] + (resource_rva - resource_section[1])
_, _, _, _, named_count, id_count = struct.unpack_from("<IIHHHH", data, base)
resource_type_ids = []
for index in range(named_count + id_count):
    name_or_id, _ = struct.unpack_from("<II", data, base + 16 + index * 8)
    resource_type_ids.append(name_or_id & 0xFFFF)
if 3 not in resource_type_ids or 14 not in resource_type_ids:
    raise SystemExit(
        f"missing icon resources; found PE resource type IDs: {resource_type_ids}"
    )
PY
  then
    echo "missing Windows icon resources in $binary" >&2
    exit 1
  fi
  echo "verified Windows icon resources: $binary"
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
  mingw_prefix="$(windows_tool_prefix "$target")"
  require_command "${mingw_prefix}-gcc"
  require_command "${mingw_prefix}-windres"
fi

section "Building Windows release executable"
cargo build --release --locked --target "$target"

section "Verifying Windows icon resource"
verify_windows_icon_resource "$binary"

section "Staging Wintun runtime DLL"
stage_wintun_dll "$target" "$binary"

section "Packaging Windows release artifact"
./scripts/release-artifact.sh windows "$target" "$binary" TabbyMew.exe
