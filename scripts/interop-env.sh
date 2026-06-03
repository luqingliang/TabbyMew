#!/usr/bin/env bash
set -euo pipefail

tools=(sing-box xray v2ray ssserver)
found=0

print_version() {
  local tool_path="$1"
  local output

  output="$("$tool_path" version 2>&1 | sed -n '1p' || true)"
  if [[ -z "$output" ]]; then
    output="$("$tool_path" --version 2>&1 | sed -n '1p' || true)"
  fi
  if [[ -z "$output" ]]; then
    output="version command unavailable"
  fi

  printf '%s\n' "$output"
}

for tool in "${tools[@]}"; do
  if tool_path="$(command -v "$tool")"; then
    found=1
    printf '%-10s %s\n' "$tool:" "$tool_path"
    printf '%-10s %s\n' "" "$(print_version "$tool_path")"
  else
    printf '%-10s not found\n' "$tool:"
  fi
done

if ((found == 0)); then
  echo
  echo "no real-server protocol implementation found; install sing-box, Xray/v2ray-core, or a Shadowsocks server before release interop validation" >&2
  exit 1
fi
