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

if [[ "${TABBYMEW_TUN_SMOKE:-}" != "1" ]]; then
  cat >&2 <<'MSG'
TUN smoke is skipped by default because it can change system routes/DNS.
Set TABBYMEW_TUN_SMOKE=1 and run from an administrator/root-capable session
when you intentionally want to validate TUN on this machine.
MSG
  exit 0
fi

case "$(uname -s)" in
  Darwin)
    echo "macOS detected; TUN auto-route may prompt for administrator authorization."
    ;;
  Linux)
    if [[ "$(id -u)" != "0" ]]; then
      echo "Linux TUN smoke requires root or an equivalent CAP_NET_ADMIN setup." >&2
      exit 1
    fi
    ;;
  MINGW*|MSYS*|CYGWIN*)
    if [[ "${TABBYMEW_TUN_SMOKE_ADMIN_CONFIRMED:-}" != "1" ]]; then
      echo "Windows TUN smoke must run from an elevated shell." >&2
      echo "Set TABBYMEW_TUN_SMOKE_ADMIN_CONFIRMED=1 after confirming elevation." >&2
      exit 1
    fi
    ;;
  *)
    echo "unsupported TUN smoke platform: $(uname -s)" >&2
    exit 1
    ;;
esac

binary="${TABBYMEW_BIN:-target/release/TabbyMew}"
config="${TABBYMEW_TUN_SMOKE_CONFIG:-}"
probe_url="${TABBYMEW_TUN_SMOKE_URL:-https://example.com/}"

if [[ -z "$config" ]]; then
  echo "set TABBYMEW_TUN_SMOKE_CONFIG to a real TUN-capable config file" >&2
  exit 1
fi

if [[ ! -x "$binary" ]]; then
  run cargo build --locked --release
fi

state_dir="$(mktemp -d)"
log_file="$state_dir/tun-smoke.log"

cleanup() {
  set +e
  "$binary" --config "$config" tun --state-dir "$state_dir" off --json >/dev/null 2>&1
  "$binary" --config "$config" stop --state-dir "$state_dir" --timeout-ms 10000 >/dev/null 2>&1
  rm -rf "$state_dir"
}
trap cleanup EXIT

run "$binary" --config "$config" start --state-dir "$state_dir" --log "$log_file"
run "$binary" wait --state-dir "$state_dir" service ready --timeout-ms 15000 --json
run "$binary" --config "$config" tun --state-dir "$state_dir" on --json
run "$binary" wait --state-dir "$state_dir" tun on --timeout-ms 30000 --json
run "$binary" doctor --state-dir "$state_dir" --json

if command -v curl >/dev/null 2>&1; then
  run curl --max-time 15 --silent --show-error --location --head "$probe_url"
else
  echo "curl is not available; skipped external probe $probe_url"
fi
