#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v sing-box >/dev/null 2>&1; then
  echo "sing-box is required for real-server interop validation" >&2
  exit 1
fi

sing-box version | sed -n '1p'
cargo test --locked --test sing_box_interop -- --ignored --test-threads=1 --nocapture
