#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v xray >/dev/null 2>&1; then
  echo "xray is required for cross-implementation interop validation" >&2
  exit 1
fi

xray version | sed -n '1p'
cargo test --locked --test xray_interop -- --ignored --test-threads=1 --nocapture
