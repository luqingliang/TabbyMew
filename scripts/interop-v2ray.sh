#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v v2ray >/dev/null 2>&1; then
  echo "v2ray is required for cross-implementation interop validation" >&2
  exit 1
fi

v2ray version | sed -n '1p'
cargo test --locked --test v2ray_interop -- --ignored --test-threads=1 --nocapture
