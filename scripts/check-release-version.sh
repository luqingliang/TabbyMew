#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if (($# != 1)); then
  echo "usage: $0 <release-tag>" >&2
  exit 2
fi

tag="${1#refs/tags/}"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
if [[ -z "$version" ]]; then
  echo "failed to read version from Cargo.toml" >&2
  exit 1
fi

expected="v${version}"
if [[ "$tag" != "$expected" ]]; then
  echo "release tag $tag does not match Cargo.toml version $version; expected $expected" >&2
  exit 1
fi

echo "release tag matches Cargo.toml version: $tag"
