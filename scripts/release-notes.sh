#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if (($# != 1)); then
  echo "usage: $0 <release-tag>" >&2
  exit 2
fi

tag="${1#refs/tags/}"
version="${tag#v}"

if [[ -z "$version" || "$version" == "$tag" ]]; then
  echo "release tag must use v-prefixed SemVer form, got: $tag" >&2
  exit 1
fi

if [[ ! -f CHANGELOG.md ]]; then
  echo "missing CHANGELOG.md" >&2
  exit 1
fi

notes_file="$(mktemp)"
trap 'rm -f "$notes_file"' EXIT

awk -v version="$version" '
  /^## / {
    if (in_section) {
      exit
    }
    if (index($0, "## [" version "]") == 1) {
      in_section = 1
      found = 1
      print
      next
    }
  }
  in_section {
    print
  }
  END {
    if (!found) {
      exit 42
    }
  }
' CHANGELOG.md > "$notes_file" || {
  status=$?
  if [[ "$status" -eq 42 ]]; then
    echo "CHANGELOG.md does not contain a section for $tag" >&2
  else
    echo "failed to extract changelog section for $tag" >&2
  fi
  exit 1
}

heading="$(sed -n '1p' "$notes_file")"
if [[ "$heading" == *Unreleased* || "$heading" == *unreleased* ]]; then
  echo "CHANGELOG.md section for $tag is still marked Unreleased" >&2
  exit 1
fi

if ! sed '1d' "$notes_file" | grep -q '[^[:space:]]'; then
  echo "CHANGELOG.md section for $tag is empty" >&2
  exit 1
fi

cat "$notes_file"
