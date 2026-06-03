#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if (($# != 4)); then
  echo "usage: $0 <platform> <target-triple> <binary-path> <staged-binary-name>" >&2
  exit 2
fi

platform="$1"
target_triple="$2"
binary="$3"
staged_binary_name="$4"

if [[ ! -f "$binary" ]]; then
  echo "expected executable was not produced: $binary" >&2
  exit 1
fi

version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
if [[ -z "$version" ]]; then
  echo "failed to read version from Cargo.toml" >&2
  exit 1
fi

git_sha="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"
short_sha="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
git_dirty="unknown"
display_short_sha="$short_sha"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if [[ -n "$(git status --short)" ]]; then
    git_dirty="true"
    display_short_sha="${short_sha}-dirty"
  else
    git_dirty="false"
  fi
fi
artifact_id="tabbymew-${version}-${target_triple}"
artifact_root="target/release-artifacts"
stage="${artifact_root}/${artifact_id}"
archive="${artifact_root}/${artifact_id}.tar.gz"

mkdir -p "$artifact_root"
rm -rf "$stage" "$archive" "${archive}.sha256"
mkdir -p "$stage"

cp "$binary" "${stage}/${staged_binary_name}"
chmod 0755 "${stage}/${staged_binary_name}"

if [[ ! -f LICENSE ]]; then
  echo "missing project license: LICENSE" >&2
  exit 1
fi
cp LICENSE "${stage}/LICENSE"
chmod 0644 "${stage}/LICENSE"

if [[ "$platform" == "windows" ]]; then
  wintun_dll="$(dirname "$binary")/wintun.dll"
  if [[ ! -f "$wintun_dll" ]]; then
    echo "expected Windows TUN runtime DLL was not produced: $wintun_dll" >&2
    exit 1
  fi
  cp "$wintun_dll" "${stage}/wintun.dll"
  chmod 0644 "${stage}/wintun.dll"

  wintun_license="licenses/WINTUN-PREBUILT-BINARIES-LICENSE.txt"
  if [[ ! -f "$wintun_license" ]]; then
    echo "missing Wintun prebuilt binaries license: $wintun_license" >&2
    exit 1
  fi
  mkdir -p "${stage}/licenses"
  cp "$wintun_license" "${stage}/${wintun_license}"
  chmod 0644 "${stage}/${wintun_license}"
fi

for file in docs/cli.md docs/install.md; do
  if [[ -f "$file" ]]; then
    mkdir -p "${stage}/$(dirname "$file")"
    cp "$file" "${stage}/${file}"
  fi
done

while IFS= read -r file; do
  mkdir -p "${stage}/$(dirname "$file")"
  cp "$file" "${stage}/${file}"
done < <(find examples -type f | LC_ALL=C sort)

{
  printf 'TabbyMew release artifact\n'
  printf 'version: %s\n' "$version"
  printf 'platform: %s\n' "$platform"
  printf 'target: %s\n' "$target_triple"
  printf 'git_sha: %s\n' "$git_sha"
  printf 'short_sha: %s\n' "$display_short_sha"
  printf 'git_dirty: %s\n' "$git_dirty"
  printf 'archive: %s\n' "$(basename "$archive")"
  printf '\n'
  printf 'contents:\n'
  find "$stage" -type f \
    | sed "s|^${stage}/|- |" \
    | LC_ALL=C sort
  printf '\n'
  printf 'excluded:\n'
  printf -- '- local state under ~/.tabbymew/\n'
  printf -- '- runtime logs\n'
  printf -- '- Cargo target cache and incremental build files\n'
  printf -- '- Git metadata\n'
  printf -- '- subscription URLs, tokens, passwords, UUIDs, and private keys\n'
} > "${stage}/MANIFEST.txt"

tar -C "$artifact_root" -czf "$archive" "$artifact_id"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$archive" > "${archive}.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$archive" > "${archive}.sha256"
else
  echo "warning: no sha256 tool found; skipped checksum" >&2
fi

echo "artifact: $archive"
if [[ -f "${archive}.sha256" ]]; then
  echo "checksum: ${archive}.sha256"
fi

if stat -c '%n %s bytes %y' "$archive" 2>/dev/null; then
  :
elif stat -f '%N %z bytes %Sm' "$archive" 2>/dev/null; then
  :
else
  ls -lh "$archive"
fi
