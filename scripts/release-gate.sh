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

branch="$(git branch --show-current)"
head_sha="$(git rev-parse HEAD)"
short_sha="$(git rev-parse --short HEAD)"
release_branch="${TABBYMEW_RELEASE_BRANCH:-main}"
ci_workflow="${TABBYMEW_RELEASE_GATE_WORKFLOW:-Release}"
allow_non_release_branch="${TABBYMEW_RELEASE_GATE_ALLOW_NON_RELEASE_BRANCH:-${TABBYMEW_RELEASE_GATE_ALLOW_NON_MASTER:-}}"

if [[ "$branch" != "$release_branch" && -z "$allow_non_release_branch" ]]; then
  echo "release gate must run from $release_branch, got $branch" >&2
  echo "set TABBYMEW_RELEASE_GATE_ALLOW_NON_RELEASE_BRANCH=1 to override for a preflight run" >&2
  exit 1
fi

if [[ -n "$(git status --short)" && -z "${TABBYMEW_RELEASE_GATE_ALLOW_DIRTY:-}" ]]; then
  echo "release gate must run from a clean worktree" >&2
  echo "set TABBYMEW_RELEASE_GATE_ALLOW_DIRTY=1 to override for a preflight run" >&2
  git status --short >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh is required to verify CI status for the exact release commit" >&2
  exit 1
fi

section "$ci_workflow workflow status for $short_sha"
ci_status="$(gh run list --workflow "$ci_workflow" --branch "$branch" --commit "$head_sha" --limit 1 --json status --jq '.[0].status // ""')"
ci_conclusion="$(gh run list --workflow "$ci_workflow" --branch "$branch" --commit "$head_sha" --limit 1 --json conclusion --jq '.[0].conclusion // ""')"
ci_url="$(gh run list --workflow "$ci_workflow" --branch "$branch" --commit "$head_sha" --limit 1 --json url --jq '.[0].url // ""')"

if [[ -z "$ci_status" ]]; then
  echo "no CI run found for $head_sha" >&2
  exit 1
fi

if [[ "$ci_status" != "completed" || "$ci_conclusion" != "success" ]]; then
  echo "CI is not green for $head_sha: status=$ci_status conclusion=$ci_conclusion" >&2
  if [[ -n "$ci_url" ]]; then
    echo "$ci_url" >&2
  fi
  exit 1
fi

echo "CI passed for $head_sha"
if [[ -n "$ci_url" ]]; then
  echo "$ci_url"
fi

run ./scripts/public-readiness-audit.sh
run ./scripts/interop-env.sh
run ./scripts/validate.sh
run ./scripts/interop-sing-box.sh
run ./scripts/interop-xray.sh
run ./scripts/interop-v2ray.sh

section "release gate passed for $short_sha"
