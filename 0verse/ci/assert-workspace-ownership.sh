#!/usr/bin/env bash
set -euo pipefail

workspace=${1:-${GITHUB_WORKSPACE:-}}
if [[ -z "$workspace" || ! -d "$workspace" ]]; then
  echo "error: workspace ownership check requires an existing directory" >&2
  exit 2
fi

expected_uid=$(id -u)
expected_gid=$(id -g)
offender=$(
  find "$workspace" -xdev \
    \( ! -uid "$expected_uid" -o ! -gid "$expected_gid" \) \
    -print -quit
)
if [[ -n "$offender" ]]; then
  echo "error: checkout contains an entry not owned by the runner uid:gid" >&2
  stat -c 'owner=%u:%g mode=%a type=%F path=%n' "$offender" >&2
  exit 1
fi

echo "checkout ownership verified: ${expected_uid}:${expected_gid}"
