#!/usr/bin/env bash
# Start CyberGym's network-enforced egress proxy on bench.
# This is deliberately narrow: the agent gets only its Codex auth and responses
# endpoints, plus the harness server via NO_PROXY on the internal gateway.
set -euo pipefail

: "${CYBERGYM_ROOT:=/srv/cybergym}"
: "${CYBERGYM_PYTHON:=${CYBERGYM_ROOT}/venv/bin/python}"

[[ -x "${CYBERGYM_PYTHON}" ]] || {
  printf 'missing CyberGym Python environment: %s\n' "${CYBERGYM_PYTHON}" >&2
  exit 2
}

"${CYBERGYM_PYTHON}" -m cybergym.firewall start \
  --domain auth.openai.com \
  --domain chatgpt.com

status="$("${CYBERGYM_PYTHON}" -m cybergym.firewall status)"
gateway="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["network"]["host_gateway"])' <<<"${status}")"
printf 'Firewall ready. Export CYBERGYM_SERVER=http://%s:8666 before running the agent.\n' "${gateway}"
