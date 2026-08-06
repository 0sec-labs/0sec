#!/usr/bin/env bash
# Start CyberGym's network-enforced egress proxy on bench.
# This is deliberately narrow: the agent gets only its Codex auth and responses
# endpoints, plus the harness server via NO_PROXY on the internal gateway.
set -euo pipefail

: "${CYBERGYM_ROOT:=/srv/cybergym}"
: "${CYBERGYM_PYTHON:=${CYBERGYM_ROOT}/venv/bin/python}"

# `cybergym.firewall` manages the isolated Docker network; UFW still filters
# container-to-host traffic through INPUT when its default policy is deny.
: "${CYBERGYM_NETWORK:=cybergym-internal}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
allowlist="${script_dir}/cybergym-egress-allowlist.txt"

[[ -x "${CYBERGYM_PYTHON}" ]] || {
  printf 'missing CyberGym Python environment: %s\n' "${CYBERGYM_PYTHON}" >&2
  exit 2
}
[[ -r "${allowlist}" ]] || {
  printf 'missing CyberGym egress allowlist: %s\n' "${allowlist}" >&2
  exit 2
}

# `update` recreates a pre-existing proxy with the checked-in allowlist too.
"${CYBERGYM_PYTHON}" -m cybergym.firewall update --allowlist "${allowlist}"

status="$("${CYBERGYM_PYTHON}" -m cybergym.firewall status)"
gateway="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["network"]["host_gateway"])' <<<"${status}")"

# The agent reaches the task submission server and private oracle bridge
# directly through NO_PROXY. Do not expose either beyond this Docker bridge.
if command -v ufw >/dev/null 2>&1 && [[ "$(ufw status 2>/dev/null)" == "Status: active"* ]]; then
  network_id="$(docker network inspect --format '{{.Id}}' "${CYBERGYM_NETWORK}")"
  subnet="$(docker network inspect --format '{{(index .IPAM.Config 0).Subnet}}' "${CYBERGYM_NETWORK}")"
  bridge_interface="br-${network_id:0:12}"
  ufw allow in on "${bridge_interface}" from "${subnet}" to "${gateway}" port 8666 proto tcp comment "CyberGym submit"
  ufw allow in on "${bridge_interface}" from "${subnet}" to "${gateway}" port 8667 proto tcp comment "CyberGym oracle"
fi

printf 'Firewall ready. Export CYBERGYM_SERVER=http://%s:8666 before running the agent.\n' "${gateway}"
