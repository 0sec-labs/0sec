#!/usr/bin/env bash
# Generate one official CyberGym task on the host, scope a one-use oracle
# capability to it, and execute the pwnkit agent in the isolated container.
set -euo pipefail

if (($# < 1)); then
  printf 'usage: %s <task-id> [cybergym-runner options]\n' "$0" >&2
  exit 2
fi

task_id="$1"
shift

: "${CYBERGYM_ROOT:=/srv/cybergym}"
: "${PWNKIT_ROOT:=/srv/pwnkit}"
: "${CYBERGYM_PYTHON:=${CYBERGYM_ROOT}/venv/bin/python}"
: "${CYBERGYM_DIFFICULTY:=level1}"
: "${CYBERGYM_SERVER_API_KEY_FILE:=${CYBERGYM_ROOT}/secrets/server-api-key}"
: "${CYBERGYM_BRIDGE_CAPABILITIES:=${CYBERGYM_ROOT}/bridge/capabilities.json}"

bridge_script="${PWNKIT_ROOT}/packages/benchmark/scripts/cybergym-oracle-bridge.py"
container_script="${PWNKIT_ROOT}/packages/benchmark/scripts/run-cybergym-container.sh"
for path in "${CYBERGYM_PYTHON}" "${bridge_script}" "${container_script}" "${CYBERGYM_SERVER_API_KEY_FILE}"; do
  [[ -e "${path}" ]] || { printf 'missing required path: %s\n' "${path}" >&2; exit 2; }
done

firewall_status="$("${CYBERGYM_PYTHON}" -m cybergym.firewall status)"
gateway="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["network"]["host_gateway"])' <<<"${firewall_status}")"
[[ -n "${gateway}" && "${gateway}" != "None" ]] || {
  printf 'CyberGym internal network is not ready; run start-cybergym-firewall.sh first\n' >&2
  exit 2
}

install -d -m 0700 "${CYBERGYM_ROOT}/tasks"
task_dir="$(mktemp -d "${CYBERGYM_ROOT}/tasks/${task_id//:/-}.XXXXXX")"
token=""
cleanup() {
  if [[ -n "${token}" ]]; then
    "${CYBERGYM_PYTHON}" "${bridge_script}" revoke \
      --capabilities "${CYBERGYM_BRIDGE_CAPABILITIES}" --token "${token}" >/dev/null || true
  fi
  if [[ "${CYBERGYM_KEEP_TASKS:-0}" != "1" ]]; then
    rm -rf "${task_dir}"
  fi
}
trap cleanup EXIT

"${CYBERGYM_PYTHON}" -m cybergym.task.gen_task \
  --task-id "${task_id}" \
  --difficulty "${CYBERGYM_DIFFICULTY}" \
  --out-dir "${task_dir}" \
  --data-dir "${CYBERGYM_ROOT}/data/data" \
  --server "http://${gateway}:8666" \
  --mask-map "${CYBERGYM_ROOT}/repo/mask_map.json"

agent_id="$("${CYBERGYM_PYTHON}" -c 'import sys; from pathlib import Path; source = Path(sys.argv[1]).read_text(); marker = "\"agent_id\": \""; start = source.index(marker) + len(marker); print(source[start:source.index("\"", start)])' "${task_dir}/submit.sh")"
token="$("${CYBERGYM_PYTHON}" "${bridge_script}" issue \
  --capabilities "${CYBERGYM_BRIDGE_CAPABILITIES}" --agent-id "${agent_id}")"

# The container runs as UID 10001 and must unpack the task archive and write
# candidate PoCs. It has no write access to the harness, corpus, bridge state,
# model credentials, verifier key, or shared database.
chown -R 10001:10001 "${task_dir}"

export CYBERGYM_TASK_DIR="${task_dir}"
export CYBERGYM_SERVER="http://${gateway}:8666"
export CYBERGYM_ORACLE_BRIDGE="http://${gateway}:8667"
export CYBERGYM_ORACLE_BRIDGE_TOKEN="${token}"
"${container_script}" --task-id "${task_id}" --difficulty "${CYBERGYM_DIFFICULTY}" "$@"
