#!/usr/bin/env bash
# Generate one official CyberGym task on the host, scope a one-use oracle
# capability to it, and execute the 0sec agent in the isolated container.
set -euo pipefail

if (($# < 1)); then
  printf 'usage: %s <task-id> [cybergym-runner options]\n' "$0" >&2
  exit 2
fi

task_id="$1"
shift

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
: "${0SEC_ROOT:=$(cd -- "${script_dir}/../../.." && pwd)}"
: "${CYBERGYM_ROOT:=/srv/cybergym}"
: "${CYBERGYM_PYTHON:=${CYBERGYM_ROOT}/venv/bin/python}"
: "${CYBERGYM_DIFFICULTY:=level1}"
: "${CYBERGYM_BRIDGE_CAPABILITIES:=${CYBERGYM_ROOT}/bridge/capabilities.json}"
: "${CYBERGYM_AUTH_FILE:=${HOME}/.codex/auth.json}"

bridge_script="${0SEC_ROOT}/packages/benchmark/scripts/cybergym-oracle-bridge.py"
container_script="${0SEC_ROOT}/packages/benchmark/scripts/run-cybergym-container.sh"
for path in "${CYBERGYM_PYTHON}" "${bridge_script}" "${container_script}" "${CYBERGYM_AUTH_FILE}"; do
  [[ -e "${path}" ]] || { printf 'missing required path: %s\n' "${path}" >&2; exit 2; }
done

firewall_status="$("${CYBERGYM_PYTHON}" -m cybergym.firewall status)"
gateway="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["network"]["host_gateway"])' <<<"${firewall_status}")"
[[ -n "${gateway}" && "${gateway}" != "None" ]] || {
  printf 'CyberGym internal network is not ready; run start-cybergym-firewall.sh first\n' >&2
  exit 2
}

# The upstream submission server resolves target images by mutable-looking tag
# (`n132/arvo:<id>-vul`), even when the run itself was provisioned from a
# pinned digest. Fail before task generation or any model call if the required
# local aliases are absent. Bootstrap must create each alias from the manifest's
# exact digest, never pull a floating tag here.
case "${task_id}" in
  arvo:*)
    task_number="${task_id#arvo:}"
    required_images=("n132/arvo:${task_number}-vul" "n132/arvo:${task_number}-fix")
    ;;
  oss-fuzz:*)
    task_number="${task_id#oss-fuzz:}"
    required_images=("cybergym/oss-fuzz:${task_number}-vul" "cybergym/oss-fuzz:${task_number}-fix")
    ;;
  *)
    printf 'unsupported CyberGym task id: %s\n' "${task_id}" >&2
    exit 2
    ;;
esac
for image in "${required_images[@]}"; do
  docker image inspect "${image}" >/dev/null 2>&1 || {
    printf 'missing required CyberGym image alias: %s (tag the manifest-pinned digest before running)\n' "${image}" >&2
    exit 2
  }
done
# The manifest bootstrap creates these aliases from exact digests. Do not pull
# mutable tags or remove the aliases here: either action would invalidate the
# preflight identity check before the trusted server consumes them.

install -d -m 0700 "${CYBERGYM_ROOT}/tasks" "${CYBERGYM_ROOT}/credentials"
task_dir="$(mktemp -d "${CYBERGYM_ROOT}/tasks/${task_id//:/-}.XXXXXX")"

credential_copy=""
token=""
cleanup() {
  if [[ -n "${token}" ]]; then
    "${CYBERGYM_PYTHON}" "${bridge_script}" revoke \
      --capabilities "${CYBERGYM_BRIDGE_CAPABILITIES}" --token "${token}" >/dev/null || true
  fi
  if [[ -n "${credential_copy}" ]]; then
    rm -f "${credential_copy}"
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

# The trusted container runner owns the task source and reads its task-scoped
# credential. Model-written Python runs as UID 10002 and cannot read either.
# The auth copy is deleted on exit; it has no access to the harness, corpus,
# bridge state, verifier key, or shared database.
credential_copy="$(mktemp "${CYBERGYM_ROOT}/credentials/codex-auth.XXXXXX")"
install -m 0400 -o 0 -g 0 "${CYBERGYM_AUTH_FILE}" "${credential_copy}"

export CYBERGYM_TASK_DIR="${task_dir}"
export CYBERGYM_SERVER="http://${gateway}:8666"
export CYBERGYM_ORACLE_BRIDGE="http://${gateway}:8667"
export CYBERGYM_ORACLE_BRIDGE_TOKEN="${token}"
export CYBERGYM_AUTH_FILE="${credential_copy}"
"${container_script}" --task-id "${task_id}" --difficulty "${CYBERGYM_DIFFICULTY}" "$@"
