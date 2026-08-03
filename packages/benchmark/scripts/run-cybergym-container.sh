#!/usr/bin/env bash
# Run one CyberGym benchmark process inside the harness-created internal network.
# The caller must start cybergym.firewall and bind the submission server to that
# network's gateway before invoking this wrapper.
set -euo pipefail

: "${CYBERGYM_ROOT:=/srv/cybergym}"
: "${CYBERGYM_NETWORK:=cybergym-internal}"
: "${PWNKIT_CYBERGYM_IMAGE:=pwnkit-cybergym-agent:local}"
: "${CYBERGYM_AUTH_FILE:=${HOME}/.codex/auth.json}"
: "${CYBERGYM_SERVER:?set CYBERGYM_SERVER to the submission server on the internal-network gateway}"
: "${CYBERGYM_ORACLE_BRIDGE:?set CYBERGYM_ORACLE_BRIDGE to the host-bound oracle bridge}"
: "${CYBERGYM_ORACLE_BRIDGE_TOKEN:?set CYBERGYM_ORACLE_BRIDGE_TOKEN to this task-specific one-use capability}"

: "${CYBERGYM_TASK_DIR:?set CYBERGYM_TASK_DIR to the host-created task directory}"
: "${CYBERGYM_AGENT_CPUS:=8}"
: "${CYBERGYM_AGENT_MEMORY:=16g}"

server_host="${CYBERGYM_SERVER#*://}"
server_host="${server_host%%/*}"
server_host="${server_host%%:*}"

bridge_host="${CYBERGYM_ORACLE_BRIDGE#*://}"
bridge_host="${bridge_host%%/*}"
bridge_host="${bridge_host%%:*}"
if [[ "${CYBERGYM_NETWORK}" != "cybergym-internal" ]]; then
  printf 'refusing non-isolated network: %s\n' "${CYBERGYM_NETWORK}" >&2
  exit 2
fi
for path in \
  "${CYBERGYM_AUTH_FILE}" \
  "${CYBERGYM_TASK_DIR}"; do
  [[ -e "${path}" ]] || { printf 'missing required path: %s\n' "${path}" >&2; exit 2; }
done

docker network inspect "${CYBERGYM_NETWORK}" >/dev/null
proxy_ip="$(docker inspect --format '{{with index .NetworkSettings.Networks "cybergym-internal"}}{{.IPAddress}}{{end}}' cybergym-proxy)"
[[ -n "${proxy_ip}" ]] || {
  printf 'CyberGym proxy is not attached to %s\n' "${CYBERGYM_NETWORK}" >&2
  exit 2
}
cybergym_proxy="http://${proxy_ip}:3128"
install -d -m 0700 "${CYBERGYM_ROOT}/results"
chown 10001:10001 "${CYBERGYM_ROOT}/results"

exec docker run --rm \
  --env HTTP_PROXY="${cybergym_proxy}" \
  --env HTTPS_PROXY="${cybergym_proxy}" \
  --env NO_PROXY="127.0.0.1,localhost,${server_host},${bridge_host}" \
  --env http_proxy="${cybergym_proxy}" \
  --env https_proxy="${cybergym_proxy}" \
  --env no_proxy="127.0.0.1,localhost,${server_host},${bridge_host}" \
  --env NODE_USE_ENV_PROXY=1 \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=4g \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 512 \
  --cpus "${CYBERGYM_AGENT_CPUS}" \
  --memory "${CYBERGYM_AGENT_MEMORY}" \
  --mount "type=bind,src=${CYBERGYM_ROOT}/results,dst=/results" \
  --mount "type=bind,src=${CYBERGYM_TASK_DIR},dst=/task" \
  --mount "type=bind,src=${CYBERGYM_AUTH_FILE},dst=/run/secrets/codex-auth.json,readonly" \
  --env CYBERGYM_ORACLE_BRIDGE \
  --env CYBERGYM_ORACLE_BRIDGE_TOKEN \
  --env CYBERGYM_SERVER \
  --env PWNKIT_CHATGPT_AUTH_FILE=/run/secrets/codex-auth.json \
  "${PWNKIT_CYBERGYM_IMAGE}" \
  --task-dir /task \
  --corpus-path "${CYBERGYM_CORPUS_PATH:-/results/cybergym-run.jsonl}" \
  "$@"
