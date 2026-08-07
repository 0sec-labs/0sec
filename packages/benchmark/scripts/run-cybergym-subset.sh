#!/usr/bin/env bash
# Drive the PRE-REGISTERED CyberGym subset (results/cybergym-fair-v1.subset.txt)
# one isolated container per task, appending one receipt row per task to a
# shared corpus JSONL.
#
# Why a host-side loop instead of the runner's own --subset mode: the oracle
# bridge capability is issued per generated agent_id, so every task needs its
# own run-cybergym-task.sh invocation (fresh task dir + fresh one-use token).
#
# Claim-gate discipline (epic #1026):
#   - The subset LIST is frozen; this driver never edits it.
#   - Every CAPABILITY outcome (pass / fail / refused) is appended exactly once
#     and never removed.
#   - Rows that are pure INFRASTRUCTURE artifacts (verdict=error: LLM quota
#     wall, oracle unreachable, source missing) are evicted and the task is
#     retried after the quota boundary, so the committed receipt carries one
#     real attempt per task instead of a billing accident.
#
# Quota: Qwen Token Plan enforces 5h windows (observed reset anchor
# 2026-08-06T13:31:00Z, every 18000s). On a quota signature in the task log the
# driver sleeps to the next boundary instead of burning the remaining tasks
# into error rows.
#
# Usage: run-cybergym-subset.sh <subset-file> <host-corpus-path>
# Env:   CYBERGYM_MODEL (required), CYBERGYM_MAX_STEPS (=60),
#        CYBERGYM_MAX_SUBMITS (=1), CYBERGYM_MAX_TESTS (=24),
#        CYBERGYM_LLM_TIMEOUT_MS (=360000), CYBERGYM_CRAFT_DEADLINE_MS (=2700000),
#        CYBERGYM_INFRA_RETRIES (=4 per task),
#        CYBERGYM_QUOTA_ANCHOR_EPOCH (Token Plan window anchor),
#        CYBERGYM_TASK_RUNNER (testing seam; default run-cybergym-task.sh).
set -uo pipefail

subset_file="${1:?usage: run-cybergym-subset.sh <subset-file> <host-corpus-path>}"
host_corpus="${2:?usage: run-cybergym-subset.sh <subset-file> <host-corpus-path>}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
: "${PWNKIT_ROOT:=$(cd -- "${script_dir}/../../.." && pwd)}"
: "${CYBERGYM_ROOT:=/srv/cybergym}"
: "${CYBERGYM_MODEL:?set CYBERGYM_MODEL to the model under test}"
: "${CYBERGYM_MAX_STEPS:=60}"
: "${CYBERGYM_MAX_SUBMITS:=1}"
: "${CYBERGYM_MAX_TESTS:=24}"
: "${CYBERGYM_LLM_TIMEOUT_MS:=360000}"
: "${CYBERGYM_CRAFT_DEADLINE_MS:=2700000}"
: "${CYBERGYM_INFRA_RETRIES:=4}"
: "${CYBERGYM_QUOTA_ANCHOR_EPOCH:=$(date -ud "2026-08-06 13:31:00" +%s)}"
: "${CYBERGYM_QUOTA_WINDOW_SECONDS:=18000}"
: "${CYBERGYM_TASK_RUNNER:=${script_dir}/run-cybergym-task.sh}"
export CYBERGYM_MAX_SUBMITS CYBERGYM_MAX_TESTS CYBERGYM_LLM_TIMEOUT_MS CYBERGYM_CRAFT_DEADLINE_MS

[[ -r "${subset_file}" && -x "${CYBERGYM_TASK_RUNNER}" ]] || {
  printf 'missing subset file or task runner\n' >&2
  exit 2
}
# The container mounts CYBERGYM_ROOT/results at /results; the corpus argument
# the runner sees is the container-side path.
case "${host_corpus}" in
  "${CYBERGYM_ROOT}/results/"*) ;;
  *)
    printf 'corpus must live under %s/results (container mount)\n' "${CYBERGYM_ROOT}" >&2
    exit 2
    ;;
esac
container_corpus="/results/${host_corpus#"${CYBERGYM_ROOT}/results/"}"
log_dir="${host_corpus%.jsonl}.logs"
install -d -m 0700 "${log_dir}"
touch "${host_corpus}"

# Task ids that already have a kept (capability) row in the corpus. verdict
# "error" rows are infra artifacts pending eviction, not completions.
done_ids() {
  python3 - "$1" <<'PY'
import json, sys
try:
    for line in open(sys.argv[1]):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        task = row.get("taskId")
        if isinstance(task, str) and row.get("verdict") != "error":
            print(task)
except FileNotFoundError:
    pass
PY
}

# verdict=error rows are infra artifacts (quota wall, oracle outage, missing
# source) — never capability evidence. Evict THIS task's error rows so a retry
# replaces them with a real attempt. pass/fail/refused rows are immutable.
evict_infra_rows() {
  python3 - "$1" "$2" <<'PY'
import json, sys
path, task = sys.argv[1], sys.argv[2]
kept = []
for line in open(path):
    stripped = line.strip()
    if not stripped:
        continue
    try:
        row = json.loads(stripped)
    except json.JSONDecodeError:
        kept.append(line.rstrip("\n"))
        continue
    if row.get("taskId") == task and row.get("verdict") == "error":
        continue
    kept.append(line.rstrip("\n"))
with open(path, "w") as out:
    if kept:
        out.write("\n".join(kept) + "\n")
PY
}

quota_signature() {
  grep -qiE "quota has been exhausted|usage_limit_reached|HTTP 429" "$1"
}

seconds_to_next_boundary() {
  python3 - <<PY
import time
anchor = int("${CYBERGYM_QUOTA_ANCHOR_EPOCH}")
window = int("${CYBERGYM_QUOTA_WINDOW_SECONDS}")
now = time.time()
nxt = anchor + ((int(now - anchor) // window) + 1) * window
wait_s = max(0, int(nxt - now)) + int("${CYBERGYM_QUOTA_SLEEP_BUFFER:-30}")
print(wait_s)
PY
}

printf '[subset] start %s model=%s corpus=%s\n' "$(date -u +%FT%TZ)" "${CYBERGYM_MODEL}" "${host_corpus}"
total=0
ran=0
while IFS= read -r line; do
  task_id="${line%%#*}"
  task_id="${task_id//[[:space:]]/}"
  [[ -n "${task_id}" ]] || continue
  total=$((total + 1))
  if done_ids "${host_corpus}" | grep -qxF "${task_id}"; then
    printf '[subset] skip %s (receipt row present)\n' "${task_id}"
    continue
  fi

  attempt=0
  while (( attempt <= CYBERGYM_INFRA_RETRIES )); do
    attempt=$((attempt + 1))
    task_log="${log_dir}/${task_id//:/-}.log"
    printf '[subset] run %s (attempt %d) %s\n' "${task_id}" "${attempt}" "$(date -u +%FT%TZ)"
    "${CYBERGYM_TASK_RUNNER}" "${task_id}" \
      --runtime api --model "${CYBERGYM_MODEL}" \
      --max-steps "${CYBERGYM_MAX_STEPS}" \
      --corpus-path "${container_corpus}" \
      >"${task_log}" 2>&1
    rc=$?

    # A capability outcome (pass/fail/refused row) is final for this task.
    if done_ids "${host_corpus}" | grep -qxF "${task_id}"; then
      ran=$((ran + 1))
      break
    fi
    # No kept row: either an error row was just appended, or the runner died
    # before writing one. Evict infra rows, wait out a quota wall, retry.
    evict_infra_rows "${host_corpus}" "${task_id}"
    if quota_signature "${task_log}" && (( attempt <= CYBERGYM_INFRA_RETRIES )); then
      wait_s="$(seconds_to_next_boundary)"
      printf '[subset] %s hit provider quota; sleeping %ss to next window\n' "${task_id}" "${wait_s}"
      sleep "${wait_s}"
      continue
    fi
    if (( rc != 0 )) && (( attempt <= CYBERGYM_INFRA_RETRIES )); then
      printf '[subset] %s runner exited %d; retrying\n' "${task_id}" "${rc}"
      sleep 30
      continue
    fi
    # Out of retries: leave the last error state visible in the task log and
    # move on; the missing corpus row marks the task as not measured.
    printf '[subset] %s NOT measured after %d attempt(s) — see %s\n' "${task_id}" "${attempt}" "${task_log}"
    break
  done
done < "${subset_file}"

printf '[subset] DONE %s ran=%d total=%d corpus=%s\n' "$(date -u +%FT%TZ)" "${ran}" "${total}" "${host_corpus}"
