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
#   - A `costCeilingExceeded` error is a terminal budget-inconclusive receipt,
#     never a capability row and never an automatic retry.
#   - Rows that are pure INFRASTRUCTURE artifacts (verdict=error: LLM quota
#     wall, oracle unreachable, source missing) are evicted and the task is
#     retried after the quota boundary, so the committed receipt carries one
#     real attempt per task instead of a billing accident.
#
# Quota windows are provider-specific. Set CYBERGYM_QUOTA_ANCHOR_EPOCH only
# when the configured provider has a documented fixed reset boundary. Without
# it, a quota-like response uses the ordinary bounded infrastructure retry
# instead of assuming Qwen's five-hour Token Plan schedule.
#
# Usage: run-cybergym-subset.sh <subset-file> <host-corpus-path>
# Env:   CYBERGYM_MODEL (required), CYBERGYM_MAX_STEPS (=60),
#        CYBERGYM_MAX_SUBMITS (=1), CYBERGYM_MAX_TESTS (=24),
#        CYBERGYM_LLM_TIMEOUT_MS (=360000), CYBERGYM_CRAFT_DEADLINE_MS (=2700000),
#        CYBERGYM_INFRA_RETRIES (=4 per task),
#        CYBERGYM_QUOTA_ANCHOR_EPOCH (optional provider reset anchor),
#        CYBERGYM_TASK_RUNNER (testing seam; default run-cybergym-task.sh).
set -uo pipefail

subset_file="${1:?usage: run-cybergym-subset.sh <subset-file> <host-corpus-path>}"
host_corpus="${2:?usage: run-cybergym-subset.sh <subset-file> <host-corpus-path>}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
: "${0SEC_ROOT:=$(cd -- "${script_dir}/../../.." && pwd)}"
: "${CYBERGYM_ROOT:=/srv/cybergym}"
: "${CYBERGYM_MODEL:?set CYBERGYM_MODEL to the model under test}"
: "${CYBERGYM_MAX_STEPS:=60}"
: "${CYBERGYM_MAX_SUBMITS:=1}"
: "${CYBERGYM_MAX_TESTS:=24}"
: "${CYBERGYM_LLM_TIMEOUT_MS:=360000}"
: "${CYBERGYM_CRAFT_DEADLINE_MS:=2700000}"
: "${CYBERGYM_INFRA_RETRIES:=4}"
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

# Task ids that already have a terminal receipt row. `costCeilingExceeded`
# errors are terminal budget evidence, while other error rows remain retryable
# infrastructure artifacts.
terminal_ids() {
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
        if (
            isinstance(task, str)
            and (
                row.get("verdict") != "error"
                or row.get("costCeilingExceeded") is True
            )
        ):
            print(task)
except FileNotFoundError:
    pass
PY
}

# verdict=error rows are normally infra artifacts (quota wall, oracle outage,
# missing source). Preserve cost-ceiling errors: retrying them would spend more
# after a declared budget-control failure.
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
    if (
        row.get("taskId") == task
        and row.get("verdict") == "error"
        and row.get("costCeilingExceeded") is not True
    ):
        continue
    kept.append(line.rstrip("\n"))
with open(path, "w") as out:
    if kept:
        out.write("\n".join(kept) + "\n")
PY
}

# Seconds until the provider-stated quota reset. Sources, in order: (1) the
# task log's resets_at=<iso> (engine-surfaced), (2) a direct 1-token probe of
# the provider, parsing "quota will reset at <date>" from its 429 body — the
# plan weekly wall outlasts every local estimate, and only the provider knows
# it. Prints nothing when neither yields a time; callers fall back to the
# window-anchor math.
seconds_to_provider_reset() {
  python3 - "$1" <<'PY'
import datetime, json, os, re, sys, time, urllib.request, urllib.error
try:
    text = open(sys.argv[1], errors="ignore").read()
except OSError:
    text = ""
matches = re.findall(r"resets_at=([0-9T:.\-+Z]+)", text)
if matches:
    try:
        t = datetime.datetime.fromisoformat(matches[-1].replace("Z", "+00:00")).timestamp()
        print(max(0, int(t - time.time())) + int(os.environ.get("CYBERGYM_QUOTA_RESET_BUFFER", "60")))
        sys.exit(0)
    except ValueError:
        pass
# (2) probe: a 429 body names the reset ("will reset at 08-20 15:24:00 UTC").
try:
    env = {}
    for line in open(os.environ.get("CYBERGYM_PROVIDER_ENV", "/srv/cybergym/credentials/provider.env")):
        line = line.strip()
        if line and "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1); env[k] = v
    base = env.get("QWEN_BASE_URL", "").rstrip("/") or "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1"
    key = env.get("QWEN_API_KEY", "")
    model = os.environ.get("CYBERGYM_MODEL", "")
    if base and key and model:
        req = urllib.request.Request(
            f"{base}/chat/completions",
            data=json.dumps({"model": model, "messages": [{"role": "user", "content": "ok"}], "max_tokens": 1}).encode(),
            headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=30)
        except urllib.error.HTTPError as e:
            m = re.search(r"resets? at (\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})", e.read().decode(errors="ignore"))
            if m:
                now = time.time()
                year = datetime.datetime.fromtimestamp(now, datetime.UTC).year
                def at(y):
                    return datetime.datetime(y, int(m[1]), int(m[2]), int(m[3]), int(m[4]), int(m[5]), tzinfo=datetime.UTC).timestamp()
                t = at(year)
                if t <= now: t = at(year + 1)
                print(max(0, int(t - now)) + int(os.environ.get("CYBERGYM_QUOTA_RESET_BUFFER", "60")))
except OSError:
    pass
PY
}

quota_signature() {
  grep -qiE "quota has been exhausted|usage_limit_reached|insufficient_quota|HTTP 429" "$1"
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
  if terminal_ids "${host_corpus}" | grep -qxF "${task_id}"; then
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
    if terminal_ids "${host_corpus}" | grep -qxF "${task_id}"; then
      ran=$((ran + 1))
      break
    fi
    # No kept row: either an error row was just appended, or the runner died
    # before writing one. Evict infra rows, then ALWAYS retry up to the cap —
    # a transient provider stall exits 0 with an evicted error row and no quota
    # signature. A provider-stated reset is trusted; otherwise a reset window
    # is used only when the operator explicitly configured it.
    evict_infra_rows "${host_corpus}" "${task_id}"
    if (( attempt <= CYBERGYM_INFRA_RETRIES )); then
      if quota_signature "${task_log}"; then
        # A weekly/monthly plan wall outlasts the 5h window math; sleep to the
        # provider-stated reset when the engine surfaced one.
        wait_s="$(seconds_to_provider_reset "${task_log}")"
        if [[ -z "${wait_s}" && -n "${CYBERGYM_QUOTA_ANCHOR_EPOCH:-}" ]]; then
          wait_s="$(seconds_to_next_boundary)"
        fi
        if [[ -n "${wait_s}" ]]; then
          printf '[subset] %s hit provider quota; sleeping %ss to reset/boundary\n' "${task_id}" "${wait_s}"
        else
          wait_s="${CYBERGYM_INFRA_RETRY_WAIT_SECONDS:-300}"
          printf '[subset] %s not measured (rc=%d, infra/transient); retrying in %ss\n' "${task_id}" "${rc}" "${wait_s}"
        fi
      else
        wait_s="${CYBERGYM_INFRA_RETRY_WAIT_SECONDS:-300}"
        printf '[subset] %s not measured (rc=%d, infra/transient); retrying in %ss\n' "${task_id}" "${rc}" "${wait_s}"
      fi
      sleep "${wait_s}"
      continue
    fi
    # Out of retries: leave the last error state visible in the task log and
    # move on; the missing corpus row marks the task as not measured.
    printf '[subset] %s NOT measured after %d attempt(s) — see %s\n' "${task_id}" "$((attempt - 1))" "${task_log}"
    break
  done
done < "${subset_file}"

budget_inconclusive_count() {
  python3 - "$1" <<'PY'
import json, sys
count = 0
try:
    for line in open(sys.argv[1]):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("verdict") == "error" and row.get("costCeilingExceeded") is True:
            count += 1
except FileNotFoundError:
    pass
print(count)
PY
}

printf '[subset] DONE %s ran=%d total=%d corpus=%s\n' "$(date -u +%FT%TZ)" "${ran}" "${total}" "${host_corpus}"
budget_inconclusive="$(budget_inconclusive_count "${host_corpus}")"
if (( budget_inconclusive > 0 )); then
  printf '[subset] BUDGET-INCONCLUSIVE rows=%d corpus=%s\n' "${budget_inconclusive}" "${host_corpus}" >&2
  exit 3
fi
