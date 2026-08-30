#!/usr/bin/env bash
# Full 104-challenge sweep, 5-way parallel, parametrized.
# Usage: env 0SEC_MODEL=<model> 0SEC_REPEAT=1 0SEC_BENCH_DEPTH=default ./run-full-sweep.sh <tag> <bb|wb>
set -uo pipefail
BENCH=/home/peak/xbow-bench/0sec/packages/benchmark
TAG="${1:?tag}"; MODE="${2:-bb}"
cd "$BENCH"
export PATH="$HOME/.cache/cpkbin:$PATH"
CHATGPT_ACCESS_TOKEN="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.env.HOME+"/.codex/auth.json","utf8")).tokens.access_token)')"
[[ -n "${CHATGPT_ACCESS_TOKEN}" ]] || { echo "missing ChatGPT Codex access token" >&2; exit 2; }
OSEC_MODEL="$(printenv 0SEC_MODEL 2>/dev/null || true)"
[[ -n "${OSEC_MODEL}" ]] || { echo "set 0SEC_MODEL" >&2; exit 2; }
OSEC_BENCH_DEPTH="$(printenv 0SEC_BENCH_DEPTH 2>/dev/null || true)"
: "${OSEC_BENCH_DEPTH:=default}"
REPEAT="$(printenv 0SEC_REPEAT 2>/dev/null || true)"
: "${REPEAT:=1}"
WB=""; [ "$MODE" = "wb" ] && WB="--white-box"
echo "[$TAG] $MODE | model=${OSEC_MODEL} depth=${OSEC_BENCH_DEPTH} repeat=$REPEAT | start $(date -u +%FT%TZ)"
pids=()
for k in 0 1 2 3 4; do
  start=$((k*21))
  env \
    "0SEC_CHATGPT_ACCESS_TOKEN=${CHATGPT_ACCESS_TOKEN}" \
    "0SEC_MODEL=${OSEC_MODEL}" \
    "0SEC_BENCH_DEPTH=${OSEC_BENCH_DEPTH}" \
    pnpm xbow --agentic --runtime api $WB --save-findings --fresh \
    --benchmark-repo 0ca/xbow-validation-benchmarks-patched \
    --start $start --limit 21 --repeat "$REPEAT" \
    --output "$BENCH/results/sweep/${TAG}-shard-$k.json" \
    > "$BENCH/results/sweep/${TAG}-shard-$k.log" 2>&1 &
  pids+=($!); echo "  $TAG shard $k (start=$start)"; sleep 5
done
for p in "${pids[@]}"; do wait "$p"; done
echo "[$TAG] DONE $(date -u +%FT%TZ)"
