#!/usr/bin/env bash
# Full 104-challenge sweep, 5-way parallel, parametrized.
# Usage: <tag> <bb|wb>    env: 0SEC_MODEL, 0SEC_REPEAT(=1), 0SEC_BENCH_DEPTH(=default)
set -uo pipefail
BENCH=/home/peak/xbow-bench/0sec/packages/benchmark
TAG="${1:?tag}"; MODE="${2:-bb}"
cd "$BENCH"
export PATH="$HOME/.cache/cpkbin:$PATH"
export 0SEC_CHATGPT_ACCESS_TOKEN="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.env.HOME+"/.codex/auth.json","utf8")).tokens.access_token)')"
: "${0SEC_MODEL:?set 0SEC_MODEL}"
export 0SEC_BENCH_DEPTH="${0SEC_BENCH_DEPTH:-default}"
REPEAT="${0SEC_REPEAT:-1}"
WB=""; [ "$MODE" = "wb" ] && WB="--white-box"
echo "[$TAG] $MODE | model=$0SEC_MODEL depth=$0SEC_BENCH_DEPTH repeat=$REPEAT | start $(date -u +%FT%TZ)"
pids=()
for k in 0 1 2 3 4; do
  start=$((k*21))
  pnpm xbow --agentic --runtime api $WB --save-findings --fresh \
    --benchmark-repo 0ca/xbow-validation-benchmarks-patched \
    --start $start --limit 21 --repeat "$REPEAT" \
    --output "$BENCH/results/sweep/${TAG}-shard-$k.json" \
    > "$BENCH/results/sweep/${TAG}-shard-$k.log" 2>&1 &
  pids+=($!); echo "  $TAG shard $k (start=$start)"; sleep 5
done
for p in "${pids[@]}"; do wait "$p"; done
echo "[$TAG] DONE $(date -u +%FT%TZ)"
