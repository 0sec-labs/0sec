#!/usr/bin/env bash
# Full 104-challenge sweep, 5-way parallel, parametrized.
# Usage: <tag> <bb|wb>    env: PWNKIT_MODEL, PWNKIT_REPEAT(=1), PWNKIT_BENCH_DEPTH(=default)
set -uo pipefail
BENCH=/home/peak/xbow-bench/pwnkit/packages/benchmark
TAG="${1:?tag}"; MODE="${2:-bb}"
cd "$BENCH"
export PATH="$HOME/.cache/cpkbin:$PATH"
export PWNKIT_CHATGPT_ACCESS_TOKEN="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.env.HOME+"/.codex/auth.json","utf8")).tokens.access_token)')"
: "${PWNKIT_MODEL:?set PWNKIT_MODEL}"
export PWNKIT_BENCH_DEPTH="${PWNKIT_BENCH_DEPTH:-default}"
REPEAT="${PWNKIT_REPEAT:-1}"
WB=""; [ "$MODE" = "wb" ] && WB="--white-box"
echo "[$TAG] $MODE | model=$PWNKIT_MODEL depth=$PWNKIT_BENCH_DEPTH repeat=$REPEAT | start $(date -u +%FT%TZ)"
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
