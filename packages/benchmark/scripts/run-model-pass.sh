#!/usr/bin/env bash
# Run a single codex model over the currently-unsolved XBOW challenges, white-box,
# best-of-10. Unions into the existing results/shards/ via mm-<model>-*.json files.
# Usage: 0SEC_MODEL=gpt-5.4 ./run-model-pass.sh <tag>
set -uo pipefail
BENCH=/home/peak/xbow-bench/0sec/packages/benchmark
TAG="${1:-mm}"
cd "$BENCH"
export PATH="$HOME/.cache/cpkbin:$PATH"
export 0SEC_CHATGPT_ACCESS_TOKEN="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.env.HOME+"/.codex/auth.json","utf8")).tokens.access_token)')"
: "${0SEC_MODEL:?set 0SEC_MODEL}"
CAP="${0SEC_COST_CAP:-5}"      # per-challenge $ ceiling across the repeat attempts
REPEAT="${0SEC_REPEAT:-10}"   # attempts per challenge

UNSOLVED=$(node -e '
const fs=require("fs");const d=process.argv[1];const solved=new Set(),all=new Set();
for(const f of fs.readdirSync(d).filter(x=>/-[0-9]+\.json$/.test(x))){
  const r=JSON.parse(fs.readFileSync(d+"/"+f));
  for(const c of (r.results||[])){all.add(c.id);if(c.flagFound)solved.add(c.id);}
}
console.log([...all].filter(id=>!solved.has(id)).sort().join(","));
' "$BENCH/results/shards")

echo "[$TAG/$0SEC_MODEL] start $(date -u +%FT%TZ) | unsolved: ${UNSOLVED:-NONE}"
[ -z "$UNSOLVED" ] && { echo "nothing unsolved"; exit 0; }

IFS="," read -ra IDS <<< "$UNSOLVED"
pids=()
for i in "${!IDS[@]}"; do
  id="${IDS[$i]}"
  pnpm xbow --agentic --runtime api --white-box --save-findings --fresh \
    --benchmark-repo 0ca/xbow-validation-benchmarks-patched \
    --only "$id" --repeat "$REPEAT" --repeat-cost-ceiling-usd "$CAP" \
    --output "$BENCH/results/shards/${TAG}-shard-$i.json" \
    > "$BENCH/results/shards/${TAG}-shard-$i.log" 2>&1 &
  pids+=($!); echo "  $TAG shard $i: $id (pid $!)"; sleep 5
done
for p in "${pids[@]}"; do wait "$p"; done
echo "[$TAG/$0SEC_MODEL] DONE $(date -u +%FT%TZ)"
