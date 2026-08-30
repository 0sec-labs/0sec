#!/usr/bin/env bash
# Run a single codex model over the currently-unsolved XBOW challenges, white-box,
# best-of-10. Unions into the existing results/shards/ via mm-<model>-*.json files.
# Usage: env 0SEC_MODEL=gpt-5.4 ./run-model-pass.sh <tag>
set -uo pipefail
BENCH=/home/peak/xbow-bench/0sec/packages/benchmark
TAG="${1:-mm}"
cd "$BENCH"
export PATH="$HOME/.cache/cpkbin:$PATH"
CHATGPT_ACCESS_TOKEN="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.env.HOME+"/.codex/auth.json","utf8")).tokens.access_token)')"
[[ -n "${CHATGPT_ACCESS_TOKEN}" ]] || { echo "missing ChatGPT Codex access token" >&2; exit 2; }
OSEC_MODEL="$(printenv 0SEC_MODEL 2>/dev/null || true)"
[[ -n "${OSEC_MODEL}" ]] || { echo "set 0SEC_MODEL" >&2; exit 2; }
CAP="$(printenv 0SEC_COST_CAP 2>/dev/null || true)"      # per-challenge $ ceiling across the repeat attempts
: "${CAP:=5}"
REPEAT="$(printenv 0SEC_REPEAT 2>/dev/null || true)"   # attempts per challenge
: "${REPEAT:=10}"

UNSOLVED=$(node -e '
const fs=require("fs");const d=process.argv[1];const solved=new Set(),all=new Set();
for(const f of fs.readdirSync(d).filter(x=>/-[0-9]+\.json$/.test(x))){
  const r=JSON.parse(fs.readFileSync(d+"/"+f));
  for(const c of (r.results||[])){all.add(c.id);if(c.flagFound)solved.add(c.id);}
}
console.log([...all].filter(id=>!solved.has(id)).sort().join(","));
' "$BENCH/results/shards")

echo "[$TAG/${OSEC_MODEL}] start $(date -u +%FT%TZ) | unsolved: ${UNSOLVED:-NONE}"
[ -z "$UNSOLVED" ] && { echo "nothing unsolved"; exit 0; }

IFS="," read -ra IDS <<< "$UNSOLVED"
pids=()
for i in "${!IDS[@]}"; do
  id="${IDS[$i]}"
  env \
    "0SEC_CHATGPT_ACCESS_TOKEN=${CHATGPT_ACCESS_TOKEN}" \
    "0SEC_MODEL=${OSEC_MODEL}" \
    pnpm xbow --agentic --runtime api --white-box --save-findings --fresh \
    --benchmark-repo 0ca/xbow-validation-benchmarks-patched \
    --only "$id" --repeat "$REPEAT" --repeat-cost-ceiling-usd "$CAP" \
    --output "$BENCH/results/shards/${TAG}-shard-$i.json" \
    > "$BENCH/results/shards/${TAG}-shard-$i.log" 2>&1 &
  pids+=($!); echo "  $TAG shard $i: $id (pid $!)"; sleep 5
done
for p in "${pids[@]}"; do wait "$p"; done
echo "[$TAG/${OSEC_MODEL}] DONE $(date -u +%FT%TZ)"
