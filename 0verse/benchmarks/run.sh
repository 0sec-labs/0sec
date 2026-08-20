#!/usr/bin/env bash
# 0verse benchmark corpus — compile each known-vuln program and assert the
# pipeline CONFIRMS the expected source->sink with a reproducing PoV.
# Run inside the 0verse image:  docker run --rm -v "$PWD:/work" ... bash /work/benchmarks/run.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${ZEROVERSE_SRC:-/work/src}"
export ZEROVERSE_CONF="${ZEROVERSE_CONF:-$(dirname "$HERE")/conf}"

# name | compile flags | expected "source:sink"
CASES=(
  "cmdi||getenv:system"
  "overflow|-fno-stack-protector -no-pie|read:strcpy"
  "heap_overflow|-no-pie|read:strcpy"
)

run_one() {
  local name="$1" flags="$2" expect="$3"
  local bin="/tmp/bench_$name"
  # shellcheck disable=SC2086
  gcc -O0 -no-pie $flags -o "$bin" "$HERE/$name.c" 2>/dev/null || { echo "FAIL[$name]: compile"; return 1; }
  local json
  json="$(PYTHONPATH="$SRC" python -m zeroverse.cli run "$bin" --format json 2>/dev/null)"
  ZV_EXPECT="$expect" python - "$json" <<'PY'
import json, os, sys
want_src, want_sink = os.environ["ZV_EXPECT"].split(":")
data = json.loads(sys.argv[1])
ok = any(f["confirmed"] and f["source"] == want_src and f["sink"] == want_sink
         for f in data["findings"])
sys.exit(0 if ok else 1)
PY
}

fails=0
for c in "${CASES[@]}"; do
  IFS='|' read -r name flags expect <<<"$c"
  if run_one "$name" "$flags" "$expect"; then
    echo "PASS[$name]: confirmed $expect"
  else
    echo "FAIL[$name]: expected confirmed $expect"
    fails=$((fails + 1))
  fi
done
echo "---"; echo "$(( ${#CASES[@]} - fails ))/${#CASES[@]} benchmarks passed"
exit "$fails"
