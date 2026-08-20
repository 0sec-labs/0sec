#!/bin/bash
# 0verse-lane (CMPLOG/redqueen) vs baseline AFL++ on REAL Magma targets, scored
# against Magma's ground-truth fatal canaries (isan build => a canary trigger
# aborts == a confirmed real-CVE-class bug). Time-to-first-trigger,
# AFL_BENCH_UNTIL_CRASH. Emits zeroverse.benchmark BenchTrial NDJSON.
BUDGET=${BUDGET:-300}
OUT=/root/magma-afl-results.ndjson
: > "$OUT"
declare -A PROG=( [libpng]=libpng_read_fuzzer [libxml2]=libxml2_xml_read_memory_fuzzer
                  [libsndfile]=sndfile_fuzzer [libtiff]=tiff_read_rgba_fuzzer )
run_lane() {  # target prog extra(cmplog|"")
  local t=$1 prog=$2 extra=$3
  docker run --rm --entrypoint bash "magma/aflplusplus/$t:isan" -c '
    set +e
    PROG="'"$prog"'"; EXTRA="'"$extra"'"; W=/tmp/aflw; rm -rf $W; mkdir -p $W/seeds
    cp /magma/targets/'"$t"'/corpus/$PROG/* $W/seeds/ 2>/dev/null || printf x >$W/seeds/s0
    export AFL_BENCH_UNTIL_CRASH=1 AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    AFL=/magma/fuzzers/aflplusplus/repo/afl-fuzz
    BIN=/magma_out/afl/$PROG; CMP=/magma_out/cmplog/$PROG
    [ -n "$EXTRA" ] && EXTRA="-c $CMP"
    t0=$(date +%s%N)
    timeout '"$BUDGET"' $AFL $EXTRA -i $W/seeds -o $W/out -- $BIN @@ >$W/log 2>&1
    t1=$(date +%s%N)
    cr=$(ls $W/out/default/crashes/ 2>/dev/null | grep -c "^id:")
    ex=$(grep -oE "execs_done +: [0-9]+" $W/out/default/fuzzer_stats 2>/dev/null | grep -oE "[0-9]+$")
    echo "RESULT WALL_MS=$(( (t1-t0)/1000000 )) CRASHES=${cr:-0} EXECS=${ex:-0}"
  ' 2>/dev/null | grep "^RESULT"
}
for t in libpng libxml2 libsndfile libtiff; do
  prog=${PROG[$t]}
  for lane in baseline 0verse; do
    extra=""; [ "$lane" = "0verse" ] && extra="cmplog"
    echo ">> $t $lane (budget ${BUDGET}s)" >&2
    line=$(run_lane "$t" "$prog" "$extra")
    wall=$(echo "$line" | grep -oE "WALL_MS=[0-9]+" | cut -d= -f2); wall=${wall:-0}
    cr=$(echo "$line" | grep -oE "CRASHES=[0-9]+" | cut -d= -f2); cr=${cr:-0}
    ex=$(echo "$line" | grep -oE "EXECS=[0-9]+" | cut -d= -f2); ex=${ex:-0}
    found=false; ttc=null; [ "$cr" -gt 0 ] && { found=true; ttc=$(awk "BEGIN{print $wall/1000}"); }
    echo "{\"schema_version\":\"1.0\",\"target\":\"magma/$t\",\"lane\":\"$lane\",\"crash_found\":$found,\"confirmed_pov\":$found,\"time_to_crash_s\":$ttc,\"budget_s\":$BUDGET,\"execs\":$ex,\"execs_per_sec\":0.0,\"note\":\"magma fatal-canary; crash==ground-truth bug trigger\"}" >> "$OUT"
    echo "   $t $lane: crash=$found ttc=$ttc execs=$ex" >&2
  done
done
echo "MAGMA AFL CAMPAIGN DONE -> $OUT" >&2; cat "$OUT" >&2
