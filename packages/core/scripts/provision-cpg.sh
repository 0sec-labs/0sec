#!/usr/bin/env bash
#
# provision-cpg.sh — build the pre-exported Joern CPG that `pwnkit hunt
# --graph-slice` consumes. Produces the graphson JSON the graph-slice stage
# loads (packages/core/src/stages/graph-slice.ts).
#
# WHY a separate script: Joern is a Java tool (c2cpg + joern-export) that must
# run where the source is; we deliberately do NOT bundle it into the npm
# package. The graph-slice stage reads the JSON this script emits and
# fail-opens to the flat-text finder when it is absent. Provisioning Joern
# inside the cloud sandbox so the stage can build-on-demand is a follow-up.
#
# Bench-measured feasibility (docs/operations/graph-native-lpe-harness-2026-07-21.md):
#   net/unix (5 files):  c2cpg 1.8s / 302MB.
#   whole net/ (1537 files, 38MB):  c2cpg 29.7s / 14.6GB / 67MB CPG.
# Subsystem-scale fits a 24c/62GB box; do NOT try to build a whole-kernel CPG.
#
# Usage:
#   provision-cpg.sh <source-root> <subsystem> [out-dir] [joern-cli-dir]
# Example:
#   provision-cpg.sh /root/linux-6.12-git net/unix
#     -> writes <source-root>/.pwnkit/cpg/net__unix.json  (the convention the
#        stage loads by default). Then run:
#        pwnkit hunt --source /root/linux-6.12-git --seed fix.patch --graph-slice
#
# The optional Phase-1 ops map (<slug>.ops.json) is produced separately by the
# tree-sitter ops harvester (bench:/root/graph-lpe/ops_harvest.py) — the stage
# picks it up automatically when present next to the CPG JSON.
set -euo pipefail

SRC_ROOT="${1:?usage: provision-cpg.sh <source-root> <subsystem> [out-dir] [joern-cli-dir]}"
SUBSYS="${2:?missing <subsystem> (e.g. net/unix)}"
SLUG="${SUBSYS//\//__}"
OUT_DIR="${3:-${SRC_ROOT}/.pwnkit/cpg}"
JOERN_DIR="${4:-${JOERN_HOME:-/root/joern-cli}}"

SUBSYS_DIR="${SRC_ROOT}/${SUBSYS}"
[ -d "$SUBSYS_DIR" ] || { echo "error: subsystem dir not found: $SUBSYS_DIR" >&2; exit 1; }
[ -x "${JOERN_DIR}/c2cpg.sh" ] || { echo "error: c2cpg.sh not found under $JOERN_DIR (set JOERN_HOME or pass joern-cli-dir)" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
CPG_BIN="${WORK}/cpg.bin.zip"
EXPORT_DIR="${WORK}/export"
mkdir -p "$OUT_DIR"

# Heap: roughly 2x the source footprint, capped; net/ (38MB) needed ~16GB.
XMX="${PWNKIT_CPG_XMX:-16000}"

echo "[provision-cpg] c2cpg over ${SUBSYS_DIR} (Xmx=${XMX}m) ..." >&2
"${JOERN_DIR}/c2cpg.sh" -J-Xmx"${XMX}"m "$SUBSYS_DIR" --output "$CPG_BIN"

# Add the DDG/PDG dataflow overlay (REACHING_DEF edges the slicer walks), then
# export the whole CPG to graphson JSON.
echo "[provision-cpg] ossdataflow overlay + graphson export ..." >&2
"${JOERN_DIR}/joern" --script /dev/stdin <<EOF
importCpg("${CPG_BIN}")
run.ossdataflow
save
EOF

"${JOERN_DIR}/joern-export" --repr all --format graphson --out "$EXPORT_DIR" "$CPG_BIN"

# joern-export writes export.json (+ optional shards) into EXPORT_DIR.
SRC_JSON="${EXPORT_DIR}/export.json"
[ -f "$SRC_JSON" ] || SRC_JSON="$(find "$EXPORT_DIR" -maxdepth 1 -name '*.json' | head -1)"
[ -f "$SRC_JSON" ] || { echo "error: joern-export produced no JSON under $EXPORT_DIR" >&2; exit 1; }

DEST="${OUT_DIR}/${SLUG}.json"
cp "$SRC_JSON" "$DEST"
echo "[provision-cpg] wrote ${DEST} ($(du -h "$DEST" | cut -f1))" >&2
echo "[provision-cpg] next: pwnkit hunt --source ${SRC_ROOT} --seed <fix.patch> --graph-slice" >&2
