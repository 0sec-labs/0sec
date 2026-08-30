#!/usr/bin/env bash
#
# provision-cpg.sh — build the pre-exported Joern CPG that `0sec hunt
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
#     -> writes <source-root>/.0sec/cpg/net__unix.json  (the convention the
#        stage loads by default). Then run:
#        0sec hunt --source /root/linux-6.12-git --seed fix.patch --graph-slice
# For code selected by kernel Kconfig, pass its enabled symbols as a
# comma-separated environment variable, for example:
#   env 0SEC_CPG_DEFINES=CONFIG_SMB_SERVER_KERBEROS5=1 provision-cpg.sh …
# This lets c2cpg retain the compiled branch instead of indexing the fallback
# `#else` stub.
#
# Phase-1 static dispatch can use either a precomputed `<slug>.ops.json` next
# to the CPG, or the in-process harvester:
#   0sec hunt ... --graph-slice --ops-harvest net/unix/af_unix.c
set -euo pipefail

SRC_ROOT="${1:?usage: provision-cpg.sh <source-root> <subsystem> [out-dir] [joern-cli-dir]}"
SUBSYS="${2:?missing <subsystem> (e.g. net/unix)}"
SLUG="${SUBSYS//\//__}"
OUT_DIR="${3:-${SRC_ROOT}/.0sec/cpg}"
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
XMX="$(printenv 0SEC_CPG_XMX 2>/dev/null || true)"
: "${XMX:=16000}"
CPG_DEFINES="$(printenv 0SEC_CPG_DEFINES 2>/dev/null || true)"

declare -a C2CPG_ARGS
C2CPG_ARGS=(-J-Xmx"${XMX}"m)
if [ -n "$CPG_DEFINES" ]; then
  IFS=',' read -r -a C2CPG_DEFINES_ARRAY <<< "$CPG_DEFINES"
  for DEFINE in "${C2CPG_DEFINES_ARRAY[@]}"; do
    DEFINE="${DEFINE//[[:space:]]/}"
    [ -n "$DEFINE" ] || continue
    C2CPG_ARGS+=(--define "$DEFINE")
  done
  echo "[provision-cpg] enabled preprocessor definitions: ${CPG_DEFINES}" >&2
fi

echo "[provision-cpg] c2cpg over ${SUBSYS_DIR} (Xmx=${XMX}m) ..." >&2
"${JOERN_DIR}/c2cpg.sh" "${C2CPG_ARGS[@]}" "$SUBSYS_DIR" --output "$CPG_BIN"

# GraphSON's supported whole-CPG representation is `all`: it contains the
# METHOD/CALL/AST nodes the slicer needs and Joern computes a missing dataflow
# overlay while exporting. Do NOT pre-run `joern --script ... run.ossdataflow`:
# on Joern 4 it can leave a non-interactive process hung after saving, while
# joern-export completes the same overlay itself. There is no call-only GraphSON
# representation (`--repr ast` is unsupported for graphson), so do not expose a
# misleading skip-dataflow switch.
echo "[provision-cpg] exporting GraphSON + dataflow overlay ..." >&2
"${JOERN_DIR}/joern-export" --repr all --format graphson --out "$EXPORT_DIR" "$CPG_BIN"

# joern-export writes export.json (+ optional shards) into EXPORT_DIR.
SRC_JSON="${EXPORT_DIR}/export.json"
[ -f "$SRC_JSON" ] || SRC_JSON="$(find "$EXPORT_DIR" -maxdepth 1 -name '*.json' | head -1)"
[ -f "$SRC_JSON" ] || { echo "error: joern-export produced no JSON under $EXPORT_DIR" >&2; exit 1; }

DEST="${OUT_DIR}/${SLUG}.json"
cp "$SRC_JSON" "$DEST"
echo "[provision-cpg] wrote ${DEST} ($(du -h "$DEST" | cut -f1))" >&2
echo "[provision-cpg] next: 0sec hunt --source ${SRC_ROOT} --seed <fix.patch> --graph-slice" >&2
