# Ghidra headless post-script — runs INSIDE Ghidra's interpreter (PyGhidra/Jython),
# NOT under the zeroverse package. Invoked by the GhidraAdapter as:
#
#   $GHIDRA_HOME/support/analyzeHeadless <proj_dir> tmp -import <binary> \
#       -postScript ghidra_export.py <out.json> -scriptPath docker
#
# It walks the decompiled HighFunction (P-Code SSA) and emits the JSON the
# ILAdapter consumes: functions, their P-Code instructions (kind + operands),
# def-use edges, call sites, and memory defs.
#
# STATUS (M1 #1, landed): the adapter now drives Ghidra **in-process** via
# PyGhidra — `GhidraAdapter.analyze()` opens the program, walks
# `HighFunction.getPcodeOps()` (high P-Code SSA), resolves callee names through
# thunks and `.plt.sec` stubs, and emits `ProgramMeta` (decompiled C, imports,
# exports, call graph, `unresolved_edges`). The result is cached as the export
# JSON (`GhidraAdapter.to_json`), keyed by the binary's content hash.
#
# This standalone `analyzeHeadless -postScript` path is kept as the documented
# *batch* alternative (DESIGN-NOTES Decision 4 node model:
# VAR/PHI/CALL/LOAD/STORE/BINOP/RET/CONST/PARAM); the in-process path above is
# what the pipeline uses today.

raise SystemExit(
    "ghidra_export.py: use GhidraAdapter.analyze() (in-process PyGhidra) — "
    "this batch post-script path is not wired"
)
