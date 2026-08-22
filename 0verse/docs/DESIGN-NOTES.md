# Design notes — lessons from prior art

> Distilled from source-level study of three reference systems (2026-06-27).
> These decisions drive the M1/M2 architecture in [../ROADMAP.md](../ROADMAP.md).

## Systems studied

| System | What it is | What we take |
|---|---|---|
| **CYD `mole`** | Binary Ninja MLIL backward-slicing + LLM triage | Taint-model schema, slice-then-intersect strategy, LLM-on-the-slice prompt |
| **Atlantis** (Team Atlanta, AIxCC 🥇) | K8s multi-module CRS, fuzzing+concolic+LLM | Orchestration DNA: deterministic scheduler, LLM-as-worker, cost discipline |
| **Buttercup** (Trail of Bits, AIxCC 🥈) | Leaner CRS, cheaper models (~$181/bug) | Deterministic scheduler, tiered-model cost discipline, WASI generator-code trick |

> Cross-project reuse (foxguard as the decompiled-C static pass; the source-side
> engine's oracle boundary) is its own doc: [INTEGRATION.md](INTEGRATION.md).

**Framing caveat:** AIxCC was *source-available* (provided harnesses + ASan/UBSan/Jazzer). Binary-only loses all three. We take the *orchestration*, and must build the *substrate* (harness synthesis, crash oracle, sink detection) ourselves.

---

## Decision 1 — Deterministic orchestrator; the LLM is a worker, not the router

The single biggest lesson from the AIxCC winner: **there is no "LLM decides everything" loop.** A coded scheduler owns *what runs when*; the LLM is dispatched for bounded subtasks (driver synthesis, seed/payload scripts, sink triage, last-mile exploit reasoning). Atlantis's own conclusion: *"comprehensive vulnerability discovery requires solid engineering fundamentals before adding LLM."*

→ 0verse's `pipeline.py` stays a deterministic scheduler. `agent.py` is a worker invoked at specific stages. We resist making the agent the top-level controller.

## Decision 2 — Traditional fuzzing is the backbone; LLM is a selective multiplier

Atlantis got ~57% of its PoVs from plain corpus+fuzzer; each LLM-heavy generator added only single-digit %. → AFL++ (QEMU mode for binary-only) + a good seed corpus is the **floor**. angr concolic and the LLM layer *on top*, gated behind cheap signals (stuck fuzzer, reached-but-uncrashed sink).

## Decision 3 — Adopt mole's taint-model schema almost verbatim

The most directly portable artifact. JSON, `taint_model → library → category → function`, merged from `conf/NNN-*.json` in filename order so users extend by dropping a file:

```json
"read":   { "synopsis": "ssize_t read (int filedes, void *buffer, size_t size)",
            "roles": { "source": { "enabled": true, "par_slice": "i == 2" } } },
"memcpy": { "synopsis": "void * memcpy (void *to, const void *from, size_t size)",
            "roles": { "sink":   { "enabled": true, "par_slice": "True" } } }
```

- `synopsis` = real C prototype → parse for arg count / varargs.
- `par_slice` = tiny boolean DSL over 1-based arg index `i` (`i == 2`, `True`, `i >= 2`). **Reimplement with an `ast`-whitelist evaluator, NOT mole's `eval()`.**
- `fixer` role = apply the prototype to the binary before analysis to sharpen decompilation.
- Port mole's `conf/003-libc.json` (113 funcs, 51 sources / 62 sinks) as the seed corpus.

## Decision 4 — Engine-agnostic slicer behind a thin IL adapter

mole's `core/slice.py` (traversal) is cleanly separable from Binary-Ninja queries (funneled through `FunctionHelper`). We mirror that seam so the *same* `BackwardSlicer` + `CallTracker` run over either backend:

```
Slicer (pure traversal over abstract nodes: VAR/PHI/CALL/LOAD/STORE/BINOP/RET)
  └── ILAdapter interface:
        get_def(var) · get_uses · get_memory_defs(version) · get_callers(func)
        get_callee_returns(func) · get_param_insts(func) · get_ptr_map(func)
  ├── GhidraAdapter   (P-Code SSA via HighFunction; alias on PTRADD/PTRSUB/LOAD/STORE)  ← default
  └── BinjaAdapter    (MLIL-SSA; optional, license holders)
```

Strategy (from mole's `PathService`): slice sources and sinks **independently**, cache source slices, then emit a finding where the two backward slices **intersect** (graph reachability via networkx `all_simple_paths`/`shortest_path`). Annotate instruction-graph nodes as `(call_site, inst)` for context sensitivity. Carry a pointer/out-param map so taint follows *through* `read(fd,buf,n)`/`memcpy(dst,...)` arguments.

## Decision 5 — LLM triage: feed the *slice*, not the binary; give it read-only tools

mole's prompt feeds the path (instructions tagged `[Src]/[Snk]` + call sequence), not raw decompilation, then lets the model pull code on demand via 4 read-only tools (`get_code(addr, il_level)`, `get_callers(name|addr)`). Structured output:

```python
{ truePositive: bool, vulnerabilityClass: CWE-enum, shortExplanation: str,
  severityLevel: Low|Medium|High|Critical, inputExample: str }
```

Keep a no-API **mock mode** for pipeline testing. From Atlantis: have the LLM emit a **Python "payload recipe" (`create_payload() -> bytes`) refined on feedback**, not raw bytes.

## Decision 6 — The three substrate gaps binary-only forces us to build

AIxCC got these for free from source; we must build them, and they are the hard part:

1. **Harness / driver synthesis.** No source harness exists. Recover a function signature from Ghidra → LLM writes an AFL++/Qiling driver that calls it. (This is also the best-evidenced LLM win — OSS-Fuzz-Gen.)
2. **Crash oracle without sanitizers.** AIxCC keyed on ASan/UBSan return codes (1/77/70/71). We approximate with native crash signals (SIGSEGV/SIGABRT), QEMU/Valgrind, optional ASan-on-recompile, or guard-page harnesses — and accept a noisier oracle. Non-crashing memory bugs are invisible without instrumentation; say so.
3. **Coverage → decompiled-line mapping.** LLMs can't read edge coverage. Atlantis converts edge→source-line before showing the model anything. Our analog: map basic-block/edge coverage to **Ghidra decompiler lines / disassembly addresses**. Build this translation layer early.

Plus: sink detection via **Ghidra P-Code taint** (not CodeQL/Joern), and the **"last-mile" insight** — 73.8% of sinks get *reached* but only 35.7% *exploited*; spend LLM reasoning on reached-but-uncrashed targets (highest ROI).

## Decision 7 — Cost discipline is a subsystem, from day one

- LiteLLM-style proxy with **per-stage budgets + API keys + rate limits**.
- **Cache every LLM interaction and static-analysis lookup** to disk/Redis (re-runs cost zero tokens).
- Deterministic **PoV verifier**: re-run blob → classify crash signal → **stack-trace dedup** (never an LLM). Add a second "does an existing repro already cover this" layer.
- Prefer "first output that passes a cheap oracle" over LLM-judge ensembling.

## Decision 8 — Buttercup-specific adoptions (the lean, cheap path)

Buttercup placed 2nd with a **~7-function deterministic polling loop and NO symbolic
execution at all** — the LLM only writes inputs/patches. Reinforces Decision 1 and
adds concrete machinery:

- **Tiered models + fallback chains** behind a LiteLLM proxy with per-stage
  **virtual budget keys** (the mechanism behind ~$181/bug): cheap workhorse model by
  default, `mini`/`nano` tier for high-frequency cheap calls (snippet filtering,
  dedup, classification), strong model reserved for root-cause/PoV reasoning.
  `.with_fallbacks()` spends on failure, not speculatively.
- **WASI-sandboxed "LLM writes a `gen()->bytes` generator function"** (wasmtime) for
  seed/PoV synthesis — safer and far more token-efficient than emitting raw bytes,
  and **fully source-independent**, so it transfers to no-source binaries directly.
- **ClusterFuzz-style crash dedup** (`crash_state` = normalized top frames +
  instrumentation key + line) over a shared Redis set — build the frames from the
  Ghidra/ASan symbolized backtrace.
- **Softmax-over-inverse-coverage** to steer the LLM toward under-covered code —
  works on AFL++/angr edge coverage, not just `llvm-cov`.
- **Reflection loop-break**: same failure category N times ⇒ forcibly switch
  strategy; hard retry caps per phase. A deterministic guardrail around LLM loops.

---

## Net effect on the MVP (ROADMAP M1)

The M1 vertical slice is unchanged in scope but now has a proven shape:
**Ghidra decompile → P-Code backward-slice with the ported taint model → intersect source/sink slices → LLM triages the slice (structured output) → angr proves reachability → PoV verifier re-runs + classifies + dedups → report.** Fuzzing/harness-synthesis (M2) layers on as the backbone once the slice→PoV loop is green.
