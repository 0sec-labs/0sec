# 0verse architecture

> Status: 2026-07-25. Scope frozen: 0verse is an evidence-producer/notary,
> not a dispatchable platform engine, until the blind stripped-binary gate passes.
> M1–M7 describe in-tree implementation and test/proof coverage, not uniform live
> or operational maturity. Expensive or mutating lanes remain opt-in by flag.

## One-line story

> *0verse is a binary-native Cyber Reasoning System: an agentic orchestration
> layer over free binary-analysis engines (Ghidra headless, angr, AFL++). The
> LLM writes fuzz harnesses, guides exploration, and triages crashes; the engine
> proves each hypothesis with a reproducing PoV and proposes a verified patch —
> but a runnable proof-of-vuln is the only thing that counts as a finding. The
> moat, as with the rest of the 0sec line, is the dataset and trust, not the
> engine.*

## Design principles

1. **PoV is the unit of truth.** A finding without a reproducing input + crash
   trace is a hypothesis, not a finding. This is the single biggest
   credibility differentiator and mirrors Big Sleep / OSS-Fuzz / AIxCC.
2. **Open engine by default.** Ghidra (Apache-2.0) is the default decompiler so
   the whole tool is free and redistributable in a Docker image. No end-user
   needs a paid license to run the core pipeline.
3. **LLM guides and synthesizes; it does not adjudicate.** The proven LLM wins
   are harness synthesis, seed generation, and triage *around* a fuzzing +
   symbolic core — not "read the disassembly and name the bug."
4. **Hybrid by default.** Fuzzing finds shallow bugs fast; symbolic execution
   gets past magic-value/checksum gates. The CGC/Mayhem lesson: combine them,
   with the LLM as the router deciding when to spend symbolic budget.
5. **Honest benchmarks.** Every claim is measured against plain AFL++
   (FuzzBench/Magma). Negative results are published.
6. **Close the loop (the CRS second half).** A confirmed PoV is not the end:
   propose a fix and prove it closes the PoV without regression. A patch is
   `verified` only by the same deterministic, LLM-free adjudicator that confirms
   a PoV — the AIxCC scoring discipline, applied to binary-only targets.

## Scope decision and maturity vocabulary

This repository follows
[0sec ADR-066](https://github.com/0sec-labs/0sec/blob/main/docs/DECISIONS.md#adr-066--2026-07-17--0verse-is-an-evidence-producernotary-input-not-a-dispatchable-engine-yet):
**0verse produces and notarizes evidence out of band; it is not a generic
managed dispatch engine.** Dispatch investment is gated on a blind run that
confirms a known-CVE stripped x86-64 ELF. Until that gate passes, the generic
cloud job type, engine template, and agent-callable binary tool are parked.

Capability statements use these terms:

| Term | Meaning |
|---|---|
| **implemented** | Code exists in-tree; this alone says nothing about validation or usability. |
| **unit-tested** | Focused deterministic tests cover the code path with controlled doubles or inputs. |
| **fixture-proven** | A committed proof or benchmark reproduces the claimed behavior on a controlled fixture. |
| **live-proven** | Reproducible evidence records the behavior on a target-relevant artifact and environment outside the controlled fixture set. |
| **operational** | An owned, repeatable workflow is deployed, monitored, and supported for its stated users and boundary. |
| **unsupported** | No supported safe/correct path exists for the stated use, even if partial code or a research seam exists. |
| **parked** | Further investment is outside the current ordered program; existing code may remain for evidence or later review. |

The first five terms are a maturity ladder: a lower level never implies a higher
one. `unsupported` describes the usable boundary; `parked` describes priority.
Windows and browser execution expansion, Mach-O dynamic expansion, and generic
cloud dispatch are parked. Their existing ingest, adapter, unit-test, or fixture
work must not be described as live-proven or operational. Firmware Scout is a
separate ordered research program and is not parked by this decision; its R0–R5
sequence remains tracked in
[issue #84](https://github.com/0sec-labs/0verse/issues/84).

## The pipeline

A deterministic scheduler runs a swappable, best-effort stage spine; every
optional engine degrades gracefully rather than blocking the run.

```
 (1) ingest      format / arch / compiler / mitigations / packing      pure-python ELF/Mach-O/PE/.ko + LIEF/capa when present
 (2) decompile   functions + CFG + pseudo-C                            Ghidra headless (default) | rizin/r2 | angr (fallbacks)
 (3) lift        IR + call graph + data-flow + source/sink tagging     Ghidra P-Code SSA | pseudo-C IL (cdecomp)
 (4) analyze     static bug hypotheses, high-recall, unioned:          backward source→sink slice
                   + foxguard C-taint pre-pass                         foxguard (optional, graceful stub)
                   + 90-archetype seed registry / kernel·IOKit seeds   seedcatalog / seedbugs
                   + five bug-class lenses (overflow/intoverflow/       bugclasses
                     fmtstring/uaf/cmdi) + logic (hypothesis-only)
 (5) prime       optional flywheel recall/rank/cost priming             flywheel memory (never confirms)
 (6) reason      cheap→expensive LLM triage funnel + harness synth     provider-agnostic agent loop (TriageFunnel)
 (7) dynamic     prove reachability / trigger crash:                   angr concolic prune (Ghidra-only),
                   angr UNSAT-prune → crash oracle → fuzz complement     differential-allocator/quarantine-guard/
                   (AFL++ QEMU-mode CMPLOG [+ directed scheduling +      exec-trap oracles, AFL++, DistanceDriller,
                   DistanceDriller], Qiling firmware lane)               Qiling (firmware)
 (8) poc         crashing input + exploitability class                 pwntools standalone replay
 (9) patch       fix the confirmed PoV, verify it no longer reproduces patch stage (B0 recommendation always; opt-in
                  without regression (opt-in, ZEROVERSE_PATCH=1)        source-diff / binary micro-patch)
 (10) report     evidence-backed finding (+ PoV + patch)               json / sarif / ndjson / markdown; --cloud sink
```

Stages 1–8 are the always-on find→prove spine; stage 9 (patch+verify), the
directed-fuzzing lane inside stage 7, the scheduler, and the flywheel are merged
but **opt-in** behind `ZEROVERSE_PATCH` / `ZEROVERSE_DIRECTED` /
`ZEROVERSE_SCHEDULER` / `ZEROVERSE_FLYWHEEL` when they add cost, mutate artifacts,
or change ordering. None of those flags can create a confirmed finding; only the
oracle can.

Each stage is a module behind a typed interface so backends swap cleanly and
stages can run standalone (`0verse triage` is just stage 1). The fuzz complement
runs only when the static slice confirmed nothing (or `ZEROVERSE_FORCE_FUZZ`):
a synthesized harness without a reproduced crash is an artifact, never a finding.

## Stack decision (and why)

| Layer | Choice | Why |
|---|---|---|
| Core / orchestration | **Python** | The two engines we depend on (Ghidra via pyghidra/Ghidrathon, and angr) are Python-first; capa/LIEF/Unicorn/pwntools/MCP are all Python. TS would FFI-bridge everything; Rust has no decompiler or symbolic engine. |
| Default decompiler | **Ghidra headless** (Apache-2.0) | Only mature decompiler that is legally redistributable and free for every user. P-Code IR, broad arch coverage, healthy pyghidra/MCP ecosystem. |
| Symbolic execution | **angr** (BSD-2) | No production Rust/other substitute exists. |
| Binary-only fuzzing | **AFL++** (Apache-2.0, QEMU/Frida modes) | libFuzzer/SymCC need source; AFL++ covers no-source via emulation. |
| Optional premium decompiler | **Binary Ninja** adapter | Best HLIL, but headless needs $1,499+/seat — opt-in only, never bundled. |
| Hot leaf components (later) | **Rust via PyO3** | `goblin`/`object`/`iced-x86` are excellent for parsing/x86 decode. Use selectively, not as the brain. |

**Rust verdict:** not the core. There is no mature Rust decompiler or symbolic
engine; you inevitably shell out to Ghidra (JVM) and angr (Python). Reserve
Rust for performance-critical leaf passes behind PyO3.

## Licensing map (keep the core clean)

- **Bundle freely (permissive):** Ghidra, angr, capa, LIEF, AFL++, Driller.
- **Shell out, never link (copyleft):** Unicorn/Qiling (GPL-2.0), SymCC (GPL-3.0), rizin (LGPL-3.0).
- **Never bundle:** Binary Ninja (proprietary) — optional adapter for license holders only.

## Relationship to the rest of the line

- **foxguard** — source-level SAST (Rust). `0verse` is its no-source sibling.
- **the managed platform (proprietary)** — currently imports the specific signed
  Hyper-V evidence shape produced by `0verse` out of band. Provider-neutral PoV
  import, the generic dispatch engine, binary job type, and agent-callable binary
  tool remain planned and parked behind the blind stripped-ELF gate above.

## Module layout

The import package is `zeroverse` (a module can't start with a digit; the brand
and CLI are "0verse"). The module list records in-tree implementation, not uniform
default-path integration or maturity; use the vocabulary above for each lane.

```
src/zeroverse/
  cli.py              # `0verse triage | run | scan`
  api.py              # embeddable scan() + format_result() (versioned ScanResult)
  pipeline.py         # deterministic stage scheduler (ingest → … → report)
  ingest.py           # stage 1 — pure-python ELF/Mach-O/PE/.ko format/arch/mitigation triage
  abi.py              # arch-aware ABIs (SysV / MS-x64 / AAPCS64 / AAPCS32 / MIPS o32) + can_execute
  backends/           # decompiler backends behind one Protocol: ghidra | rizin | angr (+ cdecomp pseudo-C IL)
  il.py / slicer.py / analyze.py / taint.py   # IL + backward source→sink slice + taint model
  static_prepass.py   # foxguard C-taint pre-pass (optional, graceful stub)
  bugclasses.py       # five bug-class lenses + confirmable-origin routing
  seedbugs.py / seedcatalog.py / data/archetypes.json   # kernel/IOKit/firmware seeds + 90-archetype registry
  agent.py / llm/     # provider-agnostic LLM loop + TriageFunnel; anthropic/codex/openai/glm/mock backends
  flywheel.py         # M7 preseeded memory: recall/rank/cost priming, never confirmation
  concolic.py         # angr reachability prune (Ghidra-only)
  dynamic.py / oracle.py / poc.py             # crash oracles + PoV emit (PoV-or-it-didn't-happen)
  fuzz/               # harness synth + AFL++ + Driller + directed (UniAFL) + coverage + orchestrator
  acquisition.py      # hardware-free AcquisitionManifest boundary for Firmware Scout evidence
  acquisition_bundle.py  # fail-closed offline bundle path/size/SHA-256 verification
  firmware_inspection.py  # deterministic opaque-byte structure and candidate-region evidence
  firmware.py         # binwalk carve + Qiling firmware emulation lane
  schedule.py         # M7 deterministic epoch scheduler + LLM budget/cache
  fleet.py            # M7 fleet-scale variant analysis (1 seed -> N confirmed variants)
  crs_api.py / dedup.py        # M7 CRS-API/SARIF adapter + tiered crash dedup
  patch.py            # stage 9 — patch + deterministic verify (opt-in)
  report.py           # Finding + PoV + Patch data model; json/sarif/ndjson/md
  cloud_sink.py / mcp.py            # managed cloud sink + stdio MCP bridge
  dataset.py / negative.py / groundtruth.py / benchmark.py   # the rigor layer (moat + honesty + eval)
```
