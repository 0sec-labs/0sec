# 0verse roadmap

> Status: 2026-07-25. Scope frozen under
> [0sec ADR-066](https://github.com/0sec-labs/0sec/blob/main/docs/DECISIONS.md#adr-066--2026-07-17--0verse-is-an-evidence-producernotary-input-not-a-dispatchable-engine-yet).
> Milestone checkboxes record in-tree implementation or proof work; they do not by
> themselves mean live-proven or operational. Use the canonical
> [maturity vocabulary](ARCHITECTURE.md#scope-decision-and-maturity-vocabulary).

The plan is ambitious *as a backlog* but sequenced *as code*: ship one vertical
slice end-to-end before fanning out. An OSS RE tool lives or dies on a working
day-one demo, not eight half-built stages.

Each unchecked item below is intended to become a GitHub issue (labels in
parentheses). Run `gh issue create` from this list once the repo has a remote.

## M0 — Skeleton (this commit)
- [x] Repo, README positioning, ARCHITECTURE, license, CI
- [x] `0verse triage` — dependency-free ELF/PE/Mach-O format + arch + mitigation detection
- [x] `0verse run` wired as a full pipeline (ingest→decompile→analyze→reason→dynamic→poc→report)

## M1 — MVP vertical slice  ← build this fully before anything below
**Target: Linux ELF x86-64, bug class: stack/heap buffer overflow, output: a reproducing PoV.**
Architecture per [docs/DESIGN-NOTES.md](docs/DESIGN-NOTES.md): deterministic scheduler, LLM-as-worker, PoV-as-truth.
- [x] **Taint-model schema** ported from mole: `conf/NNN-*.json`, `taint_model→library→category→function`, `synopsis` + `par_slice` DSL (ast-whitelist eval, NOT `eval`); seed from libc 113-func set (`taint-model`)
- [x] **Ghidra headless adapter**: decompile + export P-Code SSA / HighFunction + CFG as JSON (`stage:decompile`, `backend:ghidra`)
- [x] **ILAdapter interface** + engine-agnostic `BackwardSlicer`/`CallTracker` (get_def/get_memory_defs/get_callers/get_ptr_map) (`stage:lift`)
- [x] **Slice-then-intersect**: slice sources & sinks independently, cache source slices, emit finding on graph-reachability intersection (networkx); pointer/out-param map for `read`/`memcpy` (`stage:analyze`)
- [x] **foxguard static pre-pass**: run the foxguard C-taint scanner over Ghidra's decompiled C → SARIF → union hits as hypotheses (origin `foxguard`), deduped against the #2 slice; graceful stub when foxguard absent (`stage:analyze`, `integration:foxguard`)
- [x] **LLM triage on the slice** (not raw binary): tagged instruction listing + call sequence; read-only `get_code`/`get_callers` tools; structured output `{truePositive, CWE, severity, inputExample}`; mock mode (`stage:reason`)
- [x] **angr concolic**: slice-scoped `call_state` reachability — concretizes a witness, prunes UNSAT hypotheses, timeboxes/falls-through on choke; wired before the oracle (`stage:dynamic`, `backend:angr`)
- [x] **Crash oracle (no sanitizers)**: native signal classification (SIGSEGV-write/SIGABRT), optional QEMU/Valgrind; document blind spots (`stage:dynamic`, `oracle`)
- [x] **Deterministic PoV verifier**: re-run blob → classify crash signal → **stack-trace dedup** (`stage:poc`)
- [x] **Open oracles** (reimplemented from pwnkit *concepts*, not code): differential crash oracle (target crashes / control clean); **canary-marker capability oracle** + 5 false-confirm guards; dedup vs **public** CVE/GHSA/OSV (`stage:poc`, `oracle`)
- [x] **PoV emitter**: crashing stdin/argv + crash class via pwntools (`stage:poc`)
- [x] **Report**: markdown + SARIF + JSON finding with embedded PoV; NDJSON streaming headless contract (`stage:report`)
- [x] Green on a corpus of known-vuln binaries; CI gate on PoV reproduction (`benchmark`) — cmdi + overflow + heap_overflow all confirmed end-to-end (3/3); Docker `benchmark-gate` workflow + `make benchmark`; angr proof in `benchmarks/angr_proof.py`

## M2 — Fuzzing backbone + harness synthesis (Atlantis orchestration patterns)
Traditional fuzzing is the floor; LLM is a selective multiplier gated behind cheap signals.
- [x] **AFL++ driver** (#15): persistent/CMPLOG/dictionary + QEMU-mode (`-Q`, gated on
  `afl-qemu-trace`) for binary-only targets; `AflBackend` protocol + fake runner
  (`stage:dynamic`, `fuzzing`)
- [x] **LLM harness synthesis** (#16): recover signature from Ghidra → synthesize a
  thin stdin/persistent C driver, with a compile→repair→reach-validate feedback
  loop (mock = deterministic template); the #1 binary-only gap (`stage:reason`, `fuzzing`)
- [ ] **LLM payload-recipe** scripts (`create_payload()->bytes`) refined on coverage/crash feedback — not raw bytes (`stage:reason`, `fuzzing`)
- [ ] LLM seed/corpus generation for structured inputs (`fuzzing`)
- [ ] **Coverage → decompiled-line mapping** so the LLM can reason on coverage (`stage:dynamic`, `coverage`)
- [ ] **Epoch scheduler** with weighted-random task sampling + dynamic sink (de)prioritization (`orchestration`)
- [x] **Driller-style hybrid** (#17): on an AFL++ stall, hand a stuck input to angr
  (#5 concolic) to solve the blocking gate, then re-seed AFL++ (`orchestration`)
- [ ] **Shared seed bus** with in-memory injection of concolic/LLM seeds into live fuzzers (`orchestration`)
- [x] **Last-mile assist**: track reached-but-uncrashed sinks, spend LLM reasoning there (`triage`) — `CoverageProbe.uncrashed_but_reached` (#40 signal) feeds `fuzz/lastmile.py` (#224): opt-in `ZEROVERSE_LAST_MILE`, the LLM conditions on the decompiled sink + the corpus inputs that REACH it and proposes targeted byte mutations (structure-preserving, never a reference PoC); every candidate is adjudicated by the same crash oracle. Wired into `directed_fuzz_function` when the window budget ends reached-but-uncrashed
- [ ] **Cost subsystem**: LiteLLM-style proxy, per-stage budgets, cache all LLM + static lookups (`cost`)
- [ ] Crash triage + dedup + exploitability classification (`stage:poc`, `triage`)

## M3 — Breadth: formats & architectures

M3 records format/ABI implementation and controlled proofs. Windows execution
expansion and Mach-O dynamic expansion are **parked**; neither is claimed
live-proven or operational.

- [x] **Windows PE x86-64 static support** (#20) (`format:pe`) — byte-level PE/PE32+ ingest
  (machine/bits/kind + NX/ASLR/CFG/canary from `DllCharacteristics`) and the
  **Microsoft x64 ABI** (`MSVC_X64`: RCX/RDX/R8/R9, 32-byte shadow space,
  caller-cleanup — distinct from SysV, selected by *format*). Ghidra loads PE
  natively, so the slice + foxguard + LLM triage (+ angr where CLE loads the PE)
  run on Linux and surface the bug as a hypothesis. The explicit Windows adapter
  and its controlled evidence remain in-tree, but no live-proven or operational
  worker lane is claimed. WinAFL discovery and further Windows execution work are
  **parked**. The lane degrades honestly and never fakes a crash
  (`benchmarks/m3_pe_proof.py`, `benchmarks/windows_oracle/`)
- [x] **ARM64 / ARMv7 support** (#19) (`arch:arm`) — arch-aware `Abi` (AAPCS64 X0–X7 /
  AAPCS32 R0–R3) keyed off the Ghidra processor; the high-P-Code SSA slice +
  pointer-taint summaries carry over unchanged. **Full pipeline proven on AArch64
  ELF**: Ghidra slice (arm64 ABI) → angr → AFL++ **QEMU-mode via qemu-aarch64**
  (cross-arch `afl-qemu-trace`, `CPU_TARGET=aarch64`) → differential-allocator
  oracle → PoV that reproduces under qemu-aarch64 (`benchmarks/m3_arm64_proof.py`)
- [x] **MIPS support + firmware lane via Qiling** (#21) (`arch:mips`, `firmware`) —
  MIPS o32 `Abi` ($a0-$a3 / $v0, $ra return-address) keyed off the Ghidra
  processor; the high-P-Code SSA slice carries over unchanged. A **Qiling**
  emulation engine drives a recovered function directly (arg + return-address
  regs seeded from the ABI) and a **differential reachability/crash** (control
  returns to the sentinel; the gated overflow corrupts the saved $ra and faults)
  becomes a PoV via the M1 oracle dedup — the firmware-appropriate dynamic vector
  where bare qemu-user has no rootfs and the native guard-allocator has no
  arch-matched libs. **binwalk** unpack (`firmware.unpack_firmware`) carves a real
  image's rootfs + ELFs upstream. Proven on a committed MIPS ELF; a genuine
  router image is out of scope on the bench and is documented, never faked
  (`benchmarks/m3_mips_qiling_proof.py`)
- [x] **Mach-O support** (#18) (`format:macho`) — real Mach-O ingest (thin + FAT,
  exec/object/dylib/**kext**), Ghidra-backed static slice + foxguard + LLM triage,
  and the **XNU/IOKit fold-in**: an IOKit-user-client seed-bug-class
  (`seedbugs.py`) primes externalMethod-dispatch / IOMalloc·copyin OOB hypotheses
  when pointed at a kext. Static ingest and fixture proof remain, while arm64
  Mach-O dynamic confirmation is unsupported and further expansion is **parked**.
  No Mac/XNU live-proof or operational lane is claimed
  (`benchmarks/macho_proof.py`)

## M4 — Breadth: bug classes
Each class = a static detection **lens** (high-recall hypothesis source, tagged
`origin=bugclass:<id>`, unioned into the #4 funnel) + a **confirming oracle**
where a generic one exists + a benchmark with a reproducing **PoV**. PoV-is-truth:
a class is `confirmed` only with a PoV; classes with no generic oracle stay honest
hypotheses (`src/zeroverse/bugclasses.py`, `benchmarks/m4_proof.py`).
- [x] **Integer overflow in size calculations** (#22) (`bug:intoverflow`) — lens:
  size arithmetic (`a*b` / `a+len` / shifts) feeding malloc/calloc/realloc/alloca/
  memcpy. **Oracle: REUSE the differential-allocator** + the page-granular
  quarantine guard — a proposed input that overflows the size computation →
  undersized alloc → heap OOB that only faults under the guard (`clean→crash`).
  **CONFIRMED PoV** (`benchmarks/intoverflow.c`)
- [x] **Format-string bugs** (#23) (`bug:fmtstring`) — lens: a taint-controlled
  value in the FORMAT position (not the varargs) of printf/fprintf/sprintf/
  snprintf/syslog. **Oracle: a `%s`-spray (+`%n`) probe** → a wild read/write
  crash a benign control does not trigger (differential). **CONFIRMED PoV**
  (`benchmarks/fmtstring.c`)
- [x] **Use-after-free / double-free** (#24) (`bug:uaf`) — lens: `free(p)`→use(p)
  or `free(p)`…`free(p)` in a function body. **Oracle: the guard-allocator EXTENDED
  with POISON-on-free + quarantine** (`oracle.build_quarantine_guard` /
  `uaf_differential`) — a UAF read/write faults (SIGSEGV) and a double-free traps;
  a benign control stays clean. Confirmable *given a triggering input*, else an
  honest hypothesis (the hardest binary class). **CONFIRMED PoVs**
  (`benchmarks/uaf.c`, `benchmarks/double_free.c`)
- [x] **Command injection** (#25) (`bug:cmdi`) — lens: taint into system/popen/
  exec*/posix_spawn (the M1 cmdi canary, now a first-class class). **Oracle: a
  sentinel-command (`echo <canary>`) canary** that PROVES injection via a
  token-bound marker without running anything harmful. **CONFIRMED PoV**
  (`benchmarks/cmdi.c`)
- [x] **Auth-bypass / logic bugs** (#26) (`bug:logic`) — LLM-led reasoning over the
  decompiled slice (comparison / auth / missing-check / off-by-one). **Hypothesis-
  only**: no generic binary oracle, so surfaced as high-value funnel leads + wired
  into the variant-analysis funnel, NEVER confirmed without a PoV. Honest
  confirmation gap (`benchmarks/auth_bypass.c`)

## M5 — Backends & integration
- [ ] Binary Ninja optional adapter (HLIL) for license holders (`backend:binja`) —
  **deferred** (no license)
- [x] rizin/angr decompiler fallback when Ghidra unavailable (`backend:rizin`/
  `backend:angr`) (#27) — explicit `DecompilerBackend` Protocol + `ProgramAdapter`
  in `backends/contract.py`; **rizin** (radare2 + r2ghidra `pdg`, no Java) and
  **angr** (pure-Python) backends mine a pseudo-C IL (`backends/cdecomp.py`);
  `ZEROVERSE_BACKEND=auto` prefers Ghidra, falls back. Honest fidelity gap (no SSA
  def-use, no per-sink addresses → angr reachability stage skipped). **Proof:**
  `benchmarks/m5_backend_proof.py` slices+confirms `read→strcpy` with Ghidra disabled
- [x] GhidraMCP-style bridge so external agents can drive the engine
  (`integration:mcp`) (#29) — `python -m zeroverse.mcp`: stdio MCP server exposing
  `scan_binary`/`list_findings`/`get_pov`/`get_report` over the embeddable API;
  official MCP SDK when installed, JSON-RPC-over-stdio stub otherwise
- [x] pwnkit/0cloud evidence contract and reference adapter (`integration:pwnkit`)
  (#28) — embeddable `zeroverse.api.scan()` + `0verse scan --format
  ndjson|sarif|json` with a **versioned** machine contract
  (`docs/RESULT-CONTRACT.md`, PoV-is-truth); reference adapter
  `examples/pwnkit_cloud_lane.py`. This is implemented contract scaffolding, not a
  platform lane. Under ADR-066, generic cloud dispatch is **parked** and
  operationally **unsupported** until the blind stripped-ELF gate passes.
- [ ] Rust (PyO3) fast-path for ingest/triage of large blobs (`perf`) — **deferred**

## M6 — Rigor & community
- [x] **FuzzBench/Magma comparison harness vs plain AFL++; publish results** (#33)
  (`benchmark`) — an honest, **bounded** ablation (`benchmarks/fuzzbench/compare.py`):
  0verse's slice-mined dictionary + CMPLOG lane vs default AFL++ on the **same**
  synthesized harness + identical seed, isolating 0verse's value-add. Results in
  [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md): **0verse wins the two gated targets**
  (cracks `REC0` / `FMW1`+`0xCAFEBABE` in <1s where baseline burns ~2M execs and
  never cracks them in 60s) and **ties — losing TTE by 0.2s — on the ungated
  control** (no gate, no value-add). NOT a full multi-day Magma sweep; caveats and
  the no-cherry-picking rule are explicit. Parsing/aggregation in
  `src/zeroverse/benchmark.py` (schema v1.0). **Real Magma is now built** (8 C/C++
  targets, fatal-canary `-O0` images) and run two ways: a real `0verse-CMPLOG vs
  baseline AFL++` campaign scored on Magma's ground-truth canaries
  ([`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)) and the binary-native pipeline scored
  for reach/confirm/FP ([`docs/EVAL-GROUNDTRUTH.md`](docs/EVAL-GROUNDTRUTH.md));
  `src/zeroverse/magma.py` + `benchmarks/magma/run.py` (schema v1.0)
- [x] **Negative-results log (honest reporting)** (#34) (`docs`) —
  [`NEGATIVE-RESULTS.md`](NEGATIVE-RESULTS.md) (curated residuals from M1-M6: Mach-O
  needs a Mac, rizin/angr lower-fidelity, angr-prune off on fallback backends,
  logic-class hypothesis-only, PE static-only) + a machine emitter
  (`src/zeroverse/negative.py`): one classified NDJSON record per **negative** run
  (zero confirmed PoVs), so clean/empty scans are logged too
- [x] **Labeled PoV dataset schema (the moat)** (#32) (`dataset`) — versioned schema
  + append-only NDJSON emitter (`src/zeroverse/dataset.py`,
  [`docs/DATASET.md`](docs/DATASET.md)): `features → (bug_class, source, sink) → PoV
  pointer → verdict + oracle`. **OSS ships the capture mechanism, not the corpus**:
  no raw exploit bytes (schema has no field; `validate_record` rejects bytes-keys),
  PoV-is-truth (`confirmed` ⇒ a real `pov.path`), real corpus is git-ignored and
  out-of-tree. Synthetic-only examples in `examples/dataset/`, guarded by a test
- [x] **Contributor guide + good-first-issues** (#35) (`community`) —
  [`CONTRIBUTING.md`](CONTRIBUTING.md) (Linux setup, the backend/bug-class/ABI/
  benchmark extension contracts, PoV-is-truth as rule #1) + 4 stubs in
  [`docs/good-first-issues/`](docs/good-first-issues/) + a README pass accurate to
  what M1-M6 shipped

## M7 — AIxCC-grade Cyber Reasoning System
The CRS leap: from *find a PoV* to *find → prove → patch → verify*, plus the
scale machinery (directed fuzzing, fleet variant analysis, the scheduler, CRS-API,
dedup, and the dataset flywheel) that turns one confirmed bug into many. M7 is
merged; expensive/mutating lanes remain opt-in by flag, but every item below is
in-tree and covered by tests or a proof harness.

- [x] **Directed fuzzing toward seed-flagged sinks** (#39/#40/#41)
  (`fuzzing`, `orchestration`) — the ATLANTIS **UniAFL** model (no compile-time
  AFLGo/BULLSEYE distance instrumentation, which stripped binaries can't carry):
  `fuzz/coverage.py` (#40) builds a per-seed key-address hit map from a qemu block
  trace; `fuzz/directed.py` (#39) folds slice sink addrs + bug-class lens
  hypotheses + seed-archetype matches into a weighted `SinkTarget` set and a
  `DirectedScheduler` that re-prioritises the corpus with the 25/25/50 policy and
  emits `AFL_QEMU_INST_RANGES`; **DistanceDriller** (#41) steers concolic budget to
  the nearest blocking gate. Wired via `fuzz/orchestrator.directed_fuzz_stage`,
  which **falls back to the coverage-guided lane** when there are no targets — so it
  never reduces reach. **Opt-in behind `ZEROVERSE_DIRECTED`**; PoV-is-truth
  untouched (the oracle still adjudicates every crash). Proof: a gated checksum /
  ARX-style target that baseline coverage misses is confirmed by the directed lane.
- [x] **Patch + verify loop — the AIxCC second half** (#45/#46) (`stage:patch`,
  `oracle`) — `src/zeroverse/patch.py`, gated on `ZEROVERSE_PATCH=1`, iterating
  ONLY over findings that already carry a reproducing PoV. Three layers by maturity:
  **B0** a deterministic, zero-dep located fix *recommendation* (always-on);
  **Mode A** an LLM unified-diff source patch with RCA → rebuild → reflect (cap 3);
  **B1** a flag-gated x86-64 ELF binary micro-patch (immediate-clamp guard works;
  SCRIBE/e9patch/Patcherex2 engines scaffolded, degrade to B0 when absent). A patch
  is `verified` ONLY when `oracle.verify_patch` confirms the PoV no longer
  reproduces AND no regression — the deterministic, LLM-free adjudicator (PoV-is-
  truth's sibling discipline).
- [x] **Fleet / variant analysis at scale** (#42) (`orchestration`) — fan one
  confirmed bug shape across a corpus of related binaries (the Big-Sleep variant
  hunt at fleet scale). `src/zeroverse/fleet.py` builds a seed from an archetype or
  reference binary, ingests a directory/manifest/list, detects variants, confirms
  each target through the right oracle, dedups same-crash variants, and emits one
  dataset record per swept variant. Proof: one seed confirms **5/5** vulnerable
  vendor variants with real PoVs and **0** false confirmations on patched controls;
  kernel routes stay hypothesis-only.
- [x] **Strategy scheduler + per-lane LLM budget/cache** (#44) (`orchestration`) —
  deterministic weighted epoch sampler, event-driven reprioritization, per-lane and
  global token budgets, content-hash LLM cache, fallback-chain demotion, and a
  no-signal fuzz skip under tight budgets. Proof: the scheduler preserves the same
  confirmed findings as the sequential run while avoiding wasted no-signal spend
  (measured speedup on the no-signal proof target), and the cache dedups identical
  prompts.
- [x] **Dataset flywheel** (#43) (`dataset`) — preseeded 5-layer memory from the 90
  archetypes (principle / semantic / procedural + corpus-fed episodic / analogical),
  corpus capture via `ZEROVERSE_DATASET_PATH`, MCP `recall_similar` when
  `ZEROVERSE_FLYWHEEL=1`, RAG priming, rank bonus, and cost routing. Proof: the
  preseeded store is non-empty (**251** memories in the M7 proof run), priming moves
  a similar known bug from cold escalation #5 to primed #1, the un-similar control
  gets no spurious lift, and memory never changes `confirmed`/`verdict`/PoV state.
- [x] **CRS-API / SARIF adapter + tiered crash dedup** (#47/#48) (`integration`,
  `triage`) — `src/zeroverse/crs_api.py` ingests AIxCC-style task bundles, consumes
  SARIF broadcasts as hints, runs 0verse, and emits CRS-API `POVSubmission` rows;
  `src/zeroverse/dedup.py` fuzzy-merges same-crash findings across exact stack,
  LCS, and Levenshtein tiers before dataset/fleet emission.

## Scope freeze after M7

The current 0verse role is an evidence-producer/notary. Generic pwnkit/0cloud
dispatch remains parked until 0verse blindly confirms a known-CVE stripped
x86-64 ELF and the result is recorded. Windows execution, browser execution, and
Mach-O dynamic-execution expansion are also parked. Existing code, tests, and
fixtures stay available, but they do not establish live-proven or operational
maturity.

**Firmware Scout remains an independent ordered program.** It is not parked by
the dispatch gate. Its canonical dependency chain is
[issue #84](https://github.com/0sec-labs/0verse/issues/84): R0 baseline/contracts →
R1 offline intake → R2 passive Scout → R3 safe UDS reconnaissance → R4 Delphi
MT05.3 acquisition decision → R5 firmware-to-finding vertical slice. Stages must
remain ordered and fail closed; a documented blocker is a valid result.

All benchmark numbers in this roadmap are historical, condition-specific results
from the recorded campaigns. They do not establish operational maturity; see
[docs/BENCHMARKS.md](docs/BENCHMARKS.md) for the exact environment and caveats.

## Explicitly out of scope (for now)
- Reimplementing a decompiler or symbolic engine (use Ghidra/angr).
- Neural decompilation as ground truth (still fails ~half of HumanEval-Decompile).
- Any finding without a reproducing PoV.
