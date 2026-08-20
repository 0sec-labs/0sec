# 0verse M1 Vertical-Slice — Engineering Guidance

PoV-is-the-unit-of-truth. The whole doc optimizes for one outcome: a deterministic crashing input, replayed natively, on a real binary. Everything that doesn't serve that is M2.

---

## 1. Per-Issue Guidance

### #1 — Ghidra headless adapter (ILAdapter over P-Code)

- **Copy from:** the Ghidra brief's "operate on **high P-Code SSA**, never raw asm/raw P-Code" rule. This is the single most important decision in the issue — high P-Code gives you def-use for free.
- **Key API:** **PyGhidra** (`pyghidra.start()` / `open_program()`), bundled since Ghidra 11.3. Stay in CPython so the LLM SDK / z3 / your core live in-process. `DecompInterface.decompileFunction()` → `HighFunction.getPcodeOps()` returns `PcodeOpAST` in SSA form. Def-use = `varnode.getDef()` (back one step) and `op.getOutput().getDescendants()` (forward).
- **Implementation details:**
  1. The adapter must expose a **stable, version-pinned `ILAdapter` interface** (functions, decompiled C, call graph, xrefs, imports/exports, per-function high-P-Code op list, varnode storage class). PcodeOp AST shape drifts across Ghidra versions — wrap every accessor, pin the Ghidra version in the container.
  2. **Cache decompilation aggressively, keyed by function content hash.** Decompilation dominates runtime; you will re-query the same functions from #2/#3/#4.
  3. Run `analyzeHeadless` for the import+auto-analysis batch step (most stable), then PyGhidra for interactive queries against the saved project.
- **Honest hard part:** indirect/virtual calls and jump tables silently produce an incomplete call graph. Don't hide it — emit an explicit `unresolved_edges` list so downstream stages know coverage is partial. Stripped binaries degrade symbol names to module+offset.

### #2 — Slice-then-intersect on real P-Code + pointer/out-param map

- **Copy from:** LATTE's slicing module (Ghidra brief) — backward slice from a sink arg via transitive `getDef()`; if the slice terminates at a source, the sink is input-reachable. Forward-slice from source to confirm. **Slice-first, symbolic-execute-second** is the load-bearing architectural idea — it's what keeps angr (#5) tractable.
- **Key API:** `getDef()` / `getDescendants()` for intra-procedural; inter-procedural via re-decompilation + actual→formal param mapping at CALL sites, with a per-function **callee out-param/return-taint summary** cache.
- **Implementation details:**
  1. Source/sink config is data, not code: sources = `recv/read/fgets/getenv/argv` + exported-func params; sinks = `memcpy/strcpy/sprintf/system` + tainted-size/tainted-index. Ship a default YAML.
  2. "Intersect" = keep only sinks whose backward slice reaches a source. This is your high-recall/low-precision candidate queue — that's correct by design.
  3. **Pointer/out-param modeling:** track taint into the pointee by following the pointer varnode through `PTRSUB`/`PTRADD`/`STORE`, not the value. Build the "does callee write through arg N?" summary once per function.
- **Honest hard part:** LOAD/STORE aliasing is the #1 correctness hole — over-tainting (false positives) and missed flows (false negatives). Accept it; the whole pipeline exists to discharge static hypotheses with execution. Don't try to make the slicer sound.

### #3 — foxguard static pre-pass over decompiled C (C taint → SARIF hypotheses)

- **Copy from:** OSS-Fuzz-Gen's "static reachability targeting **first**, LLM second," and Infer's brutal lesson (~99.9% FP without an agent filter). foxguard runs cheap and high-recall; its output is **hypotheses, never findings**.
- **Key API:** foxguard's existing C taint engine (you own it) consuming Ghidra's decompiled C; emit **SARIF** as the common hypothesis format so #4/#8 share a schema.
- **Implementation details:**
  1. Feed foxguard the decompiled C *plus* the #2 slice context — don't run it blind on whole functions.
  2. Emit SARIF with `ruleId` = bug class (OOB-write/UAF/tainted-size) and the slice as `codeFlows`. This is the LLM's prompt context in #4 and the angr target set in #5.
  3. Treat foxguard + #2 as **two independent high-recall generators** whose union feeds triage. Divergence between them is signal.
- **Honest hard part:** decompiled C is not source C — types are approximate, casts of random bytes look like real flows. Expect a high FP rate and rank, don't gate, on it.

### #4 — LLM triage on the slice (structured output + mock mode)

- **Copy from:** RoboDuck's **two-stage cheap→expensive funnel** ($0.001 logprob score → top ~20% get the $0.50 agent) and Big Sleep's **variant-analysis framing** (seed a known bug, hunt siblings — far higher signal than open-ended).
- **Key API:** provider-agnostic LLM client with **structured output** (JSON schema). Mandatory **mock mode** (deterministic canned responses) so CI (#9) runs with zero API spend/flakiness.
- **Implementation details:**
  1. The agent's deliverable is a **structured hypothesis** — `(sink, slice, claimed input precondition, suspected bug class, confidence)` — **not a verdict**. Never let it claim reachability or "this overflows"; that's #5/#6's job.
  2. Cheap classifier ranks the whole #2+#3 queue; only the top slice escalates to a source-browsing agent with Ghidra-MCP-style tools (decompile/xref on demand — keeps reasoning token-bounded vs context-stuffing).
  3. Use a **small/cheap model** for ranking, frontier only for the hard root-cause step. Match model to task (Buttercup won 2nd with zero reasoning models).
- **Honest hard part:** LLM hallucinates flows confidently. The mitigation is structural — it can only *propose*; nothing it says is true until #6 produces a crash. Wire that gate, don't trust prompt discipline.

### #5 — angr concolic reachability

- **Copy from:** Driller's **fuzzer-first, symbolic-as-fallback** and the Ghidra brief's **slice-scoped** rule: start at `call_state`/`blank_state` on the target function with symbolic args, **never from program entry**. This sidesteps angr's environment-modeling weakness.
- **Key API:** `SimulationManager.explore(find=sink_addr, avoid=...)`, `state.solver.eval` to concretize the witness; the **`unconstrained` stash** as the control-hijack oracle (symbolic PC = `SegFaultOnPc` equivalent). Compose `LoopSeer`, `veritesting=True`, `MemoryWatcher`, `Spiller`.
- **Implementation details:**
  1. Only symbolically execute the **functions on the #2 slice** — this is the entire reason angr is tractable here.
  2. Stub libc/noisy helpers with **SimProcedures**; leave only target code symbolic.
  3. Output is one of three: concrete witness input, UNSAT (prune the hypothesis), or timeout/unknown. All three are useful. **Reject any hypothesis angr can't satisfy** — this kills LLM hallucinations cheaply.
- **Honest hard part:** symbolic memory (attacker-controlled addresses) and nonlinear constraints (checksums/crypto) are walls — angr cannot invert a hash. Hard-timebox every run; treat angr as an occasional expensive consult, not the spine. For M1, if angr chokes, fall straight through to fuzzing — don't block.

### #6 — Crash oracle (native, no sanitizers) + differential + canary + dedup

- **Copy from:** the oracle brief wholesale. **Wrap CASR** (`casr-gdb` + `casr-cluster`) rather than reimplementing `!exploitable`. This is the crown jewel — port the read-vs-write / near-null / PC==fault rule logic.
- **Key API:** CASR (`casr-afl`, `casr-cluster -d/-c`); GDB-via-pygdbmi for register/backtrace capture; OSV API (`api.osv.dev`) + GitHub Advisory DB for known-CVE fuzzy match.
- **Implementation details:**
  1. **Differential allocator oracle is the highest-value no-sanitizer trick:** re-run each unique crash under stock allocator vs guard-page (`MALLOC_CHECK_=3` / Electric Fence / GWP-ASan). `clean→crash` = high-confidence real heap bug, with the fault pinned to the exact instruction. Run both; treat divergence as signal.
  2. **Canary-marker capability oracle:** inject sentinel bytes into input fields; at crash, scan PC/regs/fault-addr for the sentinel → emit `capability` (`pc_control`/`write_what_where`/`controlled_deref`/`none`). This is the bridge from "classified" to "demonstrated."
  3. Dedup on **normalized top-5 frames** (strip addresses/offsets, drop libc/allocator frames). Record both a tight (5-frame) and loose (1-frame) bucket. CVE/OSV match is `package+version+symbol` fuzzy → **mark "suspected-known," never auto-dismiss**.
- **Honest hard part:** exploitability labels are heuristic guesses; crash site ≠ bug site. Stripped binaries with no DWARF degrade buckets to address ranges, and unwinding past a smashed stack is unreliable exactly when it matters. The label is only a **priority ordering** — the PoV is the truth.

### #7 — PoV emitter (pwntools)

- **Copy from:** Big Sleep's reusable, unit-tested **cached input encoders** (semantic params → bytes) and AIxCC's "PoV = deterministic crashing input reproduced under an oracle."
- **Key API:** pwntools for process spawn/stdin/argv/env delivery and crash detection; emit a standalone runnable repro script.
- **Implementation details:**
  1. The PoV is `(target, exact delivery vector, bytes, expected signal/fault-addr)` — fully self-contained and re-runnable.
  2. **Native replay on `ssh sandbox` is the non-negotiable gate.** angr "crashes" must reproduce on real hardware; symbolic environment modeling lies.
  3. Cache encoders as reusable Python functions, unit-tested in isolation, so PoV construction is composable across bugs.
- **Honest hard part:** the witness from #5 drives the *sliced function*, but a real PoV ideally drives the *public entry point*. For M1, accept a harness-level PoV (drives the target function directly) as long as it natively reproduces — full public-path reachability is M2.

### #8 — Report stage: markdown + SARIF + JSON + NDJSON

- **Copy from:** AIxCC's "no unproven claims; default to *not* reporting." Reports are mechanical serialization of verified state.
- **Key API:** plain serializers; reuse the #3 SARIF schema so static hypotheses and confirmed PoVs share a format.
- **Implementation details:**
  1. **Two tiers, clearly separated:** `hypothesis` (static, unproven) vs `confirmed` (PoV-backed, native-replayed). Never let a hypothesis render as a finding.
  2. NDJSON for machine/CI consumption (#9), markdown for humans, SARIF for tooling interop, JSON as the canonical record.
  3. Each confirmed finding embeds the PoV, CASR severity, capability tag, dedup bucket, and suspected-CVE candidates.
- **Honest hard part:** none technically — the discipline risk is letting unverified LLM/static output leak into the "confirmed" tier. Enforce schema-level separation.

### #9 — Benchmark corpus + CI PoV-repro gate

- **Copy from:** AIxCC's reliability-first postmortem — *scaffolding, not AI, is where systems die.* The CI gate is what makes the tool trustworthy.
- **Key API:** small corpus of binaries with **known, planted memory-safety bugs** (compile your own + a few CGC-style); CI runs the full pipeline and asserts PoV reproduction.
- **Implementation details:**
  1. Each corpus entry ships a ground-truth `(bug location, expected crash signal)`. CI **fails if a known bug's PoV stops reproducing** (regression gate) and flags new claims for review.
  2. Run with LLM **mock mode** so CI is deterministic and free.
  3. Wrap every external tool (Ghidra/angr/CASR/AFL++) with timeouts, retries, crash isolation, idempotent jobs — the ATLANTIS "one string-match bug nearly lost everything" lesson.
- **Honest hard part:** keeping the corpus honest and non-trivial. A handful of planted-overflow binaries is enough for M1; resist gold-plating.

---

## 2. Build Sequence & Parallelization

**Critical path (must be serial):** #1 → #2 → #5/#6 → #7. The IL adapter gates slicing, slicing gates everything dynamic, the oracle+PoV gate the unit of truth.

**Phase 0 (foundations, parallel):**
- #1 Ghidra adapter (longest pole — start first, one engineer owns it)
- #6 Crash oracle — **build it independently and early.** It only needs a binary + a crashing input, zero dependency on #1–#5. The Big Sleep/Naptime lesson: *verification harness FIRST, or you're building a hallucination machine.* Develop it against hand-written crashers.
- #9 CI scaffold + corpus — also independent; build the planted-bug binaries in parallel.

**Phase 1 (needs #1):**
- #2 Slice-then-intersect (serial after #1)

**Phase 2 (needs #2's slices, fully parallel with each other):**
- #3 foxguard pre-pass
- #4 LLM triage (mock mode lets it develop without #3 done)

**Phase 3 (needs #2 slices + ranked queue):**
- #5 angr reachability (parallel with #6 which is already built)
- #7 PoV emitter (needs #5 witness OR #6 crash + native replay)

**Phase 4:**
- #8 Report (needs verified state from #6/#7; trivial once they exist)

**Parallelizable pairs:** {#1, #6, #9} at start; {#3, #4} after #2; #5 runs alongside the already-built #6.

---

## 3. The Single Highest-Leverage Thing for M1

**Nail the closed loop on ONE bug class — tainted-size `memcpy`/`strcpy` heap overflow — end to end, with the differential guard-page oracle (#6) as the crash truth, before broadening anything.**

Concretely: pick the *easiest real win* — an exported C parser/decoder function taking `(buf, len)`, where Ghidra recovers the signature cleanly (headers available is a huge boost). The proven path is: #2 slice finds tainted len → memcpy → #4 ranks it → **skip or timebox angr** → drive AFL++/direct-call harness on the function → crash → **guard-page differential confirms real heap OOB** → #7 emits PoV → native replay on sandbox.

Why this and not the fancy angr path: every brief says the same thing — *for any target where you can stand up a fuzzer, the fuzzer finds it as well or better*, and *symbolic execution had low competition ROI*. The differentiator that actually produces a PoV-backed bug in M1 is **(a) high-recall slice targeting + (b) the guard-page differential oracle that turns a silent overflow into a deterministic, instruction-pinned crash without a sanitizer.** That oracle is cheap, deterministic, and is the thing that separates "real bug" from noise. Get one true positive through that pipe and M1 is real.

---

## 4. Deliberately SKIP / Defer to M2+

- **Patch generation + re-validation.** AIxCC's hardest, lowest-accuracy stage (38–46% of "validated" patches were wrong). Not in the M1 issue list — keep it out. PoV is the deliverable.
- **angr as anything more than a timeboxed scalpel.** If it chokes (it will, on symbolic memory/checksums), fall through to fuzzing. Do **not** invest in whole-program symbolic execution, the P-Code engine over VEX, or veritesting tuning in M1.
- **Stripped C++ / mangled vtables / virtual-call resolution.** Worst-case signature recovery. M1 = exported C with recoverable signatures, ideally with headers. Defer indirect-call resolution beyond best-effort flagging.
- **Full public-entry-point reachability for the PoV.** M1 accepts a harness-level PoV that drives the target function directly and natively reproduces. Proving the bug from the real public input path is M2.
- **Fine-grained semantic dedup and a real "stack-signature→CVE" service.** M1 = normalized top-5-frame buckets + fuzzy OSV `package+version+symbol` match marked "suspected." No embedding dedup, no root-cause clustering (Igor-style).
- **FRIDA/Unicorn/Nyx backends, macOS/mobile, kernel targets.** M1 = **Linux ELF + AFL++ QEMU persistent mode only.** Everything else is M2.
- **The Driller seed-roundtrip loop.** Nice-to-have; M1 can run AFL++ and angr as separate consults. The full feedback loop is M2 polish.
- **Custom/fine-tuned models.** Provider-agnostic API + mock mode is enough. ATLANTIS's Llama-7B was a winner's luxury, not an M1 need.

**The meta-rule for M1 shippability:** spend your reliability budget on scaffolding (tool timeouts, retries, native-replay gate, CI), not on technique sophistication. Every postmortem says systems die on build/orchestration brittleness, not on the AI. Ship the boring, verified loop.