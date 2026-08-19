# Engine B — primitive-first autonomous weaponization ladder (L0→L4 on a KASAN VM)

> Status: 2026-07-13. Design + prototype for 0sec#1230 (EPIC #1227,
> plan `docs/operations/llm-lpe-innovation-plan.md`). NOT a merge — a
> PR-ready branch (`feat/engine-b-primitive-first-ladder`) with a driver
> skeleton + worked-example test. Prototype: `packages/core/src/kernel/exploit/ladder-driver.ts`.

## The thesis (U2, verbatim from the plan)

> "No system yet has an LLM autonomously formulate *'I need a T2 arbitrary-write,
> therefore hunt for a bug that yields it'*." FreeBSoD proved the ladder is
> *crossable* but with a human driving it.

Engine B flips the search. Instead of *find a crash → see what it gives you*, it
(1) enumerates the exploitable **primitives a target offers**, (2) picks a **goal
primitive** and hunts a bug that **reaches** it, then (3) **auto-climbs an L0→L4
ladder** where each rung is *proposed by the model given the accumulated state*
and *validated by a sanitizer oracle before the next rung is attempted*. The
output is a **proven** PoC (a sanitizer artifact per rung), not a claim.

## What already exists (build ON, don't reinvent)

The engine survey (both halves) established that the shipped weaponization path
is already a *climb*, but it is **bug-first, monolithic, deterministic, and
one-shot** — the exact three limbs Engine B has to change:

| Shipped asset | File | Role in Engine B |
|---|---|---|
| Crash→primitive classifier + single control-demo | `triage/kernel-primitive.ts` | The bug we climb FROM; `attemptControlDemo(probe)` is the single-rung seam we generalize |
| Escalation ladder + monotone ratchet | `kernel/exploit/strategy.ts` (`EscalationRung`, `ratchet`) | The capability mirror the L-ladder folds into |
| Deterministic canary/uid/reclaim oracle | `kernel/exploit/oracle.ts` (`adjudicate`, `reclaimWitnessed`, `droppedBeforeRoot`) | The **L2/L4 oracle**, verbatim |
| KASAN/KCOV QEMU runner, N-boot gate | `triage/kernel-vm-runner.ts` (`runReproducerInKernelVm`, `verifyAcrossBoots`, `parseCoveragePcs`) | The **L0/L1/L3 oracle** substrate |
| Structured exploit-state carrier | `kernel/exploit/exploit-context.ts` (`WritePrimitiveProfile`, `SprayPlan`, `RootTailPlan`) | The state the model accumulates rung-to-rung |
| Primitive-enumeration toolbox | `spray-selector.ts` (`selectSprayPlans`), `introspect.ts` (`structLayout`, `resolveSymbol`, `introspectExploitConfig`), `write-primitive-analyzer.ts` | Feeds `enumerateGoalPrimitives` |
| Capability composition planner | `kernel/exploit/chain/planner.ts` + `node.ts` (`Capability`, provides/needs) | KOOBE/BridgeRouter *across bugs*; Engine B reuses the same `Capability` alphabet *within one bug* |
| The bug→root harness | `kernel/exploit/harness.ts` (`runWeaponization`) | What Engine B replaces for the single-bug climb |

Two facts from the survey fix the design:

1. **There is NO LLM in the current loop.** Exploit C is emitted by a declarative
   template (`templates.ts:emitWeaponizationC` via `strategy.emit(params)`); the
   only "prompt equivalent" is `ExploitTemplateParams`. The `emit: (params) =>
   string` hook (`library.ts:48`) is the exact injection seam.
2. **There is NO replan-on-failure.** `runWeaponization` (`harness.ts:229-253`)
   picks strategies from a static catalog, runs each end-to-end, ratchets, and
   stops. Planning is one-shot up front (`run-chain.ts`); a rung that fails never
   feeds its evidence back into a corrected next attempt.

Engine B's two genuinely new pieces are therefore: **(a) a per-rung `RungPlanner`
seam (the model call)** and **(b) primitive-first enumeration**. Everything else
is wiring over shipped oracles.

## 1. The ladder model (L0→L4) — what artifact proves each rung

The L-ladder is a superset of `EscalationRung`. It **adds the two pre-corruption
rungs** an exploit dev proves first (you reach the sink, then you make it fault)
and **splits "control happened once" from "control happens every time"** — because
reclaim reliability under SLAB randomization is the real wall, and treating one
lucky reclaim as a weaponization is exactly the dishonesty the pipeline guards
against.

| Rung | Meaning | Proof artifact on the KASAN VM | Oracle (shipped) |
|---|---|---|---|
| **L0 reach** | control flow reaches the vulnerable sink | the sink's PC appears in `ReproducerResult.coveragePcs` (KCOV) | `parseCoveragePcs` + sink-PC membership |
| **L1 corrupt** | the bug fires the expected memory-safety violation | a KASAN splat of the expected class in dmesg | `detectKernelSignature` / `KernelVerifyOracleResult.signatureMatched` |
| **L2 control** | attacker bytes land at a controlled offset **or** a real kernel/heap pointer is recovered — even if only once | canary-bound `ARB-WRITE` marker **and** the sprayed id at the KASAN write site (`reclaimWitnessed`), or a canary-bound `ARB-READ` marker carrying a pointer | `oracle.adjudicate` (`arb-write` / `arb-read`) |
| **L3 groom** | the L2 control is **deterministic** | the L2 canary witness reproduces in **≥M of K fresh boots** (snapshot-on ⇒ each boot independent) | `verifyAcrossBoots` (M-of-K) applied to the L2 marker |
| **L4 escalate** | root | canary `ROOT` marker + `uid=0` witness + a **preceding** `DROP:uid=N≠0` (drop-precedence) + execution attestation | `oracle.adjudicate` (`root`) + `bindKernelExecutionAttestation` |

Two subtleties that keep it honest:

- **L0/L1 map to `EscalationRung.attempted`** (ran + crashed, no capability yet);
  **L2/L3 → `arb-write`**; **L4 → `root`**. The capability mirror on
  `KernelExploitContext.highestRung` therefore never over-claims.
- **L3 is the wall, and it is a *distinct rung on purpose*.** The AIxCC-style
  N-boot gate (`verifyAcrossBoots`, `snapshot=on` per boot) is repurposed from
  "is the crash a fluke" to "is the *reclaim* a fluke". A control that holds on
  one boot but 1/5 across boots is refuted as `L2` with reason
  *"SLAB-randomization wall"* — never promoted to a groom. `SLAB_FREELIST_RANDOM`
  / `RANDOM_KMALLOC_CACHES` (read by `introspectExploitConfig`) are the reason a
  single boot is unrepresentative.

## 2. Primitive-first search (the target-first flip)

Before a bug is chosen, `enumerateGoalPrimitives(target)` produces a ranked list
of **`GoalPrimitive`s** — the leverage the *target* offers — by fusing the
deterministic toolbox with a model ranking pass:

- **groom-object** — which allocation is a good reclaim vector: `selectSprayPlans(slabCache, cfg)`
  already ranks the catalog (`msgsnd-2ndseg`, `user_key_payload`, `msg_msg`,
  `pipe_buffer`, `cmsg`, `setxattr`) against the SLAB_BUCKETS / MEMCG gates.
- **fn-ptr-field** — which struct field is a function pointer the kernel calls:
  `structLayout(vmlinux, struct)` (pahole) + `isControlFlowCallSite` pin the
  `timer_list.function` / ops-slot offset. This is the fake-cred one-shot's `+0x18`.
- **infoleak-site** — where an adjacent object leaks a pointer: an OOB/UAF read
  whose neighbour is a pointer-bearing object (`deriveProvides` → `kaslr-leak`).
- **cred-adjacent** — an object co-located with `struct cred` / `modprobe_path`:
  `resolveSymbol(vmlinux, "modprobe_path")` gives the write target.

Each `GoalPrimitive` carries the **capability it yields** (the chain `Capability`
alphabet — `arb-write`, `kaslr-leak`, `cred-overwrite`) and a **`reachedBy`**
string: the bug-shaped requirement the hunter (Engine A / the variant-hunter) is
pointed at, e.g. *"a write-UAF whose freed object is kmalloc-192 and whose free
precedes a callback dispatch"*. This is the **capability-guided** step in the
KOOBE sense: characterize the capability you *want* first, then search the object
/ bug space for something that yields it. It is the same edge model
(`provides ⊇ needs`) the chain planner already uses **across** bugs, applied
**within** one bug's climb.

**Relation to prior art.** *KOOBE* (USENIX Sec '20) extracts an OOB write's
*capability* (offset/value/length ranges) by symbolic tracing, then searches the
object space for a victim whose corruption is useful — capability-first, not
crash-first. *BridgeRouter*-style capability-guided search generalizes this to
composing primitives (leak → write → pivot). *FreeBSoD* (Praetorian) proved an
LLM can drive the L0→Ln climb on a sanitizer VM *with a human in the loop*.
Engine B's contribution is the **autonomous driver**: the human's per-rung
"try this, did it work, adjust" is exactly the `RungPlanner` + `confirmRung` +
replan loop below.

## 3. How it extends `kernel-primitive.ts`

`kernel-primitive.ts` today: `classifyKernelPrimitive(report) → KernelPrimitive`,
then a **single** `ControlDemoStep` (`demonstrated:false` until an oracle flips
it) via `attemptControlDemo(primitive, probe)`. `probe.ts:makeKernelVmProbe`
already backs that seam with **one** bounded VM run (`runWeaponization`) that
returns `controlled:true` only when the canary oracle confirms the required rung.

Engine B **generalizes the single control-demo into a multi-rung ladder driver**:

```
attemptControlDemo(primitive, probe)          // 1 rung, 1 run, boolean
        ↓  generalized to
climbLadder({ primitive, goalPrimitive, planner, vmRunner, confirmDeps })
        //  L0..L4, N runs/rung, model proposes + replans, per-rung sanitizer oracle
```

New types (in `ladder-driver.ts`):

- `LadderRung` (`L0-reach`…`L4-escalate`) + `LADDER`, `ladderRank`, `maxLadderRung`,
  `RUNG_PROOF` (the per-rung proof contract, made auditable).
- `GoalPrimitive` + `PrimitiveEnumerator` — the target-first artifact + its seam.
- `RungProposal` (the probe C + `canary` + the model's `hypothesis` + a
  `contextDelta` of structured progress) and `RungPlanner` — **the model call**.
- `RungOutcome` + `confirmRung(rung, proposal, result, goal, deps)` — **the
  per-rung sanitizer oracle**, which dispatches to the shipped oracles above.
- `climbLadder(opts) → LadderResult` — the driver loop.

The loop (`climbLadder`):

```
for targetRung in L0..ceiling:
  attempts = 0
  while attempts < budget and not confirmed:
    proposal = await planner({ primitive, goalPrimitive, targetRung,
                               proven, context, lastFailure, seenEdges })   // MODEL
    result   = await vmRunner(report(proposal.reproducer))                  // KASAN/KCOV VM
    outcome  = await confirmRung(targetRung, proposal, result, goal, deps)  // SANITIZER ORACLE
    seenEdges ∪= outcome.coveragePcs        // KCOV directed-search feedback (reuses newEdges)
    context   ∪= proposal.contextDelta      // model's structured progress threads forward
    if outcome.confirmed:
        proven = ratchet(proven, targetRung); artifactC = proposal.reproducer; break
    else:
        lastFailure = outcome                // ← the REPLAN the old harness lacks
  if not confirmed: return { stalledAt: targetRung, reason: <why> + goalPrimitive.reachedBy }
return { highestRung: proven, reachedCeiling, rungs, context, artifactC }
```

The three behaviours the shipped harness does not have, all present here:

1. **Per-rung model proposal** — `RungPlanner` is called *per rung, per attempt*,
   given the accumulated `context` + the goal primitive + the last failure.
2. **Replan-on-failure** — a refuted rung feeds `lastFailure` (real dmesg + oracle
   reason) + `seenEdges` (KCOV) back into the next proposal. The worked example
   shows the model switching spray vector after a reclaim miss.
3. **Sanitizer-gated advance** — nothing ratchets on prose; each rung waits on a
   *positive* artifact (`confirmRung`), and L3 additionally waits on N-boot
   stability.

## 4. Prototype + worked example

`packages/core/src/kernel/exploit/ladder-driver.ts` is the driver skeleton (pure
where possible; the two I/O seams — `RungPlanner`, `PrimitiveEnumerator`, and the
`vmRunner`/`nbootStable` — are injected). `ladder-driver.test.ts` is the worked
example (8 vitest cases, all green):

- **`confirmRung` per rung** — L0 needs the sink PC in the KCOV set (not just any
  coverage); L1 needs a KASAN splat; L2 needs the canary-bound `arb-write` marker
  *and* the reclaim witness (anti-replay: a stale canary is refused); **L3 refuses
  a 1/5-boot reclaim as the SLAB-randomization wall and only confirms at 4/5**;
  L4 requires `uid=0` preceded by a real drop (root-from-root is refused).
- **`climbLadder` worked example** — the model climbs L0→L2, **replans L2 once**
  after the first reclaim misses under bucketing (switching `msgsnd-2ndseg →
  user_key_payload`, the hardening-resistant sibling straight off the
  `GoalPrimitive.sprayVectors`), and threads the chosen spray onto the context.
  A second case **stalls honestly at L3** and reports *"reclaim NOT deterministic
  … SLAB-randomization wall"*.

The scenario mirrors the engine's one hand-proven family: a kmalloc-192 write-UAF
whose faulting PC is a callback dispatch (`snd_rawmidi_kernel_write1+0x1ba`), goal
primitive `snd_rawmidi_runtime @ kmalloc-192 +0x18`, reclaimed by `msgsnd-2ndseg`
/ `user_key_payload`, finished by the fake-cred one-shot.

## What is genuinely hard (honest)

- **L3 reclaim reliability is THE wall.** `SLAB_FREELIST_RANDOM` +
  `RANDOM_KMALLOC_CACHES` + per-CPU freelists mean a reclaim that lands once may
  land 1-in-K. Engine B does not *solve* this — it *refuses to lie about it*: L3
  is a separate rung gated on M-of-K boots, so the honest output of most climbs
  will be "L2 reached, L3 stalled — reclaim non-deterministic", which is the true
  state of the art and the correct signal to re-aim the primitive search (e.g.
  toward a same-CPU-pinnable persistent vector).
- **The `RungPlanner` is the research risk.** Getting a model to emit a *bounded,
  compiling* probe that isolates one rung (not a whole exploit) — and to *correct*
  it from a KASAN reason string — is the open problem. The seam is honest about
  this: the default planner is a stub; the value is the *loop + oracle contract*
  that turns a noisy generator into a rung-verified climber (Big Sleep's
  "multi-trajectory + verification" applied to weaponization).
- **KCOV sink-PC identification (L0).** We need the sink's runtime PC to check
  membership. `buildReachabilityHint` + the verify loop's `newEdges` give a
  directed signal, but mapping a source-level sink to a KASLR-stable PC set is
  approximate; L0 fails soft (no sink PC declared ⇒ "cannot prove reach") rather
  than false-confirming.
- **Enumeration precision.** `enumerateGoalPrimitives` is only as good as
  `structLayout`/`resolveSymbol` (need `vmlinux`) and the spray catalog; on a
  stripped target it degrades to the config-gated catalog alone.

## Wiring path (post-prototype, not in this branch)

1. Back `RungPlanner` with the unified LLM service (`@0cloud/llm callLlm` /
   `0sec chatgpt-codex` — never raw keys) behind the same injectable seam.
2. Back `ConfirmRungDeps.nbootStable` with a `verifyAcrossBoots` adapter and
   `detectSignature` with the shipped `detectKernelSignature`.
3. Have `enumerateGoalPrimitives` call `selectSprayPlans` + `introspect` +
   `analyzeWritePrimitive` for the deterministic half, model-rank the result.
4. Route confirmed `L4` climbs through `applyVerificationToFinding` +
   the disclosure pipeline exactly as `runWeaponization` results are today.
```
