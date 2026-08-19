# Engine C — the mechanized-artifact oracle + auto-harness-synthesis

> Status: 2026-07-13. Design + prototype. Implements 0sec#1228, part of the
> LLM-native-LPE EPIC (0sec#1227). Plan:
> `docs/operations/llm-lpe-innovation-plan.md`.

## Why

The field's #1 convergent bottleneck is **precision, not recall**. LLM
code-review flags plenty; almost all of it is wrong. Measured, from the 6-angle
frontier sweep:

- o3 / ksmbd: **1:50 signal-to-noise**, confidently-worded false positives.
- Windows binary-RE: **~60% of high/critical decompiled findings hallucinate.**
- AIxCC: 37–46% of even *auto-validated* patches were semantically wrong.

Nobody has a **cheap, sound oracle** between "an LLM flagged a candidate" and "a
weaponized PoC." Our adversarial `finder→skeptic→prover` + the shipped **N×
reproduction gate** is *literally* that missing piece. Engine C hardens it into
a gate that **refuses to confirm any candidate that cannot carry a mechanized
artifact**, and adds the one thing that unblocks binary/Windows:
**auto-harness-synthesis** — generate the driver-load handshake + device state
that reaches a target IOCTL so the candidate can actually be triggered.

## The mechanized-artifact contract

A candidate is **CONFIRMED** only when it carries BOTH:

1. **A grep-verifiable structural proof** — the exact sink / two call sites /
   freed field / missing lock, each named as a *needle* that MUST literally
   exist in the real source (or the decompiled unit, for binary/Windows). Every
   needle is grepped against the bytes on disk. A needle that is not there
   **refutes** the finding. This is the o3 lesson mechanized: no hand-waving, no
   quoted-snippet misreads, no invented IOCTL codes.

2. **EITHER** a reproduced sanitizer artifact (a real `CrashArtifact` under
   ASan/UBSan/MSan/Miri/KASAN, N× reproduced — reusing `isReproducedMemCorruption`
   + the N× gate) **OR** a bounded structural check — a small, decidable set of
   grep assertions that establish the specific invariant violation for a
   **non-crashing** bug (the logic/auth/lifetime class the crash oracle is blind
   to; the U1 whitespace).

### Verdict semantics (`mechanizedArtifactVerdict`)

Mirrors `VerifyOutcome`, keeps the #518 discipline (inconclusive ≠ rejected):

| Verdict | When | Effect |
|---|---|---|
| `rejected` | a structural claim **failed to grep-verify** | mechanized FP-kill — the one place Engine C hard-drops, because we have machine proof the finding is fabricated |
| `confirmed` | structural proof verified **AND** (reproduced sanitizer crash OR passing bounded check) | disclosure-grade; N× folded into confidence |
| `inconclusive` | proof verified but no dynamic/bounded proof yet, **or** no proof supplied at all | **held** for the prover / harness-synth — never disclosed, never silently dropped |

This is **stricter than `memCorruptionVerdict`**: that verdict confirms on a
reproduced crash alone. Engine C demands the grep-verifiable structural proof
*first* — a crash reproduced at a site the finding mis-attributes is still an FP.

### Schema (`packages/core/src/triage/mechanized-artifact.ts`)

```
MechanizedArtifact {
  structuralProof: StructuralClaim[]   // REQUIRED, non-empty
  reproducedCrash?: CrashArtifact      // crash-class branch (N× gate)
  boundedCheck?: BoundedStructuralCheck // non-crashing branch
}
StructuralClaim { kind, file, needle, isRegex?, absent?, spanStart?, spanEnd?, line?, note? }
BoundedStructuralCheck { kind, assertion, evidence: StructuralClaim[] }
```

A `missing-lock` is a **negative** claim (`absent: true`) over a line span: the
lock-acquire needle must be *absent* between the free and the use. That is how
the "missing lock" from the o3 lesson is mechanized rather than asserted.

The artifact is emitted by the synthesiser LLM through a **Zod-validated tool
schema** (`emit_mechanized_artifact`), the same structured-output discipline as
`kernel-run.ts`: a malformed submission is rejected, unknown keys are stripped.

## Auto-harness-synthesis (`packages/core/src/verify/harness-synth.ts`)

The oracle can only confirm a bug it can **reproduce**, and it cannot reproduce a
bug it cannot **reach**. This is the binary/Windows choke point (U3): "auto-
synthesizing the init handshake / device state so a closed-source driver loads
and reaches its vulnerable IOCTL."

`synthesizeHarness(target, model, runner)` drives an LLM to emit a harness that
opens the device, runs the init handshake, builds the arg struct, and issues the
call that lands on the sink — validated by a **real reachability signal**, not
the model's say-so. It reuses two shipped ideas verbatim:

- **Two-phase reach→refine** (`kernel-verify.ts`): early attempts run under a
  cheap `reach` build to *land the path*; only once reached do we escalate to the
  sanitizer `refine` build to nail the crash. Cheap first, expensive only on
  reach.
- **Coverage-feedback re-prompt** (`kernel-verify.ts`): each run returns which
  new edges it reached toward the sink (or which gate it stalled at, e.g.
  "returned -EINVAL — handshake missing"); that is fed back into the next prompt.

**Domain-neutral by design.** The execution + reachability oracle is an injected
`HarnessRunner` returning one shape for both worlds:

- **Kernel** prod wraps `kernel-vm-runner` with KCOV; `reached` = a KCOV PC
  landing in the sink neighbourhood.
- **Windows** prod wraps the Hyper-V host (`reference_visor_hyperv_box`) with a
  WinDbg breakpoint at the dispatch routine; `reached` = breakpoint hit.

The synth logic is identical, so it is fully unit-testable with a fake runner —
no VM, no keys.

Outputs: `reached-and-crashed` (the win → the crash feeds the mechanized gate's
`reproduce` seam and the N× gate), `reached` (triggerable but benign → hand to
N× repro / bounded check), `not-reached`, `no-harness`.

## How it plugs into finder→skeptic→prover

Engine C is the **formalized prover stage** — it composes into `runHuntScan`'s
`composeGate` exactly where the existing prover sits:

```ts
verify = composeGate(
  makeSkepticVerifier(...),          // cheap adversarial refute (kills easy FPs)
  makeMechanizedArtifactGate({       // Engine C — grep-verifiable proof + repro/bounded
    synthesize,                      //   LLM extracts the structural claims
    loadSource,                      //   reads the real bytes to grep-check them
    reproduce: harnessSynthReproduce,//   → synthesizeHarness → withNxReproduction(runner, N)
  }),
  makeExploitabilityGate(...),       // PROVE stage (existing) — gates weaponization
);
```

- `composeGate` short-circuits on the first stage that rejects, so the cheap
  skeptic runs first and Engine C only pays the synth+grep cost on survivors.
- Engine C confirms ⇔ `mechanizedArtifactVerdict` is `confirmed`. A `rejected`
  (mechanized refutation) and an `inconclusive` (held) both return
  `confirmed:false`, with a reason that distinguishes them.
- **The N× gate composes inside the `reproduce` seam**: prod wires
  `reproduce` to `synthesizeHarness → withNxReproduction(defaultKernelVerifyRunner, N)`,
  which stamps `reproConfirmations`/`reproAttempts` onto the `CrashArtifact`;
  `mechanizedArtifactVerdict` then folds them into confidence (2+ → 0.95,
  1-of-N → 0.82 flagged flaky) — the same policy as `memCorruptionVerdict`.

## What ships in the prototype

- `packages/core/src/triage/mechanized-artifact.ts` — schema, the deterministic
  grep core (`verifyStructuralProof`), the stricter gate
  (`mechanizedArtifactVerdict`), the Zod-validated synthesiser
  (`synthesizeMechanizedArtifact` / `parseMechanizedArtifact`), and the
  `HuntVerifier` adapter (`makeMechanizedArtifactGate`).
- `packages/core/src/verify/harness-synth.ts` — the reach→refine synth loop with
  the injected `HarnessRunner` / `HarnessSynthModel` seams.
- 30 unit tests (offline, injected seams) covering the FP-kill (hallucinated
  needle / file / IOCTL code → `rejected`), both confirm paths, N× dampening,
  bounded-check pass/fail, held-not-dropped semantics, and the harness
  reach→refine + coverage-feedback loop.

## Not in this prototype (follow-ups)

- Prod wiring of `loadSource` to the repo checkout + the Ghidra/BinaryNinja
  decompile cache (the Windows unit id → pseudo-C map).
- Prod `HarnessRunner` implementations (KCOV kernel lane; Hyper-V + WinDbg
  Windows lane).
- Persisting `MechanizedVerdict` + `claimResults` onto the finding record for
  the disclosure trail.
- Extending `argStructLayout` / `ioctlCode` extraction from the decompiler into
  the `HarnessTarget` builder.
