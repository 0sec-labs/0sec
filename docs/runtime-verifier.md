# Runtime Verifier Stage

## Status

Design doc + skeleton seam. Not wired into any scan path by default.

## Motivation

The cloudflare-os campaign (2026-08-05) demonstrated a sharp quality jump when
findings were PoC'd against a live target instead of only being
source-reviewed. Static-only scans produce unverifiable candidates: the source
says the bug should trigger, but no runtime confirmation exists. The runtime
verifier stage closes that gap.

Per the postmortem pipeline:

```
target → threat-model planner → per-lane finders → adversarial refuter
       → deployment-context filter → RUNTIME VERIFIER → report assembler
```

The runtime verifier runs **after the adversarial refuter**, **before the
report assembler**, and **only for targets the engine can self-host** (i.e.
targets whose `quickstart` or equivalent brings up the service on a known
port).

## When it runs

- Only after the finding has survived the skeptic+prover gate (confirmed).
- Only for targets tagged as `selfHostable` in the target descriptor (never
  for third-party / production targets that the engine should not reach).
- Only when `E2B_API_KEY` is set in the environment. Without it, the stage is
  a silent no-op.

The stage is **never blocking**: a sandbox failure, a setup error, or a
verifier that hangs or errors out only **downgrades confidence** on the
finding — it does not drop it from the report, does not raise an exception,
and does not abort the scan.

## What it does

For each confirmed, self-hostable finding with a `poc_plan` (structured or
prose description of how to demonstrate the bug against a running target):

1. **Provision** an E2B sandbox from the target's declared quickstart image
   (the pwnkit Docker image or equivalent).
2. **Stand up** the target service inside the sandbox using its declared
   startup sequence (e.g. `docker compose up`, `pnpm run-local`, a script).
3. **Discover** the live endpoint (sandbox hostname + mapped port).
4. **Hand a verifier agent** the finding + poc_plan + live endpoint URL.
5. **Collect** the verifier's result: `PASS` (PoC produced evidence of
   exploitation), `FAIL` (PoC did not reproduce), `ERROR` (sandbox or agent
   failure).
6. **Capture** the full verifier transcript as verification evidence.
7. **Tear down** the sandbox.

### Verifier input/output contract

```typescript
interface RuntimeVerifierInput {
  finding: Finding;
  /** The finding's poc_plan — structured or prose steps for reproducing the
   *  bug against a running target instance. */
  pocPlan: string;
  /** The live target endpoint after sandbox provisioning, e.g.
   *  "https://e2b-sandbox-abc123:8080" */
  endpoint: string;
}

interface RuntimeVerdict {
  outcome: "pass" | "fail" | "error";
  confidence: number; // 0.0–1.0
  /** Verbatim transcript of the verifier agent's interaction with the target,
   *  including any output, screenshots, or error logs. */
  transcript: string;
  /** Human-readable explanation of the verdict. */
  reason: string;
}
```

## Failure posture

| Condition | Effect on finding |
|---|---|
| E2B_API_KEY unset | No-op (finding passes through with original confidence) |
| Sandbox provisioning fails | Finding confidence NOT downgraded; warning logged |
| Target startup fails | Confidence downgraded (unreproducible); warning logged |
| Verifier agent errors | Confidence downgraded; error transcript attached |
| Verifier returns FAIL | Confidence downgraded; transcript attached |
| Verifier returns PASS | Finding promoted; evidence enriched with transcript |
| Per-scan cost cap hit | Verifier skipped for remaining findings; warning logged |

## Cost guardrails

- A per-scan cost cap (env var `RUNTIME_VERIFY_COST_CAP`, default $5) limits
  total E2B provisioned time during one scan. When the cap is reached,
  remaining findings skip the verifier with a single log line.
- Each sandbox has a hard timeout (env var `RUNTIME_VERIFY_SANDBOX_TIMEOUT`,
  default 120s). Past this, the sandbox is destroyed and the finding's
  verifier attempt is recorded as `error`.
- The verifier agent itself has a timeout (env var
  `RUNTIME_VERIFY_AGENT_TIMEOUT`, default 60s).

## Safety

- Only targets tagged `selfHostable` in their target descriptor are eligible.
- The engine never provisions a sandbox against a target pointing at
  third-party infrastructure (production, staging, CI — any non-local URL).
- The sandbox runs the pwnkit Docker image, which has no host network access
  beyond the E2B gateway.
- No scan output written from inside the sandbox is trusted by the engine:
  transcripts are evidence, not commands.

## Wiring

The runtime verifier fits into the existing stage architecture at two seams:

### Seam A: composeGate (recommended for MVP)

Add an optional `runtimeVerify?: HuntVerifier` field to `HuntScanOptions`.
Wire it the same way as `exploitability`:

```typescript
// In the verify composition section of runHuntScan:
let verify = opts.verify;
if (opts.exploitability) {
  verify = composeGate(opts.verify!, opts.exploitability);
}
if (opts.runtimeVerify) {
  verify = composeGate(verify ?? /* pass-through */, opts.runtimeVerify);
}
```

This places the runtime verifier as the **terminal gate stage** — it only runs
on findings that survived the skeptic+prover gate (and the exploitability
gate, if wired). The same `composeGate` short-circuit behavior applies: if an
earlier gate rejects the finding, the runtime verifier never sees it.

### Seam B: VerifyLens (for multi-lens quorum)

Add a `RuntimeVerifyLens` type:

```typescript
interface RuntimeVerifyLens extends VerifyLens {
  type: "runtime";
  /** The finding's poc_plan steps for the verifier agent. */
  pocPlan: string;
  /** Which self-hostable target to stand up. */
  targetDescriptor: string;
}
```

A `makeMultiLensVerifier` that includes a runtime lens would run the
adversarial refute AND the sandbox PoC in parallel, requiring all lenses to
survive. This is architecturally cleaner but needs the E2B client at lens
construction time.

### Chosen seam for skeleton

The skeleton implements **Seam A** (composeGate stage) because it requires no
changes to `makeMultiLensVerifier` or the lens quorum logic. See
`packages/core/src/stages/runtime-verify.ts` for the interface.

## Dependencies

- `@e2b/sdk` (or equivalent E2B client) — not yet added to `package.json`;
  the skeleton is a no-op without `E2B_API_KEY` and imports nothing from E2B.
- The target's quickstart/startup descriptor — TBD per target type.

## Future work

- Full E2B driver (`E2bSandboxProvisioner` class).
- Verifier agent prompt and handoff protocol.
- `selfHostable` target descriptor field.
- `poc_plan` structured field on `Finding` (currently prose in
  `evidence.analysis`).
- Per-target startup scripts baked into the pwnkit Docker image.
- Integration test against a real E2B sandbox.