/**
 * Engine C — the mechanized-artifact oracle (0sec#1228).
 *
 * The FP-killer that converts LLM RECALL into PRECISION. The field's #1
 * convergent bottleneck (docs/operations/llm-lpe-innovation-plan.md): LLM
 * code-review has high recall but catastrophic precision — o3/ksmbd measured
 * 1:50 signal-to-noise with confidently-worded false positives; Windows
 * binary-RE hallucinates ~60% of high/critical decompiled findings. Nobody has
 * a cheap, SOUND oracle between "an LLM flagged a candidate" and "a weaponized
 * PoC". Our adversarial finder→skeptic→prover + the N× reproduction gate is
 * literally that missing piece — this module HARDENS it into a gate that
 * REJECTS any candidate that cannot carry a mechanized artifact.
 *
 * A "mechanized artifact" is the demand that separates a real bug from a
 * plausible-but-wrong one. A candidate is only CONFIRMED when it carries BOTH:
 *
 *   (1) a grep-verifiable STRUCTURAL PROOF — the exact two call sites / freed
 *       field / missing lock, named as needles that MUST literally exist in the
 *       real source (or the decompiled unit, for binary/Windows). This is the
 *       o3 lesson mechanized: the model may not hand-wave; every claim is
 *       checked against the bytes on disk, so a fabricated sink / an invented
 *       IOCTL code / a misread layout is caught deterministically. AND
 *
 *   (2) EITHER a reproduced sanitizer artifact (a real {@link CrashArtifact}
 *       that fired under ASan/UBSan/MSan/Miri/KASAN, N× reproduced — reusing
 *       the shipped {@link isReproducedMemCorruption} + N× reproduction gate),
 *       OR a BOUNDED STRUCTURAL CHECK — a small, decidable set of grep/AST
 *       assertions that together establish the specific invariant violation for
 *       a NON-crashing bug (a logic/auth/lifetime bug where no sanitizer oracle
 *       exists — the U1 whitespace: "no public demo of an LLM finding a
 *       non-crashing logic bug"). The bounded check does not prove
 *       exploitability (the model still reasons about that) — it mechanizes the
 *       STRUCTURAL FACTS the reasoning stands on.
 *
 * Relationship to {@link memCorruptionVerdict} (pov-gate.ts): that verdict is
 * the crash-side half — "did a sanitizer crash reproduce?". Engine C is
 * STRICTER: it demands the grep-verifiable structural proof FIRST, before it
 * will even trust a reproduced crash (a crash reproduced at a site the finding
 * mis-attributes is still an FP), and it extends coverage to the non-crashing
 * class the crash oracle is blind to.
 *
 * VERDICT SEMANTICS (mirrors {@link VerifyOutcome}, keeps the #518 discipline):
 *   - `rejected`    — a structural claim FAILED to grep-verify. This is a
 *                     MECHANIZED refutation: we proved the claim is fabricated
 *                     (the needle is not in the source). The one place Engine C
 *                     hard-drops, because we have machine proof it is wrong.
 *   - `confirmed`   — structural proof grep-verified AND (a reproduced sanitizer
 *                     crash OR a passing bounded structural check).
 *   - `inconclusive`— structural proof verified but no reproduction / bounded
 *                     check landed yet. HELD for the prover, never disclosed,
 *                     never silently dropped (a real bug that just isn't proven
 *                     yet must not be buried — the #518 failure mode).
 *
 * TESTABILITY: every side effect (reading source, reproducing a crash,
 * synthesising the artifact via an LLM) is an INJECTED seam, so the whole gate
 * is unit-testable with fakes — no VM, no network, no keys. Prod wires the real
 * source reader + the kernel-VM / sanitizer reproduce lane + the engine
 * runtime.
 */

import { z } from "zod";
import type { Finding } from "@0sec/shared";
import type { CrashArtifact } from "./memsafety-types.js";
import { isReproducedMemCorruption } from "./pov-gate.js";
import type { VerifyVerdict, VerifySignal } from "./verify-verdict.js";
import type { HuntVerifier, HuntCandidate } from "../stages/hunt-scan.js";

// ────────────────────────────────────────────────────────────────────
// The structural-proof contract — grep-verifiable claims
// ────────────────────────────────────────────────────────────────────

/**
 * What KIND of structural fact a claim asserts. Not load-bearing for
 * verification (the `needle` grep is what decides), but it names the anti-FP
 * category the o3 / Windows-RE reports call out so the audit trail is legible.
 */
export type StructuralClaimKind =
  | "sink" // the vulnerable operation itself (memcpy, kfree, DeviceIoControl arg use)
  | "call-site" // one of the two call sites in a UAF/double-free (free here, use there)
  | "freed-field" // the exact field freed then reused (sk->sk_user_data)
  | "missing-lock" // the guard that is ABSENT on the racing path (negative claim)
  | "alloc-site" // where the object is allocated (lifetime reasoning)
  | "ioctl-code" // a decompiled Windows IOCTL code / dispatch constant
  | "guard" // a bounds/permission check the finding claims present-or-absent
  | "custom";

/**
 * One grep-verifiable claim. The `needle` MUST appear (or, for `absent`, MUST
 * NOT appear) in the real source of `file` — this is the mechanization. The
 * model cannot advance a finding on prose alone; it must point at bytes.
 */
export interface StructuralClaim {
  kind: StructuralClaimKind;
  /**
   * Path (relative to the source root) of the file the claim is about. For a
   * binary/Windows target this is the decompiled-unit id (e.g.
   * "driver.sys::DispatchDeviceControl") — the loader returns the pseudo-C for
   * it, so an invented IOCTL code that Ghidra never produced is caught here.
   */
  file: string;
  /**
   * The exact token/expression that must be present in `file` (a substring or,
   * when {@link StructuralClaim.isRegex} is set, a RegExp source). Keep it
   * specific — `kfree(sk->sk_user_data)`, not `kfree`.
   */
  needle: string;
  /** Treat `needle` as a RegExp source instead of a literal substring. */
  isRegex?: boolean;
  /**
   * A NEGATIVE claim: the needle must NOT appear (in the whole file, or within
   * {@link StructuralClaim.spanStart}..{@link StructuralClaim.spanEnd} when
   * given). This is how "missing lock between free and use" is mechanized: the
   * lock acquire needle must be ABSENT in the span between the two sites.
   */
  absent?: boolean;
  /** Optional line span (1-indexed, inclusive) to bound a needle / absence check. */
  spanStart?: number;
  spanEnd?: number;
  /** Advisory expected line for a positive claim (needle presence still decides). */
  line?: number;
  /** Human-readable note for the audit trail. */
  note?: string;
}

/**
 * A BOUNDED STRUCTURAL CHECK — the non-crashing-bug branch. A small set of
 * decidable grep/AST assertions ({@link StructuralClaim}s) that TOGETHER
 * establish a specific invariant violation. Bounded, not a theorem prover: it
 * mechanizes the structural FACTS (the free exists here; no re-init/guard on the
 * path to the use there) so the reasoning that it is a bug stands on machine-
 * checked ground rather than a hallucinated snippet.
 */
export interface BoundedStructuralCheck {
  kind:
    | "unbalanced-free" // free with no matching re-init / null-out before reuse
    | "missing-guard" // sink reached with the guarding check provably absent
    | "lock-not-held" // shared field touched with the lock provably not acquired
    | "unchecked-return" // fallible call whose error path is provably not taken
    | "reachable-dead-guard" // an "unreachable/guarded" claim disproven structurally
    | "custom";
  /** The invariant asserted, phrased mechanically ("free at A, no re-init before use at B"). */
  assertion: string;
  /**
   * The evidence spans that make the assertion DECIDABLE. Typically a positive
   * claim (the free exists) plus a negative claim (the guard is absent on the
   * span between free and use). ALL must verify for the check to hold.
   */
  evidence: StructuralClaim[];
}

/**
 * The mechanized artifact a candidate must carry to be confirmable. Produced by
 * {@link synthesizeMechanizedArtifact} (the LLM extraction) and adjudicated by
 * {@link mechanizedArtifactVerdict} (the deterministic gate).
 */
export interface MechanizedArtifact {
  /**
   * The grep-verifiable structural proof — the exact call sites / freed field /
   * missing lock. REQUIRED and non-empty: a candidate with no structural claim
   * cannot be mechanized, so it can never be confirmed by this gate.
   */
  structuralProof: StructuralClaim[];
  /**
   * A reproduced sanitizer crash, when the bug is a memory-corruption class the
   * crash oracle can catch. Trusted only through {@link isReproducedMemCorruption}
   * (saved reproducing input + a real ASan/UBSan/MSan/Miri/segfault signature),
   * with the N× reproduction count folded into confidence.
   */
  reproducedCrash?: CrashArtifact;
  /**
   * A bounded structural check, for the NON-crashing class (logic / auth /
   * lifetime bugs with no sanitizer oracle). Mutually complementary with
   * `reproducedCrash` — either one (with a verified structural proof) confirms.
   */
  boundedCheck?: BoundedStructuralCheck;
  /** Free-form provenance the synthesiser attaches (which model, which pass). */
  provenance?: string;
}

// ────────────────────────────────────────────────────────────────────
// Structural-proof verification — the deterministic grep core
// ────────────────────────────────────────────────────────────────────

/**
 * Load the source of a claimed `file` (relative path or decompiled-unit id).
 * Returns null when the file does not exist — a claim about a non-existent file
 * is itself a hallucination and fails. Injected so prod reads from disk / the
 * decompiler cache and tests pass a fixture map.
 */
export type SourceLoader = (file: string) => Promise<string | null> | (string | null);

/** Per-claim verification outcome for the audit trail. */
export interface ClaimResult {
  claim: StructuralClaim;
  /** True when the claim held (needle present for a positive claim, absent for a negative). */
  verified: boolean;
  /** Why — for the record. */
  reason: string;
}

function sliceSpan(source: string, start?: number, end?: number): string {
  if (start === undefined && end === undefined) return source;
  const lines = source.split("\n");
  const from = Math.max(1, start ?? 1);
  const to = Math.min(lines.length, end ?? lines.length);
  if (from > to) return "";
  return lines.slice(from - 1, to).join("\n");
}

function needleHit(haystack: string, claim: StructuralClaim): boolean {
  if (claim.isRegex) {
    try {
      return new RegExp(claim.needle).test(haystack);
    } catch {
      // A malformed regex needle can never verify — treat as a miss, not a throw.
      return false;
    }
  }
  return haystack.includes(claim.needle);
}

/**
 * Verify ONE structural claim against the real source. Positive claims require
 * the needle present; negative (`absent`) claims require it absent in the span.
 * A claim about a missing file, or a needle that is not where the model said it
 * is, FAILS — that is the mechanized FP-kill.
 */
export async function verifyStructuralClaim(
  claim: StructuralClaim,
  loadSource: SourceLoader,
): Promise<ClaimResult> {
  const source = await loadSource(claim.file);
  if (source == null) {
    return {
      claim,
      verified: false,
      reason: `file not found: ${claim.file} — claim references source that does not exist (hallucination)`,
    };
  }
  const span = sliceSpan(source, claim.spanStart, claim.spanEnd);
  const hit = needleHit(span, claim);

  if (claim.absent) {
    // Negative claim: the needle must NOT be present in the span.
    return {
      claim,
      verified: !hit,
      reason: hit
        ? `negative claim FAILED: "${clip(claim.needle, 60)}" IS present in ${claim.file}${spanTag(claim)} — the '${claim.kind}' the finding relies on being absent is actually there`
        : `negative claim held: "${clip(claim.needle, 60)}" absent in ${claim.file}${spanTag(claim)}`,
    };
  }

  return {
    claim,
    verified: hit,
    reason: hit
      ? `"${clip(claim.needle, 60)}" present in ${claim.file}${spanTag(claim)}`
      : `"${clip(claim.needle, 60)}" NOT found in ${claim.file}${spanTag(claim)} — claimed ${claim.kind} does not exist as stated (hallucination)`,
  };
}

/** Verify every claim in a structural proof. */
export async function verifyStructuralProof(
  claims: StructuralClaim[],
  loadSource: SourceLoader,
): Promise<{ verified: boolean; results: ClaimResult[]; failures: ClaimResult[] }> {
  const results: ClaimResult[] = [];
  for (const claim of claims) {
    results.push(await verifyStructuralClaim(claim, loadSource));
  }
  const failures = results.filter((r) => !r.verified);
  return { verified: failures.length === 0, results, failures };
}

// ────────────────────────────────────────────────────────────────────
// The gate — mechanizedArtifactVerdict (stricter than memCorruptionVerdict)
// ────────────────────────────────────────────────────────────────────

/**
 * Engine-C-local evidence basis. Kept OUT of the parity-locked
 * `VERIFY_EVIDENCE_KINDS*` tuples in verify-verdict.ts (the 0cloud contract
 * mirror is asserted verbatim) — Engine C carries its own basis label on the
 * result so the shared union is untouched. `reproduced-sanitizer-crash` reuses
 * the same signal as `reproduced-memcorruption-poc`; `bounded-structural-check`
 * is the non-crashing branch that has no crash to point at.
 */
export type MechanizedBasis =
  | "reproduced-sanitizer-crash"
  | "bounded-structural-check"
  | "none";

/** Engine C's verdict — a {@link VerifyVerdict} plus the mechanized basis. */
export interface MechanizedVerdict extends VerifyVerdict {
  mechanizedBasis: MechanizedBasis;
  /** Per-claim structural-proof results (the audit trail behind the verdict). */
  claimResults: ClaimResult[];
}

/**
 * Fold an N× reproduction count into a confidence + note (same policy as
 * pov-gate.ts's `reproConfidence`, re-derived here so Engine C does not reach
 * into that module's private helper). A crash with no `reproConfirmations`
 * keeps the legacy 0.95; a lone 1-of-N reproduction is dampened to 0.82 and
 * flagged flaky; 2+ is full strength.
 */
function foldReproConfidence(crash: CrashArtifact): { confidence: number; note: string } {
  const n = crash.reproConfirmations;
  if (n == null) return { confidence: 0.95, note: "" };
  if (n >= 2) {
    const attempts = crash.reproAttempts ?? n;
    return { confidence: 0.95, note: ` Reproduced ${n}/${attempts}× (N× confirmed).` };
  }
  const attempts = crash.reproAttempts ?? 1;
  return {
    confidence: 0.82,
    note:
      attempts > 1
        ? ` Reproduced only 1/${attempts}× — flaky-repro risk; re-run to confirm.`
        : ` Single-shot reproduction (N=1) — re-run to rule out an environment fluke.`,
  };
}

/** Does a bounded structural check HOLD? True iff every evidence claim verifies. */
export async function evaluateBoundedCheck(
  check: BoundedStructuralCheck,
  loadSource: SourceLoader,
): Promise<{ holds: boolean; results: ClaimResult[] }> {
  const { verified, results } = await verifyStructuralProof(check.evidence, loadSource);
  return { holds: verified, results };
}

export interface MechanizedVerdictOptions {
  /**
   * Minimum number of structural claims a proof must carry to be taken
   * seriously. Default 1. Raise it (e.g. 2, "name the free AND the use") to
   * demand the two-call-site discipline the o3 lesson calls for on UAF-class
   * findings.
   */
  minClaims?: number;
  log?: (msg: string) => void;
}

/**
 * Adjudicate a {@link MechanizedArtifact} into a {@link MechanizedVerdict}.
 *
 * Order matters — the structural proof is the GATE on everything else:
 *   1. No structural proof (empty / below `minClaims`) → inconclusive. It is
 *      not disprovable, but it carries no mechanized artifact, so it cannot be
 *      confirmed. (Held, not dropped — #518.)
 *   2. Any structural claim FAILS to grep-verify → REJECTED. We have machine
 *      proof the finding is fabricated (the named sink/field/lock is not in the
 *      source). This is the FP-kill.
 *   3. Structural proof verifies + a reproduced sanitizer crash → CONFIRMED
 *      (basis reproduced-sanitizer-crash, N× folded into confidence).
 *   4. Structural proof verifies + a passing bounded structural check →
 *      CONFIRMED (basis bounded-structural-check).
 *   5. Structural proof verifies but neither dynamic proof landed → inconclusive
 *      (structural facts are real; hand it to the prover / harness-synth to
 *      reproduce). Held, not dropped.
 */
export async function mechanizedArtifactVerdict(
  artifact: MechanizedArtifact,
  loadSource: SourceLoader,
  opts: MechanizedVerdictOptions = {},
): Promise<MechanizedVerdict> {
  const minClaims = Math.max(1, opts.minClaims ?? 1);
  const log = opts.log ?? (() => {});
  const claims = artifact.structuralProof ?? [];

  // 1. No mechanized structural proof at all → cannot confirm, but not disproven.
  if (claims.length < minClaims) {
    return {
      verdict: "inconclusive",
      confidence: 0,
      reasoning:
        `No mechanized structural proof (${claims.length} claim(s) < required ${minClaims}). ` +
        "A candidate must name the exact sink / freed field / missing lock as grep-verifiable " +
        "claims before it can be confirmed. Held for the prover — not a rejection.",
      signals: [claimSignal("structural_proof", false, `only ${claims.length} claim(s)`)],
      mechanizedBasis: "none",
      claimResults: [],
    };
  }

  // 2. Verify the structural proof against the REAL source.
  const proof = await verifyStructuralProof(claims, loadSource);
  const claimResults = proof.results;
  if (!proof.verified) {
    // A claimed structural fact is not in the source → mechanized refutation.
    const firstFail = proof.failures[0]!;
    log(`[engine-c] REJECT: structural proof failed — ${firstFail.reason}`);
    return {
      verdict: "rejected",
      confidence: 0.9,
      reasoning:
        `Mechanized refutation: ${proof.failures.length}/${claims.length} structural claim(s) ` +
        `do not grep-verify against the real source. First failure: ${firstFail.reason}. ` +
        "The finding names code that is not there — a hallucination.",
      signals: [
        claimSignal(
          "structural_proof",
          false,
          `${proof.failures.length}/${claims.length} claims failed to verify`,
        ),
      ],
      mechanizedBasis: "none",
      claimResults,
    };
  }

  const proofSignal = claimSignal(
    "structural_proof",
    true,
    `${claims.length}/${claims.length} structural claim(s) grep-verified`,
  );

  // 3. Reproduced sanitizer crash — the strongest basis when the class allows it.
  if (artifact.reproducedCrash && isReproducedMemCorruption(artifact.reproducedCrash)) {
    const gate = foldReproConfidence(artifact.reproducedCrash);
    log(`[engine-c] CONFIRM: structural proof + reproduced ${artifact.reproducedCrash.kind} crash`);
    return {
      verdict: "confirmed",
      confidence: gate.confidence,
      reasoning:
        `Structural proof grep-verified AND a sanitizer crash reproduced ` +
        `(kind=${artifact.reproducedCrash.kind}, signature=${artifact.reproducedCrash.signature}).${gate.note}`,
      signals: [
        proofSignal,
        {
          name: "reproduced_sanitizer_crash",
          passed: true,
          confidence: gate.confidence,
          reasoning:
            `signature=${artifact.reproducedCrash.signature}, input=${artifact.reproducedCrash.inputPath}` +
            (artifact.reproducedCrash.reproConfirmations != null
              ? `, repro=${artifact.reproducedCrash.reproConfirmations}/${artifact.reproducedCrash.reproAttempts ?? artifact.reproducedCrash.reproConfirmations}`
              : ""),
        },
      ],
      evidenceKind: "reproduced-memcorruption-poc",
      mechanizedBasis: "reproduced-sanitizer-crash",
      claimResults,
    };
  }

  // 4. Bounded structural check — the non-crashing branch.
  if (artifact.boundedCheck) {
    const evalResult = await evaluateBoundedCheck(artifact.boundedCheck, loadSource);
    if (evalResult.holds) {
      log(`[engine-c] CONFIRM: structural proof + bounded check (${artifact.boundedCheck.kind})`);
      return {
        verdict: "confirmed",
        // A bounded structural check is sound about the STRUCTURE but the
        // exploitability reasoning on top is still the model's — so it caps
        // below a reproduced crash. Disclosure-grade, weaponization-gated.
        confidence: 0.75,
        reasoning:
          `Structural proof grep-verified AND a bounded structural check holds ` +
          `(${artifact.boundedCheck.kind}): ${artifact.boundedCheck.assertion}. ` +
          "Non-crashing bug — structural facts are mechanized; exploitability reasoning is the model's.",
        signals: [
          proofSignal,
          claimSignal(
            "bounded_structural_check",
            true,
            `${artifact.boundedCheck.kind}: all ${artifact.boundedCheck.evidence.length} evidence claim(s) held`,
          ),
        ],
        mechanizedBasis: "bounded-structural-check",
        claimResults: [...claimResults, ...evalResult.results],
      };
    }
    // Bounded check named but its evidence did not hold → the non-crashing
    // proof is unproven. Structural proof still verified, so this is not a
    // rejection — it is held.
    return {
      verdict: "inconclusive",
      confidence: 0.2,
      reasoning:
        `Structural proof grep-verified but the bounded structural check did NOT hold ` +
        `(${artifact.boundedCheck.kind}): ${evalResult.results.find((r) => !r.verified)?.reason ?? "evidence incomplete"}. ` +
        "Held — the structural facts are real but the invariant-violation claim is not yet established.",
      signals: [proofSignal, claimSignal("bounded_structural_check", false, "evidence did not hold")],
      mechanizedBasis: "none",
      claimResults: [...claimResults, ...evalResult.results],
    };
  }

  // 5. Structural proof verified, but no dynamic proof and no bounded check.
  //    Hand it to the prover / harness-synth. Held, never dropped.
  return {
    verdict: "inconclusive",
    confidence: 0.4,
    reasoning:
      "Structural proof grep-verified, but no reproduced sanitizer crash and no bounded structural " +
      "check was supplied. The named sink/field/lock are real — reproduce it (harness-synth → N× gate) " +
      "or attach a bounded check to confirm. Held, not a rejection.",
    signals: [proofSignal, claimSignal("dynamic_proof", false, "no crash / bounded check attached")],
    mechanizedBasis: "none",
    claimResults,
  };
}

function claimSignal(name: string, passed: boolean, reasoning: string): VerifySignal {
  return { name, passed, confidence: passed ? 1 : 0, reasoning };
}

function spanTag(claim: StructuralClaim): string {
  if (claim.spanStart === undefined && claim.spanEnd === undefined) return "";
  return ` [lines ${claim.spanStart ?? 1}..${claim.spanEnd ?? "end"}]`;
}

function clip(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}

// ────────────────────────────────────────────────────────────────────
// LLM synthesis of the mechanized artifact (structured-output discipline)
// ────────────────────────────────────────────────────────────────────

/**
 * The tool the synthesiser LLM must call. Structured-output discipline (AIxCC
 * T9 / kernel-run.ts): the model emits the artifact through a schema, and a
 * malformed submission is REJECTED rather than trusted. The model's job is to
 * NAME the grep-verifiable needles — it is then held to them by the gate.
 */
export const emitMechanizedArtifactTool = {
  name: "emit_mechanized_artifact",
  description:
    "Emit the mechanized artifact for this finding: the exact grep-verifiable structural claims " +
    "(the sink, the two call sites, the freed field, the missing lock) that MUST literally exist " +
    "in the source, plus (if it is a non-crashing bug) a bounded structural check. Do NOT invent " +
    "needles — every needle you name will be grep-checked against the real file, and a needle that " +
    "is not there REFUTES the finding. Name specific tokens (kfree(sk->sk_user_data)), not bare symbols.",
  input_schema: {
    type: "object",
    properties: {
      structural_proof: {
        type: "array",
        description:
          "The grep-verifiable claims. Each: {kind, file, needle, absent?, span_start?, span_end?, note?}.",
        items: {
          type: "object",
          properties: {
            kind: {
              type: "string",
              enum: [
                "sink",
                "call-site",
                "freed-field",
                "missing-lock",
                "alloc-site",
                "ioctl-code",
                "guard",
                "custom",
              ],
            },
            file: { type: "string", description: "Path (or decompiled-unit id) the claim is about." },
            needle: { type: "string", description: "Exact token/expression that must exist in the file." },
            is_regex: { type: "boolean", description: "Treat needle as a RegExp source." },
            absent: {
              type: "boolean",
              description: "Negative claim: needle must NOT appear (e.g. the missing lock).",
            },
            span_start: { type: "number", description: "1-indexed start line to bound the check." },
            span_end: { type: "number", description: "1-indexed end line to bound the check." },
            note: { type: "string" },
          },
          required: ["kind", "file", "needle"],
        },
      },
      bounded_check: {
        type: "object",
        description:
          "For a NON-crashing bug only: the bounded structural check. Omit for a crash-class bug.",
        properties: {
          kind: {
            type: "string",
            enum: [
              "unbalanced-free",
              "missing-guard",
              "lock-not-held",
              "unchecked-return",
              "reachable-dead-guard",
              "custom",
            ],
          },
          assertion: { type: "string" },
          evidence: {
            type: "array",
            items: {
              type: "object",
              properties: {
                kind: { type: "string" },
                file: { type: "string" },
                needle: { type: "string" },
                is_regex: { type: "boolean" },
                absent: { type: "boolean" },
                span_start: { type: "number" },
                span_end: { type: "number" },
              },
              required: ["kind", "file", "needle"],
            },
          },
        },
        required: ["kind", "assertion", "evidence"],
      },
    },
    required: ["structural_proof"],
  },
} as const;

/** Zod schema for one emitted claim (structured-output discipline). */
const claimSchema = z
  .object({
    kind: z
      .enum([
        "sink",
        "call-site",
        "freed-field",
        "missing-lock",
        "alloc-site",
        "ioctl-code",
        "guard",
        "custom",
      ])
      .catch("custom"),
    file: z.string().min(1),
    needle: z.string().min(1),
    is_regex: z.boolean().optional(),
    absent: z.boolean().optional(),
    span_start: z.number().int().positive().optional(),
    span_end: z.number().int().positive().optional(),
    line: z.number().int().positive().optional(),
    note: z.string().optional(),
  })
  .strip()
  .transform((c): StructuralClaim => ({
    kind: c.kind,
    file: c.file,
    needle: c.needle,
    ...(c.is_regex !== undefined ? { isRegex: c.is_regex } : {}),
    ...(c.absent !== undefined ? { absent: c.absent } : {}),
    ...(c.span_start !== undefined ? { spanStart: c.span_start } : {}),
    ...(c.span_end !== undefined ? { spanEnd: c.span_end } : {}),
    ...(c.line !== undefined ? { line: c.line } : {}),
    ...(c.note !== undefined ? { note: c.note } : {}),
  }));

/** Zod schema for the whole `emit_mechanized_artifact` payload. */
export const mechanizedArtifactSchema = z
  .object({
    structural_proof: z.array(claimSchema).min(1, "structural_proof must name at least one claim"),
    bounded_check: z
      .object({
        kind: z
          .enum([
            "unbalanced-free",
            "missing-guard",
            "lock-not-held",
            "unchecked-return",
            "reachable-dead-guard",
            "custom",
          ])
          .catch("custom"),
        assertion: z.string().min(1),
        evidence: z.array(claimSchema).min(1),
      })
      .strip()
      .optional(),
  })
  .strip()
  .transform((p): MechanizedArtifact => ({
    structuralProof: p.structural_proof,
    ...(p.bounded_check
      ? {
          boundedCheck: {
            kind: p.bounded_check.kind,
            assertion: p.bounded_check.assertion,
            evidence: p.bounded_check.evidence,
          },
        }
      : {}),
  }));

/** Validate a raw `emit_mechanized_artifact` payload; reject a malformed shape. */
export function parseMechanizedArtifact(
  raw: unknown,
): { ok: true; artifact: MechanizedArtifact } | { ok: false; error: string } {
  const parsed = mechanizedArtifactSchema.safeParse(raw);
  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "invalid mechanized artifact" };
  }
  return { ok: true, artifact: parsed.data };
}

/**
 * The single LLM call the synthesiser makes, injected so prod wires the engine
 * runtime and tests stub it (no keys, no network). Given the system + user
 * prompt and the emit tool, it returns the model's tool-call input bag (the raw
 * artifact) or null when the model refused to emit one.
 */
export type ArtifactSynthModel = (
  system: string,
  user: string,
) => Promise<unknown | null>;

const SYNTH_SYSTEM =
  "You are the MECHANIZED-ARTIFACT synthesiser for a novel-vulnerability engine. A prior stage " +
  "produced a candidate finding. Your ONE job: reduce it to grep-verifiable structural claims — the " +
  "exact sink, the two call sites (free here / use there), the freed field, the missing lock — each " +
  "named as a token that MUST literally appear (or, for a missing lock, MUST be absent) in the real " +
  "source file. Every needle you emit is grep-checked against the bytes on disk; a needle that is not " +
  "there REFUTES the finding, so do not guess or paraphrase — quote the real token. If the bug is a " +
  "NON-crashing logic/lifetime/auth bug, also emit a bounded structural check: the small set of " +
  "positive+negative claims that together establish the invariant violation. Call " +
  "emit_mechanized_artifact exactly once.";

/**
 * Synthesise a mechanized artifact from a finding via one constrained LLM call.
 * Returns null when the model produced no usable artifact (the gate then treats
 * the finding as carrying no mechanized proof → inconclusive, held not dropped).
 */
export async function synthesizeMechanizedArtifact(
  finding: Finding,
  candidate: HuntCandidate,
  model: ArtifactSynthModel,
): Promise<MechanizedArtifact | null> {
  const user = [
    `## Candidate finding`,
    `title: ${finding.title}`,
    `path: ${candidate.path}`,
    `category: ${finding.category}`,
    `severity: ${finding.severity}`,
    ``,
    `## Description`,
    finding.description ?? "",
    ``,
    `## Analysis`,
    finding.evidence?.analysis ?? "",
  ].join("\n");

  let raw: unknown | null;
  try {
    raw = await model(SYNTH_SYSTEM, user);
  } catch {
    return null;
  }
  if (raw == null) return null;

  const parsed = parseMechanizedArtifact(raw);
  return parsed.ok ? parsed.artifact : null;
}

// ────────────────────────────────────────────────────────────────────
// composeGate wiring — the HuntVerifier adapter
// ────────────────────────────────────────────────────────────────────

export interface MechanizedGateDeps {
  /** Synthesise the artifact from the finding (injected LLM). */
  synthesize: (finding: Finding, candidate: HuntCandidate) => Promise<MechanizedArtifact | null>;
  /** Read the real source of a claimed file / decompiled unit. */
  loadSource: SourceLoader;
  /**
   * OPTIONAL reproduce lane. When the synthesised artifact carries no crash but
   * the finding is a crash-class bug, the gate can ask this seam to produce one
   * (prod wires harness-synth → the N× kernel-VM / sanitizer runner). Returns a
   * reproduced {@link CrashArtifact} or null. Injected; omit and the gate simply
   * relies on whatever the artifact already carries.
   */
  reproduce?: (
    finding: Finding,
    candidate: HuntCandidate,
    artifact: MechanizedArtifact,
  ) => Promise<CrashArtifact | null>;
  /** Sink for the full verdict (prod persists it onto the finding record). */
  onVerdict?: (finding: Finding, candidate: HuntCandidate, verdict: MechanizedVerdict) => void;
  /** Minimum structural claims required (see {@link MechanizedVerdictOptions.minClaims}). */
  minClaims?: number;
  log?: (msg: string) => void;
}

/**
 * Engine C as a {@link HuntVerifier}, ready to slot into `runHuntScan`'s
 * composeGate. It is the FORMALIZED prover stage: the demand that every
 * candidate carry a mechanized artifact. Placement in the gate:
 *
 *   verify = composeGate(
 *     makeSkepticVerifier(...),         // cheap adversarial refute (kills easy FPs)
 *     makeMechanizedArtifactGate({      // Engine C — grep-verifiable proof + repro/bounded
 *       synthesize, loadSource,
 *       reproduce: harnessSynthReproduce,  // → withNxReproduction(runner, N)
 *     }),
 *     makeExploitabilityGate(...),      // PROVE stage (existing, gates weaponization)
 *   );
 *
 * Because `composeGate` short-circuits on the first stage that rejects, the
 * cheap skeptic runs first and Engine C only pays the synth+grep cost on
 * findings that survived it. Engine C confirms ⇔ mechanizedArtifactVerdict is
 * `confirmed`; a `rejected` (mechanized refutation) or `inconclusive` (held,
 * unproven) both return `confirmed:false` with a reason that distinguishes them.
 */
export function makeMechanizedArtifactGate(deps: MechanizedGateDeps): HuntVerifier {
  const log = deps.log ?? (() => {});
  return async (finding, candidate) => {
    let artifact = await deps.synthesize(finding, candidate);
    if (!artifact) {
      return {
        confirmed: false,
        reason: "engine-c: no mechanized artifact synthesised (held, not disproven)",
      };
    }

    // If the artifact has a verified structural proof but no crash, and a
    // reproduce lane is wired, try to produce one before adjudicating.
    if (deps.reproduce && !artifact.reproducedCrash && !artifact.boundedCheck) {
      try {
        const crash = await deps.reproduce(finding, candidate, artifact);
        if (crash) artifact = { ...artifact, reproducedCrash: crash };
      } catch (e) {
        log(`[engine-c] reproduce lane failed for ${finding.title}: ${String(e).slice(0, 120)}`);
      }
    }

    const verdict = await mechanizedArtifactVerdict(artifact, deps.loadSource, {
      ...(deps.minClaims !== undefined ? { minClaims: deps.minClaims } : {}),
      log,
    });
    deps.onVerdict?.(finding, candidate, verdict);

    return {
      confirmed: verdict.verdict === "confirmed",
      reason: `engine-c[${verdict.verdict}/${verdict.mechanizedBasis}]: ${verdict.reasoning}`,
    };
  };
}
