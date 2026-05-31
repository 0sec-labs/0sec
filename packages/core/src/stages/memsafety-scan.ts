/**
 * Userspace / Rust memory-safety scan stage ("Monty-mode" integration spine).
 *
 * This is the focused module the integration spine in
 * `docs/pwnkit-rust-memsafety-pipeline.md` calls for: it chains the three
 * tracks that already exist in `@pwnkit/core` into a single, side-effect-light
 * flow, *without* growing the `agentic-scanner.ts` god-module.
 *
 *   Track A (audit/playbook)  →  Track B (closed fuzz loop)  →  Track C (triage)
 *   ──────────────────────────   ─────────────────────────────  ────────────────
 *   inject the `rust_memsafety`   runUserspaceFuzzLoop()          classifyUserspacePrimitive()
 *   playbook methodology          (compile → run → crash →        + memCorruptionVerdict()
 *   (agent/playbooks.ts)          dedup → minimise)               → Finding[]
 *
 * Discipline encoded here (these are load-bearing, not decoration):
 *   - **No fabricated findings.** When `FuzzLoopResult.toolingMissing` is
 *     non-empty (cargo-fuzz / miri / clang absent — the default state on the
 *     dev box today), the loop ran no real iterations. We surface that honestly
 *     as a `toolingMissing` list + warning and return ZERO findings, exactly
 *     like `kernel-vm-runner` degrades when QEMU is absent. Never invent a
 *     crash, never emit a "clean" confirmation we did not earn.
 *   - **Assume-FP.** A captured crash is only a `confirmed` PoC when it
 *     reproduced under the sanitizer/Miri build with a saved input
 *     (`memCorruptionVerdict` enforces this). A bare panic / timeout / OOM is
 *     `inconclusive`, never a rejection. The verdict is attached to the
 *     finding; this module does NOT submit, drop, or disclose anything.
 *   - **Reuse, don't reinvent.** Crashes become the existing `Finding` shape
 *     (mirroring `ingest/kernel-crash.ts:crashToFinding`), so every downstream
 *     renderer / sink / DB path works unchanged. No parallel finding type.
 */

import { randomUUID } from "node:crypto";
import type {
  AttackCategory,
  Finding,
  Severity,
} from "@pwnkit/shared";
import { buildPlaybookInjection } from "../agent/playbooks.js";
import {
  runUserspaceFuzzLoop,
  type UserspaceFuzzOptions,
} from "../triage/userspace-fuzz-runner.js";
import {
  classifyUserspacePrimitive,
  describeExploitabilityVerdict,
} from "../triage/userspace-primitive.js";
import { memCorruptionVerdict } from "../triage/pov-gate.js";
import type {
  CrashArtifact,
  ExploitabilityVerdict,
  FuzzLoopResult,
  MemPrimitive,
  MemSafetyTarget,
} from "../triage/memsafety-types.js";
import type { VerifyVerdict } from "../triage/verify-verdict.js";

// ── Options + result contract ───────────────────────────────────────────────

export interface MemSafetyScanOptions {
  /** The local cloned build under test (source root + optional harness). */
  target: MemSafetyTarget;
  /**
   * Forwarded verbatim to `runUserspaceFuzzLoop`. The `target` is taken from
   * `MemSafetyScanOptions.target`; any `target` set here is ignored.
   */
  fuzz?: Omit<UserspaceFuzzOptions, "target">;
  /** Custom logger; defaults to `console.log`. Matches the fuzz runner. */
  logger?: (line: string) => void;
}

/** A crash promoted to a finding, paired with its verify verdict. */
export interface MemSafetyFinding {
  finding: Finding;
  crash: CrashArtifact;
  exploitability: ExploitabilityVerdict;
  /**
   * The memory-corruption PoV verdict (`memCorruptionVerdict`). `confirmed`
   * only when the crash reproduced under the sanitizer/Miri build with a saved
   * input; otherwise `inconclusive` (NEVER a rejection). Mirrored onto
   * `finding.verification_result`-adjacent fields via the finding's evidence.
   */
  verdict: VerifyVerdict;
}

export interface MemSafetyScanResult {
  /** Findings derived from reproduced/observed crashes. Empty is honest. */
  findings: Finding[];
  /** Per-crash detail (finding + classification + verdict). */
  details: MemSafetyFinding[];
  /** The raw fuzz-loop result, surfaced for callers that want loop telemetry. */
  loop: FuzzLoopResult;
  /**
   * Tooling that was required but absent (cargo-fuzz / miri / clang / cargo).
   * Non-empty means the loop could not actually run — `findings` is empty by
   * construction and the caller must report "could not run", not "clean".
   */
  toolingMissing: string[];
  /** The playbook methodology injected for this run (Track A context). */
  playbookContext: string;
  /** Human-readable, non-fatal notes (e.g. the tooling-absent explanation). */
  warnings: string[];
}

// ── Track C → finding shape (mirror of ingest/kernel-crash.ts:crashToFinding) ─

/** Map a userspace memory-safety primitive onto the shared AttackCategory. */
export function memPrimitiveToCategory(primitive: MemPrimitive): AttackCategory {
  switch (primitive) {
    case "use-after-free":
      return "use-after-free";
    case "double-free":
      return "double-free";
    case "heap-oob-read":
      return "out-of-bounds-read";
    case "heap-oob-write":
      return "out-of-bounds-write";
    case "stack-oob":
      return "stack-buffer-overflow";
    case "type-confusion":
      return "type-confusion";
    case "uninit-read":
      return "uninitialized-memory";
    case "null-deref":
      return "null-deref";
    case "integer-overflow":
      return "integer-overflow";
    case "unknown":
      return "other";
  }
}

/**
 * Build a `Finding` from a captured crash + its classification + verdict. The
 * userspace analogue of `crashToFinding` in `ingest/kernel-crash.ts`: same
 * field semantics (`status: "discovered"`, severity from the exploitability
 * classifier, the raw report parked in `evidence.response`, the primitive
 * breakdown in `evidence.analysis`) so every existing renderer / sink / DB
 * round-trip keeps working.
 */
export function crashArtifactToFinding(
  crash: CrashArtifact,
  target: MemSafetyTarget,
  exploitability: ExploitabilityVerdict,
  verdict: VerifyVerdict,
): Finding {
  const severity: Severity = exploitability.severity;
  const category = memPrimitiveToCategory(exploitability.primitive);
  const stackSummary = (crash.stack ?? []).slice(0, 5).join(" → ");

  const reproduced = verdict.verdict === "confirmed";
  const description = [
    `Userspace ${crash.kind} crash in ${target.language} target (${target.sourceRoot}).`,
    `Primitive: ${exploitability.primitive} (op=${exploitability.readWrite}, controllable=${exploitability.controllable}).`,
    stackSummary ? `Stack: ${stackSummary}.` : "",
    crash.inputPath ? `Reproducing input: ${crash.inputPath}.` : "",
    reproduced
      ? "Reproduced under the sanitizer/Miri build (memory-corruption PoC)."
      : "Observed crash; not yet a reproduced memory-corruption PoC (inconclusive — not a rejection).",
  ]
    .filter(Boolean)
    .join("\n");

  const analysisLines = [
    `Crash kind: ${crash.kind}`,
    `Signature: ${crash.signature}`,
    `Category: ${category}`,
    `Build system: ${target.buildSystem}`,
    target.harnessEntry ? `Harness: ${target.harnessEntry}` : "",
    "",
    "---exploitability---",
    ...describeExploitabilityVerdict(exploitability),
    "",
    "---verify verdict---",
    `Verdict: ${verdict.verdict} (confidence=${verdict.confidence})`,
    verdict.evidenceKind ? `Evidence: ${verdict.evidenceKind}` : "",
    verdict.reasoning,
  ].filter(Boolean);

  // Confidence tracks the verify verdict: a reproduced PoC is high-confidence;
  // an unproven crash is a lead, not a conclusion.
  const confidence = reproduced ? verdict.confidence : 0.3;

  const rawOut = crash.rawOutput ?? "";
  return {
    id: randomUUID(),
    templateId: `memsafety-${crash.kind}`,
    title: `Userspace ${exploitability.primitive} (${crash.kind}) in ${target.sourceRoot}`,
    description,
    severity,
    category,
    status: "discovered",
    evidence: {
      request: crash.inputPath ?? "N/A (userspace crash artifact)",
      response:
        rawOut.length > 4000 ? rawOut.slice(0, 4000) + "\n... [truncated]" : rawOut,
      analysis: analysisLines.join("\n"),
    },
    fingerprint: `memsafety:${crash.signature}`,
    confidence,
    timestamp: Date.now(),
  };
}

// ── The stage entrypoint (A → B → C) ─────────────────────────────────────────

/**
 * Run a userspace / Rust memory-safety scan against a locally cloned target.
 *
 * Sequences the three existing tracks:
 *   A. Inject the `rust_memsafety` playbook methodology (returned in
 *      `playbookContext` so the agentic layer / operator can fold it into the
 *      driving prompt — the variant-hunt + unsafe-enumeration steps).
 *   B. Drive the closed fuzz loop (`runUserspaceFuzzLoop`): compile → run →
 *      capture → dedup → minimise. Degrades honestly when tooling is absent.
 *   C. For each captured crash, classify the exploitation primitive and
 *      adjudicate the memory-corruption verdict, then promote to a `Finding`.
 *
 * Returns a structured result; never throws on a tooling-absent loop. The
 * caller decides what to do with the findings — this stage does no I/O beyond
 * what the fuzz loop already performs under its artifact dir, and submits /
 * discloses nothing (operator + disclosure gate own that).
 */
export async function runMemSafetyScan(
  opts: MemSafetyScanOptions,
): Promise<MemSafetyScanResult> {
  const log = opts.logger ?? ((line: string) => console.log(line));
  const warnings: string[] = [];

  // ── Track A: playbook methodology context ──────────────────────────
  const playbookContext = buildPlaybookInjection(["rust_memsafety"]);

  // ── Track B: closed fuzz loop ──────────────────────────────────────
  log(
    `[memsafety] fuzzing ${opts.target.language} target at ${opts.target.sourceRoot}` +
      (opts.target.harnessEntry ? ` (harness=${opts.target.harnessEntry})` : ""),
  );
  const loop = await runUserspaceFuzzLoop({
    ...opts.fuzz,
    target: opts.target,
    logger: log,
  });

  const toolingMissing = loop.toolingMissing ?? [];

  // Tooling-absent contract: an empty-but-honest loop yields NO findings. Surface
  // the missing tools so the caller reports "could not run", not "clean".
  if (toolingMissing.length > 0) {
    const note =
      `[memsafety] fuzz loop could not run — missing tooling: ${toolingMissing.join(", ")}. ` +
      "No findings emitted (no fabricated results).";
    log(note);
    warnings.push(note);
  }

  // ── Track C: classify + adjudicate each crash → Finding ────────────
  const details: MemSafetyFinding[] = [];
  for (const crash of loop.crashes) {
    const exploitability = classifyUserspacePrimitive(crash);
    const verdict = memCorruptionVerdict(crash);
    const finding = crashArtifactToFinding(crash, opts.target, exploitability, verdict);
    details.push({ finding, crash, exploitability, verdict });
  }

  if (details.length === 0 && toolingMissing.length === 0) {
    log(
      `[memsafety] fuzz loop ran ${loop.iterations} iteration(s) with no crashes captured.`,
    );
  }

  return {
    findings: details.map((d) => d.finding),
    details,
    loop,
    toolingMissing,
    playbookContext,
    warnings,
  };
}
