// 0sec#666 / EPIC #674 Part A — agentic PoC-gen for static / no-PoC findings.
//
// THE GAP (root-caused 2026-05-30): high/critical findings emitted by the
// static / code-analysis path ship with `pocSteps === undefined`. The cloud
// verify fan-out only promotes a finding to `pending` (→ verify) when it has a
// non-empty `poc_steps` array, so these were silently `skipped` — never
// verified, never disclosed. 112 high/crit findings were buried this way, and
// a manual re-verify swarm proved many were real true-positives.
//
// THE FIX (this module): when a static finding has no executable PoC, run an
// agentic PoC-generation pass that *builds and runs* a minimal PoC in the scan
// substrate (reusing the existing `generatePov` mini-loop — same bash /
// http_request / oracle execution path the PoV gate already uses; no new
// infra). Two outcomes, never a silent skip:
//
//   reproduced → synthesize a runnable `pocSteps` graph from the working
//                artifact + captured proof and attach it to the finding, so
//                the verify runner picks it up instead of skipping it.
//   not repro  → flag the finding `poc:none` (triageNote + a `poc_gen` layer
//                verdict) so 0cloud routes it to manual / inconclusive review.
//                We never downgrade severity or drop the finding here — the
//                whole point of #666 is that no-PoC ≠ false-positive.
//
// Behind the default-OFF `0SEC_FEATURE_POC_GEN_STATIC` flag so it is
// A/B-able via the #656 harness and safe to merge dark. Wired into
// agentic-scanner.ts after the PoV gate.

import type {
  Finding,
  LayerVerdict,
  PocStep,
  PocStepAction,
} from "@0sec/shared";
import type { NativeRuntime } from "../runtime/types.js";
import {
  generatePov,
  type GeneratePovOptions,
  type PovArtifactType,
  type PovResult,
} from "../triage/pov-gate.js";

/** triageNote / layer-verdict marker for a finding we could not reproduce. */
export const POC_NONE_MARKER = "poc:none";

export interface StaticPocGenResult {
  /** Always true once `generateStaticPoc` ran (the agent was given a shot). */
  attempted: boolean;
  /** The agent built + ran a PoC whose output proved the vuln. */
  reproduced: boolean;
  /** Synthesized runnable step graph — present only when `reproduced`. */
  pocSteps?: PocStep[];
  /** Raw PoV mini-loop result (artifact, evidence, oracle, confidence). */
  pov: PovResult;
  /**
   * Short marker string: `poc_reproduced(<artifactType>)` on success, or
   * `poc:none: <reason>` when the agent could not reproduce.
   */
  marker: string;
}

export interface StaticPocGenOptions extends GeneratePovOptions {
  /** Turn budget for the PoC-gen mini-loop. Defaults to 5 (matches PoV gate). */
  maxTurns?: number;
}

// ────────────────────────────────────────────────────────────────────
// Step synthesis
//
// The PoV mini-loop returns a working *artifact* (curl command, python /
// js / bash source) plus the *execution evidence* that proved exploitation,
// but it stores them as prose on `evidence.analysis`. That prose is exactly
// why these findings still got skipped: the verify runner keys off the
// structured `pocSteps` graph, not prose. So we convert the proven artifact
// into a runnable two-step graph (exploit → verify) the runner can replay.
// ────────────────────────────────────────────────────────────────────

const MAX_NOTE_CHARS = 8000;
const HEREDOC = "0SEC_POC_EOF";

function clip(s: string, max = MAX_NOTE_CHARS): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max)}\n…[truncated ${s.length - max} chars]`;
}

/** Turn a proven PoV artifact into a single runnable step action. */
function actionForArtifact(
  artifactType: PovArtifactType,
  artifact: string,
): PocStepAction {
  switch (artifactType) {
    case "curl":
    case "bash":
      // Already a shell command — run it verbatim.
      return { type: "shell", cmd: artifact };
    case "python":
      // Source body → run via stdin heredoc so the step is self-contained.
      return {
        type: "shell",
        cmd: `python3 - <<'${HEREDOC}'\n${artifact}\n${HEREDOC}`,
      };
    case "javascript":
      return {
        type: "shell",
        cmd: `node - <<'${HEREDOC}'\n${artifact}\n${HEREDOC}`,
      };
    default:
      // Unknown / "none" — keep the artifact as a note so we never drop it,
      // but it isn't directly executable.
      return { type: "note", text: clip(artifact) };
  }
}

/** First non-empty, trimmed line of the evidence — used as a body-contains assertion. */
function proofAssertion(evidence: string): string | undefined {
  for (const raw of evidence.split("\n")) {
    const line = raw.trim();
    // Skip our own `$ cmd` echo prefix and empty lines.
    if (!line || line.startsWith("$ ")) continue;
    return line.slice(0, 120);
  }
  return undefined;
}

/**
 * Synthesize a runnable `pocSteps` graph from a *successful* PoV result.
 * Always returns at least one step so the finding stops being treated as
 * "no executable PoC" by the verify runner.
 */
export function pocStepsFromPov(pov: PovResult): PocStep[] {
  const artifact = (pov.povArtifact ?? "").trim();
  const evidence = (pov.executionEvidence ?? "").trim();
  const steps: PocStep[] = [];

  if (artifact) {
    steps.push({
      id: "exploit-1",
      kind: "exploit",
      summary: `Run reproduced ${pov.artifactType} proof-of-concept`,
      action: actionForArtifact(pov.artifactType, artifact),
    });
  }

  const assertion = proofAssertion(evidence);
  steps.push({
    id: "verify-1",
    kind: "verify",
    summary: "Confirm category-specific proof of exploitation in output",
    action: { type: "note", text: clip(evidence) || "(no captured output)" },
    ...(assertion ? { expect: { type: "body-contains", text: assertion } } : {}),
  });

  return steps;
}

// ────────────────────────────────────────────────────────────────────
// Generation
// ────────────────────────────────────────────────────────────────────

/**
 * Run the agentic PoC-generation pass for a single static / no-PoC finding.
 *
 * Delegates the build-and-run loop to `generatePov` (the existing PoV mini
 * agent — same execution substrate the scanner already uses), then converts
 * a successful, oracle-confirmed result into a structured step graph. A
 * result flagged `inconclusive` (the deterministic oracle could not run to a
 * conclusion) is NOT treated as reproduced — it falls through to `poc:none`
 * so the finding is routed to manual review, never silently passed or
 * dropped.
 */
export async function generateStaticPoc(
  finding: Finding,
  target: string,
  runtime: NativeRuntime,
  opts: StaticPocGenOptions = {},
): Promise<StaticPocGenResult> {
  const { maxTurns = 5, ...povOpts } = opts;
  const pov = await generatePov(finding, target, runtime, maxTurns, povOpts);

  if (pov.hasPov && !pov.inconclusive) {
    const pocSteps = pocStepsFromPov(pov);
    return {
      attempted: true,
      reproduced: true,
      pocSteps,
      pov,
      marker: `poc_reproduced(${pov.artifactType})`,
    };
  }

  const why = pov.inconclusive
    ? `inconclusive(${pov.oracle}): ${pov.reason}`
    : pov.reason;
  return {
    attempted: true,
    reproduced: false,
    pov,
    marker: `${POC_NONE_MARKER}: ${why}`,
  };
}

// ────────────────────────────────────────────────────────────────────
// Apply to finding
//
// Kept here (not in agentic-scanner) so the mutation is unit-testable in
// isolation. Mirrors the LayerVerdict shape used by `pushLayerVerdict` in
// agentic-scanner.ts, but is self-contained (no DB / scanner deps).
// ────────────────────────────────────────────────────────────────────

function appendNote(existing: string | undefined, note: string): string {
  return existing ? `${existing}; ${note}` : note;
}

function pushPocGenVerdict(
  finding: Finding,
  v: {
    verdict: LayerVerdict["verdict"];
    confidence?: number;
    reason: string;
    startedAt: number;
  },
): void {
  if (!finding.layerVerdicts) finding.layerVerdicts = [];
  const entry: LayerVerdict = {
    layer: "poc_gen",
    verdict: v.verdict,
    reason: v.reason,
    durationMs: Math.max(0, Date.now() - v.startedAt),
    costUsd: 0,
  };
  if (v.confidence !== undefined) entry.confidence = v.confidence;
  finding.layerVerdicts.push(entry);
}

/**
 * Apply a `StaticPocGenResult` to a finding in place.
 *
 *  reproduced → attach the synthesized `pocSteps` (so the verify runner stops
 *               skipping it), boost confidence, record the working artifact on
 *               `evidence.analysis`, and push a `poc_gen` PASS verdict.
 *  not repro  → flag `poc:none` on `triageNote` + push a `poc_gen` SKIP
 *               verdict. Severity is left untouched and the finding is NOT
 *               dropped — it must reach manual / inconclusive review.
 */
export function applyStaticPocResult(
  finding: Finding,
  result: StaticPocGenResult,
  startedAt: number,
): void {
  if (result.reproduced && result.pocSteps && result.pocSteps.length > 0) {
    finding.pocSteps = result.pocSteps;
    finding.confidence = Math.max(finding.confidence ?? 0, result.pov.confidence);
    finding.triageNote = appendNote(finding.triageNote, result.marker);
    const existing = finding.evidence.analysis ?? "";
    finding.evidence.analysis =
      `${existing}${existing ? "\n\n" : ""}` +
      `## Generated PoC (${result.pov.artifactType})\n${result.pov.povArtifact ?? ""}\n\n` +
      `## Execution Evidence\n${result.pov.executionEvidence}`;
    pushPocGenVerdict(finding, {
      verdict: "pass",
      confidence: result.pov.confidence,
      reason: result.marker,
      startedAt,
    });
    return;
  }

  // poc:none — flag, do not drop, do not downgrade severity.
  finding.triageNote = appendNote(finding.triageNote, result.marker);
  pushPocGenVerdict(finding, {
    verdict: "skip",
    confidence: result.pov.confidence,
    reason: result.marker,
    startedAt,
  });
}
