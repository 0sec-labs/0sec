/**
 * Self-improving lens loop — orchestration.
 *
 * Composes the four stages into one manually-runnable pass:
 *
 *   miss-capture ─▶ synthesize ─▶ validate (fail-closed) ─▶ register
 *
 * Guardrails (this mutates the engine's own detector registry):
 *   - Fail-closed everywhere: a synthesis, validation, or registration ERROR
 *     rejects the candidate; it never registers anything.
 *   - A candidate that isn't a clear tournament champion is DISCARDED.
 *   - A hard cap (`maxRegistrations`, default 1) bounds how many lenses ONE run
 *     may write.
 *   - The "primes, never confirms" flywheel invariant is untouched — this loop
 *     adds LENSES; nothing here confirms a FINDING.
 *
 * Autonomous nightly triggering is a FOLLOW-UP (no cron is wired here); this is
 * the solid, manually-invokable mechanism the CLI `lens-synth` command runs.
 */

import { captureLensCandidates } from "./miss-capture.js";
import { registerArchetype } from "./register.js";
import { clusterCandidates, makeDefaultLensSynthesisModel, synthesizeArchetypes } from "./synthesize.js";
import { validateCandidateLens } from "./validate.js";
import type {
  LensSynthesisDeps,
  LensSynthesisInput,
  LensSynthesisResult,
  LensValidationReport,
  RegisteredLens,
  SynthesizedArchetype,
} from "./types.js";

export async function runLensSynthesisLoop(
  input: LensSynthesisInput,
  deps: LensSynthesisDeps,
): Promise<LensSynthesisResult> {
  const log = deps.log ?? (() => {});
  const now = deps.now ?? (() => new Date().toISOString());
  const maxRegistrations = Math.max(0, deps.maxRegistrations ?? 1);
  const model = deps.model ?? makeDefaultLensSynthesisModel(deps.modelId);
  const warnings: string[] = [];

  // ── Stage 1: capture ──
  const candidates = captureLensCandidates(input.misses);
  const clusters = clusterCandidates(candidates).length;
  log(`[lens-synth] captured ${candidates.length} miss candidate(s) in ${clusters} cluster(s)`);

  // ── Stage 2: synthesize (isolated — a synth fault yields zero archetypes) ──
  let synthesized: SynthesizedArchetype[];
  try {
    synthesized = await synthesizeArchetypes(candidates, { model, log });
  } catch (err) {
    warnings.push(`synthesis failed (fail-closed, nothing synthesized): ${err instanceof Error ? err.message : String(err)}`);
    synthesized = [];
  }
  log(`[lens-synth] synthesized ${synthesized.length} candidate archetype(s)`);

  // ── Stage 3 + 4: validate then register (per candidate) ──
  const validations: LensValidationReport[] = [];
  const registered: RegisteredLens[] = [];
  const rejected: Array<{ id: string; reason: string }> = [];

  for (const archetype of synthesized) {
    const id = archetype.content.id;

    // ── Stage 3: validate EVERY candidate (so a dry run still reports champions) ──
    let report: LensValidationReport;
    try {
      report = await validateCandidateLens(archetype, input.corpus, { probe: deps.probe, log });
    } catch (err) {
      rejected.push({ id, reason: `validation error (fail-closed): ${err instanceof Error ? err.message : String(err)}` });
      continue;
    }
    validations.push(report);
    if (!report.passed) {
      rejected.push({ id, reason: report.reason });
      continue;
    }

    // A champion, but writing is gated by dry-run + the registration cap.
    if (deps.dryRun) {
      log(`[lens-synth] dry-run: would register ${id} (not written)`);
      continue;
    }
    if (registered.length >= maxRegistrations) {
      rejected.push({ id, reason: `registration cap reached (max ${maxRegistrations} per run)` });
      continue;
    }

    // ── Stage 4: register the validated champion (fail-closed) ──
    try {
      const outcome = registerArchetype(archetype, {
        ...(deps.registryPath ? { registryPath: deps.registryPath } : {}),
        validatedAt: now(),
      });
      if (outcome.written && outcome.registered) {
        registered.push(outcome.registered);
        log(`[lens-synth] REGISTERED ${outcome.registered.uid} (validated ${outcome.registered.validatedAt})`);
      } else {
        rejected.push({ id, reason: outcome.reason ?? "not written" });
      }
    } catch (err) {
      rejected.push({ id, reason: `register error (fail-closed): ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  return {
    candidatesCaptured: candidates.length,
    clusters,
    synthesized,
    validations,
    registered,
    rejected,
    warnings,
  };
}
