/**
 * `pwnkit assumption-hunt <source-root>` — the SEEDLESS ASSUMPTION-MINING hunt.
 *
 * The fourth seedless discovery axis (alongside the invariant-model, interproc-
 * refcount, and concurrency-race stages). Unlike those — which ask "is THIS access
 * correctly guarded?" against a FIXED invariant shape — this MINES the implicit
 * relied-on preconditions each function makes (a validated ref, a held lock, a
 * re-checked value, a once-only init, an exclusive owner, a caller-side capability
 * check) and hunts reachable callers that reach a relied-on subject WITHOUT
 * establishing its precondition. That is the dual-view / DirtyCred / AF_UNIX-GC /
 * io_uring shape our fixed-schema checkers structurally cannot represent.
 *
 *   mine (LLM, once) ─▶ AssumptionModel ─▶ 1b enforced/relied cross-check (no LLM)
 *        ─▶ establisher-propagation caller-scan (no LLM) ─▶ runHuntScan(skeptic gate)
 *
 * A surviving context is a CANDIDATE to DISPROVE, not a bug: the deterministic scan
 * (coarse establisher-anywhere, name-based call graph) plus the skeptic gate filter,
 * they do not PROVE. Hand survivors to manual / kernel-VM prove.
 *
 * Exit codes: 0 = the pipeline ran (with or without a surviving candidate — a clean
 * 0-candidate run is a valid outcome, not a failure); 3 = error (bad flags / no
 * readable source / mine failure).
 */

import type { Command } from "commander";
import { resolve } from "node:path";
import type { RuntimeMode } from "@pwnkit/shared";

interface AssumptionHuntOpts {
  subsystem?: string;
  files?: string;
  modelPath?: string;
  remine?: boolean;
  skipHunt?: boolean;
  noVerify?: boolean;
  models?: string;
  maxContexts?: string;
  runtime?: string;
  format?: string;
  output?: string;
  // commander maps `--no-x` to opts.x = false (NOT opts.noX). Read the negated key.
  wrapperResolution?: boolean;
  finderTargeting?: boolean;
  dualView?: boolean;
  excerptDir?: string;
  dynamicWitness?: boolean;
  witnessRounds?: string;
  witnessCandidates?: string;
  witnessModel?: string;
  witnessMode?: string;
  witnessRaceThreads?: string;
  witnessRaceIters?: string;
}

type WitnessModeName = "single" | "race" | "auto";

/** Parse `--witness-mode single|race|auto` → validated mode (default undefined = engine's `auto`). */
function parseWitnessMode(raw: string | undefined): WitnessModeName | undefined {
  if (raw === undefined) return undefined;
  const m = raw.trim();
  if (m !== "single" && m !== "race" && m !== "auto") {
    throw new Error(`invalid --witness-mode '${raw}' (allowed: single, race, auto)`);
  }
  return m;
}

/** Run the seedless assumption-mining hunt and return a JSON-ready outcome. Exposed for testing. */
export async function runAssumptionHuntCli(sourceRoot: string, opts: AssumptionHuntOpts): Promise<{ exitCode: number; result: unknown }> {
  const { runAssumptionHunt, makeSkepticVerifier } = await import("@pwnkit/core");
  const log = (m: string) => process.stderr.write(m + "\n");
  const runtime: RuntimeMode = (opts.runtime as RuntimeMode) ?? "api";

  const root = resolve(sourceRoot);
  const subsystem = opts.subsystem?.trim() || "subsystem";
  const files = (opts.files ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (files.length === 0) {
    throw new Error("--files is required: a comma-separated list of subsystem source files (repo-relative to <source-root>)");
  }
  const modelPath = opts.modelPath
    ? resolve(opts.modelPath)
    : resolve(root, `.pwnkit/assumption-models/${subsystem.replaceAll("/", "_")}.json`);
  const models = opts.models ? opts.models.split(",").map((s) => s.trim()).filter(Boolean) : undefined;

  // Skip the (LLM) skeptic gate when --no-verify or --skip-hunt: candidate-gen only.
  const verify =
    opts.skipHunt || opts.noVerify
      ? undefined
      : // `finderModels` decorrelates the refute pass from the finder fan-out
        // when a second provider is configured (#661); with one provider it
        // passes straight through to `models[0]`, as before.
        makeSkepticVerifier({
          sourceRoot: root,
          runtime,
          ...(models?.[0] ? { model: models[0] } : {}),
          ...(models && models.length > 0 ? { finderModels: models } : {}),
          log,
        });

  const res = await runAssumptionHunt({
    sourceRoot: root,
    subsystem,
    subsystemFiles: files,
    runtime,
    modelPath,
    ...(opts.remine ? { remine: true } : {}),
    ...(opts.skipHunt ? { skipHunt: true } : {}),
    ...(verify ? { verify } : {}),
    ...(models ? { finderModels: models } : {}),
    ...(opts.finderTargeting === false ? { finderTargeting: false } : {}),
    ...(opts.dualView === false ? { dualView: false } : {}),
    ...(opts.excerptDir ? { excerptDir: resolve(opts.excerptDir) } : {}),
    ...(opts.dynamicWitness
      ? {
          dynamicWitness: {
            runtime,
            ...(opts.witnessModel ? { model: opts.witnessModel } : {}),
            ...(opts.witnessRounds ? { maxRounds: parseInt(opts.witnessRounds, 10) } : {}),
            ...(opts.witnessCandidates ? { maxCandidates: parseInt(opts.witnessCandidates, 10) } : {}),
            // Race-capable witness knobs: mode defaults to the engine's `auto`; the race
            // thread/iteration knobs only override the defaults when supplied.
            ...(parseWitnessMode(opts.witnessMode) ? { witnessMode: parseWitnessMode(opts.witnessMode) } : {}),
            ...(opts.witnessRaceThreads || opts.witnessRaceIters
              ? {
                  raceConfig: {
                    ...(opts.witnessRaceThreads ? { threads: parseInt(opts.witnessRaceThreads, 10) } : {}),
                    ...(opts.witnessRaceIters ? { iters: parseInt(opts.witnessRaceIters, 10) } : {}),
                  },
                }
              : {}),
            log,
          },
        }
      : {}),
    scanOptions: {
      ...(opts.maxContexts ? { maxContexts: parseInt(opts.maxContexts, 10) } : {}),
      ...(opts.wrapperResolution === false ? { resolveWrappers: false } : {}),
    },
    log,
  });

  // The honest funnel: mined → survived 1b → violating contexts → confirmed.
  const result = {
    mode: "assumption_hunt",
    subsystem,
    source: root,
    model_path: res.modelPath,
    model_loaded: res.modelLoaded,
    funnel: {
      mined: res.model.assumptions.length,
      kept_1b: res.crossCheck.kept.length,
      dropped_1b: res.crossCheck.dropped.length,
      reclassified_1b: res.crossCheck.reclassified.length,
      violating_contexts: res.contexts.length,
      dual_view_contexts: res.dualViewContexts.length,
      candidate_files: res.plan.candidates.length,
      confirmed: res.hunt ? res.hunt.confirmed.length : null,
      ...(res.witness
        ? {
            witness_ran: res.witness.results.length,
            witness_confirmed: res.witness.confirmed.length,
            witness_refuted: res.witness.refuted.length,
            witness_inconclusive: res.witness.inconclusive.length,
          }
        : {}),
    },
    kept: res.crossCheck.kept.map((a) => ({ id: a.id, kind: a.kind, subject: a.subject, provenance: a.provenance, establisher: a.oracle.establisherToken, relevance: a.securityRelevance, predicate: a.predicate })),
    dropped: res.crossCheck.dropped.slice(0, 40).map((d) => ({ id: d.assumption.id, reason: d.reason })),
    contexts: [...res.contexts, ...res.dualViewContexts].map((c) => ({
      assumption: c.assumptionId,
      subject: c.subject,
      caller: c.caller,
      site: `${c.callerFile}:${c.callLine}`,
      establisher: c.establisherToken,
      unpriv_entry: c.unprivEntry,
      ...(c.dualView ? { dual_view: true, paired_entry: c.pairedEntry, object: c.object } : {}),
    })),
    confirmed: res.hunt
      ? res.hunt.confirmed.map((f) => ({ title: f.title, severity: f.severity, analysis: f.evidence.analysis ?? "" }))
      : null,
    warnings: res.hunt?.warnings?.slice(0, 10) ?? [],
    witness: res.witness
      ? res.witness.results.map((w) => ({
          assumption: w.candidate.assumptionId,
          object: w.candidate.object,
          entry_a: w.candidate.entryA,
          entry_b: w.candidate.entryB,
          verdict: w.verdict,
          rounds: w.attempts.length,
          signature: w.witnessedAttempt?.check?.signature ?? null,
          summary: w.summary,
          ...(w.verdict === "confirmed" ? { splat: w.splat } : {}),
        }))
      : null,
    note: "CANDIDATES to disprove, not bugs. A surviving context is an assumption to refute — confirm the establisher is genuinely absent on THIS reachable path before trusting it. Dynamic-witness verdicts: 'confirmed' = an object-bound KASAN splat fired in a KASAN VM (a real dynamic witness); 'refuted' = a PoC ran but never faulted; 'inconclusive' = no PoC compiled+ran (AEG/synthesis limit, NOT a proof the assumption holds).",
  };
  return { exitCode: 0, result };
}

export function registerAssumptionHuntCommand(program: Command): void {
  program
    .command("assumption-hunt")
    .description(
      "Seedless ASSUMPTION-MINING hunt: mine the implicit relied-on preconditions each function makes, " +
        "cross-check enforced-vs-relied (no LLM), then scan for reachable callers that reach a relied-on " +
        "subject WITHOUT establishing its precondition. Emits CANDIDATES to disprove (not confirmed bugs). " +
        "Exit 0 = ran (with or without a candidate), 3 = error.",
    )
    .argument("<source-root>", "Local source tree the subsystem files live under (e.g. a kernel checkout)")
    .requiredOption("--files <a.c,b.c>", "Comma-separated subsystem source files, repo-relative to <source-root>")
    .option("--subsystem <label>", "Subsystem label for the stored model (e.g. net/unix)")
    .option("--model-path <path>", "Where the durable assumption model JSON lives (default under <source-root>/.pwnkit)")
    .option("--remine", "Force a fresh LLM mine even if the stored model exists")
    .option("--skip-hunt", "Stop after the deterministic caller-scan (no LLM finder/skeptic gate)")
    .option("--no-verify", "Run the finder fan-out but skip the skeptic gate")
    .option("--models <a,b>", "Comma-separated finder/mine models for diversity")
    .option("--max-contexts <N>", "Cap the violating contexts fed to the hunt")
    .option("--no-wrapper-resolution", "Disable v1 establisher-wrapper resolution (reproduces the v0 direct-token scan — FP ablation)")
    .option("--no-finder-targeting", "Feed the finder the whole subsystem file instead of focused per-function excerpts")
    .option("--no-dual-view", "Disable the v2 dual-api/cross-phase enumerator (caller-scan only — the v1 behavior)")
    .option("--dynamic-witness", "v3: route dual-view candidates to the KASAN synthesize→boot→witness oracle (bypasses the static skeptic). Needs a KASAN VM env (PWNKIT_KERNEL_QEMU_*).")
    .option("--witness-rounds <N>", "Bounded PoC-repair rounds per dual-view candidate (default 3)")
    .option("--witness-candidates <N>", "Cap dual-view candidates run through the dynamic oracle (default 10)")
    .option("--witness-model <name>", "Model for PoC synthesis (default: runtime default)")
    .option("--witness-mode <mode>", "PoC shape: single (sequential), race (concurrent multi-thread), auto (race for race-shaped seams; default)")
    .option("--witness-race-threads <N>", "Race-mode worker threads driving entryA vs entryB (default 4)")
    .option("--witness-race-iters <N>", "Race-mode per-thread hammer iterations to widen the race window (default 200000)")
    .option("--excerpt-dir <path>", "Where finder-targeting excerpts are written (default: os tmpdir)")
    .option("--runtime <mode>", "Engine runtime (default api)")
    .option("--format <fmt>", "Output format (json)", "json")
    .option("--output <path>", "Write the result JSON to this path instead of stdout")
    .action(async (sourceRoot: string, opts: AssumptionHuntOpts) => {
      try {
        const outcome = await runAssumptionHuntCli(sourceRoot, opts);
        const json = JSON.stringify(outcome.result, null, 2);
        if (opts.output) {
          const { writeFileSync } = await import("node:fs");
          writeFileSync(resolve(opts.output), json + "\n", "utf8");
        } else process.stdout.write(json + "\n");
        process.exitCode = outcome.exitCode;
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        process.stdout.write(JSON.stringify({ mode: "assumption_hunt", error: reason }, null, 2) + "\n");
        process.exitCode = 3;
      }
    });
}
