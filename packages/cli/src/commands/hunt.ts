/**
 * `pwnkit hunt` — novel-bug variant hunt CLI (the `runHuntScan` engine stage).
 *
 * Turns a proven fix into a tree-wide hunt for the SAME bug class at OTHER
 * sites: seed diff → `generateVariantCandidates` (LLM bug-class + grep'd
 * candidate sites) → `runHuntScan` (parallel finders → adversarial skeptic
 * gate). The discovery sibling of `pwnkit exploit` (weaponize) and
 * `pwnkit scan` (single-target). Engine-driven; this command is the surface.
 *
 * `--invariant` (Engine A) layers the seed-touched subsystem's stored invariant
 * model on top: before candidate generation it builds (or loads) the model and
 * runs the deterministic violation checker, then injects the rules + violation
 * hypotheses into every finder prompt as context. No candidates added, no gate
 * changed; the stored model makes repeat hunts LLM-free at this step.
 *
 * A hunt finding is a LEAD, not a confirmed 0-day: the skeptic gate filters
 * (it re-reads and refutes) but does not PROVE, and novelty (is it already
 * fixed?) is a downstream gate. Treat `confirmed` as "worth verifying", and
 * verify the real sink + upstream-fix status before any disclosure.
 *
 * Exit codes (mirroring `pwnkit exploit`/`verify` so dispatchers branch on code):
 *   0 → ≥1 finding survived the skeptic gate (leads to verify)
 *   1 → ran, no finding survived the gate
 *   2 → skipped (no candidate sites generated from the seed)
 *   3 → error (bad flags, unreadable seed, LLM failure)
 */

import type { Command } from "commander";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Finding, RuntimeMode } from "@pwnkit/shared";
import type { ImpactCeiling } from "@pwnkit/core";
import { stampDeploymentContext } from "@pwnkit/core";

/**
 * #1051 — map a gated hunt LEAD onto the cloud-sink finding shape as a
 * CANDIDATE: status forced to `discovered` (never `confirmed`/sendable — these
 * are hypotheses, not proven bugs) and a provenance note stamped into
 * `evidence.analysis`. The orchestrator sets verify_status server-side, so a
 * `discovered` lead enters the verify queue as a candidate; sendability stays
 * gated behind the cloud's own adversarial verify (verify_status='verified').
 * Returned as a plain object — `postFinding` normalizes it to CloudSinkFinding.
 *
 * When `candidatePath` is provided, the finding gets a deployment-context
 * classification via mechanical path heuristics (issue #1215), with severity
 * capped at low/info for dev-only/test-only/build-only code unless the evidence
 * shows a trust-boundary bypass from production.
 *
 * Exposed for unit testing the lead → finding mapping.
 */
export function leadToCandidateFinding(
  finding: Finding,
  bugClass: string,
  seedRef: string,
  candidatePath?: string,
): Record<string, unknown> {
  const evidence =
    (finding.evidence as { request?: string; response?: string; analysis?: string } | undefined) ??
    {};
  const provenance =
    `Variant-hunt LEAD (bug class: ${bugClass}; seed: ${seedRef}). ` +
    `Surfaced by the recency hunt and gated by the adversarial skeptic — a HYPOTHESIS, ` +
    `not a confirmed bug. Verify the real sink + upstream-fix status (novelty) before any disclosure.`;

  // #1215 — stamp deployment context and apply severity cap BEFORE serialising
  // the finding. The path heuristic is the deterministic floor; the model lens
  // (deployment-context verify lens) may overlap but never overrides it.
  if (candidatePath) stampDeploymentContext(finding, candidatePath);

  return {
    ...finding,
    // LEADS are never confirmed/sendable: force candidate status so the cloud
    // ingests them as verify candidates, never as confirmed findings.
    status: "discovered",
    templateId: "recency-hunt-lead",
    evidence: {
      request: evidence.request ?? "",
      response: evidence.response ?? "",
      analysis: evidence.analysis ? `${evidence.analysis}\n\n${provenance}` : provenance,
    },
  };
}

interface HuntOpts {
  source?: string;
  seed?: string;
  ref?: string;
  concurrency?: string;
  maxCandidates?: string;
  skipCandidates?: string;
  models?: string;
  reachableOnly?: boolean;
  reachablePrefer?: boolean;
  verify?: boolean; // commander sets false when --no-verify is passed
  novelty?: boolean;
  noveltyRoot?: string;
  noveltyLists?: string;
  noveltyRecentEpochs?: string;
  noveltySync?: boolean;
  noveltyModel?: string;
  noveltyRequired?: boolean;
  methodology?: boolean;
  invariant?: boolean;
  graphSlice?: boolean;
  cpg?: string;
  opsHarvest?: string;
  graphSliceHops?: string;
  exploitability?: boolean;
  proveMinCeiling?: string;
  output?: string;
  runtime?: string;
  timeout?: string;
}

function parsePositive(flag: string, raw: string | undefined, dflt: number): number {
  if (raw === undefined) return dflt;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`invalid ${flag} '${raw}' (expected positive integer)`);
  return n;
}

const IMPACT_CEILINGS: readonly ImpactCeiling[] = ["dos-only", "info-leak", "oob-write", "uaf-control"];

/** Validate `--prove-min-ceiling` against the impact ladder (fail fast on a typo). */
export function parseCeiling(raw: string): ImpactCeiling {
  const v = raw.trim() as ImpactCeiling;
  if (!IMPACT_CEILINGS.includes(v)) {
    throw new Error(`invalid --prove-min-ceiling '${raw}' (expected one of: ${IMPACT_CEILINGS.join(", ")})`);
  }
  return v;
}

function parseNonNegative(flag: string, raw: string | undefined, dflt: number): number {
  if (raw === undefined) return dflt;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 0) throw new Error(`invalid ${flag} '${raw}' (expected non-negative integer)`);
  return n;
}

/** Same parse-guard pattern as `cyberGymBestOfN()`: an unset/invalid env value falls back silently. */
function parseEnvBestOfN(raw: string | undefined): number | undefined {
  if (raw === undefined || raw.trim() === "") return undefined;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 1 ? n : undefined;
}

function parseEnvPositiveInt(raw: string | undefined): number | undefined {
  if (raw === undefined || raw.trim() === "") return undefined;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

export interface HuntOutcome {
  exitCode: number;
  result: unknown;
}

/** Run a seed-driven variant hunt and return a JSON-ready outcome. Exposed for testing. */
export async function runHunt(opts: {
  sourceRoot: string;
  seedPath: string;
  ref?: string;
  concurrency?: number;
  maxCandidates?: number;
  skipCandidates?: number;
  models?: string[];
  /** Restrict candidates to kernelCTF-reachable paths. Defaults to the `HUNT_REACHABLE_ONLY` env. */
  reachableOnly?: boolean;
  /** Sort kernelCTF-reachable candidates first (nothing dropped). Defaults to the `HUNT_REACHABLE_PREFER` env. */
  reachablePrefer?: boolean;
  verify?: boolean;
  /** Best-of-N finder attempts per (candidate, model). Defaults to the `HUNT_BEST_OF_N` env, then 1. */
  attemptsPerCandidate?: number;
  /** How many judge-ranked findings per site reach the skeptic gate. Defaults to `HUNT_JUDGE_TOP_K`, then 1. */
  judgeTopK?: number;
  /** Judge model override. Defaults to the `HUNT_JUDGE_MODEL` env (mirrors `HUNT_SKEPTIC_MODEL`). */
  judgeModel?: string;
  novelty?: {
    rootDir?: string;
    lists?: string[];
    recentEpochs?: number;
    sync?: boolean;
    model?: string;
    /** Abort before discovery when novelty evidence is unavailable. */
    required?: boolean;
  };
  /** Apply the evidence-backed kernel-LPE discovery preset. */
  methodology?: boolean;
  /**
   * Engine A: before candidate generation, build (or load) the stored invariant
   * model of the subsystem the seed diff touches and inject its rules +
   * deterministic violation hypotheses into every finder prompt as context.
   */
  invariant?: boolean;
  /**
   * Graph-slice finder: before candidate generation, load the pre-exported CPG
   * of the seed-touched subsystem and inject a compact interprocedural
   * reachability slice around the fix site into every finder prompt as context.
   * Fail-open — no CPG / no scope degrades to the flat-text finder.
   */
  graphSlice?: boolean;
  /** Explicit CPG graphson JSON path (overrides the `.pwnkit/cpg/<subsystem>.json` convention). */
  cpgPath?: string;
  /**
   * Optional comma-separated repo-relative C source files whose static
   * ops-struct initializers should resolve indirect calls in the graph slice.
   * Omit it to preserve the precomputed `.ops.json` path.
   */
  opsHarvestSourceFiles?: string[];
  /** Graph traversal radius for --graph-slice. Unset preserves the stage default (3). */
  graphSliceHops?: number;
  /**
   * PROVE stage (#1119): run the execution-verified exploitability oracle as a
   * terminal gate after the skeptic+prover pair. This BOOTS REAL QEMU VMs per
   * confirmed finding, so it is opt-in and requires `--verify` (there is nothing
   * to prove without a confirmed finding). Each finding is bound to its OWN
   * reproducer via `makeHuntProveStage`; findings with no extractable C
   * reproducer pass through unproven rather than being dropped.
   */
  exploitability?: boolean;
  /**
   * Minimum assessed impact ceiling required to spend VM budget on a finding
   * (the cheap, VM-free SyzScope pre-filter). Default `info-leak` — i.e. only
   * `dos-only` bugs are filtered out before QEMU is touched.
   */
  proveMinCeiling?: ImpactCeiling;
  runtime?: RuntimeMode;
  timeoutMs?: number;
  log?: (msg: string) => void;
}): Promise<HuntOutcome> {
  const {
    generateVariantCandidates,
    runHuntScan,
    makeSkepticVerifier,
    loadKnownNegativesFromEnv,
    buildInvariantHuntContext,
    buildGraphSliceHuntContext,
    localMirrors,
    syncLoreMirror,
    makeLloreJudge,
    makeHuntProveStage,
    prepare,
    getCloudSinkConfig,
    postFinding,
  } = await import("@pwnkit/core");
  const log = opts.log ?? (() => {});
  const runtime: RuntimeMode = opts.runtime ?? "api";
  const seedDiff = readFileSync(resolve(opts.seedPath), "utf8");

  // #1051 — `--source` may be a git URL (the cloud recency feed passes the
  // target's clone URL) or a local checkout. Reuse the engine's prepare()
  // helper (prepare.ts → resolveRepo: a local path is used as-is, a git URL is
  // shallow-cloned `git clone --depth 1` into a temp dir) to resolve EITHER
  // into a local tree the variant grep can walk. generateVariantCandidates only
  // greps the working tree, so depth-1 is sufficient; the temp clone is removed
  // by prepared.cleanup() in the finally.
  const prepared = await prepare(opts.sourceRoot, "source-code", { ...(opts.timeoutMs ? { timeout: opts.timeoutMs } : {}) }, (e) => {
    if (e.message) log(`[hunt:source] ${e.message}`);
  });
  const sourceRoot = resolve(prepared.resolvedTarget);
  const noveltyRoot = opts.novelty?.rootDir ?? process.env.PWNKIT_LORE_MIRROR_ROOT ?? "/root/lore-mirror";
  const noveltyLists = opts.novelty?.lists ?? (process.env.PWNKIT_LORE_LISTS ?? "linux-media").split(",").map((s) => s.trim()).filter(Boolean);
  const noveltyRecentEpochs = opts.novelty?.recentEpochs ?? 1;
  const noveltyWarnings: string[] = [];

  // #1051 — capture the cloud-sink config BEFORE suppressing the env below.
  // In cloud mode (PWNKIT_CLOUD_SINK + scan id set) the inner finder/skeptic
  // agenticScan passes would auto-POST their RAW, pre-gate findings (status
  // 'confirmed') straight to the orchestrator — flooding the scan with
  // unverified, mislabeled findings. We instead post ONLY the gated leads
  // ourselves (as honest 'discovered' candidates) after the gate.
  // getCloudSinkConfig() reads PWNKIT_CLOUD_SINK at call time, so clearing it
  // for the duration of the finder runs disables that inner auto-post; the env
  // is restored in the finally and the captured config is used for our own post.
  const sinkCfg = getCloudSinkConfig();
  const savedCloudSink = process.env.PWNKIT_CLOUD_SINK;
  if (sinkCfg) delete process.env.PWNKIT_CLOUD_SINK;

  try {
    let noveltyMirrors: Awaited<ReturnType<typeof localMirrors>> = [];
    if (opts.novelty && noveltyLists.length > 0) {
      try {
        noveltyMirrors = opts.novelty.sync
          ? await syncLoreMirror({
              rootDir: noveltyRoot,
              lists: noveltyLists,
              recentEpochs: noveltyRecentEpochs,
              log,
            })
          : localMirrors(noveltyRoot, noveltyLists);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        noveltyWarnings.push(`hunt: novelty sync failed: ${reason.slice(0, 160)}`);
        log(`[hunt] ${noveltyWarnings[noveltyWarnings.length - 1]}`);
      }
    }

    if (opts.novelty && noveltyMirrors.length === 0) {
      const message =
        `novelty requested but no lore mirrors found under ${noveltyRoot} ` +
        `for ${noveltyLists.join(",") || "(no lists)"}`;
      return {
        exitCode: 3,
        result: {
          mode: "hunt",
          seed: opts.ref ?? opts.seedPath,
          candidates: 0,
          novelty: { enabled: true, required: true, mirrors: [] },
          warnings: [...noveltyWarnings, `hunt: ${message}; aborting fail-closed`],
          note: "Discovery did not run because requested novelty evidence was unavailable.",
        },
      };
    }

    // 1. Seed → variant-hunt plan (bug class + grep'd candidate sites).
    const skipCandidates = opts.skipCandidates ?? 0;
    const maxCandidates = opts.maxCandidates ?? 40;
    const reachableOnly = opts.reachableOnly ?? process.env.HUNT_REACHABLE_ONLY === "1";
    const reachablePrefer = opts.reachablePrefer ?? (opts.methodology ? true : process.env.HUNT_REACHABLE_PREFER === "1");

    // Engine A (--invariant): BEFORE candidate generation, build (or load) the
    // stored invariant model of the subsystem the seed touches and run the
    // deterministic violation checker against the current source. The result is
    // injected into every finder prompt as a context block below — it adds NO
    // candidates and changes NO gate. Fail-open like the novelty sync: a scope /
    // model-build failure degrades to the plain seeded hunt, it never aborts it.
    let invariantCtx: Awaited<ReturnType<typeof buildInvariantHuntContext>> = null;
    const invariantWarnings: string[] = [];
    if (opts.invariant) {
      try {
        invariantCtx = await buildInvariantHuntContext({ sourceRoot, seedDiff, runtime, log });
        if (!invariantCtx) {
          invariantWarnings.push("hunt: --invariant set but no subsystem scope/files derivable from the seed — continuing without invariant context");
          log(`[hunt] ${invariantWarnings[invariantWarnings.length - 1]}`);
        }
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        invariantWarnings.push(`hunt: invariant-model stage failed, continuing without it: ${reason.slice(0, 160)}`);
        log(`[hunt] ${invariantWarnings[invariantWarnings.length - 1]}`);
      }
    }

    // Graph-slice stage (--graph-slice): BEFORE candidate generation, load the
    // seed-touched subsystem's PRE-EXPORTED CPG and build a compact
    // interprocedural reachability slice around the fix site. Injected into
    // every finder prompt as a context block below (SAME channel as --invariant)
    // — it adds NO candidates and changes NO gate. Fail-open: no scope, no CPG
    // export, or an empty slice degrades to the plain flat-text hunt.
    let graphSliceCtx: ReturnType<typeof buildGraphSliceHuntContext> = null;
    const graphSliceWarnings: string[] = [];
    if (opts.graphSlice) {
      try {
        graphSliceCtx = buildGraphSliceHuntContext({
          sourceRoot,
          seedDiff,
          ...(opts.cpgPath ? { cpgPath: opts.cpgPath } : {}),
          log,
          ...(opts.opsHarvestSourceFiles !== undefined
            ? { opsHarvestSourceFiles: opts.opsHarvestSourceFiles }
            : {}),
          ...(opts.graphSliceHops !== undefined ? { hops: opts.graphSliceHops } : {}),
        });
        if (!graphSliceCtx) {
          graphSliceWarnings.push("hunt: --graph-slice set but no CPG/scope/slice derivable — continuing with the flat-text finder");
          log(`[hunt] ${graphSliceWarnings[graphSliceWarnings.length - 1]}`);
        }
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        graphSliceWarnings.push(`hunt: graph-slice stage failed, continuing without it: ${reason.slice(0, 160)}`);
        log(`[hunt] ${graphSliceWarnings[graphSliceWarnings.length - 1]}`);
      }
    }

    const plan = await generateVariantCandidates({
      sourceRoot,
      fix: { diff: seedDiff, reference: opts.ref ?? opts.seedPath },
      runtime,
      maxCandidates: skipCandidates + maxCandidates,
      ...(opts.models ? { models: opts.models } : {}),
      ...(reachableOnly ? { reachableOnly } : {}),
      ...(reachablePrefer ? { reachablePrefer } : {}),
      log,
    });

    const selectedCandidates = plan.candidates.slice(skipCandidates, skipCandidates + maxCandidates);

    if (selectedCandidates.length === 0) {
      return {
        exitCode: 2,
        result: {
          mode: "hunt",
          seed: opts.ref ?? opts.seedPath,
          bug_class: plan.brief.bugClass,
          grep_patterns: plan.grepPatterns,
          candidates: 0,
          skipped_candidates: Math.min(skipCandidates, plan.candidates.length),
          warnings: [...noveltyWarnings, ...plan.warnings],
          note: plan.candidates.length === 0
            ? "no candidate sites generated — seed too narrow or surface already clean"
            : "no candidate sites left after --skip-candidates",
        },
      };
    }

    // 2. Fan finders out over the variant sites (absolute paths); skeptic-gate each.
    const candidates = selectedCandidates.map((c) => ({ ...c, path: `${sourceRoot}/${c.path}` }));
    const attemptsPerCandidate = opts.attemptsPerCandidate ?? parseEnvBestOfN(process.env.HUNT_BEST_OF_N) ?? (opts.methodology ? 4 : undefined);
    const judgeTopK = opts.judgeTopK ?? parseEnvPositiveInt(process.env.HUNT_JUDGE_TOP_K) ?? (opts.methodology ? 2 : undefined);
    const judgeModel = opts.judgeModel ?? process.env.HUNT_JUDGE_MODEL;
    const baseBrief = opts.methodology
      ? {
          ...plan.brief,
          pattern:
            `${plan.brief.pattern}\n\nMETHODOLOGY LENSES: map the full object lifecycle across handlers, callbacks, ` +
            `error/teardown paths and concurrent sessions; trace buffer/page provenance across zero-copy and in-place ` +
            `subsystem boundaries; look for a fix applied to one sibling path but bypassed by another. Refute capability, ` +
            `configuration and state-machine reachability before claiming impact. Treat source reasoning as a hypothesis ` +
            `until a sanitizer-backed reproducer proves it.`,
        }
      : plan.brief;
    // Engine A context injection: the invariant rules + violation hypotheses ride
    // the SAME prompt channel the methodology preset uses (brief.pattern), so
    // every finder run sees them while chasing the seed's bug class.
    // Both context stages ride the SAME brief.pattern channel and compose: the
    // invariant rules and the reachability slice are additive finder context.
    let huntPattern = baseBrief.pattern;
    if (invariantCtx) huntPattern = `${huntPattern}\n\n${invariantCtx.promptBlock}`;
    if (graphSliceCtx) huntPattern = `${huntPattern}\n\n${graphSliceCtx.promptBlock}`;
    const huntBrief = huntPattern === baseBrief.pattern ? baseBrief : { ...baseBrief, pattern: huntPattern };
    const res = await runHuntScan({
      sourceRoot,
      candidates,
      brief: huntBrief,
      runtime,
      concurrency: opts.concurrency ?? 4,
      ...(opts.models ? { models: opts.models } : {}),
      ...(attemptsPerCandidate ? { attemptsPerCandidate } : {}),
      ...(judgeTopK ? { judgeTopK } : {}),
      ...(judgeModel ? { judgeModel } : {}),
      // The skeptic is handed `models[0]` — i.e. by default the refute pass runs
      // on the SAME MODEL that found the bug, which is the correlated-error
      // problem in #661. `finderModels` lets the cross-family selector avoid
      // every family in the finder fan-out (not just the first) and swap the
      // refuter to a different family when one is configured; when only one
      // provider is configured it passes through to exactly this model. `log`
      // makes that decision visible in the run log instead of implicit.
      ...(opts.verify === false
        ? {}
        : {
            verify: makeSkepticVerifier({
              sourceRoot,
              runtime,
              ...(opts.models?.[0] ? { model: opts.models[0] } : {}),
              ...(opts.models && opts.models.length > 0 ? { finderModels: opts.models } : {}),
              negatives: loadKnownNegativesFromEnv(),
              log,
            }),
          }),
      // PROVE stage (#1119) — the terminal gate. Only wired on --exploitability,
      // because it boots REAL QEMU per confirmed finding. runHuntScan itself
      // ignores it (with a warning) when `verify` is absent, so --no-verify
      // --exploitability degrades safely instead of booting anything.
      ...(opts.exploitability
        ? {
            exploitability: makeHuntProveStage({
              // Cheap VM-free pre-filter: never spend a QEMU slot on a dos-only bug.
              escalation: opts.proveMinCeiling ? { minCeiling: opts.proveMinCeiling } : {},
              onVerdict: (f, _c, v) =>
                log(
                  `[hunt:prove] ${f.title}: maxObserved=${v.maxObservedClass} upgraded=${v.upgraded} ` +
                    `reachesPrivesc=${v.reachesPrivesc} proven=${v.provenExploitability}`,
                ),
              onEscalation: (f, _c, v) =>
                log(`[hunt:prove] ${f.title}: impact ceiling ${v.ceiling} (${v.basis}, conf ${v.confidence})`),
              log,
            }),
          }
        : {}),
      ...(opts.novelty && noveltyMirrors.length > 0
        ? {
            novelty: {
              mirrors: noveltyMirrors,
              ...(opts.novelty.model ? { judge: makeLloreJudge({ model: opts.novelty.model }) } : {}),
            },
          }
        : {}),
      log,
    });

    const gated = opts.verify !== false;
    const leads = gated ? res.confirmed : res.findings;

    // 3. #1051 — post the gated leads to the cloud-sink as CANDIDATE findings so
    // they flow through the cloud's existing adversarial gate + verify, the same
    // way scan/review reach the cloud (postFinding → POST /scans/:id/findings).
    // No-op when not in cloud mode (sinkCfg null). Honest: leadToCandidateFinding
    // forces status 'discovered' (never confirmed/sendable).
    let ingested = 0;
    if (sinkCfg) {
      const seedRef = opts.ref ?? opts.seedPath;
      // #1215 — build a finding-id → candidate-path lookup from the scan records
      // so leadToCandidateFinding can stamp the deployment context from the path.
      const pathForId = new Map<string, string>();
      for (const rec of res.records) pathForId.set(rec.finding.id, rec.candidatePath);
      for (const lead of leads) {
        const candidatePath = pathForId.get(lead.id);
        await postFinding(leadToCandidateFinding(lead, plan.brief.bugClass, seedRef, candidatePath), sinkCfg);
        ingested++;
      }
      log(`[hunt] posted ${ingested} lead(s) to the cloud-sink as candidate findings`);
    }

    return {
      exitCode: leads.length > 0 ? 0 : 1,
      result: {
        mode: "hunt",
        seed: opts.ref ?? opts.seedPath,
        bug_class: plan.brief.bugClass,
        source: sourceRoot,
        candidate_sites: selectedCandidates.map((c) => c.path),
        skipped_candidates: skipCandidates,
        scanned: res.scanned,
        findings: res.findings.length,
        confirmed: gated ? res.confirmed.length : null,
        novelty: opts.novelty
          ? {
              enabled: true,
              required: true,
              root: noveltyRoot,
              lists: noveltyLists,
              mirrors: noveltyMirrors.map((m) => ({ list: m.list, epoch: m.epoch, dir: m.dir })),
              duplicates: res.duplicates.map((d) => ({
                title: d.finding.title,
                matches: d.novelty.duplicates,
              })),
            }
          : { enabled: false },
        leads: leads.map((f) => ({
          title: f.title,
          severity: f.severity,
          analysis: f.evidence.analysis ?? "",
        })),
        dropped: res.dropped.map((d) => ({
          title: d.finding.title,
          severity: d.finding.severity,
          candidatePath: d.candidatePath,
          lensId: d.lensId,
          dropReason: d.dropReason,
          detail: d.detail,
        })),
        invariant: invariantCtx
          ? {
              enabled: true,
              subsystem: invariantCtx.subsystem,
              model_path: invariantCtx.modelPath,
              model_loaded: invariantCtx.modelLoaded,
              objects: invariantCtx.model.objects.length,
              violations: invariantCtx.violations.length,
            }
          : { enabled: false },
        graph_slice: graphSliceCtx
          ? {
              enabled: true,
              subsystem: graphSliceCtx.subsystem,
              cpg_path: graphSliceCtx.cpgPath,
              target_functions: graphSliceCtx.targetFunctions,
              resolved_targets: graphSliceCtx.resolvedTargets,
              ops_edges: graphSliceCtx.opsEdges,
              functions: graphSliceCtx.stats.functions,
              files: graphSliceCtx.stats.files.length,
              call_edges: graphSliceCtx.stats.callEdges,
              slice_chars: graphSliceCtx.stats.chars,
            }
          : { enabled: false },
        ingested: sinkCfg ? ingested : null,
        gated,
        methodology: opts.methodology === true,
        warnings: [...invariantWarnings, ...graphSliceWarnings, ...noveltyWarnings, ...plan.warnings, ...res.warnings].slice(0, 10),
        note: opts.novelty
          ? "LEADS, not confirmed 0-days. Novelty-duplicate leads were dropped when lore mirrors matched; still verify the real sink before disclosure."
          : "LEADS, not confirmed 0-days. Verify the real sink + upstream-fix (novelty) before disclosure.",
      },
    };
  } finally {
    if (savedCloudSink !== undefined) process.env.PWNKIT_CLOUD_SINK = savedCloudSink;
    prepared.cleanup();
  }
}

async function huntAction(opts: HuntOpts): Promise<void> {
  if (!opts.source) throw new Error("missing required flag: --source <kernel/src tree>");
  if (!opts.seed) throw new Error("missing required flag: --seed <fix diff/patch to hunt variants of>");

  const outcome = await runHunt({
    sourceRoot: opts.source,
    seedPath: opts.seed,
    ...(opts.ref ? { ref: opts.ref } : {}),
    concurrency: parsePositive("--concurrency", opts.concurrency, 4),
    skipCandidates: parseNonNegative("--skip-candidates", opts.skipCandidates, 0),
    ...(opts.models ? { models: opts.models.split(",").map((s) => s.trim()).filter(Boolean) } : {}),
    ...(opts.reachableOnly ? { reachableOnly: true } : {}),
    ...(opts.reachablePrefer ? { reachablePrefer: true } : {}),
    verify: opts.verify,
    ...(opts.novelty || opts.noveltyRequired || opts.methodology
      ? {
          novelty: {
            ...(opts.noveltyRoot ? { rootDir: opts.noveltyRoot } : {}),
            ...(opts.noveltyLists ? { lists: opts.noveltyLists.split(",").map((s) => s.trim()).filter(Boolean) } : {}),
            recentEpochs: parsePositive("--novelty-recent-epochs", opts.noveltyRecentEpochs, 1),
            sync: opts.noveltySync === true || opts.methodology === true,
            ...(opts.noveltyModel ? { model: opts.noveltyModel } : {}),
            required: opts.noveltyRequired === true || opts.methodology === true,
          },
        }
      : {}),
    methodology: opts.methodology === true,
    invariant: opts.invariant === true,
    graphSlice: opts.graphSlice === true,
    ...(opts.cpg ? { cpgPath: opts.cpg } : {}),
    ...(opts.opsHarvest !== undefined
      ? {
          opsHarvestSourceFiles: opts.opsHarvest
            .split(",")
            .map((path) => path.trim())
            .filter(Boolean),
        }
      : {}),
    ...(opts.graphSliceHops
      ? { graphSliceHops: parsePositive("--graph-slice-hops", opts.graphSliceHops, 3) }
      : {}),
    exploitability: opts.exploitability === true,
    ...(opts.proveMinCeiling ? { proveMinCeiling: parseCeiling(opts.proveMinCeiling) } : {}),
    ...(opts.runtime ? { runtime: opts.runtime as RuntimeMode } : {}),
    timeoutMs: parsePositive("--timeout", opts.timeout, 600_000),
    log: (m) => process.stderr.write(m + "\n"),
  });

  const json = JSON.stringify(outcome.result, null, 2);
  if (opts.output) writeFileSync(resolve(opts.output), json + "\n", "utf8");
  else process.stdout.write(json + "\n");
  process.exitCode = outcome.exitCode;
}

export function registerHuntCommand(program: Command): void {
  program
    .command("hunt")
    .description(
      "Hunt a bug CLASS across a source tree, seeded by a proven fix: " +
        "generate variant candidate sites from the fix, fan finders out over them, " +
        "and gate each finding through an adversarial skeptic. Emits LEADS to verify " +
        "(not confirmed 0-days). Exit 0=lead(s), 1=none, 2=no candidates, 3=error.",
    )
    .requiredOption("--source <path>", "Source tree to hunt in (e.g. a linux checkout)")
    .requiredOption("--seed <path>", "Fix diff / .patch whose bug class to hunt variants of")
    .option("--ref <name>", "Provenance label for the seed (e.g. the CVE / commit)")
    .option("--concurrency <N>", "Max finders in flight (default 4)")
    .option("--max-candidates <N>", "Cap candidate sites hunted (default 40)")
    .option("--skip-candidates <N>", "Skip the first N ranked candidate sites before hunting (default 0)")
    .option("--models <a,b>", "Comma-separated finder models for diversity (default: provider default)")
    .option("--reachable-only", "Restrict candidates to paths built + zero-cap reachable on the kernelCTF COS target (default: HUNT_REACHABLE_ONLY env)")
    .option("--reachable-prefer", "Sort kernelCTF-reachable candidates first, without dropping any (default: HUNT_REACHABLE_PREFER env)")
    .option("--no-verify", "Skip the skeptic gate (emit all raw findings — triage only, never disclosure)")
    .option("--novelty", "Require lore.kernel.org duplicate suppression; abort before discovery when evidence is unavailable")
    .option("--novelty-root <path>", "Lore mirror root (default: PWNKIT_LORE_MIRROR_ROOT or /root/lore-mirror)")
    .option("--novelty-lists <a,b>", "Comma-separated lore lists to search (default: PWNKIT_LORE_LISTS or linux-media)")
    .option("--novelty-recent-epochs <N>", "Newest public-inbox epochs to sync per list when --novelty-sync is set (default 1)")
    .option("--novelty-sync", "Clone/fetch lore mirrors before running the novelty gate")
    .option("--novelty-model <model>", "Optional model override for the lore duplicate judge")
    .option("--novelty-required", "Legacy alias; --novelty already aborts when evidence is unavailable")
    .option("--methodology", "Use the kernel-LPE methodology preset: lifecycle/provenance lenses, best-of-4, top-2 skeptic gate, reachable-first")
    .option("--invariant", "Engine A: build (or load) the seed-touched subsystem's stored invariant model and inject its rules + deterministic violation hypotheses into every finder prompt")
    .option("--graph-slice", "Load the seed-touched subsystem's pre-exported Joern CPG and inject a compact interprocedural reachability slice around the fix site into every finder prompt (needs scripts/provision-cpg.sh; fail-open to flat-text)")
    .option("--cpg <path>", "Explicit CPG graphson JSON path for --graph-slice (default: <source>/.pwnkit/cpg/<subsystem>.json)")
    .option(
      "--ops-harvest <paths>",
      "[--graph-slice] Comma-separated repo-relative C files to harvest static ops-struct initializers from; overrides a precomputed .ops.json",
    )
    .option(
      "--graph-slice-hops <N>",
      "[--graph-slice] Call-graph radius around the seed functions (default 3; use 8 for the exp527 known answer)",
    )
    .option(
      "--exploitability",
      "PROVE stage: after the skeptic+prover gate, run the execution-verified exploitability oracle " +
        "on each confirmed finding (GREBE diversify + SCAVY differential). BOOTS REAL QEMU VMs — " +
        "requires staged kernel-VM artifacts and is ignored under --no-verify. Never rejects a finding; " +
        "it stamps a proven verdict and gates the weaponize budget.",
    )
    .option(
      "--prove-min-ceiling <ceiling>",
      "[--exploitability] Minimum assessed impact ceiling worth a VM slot: dos-only|info-leak|oob-write|uaf-control " +
        "(default info-leak — filters out dos-only before QEMU is touched)",
    )
    .option("--output <path>", "Write the hunt result JSON to this path instead of stdout")
    .option("--runtime <mode>", "Engine runtime (default api)")
    .option("--timeout <ms>", "Accepted cloud agent timeout budget in milliseconds", "600000")
    .action(async (opts: HuntOpts) => {
      try {
        await huntAction(opts);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        const json = JSON.stringify({ mode: "hunt", error: reason }, null, 2);
        if (opts.output) {
          try { writeFileSync(resolve(opts.output), json + "\n", "utf8"); } catch { process.stderr.write(json + "\n"); }
        } else process.stdout.write(json + "\n");
        process.exitCode = 3;
      }
    });
}
