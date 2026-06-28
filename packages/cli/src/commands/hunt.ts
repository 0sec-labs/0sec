/**
 * `pwnkit hunt` — novel-bug variant hunt CLI (the `runHuntScan` engine stage).
 *
 * Turns a proven fix into a tree-wide hunt for the SAME bug class at OTHER
 * sites: seed diff → `generateVariantCandidates` (LLM bug-class + grep'd
 * candidate sites) → `runHuntScan` (parallel finders → adversarial skeptic
 * gate). The discovery sibling of `pwnkit exploit` (weaponize) and
 * `pwnkit scan` (single-target). Engine-driven; this command is the surface.
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

/**
 * #1051 — map a gated hunt LEAD onto the cloud-sink finding shape as a
 * CANDIDATE: status forced to `discovered` (never `confirmed`/sendable — these
 * are hypotheses, not proven bugs) and a provenance note stamped into
 * `evidence.analysis`. The orchestrator sets verify_status server-side, so a
 * `discovered` lead enters the verify queue as a candidate; sendability stays
 * gated behind the cloud's own adversarial verify (verify_status='verified').
 * Returned as a plain object — `postFinding` normalizes it to CloudSinkFinding.
 *
 * Exposed for unit testing the lead → finding mapping.
 */
export function leadToCandidateFinding(
  finding: Finding,
  bugClass: string,
  seedRef: string,
): Record<string, unknown> {
  const evidence =
    (finding.evidence as { request?: string; response?: string; analysis?: string } | undefined) ??
    {};
  const provenance =
    `Variant-hunt LEAD (bug class: ${bugClass}; seed: ${seedRef}). ` +
    `Surfaced by the recency hunt and gated by the adversarial skeptic — a HYPOTHESIS, ` +
    `not a confirmed bug. Verify the real sink + upstream-fix status (novelty) before any disclosure.`;
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
  verify?: boolean; // commander sets false when --no-verify is passed
  novelty?: boolean;
  noveltyRoot?: string;
  noveltyLists?: string;
  noveltyRecentEpochs?: string;
  noveltySync?: boolean;
  noveltyModel?: string;
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

function parseNonNegative(flag: string, raw: string | undefined, dflt: number): number {
  if (raw === undefined) return dflt;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 0) throw new Error(`invalid ${flag} '${raw}' (expected non-negative integer)`);
  return n;
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
  verify?: boolean;
  novelty?: {
    rootDir?: string;
    lists?: string[];
    recentEpochs?: number;
    sync?: boolean;
    model?: string;
  };
  runtime?: RuntimeMode;
  timeoutMs?: number;
  log?: (msg: string) => void;
}): Promise<HuntOutcome> {
  const {
    generateVariantCandidates,
    runHuntScan,
    makeSkepticVerifier,
    localMirrors,
    syncLoreMirror,
    makeLloreJudge,
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
        noveltyWarnings.push(`hunt: novelty sync failed, continuing without duplicate suppression: ${reason.slice(0, 160)}`);
        log(`[hunt] ${noveltyWarnings[noveltyWarnings.length - 1]}`);
      }
    }

    if (opts.novelty && noveltyMirrors.length === 0) {
      log(
        `[hunt] novelty requested but no lore mirrors found under ${noveltyRoot} ` +
          `for ${noveltyLists.join(",") || "(no lists)"}; continuing fail-open`,
      );
    }

    // 1. Seed → variant-hunt plan (bug class + grep'd candidate sites).
    const skipCandidates = opts.skipCandidates ?? 0;
    const maxCandidates = opts.maxCandidates ?? 40;
    const plan = await generateVariantCandidates({
      sourceRoot,
      fix: { diff: seedDiff, reference: opts.ref ?? opts.seedPath },
      runtime,
      maxCandidates: skipCandidates + maxCandidates,
      ...(opts.models ? { models: opts.models } : {}),
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
    const res = await runHuntScan({
      sourceRoot,
      candidates,
      brief: plan.brief,
      runtime,
      concurrency: opts.concurrency ?? 4,
      ...(opts.models ? { models: opts.models } : {}),
      ...(opts.verify === false ? {} : { verify: makeSkepticVerifier({ sourceRoot, runtime, ...(opts.models?.[0] ? { model: opts.models[0] } : {}) }) }),
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
      for (const lead of leads) {
        await postFinding(leadToCandidateFinding(lead, plan.brief.bugClass, seedRef), sinkCfg);
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
              root: noveltyRoot,
              lists: noveltyLists,
              mirrors: noveltyMirrors.map((m) => ({ list: m.list, epoch: m.epoch, dir: m.dir })),
              duplicates: res.duplicates.map((d) => ({
                title: d.finding.title,
                matches: d.novelty.duplicates,
              })),
            }
          : { enabled: false },
        leads: leads.map((f) => ({ title: f.title, severity: f.severity })),
        ingested: sinkCfg ? ingested : null,
        gated,
        warnings: [...noveltyWarnings, ...plan.warnings, ...res.warnings].slice(0, 10),
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
    maxCandidates: parsePositive("--max-candidates", opts.maxCandidates, 40),
    skipCandidates: parseNonNegative("--skip-candidates", opts.skipCandidates, 0),
    ...(opts.models ? { models: opts.models.split(",").map((s) => s.trim()).filter(Boolean) } : {}),
    verify: opts.verify,
    ...(opts.novelty
      ? {
          novelty: {
            ...(opts.noveltyRoot ? { rootDir: opts.noveltyRoot } : {}),
            ...(opts.noveltyLists ? { lists: opts.noveltyLists.split(",").map((s) => s.trim()).filter(Boolean) } : {}),
            recentEpochs: parsePositive("--novelty-recent-epochs", opts.noveltyRecentEpochs, 1),
            sync: opts.noveltySync === true,
            ...(opts.noveltyModel ? { model: opts.noveltyModel } : {}),
          },
        }
      : {}),
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
    .option("--no-verify", "Skip the skeptic gate (emit all raw findings — triage only, never disclosure)")
    .option("--novelty", "After the skeptic gate, drop confirmed findings duplicated by lore.kernel.org mirror patches")
    .option("--novelty-root <path>", "Lore mirror root (default: PWNKIT_LORE_MIRROR_ROOT or /root/lore-mirror)")
    .option("--novelty-lists <a,b>", "Comma-separated lore lists to search (default: PWNKIT_LORE_LISTS or linux-media)")
    .option("--novelty-recent-epochs <N>", "Newest public-inbox epochs to sync per list when --novelty-sync is set (default 1)")
    .option("--novelty-sync", "Clone/fetch lore mirrors before running the novelty gate")
    .option("--novelty-model <model>", "Optional model override for the lore duplicate judge")
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
