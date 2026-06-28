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
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import type { RuntimeMode } from "@pwnkit/shared";

interface HuntOpts {
  source?: string;
  seed?: string;
  ref?: string;
  concurrency?: string;
  maxCandidates?: string;
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

export interface HuntOutcome {
  exitCode: number;
  result: unknown;
}

function seedToFix(seed: string, ref: string | undefined): { commit?: string; diff?: string; reference?: string } {
  const seedPath = resolve(seed);
  if (existsSync(seedPath)) {
    return { diff: readFileSync(seedPath, "utf8"), reference: ref ?? seed };
  }
  if (seed.includes("\n") || /^diff --git\b/.test(seed.trimStart()) || /^@@\s/m.test(seed)) {
    return { diff: seed, reference: ref ?? "inline-diff" };
  }
  return { commit: seed, reference: ref ?? seed };
}

/** Run a seed-driven variant hunt and return a JSON-ready outcome. Exposed for testing. */
export async function runHunt(opts: {
  sourceRoot: string;
  seedPath: string;
  ref?: string;
  concurrency?: number;
  maxCandidates?: number;
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
    detectTargetType,
    prepare,
  } = await import("@pwnkit/core");
  const log = opts.log ?? (() => {});
  const runtime: RuntimeMode = opts.runtime ?? "api";
  const targetType = detectTargetType(opts.sourceRoot);
  if (targetType !== "source-code") {
    throw new Error(`hunt --source must be a local source tree or git URL (got ${targetType})`);
  }
  const prepared = await prepare(
    opts.sourceRoot,
    targetType,
    { ...(opts.timeoutMs ? { timeout: opts.timeoutMs } : {}) },
    (event) => log(`[hunt] ${event.message}`),
  );
  const sourceRoot = prepared.resolvedTarget;
  const fix = seedToFix(opts.seedPath, opts.ref);
  const noveltyRoot = opts.novelty?.rootDir ?? process.env.PWNKIT_LORE_MIRROR_ROOT ?? "/root/lore-mirror";
  const noveltyLists = opts.novelty?.lists ?? (process.env.PWNKIT_LORE_LISTS ?? "linux-media").split(",").map((s) => s.trim()).filter(Boolean);
  const noveltyRecentEpochs = opts.novelty?.recentEpochs ?? 1;
  const noveltyWarnings: string[] = [];
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
    const plan = await generateVariantCandidates({
      sourceRoot,
      fix,
      runtime,
      maxCandidates: opts.maxCandidates ?? 40,
      ...(opts.models ? { models: opts.models } : {}),
      log,
    });

    if (plan.candidates.length === 0) {
      return {
        exitCode: 2,
        result: {
          mode: "hunt",
          seed: opts.ref ?? opts.seedPath,
          bug_class: plan.brief.bugClass,
          grep_patterns: plan.grepPatterns,
          candidates: 0,
          warnings: [...noveltyWarnings, ...plan.warnings],
          note: "no candidate sites generated — seed too narrow or surface already clean",
        },
      };
    }

    // 2. Fan finders out over the variant sites (absolute paths); skeptic-gate each.
    const candidates = plan.candidates.map((c) => ({ ...c, path: `${sourceRoot}/${c.path}` }));
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
    return {
      exitCode: leads.length > 0 ? 0 : 1,
      result: {
        mode: "hunt",
        seed: opts.ref ?? opts.seedPath,
        bug_class: plan.brief.bugClass,
        source: sourceRoot,
        candidate_sites: plan.candidates.map((c) => c.path),
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
        gated,
        warnings: [...noveltyWarnings, ...plan.warnings, ...res.warnings].slice(0, 10),
        note: opts.novelty
          ? "LEADS, not confirmed 0-days. Novelty-duplicate leads were dropped when lore mirrors matched; still verify the real sink before disclosure."
          : "LEADS, not confirmed 0-days. Verify the real sink + upstream-fix (novelty) before disclosure.",
      },
    };
  } finally {
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
