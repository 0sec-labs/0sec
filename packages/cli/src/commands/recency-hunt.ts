/**
 * `pwnkit recency-hunt` — the RECENCY FLYWHEEL surface.
 *
 * Continuous kernel-LPE discovery on the freshness window: git-diff a fresh
 * linux-next range → reachability filter → SEMANTIC-vs-COSMETIC classifier →
 * the refined invariant engine (buildInvariantModel → dataflow violations →
 * runHuntScan adversarial gate) → ranked report. The engine lives in
 * `@pwnkit/core` ({@link runRecencyHunt}); this command is the thin surface + a
 * daily-scheduler entrypoint (`--report-dir` writes `YYYY-MM-DD.{json,md}`).
 *
 * A survivor is a LEAD, not a proven 0-day: verify real reachability + novelty
 * (not already patched later in the window) before any operator-gated
 * disclosure. Nothing here sends.
 *
 * Exit codes (so a scheduler/dispatcher can branch on code):
 *   0 → ≥1 survivor lead (worth weaponizing via autoclimb)
 *   1 → ran, 0 survivors (the honest expected result for a short window)
 *   2 → empty window (no commits in range) — nothing to hunt
 *   3 → error (bad flags, unreadable tree, engine failure)
 */

import type { Command } from "commander";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { RuntimeMode } from "@pwnkit/shared";

interface RecencyOpts {
  tree?: string;
  since?: string;
  hours?: string;
  model?: string;
  classifierModel?: string;
  runtime?: string;
  modelDir?: string;
  maxHuntFiles?: string;
  maxClassifyFiles?: string;
  detectors?: string;
  output?: string;
  md?: string;
  reportDir?: string;
}

/** Parse `--detectors dataflow,refcount,race` → validated detector list (default all). */
function parseDetectors(raw: string | undefined): ("dataflow" | "refcount" | "race")[] | undefined {
  if (!raw) return undefined;
  const valid = new Set(["dataflow", "refcount", "race"]);
  const list = raw.split(",").map((s) => s.trim()).filter(Boolean);
  const bad = list.filter((d) => !valid.has(d));
  if (bad.length > 0) throw new Error(`invalid --detectors '${bad.join(", ")}' (allowed: dataflow, refcount, race)`);
  return list as ("dataflow" | "refcount" | "race")[];
}

function parsePositive(flag: string, raw: string | undefined, dflt: number): number {
  if (raw === undefined) return dflt;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`invalid ${flag} '${raw}' (expected positive integer)`);
  return n;
}

async function recencyAction(opts: RecencyOpts): Promise<void> {
  if (!opts.tree) throw new Error("missing required flag: --tree <kernel source tree>");

  const { runRecencyHunt, renderRecencyReportMarkdown } = await import("@pwnkit/core");

  const tree = resolve(opts.tree);
  const runtime: RuntimeMode = (opts.runtime as RuntimeMode) ?? "api";
  const modelDir = opts.modelDir ? resolve(opts.modelDir) : join(tree, ".recency-models");
  mkdirSync(modelDir, { recursive: true });

  const report = await runRecencyHunt({
    tree,
    ...(opts.since ? { range: opts.since } : {}),
    ...(opts.hours ? { hours: parsePositive("--hours", opts.hours, 24) } : opts.since ? {} : { hours: 24 }),
    runtime,
    modelDir,
    ...(opts.model ? { model: opts.model } : {}),
    ...(opts.classifierModel ? { classifierModel: opts.classifierModel } : {}),
    maxHuntFiles: parsePositive("--max-hunt-files", opts.maxHuntFiles, 25),
    maxClassifyFiles: parsePositive("--max-classify-files", opts.maxClassifyFiles, 80),
    ...(parseDetectors(opts.detectors) ? { detectors: parseDetectors(opts.detectors) } : {}),
    log: (m) => process.stderr.write(m + "\n"),
  });

  const json = JSON.stringify(report, null, 2);
  const md = renderRecencyReportMarkdown(report);

  // --report-dir: the scheduler mode — write dated JSON + markdown side by side
  // and log a one-line summary to stdout.
  if (opts.reportDir) {
    const dir = resolve(opts.reportDir);
    mkdirSync(dir, { recursive: true });
    const day = new Date().toISOString().slice(0, 10);
    writeFileSync(join(dir, `${day}.json`), json + "\n", "utf8");
    writeFileSync(join(dir, `${day}.md`), md + "\n", "utf8");
    const f = report.funnel;
    const cbd = f.candidatesByDetector;
    process.stdout.write(
      `recency-flywheel ${day}: ${f.commits} commits → ${f.changedFiles} files → ${f.inScope} in-scope → ` +
        `${f.semantic} semantic → ${f.candidates} candidates ` +
        `{dataflow: ${cbd.dataflow}, refcount: ${cbd.refcount}, race: ${cbd.race}} → ${f.survivors} survivor(s). ` +
        `detectors: ${report.detectors.join("+")}. reports: ${join(dir, day)}.{json,md}\n`,
    );
  } else {
    if (opts.output) writeFileSync(resolve(opts.output), json + "\n", "utf8");
    else process.stdout.write(json + "\n");
    if (opts.md) writeFileSync(resolve(opts.md), md + "\n", "utf8");
  }

  process.exitCode = report.range === "(empty window)" ? 2 : report.survivors.length > 0 ? 0 : 1;
}

export function registerRecencyHuntCommand(program: Command): void {
  program
    .command("recency-hunt")
    .description(
      "Recency flywheel: hunt the kernelCTF freshness window. git-diff a fresh " +
        "linux-next range → drop non-unpriv-reachable files → classify each diff " +
        "SEMANTIC (lifetime/refcount/lock change) vs COSMETIC (reshuffle) → run the " +
        "refined invariant engine on semantic files → adversarial verify → ranked " +
        "report. Emits LEADS (verify novelty/reachability before disclosure). " +
        "Exit 0=survivor(s), 1=none, 2=empty window, 3=error.",
    )
    .requiredOption("--tree <path>", "Kernel source tree to hunt (e.g. /root/linux-next)")
    .option("--since <gitrange>", "Explicit git range (e.g. HEAD~20..HEAD or <sha>..HEAD); overrides --hours")
    .option("--hours <N>", "Hunt commits from the last N hours (default 24)")
    .option("--model <model>", "Model-build / finder model override")
    .option("--classifier-model <model>", "Semantic-vs-cosmetic classifier model (default gpt-5.5)")
    .option("--runtime <mode>", "Engine runtime (default api)")
    .option("--model-dir <path>", "Where per-file invariant models are stored (default <tree>/.recency-models)")
    .option("--max-hunt-files <N>", "Cap files run through the engine (default 25)")
    .option("--max-classify-files <N>", "Cap in-scope files sent to the LLM classifier (default 80; snapshot merge-window cost control)")
    .option("--detectors <list>", "Comma-separated detectors to run per semantic file: dataflow,refcount,race (default all three)")
    .option("--output <path>", "Write the report JSON here instead of stdout")
    .option("--md <path>", "Also write the markdown report here")
    .option("--report-dir <dir>", "Scheduler mode: write <dir>/YYYY-MM-DD.{json,md} + log a one-line summary")
    .action(async (opts: RecencyOpts) => {
      try {
        await recencyAction(opts);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        const json = JSON.stringify({ mode: "recency-hunt", error: reason }, null, 2);
        if (opts.output) {
          try { writeFileSync(resolve(opts.output), json + "\n", "utf8"); } catch { process.stderr.write(json + "\n"); }
        } else process.stdout.write(json + "\n");
        process.exitCode = 3;
      }
    });
}
