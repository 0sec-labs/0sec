// Pipeline orchestrator for the file-review harness (deepsec init/steady-state
// graph): scan → coverage gate → process → revalidate, with global cost and
// duration caps that stop at a resumable checkpoint (exit code 3) instead of
// destroying partial state. Every stage ADDS to the on-disk records; a
// re-run of the same command resumes where it stopped.

import path from "node:path";
import { ReviewStore } from "./store.js";
import { compileMatchers, runReviewScan } from "./scan.js";
import { DEFAULT_REVIEW_MATCHERS } from "./matchers-default.js";
import { evaluateReviewCoverage } from "./coverage.js";
import { runReviewProcess } from "./process.js";
import { runReviewRevalidate } from "./revalidate.js";
import { collectScannableFiles } from "./scan.js";
import { generateSurfaceInventory } from "./inventory.js";
import { atomicWriteFileSync } from "./atomic-file.js";
import fs from "node:fs";
import type {
  ReviewExitCode,
  ReviewInvoker,
  ReviewLimitError as LimitErrType,
  ReviewPipelineResult,
  ReviewRevalidationVerdict,
} from "./types.js";
import { ReviewLimitError } from "./types.js";

export interface FileReviewPipelineOptions {
  /** Absolute path of the repo being reviewed. */
  rootPath: string;
  /** Project id; defaults to the rootPath basename. */
  projectId?: string;
  /** Data dir for records; defaults to `<rootPath>/.pwnkit-review`. */
  dataDir?: string;
  invoker: ReviewInvoker;
  /** Free-form project context appended to every investigation prompt (INFO.md). */
  projectInfo?: string;
  promptAppend?: string;
  /** Generate the AI surface inventory + INFO.md before scanning. */
  withInventory?: boolean;
  /** Run the static revalidate stage on HIGH+ findings after process. */
  withRevalidate?: boolean;
  /** Extra matcher specs layered on top of the defaults. */
  extraMatcherSpecs?: Parameters<typeof compileMatchers>[0];
  ignorePatterns?: readonly string[];
  maxCostUsd?: number;
  maxDurationMs?: number;
  batchSize?: number;
  concurrency?: number;
  /** Model label recorded on analysis entries. */
  model?: string;
  log?: (msg: string) => void;
}

/**
 * Run the full review pipeline. Returns a ReviewPipelineResult whose
 * exitCode follows the deepsec contract: 0 clean, 1 findings, 3 cost/duration
 * limit reached at a resumable checkpoint (re-run the same command to
 * resume — completed files are skipped, pending ones continue).
 */
export async function runFileReviewPipeline(
  opts: FileReviewPipelineOptions,
): Promise<ReviewPipelineResult> {
  const startedAt = Date.now();
  const projectId = opts.projectId ?? (path.basename(opts.rootPath.replace(/\/$/, "")) || "project");
  const dataDir = opts.dataDir ?? path.join(opts.rootPath, ".pwnkit-review");
  const store = new ReviewStore({ dataDir });
  const log = opts.log ?? (() => {});

  const checkDuration = (): void => {
    if (opts.maxDurationMs !== undefined && Date.now() - startedAt >= opts.maxDurationMs) {
      throw new ReviewLimitError(
        "duration",
        `Review reached its ${opts.maxDurationMs}ms duration limit at a resumable checkpoint.`,
      );
    }
  };

  let infoMarkdown = [opts.projectInfo, opts.promptAppend].filter(Boolean).join("\n\n");
  let coveragePassed: boolean | undefined;
  let totalCostUsd = 0;
  let netNew = 0;
  let tp = 0;
  let fp = 0;
  let candidatesFound = 0;
  let filesScanned = 0;
  let runId = "";

  try {
    // ── Inventory (optional) ───────────────────────────────────────────────
    if (opts.withInventory) {
      checkDuration();
      const universe = collectScannableFiles(opts.rootPath, opts.ignorePatterns);
      const inv = await generateSurfaceInventory({
        rootPath: opts.rootPath,
        invoker: opts.invoker,
        repositoryFiles: universe,
        log,
      });
      totalCostUsd += inv.costUsd;
      checkDuration();
      if (opts.maxCostUsd !== undefined && totalCostUsd >= opts.maxCostUsd) {
        throw new ReviewLimitError(
          "cost",
          `Review reached its $${opts.maxCostUsd.toFixed(4)} cost limit at an inventory checkpoint.`,
        );
      }
      infoMarkdown = [infoMarkdown, inv.infoMarkdown].filter(Boolean).join("\n\n");
      atomicWriteFileSync(path.join(store.projectDir(projectId), "INFO.md"), infoMarkdown);
      atomicWriteFileSync(
        path.join(store.projectDir(projectId), "surface-inventory.json"),
        JSON.stringify(inv.inventory, null, 2),
      );
      log(`inventory: ${inv.inventory.items.length} surface(s), ${inv.inventory.sourceFiles.length} files`);
    }

    // ── Scan (free) ────────────────────────────────────────────────────────
    checkDuration();
    const matchers = compileMatchers([...DEFAULT_REVIEW_MATCHERS, ...(opts.extraMatcherSpecs ?? [])]);
    const scanResult = runReviewScan(store, {
      projectId,
      rootPath: opts.rootPath,
      matchers,
      ignorePatterns: opts.ignorePatterns,
      log,
    });
    runId = scanResult.runId;
    filesScanned = scanResult.filesScanned;
    candidatesFound = scanResult.candidatesFound;

    // ── Coverage gate (explicit inventory must justify paid processing) ────
    if (opts.withInventory) {
      const invRaw = path.join(store.projectDir(projectId), "surface-inventory.json");
      if (fs.existsSync(invRaw)) {
        const inventory = JSON.parse(fs.readFileSync(invRaw, "utf8"));
        const records = store.listRecords(projectId);
        const coverage = evaluateReviewCoverage({
          inventory,
          records,
          runId: scanResult.runId,
          languageStats: scanResult.languageStats,
          newMatcherHits: {}, // built-ins are exempt from explosion checks
        });
        coveragePassed = coverage.passed;
        atomicWriteFileSync(
          path.join(store.projectDir(projectId), "coverage.json"),
          JSON.stringify(coverage, null, 2),
        );
        if (!coverage.passed) {
          log(`coverage gate FAILED — no paid process: ${coverage.reasons.join("; ")}`);
        }
        for (const warn of coverage.languageWarnings) log(`coverage: ${warn.reason}`);
        if (!coverage.passed) {
          return {
            exitCode: 2,
            runId,
            projectId,
            stats: {
              filesScanned,
              candidatesFound,
              findingsCount: 0,
              netNewFindings: 0,
              truePositives: 0,
              falsePositives: 0,
              totalCostUsd,
              coveragePassed,
            },
          };
        }
      }
    }

    // ── Process (paid) ─────────────────────────────────────────────────────
    checkDuration();
    const remainingBudgetUsd =
      opts.maxCostUsd !== undefined ? Math.max(0, opts.maxCostUsd - totalCostUsd) : undefined;
    const remainingDurationMs =
      opts.maxDurationMs !== undefined ? Math.max(0, opts.maxDurationMs - (Date.now() - startedAt)) : undefined;

    const findingsBefore = store.listRecords(projectId).reduce((n, r) => n + r.findings.length, 0);
    const processResult = await runReviewProcess(store, {
      projectId,
      rootPath: opts.rootPath,
      invoker: opts.invoker,
      projectInfo: infoMarkdown,
      batchSize: opts.batchSize,
      concurrency: opts.concurrency,
      maxCostUsd: remainingBudgetUsd,
      maxDurationMs: remainingDurationMs,
      model: opts.model,
      log,
    });
    totalCostUsd += processResult.costUsd;
    runId = processResult.runId;
    const findingsAfter = store.listRecords(projectId).reduce((n, r) => n + r.findings.length, 0);
    netNew = Math.max(0, findingsAfter - findingsBefore);


    // deepsec contract: a stage that stopped at a cost/duration limit ends
    // the whole pipeline at exit code 3 (resumable checkpoint). Interrupted
    // files were reverted to pending by the stage that hit the limit.
    if (processResult.limitReached) {
      throw new ReviewLimitError(
        processResult.limitReached.kind,
        `Review stopped by ${processResult.limitReached.kind} limit at a resumable checkpoint.`,
      );
    }
    // ── Revalidate (paid, HIGH+ only) ──────────────────────────────────────
    if (opts.withRevalidate && netNew > 0) {
      checkDuration();
      const budgetUsd =
        opts.maxCostUsd !== undefined ? Math.max(0, opts.maxCostUsd - totalCostUsd) : undefined;
      const durationMs =
        opts.maxDurationMs !== undefined ? Math.max(0, opts.maxDurationMs - (Date.now() - startedAt)) : undefined;
      const revResult = await runReviewRevalidate(store, {
        projectId,
        rootPath: opts.rootPath,
        invoker: opts.invoker,
        minSeverity: "high",
        maxCostUsd: budgetUsd,
        maxDurationMs: durationMs,
        model: opts.model,
        log,
      });
      totalCostUsd += revResult.costUsd;
      tp = revResult.truePositives;
      fp = revResult.falsePositives;
      log(
        `revalidate: ${revResult.revalidated} verdict(s) — TP ${revResult.truePositives}, FP ${revResult.falsePositives}, fixed ${revResult.fixed}, uncertain ${revResult.uncertain}`,
      );
      if (revResult.limitReached) {
        const kind =
          opts.maxCostUsd !== undefined && totalCostUsd >= opts.maxCostUsd ? "cost" : "duration";
        throw new ReviewLimitError(
          kind,
          `Revalidation stopped by ${kind} limit at a resumable checkpoint.`,
        );
      }
    }

    // ── Result ─────────────────────────────────────────────────────────────
    const exitCode: ReviewExitCode = netNew > 0 ? 1 : 0;
    return {
      exitCode,
      runId,
      projectId,
      stats: {
        filesScanned,
        candidatesFound,
        findingsCount: netNew,
        netNewFindings: netNew,
        truePositives: tp,
        falsePositives: fp,
        totalCostUsd,
        coveragePassed,
      },
    };
  } catch (err) {
    if (err instanceof ReviewLimitError) {
      // deepsec exit-code-3 contract: the run stopped at a resumable
      // checkpoint. Records on disk are intact; interrupted files were
      // reverted to pending by the stage that hit the limit. Re-running the
      // same command continues where it stopped.
      log(`limit reached (${err.kind}): ${err.message}`);
      return {
        exitCode: 3,
        runId,
        projectId,
        stats: {
          filesScanned,
          candidatesFound,
          findingsCount: netNew,
          netNewFindings: netNew,
          truePositives: tp,
          falsePositives: fp,
          totalCostUsd,
          coveragePassed,
        },
      };
    }
    throw err;
  }
}

export type { ReviewRevalidationVerdict, LimitErrType };
