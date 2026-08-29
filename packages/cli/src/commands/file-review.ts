// `0sec file-review` — the deepsec-pattern whole-repo review harness:
// free regex scan → coverage gate → batched AI investigation with refusal
// audit + field repair → optional static revalidation, with global cost and
// duration caps that stop at a resumable checkpoint (exit code 3).
//
// Exit codes follow the deepsec contract: 0 clean, 1 findings, 3 limit
// reached (re-run the same command to resume).

import type { Command } from "commander";
import { resolve } from "node:path";
import { createRuntime, runFileReviewPipeline } from "@0sec/core";
import type { Runtime, ReviewInvoker } from "@0sec/core";

interface FileReviewOpts {
  projectId?: string;
  dataDir?: string;
  runtime?: string;
  model?: string;
  timeout?: string;
  maxCostUsd?: string;
  maxDuration?: string;
  batchSize?: string;
  concurrency?: string;
  inventory?: boolean;
  revalidate?: boolean;
  json?: boolean;
}

/** Parse `2h` / `45m` / `90s` / plain-ms into milliseconds. */
function parseDurationMs(raw: string): number {
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h)?$/.exec(raw.trim());
  if (!m) throw new Error(`invalid duration '${raw}' — use e.g. 30m, 2h, 500ms`);
  const value = Number(m[1]);
  const unit = m[2] ?? "ms";
  const factor: Record<string, number> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000 };
  return Math.round(value * factor[unit]);
}

function parsePositiveInteger(raw: string, option: "--batch-size" | "--concurrency"): number {
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`Invalid ${option} '${raw}': must be a positive integer.`);
  }
  return value;
}

function buildInvoker(runtime: Runtime, model?: string): ReviewInvoker {
  return async (prompt: string, _label: string) => {
    const result = await runtime.execute(prompt);
    return {
      output: result.output,
      usage: result.usage,
      durationMs: result.durationMs,
      model,
    };
  };
}

export function registerFileReviewCommand(program: Command): void {
  program
    .command("file-review <target>")
    .description(
      "Whole-repo file-level security review: regex scan → coverage gate → batched AI " +
        "investigation (refusal audit, field repair) → optional static revalidation. " +
        "Resumable: exit code 3 means a cost/duration limit stopped the run at a " +
        "checkpoint — re-run the same command to continue.",
    )
    .option("--project-id <id>", "Project id (defaults to the target basename)")
    .option("--data-dir <path>", "Record store directory (default <target>/.0sec-review)")
    .option("--runtime <mode>", "Engine runtime: api|claude|codex|gemini|ollama (default api)")
    .option("-m, --model <model>", "Model for the investigation/revalidation agents")
    .option("--timeout <ms>", "Per-invocation timeout in milliseconds", "600000")
    .option("--max-cost-usd <usd>", "Hard USD cap for the whole run (resumable stop)")
    .option("--max-duration <dur>", "Wall-clock cap: 30m / 2h / ms (resumable stop)")
    .option("--batch-size <n>", "Files per investigation batch (default 5)")
    .option("--concurrency <n>", "Batches in flight (default 2)")
    .option("--inventory", "Generate the AI surface inventory + INFO.md first (requires claude, codex, or gemini)")
    .option("--revalidate", "Run the static adversarial revalidation on HIGH+ findings")
    .option("--json", "Emit the pipeline result as JSON")
    .action(async (target: string, opts: FileReviewOpts) => {
      const rootPath = resolve(target);
      const rtType = ((opts.runtime ?? "api") === "auto" ? "api" : (opts.runtime ?? "api")) as
        | "api" | "claude" | "codex" | "gemini" | "ollama";
      if (opts.inventory && (rtType === "api" || rtType === "ollama")) {
        console.error(
          "--inventory requires --runtime claude, codex, or gemini so the agent can inspect repository files.",
        );
        process.exitCode = 2;
        return;
      }
      const runtime = createRuntime({
        type: rtType,
        timeout: opts.timeout ? parseInt(opts.timeout, 10) : 600_000,
        model: opts.model,
        cwd: rootPath,
      });

      const log = (msg: string): void => {
        process.stderr.write(`[file-review] ${msg}\n`);
      };

      let maxCostUsd: number | undefined;
      if (opts.maxCostUsd !== undefined) {
        maxCostUsd = Number(opts.maxCostUsd);
        if (!Number.isFinite(maxCostUsd) || maxCostUsd <= 0) {
          console.error(`Invalid --max-cost-usd '${opts.maxCostUsd}': must be a positive number.`);
          process.exitCode = 2;
          return;
        }
      }
      let maxDurationMs: number | undefined;
      let batchSize: number | undefined;
      let concurrency: number | undefined;
      try {
        if (opts.maxDuration !== undefined) {
          maxDurationMs = parseDurationMs(opts.maxDuration);
        }
        if (opts.batchSize !== undefined) {
          batchSize = parsePositiveInteger(opts.batchSize, "--batch-size");
        }
        if (opts.concurrency !== undefined) {
          concurrency = parsePositiveInteger(opts.concurrency, "--concurrency");
        }
      } catch (err) {
        console.error((err as Error).message);
        process.exitCode = 2;
        return;
      }

      const result = await runFileReviewPipeline({
        rootPath,
        projectId: opts.projectId,
        dataDir: opts.dataDir,
        invoker: buildInvoker(runtime, opts.model),
        withInventory: opts.inventory === true,
        withRevalidate: opts.revalidate === true,
        maxCostUsd,
        maxDurationMs,
        batchSize,
        concurrency,
        model: opts.model,
        log,
      });

      if (opts.json) {
        process.stdout.write(JSON.stringify(result, null, 2) + "\n");
      } else {
        const s = result.stats;
        log(
          `done: ${s.filesScanned} files scanned, ${s.candidatesFound} candidates, ` +
            `${s.netNewFindings} new finding(s) (TP ${s.truePositives} / FP ${s.falsePositives} after revalidate), ` +
            `$${s.totalCostUsd.toFixed(4)} spent${s.coveragePassed !== undefined ? `, coverage ${s.coveragePassed ? "passed" : "FAILED"}` : ""}`,
        );
        if (result.exitCode === 3) {
          log("stopped at a cost/duration limit — re-run the same command to resume.");
        }
      }
      process.exitCode = result.exitCode;
    });
}
