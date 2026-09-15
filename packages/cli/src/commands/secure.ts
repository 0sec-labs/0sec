import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { InvalidArgumentError } from "commander";
import type { Command } from "commander";
import { runSecureProject } from "@0sec/core";
import type { SecureEvent, SecureProjectResult } from "@0sec/core";

interface SecureOptions {
  testCommand: string;
  setupCommand?: string;
  stateDir?: string;
  runtime: string;
  model?: string;
  timeout: number;
  costCeiling?: number;
  maxFindings: number;
  maxAttempts: number;
  maxTurns: number;
  resume: boolean;
  publish: boolean;
  format: string;
}

function positiveInteger(value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new InvalidArgumentError("Must be a positive integer.");
  }
  return parsed;
}

function positiveAmount(value: string): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new InvalidArgumentError("Must be a positive finite dollar amount.");
  }
  return parsed;
}

export function registerSecureCommand(program: Command): void {
  program.command("secure")
    .description("Investigate, reproduce, repair, test, and independently verify a repository; retain evidence and optionally open repair PRs")
    .argument("<repo>", "Local Git repository or HTTPS Git URL; execution occurs in the current worker, not a newly provisioned sandbox")
    .requiredOption("--test-command <command>", "Operator-approved regression command; must pass before and after repair")
    .option("--setup-command <command>", "Operator-approved setup/build command run in each disposable checkout")
    .option("--state-dir <path>", "Private persistent run directory; required when resuming")
    .option("--runtime <runtime>", "Native repair runtime: auto or api", "api")
    .option("-m, --model <model>", "Model for investigation and repair; inherits configured provider when omitted")
    .option("--timeout <ms>", "Whole workflow deadline in milliseconds", positiveInteger, 3_600_000)
    .option("--cost-ceiling <usd>", "Whole workflow model cost ceiling in USD", positiveAmount)
    .option("--max-findings <n>", "Maximum findings to repair; remaining findings keep the run blocked", positiveInteger, 10)
    .option("--max-attempts <n>", "Maximum repair candidates per finding", positiveInteger, 3)
    .option("--max-turns <n>", "Maximum model turns per repair phase", positiveInteger, 30)
    .option("--resume", "Resume compatible persisted work; never blindly replay publication", false)
    .option("--publish", "Publish verified patches as PRs using authorized repository credentials; never merge or deploy", false)
    .option("--format <format>", "Output format: json", "json")
    .action(async (repo: string, options: SecureOptions) => {
      if (options.format !== "json") throw new InvalidArgumentError("--format must be json.");
      if (!["api", "auto"].includes(options.runtime)) throw new InvalidArgumentError("--runtime must be api or auto.");
      if (!options.testCommand.trim()) throw new InvalidArgumentError("--test-command cannot be blank.");
      if (options.setupCommand !== undefined && !options.setupCommand.trim()) throw new InvalidArgumentError("--setup-command cannot be blank.");
      if (options.resume && !options.stateDir) throw new InvalidArgumentError("--resume requires --state-dir.");
      const stateDir = resolve(options.stateDir ?? join(homedir(), ".0sec", "secure", randomUUID()));
      const controller = new AbortController();
      const cancel = () => controller.abort(new Error("Workflow cancelled by operator"));
      process.once("SIGINT", cancel);
      process.once("SIGTERM", cancel);
      const cloudOutput = process.env["0SEC_EMIT_RESULT_LINE"] === "1" || Boolean(process.env["0SEC_CLOUD_SINK"]);
      const onEvent = (event: SecureEvent) => {
        if (cloudOutput) process.stdout.write(`0SEC_SECURE_EVENT=${JSON.stringify(event)}\n`);
        else process.stderr.write(`[secure:${event.phase}] ${event.message}\n`);
      };
      try {
        const result: SecureProjectResult = await runSecureProject({
          repoRoot: repo,
          stateDir,
          testCommand: options.testCommand,
          setupCommand: options.setupCommand,
          runtime: options.runtime as "api" | "auto",
          model: options.model,
          timeoutMs: options.timeout,
          costCeilingUsd: options.costCeiling,
          maxFindings: options.maxFindings,
          maxAttempts: options.maxAttempts,
          maxTurns: options.maxTurns,
          resume: options.resume,
          publish: options.publish,
          signal: controller.signal,
          onEvent,
        });
        process.stdout.write(cloudOutput
          ? `0SEC_RESULT=${JSON.stringify(result)}\n`
          : `${JSON.stringify(result, null, 2)}\n`);
        process.exitCode = { completed: 0, blocked: 2, failed: 3, cancelled: 130 }[result.status];
      } finally {
        process.removeListener("SIGINT", cancel);
        process.removeListener("SIGTERM", cancel);
      }
    });
}
