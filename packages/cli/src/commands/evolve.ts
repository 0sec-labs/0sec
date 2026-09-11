/**
 * `0sec evolve` — Autonomous self-improvement: source-candidate proposal,
 * lens evaluation, durable feedback, and automatic promotion with canary
 * and rollback.
 *
 * Subcommands:
 *
 *   0sec evolve run           --config <path>    [--watch] [--json]
 *                              [--auto-promote]  [--allow-source-access]
 *   0sec evolve status        [--store <path>]   [--json]
 *   0sec evolve rollback      --store <path>     --version <id> [--reason <text>]
 *   0sec evolve exec          --config <path>    --run-id <id>  --input <json>
 *                              [--json]
 *   0sec evolve feedback capture   --source <hunt-scan|deep-review> [--reason <text>]
 *   0sec evolve feedback approve   --id <feedback-id>
 *   0sec evolve feedback status    [--json]
 *
 * Error codes:
 *   0  — success
 *   1  — user error (bad args, missing config, bad input)
 *   2  — runtime error (evaluation failure, budget exceeded, I/O error)
 *   3  — AbortSignal (user interrupt)
 */

import { readFileSync, existsSync, realpathSync } from "node:fs";
import { resolve, sep } from "node:path";
import type { Command } from "commander";
import chalk from "chalk";
import type {
  EvolutionConfig,
  EvolutionRegistry,
  EvolutionRunResult,
  EvolutionExecution,
} from "@0sec/core";
import {
  parseEvolutionConfig,
  runEvolution,
  executeEvolutionVersion,
  approveEvolutionCandidate,
  loadEvolutionRegistry,
  captureObservation,
  approveObservation,
  listObservations,
  releaseClaim,
  parseObservationInput,
  parseApprovedObservationShape,
  rollbackEvolutionVersion as rollbackEvolutionRegistryVersion,
} from "@0sec/core";


// ── Exit codes ──────────────────────────────────────────────────────────────

const EXIT_OK = 0;
const EXIT_USER_ERROR = 1;
const EXIT_RUNTIME_ERROR = 2;
const EXIT_INTERRUPT = 3;


// ── Helpers ──────────────────────────────────────────────────────────────────

export function loadEvolutionConfigFile(path: string): EvolutionConfig {
  const absPath = resolve(path);
  if (!existsSync(absPath)) throw new Error(`config file not found: ${absPath}`);
  const configFile = realpathSync(absPath);
  const raw = JSON.parse(readFileSync(absPath, "utf8"));
  const config = parseEvolutionConfig(raw, resolve(path, ".."));
  for (const source of config.sourcePaths) {
    const sourcePath = resolve(config.sourceRoot, source);
    const selected = existsSync(sourcePath) ? realpathSync(sourcePath) : sourcePath;
    if (configFile === selected || configFile.startsWith(`${selected}${sep}`)) {
      throw new Error("evolution config contains private answers and must be outside selected source paths");
    }
  }
  return config;
}

function formatRegistryStatus(registry: EvolutionRegistry, json: boolean, out: (line: string) => void): void {
  if (json) {
    out(JSON.stringify(registry, null, 2));
    return;
  }

  const active = registry.activeId
    ? registry.versions.find((v) => v.id === registry.activeId)
    : null;
  const canary = registry.canaryId
    ? registry.versions.find((v) => v.id === registry.canaryId)
    : null;

  out(chalk.bold("Evolution Status"));
  out(chalk.dim("━━━━━━━━━━━━━━━━━━━"));

  if (active) {
    out(`  ${chalk.green("Active:")}   ${active.id} (kind: ${active.kind}, status: ${active.status})`);
    out(`              parent: ${active.parentId ?? "none"}`);
    out(`              created: ${active.createdAt}`);
  } else {
    out(`  ${chalk.dim("Active:")}   none`);
  }

  if (canary) {
    out(`  ${chalk.yellow("Canary:")}  ${canary.id} (kind: ${canary.kind}, status: ${canary.status})`);
    out(`              parent: ${canary.parentId ?? "none"}`);
    out(`              created: ${canary.createdAt}`);
  } else {
    out(`  ${chalk.dim("Canary:")}    none`);
  }

  out(`  ${chalk.dim("Versions:")} ${registry.versions.length}`);
  out(`  ${chalk.dim("Events:")}   ${registry.events.length}`);
  out(chalk.dim("  Evaluation: canaries repeat the configured corpus; passing does not establish fresh-corpus generalization."));

  if (registry.events.length > 0) {
    out("");
    out(chalk.bold("Recent Events"));
    out(chalk.dim("━━━━━━━━━━━━━━━━━━━"));
    for (const event of registry.events.slice(-5)) {
      const typeLabel = event.type === "promoted" ? chalk.green("promoted")
        : event.type === "rolled_back" ? chalk.red("rolled back")
        : event.type === "canary_started" ? chalk.yellow("canary started")
        : chalk.dim("recorded");
      out(`  ${typeLabel} ${event.versionId.slice(0, 12)}… — ${event.reason}`);
    }
  }
}

function formatEvaluationResult(
  result: EvolutionRunResult,
  json: boolean,
  out: (line: string) => void,
): void {
  if (json) {
    out(JSON.stringify(result, null, 2));
    return;
  }

  out("");
  out(chalk.bold("Evolution Run Result"));
  out(chalk.dim("━━━━━━━━━━━━━━━━━━━━━━"));

  for (let i = 0; i < result.iterations.length; i++) {
    const iteration = result.iterations[i]!;
    const stateIcon = iteration.state === "promoted" ? chalk.green("✓")
      : iteration.state === "rejected" ? chalk.red("✗")
      : iteration.state === "rolled_back" ? chalk.red("↩")
      : chalk.yellow("○");

    out(`  ${stateIcon} Iteration ${i + 1}: ${iteration.candidateId}`);
    out(`     State:    ${iteration.state}`);
    out(`     Decision: ${iteration.decision.status}`);
    if (iteration.rationale) out(`     Rationale: ${iteration.rationale.slice(0, 120)}`);
    if (iteration.receiptPath) out(`     Receipt:  ${iteration.receiptPath}`);
  }

  out("");
  out(`  ${chalk.dim("Active version:")} ${result.activeVersionId ?? "none"}`);
  out(`  ${chalk.dim("Model cost:")}     $${result.modelCostUsd.toFixed(4)}`);
  out(`  ${chalk.dim("Evaluation cost:")} $${result.evaluationCostUsd.toFixed(4)}`);
}

function formatExecResult(
  versionId: string,
  execution: { versionId: string; execution: EvolutionExecution },
  json: boolean,
  out: (line: string) => void,
): void {
  if (json) {
    out(JSON.stringify(execution, null, 2));
    return;
  }

  out("");
  out(chalk.bold(`Execution: ${versionId.slice(0, 12)}…`));
  out(chalk.dim("━━━━━━━━━━━━━━━━━━━━━━━━━"));
  out(`  ${chalk.dim("Exit code:")}  ${execution.execution.exitCode ?? "null"}`);
  out(`  ${chalk.dim("Duration:")}   ${execution.execution.durationMs}ms`);
  out(`  ${chalk.dim("Timed out:")}  ${execution.execution.timedOut}`);

  if (execution.execution.error) {
    out(`  ${chalk.red("Error:")}     ${execution.execution.error}`);
  }

  if (execution.execution.stdout) {
    out("");
    out(chalk.dim("── stdout ──"));
    const lines = execution.execution.stdout.split("\n");
    const display = lines.length > 30
      ? [...lines.slice(0, 15), chalk.dim(`… ${lines.length - 30} more lines …`), ...lines.slice(-15)]
      : lines;
    for (const line of display) out(`  ${line}`);
  }

  if (execution.execution.stderr) {
    out("");
    out(chalk.dim("── stderr ──"));
    const lines = execution.execution.stderr.split("\n");
    const display = lines.length > 30
      ? [...lines.slice(0, 15), chalk.dim(`… ${lines.length - 30} more lines …`), ...lines.slice(-15)]
      : lines;
    for (const line of display) out(`  ${line}`);
  }
}

// ── Commander wiring ─────────────────────────────────────────────────────────

export function registerEvolveCommand(program: Command): void {
  const evolve = program
    .command("evolve")
    .description("Autonomous self-improvement: source-candidate proposal, lens evaluation, and automatic promotion");

  // ── run ────────────────────────────────────────────────────────────────────

  evolve
    .command("run")
    .description("Propose, independently evaluate, and optionally promote future workers")
    .requiredOption("--config <path>", "Path to evolution config JSON file")
    .option("--watch", "Repeat until stable, budget exhausted, a failure, or interruption")
    .option("--json", "Output JSON (one result per line in watch mode)")
    .option("--auto-promote", "Enable automatic promotion")
    .option("--no-auto-promote", "Disable automatic promotion")
    .option("--allow-source-access", "Allow sending selected source to the model")
    .option("--no-allow-source-access", "Deny model source access")
    .option("--max-passes <number>", "Maximum watch passes (default: budget-limited)", Number)
    .action(async (opts: {
      config: string; watch?: boolean; json?: boolean;
      autoPromote?: boolean; allowSourceAccess?: boolean; maxPasses?: number;
    }) => {
      const out = (line: string) => console.log(line);
      const err = (line: string) => console.error(line);
      const abortController = new AbortController();
      const onInterrupt = () => {
        err(chalk.yellow("\nEvolution interrupted; cancelling the current pass."));
        abortController.abort();
        process.removeListener("SIGINT", onInterrupt);
      };
      try {
        if (opts.maxPasses !== undefined && (!Number.isSafeInteger(opts.maxPasses) || opts.maxPasses < 1)) {
          throw new Error("--max-passes must be a positive integer");
        }
        const rawConfig = loadEvolutionConfigFile(opts.config);
        const config: EvolutionConfig = {
          ...rawConfig,
          ...(opts.autoPromote !== undefined ? { autoPromote: opts.autoPromote } : {}),
          ...(opts.allowSourceAccess !== undefined ? { allowModelSourceAccess: opts.allowSourceAccess } : {}),
        };
        let modelCost = 0;
        let evaluationCost = 0;
        const maxPasses = opts.watch ? (opts.maxPasses ?? Infinity) : 1;
        process.on("SIGINT", onInterrupt);
        for (let pass = 0; pass < maxPasses && !abortController.signal.aborted; pass++) {
          const passConfig: EvolutionConfig = {
            ...config,
            maxModelCostUsd: Math.max(0, config.maxModelCostUsd - modelCost),
            maxEvaluationCostUsd: Math.max(0, config.maxEvaluationCostUsd - evaluationCost),
          };
          if (passConfig.maxModelCostUsd <= 0 || passConfig.maxEvaluationCostUsd <= 0) {
            err(chalk.yellow("Evolution budget exhausted."));
            break;
          }
          if (opts.watch && !opts.json) out(chalk.dim(`Pass ${pass + 1}`));
          // A failed pass may already have incurred model charges. Stop rather
          // than retrying with an unchanged budget and concealing that spend.
          const result = await runEvolution(passConfig, { signal: abortController.signal });
          modelCost += result.modelCostUsd;
          evaluationCost += result.evaluationCostUsd;
          if (opts.watch && opts.json) out(JSON.stringify(result));
          else formatEvaluationResult(result, Boolean(opts.json), out);
          if (result.iterations.length === 0) break;
        }
        process.exitCode = abortController.signal.aborted ? EXIT_INTERRUPT : EXIT_OK;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (opts.json) out(JSON.stringify({ error: message }));
        else err(chalk.red(`Evolution run failed: ${message}`));
        process.exitCode = abortController.signal.aborted ? EXIT_INTERRUPT : EXIT_RUNTIME_ERROR;
      } finally {
        process.removeListener("SIGINT", onInterrupt);
      }
    });

  // ── status ──────────────────────────────────────────────────────────────────

  evolve
    .command("status")
    .description("Show active and canary versions, snapshot identities, and registry events")
    .option("--store <path>", "Required path to evolution store directory")
    .option("--json", "Output structured JSON")
    .action(async (opts: { store?: string; json?: boolean }) => {
      try {
        const storePath = opts.store ? resolve(opts.store) : undefined;
        if (!storePath) {
          console.error(chalk.red("--store <path> is required. Point it to the evolution store directory containing registry.json."));
          process.exitCode = EXIT_USER_ERROR;
          return;
        }
        if (!existsSync(storePath)) {
          console.error(chalk.red(`store directory not found: ${storePath}`));
          process.exitCode = EXIT_USER_ERROR;
          return;
        }

        const registry = loadEvolutionRegistry(storePath);
        formatRegistryStatus(registry, Boolean(opts.json), (l) => console.log(l));
        process.exitCode = EXIT_OK;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (opts.json) {
          console.log(JSON.stringify({ error: message }, null, 2));
        } else {
          console.error(chalk.red(`Status error: ${message}`));
        }
        process.exitCode = EXIT_USER_ERROR;
      }
    });

  evolve
    .command("promote")
    .description("Approve an exact staged candidate after independent canary evaluation")
    .requiredOption("--store <path>", "Path to evolution store directory")
    .requiredOption("--version <id>", "Evaluated candidate ID to approve")
    .option("--json", "Output structured JSON")
    .action(async (opts: { store: string; version: string; json?: boolean }) => {
      const controller = new AbortController();
      const interrupt = () => controller.abort();
      process.once("SIGINT", interrupt);
      try {
        const result = await approveEvolutionCandidate(resolve(opts.store), opts.version, { signal: controller.signal });
        if (opts.json) console.log(JSON.stringify(result));
        else console.log(`Promoted ${result.versionId}; canary cost $${result.evaluationCostUsd.toFixed(4)}`);
        process.exitCode = EXIT_OK;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (opts.json) console.log(JSON.stringify({ error: message }));
        else console.error(chalk.red(`Promotion failed: ${message}`));
        process.exitCode = controller.signal.aborted ? EXIT_INTERRUPT : EXIT_RUNTIME_ERROR;
      } finally {
        process.removeListener("SIGINT", interrupt);
      }
    });

  // ── rollback ──────────────────────────────────────────────────────────────

  evolve
    .command("rollback")
    .description("Retire an active or canary evolution version and restore its parent")
    .requiredOption("--store <path>", "Path to evolution store directory")
    .requiredOption("--version <id>", "Active or canary version ID to retire")
    .option("--reason <text>", "Reason for rollback", "operator rollback")
    .action(async (opts: { store: string; version: string; reason: string }) => {
      try {
        const storePath = resolve(opts.store);
        if (!existsSync(storePath)) {
          console.error(chalk.red(`store directory not found: ${storePath}`));
          process.exitCode = EXIT_USER_ERROR;
          return;
        }

        const registry = loadEvolutionRegistry(storePath);
        const target = registry.versions.find((v) => v.id === opts.version);
        if (!target) {
          console.error(chalk.red(`version not found in registry: ${opts.version}`));
          process.exitCode = EXIT_USER_ERROR;
          return;
        }

        await rollbackEvolutionRegistryVersion(storePath, opts.version, opts.reason);

        console.log(chalk.green(`Retired ${opts.version.slice(0, 12)}…; restored ${loadEvolutionRegistry(storePath).activeId}`));
        console.log(`  Reason: ${opts.reason}`);
        process.exitCode = EXIT_OK;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(chalk.red(`Rollback failed: ${message}`));
        process.exitCode = EXIT_RUNTIME_ERROR;
      }
    });

  // ── exec ──────────────────────────────────────────────────────────────────

  evolve
    .command("exec")
    .description("Execute a pinned evolution version snapshot against an input")
    .requiredOption("--config <path>", "Path to evolution config JSON file (to determine store)")
    .requiredOption("--run-id <id>", "Evolution run ID to pin and execute the active snapshot from")
    .requiredOption("--input <json>", "JSON input to pass to the snapshot execution")
    .option("--json", "Output structured JSON instead of human-readable text")
    .action(async (opts: { config: string; runId: string; input: string; json?: boolean }) => {
      const out = (l: string) => console.log(l);
      const err = (l: string) => console.error(l);
      const abortController = new AbortController();
      const onInterrupt = () => {
        err(chalk.yellow("\nExecution interrupted; signalling the running worker."));
        abortController.abort();
        process.removeListener("SIGINT", onInterrupt);
        process.removeListener("SIGTERM", onInterrupt);
      };

      try {
        process.on("SIGINT", onInterrupt);
        process.on("SIGTERM", onInterrupt);
        const config = loadEvolutionConfigFile(opts.config);

        let input: unknown;
        try {
          input = JSON.parse(opts.input);
        } catch {
          throw new Error("--input must be a valid JSON string");
        }

        const executionResult = await executeEvolutionVersion(config, opts.runId, input, { signal: abortController.signal });

        const exec = executionResult.execution;
        const hasError = abortController.signal.aborted || exec.error !== undefined || exec.timedOut || exec.exitCode !== 0;
        if (hasError && !abortController.signal.aborted) {
          err(chalk.red(`Execution produced an error (exit code: ${exec.exitCode ?? "null"}, timedOut: ${exec.timedOut})`));
          if (exec.error) err(chalk.red(`  ${exec.error}`));
        }

        formatExecResult(executionResult.versionId, executionResult, Boolean(opts.json), out);
        process.exitCode = abortController.signal.aborted ? EXIT_INTERRUPT : hasError ? EXIT_RUNTIME_ERROR : EXIT_OK;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (opts.json) {
          out(JSON.stringify({ error: message }, null, 2));
        } else {
          err(chalk.red(`Exec failed: ${message}`));
        }
        process.exitCode = abortController.signal.aborted ? EXIT_INTERRUPT : EXIT_RUNTIME_ERROR;
      } finally {
        process.removeListener("SIGINT", onInterrupt);
        process.removeListener("SIGTERM", onInterrupt);
      }
    });

  // ── feedback ──────────────────────────────────────────────────────────────

  const feedback = evolve
    .command("feedback")
    .description("Capture, approve, and inspect evolution feedback candidates");

  feedback
    .command("capture")
    .description("Capture an evidence-backed observation from a JSON file; does not confirm a finding")
    .requiredOption("--input <path>", "Observation JSON file with source revision and evidence references")
    .option("--store <path>", "Feedback queue JSON file")
    .option("--allow-source-access", "Explicitly consent to source use for this observation")
    .action((opts: { input: string; store?: string; allowSourceAccess?: boolean }) => {
      try {
        const input = parseObservationInput(JSON.parse(readFileSync(resolve(opts.input), "utf8")));
        const result = captureObservation({ ...input, consent: opts.allowSourceAccess === true }, {
          ...(opts.store ? { storePath: resolve(opts.store) } : {}),
        });
        console.log(JSON.stringify(result, null, 2));
        process.exitCode = EXIT_OK;
      } catch (error) {
        console.error(chalk.red(`Feedback capture failed: ${error instanceof Error ? error.message : String(error)}`));
        process.exitCode = EXIT_RUNTIME_ERROR;
      }
    });

  feedback
    .command("approve")
    .description("Approve independent positive, held-out, and negative fixtures for an observation")
    .requiredOption("--id <feedback-id>", "Full observation ID")
    .requiredOption("--fixtures <path>", "Curation JSON containing positives, heldOut, and negativeControls")
    .option("--store <path>", "Feedback queue JSON file")
    .option("--allow-source-access", "Explicitly consent to source use for synthesis")
    .action((opts: { id: string; fixtures: string; store?: string; allowSourceAccess?: boolean }) => {
      try {
        const shape = parseApprovedObservationShape(JSON.parse(readFileSync(resolve(opts.fixtures), "utf8")));
        const result = approveObservation(opts.id, shape, {
          ...(opts.store ? { storePath: resolve(opts.store) } : {}),
          ...(opts.allowSourceAccess === true ? { allowModelSourceAccess: true } : {}),
        });
        if (!result) throw new Error("observation was not found or is not pending");
        console.log(JSON.stringify(result, null, 2));
        process.exitCode = EXIT_OK;
      } catch (error) {
        console.error(chalk.red(`Feedback approval failed: ${error instanceof Error ? error.message : String(error)}`));
        process.exitCode = EXIT_RUNTIME_ERROR;
      }
    });

  feedback
    .command("release")
    .description("Release a stale processing claim after its worker has stopped")
    .requiredOption("--id <feedback-id>", "Full observation ID")
    .requiredOption("--claim-token <token>", "Exact claim token shown by feedback status --json")
    .option("--store <path>", "Feedback queue JSON file")
    .action((opts: { id: string; claimToken: string; store?: string }) => {
      try {
        if (!releaseClaim(opts.id, opts.claimToken, opts.store ? { storePath: resolve(opts.store) } : {})) {
          throw new Error("observation or processing claim no longer matches");
        }
        console.log(`Released feedback claim ${opts.id}`);
        process.exitCode = EXIT_OK;
      } catch (error) {
        console.error(`Feedback release failed: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = EXIT_USER_ERROR;
      }
    });

  feedback
    .command("status")
    .description("Show retained observations and their approval/processing status")
    .option("--store <path>", "Feedback queue JSON file")
    .option("--json", "Output structured JSON")
    .action((opts: { store?: string; json?: boolean }) => {
      try {
        const observations = listObservations(undefined, { ...(opts.store ? { storePath: resolve(opts.store) } : {}) });
        if (opts.json) console.log(JSON.stringify(observations, null, 2));
        else if (observations.length === 0) console.log("No feedback observations.");
        else for (const observation of observations) console.log(`${observation.id}  ${observation.status}  ${observation.classHint}`);
        process.exitCode = EXIT_OK;
      } catch (error) {
        console.error(chalk.red(`Feedback status failed: ${error instanceof Error ? error.message : String(error)}`));
        process.exitCode = EXIT_RUNTIME_ERROR;
      }
    });
}