/**
 * `0sec lens-synth --miss-input <path>` — run the self-evolving lens loop.
 *
 *   miss capture → synthesize → independent corpus validation → durable
 *   promotion → next-review lens snapshot
 *
 * `--watch` follows atomic updates to one curated miss-input file. It runs once
 * for the initial revision, then only on content changes. `--promote` remains
 * explicit: without it, a watcher evaluates and reports candidates but writes
 * nothing. Active scans never reload their snapshot.
 *
 * The miss-input JSON supplies the two miss signals plus a positive and
 * negative-control corpus. A corpus is not inferred from a target: an
 * unverified or self-reported result is insufficient promotion evidence.
 *
 * Exit codes: 0 = a requested action completed; 3 = malformed input, unsafe
 * registry state, or invalid flags.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Command } from "commander";
import {
  inspectLensRegistry,
  makeFinderLensProbe,
  retireArchetype,
  runLensSynthesisLoop,
  type LensProbe,
  type LensSynthesisInput,
  type LensSynthesisModel,
  type LensSynthesisResult,
  type LensRegistryStatus,
  type MissInput,
  type ValidationCorpus,
  type ValidationFixture,
} from "@0sec/core";

// ── Miss-input parsing (defensive) ────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseFixtures(value: unknown, label: string): ValidationFixture[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value.map((entry, i) => {
    if (!isRecord(entry)) throw new Error(`${label}[${i}] must be an object`);
    const id = entry.id;
    const path = entry.path;
    if (typeof id !== "string" || id.trim() === "") throw new Error(`${label}[${i}].id must be a non-empty string`);
    if (typeof path !== "string" || path.trim() === "") throw new Error(`${label}[${i}].path must be a non-empty string`);
    return { id, path, ...(typeof entry.note === "string" ? { note: entry.note } : {}) };
  });
}

/** Validate + normalize the miss-input file into a {@link LensSynthesisInput}. */
export function parseMissInputFile(raw: unknown): LensSynthesisInput {
  if (!isRecord(raw)) throw new Error("miss-input must be a JSON object");
  const missesRaw = isRecord(raw.misses) ? raw.misses : {};
  const corpusRaw = isRecord(raw.corpus) ? raw.corpus : {};

  const misses: MissInput = {
    ...(Array.isArray(missesRaw.confirmedMisses) ? { confirmedMisses: missesRaw.confirmedMisses as MissInput["confirmedMisses"] } : {}),
    ...(Array.isArray(missesRaw.incompleteCoverage) ? { incompleteCoverage: missesRaw.incompleteCoverage as MissInput["incompleteCoverage"] } : {}),
  };
  const corpus: ValidationCorpus = {
    positives: parseFixtures(corpusRaw.positives, "corpus.positives"),
    negativeControls: parseFixtures(corpusRaw.negativeControls, "corpus.negativeControls"),
  };
  if (corpus.positives.length === 0) {
    throw new Error("corpus.positives must contain at least one fixture (the seeded miss) — the loop is fail-closed without it");
  }
  return { misses, corpus };
}

// ── Command core (injectable for tests) ───────────────────────────────────

export interface LensSynthCommandOptions {
  missInput: string;
  registry?: string;
  maxRegister?: number;
  model?: string;
  promote?: boolean;
}

export interface LensSynthCommandDeps {
  /** Override the synthesis model (tests inject a fake). */
  model?: LensSynthesisModel;
  /** Override the validation probe (tests inject a fake). */
  probe?: LensProbe;
  log?: (msg: string) => void;
}

export interface LensSynthWatchOptions extends LensSynthCommandOptions {
  pollIntervalMs?: number;
}

export interface LensSynthWatchDeps extends LensSynthCommandDeps {
  signal?: AbortSignal;
  sleep?: (milliseconds: number) => Promise<void>;
  onResult?: (result: LensSynthesisResult) => void;
  onError?: (error: Error) => void;
}

/**
 * Run the loop from a parsed, immutable input revision. The watcher uses this
 * form so the bytes it fingerprints are the bytes it validates and promotes.
 */
export async function runLensSynthesisInput(
  input: LensSynthesisInput,
  opts: Omit<LensSynthCommandOptions, "missInput">,
  deps: LensSynthCommandDeps = {},
): Promise<LensSynthesisResult> {
  const log = deps.log ?? (() => {});
  const probe = deps.probe ?? makeFinderLensProbe({ log });
  return runLensSynthesisLoop(input, {
    ...(deps.model ? { model: deps.model } : {}),
    ...(opts.model ? { modelId: opts.model } : {}),
    probe,
    ...(opts.registry ? { registryPath: resolve(opts.registry) } : {}),
    maxRegistrations: opts.maxRegister ?? 1,
    dryRun: !opts.promote,
    log,
  });
}

/**
 * Parse one miss-input revision and run the loop. Registration is dry-run by
 * default and requires an explicit promotion request.
 */
export async function runLensSynthCommand(
  opts: LensSynthCommandOptions,
  deps: LensSynthCommandDeps = {},
): Promise<LensSynthesisResult> {
  const raw = JSON.parse(readFileSync(resolve(opts.missInput), "utf8")) as unknown;
  return runLensSynthesisInput(parseMissInputFile(raw), opts, deps);
}

/**
 * Poll one curated input file. Polling is deliberate: atomic replace is the
 * supported producer protocol, and `fs.watch` can lose rename events across
 * editors, containers, and networked filesystems.
 */
export async function watchLensSynthCommand(
  opts: LensSynthWatchOptions,
  deps: LensSynthWatchDeps = {},
): Promise<void> {
  const inputPath = resolve(opts.missInput);
  const log = deps.log ?? (() => {});
  const requestedInterval = opts.pollIntervalMs ?? 2_000;
  const pollIntervalMs = Number.isFinite(requestedInterval)
    ? Math.max(100, Math.floor(requestedInterval))
    : 2_000;
  const sleep = deps.sleep ?? ((milliseconds: number) =>
    new Promise<void>((done) => setTimeout(done, milliseconds)));
  let previousRevision: string | undefined;

  while (!deps.signal?.aborted) {
    try {
      const bytes = readFileSync(inputPath);
      const revision = createHash("sha256").update(bytes).digest("hex");
      if (revision !== previousRevision) {
        previousRevision = revision;
        const input = parseMissInputFile(JSON.parse(bytes.toString("utf8")) as unknown);
        const result = await runLensSynthesisInput(input, opts, deps);
        deps.onResult?.(result);
      }
    } catch (cause) {
      const error = cause instanceof Error ? cause : new Error(String(cause));
      const revision = `error:${error.name}:${error.message}`;
      if (revision !== previousRevision) {
        previousRevision = revision;
        if (deps.onError) deps.onError(error);
        else log(`[lens-synth] input revision rejected: ${error.message}`);
      }
    }

    if (deps.signal?.aborted) return;
    const signal = deps.signal;
    if (!signal) {
      await sleep(pollIntervalMs);
      continue;
    }
    if (signal.aborted) return;
    await new Promise<void>((resume) => {
      const onAbort = () => {
        signal.removeEventListener("abort", onAbort);
        resume();
      };
      signal.addEventListener("abort", onAbort, { once: true });
      void sleep(pollIntervalMs).then(() => {
        signal.removeEventListener("abort", onAbort);
        resume();
      });
    });
  }
}

/** Human summary of a loop result. */
export function formatLensSynthResult(result: LensSynthesisResult, dryRun: boolean): string {
  const lines = [
    `captured ${result.candidatesCaptured} miss candidate(s) → ${result.clusters} cluster(s) → ${result.synthesized.length} synthesized`,
  ];
  for (const validation of result.validations) {
    lines.push(`  validate ${validation.lensId}: ${validation.passed ? "CHAMPION" : "rejected"} — ${validation.reason}`);
  }
  if (dryRun) {
    lines.push(`dry-run: ${result.validations.filter((validation) => validation.passed).length} champion(s) would register (nothing written)`);
  } else {
    lines.push(
      result.registered.length > 0
        ? `REGISTERED ${result.registered.length} lens(es): ${result.registered.map((registered) => registered.uid).join(", ")}`
        : "registered 0 lenses",
    );
  }
  for (const rejected of result.rejected) lines.push(`  rejected ${rejected.id}: ${rejected.reason}`);
  for (const warning of result.warnings) lines.push(`  warning: ${warning}`);
  return lines.join("\n");
}

export function formatLensRegistryStatus(status: LensRegistryStatus): string {
  const lines = [
    `registry: ${status.path}`,
    `state: ${status.valid ? "valid" : "INVALID"}`,
    `exists: ${status.exists ? "yes" : "no"}`,
    `active lenses: ${status.activeLensCount}`,
    `ledger entries: ${status.ledgerEntries}`,
    `unbound archetypes: ${status.unboundArchetypes}`,
  ];
  if (status.error) lines.push(`error: ${status.error}`);
  return lines.join("\n");
}

// ── Commander wiring ──────────────────────────────────────────────────────

type LensSynthCliOptions = {
  missInput?: string;
  registry?: string;
  maxRegister?: number;
  model?: string;
  promote?: boolean;
  watch?: boolean;
  pollInterval?: string;
  status?: boolean;
  rollback?: string;
  json?: boolean;
};

export function registerLensSynthCommand(program: Command): void {
  program
    .command("lens-synth")
    .description("Evolve appsec finder coverage from curated misses; promotion is corpus-gated and active reviews stay pinned")
    .option("--miss-input <path>", "curated miss-input JSON ({ misses, corpus })")
    .option("--registry <path>", "durable overlay path (default: ~/.0sec/lenses/appsec-archetypes.json)")
    .option("--max-register <n>", "cap promoted champions per input revision", (value) => Number.parseInt(value, 10))
    .option("-m, --model <id>", "synthesis model override")
    .option("--promote", "persist a validated champion to the durable overlay", false)
    .option("--watch", "poll the miss-input and process each new content revision", false)
    .option("--poll-interval <ms>", "watch polling interval (minimum 100ms)", "2000")
    .option("--status", "show the active durable overlay and promotion ledger", false)
    .option("--rollback <lens-id>", "retire one previously promoted overlay lens")
    .option("--json", "print machine-readable output", false)
    .action(async (opts: LensSynthCliOptions) => {
      try {
        const registry = opts.registry ? resolve(opts.registry) : undefined;
        if (opts.status && opts.rollback) throw new Error("--status and --rollback cannot be combined");
        if (opts.status) {
          const status = inspectLensRegistry(registry);
          process.stdout.write(opts.json ? `${JSON.stringify(status, null, 2)}\n` : `${formatLensRegistryStatus(status)}\n`);
          if (!status.valid) process.exitCode = 3;
          return;
        }
        if (opts.rollback) {
          const outcome = retireArchetype(String(opts.rollback), { ...(registry ? { registryPath: registry } : {}) });
          process.stdout.write(
            opts.json
              ? `${JSON.stringify(outcome, null, 2)}\n`
              : outcome.retired
                ? `RETIRED ${outcome.id} from ${outcome.registryPath}\n`
                : `not retired ${outcome.id}: ${outcome.reason ?? "unknown reason"}\n`,
          );
          if (!outcome.retired) process.exitCode = 3;
          return;
        }
        if (!opts.missInput) throw new Error("--miss-input is required unless --status or --rollback is used");
        if (opts.maxRegister !== undefined && (!Number.isInteger(opts.maxRegister) || opts.maxRegister < 0)) {
          throw new Error("--max-register must be a non-negative integer");
        }
        const pollIntervalMs = Number.parseInt(opts.pollInterval ?? "2000", 10);
        if (!Number.isInteger(pollIntervalMs) || pollIntervalMs < 100) {
          throw new Error("--poll-interval must be an integer of at least 100ms");
        }
        const request: LensSynthCommandOptions = {
          missInput: String(opts.missInput),
          ...(registry ? { registry } : {}),
          ...(opts.maxRegister !== undefined ? { maxRegister: opts.maxRegister } : {}),
          ...(opts.model ? { model: String(opts.model) } : {}),
          promote: Boolean(opts.promote),
        };
        const printResult = (result: LensSynthesisResult): void => {
          process.stdout.write(
            opts.json
              ? `${JSON.stringify(result, null, 2)}\n`
              : `${formatLensSynthResult(result, !opts.promote)}\n`,
          );
        };
        const log = (message: string): void => {
          process.stderr.write(`${message}\n`);
        };

        if (!opts.watch) {
          printResult(await runLensSynthCommand(request, { log }));
          return;
        }

        const controller = new AbortController();
        const stop = (): void => controller.abort();
        process.once("SIGINT", stop);
        process.once("SIGTERM", stop);
        try {
          await watchLensSynthCommand(
            { ...request, pollIntervalMs },
            {
              log,
              signal: controller.signal,
              onResult: printResult,
              onError: (error) => process.stderr.write(`lens-synth watch: ${error.message}\n`),
            },
          );
        } finally {
          process.off("SIGINT", stop);
          process.off("SIGTERM", stop);
        }
      } catch (error) {
        process.stderr.write(`lens-synth: ${error instanceof Error ? error.message : String(error)}\n`);
        process.exitCode = 3;
      }
    });
}
