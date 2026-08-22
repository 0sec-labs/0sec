/**
 * 0sec#194 — `0sec verify` command.
 *
 * Wraps `executePocSteps` (the deterministic-replay runtime introduced in
 * 0sec#171, see `packages/core/src/disclose/poc-runtime.ts`) behind a
 * single CLI surface so cloud's worker-controller (0sec-cloud#193) can
 * shell out to the OSS engine instead of re-implementing replay logic
 * in-process.
 *
 * Contract:
 *   - Read a {@link Finding} from `--finding <path>`.
 *   - Optionally read a {@link PocExecutionTarget} from `--target <path>`.
 *   - Run the finding's `pocSteps` (if any) via `executePocSteps`.
 *   - Emit a JSON {@link VerificationResult} to stdout (or to `--output`).
 *   - Exit 0 (reproduced) / 1 (not_reproduced) / 2 (skipped) / 3 (error).
 *
 * Bundle support (`--finding-id <id> --bundle <zip>`) is reserved for a
 * follow-up; the proposed flag is parsed and rejected explicitly so the
 * cloud side can detect engine capability without a silent miss.
 */

import type { Command } from "commander";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  executePocSteps,
  runCliPathTraversalReplayFixture,
  runDeterministicReplay,
  LocalShellRunner,
  DockerRunner,
  QemuRunner,
  VerifyNotImplementedError,
  evidenceKindForFinding,
  oracleForCategory,
  type PocExecutionReport,
  type PocExecutionTarget,
  type PocStepResult,
  type VerifyEvidenceKind,
} from "@0sec/core";
import type {
  EvidenceArtifact,
  Finding,
  PocStep,
  VerificationAssertion,
  VerificationCommand,
  VerificationResult as SharedVerificationResult,
  VerificationStatus as SharedVerificationStatus,
} from "@0sec/shared";
import {
  VERSION,
  VerificationResultSchema,
} from "@0sec/shared";
import { z } from "zod";
import { findingSchema, formatZodError } from "./schemas.js";

// ── Public output schema ────────────────────────────────────────────────────

export type VerificationStatus = SharedVerificationStatus;
export type VerificationResult = SharedVerificationResult;

// ── Tunables ────────────────────────────────────────────────────────────────

/** stdout/stderr excerpt cap in the emitted JSON. The runtime caps captures at
 *  1 MiB; the verifier's JSON is meant to be log-sized, so re-cap at 4 KiB
 *  per stream. Cloud-side ingestion can always re-fetch the full bundle. */
export const EXCERPT_BYTES = 4 * 1024;

// ── Pure helpers (exported for unit tests) ──────────────────────────────────

/** Truncate to N bytes with a trailing marker if cut. */
export function excerpt(text: string | undefined, max = EXCERPT_BYTES): string {
  if (!text) return "";
  if (text.length <= max) return text;
  return text.slice(0, max) + "…[truncated]";
}

/** Map `PocOverallVerdict` → public `VerificationStatus`. */
export function statusFromVerdict(
  verdict: PocExecutionReport["overallVerdict"],
): VerificationStatus {
  switch (verdict) {
    case "exploit_still_works":
      return "reproduced";
    case "exploit_broken":
      return "not_reproduced";
    case "could_not_run":
      return "skipped";
    default: {
      const _exhaustive: never = verdict;
      void _exhaustive;
      return "skipped";
    }
  }
}

/** Map `VerificationStatus` → process exit code per 0sec#194. */
export function exitCodeForStatus(status: VerificationStatus): number {
  switch (status) {
    case "reproduced":
      return 0;
    case "not_reproduced":
      return 1;
    case "skipped":
      return 2;
    case "error":
      return 3;
    default: {
      const _exhaustive: never = status;
      void _exhaustive;
      return 3;
    }
  }
}

/**
 * Render a one-line, deterministic argv slug for a step. The runtime doesn't
 * surface argv directly (shell steps are spawned through `/bin/sh -c`, http
 * steps don't have argv at all), so we synthesise something stable per
 * action kind that's good enough for log triage and downstream search.
 */
function argvForStep(step: PocStep): string[] {
  switch (step.action.type) {
    case "shell":
      return ["/bin/sh", "-c", step.action.cmd];
    case "docker":
      return ["docker", "run", "--rm", ...step.action.args, step.action.image];
    case "http":
      return [step.action.method, step.action.url];
    case "note":
      return ["note", step.id];
    default: {
      const _exhaustive: never = step.action;
      void _exhaustive;
      return ["unknown"];
    }
  }
}

/** Default summary string for the four terminal states. */
function defaultSummary(
  status: VerificationStatus,
  ran: number,
  total: number,
): string {
  switch (status) {
    case "reproduced":
      return `Replay reproduced the finding (${ran}/${total} steps executed).`;
    case "not_reproduced":
      return `Replay completed but the exploit no longer reproduces (${ran}/${total} steps executed).`;
    case "skipped":
      return total === 0
        ? "No PoC steps to execute"
        : `Replay was skipped (${ran}/${total} steps executed).`;
    case "error":
      return "Verifier failed before reaching a verdict.";
  }
}

function durationMs(startedAt: string, completedAt: string): number {
  const started = Date.parse(startedAt);
  const completed = Date.parse(completedAt);
  if (!Number.isFinite(started) || !Number.isFinite(completed)) return 0;
  return Math.max(0, completed - started);
}

function engineMetadata(): VerificationResult["engine_metadata"] {
  return {
    os: process.platform,
    arch: process.arch,
    runner: "local",
  };
}

function actualOutput(result: PocStepResult): string {
  return result.observedStdout ?? result.observedResponseBody ?? "";
}

function assertionForStep(
  result: PocStepResult,
  step: PocStep,
): VerificationAssertion | null {
  const expect = step.expect;
  if (!expect) return null;

  switch (expect.type) {
    case "exit-zero":
      return {
        kind: "exit_code",
        target: step.id,
        expected: 0,
        actual: result.observedExit ?? null,
        passed: result.kind === "passed",
      };
    case "http-status":
      return {
        kind: "http_status",
        target: step.id,
        expected: Array.isArray(expect.status) ? expect.status.join(",") : expect.status,
        actual: result.observedStatus ?? null,
        passed: result.kind === "passed",
      };
    case "body-contains":
      return {
        kind: "string_in_output",
        target: step.id,
        expected: expect.text,
        actual: excerpt(actualOutput(result)),
        passed: result.kind === "passed",
      };
    case "body-matches":
      return {
        kind: "string_in_output",
        target: step.id,
        expected: `/${expect.pattern}/`,
        actual: excerpt(actualOutput(result)),
        passed: result.kind === "passed",
      };
    case "file-exists":
      return {
        kind: "file_exists",
        target: expect.path,
        expected: true,
        actual: result.kind === "passed",
        passed: result.kind === "passed",
      };
    default: {
      const _exhaustive: never = expect;
      void _exhaustive;
      return null;
    }
  }
}

/**
 * Whether a token-matched OAST out-of-band callback proved this finding
 * (0sec#659 / #1278). The deterministic replay this command runs cannot
 * re-fire an out-of-band callback — its `expect` predicates only see the
 * in-band request/response — so an OAST proof is scan-time PoV provenance
 * carried on the finding. We recognise it two ways:
 *
 *   1. an explicit `oastConfirmed` flag on the finding (the finding schema is
 *      `.passthrough()`; the 0cloud verify runner re-synthesises a minimal
 *      finding and can stamp this from the orchestrator's scan-time pov_oracle
 *      record), or
 *   2. the pov_oracle bucketing itself: the finding's category delegates to the
 *      out-of-band OAST oracle (`oracleForCategory` → `oast-callback` for SSRF /
 *      command-injection / code-injection) AND a deterministic PoV layer
 *      (`pov_gate` / `oracle`) recorded a `pass`. Gating on the pass is what
 *      stops it from ever firing on category alone.
 */
export function findingOastConfirmed(finding: Finding): boolean {
  if ((finding as { oastConfirmed?: unknown }).oastConfirmed === true) return true;
  if (oracleForCategory(finding.category) !== "oast-callback") return false;
  return (finding.layerVerdicts ?? []).some(
    (v) =>
      v?.verdict === "pass" && (v.layer === "pov_gate" || v.layer === "oracle"),
  );
}

/**
 * Derive the additive evidence-provenance fields for a {@link VerificationResult}
 * from the finding (0sec#659 / #1278). Shared by every result builder so the
 * signal is stamped identically regardless of replay outcome.
 *
 * Contract, tuned to the 0cloud consumer (its verify writeback + #1302's
 * `mapOsecResult`):
 *   - `oast_confirmed: true` when an OAST callback proved the finding — the
 *     load-bearing flag that lets the cloud promote a blind-class proof even
 *     when the in-band replay left the status `not_reproduced` / `skipped`.
 *   - `evidence_kind`: only ever a REPRODUCED kind, never `source-only`. An OAST
 *     hit folds to `reproduced-poc`; otherwise we surface the finding's own
 *     reproduced kind when it has one, and leave the field undefined for a
 *     source-only finding so the consumer keeps its own status-based default
 *     (a `reproduced` replay must stay `reproduced-poc`, not be downgraded).
 */
export function oastEvidenceFields(finding: Finding): {
  evidence_kind?: VerifyEvidenceKind;
  oast_confirmed?: boolean;
} {
  const oast_confirmed = findingOastConfirmed(finding);
  const findingKind = evidenceKindForFinding(finding);
  const evidence_kind: VerifyEvidenceKind | undefined = oast_confirmed
    ? "reproduced-poc"
    : findingKind === "source-only"
      ? undefined
      : findingKind;
  return {
    ...(evidence_kind ? { evidence_kind } : {}),
    ...(oast_confirmed ? { oast_confirmed: true } : {}),
  };
}

/**
 * Build a {@link VerificationResult} from the runtime's report plus the
 * original finding (needed because `PocStepResult` doesn't carry the action
 * or the `expect` predicate — both are on the source `PocStep`).
 */
export function buildVerificationResult(args: {
  finding: Finding;
  report: PocExecutionReport;
  startedAt: string;
  completedAt: string;
}): VerificationResult {
  const { finding, report, startedAt, completedAt } = args;
  const stepsById = new Map<string, PocStep>(
    (finding.pocSteps ?? []).map((s) => [s.id, s]),
  );
  const status = statusFromVerdict(report.overallVerdict);

  const commands: VerificationCommand[] = report.steps
    .filter((r) => r.kind !== "skipped")
    .map((r) => {
      const step = stepsById.get(r.stepId);
      const argv = step ? argvForStep(step) : ["unknown", r.stepId];
      // For http steps the runtime returns observedStatus instead of an exit
      // code; we surface that as the exit_code field so cloud can read a
      // single uniform "did it succeed numerically" signal across step kinds.
      const exit_code =
        typeof r.observedExit === "number"
          ? r.observedExit
          : typeof r.observedStatus === "number"
            ? r.observedStatus
            : null;
      const stdout = r.observedStdout ?? r.observedResponseBody ?? "";
      const stderr = r.observedStderr ?? r.error ?? "";
      return {
        argv,
        exit_code,
        stdout_excerpt: excerpt(stdout),
        stderr_excerpt: excerpt(stderr),
        duration_ms: r.durationMs,
      };
    });

  const assertions: VerificationAssertion[] = [];
  for (const r of report.steps) {
    const step = stepsById.get(r.stepId);
    if (!step) continue;
    const assertion = assertionForStep(r, step);
    if (assertion) assertions.push(assertion);
  }

  const ran = report.steps.filter((r) => r.kind !== "skipped").length;
  const total = (finding.pocSteps ?? []).length;

  return {
    status,
    mode: "deterministic_replay",
    finding_id: finding.id,
    engine_version: VERSION,
    started_at: startedAt,
    completed_at: completedAt,
    duration_ms: durationMs(startedAt, completedAt),
    commands,
    assertions,
    evidence_artifacts: [],
    engine_metadata: engineMetadata(),
    summary: defaultSummary(status, ran, total),
    error_reason: null,
    ...oastEvidenceFields(finding),
  };
}

/**
 * Build the `skipped` result returned when the finding has no PoC
 * steps to execute. Per #193 shared contract: status='skipped', exit 2.
 */
export function buildNoStepsResult(args: {
  finding: Finding;
  startedAt: string;
  completedAt: string;
}): VerificationResult {
  return {
    status: "skipped",
    mode: "deterministic_replay",
    finding_id: args.finding.id,
    engine_version: VERSION,
    started_at: args.startedAt,
    completed_at: args.completedAt,
    duration_ms: durationMs(args.startedAt, args.completedAt),
    commands: [],
    assertions: [],
    evidence_artifacts: [],
    engine_metadata: engineMetadata(),
    summary: "No PoC steps to execute",
    error_reason: null,
    // A finding proven purely out-of-band (an OAST callback) may carry no
    // runnable pocSteps — the callback IS the proof. Stamp the provenance so
    // the cloud still promotes it instead of reading `skipped` as no-evidence.
    ...oastEvidenceFields(args.finding),
  };
}

/** Build the `error` result returned when the verifier itself crashes. */
export function buildErrorResult(args: {
  finding: Finding | null;
  startedAt: string;
  completedAt: string;
  error: unknown;
}): VerificationResult {
  const reason =
    args.error instanceof Error ? args.error.message : String(args.error);
  return {
    status: "error",
    mode: "deterministic_replay",
    finding_id: args.finding?.id ?? "unknown",
    engine_version: VERSION,
    started_at: args.startedAt,
    completed_at: args.completedAt,
    duration_ms: durationMs(args.startedAt, args.completedAt),
    commands: [],
    assertions: [],
    evidence_artifacts: [],
    engine_metadata: engineMetadata(),
    summary: "Verifier failed before reaching a verdict.",
    error_reason: reason,
  };
}

function legacyFixtureStatus(status: string): VerificationStatus {
  return status === "reproduced" ||
    status === "not_reproduced" ||
    status === "error"
    ? status
    : "skipped";
}

function legacyAssertionKind(kind: string): VerificationAssertion["kind"] {
  if (kind === "command_exit_zero") return "exit_code";
  if (kind.startsWith("filesystem_")) return "file_exists";
  return "string_in_output";
}

function artifactFromPath(kind: string, path: string): EvidenceArtifact | null {
  try {
    const stat = statSync(path);
    if (!stat.isFile()) return null;
    const body = readFileSync(path);
    return {
      kind: kind.replace(/_ref$/, ""),
      path,
      sha256: createHash("sha256").update(body).digest("hex"),
      bytes: stat.size,
    };
  } catch {
    return null;
  }
}

function fixtureResultToShared(result: Awaited<ReturnType<typeof runCliPathTraversalReplayFixture>>): VerificationResult {
  return {
    status: legacyFixtureStatus(result.status),
    mode: "deterministic_replay",
    finding_id: result.finding_id,
    engine_version: result.engine_version,
    started_at: result.started_at,
    completed_at: result.completed_at,
    duration_ms: durationMs(result.started_at, result.completed_at),
    commands: result.commands.map((command) => ({
      argv: command.argv,
      exit_code: command.exit_code,
      stdout_excerpt: command.stdout_excerpt,
      stderr_excerpt: command.stderr_excerpt,
      duration_ms: 0,
    })),
    assertions: result.assertions.map((assertion) => ({
      kind: legacyAssertionKind(assertion.kind),
      target: assertion.kind,
      expected: true,
      actual: assertion.passed,
      passed: assertion.passed,
    })),
    evidence_artifacts: Object.entries(result.artifacts)
      .map(([kind, path]) => artifactFromPath(kind, path))
      .filter((artifact): artifact is EvidenceArtifact => artifact !== null),
    engine_metadata: engineMetadata(),
    summary: result.summary,
    error_reason: result.error_reason,
  };
}

// ── Input parsing ───────────────────────────────────────────────────────────

interface VerifyOpts {
  finding?: string;
  findingId?: string;
  bundle?: string;
  target?: string;
  fixture?: string;
  fixtureCommand?: string;
  fixtureMode?: string;
  retainArtifacts?: boolean;
  artifactDir?: string;
  format?: string;
  output?: string;
  // ── kernel-finding mode (0sec#271 Tier 2) ──
  kernelFinding?: string;
  kernelTree?: string;
  kernelConfig?: string;
  attempts?: string;
  wallClock?: string;
  /**
   * 0sec#193 — runner selection. `local` (default) uses the in-process
   * shell runner; `docker` / `qemu` are sandbox-isolation stubs that
   * print a NotImplemented error JSON and exit non-zero so cloud-side
   * dispatchers can detect engine capability without parsing prose.
   */
  runner?: string;
  /** 0sec#193 — run directory for the deterministic-replay runner. */
  out?: string;
}

function readJson<T>(path: string, kind: string): T {
  const abs = resolve(path);
  let raw: string;
  try {
    raw = readFileSync(abs, "utf8");
  } catch (err) {
    throw new Error(
      `failed to read ${kind} from ${abs}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  try {
    return JSON.parse(raw) as T;
  } catch (err) {
    throw new Error(
      `failed to parse ${kind} as JSON (${abs}): ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

function parseFixtureCommand(raw: string | undefined): string[] | undefined {
  if (!raw) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `failed to parse --fixture-command as JSON argv array: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (
    !Array.isArray(parsed) ||
    parsed.length === 0 ||
    !parsed.every((item) => typeof item === "string" && item.length > 0)
  ) {
    throw new Error("--fixture-command must be a non-empty JSON array of strings");
  }
  return parsed;
}

/**
 * Parse a duration string like "30m", "90s", "2h", or a bare integer (ms).
 * Returns milliseconds. Throws on unparseable input. Exported for tests.
 */
export function parseDurationMs(raw: string): number {
  const trimmed = raw.trim();
  if (trimmed === "") throw new Error("duration is empty");
  const match = trimmed.match(/^(\d+(?:\.\d+)?)(ms|s|m|h)?$/i);
  if (!match) {
    throw new Error(`invalid duration '${raw}' (expected e.g. 30m, 90s, 2h)`);
  }
  const value = parseFloat(match[1]!);
  const unit = (match[2] ?? "ms").toLowerCase();
  switch (unit) {
    case "ms":
      return value;
    case "s":
      return value * 1000;
    case "m":
      return value * 60 * 1000;
    case "h":
      return value * 60 * 60 * 1000;
    default:
      throw new Error(`invalid duration unit '${unit}'`);
  }
}

// ── Main entry point ────────────────────────────────────────────────────────

export interface VerifyOutcome {
  result: VerificationResult;
  exitCode: number;
}

/**
 * Run the Tier 2 kernel-finding verifier (#271) and return a JSON-ready
 * result. Lives next to `runVerify` so the CLI surface stays in one file.
 *
 * Gated by `0SEC_KERNEL_VERIFY=1` so CI cost stays predictable — operators
 * who want to run this opt in explicitly. The flag check is enforced at the
 * caller (`verifyAction` below), not here, so tests can call this directly.
 */
export async function runKernelFindingVerify(opts: {
  findingPath: string;
  kernelTree: string;
  kernelConfig?: string;
  attempts?: number;
  wallClockMs?: number;
}): Promise<{ exitCode: number; result: unknown }> {
  const { verifyStaticKernelFinding, applyVerificationToFinding } = await import("@0sec/core");

  const rawFinding = readJson<unknown>(opts.findingPath, "finding");
  let finding;
  try {
    finding = findingSchema.parse(rawFinding);
  } catch (err) {
    if (err instanceof z.ZodError) {
      throw new Error(formatZodError(err, "finding JSON"));
    }
    throw err;
  }

  const result = await verifyStaticKernelFinding(finding as unknown as import("@0sec/shared").Finding, {
    kernelTree: opts.kernelTree,
    kernelConfig: opts.kernelConfig,
    attempts: opts.attempts,
    wallClockMs: opts.wallClockMs,
  });

  const promotedFinding = applyVerificationToFinding(
    finding as unknown as import("@0sec/shared").Finding,
    result,
  );

  const exitCode =
    result.status === "confirmed"
      ? 0
      : result.status === "soft_hit"
        ? 1
        : result.status === "error"
          ? 3
          : 2;

  return {
    exitCode,
    result: {
      mode: "kernel_finding_verify",
      finding_id: finding.id,
      status: result.status,
      new_confidence: result.new_confidence,
      signature: result.signature,
      generated_program: result.generated_program,
      generated_program_lang: result.generated_program_lang,
      attempts: result.attempts.map((a) => ({
        index: a.index,
        program_lang: a.programLang,
        expected_signature: a.expectedSignature,
        rejected: a.rejected,
        duration_ms: a.durationMs,
        oracle: a.oracle,
      })),
      reason: result.reason,
      error: result.errorMessage,
      finding: promotedFinding,
    },
  };
}

/**
 * Allocate an isolated workspace for shell/docker PoC steps when the caller
 * didn't pass a `--target` (and therefore didn't specify a `cwd`). Without
 * this, Node's `spawn()` falls through to `process.cwd()` — meaning a PoC
 * would execute in the operator's current working directory, which is
 * exactly the kind of "PoC steps touching real user paths" the #194 spec
 * is designed to prevent. We create the dir under `os.tmpdir()` with a
 * recognisable prefix, return both the dir and a cleanup callback to the
 * caller, and the caller is responsible for invoking cleanup once
 * execution completes (or errors out).
 */
function allocateIsolatedWorkspace(): { cwd: string; cleanup: () => void } {
  const cwd = mkdtempSync(join(tmpdir(), "0sec-verify-"));
  return {
    cwd,
    cleanup: () => {
      try {
        rmSync(cwd, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup. Leaving a stale tmp dir behind is preferable
        // to throwing in a finally block and masking the real outcome.
      }
    },
  };
}

/**
 * Run the verifier and return the outcome without writing files or exiting.
 * Exposed separately from the commander action so tests can drive it
 * directly without spawning a subprocess.
 *
 * Working-directory contract: if `--target` is supplied and provides a
 * `cwd`, that wins. Otherwise, we always allocate an isolated tmpdir under
 * `os.tmpdir()` and pass that as `target.cwd`, then clean it up when
 * execution completes. PoC shell/docker steps therefore never inherit the
 * caller's `process.cwd()`.
 */
export async function runVerify(opts: {
  findingPath?: string;
  targetPath?: string;
  fixture?: string;
  fixtureCommand?: string[];
  fixtureMode?: string;
  retainArtifacts?: boolean;
  artifactDir?: string;
}): Promise<VerifyOutcome> {
  const startedAt = new Date().toISOString();
  let finding: Finding | null = null;
  let cleanup: (() => void) | undefined;
  try {
    if (opts.fixture) {
      if (opts.fixture !== "cli-path-traversal") {
        throw new Error(
          `unsupported fixture '${opts.fixture}', supported fixtures: cli-path-traversal`,
        );
      }
      if (
        opts.fixtureMode &&
        opts.fixtureMode !== "vulnerable" &&
        opts.fixtureMode !== "patched"
      ) {
        throw new Error(
          `unsupported --fixture-mode '${opts.fixtureMode}', expected 'vulnerable' or 'patched'`,
        );
      }
      if (!opts.fixtureCommand || opts.fixtureCommand.length === 0) {
        throw new Error("--fixture-command is required with --fixture");
      }
      const legacyResult = await runCliPathTraversalReplayFixture({
        commandArgv: opts.fixtureCommand,
        fixtureMode:
          opts.fixtureMode === "patched" ? "patched" : "vulnerable",
        retainArtifacts: opts.retainArtifacts,
        artifactDir: opts.artifactDir,
        engineVersion: VERSION,
      });
      const result = fixtureResultToShared(legacyResult);
      VerificationResultSchema.parse(result);
      return { result, exitCode: exitCodeForStatus(result.status) };
    }

    if (opts.fixtureMode) {
      throw new Error("--fixture-mode is only supported with --fixture");
    }

    if (!opts.findingPath) {
      throw new Error("missing required flag: --finding <path>");
    }

    const rawFinding = readJson<unknown>(opts.findingPath, "finding");
    try {
      // Validated parse: the cast is now sound because zod has checked every
      // field the rest of the pipeline reads. Schema mirrors the canonical
      // `Finding` type in `@0sec/shared` — see `./schemas.ts`.
      finding = findingSchema.parse(rawFinding) as Finding;
    } catch (err) {
      if (err instanceof z.ZodError) {
        throw new Error(formatZodError(err, "finding JSON"));
      }
      throw err;
    }

    const baseTarget: PocExecutionTarget = opts.targetPath
      ? readJson<PocExecutionTarget>(opts.targetPath, "target")
      : {};

    // Always provide a cwd to the runtime. If the caller's target didn't set
    // one, allocate an isolated tmpdir so PoC steps cannot reach into the
    // operator's process.cwd() (#194 isolation requirement).
    let target: PocExecutionTarget = { ...baseTarget, allowProcessActions: false };
    if (!baseTarget.cwd) {
      const isolated = allocateIsolatedWorkspace();
      cleanup = isolated.cleanup;
      target = { ...target, cwd: isolated.cwd };
    }

    if (!finding.pocSteps || finding.pocSteps.length === 0) {
      const completedAt = new Date().toISOString();
      const result = buildNoStepsResult({ finding, startedAt, completedAt });
      return { result, exitCode: exitCodeForStatus(result.status) };
    }

    const report = await executePocSteps(finding, target);
    const completedAt = new Date().toISOString();
    const result = buildVerificationResult({
      finding,
      report,
      startedAt,
      completedAt,
    });
    return { result, exitCode: exitCodeForStatus(result.status) };
  } catch (err) {
    const completedAt = new Date().toISOString();
    const result = buildErrorResult({
      finding,
      startedAt,
      completedAt,
      error: err,
    });
    return { result, exitCode: exitCodeForStatus(result.status) };
  } finally {
    if (cleanup) cleanup();
  }
}

// ── #193 deterministic replay path ──────────────────────────────────────────
//
// When `--runner` is supplied (or a positional finding path is used), we
// route to the #193 deterministic-replay runner skeleton. The legacy
// --finding/--fixture path above now emits the same canonical
// shared-schema `VerificationResult`, so every verify entry point shares
// one JSON contract.

export type ReplayRunnerKind = "local" | "docker" | "qemu";

export function parseRunnerKind(raw: string | undefined): ReplayRunnerKind {
  const v = (raw ?? "local").toLowerCase();
  if (v === "local" || v === "docker" || v === "qemu") return v;
  throw new Error(
    `unsupported --runner '${raw}', expected one of local|docker|qemu`,
  );
}

/**
 * Run the #193 deterministic-replay path. Returns a result + the exit code
 * the CLI should bubble out. Distinct exit codes per status so cloud's
 * worker-controller can branch without re-parsing the JSON:
 *
 *   0 → reproduced
 *   1 → not_reproduced
 *   2 → skipped (e.g. no pocSteps)
 *   3 → error
 *   4 → runner not yet implemented (docker/qemu)
 */
export async function runDeterministicReplayCli(args: {
  findingPath: string;
  runner: ReplayRunnerKind;
  outDir?: string;
}): Promise<{ result: SharedVerificationResult; exitCode: number }> {
  // Always load the finding first so the result references it by id —
  // even when we're going to short-circuit because the runner is a stub.
  // Cloud's ingest keys on finding_id, so emitting an empty string would
  // make the failure non-attributable.
  const rawFinding = readJson<unknown>(args.findingPath, "finding");
  let finding: Finding;
  try {
    finding = findingSchema.parse(rawFinding) as Finding;
  } catch (err) {
    if (err instanceof z.ZodError) {
      throw new Error(formatZodError(err, "finding JSON"));
    }
    throw err;
  }

  // Eagerly fail the docker/qemu paths with a structured error result so
  // cloud-side dispatchers can detect engine capability without parsing
  // prose. The result still validates against the canonical schema.
  if (args.runner !== "local") {
    const now = new Date().toISOString();
    const result: SharedVerificationResult = {
      status: "error",
      mode: "deterministic_replay",
      finding_id: finding.id,
      engine_version: VERSION,
      started_at: now,
      completed_at: now,
      duration_ms: 0,
      commands: [],
      assertions: [],
      evidence_artifacts: [],
      engine_metadata: {
        os: process.platform,
        arch: process.arch,
        runner: args.runner,
      },
      error_reason: `runner '${args.runner}' is not implemented yet; see 0sec#193 sandbox-isolation follow-up`,
      summary: `runner '${args.runner}' not implemented`,
    };
    return { result, exitCode: 4 };
  }

  // Use the operator-supplied --out as the run dir if provided; otherwise
  // the runner allocates a fresh tmpdir.
  let runDir: string | undefined;
  if (args.outDir) {
    runDir = resolve(args.outDir);
    mkdirSync(runDir, { recursive: true });
  }

  const runner =
    args.runner === "local"
      ? new LocalShellRunner()
      : args.runner === "docker"
        ? new DockerRunner()
        : new QemuRunner();

  const { result } = await runDeterministicReplay(finding, {
    runner,
    runDir,
    engineVersion: VERSION,
  });

  // Validate against the canonical schema so a producer drift surfaces here
  // rather than at the consumer.
  VerificationResultSchema.parse(result);

  const exitCode =
    result.status === "reproduced"
      ? 0
      : result.status === "not_reproduced"
        ? 1
        : result.status === "skipped"
          ? 2
          : 3;
  return { result, exitCode };
}

async function verifyAction(opts: VerifyOpts, positionalFinding?: string): Promise<void> {
  // Kernel-finding (#271 Tier 2) mode is a separate pipeline from the
  // deterministic-replay verifier — handle it first and exit.
  if (opts.kernelFinding) {
    if (process.env["0SEC_KERNEL_VERIFY"] !== "1") {
      throw new Error(
        "--kernel-finding requires 0SEC_KERNEL_VERIFY=1 (CI cost gate, #271). " +
          "Export 0SEC_KERNEL_VERIFY=1 to opt in.",
      );
    }
    if (!opts.kernelTree) {
      throw new Error("--kernel-finding requires --kernel-tree <path>");
    }
    if (
      opts.finding ||
      opts.fixture ||
      opts.bundle ||
      opts.findingId ||
      positionalFinding ||
      opts.runner
    ) {
      throw new Error(
        "--kernel-finding cannot be combined with --finding / --fixture / --bundle / --finding-id / <finding> positional / --runner",
      );
    }
    const attempts = opts.attempts ? parseInt(opts.attempts, 10) : undefined;
    if (opts.attempts && (!Number.isFinite(attempts) || (attempts as number) <= 0)) {
      throw new Error(`invalid --attempts '${opts.attempts}' (expected positive integer)`);
    }
    const wallClockMs = opts.wallClock ? parseDurationMs(opts.wallClock) : undefined;

    const kernelOutcome = await runKernelFindingVerify({
      findingPath: opts.kernelFinding,
      kernelTree: opts.kernelTree,
      kernelConfig: opts.kernelConfig ?? "kasan",
      attempts,
      wallClockMs,
    });
    const kernelJson = JSON.stringify(kernelOutcome.result, null, 2);
    if (opts.output) {
      writeFileSync(resolve(opts.output), kernelJson + "\n", "utf8");
    } else {
      process.stdout.write(kernelJson + "\n");
    }
    process.exitCode = kernelOutcome.exitCode;
    return;
  }

  // 0sec#193 deterministic-replay path: triggered by a positional
  // <finding.json> argument or an explicit --runner flag.
  if (positionalFinding || opts.runner) {
    if (positionalFinding && opts.finding) {
      throw new Error(
        "pass a finding path EITHER as a positional argument OR via --finding, not both",
      );
    }
    const findingPath = positionalFinding ?? opts.finding;
    if (!findingPath) {
      throw new Error(
        "missing finding path. Usage: 0sec verify <finding.json> [--runner local|docker|qemu]",
      );
    }
    const runner = parseRunnerKind(opts.runner);
    const { result, exitCode } = await runDeterministicReplayCli({
      findingPath,
      runner,
      outDir: opts.out,
    });
    const json = JSON.stringify(result, null, 2);
    if (opts.output) {
      writeFileSync(resolve(opts.output), json + "\n", "utf8");
    } else {
      process.stdout.write(json + "\n");
    }
    process.exitCode = exitCode;
    return;
  }

  // Validate flag combinations early so users get a clear error rather than
  // a confusing "no finding loaded" downstream.
  if (opts.findingId || opts.bundle) {
    if (opts.findingId && !opts.bundle) {
      throw new Error("--finding-id requires --bundle <path>");
    }
    if (opts.bundle && !opts.findingId) {
      throw new Error("--bundle requires --finding-id <id>");
    }
    throw new Error(
      "--finding-id / --bundle is reserved for a follow-up. Use --finding <path> for now.",
    );
  }
  if (opts.fixture && opts.finding) {
    throw new Error("--fixture and --finding are mutually exclusive");
  }
  if (opts.fixtureCommand && !opts.fixture) {
    throw new Error("--fixture-command is only supported with --fixture");
  }
  if (opts.fixtureMode && !opts.fixture) {
    throw new Error("--fixture-mode is only supported with --fixture");
  }
  if ((opts.retainArtifacts || opts.artifactDir) && !opts.fixture) {
    throw new Error("--retain-artifacts / --artifact-dir are only supported with --fixture");
  }
  if (!opts.finding && !opts.fixture) {
    throw new Error("missing required flag: --finding <path>");
  }
  if (opts.format && opts.format !== "json") {
    throw new Error(`unsupported --format '${opts.format}', only 'json' is supported`);
  }
  const fixtureCommand = parseFixtureCommand(opts.fixtureCommand);

  const outcome = await runVerify({
    findingPath: opts.finding,
    targetPath: opts.target,
    fixture: opts.fixture,
    fixtureCommand,
    fixtureMode: opts.fixtureMode,
    retainArtifacts: opts.retainArtifacts,
    artifactDir: opts.artifactDir,
  });

  const json = JSON.stringify(outcome.result, null, 2);
  if (opts.output) {
    writeFileSync(resolve(opts.output), json + "\n", "utf8");
  } else {
    process.stdout.write(json + "\n");
  }
  // Avoid `process.exit()` immediately after a stdout write — Node's docs warn
  // that exit() can truncate pending async writes. Setting `process.exitCode`
  // and returning lets the event loop drain the JSON cleanly before we exit.
  process.exitCode = outcome.exitCode;
}

export function registerVerifyCommand(program: Command): void {
  program
    .command("verify")
    .description(
      "Deterministically replay a finding's PoC steps and emit a verification_result JSON.",
    )
    .argument(
      "[finding]",
      "Path to a finding.json (0sec#193 deterministic-replay path). Equivalent to --finding when --runner is supplied.",
    )
    .option(
      "--runner <kind>",
      "0sec#193 replay runner: local|docker|qemu (default local; docker/qemu are NotImplemented stubs that exit 4).",
    )
    .option(
      "--out <dir>",
      "0sec#193 run directory (artifacts go under <out>/artifacts/). Defaults to a fresh tmpdir.",
    )
    .option("--finding <path>", "Path to a finding.json (required for now).")
    .option(
      "--finding-id <id>",
      "[reserved] Finding id; pair with --bundle for cloud-bundle mode (not yet implemented).",
    )
    .option(
      "--bundle <path>",
      "[reserved] Artifact bundle zip; pair with --finding-id (not yet implemented).",
    )
    .option(
      "--target <path>",
      "Path to a target.json (PocExecutionTarget: baseUrl, env, cwd, timeoutMs, personas).",
    )
    .option(
      "--fixture <name>",
      "Run a built-in deterministic replay fixture. Supported: cli-path-traversal.",
    )
    .option(
      "--fixture-command <json>",
      "JSON argv array for the CLI under test. Supports {{apiUrl}}, {{exportDir}}, and {{fixtureMode}} placeholders.",
    )
    .option(
      "--fixture-mode <mode>",
      "Fixture behavior for --fixture: vulnerable or patched.",
    )
    .option(
      "--retain-artifacts",
      "Keep the fixture sandbox, harness metadata, and stdout/stderr logs.",
      false,
    )
    .option(
      "--artifact-dir <path>",
      "Use this directory as the fixture sandbox root.",
    )
    .option("--format <fmt>", "Output format. Only 'json' is supported.", "json")
    .option(
      "--output <path>",
      "Write the verification_result JSON to this path instead of stdout.",
    )
    // ── Kernel-finding (Tier 2, 0sec#271) ──
    .option(
      "--kernel-finding <path>",
      "Path to a kernel-review finding.json. Runs the Tier 2 agent loop to " +
        "produce a reproducer and promote the finding via the kernel oracle. " +
        "Requires 0SEC_KERNEL_VERIFY=1.",
    )
    .option(
      "--kernel-tree <path>",
      "Linux source tree used by --kernel-finding for Tier 1 kernel build.",
    )
    .option(
      "--kernel-config <profile>",
      "Kernel build config profile for --kernel-finding (only 'kasan' supported).",
      "kasan",
    )
    .option(
      "--attempts <N>",
      "Max reproducer attempts for --kernel-finding (default 5).",
    )
    .option(
      "--wall-clock <duration>",
      "Wall-clock budget for --kernel-finding (e.g. 30m, 90s; default 30m).",
    )
    .action(async (positionalFinding: string | undefined, opts: VerifyOpts) => {
      try {
        await verifyAction(opts, positionalFinding);
      } catch (err) {
        // Verifier-infrastructure failure (bad flags, unreadable file, etc.)
        // — distinct from a non-reproduction. Per #194 spec: exit 3.
        const reason = err instanceof Error ? err.message : String(err);
        const now = new Date().toISOString();
        const result: VerificationResult = {
          status: "error",
          mode: "deterministic_replay",
          finding_id: "unknown",
          engine_version: VERSION,
          started_at: now,
          completed_at: now,
          duration_ms: 0,
          commands: [],
          assertions: [],
          evidence_artifacts: [],
          engine_metadata: engineMetadata(),
          summary: "Verifier failed before reaching a verdict.",
          error_reason: reason,
        };
        const json = JSON.stringify(result, null, 2);
        if (opts.output) {
          try {
            writeFileSync(resolve(opts.output), json + "\n", "utf8");
          } catch {
            process.stderr.write(json + "\n");
          }
        } else {
          process.stdout.write(json + "\n");
        }
        // Same reason as the success path: prefer `process.exitCode` so the
        // pending stderr/stdout JSON write actually flushes before exit.
        process.exitCode = 3;
      }
    });
}
