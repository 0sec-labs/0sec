/**
 * pwnkit#193 — Deterministic replay runner skeleton.
 *
 * This file is the SHIPPING execution path for the local-shell variant of the
 * verifier plus the contracts for the docker/qemu sandbox variants. It
 * consumes a finding's `pocSteps`, sequentially executes each one, evaluates
 * the declared assertions, and emits a `VerificationResult` matching the
 * canonical schema in `@pwnkit/shared/verification`.
 *
 * Design notes:
 *
 *   • The runner is split into a pure orchestrator (`runDeterministicReplay`)
 *     and a pluggable `ReplayRunner` interface that knows how to execute a
 *     single step. The orchestrator owns the run-directory lifecycle,
 *     assertion evaluation, timing, and result assembly; the runner owns
 *     the *how* (spawn a subprocess locally vs. docker exec vs. qemu agent
 *     channel). The interface is the seam for issue-#193's follow-up
 *     sandbox-isolation work.
 *
 *   • `LocalShellRunner` is the only impl shipped today. It spawns each
 *     `shell`-action step under `/bin/sh -c` with the run-directory as
 *     cwd, applies a per-step wallclock timeout, and caps stdout/stderr
 *     captures at `STREAM_EXCERPT_BYTES` (8 KiB by default per #193 spec).
 *
 *   • `DockerRunner` and `QemuRunner` are exported as interfaces with
 *     NotImplemented stubs. Call sites can already type against them; the
 *     concrete impls land in the sandbox-isolation slice.
 *
 *   • Assertions are derived from each step's `PocStepExpect` predicate
 *     (we map `body-contains` → `string_in_output`, `exit-zero` →
 *     `exit_code = 0`, etc). A finding without `pocSteps` yields status
 *     `skipped`.
 *
 *   • Evidence artifacts (full stdout, full stderr, request/response
 *     captures) are written to `<runDir>/artifacts/` and referenced by
 *     sha256 in the result. The excerpts in `commands[]` are bounded; the
 *     full payload lives on disk for forensic re-fetching.
 */

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  writeFileSync,
  existsSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, isAbsolute } from "node:path";
import { arch as nodeArch, platform as nodePlatform } from "node:process";
import type { Finding, PocStep, PocStepExpect } from "@pwnkit/shared";
import {
  VERSION,
  type EvidenceArtifact,
  type RunnerKind,
  type VerificationAssertion,
  type VerificationCommand,
  type VerificationResult,
} from "@pwnkit/shared";

// ── Tunables ────────────────────────────────────────────────────────────────

/**
 * Maximum bytes of stdout/stderr captured into the result's per-command
 * excerpt. Anything beyond this is truncated with a trailing marker; the
 * full payload is still persisted to disk as an evidence artifact and
 * referenced by sha256 so a downstream consumer can re-fetch.
 *
 * 8 KiB matches the #193 spec ("cap excerpt length, e.g. 8KB each").
 */
export const STREAM_EXCERPT_BYTES = 8 * 1024;

/**
 * Default per-step wallclock timeout. The verifier is meant to be cheap
 * and deterministic; a step that doesn't terminate inside this window is
 * killed and recorded with a `null` exit code. Callers can override via
 * `opts.stepTimeoutMs`.
 */
export const DEFAULT_STEP_TIMEOUT_MS = 30_000;

/** Maximum total bytes of stream payload captured per step (full, not excerpt). */
export const MAX_STREAM_CAPTURE_BYTES = 1 * 1024 * 1024;

// ── Runner interface ────────────────────────────────────────────────────────

/**
 * One executed step's raw result, in the shape the orchestrator needs to
 * (a) populate `commands[]` and (b) evaluate assertions against. The
 * runner is responsible for capping `stdoutFull`/`stderrFull` to
 * `MAX_STREAM_CAPTURE_BYTES`; the orchestrator handles excerpt
 * truncation, sha256, and on-disk persistence.
 */
export interface StepResult {
  argv: string[];
  exitCode: number | null;
  stdoutFull: string;
  stderrFull: string;
  durationMs: number;
  /** When the runner kills a step for exceeding timeout, set this so the
   *  orchestrator can surface "timed out" rather than "non-zero exit". */
  timedOut?: boolean;
  /** Optional error message when the runner itself failed to even launch
   *  the step (e.g. no shell binary). Distinct from a non-zero exit. */
  launchError?: string;
}

export interface ReplayRunnerContext {
  /** Run directory the orchestrator allocated. Step `cwd` defaults here. */
  runDir: string;
  /** Per-step timeout the caller configured. */
  stepTimeoutMs: number;
}

/**
 * Pluggable step executor. The orchestrator hands each step to `exec()`
 * along with the run context; the runner returns a `StepResult`. The
 * interface is intentionally narrow — anything more (e.g. side-channel
 * artifacts) is the runner's responsibility to write into `runDir`
 * before returning.
 */
export interface ReplayRunner {
  readonly kind: RunnerKind;
  exec(step: PocStep, ctx: ReplayRunnerContext): Promise<StepResult>;
}

// ── LocalShellRunner ────────────────────────────────────────────────────────
//
// The "real" runner shipped with #193's first slice. It spawns each shell
// step under `/bin/sh -c "<cmd>"` in `ctx.runDir`, enforcing a wallclock
// timeout and capping captured streams.
//
// Non-shell step kinds (http / docker / note) are recorded but not
// actually executed in this slice; they round-trip as informational steps
// with a launchError marker so the orchestrator can keep going. The
// reasoning: #193's foundational deliverable is the SHAPE; HTTP replay
// has its own runtime in `disclose/poc-runtime.ts` that we deliberately
// don't duplicate here.

export class LocalShellRunner implements ReplayRunner {
  readonly kind: RunnerKind = "local";

  async exec(step: PocStep, ctx: ReplayRunnerContext): Promise<StepResult> {
    const start = Date.now();

    // Shell steps are the only kind the local runner actually executes in
    // this slice. Everything else is recorded so the result is complete
    // but flagged as non-executed so a future runner impl can fill in.
    if (step.action.type !== "shell") {
      return {
        argv: argvForStep(step),
        exitCode: null,
        stdoutFull: "",
        stderrFull: "",
        durationMs: Date.now() - start,
        launchError: `LocalShellRunner only executes shell steps; got '${step.action.type}'`,
      };
    }

    const cmd = step.action.cmd;
    const stepCwd = step.action.cwd
      ? resolveStepCwd(step.action.cwd, ctx.runDir)
      : ctx.runDir;

    return new Promise<StepResult>((resolveP) => {
      const argv = ["/bin/sh", "-c", cmd];
      let stdout = "";
      let stderr = "";
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let timedOut = false;
      let settled = false;

      let child;
      try {
        child = spawn("/bin/sh", ["-c", cmd], {
          cwd: stepCwd,
          env: { ...process.env, PWNKIT_VERIFY: "1" },
          stdio: ["ignore", "pipe", "pipe"],
        });
      } catch (err) {
        resolveP({
          argv,
          exitCode: null,
          stdoutFull: "",
          stderrFull: "",
          durationMs: Date.now() - start,
          launchError: err instanceof Error ? err.message : String(err),
        });
        return;
      }

      const timer = setTimeout(() => {
        timedOut = true;
        try {
          child.kill("SIGKILL");
        } catch {
          // Best-effort: the child may have already exited racy with the
          // timer fire. The `close` handler still wins and we record the
          // outcome there.
        }
      }, ctx.stepTimeoutMs);

      child.stdout?.on("data", (chunk: Buffer) => {
        if (stdoutBytes >= MAX_STREAM_CAPTURE_BYTES) return;
        const remaining = MAX_STREAM_CAPTURE_BYTES - stdoutBytes;
        const slice =
          chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
        stdout += slice.toString("utf8");
        stdoutBytes += slice.length;
      });
      child.stderr?.on("data", (chunk: Buffer) => {
        if (stderrBytes >= MAX_STREAM_CAPTURE_BYTES) return;
        const remaining = MAX_STREAM_CAPTURE_BYTES - stderrBytes;
        const slice =
          chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
        stderr += slice.toString("utf8");
        stderrBytes += slice.length;
      });

      child.on("error", (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolveP({
          argv,
          exitCode: null,
          stdoutFull: stdout,
          stderrFull: stderr,
          durationMs: Date.now() - start,
          launchError: err.message,
        });
      });
      child.on("close", (code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolveP({
          argv,
          exitCode: typeof code === "number" ? code : null,
          stdoutFull: stdout,
          stderrFull: stderr,
          durationMs: Date.now() - start,
          timedOut,
        });
      });
    });
  }
}

/**
 * Resolve a step-declared cwd against the run directory. Absolute paths
 * are *rejected* (we don't want a PoC to escape into `/etc`); relative
 * paths are joined onto `runDir`. The resolved path must still live
 * under `runDir` after normalisation.
 */
function resolveStepCwd(cwd: string, runDir: string): string {
  if (isAbsolute(cwd)) {
    // Defence: refuse to let a PoC step jump to an absolute host path.
    // Fall back to the runDir; the step still runs, just isolated.
    return runDir;
  }
  const resolved = resolve(runDir, cwd);
  if (!resolved.startsWith(runDir)) return runDir;
  return resolved;
}

// ── DockerRunner / QemuRunner stubs ─────────────────────────────────────────
//
// These exist so cloud's worker-controller can already type against them.
// The first call lands the SandboxIsolation slice; until then,
// constructing one is fine, calling `exec()` is a hard NotImplemented.

export class DockerRunner implements ReplayRunner {
  readonly kind: RunnerKind = "docker";
  async exec(_step: PocStep, _ctx: ReplayRunnerContext): Promise<StepResult> {
    throw new NotImplementedError(
      "DockerRunner.exec is not implemented yet; see pwnkit#193 sandbox-isolation follow-up",
    );
  }
}

export class QemuRunner implements ReplayRunner {
  readonly kind: RunnerKind = "qemu";
  async exec(_step: PocStep, _ctx: ReplayRunnerContext): Promise<StepResult> {
    throw new NotImplementedError(
      "QemuRunner.exec is not implemented yet; see pwnkit#193 sandbox-isolation follow-up",
    );
  }
}

export class NotImplementedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotImplementedError";
  }
}

// ── Argv synthesis ──────────────────────────────────────────────────────────
//
// Per-step argv used to populate `VerificationCommand.argv`. Mirrors the
// shape `executePocSteps` (#194 runtime) emits, so cloud-side log triage
// works against both result variants without bespoke parsing.

export function argvForStep(step: PocStep): string[] {
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

// ── Assertion evaluation ────────────────────────────────────────────────────
//
// We accept TWO assertion shapes:
//   1. The richer #193 form (file_exists / http_status / string_in_output /
//      exit_code) — passed in via `opts.assertions`. Cloud / a runner caller
//      will produce these from a structured verification contract.
//   2. The legacy `PocStepExpect` form attached to the step itself. We
//      derive a `VerificationAssertion` from each step's `expect` so the
//      first-version runner has something to evaluate without requiring
//      the caller to author the new contract.

export interface AssertionInput {
  kind: "file_exists" | "http_status" | "string_in_output" | "exit_code";
  target: string;
  expected: string | number | boolean;
}

/** Map a `PocStepExpect` + observed step result to a #193 assertion. */
export function assertionFromStepExpect(
  step: PocStep,
  expect: PocStepExpect,
  result: StepResult,
): VerificationAssertion {
  switch (expect.type) {
    case "exit-zero": {
      const passed = result.exitCode === 0;
      return {
        kind: "exit_code",
        target: step.id,
        expected: 0,
        actual: result.exitCode,
        passed,
      };
    }
    case "http-status": {
      const expected = Array.isArray(expect.status)
        ? expect.status.join(",")
        : expect.status;
      // The local shell runner doesn't speak HTTP; record actual = null so
      // a downstream consumer can tell the assertion couldn't be evaluated.
      return {
        kind: "http_status",
        target: step.id,
        expected,
        actual: null,
        passed: false,
      };
    }
    case "body-contains": {
      const haystack = result.stdoutFull;
      const passed = haystack.includes(expect.text);
      return {
        kind: "string_in_output",
        target: step.id,
        expected: expect.text,
        actual: passed ? expect.text : null,
        passed,
      };
    }
    case "body-matches": {
      let passed = false;
      try {
        passed = new RegExp(expect.pattern).test(result.stdoutFull);
      } catch {
        passed = false;
      }
      return {
        kind: "string_in_output",
        target: step.id,
        expected: expect.pattern,
        actual: passed ? "matched" : null,
        passed,
      };
    }
    case "file-exists": {
      // Resolve against the run dir if relative; assertion fails if path
      // isn't present after the step ran. This is the canonical
      // "did the PoC drop a file" check.
      const passed = existsSync(expect.path);
      return {
        kind: "file_exists",
        target: expect.path,
        expected: true,
        actual: passed,
        passed,
      };
    }
    default: {
      const _exhaustive: never = expect;
      void _exhaustive;
      return {
        kind: "string_in_output",
        target: step.id,
        expected: "",
        actual: null,
        passed: false,
      };
    }
  }
}

/**
 * Evaluate a freestanding assertion declared in `opts.assertions` (not
 * tied to a single step's `expect`). The orchestrator runs these AFTER
 * all steps have executed.
 */
export function evaluateAssertion(
  input: AssertionInput,
  ctx: {
    lastExitCode: number | null;
    aggregatedStdout: string;
    runDir: string;
  },
): VerificationAssertion {
  switch (input.kind) {
    case "exit_code": {
      const actual = ctx.lastExitCode;
      return {
        ...input,
        actual,
        passed: actual === input.expected,
      };
    }
    case "string_in_output": {
      const needle = String(input.expected);
      const passed = ctx.aggregatedStdout.includes(needle);
      return {
        ...input,
        actual: passed ? needle : null,
        passed,
      };
    }
    case "file_exists": {
      const path = isAbsolute(input.target)
        ? input.target
        : join(ctx.runDir, input.target);
      const passed = existsSync(path);
      return {
        ...input,
        actual: passed,
        passed,
      };
    }
    case "http_status": {
      // Local runner doesn't produce HTTP responses; ledger assertion as
      // unevaluated. A future HTTP-aware runner overrides this.
      return {
        ...input,
        actual: null,
        passed: false,
      };
    }
    default: {
      const _exhaustive: never = input.kind;
      void _exhaustive;
      return {
        ...input,
        actual: null,
        passed: false,
      };
    }
  }
}

// ── Excerpt + artifact helpers ──────────────────────────────────────────────

export function excerpt(text: string, max = STREAM_EXCERPT_BYTES): string {
  if (!text) return "";
  if (Buffer.byteLength(text, "utf8") <= max) return text;
  const buf = Buffer.from(text, "utf8");
  return buf.subarray(0, max).toString("utf8") + "…[truncated]";
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

/**
 * Persist a stream capture as a sidecar artifact under `<runDir>/artifacts/`
 * and return an `EvidenceArtifact` descriptor referencing it by sha256.
 * Returns `null` when the payload is empty so we don't litter the run dir
 * with zero-byte stubs.
 */
export function persistArtifact(args: {
  runDir: string;
  kind: string;
  filenameHint: string;
  body: string;
}): EvidenceArtifact | null {
  if (!args.body) return null;
  const artifactsDir = join(args.runDir, "artifacts");
  mkdirSync(artifactsDir, { recursive: true });
  const sha = sha256Hex(args.body);
  // Embed the sha in the filename so collisions across step ids don't
  // overwrite each other and so a content-addressed lookup is trivial.
  const safeHint = args.filenameHint.replace(/[^a-zA-Z0-9._-]/g, "_");
  const fname = `${safeHint}-${sha.slice(0, 16)}`;
  const fullPath = join(artifactsDir, fname);
  writeFileSync(fullPath, args.body, "utf8");
  return {
    kind: args.kind,
    path: join("artifacts", fname),
    sha256: sha,
    bytes: statSync(fullPath).size,
  };
}

// ── Orchestrator ────────────────────────────────────────────────────────────

export interface RunDeterministicReplayOpts {
  /** Pluggable runner. Defaults to {@link LocalShellRunner}. */
  runner?: ReplayRunner;
  /** Where to put the run dir. Defaults to a fresh tmpdir. */
  runDir?: string;
  /** Per-step wallclock timeout. Defaults to {@link DEFAULT_STEP_TIMEOUT_MS}. */
  stepTimeoutMs?: number;
  /** Optional free-standing assertions evaluated after the steps run. */
  assertions?: AssertionInput[];
  /** Engine version stamp; defaults to the shared `VERSION` constant. */
  engineVersion?: string;
}

export interface DeterministicReplayOutcome {
  result: VerificationResult;
  runDir: string;
}

/**
 * Run a finding's `pocSteps` through the configured runner and return a
 * `VerificationResult` matching the canonical #193 schema. The result is
 * NOT validated here against the zod schema — the CLI caller does that
 * before serialising, so the schema is the single trust boundary. Pure
 * test code can re-validate via `VerificationResultSchema.parse`.
 */
export async function runDeterministicReplay(
  finding: Finding,
  opts: RunDeterministicReplayOpts = {},
): Promise<DeterministicReplayOutcome> {
  const runner = opts.runner ?? new LocalShellRunner();
  const stepTimeoutMs = opts.stepTimeoutMs ?? DEFAULT_STEP_TIMEOUT_MS;
  const engineVersion = opts.engineVersion ?? VERSION;
  const runDir =
    opts.runDir ?? mkdtempSync(join(tmpdir(), "pwnkit-replay-"));
  mkdirSync(runDir, { recursive: true });

  const startedAt = new Date();
  const startMs = Date.now();

  const commands: VerificationCommand[] = [];
  const assertions: VerificationAssertion[] = [];
  const evidenceArtifacts: EvidenceArtifact[] = [];

  const steps = finding.pocSteps ?? [];

  // Empty `pocSteps` → status `skipped`. Distinct from a runner failure: we
  // chose not to execute because the finding didn't tell us what to do.
  if (steps.length === 0) {
    const completedAt = new Date();
    return {
      runDir,
      result: {
        status: "skipped",
        mode: "deterministic_replay",
        finding_id: finding.id,
        engine_version: engineVersion,
        started_at: startedAt.toISOString(),
        completed_at: completedAt.toISOString(),
        duration_ms: completedAt.getTime() - startMs,
        commands: [],
        assertions: [],
        evidence_artifacts: [],
        engine_metadata: {
          os: nodePlatform,
          arch: nodeArch,
          runner: runner.kind,
        },
        summary: "no pocSteps to execute",
      },
    };
  }

  let lastExit: number | null = null;
  let aggregatedStdout = "";
  let runnerLaunchError: string | null = null;

  for (const step of steps) {
    let stepResult: StepResult;
    try {
      stepResult = await runner.exec(step, { runDir, stepTimeoutMs });
    } catch (err) {
      // Runner-level failure (e.g. DockerRunner.exec throws NotImplemented).
      // We record it as a synthetic command + a launchError and stop the
      // loop; the surrounding orchestrator surfaces it as `error`.
      stepResult = {
        argv: argvForStep(step),
        exitCode: null,
        stdoutFull: "",
        stderrFull: "",
        durationMs: 0,
        launchError: err instanceof Error ? err.message : String(err),
      };
      runnerLaunchError = stepResult.launchError ?? "runner exec failed";
    }

    lastExit = stepResult.exitCode;
    aggregatedStdout += stepResult.stdoutFull;

    commands.push({
      argv: stepResult.argv,
      exit_code: stepResult.exitCode,
      stdout_excerpt: excerpt(stepResult.stdoutFull),
      stderr_excerpt: excerpt(stepResult.stderrFull),
      duration_ms: stepResult.durationMs,
    });

    // Persist full captures as evidence artifacts (sidecar files) so the
    // 8 KiB excerpt above isn't the end of the story.
    const stdoutArt = persistArtifact({
      runDir,
      kind: "stdout",
      filenameHint: `step-${step.id}.stdout`,
      body: stepResult.stdoutFull,
    });
    if (stdoutArt) evidenceArtifacts.push(stdoutArt);
    const stderrArt = persistArtifact({
      runDir,
      kind: "stderr",
      filenameHint: `step-${step.id}.stderr`,
      body: stepResult.stderrFull,
    });
    if (stderrArt) evidenceArtifacts.push(stderrArt);

    // Per-step assertion derived from the step's declared `expect`.
    if (step.expect) {
      assertions.push(assertionFromStepExpect(step, step.expect, stepResult));
    }

    if (runnerLaunchError) break;
  }

  // Freestanding assertions evaluated after all steps ran.
  for (const a of opts.assertions ?? []) {
    assertions.push(
      evaluateAssertion(a, {
        lastExitCode: lastExit,
        aggregatedStdout,
        runDir,
      }),
    );
  }

  const completedAt = new Date();
  const allAssertionsPassed =
    assertions.length === 0 ? false : assertions.every((a) => a.passed);
  const status = runnerLaunchError
    ? "error"
    : allAssertionsPassed
      ? "reproduced"
      : "not_reproduced";

  return {
    runDir,
    result: {
      status,
      mode: "deterministic_replay",
      finding_id: finding.id,
      engine_version: engineVersion,
      started_at: startedAt.toISOString(),
      completed_at: completedAt.toISOString(),
      duration_ms: completedAt.getTime() - startMs,
      commands,
      assertions,
      evidence_artifacts: evidenceArtifacts,
      engine_metadata: {
        os: nodePlatform,
        arch: nodeArch,
        runner: runner.kind,
      },
      error_reason: runnerLaunchError ?? null,
      summary: summariseOutcome({
        status,
        ran: commands.length,
        total: steps.length,
        runnerLaunchError,
      }),
    },
  };
}

function summariseOutcome(args: {
  status: "reproduced" | "not_reproduced" | "error" | "skipped";
  ran: number;
  total: number;
  runnerLaunchError: string | null;
}): string {
  switch (args.status) {
    case "reproduced":
      return `replay reproduced the finding (${args.ran}/${args.total} steps executed)`;
    case "not_reproduced":
      return `replay completed but assertions failed (${args.ran}/${args.total} steps executed)`;
    case "error":
      return args.runnerLaunchError
        ? `runner error: ${args.runnerLaunchError}`
        : "runner error";
    case "skipped":
      return "no pocSteps to execute";
  }
}
