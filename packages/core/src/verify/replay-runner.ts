/**
 * 0sec#193 — Deterministic replay runner.
 *
 * It consumes a finding's `pocSteps`, executes each through a selected local,
 * Docker, or QEMU runner, evaluates declared assertions, and emits a
 * `VerificationResult` matching the canonical schema in
 * `@0sec/shared/verification`.
 *
 * Design notes:
 *
 *   • The pure orchestrator (`runDeterministicReplay`) owns run-directory
 *     lifecycle, assertion evaluation, timing, and result assembly; a narrow
 *     `ReplayRunner` owns one step's execution boundary.
 *
 *   • `LocalShellRunner` executes shell steps under `/bin/sh -c` in the
 *     run-directory with a per-step timeout and bounded captures.
 *
 *   • `DockerRunner` creates a fresh unprivileged, read-only container per
 *     step. It defaults to no network; scoped declarative HTTP steps can opt
 *     into a bridge or named network. `QemuRunner` boots an initramfs-only,
 *     offline guest for shell PoCs when the operator supplies a kernel and
 *     static BusyBox binary.
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

import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  writeFileSync,
  existsSync,
  statSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, isAbsolute } from "node:path";
import { arch as nodeArch, platform as nodePlatform } from "node:process";
import { gzipSync } from "node:zlib";
import type { Finding, PocStep, PocStepExpect } from "@0sec/shared";
import {
  VERSION,
  type EvidenceArtifact,
  type RunnerKind,
  type VerificationAssertion,
  type VerificationCommand,
  type VerificationResult,
} from "@0sec/shared";
import type { ScopePolicy } from "../scope/scope.js";
import { allowlistedChildEnv } from "../agent/sanitized-env.js";

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
interface PromiseResolvers<T> {
  promise: Promise<T>;
  resolve(value: T | PromiseLike<T>): void;
  reject(reason?: unknown): void;
}

// Node 24 is the published runtime floor. Keep the ES2022 compiler target for
// emitted syntax while supplying the newer standard-library declaration here.
const promiseWithResolvers = Promise as typeof Promise & {
  withResolvers<T>(): PromiseResolvers<T>;
};

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
  /** HTTP status emitted by an HTTP-aware sandbox runner. */
  httpStatus?: number;
}

export interface ReplayRunnerContext {
  /** Run directory the orchestrator allocated. Step `cwd` defaults here. */
  runDir: string;
  /** Per-step timeout the caller configured. */
  stepTimeoutMs: number;
  /**
   * Engagement scope. A Docker runner refuses networked replay without this
   * policy and checks every declarative HTTP target before container launch.
   */
  scope?: ScopePolicy;
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
          // `cmd` is a PoC-authored shell step (model/target-derived), so this
          // child must not inherit the harness's provider/cloud credentials.
          // Build from the allowlist (PATH/HOME/TMPDIR + target-auth vars a
          // reproduction legitimately needs) rather than copying process.env.
          env: allowlistedChildEnv({ "0SEC_VERIFY": "1" }),
          stdio: ["ignore", "pipe", "pipe"],
          // On POSIX, isolate the shell and all descendants into a process
          // group so a timeout cannot leave a grandchild holding stdout open.
          detached: nodePlatform !== "win32",
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
          if (nodePlatform !== "win32" && child.pid) {
            process.kill(-child.pid, "SIGKILL");
          } else {
            child.kill("SIGKILL");
          }
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

// ── DockerRunner ────────────────────────────────────────────────────────────
//
// Each executable step gets a fresh, unprivileged, read-only container. The
// run directory is the only host bind mount, and is shared deliberately so
// sequential PoC steps can exchange evidence. Images are never pulled by the
// runner: an operator must provision a trusted local image before execution.
// Network is disabled by default. The only networked mode is an explicit,
// scope-checked declarative HTTP action; arbitrary shell/container commands
// never receive a network-capable sandbox.

export const DEFAULT_DOCKER_SHELL_IMAGE = "alpine:3.20";
export const DEFAULT_DOCKER_HTTP_IMAGE = "curlimages/curl:8.12.1";

const DOCKER_HTTP_STATUS_MARKER = "\n__0SEC_HTTP_STATUS__:";
const CONTAINER_ID_RE = /^[a-f0-9]{12,64}$/i;
const DOCKER_NETWORK_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;

export interface DockerRunnerOptions {
  /** Docker CLI binary. Injectable for a compatible daemon or integration test. */
  dockerBinary?: string;
  /** Local image used for shell steps. Must contain /bin/sh. */
  shellImage?: string;
  /** Local image used for declarative HTTP steps. Must contain curl. */
  httpImage?: string;
  /**
   * Docker network name. Defaults to "none". "host" is intentionally refused;
   * bridge/custom networks require a scope policy and only allow HTTP actions.
   */
  network?: string;
  /** Hard memory cap applied to every container. */
  memoryMb?: number;
  /** Hard process cap applied to every container. */
  pidsLimit?: number;
  /** CPU quota applied to every container. */
  cpus?: number;
}

interface DockerStepCommand {
  image: string;
  /** Docker run options which must appear before the image reference. */
  dockerOptions?: string[];
  /** Container argv, always placed after the image reference. */
  command: string[];
  parseHttpStatus: boolean;
}

export class DockerRunner implements ReplayRunner {
  readonly kind: RunnerKind = "docker";
  private readonly dockerBinary: string;
  private readonly shellImage: string;
  private readonly httpImage: string;
  private readonly network: string;
  private readonly memoryMb: number;
  private readonly pidsLimit: number;
  private readonly cpus: number;

  constructor(options: DockerRunnerOptions = {}) {
    this.dockerBinary = options.dockerBinary ?? "docker";
    this.shellImage = options.shellImage ?? DEFAULT_DOCKER_SHELL_IMAGE;
    this.httpImage = options.httpImage ?? DEFAULT_DOCKER_HTTP_IMAGE;
    this.network = options.network ?? "none";
    this.memoryMb = options.memoryMb ?? 256;
    this.pidsLimit = options.pidsLimit ?? 128;
    this.cpus = options.cpus ?? 1;

    if (
      !this.dockerBinary ||
      !this.shellImage ||
      !this.httpImage ||
      !Number.isInteger(this.memoryMb) ||
      this.memoryMb < 16 ||
      !Number.isInteger(this.pidsLimit) ||
      this.pidsLimit < 1 ||
      !Number.isFinite(this.cpus) ||
      this.cpus <= 0
    ) {
      throw new Error("invalid DockerRunner configuration");
    }
    if (
      this.network !== "none" &&
      this.network !== "bridge" &&
      (!DOCKER_NETWORK_RE.test(this.network) || this.network === "host")
    ) {
      throw new Error(
        "DockerRunner network must be none, bridge, or a simple custom network name (host is refused)",
      );
    }
  }

  async exec(step: PocStep, ctx: ReplayRunnerContext): Promise<StepResult> {
    const startedAt = Date.now();
    const preflightError = this.networkPreflight(step, ctx.scope);
    if (preflightError) {
      return failedStep(step, startedAt, preflightError);
    }

    const command = this.commandForStep(step, ctx.stepTimeoutMs);
    if (typeof command === "string") {
      return failedStep(step, startedAt, command);
    }

    const safeStepId =
      step.id.replace(/[^a-zA-Z0-9_.-]/g, "_").slice(0, 64) || "step";
    const cidPath = join(
      ctx.runDir,
      `.0sec-docker-${safeStepId}-${randomUUID()}.cid`,
    );
    const args = this.dockerRunArgs(command, ctx.runDir, cidPath);
    const result = await runDockerCommand({
      dockerBinary: this.dockerBinary,
      args,
      runDir: ctx.runDir,
      cidPath,
      stepTimeoutMs: ctx.stepTimeoutMs,
    });

    if (!command.parseHttpStatus) return result;
    const parsed = parseDockerHttpStatus(result.stdoutFull);
    return {
      ...result,
      stdoutFull: parsed.stdout,
      ...(parsed.httpStatus === undefined ? {} : { httpStatus: parsed.httpStatus }),
    };
  }

  private networkPreflight(step: PocStep, scope: ScopePolicy | undefined): string | undefined {
    if (this.network === "none") return undefined;
    if (step.action.type !== "http") {
      return (
        "networked Docker replay only permits declarative HTTP steps; " +
        "shell and docker actions always run with network=none"
      );
    }
    let parsed: URL;
    try {
      parsed = new URL(step.action.url);
    } catch {
      return `invalid HTTP replay URL: ${step.action.url}`;
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return `Docker HTTP replay only permits http(s) URLs, got ${parsed.protocol}`;
    }
    if (!scope) {
      return "networked Docker replay requires an explicit engagement scope";
    }
    const scopeMatch = scope.match(step.action.url);
    return scopeMatch.allowed
      ? undefined
      : `Docker replay refused ${step.action.url}: ${scopeMatch.reason}`;
  }

  private commandForStep(step: PocStep, stepTimeoutMs: number): DockerStepCommand | string {
    switch (step.action.type) {
      case "shell":
        return {
          image: this.shellImage,
          command: ["/bin/sh", "-lc", step.action.cmd],
          parseHttpStatus: false,
        };
      case "docker":
        if (!step.action.image.trim()) return "Docker action is missing an image";
        return {
          image: step.action.image,
          // These arguments come after the image and therefore cannot alter
          // Docker's hardening flags (for example, they cannot add --privileged).
          command: step.action.args,
          parseHttpStatus: false,
        };
      case "http": {
        const method = step.action.method.trim().toUpperCase();
        if (!/^[A-Z]+$/.test(method)) {
          return `invalid HTTP method for Docker replay: ${step.action.method}`;
        }
        const headers = Object.entries(step.action.headers ?? {});
        if (
          headers.some(
            ([name, value]) =>
              !name.trim() ||
              /[\r\n]/.test(name) ||
              /[\r\n]/.test(value),
          )
        ) {
          return "HTTP replay headers must be non-empty single-line values";
        }
        const command = [
          "--silent",
          "--show-error",
          "--request",
          method,
          "--max-time",
          String(Math.max(1, Math.ceil(stepTimeoutMs / 1000))),
          "--output",
          "-",
          "--write-out",
          `${DOCKER_HTTP_STATUS_MARKER}%{http_code}\n`,
        ];
        for (const [name, value] of headers) {
          command.push("--header", `${name}: ${value}`);
        }
        if (step.action.body !== undefined) {
          command.push("--data-binary", step.action.body);
        }
        command.push(step.action.url);
        return {
          image: this.httpImage,
          dockerOptions: ["--entrypoint", "curl"],
          command,
          parseHttpStatus: true,
        };
      }
      case "note":
        return `DockerRunner only executes shell, docker, and http steps; got '${step.action.type}'`;
      default: {
        const _exhaustive: never = step.action;
        void _exhaustive;
        return "unsupported Docker replay action";
      }
    }
  }

  private dockerRunArgs(
    command: DockerStepCommand,
    runDir: string,
    cidPath: string,
  ): string[] {
    const args = [
      "run",
      "--rm",
      "--pull",
      "never",
      "--init",
      "--read-only",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges:true",
      "--pids-limit",
      String(this.pidsLimit),
      "--memory",
      `${this.memoryMb}m`,
      "--cpus",
      String(this.cpus),
      "--network",
      this.network,
      "--workdir",
      "/work",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=64m",
      "--mount",
      `type=bind,src=${resolve(runDir)},dst=/work`,
      "--cidfile",
      cidPath,
      ...(command.dockerOptions ?? []),
    ];
    if (typeof process.getuid === "function" && typeof process.getgid === "function") {
      args.push("--user", `${process.getuid()}:${process.getgid()}`);
    }
    args.push(command.image, ...command.command);
    return args;
  }
}


function failedStep(step: PocStep, startedAt: number, launchError: string): StepResult {
  return {
    argv: argvForStep(step),
    exitCode: null,
    stdoutFull: "",
    stderrFull: "",
    durationMs: Date.now() - startedAt,
    launchError,
  };
}

function parseDockerHttpStatus(stdout: string): {
  stdout: string;
  httpStatus?: number;
} {
  const markerIndex = stdout.lastIndexOf(DOCKER_HTTP_STATUS_MARKER);
  if (markerIndex === -1) return { stdout };
  const status = /^(\d{3})\r?\n?$/.exec(
    stdout.slice(markerIndex + DOCKER_HTTP_STATUS_MARKER.length),
  );
  if (!status) return { stdout };
  return {
    stdout: stdout.slice(0, markerIndex),
    httpStatus: Number(status[1]),
  };
}

async function runDockerCommand(args: {
  dockerBinary: string;
  args: string[];
  runDir: string;
  cidPath: string;
  stepTimeoutMs: number;
}): Promise<StepResult> {
  const startedAt = Date.now();
  const { promise, resolve: resolveResult } =
    promiseWithResolvers.withResolvers<StepResult>();
  let timer: NodeJS.Timeout | undefined;
  const argv = [args.dockerBinary, ...args.args];
  let stdout = "";
  let stderr = "";
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let timedOut = false;
  let settled = false;
  let timeoutCleanup: Promise<void> | undefined;
  let child: ChildProcess;

  const finish = async (exitCode: number | null, launchError?: string): Promise<void> => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    if (timeoutCleanup) await timeoutCleanup;
    const containerStarted = existsSync(args.cidPath);
    rmSync(args.cidPath, { force: true });
    const startError =
      launchError ??
      (exitCode !== 0 && !timedOut && !containerStarted
        ? `Docker sandbox did not start (exit ${exitCode ?? "unknown"}): ${excerpt(stderr, 512)}`
        : undefined);
    resolveResult({
      argv,
      exitCode,
      stdoutFull: stdout,
      stderrFull: stderr,
      durationMs: Date.now() - startedAt,
      ...(timedOut ? { timedOut: true } : {}),
      ...(startError ? { launchError: startError } : {}),
    });
  };

  try {
    child = spawn(args.dockerBinary, args.args, {
      cwd: args.runDir,
      env: allowlistedChildEnv({ "0SEC_VERIFY": "1" }),
      stdio: ["ignore", "pipe", "pipe"],
      detached: nodePlatform !== "win32",
    });
  } catch (err) {
    void finish(null, err instanceof Error ? err.message : String(err));
    return promise;
  }

  timer = setTimeout(() => {
    timedOut = true;
    timeoutCleanup = stopDockerContainer(
      args.dockerBinary,
      args.cidPath,
      args.runDir,
    ).finally(() => killProcessGroup(child));
  }, args.stepTimeoutMs);

  child.stdout?.on("data", (chunk: Buffer) => {
    if (stdoutBytes >= MAX_STREAM_CAPTURE_BYTES) return;
    const remaining = MAX_STREAM_CAPTURE_BYTES - stdoutBytes;
    const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
    stdout += slice.toString("utf8");
    stdoutBytes += slice.length;
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    if (stderrBytes >= MAX_STREAM_CAPTURE_BYTES) return;
    const remaining = MAX_STREAM_CAPTURE_BYTES - stderrBytes;
    const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
    stderr += slice.toString("utf8");
    stderrBytes += slice.length;
  });
  child.on("error", (err) => {
    void finish(null, err.message);
  });
  child.on("close", (code) => {
    void finish(typeof code === "number" ? code : null);
  });
  return promise;
}

async function stopDockerContainer(
  dockerBinary: string,
  cidPath: string,
  runDir: string,
): Promise<void> {
  let containerId: string | undefined;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      const candidate = readFileSync(cidPath, "utf8").trim();
      if (CONTAINER_ID_RE.test(candidate)) {
        containerId = candidate;
        break;
      }
    } catch {
      // The Docker client may still be pulling or creating the container.
    }
    const { promise, resolve } = promiseWithResolvers.withResolvers<void>();
    setTimeout(resolve, 25);
    await promise;
  }
  if (!containerId) return;
  await runDockerControl(dockerBinary, ["kill", containerId], runDir);
  await runDockerControl(dockerBinary, ["rm", "--force", containerId], runDir);
}

function runDockerControl(
  dockerBinary: string,
  args: string[],
  cwd: string,
): Promise<void> {
  const { promise, resolve } = promiseWithResolvers.withResolvers<void>();
  let child: ChildProcess;
  try {
    child = spawn(dockerBinary, args, {
      cwd,
      env: allowlistedChildEnv({ "0SEC_VERIFY": "1" }),
      stdio: "ignore",
      detached: nodePlatform !== "win32",
    });
  } catch {
    resolve();
    return promise;
  }
  const timer = setTimeout(() => {
    killProcessGroup(child);
  }, 5_000);
  child.once("error", () => {
    clearTimeout(timer);
    resolve();
  });
  child.once("close", () => {
    clearTimeout(timer);
    resolve();
  });
  return promise;
}

function killProcessGroup(child: ChildProcess): void {
  try {
    if (nodePlatform !== "win32" && child.pid) {
      process.kill(-child.pid, "SIGKILL");
    } else {
      child.kill("SIGKILL");
    }
  } catch {
    // The process may have completed between timeout and cleanup.
  }
}

// ── QemuRunner ──────────────────────────────────────────────────────────────
//
// QEMU replays shell PoCs in a fresh initramfs-only guest. The guest has no
// disk, no NIC, and only one writable 9p share: the replay run directory. That
// share carries the step script and evidence back to the host; the QEMU process
// itself runs as the invoking user, never as root.

export interface QemuRunnerOptions {
  /** QEMU system emulator. Defaults to the native architecture's emulator. */
  qemuBinary?: string;
  /** Kernel image for the disposable guest. */
  kernelImage?: string;
  /** Static BusyBox binary used to construct the initramfs. */
  busyboxPath?: string;
  /** Guest RAM limit. */
  memoryMb?: number;
  /** Guest vCPU count. */
  cpus?: number;
}

interface QemuProcessResult {
  exitCode: number | null;
  stdoutFull: string;
  stderrFull: string;
  durationMs: number;
  timedOut?: boolean;
  launchError?: string;
}

interface CpioEntry {
  name: string;
  mode: number;
  body: Buffer;
}

export class QemuRunner implements ReplayRunner {
  readonly kind: RunnerKind = "qemu";
  private readonly qemuBinary: string;
  private readonly kernelImage: string;
  private readonly busyboxPath: string;
  private readonly memoryMb: number;
  private readonly cpus: number;

  constructor(options: QemuRunnerOptions = {}) {
    this.qemuBinary =
      options.qemuBinary ??
      process.env["0SEC_REPLAY_QEMU_BINARY"]?.trim() ??
      (nodeArch === "arm64" ? "qemu-system-aarch64" : "qemu-system-x86_64");
    this.kernelImage =
      options.kernelImage ?? process.env["0SEC_REPLAY_QEMU_KERNEL"]?.trim() ?? "";
    this.busyboxPath =
      options.busyboxPath ?? process.env["0SEC_REPLAY_QEMU_BUSYBOX"]?.trim() ?? "";
    this.memoryMb = options.memoryMb ?? 512;
    this.cpus = options.cpus ?? 1;

    if (
      !this.qemuBinary ||
      !Number.isInteger(this.memoryMb) ||
      this.memoryMb < 128 ||
      !Number.isInteger(this.cpus) ||
      this.cpus < 1
    ) {
      throw new Error("invalid QemuRunner configuration");
    }
  }

  async exec(step: PocStep, ctx: ReplayRunnerContext): Promise<StepResult> {
    const startedAt = Date.now();
    if (!this.kernelImage || !this.busyboxPath) {
      return failedStep(
        step,
        startedAt,
        "QEMU replay requires kernelImage and busyboxPath (or 0SEC_REPLAY_QEMU_KERNEL and 0SEC_REPLAY_QEMU_BUSYBOX)",
      );
    }
    if (!existsSync(this.kernelImage) || !statSync(this.kernelImage).isFile()) {
      return failedStep(step, startedAt, `QEMU kernel image is not a file: ${this.kernelImage}`);
    }
    if (!existsSync(this.busyboxPath) || !statSync(this.busyboxPath).isFile()) {
      return failedStep(step, startedAt, `QEMU BusyBox binary is not a file: ${this.busyboxPath}`);
    }
    if (step.action.type !== "shell") {
      return failedStep(
        step,
        startedAt,
        `QemuRunner only executes shell steps in an offline guest; got '${step.action.type}'`,
      );
    }

    const guestCwd = qemuGuestWorkingDirectory(step.action.cwd);
    if (!guestCwd) {
      return failedStep(step, startedAt, "QEMU replay refuses an absolute step cwd");
    }
    const safeStepId =
      step.id.replace(/[^a-zA-Z0-9_.-]/g, "_").slice(0, 64) || "step";
    const workspaceName = `.0sec-qemu-${safeStepId}-${randomUUID()}`;
    const workspace = join(ctx.runDir, workspaceName);
    mkdirSync(workspace, { recursive: true });
    writeFileSync(join(workspace, "step.sh"), step.action.cmd, "utf8");

    const initrdPath = buildQemuInitramfs({
      runDir: ctx.runDir,
      busyboxPath: this.busyboxPath,
      workspaceName,
      guestCwd,
    });
    const args = this.qemuArgs(ctx.runDir, initrdPath);
    const qemu = await runQemuCommand({
      qemuBinary: this.qemuBinary,
      args,
      runDir: ctx.runDir,
      stepTimeoutMs: ctx.stepTimeoutMs,
    });
    const stdout = readQemuCapture(join(workspace, "stdout.log"));
    const guestStderr = readQemuCapture(join(workspace, "stderr.log"));
    const guestExitCode = readQemuExitCode(join(workspace, "exit-code"));
    const serial = qemu.stdoutFull
      ? `\n[qemu serial]\n${qemu.stdoutFull}`
      : "";
    const stderr = `${guestStderr}${qemu.stderrFull}${serial}`;
    const missingExitMarker =
      !qemu.timedOut && guestExitCode === null
        ? "QEMU guest did not write an exit marker; inspect serial evidence"
        : undefined;

    return {
      argv: [this.qemuBinary, ...args],
      exitCode: guestExitCode,
      stdoutFull: stdout,
      stderrFull: stderr,
      durationMs: qemu.durationMs,
      ...(qemu.timedOut ? { timedOut: true } : {}),
      ...(qemu.launchError || missingExitMarker
        ? { launchError: qemu.launchError ?? missingExitMarker }
        : {}),
    };
  }

  private qemuArgs(runDir: string, initrdPath: string): string[] {
    return [
      "-nodefaults",
      "-no-reboot",
      "-display",
      "none",
      "-monitor",
      "none",
      "-serial",
      "stdio",
      "-m",
      String(this.memoryMb),
      "-smp",
      String(this.cpus),
      "-kernel",
      this.kernelImage,
      "-initrd",
      initrdPath,
      "-append",
      "console=ttyS0 rdinit=/init panic=-1",
      "-virtfs",
      `local,path=${resolve(runDir)},mount_tag=0sec-replay,security_model=none,id=osecshare`,
      "-net",
      "none",
      "-sandbox",
      "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
    ];
  }
}

function qemuGuestWorkingDirectory(cwd: string | undefined): string | undefined {
  if (!cwd) return "/mnt/0sec";
  if (isAbsolute(cwd)) return undefined;
  const relative = resolve("/", cwd).slice(1);
  return relative ? `/mnt/0sec/${relative}` : "/mnt/0sec";
}

function buildQemuInitramfs(args: {
  runDir: string;
  busyboxPath: string;
  workspaceName: string;
  guestCwd: string;
}): string {
  const empty = Buffer.alloc(0);
  const init = Buffer.from(renderQemuInit(args.workspaceName, args.guestCwd), "utf8");
  const entries: CpioEntry[] = [
    { name: "bin", mode: 0o040755, body: empty },
    { name: "dev", mode: 0o040755, body: empty },
    { name: "mnt", mode: 0o040755, body: empty },
    { name: "mnt/0sec", mode: 0o040755, body: empty },
    { name: "proc", mode: 0o040755, body: empty },
    { name: "sys", mode: 0o040755, body: empty },
    { name: "tmp", mode: 0o040755, body: empty },
    { name: "bin/busybox", mode: 0o100755, body: readFileSync(args.busyboxPath) },
    { name: "init", mode: 0o100755, body: init },
  ];
  const chunks: Buffer[] = [];
  for (let index = 0; index < entries.length; index += 1) {
    appendNewcEntry(chunks, entries[index], index + 1);
  }
  appendNewcEntry(chunks, { name: "TRAILER!!!", mode: 0, body: empty }, 0);
  const initrdPath = join(args.runDir, `.0sec-qemu-initrd-${randomUUID()}.cpio.gz`);
  writeFileSync(initrdPath, gzipSync(Buffer.concat(chunks)));
  return initrdPath;
}

function appendNewcEntry(chunks: Buffer[], entry: CpioEntry, inode: number): void {
  const name = Buffer.from(`${entry.name}\0`, "utf8");
  const fields = [
    inode,
    entry.mode,
    0,
    0,
    1,
    0,
    entry.body.length,
    0,
    0,
    0,
    0,
    name.length,
    0,
  ];
  const header = Buffer.from(
    `070701${fields.map((field) => field.toString(16).padStart(8, "0")).join("")}`,
    "ascii",
  );
  chunks.push(header, name);
  const headerPadding = (4 - ((header.length + name.length) % 4)) % 4;
  if (headerPadding > 0) chunks.push(Buffer.alloc(headerPadding));
  chunks.push(entry.body);
  const bodyPadding = (4 - (entry.body.length % 4)) % 4;
  if (bodyPadding > 0) chunks.push(Buffer.alloc(bodyPadding));
}

function renderQemuInit(workspaceName: string, guestCwd: string): string {
  const workspace = `/mnt/0sec/${workspaceName}`;
  const step = `${workspace}/step.sh`;
  const stdout = `${workspace}/stdout.log`;
  const stderr = `${workspace}/stderr.log`;
  const exitCode = `${workspace}/exit-code`;
  return [
    "#!/bin/busybox sh",
    "/bin/busybox mkdir -p /proc /sys /dev /tmp /mnt/0sec",
    "/bin/busybox mount -t proc proc /proc",
    "/bin/busybox mount -t sysfs sysfs /sys",
    "/bin/busybox mount -t devtmpfs devtmpfs /dev 2>/dev/null || true",
    "if ! /bin/busybox mount -t 9p -o trans=virtio,version=9p2000.L 0sec-replay /mnt/0sec; then",
    '  echo "__0SEC_QEMU_MOUNT_FAILED__"',
    "  /bin/busybox poweroff -f",
    "fi",
    `(
      cd ${shellQuote(guestCwd)} || exit 125
      /bin/busybox sh ${shellQuote(step)}
    ) > ${shellQuote(stdout)} 2> ${shellQuote(stderr)}`,
    "rc=$?",
    `printf '%s\\n' "$rc" > ${shellQuote(exitCode)}`,
    "/bin/busybox sync",
    "/bin/busybox poweroff -f",
  ].join("\n");
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function readQemuCapture(path: string): string {
  try {
    return readFileSync(path).subarray(0, MAX_STREAM_CAPTURE_BYTES).toString("utf8");
  } catch {
    return "";
  }
}

function readQemuExitCode(path: string): number | null {
  try {
    const raw = readFileSync(path, "utf8").trim();
    if (!/^(0|[1-9][0-9]{0,2})$/.test(raw)) return null;
    const value = Number(raw);
    return value <= 255 ? value : null;
  } catch {
    return null;
  }
}

function runQemuCommand(args: {
  qemuBinary: string;
  args: string[];
  runDir: string;
  stepTimeoutMs: number;
}): Promise<QemuProcessResult> {
  const startedAt = Date.now();
  const { promise, resolve: resolveResult } =
    promiseWithResolvers.withResolvers<QemuProcessResult>();
  let timer: NodeJS.Timeout | undefined;
  let stdout = "";
  let stderr = "";
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let timedOut = false;
  let settled = false;
  let child: ChildProcess;

  const finish = (exitCode: number | null, launchError?: string): void => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    resolveResult({
      exitCode,
      stdoutFull: stdout,
      stderrFull: stderr,
      durationMs: Date.now() - startedAt,
      ...(timedOut ? { timedOut: true } : {}),
      ...(launchError ? { launchError } : {}),
    });
  };

  try {
    child = spawn(args.qemuBinary, args.args, {
      cwd: args.runDir,
      env: allowlistedChildEnv({ "0SEC_VERIFY": "1" }),
      stdio: ["ignore", "pipe", "pipe"],
      detached: nodePlatform !== "win32",
    });
  } catch (err) {
    finish(null, err instanceof Error ? err.message : String(err));
    return promise;
  }

  timer = setTimeout(() => {
    timedOut = true;
    killProcessGroup(child);
  }, args.stepTimeoutMs);
  child.stdout?.on("data", (chunk: Buffer) => {
    if (stdoutBytes >= MAX_STREAM_CAPTURE_BYTES) return;
    const remaining = MAX_STREAM_CAPTURE_BYTES - stdoutBytes;
    const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
    stdout += slice.toString("utf8");
    stdoutBytes += slice.length;
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    if (stderrBytes >= MAX_STREAM_CAPTURE_BYTES) return;
    const remaining = MAX_STREAM_CAPTURE_BYTES - stderrBytes;
    const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
    stderr += slice.toString("utf8");
    stderrBytes += slice.length;
  });
  child.on("error", (err) => {
    finish(null, err.message);
  });
  child.on("close", (code) => {
    const exitCode = typeof code === "number" ? code : null;
    finish(
      exitCode,
      exitCode !== 0 && !timedOut
        ? `QEMU exited before guest completion (exit ${exitCode ?? "unknown"})`
        : undefined,
    );
  });
  return promise;
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
      const expectedStatuses = Array.isArray(expect.status)
        ? expect.status
        : [expect.status];
      const actual = result.httpStatus ?? null;
      return {
        kind: "http_status",
        target: step.id,
        expected: Array.isArray(expect.status)
          ? expect.status.join(",")
          : expect.status,
        actual,
        passed: actual !== null && expectedStatuses.includes(actual),
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
    lastHttpStatus: number | null;
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
      const actual = ctx.lastHttpStatus;
      const expectedStatuses = String(input.expected)
        .split(",")
        .map((status) => Number(status.trim()))
        .filter((status) => Number.isInteger(status));
      return {
        ...input,
        actual,
        passed: actual !== null && expectedStatuses.includes(actual),
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
  /** Scope enforced by network-capable sandbox runners. */
  scope?: ScopePolicy;
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
    opts.runDir ?? mkdtempSync(join(tmpdir(), "0sec-replay-"));
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
  let lastHttpStatus: number | null = null;
  let aggregatedStdout = "";
  let runnerLaunchError: string | null = null;
  for (const step of steps) {
    let stepResult: StepResult;
    try {
      stepResult = await runner.exec(step, { runDir, stepTimeoutMs, scope: opts.scope });
    } catch (err) {
      // Runner-level failures are recorded as a synthetic command so the
      // canonical result remains attributable to the finding and runner.
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
    if (stepResult.launchError) {
      runnerLaunchError = stepResult.launchError;
    }
    lastHttpStatus = stepResult.httpStatus ?? null;

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
        lastHttpStatus,
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
