import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import { access, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";

export type ReplayStatus =
  | "reproduced"
  | "not_reproduced"
  | "inconclusive"
  | "error";

export interface ReplayCommand {
  argv: string[];
  exit_code: number | null;
  stdout_excerpt: string;
  stderr_excerpt: string;
}

export interface ReplayAssertion {
  kind: string;
  passed: boolean;
  detail: string;
}

export interface DeterministicReplayResult {
  status: ReplayStatus;
  mode: "deterministic_replay";
  finding_id: string;
  engine_version: string;
  started_at: string;
  completed_at: string;
  commands: ReplayCommand[];
  assertions: ReplayAssertion[];
  artifacts: Record<string, string>;
  summary: string;
  error_reason: string | null;
}

export interface CliPathTraversalFixtureOptions {
  /**
   * Command argv for the real CLI implementation under test. Arguments may
   * contain these placeholders:
   *   - {{apiUrl}} -> malicious local API base URL
   *   - {{exportDir}} -> sandboxed export directory
   *   - {{fixtureMode}} -> vulnerable or patched, for local test fixtures only
   */
  commandArgv?: string[];
  /**
   * `vulnerable` writes returned file paths directly. `patched` rejects paths
   * that resolve outside the selected export directory and acts as the
   * negative control for the replay harness.
   */
  fixtureMode?: "vulnerable" | "patched";
  /** Keep the sandbox, fixture script, and stdout/stderr files after running. */
  retainArtifacts?: boolean;
  /**
   * Sandbox root. When omitted, a fresh pwnkit-verify-* directory is created
   * under os.tmpdir(). Passing an explicit directory implies artifact
   * retention so a caller-chosen path is never deleted by surprise.
   */
  artifactDir?: string;
  /** Per-command timeout. */
  timeoutMs?: number;
  /** Version string to record in the emitted result. */
  engineVersion?: string;
}

interface CapturedCommand {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  error?: string;
}

const FIXTURE_ID = "fixture:cli-path-traversal";
const DEFAULT_TIMEOUT_MS = 10_000;
const SIGKILL_GRACE_MS = 1_000;
const CAPTURE_BYTES = 1024 * 1024;
const EXCERPT_BYTES = 4 * 1024;

function excerpt(text: string, max = EXCERPT_BYTES): string {
  if (text.length <= max) return text;
  return text.slice(0, max) + "...[truncated]";
}

function isInside(root: string, candidate: string): boolean {
  return candidate === root || candidate.startsWith(root + sep);
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function appendCapped(current: string, chunk: Buffer): string {
  if (current.length >= CAPTURE_BYTES) return current;
  const next = current + chunk.toString("utf8");
  if (next.length <= CAPTURE_BYTES) return next;
  return next.slice(0, CAPTURE_BYTES) + "\n...[truncated at 1MiB]";
}

async function runCommand(
  argv: string[],
  options: { cwd: string; timeoutMs: number },
): Promise<CapturedCommand> {
  return await new Promise((resolveCommand) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let killTimer: ReturnType<typeof setTimeout> | undefined;

    const child = spawn(argv[0], argv.slice(1), {
      cwd: options.cwd,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const finish = (result: CapturedCommand) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      resolveCommand(result);
    };

    timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      killTimer = setTimeout(() => {
        if (settled) return;
        child.kill("SIGKILL");
        finish({
          exitCode: null,
          stdout,
          stderr,
          timedOut,
          error: `command timed out after ${options.timeoutMs}ms and did not exit after SIGTERM`,
        });
      }, SIGKILL_GRACE_MS);
    }, options.timeoutMs);

    child.stdout?.on("data", (chunk: Buffer) => {
      stdout = appendCapped(stdout, chunk);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr = appendCapped(stderr, chunk);
    });
    child.on("error", (err) => {
      finish({
        exitCode: null,
        stdout,
        stderr,
        timedOut,
        error: err instanceof Error ? err.message : String(err),
      });
    });
    child.on("close", (code) => {
      finish({
        exitCode: code,
        stdout,
        stderr,
        timedOut,
        error: timedOut ? `command timed out after ${options.timeoutMs}ms` : undefined,
      });
    });
  });
}

async function startMaliciousExportServer(): Promise<{
  server: Server;
  baseUrl: string;
}> {
  const payload = {
    rootPath: "demo",
    paperclipExtensionPath: null,
    warnings: [],
    files: {
      "../escaped-marker": "pwnkit deterministic verification\n",
      "README.md": "normal export content\n",
    },
  };

  const server = createServer((req, res) => {
    if (req.method === "GET" && req.url === "/company/export") {
      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(payload));
      return;
    }
    res.statusCode = 404;
    res.end("not found");
  });

  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", () => resolveListen());
  });

  const address = server.address();
  if (!address || typeof address === "string") {
    await closeServer(server);
    throw new Error("failed to allocate fixture server port");
  }

  return {
    server,
    baseUrl: `http://127.0.0.1:${address.port}`,
  };
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolveClose) => {
    server.close(() => resolveClose());
  });
}

function expandCommandArgv(
  argv: string[],
  replacements: { apiUrl: string; exportDir: string; fixtureMode: string },
): string[] {
  return argv.map((arg) =>
    arg
      .replaceAll("{{apiUrl}}", replacements.apiUrl)
      .replaceAll("{{exportDir}}", replacements.exportDir)
      .replaceAll("{{fixtureMode}}", replacements.fixtureMode),
  );
}

function assertion(
  kind: string,
  passed: boolean,
  detail: string,
): ReplayAssertion {
  return { kind, passed, detail };
}

async function buildAssertions(paths: {
  sandboxRoot: string;
  exportDir: string;
  escapedPath: string;
  insideExportPath: string;
}): Promise<ReplayAssertion[]> {
  const [sandboxReal, exportReal] = await Promise.all([
    realpath(paths.sandboxRoot),
    realpath(paths.exportDir),
  ]);
  const escapedExists = await exists(paths.escapedPath);
  const insideExportExists = await exists(paths.insideExportPath);

  let escapedReal = resolve(paths.escapedPath);
  if (escapedExists) {
    escapedReal = await realpath(paths.escapedPath);
  }

  const homeReal = await realpath(homedir()).catch(() => homedir());
  const profileNames = new Set([".bashrc", ".zshrc", ".profile", ".bash_profile"]);
  const escapedBase = escapedReal.split(sep).at(-1) ?? "";
  const escapedInsideHome = isInside(homeReal, escapedReal);
  const escapedMatchesProfile = profileNames.has(escapedBase);
  const noHomeProfileTouch = !escapedInsideHome && !escapedMatchesProfile;
  const noHomeProfileTouchDetail = escapedInsideHome
    ? `touched path ${escapedReal} is inside home directory ${homeReal}`
    : escapedMatchesProfile
      ? `touched path ${escapedReal} matches profile basename ${escapedBase}`
      : `touched path ${escapedReal} is not a home directory or shell profile target`;

  return [
    assertion(
      "filesystem_exists",
      escapedExists,
      escapedExists
        ? `escaped marker exists at ${escapedReal}`
        : `escaped marker not found at ${paths.escapedPath}`,
    ),
    assertion(
      "filesystem_not_exists",
      !insideExportExists,
      insideExportExists
        ? `unexpected marker found inside export root at ${paths.insideExportPath}`
        : `no escaped marker exists inside export root at ${paths.insideExportPath}`,
    ),
    assertion(
      "path_outside_export_root",
      escapedExists && !isInside(exportReal, escapedReal),
      escapedExists
        ? `escaped marker realpath ${escapedReal} is outside export root ${exportReal}`
        : "escaped marker missing, so export-root escape was not reproduced",
    ),
    assertion(
      "path_inside_sandbox",
      escapedExists && isInside(sandboxReal, escapedReal),
      escapedExists
        ? `escaped marker stayed inside sandbox ${sandboxReal}`
        : "escaped marker missing, so sandbox containment could not be proven",
    ),
    assertion(
      "no_home_profile_touch",
      noHomeProfileTouch,
      noHomeProfileTouchDetail,
    ),
  ];
}

function resultStatus(args: {
  command: CapturedCommand;
  assertions: ReplayAssertion[];
}): ReplayStatus {
  const required = new Set([
    "filesystem_exists",
    "filesystem_not_exists",
    "path_outside_export_root",
    "path_inside_sandbox",
    "no_home_profile_touch",
  ]);
  const filesystemAssertions = args.assertions.filter((a) => required.has(a.kind));
  if (filesystemAssertions.length > 0) {
    if (
      filesystemAssertions.some(
        (a) => a.kind === "filesystem_exists" && a.passed,
      )
    ) {
      return "reproduced";
    }
    if (args.command.timedOut) return "error";
    if (args.command.error && args.command.exitCode === null) return "error";
    return "not_reproduced";
  }

  if (args.command.error && args.command.exitCode === null) return "error";
  if (args.command.timedOut) return "error";
  if (args.command.exitCode !== 0) return "error";
  return "inconclusive";
}

function summaryFor(status: ReplayStatus): string {
  switch (status) {
    case "reproduced":
      return "CLI path traversal replay wrote a marker outside the selected export directory inside the sandbox.";
    case "not_reproduced":
      return "CLI path traversal replay completed but did not write outside the selected export directory.";
    case "inconclusive":
      return "CLI path traversal replay was inconclusive.";
    case "error":
      return "CLI path traversal replay failed before reaching a reliable verdict.";
  }
}

/**
 * Run the deterministic CLI path traversal replay from pwnkit#195.
 *
 * The fixture starts a malicious local API server and runs the caller-supplied
 * CLI command against a sandboxed export directory. The harness itself never
 * implements export behavior; the verdict comes from the CLI under test plus
 * filesystem assertions over the sandbox.
 */
export async function runCliPathTraversalReplayFixture(
  options: CliPathTraversalFixtureOptions = {},
): Promise<DeterministicReplayResult> {
  const startedAt = new Date().toISOString();
  const fixtureMode = options.fixtureMode ?? "vulnerable";
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const retainArtifacts = options.retainArtifacts || Boolean(options.artifactDir);
  const sandboxRoot = options.artifactDir
    ? resolve(options.artifactDir)
    : await mkdtemp(join(tmpdir(), "pwnkit-verify-"));
  const exportDir = join(sandboxRoot, "export");
  const harnessDir = join(sandboxRoot, "harness");
  const harnessRef = join(harnessDir, "harness.json");
  const stdoutRef = join(sandboxRoot, "stdout.log");
  const stderrRef = join(sandboxRoot, "stderr.log");
  const artifacts: Record<string, string> = {};
  if (retainArtifacts) {
    artifacts.sandbox_ref = sandboxRoot;
    artifacts.harness_ref = harnessRef;
    artifacts.stdout_ref = stdoutRef;
    artifacts.stderr_ref = stderrRef;
    artifacts.export_ref = exportDir;
  }
  let server: Server | undefined;
  let argv: string[] = [];
  let command: CapturedCommand | undefined;

  try {
    await mkdir(exportDir, { recursive: true });
    const fixture = await startMaliciousExportServer();
    server = fixture.server;

    if (!options.commandArgv || options.commandArgv.length === 0) {
      throw new Error(
        "cli-path-traversal fixture requires commandArgv for the real CLI under test",
      );
    }
    argv = expandCommandArgv(options.commandArgv, {
      apiUrl: fixture.baseUrl,
      exportDir,
      fixtureMode,
    });
    await mkdir(harnessDir, { recursive: true });
    await writeFile(
      harnessRef,
      JSON.stringify(
        {
          fixture: "cli-path-traversal",
          fixtureMode,
          commandArgv: options.commandArgv,
          expandedArgv: argv,
          apiUrl: fixture.baseUrl,
          exportDir,
        },
        null,
        2,
      ) + "\n",
      "utf8",
    );

    command = await runCommand(argv, {
      cwd: sandboxRoot,
      timeoutMs,
    });

    await writeFile(stdoutRef, command.stdout, "utf8");
    await writeFile(stderrRef, command.stderr, "utf8");

    const assertions = await buildAssertions({
      sandboxRoot,
      exportDir,
      escapedPath: join(sandboxRoot, "escaped-marker"),
      insideExportPath: join(exportDir, "escaped-marker"),
    });
    if (command.exitCode !== 0 || command.error) {
      assertions.unshift(
        assertion(
          "command_exit_zero",
          false,
          command.error ?? `fixture command exited ${String(command.exitCode)}`,
        ),
      );
    } else {
      assertions.unshift(
        assertion("command_exit_zero", true, "fixture command exited 0"),
      );
    }

    const status = resultStatus({ command, assertions });
    return {
      status,
      mode: "deterministic_replay",
      finding_id: FIXTURE_ID,
      engine_version: options.engineVersion ?? "unknown",
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      commands: [
        {
          argv,
          exit_code: command.exitCode,
          stdout_excerpt: excerpt(command.stdout),
          stderr_excerpt: excerpt(command.stderr),
        },
      ],
      assertions,
      artifacts,
      summary: summaryFor(status),
      error_reason: status === "error" ? command.error ?? "fixture command failed" : null,
    };
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    return {
      status: "error",
      mode: "deterministic_replay",
      finding_id: FIXTURE_ID,
      engine_version: options.engineVersion ?? "unknown",
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      commands: command
        ? [
            {
              argv,
              exit_code: command.exitCode,
              stdout_excerpt: excerpt(command.stdout),
              stderr_excerpt: excerpt(command.stderr),
            },
          ]
        : [],
      assertions: [],
      artifacts,
      summary: summaryFor("error"),
      error_reason: reason,
    };
  } finally {
    if (server) await closeServer(server);
    if (!retainArtifacts) {
      await rm(sandboxRoot, { recursive: true, force: true });
    }
  }
}
