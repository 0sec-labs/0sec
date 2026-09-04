import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";

const READY_PREFIX = "0SEC_DASHBOARD_READY ";
const DEFAULT_STARTUP_TIMEOUT_MS = 20_000;
const GRACEFUL_STOP_TIMEOUT_MS = 5_000;
const STDERR_LIMIT = 4_096;

export interface DashboardSidecarInvocation {
  command: string;
  args: string[];
  cwd: string;
}

export interface DashboardSidecar {
  url: string;
  stop(): Promise<void>;
}

export interface DashboardSidecarLaunchOptions {
  assetDir: string;
  cwd: string;
  packaged: boolean;
  resourcesPath?: string;
  projectRoot?: string;
  platform?: NodeJS.Platform;
  arch?: NodeJS.Architecture;
  bunPath?: string;
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return normalized === "::1" || /^127(?:\.\d{1,3}){3}$/.test(normalized);
}

export function parseDashboardReadyLine(line: string): string | null {
  if (!line.startsWith(READY_PREFIX)) return null;

  try {
    const value: unknown = JSON.parse(line.slice(READY_PREFIX.length));
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const urlValue = (value as Record<string, unknown>).url;
    if (typeof urlValue !== "string") return null;

    const url = new URL(urlValue);
    if (
      url.protocol !== "http:"
      || !url.port
      || !isLoopbackHostname(url.hostname)
      || url.username
      || url.password
      || url.pathname !== "/"
      || url.search
      || url.hash
    ) {
      return null;
    }
    return url.origin;
  } catch {
    return null;
  }
}

export function sidecarResourceFileName(
  platform: NodeJS.Platform = process.platform,
  arch: NodeJS.Architecture = process.arch,
): string {
  if (arch !== "x64" && arch !== "arm64") {
    throw new Error(`Unsupported desktop architecture: ${arch}`);
  }

  switch (platform) {
    case "linux":
    case "darwin":
      return `0sec-${platform}-${arch}`;
    case "win32":
      return `0sec-windows-${arch}.exe`;
    default:
      throw new Error(`Unsupported desktop platform: ${platform}`);
  }
}

export function findWorkspaceRoot(startDirectory: string): string {
  let current = resolve(startDirectory);
  while (true) {
    if (existsSync(join(current, "pnpm-workspace.yaml"))) return current;
    const parent = dirname(current);
    if (parent === current) {
      throw new Error("Unable to locate the 0sec workspace. Set OSEC_DESKTOP_ROOT to the workspace path.");
    }
    current = parent;
  }
}

function dashboardArgs(assetDir: string): string[] {
  return [
    "dashboard",
    "--no-open",
    "--host",
    "127.0.0.1",
    "--port",
    "0",
    "--asset-dir",
    assetDir,
    "--ready-json",
  ];
}

function assertDashboardAssets(assetDir: string): void {
  if (!existsSync(join(assetDir, "index.html"))) {
    throw new Error(`Dashboard assets not found at ${assetDir}. Build @0sec/dashboard before launching desktop.`);
  }
}

function assertSidecar(path: string): void {
  if (!existsSync(path)) {
    throw new Error(
      `0sec desktop sidecar not found at ${path}. Build the matching dist-bin/0sec-* release binary before packaging.`,
    );
  }
}

/**
 * Builds an argv-only launch specification. The renderer never contributes a
 * command, an argument, or a filesystem path to this boundary.
 */
export function createDashboardSidecarInvocation(
  options: DashboardSidecarLaunchOptions,
): DashboardSidecarInvocation {
  assertDashboardAssets(options.assetDir);

  if (options.packaged) {
    if (!options.resourcesPath) throw new Error("Packaged desktop is missing its resources path.");
    const sidecar = join(
      options.resourcesPath,
      "sidecars",
      sidecarResourceFileName(options.platform, options.arch),
    );
    assertSidecar(sidecar);
    return { command: sidecar, args: dashboardArgs(options.assetDir), cwd: options.cwd };
  }

  const projectRoot = options.projectRoot ?? findWorkspaceRoot(process.env.OSEC_DESKTOP_ROOT ?? process.cwd());
  const cliEntrypoint = join(projectRoot, "packages", "cli", "dist", "index.js");
  if (!existsSync(cliEntrypoint)) {
    throw new Error(`CLI build not found at ${cliEntrypoint}. Run pnpm --filter 0sec-cli build first.`);
  }

  return {
    command: options.bunPath ?? process.env.BUN_PATH ?? "bun",
    args: [cliEntrypoint, ...dashboardArgs(options.assetDir)],
    cwd: options.cwd,
  };
}

function sidecarFailure(message: string, stderr: string): Error {
  const detail = stderr.trim();
  return new Error(detail ? `${message}\n${detail}` : message);
}

function waitForDashboardReady(child: ChildProcess, timeoutMs: number): Promise<string> {
  if (!child.stdout || !child.stderr) {
    throw new Error("Dashboard sidecar did not expose stdout and stderr pipes.");
  }

  const { promise, resolve: resolveReady, reject: rejectReady } = Promise.withResolvers<string>();
  const lines = createInterface({ input: child.stdout });
  let stderr = "";
  let settled = false;
  let timeout: ReturnType<typeof setTimeout> | undefined;

  const finish = (result: { url: string } | { error: Error }) => {
    if (settled) return;
    settled = true;
    clearTimeout(timeout);
    lines.close();
    child.off("error", onError);
    child.off("exit", onExit);
    child.stderr?.off("data", onStderr);
    if ("url" in result) resolveReady(result.url);
    else rejectReady(result.error);
  };

  const onLine = (line: string) => {
    const url = parseDashboardReadyLine(line);
    if (url) finish({ url });
  };
  const onStderr = (chunk: Buffer | string) => {
    stderr = `${stderr}${chunk.toString()}`.slice(-STDERR_LIMIT);
  };
  const onError = (error: Error) => {
    finish({ error: sidecarFailure(`Could not start the dashboard sidecar: ${error.message}`, stderr) });
  };
  const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
    finish({
      error: sidecarFailure(
        `Dashboard sidecar exited before it was ready (code ${code ?? "none"}, signal ${signal ?? "none"}).`,
        stderr,
      ),
    });
  };
  timeout = setTimeout(() => {
    finish({ error: sidecarFailure(`Dashboard sidecar did not become ready within ${timeoutMs}ms.`, stderr) });
  }, timeoutMs);

  lines.on("line", onLine);
  child.stderr.on("data", onStderr);
  child.once("error", onError);
  child.once("exit", onExit);
  return promise;
}

function waitForExit(child: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);

  const { promise, resolve: resolveExit } = Promise.withResolvers<boolean>();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const finish = (exited: boolean) => {
    clearTimeout(timeout);
    child.off("exit", onExit);
    child.off("error", onError);
    resolveExit(exited);
  };
  const onExit = () => finish(true);
  const onError = () => finish(true);
  timeout = setTimeout(() => finish(false), timeoutMs);
  child.once("exit", onExit);
  child.once("error", onError);
  return promise;
}

async function stopDashboardSidecar(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;

  try {
    child.kill("SIGTERM");
  } catch {
    return;
  }
  if (await waitForExit(child, GRACEFUL_STOP_TIMEOUT_MS)) return;

  try {
    child.kill("SIGKILL");
  } catch {
    return;
  }
  await waitForExit(child, GRACEFUL_STOP_TIMEOUT_MS);
}

export async function startDashboardSidecar(
  invocation: DashboardSidecarInvocation,
  startupTimeoutMs = DEFAULT_STARTUP_TIMEOUT_MS,
): Promise<DashboardSidecar> {
  let child: ChildProcess;
  try {
    child = spawn(invocation.command, invocation.args, {
      cwd: invocation.cwd,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
  } catch (error) {
    throw new Error(`Could not spawn dashboard sidecar: ${error instanceof Error ? error.message : String(error)}`);
  }

  try {
    const url = await waitForDashboardReady(child, startupTimeoutMs);
    return { url, stop: () => stopDashboardSidecar(child) };
  } catch (error) {
    await stopDashboardSidecar(child);
    throw error;
  }
}
