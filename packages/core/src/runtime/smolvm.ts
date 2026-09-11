import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants, createWriteStream } from "node:fs";
import { mkdir, mkdtemp, open, readdir, readFile, readlink, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, posix } from "node:path";
import { pipeline } from "node:stream/promises";
import { setTimeout as delay } from "node:timers/promises";
import { allowlistedChildEnv } from "../agent/sanitized-env.js";

const IMAGE_DIGEST = /^sha256:[a-f0-9]{64}$/;
const MAX_IMAGE_BYTES = 8 * 1024 ** 3;
const CLEANUP_TIMEOUT_MS = 10000;

export interface SmolvmExecutionOptions {
  imageArchive: string;
  imageDigest?: string;
  command: string[];
  stdin?: string;
  /** Explicit source directories; every mount is read-only. */
  mounts?: Array<{ source: string; target: string }>;
  timeoutMs: number;
  memoryMb: number;
  cpus: number;
  maxOutputBytes: number;
  signal?: AbortSignal;
  binary?: string;
  storageGb?: number;
}

export interface SmolvmExecutionResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
  error?: string;
}

async function hashArchive(path: string, destination?: string, signal?: AbortSignal): Promise<string> {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size === 0 || stat.size > MAX_IMAGE_BYTES) {
      throw new Error("smolvm image must be a nonempty regular archive no larger than 8 GiB");
    }
    const hash = createHash("sha256");
    const source = file.createReadStream({ autoClose: false, signal });
    if (destination) {
      source.on("data", (chunk: Buffer) => hash.update(chunk));
      await pipeline(source, createWriteStream(destination, { flags: "wx", mode: 0o600 }), { signal });
    } else {
      for await (const chunk of source) hash.update(chunk);
    }
    return `sha256:${hash.digest("hex")}`;
  } finally {
    await file.close();
  }
}

/** Archive-byte identity, not an OCI manifest or Docker daemon image ID. */
export async function resolveSmolvmImage(path: string): Promise<string> {
  return hashArchive(path);
}

function validate(options: SmolvmExecutionOptions): void {
  if (process.platform !== "linux" || process.getuid?.() === 0) {
    throw new Error("the qualified smolvm backend requires a non-root Linux host with KVM and setpriv");
  }
  for (const [name, value, minimum, maximum] of [
    ["cpus", options.cpus, 1, 16], ["memoryMb", options.memoryMb, 32, 16384],
    ["storageGb", options.storageGb ?? 4, 1, 64], ["timeoutMs", options.timeoutMs, 100, 600000],
    ["maxOutputBytes", options.maxOutputBytes, 256, 16 * 1024 * 1024],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`invalid smolvm ${name}`);
  }
  if (!options.command.length || !options.command[0] || options.command.some((arg) => typeof arg !== "string" || arg.includes("\0"))) {
    throw new Error("smolvm command must be a nonempty argv without NUL bytes");
  }
  if (options.imageDigest !== undefined && !IMAGE_DIGEST.test(options.imageDigest)) throw new Error("invalid smolvm archive digest");
  if (options.stdin !== undefined && (typeof options.stdin !== "string" || Buffer.byteLength(options.stdin) > 16 * 1024 * 1024)) {
    throw new Error("smolvm input exceeds 16 MiB or is not a string");
  }
}

function launcherEnvironment(root: string): NodeJS.ProcessEnv {
  const env = allowlistedChildEnv();
  // Separate configuration, registry, caches, sockets and cwd from both the
  // operator's smolvm state and untrusted project Smolfiles. Never inherit
  // SMOLVM_EXTRA_DISK, registry credentials, proxies or guest feature overrides.
  Object.assign(env, {
    HOME: join(root, "h"), XDG_CACHE_HOME: join(root, "c"), XDG_DATA_HOME: join(root, "d"),
    XDG_CONFIG_HOME: join(root, "f"), XDG_RUNTIME_DIR: join(root, "r"), TMPDIR: join(root, "t"),
  });
  for (const key of ["SMOLVM_LIB_DIR", "SMOLVM_AGENT_ROOTFS"] as const) {
    if (process.env[key]) env[key] = process.env[key];
  }
  if (env.SMOLVM_LIB_DIR) env.LD_LIBRARY_PATH = env.SMOLVM_LIB_DIR;
  return env;
}

function version(binary: string, cwd: string, env: NodeJS.ProcessEnv, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile(binary, ["--version"], { cwd, env, signal, timeout: 5000, killSignal: "SIGKILL", maxBuffer: 4096 }, (error, stdout, stderr) => {
      if (error) reject(new Error(`smolvm runtime unavailable: ${stderr.trim() || error.message}`));
      else if (stdout.trim() !== "smolvm 1.14.6") reject(new Error("smolvm 1.14.6 is required; other versions need lifecycle qualification"));
      else resolve();
    });
  });
}

/** Observe only processes carrying this private run's path. Never signal a PID
 * learned from guest output or a stale registry. The pinned runtime watchdog
 * kills its VM when its foreground CLI dies; we wait for that teardown AND the
 * detached cleanup helper rather than treating CLI exit as VM termination. */
async function ownedProcesses(root: string): Promise<number[]> {
  const processes: number[] = [];
  for (const entry of await readdir("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const command = await readFile(`/proc/${entry}/cmdline`);
      if (!command.includes(`${root}/`) && !(command.includes("smolvm")
        && await readlink(`/proc/${entry}/cwd`) === root)) continue;
      const stat = await readFile(`/proc/${entry}/stat`, "utf8");
      if (stat.slice(stat.lastIndexOf(")") + 2).startsWith("Z ")) continue;
      processes.push(Number(entry));
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT" && code !== "ESRCH" && code !== "EACCES") throw error;
    }
  }
  return processes;
}

async function cleanup(root: string): Promise<void> {
  const deadline = performance.now() + CLEANUP_TIMEOUT_MS;
  let quiet = false;
  while (performance.now() < deadline) {
    if ((await ownedProcesses(root)).length === 0) {
      if (quiet) { await rm(root, { recursive: true, force: true }); return; }
      quiet = true;
    } else quiet = false;
    await delay(50);
  }
  throw new Error(`smolvm cleanup did not confirm VM termination; retained recovery state at ${root}`);
}

/** One offline, non-root guest. No Docker, image pull, shared writable host
 * filesystem, or host-execution fallback. Linux setpriv ties the CLI to its
 * controller; smolvm's foreground watchdog in turn ties the VM to the CLI. */
export async function runSmolvm(options: SmolvmExecutionOptions): Promise<SmolvmExecutionResult> {
  validate(options);
  options.signal?.throwIfAborted();
  const start = performance.now();
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, options.timeoutMs);
  const onAbort = () => controller.abort();
  options.signal?.addEventListener("abort", onAbort, { once: true });
  if (options.signal?.aborted) controller.abort();
  let root: string | undefined;
  const result: SmolvmExecutionResult = { exitCode: null, stdout: "", stderr: "", durationMs: 0, timedOut: false };
  try {
    root = await mkdtemp(join(tmpdir(), "0s-"));
    await Promise.all(["h", "c", "d", "f", "r", "t"].map((directory) => mkdir(join(root!, directory), { mode: 0o700 })));
    const env = launcherEnvironment(root);
    const binary = options.binary ?? "smolvm";
    await version(binary, root, env, controller.signal);
    const archive = join(root, "image.tar");
    const digest = await hashArchive(options.imageArchive, archive, controller.signal);
    if (options.imageDigest && digest !== options.imageDigest) throw new Error("smolvm archive identity mismatch");
    const args = ["--pdeathsig", "KILL", "--", binary, "machine", "run", "--image", archive,
      "--unprivileged", "--user", "1000:1000", "--cpus", String(options.cpus),
      "--mem", String(options.memoryMb), "--storage", String(options.storageGb ?? 4), "--overlay", "1", "--interactive"];
    const targets = new Set<string>();
    for (const mount of options.mounts ?? []) {
      const source = await realpath(mount.source);
      if (source.includes(":") || source.includes("\0") || !isAbsolute(mount.target)
        || posix.normalize(mount.target) !== mount.target || mount.target === "/" || /[:\0]/.test(mount.target)
        || targets.has(mount.target)) throw new Error("invalid or duplicate smolvm read-only mount");
      targets.add(mount.target);
      args.push("--volume", `${source}:${mount.target}:ro`);
    }
    args.push("--", ...options.command);
    controller.signal.throwIfAborted();
    await new Promise<void>((resolve) => {
      const child = spawn("setpriv", args, { cwd: root, env, stdio: ["pipe", "pipe", "pipe"], detached: true });
      const stdout: Buffer[] = [], stderr: Buffer[] = [];
      let stdoutBytes = 0, stderrBytes = 0;
      let prefix = Buffer.alloc(0);
      let banner = false;
      let settled = false;
      const stop = (reason: string) => {
        result.error ??= reason;
        if (child.pid && !settled) {
          try { process.kill(-child.pid, "SIGKILL"); }
          catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") result.error += `; ${String(error)}`; }
        }
      };
      const abort = () => stop(timedOut ? "smolvm execution timed out" : "smolvm execution cancelled by operator");
      const collect = (chunk: Buffer, destination: Buffer[], count: number): number => {
        const keep = chunk.subarray(0, Math.max(0, options.maxOutputBytes - count));
        if (keep.length) destination.push(keep);
        if (count + chunk.length > options.maxOutputBytes) stop("smolvm output exceeded its byte limit");
        return count + keep.length;
      };
      child.stdout.on("data", (chunk: Buffer) => { stdoutBytes = collect(chunk, stdout, stdoutBytes); });
      child.stderr.on("data", (chunk: Buffer) => {
        if (!banner) {
          prefix = Buffer.concat([prefix, chunk]);
          const newline = prefix.indexOf(10);
          if (newline < 0 && prefix.length <= 4096) return;
          if (newline < 0 || !/^Starting ephemeral machine \(vm-[a-f0-9]+\)\.\.\.\r?\n$/.test(prefix.subarray(0, newline + 1).toString("utf8"))) {
            stderrBytes = collect(prefix, stderr, stderrBytes);
            prefix = Buffer.alloc(0);
            stop("smolvm did not establish the qualified ephemeral execution protocol");
            return;
          }
          banner = true;
          chunk = prefix.subarray(newline + 1);
          prefix = Buffer.alloc(0);
        }
        stderrBytes = collect(chunk, stderr, stderrBytes);
      });
      child.stdin.on("error", (error: NodeJS.ErrnoException) => {
        if (error.code !== "EPIPE") stop(`smolvm input delivery failed: ${error.message}`);
      });
      child.on("error", (error) => { result.error ??= `smolvm launch failed: ${error.message}`; });
      child.on("close", (code, signal) => {
        settled = true;
        controller.signal.removeEventListener("abort", abort);
        result.exitCode = code;
        if (prefix.length) stderrBytes = collect(prefix, stderr, stderrBytes);
        result.stdout = Buffer.concat(stdout, stdoutBytes).toString("utf8");
        result.stderr = Buffer.concat(stderr, stderrBytes).toString("utf8");
        if (!banner || signal) result.error ??= `smolvm launcher failed${signal ? ` (${signal})` : " before guest execution"}`;
        resolve();
      });
      controller.signal.addEventListener("abort", abort, { once: true });
      if (controller.signal.aborted) abort();
      else child.stdin.end(options.stdin ?? "");
    });
  } catch (error) {
    result.error = controller.signal.aborted
      ? timedOut ? "smolvm execution timed out" : "smolvm execution cancelled by operator"
      : error instanceof Error ? error.message : String(error);
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", onAbort);
    if (root) {
      try { await cleanup(root); }
      catch (error) { result.error = `${result.error ? `${result.error}; ` : ""}${String(error)}`; }
    }
    result.timedOut = timedOut;
    result.durationMs = performance.now() - start;
  }
  return result;
}
