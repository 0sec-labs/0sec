import { execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { canonicalEvolutionJson, parseEvolutionConfig } from "./config.js";
import { verifyEvolutionSnapshot } from "./registry.js";
import { allowlistedChildEnv } from "../agent/sanitized-env.js";
import { resolveSmolvmImage, runSmolvm } from "../runtime/smolvm.js";
import type { EvolutionConfig, EvolutionExecution, EvolutionSandbox } from "./types.js";

const IMAGE_ID = /^sha256:[a-f0-9]{64}$/;
const CONTROL_TIMEOUT_MS = 5000;

// Node >=24 supplies this API; the repository's ES2022 lib omits its type.
const deferredPromise = Promise as PromiseConstructor & {
  withResolvers<T>(): { promise: Promise<T>; resolve(value: T): void; reject(reason: unknown): void };
};

function dockerEnvironment(): NodeJS.ProcessEnv {
  const env = allowlistedChildEnv();
  for (const key of ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "XDG_RUNTIME_DIR"]) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  return env;
}

function control(binary: string, args: string[], timeout: number, signal?: AbortSignal): Promise<string> {
  const { promise, resolve, reject } = deferredPromise.withResolvers<string>();
  execFile(binary, args, { env: dockerEnvironment(), encoding: "utf8", timeout, killSignal: "SIGKILL", maxBuffer: 65536, signal },
    (error, stdout, stderr) => {
      if (error) reject(new Error(`Docker ${args[0]} failed: ${stderr.trim() || error.message}`));
      else resolve(stdout.trim());
    });
  return promise;
}

/** Resolve a locally installed image; never pull or substitute a mutable image. */
export async function resolveEvolutionImage(image: string, dockerBinary = "docker"): Promise<string> {
  if (typeof image !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9_./:@-]*$/.test(image)) {
    throw new Error("invalid evolution image reference");
  }
  const id = await control(dockerBinary, ["image", "inspect", "--format", "{{.Id}}", image], CONTROL_TIMEOUT_MS);
  if (!IMAGE_ID.test(id)) throw new Error("Docker did not return an immutable image identity");
  return id;
}

function quoteCommand(argv: string[]): string {
  return argv.map((argument) => `'${argument.replace(/'/g, `'\\''`)}'`).join(" ");
}

function workerScript(config: EvolutionConfig, workspace = "/workspace"): string {
  return [
    "set -eu",
    `mkdir -p ${quoteCommand([workspace])}`,
    `cd ${quoteCommand([workspace])}`,
    `cp -R /snapshot/. ${quoteCommand([workspace])}/`,
    `chmod -R u+rwX ${quoteCommand([workspace])}`,
    ...(config.buildCommand ? [`${quoteCommand(config.buildCommand)} >&2`] : []),
    `exec ${quoteCommand(config.command)}`,
  ].join("\n");
}

/** Source executes only inside a fresh non-root, networkless container. */
export function createDockerEvolutionSandbox(dockerBinary = "docker"): EvolutionSandbox {
  return async ({ snapshot, config: rawConfig, input, signal }): Promise<EvolutionExecution> => {
    const config = parseEvolutionConfig(rawConfig);
    signal?.throwIfAborted();
    if (typeof process.getuid !== "function" || typeof process.getgid !== "function" || process.getuid() === 0) {
      throw new Error("evolution workers require a non-root POSIX host user");
    }
    verifyEvolutionSnapshot(snapshot);
    if (snapshot.root.includes(",")) throw new Error("snapshot path cannot contain a Docker mount separator");
    const stdin = canonicalEvolutionJson(input);
    const image = IMAGE_ID.test(config.image) ? config.image : await resolveEvolutionImage(config.image, dockerBinary);
    const name = `0sec-evolution-${randomUUID()}`;
    const uid = process.getuid();
    const gid = process.getgid();
    const start = performance.now();
    let created = false;
    let execution: EvolutionExecution = { exitCode: null, stdout: "", stderr: "", durationMs: 0, timedOut: false };
    try {
      // Creation completes before start: cancellation can remove a known named
      // container instead of racing an in-flight `docker run` creation request.
      await control(dockerBinary, [
        "create", "--name", name, "--pull", "never", "--interactive", "--init",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--pids-limit", "64", "--memory", `${config.memoryMb}m`, "--memory-swap", `${config.memoryMb}m`,
        "--cpus", String(config.cpus), "--network", "none", "--user", `${uid}:${gid}`,
        "--workdir", "/workspace", "--mount", `type=bind,src=${snapshot.root},dst=/snapshot,ro`,
        "--tmpfs", `/workspace:rw,nosuid,nodev,mode=0700,uid=${uid},gid=${gid},size=${config.memoryMb}m`,
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
        image, "/bin/sh", "-c", workerScript(config),
      ], Math.min(config.timeoutMs, 30000), signal);
      created = true;
      signal?.throwIfAborted();
      const remainingMs = config.timeoutMs - (performance.now() - start);
      if (remainingMs <= 0) throw new Error("sandbox timeout during container creation");
      const pending = deferredPromise.withResolvers<EvolutionExecution>();
      const child = spawn(dockerBinary, ["start", "--attach", "--interactive", name], {
        env: dockerEnvironment(), stdio: ["pipe", "pipe", "pipe"],
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let failure: string | undefined;
      let timedOut = false;
      let settled = false;
      const stop = (reason: string) => {
        failure ??= reason;
        child.kill("SIGKILL");
      };
      const onAbort = () => stop("sandbox cancelled by operator");
      const timer = setTimeout(() => { timedOut = true; stop("sandbox execution timed out"); }, remainingMs);
      signal?.addEventListener("abort", onAbort, { once: true });
      const collect = (chunk: Buffer, destination: Buffer[], bytes: number): number => {
        const kept = chunk.subarray(0, Math.max(0, config.maxOutputBytes - bytes));
        if (kept.length) destination.push(kept);
        if (bytes + chunk.length > config.maxOutputBytes) stop("sandbox output exceeded its byte limit");
        return bytes + kept.length;
      };
      child.stdout.on("data", (chunk: Buffer) => { stdoutBytes = collect(chunk, stdout, stdoutBytes); });
      child.stderr.on("data", (chunk: Buffer) => { stderrBytes = collect(chunk, stderr, stderrBytes); });
      child.stdin.on("error", (error: Error) => stop(`sandbox input delivery failed: ${error.message}`));
      const finish = (code: number | null, error?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        pending.resolve({
          exitCode: code, stdout: Buffer.concat(stdout, stdoutBytes).toString("utf8"),
          stderr: Buffer.concat(stderr, stderrBytes).toString("utf8"), durationMs: performance.now() - start, timedOut,
          ...((failure || error) ? { error: failure ?? error!.message } : {}),
        });
      };
      child.on("error", (error) => finish(null, error));
      child.on("close", (code) => finish(code));
      if (signal?.aborted) onAbort();
      else child.stdin.end(stdin);
      execution = await pending.promise;
    } catch (error) {
      execution.error = error instanceof Error ? error.message : String(error);
      execution.timedOut = !signal?.aborted && performance.now() - start >= config.timeoutMs;
    } finally {
      try { await control(dockerBinary, ["rm", "--force", name], CONTROL_TIMEOUT_MS); }
      catch (error) {
        if (created) execution.error = `${execution.error ?? "worker cleanup failed"}; ${error instanceof Error ? error.message : String(error)}`;
      }
      execution.durationMs = performance.now() - start;
    }
    verifyEvolutionSnapshot(snapshot);
    return execution;
  };
}

/** Resolve the operator-selected backend without substituting an execution engine. */
export async function resolveEvolutionConfigImage(config: EvolutionConfig): Promise<string> {
  if (config.backend !== "smolvm") return resolveEvolutionImage(config.image);
  if (!config.imageArchive) throw new Error("smolvm requires a local imageArchive");
  const digest = await resolveSmolvmImage(config.imageArchive);
  if (IMAGE_ID.test(config.image) && config.image !== digest) throw new Error("smolvm archive identity mismatch");
  return digest;
}

export function createSmolvmEvolutionSandbox(binary?: string): EvolutionSandbox {
  return async ({ snapshot, config: rawConfig, input, signal }) => {
    const config = parseEvolutionConfig(rawConfig);
    if (config.backend !== "smolvm" || !config.imageArchive || !IMAGE_ID.test(config.image)) {
      throw new Error("smolvm execution requires a resolved archive identity and backend smolvm");
    }
    verifyEvolutionSnapshot(snapshot);
    const execution = await runSmolvm({
      imageArchive: config.imageArchive, imageDigest: config.image, binary,
      command: ["/bin/sh", "-c", workerScript(config, "/tmp/0sec-workspace")],
      stdin: canonicalEvolutionJson(input),
      mounts: [{ source: snapshot.root, target: "/snapshot" }],
      timeoutMs: config.timeoutMs, memoryMb: config.memoryMb, cpus: config.cpus,
      maxOutputBytes: config.maxOutputBytes, signal,
    });
    verifyEvolutionSnapshot(snapshot);
    return execution;
  };
}

export function createEvolutionSandbox(config: EvolutionConfig): EvolutionSandbox {
  return config.backend === "smolvm" ? createSmolvmEvolutionSandbox() : createDockerEvolutionSandbox();
}
