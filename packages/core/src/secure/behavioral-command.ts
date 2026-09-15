import { spawn } from "node:child_process";
import { sanitizedEnv } from "../agent/sanitized-env.js";

// Node >=24 provides this API; the workspace's ES2022 library omits its type.
const deferredPromise = Promise as PromiseConstructor & {
  withResolvers<T>(): { promise: Promise<T>; resolve(value: T): void; reject(reason: unknown): void };
};

export interface SecureCommandResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  interrupted: boolean;
}

/** Runs in the existing worker. Cancellation kills the owned process group, not just its shell. */
export async function runSecureCommand(
  command: string,
  args: string[],
  cwd: string,
  signal: AbortSignal,
  maxBytes = 2 * 1024 * 1024,
): Promise<SecureCommandResult> {
  signal.throwIfAborted();
  const { promise, resolve, reject } = deferredPromise.withResolvers<SecureCommandResult>();
    const child = spawn(command, args, { cwd, env: sanitizedEnv(), stdio: ["ignore", "pipe", "pipe"], detached: process.platform !== "win32" });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let bytes = 0;
    let interrupted = false;
    const stop = () => {
      interrupted = true;
      if (!child.pid) return;
      try {
        if (process.platform === "win32") child.kill("SIGKILL");
        else process.kill(-child.pid, "SIGKILL");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ESRCH") child.kill("SIGKILL");
      }
    };
    signal.addEventListener("abort", stop, { once: true });
    if (signal.aborted) stop();
    child.stdout.on("data", (chunk: Buffer) => {
      if (bytes < maxBytes) stdout.push(chunk.subarray(0, maxBytes - bytes));
      bytes += chunk.length;
      if (bytes > maxBytes) stop();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      if (bytes < maxBytes) stderr.push(chunk.subarray(0, maxBytes - bytes));
      bytes += chunk.length;
      if (bytes > maxBytes) stop();
    });
    child.once("error", (error) => {
      signal.removeEventListener("abort", stop);
      reject(error);
    });
    child.once("close", (exitCode) => {
      signal.removeEventListener("abort", stop);
      // A command may exit with background children still alive. They are never retained.
      if (child.pid && process.platform !== "win32") {
        try { process.kill(-child.pid, "SIGKILL"); } catch { /* group has exited */ }
      }
      resolve({ exitCode, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8"), interrupted });
    });
  return promise;
}
