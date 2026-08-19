/**
 * Production isolation for npm dynamic-discovery — the **per-package sandbox
 * runner**.
 *
 * Why not a sandbox-backed `PackageProbe`? The `PackageProbe.load()` seam is
 * synchronous and hands the detector a LIVE module object that `confirm()` then
 * invokes in-realm (SSPP is confirmed by observing `Object.prototype` mutated in
 * the same process that called the merge). A remote sandbox can neither serve a
 * sync `load()` nor return a live cross-realm object, and the pollution must be
 * observed where it happens. So the isolation boundary is necessarily the whole
 * per-package detector sweep, not an individual module load — exactly the
 * prototype's dedicated-`worker.js`-per-package model.
 *
 * `createSandboxPackageRunner` returns an {@link NpmPackageRunner}: for each
 * package it acquires a fresh disposable environment, `npm install
 * --ignore-scripts` the package, spawns {@link ./sandbox-harness.ts} to run the
 * detector cores against it, parses the structured result, and tears the
 * environment down. Fail-safe by construction: ANY fault (create / install /
 * harness / parse) yields `undefined` — the stage records the package as
 * unpreparable and skips it. A sandbox error is NEVER promoted to a finding.
 *
 * The `SandboxProvider` is the injected transport seam. The default
 * {@link localSandboxProvider} uses a throwaway temp dir + child process on the
 * current host (real cross-realm isolation via a separate Node process). The
 * cloud/worker layer injects an e2b-backed provider that satisfies the same
 * interface (per `docs/operations/sspp-dynamic-miner-design.md` — the sandbox
 * transport lives at the worker layer, not in the engine core).
 */

import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { DetectorRunOutcome } from "./base.js";
import type { PackageRef } from "./types.js";

/** Captured result of one command run inside a sandbox session. */
export interface SandboxCommandResult {
  stdout: string;
  stderr: string;
  /** Process exit code (0 = success). A non-zero code is a soft failure the
   *  runner turns into a skip — it must NOT throw for a non-zero exit. */
  exitCode: number;
}

/** One disposable environment: its own working dir + command exec + teardown. */
export interface SandboxSession {
  /** Absolute working dir inside the disposable environment (the install root). */
  readonly workdir: string;
  /** Run a command. Resolves with the captured result (incl. non-zero exit);
   *  rejects only on an infrastructure fault (spawn failure / timeout). */
  run(
    cmd: string,
    args: string[],
    opts?: { cwd?: string; timeoutMs?: number; env?: Record<string, string> },
  ): Promise<SandboxCommandResult>;
  /** Tear the environment down. Best-effort; never throws in the runner's finally. */
  dispose(): Promise<void>;
}

/** Factory for fresh disposable environments (temp dir locally; e2b in prod). */
export interface SandboxProvider {
  create(): Promise<SandboxSession>;
}

/** The result the stage consumes: per-detector outcomes + package-level warnings. */
export interface PackageRunResult {
  outcomes: DetectorRunOutcome[];
  warnings: string[];
}

/**
 * Per-package sandbox runner: install + run the detector harness in isolation,
 * return the outcomes, tear down. `undefined` ⇒ the package could not be
 * prepared/executed and is SKIPPED (never a fabricated confirmation).
 */
export type NpmPackageRunner = (
  pkg: PackageRef,
  detectorIds: string[],
) => Promise<PackageRunResult | undefined>;

export interface SandboxRunnerOptions {
  /** Injected environment transport. Default: {@link localSandboxProvider}. */
  provider?: SandboxProvider;
  /** Path to the compiled harness entry. Default: sibling `sandbox-harness.js`. */
  harnessPath?: string;
  /** Node binary used to spawn the harness. Default: `process.execPath`. */
  nodeBin?: string;
  /** `npm install` timeout (ms). Default 180000. */
  installTimeoutMs?: number;
  /** Harness run timeout (ms). Default 120000. */
  runTimeoutMs?: number;
  /** Skip the live OSV lookup inside the harness (air-gapped/hermetic runs). */
  offlineDedup?: boolean;
  log?: (msg: string) => void;
}

const DEFAULT_INSTALL_TIMEOUT_MS = 180_000;
const DEFAULT_RUN_TIMEOUT_MS = 120_000;

function defaultHarnessPath(): string {
  // In dist this resolves to `dist/stages/npm-detectors/sandbox-harness.js`.
  return fileURLToPath(new URL("./sandbox-harness.js", import.meta.url));
}

/**
 * Local disposable environment: a fresh `mkdtemp` dir + `execFile` child
 * processes + `rm -rf` teardown. The harness runs in a SEPARATE Node process, so
 * a package that pollutes `Object.prototype` cannot corrupt the host pipeline —
 * real cross-realm isolation, no e2b required. Use on a trusted/disposable host
 * (or nested inside the per-scan e2b sandbox); the untrusted install/exec is
 * still confined to the child + temp dir.
 */
export function localSandboxProvider(): SandboxProvider {
  return {
    async create(): Promise<SandboxSession> {
      const workdir = await mkdtemp(join(tmpdir(), "0sec-npm-dyn-"));
      return {
        workdir,
        run(cmd, args, runOpts) {
          return new Promise<SandboxCommandResult>((resolve, reject) => {
            execFile(
              cmd,
              args,
              {
                cwd: runOpts?.cwd ?? workdir,
                timeout: runOpts?.timeoutMs ?? DEFAULT_RUN_TIMEOUT_MS,
                maxBuffer: 64 * 1024 * 1024,
                env: runOpts?.env ? { ...process.env, ...runOpts.env } : process.env,
              },
              (err, stdout, stderr) => {
                // A non-zero exit surfaces as `err.code`; that is a soft failure
                // (resolve with the code), NOT a reject. Reject only on a spawn
                // fault / timeout (no numeric code), which the runner also skips.
                const anyErr = err as (NodeJS.ErrnoException & { code?: number | string }) | null;
                if (anyErr && typeof anyErr.code !== "number") {
                  reject(anyErr);
                  return;
                }
                resolve({
                  stdout: stdout?.toString() ?? "",
                  stderr: stderr?.toString() ?? "",
                  exitCode: typeof anyErr?.code === "number" ? anyErr.code : 0,
                });
              },
            );
          });
        },
        async dispose(): Promise<void> {
          await rm(workdir, { recursive: true, force: true });
        },
      };
    },
  };
}

/** Extract the final JSON object line from harness stdout (tolerates noise). */
function parseHarnessResult(stdout: string): PackageRunResult | undefined {
  const lines = stdout.split("\n").map((l) => l.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    if (!line.startsWith("{")) continue;
    try {
      const parsed = JSON.parse(line) as Partial<PackageRunResult>;
      if (parsed && Array.isArray(parsed.outcomes)) {
        return { outcomes: parsed.outcomes, warnings: Array.isArray(parsed.warnings) ? parsed.warnings : [] };
      }
    } catch {
      // Not the JSON line — keep scanning older lines.
    }
  }
  return undefined;
}

/**
 * Build the production {@link NpmPackageRunner}. Reuses the engine's own
 * child-process exec primitive by default; swap in an e2b `SandboxProvider` at
 * the worker layer for true VM-grade isolation at ecosystem scale.
 */
export function createSandboxPackageRunner(options: SandboxRunnerOptions = {}): NpmPackageRunner {
  const provider = options.provider ?? localSandboxProvider();
  const harnessPath = options.harnessPath ?? defaultHarnessPath();
  const nodeBin = options.nodeBin ?? process.execPath;
  const installTimeoutMs = options.installTimeoutMs ?? DEFAULT_INSTALL_TIMEOUT_MS;
  const runTimeoutMs = options.runTimeoutMs ?? DEFAULT_RUN_TIMEOUT_MS;
  const log = options.log ?? (() => {});

  return async function sandboxRunner(pkg, detectorIds) {
    let session: SandboxSession;
    try {
      session = await provider.create();
    } catch (e) {
      log(`SKIP ${pkg.name}: sandbox create failed: ${errMsg(e)}`);
      return undefined;
    }

    let result: PackageRunResult | undefined;
    try {
      const spec = pkg.version ? `${pkg.name}@${pkg.version}` : pkg.name;
      // --ignore-scripts is the load-bearing safety gate: no pre/post-install
      // hooks execute during acquisition; the package's code runs ONLY under the
      // detector harness, in this isolated child.
      const install = await session.run(
        "npm",
        ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--no-package-lock", "--prefix", session.workdir, spec],
        { cwd: session.workdir, timeoutMs: installTimeoutMs },
      );
      if (install.exitCode !== 0) {
        log(`SKIP ${pkg.name}: npm install exited ${install.exitCode}: ${firstLine(install.stderr)}`);
        return undefined; // fail-safe: install failure is a skip, not a finding
      }

      const config = JSON.stringify({
        installDir: session.workdir,
        pkg,
        detectorIds,
        offlineDedup: options.offlineDedup ?? false,
      });
      const harness = await session.run(nodeBin, [harnessPath, config], {
        cwd: session.workdir,
        timeoutMs: runTimeoutMs,
      });
      if (harness.exitCode !== 0) {
        log(`SKIP ${pkg.name}: harness exited ${harness.exitCode}: ${firstLine(harness.stderr)}`);
        return undefined; // fail-safe
      }

      const parsed = parseHarnessResult(harness.stdout);
      if (!parsed) {
        log(`SKIP ${pkg.name}: harness produced no parseable result`);
        return undefined; // fail-safe: unparseable ⇒ inconclusive, never a finding
      }
      result = parsed;
    } catch (e) {
      // Spawn fault / timeout / anything unexpected ⇒ skip, never false-confirm.
      log(`SKIP ${pkg.name}: sandbox run threw: ${errMsg(e)}`);
      result = undefined;
    } finally {
      try {
        await session.dispose();
      } catch (e) {
        log(`WARN ${pkg.name}: sandbox dispose failed: ${errMsg(e)}`);
      }
    }
    return result;
  };
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message.split("\n")[0].slice(0, 200) : String(e);
}
function firstLine(s: string): string {
  return (s.split("\n").find(Boolean) ?? "").slice(0, 200);
}
