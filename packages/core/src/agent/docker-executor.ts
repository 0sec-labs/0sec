/**
 * Docker executor — runs agent bash commands inside a Kali Linux container.
 *
 * Provides a full pentesting toolset (nmap, sqlmap, wpscan, nikto, etc.)
 * in an isolated environment, similar to BoxPwnr's approach.
 *
 * Container naming for parallel sweeps (issue #233):
 *   Names follow `pwnkit-{scanId}-{random8}` where `random8` is 8 hex chars
 *   from `crypto.randomBytes(4)`. This guarantees collision-free names when
 *   the benchmark runner spawns multiple sweeps concurrently against the
 *   same target image.
 *
 * Containers are launched with `--rm` so they auto-cleanup on exit. As a
 * defensive net for crashed processes that bypass `--rm`, callers can invoke
 * `DockerExecutor.cleanupOrphans()` at scan-suite teardown to prune any
 * `pwnkit-*` containers older than the configured age window.
 *
 * Usage:
 *   const docker = DockerExecutor.forScan(scanId);
 *   await docker.ensureRunning();
 *   const result = await docker.exec("nmap -sV target.com", 60);
 *   await docker.stop();
 */

import { execSync, execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";

const PREBUILT_IMAGE = "ghcr.io/0sec-labs/pwnkit-kali:latest";
const LEGACY_KALI_IMAGE = "kalilinux/kali-rolling";
const CONTAINER_PREFIX = "pwnkit";

/** Packages to install inside the Kali container on first boot. */
const PENTEST_PACKAGES = [
  "nmap",
  "sqlmap",
  "wpscan",
  "nikto",
  "gobuster",
  "dirb",
  "hydra",
  "john",
  "whatweb",
  "wfuzz",
  "ffuf",
  "seclists",
  "curl",
  "wget",
  "netcat-openbsd",
  "socat",
  "proxychains4",
  "python3",
  "python3-pip",
  "gdb",
  "gdb-multiarch",
  "radare2",
  "binwalk",
  "foremost",
  "libimage-exiftool-perl",
  "ltrace",
  "strace",
  "file",
  "binutils",
  "python3-ropgadget",
];

/** Extra Python packages to pip-install after apt bootstrap. */
const PENTEST_PIP_PACKAGES = ["requests", "pwntools", "beautifulsoup4"];

export interface DockerExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
}

/** A bind mount injected at `docker run` time (replaces `docker cp`). */
export interface BindMount {
  /** Absolute path on the host. */
  host: string;
  /** Absolute path inside the container. */
  container: string;
  /** When true, mount read-only (`:ro`). Defaults to false. */
  readOnly?: boolean;
}

/** Sanitise an arbitrary scan id into a Docker-safe name fragment. */
function sanitiseScanId(scanId: string): string {
  // Docker container names allow [a-zA-Z0-9][a-zA-Z0-9_.-]*
  // Replace any other char with '-' and trim. Empty → "anon".
  const cleaned = scanId.replace(/[^a-zA-Z0-9_.-]/g, "-").replace(/^-+|-+$/g, "");
  return cleaned || "anon";
}

/** Generate a `pwnkit-{scanId}-{random8}` container name. */
export function generateContainerName(scanId: string): string {
  const suffix = randomBytes(4).toString("hex");
  return `${CONTAINER_PREFIX}-${sanitiseScanId(scanId)}-${suffix}`;
}

/** Build the `docker run` argument list for a given config. */
export function buildDockerRunArgs(opts: {
  containerName: string;
  image: string;
  network: string;
  target: string;
  mounts: BindMount[];
}): string[] {
  const args: string[] = [
    "run",
    "-d",
    "--rm",
    "--name",
    opts.containerName,
    "--network",
    opts.network,
  ];
  for (const m of opts.mounts) {
    const flag = m.readOnly ? `${m.host}:${m.container}:ro` : `${m.host}:${m.container}`;
    args.push("-v", flag);
  }
  args.push(
    "-e",
    `TARGET=${opts.target}`,
    "--entrypoint",
    "sleep",
    opts.image,
    "infinity",
  );
  return args;
}

export class DockerExecutor {
  /** Per-scan registry — one container per (scanId) within a process. */
  private static instances: Map<string, DockerExecutor> = new Map();
  /** Backwards-compatible default (used when no scanId is supplied). */
  private static legacyInstance: DockerExecutor | null = null;

  private containerId: string | null = null;
  private readonly containerName: string;
  private readonly scanId: string;
  private ready = false;
  private targetEnv: string = "";
  private image: string;
  /** Bind mounts attached to this container at `docker run` time. */
  private mounts: BindMount[] = [
    { host: "/tmp/pwnkit-shared", container: "/shared" },
  ];

  private constructor(scanId: string) {
    this.scanId = scanId;
    this.containerName = generateContainerName(scanId);
    this.image = process.env.PWNKIT_DOCKER_IMAGE || PREBUILT_IMAGE;
  }

  /**
   * Get-or-create an executor scoped to a scan id.
   *
   * Two parallel scans pass distinct ids and receive distinct containers
   * with collision-free names.
   */
  static forScan(scanId: string): DockerExecutor {
    const existing = DockerExecutor.instances.get(scanId);
    if (existing) return existing;
    const next = new DockerExecutor(scanId);
    DockerExecutor.instances.set(scanId, next);
    return next;
  }

  /** Singleton — backwards-compatible accessor for legacy callers. */
  static getInstance(): DockerExecutor {
    if (!DockerExecutor.legacyInstance) {
      DockerExecutor.legacyInstance = new DockerExecutor("default");
    }
    return DockerExecutor.legacyInstance;
  }

  /** Reset the singleton + per-scan registry (for testing). */
  static resetInstance(): void {
    DockerExecutor.legacyInstance = null;
    DockerExecutor.instances.clear();
  }

  /** Container name for this executor (test inspection). */
  getContainerName(): string {
    return this.containerName;
  }

  /** Set the TARGET environment variable inside the container. */
  setTarget(target: string): void {
    this.targetEnv = target;
  }

  /**
   * Add a bind mount that will be applied at `docker run` time. Replaces
   * `docker cp` for file injection — files are exposed via -v rather than
   * copied via container-name lookup. Must be called BEFORE `ensureRunning`.
   */
  addBindMount(mount: BindMount): void {
    if (this.ready) {
      throw new Error(
        "addBindMount: cannot add bind mount after container is running",
      );
    }
    this.mounts.push(mount);
  }

  /** Inspect the run-arg list this executor would issue (test inspection). */
  buildRunArgs(): string[] {
    return buildDockerRunArgs({
      containerName: this.containerName,
      image: this.image,
      network: process.env.PWNKIT_DOCKER_NETWORK || "bridge",
      target: this.targetEnv,
      mounts: this.mounts,
    });
  }

  /** Start the Kali container if not already running, install tools. */
  async ensureRunning(): Promise<void> {
    if (this.ready && this.containerId && this.isContainerAlive()) {
      return;
    }

    this.assertDockerAvailable();

    // Pull image if not present (best-effort, may already be cached)
    try {
      execSync(`docker image inspect ${this.image} > /dev/null 2>&1`, {
        timeout: 5_000,
      });
    } catch {
      // Image not found locally — pull it
      execSync(`docker pull ${this.image}`, {
        timeout: 300_000, // 5 min for pull
        stdio: "pipe",
      });
    }

    // Start the container with:
    //  - --rm for automatic cleanup on stop
    //  - bind mounts injected at run time (replaces `docker cp`)
    //  - bridge networking by default (override via PWNKIT_DOCKER_NETWORK)
    //  - long-running sleep to keep it alive
    const runArgs = this.buildRunArgs();

    const id = execFileSync("docker", runArgs, {
      timeout: 30_000,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();

    this.containerId = id;
    this.registerExitHandlers();

    // The GHCR image is pre-baked with the standard toolchain.
    // Keep the legacy Kali bootstrap path for raw-image fallback.
    if (this.shouldBootstrapTools()) {
      const aptCmd = `apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ${PENTEST_PACKAGES.join(" ")}`;
      this.dockerExecSync(aptCmd, 600_000); // 10 min for install
      const pipCmd = `pip3 install --no-cache-dir --break-system-packages ${PENTEST_PIP_PACKAGES.join(" ")}`;
      this.dockerExecSync(pipCmd, 300_000); // 5 min for pip
    }

    this.ready = true;
  }

  /**
   * Execute a command inside the Kali container.
   * Returns structured result with stdout, stderr, exit code, and timeout flag.
   */
  async exec(command: string, timeoutSec: number = 30): Promise<DockerExecResult> {
    if (!this.containerId || !this.ready) {
      await this.ensureRunning();
    }

    const timeoutMs = timeoutSec * 1000;

    try {
      const stdout = execFileSync(
        "docker",
        ["exec", "-e", `TARGET=${this.targetEnv}`, this.containerId!, "bash", "-c", command],
        {
          timeout: timeoutMs,
          maxBuffer: 1024 * 1024, // 1MB
          encoding: "utf-8",
          stdio: ["pipe", "pipe", "pipe"],
        },
      );

      return {
        stdout: stdout ?? "",
        stderr: "",
        exitCode: 0,
        timedOut: false,
      };
    } catch (err: any) {
      if (err.killed) {
        return {
          stdout: (err.stdout as string) ?? "",
          stderr: (err.stderr as string) ?? "",
          exitCode: -1,
          timedOut: true,
        };
      }

      return {
        stdout: (err.stdout as string) ?? "",
        stderr: (err.stderr as string) ?? "",
        exitCode: err.status ?? 1,
        timedOut: false,
      };
    }
  }

  /** Stop and remove the container. */
  async stop(): Promise<void> {
    if (!this.containerId) return;

    try {
      execSync(`docker rm -f ${this.containerId}`, {
        timeout: 15_000,
        stdio: "pipe",
      });
    } catch {
      // Best-effort cleanup
    }

    this.containerId = null;
    this.ready = false;
    DockerExecutor.instances.delete(this.scanId);
    if (DockerExecutor.legacyInstance === this) {
      DockerExecutor.legacyInstance = null;
    }
  }

  /**
   * Test-injectable hook for `docker` invocations issued by static methods
   * (cleanupOrphans). Defaults to a thin wrapper over `execFileSync`. Tests
   * override this so they don't shell out to a real docker daemon.
   */
  static dockerRunner: (args: string[]) => string = (args: string[]): string => {
    return execFileSync("docker", args, {
      timeout: 15_000,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });
  };

  /**
   * Prune `pwnkit-*` containers older than the configured age threshold.
   *
   * Defensive against crashed processes that bypass `--rm`. Filters by name
   * prefix so unrelated containers are never touched, and by creation age so
   * in-flight containers from concurrent scans are left alone.
   *
   * @param maxAgeHours containers created MORE than this many hours ago are
   *   removed. Defaults to 6h, well above any realistic single scan runtime.
   */
  static cleanupOrphans(maxAgeHours: number = 6): { removed: string[] } {
    const removed: string[] = [];
    let listing: string;
    try {
      listing = DockerExecutor.dockerRunner([
        "ps",
        "-a",
        "--filter",
        `name=${CONTAINER_PREFIX}-`,
        "--format",
        "{{.Names}}\t{{.CreatedAt}}",
      ]);
    } catch {
      // Docker unavailable — nothing to clean up.
      return { removed };
    }

    const cutoffMs = Date.now() - maxAgeHours * 60 * 60 * 1000;
    for (const line of listing.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const [name, createdAtRaw] = trimmed.split("\t");
      if (!name || !name.startsWith(`${CONTAINER_PREFIX}-`)) continue;
      // Docker `CreatedAt` looks like: "2026-05-07 11:23:08 +0000 UTC".
      // Drop the trailing tz label — JS Date parses the rest fine.
      const createdAt = createdAtRaw
        ? Date.parse(createdAtRaw.replace(/\s+[A-Z]{3,4}$/, "").trim())
        : NaN;
      if (Number.isFinite(createdAt) && createdAt >= cutoffMs) {
        // Younger than threshold — likely an in-flight scan, leave alone.
        continue;
      }
      try {
        DockerExecutor.dockerRunner(["rm", "-f", name]);
        removed.push(name);
      } catch {
        // Best-effort — container may have just exited or be locked.
      }
    }

    return { removed };
  }

  /** Check if container is still running. */
  private isContainerAlive(): boolean {
    if (!this.containerId) return false;
    try {
      const status = execSync(
        `docker inspect -f '{{.State.Running}}' ${this.containerId}`,
        { timeout: 5_000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
      ).trim();
      return status === "true";
    } catch {
      return false;
    }
  }

  /** Run a command inside the container synchronously (used during setup). */
  private dockerExecSync(command: string, timeoutMs: number): string {
    return execFileSync(
      "docker",
      ["exec", this.containerId!, "bash", "-c", command],
      {
        timeout: timeoutMs,
        maxBuffer: 2 * 1024 * 1024,
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
  }

  /** Throw if Docker CLI is not available. */
  private assertDockerAvailable(): void {
    try {
      execSync("docker info > /dev/null 2>&1", { timeout: 10_000 });
    } catch {
      throw new Error(
        "Docker is not available. Install Docker and ensure the daemon is running to use --docker mode.",
      );
    }
  }

  /** Register process exit handlers to stop the container on termination. */
  private registerExitHandlers(): void {
    const cleanup = () => {
      if (this.containerId) {
        try {
          execSync(`docker stop ${this.containerId}`, {
            timeout: 10_000,
            stdio: "pipe",
          });
        } catch {
          // Best-effort — container may already be gone (--rm)
        }
        this.containerId = null;
        this.ready = false;
      }
    };

    process.once("exit", cleanup);
    process.once("SIGINT", () => { cleanup(); process.exit(130); });
    process.once("SIGTERM", () => { cleanup(); process.exit(143); });
  }

  private shouldBootstrapTools(): boolean {
    if (process.env.PWNKIT_DOCKER_BOOTSTRAP_TOOLS === "1") return true;
    if (process.env.PWNKIT_DOCKER_BOOTSTRAP_TOOLS === "0") return false;
    return this.image === LEGACY_KALI_IMAGE;
  }
}

/**
 * Convenience function for use in the tool executor.
 * Matches the same interface pattern as shellExec.
 */
export async function execInDocker(
  command: string,
  timeout: number,
  target?: string,
  scanId?: string,
): Promise<{ output: string; timedOut: boolean; exitCode: number }> {
  const docker = scanId
    ? DockerExecutor.forScan(scanId)
    : DockerExecutor.getInstance();
  if (target) docker.setTarget(target);
  await docker.ensureRunning();

  const result = await docker.exec(command, timeout);
  const output = (result.stdout + "\n" + result.stderr).trim();

  return {
    output,
    timedOut: result.timedOut,
    exitCode: result.exitCode,
  };
}
