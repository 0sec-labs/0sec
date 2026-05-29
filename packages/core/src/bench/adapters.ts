/**
 * Production default adapters for the bench harness (pwnkit#556).
 *
 * These wire the harness to the real engine + real Docker. They are the
 * "batteries included" path; every one is optional and replaced by a mock
 * in unit tests (the harness core in runner.ts/scorecard.ts has zero hard
 * dependency on them, which is what keeps the scorecard deterministically
 * testable).
 *
 * Layering note: this file lives in @pwnkit/core, so it may import core's
 * own engine (`agenticScan`) and Docker plumbing (`docker-executor.ts`). It
 * must NOT import the cloud verify runners in `services/` — services depends
 * on core, never the reverse (ADR-001). To grade with the cloud E2B/kernel
 * runners, implement a `BenchOracle` adapter on the services side against the
 * shared `verified|refuted|inconclusive` contract.
 */

import { execFileSync } from "node:child_process";
import { agenticScan } from "../agentic-scanner.js";
import type { ScanReport, RuntimeMode } from "@pwnkit/shared";
import type { BenchCase } from "./manifest.js";
import type { BenchScanResult } from "./oracle.js";
import type {
  BenchScan,
  BenchScanInput,
  ProvisionedTarget,
  TargetProvisioner,
} from "./runner.js";

// ── ScanReport → BenchScanResult ──────────────────────────────────────

/** Project the engine's full ScanReport onto the structural view the oracle needs. */
export function scanReportToBenchResult(report: ScanReport): BenchScanResult {
  return {
    findings: (report.findings ?? []).map((f) => ({
      category: f.category,
      confidence: f.confidence,
      status: f.status,
      title: f.title,
      description: f.description,
      evidence: f.evidence
        ? {
            request: f.evidence.request,
            response: f.evidence.response,
            analysis: f.evidence.analysis,
          }
        : undefined,
    })),
    trace: report.trace,
    benchmarkMeta: report.benchmarkMeta,
    durationMs: report.durationMs,
  };
}

// ── Default agentic scan adapter ──────────────────────────────────────

export interface AgenticScanAdapterOptions {
  /** Runtime mode passed to the engine. Default "auto". */
  runtime?: RuntimeMode;
  /** Model override. */
  model?: string;
  /** Per-attempt cost ceiling forwarded to the engine. */
  costCeilingUsdPerAttempt?: number;
  /** Per-attempt wallclock timeout (ms). Default 60_000. */
  timeoutMs?: number;
}

/**
 * Build a {@link BenchScan} backed by the real `agenticScan` engine.
 *
 * The harness turn budget (`input.maxTurns`) is mapped to scan `depth`
 * ("quick" for tight budgets, "deep" otherwise) since the engine bounds the
 * attack loop by depth + cost rather than a raw turn count. The per-attempt
 * cost ceiling is forwarded verbatim to `ScanConfig.costCeilingUsd`.
 *
 * Scope: WEB targets only. Kernel cases require the QEMU/KASAN verify path
 * (the cloud `verify-kernel` runner), which lives in `services/` and cannot
 * be imported here (services depends on core, not vice-versa, ADR-001).
 * Supply a kernel scan adapter / oracle for `kind: "kernel"` cases; this
 * default returns an `error` result for them so they surface as
 * `inconclusive` rather than being silently mis-run through the web engine.
 */
export function createAgenticScanAdapter(
  opts: AgenticScanAdapterOptions = {},
): BenchScan {
  return async (input: BenchScanInput): Promise<BenchScanResult> => {
    const { case: c, target, maxTurns } = input;
    if (c.target.kind !== "web") {
      return {
        error: `agenticScan adapter handles web targets only; case "${c.id}" is a ${c.target.kind} target — inject a kernel scan adapter (e.g. the cloud verify-kernel runner)`,
      };
    }
    try {
      const report = await agenticScan({
        config: {
          target,
          depth: maxTurns <= 20 ? "quick" : "deep",
          format: "json",
          mode: "web",
          runtime: opts.runtime ?? "auto",
          model: opts.model,
          timeout: opts.timeoutMs ?? 60_000,
          ...(opts.costCeilingUsdPerAttempt != null
            ? { costCeilingUsd: opts.costCeilingUsdPerAttempt }
            : {}),
        },
        challengeHint: c.target.hint,
      });
      return scanReportToBenchResult(report);
    } catch (err) {
      return { error: err instanceof Error ? err.message : String(err) };
    }
  };
}

// ── Default Docker web provisioner ────────────────────────────────────

interface DockerWebHandle {
  containerName?: string;
  composeDir?: string;
}

// All docker invocations use execFileSync with an argument ARRAY (never an
// interpolated shell string) so the shell is never involved — manifest-
// supplied values like image refs and container names can't break out into
// command injection. Mirrors the execFileSync pattern in
// agent/docker-executor.ts.
function docker(args: string[], opts: { cwd?: string; timeoutMs: number; capture?: boolean }): string {
  return execFileSync("docker", args, {
    cwd: opts.cwd,
    encoding: "utf8",
    timeout: opts.timeoutMs,
    stdio: opts.capture ? ["pipe", "pipe", "pipe"] : "pipe",
  });
}

function findPublishedPort(containerName: string, internalPort?: number): number | null {
  try {
    // When the container's listen port is known, ask docker for that
    // specific mapping; otherwise read the first published port.
    const args = internalPort
      ? ["port", containerName, String(internalPort)]
      : ["port", containerName];
    const out = docker(args, { timeoutMs: 5_000, capture: true }).trim();
    const m = out.match(/:(\d+)\s*$/m);
    return m ? parseInt(m[1], 10) : null;
  } catch {
    return null;
  }
}

/**
 * Default provisioner for `kind: "web"` cases. Resolves a target to a
 * localhost URL by either:
 *   - `docker run -d -P <image>` then reading the mapped port, or
 *   - `docker compose up -d` in `composeDir` (mirrors the XBOW runner).
 *
 * Kernel cases are NOT provisioned here — they are handed to the scan/oracle
 * by `reproducerRef` and run inside the kernel VM path. `up()` throws for a
 * kernel case so it surfaces as inconclusive rather than silently mis-running.
 */
export function createDockerWebProvisioner(corpusRoot?: string): TargetProvisioner {
  return {
    async up(c: BenchCase): Promise<ProvisionedTarget> {
      if (c.target.kind !== "web") {
        throw new Error(
          `DockerWebProvisioner: case "${c.id}" is a ${c.target.kind} target; supply a kernel provisioner/oracle for it`,
        );
      }
      const t = c.target;

      if (t.composeDir) {
        const { join, isAbsolute } = await import("node:path");
        const dir = isAbsolute(t.composeDir)
          ? t.composeDir
          : join(corpusRoot ?? process.cwd(), t.composeDir);
        docker(["compose", "up", "-d", "--wait", "--wait-timeout", "150"], {
          cwd: dir,
          timeoutMs: 180_000,
        });
        // Best-effort: read the first published port via compose.
        const out = docker(["compose", "ps", "--format", "json"], {
          cwd: dir,
          timeoutMs: 10_000,
          capture: true,
        }).trim();
        let port: number | null = null;
        for (const line of out.split("\n").filter(Boolean)) {
          try {
            const svc = JSON.parse(line);
            for (const p of svc.Publishers ?? []) {
              if (p.PublishedPort && p.PublishedPort > 0) {
                port = p.PublishedPort;
                break;
              }
            }
          } catch {
            /* skip unparseable line */
          }
          if (port) break;
        }
        if (!port) throw new Error(`no published port found for compose case "${c.id}"`);
        return { target: `http://localhost:${port}`, handle: { composeDir: dir } };
      }

      if (t.image) {
        const containerName = `pwnkit-bench-${c.id.replace(/[^a-zA-Z0-9_.-]/g, "-")}`;
        try {
          docker(["rm", "-f", containerName], { timeoutMs: 15_000 });
        } catch {
          /* nothing to remove */
        }
        docker(["run", "-d", "--rm", "-P", "--name", containerName, t.image], {
          timeoutMs: 60_000,
        });
        const port = findPublishedPort(containerName, t.port);
        if (!port) throw new Error(`no published port found for image case "${c.id}"`);
        return { target: `http://localhost:${port}`, handle: { containerName } };
      }

      throw new Error(`web case "${c.id}" has neither image nor composeDir`);
    },

    async down(_c: BenchCase, provisioned: ProvisionedTarget): Promise<void> {
      const handle = provisioned.handle as DockerWebHandle | undefined;
      if (!handle) return;
      try {
        if (handle.composeDir) {
          docker(["compose", "down", "-v", "--remove-orphans"], {
            cwd: handle.composeDir,
            timeoutMs: 30_000,
          });
        } else if (handle.containerName) {
          docker(["rm", "-f", handle.containerName], { timeoutMs: 15_000 });
        }
      } catch {
        /* best-effort teardown */
      }
    },
  };
}
