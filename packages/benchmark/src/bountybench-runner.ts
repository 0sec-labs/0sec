#!/usr/bin/env node

/**
 * BountyBench Benchmark Runner
 *
 * Orchestrates BountyBench's own evaluation harness (python -m workflows.runner)
 * against its 40 real-world bug bounties across 25 codebases. Each bounty has a
 * dollar value ($10-$30k) and one of three task types:
 *
 *   - Detect:  find the vulnerability (white-box scan with source access)
 *   - Exploit: produce a working exploit / PoC
 *   - Patch:   fix the vulnerability
 *
 * The headline metric is dollar-denominated: total bounty value earned.
 *
 * BountyBench's harness handles Docker orchestration, Kali containers, agent
 * prompting, and verification (verify.sh) — this runner just invokes it.
 *
 * Reference: arXiv:2505.15216 (BountyBench, Stanford, NeurIPS 2025)
 * Repo: https://github.com/bountybench/bountybench
 *
 * Prerequisites:
 * - Docker + Docker Compose installed
 * - Python 3.10+ with BountyBench dependencies (pip install -r requirements.txt)
 * - BountyBench repo cloned (with submodules for bountytasks):
 *     git clone --recurse-submodules https://github.com/bountybench/bountybench /tmp/bountybench
 *   Or set BOUNTYBENCH_PATH env var, or use --benchmark-path <dir>
 *
 * Usage:
 *   tsx src/bountybench-runner.ts                          # run all bounties
 *   tsx src/bountybench-runner.ts --limit 10               # first 10 only
 *   tsx src/bountybench-runner.ts --task-type exploit      # only Exploit tasks
 *   tsx src/bountybench-runner.ts --only lunary__0,gradio__1
 *   tsx src/bountybench-runner.ts --start 5
 *   tsx src/bountybench-runner.ts --retries 3
 *   tsx src/bountybench-runner.ts --json
 *   tsx src/bountybench-runner.ts --dry-run
 *   tsx src/bountybench-runner.ts --model anthropic/claude-3-5-sonnet-20241022
 *   tsx src/bountybench-runner.ts --phase-iterations 5
 */

import { spawnSync } from "node:child_process";
import {
  readFileSync,
  existsSync,
  writeFileSync,
  appendFileSync,
  mkdirSync,
  readdirSync,
  statSync,
} from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── CLI Args ──
const args = process.argv.slice(2);

function argVal(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx >= 0 ? args[idx + 1] : undefined;
}
function argInt(flag: string, fallback: number): number {
  const v = argVal(flag);
  return v !== undefined ? parseInt(v) : fallback;
}
function argBool(flag: string): boolean {
  return args.includes(flag);
}

const limit = argInt("--limit", Infinity);
const taskTypeFilter = argVal("--task-type") as BountyTaskType | undefined;
const jsonOutput = argBool("--json");
const dryRun = argBool("--dry-run");
const retries = argInt("--retries", 1);
const startAt = argInt("--start", 0);
const onlyIds = argVal("--only")
  ? argVal("--only")!.split(",").map((s) => s.trim().toLowerCase())
  : undefined;
const freshRun = argBool("--fresh");
const phaseIterations = argInt("--phase-iterations", 3);
const benchmarkPathArg = argVal("--benchmark-path");
const benchmarkRepoArg = argVal("--benchmark-repo");
const benchmarkRefArg = argVal("--benchmark-ref");

// Model: explicit flag > env var > provider-aware default
// When only Azure credentials are available, use the Azure deployment name
// so BountyBench's harness routes to the OpenAI-compatible endpoint.
const defaultModel =
  process.env.AZURE_OPENAI_MODEL &&
  !process.env.ANTHROPIC_API_KEY &&
  !process.env.OPENAI_API_KEY
    ? process.env.AZURE_OPENAI_MODEL
    : "anthropic/claude-3-5-sonnet-20241022";

const modelArg = argVal("--model")
  ?? process.env.BOUNTYBENCH_MODEL
  ?? defaultModel;

// ── Types ──
type BountyTaskType = "detect" | "exploit" | "patch";

const WORKFLOW_TYPE_MAP: Record<BountyTaskType, string> = {
  detect: "detect_workflow",
  exploit: "exploit_workflow",
  patch: "patch_workflow",
};

interface BountyBenchChallenge {
  /** e.g. "lunary__0__exploit" */
  id: string;
  /** Parent codebase name, e.g. "lunary" */
  codebase: string;
  /** Human-readable name */
  name: string;
  /** Task type: detect, exploit, or patch */
  taskType: BountyTaskType;
  /** Bounty number within the project (the N in bounty_N) */
  bountyNumber: number;
  /** Bounty value in USD */
  bountyUsd: number;
  /** CWE identifier if available */
  cwe?: string;
  /** Severity label */
  severity?: string;
  /** Path to the bounty directory within BountyBench */
  path: string;
}

interface BountyBenchResult {
  id: string;
  codebase: string;
  name: string;
  taskType: BountyTaskType;
  bountyNumber: number;
  bountyUsd: number;
  severity?: string;
  cwe?: string;
  passed: boolean;
  durationMs: number;
  error?: string;
}

interface BountyBenchReport {
  timestamp: string;
  model: string;
  phaseIterations: number;
  retries: number;
  bounties: number;
  started: number;
  passed: number;
  totalBountyValueUsd: number;
  earnedBountyValueUsd: number;
  harnessErrors: number;
  byTaskType: Record<BountyTaskType, { total: number; passed: number; earnedUsd: number }>;
  results: BountyBenchResult[];
}

function chooseBetterResult(a: BountyBenchResult, b: BountyBenchResult): BountyBenchResult {
  if (b.passed && !a.passed) return b;
  if (a.passed && !b.passed) return a;
  if (!!a.error !== !!b.error) return a.error ? b : a;
  return b.durationMs < a.durationMs ? b : a;
}

// ── Benchmark Path Resolution ──

function normalizeBenchmarkRepo(repo: string): string {
  if (/^[\w.-]+\/[\w.-]+$/.test(repo)) {
    return `https://github.com/${repo}.git`;
  }
  return repo;
}

function cacheDirForRepo(repo: string): string {
  const slug = repo
    .replace(/^https?:\/\//, "")
    .replace(/^git@/, "")
    .replace(/\.git$/, "")
    .replace(/[^\w.-]+/g, "_");
  return join(tmpdir(), "0sec-bountybench-cache", slug);
}

function ensureBenchmarkRepo(repo: string, ref: string | undefined): string {
  const url = normalizeBenchmarkRepo(repo);
  const dest = cacheDirForRepo(url);

  if (existsSync(dest) && readdirSync(dest).length > 0) {
    if (!jsonOutput) {
      console.log(`  using cached BountyBench repo at ${dest}`);
    }
    return dest;
  }

  mkdirSync(dirname(dest), { recursive: true });
  const cloneArgs = ["clone", "--depth", "1", "--recurse-submodules"];
  if (ref) cloneArgs.push("--branch", ref);
  cloneArgs.push(url, dest);

  if (!jsonOutput) {
    console.log(`  cloning BountyBench repo ${url}${ref ? ` @ ${ref}` : ""} -> ${dest}`);
  }
  const res = spawnSync("git", cloneArgs, { stdio: "pipe" });
  if (res.status !== 0) {
    const stderr = res.stderr?.toString() ?? "";
    console.error(`Failed to clone BountyBench repo ${url}: ${stderr}`);
    process.exit(1);
  }

  // Try to init submodules (some may fail for private repos)
  spawnSync("git", ["submodule", "update", "--init", "--depth", "1", "--jobs", "4"], {
    cwd: dest,
    stdio: "pipe",
  });

  return dest;
}

function resolveBountyBenchPath(): string {
  if (benchmarkPathArg) return benchmarkPathArg;
  if (process.env.BOUNTYBENCH_PATH) return process.env.BOUNTYBENCH_PATH;
  if (benchmarkRepoArg) return ensureBenchmarkRepo(benchmarkRepoArg, benchmarkRefArg);
  return "/tmp/bountybench";
}

const BOUNTYBENCH_PATH = resolveBountyBenchPath();

// ── Discover Bounties ──
//
// BountyBench repo structure:
//   bountytasks/<codebase>/bounties/bounty_<n>/bounty_metadata.json
//
// bounty_metadata.json contains: disclosure_bounty, CWE, severity, etc.

function loadChallenges(): BountyBenchChallenge[] {
  const bountytasksDir = join(BOUNTYBENCH_PATH, "bountytasks");

  if (!existsSync(bountytasksDir) || !statSync(bountytasksDir).isDirectory()) {
    const foundDirs = existsSync(BOUNTYBENCH_PATH)
      ? readdirSync(BOUNTYBENCH_PATH)
          .filter((d) => {
            try { return statSync(join(BOUNTYBENCH_PATH, d)).isDirectory(); } catch { return false; }
          })
          .join(", ")
      : "(path does not exist)";
    console.error(`BountyBench bountytasks not found at ${bountytasksDir}`);
    console.error(`Directories found: ${foundDirs}`);
    console.error(`Expected: bountytasks/<codebase>/bounties/bounty_<n>/ with bounty_metadata.json files`);
    console.error(`Clone the repo: git clone --recurse-submodules https://github.com/bountybench/bountybench ${BOUNTYBENCH_PATH}`);
    console.error(`Or set BOUNTYBENCH_PATH or use --benchmark-path <dir>`);
    process.exit(1);
  }

  const challenges: BountyBenchChallenge[] = [];
  const skippedBounties: string[] = [];

  const codebases = readdirSync(bountytasksDir)
    .filter((d) => {
      const full = join(bountytasksDir, d);
      return statSync(full).isDirectory() && !d.startsWith(".");
    })
    .sort();

  for (const codebase of codebases) {
    const bountiesSubdir = join(bountytasksDir, codebase, "bounties");
    if (!existsSync(bountiesSubdir) || !statSync(bountiesSubdir).isDirectory()) continue;

    const bountyDirs = readdirSync(bountiesSubdir)
      .filter((d) => {
        const full = join(bountiesSubdir, d);
        return statSync(full).isDirectory() && d.startsWith("bounty_");
      })
      .sort();

    for (const bountyDirName of bountyDirs) {
      const bountyDir = join(bountiesSubdir, bountyDirName);
      const metaPath = join(bountyDir, "bounty_metadata.json");

      if (!existsSync(metaPath)) {
        skippedBounties.push(`${codebase}/${bountyDirName}`);
        continue;
      }

      let metadata: any;
      try {
        metadata = JSON.parse(readFileSync(metaPath, "utf8"));
      } catch {
        skippedBounties.push(`${codebase}/${bountyDirName}`);
        continue;
      }

      const bountyNumber = parseInt(bountyDirName.replace("bounty_", ""), 10);
      const bountyUsd = parseFloat(
        metadata.disclosure_bounty ?? metadata.bounty_value ?? metadata.bounty ?? metadata.reward ?? "0",
      );
      const cwe = metadata.CWE ?? metadata.cwe ?? metadata.cwe_id;
      const severity = metadata.severity ?? metadata.risk;

      // Determine available task types from directory structure
      const taskTypes = inferTaskTypes(bountyDir, metadata);

      for (const taskType of taskTypes) {
        if (taskTypeFilter && taskType !== taskTypeFilter) continue;

        const id = `${codebase}__${bountyNumber}__${taskType}`;
        challenges.push({
          id,
          codebase,
          name: metadata.name ?? metadata.title ?? `${codebase}/bounty_${bountyNumber}`,
          taskType,
          bountyNumber,
          bountyUsd,
          cwe,
          severity,
          path: bountyDir,
        });
      }
    }
  }

  if (skippedBounties.length > 0 && !jsonOutput) {
    console.warn(
      `\x1b[33m  [warn] ${skippedBounties.length} bounty dirs skipped (missing metadata)\x1b[0m`,
    );
    if (skippedBounties.length <= 10) {
      for (const b of skippedBounties) {
        console.warn(`\x1b[33m           - ${b}\x1b[0m`);
      }
    }
    console.warn("");
  }

  return challenges;
}

function inferTaskTypes(bountyDir: string, metadata: any): BountyTaskType[] {
  if (metadata?.task_types && Array.isArray(metadata.task_types)) {
    return metadata.task_types.filter((t: string) =>
      ["detect", "exploit", "patch"].includes(t),
    ) as BountyTaskType[];
  }

  const types: BountyTaskType[] = [];
  if (existsSync(join(bountyDir, "exploit_files"))) types.push("exploit");
  if (existsSync(join(bountyDir, "patch_files"))) types.push("patch");
  if (existsSync(join(bountyDir, "verify_files"))) types.push("detect");

  // Default to exploit if nothing detected (the most common BountyBench task)
  return types.length > 0 ? types : ["exploit"];
}

// ── Run Single Bounty via BountyBench Harness ──

function runHarness(challenge: BountyBenchChallenge): { passed: boolean; error?: string; stdout: string } {
  const workflowType = WORKFLOW_TYPE_MAP[challenge.taskType];
  const taskDir = `bountytasks/${challenge.codebase}`;

  const pythonArgs = [
    "-m", "workflows.runner",
    "--workflow-type", workflowType,
    "--task_dir", taskDir,
    "--bounty_number", String(challenge.bountyNumber),
    "--model", modelArg,
    "--phase_iterations", String(phaseIterations),
  ];

  if (!jsonOutput) {
    console.log(`    $ python ${pythonArgs.join(" ")}`);
  }

  // When only Azure credentials are available, expose them as OpenAI-compatible
  // env vars so BountyBench's Python harness can authenticate.
  const extraEnv: Record<string, string> = {};
  if (
    process.env.AZURE_OPENAI_API_KEY &&
    !process.env.ANTHROPIC_API_KEY &&
    !process.env.OPENAI_API_KEY
  ) {
    extraEnv.OPENAI_API_KEY = process.env.AZURE_OPENAI_API_KEY;
    if (process.env.AZURE_OPENAI_BASE_URL) {
      extraEnv.OPENAI_BASE_URL = process.env.AZURE_OPENAI_BASE_URL;
    }
  }

  const result = spawnSync("python", pythonArgs, {
    cwd: BOUNTYBENCH_PATH,
    stdio: "pipe",
    timeout: 20 * 60 * 1000, // 20 min per bounty
    env: {
      ...process.env,
      ...extraEnv,
      // Ensure BountyBench picks up API keys from our env
      PYTHONUNBUFFERED: "1",
    },
  });

  const stdout = result.stdout?.toString() ?? "";
  const stderr = result.stderr?.toString() ?? "";
  const combined = stdout + "\n" + stderr;

  if (result.error) {
    return {
      passed: false,
      error: result.error.message,
      stdout: combined,
    };
  }

  if (result.status !== 0) {
    // Non-zero exit might still contain useful output — check for pass/fail markers
    const passed = parsePassFail(combined);
    if (passed !== null) {
      return { passed, stdout: combined };
    }
    return {
      passed: false,
      error: `exit code ${result.status}: ${stderr.slice(0, 200)}`,
      stdout: combined,
    };
  }

  const passed = parsePassFail(combined);
  return {
    passed: passed ?? false,
    stdout: combined,
  };
}

/**
 * Parse BountyBench harness output to determine pass/fail.
 *
 * The harness prints results in several possible formats:
 * - "PASS" / "FAIL" in verification output
 * - verify.sh exit code (reflected in harness output)
 * - JSON results in a results/ directory
 */
function parsePassFail(output: string): boolean | null {
  const lower = output.toLowerCase();

  // Check for explicit verification results
  // BountyBench verify.sh prints success/failure markers
  if (/verification.*pass/i.test(output) || /exploit.*succeeded/i.test(output)) return true;
  if (/verification.*fail/i.test(output) || /exploit.*failed/i.test(output)) return false;

  // Check for common pass/fail patterns in harness output
  if (/\bpass(?:ed)?\b/i.test(output) && !/\bfail(?:ed)?\b/i.test(output)) return true;
  if (/\bfail(?:ed)?\b/i.test(output) && !/\bpass(?:ed)?\b/i.test(output)) return false;

  // Try to parse JSON result blocks
  const jsonMatch = output.match(/\{[^{}]*"success"\s*:\s*(true|false)[^{}]*\}/);
  if (jsonMatch) {
    return jsonMatch[1] === "true";
  }

  const resultMatch = output.match(/\{[^{}]*"result"\s*:\s*"?(pass|fail)"?[^{}]*\}/i);
  if (resultMatch) {
    return resultMatch[1].toLowerCase() === "pass";
  }

  // Also check for results written to disk
  return null;
}

/**
 * Check BountyBench results directory for outcome.
 * The harness may write results to results/<task_dir>/<bounty_number>/
 */
function checkResultsDir(challenge: BountyBenchChallenge): boolean | null {
  const possiblePaths = [
    join(BOUNTYBENCH_PATH, "results", challenge.codebase, `bounty_${challenge.bountyNumber}`),
    join(BOUNTYBENCH_PATH, "results", `${challenge.codebase}__${challenge.bountyNumber}`),
    join(BOUNTYBENCH_PATH, "output", challenge.codebase, `bounty_${challenge.bountyNumber}`),
  ];

  for (const dir of possiblePaths) {
    if (!existsSync(dir)) continue;

    // Look for result JSON files
    try {
      const files = readdirSync(dir).filter((f) => f.endsWith(".json"));
      for (const file of files) {
        try {
          const data = JSON.parse(readFileSync(join(dir, file), "utf8"));
          if (typeof data.success === "boolean") return data.success;
          if (typeof data.passed === "boolean") return data.passed;
          if (data.result === "pass" || data.result === "PASS") return true;
          if (data.result === "fail" || data.result === "FAIL") return false;
        } catch { /* skip unparseable files */ }
      }
    } catch { /* skip unreadable dirs */ }
  }

  return null;
}

async function runBountyOnce(challenge: BountyBenchChallenge): Promise<BountyBenchResult> {
  const start = Date.now();

  const { passed, error, stdout } = runHarness(challenge);

  // If harness output was ambiguous, check the results directory
  let finalPassed = passed;
  if (!passed && !error) {
    const diskResult = checkResultsDir(challenge);
    if (diskResult !== null) finalPassed = diskResult;
  }

  return {
    id: challenge.id,
    codebase: challenge.codebase,
    name: challenge.name,
    taskType: challenge.taskType,
    bountyNumber: challenge.bountyNumber,
    bountyUsd: challenge.bountyUsd,
    severity: challenge.severity,
    cwe: challenge.cwe,
    passed: finalPassed,
    durationMs: Date.now() - start,
    error,
  };
}

async function runBounty(challenge: BountyBenchChallenge): Promise<BountyBenchResult> {
  let result = await runBountyOnce(challenge);
  for (let attempt = 2; attempt <= retries && !result.passed && !result.error; attempt++) {
    if (!jsonOutput) {
      process.stdout.write(`  ... retry ${attempt}/${retries}\n`);
    }
    const next = await runBountyOnce(challenge);
    result = chooseBetterResult(result, next);
    if (result.passed) break;
  }
  return result;
}

// ── Main ──

async function main() {
  let challenges = loadChallenges();

  if (onlyIds) {
    const idSet = new Set(onlyIds);
    challenges = challenges.filter(
      (c) =>
        idSet.has(c.id.toLowerCase()) ||
        idSet.has(c.codebase.toLowerCase()) ||
        idSet.has(`${c.codebase}__${c.bountyNumber}`.toLowerCase()),
    );
  }
  if (startAt > 0) challenges = challenges.slice(startAt);
  challenges = challenges.slice(0, limit);

  // Compute total available bounty value
  // De-duplicate by bounty dir (same bounty across task types shares the same dollar value)
  const bountyByDir = new Map<string, number>();
  for (const c of challenges) {
    bountyByDir.set(c.path, c.bountyUsd);
  }
  const totalAvailableBountyUsd = [...bountyByDir.values()].reduce((a, b) => a + b, 0);

  if (!jsonOutput) {
    console.log("\x1b[36m\x1b[1m  0sec x BountyBench benchmark\x1b[0m");
    console.log(`  bounties: ${challenges.length}  retries: ${retries}  model: ${modelArg}`);
    console.log(`  phase iterations: ${phaseIterations}`);
    if (taskTypeFilter) console.log(`  task filter: ${taskTypeFilter}`);
    console.log(`  total available bounty value: $${totalAvailableBountyUsd.toLocaleString()}`);
    console.log(`  harness: python -m workflows.runner (${BOUNTYBENCH_PATH})`);
    console.log("");
  }

  if (dryRun) {
    for (const c of challenges) {
      const bounty = c.bountyUsd > 0 ? `$${c.bountyUsd.toLocaleString()}` : "n/a";
      console.log(
        `  [${c.taskType.padEnd(7)}] ${bounty.padStart(8)}  ${c.id}  ${c.cwe ?? ""}  ${c.severity ?? ""}`,
      );
    }
    console.log(`\n  Total: ${challenges.length} tasks across ${new Set(challenges.map((c) => c.codebase)).size} codebases`);
    console.log(`  Total bounty value: $${totalAvailableBountyUsd.toLocaleString()}`);
    return;
  }

  const results: BountyBenchResult[] = [];

  // Incremental persistence
  const incrementalDir = join(__dirname, "..", "results");
  mkdirSync(incrementalDir, { recursive: true });
  const incrementalPath = join(incrementalDir, "bountybench-incremental.jsonl");
  if (freshRun) {
    writeFileSync(incrementalPath, "");
  }

  for (const challenge of challenges) {
    if (!jsonOutput) {
      const bountyStr = challenge.bountyUsd > 0 ? ` $${challenge.bountyUsd.toLocaleString()}` : "";
      console.log(
        `\x1b[1m  >> ${challenge.id}\x1b[0m  [${challenge.taskType}]${bountyStr}`,
      );
    }

    const result = await runBounty(challenge);
    results.push(result);

    // Append to incremental sidecar
    try {
      appendFileSync(incrementalPath, JSON.stringify(result) + "\n");
    } catch (err) {
      console.error(
        `  [warn] could not append incremental result: ${err instanceof Error ? err.message : err}`,
      );
    }

    if (!jsonOutput) {
      const icon = result.passed ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m";
      const time = `${(result.durationMs / 1000).toFixed(0)}s`;
      const earned = result.passed && result.bountyUsd > 0 ? ` +$${result.bountyUsd.toLocaleString()}` : "";
      console.log(
        `  ${icon} ${challenge.name.slice(0, 40).padEnd(40)} ${time}${earned}${result.error ? `  err: ${result.error.slice(0, 60)}` : ""}`,
      );
    }
  }

  // ── Compute Summary ──
  const passed = results.filter((r) => r.passed).length;
  const earnedBountyValueUsd = results
    .filter((r) => r.passed)
    .reduce((sum, r) => sum + r.bountyUsd, 0);
  const harnessErrors = results.filter((r) => r.error).length;
  const started = challenges.length - harnessErrors;

  // By task type
  const byTaskType: Record<BountyTaskType, { total: number; passed: number; earnedUsd: number }> = {
    detect: { total: 0, passed: 0, earnedUsd: 0 },
    exploit: { total: 0, passed: 0, earnedUsd: 0 },
    patch: { total: 0, passed: 0, earnedUsd: 0 },
  };
  for (const r of results) {
    const entry = byTaskType[r.taskType];
    entry.total++;
    if (r.passed) {
      entry.passed++;
      entry.earnedUsd += r.bountyUsd;
    }
  }

  const report: BountyBenchReport = {
    timestamp: new Date().toISOString(),
    model: modelArg,
    phaseIterations,
    retries,
    bounties: challenges.length,
    started,
    passed,
    totalBountyValueUsd: totalAvailableBountyUsd,
    earnedBountyValueUsd,
    harnessErrors,
    byTaskType,
    results,
  };

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log("\n  ──────────────────────────────────────");
    console.log(
      `  \x1b[1m\x1b[32mBounty earned: $${earnedBountyValueUsd.toLocaleString()} / $${totalAvailableBountyUsd.toLocaleString()}\x1b[0m`,
    );
    console.log(
      `  Passed:        \x1b[1m${passed}/${challenges.length}\x1b[0m  (${(
        (passed / Math.max(challenges.length, 1)) *
        100
      ).toFixed(1)}%)`,
    );
    console.log(
      `  Started:       \x1b[1m${started}/${challenges.length}\x1b[0m  (harness errors: ${harnessErrors})`,
    );
    console.log(
      `  Total time:    ${(results.reduce((a, r) => a + r.durationMs, 0) / 1000).toFixed(0)}s`,
    );

    console.log("\n  By task type:");
    for (const [type, data] of Object.entries(byTaskType)) {
      const earnStr = data.earnedUsd > 0 ? `  ($${data.earnedUsd.toLocaleString()} earned)` : "";
      console.log(`    ${type.padEnd(10)} ${data.passed}/${data.total}${earnStr}`);
    }

    // By codebase
    const codebaseMap = new Map<string, { total: number; passed: number; earnedUsd: number }>();
    for (const r of results) {
      const entry = codebaseMap.get(r.codebase) ?? { total: 0, passed: 0, earnedUsd: 0 };
      entry.total++;
      if (r.passed) {
        entry.passed++;
        entry.earnedUsd += r.bountyUsd;
      }
      codebaseMap.set(r.codebase, entry);
    }
    console.log("\n  By codebase:");
    for (const [cb, data] of [...codebaseMap.entries()].sort((a, b) => b[1].earnedUsd - a[1].earnedUsd)) {
      const earnStr = data.earnedUsd > 0 ? `  ($${data.earnedUsd.toLocaleString()})` : "";
      console.log(`    ${cb.padEnd(20)} ${data.passed}/${data.total}${earnStr}`);
    }
    console.log("");
  }

  // ── Save Results (merge with existing) ──
  const resultsDir = join(__dirname, "..", "results");
  mkdirSync(resultsDir, { recursive: true });
  const latestPath = join(resultsDir, "bountybench-latest.json");

  if (!freshRun && existsSync(latestPath)) {
    try {
      const existing: BountyBenchReport = JSON.parse(readFileSync(latestPath, "utf8"));
      const existingById = new Map(existing.results.map((r) => [r.id, r]));
      for (const r of report.results) {
        existingById.set(r.id, r);
      }
      const mergedResults = [...existingById.values()].sort((a, b) => a.id.localeCompare(b.id));

      const mergedHarnessErrors = mergedResults.filter((r) => r.error).length;
      const mergedStarted = mergedResults.length - mergedHarnessErrors;
      const mergedPassed = mergedResults.filter((r) => r.passed).length;
      const mergedEarned = mergedResults.filter((r) => r.passed).reduce((sum, r) => sum + r.bountyUsd, 0);

      const mergedByTaskType: Record<BountyTaskType, { total: number; passed: number; earnedUsd: number }> = {
        detect: { total: 0, passed: 0, earnedUsd: 0 },
        exploit: { total: 0, passed: 0, earnedUsd: 0 },
        patch: { total: 0, passed: 0, earnedUsd: 0 },
      };
      for (const r of mergedResults) {
        const entry = mergedByTaskType[r.taskType];
        entry.total++;
        if (r.passed) {
          entry.passed++;
          entry.earnedUsd += r.bountyUsd;
        }
      }

      const mergedReport: BountyBenchReport = {
        ...report,
        timestamp: new Date().toISOString(),
        bounties: mergedResults.length,
        started: mergedStarted,
        passed: mergedPassed,
        earnedBountyValueUsd: mergedEarned,
        harnessErrors: mergedHarnessErrors,
        byTaskType: mergedByTaskType,
        results: mergedResults,
      };

      writeFileSync(latestPath, JSON.stringify(mergedReport, null, 2));
    } catch {
      writeFileSync(latestPath, JSON.stringify(report, null, 2));
    }
  } else {
    writeFileSync(latestPath, JSON.stringify(report, null, 2));
  }

  if (!jsonOutput) {
    console.log(`  Results saved to ${latestPath}`);
  }
}

main()
  .then(() => {
    process.exit(0);
  })
  .catch((err) => {
    console.error("BountyBench benchmark failed:", err);
    process.exit(1);
  });
