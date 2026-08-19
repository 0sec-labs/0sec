#!/usr/bin/env node

/**
 * Cybench Benchmark Runner
 *
 * Runs pwnkit against the Cybench benchmark suite (40 real CTF challenges from
 * HackTheBox, project-sekai-ctf, GlacierCTF, hkcert-ctf, and other CTF platforms).
 * Categories: web, crypto, pwn, reverse, forensics, misc.
 *
 * Reference: https://arxiv.org/abs/2408.08926 (Cybench paper)
 * Repo: https://github.com/andyzorigin/cybench
 *
 * Prerequisites:
 * - Docker + Docker Compose installed (for tasks that have a docker-compose.yml)
 * - Cybench repo cloned: git clone https://github.com/andyzorigin/cybench /tmp/cybench
 *   (NOTE: cybench uses git submodules — clone with --recurse-submodules to get
 *    all 40 tasks. Without submodules ~31/40 tasks are available.)
 *
 * Usage:
 *   tsx src/cybench-runner.ts                    # run all 40
 *   tsx src/cybench-runner.ts --limit 5          # first 5 only
 *   tsx src/cybench-runner.ts --only flag-command,noisier-crc
 *   tsx src/cybench-runner.ts --start 10
 *   tsx src/cybench-runner.ts --retries 3
 *   tsx src/cybench-runner.ts --save-findings
 *   tsx src/cybench-runner.ts --json
 *   tsx src/cybench-runner.ts --dry-run
 */

import { execSync } from "node:child_process";
import { readFileSync, existsSync, writeFileSync, appendFileSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { agenticScan } from "@pwnkit/core";
import { tmpdir } from "node:os";
import type { RuntimeMode } from "@pwnkit/shared";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CYBENCH_PATH = process.env.CYBENCH_PATH ?? "/tmp/cybench";

// Hard wall-clock ceiling per challenge attempt (including Docker start/stop,
// retries are separate attempts). Prevents a single hung challenge from
// consuming the entire CI budget.
const PER_CHALLENGE_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes

// ── CLI Args ──
const args = process.argv.slice(2);
const limit = args.includes("--limit") ? parseInt(args[args.indexOf("--limit") + 1]) : Infinity;
const categoryFilter = args.includes("--category") ? args[args.indexOf("--category") + 1] : undefined;
const jsonOutput = args.includes("--json");
const dryRun = args.includes("--dry-run");
const retries = args.includes("--retries") ? parseInt(args[args.indexOf("--retries") + 1]) : 1;
const startAt = args.includes("--start") ? parseInt(args[args.indexOf("--start") + 1]) : 0;
const onlyIds = args.includes("--only")
  ? args[args.indexOf("--only") + 1].split(",").map((s) => s.trim().toLowerCase())
  : undefined;
const saveFindings = args.includes("--save-findings");
const freshRun = args.includes("--fresh");
const runtimeArg = args.includes("--runtime") ? args[args.indexOf("--runtime") + 1] : "auto";

// ── Types ──
interface CybenchChallenge {
  id: string;
  name: string;
  category: string;
  difficulty: number;
  description: string;
  flag: string;
  targetHost?: string;
  hasDockerCompose: boolean;
  path: string;
  composePath?: string;
}

interface CybenchResult {
  id: string;
  name: string;
  category: string;
  difficulty: number;
  attackTurns?: number;
  estimatedCostUsd?: number;
  passed: boolean;
  flagFound: boolean;
  findingsCount: number;
  durationMs: number;
  error?: string;
  findings?: unknown[];
}

interface CybenchReport {
  timestamp: string;
  runtime: string;
  retries: number;
  challenges: number;
  started: number;
  passed: number;
  flags: number;
  totalAttackTurns: number;
  totalEstimatedCostUsd: number;
  startupFailures: number;
  scanErrors: number;
  results: CybenchResult[];
}

function chooseBetterResult(a: CybenchResult, b: CybenchResult): CybenchResult {
  if (b.flagFound && !a.flagFound) return b;
  if (a.flagFound && !b.flagFound) return a;
  if (b.passed && !a.passed) return b;
  if (a.passed && !b.passed) return a;
  if (!!a.error !== !!b.error) return a.error ? b : a;
  if (b.findingsCount !== a.findingsCount) return b.findingsCount > a.findingsCount ? b : a;
  return b.durationMs < a.durationMs ? b : a;
}

// ── Load Challenges ──
/** Race a promise against a wall-clock timeout. */
function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Per-challenge timeout (${ms / 1000}s) exceeded: ${label}`)), ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

/** Prune stopped containers, dangling images, and unused networks/volumes. */
function dockerCleanup(): void {
  try {
    execSync("docker container prune -f", { stdio: "pipe", timeout: 30_000 });
  } catch {}
  try {
    execSync("docker volume prune -f", { stdio: "pipe", timeout: 30_000 });
  } catch {}
  try {
    execSync("docker network prune -f", { stdio: "pipe", timeout: 30_000 });
  } catch {}
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/\[[^\]]*\]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function readFlag(taskPath: string, metadata: any): string {
  // Preferred: metadata/solution/flag.txt
  const flagPath = join(taskPath, "metadata", "solution", "flag.txt");
  if (existsSync(flagPath)) {
    return readFileSync(flagPath, "utf8").trim();
  }
  // Fallback 1: top-level flag.txt
  const altFlag = join(taskPath, "flag.txt");
  if (existsSync(altFlag)) {
    return readFileSync(altFlag, "utf8").trim();
  }
  // Fallback 2: last subtask answer that looks like a flag
  const subtasks = metadata?.subtasks ?? [];
  for (let i = subtasks.length - 1; i >= 0; i--) {
    const ans = subtasks[i]?.answer;
    if (typeof ans === "string" && /\{[^}]+\}/.test(ans)) {
      return ans.trim();
    }
  }
  return "";
}

function loadChallenges(): CybenchChallenge[] {
  const taskListPath = join(CYBENCH_PATH, "task_list.txt");
  if (!existsSync(taskListPath)) {
    console.error(`Cybench task_list.txt not found at ${taskListPath}`);
    console.error(`Clone the repo: git clone --recurse-submodules https://github.com/andyzorigin/cybench ${CYBENCH_PATH}`);
    process.exit(1);
  }

  const taskRelPaths = readFileSync(taskListPath, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

  const challenges: CybenchChallenge[] = [];
  const skippedTasks: string[] = [];

  for (const rel of taskRelPaths) {
    const path = join(CYBENCH_PATH, rel);
    const metadataPath = join(path, "metadata", "metadata.json");
    if (!existsSync(metadataPath)) {
      skippedTasks.push(rel);
      continue;
    }

    let metadata: any;
    try {
      metadata = JSON.parse(readFileSync(metadataPath, "utf8"));
    } catch {
      skippedTasks.push(rel);
      continue;
    }

    const name = basename(rel);
    const id = slugify(name);
    const categories: string[] = metadata.categories ?? [];
    const category = categories[0] ?? "misc";
    const difficulty = parseInt(metadata.difficulty ?? "0", 10);
    const description: string = metadata.hard_prompt ?? metadata.easy_prompt ?? "";
    const flag = readFlag(path, metadata);
    const composePath = join(path, "docker-compose.yml");
    const hasDockerCompose = existsSync(composePath);

    challenges.push({
      id,
      name,
      category,
      difficulty,
      description,
      flag,
      targetHost: metadata.target_host,
      hasDockerCompose,
      path,
      composePath: hasDockerCompose ? composePath : undefined,
    });
  }

  if (skippedTasks.length > 0 && !jsonOutput) {
    console.warn(`\x1b[33m  [warn] ${skippedTasks.length}/${taskRelPaths.length} tasks skipped (missing metadata — likely missing git submodules)\x1b[0m`);
    console.warn(`\x1b[33m         Clone with --recurse-submodules to get all 40 tasks.\x1b[0m`);
    if (skippedTasks.length <= 15) {
      for (const t of skippedTasks) {
        console.warn(`\x1b[33m           - ${t}\x1b[0m`);
      }
    }
    console.warn("");
  }

  return challenges;
}

// ── Docker Helpers ──
function startChallenge(challenge: CybenchChallenge): boolean {
  if (!challenge.hasDockerCompose) return true;

  try {
    // Cybench compose files reference an external "shared_net" network
    try { execSync("docker network create shared_net", { stdio: "pipe", timeout: 10_000 }); } catch {}

    // Stop any previously running containers from this task
    try { execSync("docker compose down -v --remove-orphans", { cwd: challenge.path, stdio: "pipe", timeout: 30_000 }); } catch {}

    // If a start_docker.sh helper exists, prefer it (cybench convention)
    const startScript = join(challenge.path, "start_docker.sh");
    if (existsSync(startScript)) {
      execSync("bash start_docker.sh", { cwd: challenge.path, stdio: "pipe", timeout: 180_000 });
    } else {
      execSync("docker compose up -d --wait", { cwd: challenge.path, stdio: "pipe", timeout: 180_000 });
    }
    return true;
  } catch {
    return false;
  }
}

function stopChallenge(challenge: CybenchChallenge): void {
  if (!challenge.hasDockerCompose) return;
  try {
    const stopScript = join(challenge.path, "stop_docker.sh");
    if (existsSync(stopScript)) {
      execSync("bash stop_docker.sh", { cwd: challenge.path, stdio: "pipe", timeout: 60_000 });
    } else {
      execSync("docker compose down -v --remove-orphans", { cwd: challenge.path, stdio: "pipe", timeout: 60_000 });
    }
  } catch {}
}

// ── Build Target URL/Hint ──
function buildTarget(challenge: CybenchChallenge): string {
  // Cybench target_host values look like "web_flag:1337" or "noisiercrc:9999".
  // For web targets we can prefix http:// for the agent. For non-web (crypto/pwn)
  // we still hand over the host:port and let the agent connect via nc/python.
  const host = challenge.targetHost ?? "localhost";
  if (challenge.category === "web") {
    return host.startsWith("http") ? host : `http://${host}`;
  }
  return host;
}

function buildHint(challenge: CybenchChallenge): string {
  const parts: string[] = [];
  if (challenge.description) parts.push(`Challenge description: ${challenge.description}`);
  parts.push(`Category: ${challenge.category}`);
  if (challenge.targetHost) parts.push(`Target: ${challenge.targetHost}`);

  // Surface the challenge files directory so the agent can read provided sources.
  // Cybench tasks usually expose files via "challenge/" or "release/" subdirs.
  const candidateDirs = ["release", "challenge", "dist"];
  for (const d of candidateDirs) {
    const p = join(challenge.path, d);
    if (existsSync(p)) {
      parts.push(`Provided files (read-only): ${p}`);
      break;
    }
  }
  return parts.join("\n");
}

// ── Run Single Challenge ──
async function runChallengeOnce(challenge: CybenchChallenge): Promise<CybenchResult> {
  const start = Date.now();

  if (!startChallenge(challenge)) {
    stopChallenge(challenge);
    return {
      id: challenge.id,
      name: challenge.name,
      category: challenge.category,
      difficulty: challenge.difficulty,
      passed: false,
      flagFound: false,
      findingsCount: 0,
      durationMs: Date.now() - start,
      error: "Docker start failed",
    };
  }

  const target = buildTarget(challenge);
  const hint = buildHint(challenge);

  try {
    const dbPath = join(tmpdir(), `pwnkit-cybench-${challenge.id}-${Date.now()}.db`);
    const report = await agenticScan({
      config: {
        target,
        depth: "deep",
        format: "json",
        mode: challenge.category === "web" ? "web" : "web",
        timeout: 120_000,
        runtime: runtimeArg as RuntimeMode,
        verbose: false,
      },
      dbPath,
      challengeHint: hint,
    });

    const findings = report.findings ?? [];
    const allText = JSON.stringify(report);
    // Cybench flags are case-sensitive — match exact, then fall back to
    // case-insensitive (covers wrappers that lowercase agent output).
    let flagFound = false;
    if (challenge.flag) {
      flagFound = allText.includes(challenge.flag) || allText.toLowerCase().includes(challenge.flag.toLowerCase());
    }

    return {
      id: challenge.id,
      name: challenge.name,
      category: challenge.category,
      difficulty: challenge.difficulty,
      attackTurns: report.benchmarkMeta?.attackTurns,
      estimatedCostUsd: report.benchmarkMeta?.estimatedCostUsd,
      passed: flagFound,
      flagFound,
      findingsCount: findings.length,
      durationMs: Date.now() - start,
      ...(saveFindings && findings.length > 0 ? { findings } : {}),
    };
  } catch (err) {
    return {
      id: challenge.id,
      name: challenge.name,
      category: challenge.category,
      difficulty: challenge.difficulty,
      passed: false,
      flagFound: false,
      findingsCount: 0,
      durationMs: Date.now() - start,
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    stopChallenge(challenge);
  }
}

async function runChallengeWithTimeout(challenge: CybenchChallenge): Promise<CybenchResult> {
  try {
    return await withTimeout(
      runChallengeOnce(challenge),
      PER_CHALLENGE_TIMEOUT_MS,
      challenge.id,
    );
  } catch (err) {
    // On timeout, force-stop Docker resources for this challenge
    stopChallenge(challenge);
    return {
      id: challenge.id,
      name: challenge.name,
      category: challenge.category,
      difficulty: challenge.difficulty,
      passed: false,
      flagFound: false,
      findingsCount: 0,
      durationMs: PER_CHALLENGE_TIMEOUT_MS,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

async function runChallenge(challenge: CybenchChallenge): Promise<CybenchResult> {
  let result = await runChallengeWithTimeout(challenge);
  for (let attempt = 2; attempt <= retries && !result.flagFound && !result.error; attempt++) {
    if (!jsonOutput) {
      process.stdout.write(`  ... retry ${attempt}/${retries}\n`);
    }
    const next = await runChallengeWithTimeout(challenge);
    result = chooseBetterResult(result, next);
    if (result.flagFound) break;
  }
  return result;
}

// ── Main ──
async function main() {
  let challenges = loadChallenges();

  if (categoryFilter) challenges = challenges.filter((c) => c.category === categoryFilter);
  if (onlyIds) {
    const idSet = new Set(onlyIds);
    challenges = challenges.filter((c) => idSet.has(c.id) || idSet.has(c.name.toLowerCase()));
  }
  if (startAt > 0) challenges = challenges.slice(startAt);
  challenges = challenges.slice(0, limit);

  if (!jsonOutput) {
    console.log("\x1b[36m\x1b[1m  pwnkit x Cybench benchmark\x1b[0m");
    console.log(`  challenges: ${challenges.length}  retries: ${retries}`);
    console.log("");
  }

  if (dryRun) {
    for (const c of challenges) {
      const dock = c.hasDockerCompose ? "docker" : "no-docker";
      console.log(`  [${c.category}] [d${c.difficulty}] [${dock}] ${c.id}  flag=${c.flag ? "yes" : "MISSING"}`);
    }
    console.log(`\n  Total: ${challenges.length} tasks`);
    return;
  }

  const results: CybenchResult[] = [];

  // Incremental persistence — append every completed result to a JSONL
  // sidecar so a workflow timeout produces useful partial data instead of
  // total data loss. The end-of-run write to cybench-latest.json still
  // happens below; this is the safety net for the 6-hour CI ceiling.
  const incrementalDir = join(__dirname, "..", "results");
  mkdirSync(incrementalDir, { recursive: true });
  const incrementalPath = join(incrementalDir, "cybench-incremental.jsonl");
  if (freshRun) {
    // Truncate the sidecar so a fresh run starts with a clean stream
    writeFileSync(incrementalPath, "");
  }

  for (const challenge of challenges) {
    if (!jsonOutput) {
      console.log(`\x1b[1m  >> ${challenge.id}\x1b[0m  [${challenge.category}/d${challenge.difficulty}]`);
    }

    const result = await runChallenge(challenge);
    results.push(result);

    // Append-on-complete to the incremental sidecar. Single line of JSON
    // per challenge, in completion order. Safe across crashes — append
    // is atomic enough at the OS layer for our purposes.
    try {
      appendFileSync(incrementalPath, JSON.stringify(result) + "\n");
    } catch (err) {
      console.error(`  [warn] could not append incremental result: ${err instanceof Error ? err.message : err}`);
    }

    if (!jsonOutput) {
      const icon = result.flagFound ? "\x1b[32mFLAG\x1b[0m" : "\x1b[31mFAIL\x1b[0m";
      const time = `${(result.durationMs / 1000).toFixed(0)}s`;
      console.log(`  ${icon} ${challenge.name.slice(0, 50).padEnd(50)} ${result.findingsCount} findings  ${time}${result.error ? `  err: ${result.error.slice(0, 40)}` : ""}`);
    }

    // Reclaim Docker resources between challenges to prevent disk/memory
    // exhaustion on long runs (especially full-40).
    dockerCleanup();
  }

  const passed = results.filter((r) => r.passed).length;
  const flags = results.filter((r) => r.flagFound).length;
  const startupFailures = results.filter((r) => r.error === "Docker start failed").length;
  const scanErrors = results.filter((r) => r.error && r.error !== "Docker start failed").length;
  const started = challenges.length - startupFailures;
  const totalAttackTurns = results.reduce((sum, r) => sum + (r.attackTurns ?? 0), 0);
  const totalEstimatedCostUsd = results.reduce((sum, r) => sum + (r.estimatedCostUsd ?? 0), 0);

  const report: CybenchReport = {
    timestamp: new Date().toISOString(),
    runtime: runtimeArg,
    retries,
    challenges: challenges.length,
    started,
    passed,
    flags,
    totalAttackTurns,
    totalEstimatedCostUsd,
    startupFailures,
    scanErrors,
    results,
  };

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log("\n  ──────────────────────────────────────");
    console.log(`  Flag extraction: \x1b[1m${flags}/${challenges.length}\x1b[0m  (${(flags / Math.max(challenges.length, 1) * 100).toFixed(1)}%)`);
    console.log(`  Started:         \x1b[1m${started}/${challenges.length}\x1b[0m  (start fails: ${startupFailures})`);
    if (totalAttackTurns > 0) console.log(`  Attack turns:    \x1b[1m${totalAttackTurns}\x1b[0m`);
    if (totalEstimatedCostUsd > 0) console.log(`  Est. cost:       \x1b[1m$${totalEstimatedCostUsd.toFixed(2)}\x1b[0m`);
    console.log(`  Total time:      ${(results.reduce((a, r) => a + r.durationMs, 0) / 1000).toFixed(0)}s`);

    // By category
    const catMap = new Map<string, { total: number; flags: number }>();
    for (const r of results) {
      const entry = catMap.get(r.category) ?? { total: 0, flags: 0 };
      entry.total++;
      if (r.flagFound) entry.flags++;
      catMap.set(r.category, entry);
    }
    console.log("\n  By category:");
    for (const [cat, data] of [...catMap.entries()].sort((a, b) => b[1].total - a[1].total)) {
      console.log(`    ${cat.padEnd(15)} ${data.flags}/${data.total}`);
    }
    console.log("");
  }

  // Save results — merge with existing file so partial/resumed runs accumulate
  const resultsDir = join(__dirname, "..", "results");
  mkdirSync(resultsDir, { recursive: true });
  const latestPath = join(resultsDir, "cybench-latest.json");

  if (!freshRun && existsSync(latestPath)) {
    try {
      const existing: CybenchReport = JSON.parse(readFileSync(latestPath, "utf8"));
      const existingById = new Map(existing.results.map((r) => [r.id, r]));
      for (const r of report.results) {
        existingById.set(r.id, r);
      }
      const mergedResults = [...existingById.values()].sort((a, b) => a.id.localeCompare(b.id));

      const mergedStartupFailures = mergedResults.filter((r) => r.error === "Docker start failed").length;
      const mergedScanErrors = mergedResults.filter((r) => r.error && r.error !== "Docker start failed").length;
      const mergedStarted = mergedResults.length - mergedStartupFailures;

      const mergedReport: CybenchReport = {
        ...report,
        timestamp: new Date().toISOString(),
        challenges: mergedResults.length,
        started: mergedStarted,
        passed: mergedResults.filter((r) => r.passed).length,
        flags: mergedResults.filter((r) => r.flagFound).length,
        startupFailures: mergedStartupFailures,
        scanErrors: mergedScanErrors,
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
    // Force exit — async resources (DB connections, event loop timers from
    // the agentic scanner) sometimes keep the process alive after main()
    // completes. We've already written results to disk, so exiting cleanly
    // here is safe and prevents CI timeouts.
    process.exit(0);
  })
  .catch((err) => {
    console.error("Cybench benchmark failed:", err);
    process.exit(1);
  });
