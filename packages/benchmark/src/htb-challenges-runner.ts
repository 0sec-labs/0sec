#!/usr/bin/env node

/**
 * HackTheBox Challenges Benchmark Runner
 *
 * Runs pwnkit against HackTheBox Challenges (~818 challenges across 11
 * categories — BoxPwnr scores 39.6%). This is separate from Starting Point
 * machines: challenges are self-contained CTF problems, either static
 * (download a ZIP) or dynamic (spawn a Docker instance).
 *
 * Prerequisites:
 * - HTB_API_TOKEN env var set (Profile → Settings → App Tokens on HTB)
 * - For dynamic challenges: active OpenVPN connection to the HTB lab network
 * - Static challenges don't require VPN — just download and analyze
 *
 * Usage:
 *   tsx src/htb-challenges-runner.ts                              # run all challenges
 *   tsx src/htb-challenges-runner.ts --limit 10                   # first 10
 *   tsx src/htb-challenges-runner.ts --category web,crypto        # filter by category
 *   tsx src/htb-challenges-runner.ts --difficulty easy,medium      # filter by difficulty
 *   tsx src/htb-challenges-runner.ts --challenge-type static       # only static or dynamic
 *   tsx src/htb-challenges-runner.ts --only challenge-name         # specific challenges
 *   tsx src/htb-challenges-runner.ts --start 5                    # skip first 5
 *   tsx src/htb-challenges-runner.ts --retries 3
 *   tsx src/htb-challenges-runner.ts --save-findings
 *   tsx src/htb-challenges-runner.ts --json
 *   tsx src/htb-challenges-runner.ts --dry-run
 *
 * HTB API v4 reference: https://labs.hackthebox.com/api/v4/
 * Flag format: HTB{...}
 */

import { execSync } from "node:child_process";
import { readFileSync, existsSync, writeFileSync, appendFileSync, mkdirSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { agenticScan } from "@pwnkit/core";
import { tmpdir } from "node:os";
import type { RuntimeMode } from "@pwnkit/shared";

const __dirname = dirname(fileURLToPath(import.meta.url));

const HTB_API_BASE = "https://labs.hackthebox.com/api/v4";
const HTB_API_TOKEN = process.env.HTB_API_TOKEN;

// ── All HTB Challenge categories ──
const ALL_CATEGORIES = [
  "crypto", "forensics", "reversing", "pwn", "web", "misc",
  "osint", "hardware", "mobile", "blockchain", "gamepwn",
] as const;

type ChallengeCategory = typeof ALL_CATEGORIES[number];

// ── CLI Args ──
const args = process.argv.slice(2);
const limit = args.includes("--limit") ? parseInt(args[args.indexOf("--limit") + 1]) : Infinity;
const categoryFilter = args.includes("--category")
  ? args[args.indexOf("--category") + 1].split(",").map((s) => s.trim().toLowerCase())
  : undefined;
const difficultyFilter = args.includes("--difficulty")
  ? args[args.indexOf("--difficulty") + 1].split(",").map((s) => s.trim().toLowerCase())
  : undefined;
const challengeTypeFilter = args.includes("--challenge-type")
  ? args[args.indexOf("--challenge-type") + 1].toLowerCase() as "static" | "dynamic"
  : undefined;
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
const spawnTimeout = args.includes("--spawn-timeout")
  ? parseInt(args[args.indexOf("--spawn-timeout") + 1]) * 1000
  : 180_000; // 3 min default for challenge instances

// ── Types ──
interface HtbChallenge {
  id: number;
  name: string;
  category: string;
  difficulty: string;
  /** Whether this is a static (download ZIP) or dynamic (spawn Docker) challenge */
  isStatic: boolean;
  /** Number of solves — higher means easier in practice */
  solves: number;
  /** Challenge description from HTB, if available */
  description?: string;
}

interface HtbChallengeResult {
  id: number;
  name: string;
  category: string;
  difficulty: string;
  challengeType: "static" | "dynamic";
  attackTurns?: number;
  estimatedCostUsd?: number;
  passed: boolean;
  flagSubmitted: boolean;
  findingsCount: number;
  durationMs: number;
  error?: string;
  findings?: unknown[];
}

interface HtbChallengeReport {
  timestamp: string;
  runtime: string;
  retries: number;
  challenges: number;
  started: number;
  passed: number;
  flagsSubmitted: number;
  totalAttackTurns: number;
  totalEstimatedCostUsd: number;
  spawnFailures: number;
  scanErrors: number;
  /** Per-category breakdown */
  categoryBreakdown: Record<string, { total: number; flags: number; passed: number }>;
  results: HtbChallengeResult[];
}

function chooseBetterResult(a: HtbChallengeResult, b: HtbChallengeResult): HtbChallengeResult {
  if (b.flagSubmitted && !a.flagSubmitted) return b;
  if (a.flagSubmitted && !b.flagSubmitted) return a;
  if (b.passed && !a.passed) return b;
  if (a.passed && !b.passed) return a;
  if (!!a.error !== !!b.error) return a.error ? b : a;
  if (b.findingsCount !== a.findingsCount) return b.findingsCount > a.findingsCount ? b : a;
  return b.durationMs < a.durationMs ? b : a;
}

// ── HTB API Helpers ──

async function htbFetch(path: string, options: RequestInit = {}): Promise<any> {
  if (!HTB_API_TOKEN) {
    throw new Error("HTB_API_TOKEN env var is required. Get one from https://labs.hackthebox.com → Settings → App Tokens");
  }

  const url = `${HTB_API_BASE}${path}`;
  const resp = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${HTB_API_TOKEN}`,
      "Content-Type": "application/json",
      Accept: "application/json",
      ...(options.headers as Record<string, string> ?? {}),
    },
  });

  if (!resp.ok) {
    const body = await resp.text().catch(() => "");
    throw new Error(`HTB API ${resp.status}: ${resp.statusText} — ${body.slice(0, 200)}`);
  }

  return resp.json();
}

/** Fetch a binary response from the HTB API (for ZIP downloads). */
async function htbFetchBinary(path: string): Promise<ArrayBuffer> {
  if (!HTB_API_TOKEN) {
    throw new Error("HTB_API_TOKEN env var is required.");
  }

  const url = `${HTB_API_BASE}${path}`;
  const resp = await fetch(url, {
    headers: {
      Authorization: `Bearer ${HTB_API_TOKEN}`,
      Accept: "application/octet-stream, application/zip, */*",
    },
  });

  if (!resp.ok) {
    const body = await resp.text().catch(() => "");
    throw new Error(`HTB API ${resp.status}: ${resp.statusText} — ${body.slice(0, 200)}`);
  }

  return resp.arrayBuffer();
}

/** Fetch all challenges from the HTB API with pagination. */
async function fetchChallenges(): Promise<HtbChallenge[]> {
  const challenges: HtbChallenge[] = [];

  // The HTB challenge list endpoint returns paginated results.
  // Try the list endpoint first; fall back to iterating pages.
  try {
    const data = await htbFetch("/challenge/list");
    const items = data?.challenges ?? data?.data ?? data ?? [];

    if (Array.isArray(items)) {
      for (const c of items) {
        challenges.push(parseChallengeEntry(c));
      }
    }
  } catch (err) {
    // If list endpoint fails, try paginated approach
    if (!jsonOutput) {
      console.error(`  [warn] /challenge/list failed, trying paginated fetch: ${err instanceof Error ? err.message : err}`);
    }

    let page = 1;
    const perPage = 100;
    let hasMore = true;

    while (hasMore) {
      try {
        const data = await htbFetch(`/challenge/list?page=${page}&per_page=${perPage}`);
        const items = data?.challenges ?? data?.data ?? [];

        if (!Array.isArray(items) || items.length === 0) {
          hasMore = false;
          break;
        }

        for (const c of items) {
          challenges.push(parseChallengeEntry(c));
        }

        // If we got fewer than perPage, we've hit the last page
        if (items.length < perPage) {
          hasMore = false;
        }

        page++;
      } catch {
        hasMore = false;
      }
    }
  }

  return challenges;
}

function parseChallengeEntry(c: any): HtbChallenge {
  return {
    id: c.id,
    name: c.name,
    category: (c.category_name ?? c.category ?? "misc").toLowerCase(),
    difficulty: c.difficulty ?? c.difficultyText ?? "Easy",
    isStatic: !c.docker && !c.docker_ip,
    solves: c.solves ?? 0,
    description: c.description,
  };
}

/**
 * Download and extract a static challenge's ZIP file.
 * Returns the path to the extracted directory.
 */
async function downloadStaticChallenge(challenge: HtbChallenge): Promise<string> {
  const workDir = join(tmpdir(), `pwnkit-htb-challenge-${challenge.id}-${Date.now()}`);
  mkdirSync(workDir, { recursive: true });

  const zipPath = join(workDir, "challenge.zip");

  try {
    const buffer = await htbFetchBinary(`/challenge/download/${challenge.id}`);
    writeFileSync(zipPath, Buffer.from(buffer));

    // Extract the ZIP
    const extractDir = join(workDir, "files");
    mkdirSync(extractDir, { recursive: true });

    execSync(`unzip -o -q "${zipPath}" -d "${extractDir}"`, {
      timeout: 30_000,
      stdio: "pipe",
    });

    return extractDir;
  } catch (err) {
    // If download/extract fails, return the workdir anyway so we have a scratch space
    throw new Error(`Failed to download/extract challenge: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * Spawn a dynamic challenge instance (Docker container on HTB).
 * Returns { host, port } or null on timeout.
 */
async function spawnDynamicChallenge(challenge: HtbChallenge): Promise<{ host: string; port: number } | null> {
  try {
    await htbFetch(`/challenge/start`, {
      method: "POST",
      body: JSON.stringify({ id: challenge.id }),
    });
  } catch (err) {
    // 400 often means "already spawned" — try to get connection info anyway
    if (!(err instanceof Error && err.message.includes("400"))) {
      throw err;
    }
  }

  // Poll for the instance to come up
  const deadline = Date.now() + spawnTimeout;
  while (Date.now() < deadline) {
    try {
      const status = await htbFetch(`/challenge/info/${challenge.id}`);
      const ip = status?.docker_ip ?? status?.ip;
      const port = status?.docker_port ?? status?.port;

      if (ip && port) {
        return { host: ip, port: typeof port === "string" ? parseInt(port) : port };
      }
    } catch {
      // Transient API errors — keep polling
    }
    await sleep(5_000);
  }

  return null;
}

/** Stop a dynamic challenge instance. */
async function stopDynamicChallenge(challenge: HtbChallenge): Promise<void> {
  try {
    await htbFetch(`/challenge/stop`, {
      method: "POST",
      body: JSON.stringify({ id: challenge.id }),
    });
  } catch {
    // Best-effort cleanup
  }
}

/** Submit a flag to the HTB Challenges API. Returns true if accepted. */
async function submitChallengeFlag(challengeId: number, flag: string, difficulty: number): Promise<boolean> {
  try {
    const resp = await htbFetch("/challenge/own", {
      method: "POST",
      body: JSON.stringify({ id: challengeId, flag, difficulty }),
    });
    return resp?.success === "1" || resp?.success === true || resp?.message?.toLowerCase()?.includes("correct");
  } catch {
    return false;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Map difficulty string to the numeric value HTB expects for flag submission. */
function difficultyToNumber(difficulty: string): number {
  const map: Record<string, number> = {
    easy: 20,
    medium: 30,
    hard: 40,
    insane: 50,
  };
  return map[difficulty.toLowerCase()] ?? 20;
}

// ── Scan ──

function buildStaticHint(challenge: HtbChallenge, extractDir: string): string {
  const parts: string[] = [];
  parts.push(`HackTheBox Challenge: ${challenge.name}`);
  parts.push(`Category: ${challenge.category}, Difficulty: ${challenge.difficulty}`);
  if (challenge.description) {
    parts.push(`Description: ${challenge.description}`);
  }
  parts.push(`Type: Static (files downloaded)`);
  parts.push(`Challenge files are extracted to: ${extractDir}`);
  parts.push(`Goal: Analyze the challenge files and find the flag.`);
  parts.push(`The flag format is HTB{...}`);
  parts.push(`Start by listing and examining the files in the extraction directory.`);
  return parts.join("\n");
}

function buildDynamicHint(challenge: HtbChallenge, host: string, port: number): string {
  const parts: string[] = [];
  parts.push(`HackTheBox Challenge: ${challenge.name}`);
  parts.push(`Category: ${challenge.category}, Difficulty: ${challenge.difficulty}`);
  if (challenge.description) {
    parts.push(`Description: ${challenge.description}`);
  }
  parts.push(`Type: Dynamic (live instance)`);
  parts.push(`Target: ${host}:${port}`);
  parts.push(`Goal: Exploit the running service and find the flag.`);
  parts.push(`The flag format is HTB{...}`);

  // Category-specific guidance
  if (challenge.category === "web") {
    parts.push(`This is a web challenge — start by browsing http://${host}:${port} and looking for common web vulnerabilities.`);
  } else if (challenge.category === "pwn") {
    parts.push(`This is a binary exploitation challenge — connect to ${host}:${port} and look for buffer overflows, format strings, etc.`);
  } else if (challenge.category === "crypto") {
    parts.push(`This is a cryptography challenge — the service at ${host}:${port} likely implements a crypto scheme to break.`);
  } else {
    parts.push(`Start by connecting to ${host}:${port} and probing the service.`);
  }

  return parts.join("\n");
}

/** Extract potential HTB flags from scan output. */
function extractFlags(text: string): string[] {
  const matches = text.match(/HTB\{[^}]+\}/gi);
  return [...new Set(matches ?? [])];
}

/** List files in a directory for the scan hint. */
function listExtractedFiles(dir: string): string[] {
  try {
    const output = execSync(`find "${dir}" -type f -maxdepth 3 2>/dev/null | head -30`, {
      timeout: 5000,
      encoding: "utf8",
    });
    return output.trim().split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

async function runChallengeOnce(challenge: HtbChallenge): Promise<HtbChallengeResult> {
  const start = Date.now();
  const isStatic = challenge.isStatic;
  let cleanupDir: string | undefined;

  if (!jsonOutput) {
    process.stdout.write(`    ${isStatic ? "downloading" : "spawning"} ${challenge.name}...`);
  }

  try {
    let hint: string;
    let target: string;
    let repoPath: string | undefined;

    if (isStatic) {
      // Static challenge: download ZIP and analyze files
      let extractDir: string;
      try {
        extractDir = await downloadStaticChallenge(challenge);
        cleanupDir = dirname(extractDir); // parent workdir for cleanup
      } catch (err) {
        if (!jsonOutput) process.stdout.write(` FAILED\n`);
        return {
          id: challenge.id,
          name: challenge.name,
          category: challenge.category,
          difficulty: challenge.difficulty,
          challengeType: "static",
          passed: false,
          flagSubmitted: false,
          findingsCount: 0,
          durationMs: Date.now() - start,
          error: `Download failed: ${err instanceof Error ? err.message : String(err)}`,
        };
      }

      const files = listExtractedFiles(extractDir);
      hint = buildStaticHint(challenge, extractDir);
      if (files.length > 0) {
        hint += `\n\nExtracted files:\n${files.map((f) => `  - ${f}`).join("\n")}`;
      }

      // Use a dummy target for static challenges — the agent works with local files
      target = "file://localhost";
      repoPath = extractDir;

      if (!jsonOutput) process.stdout.write(` ${files.length} files\n`);
    } else {
      // Dynamic challenge: spawn instance
      let connectionInfo: { host: string; port: number } | null;
      try {
        connectionInfo = await spawnDynamicChallenge(challenge);
      } catch (err) {
        if (!jsonOutput) process.stdout.write(` FAILED\n`);
        return {
          id: challenge.id,
          name: challenge.name,
          category: challenge.category,
          difficulty: challenge.difficulty,
          challengeType: "dynamic",
          passed: false,
          flagSubmitted: false,
          findingsCount: 0,
          durationMs: Date.now() - start,
          error: `Spawn failed: ${err instanceof Error ? err.message : String(err)}`,
        };
      }

      if (!connectionInfo) {
        if (!jsonOutput) process.stdout.write(` TIMEOUT\n`);
        return {
          id: challenge.id,
          name: challenge.name,
          category: challenge.category,
          difficulty: challenge.difficulty,
          challengeType: "dynamic",
          passed: false,
          flagSubmitted: false,
          findingsCount: 0,
          durationMs: Date.now() - start,
          error: "Spawn timeout — no connection info",
        };
      }

      const { host, port } = connectionInfo;
      hint = buildDynamicHint(challenge, host, port);

      // For web challenges, target is the HTTP URL; for others, use the host:port
      target = challenge.category === "web"
        ? `http://${host}:${port}`
        : `tcp://${host}:${port}`;

      if (!jsonOutput) process.stdout.write(` ${host}:${port}\n`);
    }

    const dbPath = join(tmpdir(), `pwnkit-htb-ch-${challenge.name.toLowerCase().replace(/\s+/g, "-")}-${Date.now()}.db`);
    const report = await agenticScan({
      config: {
        target,
        depth: "deep",
        format: "json",
        mode: "web",
        timeout: 300_000, // 5 min per challenge
        runtime: runtimeArg as RuntimeMode,
        verbose: false,
        ...(repoPath ? { repoPath } : {}),
      },
      dbPath,
      challengeHint: hint,
    });

    const findings = report.findings ?? [];
    const allText = JSON.stringify(report);

    // Try to extract and submit flags
    const candidateFlags = extractFlags(allText);
    let flagSubmitted = false;
    for (const flag of candidateFlags) {
      if (await submitChallengeFlag(challenge.id, flag, difficultyToNumber(challenge.difficulty))) {
        flagSubmitted = true;
        break;
      }
    }

    return {
      id: challenge.id,
      name: challenge.name,
      category: challenge.category,
      difficulty: challenge.difficulty,
      challengeType: isStatic ? "static" : "dynamic",
      attackTurns: report.benchmarkMeta?.attackTurns,
      estimatedCostUsd: report.benchmarkMeta?.estimatedCostUsd,
      passed: flagSubmitted || findings.length > 0,
      flagSubmitted,
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
      challengeType: isStatic ? "static" : "dynamic",
      passed: false,
      flagSubmitted: false,
      findingsCount: 0,
      durationMs: Date.now() - start,
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    // Cleanup
    if (!isStatic) {
      await stopDynamicChallenge(challenge);
    }
    if (cleanupDir) {
      try {
        rmSync(cleanupDir, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup
      }
    }
  }
}

async function runChallenge(challenge: HtbChallenge): Promise<HtbChallengeResult> {
  let result = await runChallengeOnce(challenge);
  for (let attempt = 2; attempt <= retries && !result.flagSubmitted && !result.error; attempt++) {
    if (!jsonOutput) {
      process.stdout.write(`  ... retry ${attempt}/${retries}\n`);
    }
    const next = await runChallengeOnce(challenge);
    result = chooseBetterResult(result, next);
    if (result.flagSubmitted) break;
  }
  return result;
}

// ── Reporting ──

function buildCategoryBreakdown(results: HtbChallengeResult[]): Record<string, { total: number; flags: number; passed: number }> {
  const breakdown: Record<string, { total: number; flags: number; passed: number }> = {};
  for (const r of results) {
    const cat = r.category;
    if (!breakdown[cat]) breakdown[cat] = { total: 0, flags: 0, passed: 0 };
    breakdown[cat].total++;
    if (r.flagSubmitted) breakdown[cat].flags++;
    if (r.passed) breakdown[cat].passed++;
  }
  return breakdown;
}

// ── Main ──

async function main() {
  if (!HTB_API_TOKEN && !dryRun) {
    console.error("Error: HTB_API_TOKEN environment variable is required.");
    console.error("Get an App Token from https://labs.hackthebox.com → Profile → Settings → App Tokens");
    process.exit(1);
  }

  let challenges: HtbChallenge[];

  if (dryRun && !HTB_API_TOKEN) {
    // For dry-run without a token, use a small static sample
    challenges = KNOWN_SAMPLE_CHALLENGES;
  } else {
    challenges = await fetchChallenges();
  }

  // Apply filters
  if (categoryFilter) {
    const cats = new Set(categoryFilter);
    challenges = challenges.filter((c) => cats.has(c.category.toLowerCase()));
  }
  if (difficultyFilter) {
    const diffs = new Set(difficultyFilter);
    challenges = challenges.filter((c) => diffs.has(c.difficulty.toLowerCase()));
  }
  if (challengeTypeFilter) {
    challenges = challenges.filter((c) =>
      challengeTypeFilter === "static" ? c.isStatic : !c.isStatic
    );
  }
  if (onlyIds) {
    const idSet = new Set(onlyIds);
    challenges = challenges.filter((c) => idSet.has(c.name.toLowerCase()));
  }

  // Sort by solves descending (easiest first) for best initial results
  challenges.sort((a, b) => b.solves - a.solves);

  if (startAt > 0) challenges = challenges.slice(startAt);
  challenges = challenges.slice(0, limit);

  if (!jsonOutput) {
    console.log("\x1b[36m\x1b[1m  pwnkit x HackTheBox Challenges benchmark\x1b[0m");
    console.log(`  challenges: ${challenges.length}  retries: ${retries}`);
    if (categoryFilter) console.log(`  category filter: ${categoryFilter.join(", ")}`);
    if (difficultyFilter) console.log(`  difficulty filter: ${difficultyFilter.join(", ")}`);
    if (challengeTypeFilter) console.log(`  type filter: ${challengeTypeFilter}`);
    console.log("");
  }

  if (dryRun) {
    for (const c of challenges) {
      const type = c.isStatic ? "static" : "dynamic";
      console.log(`  [${c.category.padEnd(10)}] [${c.difficulty.padEnd(6)}] [${type.padEnd(7)}] ${c.name}  (${c.solves} solves)`);
    }
    console.log(`\n  Total: ${challenges.length} challenges`);

    // Show category breakdown
    const cats = new Map<string, number>();
    for (const c of challenges) {
      cats.set(c.category, (cats.get(c.category) ?? 0) + 1);
    }
    console.log("\n  By category:");
    for (const [cat, count] of [...cats.entries()].sort((a, b) => b[1] - a[1])) {
      console.log(`    ${cat.padEnd(12)} ${count}`);
    }
    return;
  }

  const results: HtbChallengeResult[] = [];

  // Incremental persistence
  const incrementalDir = join(__dirname, "..", "results");
  mkdirSync(incrementalDir, { recursive: true });
  const incrementalPath = join(incrementalDir, "htb-challenges-incremental.jsonl");
  if (freshRun) {
    writeFileSync(incrementalPath, "");
  }

  for (const challenge of challenges) {
    if (!jsonOutput) {
      const type = challenge.isStatic ? "static" : "dynamic";
      console.log(`\x1b[1m  >> ${challenge.name}\x1b[0m  [${challenge.category}/${challenge.difficulty}/${type}]`);
    }

    const result = await runChallenge(challenge);
    results.push(result);

    try {
      appendFileSync(incrementalPath, JSON.stringify(result) + "\n");
    } catch (err) {
      console.error(`  [warn] could not append incremental result: ${err instanceof Error ? err.message : err}`);
    }

    if (!jsonOutput) {
      const icon = result.flagSubmitted ? "\x1b[32mFLAG\x1b[0m" : "\x1b[31mFAIL\x1b[0m";
      const time = `${(result.durationMs / 1000).toFixed(0)}s`;
      console.log(`  ${icon} ${challenge.name.slice(0, 45).padEnd(45)} ${result.findingsCount} findings  ${time}${result.error ? `  err: ${result.error.slice(0, 40)}` : ""}`);
    }
  }

  const passed = results.filter((r) => r.passed).length;
  const flagsSubmitted = results.filter((r) => r.flagSubmitted).length;
  const spawnFailures = results.filter((r) => r.error?.startsWith("Spawn") || r.error?.startsWith("Download")).length;
  const scanErrors = results.filter((r) => r.error && !r.error.startsWith("Spawn") && !r.error.startsWith("Download")).length;
  const started = challenges.length - spawnFailures;
  const totalAttackTurns = results.reduce((sum, r) => sum + (r.attackTurns ?? 0), 0);
  const totalEstimatedCostUsd = results.reduce((sum, r) => sum + (r.estimatedCostUsd ?? 0), 0);
  const categoryBreakdown = buildCategoryBreakdown(results);

  const report: HtbChallengeReport = {
    timestamp: new Date().toISOString(),
    runtime: runtimeArg,
    retries,
    challenges: challenges.length,
    started,
    passed,
    flagsSubmitted,
    totalAttackTurns,
    totalEstimatedCostUsd,
    spawnFailures,
    scanErrors,
    categoryBreakdown,
    results,
  };

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log("\n  ──────────────────────────────────────");
    console.log(`  Flags submitted: \x1b[1m${flagsSubmitted}/${challenges.length}\x1b[0m  (${(flagsSubmitted / Math.max(challenges.length, 1) * 100).toFixed(1)}%)`);
    console.log(`  Started:         \x1b[1m${started}/${challenges.length}\x1b[0m  (failures: ${spawnFailures})`);
    if (totalAttackTurns > 0) console.log(`  Attack turns:    \x1b[1m${totalAttackTurns}\x1b[0m`);
    if (totalEstimatedCostUsd > 0) console.log(`  Est. cost:       \x1b[1m$${totalEstimatedCostUsd.toFixed(2)}\x1b[0m`);
    console.log(`  Total time:      ${(results.reduce((a, r) => a + r.durationMs, 0) / 1000).toFixed(0)}s`);

    // Per-category breakdown
    console.log("\n  By category:");
    for (const [cat, data] of Object.entries(categoryBreakdown).sort((a, b) => b[1].total - a[1].total)) {
      console.log(`    ${cat.padEnd(12)} ${data.flags}/${data.total} flags  (${data.passed} passed)`);
    }

    // By difficulty
    const diffMap = new Map<string, { total: number; flags: number }>();
    for (const r of results) {
      const entry = diffMap.get(r.difficulty) ?? { total: 0, flags: 0 };
      entry.total++;
      if (r.flagSubmitted) entry.flags++;
      diffMap.set(r.difficulty, entry);
    }
    console.log("\n  By difficulty:");
    for (const [diff, data] of [...diffMap.entries()].sort((a, b) => a[1].total - b[1].total)) {
      console.log(`    ${diff.padEnd(12)} ${data.flags}/${data.total}`);
    }

    // By type
    const staticResults = results.filter((r) => r.challengeType === "static");
    const dynamicResults = results.filter((r) => r.challengeType === "dynamic");
    console.log("\n  By type:");
    console.log(`    static       ${staticResults.filter((r) => r.flagSubmitted).length}/${staticResults.length}`);
    console.log(`    dynamic      ${dynamicResults.filter((r) => r.flagSubmitted).length}/${dynamicResults.length}`);
    console.log("");
  }

  // Save results — merge with existing
  const resultsDir = join(__dirname, "..", "results");
  mkdirSync(resultsDir, { recursive: true });
  const latestPath = join(resultsDir, "htb-challenges-latest.json");

  if (!freshRun && existsSync(latestPath)) {
    try {
      const existing: HtbChallengeReport = JSON.parse(readFileSync(latestPath, "utf8"));
      const existingById = new Map(existing.results.map((r) => [r.id, r]));
      for (const r of report.results) {
        existingById.set(r.id, r);
      }
      const mergedResults = [...existingById.values()].sort((a, b) => a.name.localeCompare(b.name));
      const mergedSpawnFails = mergedResults.filter((r) => r.error?.startsWith("Spawn") || r.error?.startsWith("Download")).length;
      const mergedReport: HtbChallengeReport = {
        ...report,
        timestamp: new Date().toISOString(),
        challenges: mergedResults.length,
        started: mergedResults.length - mergedSpawnFails,
        passed: mergedResults.filter((r) => r.passed).length,
        flagsSubmitted: mergedResults.filter((r) => r.flagSubmitted).length,
        spawnFailures: mergedSpawnFails,
        scanErrors: mergedResults.filter((r) => r.error && !r.error.startsWith("Spawn") && !r.error.startsWith("Download")).length,
        categoryBreakdown: buildCategoryBreakdown(mergedResults),
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

// ── Known sample challenges (for --dry-run without API token) ──
const KNOWN_SAMPLE_CHALLENGES: HtbChallenge[] = [
  // Web — easiest first
  { id: 1, name: "Templated", category: "web", difficulty: "Easy", isStatic: false, solves: 25000, description: "Can you exploit this simple web app?" },
  { id: 2, name: "Trapped Source", category: "web", difficulty: "Easy", isStatic: false, solves: 22000, description: "Inspect the source." },
  { id: 3, name: "Gunhead", category: "web", difficulty: "Easy", isStatic: false, solves: 18000, description: "Command injection in a web app." },
  { id: 4, name: "Drobots", category: "web", difficulty: "Easy", isStatic: false, solves: 16000, description: "SQL injection challenge." },
  { id: 5, name: "Neonify", category: "web", difficulty: "Easy", isStatic: false, solves: 14000, description: "SSTI in a neon text generator." },
  { id: 6, name: "Looking Glass", category: "web", difficulty: "Easy", isStatic: false, solves: 12000, description: "Ping tool with OS command injection." },
  { id: 7, name: "Toxic", category: "web", difficulty: "Easy", isStatic: false, solves: 11000, description: "PHP deserialization vulnerability." },
  // Crypto
  { id: 100, name: "Ancient Encodings", category: "crypto", difficulty: "Easy", isStatic: true, solves: 20000, description: "Decode the ancient text." },
  { id: 101, name: "Primary Knowledge", category: "crypto", difficulty: "Easy", isStatic: true, solves: 15000, description: "RSA with weak primes." },
  { id: 102, name: "BabyEncryption", category: "crypto", difficulty: "Easy", isStatic: true, solves: 14000, description: "Simple custom encryption." },
  // Forensics
  { id: 200, name: "Illumination", category: "forensics", difficulty: "Easy", isStatic: true, solves: 18000, description: "Git forensics challenge." },
  { id: 201, name: "MarketDump", category: "forensics", difficulty: "Easy", isStatic: true, solves: 15000, description: "PCAP analysis." },
  // Reversing
  { id: 300, name: "Behind the Scenes", category: "reversing", difficulty: "Easy", isStatic: true, solves: 17000, description: "Simple reversing challenge." },
  // Misc
  { id: 400, name: "Compressor", category: "misc", difficulty: "Easy", isStatic: false, solves: 16000, description: "Interactive misc challenge." },
  // Pwn
  { id: 500, name: "Leet Test", category: "pwn", difficulty: "Easy", isStatic: true, solves: 10000, description: "Basic buffer overflow." },
];

main()
  .then(() => {
    process.exit(0);
  })
  .catch((err) => {
    console.error("HTB Challenges benchmark failed:", err);
    process.exit(1);
  });
