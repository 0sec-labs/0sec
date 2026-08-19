#!/usr/bin/env node

/**
 * picoCTF Benchmark Runner
 *
 * Runs pwnkit against a curated subset of picoCTF challenges. Challenges
 * span web exploitation, cryptography, forensics, binary exploitation, and
 * reverse engineering.
 *
 * Prerequisites:
 * - Challenge manifest: packages/benchmark/src/challenges/picoctf-manifest.json
 *   (ships with the repo — a curated set of ~50 challenges with URLs/metadata)
 * - For web challenges: no special setup (targets are hosted at play.picoctf.org)
 * - For non-web challenges: the agent uses bash to download files, analyze, and solve
 *
 * Usage:
 *   tsx src/picoctf-runner.ts                    # run all manifest challenges
 *   tsx src/picoctf-runner.ts --limit 10         # first 10 only
 *   tsx src/picoctf-runner.ts --category web     # filter by category
 *   tsx src/picoctf-runner.ts --only obedient-cat,mod-26
 *   tsx src/picoctf-runner.ts --start 5
 *   tsx src/picoctf-runner.ts --retries 3
 *   tsx src/picoctf-runner.ts --save-findings
 *   tsx src/picoctf-runner.ts --json
 *   tsx src/picoctf-runner.ts --dry-run
 *
 * picoCTF platform: https://play.picoctf.org/
 * Flag format: picoCTF{...}
 */

import { readFileSync, existsSync, writeFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { agenticScan } from "@pwnkit/core";
import { tmpdir } from "node:os";
import type { RuntimeMode } from "@pwnkit/shared";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── CLI Args ──
const args = process.argv.slice(2);
const limit = args.includes("--limit") ? parseInt(args[args.indexOf("--limit") + 1]) : Infinity;
const categoryFilter = args.includes("--category") ? args[args.indexOf("--category") + 1] : undefined;
const difficultyFilter = args.includes("--difficulty") ? args[args.indexOf("--difficulty") + 1] : undefined;
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
const manifestPath = args.includes("--manifest")
  ? args[args.indexOf("--manifest") + 1]
  : join(__dirname, "challenges", "picoctf-manifest.json");

// ── Types ──
interface PicoChallenge {
  id: string;
  name: string;
  category: string;
  difficulty: string;
  points: number;
  /** URL for web challenges or download URL for file-based challenges */
  url: string;
  /** Optional direct download URLs for challenge files */
  files?: string[];
  /** Brief description / hint */
  description: string;
  /** Year / competition instance (e.g., "2024", "2023", "picoGym") */
  event: string;
}

interface PicoResult {
  id: string;
  name: string;
  category: string;
  difficulty: string;
  points: number;
  event: string;
  attackTurns?: number;
  estimatedCostUsd?: number;
  passed: boolean;
  flagFound: boolean;
  findingsCount: number;
  durationMs: number;
  error?: string;
  findings?: unknown[];
}

interface PicoReport {
  timestamp: string;
  runtime: string;
  retries: number;
  challenges: number;
  started: number;
  passed: number;
  flags: number;
  totalAttackTurns: number;
  totalEstimatedCostUsd: number;
  scanErrors: number;
  results: PicoResult[];
}

function chooseBetterResult(a: PicoResult, b: PicoResult): PicoResult {
  if (b.flagFound && !a.flagFound) return b;
  if (a.flagFound && !b.flagFound) return a;
  if (b.passed && !a.passed) return b;
  if (a.passed && !b.passed) return a;
  if (!!a.error !== !!b.error) return a.error ? b : a;
  if (b.findingsCount !== a.findingsCount) return b.findingsCount > a.findingsCount ? b : a;
  return b.durationMs < a.durationMs ? b : a;
}

// ── Load Challenges ──
function loadChallenges(): PicoChallenge[] {
  if (!existsSync(manifestPath)) {
    console.error(`picoCTF manifest not found at ${manifestPath}`);
    console.error("The manifest ships with the repo at packages/benchmark/src/challenges/picoctf-manifest.json");
    process.exit(1);
  }

  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const challenges: PicoChallenge[] = manifest.challenges ?? manifest;

  if (!Array.isArray(challenges) || challenges.length === 0) {
    console.error("picoCTF manifest is empty or malformed.");
    process.exit(1);
  }

  return challenges;
}

// ── Build Scan Config ──

/** Determine if this is a web challenge that has a live target URL. */
function isWebChallenge(challenge: PicoChallenge): boolean {
  return (
    challenge.category === "web" ||
    challenge.category === "Web Exploitation" ||
    (challenge.url?.startsWith("http") && !challenge.url?.includes("/static/"))
  );
}

function buildTarget(challenge: PicoChallenge): string {
  // For web challenges, the URL is the target
  if (isWebChallenge(challenge) && challenge.url) {
    return challenge.url;
  }
  // For non-web challenges, we give the agent a placeholder — the real work
  // happens via the challengeHint which tells it to download and analyze files
  return challenge.url || "https://play.picoctf.org";
}

function buildHint(challenge: PicoChallenge): string {
  const parts: string[] = [];
  parts.push(`picoCTF challenge: ${challenge.name}`);
  parts.push(`Category: ${challenge.category}`);
  parts.push(`Difficulty: ${challenge.difficulty} (${challenge.points} points)`);
  parts.push(`Event: ${challenge.event}`);

  if (challenge.description) {
    parts.push(`Description: ${challenge.description}`);
  }

  if (isWebChallenge(challenge)) {
    parts.push(`This is a web challenge. The target URL is: ${challenge.url}`);
    parts.push(`Look for vulnerabilities like SQLi, XSS, SSTI, path traversal, IDOR, etc.`);
  } else {
    parts.push(`This is a ${challenge.category} challenge. Use bash tools to download files, analyze them, and extract the flag.`);
    if (challenge.files && challenge.files.length > 0) {
      parts.push(`Challenge files to download:`);
      for (const f of challenge.files) {
        parts.push(`  - ${f}`);
      }
    }
  }

  parts.push(`Flag format: picoCTF{...}`);
  return parts.join("\n");
}

// ── Check for flag in output ──
const PICO_FLAG_RE = /picoCTF\{[^}]+\}/i;

function containsFlag(text: string): boolean {
  return PICO_FLAG_RE.test(text);
}

// ── Run Single Challenge ──
async function runChallengeOnce(challenge: PicoChallenge): Promise<PicoResult> {
  const start = Date.now();
  const target = buildTarget(challenge);
  const hint = buildHint(challenge);

  try {
    const dbPath = join(tmpdir(), `pwnkit-picoctf-${challenge.id}-${Date.now()}.db`);
    const report = await agenticScan({
      config: {
        target,
        depth: "deep",
        format: "json",
        mode: "web",
        timeout: 180_000, // 3 min per challenge
        runtime: runtimeArg as RuntimeMode,
        verbose: false,
      },
      dbPath,
      challengeHint: hint,
    });

    const findings = report.findings ?? [];
    const allText = JSON.stringify(report);
    const flagFound = containsFlag(allText);

    return {
      id: challenge.id,
      name: challenge.name,
      category: challenge.category,
      difficulty: challenge.difficulty,
      points: challenge.points,
      event: challenge.event,
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
      points: challenge.points,
      event: challenge.event,
      passed: false,
      flagFound: false,
      findingsCount: 0,
      durationMs: Date.now() - start,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

async function runChallenge(challenge: PicoChallenge): Promise<PicoResult> {
  let result = await runChallengeOnce(challenge);
  for (let attempt = 2; attempt <= retries && !result.flagFound && !result.error; attempt++) {
    if (!jsonOutput) {
      process.stdout.write(`  ... retry ${attempt}/${retries}\n`);
    }
    const next = await runChallengeOnce(challenge);
    result = chooseBetterResult(result, next);
    if (result.flagFound) break;
  }
  return result;
}

// ── Main ──
async function main() {
  let challenges = loadChallenges();

  if (categoryFilter) {
    const catLower = categoryFilter.toLowerCase();
    // Short aliases so `--category web` matches "Web Exploitation", etc.
    const CATEGORY_ALIASES: Record<string, string> = {
      web: "web exploitation",
      crypto: "cryptography",
      forensics: "forensics",
      pwn: "binary exploitation",
      binary: "binary exploitation",
      re: "reverse engineering",
      reverse: "reverse engineering",
      general: "general skills",
      misc: "general skills",
    };
    const resolved = CATEGORY_ALIASES[catLower] ?? catLower;
    challenges = challenges.filter((c) => c.category.toLowerCase() === resolved);
  }
  if (difficultyFilter) {
    const difLower = difficultyFilter.toLowerCase();
    challenges = challenges.filter((c) => c.difficulty.toLowerCase() === difLower);
  }
  if (onlyIds) {
    const idSet = new Set(onlyIds);
    challenges = challenges.filter(
      (c) => idSet.has(c.id.toLowerCase()) || idSet.has(c.name.toLowerCase().replace(/\s+/g, "-"))
    );
  }
  if (startAt > 0) challenges = challenges.slice(startAt);
  challenges = challenges.slice(0, limit);

  if (!jsonOutput) {
    console.log("\x1b[36m\x1b[1m  pwnkit x picoCTF benchmark\x1b[0m");
    console.log(`  challenges: ${challenges.length}  retries: ${retries}`);
    console.log("");
  }

  if (dryRun) {
    for (const c of challenges) {
      console.log(`  [${c.category}] [${c.difficulty}] [${c.points}pts] ${c.name}  (${c.event})`);
    }
    console.log(`\n  Total: ${challenges.length} challenges`);
    return;
  }

  const results: PicoResult[] = [];

  // Incremental persistence
  const incrementalDir = join(__dirname, "..", "results");
  mkdirSync(incrementalDir, { recursive: true });
  const incrementalPath = join(incrementalDir, "picoctf-incremental.jsonl");
  if (freshRun) {
    writeFileSync(incrementalPath, "");
  }

  for (const challenge of challenges) {
    if (!jsonOutput) {
      console.log(`\x1b[1m  >> ${challenge.name}\x1b[0m  [${challenge.category}/${challenge.difficulty}/${challenge.points}pts]`);
    }

    const result = await runChallenge(challenge);
    results.push(result);

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
  }

  const passed = results.filter((r) => r.passed).length;
  const flags = results.filter((r) => r.flagFound).length;
  const scanErrors = results.filter((r) => r.error).length;
  const started = challenges.length;
  const totalAttackTurns = results.reduce((sum, r) => sum + (r.attackTurns ?? 0), 0);
  const totalEstimatedCostUsd = results.reduce((sum, r) => sum + (r.estimatedCostUsd ?? 0), 0);

  const report: PicoReport = {
    timestamp: new Date().toISOString(),
    runtime: runtimeArg,
    retries,
    challenges: challenges.length,
    started,
    passed,
    flags,
    totalAttackTurns,
    totalEstimatedCostUsd,
    scanErrors,
    results,
  };

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log("\n  ──────────────────────────────────────");
    console.log(`  Flag extraction: \x1b[1m${flags}/${challenges.length}\x1b[0m  (${(flags / Math.max(challenges.length, 1) * 100).toFixed(1)}%)`);
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
      console.log(`    ${cat.padEnd(20)} ${data.flags}/${data.total}`);
    }
    console.log("");
  }

  // Save results — merge with existing
  const resultsDir = join(__dirname, "..", "results");
  mkdirSync(resultsDir, { recursive: true });
  const latestPath = join(resultsDir, "picoctf-latest.json");

  if (!freshRun && existsSync(latestPath)) {
    try {
      const existing: PicoReport = JSON.parse(readFileSync(latestPath, "utf8"));
      const existingById = new Map(existing.results.map((r) => [r.id, r]));
      for (const r of report.results) {
        existingById.set(r.id, r);
      }
      const mergedResults = [...existingById.values()].sort((a, b) => a.id.localeCompare(b.id));
      const mergedReport: PicoReport = {
        ...report,
        timestamp: new Date().toISOString(),
        challenges: mergedResults.length,
        started: mergedResults.length,
        passed: mergedResults.filter((r) => r.passed).length,
        flags: mergedResults.filter((r) => r.flagFound).length,
        scanErrors: mergedResults.filter((r) => r.error).length,
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
    console.error("picoCTF benchmark failed:", err);
    process.exit(1);
  });
