#!/usr/bin/env node

import express from "express";
import type { Server } from "http";
import type { AddressInfo } from "net";
import { getAllChallenges, type Challenge } from "./challenges/index.js";
import { scan, agenticScan } from "@pwnkit/core";
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── CLI Args ──

const args = process.argv.slice(2);
const depth = args.includes("--depth") ? args[args.indexOf("--depth") + 1] : "quick";
const filterCategory = args.includes("--category") ? args[args.indexOf("--category") + 1] : undefined;
const filterDifficulty = args.includes("--difficulty") ? parseInt(args[args.indexOf("--difficulty") + 1]) : undefined;
const jsonOutput = args.includes("--json");
const useAgentic = args.includes("--agentic");
const runtimeArg = args.includes("--runtime") ? args[args.indexOf("--runtime") + 1] : "auto";

// ── Types ──

interface ChallengeResult {
  id: string;
  name: string;
  category: string;
  difficulty: number;
  passed: boolean;
  flagFound: boolean;
  findingsCount: number;
  matchedCategories: string[];
  expectedCategories: string[];
  durationMs: number;
  error?: string;
}

interface BenchmarkReport {
  timestamp: string;
  depth: string;
  runtime: string;
  totalChallenges: number;
  passed: number;
  failed: number;
  detectionRate: number;
  flagExtractionRate: number;
  totalDurationMs: number;
  results: ChallengeResult[];
  categoryBreakdown: Record<string, { total: number; passed: number; rate: number }>;
  difficultyBreakdown: Record<string, { total: number; passed: number; rate: number }>;
}

// ── Runner ──

async function runBenchmark(): Promise<BenchmarkReport> {
  const allChallenges = getAllChallenges();

  // Apply filters
  let challenges = allChallenges;
  if (filterCategory) {
    challenges = challenges.filter((c) => c.category === filterCategory);
  }
  if (filterDifficulty) {
    challenges = challenges.filter((c) => c.difficulty === filterDifficulty);
  }

  if (challenges.length === 0) {
    console.error("No challenges match the filters.");
    process.exit(1);
  }

  // Start challenge server
  const app = express();
  app.use(express.json());

  for (const challenge of challenges) {
    challenge.mount(app);
  }

  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const port = (server.address() as AddressInfo).port;

  console.log(`\n  Benchmark server on port ${port} — ${challenges.length} challenges loaded\n`);

  const results: ChallengeResult[] = [];
  const startTime = Date.now();

  for (const challenge of challenges) {
    const result = await runChallenge(challenge, port);
    results.push(result);

    const icon = result.passed ? "\x1b[32m✓\x1b[0m" : result.flagFound ? "\x1b[33m~\x1b[0m" : "\x1b[31m✗\x1b[0m";
    const diffLabel = ["", "easy", "med", "hard"][challenge.difficulty];
    if (!jsonOutput) {
      console.log(`  ${icon} [${diffLabel}] ${challenge.name.padEnd(40)} ${result.findingsCount} findings  ${result.durationMs}ms${result.flagFound ? "  🏁 flag" : ""}`);
    }
  }

  server.close();

  // Compute metrics
  const passed = results.filter((r) => r.passed).length;
  const flagsFound = results.filter((r) => r.flagFound).length;

  const categoryBreakdown: Record<string, { total: number; passed: number; rate: number }> = {};
  for (const r of results) {
    const cat = categoryBreakdown[r.category] ?? { total: 0, passed: 0, rate: 0 };
    cat.total++;
    if (r.passed) cat.passed++;
    cat.rate = cat.passed / cat.total;
    categoryBreakdown[r.category] = cat;
  }

  const difficultyBreakdown: Record<string, { total: number; passed: number; rate: number }> = {};
  for (const r of results) {
    const key = ["", "easy", "medium", "hard"][r.difficulty];
    const diff = difficultyBreakdown[key] ?? { total: 0, passed: 0, rate: 0 };
    diff.total++;
    if (r.passed) diff.passed++;
    diff.rate = diff.passed / diff.total;
    difficultyBreakdown[key] = diff;
  }

  const report: BenchmarkReport = {
    timestamp: new Date().toISOString(),
    depth,
    runtime: useAgentic ? runtimeArg : "baseline",
    totalChallenges: challenges.length,
    passed,
    failed: challenges.length - passed,
    detectionRate: passed / challenges.length,
    flagExtractionRate: flagsFound / challenges.length,
    totalDurationMs: Date.now() - startTime,
    results,
    categoryBreakdown,
    difficultyBreakdown,
  };

  return report;
}

async function runChallenge(challenge: Challenge, port: number): Promise<ChallengeResult> {
  const start = Date.now();

  // Determine target URL based on challenge type
  const isMcp = challenge.id.startsWith("mcp-");
  const isWeb = challenge.id.startsWith("web-");
  const target = isMcp
    ? `mcp://localhost:${port}/challenges/${challenge.id}/mcp`
    : isWeb
      ? `http://localhost:${port}/challenges/${challenge.id}/`
      : `http://localhost:${port}/challenges/${challenge.id}/v1/chat/completions`;

  const mode = isMcp ? "mcp" : isWeb ? "web" : "deep";

  try {
    let report: any;

    if (useAgentic) {
      // Full agentic pipeline with AI analysis
      const dbPath = join(tmpdir(), `pwnkit-bench-${challenge.id}-${Date.now()}.db`);
      report = await agenticScan({
        config: {
          target,
          depth: depth as any,
          format: "json",
          mode: mode as any,
          timeout: 30_000,
          runtime: runtimeArg as any,
        },
        dbPath,
      });
    } else {
      // Baseline scanner (no AI)
      report = await scan({
        target,
        depth: depth as any,
        format: "json",
        mode: mode as any,
        timeout: 10_000,
      });
    }

    const findings = report.findings ?? [];
    const allText = JSON.stringify(report).toLowerCase();
    const flagFound = allText.includes(challenge.flag.toLowerCase());

    const matchedCategories = [
      ...new Set(findings.map((f: any) => f.category)),
    ] as string[];

    const categoryHit = challenge.expectedCategories.some((ec) =>
      matchedCategories.includes(ec),
    );

    return {
      id: challenge.id,
      name: challenge.name,
      category: challenge.category,
      difficulty: challenge.difficulty,
      passed: findings.length > 0 || categoryHit,
      flagFound,
      findingsCount: findings.length,
      matchedCategories,
      expectedCategories: challenge.expectedCategories,
      durationMs: Date.now() - start,
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
      matchedCategories: [],
      expectedCategories: challenge.expectedCategories,
      durationMs: Date.now() - start,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

// ── Main ──

async function main() {
  if (!jsonOutput) {
    console.log("\x1b[31m\x1b[1m  pwnkit benchmark\x1b[0m");
    console.log(`  mode: ${useAgentic ? "agentic" : "baseline"}  runtime: ${useAgentic ? runtimeArg : "none"}  depth: ${depth}  challenges: ${getAllChallenges().length}`);
  }

  // In baseline mode, clear API keys for deterministic results
  const savedKeys: Record<string, string | undefined> = {};
  if (!useAgentic) {
    for (const key of ["OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "AZURE_OPENAI_API_KEY", "OPENAI_API_KEY"]) {
      savedKeys[key] = process.env[key];
      process.env[key] = "";
    }
  }

  try {
    const report = await runBenchmark();

    if (jsonOutput) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log("\n  ──────────────────────────────────────");
      console.log(`  Detection rate:    \x1b[1m${(report.detectionRate * 100).toFixed(1)}%\x1b[0m  (${report.passed}/${report.totalChallenges})`);
      console.log(`  Flag extraction:   \x1b[1m${(report.flagExtractionRate * 100).toFixed(1)}%\x1b[0m`);
      console.log(`  Total time:        ${(report.totalDurationMs / 1000).toFixed(1)}s`);
      console.log("\n  By difficulty:");
      for (const [level, data] of Object.entries(report.difficultyBreakdown)) {
        console.log(`    ${level.padEnd(8)} ${data.passed}/${data.total}  (${(data.rate * 100).toFixed(0)}%)`);
      }
      console.log("\n  By category:");
      for (const [cat, data] of Object.entries(report.categoryBreakdown)) {
        const bar = "\x1b[32m" + "█".repeat(Math.round(data.rate * 10)) + "\x1b[0m" + "░".repeat(10 - Math.round(data.rate * 10));
        console.log(`    ${cat.padEnd(28)} ${bar} ${data.passed}/${data.total}`);
      }
      console.log("");
    }

    // Save results
    const resultsDir = join(__dirname, "..", "results");
    mkdirSync(resultsDir, { recursive: true });
    writeFileSync(join(resultsDir, "latest.json"), JSON.stringify(report, null, 2));
  } finally {
    // Restore keys if we cleared them
    if (!useAgentic) {
      for (const [key, val] of Object.entries(savedKeys)) {
        if (val === undefined) delete process.env[key];
        else process.env[key] = val;
      }
    }
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("Benchmark failed:", err);
    process.exit(1);
  });
