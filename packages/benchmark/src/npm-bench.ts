#!/usr/bin/env node

/**
 * pwnkit npm audit benchmark — issue #21
 *
 * Ground-truth test suite for npm package security scanning.
 * 81 cases: 27 known-malicious, 27 known-CVE, 27 known-safe.
 *
 * Each case below is verified against npm advisories, GitHub Security
 * Advisories, NVD, Socket.dev, ReversingLabs, or Phylum reports.
 *
 * Usage:
 *   tsx src/npm-bench.ts
 *   tsx src/npm-bench.ts --json
 *   tsx src/npm-bench.ts --depth deep
 *   tsx src/npm-bench.ts --repeat 3
 */

import { writeFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { packageAudit } from "@pwnkit/core";
import type { ScanDepth, RuntimeMode } from "@pwnkit/shared";
import { computeNpmBenchMetrics } from "./npm-bench-metrics.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── CLI Args ──

const args = process.argv.slice(2);
const depth = args.includes("--depth") ? args[args.indexOf("--depth") + 1] : "quick";
const jsonOutput = args.includes("--json");
const runtimeArg = args.includes("--runtime") ? args[args.indexOf("--runtime") + 1] : "api";
const repeatArg = args.includes("--repeat") ? args[args.indexOf("--repeat") + 1] : "1";
const repeat = parseRepeat(repeatArg);

function parseRepeat(raw: string | undefined): number {
  const parsed = Number(raw ?? "1");
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`--repeat must be a positive integer (got ${raw ?? ""})`);
  }
  return parsed;
}

// ── Ground Truth ──

type Verdict = "malicious" | "vulnerable" | "safe";

interface TestCase {
  /** npm package specifier (name or name@version) */
  pkg: string;
  verdict: Verdict;
  /** Short description of why this is in the ground truth set */
  reason: string;
}

const TEST_CASES: TestCase[] = [
  // ── Known malicious (should be flagged) ──
  // Original 10 (do not remove — preserve baseline comparability)
  { pkg: "event-stream",   verdict: "malicious", reason: "supply-chain attack — flatmap-stream dependency" },
  { pkg: "ua-parser-js",   verdict: "malicious", reason: "compromised version shipped crypto-miner" },
  { pkg: "colors",         verdict: "malicious", reason: "maintainer sabotaged with infinite loop (v1.4.1+)" },
  { pkg: "faker",          verdict: "malicious", reason: "maintainer sabotaged, replaced with ENDGAME" },
  { pkg: "node-ipc",       verdict: "malicious", reason: "protestware / peacenotwar geo-targeted wiper" },
  { pkg: "coa",            verdict: "malicious", reason: "hijacked — malicious preinstall script" },
  { pkg: "rc",             verdict: "malicious", reason: "hijacked — malicious preinstall script" },
  { pkg: "eslint-scope",   verdict: "malicious", reason: "credential-theft via npm token exfiltration" },
  { pkg: "crossenv",       verdict: "malicious", reason: "typosquat of cross-env — data exfiltration" },
  { pkg: "loadsh",         verdict: "malicious", reason: "typosquat of lodash" },
  // Expansion (verified against npm advisories / GHSA / Socket / ReversingLabs / Phylum)
  { pkg: "flatmap-stream",        verdict: "malicious", reason: "the actual malicious payload behind event-stream (GHSA-mh6f-8j2x-4483)" },
  { pkg: "electron-native-notify",verdict: "malicious", reason: "Komodo wallet credential stealer (GHSA-mc3j-455x-fjhj)" },
  { pkg: "bb-builder",            verdict: "malicious", reason: "credential exfiltration typosquat (GHSA-7h2p-3mh4-fj7g)" },
  { pkg: "bigchaindb-driver",     verdict: "malicious", reason: "compromised release contained malicious post-install (Snyk SNYK-JS-BIGCHAINDB)" },
  { pkg: "fallguys",              verdict: "malicious", reason: "discord token + credit-card stealer (GHSA-mh3m-62v7-68xc)" },
  { pkg: "discord-selfbot-v14",   verdict: "malicious", reason: "discord token grabber, removed by npm (Socket.dev report)" },
  { pkg: "twilio-npm",            verdict: "malicious", reason: "typosquat of twilio with reverse shell (GHSA-c2gm-cwxv-q4wx)" },
  { pkg: "ffmepg",                verdict: "malicious", reason: "typosquat of ffmpeg, payload exfiltrates env vars (GHSA-rjmj-fvf6-q9xc)" },
  { pkg: "discord.dll",           verdict: "malicious", reason: "discord token + browser data stealer (GHSA-39q7-7r5w-3pmm)" },
  { pkg: "nodejs_net_server",     verdict: "malicious", reason: "stealer + remote shell, flagged by ReversingLabs 2023" },
  { pkg: "noblox.js-proxy",       verdict: "malicious", reason: "typosquat of noblox.js — data exfiltration (GHSA-7w4q-46j2-w278)" },
  { pkg: "okhsa",                 verdict: "malicious", reason: "executes calc.exe payload (GHSA-q9w9-6hcc-xqqw)" },
  { pkg: "node-fabric",           verdict: "malicious", reason: "Phylum-reported infostealer / typosquat of fabric" },
  { pkg: "ngfm",                  verdict: "malicious", reason: "preinstall data exfil, npm-flagged 2023" },
  { pkg: "circle.js",             verdict: "malicious", reason: "Socket.dev-reported infostealer 2024" },
  { pkg: "rocketrefer",           verdict: "malicious", reason: "Phylum-reported credential stealer 2024" },
  { pkg: "lodahs",                verdict: "malicious", reason: "typosquat of lodash, miner payload (GHSA-cph5-m8f7-6c5x)" },

  // ── Known CVE packages (should report vulnerabilities) ──
  // Original 10
  { pkg: "lodash@4.17.20",     verdict: "vulnerable", reason: "prototype pollution CVE-2021-23337" },
  { pkg: "minimist@1.2.5",     verdict: "vulnerable", reason: "prototype pollution CVE-2021-44906" },
  { pkg: "node-forge@0.9.0",   verdict: "vulnerable", reason: "multiple CVEs in older forge" },
  { pkg: "express@4.17.1",     verdict: "vulnerable", reason: "path traversal in serve-static dep" },
  { pkg: "axios@0.21.0",       verdict: "vulnerable", reason: "SSRF CVE-2021-3749" },
  { pkg: "tar@4.4.12",         verdict: "vulnerable", reason: "arbitrary file overwrite CVE-2021-32803" },
  { pkg: "glob-parent@5.1.0",  verdict: "vulnerable", reason: "ReDoS CVE-2021-35065" },
  { pkg: "json5@2.2.1",        verdict: "vulnerable", reason: "prototype pollution CVE-2022-46175" },
  { pkg: "qs@6.5.2",           verdict: "vulnerable", reason: "prototype pollution CVE-2022-24999" },
  { pkg: "semver@7.3.7",       verdict: "vulnerable", reason: "ReDoS CVE-2022-25883" },
  // Expansion (verified against NVD / GHSA)
  { pkg: "lodash@4.17.10",     verdict: "vulnerable", reason: "prototype pollution CVE-2019-10744" },
  { pkg: "lodash@4.17.4",      verdict: "vulnerable", reason: "prototype pollution CVE-2018-3721" },
  { pkg: "minimist@0.0.8",     verdict: "vulnerable", reason: "prototype pollution CVE-2020-7598" },
  { pkg: "node-fetch@2.6.6",   verdict: "vulnerable", reason: "exposure of sensitive info CVE-2022-0235" },
  { pkg: "axios@0.19.0",       verdict: "vulnerable", reason: "denial of service CVE-2020-28168 / regression CVE-2019-10742" },
  { pkg: "tar@6.1.8",          verdict: "vulnerable", reason: "arbitrary file creation/overwrite CVE-2021-37701" },
  { pkg: "glob-parent@5.1.1",  verdict: "vulnerable", reason: "ReDoS CVE-2020-28469" },
  { pkg: "nth-check@1.0.2",    verdict: "vulnerable", reason: "ReDoS CVE-2021-3803" },
  { pkg: "json5@1.0.1",        verdict: "vulnerable", reason: "prototype pollution CVE-2022-46175" },
  { pkg: "ansi-regex@3.0.0",   verdict: "vulnerable", reason: "ReDoS CVE-2021-3807" },
  { pkg: "shell-quote@1.7.2",  verdict: "vulnerable", reason: "command injection CVE-2021-42740" },
  { pkg: "y18n@4.0.0",         verdict: "vulnerable", reason: "prototype pollution CVE-2020-7774" },
  { pkg: "ws@7.4.5",           verdict: "vulnerable", reason: "ReDoS CVE-2021-32640" },
  { pkg: "marked@2.0.0",       verdict: "vulnerable", reason: "ReDoS CVE-2022-21680 / CVE-2022-21681" },
  { pkg: "follow-redirects@1.14.7", verdict: "vulnerable", reason: "exposure of sensitive info CVE-2022-0155" },
  { pkg: "http-cache-semantics@4.1.0", verdict: "vulnerable", reason: "ReDoS CVE-2022-25881" },
  { pkg: "decode-uri-component@0.2.0", verdict: "vulnerable", reason: "DoS CVE-2022-38900" },

  // ── Safe packages (should produce 0 findings) ──
  // Original 10
  { pkg: "express@latest",     verdict: "safe", reason: "widely-used, patched" },
  { pkg: "react@latest",       verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "typescript@latest",  verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "zod@latest",         verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "drizzle-orm@latest", verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "vitest@latest",      verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "esbuild@latest",     verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "chalk@latest",       verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "commander@latest",   verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "dotenv@latest",      verdict: "safe", reason: "well-maintained, no known issues" },
  // Expansion — top-50 npm packages by downloads, current versions
  { pkg: "react-dom@latest",   verdict: "safe", reason: "top-10 npm download, well-maintained" },
  { pkg: "vue@latest",         verdict: "safe", reason: "top framework, well-maintained" },
  { pkg: "date-fns@latest",    verdict: "safe", reason: "top utility, well-maintained" },
  { pkg: "vite@latest",        verdict: "safe", reason: "top dev tool, well-maintained" },
  { pkg: "webpack@latest",     verdict: "safe", reason: "top bundler, well-maintained" },
  { pkg: "eslint@latest",      verdict: "safe", reason: "top linter, well-maintained" },
  { pkg: "prettier@latest",    verdict: "safe", reason: "top formatter, well-maintained" },
  { pkg: "tslib@latest",       verdict: "safe", reason: "TypeScript runtime helpers, top-10 dl" },
  { pkg: "@types/node@latest", verdict: "safe", reason: "TypeScript type definitions, top dl" },
  { pkg: "rollup@latest",      verdict: "safe", reason: "top bundler, well-maintained" },
  { pkg: "rxjs@latest",        verdict: "safe", reason: "top reactive lib, well-maintained" },
  { pkg: "fastify@latest",     verdict: "safe", reason: "top server framework, well-maintained" },
  { pkg: "pino@latest",        verdict: "safe", reason: "top logger, well-maintained" },
  { pkg: "uuid@latest",        verdict: "safe", reason: "top utility, well-maintained" },
  { pkg: "cross-env@latest",   verdict: "safe", reason: "top utility, well-maintained" },
  { pkg: "rimraf@latest",      verdict: "safe", reason: "top utility, well-maintained" },
  { pkg: "globby@latest",      verdict: "safe", reason: "top utility, well-maintained" },
];

// ── Types ──

interface CaseResult {
  pkg: string;
  verdict: Verdict;
  reason: string;
  /** 1-indexed independent attempt for this package. */
  repeatIndex: number;
  findingsCount: number;
  hasFindings: boolean;
  correct: boolean;
  durationMs: number;
  error?: string;
  infrastructureError: boolean;
  usage: { inputTokens: number; outputTokens: number } | null;
  tokenUsage: { inputTokens: number; outputTokens: number } | null;
  estimatedCostUsd: number | null;
  /**
   * Raw finding objects produced by the audit. Preserved here so the
   * triage data collector can pull (finding, ground_truth) rows from
   * npm-bench runs without re-running the agent.
   */
  findings: any[];
}

interface NpmBenchReport {
  timestamp: string;
  depth: string;
  runtime: string;
  repeat: number;
  totalCases: number;
  totalAttempts: number;
  scoredCases: number;
  scoredAttempts: number;
  infrastructureFailures: number;
  validScore: boolean;
  /** True positive + true negative rate */
  accuracy: number | null;
  accuracyCI95: [number, number] | null;
  /** TP / (TP + FN) — how many bad packages we caught */
  detectionRate: number | null;
  detectionRateCI95: [number, number] | null;
  /** FP / (FP + TN) — how often we cry wolf on safe packages */
  falsePositiveRate: number | null;
  falsePositiveRateCI95: [number, number] | null;
  /** Harmonic mean of precision and recall */
  f1: number | null;
  totalDurationMs: number;
  results: CaseResult[];
  verdictBreakdown: Record<Verdict, { total: number; correct: number; rate: number }>;
  note?: string;
}

// ── Runner ──

async function auditPackage(pkg: string): Promise<{
  findings: any[];
  raw: string;
  usage: { inputTokens: number; outputTokens: number } | null;
  estimatedCostUsd: number | null;
}> {
  // Parse package specifier into name and optional version
  let packageName: string;
  let version: string | undefined;

  if (pkg.startsWith("@")) {
    // Scoped package: @scope/name or @scope/name@version
    const idx = pkg.indexOf("@", 1);
    if (idx !== -1) {
      packageName = pkg.slice(0, idx);
      version = pkg.slice(idx + 1);
    } else {
      packageName = pkg;
    }
  } else {
    const idx = pkg.indexOf("@");
    if (idx !== -1) {
      packageName = pkg.slice(0, idx);
      version = pkg.slice(idx + 1);
    } else {
      packageName = pkg;
    }
  }

  const report = await packageAudit({
    config: {
      package: packageName,
      version,
      depth: depth as ScanDepth,
      format: "json",
      runtime: runtimeArg as RuntimeMode,
    },
  });
  const reportWithUsage = report as typeof report & {
    usage?: { inputTokens: number; outputTokens: number };
    estimatedCostUsd?: number;
  };

  return {
    findings: report.findings ?? [],
    raw: JSON.stringify(report),
    usage: reportWithUsage.usage ?? null,
    estimatedCostUsd: reportWithUsage.estimatedCostUsd ?? null,
  };
}

function shouldHaveFindings(verdict: Verdict): boolean {
  return verdict === "malicious" || verdict === "vulnerable";
}

function isInfrastructureError(error: string | undefined): boolean {
  if (!error) return false;
  const lower = error.toLowerCase();
  return [
    "enoent",
    "spawn ",
    "eacces",
    "timed out",
    "timeout",
    "rate limit",
    "api key",
    "authentication",
    "unauthorized",
    "forbidden",
    "deployment unavailable",
    "model may be rate-limited",
    "failed to install",
  ].some((token) => lower.includes(token));
}

async function runNpmBench(): Promise<NpmBenchReport> {
  const results: CaseResult[] = [];
  const start = Date.now();

  // Incremental persistence — append every completed result to a JSONL
  // sidecar so a workflow timeout produces useful partial data instead
  // of total data loss. Run #24025320432 hit the wall at 51/81 packages
  // and we lost all 51 rows because the runner only writes at end-of-run.
  // This sidecar is the safety net.
  const incrementalDir = join(__dirname, "..", "results");
  mkdirSync(incrementalDir, { recursive: true });
  const incrementalPath = join(incrementalDir, "npm-bench-incremental.jsonl");
  // Truncate at start so each run begins with a clean stream — we don't
  // try to merge across runs at the JSONL layer; that's the
  // triage-data-collector's job downstream.
  writeFileSync(incrementalPath, "");

  for (const tc of TEST_CASES) {
    for (let repeatIndex = 1; repeatIndex <= repeat; repeatIndex++) {
      const caseStart = Date.now();
      try {
        const { findings, usage, estimatedCostUsd } = await auditPackage(tc.pkg);
        const hasFindings = findings.length > 0;
        const expectFindings = shouldHaveFindings(tc.verdict);
        const correct = hasFindings === expectFindings;

        results.push({
          pkg: tc.pkg,
          verdict: tc.verdict,
          reason: tc.reason,
          repeatIndex,
          findingsCount: findings.length,
          hasFindings,
          correct,
          durationMs: Date.now() - caseStart,
          infrastructureError: false,
          usage,
          tokenUsage: usage,
          estimatedCostUsd,
          findings,
        });
      } catch (err) {
        const error = err instanceof Error ? err.message : String(err);
        results.push({
          pkg: tc.pkg,
          verdict: tc.verdict,
          reason: tc.reason,
          repeatIndex,
          findingsCount: 0,
          hasFindings: false,
          correct: false,
          durationMs: Date.now() - caseStart,
          error,
          infrastructureError: isInfrastructureError(error),
          usage: null,
          tokenUsage: null,
          estimatedCostUsd: null,
          findings: [],
        });
      }

      // Append-on-complete to the incremental sidecar. Single line of JSON
      // per package attempt, in completion order. Survives a workflow timeout.
      try {
        appendFileSync(incrementalPath, JSON.stringify(results[results.length - 1]) + "\n");
      } catch (err) {
        console.error(`  [warn] could not append incremental result: ${err instanceof Error ? err.message : err}`);
      }

      // Terminal progress
      const last = results[results.length - 1];
      const icon = last.error
        ? "\x1b[33m?\x1b[0m"
        : last.correct
          ? "\x1b[32m✓\x1b[0m"
          : "\x1b[31m✗\x1b[0m";

      if (!jsonOutput) {
        const repeatLabel = repeat > 1 ? ` #${repeatIndex}/${repeat}` : "";
        console.log(
          `  ${icon} [${last.verdict.padEnd(10)}] ${last.pkg.padEnd(30)}${repeatLabel.padEnd(7)} ${last.findingsCount} findings  ${last.durationMs}ms${last.error ? "  ERR" : ""}`,
        );
      }
    }
  }

  const infrastructureFailures = results.filter((r) => r.infrastructureError).length;
  const scoredAttempts = results.length - infrastructureFailures;
  const scoredCases = new Set(results.filter((r) => !r.infrastructureError).map((r) => r.pkg)).size;
  const validScore = infrastructureFailures === 0;

  // ── Metrics ──

  const metrics = computeNpmBenchMetrics(results, validScore);

  // Per-verdict breakdown
  const verdictBreakdown = {} as Record<Verdict, { total: number; correct: number; rate: number }>;
  for (const v of ["malicious", "vulnerable", "safe"] as Verdict[]) {
    const subset = results.filter((r) => r.verdict === v && !r.infrastructureError);
    const correct = subset.filter((r) => r.correct).length;
    verdictBreakdown[v] = {
      total: subset.length,
      correct,
      rate: subset.length > 0 ? correct / subset.length : 0,
    };
  }

  return {
    timestamp: new Date().toISOString(),
    depth,
    runtime: runtimeArg,
    repeat,
    totalCases: TEST_CASES.length,
    totalAttempts: results.length,
    scoredCases,
    scoredAttempts,
    infrastructureFailures,
    validScore,
    accuracy: metrics.accuracy,
    accuracyCI95: metrics.accuracyCI95,
    detectionRate: metrics.detectionRate,
    detectionRateCI95: metrics.detectionRateCI95,
    falsePositiveRate: metrics.falsePositiveRate,
    falsePositiveRateCI95: metrics.falsePositiveRateCI95,
    f1: metrics.f1,
    totalDurationMs: Date.now() - start,
    results,
    verdictBreakdown,
    note: validScore
      ? undefined
      : `Infrastructure failures affected ${infrastructureFailures}/${results.length} cases. Metrics are invalid; inspect case-level errors instead of using this run as a score.`,
  };
}

// ── Main ──

async function main() {
  if (!jsonOutput) {
    console.log("\n\x1b[31m\x1b[1m  pwnkit npm audit benchmark\x1b[0m");
    console.log(`  depth: ${depth}  cases: ${TEST_CASES.length}  repeat: ${repeat}\n`);
  }

  const report = await runNpmBench();

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log("\n  ──────────────────────────────────────");
    console.log(`  Runtime:           \x1b[1m${report.runtime}\x1b[0m`);
    console.log(`  Repeat:            \x1b[1m${report.repeat}\x1b[0m`);
    console.log(`  Infrastructure:    \x1b[1m${report.infrastructureFailures}/${report.totalAttempts}\x1b[0m errored attempts`);
    if (report.validScore && report.accuracy !== null && report.detectionRate !== null && report.falsePositiveRate !== null && report.f1 !== null) {
      const accuracyCi = report.accuracyCI95 ? ` [${(report.accuracyCI95[0] * 100).toFixed(1)}, ${(report.accuracyCI95[1] * 100).toFixed(1)}]` : "";
      const detectionCi = report.detectionRateCI95 ? ` [${(report.detectionRateCI95[0] * 100).toFixed(1)}, ${(report.detectionRateCI95[1] * 100).toFixed(1)}]` : "";
      const fpCi = report.falsePositiveRateCI95 ? ` [${(report.falsePositiveRateCI95[0] * 100).toFixed(1)}, ${(report.falsePositiveRateCI95[1] * 100).toFixed(1)}]` : "";
      console.log(`  Accuracy:          \x1b[1m${(report.accuracy * 100).toFixed(1)}%\x1b[0m${accuracyCi}  (${Math.round(report.accuracy * report.scoredAttempts)}/${report.scoredAttempts})`);
      console.log(`  Detection rate:    \x1b[1m${(report.detectionRate * 100).toFixed(1)}%\x1b[0m${detectionCi}  (recall, 95% Wilson CI)`);
      console.log(`  False positive:    \x1b[1m${(report.falsePositiveRate * 100).toFixed(1)}%\x1b[0m${fpCi}  (95% Wilson CI)`);
      console.log(`  F1 score:          \x1b[1m${report.f1.toFixed(3)}\x1b[0m`);
    } else {
      console.log("  Score:             \x1b[33mINVALID\x1b[0m  infrastructure errors make this run unusable for comparison");
      if (report.note) {
        console.log(`  Note:              ${report.note}`);
      }
    }
    console.log(`  Total time:        ${(report.totalDurationMs / 1000).toFixed(1)}s`);

    console.log("\n  By verdict:");
    for (const [verdict, data] of Object.entries(report.verdictBreakdown)) {
      const bar =
        "\x1b[32m" +
        "█".repeat(Math.round(data.rate * 10)) +
        "\x1b[0m" +
        "░".repeat(10 - Math.round(data.rate * 10));
      console.log(`    ${verdict.padEnd(14)} ${bar} ${data.correct}/${data.total}`);
    }
    console.log("");
  }

  // Save results
  const resultsDir = join(__dirname, "..", "results");
  mkdirSync(resultsDir, { recursive: true });
  writeFileSync(
    join(resultsDir, "npm-bench-latest.json"),
    JSON.stringify(report, null, 2),
  );

  if (!jsonOutput) {
    console.log(`  Results saved to results/npm-bench-latest.json\n`);
  }

  if (!report.validScore) {
    process.exitCode = 2;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((err) => {
    console.error("npm-bench failed:", err);
    process.exit(1);
  });
}
