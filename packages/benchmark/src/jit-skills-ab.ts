#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface BenchmarkReportLike {
  challenges: number;
  passed: number;
  flags: number;
  totalAttackTurns?: number;
  totalEstimatedCostUsd?: number;
  totalInputTokens?: number;
  totalOutputTokens?: number;
  totalTokens?: number;
  buildFailures?: number;
  startupFailures?: number;
  scanErrors?: number;
}

export interface JitSkillsAbCell {
  label: "baseline" | "jit-skills";
  jitSkills: boolean;
  challenges: number;
  passed: number;
  flags: number;
  passRate: number;
  flagRate: number;
  totalAttackTurns: number;
  totalEstimatedCostUsd: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  totalTokens: number;
  averageAttackTurns: number;
  averageEstimatedCostUsd: number;
  averageTokens: number;
  buildFailures: number;
  startupFailures: number;
  scanErrors: number;
}

export interface JitSkillsAbReport {
  timestamp: string;
  runner: "xbow";
  xbowArgs: string[];
  baseline: JitSkillsAbCell;
  jitSkills: JitSkillsAbCell;
  delta: {
    passed: number;
    flags: number;
    passRatePctPoints: number;
    flagRatePctPoints: number;
    totalAttackTurns: number;
    totalEstimatedCostUsd: number;
    totalTokens: number;
  };
}

const VALUE_FLAGS = new Set([
  "--limit",
  "--only",
  "--tag",
  "--level",
  "--start",
  "--runtime",
  "--models",
  "--retries",
  "--repeat",
  "--repeat-cost-ceiling-usd",
]);
const BOOLEAN_FLAGS = new Set(["--white-box", "--save-findings"]);

export function buildXbowArgs(rawArgs: string[]): string[] {
  const xbowArgs = ["--agentic", "--fresh", "--json"];

  for (let i = 0; i < rawArgs.length; i++) {
    const arg = rawArgs[i]!;
    if (arg === "--json" || arg === "--runner") {
      if (arg === "--runner") i++;
      continue;
    }
    if (VALUE_FLAGS.has(arg)) {
      const value = rawArgs[i + 1];
      if (!value) throw new Error(`${arg} requires a value`);
      xbowArgs.push(arg, value);
      i++;
      continue;
    }
    if (BOOLEAN_FLAGS.has(arg)) {
      xbowArgs.push(arg);
    }
  }

  if (!xbowArgs.includes("--limit") && !xbowArgs.includes("--only")) {
    xbowArgs.push("--limit", "10");
  }

  return xbowArgs;
}

export function parseBenchmarkJson(stdout: string): BenchmarkReportLike {
  const trimmed = stdout.trim();
  if (!trimmed) throw new Error("benchmark produced no stdout");

  try {
    return JSON.parse(trimmed) as BenchmarkReportLike;
  } catch {
    const start = trimmed.indexOf("{");
    const end = trimmed.lastIndexOf("}");
    if (start === -1 || end === -1 || end <= start) {
      throw new Error("benchmark stdout did not contain a JSON report");
    }
    return JSON.parse(trimmed.slice(start, end + 1)) as BenchmarkReportLike;
  }
}

export function summarizeBenchmarkReport(
  label: JitSkillsAbCell["label"],
  jitSkills: boolean,
  report: BenchmarkReportLike,
): JitSkillsAbCell {
  const challenges = report.challenges;
  const totalAttackTurns = report.totalAttackTurns ?? 0;
  const totalEstimatedCostUsd = report.totalEstimatedCostUsd ?? 0;
  const totalInputTokens = report.totalInputTokens ?? 0;
  const totalOutputTokens = report.totalOutputTokens ?? 0;
  const totalTokens = report.totalTokens ?? totalInputTokens + totalOutputTokens;
  return {
    label,
    jitSkills,
    challenges,
    passed: report.passed,
    flags: report.flags,
    passRate: challenges > 0 ? report.passed / challenges : 0,
    flagRate: challenges > 0 ? report.flags / challenges : 0,
    totalAttackTurns,
    totalEstimatedCostUsd,
    totalInputTokens,
    totalOutputTokens,
    totalTokens,
    averageAttackTurns: challenges > 0 ? totalAttackTurns / challenges : 0,
    averageEstimatedCostUsd: challenges > 0 ? totalEstimatedCostUsd / challenges : 0,
    averageTokens: challenges > 0 ? totalTokens / challenges : 0,
    buildFailures: report.buildFailures ?? 0,
    startupFailures: report.startupFailures ?? 0,
    scanErrors: report.scanErrors ?? 0,
  };
}

export function compareCells(
  baseline: JitSkillsAbCell,
  jitSkills: JitSkillsAbCell,
): JitSkillsAbReport["delta"] {
  return {
    passed: jitSkills.passed - baseline.passed,
    flags: jitSkills.flags - baseline.flags,
    passRatePctPoints: (jitSkills.passRate - baseline.passRate) * 100,
    flagRatePctPoints: (jitSkills.flagRate - baseline.flagRate) * 100,
    totalAttackTurns: jitSkills.totalAttackTurns - baseline.totalAttackTurns,
    totalEstimatedCostUsd: jitSkills.totalEstimatedCostUsd - baseline.totalEstimatedCostUsd,
    totalTokens: jitSkills.totalTokens - baseline.totalTokens,
  };
}

function runXbowCell(label: JitSkillsAbCell["label"], jitSkills: boolean, xbowArgs: string[]): JitSkillsAbCell {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const repoRoot = join(__dirname, "../../..");
  const result = spawnSync(
    "pnpm",
    ["--filter", "@pwnkit/benchmark", "xbow", ...xbowArgs],
    {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        PWNKIT_FEATURE_JIT_SKILLS: jitSkills ? "1" : "0",
      },
    },
  );

  if (result.status !== 0) {
    const stderr = (result.stderr ?? "").trim().slice(-2000);
    throw new Error(`${label} XBOW run failed with exit ${result.status}: ${stderr}`);
  }

  return summarizeBenchmarkReport(label, jitSkills, parseBenchmarkJson(result.stdout ?? ""));
}

function formatRate(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function formatDelta(value: number, suffix = ""): string {
  const prefix = value > 0 ? "+" : "";
  return `${prefix}${value.toFixed(2)}${suffix}`;
}

async function main(): Promise<void> {
  const rawArgs = process.argv.slice(2);
  const runnerIndex = rawArgs.indexOf("--runner");
  const runner = runnerIndex >= 0 ? rawArgs[runnerIndex + 1] : "xbow";
  if (runner !== "xbow") {
    throw new Error("jit-skills A/B currently supports --runner xbow only");
  }

  const jsonOutput = rawArgs.includes("--json");
  const xbowArgs = buildXbowArgs(rawArgs);
  const baseline = runXbowCell("baseline", false, xbowArgs);
  const jitSkills = runXbowCell("jit-skills", true, xbowArgs);
  const report: JitSkillsAbReport = {
    timestamp: new Date().toISOString(),
    runner: "xbow",
    xbowArgs,
    baseline,
    jitSkills,
    delta: compareCells(baseline, jitSkills),
  };

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  console.log("pwnkit JIT skills A/B");
  console.log(`runner: xbow ${xbowArgs.join(" ")}`);
  console.log("");
  console.log(`baseline:   ${baseline.passed}/${baseline.challenges} pass, ${baseline.flags}/${baseline.challenges} flags, ${baseline.totalAttackTurns} turns, ${baseline.totalTokens} tokens, $${baseline.totalEstimatedCostUsd.toFixed(2)}`);
  console.log(`jit-skills: ${jitSkills.passed}/${jitSkills.challenges} pass, ${jitSkills.flags}/${jitSkills.challenges} flags, ${jitSkills.totalAttackTurns} turns, ${jitSkills.totalTokens} tokens, $${jitSkills.totalEstimatedCostUsd.toFixed(2)}`);
  console.log("");
  console.log(`delta pass rate: ${formatDelta(report.delta.passRatePctPoints, " pp")}`);
  console.log(`delta flag rate: ${formatDelta(report.delta.flagRatePctPoints, " pp")}`);
  console.log(`delta turns:     ${formatDelta(report.delta.totalAttackTurns)}`);
  console.log(`delta tokens:    ${formatDelta(report.delta.totalTokens)}`);
  console.log(`delta cost:      ${formatDelta(report.delta.totalEstimatedCostUsd, " USD")}`);
  console.log(`baseline rates:  pass ${formatRate(baseline.passRate)}, flags ${formatRate(baseline.flagRate)}`);
  console.log(`jit rates:       pass ${formatRate(jitSkills.passRate)}, flags ${formatRate(jitSkills.flagRate)}`);
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}
