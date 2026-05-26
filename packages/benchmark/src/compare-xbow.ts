#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const args = process.argv.slice(2);
const basePath = args.includes("--base") ? args[args.indexOf("--base") + 1] : "";
const candidatePath = args.includes("--candidate") ? args[args.indexOf("--candidate") + 1] : "";

if (!basePath || !candidatePath) {
  console.error("Usage: tsx src/compare-xbow.ts --base <base.json> --candidate <candidate.json>");
  process.exit(2);
}

type XbowResult = {
  id: string;
  flagFound?: boolean;
  error?: string;
  attackTurns?: number;
  estimatedCostUsd?: number;
};

type XbowReport = {
  runtime?: string;
  whiteBox?: boolean;
  retries?: number;
  challenges?: number;
  built?: number;
  started?: number;
  flags?: number;
  totalAttackTurns?: number;
  totalEstimatedCostUsd?: number;
  results?: XbowResult[];
};

function resolveInputPath(path: string): string {
  const normalized = path.startsWith("packages/benchmark/")
    ? path.slice("packages/benchmark/".length)
    : path;
  const candidates = [
    path,
    normalized,
    join(process.cwd(), path),
    join(process.cwd(), normalized),
    join(__dirname, "..", path),
    join(__dirname, "..", normalized),
  ];

  for (const candidate of candidates) {
    try {
      return readFileSync(candidate, "utf8"), candidate;
    } catch {
      // keep trying
    }
  }

  return path;
}

function read(path: string): XbowReport {
  return JSON.parse(readFileSync(resolveInputPath(path), "utf8")) as XbowReport;
}

function solvedIds(report: XbowReport): Set<string> {
  return new Set((report.results ?? []).filter((r) => r.flagFound).map((r) => r.id));
}

function sumTurns(report: XbowReport): number {
  return report.totalAttackTurns
    ?? (report.results ?? []).reduce((sum, r) => sum + (r.attackTurns ?? 0), 0);
}

function sumCost(report: XbowReport): number {
  return report.totalEstimatedCostUsd
    ?? (report.results ?? []).reduce((sum, r) => sum + (r.estimatedCostUsd ?? 0), 0);
}

function fmtDelta(n: number): string {
  return `${n >= 0 ? "+" : ""}${n}`;
}

const base = read(basePath);
const candidate = read(candidatePath);

const baseSolved = solvedIds(base);
const candidateSolved = solvedIds(candidate);
const gained = [...candidateSolved].filter((id) => !baseSolved.has(id)).sort();
const lost = [...baseSolved].filter((id) => !candidateSolved.has(id)).sort();

const baseFlags = base.flags ?? baseSolved.size;
const candidateFlags = candidate.flags ?? candidateSolved.size;
const baseTurns = sumTurns(base);
const candidateTurns = sumTurns(candidate);
const baseCost = sumCost(base);
const candidateCost = sumCost(candidate);

console.log("\x1b[31m\x1b[1m  XBOW compare\x1b[0m\n");
console.log(`Base:      ${basePath}`);
console.log(`Candidate: ${candidatePath}\n`);
console.log(`Flags:         ${baseFlags} -> ${candidateFlags} (${fmtDelta(candidateFlags - baseFlags)})`);
console.log(`Attack turns:  ${baseTurns} -> ${candidateTurns} (${fmtDelta(candidateTurns - baseTurns)})`);
console.log(`Est. cost:     $${baseCost.toFixed(2)} -> $${candidateCost.toFixed(2)} (${candidateCost - baseCost >= 0 ? "+" : ""}$${(candidateCost - baseCost).toFixed(2)})`);
console.log(`Runtime:       ${String(base.runtime ?? "n/a")} -> ${String(candidate.runtime ?? "n/a")}`);
console.log(`White-box:     ${String(base.whiteBox ?? "n/a")} -> ${String(candidate.whiteBox ?? "n/a")}`);
console.log(`Retries:       ${String(base.retries ?? "n/a")} -> ${String(candidate.retries ?? "n/a")}`);

if (gained.length > 0) {
  console.log(`\nGained flags (${gained.length}): ${gained.join(", ")}`);
}
if (lost.length > 0) {
  console.log(`Lost flags (${lost.length}): ${lost.join(", ")}`);
}
if (gained.length === 0 && lost.length === 0) {
  console.log("\nSolved challenge set unchanged.");
}
