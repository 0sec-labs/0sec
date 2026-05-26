#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const resultsDir = join(__dirname, "..", "results");

type JsonRecord = Record<string, unknown>;

function readJson(name: string): JsonRecord | null {
  const path = join(resultsDir, name);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as JsonRecord;
  } catch {
    return null;
  }
}

function pct(value: unknown): string {
  return typeof value === "number" ? `${(value * 100).toFixed(1)}%` : "n/a";
}

function int(value: unknown): string {
  return typeof value === "number" ? String(value) : "n/a";
}

function line(label: string, value: string): string {
  return `  ${label.padEnd(18)} ${value}`;
}

function summarizeAgenticBench(data: JsonRecord | null): string[] {
  if (!data) return ["AI/LLM latest: missing artifact"];
  return [
    "AI/LLM benchmark",
    line("timestamp", String(data.timestamp ?? "n/a")),
    line("runtime", String(data.runtime ?? "n/a")),
    line("challenges", int(data.totalChallenges)),
    line("passed", `${int(data.passed)}/${int(data.totalChallenges)}`),
    line("flag extraction", pct(data.flagExtractionRate)),
  ];
}

function summarizeXbow(data: JsonRecord | null): string[] {
  if (!data) return ["XBOW latest: missing artifact"];
  const results = Array.isArray(data.results) ? data.results as Array<Record<string, unknown>> : [];
  const buildFailures = typeof data.buildFailures === "number"
    ? data.buildFailures
    : results.filter((r) => r.error === "Docker build failed").length;
  const startupFailures = typeof data.startupFailures === "number"
    ? data.startupFailures
    : results.filter((r) => r.error === "Docker start failed or port not found").length;
  const challenges = typeof data.challenges === "number" ? data.challenges : results.length;
  const built = typeof data.built === "number" ? data.built : challenges - buildFailures;
  const started = typeof data.started === "number" ? data.started : built - startupFailures;
  return [
    "XBOW benchmark",
    line("timestamp", String(data.timestamp ?? "n/a")),
    line("mode", String(data.mode ?? "n/a")),
    line("runtime", String(data.runtime ?? "n/a")),
    line("white-box", String(data.whiteBox ?? "n/a")),
    line("retries", int(data.retries)),
    line("flags", `${int(data.flags)}/${int(challenges)}`),
    line("built", int(built)),
    line("started", int(started)),
    line("build failures", int(buildFailures)),
    line("start failures", int(startupFailures)),
  ];
}

function summarizeNpm(data: JsonRecord | null): string[] {
  if (!data) return ["npm benchmark: missing artifact"];
  const results = Array.isArray(data.results) ? data.results as Array<Record<string, unknown>> : [];
  const totalCases = typeof data.totalCases === "number" ? data.totalCases : results.length;
  const infrastructureFailures = typeof data.infrastructureFailures === "number"
    ? data.infrastructureFailures
    : results.filter((r) => typeof r.error === "string" && r.error.length > 0).length;
  const scoredCases = typeof data.scoredCases === "number"
    ? data.scoredCases
    : totalCases - infrastructureFailures;
  const valid = typeof data.validScore === "boolean" ? data.validScore : infrastructureFailures === 0;
  return [
    "npm benchmark",
    line("timestamp", String(data.timestamp ?? "n/a")),
    line("runtime", String(data.runtime ?? "n/a")),
    line("cases", int(totalCases)),
    line("scored cases", int(scoredCases)),
    line("infra failures", int(infrastructureFailures)),
    line("valid score", valid ? "yes" : "no"),
    line("accuracy", valid ? pct(data.accuracy) : "invalid"),
    line("f1", valid && typeof data.f1 === "number" ? data.f1.toFixed(3) : "invalid"),
  ];
}

function main() {
  const latest = readJson("latest.json");
  const xbow = readJson("xbow-latest.json");
  const npm = readJson("npm-bench-latest.json");

  const sections = [
    summarizeAgenticBench(latest),
    summarizeXbow(xbow),
    summarizeNpm(npm),
  ];

  console.log("\x1b[31m\x1b[1m  pwnkit benchmark report\x1b[0m\n");
  for (const section of sections) {
    for (const entry of section) console.log(entry);
    console.log("");
  }

  if (npm && npm.validScore !== true && npm.note) {
    console.log(`Note: ${String(npm.note)}`);
  }
}

main();
