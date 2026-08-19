#!/usr/bin/env node

/**
 * Argus Benchmark Runner
 *
 * Runs pwnkit against the Argus validation benchmarks (60 Dockerized web
 * vulnerability challenges from Pensar AI). Structurally very similar to
 * XBOW — each challenge is a self-contained Docker Compose stack with a
 * hidden flag.
 *
 * Reference: https://github.com/PensarAI/argus-validation-benchmarks
 * Patched fork: https://github.com/0ca/argus-validation-benchmarks-patched
 *
 * Prerequisites:
 * - Docker + Docker Compose installed
 * - Argus repo cloned (or let the runner clone it via --benchmark-repo)
 *
 * Usage:
 *   tsx src/argus-runner.ts                      # run all 60
 *   tsx src/argus-runner.ts --limit 10           # first 10 only
 *   tsx src/argus-runner.ts --only APEX-001-25,APEX-010-25
 *   tsx src/argus-runner.ts --start 5
 *   tsx src/argus-runner.ts --agentic
 *   tsx src/argus-runner.ts --retries 3
 *   tsx src/argus-runner.ts --dry-run
 *   tsx src/argus-runner.ts --json
 *   tsx src/argus-runner.ts --benchmark-repo PensarAI/argus-validation-benchmarks
 *   tsx src/argus-runner.ts --benchmark-repo 0ca/argus-validation-benchmarks-patched
 */

import { execSync, spawnSync } from "node:child_process";
import { readFileSync, existsSync, writeFileSync, mkdirSync, readdirSync, statSync, appendFileSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { agenticScan, scan } from "@pwnkit/core";
import { tmpdir } from "node:os";
import type { RuntimeMode } from "@pwnkit/shared";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── CLI Args ──
const args = process.argv.slice(2);
const limit = args.includes("--limit") ? parseInt(args[args.indexOf("--limit") + 1]) : Infinity;
const jsonOutput = args.includes("--json");
const useAgentic = args.includes("--agentic");
const dryRun = args.includes("--dry-run");
const retries = args.includes("--retries") ? parseInt(args[args.indexOf("--retries") + 1]) : 1;
const startAt = args.includes("--start") ? parseInt(args[args.indexOf("--start") + 1]) : 0;
const onlyIds = args.includes("--only")
  ? args[args.indexOf("--only") + 1].split(",").map((s) => s.trim())
  : undefined;
const saveFindings = args.includes("--save-findings");
const freshRun = args.includes("--fresh");
const runtimeArg = args.includes("--runtime") ? args[args.indexOf("--runtime") + 1] : "auto";
const whiteBox = args.includes("--white-box");

// ── Benchmark source ──
const benchmarkRepoArg = args.includes("--benchmark-repo")
  ? args[args.indexOf("--benchmark-repo") + 1]
  : undefined;
const benchmarkRefArg = args.includes("--benchmark-ref")
  ? args[args.indexOf("--benchmark-ref") + 1]
  : undefined;
const benchmarkPathArg = args.includes("--benchmark-path")
  ? args[args.indexOf("--benchmark-path") + 1]
  : undefined;

function normalizeRepo(repo: string): string {
  if (/^[\w.-]+\/[\w.-]+$/.test(repo)) return `https://github.com/${repo}.git`;
  return repo;
}

function ensureRepo(repo: string, ref: string | undefined): string {
  const url = normalizeRepo(repo);
  const slug = url
    .replace(/^https?:\/\//, "")
    .replace(/\.git$/, "")
    .replace(/[^\w.-]+/g, "_");
  const dest = join(tmpdir(), "pwnkit-argus-cache", slug);
  const benchDir = join(dest, "benchmarks");

  if (existsSync(benchDir)) {
    // Validate that at least one challenge dir contains a docker-compose
    // (either directly or inside src/)
    const hasChallenges = existsSync(benchDir) && readdirSync(benchDir).some((d) => {
      const p = join(benchDir, d);
      if (!statSync(p).isDirectory() || d.startsWith(".")) return false;
      return (
        existsSync(join(p, "docker-compose.yml")) ||
        existsSync(join(p, "docker-compose.yaml")) ||
        existsSync(join(p, "src", "docker-compose.yml")) ||
        existsSync(join(p, "src", "docker-compose.yaml"))
      );
    });

    if (hasChallenges) {
      if (!jsonOutput) console.log(`  using cached Argus repo at ${dest}`);
      return dest;
    }
    // Cache exists but looks wrong — re-clone
    if (!jsonOutput) console.log(`  cached repo at ${dest} has no valid challenges, re-cloning...`);
    execSync(`rm -rf ${dest}`, { stdio: "pipe" });
  }

  mkdirSync(dirname(dest), { recursive: true });
  const cloneArgs = ["clone", "--depth", "1"];
  if (ref) cloneArgs.push("--branch", ref);
  cloneArgs.push(url, dest);

  if (!jsonOutput) console.log(`  cloning Argus repo ${url}${ref ? ` @ ${ref}` : ""} -> ${dest}`);
  const res = spawnSync("git", cloneArgs, { stdio: "pipe" });
  if (res.status !== 0) {
    console.error(`Failed to clone Argus repo ${url}: ${res.stderr?.toString() ?? ""}`);
    process.exit(1);
  }
  return dest;
}

function resolveArgusPath(): string {
  if (benchmarkPathArg) return benchmarkPathArg;
  if (process.env.ARGUS_PATH) return process.env.ARGUS_PATH;
  if (benchmarkRepoArg) return ensureRepo(benchmarkRepoArg, benchmarkRefArg);
  // Default to patched fork (same pattern as XBOW)
  return ensureRepo("0ca/argus-validation-benchmarks-patched", benchmarkRefArg);
}

const ARGUS_PATH = resolveArgusPath();

// ── Types ──
interface ArgusChallenge {
  id: string;
  name: string;
  description: string;
  tags: string[];
  flag: string;
  path: string;
}

interface ArgusResult {
  id: string;
  name: string;
  tags: string[];
  attackTurns?: number;
  estimatedCostUsd?: number;
  passed: boolean;
  flagFound: boolean;
  findingsCount: number;
  durationMs: number;
  error?: string;
  findings?: unknown[];
}

interface ArgusReport {
  timestamp: string;
  mode: "baseline" | "agentic";
  runtime: string;
  whiteBox: boolean;
  retries: number;
  challenges: number;
  built: number;
  started: number;
  passed: number;
  flags: number;
  totalAttackTurns: number;
  totalEstimatedCostUsd: number;
  buildFailures: number;
  startupFailures: number;
  scanErrors: number;
  results: ArgusResult[];
}

function chooseBetterResult(a: ArgusResult, b: ArgusResult): ArgusResult {
  if (b.flagFound && !a.flagFound) return b;
  if (a.flagFound && !b.flagFound) return a;
  if (b.passed && !a.passed) return b;
  if (a.passed && !b.passed) return a;
  if (!!a.error !== !!b.error) return a.error ? b : a;
  if (b.findingsCount !== a.findingsCount) return b.findingsCount > a.findingsCount ? b : a;
  return b.durationMs < a.durationMs ? b : a;
}

// ── Load Challenges ──
//
// Argus challenge layout (0ca/argus-validation-benchmarks-patched):
//   benchmarks/
//     APEX-001-25/
//       src/                       <-- Docker context lives here
//         docker-compose.yml
//         benchmark.json / benchmark.yaml / metadata.json
//         .env
//         Makefile (may contain FLAG)
//         ...
//       expected_results/          <-- validation data lives here
//         APEX-001-25_vulns.json
//
// We also support the flat layout where docker-compose is directly in
// the challenge dir (no src/ subdirectory).

function extractFlagFromFile(filePath: string): string {
  if (!existsSync(filePath)) return "";
  const content = readFileSync(filePath, "utf8");
  // Look for flag patterns
  const flagMatch = content.match(/FLAG\s*[:=]\s*["']?([^\s"'\n]+)/i);
  if (flagMatch) return flagMatch[1];
  // Look for flag{...} pattern
  const braceMatch = content.match(/flag\{[^}]+\}/i);
  if (braceMatch) return braceMatch[0];
  return "";
}

function loadChallenges(): ArgusChallenge[] {
  const benchDir = join(ARGUS_PATH, "benchmarks");
  const rootDir = existsSync(benchDir) ? benchDir : ARGUS_PATH;

  if (!existsSync(rootDir)) {
    console.error(`Argus benchmarks not found at ${rootDir}`);
    console.error(`Clone the repo:`);
    console.error(`  git clone https://github.com/0ca/argus-validation-benchmarks-patched ${ARGUS_PATH}`);
    console.error(`or re-run with --benchmark-repo <owner/repo> to have the runner clone for you.`);
    process.exit(1);
  }

  // Find challenge directories (APEX-XXX-25 pattern, or any dir with docker-compose)
  const dirs = readdirSync(rootDir)
    .filter((d) => {
      const p = join(rootDir, d);
      return statSync(p).isDirectory() && !d.startsWith(".");
    })
    .sort();

  const challenges: ArgusChallenge[] = [];

  for (const dir of dirs) {
    const challengeRoot = join(rootDir, dir);

    // The Docker context may live in a src/ subdirectory (0ca patched fork)
    // or directly in the challenge dir. Prefer src/ when present.
    const srcDir = join(challengeRoot, "src");
    const challengePath = existsSync(srcDir) && statSync(srcDir).isDirectory()
      ? srcDir
      : challengeRoot;

    // Must have docker-compose or Dockerfile
    const hasCompose =
      existsSync(join(challengePath, "docker-compose.yml")) ||
      existsSync(join(challengePath, "docker-compose.yaml"));
    const hasDockerfile = existsSync(join(challengePath, "Dockerfile"));
    if (!hasCompose && !hasDockerfile) continue;

    let name = dir;
    let description = "";
    let tags: string[] = [];
    let flag = "";

    // Try benchmark.json (XBOW/Argus convention) — lives in src/ or challenge root
    const benchmarkJson = join(challengePath, "benchmark.json");
    if (existsSync(benchmarkJson)) {
      try {
        const config = JSON.parse(readFileSync(benchmarkJson, "utf8"));
        name = config.name ?? dir;
        description = config.description ?? "";
        tags = config.tags ?? [];
        flag = config.flag ?? config.expected_flag ?? "";
        // Some Argus challenges store the flag in metadata.canaries
        if (!flag && Array.isArray(config.canaries) && config.canaries.length > 0) {
          flag = config.canaries[0];
        }
        if (!flag && config.metadata?.canaries && Array.isArray(config.metadata.canaries) && config.metadata.canaries.length > 0) {
          flag = config.metadata.canaries[0];
        }
      } catch {}
    }

    // Try benchmark.yaml
    if (!description) {
      const benchmarkYaml = join(challengePath, "benchmark.yaml");
      if (existsSync(benchmarkYaml)) {
        const yaml = readFileSync(benchmarkYaml, "utf8");
        name = yaml.match(/name:\s*(.+)/)?.[1]?.trim() ?? name;
        description = yaml.match(/description:\s*(.+)/)?.[1]?.trim()
          ?? yaml.match(/content:\s*(.+)/)?.[1]?.trim()
          ?? "";
        const tagsBlock = yaml.match(/tags:\n((?:\s*-\s*.+\n?)*)/)?.[1] ?? "";
        tags = tagsBlock
          .split("\n")
          .map((l) => l.replace(/^\s*-\s*/, "").trim())
          .filter(Boolean);
      }
    }

    // Try metadata.json / config.json
    for (const metaFile of ["metadata.json", "config.json", "challenge.json"]) {
      const metaPath = join(challengePath, metaFile);
      if (!description && existsSync(metaPath)) {
        try {
          const meta = JSON.parse(readFileSync(metaPath, "utf8"));
          name = meta.name ?? meta.title ?? name;
          description = meta.description ?? meta.prompt ?? description;
          tags = meta.tags ?? meta.categories ?? tags;
          flag = meta.flag ?? meta.expected_flag ?? flag;
          // Canary extraction from metadata
          if (!flag && Array.isArray(meta.canaries) && meta.canaries.length > 0) {
            flag = meta.canaries[0];
          }
          if (!flag && meta.metadata?.canaries && Array.isArray(meta.metadata.canaries) && meta.metadata.canaries.length > 0) {
            flag = meta.metadata.canaries[0];
          }
        } catch {}
      }
    }

    // Extract flag from various sources
    if (!flag) {
      // flag.txt — check both challengePath (src/) and challengeRoot
      for (const f of ["flag.txt", "flag", ".flag"]) {
        for (const base of [challengePath, challengeRoot]) {
          const fp = join(base, f);
          if (existsSync(fp)) {
            flag = readFileSync(fp, "utf8").trim();
            break;
          }
        }
        if (flag) break;
      }
    }

    if (!flag) flag = extractFlagFromFile(join(challengePath, "Makefile"));

    if (!flag) {
      // docker-compose.yml environment
      const composePath = join(challengePath, "docker-compose.yml");
      if (existsSync(composePath)) {
        const content = readFileSync(composePath, "utf8");
        const flagMatch = content.match(/FLAG[=:]\s*["']?([^\s"'\n]+)/i);
        if (flagMatch) flag = flagMatch[1];
      }
    }

    if (!flag) {
      // expected_results directory — lives at challengeRoot level, not inside src/
      for (const base of [challengeRoot, challengePath]) {
        const expectedDir = join(base, "expected_results");
        if (existsSync(expectedDir) && statSync(expectedDir).isDirectory()) {
          for (const ef of readdirSync(expectedDir)) {
            const extracted = extractFlagFromFile(join(expectedDir, ef));
            if (extracted) { flag = extracted; break; }
          }
          if (flag) break;
        }
      }
    }

    // .env file
    if (!flag) flag = extractFlagFromFile(join(challengePath, ".env"));

    challenges.push({
      id: dir,
      name,
      description,
      tags,
      flag,
      path: challengePath,
    });
  }

  return challenges;
}

// ── Docker Helpers ──
//
// Use project-name isolation so concurrent runs (or stale containers from a
// previous run) never collide. This mirrors the XBOW pattern.

function projectName(challenge: ArgusChallenge): string {
  return `argus-${challenge.id}`.toLowerCase().replace(/[^a-z0-9-]/g, "-");
}

function buildChallenge(challenge: ArgusChallenge): boolean {
  try {
    let buildCmd = "docker compose";
    buildCmd += ` -p ${projectName(challenge)}`;
    buildCmd += ` build`;

    execSync(buildCmd, {
      cwd: challenge.path,
      stdio: "pipe",
      timeout: 600_000,
    });
    return true;
  } catch {
    return false;
  }
}

function startChallenge(challenge: ArgusChallenge): number | null {
  try {
    const pn = projectName(challenge);

    // Clean up
    try {
      execSync(`docker compose -p ${pn} down -v --remove-orphans`, {
        cwd: challenge.path,
        stdio: "pipe",
        timeout: 30_000,
      });
    } catch {}

    // Start
    execSync(`docker compose -p ${pn} up -d --wait --wait-timeout 150`, {
      cwd: challenge.path,
      stdio: "pipe",
      timeout: 180_000,
    });

    // Find published port
    const output = execSync(`docker compose -p ${pn} ps --format json`, {
      cwd: challenge.path,
      encoding: "utf8",
      timeout: 10_000,
    }).trim();

    for (const line of output.split("\n").filter(Boolean)) {
      try {
        const svc = JSON.parse(line);
        const ports = svc.Publishers ?? [];
        for (const p of ports) {
          if (p.PublishedPort && p.PublishedPort > 0) return p.PublishedPort;
        }
      } catch {}
    }

    // Fallback: common service/port combos
    for (const combo of [
      "web 80", "app 80", "web 5000", "app 5000",
      "web 8080", "app 8080", "web 3000", "app 3000",
      "web 8000", "app 8000", "web 4567", "web 8081",
    ]) {
      try {
        const out = execSync(`docker compose -p ${pn} port ${combo}`, {
          cwd: challenge.path,
          encoding: "utf8",
          timeout: 3000,
        }).trim();
        const m = out.match(/:(\d+)$/);
        if (m) return parseInt(m[1]);
      } catch {}
    }

    return null;
  } catch {
    return null;
  }
}

function stopChallenge(challenge: ArgusChallenge): void {
  try {
    execSync(`docker compose -p ${projectName(challenge)} down -v --remove-orphans`, {
      cwd: challenge.path,
      stdio: "pipe",
      timeout: 30_000,
    });
  } catch {}
}

// ── Run Single Challenge ──
async function runChallengeOnce(challenge: ArgusChallenge): Promise<ArgusResult> {
  const flag = challenge.flag;
  const start = Date.now();

  // Build
  if (!buildChallenge(challenge)) {
    return {
      id: challenge.id,
      name: challenge.name,
      tags: challenge.tags,
      passed: false,
      flagFound: false,
      findingsCount: 0,
      durationMs: Date.now() - start,
      error: "Docker build failed",
    };
  }

  // Start
  const port = startChallenge(challenge);
  if (!port) {
    stopChallenge(challenge);
    return {
      id: challenge.id,
      name: challenge.name,
      tags: challenge.tags,
      passed: false,
      flagFound: false,
      findingsCount: 0,
      durationMs: Date.now() - start,
      error: "Docker start failed or port not found",
    };
  }

  const target = `http://localhost:${port}`;
  const hint = challenge.description ? `Challenge hint: ${challenge.description}` : "";
  const repoPath = whiteBox ? challenge.path : undefined;

  try {
    let report: any;
    if (useAgentic) {
      const dbPath = join(tmpdir(), `pwnkit-argus-${challenge.id}-${Date.now()}.db`);
      report = await agenticScan({
        config: {
          target,
          depth: "quick",
          format: "json",
          mode: "web",
          timeout: 60_000,
          runtime: runtimeArg as RuntimeMode,
          verbose: !!hint,
          repoPath,
        },
        dbPath,
        challengeHint: hint,
      });
    } else {
      report = await scan({ target, depth: "quick", format: "json", mode: "web", timeout: 30_000 });
    }

    const findings = report.findings ?? [];
    const allText = JSON.stringify(report).toLowerCase();
    let flagFound = flag ? allText.includes(flag.toLowerCase()) : false;

    // Defense-in-depth: walk findings for flag patterns
    if (!flagFound && flag && findings.length > 0) {
      const flagRegex = /flag\{[^}]{1,200}\}/gi;
      const knownFlagLower = flag.toLowerCase();
      for (const f of findings) {
        const haystacks: (string | undefined)[] = [
          f.title,
          f.description,
          (f as any).analysis,
          (f as any).evidence?.request,
          (f as any).evidence?.response,
          (f as any).evidence?.analysis,
          (f as any).triageNote,
        ];
        for (const h of haystacks) {
          if (!h) continue;
          const matches = h.match(flagRegex);
          if (!matches) continue;
          for (const m of matches) {
            if (m.toLowerCase() === knownFlagLower) {
              flagFound = true;
              if (!jsonOutput) {
                console.log(`\x1b[32m  [flag-extractor] recovered flag for ${challenge.id}\x1b[0m`);
              }
            }
          }
          if (flagFound) break;
        }
        if (flagFound) break;
      }
    }

    return {
      id: challenge.id,
      name: challenge.name,
      tags: challenge.tags,
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
      tags: challenge.tags,
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

async function runChallenge(challenge: ArgusChallenge): Promise<ArgusResult> {
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

  if (onlyIds) {
    const idSet = new Set(onlyIds.map((id) => id.toUpperCase()));
    challenges = challenges.filter((c) => {
      return idSet.has(c.id.toUpperCase()) || idSet.has(c.name.toUpperCase());
    });
  }
  if (startAt > 0) challenges = challenges.slice(startAt);
  challenges = challenges.slice(0, limit);

  if (challenges.length === 0) {
    const benchDir = join(ARGUS_PATH, "benchmarks");
    const rootDir = existsSync(benchDir) ? benchDir : ARGUS_PATH;
    console.error(`\x1b[31m  0 challenges found.\x1b[0m  Diagnostic info:`);
    console.error(`  ARGUS_PATH = ${ARGUS_PATH}`);
    console.error(`  benchmarks dir exists = ${existsSync(benchDir)}`);
    if (existsSync(rootDir)) {
      const entries = readdirSync(rootDir).filter((d) => {
        const p = join(rootDir, d);
        return statSync(p).isDirectory() && !d.startsWith(".");
      });
      console.error(`  subdirectories in ${rootDir} (${entries.length}):`);
      for (const e of entries.slice(0, 15)) {
        const srcDir = join(rootDir, e, "src");
        const hasSrc = existsSync(srcDir);
        const hasCompose =
          existsSync(join(rootDir, e, "docker-compose.yml")) ||
          existsSync(join(rootDir, e, "docker-compose.yaml")) ||
          (hasSrc && existsSync(join(srcDir, "docker-compose.yml"))) ||
          (hasSrc && existsSync(join(srcDir, "docker-compose.yaml")));
        console.error(`    ${e}  src/=${hasSrc}  compose=${hasCompose}`);
      }
      if (entries.length > 15) console.error(`    ... and ${entries.length - 15} more`);
    } else {
      console.error(`  root dir ${rootDir} does not exist!`);
    }
    process.exit(1);
  }

  if (!jsonOutput) {
    console.log("\x1b[36m\x1b[1m  pwnkit x Argus benchmark\x1b[0m");
    console.log(`  mode: ${useAgentic ? "agentic" : "baseline"}  challenges: ${challenges.length}/60  retries: ${retries}`);
    console.log("");
  }

  if (dryRun) {
    for (const c of challenges) {
      console.log(`  ${c.id}  ${c.name}  [${c.tags.join(", ")}]  flag=${c.flag ? "yes" : "MISSING"}`);
    }
    console.log(`\n  Total: ${challenges.length} challenges`);
    return;
  }

  const results: ArgusResult[] = [];

  // Incremental persistence
  const incrementalDir = join(__dirname, "..", "results");
  mkdirSync(incrementalDir, { recursive: true });
  const incrementalPath = join(incrementalDir, "argus-incremental.jsonl");
  if (freshRun) writeFileSync(incrementalPath, "");

  for (const challenge of challenges) {
    if (!jsonOutput) {
      console.log(`\x1b[1m  >> ${challenge.id}\x1b[0m  [${challenge.tags.join(", ")}]`);
    }

    const result = await runChallenge(challenge);
    results.push(result);

    try {
      appendFileSync(incrementalPath, JSON.stringify(result) + "\n");
    } catch {}

    if (!jsonOutput) {
      const icon = result.flagFound ? "\x1b[32mFLAG\x1b[0m" : "\x1b[31mFAIL\x1b[0m";
      const time = `${(result.durationMs / 1000).toFixed(0)}s`;
      console.log(`  ${icon} ${challenge.name.slice(0, 50).padEnd(50)} ${result.findingsCount} findings  ${time}${result.error ? `  err: ${result.error.slice(0, 40)}` : ""}`);
    }
  }

  const passed = results.filter((r) => r.passed).length;
  const flags = results.filter((r) => r.flagFound).length;
  const buildFailures = results.filter((r) => r.error === "Docker build failed").length;
  const startupFailures = results.filter((r) => r.error === "Docker start failed or port not found").length;
  const scanErrors = results.filter((r) => r.error && r.error !== "Docker build failed" && r.error !== "Docker start failed or port not found").length;
  const built = challenges.length - buildFailures;
  const started = built - startupFailures;
  const totalAttackTurns = results.reduce((sum, r) => sum + (r.attackTurns ?? 0), 0);
  const totalEstimatedCostUsd = results.reduce((sum, r) => sum + (r.estimatedCostUsd ?? 0), 0);

  const report: ArgusReport = {
    timestamp: new Date().toISOString(),
    mode: useAgentic ? "agentic" : "baseline",
    runtime: runtimeArg,
    whiteBox,
    retries,
    challenges: challenges.length,
    built,
    started,
    passed,
    flags,
    totalAttackTurns,
    totalEstimatedCostUsd,
    buildFailures,
    startupFailures,
    scanErrors,
    results,
  };

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log("\n  ──────────────────────────────────────");
    console.log(`  Flag extraction: \x1b[1m${flags}/${challenges.length}\x1b[0m  (${(flags / Math.max(challenges.length, 1) * 100).toFixed(1)}%)`);
    console.log(`  Built / started: \x1b[1m${built}/${started}\x1b[0m  (build fails: ${buildFailures}, start fails: ${startupFailures})`);
    if (totalAttackTurns > 0) console.log(`  Attack turns:    \x1b[1m${totalAttackTurns}\x1b[0m`);
    if (totalEstimatedCostUsd > 0) console.log(`  Est. cost:       \x1b[1m$${totalEstimatedCostUsd.toFixed(2)}\x1b[0m`);
    console.log(`  Total time:      ${(results.reduce((a, r) => a + r.durationMs, 0) / 1000).toFixed(0)}s`);

    // By tag
    const tagMap = new Map<string, { total: number; flags: number }>();
    for (const r of results) {
      for (const tag of r.tags) {
        const t = tagMap.get(tag) ?? { total: 0, flags: 0 };
        t.total++;
        if (r.flagFound) t.flags++;
        tagMap.set(tag, t);
      }
    }
    if (tagMap.size > 0) {
      console.log("\n  By tag:");
      for (const [tag, data] of [...tagMap.entries()].sort((a, b) => b[1].total - a[1].total)) {
        console.log(`    ${tag.padEnd(25)} ${data.flags}/${data.total}`);
      }
    }
    console.log("");
  }

  // Save results (merge with existing)
  const resultsDir = join(__dirname, "..", "results");
  mkdirSync(resultsDir, { recursive: true });
  const latestPath = join(resultsDir, "argus-latest.json");

  if (!freshRun && existsSync(latestPath)) {
    try {
      const existing: ArgusReport = JSON.parse(readFileSync(latestPath, "utf8"));
      const existingById = new Map(existing.results.map((r) => [r.id, r]));
      for (const r of report.results) existingById.set(r.id, r);
      const mergedResults = [...existingById.values()].sort((a, b) => a.id.localeCompare(b.id));

      const mergedBuildFailures = mergedResults.filter((r) => r.error === "Docker build failed").length;
      const mergedStartupFailures = mergedResults.filter((r) => r.error === "Docker start failed or port not found").length;
      const mergedScanErrors = mergedResults.filter((r) => r.error && r.error !== "Docker build failed" && r.error !== "Docker start failed or port not found").length;
      const mergedBuilt = mergedResults.length - mergedBuildFailures;
      const mergedStarted = mergedBuilt - mergedStartupFailures;

      const mergedReport: ArgusReport = {
        ...report,
        timestamp: new Date().toISOString(),
        challenges: mergedResults.length,
        built: mergedBuilt,
        started: mergedStarted,
        passed: mergedResults.filter((r) => r.passed).length,
        flags: mergedResults.filter((r) => r.flagFound).length,
        buildFailures: mergedBuildFailures,
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

  if (!jsonOutput) console.log(`  Results saved to ${latestPath}`);
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("Argus benchmark failed:", err);
    process.exit(1);
  });
