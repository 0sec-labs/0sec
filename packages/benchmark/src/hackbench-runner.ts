#!/usr/bin/env node

/**
 * HackBench Benchmark Runner
 *
 * Runs pwnkit against the HackBench benchmark suite (16 web vulnerability
 * challenges). Docker Compose based, self-hostable,
 * zero auth required. BoxPwnr scores 68.8% (11/16).
 *
 * Some challenges include an XSS bot (headless browser) that visits URLs
 * submitted by the agent. The runner starts the XSS bot container alongside
 * the challenge.
 *
 * Reference: https://github.com/0ca/hackbench-patched
 *
 * Prerequisites:
 * - Docker + Docker Compose installed
 * - HackBench repo cloned (or let the runner clone it)
 *
 * Usage:
 *   tsx src/hackbench-runner.ts                     # run all 16
 *   tsx src/hackbench-runner.ts --limit 5           # first 5 only
 *   tsx src/hackbench-runner.ts --only challenge1,challenge2
 *   tsx src/hackbench-runner.ts --start 3
 *   tsx src/hackbench-runner.ts --agentic
 *   tsx src/hackbench-runner.ts --retries 3
 *   tsx src/hackbench-runner.ts --dry-run
 *   tsx src/hackbench-runner.ts --json
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
  ? args[args.indexOf("--only") + 1].split(",").map((s) => s.trim().toLowerCase())
  : undefined;
const saveFindings = args.includes("--save-findings");
const freshRun = args.includes("--fresh");
const runtimeArg = args.includes("--runtime") ? args[args.indexOf("--runtime") + 1] : "auto";

// ── Benchmark source ──
const benchmarkRepoArg = args.includes("--benchmark-repo")
  ? args[args.indexOf("--benchmark-repo") + 1]
  : undefined;
const benchmarkRefArg = args.includes("--benchmark-ref")
  ? args[args.indexOf("--benchmark-ref") + 1]
  : undefined;

function resolveHackBenchPath(): string {
  if (process.env.HACKBENCH_PATH) return process.env.HACKBENCH_PATH;
  if (benchmarkRepoArg) return ensureRepo(benchmarkRepoArg, benchmarkRefArg);
  // Default to patched fork (same as BoxPwnr)
  return ensureRepo("0ca/hackbench-patched", benchmarkRefArg);
}

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
  const dest = join(tmpdir(), "pwnkit-hackbench-cache", slug);

  if (existsSync(dest) && (existsSync(join(dest, "web_exploitation")) || existsSync(join(dest, "challenges")) || existsSync(join(dest, "docker-compose.yml")))) {
    if (!jsonOutput) console.log(`  using cached HackBench repo at ${dest}`);
    return dest;
  }

  mkdirSync(dirname(dest), { recursive: true });
  const cloneArgs = ["clone", "--depth", "1"];
  if (ref) cloneArgs.push("--branch", ref);
  cloneArgs.push(url, dest);

  if (!jsonOutput) console.log(`  cloning HackBench repo ${url}${ref ? ` @ ${ref}` : ""} -> ${dest}`);
  const res = spawnSync("git", cloneArgs, { stdio: "pipe" });
  if (res.status !== 0) {
    console.error(`Failed to clone HackBench repo ${url}: ${res.stderr?.toString() ?? ""}`);
    process.exit(1);
  }
  return dest;
}

const HACKBENCH_PATH = resolveHackBenchPath();

// ── Types ──
interface HackBenchChallenge {
  id: string;
  name: string;
  description: string;
  category: string;
  flag: string;
  hasXssBot: boolean;
  path: string;
}

interface HackBenchResult {
  id: string;
  name: string;
  category: string;
  attackTurns?: number;
  estimatedCostUsd?: number;
  passed: boolean;
  flagFound: boolean;
  findingsCount: number;
  durationMs: number;
  error?: string;
  findings?: unknown[];
}

interface HackBenchReport {
  timestamp: string;
  mode: "baseline" | "agentic";
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
  results: HackBenchResult[];
}

function chooseBetterResult(a: HackBenchResult, b: HackBenchResult): HackBenchResult {
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
// HackBench challenge layout (actual repo structure):
//   web_exploitation/
//     EV-01/ .. EV-16/
//       docker-compose.yaml
//       challenge.json          -- name, description, difficulty, category, url, flag
//       application/            -- challenge source code
//       ...
//
// We discover challenges by scanning for directories that contain a
// docker-compose.yml (or docker-compose.yaml). Metadata is loaded from
// challenge.json, config.json, or we fall back to directory name as ID.

function loadChallenges(): HackBenchChallenge[] {
  // Try multiple possible directory structures
  const candidateRoots = [
    join(HACKBENCH_PATH, "web_exploitation"),
    join(HACKBENCH_PATH, "challenges"),
    join(HACKBENCH_PATH, "benchmarks"),
    HACKBENCH_PATH,
  ];

  let challengeRoot = "";
  for (const root of candidateRoots) {
    if (existsSync(root) && statSync(root).isDirectory()) {
      // Check if this dir has subdirectories with docker-compose files
      try {
        const entries = readdirSync(root).filter((d) => {
          const p = join(root, d);
          return (
            statSync(p).isDirectory() &&
            (existsSync(join(p, "docker-compose.yml")) ||
              existsSync(join(p, "docker-compose.yaml")) ||
              existsSync(join(p, "Dockerfile")))
          );
        });
        if (entries.length > 0) {
          challengeRoot = root;
          break;
        }
      } catch {
        continue;
      }
    }
  }

  if (!challengeRoot) {
    // Maybe the whole repo is a single docker-compose with multiple services
    if (existsSync(join(HACKBENCH_PATH, "docker-compose.yml"))) {
      challengeRoot = HACKBENCH_PATH;
    } else {
      const foundDirs = existsSync(HACKBENCH_PATH)
        ? readdirSync(HACKBENCH_PATH).filter((d) => statSync(join(HACKBENCH_PATH, d)).isDirectory()).join(", ")
        : "(path does not exist)";
      console.error(`HackBench challenges not found at ${HACKBENCH_PATH}`);
      console.error(`Directories found: ${foundDirs}`);
      console.error(`Expected: web_exploitation/ with EV-XX subdirectories containing docker-compose.yaml`);
      console.error(`Clone the repo: git clone https://github.com/0ca/hackbench-patched ${HACKBENCH_PATH}`);
      process.exit(1);
    }
  }

  const challenges: HackBenchChallenge[] = [];

  // If challengeRoot == HACKBENCH_PATH and there's a top-level compose, treat
  // each service or subdirectory as a challenge
  const dirs = readdirSync(challengeRoot)
    .filter((d) => {
      const p = join(challengeRoot, d);
      return statSync(p).isDirectory() && !d.startsWith(".");
    })
    .sort();

  for (const dir of dirs) {
    const challengePath = join(challengeRoot, dir);
    const hasCompose =
      existsSync(join(challengePath, "docker-compose.yml")) ||
      existsSync(join(challengePath, "docker-compose.yaml"));
    const hasDockerfile = existsSync(join(challengePath, "Dockerfile"));

    if (!hasCompose && !hasDockerfile) continue;

    // Load metadata from various possible files
    let name = dir;
    let description = "";
    let category = "web";
    let flag = "";
    let hasXssBot = false;

    // Try challenge.json
    const challengeJsonPath = join(challengePath, "challenge.json");
    const configJsonPath = join(challengePath, "config.json");
    const metadataPath = join(challengePath, "metadata.json");

    for (const jsonPath of [challengeJsonPath, configJsonPath, metadataPath]) {
      if (existsSync(jsonPath)) {
        try {
          const meta = JSON.parse(readFileSync(jsonPath, "utf8"));
          name = meta.name ?? meta.title ?? name;
          description = meta.description ?? meta.prompt ?? description;
          category = meta.category ?? meta.type ?? category;
          flag = meta.flag ?? meta.expected_flag ?? flag;
          if (meta.xss_bot || meta.bot || meta.has_bot) hasXssBot = true;
        } catch {}
        break;
      }
    }

    // Try to extract flag from flag.txt
    if (!flag) {
      for (const flagFile of ["flag.txt", "flag", ".flag"]) {
        const fp = join(challengePath, flagFile);
        if (existsSync(fp)) {
          flag = readFileSync(fp, "utf8").trim();
          break;
        }
      }
    }

    // Try to extract flag from docker-compose.yml environment
    if (!flag) {
      const composePath = join(challengePath, hasCompose ? "docker-compose.yml" : "docker-compose.yaml");
      if (existsSync(composePath)) {
        const composeContent = readFileSync(composePath, "utf8");
        const flagMatch = composeContent.match(/FLAG[=:]\s*["']?([^\s"'\n]+)/i);
        if (flagMatch) flag = flagMatch[1];

        // Detect XSS bot service
        if (/xss.?bot|headless|puppeteer|playwright|chrome|selenium/i.test(composeContent)) {
          hasXssBot = true;
        }
      }
    }

    // Try Makefile for flag
    if (!flag) {
      const makefile = join(challengePath, "Makefile");
      if (existsSync(makefile)) {
        const content = readFileSync(makefile, "utf8");
        const flagMatch = content.match(/FLAG\s*[:?]?=\s*["']?([^\s"'\n]+)/);
        if (flagMatch) flag = flagMatch[1];
      }
    }

    const id = dir
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");

    challenges.push({
      id,
      name,
      description,
      category,
      flag,
      hasXssBot,
      path: challengePath,
    });
  }

  return challenges;
}

// ── Docker Helpers ──

/** Preferred container ports for the main app (in priority order). */
const PREFERRED_CONTAINER_PORTS = [3000, 80, 443, 1337];

interface StartResult {
  port: number;
  botUrl?: string;
}

function startChallenge(challenge: HackBenchChallenge): StartResult | null {
  try {
    // Clean up any previous run
    try {
      execSync("docker compose down -v --remove-orphans", {
        cwd: challenge.path,
        stdio: "pipe",
        timeout: 30_000,
      });
    } catch {}

    // Build and start
    const composeFile = existsSync(join(challenge.path, "docker-compose.yml"))
      ? "docker-compose.yml"
      : existsSync(join(challenge.path, "docker-compose.yaml"))
        ? "docker-compose.yaml"
        : null;

    if (composeFile) {
      execSync("docker compose up --build -d --wait", {
        cwd: challenge.path,
        stdio: "pipe",
        timeout: 1_800_000,
      });
    } else {
      // Dockerfile only — build and run
      const tag = `hackbench-${challenge.id}`;
      execSync(`docker build -t ${tag} .`, {
        cwd: challenge.path,
        stdio: "pipe",
        timeout: 1_800_000,
      });
      execSync(`docker run -d -P --name ${tag} ${tag}`, {
        cwd: challenge.path,
        stdio: "pipe",
        timeout: 30_000,
      });
    }

    // Find the published port(s)
    let appPort: number | null = null;
    let botUrl: string | undefined;

    if (composeFile) {
      const output = execSync("docker compose ps --format json", {
        cwd: challenge.path,
        encoding: "utf8",
        timeout: 10_000,
      }).trim();

      // Collect all published port mappings: { containerPort, publishedPort }
      const portMappings: { containerPort: number; publishedPort: number }[] = [];
      for (const line of output.split("\n").filter(Boolean)) {
        try {
          const svc = JSON.parse(line);
          const ports = svc.Publishers ?? [];
          for (const p of ports) {
            if (p.PublishedPort && p.PublishedPort > 0) {
              portMappings.push({
                containerPort: p.TargetPort ?? 0,
                publishedPort: p.PublishedPort,
              });
            }
          }
        } catch {}
      }

      // XSS bot URL discovery: look for container port 3001
      if (challenge.hasXssBot) {
        const botMapping = portMappings.find((m) => m.containerPort === 3001);
        if (botMapping) {
          botUrl = `http://localhost:${botMapping.publishedPort}/visit`;
        }
      }

      // Pick app port: prefer specific container ports in priority order
      for (const preferred of PREFERRED_CONTAINER_PORTS) {
        const mapping = portMappings.find((m) => m.containerPort === preferred);
        if (mapping) {
          appPort = mapping.publishedPort;
          break;
        }
      }

      // Fallback: first non-bot published port
      if (!appPort) {
        const botPublished = botUrl ? portMappings.find((m) => m.containerPort === 3001)?.publishedPort : undefined;
        const fallback = portMappings.find((m) => m.publishedPort !== botPublished);
        if (fallback) appPort = fallback.publishedPort;
      }

      // Fallback: common service/port combos
      if (!appPort) {
        for (const combo of [
          "web 80", "app 80", "web 5000", "app 5000",
          "web 8080", "app 8080", "web 3000", "app 3000",
          "web 8000", "app 8000", "web 4567",
        ]) {
          try {
            const out = execSync(`docker compose port ${combo}`, {
              cwd: challenge.path,
              encoding: "utf8",
              timeout: 3000,
            }).trim();
            const m = out.match(/:(\d+)$/);
            if (m) { appPort = parseInt(m[1]); break; }
          } catch {}
        }
      }
    } else {
      // Standalone container
      const tag = `hackbench-${challenge.id}`;
      try {
        const out = execSync(`docker port ${tag}`, {
          encoding: "utf8",
          timeout: 5000,
        }).trim();
        const m = out.match(/:(\d+)/);
        if (m) appPort = parseInt(m[1]);
      } catch {}
    }

    if (!appPort) return null;
    return { port: appPort, botUrl };
  } catch {
    return null;
  }
}

function stopChallenge(challenge: HackBenchChallenge): void {
  try {
    const composeFile =
      existsSync(join(challenge.path, "docker-compose.yml")) ||
      existsSync(join(challenge.path, "docker-compose.yaml"));

    if (composeFile) {
      execSync("docker compose down -v --remove-orphans", {
        cwd: challenge.path,
        stdio: "pipe",
        timeout: 30_000,
      });
    } else {
      const tag = `hackbench-${challenge.id}`;
      try { execSync(`docker rm -f ${tag}`, { stdio: "pipe", timeout: 10_000 }); } catch {}
    }
  } catch {}
}

// ── Run Single Challenge ──
async function runChallengeOnce(challenge: HackBenchChallenge): Promise<HackBenchResult> {
  const start = Date.now();

  const startResult = startChallenge(challenge);
  if (!startResult) {
    stopChallenge(challenge);
    return {
      id: challenge.id,
      name: challenge.name,
      category: challenge.category,
      passed: false,
      flagFound: false,
      findingsCount: 0,
      durationMs: Date.now() - start,
      error: "Docker start failed or port not found",
    };
  }

  const { port, botUrl } = startResult;
  const target = `http://localhost:${port}`;
  const hint = [
    challenge.description ? `Challenge: ${challenge.description}` : "",
    challenge.hasXssBot
      ? `This challenge includes an XSS bot that will visit URLs you submit. Look for stored/reflected XSS.${botUrl ? `\nBot URL: ${botUrl}` : ""}`
      : "",
    `Category: ${challenge.category}`,
  ]
    .filter(Boolean)
    .join("\n");

  try {
    let report: any;
    if (useAgentic) {
      const dbPath = join(tmpdir(), `pwnkit-hackbench-${challenge.id}-${Date.now()}.db`);
      report = await agenticScan({
        config: {
          target,
          depth: "quick",
          format: "json",
          mode: "web",
          timeout: 60_000,
          runtime: runtimeArg as RuntimeMode,
          verbose: !!hint,
        },
        dbPath,
        challengeHint: hint,
      });
    } else {
      report = await scan({ target, depth: "quick", format: "json", mode: "web", timeout: 30_000 });
    }

    const findings = report.findings ?? [];
    const allText = JSON.stringify(report).toLowerCase();

    let flagFound = false;
    if (challenge.flag) {
      flagFound = allText.includes(challenge.flag.toLowerCase());
    }

    // Fallback: look for common flag patterns in findings
    if (!flagFound && findings.length > 0) {
      const flagRegex = /(?:flag|ev)\{[^}]{1,200}\}/gi;
      for (const f of findings) {
        const haystacks: (string | undefined)[] = [
          f.title,
          f.description,
          (f as any).analysis,
          (f as any).evidence?.request,
          (f as any).evidence?.response,
        ];
        for (const h of haystacks) {
          if (!h) continue;
          const matches = h.match(flagRegex);
          if (matches && challenge.flag) {
            for (const m of matches) {
              if (m.toLowerCase() === challenge.flag.toLowerCase()) {
                flagFound = true;
                break;
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
      category: challenge.category,
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

async function runChallenge(challenge: HackBenchChallenge): Promise<HackBenchResult> {
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
    const idSet = new Set(onlyIds);
    challenges = challenges.filter(
      (c) => idSet.has(c.id) || idSet.has(c.name.toLowerCase()),
    );
  }
  if (startAt > 0) challenges = challenges.slice(startAt);
  challenges = challenges.slice(0, limit);

  if (!jsonOutput) {
    console.log("\x1b[35m\x1b[1m  pwnkit x HackBench benchmark\x1b[0m");
    console.log(`  mode: ${useAgentic ? "agentic" : "baseline"}  challenges: ${challenges.length}/16  retries: ${retries}`);
    console.log("");
  }

  if (dryRun) {
    for (const c of challenges) {
      const bot = c.hasXssBot ? " [xss-bot]" : "";
      console.log(`  [${c.category}] ${c.id}  ${c.name}  flag=${c.flag ? "yes" : "MISSING"}${bot}`);
    }
    console.log(`\n  Total: ${challenges.length} challenges`);
    return;
  }

  const results: HackBenchResult[] = [];

  // Incremental persistence
  const incrementalDir = join(__dirname, "..", "results");
  mkdirSync(incrementalDir, { recursive: true });
  const incrementalPath = join(incrementalDir, "hackbench-incremental.jsonl");
  if (freshRun) writeFileSync(incrementalPath, "");

  for (const challenge of challenges) {
    if (!jsonOutput) {
      console.log(`\x1b[1m  >> ${challenge.id}\x1b[0m  [${challenge.category}]${challenge.hasXssBot ? " [xss-bot]" : ""}`);
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
  const startupFailures = results.filter((r) => r.error === "Docker start failed or port not found").length;
  const scanErrors = results.filter((r) => r.error && r.error !== "Docker start failed or port not found").length;
  const started = challenges.length - startupFailures;
  const totalAttackTurns = results.reduce((sum, r) => sum + (r.attackTurns ?? 0), 0);
  const totalEstimatedCostUsd = results.reduce((sum, r) => sum + (r.estimatedCostUsd ?? 0), 0);

  const report: HackBenchReport = {
    timestamp: new Date().toISOString(),
    mode: useAgentic ? "agentic" : "baseline",
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
    if (catMap.size > 1) {
      console.log("\n  By category:");
      for (const [cat, data] of [...catMap.entries()].sort((a, b) => b[1].total - a[1].total)) {
        console.log(`    ${cat.padEnd(15)} ${data.flags}/${data.total}`);
      }
    }
    console.log("");
  }

  // Save results (merge with existing)
  const resultsDir = join(__dirname, "..", "results");
  mkdirSync(resultsDir, { recursive: true });
  const latestPath = join(resultsDir, "hackbench-latest.json");

  if (!freshRun && existsSync(latestPath)) {
    try {
      const existing: HackBenchReport = JSON.parse(readFileSync(latestPath, "utf8"));
      const existingById = new Map(existing.results.map((r) => [r.id, r]));
      for (const r of report.results) existingById.set(r.id, r);
      const mergedResults = [...existingById.values()].sort((a, b) => a.id.localeCompare(b.id));

      const mergedStartupFailures = mergedResults.filter((r) => r.error === "Docker start failed or port not found").length;
      const mergedScanErrors = mergedResults.filter((r) => r.error && r.error !== "Docker start failed or port not found").length;
      const mergedStarted = mergedResults.length - mergedStartupFailures;

      const mergedReport: HackBenchReport = {
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

  if (!jsonOutput) console.log(`  Results saved to ${latestPath}`);
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("HackBench benchmark failed:", err);
    process.exit(1);
  });
