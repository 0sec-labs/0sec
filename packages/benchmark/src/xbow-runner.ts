#!/usr/bin/env node

/**
 * XBOW Benchmark Runner
 *
 * Runs pwnkit against the XBOW validation benchmarks (104 Docker CTF challenges).
 * Each challenge is a vulnerable web app with a hidden flag.
 *
 * Prerequisites:
 * - Docker + Docker Compose installed
 * - XBOW repo cloned: git clone https://github.com/0ca/xbow-validation-benchmarks-patched /tmp/xbow-benchmarks
 *   (or let the runner clone it for you via --benchmark-repo)
 *
 * Usage:
 *   tsx src/xbow-runner.ts                    # run all 104
 *   tsx src/xbow-runner.ts --limit 10         # first 10 only
 *   tsx src/xbow-runner.ts --tag xss          # filter by tag
 *   tsx src/xbow-runner.ts --level 1          # easy only
 *   tsx src/xbow-runner.ts --json             # JSON output
 *
 *   # Run against an arbitrary XBOW-compatible fork
 *   tsx src/xbow-runner.ts --benchmark-repo xbow-engineering/validation-benchmarks
 *   tsx src/xbow-runner.ts --benchmark-repo 0ca/xbow-validation-benchmarks-patched
 *   tsx src/xbow-runner.ts --benchmark-repo KeygraphHQ/xbow-validation-benchmarks
 *   tsx src/xbow-runner.ts --benchmark-repo https://github.com/foo/bar.git --benchmark-ref main
 */

import { execSync, spawnSync } from "node:child_process";
import { readFileSync, existsSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { scan, agenticScan, eventBus } from "@pwnkit/core";
import { tmpdir } from "node:os";
import type { RuntimeMode } from "@pwnkit/shared";
import { aggregateRuns, type RepeatAggregate, type RepeatRun } from "./wilson.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Trace sanitization ──
// Strip API keys, tokens, and other sensitive values that may have leaked
// into tool results (e.g. env var dumps, config file reads).

const SENSITIVE_PATTERNS = [
  // Generic API keys / tokens / secrets in env-var-like assignments
  /(?:API_KEY|API_SECRET|SECRET_KEY|ACCESS_KEY|AUTH_TOKEN|BEARER|JWT|SESSION_SECRET|PRIVATE_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|AZURE_OPENAI_API_KEY|OPENROUTER_API_KEY|AWS_SECRET_ACCESS_KEY)[\s]*[=:]\s*["']?([^\s"'\n]{8,})["']?/gi,
  // Bearer tokens in HTTP headers
  /(?:Authorization|X-Api-Key):\s*(?:Bearer\s+)?([A-Za-z0-9_\-.]{20,})/gi,
  // sk-... style keys (OpenAI, Anthropic, etc.)
  /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  // Azure-style keys (hex, 32+ chars)
  /\b[0-9a-f]{32,}\b/gi,
];

export function sanitizeTraceText(text: string): string {
  let sanitized = text;
  for (const pattern of SENSITIVE_PATTERNS) {
    // Reset lastIndex for global regexes
    pattern.lastIndex = 0;
    sanitized = sanitized.replace(pattern, (match) => {
      // Keep the key name / prefix, redact the value
      const eqIdx = match.search(/[=:]\s*/);
      if (eqIdx !== -1) {
        return match.slice(0, eqIdx + 1) + " [REDACTED]";
      }
      return "[REDACTED]";
    });
  }
  return sanitized;
}

function sanitizeTrace(trace: unknown[]): unknown[] {
  // Deep-clone and walk every string value in the trace, applying sanitization
  const raw = JSON.stringify(trace);
  const sanitized = sanitizeTraceText(raw);
  return JSON.parse(sanitized) as unknown[];
}

// ── CLI Args ──
const args = process.argv.slice(2);
const limit = args.includes("--limit") ? parseInt(args[args.indexOf("--limit") + 1]) : Infinity;
const tagFilter = args.includes("--tag") ? args[args.indexOf("--tag") + 1] : undefined;
const levelFilter = args.includes("--level") ? parseInt(args[args.indexOf("--level") + 1]) : undefined;
const jsonOutput = args.includes("--json");
const useAgentic = args.includes("--agentic");
const dryRun = args.includes("--dry-run");
const retries = args.includes("--retries") ? parseInt(args[args.indexOf("--retries") + 1]) : 1;
const startAt = args.includes("--start") ? parseInt(args[args.indexOf("--start") + 1]) : 0;
const onlyIds = args.includes("--only") ? args[args.indexOf("--only") + 1].split(",").map((s) => s.trim()) : undefined;
const saveFindings = args.includes("--save-findings");
const freshRun = args.includes("--fresh");
const whiteBox = args.includes("--white-box");
const runtimeArg = args.includes("--runtime") ? args[args.indexOf("--runtime") + 1] : "auto";
const modelsArg = args.includes("--models")
  ? args[args.indexOf("--models") + 1].split(",").map((s) => s.trim()).filter(Boolean)
  : [];

/**
 * Resolve the effective model identifier for single-model runs (no --models).
 *
 * Priority mirrors LlmApiRuntime.constructor in llm-api.ts:
 *   1. PWNKIT_MODEL env var (explicit override)
 *   2. Provider-specific env vars (AZURE_OPENAI_MODEL, etc.)
 *   3. Provider-specific defaults
 *
 * For multi-model runs (--models), each result already carries the model from
 * the loop, so this function is only used when modelsArg is empty.
 */
function resolveEffectiveModel(): string {
  const explicit = process.env.PWNKIT_MODEL;
  if (explicit) return explicit;

  // Mirror detectProvider priority: openrouter > anthropic > azure > openai
  if (process.env.OPENROUTER_API_KEY) {
    return process.env.OPENROUTER_MODEL ?? "anthropic/claude-sonnet-4.6";
  }
  if (process.env.ANTHROPIC_API_KEY) {
    return "claude-sonnet-4-6";
  }
  if (process.env.AZURE_OPENAI_API_KEY) {
    return process.env.AZURE_OPENAI_MODEL ?? "gpt-4o";
  }
  if (process.env.OPENAI_API_KEY) {
    return process.env.OPENAI_MODEL ?? "gpt-4o";
  }
  return "unknown";
}

// ── n=10 statistical evaluation harness (issue #81) ──
//
// `--repeat N` runs each enabled challenge N independent times and reports
// the per-attempt success rate with a 95% Wilson score interval. This is
// NOT the same as `--retries 3`: --retries retries a FAILING attempt to
// turn it into a "best-of-K" number; --repeat is honest statistical
// evaluation — every attempt counts, pass or fail, so we can tell whether
// a single solve was a generalizable signal or noise.
//
// `--repeat-cost-ceiling-usd $5.00` caps the cumulative LLM spend per
// (challenge) cell. Subsequent attempts of a challenge are skipped once
// the ceiling is reached and the aggregated result carries
// `costCeilingHit: true` so the reader knows N_effective < N_requested.
const repeatArg = args.includes("--repeat")
  ? Math.max(1, parseInt(args[args.indexOf("--repeat") + 1]))
  : 1;
const repeatCostCeilingUsd = args.includes("--repeat-cost-ceiling-usd")
  ? parseFloat(args[args.indexOf("--repeat-cost-ceiling-usd") + 1])
  : 5.0;

// ── Benchmark source (repo / ref / path) ──
//
// Precedence for locating the XBOW-compatible benchmark suite on disk:
//   1. --benchmark-path <dir>          explicit local path (no cloning)
//   2. XBOW_PATH env var               existing behavior, no cloning
//   3. --benchmark-repo <git-url>      clone into a workspace cache dir
//   4. default                         /tmp/xbow-benchmarks
//
// --benchmark-repo accepts either a GitHub short form ("owner/repo") or a
// full git URL ("https://github.com/owner/repo.git", "git@github.com:…").
// --benchmark-ref selects a branch/tag/sha (default: repo's default branch).
const benchmarkRepoArg = args.includes("--benchmark-repo")
  ? args[args.indexOf("--benchmark-repo") + 1]
  : undefined;
const benchmarkRefArg = args.includes("--benchmark-ref")
  ? args[args.indexOf("--benchmark-ref") + 1]
  : undefined;
const benchmarkPathArg = args.includes("--benchmark-path")
  ? args[args.indexOf("--benchmark-path") + 1]
  : undefined;

function normalizeBenchmarkRepo(repo: string): string {
  // Accept short form "owner/repo" and turn it into a full HTTPS URL.
  // Anything that looks like a URL or an SSH spec is passed through.
  if (/^[\w.-]+\/[\w.-]+$/.test(repo)) {
    return `https://github.com/${repo}.git`;
  }
  return repo;
}

function cacheDirForRepo(repo: string): string {
  // Derive a stable cache dir from the normalized repo URL so different
  // forks never collide. We intentionally use /tmp so CI's ephemeral disk
  // is the default location; XBOW_PATH still wins if explicitly set.
  const slug = repo
    .replace(/^https?:\/\//, "")
    .replace(/^git@/, "")
    .replace(/\.git$/, "")
    .replace(/[^\w.-]+/g, "_");
  return join(tmpdir(), `pwnkit-xbow-cache`, slug);
}

function ensureBenchmarkRepo(repo: string, ref: string | undefined): string {
  const url = normalizeBenchmarkRepo(repo);
  const dest = cacheDirForRepo(url);
  const benchDir = join(dest, "benchmarks");

  if (existsSync(benchDir)) {
    if (!jsonOutput) {
      console.log(`  using cached benchmark repo at ${dest}`);
    }
    return dest;
  }

  mkdirSync(dirname(dest), { recursive: true });
  const cloneArgs = ["clone", "--depth", "1"];
  if (ref) cloneArgs.push("--branch", ref);
  cloneArgs.push(url, dest);

  if (!jsonOutput) {
    console.log(`  cloning benchmark repo ${url}${ref ? ` @ ${ref}` : ""} → ${dest}`);
  }
  const res = spawnSync("git", cloneArgs, { stdio: "pipe" });
  if (res.status !== 0) {
    const stderr = res.stderr?.toString() ?? "";
    console.error(`Failed to clone benchmark repo ${url}: ${stderr}`);
    process.exit(1);
  }
  return dest;
}

function resolveXbowPath(): string {
  // 1. explicit --benchmark-path
  if (benchmarkPathArg) return benchmarkPathArg;
  // 2. XBOW_PATH env var (legacy — CI clones ahead of time and sets this)
  if (process.env.XBOW_PATH) return process.env.XBOW_PATH;
  // 3. --benchmark-repo
  if (benchmarkRepoArg) return ensureBenchmarkRepo(benchmarkRepoArg, benchmarkRefArg);
  // 4. legacy default
  return "/tmp/xbow-benchmarks";
}

const XBOW_PATH = resolveXbowPath();

// ── Types ──
export interface XbowChallenge {
  id: string;
  name: string;
  description: string;
  level: number;
  tags: string[];
  winCondition: string;
  path: string;
}

export interface XbowResult {
  id: string;
  name: string;
  level: number;
  tags: string[];
  model?: string;
  attackTurns?: number;
  estimatedCostUsd?: number;
  inputTokens?: number;
  outputTokens?: number;
  totalTokens?: number;
  passed: boolean;
  flagFound: boolean;
  findingsCount: number;
  durationMs: number;
  error?: string;
  // n=10 harness fields — present only when --repeat > 1. When --repeat 1
  // these are all omitted so the JSON shape is byte-compatible with the
  // pre-issue-#81 schema and existing consumers keep working.
  attempts?: number;
  passes?: number;
  successRate?: number;
  successRateCI95?: [number, number];
  meanTurns?: number;
  stdDevTurns?: number;
  meanCostUsd?: number;
  stdDevCostUsd?: number;
  perRun?: RepeatRun[];
  costCeilingHit?: boolean;
  // JIT skill usage events — present when PWNKIT_FEATURE_JIT_SKILLS=1
  // and the agent invokes list_skills / load_skill during the scan.
  // Used by the skills-ablation harness (pwnkit#460) to measure skill
  // adoption and token overhead.
  skillsLoaded?: Array<{ skill_id: string; name: string; estimated_tokens: number }>;
  skillListings?: number;
}

interface XbowReport {
  timestamp: string;
  mode: "baseline" | "agentic";
  runtime: string;
  model?: string;
  whiteBox: boolean;
  retries: number;
  challenges: number;
  built: number;
  started: number;
  passed: number;
  flags: number;
  totalAttackTurns: number;
  totalEstimatedCostUsd: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  totalTokens: number;
  buildFailures: number;
  startupFailures: number;
  scanErrors: number;
  results: XbowResult[];
  // Present only when --repeat > 1. Encodes the N=10 protocol so any
  // consumer of the JSON can tell at a glance that each result entry
  // summarizes multiple independent runs rather than a single attempt.
  repeatProtocol?: { N: number; costCeilingUsd: number };
}

function resultTotalTokens(result: XbowResult): number {
  return result.totalTokens ?? (result.inputTokens ?? 0) + (result.outputTokens ?? 0);
}

function chooseBetterResult(a: XbowResult, b: XbowResult): XbowResult {
  if (b.flagFound && !a.flagFound) return b;
  if (a.flagFound && !b.flagFound) return a;
  if (b.passed && !a.passed) return b;
  if (a.passed && !b.passed) return a;
  if (!!a.error !== !!b.error) return a.error ? b : a;
  if (b.findingsCount !== a.findingsCount) return b.findingsCount > a.findingsCount ? b : a;
  return b.durationMs < a.durationMs ? b : a;
}

// ── Load Challenges ──
function loadChallenges(): XbowChallenge[] {
  const benchDir = join(XBOW_PATH, "benchmarks");
  if (!existsSync(benchDir)) {
    console.error(`XBOW benchmarks not found at ${benchDir}`);
    console.error(`Either clone them manually:`);
    console.error(`  git clone https://github.com/0ca/xbow-validation-benchmarks-patched ${XBOW_PATH}`);
    console.error(`or re-run with --benchmark-repo <owner/repo> to have the runner clone for you.`);
    process.exit(1);
  }

  const dirs = readdirSync(benchDir).filter((d) => d.startsWith("XBEN-")).sort();
  const challenges: XbowChallenge[] = [];

  for (const dir of dirs) {
    const configPath = join(benchDir, dir, "benchmark.json");
    const yamlPath = join(benchDir, dir, "benchmark.yaml");

    let config: any;
    if (existsSync(configPath)) {
      config = JSON.parse(readFileSync(configPath, "utf8"));
    } else if (existsSync(yamlPath)) {
      // Simple YAML parser for the benchmark format
      const yaml = readFileSync(yamlPath, "utf8");
      config = {
        name: yaml.match(/name:\s*(.+)/)?.[1]?.trim() ?? dir,
        description: yaml.match(/content:\s*(.+)/)?.[1]?.trim() ?? "",
        level: parseInt(yaml.match(/level:\s*(\d)/)?.[1] ?? "2"),
        win_condition: yaml.match(/win_condition:\s*(\w+)/)?.[1] ?? "flag",
        tags: (yaml.match(/tags:\n((?:\s*-\s*.+\n?)*)/)?.[1] ?? "")
          .split("\n")
          .map((l: string) => l.replace(/^\s*-\s*/, "").trim())
          .filter(Boolean),
      };
    } else {
      continue;
    }

    challenges.push({
      id: dir,
      name: config.name ?? dir,
      description: config.description ?? "",
      level: parseInt(config.level ?? "2"),
      tags: config.tags ?? [],
      winCondition: config.win_condition ?? "flag",
      path: join(benchDir, dir),
    });
  }

  return challenges;
}

// ── Docker Helpers ──
function buildChallenge(challenge: XbowChallenge, flag: string): boolean {
  try {
    execSync(`docker compose build --build-arg FLAG=${flag}`, {
      cwd: challenge.path,
      stdio: "pipe",
      timeout: 120_000,
    });
    return true;
  } catch {
    return false;
  }
}

function startChallenge(challenge: XbowChallenge): number | null {
  try {
    // Stop any previously running containers to avoid port conflicts
    try { execSync("docker compose down -v", { cwd: challenge.path, stdio: "pipe", timeout: 15_000 }); } catch {}

    // 180s wait so DB-backed compose stacks (XBEN-099 and friends) survive
    // their first healthcheck cycle. Investigation in
    // docs/research/xben-099-investigation.md found the previous 60s cap
    // raced exactly with mongo's 30s healthcheck interval — pwnkit timed
    // out at almost the moment mongo would have gone healthy. Cheap
    // challenges still finish in seconds; only DB-backed ones approach
    // the new ceiling.
    execSync("docker compose up -d --wait --wait-timeout 150", {
      cwd: challenge.path,
      stdio: "pipe",
      timeout: 180_000,
    });

    // Get the mapped port — use docker compose ps to find ANY published port
    const output = execSync("docker compose ps --format json", {
      cwd: challenge.path,
      encoding: "utf8",
      timeout: 10_000,
    }).trim();

    // Parse JSON output to find the first published port
    for (const line of output.split("\n").filter(Boolean)) {
      try {
        const svc = JSON.parse(line);
        const ports = svc.Publishers ?? [];
        for (const p of ports) {
          if (p.PublishedPort && p.PublishedPort > 0) return p.PublishedPort;
        }
      } catch {}
    }

    // Fallback: try common service/port combos
    for (const combo of ["web 80", "app 80", "web 5000", "web 8000", "web 8080", "app 5003", "app 8080", "app 3000", "web 4567", "web 8081"]) {
      try {
        const out = execSync(`docker compose port ${combo}`, { cwd: challenge.path, encoding: "utf8", timeout: 3000 }).trim();
        const m = out.match(/:(\d+)$/);
        if (m) return parseInt(m[1]);
      } catch {}
    }

    return null;
  } catch {
    return null;
  }
}

function stopChallenge(challenge: XbowChallenge): void {
  try {
    execSync("docker compose down -v --remove-orphans", {
      cwd: challenge.path,
      stdio: "pipe",
      timeout: 30_000,
    });
  } catch {}
}

// ── Run Single Challenge ──
async function runChallengeOnce(challenge: XbowChallenge, model?: string): Promise<XbowResult> {
  // Resolve the model name eagerly so every result carries it, even for
  // single-model runs where the caller doesn't pass one explicitly.
  const effectiveModel = model ?? resolveEffectiveModel();
  const flag = `FLAG{${randomBytes(12).toString("hex")}}`;
  const start = Date.now();

  // Build
  if (!buildChallenge(challenge, flag)) {
    return { id: challenge.id, name: challenge.name, level: challenge.level, tags: challenge.tags, model: effectiveModel, passed: false, flagFound: false, findingsCount: 0, durationMs: Date.now() - start, error: "Docker build failed" };
  }

  // Start
  const port = startChallenge(challenge);
  if (!port) {
    stopChallenge(challenge);
    return { id: challenge.id, name: challenge.name, level: challenge.level, tags: challenge.tags, model: effectiveModel, passed: false, flagFound: false, findingsCount: 0, durationMs: Date.now() - start, error: "Docker start failed or port not found" };
  }

  const target = `http://localhost:${port}`;

  try {
    let report: any;

    // ── Skill event collector (pwnkit#460) ──
    // Subscribe to the event bus before the scan to capture skill_loaded
    // and skill_listed events for the ablation harness. The unsubscribe
    // function is called after the scan completes regardless of outcome.
    const skillEvents: { loaded: Array<{ skill_id: string; name: string; estimated_tokens: number }>; listings: number } = {
      loaded: [],
      listings: 0,
    };
    const unsubSkills = eventBus.subscribe({
      emit(type, payload) {
        if (type === "skill_loaded") {
          skillEvents.loaded.push({
            skill_id: String(payload.skill_id ?? ""),
            name: String(payload.name ?? ""),
            estimated_tokens: Number(payload.estimated_tokens ?? 0),
          });
        } else if (type === "skill_listed") {
          skillEvents.listings++;
        }
      },
    });

    try {
    if (useAgentic) {
      const dbPath = join(tmpdir(), `pwnkit-xbow-${challenge.id}-${Date.now()}.db`);
      // Pass challenge description as a hint — this is standard practice
      // (KinoSec, XBOW, and MAPTA all receive the challenge description)
      const hint = challenge.description ? `\nChallenge hint: ${challenge.description}` : "";
      // White-box: pass source code path so agent reads code before attacking
      const repoPath = whiteBox ? challenge.path : undefined;
      const effectiveRuntime = modelsArg.length > 0 ? "api" : runtimeArg;
      report = await agenticScan({
        config: {
          target,
          depth: "quick",
          format: "json",
          mode: "web",
          timeout: 60_000,
          runtime: effectiveRuntime as RuntimeMode,
          model: effectiveModel,
          verbose: hint ? true : false,
          repoPath,
        },
        dbPath,
        challengeHint: hint,
      });
    } else {
      report = await scan({ target, depth: "quick", format: "json", mode: "web", timeout: 30_000 });
    }
    } finally {
      unsubSkills();
    }

    const findings = report.findings ?? [];
    const allText = JSON.stringify(report).toLowerCase();
    let flagFound = allText.includes(flag.toLowerCase());

    // Defense-in-depth flag extraction. The 2026-04-06 ceiling analysis
    // identified XBEN-066 where the agent literally read the .env file
    // and the saved finding text contains `FLAG="flag{c8653e63-...}"`,
    // yet flagFound stayed false — strongly suggesting the JSON.stringify
    // path was missing data the per-finding text actually held (e.g.
    // suppressed-finding fields, evidence sub-objects, base64 wrappers).
    //
    // This pass walks every finding's text/description/evidence/analysis
    // explicitly and pulls out any `flag{...}` shaped strings. If any
    // matches the known challenge flag, we mark the challenge solved.
    // We also log every flag-shaped string we find that DOESN'T match
    // the known flag, so plumbing bugs in future challenges surface
    // loudly instead of silently.
    if (!flagFound && findings.length > 0) {
      const flagRegex = /flag\{[^}]{1,200}\}/gi;
      const knownFlagLower = flag.toLowerCase();
      const seen = new Set<string>();
      for (const f of findings) {
        // Walk every plausible text-bearing field on the finding object.
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
            if (seen.has(m)) continue;
            seen.add(m);
            if (m.toLowerCase() === knownFlagLower) {
              flagFound = true;
              console.log(
                `\x1b[32m  [flag-extractor] recovered flag for ${challenge.id} from finding text: ${m}\x1b[0m`,
              );
            } else {
              console.log(
                `\x1b[33m  [flag-extractor] found flag-shaped string in ${challenge.id} that does not match expected: ${m} (expected: ${flag})\x1b[0m`,
              );
            }
          }
        }
      }
    }

    // ── Persist conversation trace for transparency (issue #106) ──
    if (report.trace && Array.isArray(report.trace) && report.trace.length > 0) {
      try {
        const tracesDir = join(__dirname, "..", "results", "traces");
        mkdirSync(tracesDir, { recursive: true });
        const tracePayload = {
          challengeId: challenge.id,
          timestamp: new Date().toISOString(),
          flagFound,
          turns: report.benchmarkMeta?.attackTurns ?? 0,
          messages: sanitizeTrace(report.trace),
        };
        writeFileSync(
          join(tracesDir, `${challenge.id}-trace.json`),
          JSON.stringify(tracePayload, null, 2),
        );
      } catch (traceErr) {
        // Trace export is best-effort — never fail the benchmark because of it
        if (!jsonOutput) {
          console.log(`  [trace] failed to write trace for ${challenge.id}: ${traceErr instanceof Error ? traceErr.message : String(traceErr)}`);
        }
      }
    }

    return {
      id: challenge.id,
      name: challenge.name,
      level: challenge.level,
      tags: challenge.tags,
      model: effectiveModel,
      attackTurns: report.benchmarkMeta?.attackTurns,
      estimatedCostUsd: report.benchmarkMeta?.estimatedCostUsd,
      inputTokens: report.benchmarkMeta?.inputTokens,
      outputTokens: report.benchmarkMeta?.outputTokens,
      totalTokens: report.benchmarkMeta?.totalTokens,
      // XBOW uses flag extraction as the only valid pass condition.
      // Generic findings (header issues, fingerprinting) don't count.
      passed: flagFound,
      flagFound,
      findingsCount: findings.length,
      durationMs: Date.now() - start,
      // Save full findings for triage model training data
      ...(saveFindings && findings.length > 0 ? { findings } : {}),
      // JIT skill usage tracking (pwnkit#460)
      ...(skillEvents.loaded.length > 0 ? { skillsLoaded: skillEvents.loaded } : {}),
      ...(skillEvents.listings > 0 ? { skillListings: skillEvents.listings } : {}),
    };
  } catch (err) {
    return {
      id: challenge.id,
      name: challenge.name,
      level: challenge.level,
      tags: challenge.tags,
      model: effectiveModel,
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

async function runChallenge(challenge: XbowChallenge): Promise<XbowResult> {
  if (modelsArg.length === 0) {
    return runChallengeOnce(challenge);
  }

  if (!process.env.OPENROUTER_API_KEY) {
    return {
      id: challenge.id,
      name: challenge.name,
      level: challenge.level,
      tags: challenge.tags,
      passed: false,
      flagFound: false,
      findingsCount: 0,
      attackTurns: 0,
      estimatedCostUsd: 0,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      durationMs: 0,
      error: "Multi-model mode requires OPENROUTER_API_KEY",
    };
  }

  let best: XbowResult | null = null;
  for (const model of modelsArg) {
    let result = await runChallengeOnce(challenge, model);

    for (let attempt = 2; attempt <= retries && !result.flagFound && !result.error; attempt++) {
      if (!jsonOutput) {
        process.stdout.write(`  ... ${model} retry ${attempt}/${retries}\n`);
      }
      result = await runChallengeOnce(challenge, model);
    }

    best = best ? chooseBetterResult(best, result) : result;
    if (best.flagFound) break;
  }

  return best!;
}

/**
 * n=10 repeat harness (issue #81).
 *
 * Runs a single challenge `repeat` times, aborts early if the cumulative
 * cost exceeds `costCeilingUsd`, and folds the per-run results into one
 * XbowResult that carries both the aggregated Wilson-CI summary fields
 * AND the legacy single-shot fields (populated from the first attempt)
 * for backward compatibility with consumers that don't know about the
 * new schema.
 */
export async function runChallengeRepeated(
  challenge: XbowChallenge,
  repeat: number,
  costCeilingUsd: number,
  runOne: (c: XbowChallenge) => Promise<XbowResult> = runChallenge,
): Promise<XbowResult> {
  const runs: RepeatRun[] = [];
  const rawResults: XbowResult[] = [];
  let cumulativeCost = 0;
  let costCeilingHit = false;

  for (let i = 0; i < repeat; i++) {
    const r = await runOne(challenge);
    rawResults.push(r);
    runs.push({
      runIndex: i,
      passed: r.flagFound,
      turns: r.attackTurns ?? 0,
      cost: r.estimatedCostUsd ?? 0,
      durationMs: r.durationMs,
    });
    cumulativeCost += r.estimatedCostUsd ?? 0;

    if (!jsonOutput) {
      const icon = r.flagFound ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m";
      const cost = r.estimatedCostUsd ? ` $${r.estimatedCostUsd.toFixed(3)}` : "";
      process.stdout.write(
        `    [repeat ${i + 1}/${repeat}] ${icon}  ${r.attackTurns ?? 0} turns${cost}  cumulative $${cumulativeCost.toFixed(2)}\n`,
      );
    }

    if (cumulativeCost >= costCeilingUsd && i + 1 < repeat) {
      costCeilingHit = true;
      if (!jsonOutput) {
        process.stdout.write(
          `    \x1b[33m[repeat] cost ceiling $${costCeilingUsd.toFixed(2)} hit after ${i + 1}/${repeat} runs — stopping this cell\x1b[0m\n`,
        );
      }
      break;
    }
  }

  const agg: RepeatAggregate = aggregateRuns(runs, { costCeilingHit });

  // Legacy fields come from the first attempt so readers that don't know
  // about the aggregate schema still see a recognizable single-run shape.
  const first = rawResults[0];
  return {
    ...first,
    // passed reflects "did any attempt find the flag?" so the top-level
    // `passed` counter still means something in repeat mode. The honest
    // per-attempt number lives in successRate.
    passed: agg.passes > 0,
    flagFound: agg.passes > 0,
    attempts: agg.attempts,
    passes: agg.passes,
    successRate: agg.successRate,
    successRateCI95: agg.successRateCI95,
    meanTurns: agg.meanTurns,
    stdDevTurns: agg.stdDevTurns,
    meanCostUsd: agg.meanCostUsd,
    stdDevCostUsd: agg.stdDevCostUsd,
    perRun: agg.perRun,
    costCeilingHit: agg.costCeilingHit,
  };
}

// ── Main ──
async function main() {
  if (modelsArg.length > 0 && !jsonOutput) {
    console.log(`  models: ${modelsArg.join(", ")}`);
  }

  let challenges = loadChallenges();

  if (tagFilter) challenges = challenges.filter((c) => c.tags.includes(tagFilter));
  if (levelFilter) challenges = challenges.filter((c) => c.level === levelFilter);
  if (onlyIds) {
    // --only XBEN-010,XBEN-051,XBEN-066 — run only these specific challenges
    const idSet = new Set(onlyIds.map((id) => {
      // Normalize: accept XBEN-010 or XBEN-010-24 or 010
      const num = id.replace(/^XBEN-/, "").replace(/-24$/, "");
      return num;
    }));
    challenges = challenges.filter((c) => {
      const num = c.id.replace(/^XBEN-/, "").replace(/-24$/, "");
      return idSet.has(num);
    });
  }
  if (startAt > 0) challenges = challenges.slice(startAt);
  challenges = challenges.slice(0, limit);

  if (!jsonOutput) {
    console.log("\x1b[31m\x1b[1m  pwnkit x XBOW benchmark\x1b[0m");
    console.log(`  mode: ${useAgentic ? "agentic" : "baseline"}  challenges: ${challenges.length}/104`);
    console.log("");
  }

  if (dryRun) {
    for (const c of challenges) {
      const levelLabel = ["", "easy", "med", "hard"][c.level] ?? "?";
      console.log(`  [${levelLabel}] ${c.id}  ${c.name}  [${c.tags.join(", ")}]`);
    }
    return;
  }

  const results: XbowResult[] = [];

  for (const challenge of challenges) {
    let result: XbowResult;

    if (repeatArg > 1) {
      // n=10 statistical evaluation path (issue #81). Each attempt is
      // independent — no early stopping on success, no "retry until it
      // passes" — so we can report a per-attempt success rate honestly.
      if (!jsonOutput) {
        process.stdout.write(
          `  [repeat] ${challenge.id}: ${repeatArg} attempts, cost ceiling $${repeatCostCeilingUsd.toFixed(2)}\n`,
        );
      }
      result = await runChallengeRepeated(challenge, repeatArg, repeatCostCeilingUsd);
    } else {
      result = await runChallenge(challenge);

      // Retry on failure if --retries > 1 (non-deterministic model may succeed on retry).
      // This is the legacy best-of-K behavior — see --repeat for the honest statistical path.
      for (let attempt = 2; attempt <= retries && modelsArg.length === 0 && !result.flagFound && !result.error; attempt++) {
        if (!jsonOutput) {
          process.stdout.write(`  ... retry ${attempt}/${retries}\n`);
        }
        result = await runChallenge(challenge);
      }
    }

    results.push(result);

    if (!jsonOutput) {
      const icon = result.flagFound ? "\x1b[32mFLAG\x1b[0m" : result.passed ? "\x1b[33mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m";
      const levelLabel = ["", "easy", "med", "hard"][challenge.level] ?? "?";
      const time = `${(result.durationMs / 1000).toFixed(0)}s`;
      console.log(`  ${icon} [${levelLabel}] ${challenge.name.slice(0, 50).padEnd(50)} ${result.findingsCount} findings  ${time}${result.error ? `  err: ${result.error.slice(0, 40)}` : ""}`);
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
  const totalInputTokens = results.reduce((sum, r) => sum + (r.inputTokens ?? 0), 0);
  const totalOutputTokens = results.reduce((sum, r) => sum + (r.outputTokens ?? 0), 0);
  const totalTokens = results.reduce((sum, r) => sum + resultTotalTokens(r), 0);
  const report: XbowReport = {
    timestamp: new Date().toISOString(),
    mode: useAgentic ? "agentic" : "baseline",
    runtime: useAgentic
      ? (modelsArg.length > 0 ? `api(best-of-${modelsArg.length})` : runtimeArg)
      : "baseline",
    model: modelsArg.length > 0 ? modelsArg.join(",") : resolveEffectiveModel(),
    whiteBox,
    retries,
    challenges: challenges.length,
    built,
    started,
    passed,
    flags,
    totalAttackTurns,
    totalEstimatedCostUsd,
    totalInputTokens,
    totalOutputTokens,
    totalTokens,
    buildFailures,
    startupFailures,
    scanErrors,
    results,
    ...(repeatArg > 1
      ? { repeatProtocol: { N: repeatArg, costCeilingUsd: repeatCostCeilingUsd } }
      : {}),
  };

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log("\n  ──────────────────────────────────────");
    console.log(`  Detection:       \x1b[1m${passed}/${challenges.length}\x1b[0m  (${(passed / challenges.length * 100).toFixed(1)}%)`);
    console.log(`  Flag extraction: \x1b[1m${flags}/${challenges.length}\x1b[0m  (${(flags / challenges.length * 100).toFixed(1)}%)`);
    console.log(`  Built / started: \x1b[1m${built}/${started}\x1b[0m  (build fails: ${buildFailures}, start fails: ${startupFailures})`);
    if (totalAttackTurns > 0) {
      console.log(`  Attack turns:    \x1b[1m${totalAttackTurns}\x1b[0m`);
    }
    if (totalEstimatedCostUsd > 0) {
      console.log(`  Est. cost:       \x1b[1m$${totalEstimatedCostUsd.toFixed(2)}\x1b[0m`);
    }
    console.log(`  Total time:      ${(results.reduce((a, r) => a + r.durationMs, 0) / 1000).toFixed(0)}s`);

    // By tag
    const tagMap = new Map<string, { total: number; passed: number }>();
    for (const r of results) {
      for (const tag of r.tags) {
        const t = tagMap.get(tag) ?? { total: 0, passed: 0 };
        t.total++;
        if (r.passed) t.passed++;
        tagMap.set(tag, t);
      }
    }
    console.log("\n  By tag:");
    for (const [tag, data] of [...tagMap.entries()].sort((a, b) => b[1].total - a[1].total)) {
      console.log(`    ${tag.padEnd(25)} ${data.passed}/${data.total}`);
    }
    console.log("");
  }

  // Save results — merge with existing file so partial/resumed runs accumulate
  const resultsDir = join(__dirname, "..", "results");
  mkdirSync(resultsDir, { recursive: true });
  const latestPath = join(resultsDir, "xbow-latest.json");

  if (!freshRun && existsSync(latestPath)) {
    try {
      const existing: XbowReport = JSON.parse(readFileSync(latestPath, "utf8"));
      // Build a map of existing results keyed by challenge ID
      const existingById = new Map(existing.results.map((r) => [r.id, r]));

      // Merge: new results overwrite existing ones by ID, existing ones not in
      // the current run are preserved
      for (const r of report.results) {
        existingById.set(r.id, r);
      }
      const mergedResults = [...existingById.values()].sort((a, b) => a.id.localeCompare(b.id));

      // Recompute summary stats from merged results
      const mergedBuildFailures = mergedResults.filter((r) => r.error === "Docker build failed").length;
      const mergedStartupFailures = mergedResults.filter((r) => r.error === "Docker start failed or port not found").length;
      const mergedScanErrors = mergedResults.filter((r) => r.error && r.error !== "Docker build failed" && r.error !== "Docker start failed or port not found").length;
      const mergedBuilt = mergedResults.length - mergedBuildFailures;
      const mergedStarted = mergedBuilt - mergedStartupFailures;
      const mergedTotalAttackTurns = mergedResults.reduce((sum, r) => sum + (r.attackTurns ?? 0), 0);
      const mergedTotalEstimatedCostUsd = mergedResults.reduce((sum, r) => sum + (r.estimatedCostUsd ?? 0), 0);
      const mergedTotalInputTokens = mergedResults.reduce((sum, r) => sum + (r.inputTokens ?? 0), 0);
      const mergedTotalOutputTokens = mergedResults.reduce((sum, r) => sum + (r.outputTokens ?? 0), 0);
      const mergedTotalTokens = mergedResults.reduce((sum, r) => sum + resultTotalTokens(r), 0);

      const mergedReport: XbowReport = {
        ...report,
        timestamp: new Date().toISOString(),
        challenges: mergedResults.length,
        built: mergedBuilt,
        started: mergedStarted,
        passed: mergedResults.filter((r) => r.passed).length,
        flags: mergedResults.filter((r) => r.flagFound).length,
        totalAttackTurns: mergedTotalAttackTurns,
        totalEstimatedCostUsd: mergedTotalEstimatedCostUsd,
        totalInputTokens: mergedTotalInputTokens,
        totalOutputTokens: mergedTotalOutputTokens,
        totalTokens: mergedTotalTokens,
        buildFailures: mergedBuildFailures,
        startupFailures: mergedStartupFailures,
        scanErrors: mergedScanErrors,
        results: mergedResults,
      };

      writeFileSync(latestPath, JSON.stringify(mergedReport, null, 2));
    } catch {
      // Existing file is corrupt — overwrite it
      writeFileSync(latestPath, JSON.stringify(report, null, 2));
    }
  } else {
    writeFileSync(latestPath, JSON.stringify(report, null, 2));
  }
}

// Only run main() when this file is executed directly (via `tsx xbow-runner.ts`).
// When the runner is imported by a unit test we want to exercise pure
// helpers like runChallengeRepeated without booting Docker or the agent.
const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) main()
  .then(() => {
    // Force exit — async resources (DB connections, event loop timers from
    // the agentic scanner, browser instances) sometimes keep the process
    // alive after main() completes. We've already written results to disk,
    // so exiting cleanly here is safe and prevents CI timeouts.
    process.exit(0);
  })
  .catch((err) => {
    console.error("XBOW benchmark failed:", err);
    process.exit(1);
  });
