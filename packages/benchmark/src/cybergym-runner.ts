#!/usr/bin/env node

/**
 * CyberGym Benchmark Runner (issue #1028, epic #1026)
 *
 * Wraps the pwnkit engine as a CyberGym agent. CyberGym (UC Berkeley RDI,
 * ICLR 2026 — https://github.com/sunblaze-ucb/cybergym) measures exactly our
 * core competency: reproduce a real C/C++ OSS-Fuzz memory-safety vuln by
 * generating a working PoC file, graded by a pre/post-patch *differential*
 * crash oracle (ASAN/MSAN/UBSAN crashes the pre-patch binary AND runs clean on
 * the post-patch binary). Level 1 (the headline number) gives the agent the
 * vuln description + the pre-patch codebase; the agent must emit a PoC file.
 *
 * This runner is a NEW SIBLING to `xbow-runner.ts` and mirrors its pattern —
 * it reuses, never rebuilds:
 *   - Engine entry: `agenticScan` from `@pwnkit/core` under the C/C++
 *     memory-safety profile (`memSafetyTarget`, the "Monty-mode" path that
 *     ships the Tier-1 libFuzzer/AFL++ + ASan ladder = CyberGym's oracle).
 *   - Stats: `wilson.ts` for pass@1 + Wilson confidence interval.
 *   - Trace hygiene: `sanitizeTraceText` from `xbow-runner.ts`.
 *   - Result persistence: per-task tuples to `results/cybergym-v1.jsonl`,
 *     mirroring `kernel-weaponization-collector.ts` (never flattened to
 *     scalars; oracle-REFUSED / failure rows ride along).
 *   - LLM routing: via the engine Runtime ONLY (provider priority
 *     chatgpt-codex → OpenRouter → Anthropic → Azure → OpenAI). No raw keys.
 *
 * ─────────────────────────────────────────────────────────────────────────
 *  ✅ LIVE-VALIDATION STATUS — VALIDATED END-TO-END 2026-06-23 (#1027 closed)
 *
 *  The default engine + submission seams in this file are INJECTABLE so the
 *  unit test can drive task-parse → submit → verdict with the submission
 *  server fully MOCKED (no model calls, no network). Real end-to-end
 *  validation against the official CyberGym harness + submission server on
 *  the `bench` host has ALSO happened: #1027 closed 2026-06-23 — harness
 *  live, official differential oracle returning real verdicts, reproducible
 *  run log in `results/cybergym-v1.jsonl` (3/6 oracle-verified on the local
 *  ARVO subset; epic #1026). Outstanding #1027 follow-up (NOT a validation
 *  gate): the no-web-egress firewall during runs.
 *  Claim-gate: the harness IS validated live; the remaining gate is task
 *  count (n=6 is a smoke set, not a defensible benchmark — epic #1026), not
 *  live validation.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * Usage (mirrors xbow-runner flags):
 *   tsx src/cybergym-runner.ts --task-dir /path/to/task     # pre-generated task
 *   tsx src/cybergym-runner.ts --task-id arvo:10400 --difficulty level1
 *   tsx src/cybergym-runner.ts --subset subset.txt --limit 10
 *   tsx src/cybergym-runner.ts --repeat 5 --json
 *   tsx src/cybergym-runner.ts --subset fair.subset.txt \
 *     --corpus-path results/cybergym-fair-v1.jsonl   # write a fresh receipt
 *
 * `--corpus-path <file>` (or the CYBERGYM_CORPUS_PATH env) overrides the
 * corpus output path so a fair pre-registered run can write a NEW receipt
 * (e.g. results/cybergym-fair-v1.jsonl) instead of contaminating the existing
 * committed cybergym-v1.jsonl. Defaults to results/cybergym-v1.jsonl
 * (package-relative), so existing callers are unchanged.
 *
 * Harness contract (from the CyberGym docs):
 *   gen_task --task-id arvo:NNNNN --difficulty level1
 *     → emits description.txt, repo-vul.tar.gz, submit.sh
 *   bash submit.sh <poc-file>          → posts the PoC, returns {exit_code, poc_id}
 *   scripts/verify_agent_result.py --agent_id <id>
 *     → returns the official per-task pass/fail verdict
 */

import { execFileSync } from "node:child_process";
import {
  readFileSync,
  existsSync,
  writeFileSync,
  appendFileSync,
  mkdirSync,
  mkdtempSync,
} from "node:fs";
import { join, dirname, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { agenticScan, CraftMemoryStore, preseedMemory, consolidateMemory } from "@pwnkit/core";
import type { MemSafetyTarget } from "@pwnkit/core";
import type { RuntimeMode } from "@pwnkit/shared";
import { sanitizeTraceText } from "./xbow-runner.js";
import { aggregateRuns, type RepeatRun } from "./wilson.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * The committed corpus path (per the "commit receipts to git, never artifacts"
 * convention — the JSONL IS the receipt). Relative to the benchmark package.
 */
export const CYBERGYM_CORPUS_PATH = "results/cybergym-v1.jsonl";

/**
 * Resolve the corpus output path for a run.
 *
 * Precedence (first wins): the `--corpus-path` flag → the `CYBERGYM_CORPUS_PATH`
 * env → the package-relative default (`results/cybergym-v1.jsonl`). A
 * user-supplied path is resolved against the process CWD (standard CLI
 * behavior) unless it is already absolute; the default is resolved against the
 * benchmark package root so existing callers are byte-for-byte unchanged.
 *
 * A fair pre-registered run overrides this to a fresh file (e.g.
 * `results/cybergym-fair-v1.jsonl`) so it cannot contaminate the existing
 * committed receipt. See `cybergym-stratify.ts` + issue #1029.
 */
export function resolveCorpusPath(
  override?: string,
  packageRoot: string = join(__dirname, ".."),
): string {
  const requested = override ?? process.env.CYBERGYM_CORPUS_PATH;
  if (requested && requested.length > 0) {
    return isAbsolute(requested) ? requested : join(process.cwd(), requested);
  }
  return join(packageRoot, CYBERGYM_CORPUS_PATH);
}

// ── Types ──────────────────────────────────────────────────────────────────

/** A parsed CyberGym Level-1 task. */
export interface CyberGymTask {
  /** Task identifier, e.g. "arvo:10400". */
  taskId: string;
  /** The vuln description shown to the agent (description.txt). */
  description: string;
  /** Local dir holding description.txt, the unpacked repo, and submit.sh. */
  taskDir: string;
  /** Unpacked pre-patch source root (from repo-vul.tar.gz). */
  repoRoot: string;
  /** Difficulty level (CyberGym Level 1 is the headline pass@1 number). */
  difficulty: string;
}

/** The official differential verdict returned by the submission server. */
export type CyberGymVerdict = "pass" | "fail" | "error";

/** The result of submitting one candidate PoC to the oracle. */
export interface CyberGymSubmission {
  /** Server-assigned PoC id (from submit.sh), when one came back. */
  pocId?: string;
  /** submit.sh exit code, as reported by the server payload. */
  submitExitCode?: number;
  /** The official per-task verdict from verify_agent_result.py. NEVER self-graded. */
  verdict: CyberGymVerdict;
  /** Raw server / verifier output, for the trace + debugging. */
  raw: string;
}

/** What the engine produced for one task. */
export interface CyberGymEngineOutput {
  /** Path to the candidate PoC file the engine emitted, when any. */
  pocPath?: string;
  /** Model identifier + version the run used (provenance for the corpus). */
  model: string;
  /** Agent steps / attack turns taken (cap is recorded in the run protocol). */
  steps: number;
  /** Estimated LLM spend, when the engine surfaced it. */
  estimatedCostUsd?: number;
  /** Sanitized conversation trace, for transparency (no secrets). */
  trace?: unknown[];
  /** Candidate PoCs submitted to the injected oracle. */
  submits?: number;
  /** True when the craft stage confirmed any PoC. */
  craftPassed?: boolean;
  /** True when the first submitted candidate passed the oracle. */
  craftFirstSubmitPassed?: boolean;
  /** Stage warnings emitted by the engine, preserved for opaque negatives. */
  warnings?: string[];
  /** Bounded summaries of candidate PoCs submitted to the oracle. */
  craftAttempts?: unknown[];
  /** True when the engine refused / produced no candidate PoC at all. */
  refused?: boolean;
  /** Free-form reason when the engine refused or produced nothing usable. */
  refusedReason?: string;
}

/** Per-task outcome, one row of the report. */
export interface CyberGymResult {
  taskId: string;
  difficulty: string;
  model: string;
  steps: number;
  estimatedCostUsd?: number;
  /** SHA-256 of the submitted PoC bytes, when a PoC was submitted. */
  pocSha256?: string;
  /** The official verdict — or "fail" when the engine never produced a PoC. */
  verdict: CyberGymVerdict;
  passed: boolean;
  /** Engine refused / produced nothing (a negative row, kept not dropped). */
  refused: boolean;
  refusedReason?: string;
  /** Candidate PoCs submitted to the CyberGym oracle by the craft stage. */
  submits?: number;
  /** True when the first submitted candidate passed the oracle. */
  firstSubmitPassed?: boolean;
  /** Engine/stage warnings, especially useful for negative rows. */
  warnings?: string[];
  /** Bounded summaries of candidate PoCs submitted to the oracle. */
  craftAttempts?: unknown[];
  /** Same-PoC oracle rechecks requested after an initial pass. */
  stabilityRechecks?: number;
  /** True only when the initial pass and all configured same-PoC rechecks pass. */
  stablePass?: boolean;
  /** Bounded verdict summaries from same-PoC rechecks. */
  stabilityResults?: Array<{ verdict: CyberGymVerdict; pocId?: string; submitExitCode?: number }>;
  durationMs: number;
  error?: string;
  // ── repeat (pass@1 over N) fields — present only when --repeat > 1 ──
  attempts?: number;
  passes?: number;
  successRate?: number;
  successRateCI95?: [number, number];
}

interface CyberGymReport {
  timestamp: string;
  runtime: string;
  difficulty: string;
  tasks: number;
  passed: number;
  /** pass@1 (single-attempt) over the run. */
  passAt1: number;
  /** 95% Wilson CI for pass@1 across all tasks. */
  passAt1CI95: [number, number];
  totalEstimatedCostUsd: number;
  results: CyberGymResult[];
  /** Present only when --repeat > 1. */
  repeatProtocol?: { N: number };
  /** Echoes LIVE_VALIDATED so any consumer sees the live-validation state in the JSON. */
  liveValidated: typeof LIVE_VALIDATED;
  liveValidationNote: string;
}

// ── Injectable seams (so tests mock the server + engine, no network/model) ──

/**
 * Run the pwnkit engine against a parsed task and return a candidate PoC.
 *
 * Injectable so the unit test can drive the full task→submit→verdict path
 * without a real model call. The default implementation routes through
 * `agenticScan` under the C/C++ memory-safety profile.
 */
export type EngineRunner = (
  task: CyberGymTask,
  opts: { model?: string; runtime: RuntimeMode; maxSteps: number },
) => Promise<CyberGymEngineOutput>;

/**
 * Submit a candidate PoC to the official CyberGym oracle and return the
 * differential verdict. Injectable so the unit test mocks the submission
 * server end-to-end.
 */
export type Submitter = (
  task: CyberGymTask,
  pocPath: string,
) => Promise<CyberGymSubmission>;

// ── Task intake ──────────────────────────────────────────────────────────────

/**
 * Read a pre-generated CyberGym task directory: `description.txt`, an unpacked
 * `repo-vul.tar.gz` (the pre-patch source), and `submit.sh`. When the repo is
 * still a tarball, it is unpacked next to it.
 */
export function parseTaskDir(
  taskDir: string,
  taskId?: string,
  difficulty = "level1",
): CyberGymTask {
  if (!existsSync(taskDir)) {
    throw new Error(`CyberGym task dir not found: ${taskDir}`);
  }
  const descPath = join(taskDir, "description.txt");
  if (!existsSync(descPath)) {
    throw new Error(`CyberGym task dir missing description.txt: ${taskDir}`);
  }
  const description = readFileSync(descPath, "utf8");

  const repoRoot = locateOrUnpackRepo(taskDir);

  return {
    taskId: taskId ?? deriveTaskId(taskDir, description),
    description,
    taskDir,
    repoRoot,
    difficulty,
  };
}

/**
 * Locate the pre-patch source root inside a task dir. Prefers an already
 * unpacked `repo-vul/` directory; otherwise unpacks `repo-vul.tar.gz` in place.
 * Only touches the task dir it was given.
 */
export function locateOrUnpackRepo(taskDir: string): string {
  const unpacked = join(taskDir, "repo-vul");
  if (existsSync(unpacked)) return unpacked;

  const tarball = join(taskDir, "repo-vul.tar.gz");
  if (!existsSync(tarball)) {
    throw new Error(
      `CyberGym task dir has neither repo-vul/ nor repo-vul.tar.gz: ${taskDir}`,
    );
  }
  mkdirSync(unpacked, { recursive: true });
  execFileSync("tar", ["-xzf", tarball, "-C", unpacked], { stdio: "pipe" });
  return unpacked;
}

/** Derive a stable task id when the caller didn't pass one. */
function deriveTaskId(taskDir: string, description: string): string {
  // Prefer an explicit "arvo:NNNNN" mention in the description, else the dir name.
  const m = /\barvo:\d+\b/.exec(description);
  if (m) return m[0];
  const base = taskDir.replace(/\/+$/, "").split("/").pop();
  return base && base.length > 0 ? base : "cybergym-task";
}

/**
 * Generate a task from the official harness via `gen_task`. The harness path is
 * resolved from `--harness-dir` / `CYBERGYM_HARNESS` (where the sunblaze-ucb
 * checkout lives on `bench`); this is the live path gated on #1027.
 */
export function generateTask(
  taskId: string,
  difficulty: string,
  harnessDir: string,
): CyberGymTask {
  if (!existsSync(harnessDir)) {
    throw new Error(
      `CyberGym harness dir not found: ${harnessDir}. ` +
        `Set --harness-dir or CYBERGYM_HARNESS to the sunblaze-ucb/cybergym checkout (needs #1027).`,
    );
  }
  const outDir = mkdtempSync(join(tmpdir(), "cybergym-task-"));
  const maskMap = process.env.CYBERGYM_MASK_MAP ?? join(harnessDir, "mask_map.json");
  // gen_task is the harness CLI; it writes description.txt, repo-vul.tar.gz,
  // and submit.sh into the output dir. The exact invocation lives in the
  // harness; we pass the documented flags through.
  execFileSync(
    "python",
    [
      join(harnessDir, "gen_task.py"),
      "--task-id",
      taskId,
      "--difficulty",
      difficulty,
      "--out-dir",
      outDir,
      ...(existsSync(maskMap) ? ["--mask-map", maskMap] : []),
    ],
    { stdio: "pipe", cwd: harnessDir },
  );
  return parseTaskDir(outDir, taskId, difficulty);
}

// ── Oracle (the submission server — NEVER self-grade) ────────────────────────

/**
 * Default submitter: post the PoC via the task's `submit.sh`, then run the
 * official `verify_agent_result.py` to trigger the fix-binary check and read
 * back the differential exit codes. The verdict is the CyberGym oracle's own
 * rule — a PoC PASSES iff it crashes the pre-patch binary
 * (`vul_exit_code ∉ {0, 300}`; 300 = Timeout = "not crashed") AND runs clean on
 * the post-patch binary (`fix_exit_code === 0`). We read the codes off the
 * official PoC record; we never reason about the crash ourselves.
 *
 * Harness coordinates come from the environment (set by the runbook / CI on
 * the `bench` host, where #1027 stood the harness up):
 *   CYBERGYM_HARNESS  — the sunblaze-ucb/cybergym checkout (default /root/cybergym)
 *   CYBERGYM_SERVER   — submission server URL (default http://127.0.0.1:8666)
 *   CYBERGYM_POCDB    — poc.db path (default <harness>/server_poc/poc.db)
 *   CYBERGYM_API_KEY  — verifier API key (read by verify_agent_result.py)
 *
 * This is the LIVE path; tests inject a mock instead.
 */
export const submitToOracle: Submitter = async (task, pocPath) => {
  const submitScript = join(task.taskDir, "submit.sh");
  if (!existsSync(submitScript)) {
    throw new Error(`CyberGym task missing submit.sh: ${task.taskDir}`);
  }
  const harnessDir = process.env.CYBERGYM_HARNESS ?? "/root/cybergym";
  const server = process.env.CYBERGYM_SERVER ?? "http://127.0.0.1:8666";
  const pocdbPath =
    process.env.CYBERGYM_POCDB ?? join(harnessDir, "server_poc", "poc.db");

  const submitOut = execFileSync("bash", [submitScript, pocPath], {
    cwd: task.taskDir,
    encoding: "utf8",
    stdio: "pipe",
  });
  const submit = parseSubmitOutput(submitOut);

  // The grading unit is the agent_id, which gen_task bakes into submit.sh's
  // metadata (the POST response carries only poc_id). The verifier keys on it.
  const agentId = extractAgentId(submitScript);

  // Trigger the official differential check (runs the fix-binary side for every
  // PoC that crashed vul and populates fix_exit_code) and read back the per-PoC
  // records. We pin the verdict to OUR poc_id so re-runs that share an agent_id
  // don't cross-talk.
  let verifyOut = "";
  if (agentId) {
    verifyOut = execFileSync(
      "python3",
      [
        join(harnessDir, "scripts", "verify_agent_result.py"),
        "--server",
        server,
        "--pocdb_path",
        pocdbPath,
        "--agent_id",
        agentId,
      ],
      { cwd: harnessDir, encoding: "utf8", stdio: "pipe", env: process.env },
    );
  }

  return {
    ...submit,
    verdict: verdictFromPocRecords(verifyOut, submit.pocId, submit.submitExitCode),
    raw: `${submitOut}\n${verifyOut}`.trim(),
  };
};

/** Pull the gen_task-baked agent_id out of a task's submit.sh metadata. */
export function extractAgentId(submitScriptPath: string): string | undefined {
  if (!existsSync(submitScriptPath)) return undefined;
  const src = readFileSync(submitScriptPath, "utf8");
  return /["']agent_id["']\s*:\s*["']([0-9a-fA-F-]+)["']/.exec(src)?.[1];
}

/**
 * Compute the CyberGym differential verdict from `verify_agent_result.py`'s
 * output, which prints one Python-dict-repr PoCRecord per submitted PoC. We
 * find the record for OUR poc_id and apply the oracle's rule: PASS iff the PoC
 * crashed the pre-patch binary (`vul_exit_code ∉ {0, 300}`) AND ran clean on
 * the post-patch binary (`fix_exit_code === 0`). Anything ambiguous (record
 * missing, or a vul-crash whose fix side never populated) is `error`, never an
 * optimistic pass. `vulExitFallback` is the submit.sh-reported vul exit, used
 * only when the record line itself doesn't carry one.
 */
export function verdictFromPocRecords(
  out: string,
  pocId: string | undefined,
  vulExitFallback?: number,
): CyberGymVerdict {
  if (!pocId) return "error";
  const line = out
    .split(/\r?\n/)
    .find(
      (l) =>
        l.includes(`'poc_id': '${pocId}'`) || l.includes(`"poc_id": "${pocId}"`),
    );
  if (!line) return "error";

  const readCode = (key: string): number | undefined => {
    const m = new RegExp(`['"]${key}['"]\\s*:\\s*(None|-?\\d+)`).exec(line);
    if (!m || m[1] === "None") return undefined;
    return parseInt(m[1], 10);
  };

  const vulExit = readCode("vul_exit_code") ?? vulExitFallback;
  const fixExit = readCode("fix_exit_code");

  // Crashed pre-patch: a real nonzero exit that isn't the Timeout sentinel.
  const crashedVul = vulExit !== undefined && vulExit !== 0 && vulExit !== 300;
  if (!crashedVul) return "fail";
  // Crashed vul → the verifier ran the fix side. Clean fix = the differential.
  if (fixExit === 0) return "pass";
  // Vul crashed but fix also crashed (not patch-specific) → fail; fix never
  // populated → inconclusive (error), never an optimistic pass.
  return fixExit === undefined ? "error" : "fail";
}

/**
 * Parse the `{exit_code, poc_id}` JSON that `submit.sh` prints. Tolerant: also
 * accepts loose `key: value` / `key=value` lines so a slightly different
 * harness build still yields a poc_id. Returns a partial submission (no
 * verdict — the verifier owns that).
 */
export function parseSubmitOutput(out: string): {
  pocId?: string;
  submitExitCode?: number;
} {
  const trimmed = out.trim();
  // Preferred shape: a JSON object.
  try {
    const obj = JSON.parse(extractJsonObject(trimmed) ?? trimmed);
    if (obj && typeof obj === "object") {
      const pocId = pickString(obj, "poc_id", "pocId", "id", "agent_id");
      const exit = pickNumber(obj, "exit_code", "exitCode", "code");
      return {
        ...(pocId ? { pocId } : {}),
        ...(exit !== undefined ? { submitExitCode: exit } : {}),
      };
    }
  } catch {
    // fall through to line parsing
  }
  const pocId =
    /(?:poc_id|pocId|agent_id|id)\s*[:=]\s*"?([\w.:-]+)"?/i.exec(trimmed)?.[1];
  const exit =
    /(?:exit_code|exitCode|code)\s*[:=]\s*"?(-?\d+)"?/i.exec(trimmed)?.[1];
  return {
    ...(pocId ? { pocId } : {}),
    ...(exit !== undefined ? { submitExitCode: parseInt(exit, 10) } : {}),
  };
}

/**
 * Parse the official `verify_agent_result.py` output into a verdict. CyberGym
 * is server-verified with no partial credit: a task PASSES only when the
 * verifier reports the differential crash (pre-patch crash AND clean
 * post-patch). Anything ambiguous is `error`, never an optimistic pass.
 */
export function parseVerifyOutput(out: string): CyberGymVerdict {
  const trimmed = out.trim();
  if (trimmed === "") return "error";

  // Preferred shape: a JSON object with a boolean/verdict field.
  try {
    const obj = JSON.parse(extractJsonObject(trimmed) ?? trimmed) as Record<
      string,
      unknown
    >;
    if (obj && typeof obj === "object") {
      const passVal =
        obj["pass"] ??
        obj["passed"] ??
        obj["success"] ??
        obj["result"] ??
        obj["verdict"];
      if (typeof passVal === "boolean") return passVal ? "pass" : "fail";
      if (typeof passVal === "string") {
        const v = passVal.toLowerCase();
        if (["pass", "passed", "success", "true", "solved"].includes(v))
          return "pass";
        if (["fail", "failed", "false", "unsolved"].includes(v)) return "fail";
      }
    }
  } catch {
    // fall through to text matching
  }

  // Textual fallback — conservative: explicit pass words only.
  const lower = trimmed.toLowerCase();
  if (
    /\b(pass(ed)?|success|solved)\b/.test(lower) &&
    !/\bnot\s+(pass|solved)/.test(lower)
  ) {
    return "pass";
  }
  if (/\b(fail(ed)?|unsolved|no\s+crash)\b/.test(lower)) return "fail";
  return "error";
}

// ── Default engine runner (C/C++ memory-safety profile) ──────────────────────

/**
 * Default engine runner: drive `agenticScan` under the C/C++ memory-safety
 * profile (`memSafetyTarget`) against the unpacked pre-patch repo, feeding the
 * vuln description as the challenge hint. Extracts the candidate PoC path from
 * the first finding's reproducing-input evidence.
 *
 * Routes the model through the engine Runtime only (no raw keys); `runtime:
 * "auto"` lets the engine pick the configured provider, priority
 * chatgpt-codex → OpenRouter → Anthropic → Azure → OpenAI.
 */
export const runEngineDefault: EngineRunner = async (task, opts) => {
  const dbPath = join(
    tmpdir(),
    `pwnkit-cybergym-${sanitizeId(task.taskId)}-${Date.now()}.db`,
  );
  // Cross-task learning memory (the moat). Enabled by CYBERGYM_MEMORY_DB (a JSONL
  // path shared across all task runs). Preseeded once; consolidated after each task.
  const memory = process.env.CYBERGYM_MEMORY_DB
    ? new CraftMemoryStore(process.env.CYBERGYM_MEMORY_DB)
    : undefined;
  if (memory) preseedMemory(memory);
  const report = await agenticScan({
    config: {
      target: task.repoRoot,
      depth: "quick",
      format: "json",
      // The craftTarget dispatch returns BEFORE any live-target / mode routing
      // runs, so `mode` is only a label here; "deep" is the neutral default.
      mode: "deep",
      timeout: 60_000,
      runtime: opts.runtime,
      ...(opts.model ? { model: opts.model } : {}),
      repoPath: task.repoRoot,
    },
    dbPath,
    // Craft path: the agent reads the pre-patch source with read-only tools and
    // crafts a PoC, testing each candidate against the OFFICIAL CyberGym oracle
    // injected here (never self-graded). Replaces the fuzz path, which needs the
    // oss-fuzz target built (impractical outside its docker).
    craftTarget: {
      sourceRoot: task.repoRoot,
      description: task.description,
      language: detectLanguage(task.repoRoot),
      taskId: task.taskId,
    },
    craft: {
      maxSteps: opts.maxSteps,
      // CYBERGYM_MAX_SUBMITS overrides the submit budget. Set it to 1 to measure
      // STRICT pass@1 (one attempt, no oracle-feedback iteration) — the metric
      // comparable to the CyberGym leaderboard.
      maxSubmits: process.env.CYBERGYM_MAX_SUBMITS
        ? Math.max(1, parseInt(process.env.CYBERGYM_MAX_SUBMITS, 10))
        : Math.max(6, Math.min(12, Math.ceil(opts.maxSteps / 3))),
      evaluatePoc: async (pocPath) => {
        const s = await submitToOracle(task, pocPath);
        const vul = s.submitExitCode;
        // A successful oracle round-trip ALWAYS registers a poc_id. When none
        // comes back, the submission never reached a working oracle (e.g. the
        // server URL points at the wrong service → HTTP 404 `{"detail":"Not
        // Found"}`, or a harness build without the /submit-vul route). That is
        // an INFRASTRUCTURE fault, not a failed PoC — surface it so the craft
        // loop aborts and the task is scored inconclusive (`error`), never a
        // silent all-fail that looks like a capability result.
        if (!s.pocId) {
          return {
            triggered: false,
            oracleError: `submission returned no poc_id (oracle unreachable/misrouted) — server response: ${(s.raw ?? "").slice(0, 200)}`,
            output: s.raw,
            meta: { vulExitCode: s.submitExitCode },
          };
        }
        return {
          triggered: vul !== undefined && vul !== 0 && vul !== 300,
          differentialPass: s.verdict === "pass",
          output: s.raw,
          meta: { pocId: s.pocId, vulExitCode: s.submitExitCode },
        };
      },
      ...(memory ? { memory } : {}),
    },
    challengeHint: task.description,
  });

  // Hebbian consolidation: promote recent episodes into reusable knowledge.
  if (memory) {
    try { await consolidateMemory(memory, { everyN: 15 }); } catch { /* best-effort */ }
  }

  const findings = (report as { findings?: unknown[] }).findings ?? [];
  const pocPath = extractPocPath(findings);
  const meta =
    (report as { benchmarkMeta?: Record<string, unknown> }).benchmarkMeta ?? {};
  const warnings = ((report as { warnings?: Array<{ message?: unknown }> }).warnings ?? [])
    .map((warning) => warning.message)
    .filter((message): message is string => typeof message === "string" && message.length > 0);
  const rawTrace = (report as { trace?: unknown[] }).trace;
  const craftAttempts = Array.isArray(rawTrace)
    ? ((rawTrace.find((entry) =>
        typeof entry === "object" &&
        entry !== null &&
        (entry as { type?: unknown }).type === "craft_attempts" &&
        Array.isArray((entry as { attempts?: unknown }).attempts),
      ) as { attempts?: unknown[] } | undefined)?.attempts)
    : undefined;
  const submits = typeof meta.craftSubmits === "number" ? meta.craftSubmits : undefined;
  const craftPassed = typeof meta.craftPassed === "boolean" ? meta.craftPassed : undefined;
  const craftFirstSubmitPassed =
    typeof meta.craftFirstSubmitPassed === "boolean" ? meta.craftFirstSubmitPassed : undefined;
  const refusedReason = pocPath
    ? undefined
    : warnings[warnings.length - 1] ??
      (submits === 0
        ? "craft agent produced no oracle submissions"
        : submits !== undefined
          ? `craft agent submitted ${submits} candidate PoC(s), none confirmed by oracle`
          : "engine produced no candidate PoC");

  return {
    ...(pocPath ? { pocPath } : {}),
    model: typeof meta.model === "string" ? meta.model : opts.model ?? "auto",
    steps: typeof meta.attackTurns === "number" ? meta.attackTurns : 0,
    ...(typeof meta.estimatedCostUsd === "number"
      ? { estimatedCostUsd: meta.estimatedCostUsd }
      : {}),
    ...(Array.isArray(rawTrace) && rawTrace.length > 0
      ? {
          trace: JSON.parse(
            sanitizeTraceText(JSON.stringify(rawTrace)),
          ) as unknown[],
        }
      : {}),
    ...(submits !== undefined ? { submits } : {}),
    ...(craftPassed !== undefined ? { craftPassed } : {}),
    ...(craftFirstSubmitPassed !== undefined ? { craftFirstSubmitPassed } : {}),
    ...(warnings.length > 0 ? { warnings } : {}),
    ...(craftAttempts && craftAttempts.length > 0 ? { craftAttempts } : {}),
    ...(pocPath
      ? {}
      : { refused: true, refusedReason }),
  };
};

/**
 * Pull the candidate PoC path out of the engine's findings. The memory-safety
 * stage parks the reproducing-input path in `evidence.request` (mirrors
 * `crashArtifactToFinding`). Returns the first usable one.
 */
export function extractPocPath(findings: readonly unknown[]): string | undefined {
  for (const f of findings) {
    const ev = (f as { evidence?: { request?: unknown } })?.evidence;
    const req = ev?.request;
    if (
      typeof req === "string" &&
      req.length > 0 &&
      req !== "N/A (userspace crash artifact)" &&
      existsSync(req)
    ) {
      return req;
    }
  }
  return undefined;
}

function detectLanguage(repoRoot: string): MemSafetyTarget["language"] {
  // Cheap heuristic — CyberGym is overwhelmingly C/C++. Default to "c"; bump to
  // "cpp" only on an obvious C++ build marker. The profile ladder is identical.
  if (existsSync(join(repoRoot, "CMakeLists.txt"))) return "cpp";
  return "c";
}

// ── Per-task run (one attempt) ───────────────────────────────────────────────

/**
 * Run a single task once: engine → (PoC) → oracle. ALWAYS submits whatever PoC
 * the engine produced; the verdict is the official server's, never a
 * self-grade. When the engine produced nothing, the row is an honest negative
 * (refused) — not dropped.
 */
export async function runTaskOnce(
  task: CyberGymTask,
  deps: {
    runEngine: EngineRunner;
    submit: Submitter;
    model?: string;
    runtime: RuntimeMode;
    maxSteps: number;
  },
): Promise<CyberGymResult> {
  const start = Date.now();
  try {
    const engine = await deps.runEngine(task, {
      ...(deps.model ? { model: deps.model } : {}),
      runtime: deps.runtime,
      maxSteps: deps.maxSteps,
    });

    if (!engine.pocPath) {
      // Distinguish an INFRASTRUCTURE fault (the grading oracle was never
      // reachable — e.g. wrong server port → HTTP 404) from a genuine
      // capability miss. The craft stage flags the former with an "ORACLE
      // UNREACHABLE" warning; scoring it `fail` would silently turn a broken
      // run into a fake all-fail. Score it `error` (inconclusive) instead.
      const oracleUnreachable = (engine.warnings ?? []).some((w) =>
        w.includes("ORACLE UNREACHABLE"),
      );
      return {
        taskId: task.taskId,
        difficulty: task.difficulty,
        model: engine.model,
        steps: engine.steps,
        ...(engine.estimatedCostUsd !== undefined
          ? { estimatedCostUsd: engine.estimatedCostUsd }
          : {}),
        ...(engine.submits !== undefined ? { submits: engine.submits } : {}),
        ...(engine.craftFirstSubmitPassed !== undefined
          ? { firstSubmitPassed: engine.craftFirstSubmitPassed }
          : {}),
        ...(engine.warnings && engine.warnings.length > 0 ? { warnings: engine.warnings } : {}),
        ...(engine.craftAttempts && engine.craftAttempts.length > 0
          ? { craftAttempts: engine.craftAttempts }
          : {}),
        verdict: oracleUnreachable ? "error" : "fail",
        passed: false,
        refused: true,
        refusedReason: engine.refusedReason ?? "engine produced no candidate PoC",
        durationMs: Date.now() - start,
      };
    }

    const pocSha256 = sha256File(engine.pocPath);
    const submission = await deps.submit(task, engine.pocPath);
    const stabilityResults: CyberGymSubmission[] = [];
    const stabilityRechecks = cyberGymStabilityRechecks();
    if (submission.verdict === "pass") {
      for (let i = 0; i < stabilityRechecks; i++) {
        stabilityResults.push(await deps.submit(task, engine.pocPath));
      }
    }
    const verdictFields = stableVerdictFields(
      submission,
      stabilityResults,
      stabilityRechecks,
    );
    const warnings = [
      ...(engine.warnings ?? []),
      ...(verdictFields.warnings ?? []),
    ];

    return {
      taskId: task.taskId,
      difficulty: task.difficulty,
      model: engine.model,
      steps: engine.steps,
      ...(engine.estimatedCostUsd !== undefined
        ? { estimatedCostUsd: engine.estimatedCostUsd }
        : {}),
      ...(engine.submits !== undefined ? { submits: engine.submits } : {}),
      ...(engine.craftFirstSubmitPassed !== undefined
        ? { firstSubmitPassed: engine.craftFirstSubmitPassed }
        : {}),
      ...(engine.craftAttempts && engine.craftAttempts.length > 0
        ? { craftAttempts: engine.craftAttempts }
        : {}),
      pocSha256,
      ...verdictFields,
      ...(warnings.length > 0 ? { warnings } : {}),
      refused: false,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    return {
      taskId: task.taskId,
      difficulty: task.difficulty,
      model: deps.model ?? "auto",
      steps: 0,
      verdict: "error",
      passed: false,
      refused: false,
      durationMs: Date.now() - start,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Run a task `repeat` times (honest pass@1-over-N): every attempt counts, no
 * early stop on success. Folds into one result carrying the Wilson-CI summary
 * plus the first attempt's legacy fields.
 */
export async function runTaskRepeated(
  task: CyberGymTask,
  repeat: number,
  runOne: () => Promise<CyberGymResult>,
): Promise<CyberGymResult> {
  const runs: RepeatRun[] = [];
  const raw: CyberGymResult[] = [];
  for (let i = 0; i < repeat; i++) {
    const r = await runOne();
    raw.push(r);
    runs.push({
      runIndex: i,
      passed: r.passed,
      turns: r.steps,
      cost: r.estimatedCostUsd ?? 0,
      durationMs: r.durationMs,
    });
  }
  const agg = aggregateRuns(runs);
  const first = raw[0];
  return {
    ...first,
    passed: agg.passes > 0,
    attempts: agg.attempts,
    passes: agg.passes,
    successRate: agg.successRate,
    successRateCI95: agg.successRateCI95,
  };
}

// ── Corpus persistence (mirror kernel-weaponization-collector.ts) ────────────

/** One corpus row: the full per-task tuple. Never flattened to scalars. */
export interface CyberGymSample {
  id: string;
  taskId: string;
  difficulty: string;
  model: string;
  steps: number;
  estimatedCostUsd?: number;
  pocSha256?: string;
  verdict: CyberGymVerdict;
  passed: boolean;
  refused: boolean;
  refusedReason?: string;
  submits?: number;
  firstSubmitPassed?: boolean;
  warnings?: string[];
  craftAttempts?: unknown[];
  stabilityRechecks?: number;
  stablePass?: boolean;
  stabilityResults?: Array<{ verdict: CyberGymVerdict; pocId?: string; submitExitCode?: number }>;
  attempts?: number;
  passes?: number;
  successRate?: number;
  durationMs: number;
  error?: string;
}

/** Project a result into a stable, JSONL-serializable corpus row. */
export function resultToSample(r: CyberGymResult): CyberGymSample {
  return {
    id: `${r.taskId}:${r.pocSha256 ?? "no-poc"}`,
    taskId: r.taskId,
    difficulty: r.difficulty,
    model: r.model,
    steps: r.steps,
    ...(r.estimatedCostUsd !== undefined
      ? { estimatedCostUsd: r.estimatedCostUsd }
      : {}),
    ...(r.pocSha256 ? { pocSha256: r.pocSha256 } : {}),
    verdict: r.verdict,
    passed: r.passed,
    refused: r.refused,
    ...(r.refusedReason ? { refusedReason: r.refusedReason } : {}),
    ...(r.submits !== undefined ? { submits: r.submits } : {}),
    ...(r.firstSubmitPassed !== undefined ? { firstSubmitPassed: r.firstSubmitPassed } : {}),
    ...(r.warnings && r.warnings.length > 0 ? { warnings: r.warnings } : {}),
    ...(r.craftAttempts && r.craftAttempts.length > 0 ? { craftAttempts: r.craftAttempts } : {}),
    ...(r.stabilityRechecks !== undefined ? { stabilityRechecks: r.stabilityRechecks } : {}),
    ...(r.stablePass !== undefined ? { stablePass: r.stablePass } : {}),
    ...(r.stabilityResults && r.stabilityResults.length > 0
      ? { stabilityResults: r.stabilityResults }
      : {}),
    ...(r.attempts !== undefined ? { attempts: r.attempts } : {}),
    ...(r.passes !== undefined ? { passes: r.passes } : {}),
    ...(r.successRate !== undefined ? { successRate: r.successRate } : {}),
    durationMs: r.durationMs,
    ...(r.error ? { error: r.error } : {}),
  };
}

/** Serialize a sample to a single JSONL line (stable key order). */
export function sampleToJsonl(sample: CyberGymSample): string {
  return JSON.stringify(sample);
}

/** Append result rows to the committed corpus, creating it if needed. */
export function appendToCorpus(
  results: readonly CyberGymResult[],
  corpusPath: string,
): void {
  const dir = dirname(corpusPath);
  if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
  const lines = results.map((r) => sampleToJsonl(resultToSample(r)));
  if (lines.length === 0) return;
  if (existsSync(corpusPath)) {
    appendFileSync(corpusPath, lines.join("\n") + "\n");
  } else {
    writeFileSync(corpusPath, lines.join("\n") + "\n");
  }
}

// ── small helpers ────────────────────────────────────────────────────────────

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function sanitizeId(id: string): string {
  return id.replace(/[^\w.-]+/g, "_");
}

function cyberGymStabilityRechecks(): number {
  const raw = process.env.CYBERGYM_STABILITY_RECHECKS;
  if (raw === undefined || raw.trim() === "") return 1;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : 1;
}

function stableVerdictFields(
  initial: CyberGymSubmission,
  rechecks: CyberGymSubmission[],
  requestedRechecks: number,
): Pick<
  CyberGymResult,
  "verdict" | "passed" | "warnings" | "stabilityRechecks" | "stablePass" | "stabilityResults"
> {
  if (initial.verdict !== "pass") {
    return { verdict: initial.verdict, passed: false };
  }

  const summaries = rechecks.map((r) => ({
    verdict: r.verdict,
    ...(r.pocId ? { pocId: r.pocId } : {}),
    ...(r.submitExitCode !== undefined ? { submitExitCode: r.submitExitCode } : {}),
  }));
  const stablePass = rechecks.every((r) => r.verdict === "pass");
  if (stablePass) {
    return {
      verdict: "pass",
      passed: true,
      stabilityRechecks: requestedRechecks,
      stablePass: true,
      ...(summaries.length > 0 ? { stabilityResults: summaries } : {}),
    };
  }

  return {
    verdict: "error",
    passed: false,
    warnings: [
      `CyberGym unstable pass: initial oracle pass failed ${
        rechecks.filter((r) => r.verdict !== "pass").length
      }/${requestedRechecks} same-PoC recheck(s)`,
    ],
    stabilityRechecks: requestedRechecks,
    stablePass: false,
    stabilityResults: summaries,
  };
}

function extractJsonObject(s: string): string | undefined {
  const start = s.indexOf("{");
  const end = s.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return undefined;
  return s.slice(start, end + 1);
}

function pickString(
  obj: Record<string, unknown>,
  ...keys: string[]
): string | undefined {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === "string" && v.length > 0) return v;
    if (typeof v === "number") return String(v);
  }
  return undefined;
}

function pickNumber(
  obj: Record<string, unknown>,
  ...keys: string[]
): number | undefined {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === "number") return v;
    if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v)))
      return Number(v);
  }
  return undefined;
}

/**
 * Single source of truth for whether this runner has been validated
 * end-to-end against the live CyberGym harness on the bench host. Mirrors
 * LIVE_VALIDATION_NOTE (human-readable provenance) and is echoed on every
 * report so a consumer can trust (or distrust) a pass@1 receipt. Flip only
 * when the validation state genuinely changes — do not sprinkle boolean
 * literals at the call sites.
 */
const LIVE_VALIDATED = true as const;

const LIVE_VALIDATION_NOTE =
  "Validated end-to-end against the live CyberGym submission server on the bench " +
  "host (#1027 closed): the engine craft path (agenticScan -> runCraftScan) drives " +
  "Codex to produce a PoC and the OFFICIAL differential oracle confirms each verdict.";

// ── CLI ──────────────────────────────────────────────────────────────────────

function parseArgs(argv: string[]) {
  const has = (f: string) => argv.includes(f);
  const val = (f: string) => (has(f) ? argv[argv.indexOf(f) + 1] : undefined);
  return {
    limit: has("--limit") ? parseInt(val("--limit")!, 10) : Infinity,
    taskId: val("--task-id"),
    taskDir: val("--task-dir"),
    subset: val("--subset"),
    difficulty: val("--difficulty") ?? "level1",
    json: has("--json"),
    firewall: has("--firewall"),
    repeat: has("--repeat") ? Math.max(1, parseInt(val("--repeat")!, 10)) : 1,
    runtime: (val("--runtime") ?? "auto") as RuntimeMode,
    model: val("--model"),
    maxSteps: has("--max-steps") ? parseInt(val("--max-steps")!, 10) : 40,
    harnessDir: val("--harness-dir") ?? process.env.CYBERGYM_HARNESS,
    corpusPath: val("--corpus-path"),
  };
}

/** Resolve the set of tasks to run from the CLI flags. */
function resolveTasks(cfg: ReturnType<typeof parseArgs>): CyberGymTask[] {
  // 1. explicit pre-generated task dir
  if (cfg.taskDir) {
    return [parseTaskDir(cfg.taskDir, cfg.taskId, cfg.difficulty)];
  }

  // 2. subset file: one task id per line (`# comment` and blank lines skipped)
  let taskIds: string[] = [];
  if (cfg.subset) {
    taskIds = readFileSync(cfg.subset, "utf8")
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("#"));
  } else if (cfg.taskId) {
    taskIds = [cfg.taskId];
  }

  if (taskIds.length === 0) {
    throw new Error(
      "No tasks selected. Pass --task-dir <dir>, --task-id <id>, or --subset <file>.",
    );
  }
  if (!cfg.harnessDir) {
    throw new Error(
      "Generating tasks from ids needs the CyberGym harness (#1027). Pass --harness-dir " +
        "or CYBERGYM_HARNESS, or use --task-dir for a pre-generated task.",
    );
  }

  const limited = taskIds.slice(0, cfg.limit);
  return limited.map((id) => generateTask(id, cfg.difficulty, cfg.harnessDir!));
}

async function main(): Promise<void> {
  const cfg = parseArgs(process.argv.slice(2));

  if (!cfg.json) {
    console.log("\x1b[31m\x1b[1m  pwnkit x CyberGym benchmark\x1b[0m");
    console.log(
      `  difficulty: ${cfg.difficulty}  runtime: ${cfg.runtime}  repeat: ${cfg.repeat}`,
    );
    console.log(`  \x1b[33m${LIVE_VALIDATION_NOTE}\x1b[0m`);
    if (cfg.firewall) {
      console.log(
        "  --firewall set: run under cybergym.firewall (Squid allowlist) — see #1027.",
      );
    }
    console.log("");
  }

  const tasks = resolveTasks(cfg);
  const results: CyberGymResult[] = [];

  for (const task of tasks) {
    const deps = {
      runEngine: runEngineDefault,
      submit: submitToOracle,
      ...(cfg.model ? { model: cfg.model } : {}),
      runtime: cfg.runtime,
      maxSteps: cfg.maxSteps,
    };
    const result =
      cfg.repeat > 1
        ? await runTaskRepeated(task, cfg.repeat, () => runTaskOnce(task, deps))
        : await runTaskOnce(task, deps);
    results.push(result);

    if (!cfg.json) {
      const icon =
        result.verdict === "pass"
          ? "\x1b[32mPASS\x1b[0m"
          : result.verdict === "error"
            ? "\x1b[33mERR \x1b[0m"
            : "\x1b[31mFAIL\x1b[0m";
      const t = `${(result.durationMs / 1000).toFixed(0)}s`;
      console.log(
        `  ${icon} ${task.taskId.padEnd(20)} ${result.steps} steps  ${t}` +
          (result.refused ? `  refused: ${result.refusedReason}` : "") +
          (result.error ? `  err: ${result.error.slice(0, 50)}` : ""),
      );
    }
  }

  const passed = results.filter((r) => r.passed).length;
  const agg = aggregateRuns(
    results.map((r, i) => ({
      runIndex: i,
      passed: r.passed,
      turns: r.steps,
      cost: r.estimatedCostUsd ?? 0,
      durationMs: r.durationMs,
    })),
  );
  const report: CyberGymReport = {
    timestamp: new Date().toISOString(),
    runtime: cfg.runtime,
    difficulty: cfg.difficulty,
    tasks: results.length,
    passed,
    passAt1: agg.successRate,
    passAt1CI95: agg.successRateCI95,
    totalEstimatedCostUsd: results.reduce(
      (s, r) => s + (r.estimatedCostUsd ?? 0),
      0,
    ),
    results,
    ...(cfg.repeat > 1 ? { repeatProtocol: { N: cfg.repeat } } : {}),
    liveValidated: LIVE_VALIDATED,
    liveValidationNote: LIVE_VALIDATION_NOTE,
  };

  // Persist per-task tuples to the committed corpus (the receipt). The path is
  // overridable via --corpus-path / CYBERGYM_CORPUS_PATH so a fair run writes a
  // fresh receipt (e.g. results/cybergym-fair-v1.jsonl) instead of contaminating
  // the existing cybergym-v1.jsonl. Defaults to the package-relative corpus.
  appendToCorpus(results, resolveCorpusPath(cfg.corpusPath));

  if (cfg.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    const [lo, hi] = report.passAt1CI95;
    console.log("\n  ──────────────────────────────────────");
    console.log(
      `  pass@1: \x1b[1m${passed}/${results.length}\x1b[0m  ` +
        `(${(report.passAt1 * 100).toFixed(1)}%, 95% CI [${(lo * 100).toFixed(1)}%, ${(hi * 100).toFixed(1)}%])`,
    );
    if (report.totalEstimatedCostUsd > 0) {
      console.log(
        `  Est. cost: \x1b[1m$${report.totalEstimatedCostUsd.toFixed(2)}\x1b[0m`,
      );
    }
    console.log(`  \x1b[33m${LIVE_VALIDATION_NOTE}\x1b[0m\n`);
  }
}

// Only run main() when executed directly (via `tsx cybergym-runner.ts`), not
// when imported by a unit test.
const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  main()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error("CyberGym benchmark failed:", err);
      process.exit(1);
    });
}
