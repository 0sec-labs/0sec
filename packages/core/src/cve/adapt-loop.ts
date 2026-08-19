/**
 * Issue #272 v0 part 2 — CVE PoC adaptation loop.
 *
 * Drives the discover→confirm→port→reproduce sequence:
 *
 *   1. Call the `CveArtifactProvider` (scraper, sibling branch
 *      `feat/272-cve-artifact-scraper`) to list PoC candidates.
 *   2. Try each candidate ordered by `confidence` desc:
 *        a. `fetchPoc` to grab the source.
 *        b. `verifyKernelFinding` from Tier-1 (#271) to build + run.
 *        c. If `reproduced`, return `confirmed`.
 *        d. Otherwise, ask the agent (single-shot prompt) for a unified
 *           diff against the PoC source. Apply it. Re-run. Repeat up to
 *           `attempts` (default 5) or `wallClockMs` (default 30 min).
 *   3. If no candidate confirms, return `unreproduced`.
 *   4. If the provider returns zero candidates, return `no_artifact`.
 *
 * Every attempt is recorded via the journal writer (`createJournalWriter`)
 * as an `observation` entry — `attempt_started`, `poc_fetched`, `verify_run`,
 * `adapt_diff_applied`. The journal is the audit trail callers replay.
 *
 * Adaptation is intentionally tiny in v0: a single-shot prompt produces a
 * unified diff against the PoC source, we apply it line-anchored, and
 * re-verify. Multi-turn / tool-using orchestration lands later.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import {
  createJournalWriter,
  type JournalWriter,
} from "../agent/journal/index.js";
import {
  verifyKernelFinding,
  type KernelFindingVerification,
  type VerifyKernelFindingOptions,
} from "../triage/kernel-vm-runner.js";
import { fetchPoc } from "./poc-fetcher.js";
import type {
  CveArtifactProvider,
  CveArtifacts,
  FetchedPoc,
  PocCandidate,
} from "./types.js";

export type AdaptationStatus =
  | "confirmed"
  | "unreproduced"
  | "no_artifact"
  | "budget_exhausted";

export interface AttemptRecord {
  candidate: PocCandidate;
  attemptIndex: number;
  fetched: FetchedPoc | null;
  verification: KernelFindingVerification | null;
  /** Unified diff produced by the agent for the next iteration, if any. */
  adaptDiff?: string;
  /** True if a diff was applied to produce `final_poc_path`. */
  diffApplied: boolean;
  error?: string;
  durationMs: number;
}

export interface AdaptationResult {
  status: AdaptationStatus;
  cveId: string;
  attempts: AttemptRecord[];
  final_poc_path?: string;
  signature?: string;
  /** Total wall-clock spent in the loop. */
  total_ms: number;
}

/**
 * Input bundle the agent receives when asked to produce an adaptation.
 * Exposed so callers can build the same shape for offline experiments.
 */
export interface AdaptationAgentInput {
  cveId: string;
  pocSource: string;
  pocLanguage: PocCandidate["language"];
  writeupText?: string;
  targetKernelSubsystemSource?: string;
  errorLog: string;
  attemptIndex: number;
}

/**
 * Agent adapter: produces a unified diff (against `pocSource`) the loop
 * applies before re-running verify. Returning an empty string signals
 * "no useful adaptation" and the loop moves to the next candidate.
 */
export type AdaptationAgent = (input: AdaptationAgentInput) => Promise<string>;

export type VerifyKernelFinding = (
  opts: VerifyKernelFindingOptions,
) => Promise<KernelFindingVerification>;

export interface AdaptAndVerifyOptions {
  kernelTree: string;
  kernelConfig?: string;
  /** Max number of verify-run attempts across all candidates. Default 5. */
  attempts?: number;
  /** Total wall-clock budget in ms. Default 30 min. */
  wallClockMs?: number;
  artifactProvider: CveArtifactProvider;
  fetcher?: typeof fetchPoc;
  runner?: VerifyKernelFinding;
  /** Adaptation agent. Tests inject a canned-diff stub. */
  agent?: AdaptationAgent;
  /** Journal writer factory; defaults to file-backed under `~/.pwnkit/runs`. */
  journalFactory?: (runId: string) => JournalWriter;
  /** Override `Date.now()` for deterministic budget tracking in tests. */
  clock?: () => number;
  /** Override the run id (defaults to `cve-adapt-<cveId>-<timestamp>`). */
  runId?: string;
}

const DEFAULT_ATTEMPTS = 5;
const DEFAULT_WALL_CLOCK_MS = 30 * 60 * 1000;

/**
 * Apply a unified diff against `source`. v0 implementation: line-anchored
 * application of `@@` hunks. Returns the new source.
 *
 * Throws if any hunk fails to apply. Exported for tests; not part of the
 * public API surface.
 */
export function applyUnifiedDiff(source: string, diff: string): string {
  const sourceLines = source.split("\n");
  const diffLines = diff.replace(/\r\n/g, "\n").split("\n");

  // Drop the artificial empty trailing element that `split("\n")` produces
  // for inputs that end in a newline. Real diff body lines always carry a
  // leading marker character, so a literal "" can only be that artifact.
  while (diffLines.length > 0 && diffLines[diffLines.length - 1] === "") {
    diffLines.pop();
  }

  // Skip any --- / +++ headers up to the first @@
  let i = 0;
  while (i < diffLines.length && !diffLines[i].startsWith("@@")) i += 1;
  if (i >= diffLines.length) {
    // No hunks at all — treat as a no-op so the agent's "I have nothing"
    // can be expressed as an empty diff body.
    return source;
  }

  // Parse each hunk and apply against `sourceLines` (1-based old-line
  // index from the @@ header).
  const out = [...sourceLines];
  let cursorOffset = 0; // (lines added so far) − (lines removed so far)

  while (i < diffLines.length) {
    const header = diffLines[i];
    const match = /^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/.exec(header);
    if (!match) {
      throw new Error(`malformed hunk header: ${header}`);
    }
    const oldStart = parseInt(match[1], 10);
    i += 1;

    // Walk the hunk body until the next @@ or EOF.
    let target = oldStart - 1 + cursorOffset;
    while (i < diffLines.length && !diffLines[i].startsWith("@@")) {
      const line = diffLines[i];
      // Real body lines always start with one of " ", "-", "+", "\".
      // An empty string would have been popped above; anything else is a
      // malformed entry.
      const marker = line[0];
      const text = line.slice(1);

      if (marker === " ") {
        if (out[target] !== text) {
          throw new Error(
            `context mismatch at line ${target + 1}: expected "${text}", got "${out[target] ?? "<eof>"}"`,
          );
        }
        target += 1;
      } else if (marker === "-") {
        if (out[target] !== text) {
          throw new Error(
            `delete mismatch at line ${target + 1}: expected "${text}", got "${out[target] ?? "<eof>"}"`,
          );
        }
        out.splice(target, 1);
        cursorOffset -= 1;
      } else if (marker === "+") {
        out.splice(target, 0, text);
        target += 1;
        cursorOffset += 1;
      } else if (marker === "\\") {
        // "\ No newline at end of file" — ignore.
      } else {
        throw new Error(`unknown diff marker '${marker ?? "<empty>"}' at line: ${line}`);
      }
      i += 1;
    }
  }

  return out.join("\n");
}

function inferAdaptedFilename(originalPath: string, attemptIndex: number): string {
  const base = basename(originalPath);
  const dot = base.lastIndexOf(".");
  if (dot < 0) return `${base}.adapt${attemptIndex}`;
  return `${base.slice(0, dot)}.adapt${attemptIndex}${base.slice(dot)}`;
}

function defaultAgent(): AdaptationAgent {
  return async () => {
    // No adaptation agent wired in v0 default. The CLI surface will pass
    // a real one once #272's agent-prompt module lands; tests inject a
    // canned diff. The default keeps the API safe to call without setup.
    return "";
  };
}

/**
 * Build the prompt the adaptation agent receives. Exported so the CLI and
 * the agent adapter can render the same thing for logs.
 */
export function renderAdaptationPrompt(input: AdaptationAgentInput): string {
  const lines: string[] = [];
  lines.push(`# CVE adaptation request — ${input.cveId}`);
  lines.push(`Attempt ${input.attemptIndex} did not reproduce the bug.`);
  lines.push("");
  lines.push(
    "Your job: produce a **unified diff** against the PoC source below that",
    "makes the reproducer trigger on the target kernel. Output ONLY the diff,",
    "starting with `--- a/poc.<ext>` and `+++ b/poc.<ext>` headers. If you have",
    "no useful adaptation, output an empty diff (no `@@` hunks).",
  );
  lines.push("");
  lines.push(`## PoC source (language=${input.pocLanguage})`);
  lines.push("```");
  lines.push(input.pocSource);
  lines.push("```");

  if (input.writeupText) {
    lines.push("");
    lines.push("## Writeup excerpt");
    lines.push(input.writeupText);
  }
  if (input.targetKernelSubsystemSource) {
    lines.push("");
    lines.push("## Target kernel subsystem source (relevant slice)");
    lines.push("```c");
    lines.push(input.targetKernelSubsystemSource);
    lines.push("```");
  }

  lines.push("");
  lines.push("## Error log (build / dmesg from last attempt)");
  lines.push("```");
  lines.push(input.errorLog);
  lines.push("```");
  return lines.join("\n");
}

function nowMs(clock?: () => number): number {
  return clock ? clock() : Date.now();
}

/**
 * Run the v0 adaptation loop. Public entrypoint for #272.
 */
export async function adaptAndVerify(
  cveId: string,
  opts: AdaptAndVerifyOptions,
): Promise<AdaptationResult> {
  const attemptsBudget = opts.attempts ?? DEFAULT_ATTEMPTS;
  const wallClockMs = opts.wallClockMs ?? DEFAULT_WALL_CLOCK_MS;
  const fetcher = opts.fetcher ?? fetchPoc;
  const runner = opts.runner ?? verifyKernelFinding;
  const agent = opts.agent ?? defaultAgent();
  const clock = opts.clock;
  const startedAt = nowMs(clock);
  const deadline = startedAt + wallClockMs;

  const runId = opts.runId ?? `cve-adapt-${cveId.toLowerCase()}-${startedAt}`;
  const journal: JournalWriter = (opts.journalFactory ?? ((id) => createJournalWriter({ runId: id })))(runId);

  journal.append({
    kind: "dispatch",
    targetAgent: "cve-adapt-loop",
    objective: `adapt + verify PoC for ${cveId}`,
    context: { kernelTree: opts.kernelTree, kernelConfig: opts.kernelConfig ?? "kasan", attemptsBudget, wallClockMs },
  });

  let artifacts: CveArtifacts;
  try {
    artifacts = await opts.artifactProvider(cveId);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    journal.append({ kind: "error", message: `artifact-provider failed: ${message}` });
    journal.append({ kind: "done", status: "failed", summary: "artifact provider failed" });
    return {
      status: "no_artifact",
      cveId,
      attempts: [],
      total_ms: nowMs(clock) - startedAt,
    };
  }

  if (!artifacts.pocCandidates || artifacts.pocCandidates.length === 0) {
    journal.append({
      kind: "observation",
      source: "cve-adapt-loop",
      summary: "no PoC candidates returned by artifact provider",
      data: { cveId },
    });
    journal.append({ kind: "done", status: "failed", summary: "no_artifact" });
    return {
      status: "no_artifact",
      cveId,
      attempts: [],
      total_ms: nowMs(clock) - startedAt,
    };
  }

  const ordered = [...artifacts.pocCandidates].sort((a, b) => b.confidence - a.confidence);
  const attempts: AttemptRecord[] = [];
  let totalAttempts = 0;
  let lastPocPath: string | undefined;

  for (const candidate of ordered) {
    if (totalAttempts >= attemptsBudget) break;
    if (nowMs(clock) >= deadline) break;

    journal.append({
      kind: "observation",
      source: "cve-adapt-loop",
      summary: "attempt_started",
      data: { candidate, attemptIndex: totalAttempts },
    });

    const attemptStart = nowMs(clock);
    let fetched: FetchedPoc | null = null;
    try {
      fetched = await fetcher(candidate, {});
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      journal.append({ kind: "error", message: `poc_fetch_failed: ${message}` });
      attempts.push({
        candidate,
        attemptIndex: totalAttempts,
        fetched: null,
        verification: null,
        diffApplied: false,
        error: message,
        durationMs: nowMs(clock) - attemptStart,
      });
      totalAttempts += 1;
      continue;
    }
    journal.append({
      kind: "observation",
      source: "cve-adapt-loop",
      summary: "poc_fetched",
      data: { sha256: fetched.sha256, source_url: fetched.source_url, local_path: fetched.local_path },
    });

    // Inner loop: verify, ask agent for diff, apply, re-verify, until
    // budget exhausted.
    let currentPath = fetched.local_path;
    let confirmed: KernelFindingVerification | null = null;
    while (totalAttempts < attemptsBudget && nowMs(clock) < deadline) {
      const verify = await runVerifySafe(runner, currentPath, fetched.language, opts);
      journal.append({
        kind: "observation",
        source: "cve-adapt-loop",
        summary: "verify_run",
        data: {
          attemptIndex: totalAttempts,
          status: verify.status,
          signature: verify.signature ?? null,
          dmesg_path: verify.dmesg_path,
        },
      });

      if (verify.status === "reproduced") {
        confirmed = verify;
        attempts.push({
          candidate,
          attemptIndex: totalAttempts,
          fetched,
          verification: verify,
          diffApplied: currentPath !== fetched.local_path,
          durationMs: nowMs(clock) - attemptStart,
        });
        lastPocPath = currentPath;
        totalAttempts += 1;
        break;
      }

      attempts.push({
        candidate,
        attemptIndex: totalAttempts,
        fetched,
        verification: verify,
        diffApplied: currentPath !== fetched.local_path,
        durationMs: nowMs(clock) - attemptStart,
      });
      totalAttempts += 1;
      lastPocPath = currentPath;

      if (totalAttempts >= attemptsBudget || nowMs(clock) >= deadline) break;

      // Ask the agent for a unified diff.
      const errorLog = existsSync(verify.dmesg_path) ? readFileSync(verify.dmesg_path, "utf-8") : "";
      const pocSource = readFileSync(currentPath, "utf-8");
      const promptInput: AdaptationAgentInput = {
        cveId,
        pocSource,
        pocLanguage: fetched.language,
        writeupText: artifacts.writeupText,
        errorLog,
        attemptIndex: totalAttempts,
      };
      let diff = "";
      try {
        diff = await agent(promptInput);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        journal.append({ kind: "error", message: `agent_failed: ${message}` });
        break;
      }
      if (!diff.trim() || !diff.includes("@@")) {
        journal.append({
          kind: "observation",
          source: "cve-adapt-loop",
          summary: "adapt_diff_empty",
          data: { attemptIndex: totalAttempts },
        });
        break; // move to next candidate
      }

      let nextSource: string;
      try {
        nextSource = applyUnifiedDiff(pocSource, diff);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        journal.append({
          kind: "error",
          message: `apply_diff_failed: ${message}`,
        });
        break;
      }

      const nextPath = inferAdaptedFilename(fetched.local_path, totalAttempts);
      const nextAbs = currentPath.replace(basename(currentPath), basename(nextPath));
      writeFileSync(nextAbs, nextSource, "utf-8");
      journal.append({
        kind: "observation",
        source: "cve-adapt-loop",
        summary: "adapt_diff_applied",
        data: { attemptIndex: totalAttempts, prev_path: currentPath, next_path: nextAbs },
        artifacts: [
          { name: "adapt.diff", mediaType: "text/x-diff", content: diff },
        ],
      });
      currentPath = nextAbs;
      lastPocPath = nextAbs;
    }

    if (confirmed) {
      journal.append({ kind: "done", status: "success", summary: "reproduced" });
      return {
        status: "confirmed",
        cveId,
        attempts,
        final_poc_path: lastPocPath,
        signature: confirmed.signature,
        total_ms: nowMs(clock) - startedAt,
      };
    }
  }

  const exhaustedByBudget = totalAttempts >= attemptsBudget || nowMs(clock) >= deadline;
  const status: AdaptationStatus = exhaustedByBudget ? "budget_exhausted" : "unreproduced";
  journal.append({
    kind: "done",
    status: "failed",
    summary: status,
  });
  return {
    status,
    cveId,
    attempts,
    final_poc_path: lastPocPath,
    total_ms: nowMs(clock) - startedAt,
  };
}

/**
 * Run `verifyKernelFinding` while normalising thrown errors into a
 * `run_failed` verdict. The Tier-1 surface already catches most failures
 * internally; this wrapper covers the residual "synchronous throw before
 * the build runner even starts" case so the loop keeps producing
 * `AttemptRecord` entries instead of exploding.
 */
async function runVerifySafe(
  runner: VerifyKernelFinding,
  reproducerPath: string,
  language: PocCandidate["language"],
  opts: AdaptAndVerifyOptions,
): Promise<KernelFindingVerification> {
  const isSyz = language === "syz";
  try {
    return await runner({
      kernelTree: opts.kernelTree,
      kernelConfig: opts.kernelConfig,
      reproducerPath: isSyz ? undefined : reproducerPath,
      syzProgramPath: isSyz ? reproducerPath : undefined,
    });
  } catch (err) {
    return {
      status: "run_failed",
      dmesg_path: "",
      build_cache_hit: false,
      signature: undefined,
    };
  }
}
