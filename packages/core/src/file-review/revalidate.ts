// Adversarial revalidation stage for the file-review pipeline. Runs batches
// of files through an LLM invoker, parses and reconciles verdicts, and
// annotates findings IN PLACE with revalidation metadata. Cost/duration
// capped with resumable exit behaviour — on ReviewLimitError claimed files
// revert to pending.

import { spawnSync } from "node:child_process";
import { ReviewStore, newRunId } from "./store.js";
import type { ReviewFileRecord, ReviewFinding, ReviewRevalidation } from "./types.js";
import { ReviewLimitError, type ReviewInvoker, type ReviewInvocation } from "./types.js";
import type { Severity } from "@0sec/shared";
import { estimateCost } from "../agent/cost.js";
import { expectedFindingsForBatch, parseRevalidateVerdicts, reconcileVerdicts } from "./reconcile.js";
import type { ExpectedFinding, RevalidateVerdictInput, MatchedPair } from "./reconcile.js";

// ── Types ──────────────────────────────────────────────────────────────────

export interface ReviewRevalidateParams {
  projectId: string;
  /** Git root for the default git-log implementation. */
  rootPath: string;
  /** Injected LLM invoker. */
  invoker: ReviewInvoker;
  /** Re-revalidate findings that already have a verdict. */
  force?: boolean;
  /** Minimum severity to revalidate; default 'high'. */
  minSeverity?: Severity;
  /**
   * Injectable git-log function. Default shells out `git log --oneline
   * --since=3 months ago -n 10 -- <file>` in rootPath with a 10s timeout.
   * Returns '' on any failure.
   */
  gitLog?: (filePath: string) => string;
  /** Hard cost cap in USD. */
  maxCostUsd?: number;
  /** Hard duration cap in ms. */
  maxDurationMs?: number;
  /** Model label for cost estimation. */
  model?: string;
  /** Logger callback. */
  log?: (msg: string) => void;
}

export interface ReviewRevalidateResult {
  runId: string;
  revalidated: number;
  truePositives: number;
  falsePositives: number;
  fixed: number;
  uncertain: number;
  duplicates: number;
  missing: number;
  costUsd: number;
  limitReached?: boolean;
}

// ── Severity ordering ───────────────────────────────────────────────────────

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function severityAtLeast(s: Severity, min: Severity): boolean {
  return (SEVERITY_RANK[s] ?? 99) <= (SEVERITY_RANK[min] ?? 99);
}

// ── Default git-log implementation ──────────────────────────────────────────

const GIT_LOG_TIMEOUT_MS = 10_000;

function defaultGitLog(rootPath: string, filePath: string): string {
  try {
    const result = spawnSync(
      "git",
      ["log", "--oneline", "--since=3 months ago", "-n", "10", "--", filePath],
      { cwd: rootPath, timeout: GIT_LOG_TIMEOUT_MS, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] },
    );
    if (result.status !== 0 || result.error) return "";
    return result.stdout.trim();
  } catch {
    return "";
  }
}

// ── Prompt builder ──────────────────────────────────────────────────────────

function buildRevalidatePrompt(
  records: ReviewFileRecord[],
  expected: ExpectedFinding[],
  gitLogFn: (fp: string) => string,
): string {
  // Build a lookup from filePath to expected findings for that file
  const expectedByFile = new Map<string, ExpectedFinding[]>();
  for (const exp of expected) {
    if (!expectedByFile.has(exp.filePath)) expectedByFile.set(exp.filePath, []);
    expectedByFile.get(exp.filePath)!.push(exp);
  }

  const fileSections: string[] = [];
  const aliasList: string[] = [];

  for (const record of records) {
    const fileExpected = expectedByFile.get(record.filePath) ?? [];
    if (fileExpected.length === 0) continue;

    const gitHistory = gitLogFn(record.filePath);

    const findingBlocks: string[] = [];
    for (const exp of fileExpected) {
      const finding = record.findings.find(
        (f) => (f.findingId ?? "") === exp.findingId && f.title === exp.title,
      );
      if (!finding) continue;

      findingBlocks.push(
        `**Finding ${exp.alias}:**`,
        `- Severity: ${finding.severity}`,
        `- Vulnerability slug: ${finding.vulnSlug}`,
        `- Lines: ${finding.lineNumbers.join(", ")}`,
        `- Description: ${finding.description}`,
        `- Recommendation: ${finding.recommendation}`,
      );
    }

    if (findingBlocks.length === 0) continue;

    fileSections.push(
      `### File: ${record.filePath}`,
      ...(gitHistory
        ? ["", "**Recent git history:**", "```", gitHistory, "```"]
        : []),
      "",
      ...findingBlocks,
    );

    for (const exp of fileExpected) {
      aliasList.push(`- \`${exp.findingId || exp.alias}\` (alias ${exp.alias}, title: "${exp.title}")`);
    }
  }

  if (fileSections.length === 0) return "";

  return [
    "You are an expert security engineer conducting an adversarial review of static analysis findings on a codebase. Your task is to determine, with high confidence, whether each finding is real and exploitable. If you cannot construct a concrete attack scenario, it is likely a false positive.",
    "",
    "Static analysis only — do not run or modify code.",
    "",
    "## Files for Review",
    "",
    ...fileSections,
    "",
    "## Investigation Process",
    "",
    "For each finding, follow these steps:",
    "1. Read the full source context around the finding.",
    "2. Trace imports and dependencies the code touches.",
    "3. Trace the data flow from input to the flagged operation.",
    "4. Construct a concrete attacker scenario.",
    "5. Check if the framework provides built-in protections.",
    "6. Review recent git history for related fixes.",
    "7. Be honest about uncertainty.",
    "",
    "## Verdict Definitions",
    "",
    "- `true-positive`: The finding is a real, exploitable vulnerability.",
    "- `false-positive`: The finding is not exploitable or is a false alarm.",
    "- `fixed`: The vulnerability existed but has been fixed in recent commits.",
    "- `uncertain`: Cannot determine with confidence.",
    "- `duplicate`: Same vulnerability reported elsewhere. Set `duplicateOf` to the primary finding ID.",
    "",
    "Duplicate rule: intra-file only; exactly one primary per equivalence class; duplicateOf must point to a non-duplicate.",
    "",
    "## Output Format",
    "",
    "Return a JSON array of verdicts:",
    '```json',
    '[',
    '  {',
    '    "findingId": "<finding ID or F-alias>",',
    '    "verdict": "true-positive|false-positive|fixed|uncertain|duplicate",',
    '    "adjustedSeverity": "critical|high|medium|low|info (optional)",',
    '    "duplicateOf": "<finding ID> (optional, only for duplicates)",',
    '    "reasoning": "... (5-10 sentences, show your work)"',
    '  }',
    ']',
    '```',
    "",
    "You must return exactly one verdict for every Finding ID below:",
    ...aliasList,
  ].join("\n");
}

// ── Verdict application (annotate, never replace) ────────────────────────────

/**
 * Annotate findings with revalidation metadata. Handles the
 * duplicate-of-primary invariant: if a "duplicate" verdict references a
 * finding whose own verdict is also "duplicate", the referencing verdict
 * is downgraded to "uncertain".
 */
function applyVerdictsToRecords(
  recordMap: Map<string, ReviewFileRecord>,
  matched: MatchedPair[],
  runId: string,
  model?: string,
): { truePositives: number; falsePositives: number; fixed: number; uncertain: number; duplicates: number } {
  const counts = { truePositives: 0, falsePositives: 0, fixed: 0, uncertain: 0, duplicates: 0 };
  // Group matched pairs by file
  const byFile = new Map<string, MatchedPair[]>();
  for (const m of matched) {
    const fp = m.expected.filePath;
    if (!byFile.has(fp)) byFile.set(fp, []);
    byFile.get(fp)!.push(m);
  }

  for (const [, fileMatches] of byFile) {
    // Build verdict map: findingId → verdict input
    const verdictMap = new Map<string, RevalidateVerdictInput>();
    for (const m of fileMatches) {
      if (m.expected.findingId) verdictMap.set(m.expected.findingId, m.verdict);
    }

    for (const match of fileMatches) {
      const findingId = match.expected.findingId;
      const record = recordMap.get(match.expected.filePath);
      if (!record) continue;
      const finding = record.findings.find((f) => f.findingId === findingId);
      if (!finding) continue;

      let verdict = match.verdict.verdict;
      let duplicateOf = match.verdict.duplicateOf;
      let reasoning = match.verdict.reasoning;

      // Duplicate-of-primary invariant: if duplicateOf targets a finding
      // whose verdict is also "duplicate", downgrade this one to uncertain.
      if (verdict === "duplicate" && duplicateOf) {
        const targetId = duplicateOf;
        const targetFinding = record.findings.find((f) => f.findingId === targetId);
        if (!targetFinding) {
          // Unresolvable ref → downgrade
          verdict = "uncertain";
          reasoning = `[DOWNGARDED from duplicate: referenced finding ${targetId} not found in file] ${reasoning}`;
          duplicateOf = undefined;
        } else {
          const targetVerdict = verdictMap.get(targetId);
          if (targetVerdict?.verdict === "duplicate") {
            verdict = "uncertain";
            reasoning = `[DOWNGARDED from duplicate: primary ${targetId} is also a duplicate] ${reasoning}`;
            duplicateOf = undefined;
          }
        }
      }

      // Annotate, never replace
      finding.revalidation = {
        verdict,
        reasoning,
        adjustedSeverity: match.verdict.adjustedSeverity,
        duplicateOf,
        revalidatedAt: new Date().toISOString(),
        runId,
        model,
      };
      if (verdict === "true-positive") counts.truePositives++;
      else if (verdict === "false-positive") counts.falsePositives++;
      else if (verdict === "fixed") counts.fixed++;
      else if (verdict === "uncertain") counts.uncertain++;
      else if (verdict === "duplicate") counts.duplicates++;
    }
  }
  return counts;
}

// ── runReviewRevalidate ─────────────────────────────────────────────────────

const BATCH_SIZE = 5;

export async function runReviewRevalidate(
  store: ReviewStore,
  params: ReviewRevalidateParams,
): Promise<ReviewRevalidateResult> {
  const {
    projectId,
    rootPath,
    invoker,
    force,
    minSeverity = "high",
    maxCostUsd,
    maxDurationMs,
    model: modelName,
    log,
  } = params;
  const gitLogFn = params.gitLog ?? ((filePath: string): string => defaultGitLog(rootPath, filePath));

  const runId = newRunId();
  const startTime = Date.now();
  let totalCost = 0;
  let revalidated = 0;
  let truePositives = 0;
  let falsePositives = 0;
  let fixed = 0;
  let uncertain = 0;
  let duplicates = 0;
  let missing = 0;
  let limitReached = false;

  // Create run meta
  const meta = store.createRunMeta({ projectId, rootPath, type: "revalidate", runId });

  try {
    // List all records
    const allRecords = store.listRecords(projectId);

    // Filter to eligible files: those with findings at/above minSeverity
    // that either lack revalidation or force is true
    const eligible: Array<{ record: ReviewFileRecord }> = [];
    for (const record of allRecords) {
      const hasEligible = record.findings.some((f) => {
        if (!force && f.revalidation) return false;
        return severityAtLeast(f.severity, minSeverity);
      });
      if (hasEligible) eligible.push({ record });
    }

    log?.(`Revalidate: ${allRecords.length} total records, ${eligible.length} eligible`);

    // Process in batches
    for (let batchStart = 0; batchStart < eligible.length; batchStart += BATCH_SIZE) {
      // Check duration limit before each batch
      if (maxDurationMs !== undefined && Date.now() - startTime >= maxDurationMs) {
        log?.("Revalidate: duration limit reached");
        limitReached = true;
        break;
      }

      const batch = eligible.slice(batchStart, batchStart + BATCH_SIZE);
      const filePaths = batch.map((e) => e.record.filePath);

      // Claim files
      const claimed = store.claimFiles(projectId, runId, filePaths);
      if (claimed.length === 0) continue;

      const claimedRecords: ReviewFileRecord[] = [];
      for (const fp of claimed) {
        const r = store.readRecord(projectId, fp);
        if (r) claimedRecords.push(r);
      }

      // Build expected findings
      const expected = expectedFindingsForBatch(claimedRecords, { force, minSeverity });
      if (expected.length === 0) {
        store.releaseFiles(projectId, runId, claimed);
        continue;
      }

      log?.(`Revalidate batch: ${claimed.length} files, ${expected.length} findings`);

      // Call invoker
      let invocation: ReviewInvocation;
      try {
        invocation = await invoker(buildRevalidatePrompt(claimedRecords, expected, gitLogFn), "revalidate");
      } catch (err) {
        if (err instanceof ReviewLimitError) {
          store.releaseFiles(projectId, runId, claimed, true);
          limitReached = true;
          break;
        }
        throw err;
      }

      // Track cost
      if (invocation.costUsd !== undefined) {
        totalCost += invocation.costUsd;
      } else if (invocation.usage) {
        totalCost += estimateCost(invocation.usage, modelName ?? invocation.model);
      }

      // Parse + reconcile
      const verdicts = parseRevalidateVerdicts(invocation.output);
      const { matched, unmatched: unmatchedVerdicts, missing: missingExpected } = reconcileVerdicts(expected, verdicts);

      // Build record map for claimed files
      const recordMap = new Map<string, ReviewFileRecord>();
      for (const rec of claimedRecords) {
        recordMap.set(rec.filePath, rec);
      }

      // Apply verdicts (counts reflect FINAL verdicts after the
      // duplicate-of-primary downgrade, not the raw model output)
      const counts = applyVerdictsToRecords(recordMap, matched, runId, modelName ?? invocation.model);
      truePositives += counts.truePositives;
      falsePositives += counts.falsePositives;
      fixed += counts.fixed;
      uncertain += counts.uncertain;
      duplicates += counts.duplicates;
      revalidated += matched.length;
      missing += missingExpected.length;

      // Write updated records (annotation-only, findings never replaced)
      for (const rec of recordMap.values()) {
        store.writeRecord(rec);
      }

      // Release files (annotation-only, no revert)
      store.releaseFiles(projectId, runId, claimed);

      log?.(`Revalidate batch done: ${matched.length} matched, ${unmatchedVerdicts.length} unmatched, ${missingExpected.length} missing`);

      // Check cost limit
      if (maxCostUsd !== undefined && totalCost >= maxCostUsd) {
        log?.("Revalidate: cost limit reached");
        limitReached = true;
        break;
      }
    }
  } finally {
    // Mark run as done or limit
    meta.phase = limitReached ? "limit" : "done";
    meta.completedAt = new Date().toISOString();
    meta.stats = {
      findingsCount: revalidated,
      totalCostUsd: totalCost,
      truePositives,
      falsePositives,
    };
    if (limitReached) {
      meta.limitReached = {
        kind: maxCostUsd !== undefined && totalCost >= maxCostUsd ? "cost" : "duration",
        limitUsd: maxCostUsd,
        actualUsd: totalCost,
      };
    }
    store.saveRunMeta(meta);
  }

  return {
    runId,
    revalidated,
    truePositives,
    falsePositives,
    fixed,
    uncertain,
    duplicates,
    missing,
    costUsd: totalCost,
    limitReached: limitReached || undefined,
  };
}