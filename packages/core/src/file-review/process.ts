import path from "node:path";
import fs from "node:fs";
import type { ReviewFileRecord, ReviewInvoker, ReviewAnalysisEntry, ReviewInvocation } from "./types.js";
import { ReviewStore, mergeFindings, appendAnalysis, newRunId, findingSignature } from "./store.js";
import { parseInvestigateResults, parseRefusalReport, REFUSAL_FOLLOWUP_PROMPT } from "./parse.js";
import type { ParseResult } from "./parse.js";
import { estimateCost } from "../agent/cost.js";
import { assembleReviewPrompt, buildInvestigatePrompt } from "./prompt.js";
import { formatTruncated } from "../agent/output-truncation.js";

// ── Types ──────────────────────────────────────────────────────────────────

export interface ReviewProcessParams {
  projectId: string;
  rootPath: string;
  invoker: ReviewInvoker;
  /** Prompt builder: takes batch vuln slugs + languages → system prompt. */
  assembleSystemPrompt?: (batchSlugs: string[], batchLanguages: string[]) => string;
  /** Optional project-wide context appended to each batch prompt. */
  projectInfo?: string;
  batchSize?: number;
  concurrency?: number;
  maxCostUsd?: number;
  maxDurationMs?: number;
  /** Wave marker: when set, skip files already carrying this marker. */
  reinvestigate?: number;
  model?: string;
  agentType?: string;
  log?: (msg: string) => void;
}

export interface ReviewProcessResult {
  runId: string;
  filesInvestigated: number;
  findingsAdded: number;
  costUsd: number;
  refusals: number;
  limitReached?: { kind: "cost" | "duration" };
}


// ── Batch construction ────────────────────────────────────────────────────

/**
 * Group records with candidates by directory. Split oversized groups at
 * batchSize. Merge small groups back up to batchSize.
 */
export function batchCandidates(
  records: ReviewFileRecord[],
  batchSize: number,
): ReviewFileRecord[][] {
  if (!Number.isSafeInteger(batchSize) || batchSize < 1) {
    throw new RangeError("batchSize must be a positive integer");
  }
  const groups = new Map<string, ReviewFileRecord[]>();
  for (const record of records) {
    const dir = path.posix.dirname(record.filePath);
    if (!groups.has(dir)) groups.set(dir, []);
    groups.get(dir)!.push(record);
  }

  const batches: ReviewFileRecord[][] = [];
  for (const group of groups.values()) {
    if (group.length <= batchSize) {
      batches.push(group);
    } else {
      for (let i = 0; i < group.length; i += batchSize) {
        batches.push(group.slice(i, i + batchSize));
      }
    }
  }

  // Merge small adjacent groups back up to batchSize
  if (batches.length <= 1) return batches;
  const merged: ReviewFileRecord[][] = [];
  let current: ReviewFileRecord[] = [];
  for (const batch of batches) {
    if (current.length + batch.length <= batchSize) {
      current.push(...batch);
    } else {
      if (current.length > 0) merged.push(current);
      current = [...batch];
    }
  }
  if (current.length > 0) merged.push(current);
  return merged;
}

// ── Helpers ────────────────────────────────────────────────────────────────

const EXT_LANG: Record<string, string> = {
  ts: "TypeScript", tsx: "TypeScript (React)", js: "JavaScript", jsx: "JavaScript (React)",
  py: "Python", rs: "Rust", go: "Go", java: "Java", cpp: "C++", c: "C",
  cs: "C#", rb: "Ruby", php: "PHP", swift: "Swift", kt: "Kotlin",
};

function extLanguage(filePath: string): string {
  const ext = filePath.split(".").pop() ?? "";
  return EXT_LANG[ext] ?? ext;
}

const MAX_SOURCE_BYTES_PER_FILE = 16_000;
const MAX_SOURCE_BYTES_PER_BATCH = 64_000;

function readBatchSource(rootPath: string, filePath: string, maxBytes: number): string {
  const resolvedRoot = path.resolve(rootPath);
  const resolvedFile = path.resolve(resolvedRoot, filePath);
  const relative = path.relative(resolvedRoot, resolvedFile);
  if (
    relative === "" ||
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new Error(`review file escapes root: ${filePath}`);
  }
  return formatTruncated(fs.readFileSync(resolvedFile, "utf8"), {
    limit: maxBytes,
    mode: "bytes",
  });
}

function batchSlugs(records: ReviewFileRecord[]): string[] {
  const slugs = new Set<string>();
  for (const r of records) {
    for (const c of r.candidates) {
      slugs.add(c.vulnSlug);
    }
  }
  return [...slugs];
}

function batchLanguages(records: ReviewFileRecord[]): string[] {
  const langs = new Set<string>();
  for (const r of records) langs.add(extLanguage(r.filePath));
  return [...langs];
}

function selectRecords(
  records: ReviewFileRecord[],
  reinvestigate?: number,
): ReviewFileRecord[] {
  return records.filter((r) => {
    if (!r.candidates || r.candidates.length === 0) return false;
    if (reinvestigate !== undefined) {
      return !r.analysisHistory.some((e) => e.reinvestigateMarker === reinvestigate);
    }
    return r.status === "pending";
  });
}

function repairPrompt(invalid: ParseResult["invalid"]): string {
  const lines: string[] = [
    "Some findings had validation errors. Please re-emit CORRECTED JSON for ONLY these files and findings.",
    "",
  ];
  for (const inv of invalid) {
    const rawStr = typeof inv.raw === "string"
      ? inv.raw
      : JSON.stringify(inv.raw, null, 2);
    lines.push(`## ${inv.filePath}`, "Issues:", ...inv.issues.map((s) => `  - ${s}`), "Raw:", rawStr, "");
  }
  lines.push(
    'Respond with: [{"filePath": "...", "findings": [...]}]',
    "Fix every issue listed above. Every field must be valid.",
  );
  return lines.join("\n");
}

function invocationCost(inv: { costUsd?: number; usage?: ReviewInvocationUsage }, model?: string): number {
  if (inv.costUsd !== undefined) return inv.costUsd;
  if (inv.usage) return estimateCost(inv.usage, model);
  return 0;
}

interface ReviewInvocationUsage {
  inputTokens: number;
  outputTokens: number;
  cachedInputTokens?: number;
}

function checkLimit(
  cumulativeCost: number,
  startMs: number,
  params: ReviewProcessParams,
): { kind: "cost" | "duration" } | undefined {
  if (params.maxCostUsd !== undefined && cumulativeCost >= params.maxCostUsd) {
    return { kind: "cost" };
  }
  if (params.maxDurationMs !== undefined && Date.now() - startMs >= params.maxDurationMs) {
    return { kind: "duration" };
  }
  return undefined;
}

async function invokeAndCost(
  invoker: ReviewInvoker,
  prompt: string,
  label: string,
  model: string | undefined,
  cumulativeCost: { value: number },
): Promise<ReviewInvocation> {
  const result = await invoker(prompt, label);
  cumulativeCost.value += invocationCost(result, model);
  return result;
}

// ── Main pipeline ──────────────────────────────────────────────────────────

/**
 * Run the full file-review investigation process: select candidate records,
 * batch them by directory, invoke the LLM in investigation → repair → refusal
 * rounds, merge findings into each record, and append analysis history.
 *
 * Supports reinvestigate waves (skips files with an existing marker), cost
 * and duration caps (returns partial result with limitReached), and a bounded
 * worker pool for concurrent batch processing.
 */
export async function runReviewProcess(
  store: ReviewStore,
  params: ReviewProcessParams,
): Promise<ReviewProcessResult> {
  const {
    projectId,
    rootPath,
    invoker,
    assembleSystemPrompt,
    projectInfo,
    batchSize = 5,
    concurrency = 2,
    reinvestigate,
    model,
    agentType = "native",
    log = () => {},
  } = params;

  if (!Number.isSafeInteger(batchSize) || batchSize < 1) {
    throw new RangeError("batchSize must be a positive integer");
  }
  if (!Number.isSafeInteger(concurrency) || concurrency < 1) {
    throw new RangeError("concurrency must be a positive integer");
  }

  const runId = newRunId();
  const runMeta = store.createRunMeta({ projectId, rootPath, type: "process", runId });

  const allRecords = store.listRecords(projectId);
  const candidateRecords = selectRecords(allRecords, reinvestigate);
  if (candidateRecords.length === 0) {
    runMeta.phase = "done";
    runMeta.completedAt = new Date().toISOString();
    store.saveRunMeta(runMeta);
    return { runId, filesInvestigated: 0, findingsAdded: 0, costUsd: 0, refusals: 0 };
  }

  const batches = batchCandidates(candidateRecords, batchSize);
  const allClaimed: string[][] = [];
  let totalFindings = 0;
  let totalRefusals = 0;
  const cumulativeCost = { value: 0 };
  const startMs = Date.now();
  let limitReached: { kind: "cost" | "duration" } | undefined;


  const processBatch = async (
    batchRecords: ReviewFileRecord[],
  ): Promise<void> => {
    const filePaths = batchRecords.map((r) => r.filePath);
    const claimed = store.claimFiles(projectId, runId, filePaths);
    if (claimed.length === 0) return;
    allClaimed.push(claimed);

    const claimedRecs = batchRecords.filter((r) => claimed.includes(r.filePath));
    const sourceBytesPerFile = Math.min(
      MAX_SOURCE_BYTES_PER_FILE,
      Math.floor(MAX_SOURCE_BYTES_PER_BATCH / claimedRecs.length),
    );
    const promptBatch = claimedRecs.map((record) => ({
      filePath: record.filePath,
      candidates: record.candidates,
      source: readBatchSource(rootPath, record.filePath, sourceBytesPerFile),
    }));
    const slugs = batchSlugs(claimedRecs);
    const languages = batchLanguages(claimedRecs);
    const systemPrompt = assembleSystemPrompt
      ? assembleSystemPrompt(slugs, languages)
      : assembleReviewPrompt({
          batchSlugs: slugs,
          batchLanguages: languages,
          projectInfo,
        });
    const promptWithProjectInfo =
      assembleSystemPrompt && projectInfo
        ? `${systemPrompt}\n\n## Project Context\n${projectInfo}`
        : systemPrompt;
    const investigatePrompt = buildInvestigatePrompt({
      systemPrompt: promptWithProjectInfo,
      batch: promptBatch,
    });

    log(`[${runId}] Investigating batch: ${claimed.join(", ")}`);

    // Phase 1: investigate
    const inv1 = await invokeAndCost(invoker, investigatePrompt, "investigate", model, cumulativeCost);
    const { results, invalid } = parseInvestigateResults(inv1.output, claimedRecs);

    // Phase 2: field repair (up to 2 attempts)
    let remaining = invalid;
    for (let attempt = 0; attempt < 2 && remaining.length > 0; attempt++) {
      log(`[${runId}] Repair attempt ${attempt + 1} for ${remaining.length} entries`);
      const repair = await invokeAndCost(
        invoker,
        repairPrompt(remaining),
        "field-repair",
        model,
        cumulativeCost,
      );
      const repaired = parseInvestigateResults(repair.output, claimedRecs);

      // Merge repaired findings into results (dedup by signature)
      for (const rr of repaired.results) {
        const existing = results.find((r) => r.filePath === rr.filePath);
        if (existing) {
          const seen = new Set(existing.findings.map((f) => findingSignature(f)));
          for (const f of rr.findings) {
            if (!seen.has(findingSignature(f))) {
              existing.findings.push(f);
              seen.add(findingSignature(f));
            }
          }
        } else {
          results.push(rr);
        }
      }
      remaining = repaired.invalid;
    }

    if (remaining.length > 0) {
      log(`[${runId}] Dropped ${remaining.length} invalid findings after repair`);
    }

    // Phase 3: refusal audit
    const ref = await invokeAndCost(invoker, REFUSAL_FOLLOWUP_PROMPT, "refusal", model, cumulativeCost);
    const refusalReport = parseRefusalReport(ref.output);
    const batchHasRefusal = refusalReport?.refused === true;
    if (batchHasRefusal) totalRefusals++;

    // Phase 4: write results
    for (const rec of claimedRecs) {
      const record = store.readRecord(projectId, rec.filePath);
      if (!record) continue;

      const fileResults = results.filter((r) => r.filePath === rec.filePath);
      for (const fr of fileResults) {
        mergeFindings(record, fr.findings);
        totalFindings += fr.findings.length;
      }

      const entry: ReviewAnalysisEntry = {
        runId,
        investigatedAt: new Date().toISOString(),
        durationMs: inv1.durationMs,
        agentType,
        model: model ?? inv1.model,
        findingCount: fileResults.reduce((s, r) => s + r.findings.length, 0),
        costUsd: invocationCost(inv1, model),
        usage: inv1.usage,
        refusal: batchHasRefusal ? refusalReport : undefined,
        reinvestigateMarker: reinvestigate,
        agentSessionId: inv1.sessionId,
      };
      appendAnalysis(record, entry);

      if (batchHasRefusal) {
        record.status = "pending";
      } else {
        record.status = "analyzed";
        record.analyzedHash = record.fileHash;
      }
      store.writeRecord(record);
    }

    store.releaseFiles(projectId, runId, claimed, false);
  };

  const failRun = (cause: unknown): never => {
    // A completed record remains analyzed; only a still-processing record is
    // unfinished and must become immediately resumable.
    for (const claimed of allClaimed) {
      store.releaseFiles(projectId, runId, claimed, true);
    }
    runMeta.phase = "error";
    runMeta.completedAt = new Date().toISOString();
    runMeta.stats = {
      findingsCount: totalFindings,
      totalCostUsd: cumulativeCost.value,
    };
    store.saveRunMeta(runMeta);
    throw cause instanceof Error ? cause : new Error(String(cause));
  };

  // Bounded worker pool for concurrent batch processing
  if (concurrency <= 1) {
    try {
      for (const batch of batches) {
        await processBatch(batch);
        const exceeded = checkLimit(cumulativeCost.value, startMs, params);
        if (exceeded) {
          limitReached = exceeded;
          break;
        }
      }
    } catch (err) {
      failRun(err);
    }
  } else {
    let idx = 0;
    const errors: Error[] = [];
    let aborted = false;

    const worker = async (): Promise<void> => {
      while (!aborted) {
        const batchIdx = idx++;
        if (batchIdx >= batches.length) break;

        try {
          await processBatch(batches[batchIdx]);
          const exceeded = checkLimit(cumulativeCost.value, startMs, params);
          if (exceeded) {
            limitReached = exceeded;
            aborted = true;
            break;
          }
        } catch (err) {
          errors.push(err instanceof Error ? err : new Error(String(err)));
          aborted = true;
        }
      }
    };

    const workerCount = Math.min(concurrency, batches.length);
    await Promise.all(Array.from({ length: workerCount }, () => worker()));
    if (errors.length > 0 && !limitReached) {
      failRun(errors[0]);
    }
  }

  // Completed batches remain analyzed. Only a still-locked `processing`
  // record can be incomplete, and it must return to pending for a resume.
  if (limitReached) {
    for (const claimed of allClaimed) {
      store.releaseFiles(projectId, runId, claimed, true);
    }
  }

  // Save run meta
  runMeta.phase = limitReached ? "limit" : "done";
  runMeta.completedAt = new Date().toISOString();
  runMeta.stats = {
    findingsCount: totalFindings,
    totalCostUsd: cumulativeCost.value,
  };
  if (limitReached) {
    runMeta.limitReached = limitReached;
  }
  store.saveRunMeta(runMeta);

  return {
    runId,
    filesInvestigated: allClaimed.flat().length,
    findingsAdded: totalFindings,
    costUsd: cumulativeCost.value,
    refusals: totalRefusals,
    limitReached,
  };
}