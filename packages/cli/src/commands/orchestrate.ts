import { randomUUID } from "node:crypto";
import { hostname } from "node:os";
import type { Command } from "commander";
import chalk from "chalk";
import { agenticScan, createRuntime, LlmApiRuntime, runAgentLoop, getToolsForRole } from "@pwnkit/core";
import { pwnkitDB } from "@pwnkit/db";
import type { Finding, RuntimeMode, ScanDepth, ScanMode, WorkItemKind, WorkItemRecord, WorkerRecord, WorkerStatus } from "@pwnkit/shared";

type OrchestrateOptions = {
  dbPath?: string;
  limit?: string;
  runtime?: string;
  timeout?: string;
  apiKey?: string;
  model?: string;
  watch?: boolean;
  pollInterval?: string;
  label?: string;
};

type PersistedScan = {
  id: string;
  target: string;
  depth: string;
  runtime: string;
  mode: string;
  status: string;
};

type PersistedCase = {
  id: string;
  target: string;
  targetType: string;
  latestScanId?: string | null;
};

type RunnableCandidate = {
  item: WorkItemRecord;
  caseRecord: PersistedCase;
  scan: PersistedScan;
  target: string;
  targetType: "url" | "web-app";
  mode: ScanMode;
};

type FamilyFindingRow = {
  id: string;
  scanId: string;
  templateId: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  status: string;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis?: string | null;
  timestamp: number;
};

const EXECUTABLE_KINDS: WorkItemKind[] = [
  "surface_map",
  "hypothesis",
  "poc_build",
  "blind_verify",
  "consensus",
];

const KIND_PRIORITY: Record<WorkItemKind, number> = {
  surface_map: 0,
  hypothesis: 1,
  poc_build: 2,
  blind_verify: 3,
  consensus: 4,
  human_review: 5,
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function findingRowsToFindings(rows: FamilyFindingRow[]): Finding[] {
  return rows.map((row) => ({
    id: row.id,
    templateId: row.templateId,
    title: row.title,
    description: row.description,
    severity: row.severity as Finding["severity"],
    category: row.category as Finding["category"],
    status: row.status as Finding["status"],
    evidence: {
      request: row.evidenceRequest,
      response: row.evidenceResponse,
      analysis: row.evidenceAnalysis ?? undefined,
    },
    timestamp: row.timestamp,
  }));
}

function parseTargetForExecution(target: string, scanMode?: string | null): {
  target: string;
  targetType: "url" | "web-app" | null;
  mode: ScanMode;
} {
  if (target.startsWith("web:")) {
    return {
      target: target.slice("web:".length),
      targetType: "web-app",
      mode: "web",
    };
  }

  if (target.startsWith("http://") || target.startsWith("https://")) {
    return {
      target,
      targetType: "url",
      mode: (scanMode as ScanMode | undefined) ?? "deep",
    };
  }

  if (target.startsWith("mcp://")) {
    return {
      target,
      targetType: "url",
      mode: "mcp",
    };
  }

  if (target.startsWith("scan:")) {
    return {
      target: target.slice("scan:".length),
      targetType: "url",
      mode: (scanMode as ScanMode | undefined) ?? "deep",
    };
  }

  return {
    target,
    targetType: null,
    mode: (scanMode as ScanMode | undefined) ?? "deep",
  };
}

function isRunnable(
  item: WorkItemRecord,
  workItemsById: Map<string, WorkItemRecord>,
  workItemsByCaseId: Map<string, WorkItemRecord[]>,
): boolean {
  if (!EXECUTABLE_KINDS.includes(item.kind)) return false;
  if (item.status !== "todo") return false;

  const dependency = item.dependsOn ? workItemsById.get(item.dependsOn) : null;
  if (item.dependsOn && dependency?.status !== "done") return false;

  const siblings = workItemsByCaseId.get(item.caseId) ?? [];
  if (siblings.some((candidate) => candidate.id !== item.id && candidate.status === "in_progress")) {
    return false;
  }

  return true;
}

function buildWorkerRecord(args: {
  id: string;
  label: string;
  status: WorkerStatus;
  currentCaseId?: string | null;
  currentWorkItemId?: string | null;
  currentScanId?: string | null;
  lastError?: string | null;
}): Omit<WorkerRecord, "startedAt" | "updatedAt" | "heartbeatAt"> {
  return {
    id: args.id,
    role: "orchestrator",
    status: args.status,
    label: args.label,
    currentCaseId: args.currentCaseId ?? null,
    currentWorkItemId: args.currentWorkItemId ?? null,
    currentScanId: args.currentScanId ?? null,
    pid: process.pid,
    host: hostname(),
    lastError: args.lastError ?? null,
  };
}

function touchWorker(
  dbPath: string | undefined,
  worker: Omit<WorkerRecord, "startedAt" | "updatedAt" | "heartbeatAt">,
): void {
  const db = new pwnkitDB(dbPath);
  try {
    db.upsertWorker(worker);
  } finally {
    db.close();
  }
}

function stopSupersededWorkers(
  dbPath: string | undefined,
  label: string,
  workerId: string,
): number {
  const db = new pwnkitDB(dbPath);
  try {
    return db.stopWorkersByLabel(label, workerId);
  } finally {
    db.close();
  }
}

export function recoverStaleWorkers(dbPath: string | undefined, staleAfterMs = 30_000): number {
  const db = new pwnkitDB(dbPath);

  try {
    const workers = db.listWorkers(100) as WorkerRecord[];
    const workItems = db.listWorkItems({ limit: 5000 }) as WorkItemRecord[];
    const workItemsById = new Map(workItems.map((item) => [item.id, item]));
    let recovered = 0;

    for (const worker of workers) {
      if (worker.status === "stopped") continue;
      const heartbeatAge = Date.now() - Date.parse(worker.heartbeatAt);
      if (Number.isNaN(heartbeatAge) || heartbeatAge < staleAfterMs) continue;

      if (worker.currentWorkItemId) {
        const item = workItemsById.get(worker.currentWorkItemId);
        if (item && item.status === "in_progress") {
          db.upsertWorkItem({
            ...item,
            status: "todo",
            summary: `Recovered after stale worker ${worker.label} stopped heartbeating.`,
          });
          recovered += 1;
        }
      }

      db.upsertWorker({
        id: worker.id,
        role: "orchestrator",
        status: "error",
        label: worker.label,
        currentCaseId: null,
        currentWorkItemId: null,
        currentScanId: null,
        pid: worker.pid ?? null,
        host: worker.host ?? null,
        lastError: `Heartbeat expired after ${Math.round(heartbeatAge / 1000)}s.`,
      });
    }

    return recovered;
  } finally {
    db.close();
  }
}

function findRunnableCandidates(
  dbPath: string | undefined,
  limit: number,
): RunnableCandidate[] {
  const db = new pwnkitDB(dbPath);

  try {
    const allWorkItems = db.listWorkItems({ limit: 5000 }) as WorkItemRecord[];
    const workItemsById = new Map(allWorkItems.map((item) => [item.id, item]));
    const workItemsByCaseId = new Map<string, WorkItemRecord[]>();
    for (const item of allWorkItems) {
      const list = workItemsByCaseId.get(item.caseId) ?? [];
      list.push(item);
      workItemsByCaseId.set(item.caseId, list);
    }

    const runnable = allWorkItems
      .filter((item) => isRunnable(item, workItemsById, workItemsByCaseId))
      .sort((left, right) => {
        const leftPriority = KIND_PRIORITY[left.kind] ?? 999;
        const rightPriority = KIND_PRIORITY[right.kind] ?? 999;
        if (leftPriority !== rightPriority) return leftPriority - rightPriority;
        return new Date(left.updatedAt).getTime() - new Date(right.updatedAt).getTime();
      });

    const queuedByCase = new Map<string, WorkItemRecord>();
    for (const item of runnable) {
      if (!queuedByCase.has(item.caseId)) queuedByCase.set(item.caseId, item);
    }

    const selected = [...queuedByCase.values()].slice(0, limit);
    const candidates: RunnableCandidate[] = [];

    for (const item of selected) {
      const caseRecord = db.getCase(item.caseId) as PersistedCase | undefined;
      if (!caseRecord) continue;

      const familyScanId = item.findingFingerprint
        ? (db.getRelatedFindings(item.findingFingerprint)?.[0] as { scanId?: string } | undefined)?.scanId
        : null;
      const scanId = familyScanId ?? caseRecord.latestScanId;
      if (!scanId) continue;

      const scan = db.getScan(scanId) as PersistedScan | undefined;
      if (!scan || scan.status === "running") continue;

      const resolved = parseTargetForExecution(scan.target, scan.mode);
      if (!resolved.targetType) continue;

      candidates.push({
        item,
        caseRecord,
        scan,
        target: resolved.target,
        targetType: resolved.targetType,
        mode: resolved.mode,
      });
    }

    return candidates;
  } finally {
    db.close();
  }
}

function summarizeFindingsBySeverity(findings: Array<{ severity: string }>) {
  const summary = {
    totalFindings: findings.length,
    totalAttacks: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const finding of findings) {
    if (finding.severity === "critical") summary.critical += 1;
    else if (finding.severity === "high") summary.high += 1;
    else if (finding.severity === "medium") summary.medium += 1;
    else if (finding.severity === "low") summary.low += 1;
    else summary.info += 1;
  }

  return summary;
}

function reconcileCandidateOutcome(
  dbPath: string | undefined,
  candidate: RunnableCandidate,
  result: { ok: true } | { ok: false; message: string },
): void {
  const db = new pwnkitDB(dbPath);

  try {
    const current = (db.listWorkItems({ caseId: candidate.item.caseId, limit: 5000 }) as WorkItemRecord[])
      .find((item) => item.id === candidate.item.id) ?? candidate.item;

    if (result.ok) {
      if (current.status === "in_progress") {
        db.upsertWorkItem({
          ...current,
          status: "done",
          summary: current.summary ?? "Completed by autonomous worker.",
        });
      }

      db.logEvent({
        scanId: candidate.scan.id,
        stage: candidate.item.kind,
        eventType: "worker_completed",
        findingId: candidate.item.findingFingerprint
          ? (db.getRelatedFindings(candidate.item.findingFingerprint)?.[0] as { id?: string } | undefined)?.id
          : undefined,
        agentRole: candidate.item.owner ?? undefined,
        payload: {
          caseId: candidate.caseRecord.id,
          workItemId: candidate.item.id,
          kind: candidate.item.kind,
          fingerprint: candidate.item.findingFingerprint ?? null,
          status: "done",
        },
        timestamp: Date.now(),
      });

      const findings = db.getFindings(candidate.scan.id) as Array<{ severity: string }>;
      db.completeScan(candidate.scan.id, summarizeFindingsBySeverity(findings));
      return;
    }

    if (current.status === "in_progress") {
      db.upsertWorkItem({
        ...current,
        status: "blocked",
        summary: result.message,
      });
    }
    db.logEvent({
      scanId: candidate.scan.id,
      stage: candidate.item.kind,
      eventType: "worker_failed",
      findingId: candidate.item.findingFingerprint
        ? (db.getRelatedFindings(candidate.item.findingFingerprint)?.[0] as { id?: string } | undefined)?.id
        : undefined,
      agentRole: candidate.item.owner ?? undefined,
      payload: {
        caseId: candidate.caseRecord.id,
        workItemId: candidate.item.id,
        kind: candidate.item.kind,
        fingerprint: candidate.item.findingFingerprint ?? null,
        status: "blocked",
        error: result.message,
      },
      timestamp: Date.now(),
    });
    db.failScan(candidate.scan.id, result.message);
  } finally {
    db.close();
  }
}

function claimCandidate(
  dbPath: string | undefined,
  workerId: string,
  label: string,
  candidate: RunnableCandidate,
): boolean {
  const db = new pwnkitDB(dbPath);

  try {
    const claimed = db.claimWorkItem(candidate.item.id, workerId, {
      owner: label,
      summary: candidate.item.findingFingerprint
        ? `Claimed family work by ${label}; resuming the parent scan as a family-aware bridge.`
        : `Claimed by ${label} for autonomous execution.`,
    });

    if (!claimed) return false;

    db.reopenScan(candidate.scan.id);
    db.logEvent({
      scanId: candidate.scan.id,
      stage: candidate.item.kind,
      eventType: "worker_claimed",
      findingId: candidate.item.findingFingerprint
        ? (db.getRelatedFindings(candidate.item.findingFingerprint)?.[0] as { id?: string } | undefined)?.id
        : undefined,
      agentRole: label,
      payload: {
        caseId: candidate.caseRecord.id,
        workItemId: candidate.item.id,
        kind: candidate.item.kind,
        fingerprint: candidate.item.findingFingerprint ?? null,
        owner: label,
      },
      timestamp: Date.now(),
    });
    db.upsertWorker(
      buildWorkerRecord({
        id: workerId,
        label,
        status: "running",
        currentCaseId: candidate.caseRecord.id,
        currentWorkItemId: candidate.item.id,
        currentScanId: candidate.scan.id,
      }),
    );
    return true;
  } finally {
    db.close();
  }
}

async function runCandidate(
  candidate: RunnableCandidate,
  opts: OrchestrateOptions,
): Promise<{ ok: true } | { ok: false; message: string }> {
  if (candidate.item.findingFingerprint) {
    return runFamilyCandidate(candidate, opts);
  }

  try {
    const report = await agenticScan({
      config: {
        target: candidate.target,
        depth: candidate.scan.depth as ScanDepth,
        format: "json",
        runtime: (opts.runtime as RuntimeMode | undefined) ?? (candidate.scan.runtime as RuntimeMode) ?? "auto",
        mode: candidate.mode,
        timeout: parseInt(opts.timeout ?? "30000", 10),
        verbose: false,
        apiKey: opts.apiKey,
        model: opts.model,
      },
      dbPath: opts.dbPath,
      resumeScanId: candidate.scan.id,
    });

    console.log(
      chalk.green(
        `  completed ${candidate.item.kind}: ${report.summary.totalFindings} findings, ${report.summary.critical} critical, ${report.summary.high} high`,
      ),
    );
    return { ok: true };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log(chalk.red(`  failed ${candidate.item.kind}: ${message}`));
    return { ok: false, message };
  }
}

function familyAttackPrompt(
  target: string,
  kind: WorkItemKind,
  fingerprint: string,
  latest: Finding,
): string {
  return `You are pwnkit's family execution agent.

Target: ${target}
Finding family fingerprint: ${fingerprint}
Current work item: ${kind}

Representative family finding:
- Title: ${latest.title}
- Category: ${latest.category}
- Severity: ${latest.severity}
- Existing request: ${latest.evidence.request.slice(0, 500)}
- Existing response: ${latest.evidence.response.slice(0, 500)}
- Existing analysis: ${(latest.evidence.analysis ?? "none").slice(0, 500)}

Your job:
1. Reproduce and refine this specific family only.
2. Focus on stronger evidence, cleaner reproduction, and better exploit framing.
3. Use http_request and send_prompt against the live target.
4. If you discover stronger or more precise evidence, call save_finding.
5. Query existing findings to avoid pointless duplication.
6. Call done with a concise summary of what changed for this family.

Do not broadly scan unrelated attack categories. Stay on this family.`;
}

function familyVerifyPrompt(target: string, findings: Finding[]): string {
  const findingList = findings
    .map(
      (f, index) =>
        `${index + 1}. ID: ${f.id}\n   Title: ${f.title}\n   Category: ${f.category}\n   Severity: ${f.severity}\n   Request: ${f.evidence.request.slice(0, 220)}\n   Response: ${f.evidence.response.slice(0, 220)}`,
    )
    .join("\n\n");

  return `You are pwnkit's blind family verification agent.

Target: ${target}

You must independently verify ONLY these family findings:

${findingList || "No findings supplied."}

For each finding:
1. Replay the evidence against the target.
2. If the issue reproduces, call update_finding with status "confirmed".
3. If it does not reproduce after a few focused retries, call update_finding with status "false-positive".
4. Do not invent new unrelated findings here.
5. Call done with a concise verification summary.`;
}

async function runFamilyCandidate(
  candidate: RunnableCandidate,
  opts: OrchestrateOptions,
): Promise<{ ok: true } | { ok: false; message: string }> {
  const fingerprint = candidate.item.findingFingerprint;
  if (!fingerprint) {
    return { ok: false, message: "Family candidate is missing a fingerprint." };
  }

  const db = new pwnkitDB(opts.dbPath);

  try {
    const rows = db.getRelatedFindings(fingerprint) as FamilyFindingRow[];
    if (rows.length === 0) {
      return { ok: false, message: `No persisted findings found for family ${fingerprint}.` };
    }

    const findings = findingRowsToFindings(rows);
    const latest = findings[0]!;
    const runtime =
      !opts.runtime || opts.runtime === "auto" || opts.runtime === "api"
        ? new LlmApiRuntime({
            type: "api",
            timeout: parseInt(opts.timeout ?? "30000", 10),
            apiKey: opts.apiKey,
            model: opts.model,
          })
        : createRuntime({
            type: opts.runtime as "claude" | "codex" | "gemini" | "api",
            timeout: parseInt(opts.timeout ?? "30000", 10),
            apiKey: opts.apiKey,
            model: opts.model,
          });

    if (candidate.item.kind === "consensus") {
      const latestRow = rows[0];
      const consensus = latestRow ? db.computeConsensus(latestRow.id) : "pending";

      if (consensus === "verified" || consensus === "false-positive") {
        db.updateFindingWorkflowByFingerprint(fingerprint, "human_review", candidate.item.owner ?? null);
      } else {
        db.upsertWorkItem({
          ...candidate.item,
          status: "blocked",
          owner: candidate.item.owner ?? "consensus-agent",
          summary:
            consensus === "disputed"
              ? "Verifier votes disagree. Route this family into agent review instead of retrying consensus."
              : "Consensus could not complete because verifier evidence is incomplete.",
        });
      }
      return { ok: true };
    }

    const role = candidate.item.kind === "blind_verify" ? "verify" : "attack";
    const systemPrompt =
      role === "verify"
        ? familyVerifyPrompt(candidate.target, findings)
        : familyAttackPrompt(candidate.target, candidate.item.kind, fingerprint, latest);

    await runAgentLoop({
      config: {
        role,
        systemPrompt,
        tools: getToolsForRole(role),
        maxTurns: role === "verify" ? 8 : 10,
        target: candidate.target,
        scanId: candidate.scan.id,
      },
      runtime,
      db,
    });

    return { ok: true };
  } catch (error) {
    return { ok: false, message: error instanceof Error ? error.message : String(error) };
  } finally {
    db.close();
  }
}

export function registerOrchestrateCommand(program: Command): void {
  program
    .command("orchestrate")
    .description("Run the autonomous verification worker against persisted queued case work")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--limit <n>", "Maximum queued cases to claim per pass", "1")
    .option("--runtime <runtime>", "Runtime override: auto, claude, codex, gemini, api")
    .option("--timeout <ms>", "Request timeout in milliseconds", "30000")
    .option("--api-key <key>", "API key for LLM provider")
    .option("--model <model>", "LLM model to use")
    .option("--watch", "Run as a persistent daemon loop", false)
    .option("--poll-interval <ms>", "Idle poll interval for watch mode", "5000")
    .option("--label <name>", "Operator-facing worker label")
    .action(async (opts: OrchestrateOptions) => {
      const workerId = `orchestrator:${randomUUID()}`;
      const label = opts.label?.trim() || `${hostname()}:${process.pid}`;
      const limit = Math.max(1, parseInt(opts.limit ?? "1", 10));
      const pollInterval = Math.max(1000, parseInt(opts.pollInterval ?? "5000", 10));

      let stopping = false;
      let heartbeat: ReturnType<typeof setInterval> | null = null;
      let workerState: {
        status: WorkerStatus;
        currentCaseId?: string | null;
        currentWorkItemId?: string | null;
        currentScanId?: string | null;
        lastError?: string | null;
      } = {
        status: "idle",
        currentCaseId: null,
        currentWorkItemId: null,
        currentScanId: null,
        lastError: null,
      };

      const updateWorker = (
        status: WorkerStatus,
        state?: {
          currentCaseId?: string | null;
          currentWorkItemId?: string | null;
          currentScanId?: string | null;
          lastError?: string | null;
        },
      ) => {
        workerState = {
          status,
          currentCaseId: state?.currentCaseId ?? null,
          currentWorkItemId: state?.currentWorkItemId ?? null,
          currentScanId: state?.currentScanId ?? null,
          lastError: state?.lastError ?? null,
        };
        touchWorker(
          opts.dbPath,
          buildWorkerRecord({
            id: workerId,
            label,
            status: workerState.status,
            currentCaseId: workerState.currentCaseId,
            currentWorkItemId: workerState.currentWorkItemId,
            currentScanId: workerState.currentScanId,
            lastError: workerState.lastError,
          }),
        );
      };

      const stop = () => {
        stopping = true;
      };

      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);

      stopSupersededWorkers(opts.dbPath, label, workerId);
      updateWorker("idle");
      heartbeat = setInterval(() => {
        try {
          touchWorker(
            opts.dbPath,
            buildWorkerRecord({
              id: workerId,
              label,
              status: workerState.status,
              currentCaseId: workerState.currentCaseId,
              currentWorkItemId: workerState.currentWorkItemId,
              currentScanId: workerState.currentScanId,
              lastError: workerState.lastError,
            }),
          );
        } catch {
          // Ignore transient heartbeat failures; the main loop will retry on next pass.
        }
      }, Math.min(pollInterval, 5_000));

      console.log(chalk.red.bold("◆ pwnkit") + chalk.gray(opts.watch ? ` daemon ${label} online` : ` worker ${label} starting`));

      try {
        do {
          if (stopping) break;

          const recovered = recoverStaleWorkers(opts.dbPath);
          if (recovered > 0) {
            console.log(chalk.yellow(`Recovered ${recovered} stale work item${recovered === 1 ? "" : "s"} from dead workers.`));
          }

          updateWorker("claiming");
          const candidates = findRunnableCandidates(opts.dbPath, limit);

          if (candidates.length === 0) {
            updateWorker(opts.watch ? "sleeping" : "idle");
            if (!opts.watch) {
              console.log(chalk.gray("No runnable autonomous case work found."));
              break;
            }
            await sleep(pollInterval);
            continue;
          }

          for (const candidate of candidates) {
            if (stopping) break;

            const claimed = claimCandidate(opts.dbPath, workerId, label, candidate);
            if (!claimed) continue;

    console.log("");
    console.log(chalk.white(candidate.caseRecord.target));
    console.log(
      chalk.gray(
        `  running ${candidate.item.kind}${candidate.item.findingFingerprint ? ` for family ${candidate.item.findingFingerprint.slice(0, 10)}` : ""} via ${label}`,
      ),
    );

            const result = await runCandidate(candidate, opts);
            reconcileCandidateOutcome(opts.dbPath, candidate, result);
            if (!result.ok) {
              updateWorker("error", {
                currentCaseId: candidate.caseRecord.id,
                currentWorkItemId: candidate.item.id,
                currentScanId: candidate.scan.id,
                lastError: result.message,
              });
            } else {
              updateWorker("idle");
            }
          }

          if (!opts.watch) break;
        } while (!stopping);
      } finally {
        if (heartbeat) clearInterval(heartbeat);
        updateWorker("stopped");
      }
    });
}
