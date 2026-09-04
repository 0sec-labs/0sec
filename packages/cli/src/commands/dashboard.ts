import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { URL } from "node:url";
import { isIP } from "node:net";
import type { Command } from "commander";
import chalk from "chalk";
import { z } from "zod";
import {
  createPresentationEvent,
  type FindingTriageStatus,
  type PresentationEvent,
  type PresentationSource,
} from "@0sec/shared";
import { readToolCallNames } from "@0sec/core";
import { presentationEventBus } from "../presentation/event-bus.js";
import { buildFindingConsoleCommand } from "../finding-handoff.js";
import { DesktopConsoleGateway, DesktopConsoleGatewayError } from "../desktop/console-gateway.js";
import { DesktopCodexAuthController } from "../desktop/codex-auth-controller.js";

type DashboardOptions = {
  dbPath?: string;
  port?: string;
  host?: string;
  assetDir?: string;
  readyJson?: boolean;
  // Commander 12 maps `--no-open` to `opts.open = false` (not `opts.noOpen = true`).
  // See: https://github.com/tj/commander.js/blob/master/Readme.md#other-option-types-negatable-boolean-and-booleanvalue
  open?: boolean;
};

type ManagedDaemonState = {
  child: ChildProcess;
  label: string;
};

let managedDaemon: ManagedDaemonState | null = null;

type DBFindingRow = {
  id: string;
  scanId: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  status: string;
  fingerprint?: string | null;
  triageStatus?: string | null;
  triageNote?: string | null;
  workflowStatus?: string | null;
  workflowAssignee?: string | null;
  workflowUpdatedAt?: string | null;
  timestamp: number;
  score?: number | null;
  confidence?: number | null;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis?: string | null;
};

type DBScanRow = {
  id: string;
  target: string;
  depth: string;
  runtime: string;
  mode: string;
  status: string;
  startedAt: string;
  completedAt?: string | null;
  durationMs?: number | null;
  summary?: string | null;
};

type DBEventRow = {
  id: string;
  scanId: string;
  stage: string;
  eventType: string;
  findingId?: string | null;
  agentRole?: string | null;
  source?: string;
  payload: string;
  timestamp: number;
};

type DashboardRecentEventRow = DBEventRow & {
  scanTarget: string;
  findingFingerprint?: string | null;
};

type DBVerdictRow = {
  id: string;
  findingId: string;
  agentRole: string;
  model: string;
  verdict: string;
  confidence: number;
  reasoning: string;
  timestamp: number;
};

type DBSessionRow = {
  id: string;
  scanId: string;
  agentRole: string;
  turnCount: number;
  messages: string;
  toolContext: string;
  status: string;
  createdAt: string;
  updatedAt: string;
};

type DBWorkerRow = {
  id: string;
  role: string;
  status: string;
  label: string;
  currentCaseId?: string | null;
  currentWorkItemId?: string | null;
  currentScanId?: string | null;
  pid?: number | null;
  host?: string | null;
  lastError?: string | null;
  heartbeatAt: string;
  startedAt: string;
  updatedAt: string;
};

type DBWorkItemRow = {
  id: string;
  caseId: string;
  findingFingerprint?: string | null;
  kind: string;
  title: string;
  owner?: string | null;
  status: string;
  summary?: string | null;
  dependsOn?: string | null;
  createdAt: string;
  updatedAt: string;
};

const VALID_TRIAGE_STATUSES = new Set<FindingTriageStatus>(["new", "accepted", "suppressed"]);
const VALID_WORKFLOW_STATUSES = new Set<FindingWorkflowStatus>([
  "backlog",
  "todo",
  "agent_review",
  "in_progress",
  "human_review",
  "blocked",
  "done",
  "cancelled",
]);
const CONTENT_TYPES: Record<string, string> = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

function openBrowser(url: string): void {
  const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  execFile(cmd, args, () => {});
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(body));
}

function text(res: ServerResponse, status: number, body: string, contentType = "text/plain; charset=utf-8"): void {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function sendFile(res: ServerResponse, filePath: string, controlToken?: string): void {
  const ext = extname(filePath);
  const contentType = CONTENT_TYPES[ext] ?? "application/octet-stream";
  res.writeHead(200, {
    "Content-Type": contentType,
    "Cache-Control": ext === ".html" ? "no-store" : "public, max-age=300",
  });
  let content: string | Buffer = readFileSync(filePath);
  // Inject the per-session control token into HTML pages so the dashboard
  // frontend can attach it to control API requests.
  if (controlToken && ext === ".html") {
    content = content.toString().replace(
      "</head>",
      `<meta name="0sec-control-token" content="${controlToken}"></head>`,
    );
  }
  res.end(content);
}

function readJson(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 1_000_000) {
        reject(new Error("Request body too large"));
      }
    });
    req.on("end", () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function normalizeTriageStatus(value?: string | null): FindingTriageStatus {
  return value && VALID_TRIAGE_STATUSES.has(value as FindingTriageStatus)
    ? value as FindingTriageStatus
    : "new";
}

function inferWorkflowStatus(row: {
  status?: string | null;
  triageStatus?: string | null;
}): FindingWorkflowStatus {
  if (row.triageStatus === "accepted" || row.status === "reported" || row.status === "fixed") return "done";
  if (row.triageStatus === "suppressed" || row.status === "false-positive") return "cancelled";
  if (row.status && ["verified", "confirmed", "scored"].includes(row.status)) return "human_review";
  return "backlog";
}

function normalizeWorkflowStatus(value?: string | null, row?: {
  status?: string | null;
  triageStatus?: string | null;
}): FindingWorkflowStatus {
  if (value && VALID_WORKFLOW_STATUSES.has(value as FindingWorkflowStatus)) {
    return value as FindingWorkflowStatus;
  }
  return inferWorkflowStatus(row ?? {});
}

function parseSummary(summary?: string | null): Record<string, number> {
  if (!summary) return {};
  try {
    return JSON.parse(summary) as Record<string, number>;
  } catch {
    return {};
  }
}

function parsePayload(payload: string): Record<string, unknown> | null {
  try {
    return JSON.parse(payload) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function presentationEventFromDashboardRow(
  event: DashboardRecentEventRow,
  sequence: number,
): PresentationEvent {
  const payload = parsePayload(event.payload);
  const at = Number.isFinite(event.timestamp)
    ? new Date(event.timestamp).toISOString()
    : new Date(0).toISOString();
  const source: PresentationSource =
    event.source === "cli" || event.source === "dashboard" || event.source === "adapter"
      ? event.source
      : "core";
  return createPresentationEvent({
    source,
    sequence,
    at,
    eventType: event.eventType,
    payload: payload ?? { rawPayload: event.payload },
    scanId: event.scanId,
  });
}

function summarizeRecentEvent(event: {
  stage: string;
  eventType: string;
  payload: Record<string, unknown> | null;
}): string {
  const payload = event.payload ?? {};
  const headline =
    typeof payload.summary === "string" && payload.summary.trim()
      ? payload.summary.trim()
      : typeof payload.message === "string" && payload.message.trim()
        ? payload.message.trim()
        : typeof payload.reason === "string" && payload.reason.trim()
          ? payload.reason.trim()
          : typeof payload.status === "string" && payload.status.trim()
            ? payload.status.trim()
            : null;

  if (headline) return headline;

  // `tool_calls` rows come in two shapes: action-level rows carry
  // `calls[].name`, rows written before that upgrade carry only
  // `tools: string[]`. This is an append-only audit table — read both.
  const toolNames = readToolCallNames(payload);
  if (toolNames.length > 0) {
    const turn = typeof payload.turn === "number" ? `turn ${payload.turn} · ` : "";
    return `${turn}tools: ${toolNames.join(", ")}`;
  }

  if (typeof payload.excerpt === "string" && payload.excerpt.trim()) {
    const turn = typeof payload.turn === "number" ? `turn ${payload.turn} · ` : "";
    return `${turn}no tool calls · ${payload.excerpt.trim().slice(0, 120)}`;
  }

  const fields = [
    payload.target,
    payload.kind,
    payload.templateId,
    payload.verdict,
    payload.owner,
  ]
    .filter((value): value is string => typeof value === "string" && value.trim().length > 0)
    .slice(0, 2);

  if (fields.length > 0) return fields.join(" · ");
  return `${event.stage} ${event.eventType}`.replaceAll("_", " ");
}

function summarizeScan(scan: DBScanRow) {
  const summary = parseSummary(scan.summary);
  return {
    id: scan.id,
    target: scan.target,
    depth: scan.depth,
    runtime: scan.runtime,
    mode: scan.mode,
    status: scan.status,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt ?? null,
    durationMs: scan.durationMs ?? null,
    summary: {
      totalFindings: summary.totalFindings ?? 0,
      totalAttacks: summary.totalAttacks ?? 0,
      critical: summary.critical ?? 0,
      high: summary.high ?? 0,
      medium: summary.medium ?? 0,
      low: summary.low ?? 0,
      info: summary.info ?? 0,
    },
  };
}

function summarizeWorker(
  worker: DBWorkerRow,
  workItemsById: Map<string, DBWorkItemRow>,
  casesById: Map<string, { target: string }>,
) {
  const heartbeatFresh = Date.now() - Date.parse(worker.heartbeatAt) < 20_000;
  const currentWorkItem = worker.currentWorkItemId ? workItemsById.get(worker.currentWorkItemId) : null;
  const currentCase = worker.currentCaseId ? casesById.get(worker.currentCaseId) : null;
  return {
    id: worker.id,
    role: worker.role === "orchestrator" ? "orchestrator" : "orchestrator",
    status: worker.status,
    label: worker.label,
    currentCaseId: worker.currentCaseId ?? null,
    currentCaseTarget: currentCase?.target ?? null,
    currentWorkItemId: worker.currentWorkItemId ?? null,
    currentWorkItemTitle: currentWorkItem?.title ?? null,
    currentWorkItemKind: (currentWorkItem?.kind as "surface_map" | "hypothesis" | "poc_build" | "blind_verify" | "consensus" | "human_review" | undefined) ?? null,
    currentScanId: worker.currentScanId ?? null,
    pid: worker.pid ?? null,
    host: worker.host ?? null,
    lastError: worker.lastError ?? null,
    heartbeatAt: worker.heartbeatAt,
    startedAt: worker.startedAt,
    updatedAt: worker.updatedAt,
    isActive: heartbeatFresh && worker.status !== "stopped",
  };
}

const EXECUTABLE_WORK_KINDS = new Set(["surface_map", "hypothesis", "poc_build", "blind_verify", "consensus"]);

function summarizeQueue(workItems: DBWorkItemRow[], workers: DBWorkerRow[]) {
  const executableScope = workItems.filter((item) => Boolean(item.findingFingerprint));
  const workItemsById = new Map(executableScope.map((item) => [item.id, item] as const));
  const workItemsByCaseId = new Map<string, DBWorkItemRow[]>();

  for (const item of executableScope) {
    const list = workItemsByCaseId.get(item.caseId) ?? [];
    list.push(item);
    workItemsByCaseId.set(item.caseId, list);
  }

  let runnable = 0;
  let blockedByDependency = 0;
  let active = 0;
  let manualReview = 0;
  let recoveredClaims = 0;

  for (const item of executableScope) {
    if (item.status === "in_progress") active += 1;
    if (item.kind === "human_review" && item.status === "todo") manualReview += 1;
    if (item.summary?.includes("Recovered after stale worker")) recoveredClaims += 1;

    if (!EXECUTABLE_WORK_KINDS.has(item.kind)) continue;
    const dependency = item.dependsOn ? workItemsById.get(item.dependsOn) : null;
    const siblings = workItemsByCaseId.get(item.caseId) ?? [];
    const hasActiveSibling = siblings.some((candidate) => candidate.id !== item.id && candidate.status === "in_progress");
    const dependencyDone = !item.dependsOn || dependency?.status === "done";

    if (item.status === "todo" && dependencyDone && !hasActiveSibling) {
      runnable += 1;
    } else if ((item.status === "todo" || item.status === "backlog") && !dependencyDone) {
      blockedByDependency += 1;
    }
  }

  const staleWorkers = workers.filter(
    (worker) => worker.status === "error" && typeof worker.lastError === "string" && worker.lastError.includes("Heartbeat expired"),
  ).length;

  return {
    runnable,
    active,
    blockedByDependency,
    manualReview,
    staleWorkers,
    recoveredClaims,
  };
}

function normalizeFinding(row: DBFindingRow) {
  return {
    ...row,
    triageStatus: normalizeTriageStatus(row.triageStatus),
    workflowStatus: normalizeWorkflowStatus(row.workflowStatus, row),
    workflowAssignee: row.workflowAssignee ?? null,
    workflowUpdatedAt: row.workflowUpdatedAt ?? null,
  };
}

function buildWorkflowSummary(
  rows: DBFindingRow[],
  verdicts: DBVerdictRow[],
  sessions: DBSessionRow[],
) {
  const latest = rows[0]!;
  const verdictCounts = verdicts.reduce(
    (acc, verdict) => {
      if (verdict.verdict === "TRUE_POSITIVE") acc.truePositive += 1;
      else if (verdict.verdict === "FALSE_POSITIVE") acc.falsePositive += 1;
      else acc.unsure += 1;
      acc.total += 1;
      return acc;
    },
    { truePositive: 0, falsePositive: 0, unsure: 0, total: 0 },
  );

  let consensus: "verified" | "false-positive" | "disputed" | "pending" = "pending";
  if (verdictCounts.total > 0) {
    if (verdictCounts.truePositive === verdictCounts.total) consensus = "verified";
    else if (verdictCounts.falsePositive === verdictCounts.total) consensus = "false-positive";
    else consensus = "disputed";
  } else if (latest.status === "false-positive") {
    consensus = "false-positive";
  } else if (["verified", "confirmed", "scored", "reported", "fixed"].includes(latest.status)) {
    consensus = "verified";
  }

  const activeAgentRoles = [...new Set(
    sessions
      .filter((session) => session.status === "running")
      .map((session) => session.agentRole),
  )];

  const persistedStatus = normalizeWorkflowStatus(latest.workflowStatus, latest);
  const evidenceSignal =
    consensus === "verified" || latest.status === "reported" || latest.status === "scored" || latest.status === "fixed"
      ? "strong"
      : consensus === "disputed" || verdictCounts.total > 0 || (latest.confidence ?? 0) >= 0.7
        ? "medium"
        : "weak";

  const recommendedStatus =
    activeAgentRoles.length > 0
      ? "in_progress"
      : consensus === "disputed" || verdictCounts.total > 0
        ? "agent_review"
        : consensus === "verified" || consensus === "false-positive" || ["verified", "confirmed", "scored", "reported", "fixed", "false-positive"].includes(latest.status)
          ? "human_review"
          : persistedStatus;

  const reviewGate = deriveReviewGate(consensus, verdictCounts, latest.status);
  const phase = deriveWorkflowPhase(persistedStatus, reviewGate, activeAgentRoles.length > 0);
  const reviewReason = deriveReviewReason(reviewGate, consensus, verdictCounts, activeAgentRoles);

  const status =
    persistedStatus === "done" || persistedStatus === "cancelled"
      ? persistedStatus
      : recommendedStatus;

  return {
    status,
    persistedStatus,
    recommendedStatus,
    phase,
    reviewGate,
    reviewReason,
    assignee: latest.workflowAssignee ?? null,
    updatedAt: latest.workflowUpdatedAt ?? null,
    consensus,
    activeAgentRoles,
    evidenceSignal,
    verdictCounts,
  };
}

function deriveWorkflowPhase(
  persistedStatus: FindingWorkflowStatus,
  reviewGate: "none" | "agent_review" | "human_review",
  hasActiveAgents: boolean,
): "backlog" | "todo" | "in_progress" | "blocked" | "done" | "cancelled" {
  if (persistedStatus === "done" || persistedStatus === "cancelled" || persistedStatus === "blocked") {
    return persistedStatus;
  }
  if (hasActiveAgents || persistedStatus === "in_progress") return "in_progress";
  if (persistedStatus === "todo") return "todo";
  if (persistedStatus === "agent_review" || persistedStatus === "human_review") return "todo";
  if (reviewGate !== "none") return "todo";
  return "backlog";
}

function deriveReviewGate(
  consensus: "verified" | "false-positive" | "disputed" | "pending",
  verdictCounts: { truePositive: number; falsePositive: number; unsure: number; total: number },
  latestStatus: string,
): "none" | "agent_review" | "human_review" {
  if (
    consensus === "verified"
    || consensus === "false-positive"
    || ["verified", "confirmed", "scored", "reported", "fixed", "false-positive"].includes(latestStatus)
  ) {
    return "human_review";
  }

  if (consensus === "disputed" || verdictCounts.total > 0) {
    return "agent_review";
  }

  return "none";
}

function deriveReviewReason(
  reviewGate: "none" | "agent_review" | "human_review",
  consensus: "verified" | "false-positive" | "disputed" | "pending",
  verdictCounts: { truePositive: number; falsePositive: number; unsure: number; total: number },
  activeAgentRoles: string[],
): string | null {
  if (reviewGate === "human_review") {
    if (consensus === "verified") return "Consensus indicates a true positive and needs operator sign-off.";
    if (consensus === "false-positive") return "Consensus indicates a false positive and needs final suppression.";
    return "Verification artifacts are strong enough for human disposition.";
  }

  if (reviewGate === "agent_review") {
    if (consensus === "disputed") return "Agent verdicts disagree and need another pass.";
    if (verdictCounts.total > 0) return "At least one verifier has voted, but consensus is not final yet.";
    if (activeAgentRoles.length > 0) return "Verifier activity is in progress and may need follow-up review.";
  }

  return null;
}

function groupFindings(
  rows: DBFindingRow[],
  verdictsByFindingId: Map<string, DBVerdictRow[]>,
  sessionsByScanId: Map<string, DBSessionRow[]>,
) {
  const map = new Map<string, DBFindingRow[]>();
  for (const row of rows) {
    const key = row.fingerprint ?? row.id;
    const list = map.get(key) ?? [];
    list.push(normalizeFinding(row));
    map.set(key, list);
  }

  return [...map.entries()]
    .map(([fingerprint, items]) => {
      const sorted = items.sort((a, b) => b.timestamp - a.timestamp);
      const latest = sorted[0];
      const familyVerdicts = sorted.flatMap((item) => verdictsByFindingId.get(item.id) ?? []);
      const familySessions = [...new Map(
        sorted
          .flatMap((item) => sessionsByScanId.get(item.scanId) ?? [])
          .map((session) => [session.id, session]),
      ).values()];
      return {
        fingerprint,
        latest,
        count: sorted.length,
        scanCount: new Set(sorted.map((item) => item.scanId)).size,
        workflow: buildWorkflowSummary(sorted, familyVerdicts, familySessions),
      };
    })
    .sort((a, b) => b.latest.timestamp - a.latest.timestamp);
}

function caseIdFromTarget(target: string): string {
  return `case:${encodeURIComponent(target.trim().toLowerCase())}`;
}

function inferCaseTargetType(scan: DBScanRow | undefined): "ai-app" | "package" | "repository" | "web-app" | "unknown" {
  if (!scan) return "unknown";
  if (scan.mode === "web") return "web-app";
  if (scan.mode === "probe" || scan.mode === "mcp") return "ai-app";
  if (scan.target.startsWith("http://") || scan.target.startsWith("https://")) return "ai-app";
  if (scan.target.startsWith("/") || scan.target.startsWith(".") || scan.target.includes("/")) return "repository";
  if (!scan.target.includes(" ")) return "package";
  return "unknown";
}

function buildCases(scans: DBScanRow[], groups: ReturnType<typeof groupFindings>) {
  const scansById = new Map(scans.map((scan) => [scan.id, scan] as const));
  const map = new Map<string, {
    id: string;
    target: string;
    targetType: "ai-app" | "package" | "repository" | "web-app" | "unknown";
    latestScanId: string | null;
    latestTimestamp: number;
    scanIds: Set<string>;
    familyFingerprints: Set<string>;
    activeRunCount: number;
    reviewCount: number;
    openWorkItemCount: number;
  }>();

  for (const scan of scans) {
    const caseId = caseIdFromTarget(scan.target);
    const existing = map.get(caseId) ?? {
      id: caseId,
      target: scan.target,
      targetType: inferCaseTargetType(scan),
      latestScanId: scan.id,
      latestTimestamp: Date.parse(scan.startedAt) || 0,
      scanIds: new Set<string>(),
      familyFingerprints: new Set<string>(),
      activeRunCount: 0,
      reviewCount: 0,
      openWorkItemCount: 0,
    };

    existing.scanIds.add(scan.id);
    if (scan.status === "running") existing.activeRunCount += 1;
    const started = Date.parse(scan.startedAt) || 0;
    if (started >= existing.latestTimestamp) {
      existing.latestTimestamp = started;
      existing.latestScanId = scan.id;
      existing.target = scan.target;
      existing.targetType = inferCaseTargetType(scan);
    }
    map.set(caseId, existing);
  }

  for (const group of groups) {
    const scan = scansById.get(group.latest.scanId);
    if (!scan) continue;
    const caseId = caseIdFromTarget(scan.target);
    const existing = map.get(caseId);
    if (!existing) continue;
    existing.familyFingerprints.add(group.fingerprint);
    if (group.workflow.reviewGate !== "none") existing.reviewCount += 1;
    if (group.workflow.phase !== "done" && group.workflow.phase !== "cancelled") existing.openWorkItemCount += 1;
  }

  return [...map.values()]
    .map((item) => ({
      id: item.id,
      target: item.target,
      targetType: item.targetType,
      latestScanId: item.latestScanId,
      scanCount: item.scanIds.size,
      familyCount: item.familyFingerprints.size,
      activeRunCount: item.activeRunCount,
      reviewCount: item.reviewCount,
      openWorkItemCount: item.openWorkItemCount,
    }))
    .sort((a, b) => b.activeRunCount - a.activeRunCount || b.reviewCount - a.reviewCount || b.familyCount - a.familyCount);
}

function buildWorkItems(args: {
  fingerprint: string;
  workflow: ReturnType<typeof buildWorkflowSummary>;
  rows: DBFindingRow[];
  verdicts: DBVerdictRow[];
}) {
  const { fingerprint, workflow, rows, verdicts } = args;
  const latest = rows[0]!;
  const hasAnalysis = Boolean(latest.evidenceAnalysis?.trim());
  const hasEvidence = Boolean(latest.evidenceRequest.trim() || latest.evidenceResponse.trim());
  const hasVerifierVotes = verdicts.length > 0;
  const activeOwner = workflow.activeAgentRoles[0] ?? null;

  return [
    {
      id: `${fingerprint}:surface_map`,
      kind: "surface_map",
      title: "Attack surface mapping",
      owner: "attack-surface-agent",
      status: hasEvidence ? "done" : "in_progress",
      summary: "Map the target, reachable surfaces, and initial candidate family context.",
    },
    {
      id: `${fingerprint}:hypothesis`,
      kind: "hypothesis",
      title: "Exploit hypothesis",
      owner: "research-agent",
      status: hasAnalysis ? "done" : hasEvidence ? "in_progress" : "todo",
      summary: "Turn the initial surface signal into a concrete exploit theory.",
    },
    {
      id: `${fingerprint}:poc_build`,
      kind: "poc_build",
      title: "PoC build",
      owner: workflow.assignee ?? activeOwner,
      status: workflow.phase === "in_progress" ? "in_progress" : hasEvidence ? "done" : "todo",
      summary: "Create or refine the exploit artifact chain and reproduction steps.",
    },
    {
      id: `${fingerprint}:blind_verify`,
      kind: "blind_verify",
      title: "Blind verify",
      owner: activeOwner,
      status: workflow.phase === "in_progress" ? "in_progress" : hasVerifierVotes ? "done" : "todo",
      summary: "Independent verifier takes only the PoC and artifact path.",
    },
    {
      id: `${fingerprint}:consensus`,
      kind: "consensus",
      title: "Consensus",
      owner: "consensus-agent",
      status: workflow.reviewGate === "agent_review" ? "in_progress" : hasVerifierVotes ? "done" : "backlog",
      summary: "Resolve partial or conflicting verifier evidence into the next step.",
    },
    {
      id: `${fingerprint}:human_review`,
      kind: "human_review",
      title: "Human review",
      owner: "operator",
      status:
        workflow.phase === "done" || workflow.phase === "cancelled"
          ? "done"
          : workflow.reviewGate === "human_review"
            ? "in_progress"
            : workflow.reviewGate === "agent_review"
              ? "blocked"
              : "backlog",
      summary: "Final operator sign-off before report, suppression, or closure.",
    },
  ] as const;
}

function buildArtifacts(args: {
  fingerprint: string;
  latest: DBFindingRow;
  verdicts: DBVerdictRow[];
  sessions: DBSessionRow[];
  events: DBEventRow[];
}) {
  const { fingerprint, latest, verdicts, sessions, events } = args;
  return [
    {
      id: `${fingerprint}:request`,
      kind: "request",
      label: "Exploit request",
      summary: latest.evidenceRequest ? `${latest.evidenceRequest.length} chars captured` : "No request artifact captured",
    },
    {
      id: `${fingerprint}:response`,
      kind: "response",
      label: "Exploit response",
      summary: latest.evidenceResponse ? `${latest.evidenceResponse.length} chars captured` : "No response artifact captured",
    },
    {
      id: `${fingerprint}:analysis`,
      kind: "analysis",
      label: "Analysis",
      summary: latest.evidenceAnalysis ? "Research analysis attached" : "No attached family analysis yet",
    },
    {
      id: `${fingerprint}:verdicts`,
      kind: "verdicts",
      label: "Verifier verdicts",
      summary: verdicts.length > 0 ? `${verdicts.length} verifier vote${verdicts.length > 1 ? "s" : ""}` : "No blind verifier verdicts yet",
    },
    {
      id: `${fingerprint}:sessions`,
      kind: "sessions",
      label: "Agent sessions",
      summary: sessions.length > 0 ? `${sessions.length} agent session${sessions.length > 1 ? "s" : ""} linked` : "No agent sessions linked",
    },
    {
      id: `${fingerprint}:events`,
      kind: "events",
      label: "Pipeline events",
      summary: events.length > 0 ? `${events.length} audit event${events.length > 1 ? "s" : ""} recorded` : "No pipeline events linked",
    },
  ] as const;
}

function parseScanPath(pathname: string): { scanId: string; suffix?: "events" | "findings" } | null {
  const match = pathname.match(/^\/api\/scans\/([^/]+)(?:\/(events|findings))?$/);
  if (!match) return null;
  return {
    scanId: decodeURIComponent(match[1]),
    suffix: match[2] as "events" | "findings" | undefined,
  };
}


function isPresentationEventsStreamPath(pathname: string): boolean {
  return pathname === "/api/v1/presentation/events";
}
function parseRecentEventsPath(pathname: string): boolean {
  return pathname === "/api/events/recent";
}

function parseFindingFamilyPath(pathname: string): { fingerprint: string; action?: "triage" | "workflow" } | null {
  const match = pathname.match(/^\/api\/finding-family\/([^/]+)(?:\/(triage|workflow))?$/);
  if (!match) return null;
  return {
    fingerprint: decodeURIComponent(match[1]),
    action: match[2] as "triage" | "workflow" | undefined,
  };
}

function parseControlPath(pathname: string): {
  action:
    | "recover-stale-workers"
    | "prune-stopped-workers"
    | "reset-database"
    | "start-daemon"
    | "stop-daemon"
    | "launch-run";
} | null {
  const match = pathname.match(/^\/api\/control\/(recover-stale-workers|prune-stopped-workers|reset-database|start-daemon|stop-daemon|launch-run)$/);
  if (!match) return null;
  return {
    action: match[1] as
      | "recover-stale-workers"
      | "prune-stopped-workers"
      | "reset-database"
      | "start-daemon"
      | "stop-daemon"
      | "launch-run",
  };
}

function resolveCliEntrypoint(): string {
  return resolve(process.argv[1] ?? join(process.cwd(), "dist", "index.js"));
}

function startManagedDaemon(args: {
  dbPath?: string;
  label: string;
  pollIntervalMs?: number;
}): { pid: number | null; label: string } {
  if (managedDaemon?.child.exitCode === null && !managedDaemon.child.killed) {
    return { pid: managedDaemon.child.pid ?? null, label: managedDaemon.label };
  }

  const cliEntrypoint = resolveCliEntrypoint();
  const childArgs = [
    cliEntrypoint,
    "orchestrate",
    "--watch",
    "--poll-interval",
    String(args.pollIntervalMs ?? 2000),
    "--label",
    args.label,
  ];

  if (args.dbPath) {
    childArgs.push("--db-path", args.dbPath);
  }

  const child = spawn(process.execPath, childArgs, {
    cwd: process.cwd(),
    stdio: "ignore",
  });

  child.unref();
  managedDaemon = { child, label: args.label };
  child.once("exit", () => {
    if (managedDaemon?.child.pid === child.pid) {
      managedDaemon = null;
    }
  });

  return { pid: child.pid ?? null, label: args.label };
}

function isLiveLocalPid(pid: number | null | undefined): boolean {
  if (!pid || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String((error as { code?: unknown }).code) : "";
    if (code === "ESRCH") return false;
    return true;
  }
}

function stopDaemonWorkers(
  osecDb: typeof import("@0sec/db").osecDB,
  dbPath: string | undefined,
): number {
  const db = new osecDb(dbPath);

  try {
    const workers = db.listWorkers(100) as DBWorkerRow[];
    let stopped = 0;

    for (const worker of workers) {
      const heartbeatFresh = Date.now() - Date.parse(worker.heartbeatAt) < 20_000;
      if (worker.status === "stopped" || !heartbeatFresh) continue;

      if (worker.pid) {
        try {
          process.kill(worker.pid, "SIGTERM");
          stopped += 1;
        } catch {
          // Ignore already-exited or inaccessible processes.
        }
      }

      db.upsertWorker({
        id: worker.id,
        role: "orchestrator",
        status: "stopped",
        label: worker.label,
        currentCaseId: null,
        currentWorkItemId: null,
        currentScanId: null,
        pid: worker.pid ?? null,
        host: worker.host ?? null,
        lastError: worker.lastError?.trim() || "Stopped from dashboard control.",
      });
    }

    if (managedDaemon?.child.pid) {
      try {
        managedDaemon.child.kill("SIGTERM");
      } catch {
        // Ignore if already gone.
      }
      managedDaemon = null;
    }
    return stopped;
  } finally {
    db.close();
  }
}

function launchRunProcess(args: {
  dbPath?: string;
  target: string;
  depth: string;
  mode: string;
  runtime: string;
}): { pid: number | null } {
  const cliEntrypoint = resolveCliEntrypoint();
  const childArgs = [
    cliEntrypoint,
    "scan",
    "--target",
    args.target,
    "--depth",
    args.depth,
    "--mode",
    args.mode,
    "--runtime",
    args.runtime,
    "--format",
    "json",
  ];

  if (args.dbPath) {
    childArgs.push("--db-path", args.dbPath);
  }

  const child = spawn(process.execPath, childArgs, {
    cwd: process.cwd(),
    stdio: "ignore",
  });

  child.unref();
  return { pid: child.pid ?? null };
}


function groupByKey<T, K extends keyof T>(rows: T[], key: K) {
  const map = new Map<string, T[]>();
  for (const row of rows) {
    const value = row[key];
    if (typeof value !== "string") continue;
    const list = map.get(value) ?? [];
    list.push(row);
    map.set(value, list);
  }
  return map;
}

function resolveDashboardAssetDir(explicitAssetDir?: string): string {
  const moduleDir = resolve(fileURLToPath(new URL(".", import.meta.url)));
  const candidates = [
    ...(explicitAssetDir ? [resolve(explicitAssetDir)] : []),
    join(moduleDir, "dashboard"),
    join(moduleDir, "..", "dashboard"),
    // A source checkout must serve the freshly built workspace dashboard,
    // not an unrelated stale root bundle left by an earlier packaging run.
    join(process.cwd(), "packages", "dashboard", "dist"),
    join(process.cwd(), "dist", "dashboard"),
  ];

  for (const candidate of candidates) {
    if (existsSync(join(candidate, "index.html"))) {
      return candidate;
    }
  }

  throw new Error("Dashboard assets not found. Run `pnpm build` to generate the dashboard app.");
}

function resolveAssetPath(assetDir: string, pathname: string): string | null {
  const trimmed = pathname === "/" ? "/index.html" : pathname;
  const assetRoot = resolve(assetDir);
  const candidate = resolve(assetRoot, `.${trimmed}`);
  if (candidate !== assetRoot && !candidate.startsWith(`${assetRoot}${sep}`)) return null;
  if (!existsSync(candidate)) return null;
  return candidate;
}

function requireControlToken(req: IncomingMessage, res: ServerResponse, controlToken: string): boolean {
  const provided = req.headers["x-0sec-control-token"];
  if (provided !== controlToken) {
    json(res, 403, { error: "Invalid or missing control token" });
    return false;
  }
  return true;
}

const DesktopConsoleSessionInputSchema = z.object({
  target: z.unknown().optional(),
  role: z.unknown().optional(),
  autonomyMode: z.unknown().optional(),
});

const DesktopConsoleMessageInputSchema = z.object({
  text: z.unknown().optional(),
});

function consolePath(pathname: string): { sessionId: string; action?: "events" | "messages" | "cancel"; decisionId?: string } | null {
  const match = /^\/api\/console\/sessions\/([a-zA-Z0-9-]+)(?:\/(events|messages|cancel)|\/decisions\/([a-zA-Z0-9-]+))?$/.exec(pathname);
  if (!match) return null;
  const action = match[2] as "events" | "messages" | "cancel" | undefined;
  return {
    sessionId: match[1]!,
    ...(action ? { action } : {}),
    ...(match[3] ? { decisionId: match[3] } : {}),
  };
}

function consoleEventsAfter(value: string | null): number {
  if (value === null || value === "") return 0;
  const after = Number(value);
  if (!Number.isSafeInteger(after) || after < 0) {
    throw new DesktopConsoleGatewayError("Event cursor must be a non-negative integer.", 400);
  }
  return after;
}

async function handleDesktopConsoleApiRequest(
  req: IncomingMessage,
  res: ServerResponse,
  requestUrl: URL,
  gateway: DesktopConsoleGateway,
  codexAuth: DesktopCodexAuthController,
  controlToken: string,
): Promise<boolean> {
  if (!requestUrl.pathname.startsWith("/api/console/")) return false;
  if (!requireControlToken(req, res, controlToken)) return true;

  try {
    if (requestUrl.pathname === "/api/console/providers/codex") {
      if (req.method === "GET") {
        json(res, 200, { status: codexAuth.status() });
        return true;
      }
      json(res, 405, { error: "Method not allowed" });
      return true;
    }
    if (requestUrl.pathname === "/api/console/providers/codex/device-auth") {
      if (req.method === "POST") {
        json(res, 202, { status: codexAuth.start() });
        return true;
      }
      if (req.method === "DELETE") {
        json(res, 200, { status: codexAuth.cancel() });
        return true;
      }
      json(res, 405, { error: "Method not allowed" });
      return true;
    }

    if (requestUrl.pathname === "/api/console/sessions") {
      if (req.method === "GET") {
        json(res, 200, { sessions: gateway.list() });
        return true;
      }
      if (req.method === "POST") {
        const body = DesktopConsoleSessionInputSchema.parse(await readJson(req));
        const session = gateway.create(body);
        json(res, 201, { session });
        return true;
      }
      json(res, 405, { error: "Method not allowed" });
      return true;
    }

    const parsed = consolePath(requestUrl.pathname);
    if (!parsed) return false;
    if (parsed.action === "events" && req.method === "GET") {
      json(res, 200, { events: gateway.eventsAfter(parsed.sessionId, consoleEventsAfter(requestUrl.searchParams.get("after"))) });
      return true;
    }
    if (parsed.action === "messages" && req.method === "POST") {
      const body = DesktopConsoleMessageInputSchema.parse(await readJson(req));
      json(res, 202, { session: gateway.send(parsed.sessionId, body.text) });
      return true;
    }
    if (parsed.action === "cancel" && req.method === "POST") {
      json(res, 200, { session: gateway.cancel(parsed.sessionId) });
      return true;
    }
    if (parsed.decisionId && req.method === "POST") {
      const body = await readJson(req);
      json(res, 200, { session: gateway.resolveDecision(parsed.sessionId, parsed.decisionId, body) });
      return true;
    }
    if (!parsed.action && !parsed.decisionId && req.method === "DELETE") {
      await gateway.close(parsed.sessionId);
      json(res, 200, { ok: true });
      return true;
    }
    json(res, 405, { error: "Method not allowed" });
    return true;
  } catch (error) {
    if (error instanceof z.ZodError) {
      json(res, 400, { error: "Invalid console request payload." });
      return true;
    }
    if (error instanceof DesktopConsoleGatewayError) {
      json(res, error.statusCode, { error: error.message });
      return true;
    }
    throw error;
  }
}

type PresentationCursor = {
  timestamp: number;
  id: string;
};

function encodePresentationCursor(cursor: PresentationCursor): string {
  return Buffer.from(JSON.stringify(cursor)).toString("base64url");
}

function decodePresentationCursor(value: string | string[] | undefined): PresentationCursor | undefined {
  const encoded = Array.isArray(value) ? value[0] : value;
  if (!encoded) return undefined;
  try {
    const parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as {
      timestamp?: unknown;
      id?: unknown;
    };
    return typeof parsed.timestamp === "number" && Number.isFinite(parsed.timestamp) && typeof parsed.id === "string"
      ? { timestamp: parsed.timestamp, id: parsed.id }
      : undefined;
  } catch {
    return undefined;
  }
}

function writePresentationSse(
  res: ServerResponse,
  event: PresentationEvent,
  cursor?: PresentationCursor,
): void {
  if (cursor) res.write(`id: ${encodePresentationCursor(cursor)}\n`);
  res.write(`event: presentation\ndata: ${JSON.stringify(event)}\n\n`);
}

async function handleApiRequest(
  req: IncomingMessage,
  res: ServerResponse,
  pathname: string,
  dbPath: string | undefined,
  controlToken: string,
): Promise<boolean> {
  const { osecDB } = await import("@0sec/db");

  if (isPresentationEventsStreamPath(pathname)) {
    if (req.method !== "GET") {
      json(res, 405, { error: "Method not allowed" });
      return true;
    }

    const db = new osecDB(dbPath);
    let sequence = 0;
    let cursor = decodePresentationCursor(req.headers["last-event-id"]);
    const sendPersisted = () => {
      try {
        const events = (cursor
          ? db.listEventsAfter(cursor, 250)
          : (db.listRecentEvents(250) as DashboardRecentEventRow[]).slice().reverse()
        ) as DashboardRecentEventRow[];
        for (const event of events) {
          const nextCursor = { timestamp: event.timestamp, id: event.id };
          writePresentationSse(
            res,
            presentationEventFromDashboardRow(event, ++sequence),
            nextCursor,
          );
          cursor = nextCursor;
        }
      } catch {
        // The next polling pass may succeed after a concurrent DB rotation.
      }
    };

    res.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    });
    res.write(": connected\n\n");
    sendPersisted();
    const poll = setInterval(sendPersisted, 750);
    const unsubscribe = presentationEventBus.subscribe({
      emit(event) {
        // Core scan events are persisted and arrive through the ordered DB poll.
        // Local CLI output has no DB row and remains useful to same-process users.
        if (event.source !== "core") writePresentationSse(res, event);
      },
    });
    req.once("close", () => {
      clearInterval(poll);
      unsubscribe();
      db.close();
    });
    return true;
  }

  const controlPath = parseControlPath(pathname);

  if (controlPath) {
    if (req.method !== "POST") {
      json(res, 405, { error: "Method not allowed" });
      return true;
    }

    // Require a per-session token on all state-changing control endpoints.
    // The token is injected into the dashboard HTML at serve time and sent
    // back as a header, preventing CSRF and cross-origin abuse.
    if (!requireControlToken(req, res, controlToken)) {
      return true;
    }

    if (controlPath.action === "recover-stale-workers") {
      const { recoverStaleWorkers } = await import("./orchestrate.js");
      const body = (await readJson(req)) as { staleAfterMs?: number };
      const recovered = recoverStaleWorkers(
        dbPath,
        typeof body.staleAfterMs === "number" ? body.staleAfterMs : 30_000,
      );
      json(res, 200, { ok: true, recovered });
      return true;
    }

    if (controlPath.action === "prune-stopped-workers") {
      const db = new osecDB(dbPath);
      try {
        const deleted = db.deleteWorkersByStatus("stopped");
        json(res, 200, { ok: true, deleted });
      } finally {
        db.close();
      }
      return true;
    }

    if (controlPath.action === "start-daemon") {
      const body = (await readJson(req)) as { label?: string; pollIntervalMs?: number };
      const db = new osecDB(dbPath);
      try {
        const activeWorkers = (db.listWorkers(100) as DBWorkerRow[]).filter((worker) =>
          worker.status !== "stopped" && Date.now() - Date.parse(worker.heartbeatAt) < 20_000,
        );
        if (activeWorkers.length > 0) {
          json(res, 409, { error: "An active daemon is already heartbeating. Stop it before starting another local daemon." });
          return true;
        }
      } finally {
        db.close();
      }

      const started = startManagedDaemon({
        dbPath,
        label: typeof body.label === "string" && body.label.trim() ? body.label.trim() : "control-plane-1",
        pollIntervalMs: typeof body.pollIntervalMs === "number" ? body.pollIntervalMs : 2000,
      });
      json(res, 200, { ok: true, ...started });
      return true;
    }

    if (controlPath.action === "stop-daemon") {
      const stopped = stopDaemonWorkers(osecDB, dbPath);
      json(res, 200, { ok: true, stopped });
      return true;
    }

    if (controlPath.action === "launch-run") {
      const body = (await readJson(req)) as {
        target?: string;
        depth?: string;
        mode?: string;
        runtime?: string;
        ensureDaemon?: boolean;
      };
      const target = typeof body.target === "string" ? body.target.trim() : "";
      const depth = typeof body.depth === "string" ? body.depth.trim() : "default";
      const mode = typeof body.mode === "string" ? body.mode.trim() : "deep";
      const runtime = typeof body.runtime === "string" ? body.runtime.trim() : "auto";

      if (!target) {
        json(res, 400, { error: "Target is required." });
        return true;
      }

      if (body.ensureDaemon) {
        const db = new osecDB(dbPath);
        try {
          const activeWorkers = (db.listWorkers(100) as DBWorkerRow[]).filter((worker) =>
            worker.status !== "stopped" && Date.now() - Date.parse(worker.heartbeatAt) < 20_000,
          );
          if (activeWorkers.length === 0) {
            startManagedDaemon({
              dbPath,
              label: "control-plane-1",
              pollIntervalMs: 2000,
            });
          }
        } finally {
          db.close();
        }
      }

      const launched = launchRunProcess({
        dbPath,
        target,
        depth,
        mode,
        runtime,
      });
      json(res, 200, { ok: true, ...launched });
      return true;
    }

    if (controlPath.action === "reset-database") {
      const { resetOsecDatabase } = await import("@0sec/db");
      const { seedVerificationWorkbench } = await import("./db.js");
      const body = (await readJson(req)) as { seed?: string };
      const seed = typeof body.seed === "string" ? body.seed.trim().toLowerCase() : "verification";

      if (!["verification", "empty"].includes(seed)) {
        json(res, 400, { error: `Unsupported seed preset: ${seed}` });
        return true;
      }

      const activeWorkerDb = new osecDB(dbPath);
      try {
        const hasActiveWorker = (activeWorkerDb.listWorkers(100) as DBWorkerRow[]).some((worker) =>
          ["idle", "claiming", "running", "sleeping"].includes(worker.status)
            && Date.now() - Date.parse(worker.heartbeatAt) < 20_000
            && (worker.pid ? isLiveLocalPid(worker.pid) : true),
        );
        if (hasActiveWorker) {
          json(res, 409, { error: "Stop active orchestration daemons before resetting the local database." });
          return true;
        }
      } finally {
        activeWorkerDb.close();
      }

      const path = resetOsecDatabase(dbPath);
      const resetDb = new osecDB(dbPath);
      try {
        const seeded = seed === "verification"
          ? seedVerificationWorkbench(resetDb)
          : { scans: 0, families: 0, workers: 0 };
        json(res, 200, { ok: true, path, seed, ...seeded });
      } finally {
        resetDb.close();
      }
      return true;
    }
  }

  if (pathname === "/api/dashboard") {
      const db = new osecDB(dbPath);
      try {
        const scans = db.listScans(100) as DBScanRow[];
        const findings = db.listFindings({ limit: 5000 }) as DBFindingRow[];
        const verdicts = db.listVerdicts(findings.map((finding) => finding.id)) as DBVerdictRow[];
        const sessions = db.listSessions({
          scanIds: [...new Set(findings.map((finding) => finding.scanId))],
          status: "running",
        }) as DBSessionRow[];
        const groups = groupFindings(
          findings,
          groupByKey(verdicts, "findingId"),
          groupByKey(sessions, "scanId"),
        );
        const workItems = (db.listWorkItems?.({ limit: 5000 }) ?? []) as DBWorkItemRow[];
        const workers = (db.listWorkers?.(50) ?? []) as DBWorkerRow[];
        const derivedCases = buildCases(scans, groups);
        const persistedCases = (db.listCases?.(200) ?? []) as Array<{
          id: string;
          target: string;
          targetType: string;
          latestScanId?: string | null;
          status: string;
        }>;
        const cases = derivedCases.map((item) => {
          const persisted = persistedCases.find((row) => row.id === item.id);
          return {
            ...item,
            targetType: (persisted?.targetType as typeof item.targetType | undefined) ?? item.targetType,
            latestScanId: persisted?.latestScanId ?? item.latestScanId,
          };
        });
        const casesById = new Map(cases.map((item) => [item.id, item] as const));
        const workItemsById = new Map(workItems.map((item) => [item.id, item] as const));
        json(res, 200, {
          scans: scans.map(summarizeScan),
          cases,
          groups,
          workers: workers.map((worker) => summarizeWorker(worker, workItemsById, casesById)),
          queue: summarizeQueue(workItems, workers),
        });
      } finally {
        db.close();
    }
    return true;
  }

  if (pathname === "/api/scans") {
    const db = new osecDB(dbPath);
    try {
      const scans = db.listScans(100) as DBScanRow[];
      json(res, 200, { scans: scans.map(summarizeScan) });
    } finally {
      db.close();
    }
    return true;
  }

  if (parseRecentEventsPath(pathname)) {
    const url = new URL(req.url ?? pathname, "http://localhost");
    const rawLimit = Number(url.searchParams.get("limit") ?? "20");
    const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(100, Math.floor(rawLimit))) : 20;
    const db = new osecDB(dbPath);
    try {
      const events = (db.listRecentEvents(limit) as DashboardRecentEventRow[])
        .map((event, index) => {
          const payload = parsePayload(event.payload);
          const presentation = presentationEventFromDashboardRow(event, index + 1);
          return {
            id: event.id,
            scanId: event.scanId,
            scanTarget: event.scanTarget,
            stage: event.stage,
            eventType: event.eventType,
            findingId: event.findingId ?? null,
            findingFingerprint: event.findingFingerprint ?? null,
            agentRole: event.agentRole ?? null,
            summary: summarizeRecentEvent({
              stage: event.stage,
              eventType: event.eventType,
              payload,
            }),
            payload,
            timestamp: event.timestamp,
            presentation,
          };
        });

      json(res, 200, { events });
    } finally {
      db.close();
    }
    return true;
  }

  const scanPath = parseScanPath(pathname);
  if (scanPath) {
    const db = new osecDB(dbPath);
    try {
      const scan = db.getScan(scanPath.scanId) as DBScanRow | undefined;
      if (!scan) {
        json(res, 404, { error: "Scan not found" });
        return true;
      }

      if (scanPath.suffix === "events") {
        const events = (db.getEvents(scanPath.scanId) as DBEventRow[]).map((event) => ({
          ...event,
          payload: parsePayload(event.payload),
        }));
        json(res, 200, { scan: summarizeScan(scan), events });
        return true;
      }

      if (scanPath.suffix === "findings") {
        const findings = (db.getFindings(scanPath.scanId) as DBFindingRow[]).map(normalizeFinding);
        const verdicts = db.listVerdicts(findings.map((finding) => finding.id)) as DBVerdictRow[];
        const sessions = db.listSessions({
          scanIds: [scanPath.scanId],
          status: "running",
        }) as DBSessionRow[];
        json(res, 200, {
          scan: summarizeScan(scan),
          findings,
          groups: groupFindings(
            findings,
            groupByKey(verdicts, "findingId"),
            groupByKey(sessions, "scanId"),
          ),
        });
        return true;
      }

      json(res, 200, { scan: summarizeScan(scan) });
    } finally {
      db.close();
    }
    return true;
  }

  const familyPath = parseFindingFamilyPath(pathname);
  if (familyPath) {
    const db = new osecDB(dbPath);
    try {
      if (req.method === "POST" && familyPath.action === "triage") {
        if (!requireControlToken(req, res, controlToken)) {
          return true;
        }
        const body = (await readJson(req)) as { triageStatus?: string; triageNote?: string };
        db.updateFindingTriageByFingerprint(
          familyPath.fingerprint,
          normalizeTriageStatus(body.triageStatus),
          typeof body.triageNote === "string" ? body.triageNote : undefined,
        );
        json(res, 200, { ok: true });
        return true;
      }

      if (req.method === "POST" && familyPath.action === "workflow") {
        if (!requireControlToken(req, res, controlToken)) {
          return true;
        }
        const body = (await readJson(req)) as { workflowStatus?: string; workflowAssignee?: string };
        db.updateFindingWorkflowByFingerprint(
          familyPath.fingerprint,
          normalizeWorkflowStatus(body.workflowStatus),
          typeof body.workflowAssignee === "string" ? body.workflowAssignee.trim() : null,
        );
        json(res, 200, { ok: true });
        return true;
      }

      const rows = (db.getRelatedFindings(familyPath.fingerprint) as DBFindingRow[]).map(normalizeFinding);
      if (rows.length === 0) {
        json(res, 404, { error: "Not found" });
        return true;
      }

      const verdicts = db.listVerdicts(rows.map((row) => row.id)) as DBVerdictRow[];
      const sessions = db.listSessions({
        scanIds: [...new Set(rows.map((row) => row.scanId))],
        status: "running",
      }) as DBSessionRow[];
      const scans = [...new Map(
        rows
          .map((row) => db.getScan(row.scanId) as DBScanRow | undefined)
          .filter(Boolean)
          .map((scan) => [scan!.id, scan!] as const),
      ).values()];
      const allEvents = scans.flatMap((scan) => (db.getEvents(scan.id) as DBEventRow[]));
      const workflow = buildWorkflowSummary(
        rows,
        verdicts,
        sessions,
      );
      const familyCase = buildCases(
        scans,
        [{
          fingerprint: familyPath.fingerprint,
          latest: rows[0],
          count: rows.length,
          scanCount: new Set(rows.map((row) => row.scanId)).size,
          workflow,
        }],
      )[0] ?? null;
      const persistedWorkItems = (db.listWorkItems?.({ findingFingerprint: familyPath.fingerprint, limit: 50 }) ?? []) as Array<{
        id: string;
        kind: string;
        title: string;
        owner?: string | null;
        status: string;
        summary?: string | null;
      }>;
      const persistedArtifacts = (db.listArtifacts?.({ findingFingerprint: familyPath.fingerprint, limit: 100 }) ?? []) as Array<{
        id: string;
        kind: string;
        label: string;
        content?: string | null;
      }>;
      const derivedWorkItems = buildWorkItems({
        fingerprint: familyPath.fingerprint,
        workflow,
        rows,
        verdicts,
      });
      const derivedArtifacts = buildArtifacts({
        fingerprint: familyPath.fingerprint,
        latest: rows[0],
        verdicts,
        sessions,
        events: allEvents,
      });

      json(res, 200, {
        consoleCommand: buildFindingConsoleCommand(rows[0]!, dbPath),
        fingerprint: familyPath.fingerprint,
        case: familyCase,
        latest: rows[0],
        rows,
        workflow,
        workItems: persistedWorkItems.length > 0
          ? persistedWorkItems.map((item) => ({
              id: item.id,
              kind: item.kind,
              title: item.title,
              owner: item.owner ?? null,
              status: item.status,
              summary: item.summary ?? "",
            }))
          : derivedWorkItems,
        artifacts: persistedArtifacts.length > 0
          ? persistedArtifacts.map((artifact) => ({
              id: artifact.id,
              kind: artifact.kind,
              label: artifact.label,
              summary: artifact.content ? `${artifact.content.length} chars captured` : "Persisted artifact",
            }))
          : derivedArtifacts,
      });
    } finally {
      db.close();
    }
    return true;
  }

  return false;
}

function isLoopbackDashboardHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (normalized === "::1") return true;
  return isIP(normalized) === 4 && normalized.startsWith("127.");
}

export function registerDashboardCommand(program: Command): void {
  program
    .command("dashboard")
    .description("Run a local mission-control dashboard for scans and findings")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--port <port>", "Port to bind; 0 chooses a free loopback port", "48123")
    .option("--host <host>", "Loopback host to bind (127.0.0.0/8 or ::1)", "127.0.0.1")
    .option("--asset-dir <path>", "Path to built dashboard assets")
    .option("--ready-json", "Emit the bound dashboard URL as machine-readable JSON")
    .option("--no-open", "Do not auto-open a browser")
    .action(async (opts: DashboardOptions) => {
      const host = opts.host?.trim() || "127.0.0.1";
      const port = parseInt(opts.port ?? "48123", 10);
      if (!Number.isInteger(port) || port < 0 || port > 65535) {
        throw new Error(`Invalid port: ${opts.port ?? "48123"}`);
      }
      if (!isLoopbackDashboardHost(host)) {
        throw new Error(
          "Dashboard only binds loopback addresses (127.0.0.0/8 or ::1). Use an SSH tunnel or an authenticated reverse proxy bound to local loopback for remote access.",
        );
      }
      let origin = `http://${host.includes(":") ? `[${host}]` : host}:${port}`;


      const assetDir = resolveDashboardAssetDir(opts.assetDir);
      const controlToken = randomUUID();
      const consoleGateway = new DesktopConsoleGateway();
      const codexAuth = new DesktopCodexAuthController();

      const server = createServer(async (req, res) => {
        const requestUrl = new URL(req.url ?? "/", origin);

        try {
          if (requestUrl.pathname.startsWith("/api/")) {
            const consoleHandled = await handleDesktopConsoleApiRequest(req, res, requestUrl, consoleGateway, codexAuth, controlToken);
            if (consoleHandled) return;
            const handled = await handleApiRequest(req, res, requestUrl.pathname, opts.dbPath, controlToken);
            if (!handled) json(res, 404, { error: "Not found" });
            return;
          }

          const explicitAsset = resolveAssetPath(assetDir, requestUrl.pathname);
          if (explicitAsset) {
            sendFile(res, explicitAsset, controlToken);
            return;
          }

          if (extname(requestUrl.pathname)) {
            json(res, 404, { error: "Asset not found" });
            return;
          }

          // Inject the control token into HTML so the dashboard JS can read it.
          sendFile(res, join(assetDir, "index.html"), controlToken);
        } catch (err) {
          json(res, 500, { error: err instanceof Error ? err.message : String(err) });
        }
      });

      server.listen(port, host, () => {
        const address = server.address();
        if (address && typeof address !== "string") {
          origin = `http://${host.includes(":") ? `[${host}]` : host}:${address.port}`;
        }
        const url = origin;
        console.log(chalk.red.bold("  ◆ 0sec") + chalk.gray(" dashboard"));
        console.log(chalk.gray(`  ${url}`));
        if (opts.readyJson) console.log(`0SEC_DASHBOARD_READY ${JSON.stringify({ url })}`);
        console.log(chalk.gray("  Ctrl+C to stop"));
        if (opts.open !== false) openBrowser(`${url}/dashboard`);
      });

      process.once("SIGINT", () => {
        void consoleGateway.closeAll().finally(() => {
          server.close(() => process.exit(0));
        });
      });
    });
}

type FindingWorkflowStatus =
  | "backlog"
  | "todo"
  | "agent_review"
  | "in_progress"
  | "human_review"
  | "blocked"
  | "done"
  | "cancelled";
