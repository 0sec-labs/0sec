import {
  appendStageAction,
  normalizeStageAction,
  normalizeStageEndDetail,
} from "@pwnkit/core";
import { buildShareUrl } from "../utils.js";

export type SessionMode = "audit" | "review" | "scan";
export type StageStatusKind = "pending" | "running" | "done" | "error";

export interface StageFinding {
  severity: string;
  title: string;
}

export interface StageState {
  id: string;
  label: string;
  status: StageStatusKind;
  detail?: string;
  duration?: number;
  actions: string[];
  findings: StageFinding[];
  error?: string;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info?: number;
  duration?: number;
  shareUrl?: string;
}

export interface TranscriptItem {
  id: string;
  kind: "status" | "action" | "thinking" | "finding" | "verify" | "error" | "summary" | "tool-group" | "turn" | "user-inject";
  stage?: string;
  text: string;
  tone?: "muted" | "primary" | "success" | "warning" | "error" | "info";
  turn?: number;
  actions?: string[];
  label?: string;
}

export interface SessionState {
  target: string;
  depth: string;
  mode: SessionMode;
  connection: {
    runtime: string;
    apiProviderLabel?: string;
    apiConfigured?: boolean;
    apiConnected?: boolean;
    localRuntimes: string[];
    model?: string;
  };
  usage: {
    inputTokens: number;
    outputTokens: number;
    estimatedCostUsd: number;
  };
  stages: StageState[];
  summary: ScanSummary | null;
  thinking: string | null;
  transcript: TranscriptItem[];
  /** Messages queued by the user for injection at the next agent turn boundary. */
  pendingUserMessages: string[];
}

export interface SessionEvent {
  type: string;
  stage?: string;
  message: string;
  data?: unknown;
}

function upsertFinding(findings: StageFinding[], finding: StageFinding): StageFinding[] {
  const exists = findings.some(
    (item) => item.severity.toLowerCase() === finding.severity.toLowerCase() && item.title === finding.title,
  );
  return exists ? findings : [...findings, finding];
}

function parseSavedFinding(action: string): StageFinding | null {
  const match = /^save_finding:\s*\[([^\]]+)\]\s+(.+)$/i.exec(action.trim());
  if (!match) return null;
  return {
    severity: cleanDisplayText(match[1], 24),
    title: cleanDisplayText(match[2], 200),
  };
}

function upsertThinkingItem(
  transcript: TranscriptItem[],
  stage: string | undefined,
  text: string,
  turn?: number,
): TranscriptItem[] {
  const next = [...transcript];
  for (let index = next.length - 1; index >= 0; index -= 1) {
    const item = next[index];
    if (item.kind !== "thinking" || item.stage !== stage) continue;
    if (turn !== undefined && item.turn !== turn) continue;
    if (turn === undefined && item.turn !== undefined) continue;
    next[index] = {
      ...item,
      text,
      turn,
    };
    return next;
  }
  next.push(transcriptItem("thinking", text, { stage, turn, tone: "muted" }));
  return next;
}

function getStages(): StageState[] {
  return [
    { id: "discover", label: "Discover", status: "pending", actions: [], findings: [] },
    { id: "attack", label: "Attack", status: "pending", actions: [], findings: [] },
    { id: "verify", label: "Verify", status: "pending", actions: [], findings: [] },
    { id: "report", label: "Report", status: "pending", actions: [], findings: [] },
  ];
}

function mapStageId(coreStage: string | undefined): string | undefined {
  switch (coreStage) {
    case "discovery":
    case "discover":
    case "source-analysis":
    case "prepare":
    case "analyze":
      return "discover";
    case "attack":
    case "research":
    case "agent":
      return "attack";
    case "verify":
      return "verify";
    case "report":
      return "report";
    default:
      return undefined;
  }
}

function transcriptItem(kind: TranscriptItem["kind"], text: string, options: Partial<TranscriptItem> = {}): TranscriptItem {
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    kind,
    text,
    ...options,
  };
}

function replaceLargeEncodedChunks(text: string): string {
  return text.replace(/[A-Za-z0-9+/_=-]{140,}/g, "[encoded payload omitted]");
}

function stripTerminalControl(text: string): string {
  return text
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "")
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "");
}

function cleanDisplayText(text: string, maxChars = 240): string {
  const compact = stripTerminalControl(replaceLargeEncodedChunks(text))
    .replace(/\s+/g, " ")
    .trim();
  if (compact.length <= maxChars) return compact;
  return `${compact.slice(0, maxChars)}...`;
}

function summarizeErrorText(text: string): string {
  const cleaned = cleanDisplayText(text, 1200);
  const objectMatch = cleaned.match(/\{.*\}/);
  if (!objectMatch) return cleanDisplayText(cleaned, 220);

  try {
    const parsed = JSON.parse(objectMatch[0]) as {
      message?: string;
      type?: string;
      code?: string;
      error?: { message?: string; type?: string; code?: string };
    };
    const source = parsed.error ?? parsed;
    const parts = [source.message, source.type, source.code].filter(Boolean);
    if (parts.length > 0) return cleanDisplayText(parts.join(" · "), 220);
  } catch {
    // Fall back to compact plain text.
  }

  return cleanDisplayText(cleaned, 220);
}

function summarizeDetail(detail: string): string {
  const cleaned = cleanDisplayText(detail, 1200);
  const parts = cleaned
    .split(/(?:\s+[\-•]\s+|[.!?]\s+)/)
    .map((part) => part.trim())
    .filter(Boolean)
    .filter((part, index, items) => items.indexOf(part) === index)
    .slice(0, 4)
    .map((part) => cleanDisplayText(part, 140));
  if (parts.length === 0) return cleanDisplayText(detail, 180);
  return parts.join(" • ");
}

function parseTurnAction(action: string): { turn: number; body: string } | null {
  const match = /^turn\s+(\d+):\s*(.+)$/i.exec(action.trim());
  if (!match) return null;
  const turn = Number.parseInt(match[1], 10);
  if (!Number.isFinite(turn)) return null;
  return { turn, body: cleanDisplayText(match[2], 220) };
}

function classifyAction(action: string): { label: string; tone: TranscriptItem["tone"] } {
  const lower = action.toLowerCase();
  if (lower === "thinking") return { label: "Thinking", tone: "muted" };
  if (lower.startsWith("installing ") || lower.startsWith("installed ") || lower.startsWith("target ready:")) {
    return { label: "Preparation", tone: "primary" };
  }
  if (lower.includes("semgrep") || lower.includes("npm audit") || lower.includes("dependency audit") || lower.startsWith("analysis complete:")) {
    return { label: "Static analysis", tone: "info" };
  }
  if (lower.startsWith("read_file:") || lower.startsWith("reading ") || lower.startsWith("run_command:") || lower.startsWith("running:") || lower.includes("source code")) {
    return { label: "Source review", tone: "primary" };
  }
  if (lower.startsWith("crawl:") || lower.startsWith("http_request: get") || lower.startsWith("browser.navigate") || lower.startsWith("browser.screenshot") || lower.startsWith("read:") || lower.startsWith("grep:") || lower.startsWith("glob:") || lower.startsWith("save_target_info:")) {
    return { label: "Reconnaissance", tone: "info" };
  }
  if (lower.startsWith("http_request: post") || lower.startsWith("http_request: put") || lower.startsWith("http_request: patch") || lower.startsWith("http_request: delete") || lower.startsWith("submit_form:") || lower.startsWith("bash:") || lower.startsWith("browser.click") || lower.startsWith("browser.fill") || lower.startsWith("browser.type")) {
    return { label: "Probing", tone: "primary" };
  }
  if (lower.startsWith("save_finding:") || lower.startsWith("done:")) {
    return { label: "Assessment", tone: "success" };
  }
  return { label: "Actions", tone: "info" };
}

function appendToolAction(transcript: TranscriptItem[], stage: string, turn: number, action: string): TranscriptItem[] {
  const next = [...transcript];
  let turnHeader: TranscriptItem | undefined;
  for (let i = next.length - 1; i >= 0; i -= 1) {
    const item = next[i];
    if (item.kind === "turn" && item.stage === stage && item.turn === turn) {
      turnHeader = item;
      break;
    }
  }
  if (!turnHeader) {
    next.push(transcriptItem("turn", `Turn ${turn}`, { stage, turn, tone: "primary" }));
  }
  const { label, tone } = classifyAction(action);
  const last = next[next.length - 1];
  if (last && last.kind === "tool-group" && last.stage === stage && last.turn === turn && last.label === label) {
    const actions = [...(last.actions ?? []), action];
    next[next.length - 1] = {
      ...last,
      actions,
      text: `${label} · ${actions.length} ${actions.length === 1 ? "step" : "steps"}`,
      tone,
    };
    return next;
  }
  next.push(transcriptItem("tool-group", `${label} · 1 step`, { stage, turn, label, actions: [action], tone }));
  return next;
}

function appendStageActionGroup(transcript: TranscriptItem[], stage: string, action: string): TranscriptItem[] {
  const next = [...transcript];
  const { label, tone } = classifyAction(action);
  const last = next[next.length - 1];
  if (last && last.kind === "tool-group" && last.stage === stage && last.turn === undefined && last.label === label) {
    const actions = [...(last.actions ?? []), action];
    next[next.length - 1] = {
      ...last,
      actions,
      text: `${label} · ${actions.length} ${actions.length === 1 ? "step" : "steps"}`,
      tone,
    };
    return next;
  }
  next.push(transcriptItem("tool-group", `${label} · 1 step`, { stage, label, actions: [action], tone }));
  return next;
}

export function createInitialSessionState(
  target: string,
  depth: string,
  mode: SessionMode,
  connection: Partial<SessionState["connection"]> = {},
): SessionState {
  return {
    target,
    depth,
    mode,
    connection: {
      runtime: connection.runtime ?? "auto",
      apiProviderLabel: connection.apiProviderLabel,
      apiConfigured: connection.apiConfigured,
      apiConnected: connection.apiConnected,
      localRuntimes: connection.localRuntimes ?? [],
      model: connection.model,
    },
    usage: {
      inputTokens: 0,
      outputTokens: 0,
      estimatedCostUsd: 0,
    },
    stages: getStages(),
    summary: null,
    thinking: null,
    transcript: [
      transcriptItem("status", `Session opened for ${cleanDisplayText(target, 120)}`, { tone: "primary" }),
    ],
    pendingUserMessages: [],
  };
}

function updateStage(stages: StageState[], id: string, updater: (stage: StageState) => StageState): StageState[] {
  return stages.map((stage) => (stage.id === id ? updater(stage) : stage));
}

export function applySessionEvent(state: SessionState, event: SessionEvent): SessionState {
  const msg = event.message ?? "";
  const stageId = mapStageId(event.stage);
  let next = { ...state, transcript: [...state.transcript] };

  if (event.type === "stage:start") {
    if (!stageId) return next;
    const current = next.stages.find((stage) => stage.id === stageId);
    if (current?.status === "running") {
      const action = normalizeStageAction(msg);
      if (!action) return next;
      const cleanedAction = cleanDisplayText(action, 240);
      next.stages = updateStage(next.stages, stageId, (stage) => ({
        ...stage,
        actions: appendStageAction(stage.actions, cleanedAction),
        findings: (() => {
          const savedFinding = parseSavedFinding(cleanedAction);
          return savedFinding ? upsertFinding(stage.findings, savedFinding) : stage.findings;
        })(),
      }));
      const turnAction = parseTurnAction(cleanedAction);
      if (turnAction && turnAction.body === "thinking") {
        next.transcript = appendToolAction(next.transcript, stageId, turnAction.turn, "thinking");
      } else if (turnAction) {
        next.transcript = appendToolAction(next.transcript, stageId, turnAction.turn, turnAction.body);
      } else {
        next.transcript = appendStageActionGroup(next.transcript, stageId, cleanedAction);
      }
      return next;
    }

    let detail = cleanDisplayText(msg, 180);
    const lower = msg.toLowerCase();
    if (lower.includes("claude")) detail = "using Claude";
    else if (lower.includes("codex")) detail = "using Codex";
    else if (lower.includes("gemini")) detail = "using Gemini";
    else if (lower.includes("api") || lower.includes("agentic")) detail = "using API";

    next.stages = updateStage(next.stages, stageId, (stage) => ({
      ...stage,
      status: "running",
      detail,
    }));
    next.transcript.push(transcriptItem("status", `${current?.label ?? stageId}: ${detail}`, { stage: stageId, tone: "primary" }));
    return next;
  }

  if (event.type === "stage:end") {
    if (!stageId) return next;
    const detail = cleanDisplayText(normalizeStageEndDetail(msg) || "done", 1200);
    const summary = summarizeDetail(detail);
    next.stages = updateStage(next.stages, stageId, (stage) => ({
      ...stage,
      status: "done",
      detail: summary,
      duration: (event.data as { durationMs?: number } | undefined)?.durationMs ?? stage.duration,
    }));
    next.transcript.push(transcriptItem("status", summary, { stage: stageId, tone: "muted" }));
    return next;
  }

  if (event.type === "finding") {
    const running = next.stages.find((stage) => stage.status === "running") ?? next.stages.find((stage) => stage.id === "attack");
    const severity = (event.data as { severity?: string } | undefined)?.severity ?? "info";
    const title = cleanDisplayText(msg.replace(/^\[[\w]+\]\s*/g, "").trim() || "Finding from AI analysis", 200);
    if (running) {
      next.stages = updateStage(next.stages, running.id, (stage) => ({
        ...stage,
        findings: upsertFinding(stage.findings, { severity, title }),
      }));
    }
    next.transcript.push(transcriptItem("finding", `[${severity}] ${title}`, { stage: running?.id, tone: severity === "critical" || severity === "high" ? "error" : severity === "medium" ? "warning" : "info" }));
    return next;
  }

  if (event.type === "verify:result") {
    const data = event.data as { confirmed?: boolean; title?: string; reason?: string } | undefined;
    const confirmed = data?.confirmed;
    const title = data?.title ?? event.message;
    const reason = data?.reason;
    const label = cleanDisplayText(confirmed ? `Confirmed: ${title}` : `Rejected: ${title}${reason ? ` (${reason})` : ""}`, 220);
    next.stages = updateStage(next.stages, "verify", (stage) => ({
      ...stage,
      actions: [...stage.actions, confirmed ? `✓ ${title}` : `✗ ${title}${reason ? ` — ${reason}` : ""}`],
    }));
    next.transcript.push(transcriptItem("verify", label, { stage: "verify", tone: confirmed ? "success" : "warning" }));
    return next;
  }

  if (event.type === "error") {
    const running = next.stages.find((stage) => stage.status === "running");
    const errorText = summarizeErrorText(msg);
    if (running) {
      next.stages = updateStage(next.stages, running.id, (stage) => ({
        ...stage,
        status: "error",
        error: errorText,
      }));
    }
    next.transcript.push(transcriptItem("error", errorText, { stage: running?.id, tone: "error" }));
    return next;
  }

  if (event.type === "thinking") {
    const turn = (event.data as { turn?: number } | undefined)?.turn;
    const thinking = cleanDisplayText(msg, 180);
    next.thinking = thinking;
    next.transcript = upsertThinkingItem(next.transcript, stageId, thinking, turn);
    return next;
  }

  if (event.type === "user:injected") {
    const text = (event.data as { text?: string } | undefined)?.text ?? event.message;
    // Remove the delivered message from the pending queue
    next.pendingUserMessages = next.pendingUserMessages.filter((m) => m !== text);
    next.transcript.push(transcriptItem("user-inject", text, { tone: "info" }));
    return next;
  }

  if (event.type === "usage") {
    const usage = event.data as { inputTokens?: number; outputTokens?: number; estimatedCostUsd?: number } | undefined;
    next.usage = {
      inputTokens: usage?.inputTokens ?? next.usage.inputTokens,
      outputTokens: usage?.outputTokens ?? next.usage.outputTokens,
      estimatedCostUsd: usage?.estimatedCostUsd ?? next.usage.estimatedCostUsd,
    };
    return next;
  }

  return next;
}

export function applySessionReport(state: SessionState, report: Record<string, unknown>): SessionState {
  const rep = report as {
    durationMs?: number;
    summary?: { critical?: number; high?: number; medium?: number; low?: number; info?: number };
  };

  return {
    ...state,
    stages: state.stages.map((stage) =>
      stage.status === "pending"
        ? { ...stage, status: "done", detail: "—" }
        : stage.status === "running"
          ? { ...stage, status: "done" }
          : stage,
    ),
    summary: {
      critical: rep.summary?.critical ?? 0,
      high: rep.summary?.high ?? 0,
      medium: rep.summary?.medium ?? 0,
      low: rep.summary?.low ?? 0,
      info: rep.summary?.info ?? 0,
      duration: rep.durationMs,
      shareUrl: buildShareUrl(report as any),
    },
    transcript: [
      ...state.transcript,
      transcriptItem("summary", "Report ready", { tone: "success" }),
    ],
  };
}
