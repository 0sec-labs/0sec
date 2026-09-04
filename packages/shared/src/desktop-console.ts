/**
 * Renderer-neutral contract between the desktop renderer and the local console
 * daemon. It deliberately contains only JSON-safe values: neither Electron nor
 * a browser receives a live tool, scope, credential, or runtime object.
 */
export const DESKTOP_CONSOLE_SCHEMA_VERSION = 1 as const;

export type DesktopConsoleAutonomyMode = "standard" | "recon" | "copilot" | "yolo";
export type DesktopConsoleRole = "discovery" | "attack" | "verify" | "report" | "audit" | "review";
export type DesktopConsoleSessionStatus = "ready" | "working" | "waiting" | "closed" | "failed";

export type DesktopCodexAuthPhase = "idle" | "running" | "connected" | "cancelled" | "failed";

export interface DesktopCodexAuthStatus {
  phase: DesktopCodexAuthPhase;
  message: string;
  lines: readonly string[];
}

export interface DesktopConsoleSession {
  id: string;
  target: string;
  role: DesktopConsoleRole;
  autonomyMode: DesktopConsoleAutonomyMode;
  scopeConfigured: boolean;
  localScopeConfigured: boolean;
  status: DesktopConsoleSessionStatus;
  createdAt: string;
  updatedAt: string;
}

export interface DesktopConsoleToolCall {
  id?: string;
  name: string;
  arguments: unknown;
}

export interface DesktopConsoleUsage {
  inputTokens: number;
  outputTokens: number;
  turnTokensUsed: number;
  turnTokenBudget: number;
  iterations: number;
  maxToolIterations: number;
}

export interface DesktopConsoleTurnBudget {
  tokensUsed: number;
  tokenBudget: number;
  iterations: number;
  maxToolIterations: number;
}

export interface DesktopConsoleOperatorOption {
  label: string;
  description?: string;
}

export interface DesktopConsoleOperatorQuestion {
  header: string;
  question: string;
  options?: DesktopConsoleOperatorOption[];
  multiSelect?: boolean;
  allowCustom?: boolean;
}

export type DesktopConsoleDecisionKind = "tool" | "scope" | "local-scope" | "audit-escalation" | "operator-question";

export interface DesktopConsoleDecision {
  id: string;
  kind: DesktopConsoleDecisionKind;
  title: string;
  detail: string;
  call?: DesktopConsoleToolCall;
  requestedUrls?: string[];
  requestedPath?: string;
  questions?: DesktopConsoleOperatorQuestion[];
}

export interface DesktopConsoleOperatorAnswer {
  header: string;
  selectedLabels?: string[];
  customText?: string;
}

export interface DesktopConsoleDecisionResponse {
  approve: boolean;
  answers?: DesktopConsoleOperatorAnswer[];
}

interface DesktopConsoleEventBase {
  schemaVersion: typeof DESKTOP_CONSOLE_SCHEMA_VERSION;
  sessionId: string;
  sequence: number;
  occurredAt: string;
}

export type DesktopConsoleEventPayload =
  | { type: "session"; session: DesktopConsoleSession }
  | { type: "user"; text: string }
  | { type: "assistant-delta"; text: string }
  | { type: "reasoning-delta"; text: string }
  | { type: "tool-start"; call: DesktopConsoleToolCall }
  | { type: "tool-result"; call: DesktopConsoleToolCall; result: unknown }
  | { type: "usage"; usage: DesktopConsoleUsage }
  | { type: "notice"; text: string }
  | { type: "decision"; decision: DesktopConsoleDecision }
  | { type: "decision-resolved"; decisionId: string; approved: boolean }
  | { type: "turn-complete"; assistantText: string; stopReason: string; budget: DesktopConsoleTurnBudget; error?: string }
  | { type: "error"; message: string };

export type DesktopConsoleEvent = DesktopConsoleEventBase & DesktopConsoleEventPayload;
