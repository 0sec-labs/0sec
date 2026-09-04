import { randomUUID } from "node:crypto";

import {
  ScopePolicy,
  createConsoleRuntime,
  createConsoleSession,
  type AgentRole,
  type ConsoleAutonomyMode,
  type ConsoleLocalScopeRequest,
  type ConsoleScopeRequest,
  type ConsoleSession,
  type OperatorQuestionAnswer,
  type OperatorQuestionRequest,
  type ScopedAuditEscalationRequest,
  type ToolCall,
} from "@0sec/core";
import {
  DESKTOP_CONSOLE_SCHEMA_VERSION,
  type DesktopConsoleAutonomyMode,
  type DesktopConsoleDecision,
  type DesktopConsoleDecisionResponse,
  type DesktopConsoleEvent,
  type DesktopConsoleEventPayload,
  type DesktopConsoleOperatorAnswer,
  type DesktopConsoleOperatorQuestion,
  type DesktopConsoleRole,
  type DesktopConsoleSession,
  type DesktopConsoleSessionStatus,
  type DesktopConsoleToolCall,
  type DesktopConsoleUsage,
} from "@0sec/shared";

const MAX_EVENTS_PER_SESSION = 2_000;
const MAX_MESSAGE_LENGTH = 32_000;
const MAX_TARGET_LENGTH = 4_096;
const MAX_OPERATOR_TEXT_LENGTH = 8_000;

const ROLES = new Set<DesktopConsoleRole>(["discovery", "attack", "verify", "report", "audit", "review"]);
const MODES = new Set<DesktopConsoleAutonomyMode>(["standard", "recon", "copilot", "yolo"]);

type ConsoleGatewaySessionFactoryInput = {
  scanId: string;
  target: string;
  role: AgentRole;
  autonomyMode: ConsoleAutonomyMode;
  requestScope: (request: ConsoleScopeRequest) => Promise<{ target: string; scope: ScopePolicy } | null>;
  requestLocalScope: (request: ConsoleLocalScopeRequest) => Promise<{ scopePath: string } | null>;
  approveTool: (call: ToolCall) => Promise<boolean>;
  escalateScopedAudit: (request: ScopedAuditEscalationRequest) => Promise<boolean>;
  askOperator: (request: OperatorQuestionRequest) => Promise<OperatorQuestionAnswer | null>;
};

type ConsoleGatewaySessionFactory = (input: ConsoleGatewaySessionFactoryInput) => ConsoleSession;

type PendingDecision = {
  decision: DesktopConsoleDecision;
  resolve: (response: DesktopConsoleDecisionResponse) => void;
};

type ManagedSession = {
  id: string;
  createdAt: string;
  updatedAt: string;
  role: DesktopConsoleRole;
  target: string;
  autonomyMode: DesktopConsoleAutonomyMode;
  session: ConsoleSession | null;
  status: DesktopConsoleSessionStatus;
  events: DesktopConsoleEvent[];
  listeners: Set<(event: DesktopConsoleEvent) => void>;
  pending: Map<string, PendingDecision>;
  abort: AbortController | null;
};

/**
 * Raw transport input. `create()` validates every field before an engine
 * session exists, so HTTP and Electron callers never need unchecked casts.
 */
export type CreateDesktopConsoleSessionInput = {
  target?: unknown;
  role?: unknown;
  autonomyMode?: unknown;
};

export class DesktopConsoleGatewayError extends Error {
  constructor(
    message: string,
    readonly statusCode: number,
  ) {
    super(message);
    this.name = "DesktopConsoleGatewayError";
  }
}

export interface DesktopConsoleGatewayOptions {
  createSession?: ConsoleGatewaySessionFactory;
  now?: () => Date;
  createId?: () => string;
}

function asToolCall(call: ToolCall): DesktopConsoleToolCall {
  return { name: call.name, arguments: structuredClone(call.arguments) };
}

function asOperatorQuestions(request: OperatorQuestionRequest): DesktopConsoleOperatorQuestion[] {
  return request.questions.map((question) => ({
    header: question.header,
    question: question.question,
    options: question.options?.map((option) => ({
      label: option.label,
      ...(option.description ? { description: option.description } : {}),
    })),
    ...(question.multiSelect ? { multiSelect: true } : {}),
    ...(question.allowCustom ? { allowCustom: true } : {}),
  }));
}

function normalizeTarget(value: unknown): string {
  if (value === undefined) return "";
  if (typeof value !== "string") throw new DesktopConsoleGatewayError("Target must be a string.", 400);
  const target = value.trim();
  if (target.length > MAX_TARGET_LENGTH) {
    throw new DesktopConsoleGatewayError(`Target must be at most ${MAX_TARGET_LENGTH} characters.`, 400);
  }
  return target;
}

function normalizeRole(value: unknown): DesktopConsoleRole {
  if (value === undefined) return "audit";
  if (typeof value !== "string" || !ROLES.has(value as DesktopConsoleRole)) {
    throw new DesktopConsoleGatewayError("Unsupported console role.", 400);
  }
  return value as DesktopConsoleRole;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry): entry is string => typeof entry === "string");
}

function parseDecisionResponse(value: unknown): DesktopConsoleDecisionResponse {
  if (!value || typeof value !== "object" || !("approve" in value) || typeof value.approve !== "boolean") {
    throw new DesktopConsoleGatewayError("Decision response must include an approve boolean.", 400);
  }

  if (!("answers" in value) || value.answers === undefined) return { approve: value.approve };
  if (!Array.isArray(value.answers)) {
    throw new DesktopConsoleGatewayError("Decision answers must be an array.", 400);
  }

  const rawAnswers: unknown[] = value.answers;
  const answers: DesktopConsoleOperatorAnswer[] = rawAnswers.map((answer) => {
    if (!answer || typeof answer !== "object" || !("header" in answer) || typeof answer.header !== "string") {
      throw new DesktopConsoleGatewayError("Each operator answer needs a header.", 400);
    }
    const selectedLabels = "selectedLabels" in answer ? answer.selectedLabels : undefined;
    if (selectedLabels !== undefined && !isStringArray(selectedLabels)) {
      throw new DesktopConsoleGatewayError("Selected operator labels must be strings.", 400);
    }
    const customText = "customText" in answer ? answer.customText : undefined;
    if (customText !== undefined && typeof customText !== "string") {
      throw new DesktopConsoleGatewayError("Operator custom text must be a string.", 400);
    }
    return {
      header: answer.header,
      ...(selectedLabels ? { selectedLabels } : {}),
      ...(customText !== undefined ? { customText } : {}),
    };
  });
  return { approve: value.approve, answers };
}

function normalizeMode(value: unknown): DesktopConsoleAutonomyMode {
  if (value === undefined) return "standard";
  if (typeof value !== "string" || !MODES.has(value as DesktopConsoleAutonomyMode)) {
    throw new DesktopConsoleGatewayError("Unsupported autonomy mode.", 400);
  }
  return value as DesktopConsoleAutonomyMode;
}

function normalizeMessage(value: unknown): string {
  if (typeof value !== "string") throw new DesktopConsoleGatewayError("Message must be a string.", 400);
  const text = value.trim();
  if (!text) throw new DesktopConsoleGatewayError("Message cannot be empty.", 400);
  if (text.length > MAX_MESSAGE_LENGTH) {
    throw new DesktopConsoleGatewayError(`Message must be at most ${MAX_MESSAGE_LENGTH} characters.`, 400);
  }
  return text;
}

function buildScopeResolution(request: ConsoleScopeRequest): { target: string; scope: ScopePolicy } | null {
  const raw = request.currentScope?.raw ?? {};
  const inScope = new Set(raw.in_scope ?? []);
  let target = request.target.trim();

  for (const requestedUrl of request.requestedUrls) {
    try {
      const url = new URL(requestedUrl);
      inScope.add(url.hostname);
      if (!target) target = url.origin;
    } catch {
      return null;
    }
  }

  if (!target || inScope.size === 0) return null;
  const scope = ScopePolicy.fromJson({ ...raw, in_scope: [...inScope] });
  if (request.requestedUrls.some((url) => !scope.match(url).allowed)) return null;
  return { target, scope };
}

function validOperatorAnswer(
  request: OperatorQuestionRequest,
  response: DesktopConsoleDecisionResponse,
): OperatorQuestionAnswer | null {
  if (!response.approve) return null;
  if (!Array.isArray(response.answers) || response.answers.length !== request.questions.length) return null;

  const byHeader = new Map<string, DesktopConsoleOperatorAnswer>();
  for (const answer of response.answers) {
    if (!answer || typeof answer.header !== "string" || byHeader.has(answer.header)) return null;
    byHeader.set(answer.header, answer);
  }

  const answers: OperatorQuestionAnswer["answers"] = [];
  for (const question of request.questions) {
    const answer = byHeader.get(question.header);
    if (!answer) return null;
    const selectedLabels = answer.selectedLabels ?? [];
    if (!Array.isArray(selectedLabels) || !selectedLabels.every((label) => typeof label === "string")) return null;
    const allowedLabels = new Set(question.options?.map((option) => option.label) ?? []);
    if (selectedLabels.some((label) => !allowedLabels.has(label))) return null;
    if (!question.multiSelect && selectedLabels.length > 1) return null;

    const customText = answer.customText?.trim();
    if (customText && (!question.allowCustom || customText.length > MAX_OPERATOR_TEXT_LENGTH)) return null;
    answers.push({
      header: question.header,
      ...(selectedLabels.length > 0 ? { selectedLabels } : {}),
      ...(customText ? { customText } : {}),
    });
  }
  return { requestId: request.requestId, answers };
}

export class DesktopConsoleGateway {
  readonly #sessions = new Map<string, ManagedSession>();
  readonly #now: () => Date;
  readonly #createId: () => string;
  readonly #createSession: ConsoleGatewaySessionFactory;

  constructor(options: DesktopConsoleGatewayOptions = {}) {
    this.#now = options.now ?? (() => new Date());
    this.#createId = options.createId ?? randomUUID;
    this.#createSession = options.createSession ?? ((input) => createConsoleSession({
      runtime: createConsoleRuntime(),
      scanId: input.scanId,
      target: input.target,
      role: input.role,
      autonomyMode: input.autonomyMode,
      requestScope: input.requestScope,
      requestLocalScope: input.requestLocalScope,
      approveTool: input.approveTool,
      escalateScopedAudit: input.escalateScopedAudit,
      askOperator: input.askOperator,
    }));
  }

  list(): DesktopConsoleSession[] {
    return [...this.#sessions.values()]
      .map((managed) => this.#summary(managed))
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }

  create(input: CreateDesktopConsoleSessionInput = {}): DesktopConsoleSession {
    const id = this.#createId();
    const target = normalizeTarget(input.target);
    const role = normalizeRole(input.role);
    const autonomyMode = normalizeMode(input.autonomyMode);
    const now = this.#now().toISOString();
    const managed: ManagedSession = {
      id,
      createdAt: now,
      updatedAt: now,
      role,
      target,
      autonomyMode,
      session: null,
      status: "ready",
      events: [],
      listeners: new Set(),
      pending: new Map(),
      abort: null,
    };
    this.#sessions.set(id, managed);
    this.#emit(managed, { type: "session", session: this.#summary(managed) });
    return this.#summary(managed);
  }

  eventsAfter(id: string, after = 0): DesktopConsoleEvent[] {
    const managed = this.#require(id);
    return managed.events.filter((event) => event.sequence > after);
  }

  subscribe(id: string, listener: (event: DesktopConsoleEvent) => void): () => void {
    const managed = this.#require(id);
    managed.listeners.add(listener);
    return () => managed.listeners.delete(listener);
  }

  send(id: string, value: unknown): DesktopConsoleSession {
    const managed = this.#require(id);
    const text = normalizeMessage(value);
    if (managed.status === "closed") throw new DesktopConsoleGatewayError("Console session is closed.", 410);
    if (managed.status !== "ready") throw new DesktopConsoleGatewayError("Console session is already processing a turn.", 409);

    let session: ConsoleSession;
    try {
      session = this.#ensureSession(managed);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.#emit(managed, { type: "error", message });
      throw new DesktopConsoleGatewayError(message, 409);
    }

    const abort = new AbortController();
    managed.status = "working";
    managed.abort = abort;
    this.#emit(managed, { type: "session", session: this.#summary(managed) });
    this.#emit(managed, { type: "user", text });

    void session.send(text, {
      onAssistantDelta: (delta) => this.#emit(managed, { type: "assistant-delta", text: delta }),
      onReasoningDelta: (delta) => this.#emit(managed, { type: "reasoning-delta", text: delta }),
      onToolStart: (call) => this.#emit(managed, { type: "tool-start", call: asToolCall(call) }),
      onToolResult: (call, result) => this.#emit(managed, {
        type: "tool-result",
        call: asToolCall(call),
        result: structuredClone(result),
      }),
      onUsage: (usage) => {
        const desktopUsage: DesktopConsoleUsage = structuredClone(usage);
        this.#emit(managed, { type: "usage", usage: desktopUsage });
      },
      onNotice: (notice) => this.#emit(managed, { type: "notice", text: notice }),
    }, { signal: abort.signal }).then((outcome) => {
      this.#emit(managed, {
        type: "turn-complete",
        assistantText: outcome.assistantText,
        stopReason: outcome.stopReason,
        budget: structuredClone(outcome.budget),
        ...(outcome.error ? { error: outcome.error } : {}),
      });
      this.#finishTurn(managed);
    }).catch((error: unknown) => {
      this.#emit(managed, {
        type: "error",
        message: error instanceof Error ? error.message : String(error),
      });
      this.#finishTurn(managed, "failed");
    });

    return this.#summary(managed);
  }

  cancel(id: string): DesktopConsoleSession {
    const managed = this.#require(id);
    if (managed.status !== "working" || !managed.abort) {
      throw new DesktopConsoleGatewayError("Console session has no active turn to cancel.", 409);
    }
    managed.abort.abort();
    this.#emit(managed, { type: "notice", text: "Cancellation requested; the current model call will stop at its next safe boundary." });
    return this.#summary(managed);
  }

  resolveDecision(id: string, decisionId: string, response: unknown): DesktopConsoleSession {
    const managed = this.#require(id);
    const pending = managed.pending.get(decisionId);
    if (!pending) throw new DesktopConsoleGatewayError("Approval request is no longer pending.", 404);
    const value = parseDecisionResponse(response);
    managed.pending.delete(decisionId);
    pending.resolve(value);
    if (managed.pending.size === 0 && managed.status === "waiting") {
      managed.status = "working";
      this.#emit(managed, { type: "session", session: this.#summary(managed) });
    }
    this.#emit(managed, { type: "decision-resolved", decisionId, approved: value.approve });
    this.#emit(managed, {
      type: "notice",
      text: value.approve ? `${pending.decision.title} approved.` : `${pending.decision.title} declined.`,
    });
    return this.#summary(managed);
  }

  async close(id: string): Promise<void> {
    const managed = this.#require(id);
    if (managed.status === "closed") return;
    managed.abort?.abort();
    for (const pending of managed.pending.values()) pending.resolve({ approve: false });
    managed.pending.clear();
    managed.status = "closed";
    this.#emit(managed, { type: "session", session: this.#summary(managed) });
    if (managed.session) await managed.session.cleanup();
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.#sessions.keys()].map((id) => this.close(id)));
  }

  #ensureSession(managed: ManagedSession): ConsoleSession {
    if (managed.session) return managed.session;

    const role = managed.role as AgentRole;
    const autonomyMode = managed.autonomyMode as ConsoleAutonomyMode;
    const session = this.#createSession({
      scanId: managed.id,
      target: managed.target,
      role,
      autonomyMode,
      requestScope: async (request) => {
        const response = await this.#requestDecision(managed, {
          kind: "scope",
          title: "Authorize scope expansion",
          detail: request.requestedUrls.length > 0
            ? `The next tool call reaches ${request.requestedUrls.length} target${request.requestedUrls.length === 1 ? "" : "s"} outside the current scope.`
            : "The next tool call has an unresolved network destination.",
          call: asToolCall(request.call),
          requestedUrls: [...request.requestedUrls],
        });
        return response.approve ? buildScopeResolution(request) : null;
      },
      requestLocalScope: async (request) => {
        const response = await this.#requestDecision(managed, {
          kind: "local-scope",
          title: "Authorize local directory",
          detail: "This grants this directory subtree for the current session only. Nothing is written to disk.",
          call: asToolCall(request.call),
          requestedPath: request.requestedPath,
        });
        return response.approve ? { scopePath: request.requestedPath } : null;
      },
      approveTool: async (call) => {
        const response = await this.#requestDecision(managed, {
          kind: "tool",
          title: "Confirm tool action",
          detail: "Standard mode requires an explicit confirmation before this action runs.",
          call: asToolCall(call),
        });
        return response.approve;
      },
      escalateScopedAudit: async (request) => {
        const response = await this.#requestDecision(managed, {
          kind: "audit-escalation",
          title: "Lift source-audit restriction",
          detail: "Scope, local-directory, and per-tool approval rules remain in force.",
          call: asToolCall(request.call),
        });
        return response.approve;
      },
      askOperator: async (request) => {
        const response = await this.#requestDecision(managed, {
          kind: "operator-question",
          title: "Operator input requested",
          detail: "This answers the agent's question; it authorizes no tool or scope change.",
          questions: asOperatorQuestions(request),
        });
        return validOperatorAnswer(request, response);
      },
    });
    managed.session = session;
    return session;
  }

  #requestDecision(managed: ManagedSession, input: Omit<DesktopConsoleDecision, "id">): Promise<DesktopConsoleDecisionResponse> {
    const deferred = Promise.withResolvers<DesktopConsoleDecisionResponse>();
    const decision: DesktopConsoleDecision = { id: this.#createId(), ...input };
    managed.pending.set(decision.id, { decision, resolve: deferred.resolve });
    managed.status = "waiting";
    this.#emit(managed, { type: "session", session: this.#summary(managed) });
    this.#emit(managed, { type: "decision", decision });
    return deferred.promise;
  }

  #finishTurn(managed: ManagedSession, status: DesktopConsoleSessionStatus = "ready"): void {
    managed.abort = null;
    if (managed.status !== "closed") {
      managed.status = status;
      this.#emit(managed, { type: "session", session: this.#summary(managed) });
    }
  }

  #summary(managed: ManagedSession): DesktopConsoleSession {
    return {
      id: managed.id,
      target: managed.session?.target ?? managed.target,
      role: managed.role,
      autonomyMode: managed.session?.autonomyMode ?? managed.autonomyMode,
      scopeConfigured: Boolean(managed.session?.scope),
      localScopeConfigured: Boolean(managed.session?.localScopePath),
      status: managed.status,
      createdAt: managed.createdAt,
      updatedAt: managed.updatedAt,
    };
  }

  #emit<T extends DesktopConsoleEventPayload>(managed: ManagedSession, event: T): void {
    const emitted: DesktopConsoleEvent = {
      ...event,
      schemaVersion: DESKTOP_CONSOLE_SCHEMA_VERSION,
      sessionId: managed.id,
      sequence: (managed.events.at(-1)?.sequence ?? 0) + 1,
      occurredAt: this.#now().toISOString(),
    };
    managed.updatedAt = emitted.occurredAt;
    managed.events.push(emitted);
    if (managed.events.length > MAX_EVENTS_PER_SESSION) managed.events.splice(0, managed.events.length - MAX_EVENTS_PER_SESSION);
    for (const listener of managed.listeners) listener(emitted);
  }

  #require(id: string): ManagedSession {
    const managed = this.#sessions.get(id);
    if (!managed) throw new DesktopConsoleGatewayError("Console session was not found.", 404);
    return managed;
  }
}
