import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type JSX,
} from "react";
import type {
  DesktopConsoleEvent,
  DesktopConsoleSession,
  DesktopConsoleUsage,
} from "@0sec/shared";
import {
  AlertCircle,
  ArrowDown,
  ArrowUp,
  Brain,
  ChevronDown,
  OctagonAlert,
  Plus,
  Play,
  Search,
  Settings,
  Square,
  Wrench,
  X,
} from "lucide-react";
import type { Workspace } from "./use-workspace.js";
import { Markdown } from "./markdown.js";
import { ApprovalPanel } from "./approvals.js";
import {
  reduceTurns,
  type ReducedTurn,
  type ToolCallState,
} from "./transcript.js";
import "./conversation.css";

// ── Exported Props Interfaces ─────────────────────────────────────

export interface ConversationProps {
  workspace: Workspace;
  onSettings: () => void;
  onNewSession: () => void;
  onInspect: () => void;
}

export interface InspectorProps {
  workspace: Workspace;
  onClose: () => void;
}

// ── Reasoning Block ───────────────────────────────────────────────

function ReasoningBlock({ text }: { text: string }): JSX.Element | null {
  const [expanded, setExpanded] = useState(false);
  if (!text) return null;

  return (
    <details
      className="reasoning-block"
      open={expanded}
      onToggle={(e) => setExpanded((e.target as HTMLDetailsElement).open)}
    >
      <summary>
        <Brain size={14} />
        <span>Reasoning</span>
        <ChevronDown size={14} className="chevron" />
      </summary>
      <div className="reasoning-content">{text}</div>
    </details>
  );
}

// ── Tool Call Block ───────────────────────────────────────────────

function ToolCallBlock({ call }: { call: ToolCallState }): JSX.Element {
  const [expanded, setExpanded] = useState(false);

  const resultPreview = useMemo(() => {
    if (call.result === undefined) return null;
    try {
      const raw =
        typeof call.result === "string"
          ? call.result
          : JSON.stringify(call.result, null, 2);
      return raw.length > 2000 ? raw.slice(0, 2000) + "\n… (truncated)" : raw;
    } catch {
      return String(call.result);
    }
  }, [call.result]);

  return (
    <div className={`tool-call${call.isRunning ? " running" : ""}`}>
      <button
        className="tool-call-header"
        onClick={() => setExpanded(!expanded)}
        aria-expanded={expanded}
      >
        <Wrench size={14} />
        <span className="tool-name">{call.name}</span>
        {call.isRunning && <span className="tool-status">Running…</span>}
        <ChevronDown
          size={14}
          className={`chevron${expanded ? " open" : ""}`}
        />
      </button>
      {expanded && (
        <div className="tool-call-body">
          <span className="section-label">Arguments</span>
          <pre>
            <code>
              {typeof call.arguments === "string"
                ? call.arguments
                : JSON.stringify(call.arguments, null, 2)}
            </code>
          </pre>

          {resultPreview !== null && (
            <>
              <span className="section-label">Result</span>
              <pre>
                <code>{resultPreview}</code>
              </pre>
            </>
          )}

          {call.isRunning && (
            <span style={{ fontSize: 11, color: "var(--muted)" }}>
              Awaiting result…
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ── User Message ──────────────────────────────────────────────────

function UserMessage({ text }: { text: string }): JSX.Element {
  return (
    <div className="user-message">
      <div className="bubble">{text}</div>
    </div>
  );
}

// ── Turn Error ────────────────────────────────────────────────────

function TurnError({
  error,
  stopReason,
}: {
  error: string;
  stopReason?: string;
}): JSX.Element {
  const isWarning = stopReason === "cancelled" || stopReason === "interrupted";
  return (
    <div className={`turn-error${isWarning ? " warning" : ""}`}>
      <div style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
        {isWarning ? (
          <AlertCircle size={14} style={{ flexShrink: 0, marginTop: 1 }} />
        ) : (
          <OctagonAlert size={14} style={{ flexShrink: 0, marginTop: 1 }} />
        )}
        <span>{error}</span>
      </div>
    </div>
  );
}

// ── System Notice ─────────────────────────────────────────────────

function SystemNotice({ text }: { text: string }): JSX.Element {
  return (
    <div className="system-notice">
      <AlertCircle size={12} />
      <span>{text}</span>
    </div>
  );
}

// ── Turn Block ────────────────────────────────────────────────────

function TurnBlock({
  turn,
  workspace,
}: {
  turn: ReducedTurn;
  workspace: Workspace;
}): JSX.Element {
  const hasAssistantText = turn.assistantText.trim().length > 0;
  const hasReasoning = turn.reasoningText.trim().length > 0;
  const hasTools = turn.toolCalls.length > 0;
  const hasDecisions = turn.decisions.length > 0;
  const hasNotices = turn.notices.length > 0;
  const hasError = !!turn.error;
  const isWorking = turn.isWorking;

  return (
    <div className="turn-block" data-turn-id={turn.id}>
      {/* User message */}
      <UserMessage text={turn.user.text} />

      {/* Notices */}
      {hasNotices &&
        turn.notices.map((n, i) => <SystemNotice key={i} text={n} />)}

      {/* Decisions requiring approval */}
      {hasDecisions &&
        turn.decisions.map((d) => (
          <ApprovalPanel key={d.id} decision={d} workspace={workspace} />
        ))}

      {/* Reasoning (collapsible, progressive) */}
      {hasReasoning && <ReasoningBlock text={turn.reasoningText} />}

      {/* Tool calls (collapsible live/result rows) */}
      {hasTools &&
        turn.toolCalls.map((tc) => <ToolCallBlock key={tc.id} call={tc} />)}

      {/* Assistant markdown text */}
      {hasAssistantText && <Markdown text={turn.assistantText} />}

      {/* Working indicator when streaming but nothing yet */}
      {isWorking && !hasAssistantText && !hasReasoning && !hasTools && (
        <div className="working-indicator">
          <span className="working-dot" />
          Working…
        </div>
      )}

      {/* Terminal error within turn */}
      {hasError && (
        <TurnError error={turn.error!} stopReason={turn.stopReason} />
      )}

      {/* Turn completed with error/stop-reason but no assistant text and no error string */}
      {turn.isComplete &&
        !hasAssistantText &&
        !hasError &&
        turn.stopReason != null && (
          <div className="turn-error warning">
            <div
              style={{
                display: "flex",
                gap: 6,
                alignItems: "flex-start",
              }}
            >
              <AlertCircle size={14} style={{ flexShrink: 0, marginTop: 1 }} />
              <span>Turn ended: {turn.stopReason}</span>
            </div>
          </div>
        )}
    </div>
  );
}

// ── Empty State ───────────────────────────────────────────────────

function EmptyState({
  onNewSession,
}: {
  onNewSession: () => void;
}): JSX.Element {
  return (
    <div className="conversation-empty">
      <h2>0sec Desktop</h2>
      <p>
        Run security engagements through the local console daemon. Start a new
        session to begin scanning, auditing, or reviewing a target.
      </p>
      <button className="empty-btn" onClick={onNewSession}>
        <Plus size={14} />
        New session
      </button>
    </div>
  );
}

// ── Composer ──────────────────────────────────────────────────────

function Composer({
  draft,
  onDraftChange,
  onSend,
  onStop,
  disabled,
  isWorking,
}: {
  draft: string;
  onDraftChange: (text: string) => void;
  onSend: () => void;
  onStop: () => void;
  disabled: boolean;
  isWorking: boolean;
}): JSX.Element {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [isComposing, setIsComposing] = useState(false);

  const autoResize = useCallback(() => {
    const ta = textareaRef.current;
    if (!ta) return;
    ta.style.height = "auto";
    ta.style.height = Math.min(ta.scrollHeight, 200) + "px";
  }, []);

  useEffect(() => {
    autoResize();
  }, [draft, autoResize]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if (isComposing) return;
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        if (!disabled && !isWorking && draft.trim()) onSend();
      }
    },
    [isComposing, disabled, isWorking, draft, onSend],
  );

  return (
    <div className="conversation-composer">
      <div className="composer-row">
        <textarea
          ref={textareaRef}
          className="composer-textarea"
          aria-label="Message"
          value={draft}
          onChange={(e) => onDraftChange(e.target.value)}
          onKeyDown={handleKeyDown}
          onCompositionStart={() => setIsComposing(true)}
          onCompositionEnd={() => setIsComposing(false)}
          placeholder={disabled ? "No active session" : "Send a message…"}
          disabled={disabled}
          rows={1}
        />
        <div className="composer-actions">
          {isWorking ? (
            <button
              className="composer-action-btn stop-btn"
              onClick={onStop}
              title="Stop"
              aria-label="Stop"
            >
              <Square size={14} />
            </button>
          ) : (
            <button
              className="composer-action-btn send-btn"
              onClick={onSend}
              disabled={disabled || !draft.trim()}
              title="Send"
              aria-label="Send"
            >
              <ArrowUp size={14} />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Bottom Context Row ────────────────────────────────────────────

function BottomContextRow({
  session,
  onConnection,
  onSettings,
}: {
  session: DesktopConsoleSession | null;
  onConnection: () => void;
  onSettings: () => void;
}): JSX.Element {
  if (!session) {
    return <div className="bottom-context-row" />;
  }

  return (
    <div className="bottom-context-row">
      <div className="context-left">
        <span className="context-badge" title="Role">
          <Play size={10} />
          {session.role}
        </span>
        <span className="context-badge" title="Autonomy mode">
          {session.autonomyMode}
        </span>
      </div>
      <div className="context-actions">
        <button
          className="context-action-btn"
          onClick={onConnection}
          title="Connection status"
        >
          <Search size={11} />
          Connection
        </button>
        <button
          className="context-action-btn"
          onClick={onSettings}
          title="Session settings"
        >
          <Settings size={11} />
          Settings
        </button>
      </div>
    </div>
  );
}

// ── Conversation (Main Export) ────────────────────────────────────

export function Conversation({
  workspace,
  onSettings,
  onNewSession,
  onInspect,
}: ConversationProps): JSX.Element {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [isNearBottom, setIsNearBottom] = useState(true);

  const turns = useMemo(
    () => reduceTurns(workspace.events),
    [workspace.events],
  );

  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 100;
    setIsNearBottom(nearBottom);
  }, []);

  // Auto-scroll to bottom only when user is near bottom
  useEffect(() => {
    if (isNearBottom && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [turns, isNearBottom]);

  const scrollToBottom = useCallback(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
      setIsNearBottom(true);
    }
  }, []);

  const handleSend = useCallback(() => {
    if (workspace.draft.trim() && !workspace.busy) {
      workspace.send();
    }
  }, [workspace]);

  const handleDraftChange = useCallback(
    (text: string) => {
      workspace.setDraft(text);
    },
    [workspace],
  );

  const activeSession = workspace.activeSession;

  if (!activeSession) {
    return (
      <div className="conversation-panel">
        <EmptyState onNewSession={onNewSession} />
        <Composer
          draft={workspace.draft}
          onDraftChange={handleDraftChange}
          onSend={handleSend}
          onStop={workspace.cancel}
          disabled={true}
          isWorking={false}
        />
        <BottomContextRow
          session={null}
          onConnection={onSettings}
          onSettings={onSettings}
        />
      </div>
    );
  }

  return (
    <div className="conversation-panel">
      <div
        className="conversation-scroll"
        ref={scrollRef}
        onScroll={handleScroll}
      >
        {turns.length === 0 && (
          <div className="conversation-empty">
            <p style={{ marginBottom: 0 }}>
              Session started. Send a message to begin.
            </p>
          </div>
        )}

        {turns.map((turn) => (
          <TurnBlock key={turn.id} turn={turn} workspace={workspace} />
        ))}
      </div>

      {/* Jump-to-latest button when scrolled up */}
      {!isNearBottom && turns.length > 0 && (
        <div className="jump-to-latest">
          <button onClick={scrollToBottom}>
            <ArrowDown size={14} />
            Latest
          </button>
        </div>
      )}

      <Composer
        draft={workspace.draft}
        onDraftChange={handleDraftChange}
        onSend={handleSend}
        onStop={workspace.cancel}
        disabled={
          workspace.loading ||
          activeSession.status === "closed" ||
          activeSession.status === "failed"
        }
        isWorking={
          activeSession.status === "working" ||
          activeSession.status === "waiting"
        }
      />

      <BottomContextRow
        session={activeSession}
        onConnection={onSettings}
        onSettings={onSettings}
      />
    </div>
  );
}

// ── Inspector Tab Content ─────────────────────────────────────────

function ContextTab({
  session,
}: {
  session: DesktopConsoleSession;
}): JSX.Element {
  return (
    <div>
      <div className="inspect-section">
        <div className="inspect-section-title">Session</div>
        <div className="inspect-row">
          <span className="inspect-label">Role</span>
          <span className="inspect-value">{session.role}</span>
        </div>
        <div className="inspect-row">
          <span className="inspect-label">Mode</span>
          <span className="inspect-value">{session.autonomyMode}</span>
        </div>
        <div className="inspect-row">
          <span className="inspect-label">Status</span>
          <span className={`inspect-badge ${session.status}`}>
            {session.status}
          </span>
        </div>
      </div>

      <div className="inspect-section">
        <div className="inspect-section-title">Scope</div>
        <div className="inspect-row">
          <span className="inspect-label">Target</span>
          <span className="inspect-value" style={{ fontSize: 11 }}>
            {session.target || "—"}
          </span>
        </div>
        <div className="inspect-row">
          <span className="inspect-label">Scope configured</span>
          <span className="inspect-value">
            {session.scopeConfigured ? "Yes" : "No"}
          </span>
        </div>
        <div className="inspect-row">
          <span className="inspect-label">Local scope</span>
          <span className="inspect-value">
            {session.localScopeConfigured ? "Yes" : "No"}
          </span>
        </div>
      </div>
    </div>
  );
}

function ActivityTab({
  events,
}: {
  events: DesktopConsoleEvent[];
}): JSX.Element {
  const lastUsage: DesktopConsoleUsage | null = useMemo(() => {
    const usageEvents = events.filter((e) => e.type === "usage");
    return (
      (usageEvents[usageEvents.length - 1]?.usage as
        | DesktopConsoleUsage
        | undefined) ?? null
    );
  }, [events]);

  const lastBudget = useMemo(() => {
    const completeEvents = events.filter((e) => e.type === "turn-complete");
    return completeEvents[completeEvents.length - 1]?.budget ?? null;
  }, [events]);

  const turnCount = useMemo(
    () => events.filter((e) => e.type === "user").length,
    [events],
  );

  const toolCount = useMemo(
    () => events.filter((e) => e.type === "tool-start").length,
    [events],
  );

  const usage = lastUsage;
  const budget = lastBudget;

  return (
    <div>
      <div className="inspect-section">
        <div className="inspect-section-title">Turns</div>
        <div className="inspect-row">
          <span className="inspect-label">Messages</span>
          <span className="inspect-value">{turnCount}</span>
        </div>
        <div className="inspect-row">
          <span className="inspect-label">Tool calls</span>
          <span className="inspect-value">{toolCount}</span>
        </div>
      </div>

      {usage && (
        <div className="inspect-section">
          <div className="inspect-section-title">Usage (Last Turn)</div>
          <div className="inspect-row">
            <span className="inspect-label">Input tokens</span>
            <span className="inspect-value">
              {usage.inputTokens.toLocaleString()}
            </span>
          </div>
          <div className="inspect-row">
            <span className="inspect-label">Output tokens</span>
            <span className="inspect-value">
              {usage.outputTokens.toLocaleString()}
            </span>
          </div>
          <div className="inspect-row">
            <span className="inspect-label">Iterations</span>
            <span className="inspect-value">
              {usage.iterations} / {usage.maxToolIterations}
            </span>
          </div>
          <div className="inspect-row">
            <span className="inspect-label">Token budget</span>
            <span className="inspect-value">
              {usage.turnTokensUsed.toLocaleString()} /{" "}
              {usage.turnTokenBudget.toLocaleString()}
            </span>
          </div>
          <div className="inspect-bar">
            <div
              className="inspect-bar-fill"
              style={{
                width: `${Math.min(100, (usage.turnTokensUsed / Math.max(1, usage.turnTokenBudget)) * 100)}%`,
              }}
            />
          </div>
        </div>
      )}

      {budget && (
        <div className="inspect-section">
          <div className="inspect-section-title">Budget</div>
          <div className="inspect-row">
            <span className="inspect-label">Tokens</span>
            <span className="inspect-value">
              {budget.tokensUsed.toLocaleString()} /{" "}
              {budget.tokenBudget.toLocaleString()}
            </span>
          </div>
          <div className="inspect-bar">
            <div
              className="inspect-bar-fill"
              style={{
                width: `${Math.min(100, (budget.tokensUsed / Math.max(1, budget.tokenBudget)) * 100)}%`,
              }}
            />
          </div>
          <div className="inspect-row">
            <span className="inspect-label">Iterations</span>
            <span className="inspect-value">
              {budget.iterations} / {budget.maxToolIterations}
            </span>
          </div>
        </div>
      )}

      {!usage && !budget && (
        <div
          style={{
            fontSize: 12,
            color: "var(--muted)",
            textAlign: "center",
            padding: 20,
          }}
        >
          No activity yet
        </div>
      )}
    </div>
  );
}

function EvidenceTab({
  events,
}: {
  events: DesktopConsoleEvent[];
}): JSX.Element {
  const toolResults: DesktopConsoleEvent[] = useMemo(() => {
    return events.filter((e) => e.type === "tool-result");
  }, [events]);

  if (toolResults.length === 0) {
    return (
      <div
        style={{
          fontSize: 12,
          color: "var(--muted)",
          textAlign: "center",
          padding: 20,
        }}
      >
        No tool results yet
      </div>
    );
  }

  return (
    <div className="inspect-section">
      <div className="inspect-section-title">
        Tool Results ({toolResults.length})
      </div>
      <div className="evidence-list">
        {toolResults.map((ev, i) => {
          const result = (ev as { type: "tool-result"; result: unknown })
            .result;
          const preview =
            typeof result === "string"
              ? result.slice(0, 120)
              : JSON.stringify(result).slice(0, 120);
          const call = (ev as { type: "tool-result"; call: { name: string } })
            .call;
          return (
            <div className="evidence-item" key={i}>
              <span className="ev-tool-name">{call.name}</span>
              <div className="ev-preview">{preview}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Inspector (Main Export) ───────────────────────────────────────

export function Inspector({ workspace, onClose }: InspectorProps): JSX.Element {
  const [tab, setTab] = useState<"context" | "activity" | "evidence">(
    "context",
  );

  const activeSession = workspace.activeSession;

  if (!activeSession) {
    return (
      <div className="inspector">
        <div className="inspector-header">
          <h3>Inspector</h3>
          <button
            className="close-btn"
            onClick={onClose}
            aria-label="Close inspector"
          >
            <X size={14} />
          </button>
        </div>
        <div
          style={{
            fontSize: 12,
            color: "var(--muted)",
            textAlign: "center",
            padding: 24,
          }}
        >
          No active session
        </div>
      </div>
    );
  }

  return (
    <div className="inspector">
      <div className="inspector-header">
        <h3>Inspector</h3>
        <button
          className="close-btn"
          onClick={onClose}
          aria-label="Close inspector"
        >
          <X size={14} />
        </button>
      </div>
      <div className="inspector-tabs">
        {(["context", "activity", "evidence"] as const).map((t) => (
          <button
            key={t}
            className={`inspector-tab${tab === t ? " active" : ""}`}
            onClick={() => setTab(t)}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>
      <div className="inspector-content">
        {tab === "context" && <ContextTab session={activeSession} />}
        {tab === "activity" && <ActivityTab events={workspace.events} />}
        {tab === "evidence" && <EvidenceTab events={workspace.events} />}
      </div>
    </div>
  );
}
