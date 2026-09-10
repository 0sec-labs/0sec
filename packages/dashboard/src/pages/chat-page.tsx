import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type {
  DesktopCodexAuthStatus,
  DesktopConsoleAutonomyMode,
  DesktopConsoleDecision,
  DesktopConsoleDecisionResponse,
  DesktopConsoleEvent,
  DesktopConsoleOperatorAnswer,
  DesktopConsoleRole,
  DesktopConsoleSession,
  DesktopHostCommand,
} from "@0sec/shared";
import {
  cancelDesktopCodexDeviceAuth,
  cancelDesktopConsoleTurn,
  createDesktopConsoleSession,
  getDesktopCodexAuthStatus,
  getDesktopConsoleEvents,
  getDesktopConsoleSessions,
  resolveDesktopConsoleDecision,
  sendDesktopConsoleMessage,
  startDesktopCodexDeviceAuth,
} from "@/api";
import { cn } from "@/lib/utils";
import { usePersistentState } from "@/lib/use-persistent-state";
import { useKeyboardShortcuts } from "@/lib/use-keyboard-shortcuts";
import {
  ArrowDown, ArrowUp, Check, ChevronRight, LoaderCircle, Square,
  PanelLeft, Plus, Search, Settings, FileText, FolderOpen,
  X, Sparkles,
} from "lucide-react";
import { ChatMessage } from "@/components/chat-message";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import brandMark from "../../../../assets/0sec-aperture-ink.svg";
import "@/desktop.css";

const EMPTY_EVENTS: readonly DesktopConsoleEvent[] = [];

/* ─── Types ─────────────────────────────────────────────────── */
type DetailView = "context" | "activity" | "evidence";

type TranscriptEntry =
  | { id: string; kind: "user" | "assistant" | "notice" | "error"; text: string }
  | { id: string; kind: "tool"; callId?: string; name: string; arguments: unknown; result?: unknown; status: "running" | "complete" | "interrupted" };

/* ─── Constants ─────────────────────────────────────────────── */
const MODE_LABELS: Record<DesktopConsoleAutonomyMode, string> = {
  standard: "standard",
  recon: "recon",
  copilot: "co-pilot",
  yolo: "yolo",
};

/* ─── Helpers ────────────────────────────────────────────────── */
function formatTarget(target: string): string {
  if (!target) return "target: not set";
  try {
    const url = new URL(target);
    return url.hostname || target;
  } catch {
    return target;
  }
}

function formatPayload(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function eventLabel(event: DesktopConsoleEvent): string {
  switch (event.type) {
    case "assistant-delta": return "drafting response";
    case "reasoning-delta": return "reasoning updated";
    case "tool-start": return `running ${event.call.name}`;
    case "tool-result": return `${event.call.name} completed`;
    case "usage": return `${event.usage.turnTokensUsed.toLocaleString()} tokens this turn`;
    case "decision": return event.decision.title.toLowerCase();
    case "decision-resolved": return event.approved ? "approval granted" : "approval declined";
    case "turn-complete": return event.stopReason === "end_turn" ? "turn complete" : event.stopReason;
    case "user": return "operator message";
    case "notice": return event.text;
    case "error": return event.message;
    case "session": return event.session.status;
  }
}

function buildTranscript(events: readonly DesktopConsoleEvent[]): TranscriptEntry[] {
  const entries: TranscriptEntry[] = [];
  let turnStart = 0;
  for (const event of events) {
    if (event.type === "user") {
      entries.push({ id: `user-${event.sequence}`, kind: "user", text: event.text });
      turnStart = entries.length;
      continue;
    }
    if (event.type === "assistant-delta") {
      const last = entries.at(-1);
      if (last?.kind === "assistant") last.text += event.text;
      else entries.push({ id: `assistant-${event.sequence}`, kind: "assistant", text: event.text });
      continue;
    }
    if (event.type === "tool-start") {
      entries.push({ id: `tool-${event.sequence}`, kind: "tool", callId: event.call.id, name: event.call.name, arguments: event.call.arguments, status: "running" });
      continue;
    }
    if (event.type === "tool-result") {
      const prior = entries.find((entry): entry is Extract<TranscriptEntry, { kind: "tool" }> =>
        entry.kind === "tool" && entry.status === "running" &&
        (event.call.id ? entry.callId === event.call.id : entry.name === event.call.name));
      if (prior) {
        prior.result = event.result;
        prior.status = "complete";
      } else entries.push({ id: `tool-${event.sequence}`, kind: "tool", callId: event.call.id, name: event.call.name, arguments: event.call.arguments, result: event.result, status: "complete" });
      continue;
    }
    if (event.type === "turn-complete") {
      for (const entry of entries) {
        if (entry.kind === "tool" && entry.status === "running") entry.status = "interrupted";
      }
      if (event.assistantText) {
        let streamed = "";
        for (let index = turnStart; index < entries.length; index++) {
          const entry = entries[index];
          if (entry.kind === "assistant") streamed += entry.text;
        }
        if (event.assistantText !== streamed) {
          if (event.assistantText.startsWith(streamed)) {
            const suffix = event.assistantText.slice(streamed.length);
            const last = entries.at(-1);
            if (last?.kind === "assistant") last.text += suffix;
            else entries.push({ id: `assistant-final-${event.sequence}`, kind: "assistant", text: suffix });
          } else {
            let retained = turnStart;
            for (let index = turnStart; index < entries.length; index++) {
              const entry = entries[index];
              if (entry.kind !== "assistant") entries[retained++] = entry;
            }
            entries.length = retained;
            entries.push({ id: `assistant-final-${event.sequence}`, kind: "assistant", text: event.assistantText });
          }
        }
      }
      if (event.error) entries.push({ id: `error-${event.sequence}`, kind: "error", text: event.error });
      continue;
    }
    if (event.type === "notice") entries.push({ id: `notice-${event.sequence}`, kind: "notice", text: event.text });
    if (event.type === "error") {
      for (const entry of entries) {
        if (entry.kind === "tool" && entry.status === "running") entry.status = "interrupted";
      }
      entries.push({ id: `error-${event.sequence}`, kind: "error", text: event.message });
    }
  }
  return entries;
}

function mergeEvents(current: readonly DesktopConsoleEvent[], incoming: readonly DesktopConsoleEvent[]): DesktopConsoleEvent[] {
  if (incoming.length === 0) return [...current];
  const known = new Set(current.map((event) => event.sequence));
  return [...current, ...incoming.filter((event) => !known.has(event.sequence))];
}

/* ─── Logo ──────────────────────────────────────────────────── */
function DesktopMark() {
  return <span className="desktop-wordmark" role="img" aria-label="0sec" style={{ maskImage: `url("${brandMark}")` }} />;
}

/* ─── Composer ───────────────────────────────────────────────── */
function DesktopComposer({
  value,
  disabled,
  working,
  onChange,
  onSubmit,
  onCancel,
}: {
  value: string;
  disabled: boolean;
  working: boolean;
  onChange: (value: string) => void;
  onSubmit: () => void;
  onCancel: () => void;
}) {
  const inputRef = useRef<HTMLTextAreaElement>(null);
  useLayoutEffect(() => {
    const input = inputRef.current;
    if (!input) return;
    input.style.height = "auto";
    input.style.height = `${Math.min(input.scrollHeight, 200)}px`;
  }, [value]);
  return (
    <form
      className="desktop-composer-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (!disabled && !working) onSubmit();
      }}
    >
      <textarea
        ref={inputRef}
        autoFocus
        aria-label="Message 0sec"
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
            event.preventDefault();
            if (!disabled && !working) onSubmit();
          }
        }}
        placeholder={working ? "Write your next message…" : "Ask a question, or describe what to investigate…"}
        rows={2}
        className="desktop-composer-input"
      />
      <div className="desktop-composer-toolbar">
        <span className="desktop-composer-hint"><span className="hidden sm:inline">Enter to send · </span>Shift+Enter for a new line</span>
        <div className="desktop-composer-actions">
          {working ? (
            <button type="button" aria-label="Stop response" className="desktop-btn" onClick={onCancel}>
              <Square aria-hidden className="size-3.5" />
              <span>Stop</span>
            </button>
          ) : (
            <button type="submit" aria-label="Send message" className="desktop-btn desktop-send" disabled={disabled || !value.trim()}>
              <ArrowUp aria-hidden className="size-3.5" />
            </button>
          )}
        </div>
      </div>
    </form>
  );
}

/* ─── Decision panel ──────────────────────────────────────────── */
function DesktopDecisionPanel({ decision, busy, onResolve }: { decision: DesktopConsoleDecision; busy: boolean; onResolve: (response: DesktopConsoleDecisionResponse) => Promise<void> }) {
  const [answers, setAnswers] = useState<Record<string, DesktopConsoleOperatorAnswer>>({});
  const respond = (approve: boolean) => {
    const response: DesktopConsoleDecisionResponse = decision.kind === "operator-question"
      ? { approve, answers: decision.questions?.map((question) => answers[question.header] ?? { header: question.header }) ?? [] }
      : { approve };
    void onResolve(response);
  };

  return (
    <section className="desktop-decision-panel">
      <p className="desktop-decision-label">approval required</p>
      <h2 className="desktop-decision-title">{decision.title}</h2>
      <p className="desktop-decision-detail">{decision.detail}</p>
      {decision.call ? <pre className="desktop-decision-call">{decision.call.name} {formatPayload(decision.call.arguments)}</pre> : null}
      {decision.requestedUrls?.map((url) => <p className="desktop-decision-url" key={url}>{url}</p>)}
      {decision.requestedPath ? <p className="desktop-decision-url">{decision.requestedPath}</p> : null}
      {decision.questions?.map((question) => {
        const answer = answers[question.header] ?? { header: question.header };
        return (
          <div className="desktop-question" key={question.header}>
            <p className="desktop-question-header">{question.header}</p>
            <p className="desktop-question-text">{question.question}</p>
            {question.options?.length ? (
              <div className="desktop-question-options">
                {question.options.map((option) => {
                  const selected = answer.selectedLabels?.includes(option.label) ?? false;
                  return (
                    <button
                      type="button"
                      key={option.label}
                      onClick={() => setAnswers((current) => {
                        const prior = current[question.header] ?? { header: question.header };
                        const labels = new Set(prior.selectedLabels ?? []);
                        if (labels.has(option.label)) labels.delete(option.label);
                        else if (question.multiSelect) labels.add(option.label);
                        else { labels.clear(); labels.add(option.label); }
                        return { ...current, [question.header]: { ...prior, selectedLabels: [...labels] } };
                      })}
                      className={cn("desktop-question-option", selected && "desktop-question-option-selected")}
                    >
                      {option.label}
                    </button>
                  );
                })}
              </div>
            ) : null}
            {question.allowCustom ? (
              <input
                value={answer.customText ?? ""}
                onChange={(event) => setAnswers((current) => ({
                  ...current,
                  [question.header]: { ...answer, customText: event.target.value }
                }))}
                className="desktop-question-input"
                placeholder="optional context"
              />
            ) : null}
          </div>
        );
      })}
      <div className="desktop-decision-actions">
        <button type="button" className="desktop-btn" disabled={busy} onClick={() => respond(false)}>Decline</button>
        <button type="button" className="desktop-btn desktop-btn-primary" disabled={busy} onClick={() => respond(true)}>
          {decision.kind === "operator-question" ? "Submit" : "Approve"}
        </button>
      </div>
    </section>
  );
}

/* ─── Codex connection section ────────────────────────────────── */
function DesktopCodexSection({ status, busy, onStart, onCancel }: { status: DesktopCodexAuthStatus | null; busy: boolean; onStart: () => Promise<void>; onCancel: () => Promise<void> }) {
  if (!status || status.phase === "connected") return null;
  const running = status.phase === "running";
  return (
    <div className="desktop-codex-section">
      <p className="desktop-codex-label">ChatGPT Codex</p>
      <p className="desktop-codex-desc">Device sign-in stays in the local daemon. Credentials never enter this window.</p>
      {status.lines.length > 0 ? <pre className="desktop-codex-output">{status.lines.join("\n")}</pre> : null}
      {status.phase === "failed" ? <p className="desktop-codex-error">{status.message}</p> : null}
      <div className="mt-2">
        {running ? (
          <button className="desktop-btn" disabled={busy} onClick={() => void onCancel()}>Cancel sign-in</button>
        ) : (
          <button className="desktop-btn" disabled={busy} onClick={() => void onStart()}>Connect Codex</button>
        )}
      </div>
    </div>
  );
}

/* ─── Inspector panel ──────────────────────────────────────────── */
function DesktopInspector({
  open,
  view,
  session,
  pending,
  activity,
  evidence,
  auth,
  busy,
  onClose,
  onView,
  onResolve,
  onConnect,
  onCancelConnect,
}: {
  open: boolean;
  view: DetailView;
  session: DesktopConsoleSession | null;
  pending: readonly DesktopConsoleDecision[];
  activity: readonly DesktopConsoleEvent[];
  evidence: readonly Extract<DesktopConsoleEvent, { type: "tool-result" }>[];
  auth: DesktopCodexAuthStatus | null;
  busy: boolean;
  onClose: () => void;
  onView: (view: DetailView) => void;
  onResolve: (decision: DesktopConsoleDecision, response: DesktopConsoleDecisionResponse) => Promise<void>;
  onConnect: () => Promise<void>;
  onCancelConnect: () => Promise<void>;
}) {
  return (
    <aside className={cn("desktop-inspector", open && "desktop-inspector-open")} inert={!open} aria-hidden={!open}>
      <div className="desktop-inspector-inner">
        <div className="desktop-inspector-header">
          <span className="desktop-inspector-header-label">Inspector</span>
          <button className="desktop-btn-icon" aria-label="Close inspector" onClick={onClose}>
            <X aria-hidden className="size-3.5" />
          </button>
        </div>
        <div className="desktop-inspector-tabs" role="tablist">
          {(["context", "activity", "evidence"] as const).map((tab) => (
            <button
              key={tab}
              role="tab"
              aria-selected={view === tab}
              className={cn("desktop-inspector-tab", view === tab && "desktop-inspector-tab-active")}
              onClick={() => onView(tab)}
            >
              {tab === "context" ? "Context" : tab === "activity" ? "Activity" : "Evidence"}
            </button>
          ))}
        </div>
        <div className="desktop-inspector-body">
          {pending.map((decision) => (
            <div key={decision.id} className="mb-4">
              <DesktopDecisionPanel decision={decision} busy={busy} onResolve={(response) => onResolve(decision, response)} />
            </div>
          ))}
          {view === "context" ? (
            <>
              <dl className="desktop-inspector-dl">
                <div>
                  <dt className="desktop-inspector-dt">Target</dt>
                  <dd className={cn("desktop-inspector-dd", "desktop-inspector-dd-mono")}>{session?.target || "not set"}</dd>
                </div>
                <div className="desktop-inspector-row">
                  <dt className="desktop-inspector-dt">Mode</dt>
                  <dd className="desktop-inspector-dd">{session ? MODE_LABELS[session.autonomyMode] : "standard"}</dd>
                </div>
                <div className="desktop-inspector-row">
                  <dt className="desktop-inspector-dt">Approvals</dt>
                  <dd className="desktop-inspector-dd">{pending.length}</dd>
                </div>
              </dl>
              <DesktopCodexSection status={auth} busy={busy} onStart={onConnect} onCancel={onCancelConnect} />
            </>
          ) : view === "activity" ? (
            activity.length === 0 ? (
              <p className="desktop-inspector-empty">Activity appears when a turn begins, a tool runs, or an approval is needed.</p>
            ) : (
              activity.map((event) => (
                <div key={event.sequence} className="desktop-inspector-event">
                  <p className="desktop-inspector-event-label">{eventLabel(event)}</p>
                  <p className="desktop-inspector-event-time">{new Date(event.occurredAt).toLocaleTimeString()}</p>
                </div>
              ))
            )
          ) : (
            evidence.length === 0 ? (
              <p className="desktop-inspector-empty">Evidence-producing tool results appear here. Findings remain in the Findings route.</p>
            ) : (
              evidence.map((event) => (
                <article key={event.sequence} className="desktop-inspector-evidence">
                  <p className="desktop-inspector-evidence-name">{event.call.name}</p>
                  <pre className="desktop-inspector-evidence-payload">{formatPayload(event.result)}</pre>
                </article>
              ))
            )
          )}
        </div>
      </div>
    </aside>
  );
}

/* ─── Sidebar ─────────────────────────────────────────────────── */
function DesktopSidebar({
  sessions,
  activeId,
  collapsed,
  draftMap,
  titles,
  busy,
  threadSearch,
  onToggle,
  onSelect,
  onNew,
  onScoped,
  onSettings,
  onSearchChange,
}: {
  sessions: readonly DesktopConsoleSession[];
  activeId: string | null;
  collapsed: boolean;
  draftMap: Record<string, string>;
  titles: Record<string, string>;
  busy: boolean;
  threadSearch: string;
  onToggle: () => void;
  onSelect: (id: string) => void;
  onNew: () => void;
  onScoped: () => void;
  onSettings: () => void;
  onSearchChange: (value: string) => void;
}) {
  const filtered = useMemo(() => {
    if (!threadSearch.trim()) return sessions;
    const q = threadSearch.toLowerCase();
    return sessions.filter((s) => {
      const target = formatTarget(s.target).toLowerCase();
      const draft = (draftMap[s.id] ?? "").toLowerCase();
      return target.includes(q) || (titles[s.id] ?? "").toLowerCase().includes(q) || draft.includes(q);
    });
  }, [sessions, threadSearch, draftMap, titles]);

  return (
    <aside className={cn("desktop-sidebar", collapsed && "desktop-sidebar-collapsed")} inert={collapsed} aria-hidden={collapsed}>
      <div className="desktop-sidebar-header">
        <DesktopMark />
        <div className="desktop-sidebar-header-actions">
          <button
            className="desktop-btn-icon"
            aria-label="Toggle sidebar"
            onClick={onToggle}
          >
            <PanelLeft aria-hidden className="size-3.5" />
          </button>
        </div>
      </div>
      <div className="desktop-sidebar-new">
        <button className="desktop-sidebar-action" onClick={onNew} disabled={busy}>
          <Plus aria-hidden className="size-3.5" />
          <span>New thread</span>
          <span className="desktop-kbd" style={{ marginLeft: "auto" }}>
            {navigator.platform?.includes("Mac") ? "⌘" : "Ctrl"}+N
          </span>
        </button>
        <button className="desktop-sidebar-action" onClick={onScoped} disabled={busy}>
          <FolderOpen aria-hidden className="size-3.5" />
          <span>Choose target</span>
        </button>
      </div>
      <div className="desktop-sidebar-search">
        <div style={{ position: "relative" }}>
          <Search
            aria-hidden
            style={{
              position: "absolute",
              left: "6px",
              top: "50%",
              transform: "translateY(-50%)",
              width: "12px",
              height: "12px",
              color: "var(--desktop-sidebar-muted)",
              pointerEvents: "none",
            }}
          />
          <input
            className="desktop-sidebar-search-input"
            style={{ paddingLeft: "22px" }}
            placeholder="Filter threads…"
            value={threadSearch}
            onChange={(e) => onSearchChange(e.target.value)}
            aria-label="Filter threads"
          />
        </div>
      </div>
      <nav className="desktop-sidebar-threads" aria-label="Threads">
        {filtered.length === 0 ? (
          <p className="desktop-sidebar-empty">
            {threadSearch ? "No matching threads" : "No threads yet"}
          </p>
        ) : (
          filtered.map((session) => {
            const label = titles[session.id] || (session.target ? formatTarget(session.target) : "New thread");
            // First few chars of the active draft as a hint
            const draftPreview = activeId === session.id
              ? undefined
              : draftMap[session.id]?.slice(0, 32).trim();
            return (
              <button
                key={session.id}
                aria-current={session.id === activeId ? "page" : undefined}
                title={label}
                className={cn(
                  "desktop-thread-entry",
                  session.id === activeId && "desktop-thread-entry-active",
                )}
                onClick={() => onSelect(session.id)}
              >
                <span className="desktop-thread-entry-thumb">
                  <FileText aria-hidden className="size-3" />
                </span>
                <span className="desktop-thread-entry-info">
                  <span className="desktop-thread-entry-name">
                    {label}
                  </span>
                  <span className="desktop-thread-entry-meta">
                    {MODE_LABELS[session.autonomyMode]}
                    {draftPreview ? ` · ${draftPreview}…` : ""}
                  </span>
                </span>
              </button>
            );
          })
        )}
      </nav>
      <div className="desktop-sidebar-footer">
        <button className="desktop-sidebar-action" onClick={onSettings}>
          <Settings aria-hidden className="size-3.5" />
          <span>Settings</span>
          <span className="desktop-kbd" style={{ marginLeft: "auto" }}>
            {navigator.platform?.includes("Mac") ? "⌘" : "Ctrl"}+,
          </span>
        </button>
        <Link
          className="desktop-sidebar-action"
          to="/dashboard"
          style={{ textDecoration: "none" }}
        >
          <Sparkles aria-hidden className="size-3.5" />
          <span>Operations</span>
        </Link>
      </div>
    </aside>
  );
}

function DesktopDialog({ open, title, busy = false, onClose, children }: {
  open: boolean;
  title: string;
  busy?: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  const contentRef = useRef<HTMLDivElement>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);
  return (
    <Dialog open={open} onOpenChange={(next) => { if (!next && !busy) onClose(); }}>
      <DialogContent
        ref={contentRef}
        className="desktop-dialog"
        showCloseButton={false}
        aria-describedby={undefined}
        onOpenAutoFocus={(event) => {
          returnFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
          const input = contentRef.current?.querySelector<HTMLElement>("[data-initial-focus]");
          if (input) { event.preventDefault(); input.focus(); }
        }}
        onCloseAutoFocus={(event) => {
          event.preventDefault();
          const previous = returnFocusRef.current;
          if (previous?.isConnected && !previous.closest("[inert]")) previous.focus();
          else document.querySelector<HTMLTextAreaElement>('textarea[aria-label="Message 0sec"]')?.focus();
        }}
      >
        <div className="desktop-dialog-header">
          <DialogTitle className="desktop-dialog-title">{title}</DialogTitle>
          <button type="button" className="desktop-dialog-close" aria-label="Close" disabled={busy} onClick={onClose}>
            <X aria-hidden size={16} />
          </button>
        </div>
        {children}
      </DialogContent>
    </Dialog>
  );
}

/* ─── Scoped engagement dialog ─────────────────────────────────── */
function DesktopScopedDialog({ open, busy, onClose, onCreate, initialTarget, error }: {
  open: boolean;
  busy: boolean;
  onClose: () => void;
  onCreate: (input: { target: string; role: DesktopConsoleRole; autonomyMode: DesktopConsoleAutonomyMode }) => Promise<void>;
  initialTarget: string;
  error: string | null;
}) {
  const [target, setTarget] = useState(initialTarget);
  const [role, setRole] = useState<DesktopConsoleRole>("audit");
  const [mode, setMode] = useState<DesktopConsoleAutonomyMode>("standard");
  const [picking, setPicking] = useState(false);
  const [pickerError, setPickerError] = useState<string | null>(null);
  useEffect(() => {
    if (open) { setTarget(initialTarget); setPickerError(null); }
  }, [open, initialTarget]);

  const chooseDirectory = async () => {
    if (!window.osecDesktop || picking) return;
    setPicking(true);
    setPickerError(null);
    try {
      const selected = await window.osecDesktop.chooseDirectory();
      if (selected !== null) setTarget(selected);
    } catch (cause) {
      setPickerError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setPicking(false);
    }
  };

  return (
    <DesktopDialog open={open} title="New scoped thread" busy={busy || picking} onClose={onClose}>
      <form onSubmit={(event) => {
        event.preventDefault();
        if (!busy && !picking && target.trim()) void onCreate({ target: target.trim(), role, autonomyMode: mode });
      }}>
        <label className="desktop-field-label" htmlFor="engagement-target">Target or local path</label>
        <div className="desktop-target-field">
          <input
            data-initial-focus
            id="engagement-target"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="https://app.example.com or /path/to/project"
            className="desktop-field-input"
            disabled={busy || picking}
          />
          {window.osecDesktop && (
            <button type="button" className="desktop-btn" aria-label="Browse folder" disabled={busy || picking} onClick={() => void chooseDirectory()}>
              <FolderOpen aria-hidden size={16} />
            </button>
          )}
        </div>
        <div className="desktop-target-options">
          <label className="desktop-field-label">
            Role
            <select className="desktop-field-input" value={role} disabled={busy} onChange={(event) => setRole(event.target.value as DesktopConsoleRole)}>
              {(["audit", "review", "discovery", "attack", "verify", "report"] as const).map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </select>
          </label>
          <label className="desktop-field-label">
            Autonomy
            <select className="desktop-field-input" value={mode} disabled={busy} onChange={(event) => setMode(event.target.value as DesktopConsoleAutonomyMode)}>
              {(["standard", "recon", "copilot", "yolo"] as const).map((value) => (
                <option key={value} value={value}>{MODE_LABELS[value]}</option>
              ))}
            </select>
          </label>
        </div>
        <p className="desktop-field-hint">
          Choosing a folder sets context, not permission. Network and filesystem access remain subject to scope checks.
        </p>
        {(pickerError || error) && <p role="alert" className="desktop-entry-error">{pickerError || error}</p>}
        <div className="desktop-dialog-footer">
          <button type="button" className="desktop-btn" onClick={onClose} disabled={busy || picking}>Cancel</button>
          <button type="submit" className="desktop-btn desktop-btn-primary" disabled={busy || picking || !target.trim()}>Create thread</button>
        </div>
      </form>
    </DesktopDialog>
  );
}

/* ─── Settings dialog ──────────────────────────────────────────── */
function DesktopSettingsDialog({ open, onClose, auth, busy, onConnect, onCancelConnect }: {
  open: boolean;
  onClose: () => void;
  auth: DesktopCodexAuthStatus | null;
  busy: boolean;
  onConnect: () => Promise<void>;
  onCancelConnect: () => Promise<void>;
}) {
  const modifier = navigator.platform.includes("Mac") ? "⌘" : "Ctrl";
  return (
    <DesktopDialog open={open} title="Settings" onClose={onClose}>
      <dl className="desktop-inspector-dl">
        <div className="desktop-inspector-row">
          <dt className="desktop-inspector-dt">Appearance</dt>
          <dd className="desktop-inspector-dd">Follows system</dd>
        </div>
        <div className="desktop-inspector-row">
          <dt className="desktop-inspector-dt">Codex connection</dt>
          <dd className="desktop-inspector-dd">{auth?.phase === "connected" ? "ChatGPT Codex · Connected" : auth?.message || "Provider status unavailable"}</dd>
        </div>
      </dl>
      <DesktopCodexSection status={auth} busy={busy} onStart={onConnect} onCancel={onCancelConnect} />
      <p className="desktop-field-hint">{modifier}+N new thread · {modifier}+O open folder · {modifier}+B sidebar</p>
      <p className="desktop-field-hint">Development build. Threads stay available while the local sidecar is running; quitting ends this session history.</p>
      <div className="desktop-dialog-footer">
        <button type="button" className="desktop-btn" onClick={onClose}>Done</button>
      </div>
    </DesktopDialog>
  );
}

/* ─── Main ChatPage ────────────────────────────────────────────── */
export function ChatPage() {
  const [sessions, setSessions] = useState<DesktopConsoleSession[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [events, setEvents] = useState<DesktopConsoleEvent[]>([]);
  const visibleEvents = events[0]?.sessionId === activeId ? events : EMPTY_EVENTS;
  const [drafts, setDrafts] = usePersistentState<Record<string, string>>("0sec:drafts", {});
  const [threadTitles, setThreadTitles] = usePersistentState<Record<string, string>>("0sec:thread-titles", {});
  const draft = activeId ? drafts[activeId] ?? "" : "";
  const creatingRef = useRef(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [detailView, setDetailView] = useState<DetailView>("context");
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [scopedOpen, setScopedOpen] = useState(false);
  const [scopedTarget, setScopedTarget] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = usePersistentState("0sec:sidebar:collapsed", window.matchMedia("(max-width: 760px)").matches);
  const [threadSearch, setThreadSearch] = useState("");
  const [codexAuth, setCodexAuth] = useState<DesktopCodexAuthStatus | null>(null);
  const cursorRef = useRef(0);
  const transcriptScrollRef = useRef<HTMLDivElement>(null);
  const followOutputRef = useRef(true);
  const [showJumpToLatest, setShowJumpToLatest] = useState(false);
  const isNativeMacOS = window.osecDesktop?.platform === "darwin";

  const activeSession = sessions.find((session) => session.id === activeId) ?? null;

  const applySession = useCallback((session: DesktopConsoleSession) => {
    setSessions((current) => [session, ...current.filter((item) => item.id !== session.id)]);
  }, []);

  const createSession = useCallback(async (input: { target?: string; role?: DesktopConsoleRole; autonomyMode?: DesktopConsoleAutonomyMode } = {}) => {
    if (creatingRef.current) return;
    creatingRef.current = true;
    setSubmitting(true);
    setError(null);
    try {
      const session = await createDesktopConsoleSession(input);
      applySession(session);
      setActiveId(session.id);
      setScopedOpen(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSubmitting(false);
      creatingRef.current = false;
    }
  }, [applySession]);

  /* Initial session load */
  useEffect(() => {
    let active = true;
    void (async () => {
      try {
        const loaded = await getDesktopConsoleSessions();
        if (!active) return;
        setSessions((current) => {
          if (current.length === 0) return loaded;
          const known = new Set(current.map((session) => session.id));
          return [...current, ...loaded.filter((session) => !known.has(session.id))];
        });
        if (loaded[0]) setActiveId((current) => current ?? loaded[0].id);
        else await createSession();
      } catch (cause) {
        if (active) setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => { active = false; };
  }, [createSession]);

  /* Codex auth initial + polling */
  const refreshCodexAuth = useCallback(async () => {
    setCodexAuth(await getDesktopCodexAuthStatus());
  }, []);

  useEffect(() => { void refreshCodexAuth().catch(() => undefined); }, [refreshCodexAuth]);
  useEffect(() => {
    if (codexAuth?.phase !== "running") return;
    const timer = window.setInterval(() => void refreshCodexAuth().catch((cause: unknown) => setError(cause instanceof Error ? cause.message : String(cause))), 1_000);
    return () => clearInterval(timer);
  }, [codexAuth?.phase, refreshCodexAuth]);

  /* Event polling per active session */
  useEffect(() => {
    if (!activeId) {
      cursorRef.current = 0;
      setEvents([]);
      return;
    }
    let active = true;
    let timer: number | undefined;
    let polling = false;
    cursorRef.current = 0;
    followOutputRef.current = true;
    setShowJumpToLatest(false);
    setEvents([]);
    const poll = async () => {
      if (polling || !active) return;
      polling = true;
      try {
        const incoming = await getDesktopConsoleEvents(activeId, cursorRef.current);
        if (!active || incoming.length === 0) return;
        cursorRef.current = incoming.at(-1)?.sequence ?? cursorRef.current;
        setEvents((current) => mergeEvents(current, incoming));
        const firstMessage = incoming.find((event) => event.type === "user");
        if (firstMessage?.type === "user") {
          const title = firstMessage.text.trim().replace(/\s+/g, " ").slice(0, 80);
          setThreadTitles((current) => current[activeId] ? current : { ...current, [activeId]: title });
        }
        const updates = new Map<string, DesktopConsoleSession>();
        for (const event of incoming) {
          if (event.type === "session") updates.set(event.session.id, event.session);
        }
        if (updates.size > 0) setSessions((current) => current.map((session) => updates.get(session.id) ?? session));
      } catch (cause) {
        if (active) setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        polling = false;
        if (active) timer = window.setTimeout(() => void poll(), 300);
      }
    };
    void poll();
    return () => { active = false; clearTimeout(timer); };
  }, [activeId, setThreadTitles]);

  /* Pending decisions */
  const pendingDecisions = useMemo(() => {
    const pending = new Map<string, DesktopConsoleDecision>();
    for (const event of visibleEvents) {
      if (event.type === "decision") pending.set(event.decision.id, event.decision);
      if (event.type === "decision-resolved") pending.delete(event.decisionId);
    }
    return [...pending.values()];
  }, [visibleEvents]);

  useEffect(() => { if (pendingDecisions.length > 0) setInspectorOpen(true); }, [pendingDecisions.length]);

  const transcript = useMemo(() => buildTranscript(visibleEvents), [visibleEvents]);
  const activity = useMemo(() => visibleEvents.filter((event) => event.type !== "assistant-delta" && event.type !== "reasoning-delta" && event.type !== "user").slice(-18).reverse(), [visibleEvents]);
  const evidence = useMemo(() => visibleEvents.filter((event): event is Extract<DesktopConsoleEvent, { type: "tool-result" }> => event.type === "tool-result").slice().reverse(), [visibleEvents]);

  useLayoutEffect(() => {
    const viewport = transcriptScrollRef.current;
    if (viewport && followOutputRef.current) viewport.scrollTop = viewport.scrollHeight;
  }, [visibleEvents, inspectorOpen]);

  const jumpToLatest = () => {
    const viewport = transcriptScrollRef.current;
    if (!viewport) return;
    followOutputRef.current = true;
    setShowJumpToLatest(false);
    viewport.scrollTop = viewport.scrollHeight;
  };

  const handleDraftChange = useCallback((value: string) => {
    if (activeId) setDrafts((current) => ({ ...current, [activeId]: value }));
  }, [activeId, setDrafts]);

  const handleSessionSelect = useCallback((id: string) => {
    setActiveId(id);
    setThreadSearch("");
  }, []);

  const send = async () => {
    if (submitting || !activeSession || !draft.trim() || activeSession.status !== "ready") return;
    setSubmitting(true);
    setError(null);
    followOutputRef.current = true;
    setShowJumpToLatest(false);
    try {
      const updated = await sendDesktopConsoleMessage(activeSession.id, draft);
      applySession(updated);
      setDrafts((current) => {
        if (current[activeSession.id] !== draft) return current;
        const next = { ...current };
        delete next[activeSession.id];
        return next;
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSubmitting(false);
    }
  };

  const cancel = async () => {
    if (!activeSession) return;
    try {
      applySession(await cancelDesktopConsoleTurn(activeSession.id));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  };

  const resolveDecision = async (decision: DesktopConsoleDecision, response: DesktopConsoleDecisionResponse) => {
    if (!activeSession) return;
    setSubmitting(true);
    try {
      applySession(await resolveDesktopConsoleDecision(activeSession.id, decision.id, response));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSubmitting(false);
    }
  };

  const connectCodex = async () => {
    setSubmitting(true);
    setError(null);
    try { setCodexAuth(await startDesktopCodexDeviceAuth()); }
    catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setSubmitting(false); }
  };

  const cancelCodex = async () => {
    setSubmitting(true);
    try { setCodexAuth(await cancelDesktopCodexDeviceAuth()); }
    catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setSubmitting(false); }
  };

  const openFolder = useCallback(async () => {
    setError(null);
    setSettingsOpen(false);
    if (!window.osecDesktop) {
      setScopedTarget("");
      setScopedOpen(true);
      return;
    }
    try {
      const target = await window.osecDesktop.chooseDirectory();
      if (target !== null) {
        setScopedTarget(target);
        setScopedOpen(true);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, []);

  useKeyboardShortcuts((command: DesktopHostCommand) => {
    switch (command) {
      case "new-thread": setSettingsOpen(false); setScopedOpen(false); void createSession(); break;
      case "open-folder": void openFolder(); break;
      case "toggle-sidebar": setSidebarCollapsed((value) => !value); break;
      case "settings": setScopedOpen(false); setSettingsOpen(true); break;
    }
  });

  /* ─── Empty state: NO user messages yet ──────────────────── */
  if (loading) {
    return (
      <div className="desktop-layout desktop-loading">
        <p className="desktop-loading-text" role="status">Opening your workspace…</p>
      </div>
    );
  }

  const isEmpty = transcript.length === 0;
  const working = activeSession?.status === "working" || activeSession?.status === "waiting";
  const composerDisabled = submitting || !activeSession || activeSession.status === "closed" || activeSession.status === "failed";
  let workingLabel = "Working on your request";
  for (let index = visibleEvents.length - 1; index >= 0; index--) {
    const event = visibleEvents[index];
    if (event.type === "assistant-delta") {
      workingLabel = "Writing a response";
      break;
    }
    if (event.type === "tool-start") {
      workingLabel = `Running ${event.call.name}`;
      break;
    }
    if (event.type === "user" || event.type === "reasoning-delta" || event.type === "tool-result") break;
  }
  if (pendingDecisions.length > 0) workingLabel = "Waiting for your approval";

  const threadLabel = (activeId && threadTitles[activeId]) ||
    (activeSession?.target ? formatTarget(activeSession.target) : "New thread");

  return (
    <div className={cn("desktop-layout", isNativeMacOS && "desktop-native-macos")}>
      {!sidebarCollapsed && <button type="button" className="desktop-sidebar-backdrop" aria-label="Close sidebar" onClick={() => setSidebarCollapsed(true)} />}
      <DesktopSidebar
        sessions={sessions}
        activeId={activeId}
        collapsed={sidebarCollapsed}
        draftMap={drafts}
        titles={threadTitles}
        busy={submitting}
        threadSearch={threadSearch}
        onToggle={() => setSidebarCollapsed((v) => !v)}
        onSelect={handleSessionSelect}
        onNew={() => void createSession()}
        onScoped={() => { setError(null); setScopedTarget(""); setScopedOpen(true); }}
        onSettings={() => setSettingsOpen(true)}
        onSearchChange={setThreadSearch}
      />

      <div className="desktop-main">
        {/* ── Titlebar ── */}
        <div className="desktop-titlebar">
          <div className="desktop-titlebar-section">
            {sidebarCollapsed && (
              <button
                className="desktop-btn-icon"
                aria-label="Show sidebar"
                onClick={() => setSidebarCollapsed(false)}
              >
                <PanelLeft aria-hidden className="size-3.5" />
              </button>
            )}
              <span className="desktop-titlebar-label">
                {threadLabel}
              </span>
          </div>
          <div className="desktop-titlebar-actions">
            <button
              className="desktop-titlebar-button"
              onClick={() => { setDetailView("context"); setInspectorOpen((v) => !v); }}
              title="Toggle inspector"
              aria-label="Toggle inspector"
              aria-expanded={inspectorOpen}
            >
              <FileText aria-hidden className="size-3.5" />
              {pendingDecisions.length > 0 && (
                <span style={{
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  background: "var(--desktop-accent)",
                  color: "#fff",
                  fontSize: "9px",
                  fontWeight: 600,
                  borderRadius: "8px",
                  padding: "0 5px",
                  height: "14px",
                  minWidth: "14px",
                  lineHeight: 1,
                }}>{pendingDecisions.length}</span>
              )}
            </button>
            <button
              className="desktop-titlebar-button"
              onClick={() => void createSession()}
              title="New thread"
              aria-label="New thread"
              disabled={submitting}
            >
              <Plus aria-hidden className="size-3.5" />
              <span className="hidden sm:inline">New</span>
            </button>
            <Link
              className="desktop-titlebar-button"
              to="/dashboard"
              aria-label="Open Operations"
              style={{ textDecoration: "none" }}
            >
              <Sparkles aria-hidden className="size-3.5" />
            </Link>
          </div>
        </div>

        {/* ── Content ── */}
        {isEmpty ? (
          <div className="desktop-empty">
            <div className="desktop-empty-inner">
              <h1>New thread</h1>
              <p className="desktop-empty-desc">Choose a target, or start with a question.</p>
            </div>
          </div>
        ) : (
            <div className="desktop-transcript">
              <div
                ref={transcriptScrollRef}
                className="desktop-transcript-scroll"
                onScroll={(event) => {
                  const viewport = event.currentTarget;
                  const following = viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight < 80;
                  followOutputRef.current = following;
                  setShowJumpToLatest(!following);
                }}
              >
                <div className="desktop-transcript-inner" aria-label="Conversation">
                  {transcript.map((entry, index) => {
                    if (entry.kind === "tool") {
                      return (
                        <details key={entry.id} className="desktop-tool-entry">
                          <summary className="desktop-tool-summary">
                            {entry.status === "running" ? (
                              <LoaderCircle aria-hidden className="size-3.5 desktop-spinner" />
                            ) : entry.status === "complete" ? (
                              <Check aria-hidden className="size-3.5" />
                            ) : (
                              <Square aria-hidden className="size-3" />
                            )}
                            <span className="desktop-tool-name">{entry.name}</span>
                            <span className="desktop-tool-status">
                              {entry.status === "complete" ? "Finished" : entry.status === "running" ? "Running" : "Interrupted"}
                            </span>
                            <ChevronRight aria-hidden className="size-3.5 desktop-tool-chevron" />
                          </summary>
                          <div className="desktop-tool-body">
                            <div>
                              <p className="desktop-tool-section-label">Input</p>
                              <pre className="desktop-tool-payload">{formatPayload(entry.arguments)}</pre>
                            </div>
                            {entry.status === "complete" ? (
                              <div>
                                <p className="desktop-tool-section-label">Result</p>
                                <pre className="desktop-tool-payload">{formatPayload(entry.result)}</pre>
                              </div>
                            ) : null}
                          </div>
                        </details>
                      );
                    }
                    if (entry.kind === "notice") {
                      return <p key={entry.id} className="desktop-entry-notice">{entry.text}</p>;
                    }
                    if (entry.kind === "error") {
                      return (
                        <p key={entry.id} role="alert" className="desktop-entry-error">
                          {entry.text}
                        </p>
                      );
                    }
                    if (entry.kind === "user") {
                      return (
                        <article key={entry.id} className="desktop-entry-user">
                          <span className="sr-only">You</span>
                          <p className="desktop-entry-user-text">{entry.text}</p>
                        </article>
                      );
                    }
                    return (
                      <article key={entry.id} className="desktop-entry-assistant">
                        <p className="desktop-entry-assistant-label">0sec</p>
                        <ChatMessage
                          text={entry.text}
                          streaming={activeSession?.status === "working" && index === transcript.length - 1}
                        />
                      </article>
                    );
                  })}
                </div>
              </div>
              {showJumpToLatest && (
                <button
                  type="button"
                  className="desktop-jump-btn"
                  onClick={jumpToLatest}
                >
                  <ArrowDown aria-hidden className="size-3.5" />
                  Latest response
                </button>
              )}
            </div>

        )}
            {/* ── Composer ── */}
            <div className="desktop-composer-area">
              <div role="status" aria-live="polite" className="desktop-composer-status">
                {working ? (
                  <><LoaderCircle aria-hidden className="size-3.5 desktop-spinner" /><span>{workingLabel}</span></>
                ) : (
                  <span>{activeSession?.status === "ready" ? (activeSession.target ? formatTarget(activeSession.target) : "Local · No target selected") : activeSession?.status}</span>
                )}
                {activeSession && (
                  <span style={{ marginLeft: "auto", fontSize: "10px", color: "var(--desktop-muted)" }}>
                    {MODE_LABELS[activeSession.autonomyMode]}
                  </span>
                )}
              </div>
              <DesktopComposer
                value={draft}
                disabled={Boolean(composerDisabled)}
                working={working}
                onChange={handleDraftChange}
                onSubmit={() => void send()}
                onCancel={() => void cancel()}
              />
              {error ? (
                <p role="alert" className="mt-2" style={{ fontSize: "12px", color: "var(--desktop-danger)" }}>
                  {error}
                </p>
              ) : null}
            </div>
      </div>

      <DesktopInspector
        open={inspectorOpen}
        view={detailView}
        session={activeSession}
        pending={pendingDecisions}
        activity={activity}
        evidence={evidence}
        auth={codexAuth}
        busy={submitting}
        onClose={() => setInspectorOpen(false)}
        onView={setDetailView}
        onResolve={resolveDecision}
        onConnect={connectCodex}
        onCancelConnect={cancelCodex}
      />

      <DesktopScopedDialog
        open={scopedOpen}
        busy={submitting}
        onClose={() => setScopedOpen(false)}
        onCreate={createSession}
        initialTarget={scopedTarget}
        error={error}
      />

      <DesktopSettingsDialog
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        auth={codexAuth}
        busy={submitting}
        onConnect={connectCodex}
        onCancelConnect={cancelCodex}
      />
    </div>
  );
}