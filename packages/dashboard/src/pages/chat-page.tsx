import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
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

type DetailView = "context" | "activity" | "evidence";

type TranscriptEntry =
  | { id: string; kind: "user" | "assistant" | "notice" | "error"; text: string }
  | { id: string; kind: "tool"; name: string; arguments: unknown; result?: unknown };

const MODE_LABELS: Record<DesktopConsoleAutonomyMode, string> = {
  standard: "standard",
  recon: "recon",
  copilot: "co-pilot",
  yolo: "yolo",
};

const RAIL_BUTTON = "border border-[#f7f5f2]/12 px-2.5 py-1.5 text-[11px] text-[#b6b2ad] transition hover:border-[#f7f5f2]/30 hover:text-[#f7f5f2] disabled:cursor-not-allowed disabled:opacity-45";
const ACTION_BUTTON = "border border-[#dc2626] bg-[#dc2626] px-3 py-1.5 text-[11px] font-medium text-white transition hover:bg-[#ef4444] disabled:cursor-not-allowed disabled:opacity-45";

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
  for (const event of events) {
    if (event.type === "user") {
      entries.push({ id: `user-${event.sequence}`, kind: "user", text: event.text });
      continue;
    }
    if (event.type === "assistant-delta") {
      const last = entries.at(-1);
      if (last?.kind === "assistant") last.text += event.text;
      else entries.push({ id: `assistant-${event.sequence}`, kind: "assistant", text: event.text });
      continue;
    }
    if (event.type === "tool-start") {
      entries.push({ id: `tool-${event.sequence}`, kind: "tool", name: event.call.name, arguments: event.call.arguments });
      continue;
    }
    if (event.type === "tool-result") {
      const prior = [...entries].reverse().find((entry): entry is Extract<TranscriptEntry, { kind: "tool" }> => entry.kind === "tool" && entry.name === event.call.name && entry.result === undefined);
      if (prior) prior.result = event.result;
      else entries.push({ id: `tool-${event.sequence}`, kind: "tool", name: event.call.name, arguments: event.call.arguments, result: event.result });
      continue;
    }
    if (event.type === "turn-complete") {
      const last = entries.at(-1);
      if (!event.assistantText) continue;
      if (last?.kind === "assistant" && event.assistantText.startsWith(last.text)) last.text = event.assistantText;
      else if (last?.kind !== "assistant" || last.text !== event.assistantText) entries.push({ id: `assistant-final-${event.sequence}`, kind: "assistant", text: event.assistantText });
      continue;
    }
    if (event.type === "notice") entries.push({ id: `notice-${event.sequence}`, kind: "notice", text: event.text });
    if (event.type === "error") entries.push({ id: `error-${event.sequence}`, kind: "error", text: event.message });
  }
  return entries;
}

function mergeEvents(current: readonly DesktopConsoleEvent[], incoming: readonly DesktopConsoleEvent[]): DesktopConsoleEvent[] {
  if (incoming.length === 0) return [...current];
  const known = new Set(current.map((event) => event.sequence));
  return [...current, ...incoming.filter((event) => !known.has(event.sequence))];
}

function Wordmark() {
  return (
    <div className="flex items-center gap-2 text-[13px] font-medium tracking-[-0.03em] text-[#f7f5f2]">
      <span className="relative grid size-4 place-items-center border border-[#f7f5f2]/80 text-[10px] leading-none">
        0
        <span aria-hidden className="absolute h-px w-[1.3rem] rotate-[-55deg] bg-[#dc2626]" />
      </span>
      <span>0sec</span>
    </div>
  );
}

function HeaderButton({ children, active = false, onClick }: { children: ReactNode; active?: boolean; onClick?: () => void }) {
  return <button type="button" onClick={onClick} className={cn("px-2 py-1 text-[11px] transition", active ? "text-[#f7f5f2]" : "text-[#8d8984] hover:text-[#f7f5f2]")}>{children}</button>;
}

function Transcript({ entries, endRef }: { entries: readonly TranscriptEntry[]; endRef: React.RefObject<HTMLDivElement | null> }) {
  if (entries.length === 0) return null;
  return (
    <div className="mx-auto flex w-full max-w-[44rem] flex-col gap-6 px-5 pb-8 pt-10 sm:px-8">
      {entries.map((entry) => {
        if (entry.kind === "tool") {
          const complete = entry.result !== undefined;
          return (
            <article key={entry.id} className="border-l border-[#f7f5f2]/18 pl-3">
              <div className="flex items-center gap-2 text-[11px]"><span className="text-[#8d8984]">tool</span><span className="font-mono text-[#f7f5f2]">{entry.name}</span><span className={complete ? "text-[#8fb996]" : "text-[#d7b56d]"}>{complete ? "complete" : "running"}</span></div>
              <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap text-[11px] leading-5 text-[#a7a29c]">{formatPayload(complete ? entry.result : entry.arguments)}</pre>
            </article>
          );
        }
        if (entry.kind === "notice") return <p key={entry.id} className="text-center text-[11px] text-[#8d8984]">{entry.text}</p>;
        if (entry.kind === "error") return <p key={entry.id} className="border-l border-[#dc2626] pl-3 text-sm leading-6 text-[#f18181]">{entry.text}</p>;
        if (entry.kind === "user") {
          return <article key={entry.id} className="border-l border-[#f7f5f2]/28 pl-3"><p className="mb-2 text-[11px] text-[#8d8984]">you</p><p className="whitespace-pre-wrap text-sm leading-7 text-[#f7f5f2]">{entry.text}</p></article>;
        }
        return <article key={entry.id}><p className="mb-2 text-[11px] text-[#dc2626]">0sec</p><p className="whitespace-pre-wrap text-sm leading-7 text-[#e4e0dc]">{entry.text}</p></article>;
      })}
      <div ref={endRef} />
    </div>
  );
}

function Composer({
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
  return (
    <form
      className="border border-[#f7f5f2]/18 bg-transparent"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit();
      }}
    >
      <textarea
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter" && !event.shiftKey) {
            event.preventDefault();
            onSubmit();
          }
        }}
        placeholder={working ? "0sec is working…" : "Ask 0sec to investigate…"}
        className="min-h-24 w-full resize-none bg-transparent px-4 py-3 text-sm leading-6 text-[#f7f5f2] outline-none placeholder:text-[#726f6b] disabled:cursor-not-allowed"
      />
      <div className="flex items-center justify-between border-t border-[#f7f5f2]/10 px-3 py-2">
        <p className="text-[10px] text-[#726f6b]">enter to send · shift+enter for newline</p>
        {working ? <button type="button" className={RAIL_BUTTON} onClick={onCancel}>stop</button> : <button type="submit" className={ACTION_BUTTON} disabled={disabled || !value.trim()}>send</button>}
      </div>
    </form>
  );
}

function DecisionPanel({ decision, busy, onResolve }: { decision: DesktopConsoleDecision; busy: boolean; onResolve: (response: DesktopConsoleDecisionResponse) => Promise<void> }) {
  const [answers, setAnswers] = useState<Record<string, DesktopConsoleOperatorAnswer>>({});
  const respond = (approve: boolean) => {
    const response: DesktopConsoleDecisionResponse = decision.kind === "operator-question"
      ? { approve, answers: decision.questions?.map((question) => answers[question.header] ?? { header: question.header }) ?? [] }
      : { approve };
    void onResolve(response);
  };

  return (
    <section className="border border-[#d7b56d]/35 p-4">
      <p className="text-[11px] text-[#d7b56d]">approval required</p>
      <h2 className="mt-2 text-sm font-medium text-[#f7f5f2]">{decision.title}</h2>
      <p className="mt-2 text-xs leading-5 text-[#aaa59f]">{decision.detail}</p>
      {decision.call ? <pre className="mt-3 max-h-36 overflow-auto border-l border-[#f7f5f2]/18 pl-3 text-[11px] leading-5 text-[#aaa59f]">{decision.call.name} {formatPayload(decision.call.arguments)}</pre> : null}
      {decision.requestedUrls?.map((url) => <p className="mt-2 break-all font-mono text-[11px] text-[#d7b56d]" key={url}>{url}</p>)}
      {decision.requestedPath ? <p className="mt-2 break-all font-mono text-[11px] text-[#d7b56d]">{decision.requestedPath}</p> : null}
      {decision.questions?.map((question) => {
        const answer = answers[question.header] ?? { header: question.header };
        return (
          <div className="mt-4 border-t border-[#f7f5f2]/10 pt-3" key={question.header}>
            <p className="text-xs text-[#f7f5f2]">{question.header}</p>
            <p className="mt-1 text-xs leading-5 text-[#aaa59f]">{question.question}</p>
            {question.options?.length ? <div className="mt-3 flex flex-wrap gap-2">{question.options.map((option) => {
              const selected = answer.selectedLabels?.includes(option.label) ?? false;
              return <button
                type="button"
                key={option.label}
                onClick={() => setAnswers((current) => {
                  const prior = current[question.header] ?? { header: question.header };
                  const labels = new Set(prior.selectedLabels ?? []);
                  if (labels.has(option.label)) labels.delete(option.label);
                  else if (question.multiSelect) labels.add(option.label);
                  else {
                    labels.clear();
                    labels.add(option.label);
                  }
                  return { ...current, [question.header]: { ...prior, selectedLabels: [...labels] } };
                })}
                className={cn(RAIL_BUTTON, selected && "border-[#d7b56d]/60 text-[#f7f5f2]")}
              >{option.label}</button>;
            })}</div> : null}
            {question.allowCustom ? <input value={answer.customText ?? ""} onChange={(event) => setAnswers((current) => ({ ...current, [question.header]: { ...answer, customText: event.target.value } }))} className="mt-3 h-8 w-full border border-[#f7f5f2]/12 bg-transparent px-2 text-xs text-[#f7f5f2] outline-none" placeholder="optional context" /> : null}
          </div>
        );
      })}
      <div className="mt-4 flex justify-end gap-2"><button type="button" className={RAIL_BUTTON} disabled={busy} onClick={() => respond(false)}>decline</button><button type="button" className={ACTION_BUTTON} disabled={busy} onClick={() => respond(true)}>{decision.kind === "operator-question" ? "submit" : "approve"}</button></div>
    </section>
  );
}

function CodexConnection({ status, busy, onStart, onCancel }: { status: DesktopCodexAuthStatus | null; busy: boolean; onStart: () => Promise<void>; onCancel: () => Promise<void> }) {
  if (!status || status.phase === "connected") return null;
  const running = status.phase === "running";
  return (
    <section className="border-t border-[#f7f5f2]/10 pt-4">
      <p className="text-xs text-[#f7f5f2]">ChatGPT Codex</p>
      <p className="mt-1 text-[11px] leading-5 text-[#8d8984]">Device sign-in stays in the local daemon. Credentials never enter this window.</p>
      {status.lines.length > 0 ? <pre className="mt-3 max-h-28 overflow-auto text-[11px] leading-5 text-[#aaa59f]">{status.lines.join("\n")}</pre> : null}
      {status.phase === "failed" ? <p className="mt-2 text-[11px] text-[#f18181]">{status.message}</p> : null}
      <div className="mt-3">{running ? <button className={RAIL_BUTTON} disabled={busy} onClick={() => void onCancel()}>cancel sign-in</button> : <button className={RAIL_BUTTON} disabled={busy} onClick={() => void onStart()}>connect Codex</button>}</div>
    </section>
  );
}

function Details({
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
  if (!open) return null;
  return (
    <aside className="absolute inset-y-0 right-0 z-20 w-full max-w-sm overflow-y-auto border-l border-[#f7f5f2]/12 bg-[#0a0a0a] px-5 py-4 sm:w-[22rem]">
      <div className="flex items-center justify-between"><p className="text-[11px] text-[#f7f5f2]">details</p><button className="text-[11px] text-[#8d8984] hover:text-[#f7f5f2]" onClick={onClose}>close</button></div>
      <div className="mt-5 flex gap-4 border-b border-[#f7f5f2]/10 pb-2">{(["context", "activity", "evidence"] as const).map((tab) => <HeaderButton key={tab} active={view === tab} onClick={() => onView(tab)}>{tab}</HeaderButton>)}</div>
      <div className="mt-5 space-y-5">
        {pending.map((decision) => <DecisionPanel key={decision.id} decision={decision} busy={busy} onResolve={(response) => onResolve(decision, response)} />)}
        {view === "context" ? <>
          <dl className="space-y-4 text-xs"><div><dt className="text-[#8d8984]">target</dt><dd className="mt-1 break-all font-mono text-[#e4e0dc]">{session?.target || "not set"}</dd></div><div className="flex justify-between"><dt className="text-[#8d8984]">mode</dt><dd className="text-[#e4e0dc]">{session ? MODE_LABELS[session.autonomyMode] : "standard"}</dd></div><div className="flex justify-between"><dt className="text-[#8d8984]">approvals</dt><dd className="text-[#e4e0dc]">{pending.length}</dd></div></dl>
          <CodexConnection status={auth} busy={busy} onStart={onConnect} onCancel={onCancelConnect} />
        </> : null}
        {view === "activity" ? (activity.length === 0 ? <p className="text-xs leading-5 text-[#8d8984]">Activity appears when a turn begins, a tool runs, or an approval is needed.</p> : activity.map((event) => <div key={event.sequence} className="border-l border-[#f7f5f2]/15 pl-3"><p className="text-xs text-[#e4e0dc]">{eventLabel(event)}</p><p className="mt-1 text-[10px] text-[#726f6b]">{new Date(event.occurredAt).toLocaleTimeString()}</p></div>)) : null}
        {view === "evidence" ? (evidence.length === 0 ? <p className="text-xs leading-5 text-[#8d8984]">Evidence-producing tool results appear here. Findings remain in the Findings route.</p> : evidence.map((event) => <article key={event.sequence} className="border-l border-[#f7f5f2]/15 pl-3"><p className="font-mono text-[11px] text-[#e4e0dc]">{event.call.name}</p><pre className="mt-2 max-h-40 overflow-auto text-[11px] leading-5 text-[#aaa59f]">{formatPayload(event.result)}</pre></article>)) : null}
      </div>
    </aside>
  );
}

function SessionPanel({ sessions, activeId, open, onClose, onSelect, onNew, onScoped }: { sessions: readonly DesktopConsoleSession[]; activeId: string | null; open: boolean; onClose: () => void; onSelect: (id: string) => void; onNew: () => void; onScoped: () => void }) {
  if (!open) return null;
  return (
    <aside className="absolute inset-y-0 left-0 z-20 w-full max-w-sm overflow-y-auto border-r border-[#f7f5f2]/12 bg-[#0a0a0a] px-5 py-4 sm:w-[22rem]">
      <div className="flex items-center justify-between"><Wordmark /><button className="text-[11px] text-[#8d8984] hover:text-[#f7f5f2]" onClick={onClose}>close</button></div>
      <div className="mt-6 flex gap-2"><button className={ACTION_BUTTON} onClick={onNew}>new chat</button><button className={RAIL_BUTTON} onClick={onScoped}>new scoped engagement</button></div>
      <div className="mt-6 border-t border-[#f7f5f2]/10 pt-4">
        <p className="mb-3 text-[10px] tracking-[0.12em] text-[#726f6b] uppercase">live sessions</p>
        {sessions.length === 0 ? <p className="text-xs leading-5 text-[#8d8984]">No live sessions.</p> : sessions.map((session) => <button key={session.id} type="button" onClick={() => { onSelect(session.id); onClose(); }} className={cn("block w-full border-l px-3 py-2 text-left", session.id === activeId ? "border-[#dc2626] bg-[#f7f5f2]/[0.03]" : "border-transparent hover:border-[#f7f5f2]/25")}><p className="truncate text-xs text-[#e4e0dc]">{formatTarget(session.target)}</p><p className="mt-1 text-[10px] text-[#726f6b]">{MODE_LABELS[session.autonomyMode]} · {session.status}</p></button>)}
      </div>
    </aside>
  );
}

function ScopedEngagement({ open, busy, onClose, onCreate }: { open: boolean; busy: boolean; onClose: () => void; onCreate: (input: { target: string; role: DesktopConsoleRole; autonomyMode: DesktopConsoleAutonomyMode }) => Promise<void> }) {
  const [target, setTarget] = useState("");
  const [role, setRole] = useState<DesktopConsoleRole>("audit");
  const [mode, setMode] = useState<DesktopConsoleAutonomyMode>("standard");
  if (!open) return null;
  return (
    <div className="absolute inset-0 z-30 grid place-items-center bg-black/70 p-5">
      <form className="w-full max-w-md border border-[#f7f5f2]/20 bg-[#0a0a0a] p-5" onSubmit={(event) => { event.preventDefault(); void onCreate({ target, role, autonomyMode: mode }); }}>
        <div className="flex items-center justify-between"><p className="text-sm text-[#f7f5f2]">new scoped engagement</p><button type="button" className="text-[11px] text-[#8d8984] hover:text-[#f7f5f2]" onClick={onClose}>close</button></div>
        <label className="mt-5 block text-[10px] tracking-[0.12em] text-[#726f6b] uppercase" htmlFor="engagement-target">target or local path</label>
        <input id="engagement-target" autoFocus value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://app.example.com or /workspace/repository" className="mt-2 h-10 w-full border border-[#f7f5f2]/15 bg-transparent px-3 text-sm text-[#f7f5f2] outline-none placeholder:text-[#726f6b]" />
        <div className="mt-5 grid grid-cols-2 gap-5"><fieldset><legend className="text-[10px] tracking-[0.12em] text-[#726f6b] uppercase">role</legend><div className="mt-2 flex flex-wrap gap-2">{(["audit", "review", "discovery"] as const).map((candidate) => <button key={candidate} type="button" className={cn(RAIL_BUTTON, role === candidate && "border-[#f7f5f2]/50 text-[#f7f5f2]")} onClick={() => setRole(candidate)}>{candidate}</button>)}</div></fieldset><fieldset><legend className="text-[10px] tracking-[0.12em] text-[#726f6b] uppercase">autonomy</legend><div className="mt-2 flex flex-wrap gap-2">{(["standard", "recon", "copilot", "yolo"] as const).map((candidate) => <button key={candidate} type="button" className={cn(RAIL_BUTTON, mode === candidate && "border-[#f7f5f2]/50 text-[#f7f5f2]")} onClick={() => setMode(candidate)}>{MODE_LABELS[candidate]}</button>)}</div></fieldset></div>
        <p className="mt-5 text-[11px] leading-5 text-[#8d8984]">Standard mode asks before effectful tools. Network and filesystem scope remain session-only.</p>
        <div className="mt-5 flex justify-end"><button className={ACTION_BUTTON} disabled={busy}>start engagement</button></div>
      </form>
    </div>
  );
}

export function ChatPage() {
  const [sessions, setSessions] = useState<DesktopConsoleSession[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [events, setEvents] = useState<DesktopConsoleEvent[]>([]);
  const [draft, setDraft] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [sessionsOpen, setSessionsOpen] = useState(false);
  const [scopedOpen, setScopedOpen] = useState(false);
  const [detailView, setDetailView] = useState<DetailView>("context");
  const [codexAuth, setCodexAuth] = useState<DesktopCodexAuthStatus | null>(null);
  const cursorRef = useRef(0);
  const transcriptEndRef = useRef<HTMLDivElement>(null);

  const activeSession = sessions.find((session) => session.id === activeId) ?? null;

  const applySession = useCallback((session: DesktopConsoleSession) => {
    setSessions((current) => [session, ...current.filter((item) => item.id !== session.id)]);
    setActiveId(session.id);
  }, []);

  const createSession = useCallback(async (input: { target?: string; role?: DesktopConsoleRole; autonomyMode?: DesktopConsoleAutonomyMode } = {}) => {
    setSubmitting(true);
    setError(null);
    try {
      const session = await createDesktopConsoleSession(input);
      applySession(session);
      setScopedOpen(false);
      setSessionsOpen(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSubmitting(false);
    }
  }, [applySession]);

  useEffect(() => {
    let active = true;
    void (async () => {
      try {
        const loaded = await getDesktopConsoleSessions();
        if (!active) return;
        setSessions(loaded);
        if (loaded[0]) setActiveId(loaded[0].id);
        else await createSession();
      } catch (cause) {
        if (active) setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => { active = false; };
  }, [createSession]);

  const refreshCodexAuth = useCallback(async () => {
    setCodexAuth(await getDesktopCodexAuthStatus());
  }, []);

  useEffect(() => { void refreshCodexAuth().catch(() => undefined); }, [refreshCodexAuth]);
  useEffect(() => {
    if (codexAuth?.phase !== "running") return;
    const timer = window.setInterval(() => void refreshCodexAuth().catch((cause: unknown) => setError(cause instanceof Error ? cause.message : String(cause))), 1_000);
    return () => clearInterval(timer);
  }, [codexAuth?.phase, refreshCodexAuth]);

  useEffect(() => {
    if (!activeId) {
      cursorRef.current = 0;
      setEvents([]);
      return;
    }
    let active = true;
    let timer: ReturnType<typeof window.setTimeout> | undefined;
    let polling = false;
    cursorRef.current = 0;
    setEvents([]);
    const poll = async () => {
      if (polling || !active) return;
      polling = true;
      try {
        const incoming = await getDesktopConsoleEvents(activeId, cursorRef.current);
        if (!active || incoming.length === 0) return;
        cursorRef.current = incoming.at(-1)?.sequence ?? cursorRef.current;
        setEvents((current) => mergeEvents(current, incoming));
        const updates = incoming.filter((event): event is Extract<DesktopConsoleEvent, { type: "session" }> => event.type === "session");
        if (updates.length > 0) setSessions((current) => current.map((session) => updates.find((event) => event.session.id === session.id)?.session ?? session));
      } catch (cause) {
        if (active) setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        polling = false;
        if (active) timer = window.setTimeout(() => void poll(), 300);
      }
    };
    void poll();
    return () => { active = false; clearTimeout(timer); };
  }, [activeId]);

  const pendingDecisions = useMemo(() => {
    const pending = new Map<string, DesktopConsoleDecision>();
    for (const event of events) {
      if (event.type === "decision") pending.set(event.decision.id, event.decision);
      if (event.type === "decision-resolved") pending.delete(event.decisionId);
    }
    return [...pending.values()];
  }, [events]);

  useEffect(() => { if (pendingDecisions.length > 0) setDetailsOpen(true); }, [pendingDecisions.length]);

  const transcript = useMemo(() => buildTranscript(events), [events]);
  const activity = useMemo(() => events.filter((event) => event.type !== "assistant-delta" && event.type !== "user").slice(-18).reverse(), [events]);
  const evidence = useMemo(() => events.filter((event): event is Extract<DesktopConsoleEvent, { type: "tool-result" }> => event.type === "tool-result").slice().reverse(), [events]);

  useEffect(() => { transcriptEndRef.current?.scrollIntoView({ block: "end" }); }, [transcript.length]);

  const send = async () => {
    if (!activeSession || !draft.trim() || activeSession.status !== "ready") return;
    setSubmitting(true);
    setError(null);
    try {
      const updated = await sendDesktopConsoleMessage(activeSession.id, draft);
      applySession(updated);
      setDraft("");
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

  if (loading) return <main className="grid min-h-screen place-items-center bg-[#0a0a0a] text-[11px] text-[#8d8984]">opening 0sec…</main>;

  const isEmpty = transcript.length === 0;
  const working = activeSession?.status === "working";
  return (
    <main className="relative flex h-screen min-h-[38rem] overflow-hidden bg-[#0a0a0a] font-sans text-[#f7f5f2]">
      <section className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 shrink-0 items-center justify-between border-b border-[#f7f5f2]/10 px-4 sm:px-6">
          <div className="flex min-w-0 items-center gap-5"><Wordmark /><div className="hidden min-w-0 items-center gap-3 text-[11px] text-[#8d8984] sm:flex"><span className="truncate">{activeSession ? formatTarget(activeSession.target) : "target: not set"}</span><span>scope: {activeSession?.scopeConfigured ? "set" : "on demand"}</span><span>{activeSession ? MODE_LABELS[activeSession.autonomyMode] : "standard"}</span></div></div>
          <div className="flex items-center gap-1"><HeaderButton onClick={() => setSessionsOpen(true)}>sessions {sessions.length}</HeaderButton><HeaderButton onClick={() => { setDetailView("context"); setDetailsOpen(true); }}>context</HeaderButton><HeaderButton onClick={() => void createSession()} >new</HeaderButton><Link className="px-2 py-1 text-[11px] text-[#8d8984] transition hover:text-[#f7f5f2]" to="/dashboard">operations</Link></div>
        </header>
        {isEmpty ? <div className="flex min-h-0 flex-1 flex-col items-center justify-center px-5 pb-16"><div className="w-full max-w-[34rem]"><div className="mb-8 text-center"><p className="text-[10px] tracking-[0.18em] text-[#726f6b] uppercase">0sec · operator console</p><h1 className="mt-3 text-2xl font-medium tracking-[-0.035em] text-[#f7f5f2]">What are we looking at?</h1><p className="mx-auto mt-3 max-w-sm text-xs leading-5 text-[#8d8984]">Start with the outcome you need. Scope and approval stay explicit when the work reaches a boundary.</p></div><Composer value={draft} disabled={submitting || activeSession?.status !== "ready"} working={Boolean(working)} onChange={setDraft} onSubmit={() => void send()} onCancel={() => void cancel()} />{error ? <p className="mt-3 text-center text-[11px] text-[#f18181]">{error}</p> : null}</div></div> : <><div className="min-h-0 flex-1 overflow-y-auto"><Transcript entries={transcript} endRef={transcriptEndRef} /></div><div className="mx-auto w-full max-w-[44rem] px-5 pb-5 sm:px-8"><Composer value={draft} disabled={submitting || activeSession?.status !== "ready"} working={Boolean(working)} onChange={setDraft} onSubmit={() => void send()} onCancel={() => void cancel()} />{error ? <p className="mt-3 text-[11px] text-[#f18181]">{error}</p> : null}</div></>}
      </section>
      <Details open={detailsOpen} view={detailView} session={activeSession} pending={pendingDecisions} activity={activity} evidence={evidence} auth={codexAuth} busy={submitting} onClose={() => setDetailsOpen(false)} onView={setDetailView} onResolve={resolveDecision} onConnect={connectCodex} onCancelConnect={cancelCodex} />
      <SessionPanel sessions={sessions} activeId={activeId} open={sessionsOpen} onClose={() => setSessionsOpen(false)} onSelect={setActiveId} onNew={() => void createSession()} onScoped={() => { setSessionsOpen(false); setScopedOpen(true); }} />
      <ScopedEngagement open={scopedOpen} busy={submitting} onClose={() => setScopedOpen(false)} onCreate={createSession} />
    </main>
  );
}
