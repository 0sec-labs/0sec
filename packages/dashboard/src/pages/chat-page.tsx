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
import { ArrowDown, ArrowUp, Check, ChevronRight, LoaderCircle, Square } from "lucide-react";
import { ChatMessage } from "@/components/chat-message";

type DetailView = "context" | "activity" | "evidence";

type TranscriptEntry =
  | { id: string; kind: "user" | "assistant" | "notice" | "error"; text: string }
  | { id: string; kind: "tool"; callId?: string; name: string; arguments: unknown; result?: unknown; status: "running" | "complete" | "interrupted" };

const MODE_LABELS: Record<DesktopConsoleAutonomyMode, string> = {
  standard: "standard",
  recon: "recon",
  copilot: "co-pilot",
  yolo: "yolo",
};

const RAIL_BUTTON = "rounded-lg border border-[#f7f5f2]/12 px-3 py-2 text-xs text-[#b6b2ad] transition hover:border-[#f7f5f2]/30 hover:text-[#f7f5f2] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#b6b2ad] disabled:cursor-not-allowed disabled:opacity-45";
const ACTION_BUTTON = "rounded-lg border border-[#f7f5f2] bg-[#f7f5f2] px-3 py-2 text-xs font-medium text-[#1a1815] transition hover:bg-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#b6b2ad] disabled:cursor-not-allowed disabled:opacity-45";

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
      if (!event.assistantText) continue;
      let streamed = "";
      for (let index = turnStart; index < entries.length; index++) {
        const entry = entries[index];
        if (entry.kind === "assistant") streamed += entry.text;
      }
      if (event.assistantText === streamed) continue;
      if (event.assistantText.startsWith(streamed)) {
        const suffix = event.assistantText.slice(streamed.length);
        const last = entries.at(-1);
        if (last?.kind === "assistant") last.text += suffix;
        else entries.push({ id: `assistant-final-${event.sequence}`, kind: "assistant", text: suffix });
      } else {
        // A runtime can supply authoritative text that was never streamed.
        // Replace this turn's provisional text, retaining its tool activity.
        let retained = turnStart;
        for (let index = turnStart; index < entries.length; index++) {
          const entry = entries[index];
          if (entry.kind !== "assistant") entries[retained++] = entry;
        }
        entries.length = retained;
        entries.push({ id: `assistant-final-${event.sequence}`, kind: "assistant", text: event.assistantText });
      }
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
  return <button type="button" onClick={onClick} className={cn("rounded-md px-2.5 py-2 text-xs transition focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#b6b2ad]", active ? "bg-white/5 text-[#f7f5f2]" : "text-[#a7a29c] hover:bg-white/5 hover:text-[#f7f5f2]")}>{children}</button>;
}

function Transcript({ entries, streaming }: { entries: readonly TranscriptEntry[]; streaming: boolean }) {
  return (
    <div className="mx-auto flex w-full max-w-[48rem] flex-col gap-7 px-5 pb-8 pt-10 sm:px-8" aria-label="Conversation">
      {entries.map((entry, index) => {
        if (entry.kind === "tool") {
          return (
            <details key={entry.id} className="group min-w-0 rounded-xl border border-white/8 bg-white/[0.02]">
              <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-3 text-xs text-[#b6b2ad] focus-visible:outline-2 focus-visible:outline-[#b6b2ad]">
                {entry.status === "running" ? <LoaderCircle aria-hidden className="size-3.5 motion-safe:animate-spin" /> : entry.status === "complete" ? <Check aria-hidden className="size-3.5" /> : <Square aria-hidden className="size-3.5" />}
                <span className="min-w-0 flex-1 truncate font-mono text-[#e4e0dc]">{entry.name}</span>
                <span>{entry.status === "complete" ? "Finished" : entry.status === "running" ? "Running" : "Interrupted"}</span>
                <ChevronRight aria-hidden className="size-3.5 transition-transform group-open:rotate-90 motion-reduce:transition-none" />
              </summary>
              <div className="space-y-3 border-t border-white/8 px-4 py-3">
                <div><p className="mb-2 text-[11px] text-[#a7a29c]">Input</p><pre className="max-h-56 overflow-auto whitespace-pre-wrap break-words text-xs leading-6 text-[#b6b2ad]">{formatPayload(entry.arguments)}</pre></div>
                {entry.status === "complete" ? <div><p className="mb-2 text-[11px] text-[#a7a29c]">Result</p><pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words text-xs leading-6 text-[#b6b2ad]">{formatPayload(entry.result)}</pre></div> : null}
              </div>
            </details>
          );
        }
        if (entry.kind === "notice") return <p key={entry.id} className="text-center text-xs leading-6 text-[#a7a29c]">{entry.text}</p>;
        if (entry.kind === "error") return <p key={entry.id} role="alert" className="rounded-xl border border-[#f18181]/20 px-4 py-3 text-sm leading-6 text-[#f18181]">{entry.text}</p>;
        if (entry.kind === "user") {
          return <article key={entry.id} className="ml-auto max-w-[90%] rounded-2xl bg-white/[0.06] px-5 py-3"><span className="sr-only">You</span><p className="whitespace-pre-wrap break-words text-sm leading-7 text-[#f7f5f2]">{entry.text}</p></article>;
        }
        return (
          <article key={entry.id} className="min-w-0 text-[#e4e0dc]">
            <p className="mb-3 text-xs font-medium text-[#a7a29c]">0sec</p>
            <ChatMessage text={entry.text} streaming={streaming && index === entries.length - 1} />
          </article>
        );
      })}
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
  const inputRef = useRef<HTMLTextAreaElement>(null);
  useLayoutEffect(() => {
    const input = inputRef.current;
    if (!input) return;
    input.style.height = "auto";
    input.style.height = `${Math.min(input.scrollHeight, 224)}px`;
  }, [value]);
  return (
    <form
      className="overflow-hidden rounded-2xl border border-[#f7f5f2]/15 bg-[#141414] shadow-sm transition-colors focus-within:border-[#f7f5f2]/35"
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
        className="min-h-20 w-full resize-none overflow-y-auto bg-transparent px-5 pt-4 pb-2 text-sm leading-7 text-[#f7f5f2] outline-none placeholder:text-[#8d8984] disabled:cursor-not-allowed"
      />
      <div className="flex items-center justify-between gap-3 px-4 pb-3">
        <p className="text-[11px] text-[#8d8984]"><span className="hidden sm:inline">Enter to send · </span>Shift+Enter for a new line</p>
        {working ? (
          <button type="button" aria-label="Stop response" className={RAIL_BUTTON} onClick={onCancel}><Square aria-hidden className="size-4" /></button>
        ) : (
          <button type="submit" aria-label="Send message" className={ACTION_BUTTON} disabled={disabled || !value.trim()}><ArrowUp aria-hidden className="size-4" /></button>
        )}
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
        {sessions.length === 0 ? <p className="text-xs leading-5 text-[#8d8984]">No live sessions.</p> : sessions.map((session) => <button key={session.id} type="button" onClick={() => { onSelect(session.id); onClose(); }} className={cn("block w-full rounded-lg px-3 py-3 text-left transition-colors", session.id === activeId ? "bg-[#f7f5f2]/[0.07]" : "hover:bg-[#f7f5f2]/[0.04]")}><p className="truncate text-xs text-[#e4e0dc]">{formatTarget(session.target)}</p><p className="mt-1 text-[11px] text-[#a7a29c]">{MODE_LABELS[session.autonomyMode]} · {session.status}</p></button>)}
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
  const transcriptScrollRef = useRef<HTMLDivElement>(null);
  const followOutputRef = useRef(true);
  const [showJumpToLatest, setShowJumpToLatest] = useState(false);

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
  const activity = useMemo(() => events.filter((event) => event.type !== "assistant-delta" && event.type !== "reasoning-delta" && event.type !== "user").slice(-18).reverse(), [events]);
  const evidence = useMemo(() => events.filter((event): event is Extract<DesktopConsoleEvent, { type: "tool-result" }> => event.type === "tool-result").slice().reverse(), [events]);

  useLayoutEffect(() => {
    const viewport = transcriptScrollRef.current;
    if (viewport && followOutputRef.current) viewport.scrollTop = viewport.scrollHeight;
  }, [events, detailsOpen]);

  const jumpToLatest = () => {
    const viewport = transcriptScrollRef.current;
    if (!viewport) return;
    followOutputRef.current = true;
    setShowJumpToLatest(false);
    viewport.scrollTop = viewport.scrollHeight;
  };

  const send = async () => {
    if (submitting || !activeSession || !draft.trim() || activeSession.status !== "ready") return;
    setSubmitting(true);
    setError(null);
    followOutputRef.current = true;
    setShowJumpToLatest(false);
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

  if (loading) return <main className="grid min-h-dvh place-items-center bg-[#0a0a0a] text-sm text-[#a7a29c]" role="status">Opening your workspace…</main>;

  const isEmpty = transcript.length === 0;
  const working = activeSession?.status === "working" || activeSession?.status === "waiting";
  const composerDisabled = submitting || !activeSession || activeSession.status === "closed" || activeSession.status === "failed";
  let workingLabel = "Working on your request";
  for (let index = events.length - 1; index >= 0; index--) {
    const event = events[index];
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
  const composer = <Composer value={draft} disabled={Boolean(composerDisabled)} working={working} onChange={setDraft} onSubmit={() => void send()} onCancel={() => void cancel()} />;
  return (
    <main className="relative flex h-dvh min-h-0 overflow-hidden bg-[#0a0a0a] font-sans text-[#f7f5f2] selection:bg-white/20">
      <section className="flex min-w-0 flex-1 flex-col">
        <header className="flex min-h-16 shrink-0 flex-wrap items-center justify-between gap-2 border-b border-[#f7f5f2]/8 px-4 py-2 sm:px-6">
          <div className="flex min-w-0 items-center gap-4">
            <Wordmark />
            <span className="rounded border border-white/10 px-1.5 py-0.5 text-[10px] text-[#a7a29c]">Development</span>
            <span className="hidden max-w-64 truncate text-xs text-[#a7a29c] lg:block">{activeSession?.target ? formatTarget(activeSession.target) : "Local workspace"}</span>
          </div>
          <div className="flex items-center gap-0.5">
            <HeaderButton onClick={() => setSessionsOpen(true)}>Chats</HeaderButton>
            <HeaderButton onClick={() => { setDetailView("context"); setDetailsOpen(true); }}>Context{pendingDecisions.length ? ` · ${pendingDecisions.length}` : ""}</HeaderButton>
            <HeaderButton onClick={() => void createSession()}>New chat</HeaderButton>
            <Link className="rounded-md px-2.5 py-2 text-xs text-[#a7a29c] transition hover:bg-white/5 hover:text-[#f7f5f2] focus-visible:outline-2 focus-visible:outline-[#b6b2ad]" to="/dashboard">Operations</Link>
          </div>
        </header>
        {isEmpty ? (
          <div className="flex min-h-0 flex-1 flex-col items-center justify-center overflow-y-auto px-5 py-10">
            <div className="w-full max-w-[40rem]">
              <div className="mb-9">
                <p className="mb-3 text-xs text-[#a7a29c]">Your local security workspace</p>
                <h1 className="text-3xl font-medium tracking-[-0.04em] text-[#f7f5f2] sm:text-4xl">What are we investigating?</h1>
                <p className="mt-4 max-w-lg text-sm leading-7 text-[#a7a29c]">Start with a question or an outcome. Follow the work as it happens, with scope and approvals kept explicit.</p>
              </div>
              {composer}
              <div className="mt-4 flex flex-wrap gap-2">
                {["Explain how scope and approvals work", "Help me plan a source review"].map((prompt) => (
                  <button key={prompt} type="button" className="rounded-full border border-white/10 px-3 py-2 text-xs text-[#a7a29c] transition hover:border-white/25 hover:text-[#f7f5f2] focus-visible:outline-2 focus-visible:outline-[#b6b2ad]" onClick={() => setDraft(prompt)}>{prompt}</button>
                ))}
              </div>
              {error ? <p role="alert" className="mt-4 text-sm text-[#f18181]">{error}</p> : null}
            </div>
          </div>
        ) : (
          <>
            <div className="relative min-h-0 flex-1">
              <div ref={transcriptScrollRef} className="h-full overflow-y-auto overscroll-contain" onScroll={(event) => {
                const viewport = event.currentTarget;
                const following = viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight < 80;
                followOutputRef.current = following;
                setShowJumpToLatest(!following);
              }}>
                <Transcript entries={transcript} streaming={activeSession?.status === "working"} />
              </div>
              {showJumpToLatest ? <button type="button" className="absolute bottom-4 left-1/2 flex -translate-x-1/2 items-center gap-2 rounded-full border border-white/15 bg-[#1a1a1a] px-4 py-2 text-xs text-[#f7f5f2] shadow-sm focus-visible:outline-2 focus-visible:outline-[#b6b2ad]" onClick={jumpToLatest}><ArrowDown aria-hidden className="size-3.5" />Latest response</button> : null}
            </div>
            <div className="mx-auto w-full max-w-[48rem] px-5 pb-5 sm:px-8">
              <div role="status" aria-live="polite" className="mb-3 flex min-h-5 items-center gap-2 text-xs text-[#a7a29c]">
                {working ? <><LoaderCircle aria-hidden className="size-3.5 motion-safe:animate-spin" /><span>{workingLabel}</span></> : <span>{activeSession?.status === "ready" ? "Ready for your next message" : activeSession?.status}</span>}
              </div>
              {composer}
              {error ? <p role="alert" className="mt-3 text-sm text-[#f18181]">{error}</p> : null}
            </div>
          </>
        )}
      </section>
      <Details open={detailsOpen} view={detailView} session={activeSession} pending={pendingDecisions} activity={activity} evidence={evidence} auth={codexAuth} busy={submitting} onClose={() => setDetailsOpen(false)} onView={setDetailView} onResolve={resolveDecision} onConnect={connectCodex} onCancelConnect={cancelCodex} />
      <SessionPanel sessions={sessions} activeId={activeId} open={sessionsOpen} onClose={() => setSessionsOpen(false)} onSelect={setActiveId} onNew={() => void createSession()} onScoped={() => { setSessionsOpen(false); setScopedOpen(true); }} />
      <ScopedEngagement open={scopedOpen} busy={submitting} onClose={() => setScopedOpen(false)} onCreate={createSession} />
    </main>
  );
}
