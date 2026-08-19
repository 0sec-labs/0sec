import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { NavLink, useSearchParams } from "react-router-dom";
import { AlertTriangle, ArrowRight, Beaker, Bot, ChevronDown, ChevronUp, FileSearch, Radio, Target, Terminal, Zap } from "lucide-react";
import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardEmpty, CardEyebrow, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { extractFileLine, parseHuntEvent, type osecHuntEvent } from "@/lib/hunt-stream";

/**
 * GemmaForge × 0sec live workflow view.
 *
 * Wires three parallel event streams into three lanes:
 *   1. Probe  — probe.token + probe.alarm  (raw model-internal probe firings)
 *   2. Lead   — scan.lead                  (regions that crossed the threshold)
 *   3. Hunt   — 0sec.events/v1            (agent tool calls, findings, stages)
 *
 * Event-source resolution (URL query params):
 *   ?events=<URL>       → SSE endpoint emitting ND-JSON `gemmaforge.events/v1`
 *                          (Probe + Lead lanes).
 *   ?huntEvents=<URL>   → SSE endpoint emitting ND-JSON `0sec.events/v1`
 *                          (Hunt lane). Produced by `scripts/serve-events.mjs
 *                          --0sec-log <stdout.log>` tailing a 0sec scan run
 *                          with `0SEC_CLOUD_EVENTS=1`.
 *   ?demo=1             → in-memory demo replay, no backend required. Drives
 *                          all three lanes off the same synthetic timeline.
 *
 * Bidirectional provenance:
 *   - Clicking a lead highlights its originating probe.alarm (lead → probe).
 *   - Clicking a hunt tool-use card that cites a `file:line` highlights the
 *     matching lead (tool-use → lead) and, transitively, that lead's
 *     originating probe alarm.
 */

type GemmaForgeEvent =
  | { schema: "gemmaforge.events/v1"; kind: "scan.start"; ts: number; repo?: string; model_id?: string; layer?: number; chunker?: string }
  | { schema: "gemmaforge.events/v1"; kind: "scan.file"; ts: number; file: string; chunks?: number }
  | { schema: "gemmaforge.events/v1"; kind: "probe.score"; ts: number; file: string; start_line: number; end_line: number; confidence: number; top_cwe?: string | null }
  | { schema: "gemmaforge.events/v1"; kind: "scan.lead"; ts: number; file: string; start_line: number; end_line: number; confidence: number; top_cwe?: string | null; rank?: number }
  | { schema: "gemmaforge.events/v1"; kind: "probe.token"; ts: number; token: string; score: number; position?: number }
  | { schema: "gemmaforge.events/v1"; kind: "probe.alarm"; ts: number; window: [number, number]; top_cwe?: string | null; confidence: number }
  | { schema: "gemmaforge.events/v1"; kind: "scan.end"; ts: number; files_seen?: number; chunks_scored?: number; leads_emitted?: number; elapsed_seconds?: number };

type ConnectionState = "idle" | "connecting" | "open" | "closed" | "error";

type ProbeTokenRow = {
  id: string;
  ts: number;
  token: string;
  score: number;
  position: number | null;
};

type ProbeAlarmRow = {
  id: string;
  ts: number;
  window: [number, number];
  top_cwe: string | null;
  confidence: number;
};

type LeadRow = {
  id: string;
  ts: number;
  file: string;
  start_line: number;
  end_line: number;
  confidence: number;
  top_cwe: string | null;
  rank: number | null;
  /** id of the most recent probe.alarm that fired before this lead, for provenance */
  originatingAlarmId: string | null;
};

type HuntCard = {
  id: string;
  ts: number;
  event: osecHuntEvent;
  /** Resolved on ingest: the leadRow.id whose file/line this card cites, if any. */
  citedLeadId: string | null;
};

const MAX_TOKEN_ROWS = 240;
const MAX_ALARM_ROWS = 24;
const MAX_LEAD_ROWS = 60;
const MAX_HUNT_ROWS = 80;

/** Pick a tailwind text color based on a [0, 1] probe score. */
function scoreColorClass(score: number): string {
  if (score >= 0.9) return "text-destructive";
  if (score >= 0.75) return "text-amber-600 dark:text-amber-400";
  if (score >= 0.5) return "text-sky-600 dark:text-sky-400";
  return "text-muted-foreground";
}

function scoreBgClass(score: number): string {
  if (score >= 0.9) return "bg-destructive/12";
  if (score >= 0.75) return "bg-amber-500/12";
  if (score >= 0.5) return "bg-sky-500/12";
  return "";
}

function formatScore(value: number): string {
  return value.toFixed(2);
}

function formatRelativeTs(ts: number, base: number | null): string {
  if (base === null) return new Date(ts * 1000).toLocaleTimeString();
  const delta = ts - base;
  if (delta < 0) return `${delta.toFixed(1)}s`;
  return `+${delta.toFixed(1)}s`;
}

function severityVariant(severity: string | undefined): "danger" | "warning" | "info" | "neutral" {
  const value = (severity ?? "").toLowerCase();
  if (value === "critical" || value === "high") return "danger";
  if (value === "medium") return "warning";
  if (value === "low" || value === "info") return "info";
  return "neutral";
}

/**
 * Find the lead, if any, whose file matches and whose [start_line, end_line]
 * window contains the cited line. Used to wire tool-use → lead provenance.
 *
 * Match is exact-file with a generous line tolerance (±20) since the agent
 * may quote a slightly different anchor than the lead's window. We keep the
 * tolerance one-sided-friendly so a "Read src/x.ts:38" still ties back to a
 * lead at lines 38–52.
 */
function findLeadForFileLine(leads: LeadRow[], file: string, line: number): LeadRow | null {
  const tolerance = 20;
  let best: LeadRow | null = null;
  for (const lead of leads) {
    if (!lead.file.endsWith(file) && !file.endsWith(lead.file)) continue;
    if (line < lead.start_line - tolerance) continue;
    if (line > lead.end_line + tolerance) continue;
    if (!best) { best = lead; continue; }
    // Prefer the lead whose window most tightly contains the cited line.
    const bestDist = Math.max(0, best.start_line - line, line - best.end_line);
    const here = Math.max(0, lead.start_line - line, line - lead.end_line);
    if (here < bestDist) best = lead;
  }
  return best;
}

/** Synthetic demo replay so the page is meaningful without a backend. */
function demoEvents(): GemmaForgeEvent[] {
  const t0 = Date.now() / 1000;
  const mk = <T extends GemmaForgeEvent>(e: T) => e;
  return [
    mk({ schema: "gemmaforge.events/v1", kind: "scan.start", ts: t0, repo: "examples/express-app", model_id: "google/gemma-4-E2B-it", layer: 17, chunker: "function" }),
    mk({ schema: "gemmaforge.events/v1", kind: "scan.file", ts: t0 + 0.4, file: "src/router.js", chunks: 12 }),
    mk({ schema: "gemmaforge.events/v1", kind: "probe.token", ts: t0 + 0.6, token: "app.get(", score: 0.14, position: 1 }),
    mk({ schema: "gemmaforge.events/v1", kind: "probe.token", ts: t0 + 0.7, token: "'/u/:id'", score: 0.31, position: 2 }),
    mk({ schema: "gemmaforge.events/v1", kind: "probe.token", ts: t0 + 0.8, token: " db.query(", score: 0.72, position: 12 }),
    mk({ schema: "gemmaforge.events/v1", kind: "probe.token", ts: t0 + 0.9, token: "'SELECT * FROM users WHERE id='", score: 0.84, position: 18 }),
    mk({ schema: "gemmaforge.events/v1", kind: "probe.token", ts: t0 + 1.0, token: " + req.params.id", score: 0.93, position: 23 }),
    mk({ schema: "gemmaforge.events/v1", kind: "probe.alarm", ts: t0 + 1.05, window: [38, 52], top_cwe: "CWE-89", confidence: 0.93 }),
    mk({ schema: "gemmaforge.events/v1", kind: "scan.lead", ts: t0 + 1.1, file: "src/router.js", start_line: 38, end_line: 52, confidence: 0.93, top_cwe: "CWE-89", rank: 0 }),
    mk({ schema: "gemmaforge.events/v1", kind: "scan.file", ts: t0 + 1.4, file: "src/exec.js", chunks: 4 }),
    mk({ schema: "gemmaforge.events/v1", kind: "probe.token", ts: t0 + 1.6, token: "child_process.exec(", score: 0.81, position: 4 }),
    mk({ schema: "gemmaforge.events/v1", kind: "probe.token", ts: t0 + 1.7, token: " `ping ${host}`", score: 0.88, position: 7 }),
    mk({ schema: "gemmaforge.events/v1", kind: "probe.alarm", ts: t0 + 1.78, window: [12, 22], top_cwe: "CWE-78", confidence: 0.87 }),
    mk({ schema: "gemmaforge.events/v1", kind: "scan.lead", ts: t0 + 1.82, file: "src/exec.js", start_line: 12, end_line: 22, confidence: 0.87, top_cwe: "CWE-78", rank: 1 }),
    mk({ schema: "gemmaforge.events/v1", kind: "scan.end", ts: t0 + 2.4, files_seen: 2, chunks_scored: 16, leads_emitted: 2, elapsed_seconds: 2.4 }),
  ];
}

/** Synthetic Hunt-lane events for the demo replay path. */
function demoHuntEvents(t0: number): osecHuntEvent[] {
  return [
    { schema: "0sec.events/v1", kind: "stage", ts: t0 + 1.2, stage: "audit", transition: "started", role: "attack" },
    { schema: "0sec.events/v1", kind: "tool_use", ts: t0 + 1.3, tool: "read_file", turn: 1, args_preview: "src/router.js:38", file: "src/router.js", line: 38, status: "ok", duration_ms: 14 },
    { schema: "0sec.events/v1", kind: "tool_use", ts: t0 + 1.5, tool: "shell", turn: 1, args_preview: "grep -n 'db.query' src/router.js", status: "ok", duration_ms: 47 },
    { schema: "0sec.events/v1", kind: "finding", ts: t0 + 1.9, finding_id: "f-001", title: "SQL injection via req.params.id", severity: "high", category: "injection", confidence: 0.92, file: "src/router.js", line: 42 },
    { schema: "0sec.events/v1", kind: "tool_use", ts: t0 + 2.0, tool: "read_file", turn: 2, args_preview: "src/exec.js:12", file: "src/exec.js", line: 12, status: "ok", duration_ms: 9 },
    { schema: "0sec.events/v1", kind: "finding", ts: t0 + 2.3, finding_id: "f-002", title: "Command injection in ping handler", severity: "critical", category: "rce", confidence: 0.88, file: "src/exec.js", line: 17 },
    { schema: "0sec.events/v1", kind: "stage", ts: t0 + 2.5, stage: "audit", transition: "completed", role: "attack", duration_ms: 1300 },
  ];
}

export function LivePage() {
  const [params, setParams] = useSearchParams();
  const eventsUrl = params.get("events") ?? "";
  const huntUrl = params.get("huntEvents") ?? "";
  const demoMode = params.get("demo") === "1";

  const [tokens, setTokens] = useState<ProbeTokenRow[]>([]);
  const [alarms, setAlarms] = useState<ProbeAlarmRow[]>([]);
  const [leads, setLeads] = useState<LeadRow[]>([]);
  const [huntCards, setHuntCards] = useState<HuntCard[]>([]);
  const [scanMeta, setScanMeta] = useState<{ repo?: string; model_id?: string; layer?: number } | null>(null);
  const [filesSeen, setFilesSeen] = useState<string[]>([]);
  const [endSummary, setEndSummary] = useState<{ files_seen?: number; chunks_scored?: number; leads_emitted?: number; elapsed_seconds?: number } | null>(null);
  const [connection, setConnection] = useState<ConnectionState>("idle");
  const [huntConnection, setHuntConnection] = useState<ConnectionState>("idle");
  const [lastError, setLastError] = useState<string | null>(null);
  const [selectedLeadId, setSelectedLeadId] = useState<string | null>(null);
  const [urlDraft, setUrlDraft] = useState(eventsUrl);
  const [huntUrlDraft, setHuntUrlDraft] = useState(huntUrl);

  const lastAlarmRef = useRef<ProbeAlarmRow | null>(null);
  const baseTsRef = useRef<number | null>(null);
  const counterRef = useRef(0);
  // Ref mirror of `leads` so the hunt-ingest path can resolve file:line
  // provenance without depending on stale closures (the hunt SSE callback
  // runs at arbitrary times relative to lead-ingest renders).
  const leadsRef = useRef<LeadRow[]>([]);
  useEffect(() => { leadsRef.current = leads; }, [leads]);

  const mkId = useCallback(() => {
    counterRef.current += 1;
    return `evt-${counterRef.current}`;
  }, []);

  const ingest = useCallback((event: GemmaForgeEvent) => {
    if (baseTsRef.current === null && typeof event.ts === "number") {
      baseTsRef.current = event.ts;
    }

    switch (event.kind) {
      case "scan.start":
        setScanMeta({ repo: event.repo, model_id: event.model_id, layer: event.layer });
        setEndSummary(null);
        setFilesSeen([]);
        break;
      case "scan.file":
        setFilesSeen((prev) => (prev.includes(event.file) ? prev : [...prev, event.file].slice(-12)));
        break;
      case "probe.token": {
        const row: ProbeTokenRow = {
          id: mkId(),
          ts: event.ts,
          token: event.token,
          score: event.score,
          position: event.position ?? null,
        };
        setTokens((prev) => [...prev, row].slice(-MAX_TOKEN_ROWS));
        break;
      }
      case "probe.alarm": {
        const row: ProbeAlarmRow = {
          id: mkId(),
          ts: event.ts,
          window: event.window,
          top_cwe: event.top_cwe ?? null,
          confidence: event.confidence,
        };
        lastAlarmRef.current = row;
        setAlarms((prev) => [row, ...prev].slice(0, MAX_ALARM_ROWS));
        break;
      }
      case "scan.lead": {
        const row: LeadRow = {
          id: mkId(),
          ts: event.ts,
          file: event.file,
          start_line: event.start_line,
          end_line: event.end_line,
          confidence: event.confidence,
          top_cwe: event.top_cwe ?? null,
          rank: event.rank ?? null,
          originatingAlarmId: lastAlarmRef.current?.id ?? null,
        };
        setLeads((prev) => [row, ...prev].slice(0, MAX_LEAD_ROWS));
        break;
      }
      case "scan.end":
        setEndSummary({
          files_seen: event.files_seen,
          chunks_scored: event.chunks_scored,
          leads_emitted: event.leads_emitted,
          elapsed_seconds: event.elapsed_seconds,
        });
        break;
      // probe.score is intentionally unused in the lane view; it can be added
      // as a sparkline later. Unknown kinds are ignored per the schema contract.
    }
  }, [mkId]);

  const ingestHunt = useCallback((event: osecHuntEvent) => {
    if (baseTsRef.current === null && typeof event.ts === "number") {
      baseTsRef.current = event.ts;
    }
    // Resolve provenance: for tool_use + finding events with file:line, try
    // to find a lead whose window contains the cited line. Done eagerly on
    // ingest so the card → lead lookup is O(1) at render time.
    let citedLeadId: string | null = null;
    if ((event.kind === "tool_use" || event.kind === "finding") && event.file && typeof event.line === "number") {
      const match = findLeadForFileLine(leadsRef.current, event.file, event.line);
      citedLeadId = match?.id ?? null;
    } else if (event.kind === "tool_use" && event.args_preview) {
      // Fallback: extract file:line directly from args_preview if the
      // upstream translator missed it (defensive — both transports now
      // pre-parse, but tests for hunt-stream.ts assert this behaviour).
      const parsed = extractFileLine(event.args_preview);
      if (parsed) {
        const match = findLeadForFileLine(leadsRef.current, parsed.file, parsed.line);
        citedLeadId = match?.id ?? null;
      }
    }
    const card: HuntCard = {
      id: mkId(),
      ts: event.ts,
      event,
      citedLeadId,
    };
    setHuntCards((prev) => [card, ...prev].slice(0, MAX_HUNT_ROWS));
  }, [mkId]);

  const resetState = useCallback(() => {
    setTokens([]);
    setAlarms([]);
    setLeads([]);
    setHuntCards([]);
    setScanMeta(null);
    setFilesSeen([]);
    setEndSummary(null);
    setSelectedLeadId(null);
    setLastError(null);
    lastAlarmRef.current = null;
    baseTsRef.current = null;
  }, []);

  // Demo replay — drives all three lanes off one synthetic timeline.
  useEffect(() => {
    if (!demoMode) return;
    resetState();
    setConnection("open");
    setHuntConnection("open");
    const events = demoEvents();
    const start = events[0]?.ts ?? Date.now() / 1000;
    const hunt = demoHuntEvents(start);
    const timers: ReturnType<typeof setTimeout>[] = [];
    for (const event of events) {
      const delay = Math.max(0, (event.ts - start) * 1000);
      timers.push(setTimeout(() => ingest(event), delay));
    }
    for (const event of hunt) {
      const delay = Math.max(0, (event.ts - start) * 1000);
      timers.push(setTimeout(() => ingestHunt(event), delay));
    }
    const finalDelay = ((events.at(-1)?.ts ?? start) - start) * 1000 + 300;
    timers.push(setTimeout(() => {
      setConnection("closed");
      setHuntConnection("closed");
    }, finalDelay));
    return () => {
      for (const timer of timers) clearTimeout(timer);
    };
  }, [demoMode, ingest, ingestHunt, resetState]);

  // GemmaForge SSE subscription (Probe + Lead lanes).
  useEffect(() => {
    if (demoMode || !eventsUrl) return;
    // Don't reset the hunt lane here — the two streams are independent and
    // may connect/disconnect at different times.
    setTokens([]);
    setAlarms([]);
    setLeads([]);
    setScanMeta(null);
    setFilesSeen([]);
    setEndSummary(null);
    setSelectedLeadId(null);
    lastAlarmRef.current = null;
    baseTsRef.current = null;
    setConnection("connecting");
    let source: EventSource | null = null;
    try {
      source = new EventSource(eventsUrl);
    } catch (error) {
      setConnection("error");
      setLastError(error instanceof Error ? error.message : String(error));
      return;
    }
    source.onopen = () => setConnection("open");
    source.onerror = () => {
      setConnection("error");
      setLastError("EventSource error (connection dropped or refused).");
    };
    source.onmessage = (message) => {
      const data = typeof message.data === "string" ? message.data.trim() : "";
      if (!data) return;
      try {
        const parsed = JSON.parse(data) as GemmaForgeEvent;
        if (parsed.schema !== "gemmaforge.events/v1") return;
        ingest(parsed);
      } catch (error) {
        setLastError(error instanceof Error ? error.message : String(error));
      }
    };
    return () => {
      source?.close();
      setConnection("closed");
    };
  }, [demoMode, eventsUrl, ingest]);

  // 0sec SSE subscription (Hunt lane).
  useEffect(() => {
    if (demoMode || !huntUrl) return;
    setHuntCards([]);
    setHuntConnection("connecting");
    let source: EventSource | null = null;
    try {
      source = new EventSource(huntUrl);
    } catch (error) {
      setHuntConnection("error");
      setLastError(error instanceof Error ? error.message : String(error));
      return;
    }
    source.onopen = () => setHuntConnection("open");
    source.onerror = () => {
      setHuntConnection("error");
      // Don't override gemmaforge-side errors with hunt-side; surface a
      // distinct message so the operator can tell the two apart.
      setLastError("Hunt EventSource error (connection dropped or refused).");
    };
    source.onmessage = (message) => {
      const data = typeof message.data === "string" ? message.data.trim() : "";
      if (!data) return;
      const parsed = parseHuntEvent(data);
      if (parsed) ingestHunt(parsed);
    };
    return () => {
      source?.close();
      setHuntConnection("closed");
    };
  }, [demoMode, huntUrl, ingestHunt]);

  const applyUrl = useCallback(() => {
    const next = new URLSearchParams(params);
    next.delete("demo");
    if (urlDraft.trim()) {
      next.set("events", urlDraft.trim());
    } else {
      next.delete("events");
    }
    if (huntUrlDraft.trim()) {
      next.set("huntEvents", huntUrlDraft.trim());
    } else {
      next.delete("huntEvents");
    }
    setParams(next, { replace: true });
  }, [params, setParams, urlDraft, huntUrlDraft]);

  const startDemo = useCallback(() => {
    const next = new URLSearchParams(params);
    next.delete("events");
    next.delete("huntEvents");
    next.set("demo", "1");
    setParams(next, { replace: true });
  }, [params, setParams]);

  const stopAll = useCallback(() => {
    const next = new URLSearchParams(params);
    next.delete("events");
    next.delete("huntEvents");
    next.delete("demo");
    setParams(next, { replace: true });
    resetState();
    setConnection("idle");
    setHuntConnection("idle");
  }, [params, resetState, setParams]);

  const selectedLead = useMemo(() => leads.find((l) => l.id === selectedLeadId) ?? null, [leads, selectedLeadId]);
  const highlightedAlarmId = selectedLead?.originatingAlarmId ?? null;

  // Combined connection state for the header pill — surface the "more
  // active" of the two streams so operators see "live" the moment either
  // lane starts producing.
  const combinedConnection = useMemo<ConnectionState>(() => {
    const states = [connection, huntConnection];
    if (states.includes("open")) return "open";
    if (states.includes("connecting")) return "connecting";
    if (states.includes("error")) return "error";
    if (states.includes("closed")) return "closed";
    return "idle";
  }, [connection, huntConnection]);

  const selectLeadFromHuntCard = useCallback((card: HuntCard) => {
    if (!card.citedLeadId) return;
    setSelectedLeadId((prev) => (prev === card.citedLeadId ? null : card.citedLeadId));
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="GemmaForge × 0sec"
        title="Live workflow"
        summary="Watch the probe → seed leads → agent hunt pipeline in real time. Probe firings stream from gemmaforge.events/v1, leads accumulate to the worklist, and 0sec's hunters surface tool calls and findings as they happen."
        actions={(
          <>
            <ConnectionPill state={combinedConnection} />
            <Button variant={demoMode ? "outline" : "accent"} onClick={startDemo}>
              <Beaker />
              Demo replay
            </Button>
            <Button variant="outline" onClick={stopAll} disabled={combinedConnection === "idle"}>
              Stop
            </Button>
          </>
        )}
      />

      <Card className="overflow-hidden">
        <CardHeader>
          <div>
            <CardEyebrow>Event sources</CardEyebrow>
            <CardTitle className="mt-2">SSE endpoints</CardTitle>
            <CardDescription>
              The probe + lead lanes consume <code className="font-mono text-xs">gemmaforge.events/v1</code>;
              the hunt lane consumes <code className="font-mono text-xs">0sec.events/v1</code>. Run
              {" "}<code className="font-mono text-xs">node scripts/serve-events.mjs &lt;gemma.ndjson&gt; --0sec-log &lt;0sec.log&gt;</code>{" "}
              to expose both at <code className="font-mono text-xs">/events</code> and <code className="font-mono text-xs">/hunt-events</code>.
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground/70 w-24">
              gemmaforge
            </span>
            <Input
              value={urlDraft}
              onChange={(event) => setUrlDraft(event.target.value)}
              placeholder="http://localhost:8765/events"
              className="min-w-[16rem] flex-1"
            />
            <ConnectionPill state={connection} />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground/70 w-24">
              0sec
            </span>
            <Input
              value={huntUrlDraft}
              onChange={(event) => setHuntUrlDraft(event.target.value)}
              placeholder="http://localhost:8765/hunt-events"
              className="min-w-[16rem] flex-1"
            />
            <ConnectionPill state={huntConnection} />
          </div>
          <div className="flex justify-end">
            <Button onClick={applyUrl} disabled={!urlDraft.trim() && !huntUrlDraft.trim()}>
              <Radio />
              Connect
            </Button>
          </div>
          {scanMeta ? (
            <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
              {scanMeta.repo ? <Badge variant="neutral">repo {scanMeta.repo}</Badge> : null}
              {scanMeta.model_id ? <Badge variant="neutral">model {scanMeta.model_id}</Badge> : null}
              {scanMeta.layer !== undefined ? <Badge variant="neutral">layer {scanMeta.layer}</Badge> : null}
              {filesSeen.length > 0 ? (
                <span className="text-muted-foreground">
                  files: <span className="font-mono">{filesSeen.slice(-4).join(", ")}</span>
                </span>
              ) : null}
            </div>
          ) : null}
          {endSummary ? (
            <div className="flex flex-wrap gap-2 text-xs">
              <Badge variant="success">scan complete</Badge>
              <span className="text-muted-foreground">
                {endSummary.files_seen ?? "?"} files · {endSummary.chunks_scored ?? "?"} chunks · {endSummary.leads_emitted ?? "?"} leads · {endSummary.elapsed_seconds?.toFixed(1) ?? "?"}s
              </span>
            </div>
          ) : null}
          {lastError ? (
            <div className="rounded-md border border-destructive/20 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {lastError}
            </div>
          ) : null}
        </CardContent>
      </Card>

      <section className="grid gap-4 xl:grid-cols-3">
        <ProbeLane
          tokens={tokens}
          alarms={alarms}
          highlightedAlarmId={highlightedAlarmId}
          baseTs={baseTsRef.current}
          onClearSelection={() => setSelectedLeadId(null)}
          hasSelection={selectedLead !== null}
        />
        <LeadLane
          leads={leads}
          baseTs={baseTsRef.current}
          selectedLeadId={selectedLeadId}
          onSelectLead={(id) => setSelectedLeadId((prev) => (prev === id ? null : id))}
        />
        <HuntLane
          cards={huntCards}
          selectedLead={selectedLead}
          selectedLeadId={selectedLeadId}
          baseTs={baseTsRef.current}
          onCardClick={selectLeadFromHuntCard}
        />
      </section>
    </div>
  );
}

function ConnectionPill({ state }: { state: ConnectionState }) {
  if (state === "open") return <Badge variant="success" className="gap-1.5"><Radio className="size-3" /> live</Badge>;
  if (state === "connecting") return <Badge variant="warning" className="gap-1.5"><Radio className="size-3" /> connecting</Badge>;
  if (state === "error") return <Badge variant="danger" className="gap-1.5"><Radio className="size-3" /> error</Badge>;
  if (state === "closed") return <Badge variant="neutral" className="gap-1.5"><Radio className="size-3" /> closed</Badge>;
  return <Badge variant="neutral" className="gap-1.5"><Radio className="size-3" /> idle</Badge>;
}

function ProbeLane({
  tokens,
  alarms,
  highlightedAlarmId,
  baseTs,
  onClearSelection,
  hasSelection,
}: {
  tokens: ProbeTokenRow[];
  alarms: ProbeAlarmRow[];
  highlightedAlarmId: string | null;
  baseTs: number | null;
  onClearSelection: () => void;
  hasSelection: boolean;
}) {
  const streamRef = useRef<HTMLDivElement | null>(null);

  // Auto-stick to the tail of the token stream.
  useEffect(() => {
    const el = streamRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [tokens.length]);

  return (
    <Card className="flex flex-col overflow-hidden">
      <CardHeader>
        <div>
          <CardEyebrow>Lane 1 · Probe</CardEyebrow>
          <CardTitle className="mt-2 flex items-center gap-2">
            <Zap className="size-4 text-primary" />
            Probe firings
          </CardTitle>
          <CardDescription>
            Per-token probe scores from <code className="font-mono text-xs">stream_with_probe.py</code>. Alarms pin to the top when the rolling score crosses threshold.
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-3">
        {alarms.length === 0 ? null : (
          <div className="space-y-1.5">
            <div className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground/70">
              Alarms <span className="text-muted-foreground/40">({alarms.length})</span>
            </div>
            <div className="space-y-1.5">
              {alarms.slice(0, 4).map((alarm) => (
                <div
                  key={alarm.id}
                  className={cn(
                    "rounded-md border px-3 py-2 transition-colors",
                    highlightedAlarmId === alarm.id
                      ? "border-primary/40 bg-primary/8 ring-1 ring-primary/30"
                      : "border-destructive/20 bg-destructive/5",
                  )}
                >
                  <div className="flex items-center justify-between gap-2 text-xs">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="size-3.5 text-destructive" />
                      <span className="font-mono">L{alarm.window[0]}–{alarm.window[1]}</span>
                      {alarm.top_cwe ? <Badge variant="danger">{alarm.top_cwe}</Badge> : null}
                    </div>
                    <span className="font-mono text-destructive">{formatScore(alarm.confidence)}</span>
                  </div>
                  <div className="mt-1 text-[10px] text-muted-foreground">
                    {formatRelativeTs(alarm.ts, baseTs)}
                    {highlightedAlarmId === alarm.id ? " · originating fire" : ""}
                  </div>
                </div>
              ))}
            </div>
            {hasSelection ? (
              <Button variant="ghost" size="xs" onClick={onClearSelection}>
                Clear lead selection
              </Button>
            ) : null}
          </div>
        )}

        <div className="space-y-1.5">
          <div className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground/70">
            Token stream <span className="text-muted-foreground/40">({tokens.length})</span>
          </div>
          <div
            ref={streamRef}
            className="max-h-[28rem] min-h-[12rem] overflow-y-auto rounded-md border border-border bg-muted/10 px-3 py-3 font-mono text-xs leading-relaxed"
          >
            {tokens.length === 0 ? (
              <div className="text-muted-foreground">Waiting for probe.token events…</div>
            ) : (
              <div className="flex flex-wrap gap-x-0.5 gap-y-1">
                {tokens.map((row) => (
                  <span
                    key={row.id}
                    title={`score ${formatScore(row.score)} · pos ${row.position ?? "?"}`}
                    className={cn(
                      "rounded-sm px-1 py-0.5",
                      scoreColorClass(row.score),
                      scoreBgClass(row.score),
                    )}
                  >
                    {row.token}
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
            <span className="flex items-center gap-1">
              <span className="size-2 rounded-full bg-muted-foreground/50" /> &lt;0.5
            </span>
            <span className="flex items-center gap-1">
              <span className="size-2 rounded-full bg-sky-500" /> 0.5–0.75
            </span>
            <span className="flex items-center gap-1">
              <span className="size-2 rounded-full bg-amber-500" /> 0.75–0.9
            </span>
            <span className="flex items-center gap-1">
              <span className="size-2 rounded-full bg-destructive" /> ≥0.9
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function LeadLane({
  leads,
  baseTs,
  selectedLeadId,
  onSelectLead,
}: {
  leads: LeadRow[];
  baseTs: number | null;
  selectedLeadId: string | null;
  onSelectLead: (id: string) => void;
}) {
  return (
    <Card className="flex flex-col overflow-hidden">
      <CardHeader>
        <div>
          <CardEyebrow>Lane 2 · Leads</CardEyebrow>
          <CardTitle className="mt-2 flex items-center gap-2">
            <FileSearch className="size-4 text-primary" />
            Seed worklist
          </CardTitle>
          <CardDescription>
            Regions that passed `--min-confidence` and shipped to the leads file. Click a lead to highlight the probe firing that originated it; click a hunt tool-call to highlight the lead it cites.
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col">
        {leads.length === 0 ? (
          <CardEmpty>Waiting for scan.lead events…</CardEmpty>
        ) : (
          <div className="max-h-[36rem] space-y-2 overflow-y-auto pr-1">
            {leads.map((lead) => {
              const isSelected = lead.id === selectedLeadId;
              return (
                <button
                  key={lead.id}
                  type="button"
                  onClick={() => onSelectLead(lead.id)}
                  className={cn(
                    "w-full rounded-md border px-3 py-3 text-left transition-colors",
                    isSelected
                      ? "border-primary/40 bg-primary/8 ring-1 ring-primary/30"
                      : "border-border bg-background hover:border-primary/20 hover:bg-primary/4",
                  )}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="truncate font-mono text-xs text-foreground">{lead.file}</div>
                      <div className="mt-0.5 text-[11px] text-muted-foreground">
                        lines {lead.start_line}–{lead.end_line}
                        {lead.rank !== null ? ` · rank #${lead.rank}` : ""}
                        {" · "}
                        {formatRelativeTs(lead.ts, baseTs)}
                      </div>
                    </div>
                    <div className="flex shrink-0 flex-col items-end gap-1">
                      <Badge variant="accent" className="font-mono">
                        {formatScore(lead.confidence)}
                      </Badge>
                      {lead.top_cwe ? <Badge variant="danger">{lead.top_cwe}</Badge> : null}
                    </div>
                  </div>
                  {isSelected ? (
                    <div className="mt-2 flex items-center gap-1 text-[10px] text-primary">
                      <ChevronUp className="size-3" />
                      probe lane is highlighting the originating fire
                      <ArrowRight className="ml-auto size-3" />
                      <ChevronDown className="size-3" />
                      hunt lane is targeting this lead
                    </div>
                  ) : null}
                </button>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function HuntLane({
  cards,
  selectedLead,
  selectedLeadId,
  baseTs,
  onCardClick,
}: {
  cards: HuntCard[];
  selectedLead: LeadRow | null;
  selectedLeadId: string | null;
  baseTs: number | null;
  onCardClick: (card: HuntCard) => void;
}) {
  return (
    <Card className="flex flex-col overflow-hidden">
      <CardHeader>
        <div>
          <CardEyebrow>Lane 3 · Hunt</CardEyebrow>
          <CardTitle className="mt-2 flex items-center gap-2">
            <Bot className="size-4 text-primary" />
            Agent activity
          </CardTitle>
          <CardDescription>
            Live 0sec scan events — tool calls, findings, and stage transitions. Click a card that cites a file:line to highlight the originating lead in lane 2.
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-3">
        {selectedLead ? (
          <div className="rounded-md border border-primary/20 bg-primary/4 px-3 py-3">
            <div className="flex items-center gap-2 text-[10px] font-medium uppercase tracking-widest text-primary">
              <Target className="size-3" />
              Targeting lead
            </div>
            <div className="mt-1 truncate font-mono text-xs text-foreground">{selectedLead.file}</div>
            <div className="text-[11px] text-muted-foreground">
              lines {selectedLead.start_line}–{selectedLead.end_line} · {formatScore(selectedLead.confidence)}
              {selectedLead.top_cwe ? ` · ${selectedLead.top_cwe}` : ""}
            </div>
          </div>
        ) : null}

        {cards.length === 0 ? (
          <CardEmpty>Waiting for 0sec hunt events…</CardEmpty>
        ) : (
          <div className="max-h-[36rem] space-y-2 overflow-y-auto pr-1">
            {cards.map((card) => (
              <HuntCardView
                key={card.id}
                card={card}
                baseTs={baseTs}
                highlightLead={selectedLeadId !== null && card.citedLeadId === selectedLeadId}
                onClick={() => onCardClick(card)}
              />
            ))}
          </div>
        )}

        <div className="mt-auto pt-2">
          <Button asChild variant="ghost" size="sm">
            <NavLink to="/threads">Open thread console</NavLink>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function HuntCardView({
  card,
  baseTs,
  highlightLead,
  onClick,
}: {
  card: HuntCard;
  baseTs: number | null;
  highlightLead: boolean;
  onClick: () => void;
}) {
  const event = card.event;
  const interactive = card.citedLeadId !== null;
  const sharedClass = cn(
    "block w-full rounded-md border px-3 py-3 text-left transition-colors",
    highlightLead
      ? "border-primary/40 bg-primary/8 ring-1 ring-primary/30"
      : interactive
        ? "border-border bg-background hover:border-primary/20 hover:bg-primary/4 cursor-pointer"
        : "border-border bg-background",
  );

  const body =
    event.kind === "tool_use" ? <ToolUseBody event={event} /> :
    event.kind === "finding" ? <FindingBody event={event} /> :
    <StageBody event={event} />;

  const footer = (
    <div className="mt-2 flex items-center justify-between text-[10px] text-muted-foreground">
      <span>{formatRelativeTs(card.ts, baseTs)}</span>
      {interactive ? (
        <span className="flex items-center gap-1 text-primary">
          <ArrowRight className="size-3" />
          {highlightLead ? "linked to selected lead" : "click to highlight lead"}
        </span>
      ) : null}
    </div>
  );

  if (interactive) {
    return (
      <button type="button" onClick={onClick} className={sharedClass}>
        {body}
        {footer}
      </button>
    );
  }
  return <div className={sharedClass}>{body}{footer}</div>;
}

function ToolUseBody({ event }: { event: Extract<osecHuntEvent, { kind: "tool_use" }> }) {
  const statusVariant: "success" | "danger" | "warning" =
    event.status === "ok" ? "success" : event.status === "error" ? "danger" : "warning";
  return (
    <div className="space-y-1">
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <Terminal className="size-3.5 shrink-0 text-primary" />
          <span className="truncate text-sm font-medium text-foreground">{event.tool}</span>
          {typeof event.turn === "number" ? (
            <span className="font-mono text-[10px] text-muted-foreground">turn {event.turn}</span>
          ) : null}
        </div>
        <Badge variant={statusVariant}>{event.status ?? "running"}</Badge>
      </div>
      {event.args_preview ? (
        <div className="truncate font-mono text-[11px] text-muted-foreground" title={event.args_preview}>
          {event.args_preview}
        </div>
      ) : null}
      {event.file ? (
        <div className="font-mono text-[11px] text-primary">
          {event.file}{typeof event.line === "number" ? `:${event.line}` : ""}
        </div>
      ) : null}
    </div>
  );
}

function FindingBody({ event }: { event: Extract<osecHuntEvent, { kind: "finding" }> }) {
  return (
    <div className="space-y-1">
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <AlertTriangle className="size-3.5 shrink-0 text-destructive" />
          <span className="truncate text-sm font-medium text-foreground">{event.title}</span>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          {event.severity ? <Badge variant={severityVariant(event.severity)}>{event.severity}</Badge> : null}
          {typeof event.confidence === "number" ? (
            <Badge variant="accent" className="font-mono">{formatScore(event.confidence)}</Badge>
          ) : null}
        </div>
      </div>
      {event.category ? (
        <div className="text-[11px] text-muted-foreground">{event.category}</div>
      ) : null}
      {event.file ? (
        <div className="font-mono text-[11px] text-primary">
          {event.file}{typeof event.line === "number" ? `:${event.line}` : ""}
        </div>
      ) : null}
    </div>
  );
}

function StageBody({ event }: { event: Extract<osecHuntEvent, { kind: "stage" }> }) {
  const variant = event.transition === "completed" ? "success" : "neutral";
  return (
    <div className="space-y-1">
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <ChevronDown className="size-3.5 shrink-0 text-muted-foreground" />
          <span className="truncate text-sm font-medium text-foreground">{event.stage}</span>
          {event.role ? <Badge variant="neutral">{event.role}</Badge> : null}
        </div>
        <Badge variant={variant}>{event.transition}</Badge>
      </div>
      {typeof event.duration_ms === "number" && event.duration_ms > 0 ? (
        <div className="font-mono text-[11px] text-muted-foreground">
          {event.duration_ms}ms
        </div>
      ) : null}
    </div>
  );
}
