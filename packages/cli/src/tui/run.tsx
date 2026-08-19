/** @jsxImportSource @opentui/react */
import { appendFileSync } from "node:fs";
import React, { useEffect, useMemo, useState } from "react";
import { createCliRenderer } from "@opentui/core";
import { createRoot, useKeyboard } from "@opentui/react";
import { VERSION, type FindingTriageStatus } from "@pwnkit/shared";
import { getRuntimeAvailability } from "../utils.js";
import {
  ACCENT,
  CANVAS,
  BORDER,
  ERROR,
  INFO,
  MUTED,
  PANEL,
  PANEL_ALT,
  PRIMARY,
  SUCCESS,
  TEXT,
  WARNING,
  severityTone,
} from "../ui/theme.js";
import { fitTuiText, fitTuiUrl } from "./text.js";
import {
  applySessionEvent,
  applySessionReport,
  createInitialSessionState,
  type SessionEvent,
  type SessionMode,
  type SessionState,
  type TranscriptItem,
} from "./session-state.js";

type HomeAction = "scan" | "audit" | "review" | "tui" | "doctor" | "replay" | "history" | "findings";
type LaunchRuntime = "auto" | "api" | "claude" | "codex" | "gemini";
type LaunchDepth = "quick" | "default" | "deep";
type LaunchScanMode = "auto" | "probe" | "deep" | "mcp" | "web";
type LaunchEcosystem = "npm" | "pypi" | "cargo" | "oci";

export interface HomeSelection {
  action: HomeAction;
  target?: string;
  runtime?: LaunchRuntime;
  depth?: LaunchDepth;
  mode?: LaunchScanMode;
  ecosystem?: LaunchEcosystem;
}

interface HistorySelection {
  action: "replay";
  scanId: string;
}

type ConsoleRoute =
  | { type: "launcher" }
  | { type: "ops"; dbPath?: string; refreshMs: number }
  | { type: "doctor" }
  | { type: "history"; dbPath?: string; limit: number }
  | { type: "findings"; options: FindingsScreenOptions }
  | { type: "replay"; dbPath?: string; scanId?: string }
  | { type: "session"; initialState: SessionState; subscribe: (listener: (state: SessionState) => void) => () => void; queueUserMessage?: (text: string) => void; onClose: () => void };

interface ShellNav {
  canGoBack: boolean;
  canGoForward: boolean;
  goBack: () => void;
  goForward: () => void;
  openLauncher: () => void;
  openOps: () => void;
  openDoctor: () => void;
  openHistory: () => void;
  openFindings: () => void;
  openReplay: (scanId?: string) => void;
}

interface HomeOption {
  value: HomeAction;
  label: string;
  hint: string;
}

const HOME_OPTIONS: HomeOption[] = [
  { value: "scan", label: "Scan a target", hint: "Web, API, or MCP target" },
  { value: "audit", label: "Audit a package", hint: "Registry package triage" },
  { value: "review", label: "Review a codebase", hint: "Source review and agent analysis" },
  { value: "tui", label: "Open mission control", hint: "Runs, findings, incidents" },
  { value: "doctor", label: "Check runtimes", hint: "Verify model access" },
  { value: "replay", label: "Replay last scan", hint: "Animated playback" },
  { value: "history", label: "View history", hint: "Recent results and artifacts" },
  { value: "findings", label: "Browse findings", hint: "Grouped findings and triage context" },
];

const RUNTIME_OPTIONS: LaunchRuntime[] = ["auto", "api", "claude", "codex", "gemini"];
const DEPTH_OPTIONS: LaunchDepth[] = ["quick", "default", "deep"];
const SCAN_MODE_OPTIONS: LaunchScanMode[] = ["auto", "web", "probe", "deep", "mcp"];
const ECOSYSTEM_OPTIONS: LaunchEcosystem[] = ["npm", "pypi", "cargo", "oci"];

function appendTuiTrace(record: Record<string, unknown>): void {
  const file = process.env.PWNKIT_TRACE_TUI_EVENTS;
  if (!file) return;
  try {
    appendFileSync(file, `${JSON.stringify({ ts: new Date().toISOString(), ...record })}\n`, "utf8");
  } catch {
    // best-effort only
  }
}

function serializeError(error: unknown): Record<string, unknown> {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack,
    };
  }
  return { value: String(error) };
}

function appendTuiCrash(record: Record<string, unknown>): void {
  const file = process.env.PWNKIT_TRACE_TUI_EVENTS ?? "/tmp/pwnkit-tui-crashes.ndjson";
  try {
    appendFileSync(file, `${JSON.stringify({ ts: new Date().toISOString(), kind: "tui-crash", ...record })}\n`, "utf8");
  } catch {
    // best-effort only
  }
}

let crashHandlersInstalled = false;

function installTuiCrashHandlers(): void {
  if (crashHandlersInstalled) return;
  crashHandlersInstalled = true;

  process.on("uncaughtExceptionMonitor", (error, origin) => {
    appendTuiCrash({
      source: "uncaughtExceptionMonitor",
      origin,
      error: serializeError(error),
    });
  });

  process.on("unhandledRejection", (reason) => {
    appendTuiCrash({
      source: "unhandledRejection",
      error: serializeError(reason),
    });
  });
}

class TuiErrorBoundary extends React.Component<{ children: React.ReactNode }, { error: string | null }> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error: Error): { error: string } {
    return { error: error.message || "unknown TUI error" };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo): void {
    appendTuiCrash({
      source: "react-error-boundary",
      error: serializeError(error),
      componentStack: info.componentStack,
    });
  }

  render() {
    if (this.state.error) {
      return (
        <ShellFrame view="crash">
          <box flexDirection="column">
            <text fg={ERROR}>TUI crashed while rendering the current screen.</text>
            <text fg={MUTED}>{fitTuiText(this.state.error, 96)}</text>
            <text fg={MUTED}>Trace file: {process.env.PWNKIT_TRACE_TUI_EVENTS ?? "/tmp/pwnkit-tui-crashes.ndjson"}</text>
          </box>
        </ShellFrame>
      );
    }

    return this.props.children;
  }
}

interface OpsSnapshot {
  scans: Array<{ id: string; target: string; status: string; mode: string; depth: string; runtime: string; durationMs?: number | null; summary?: string | null }>;
  findings: Array<{ id: string; title: string; severity: string; category: string; scanId: string }>;
  incidents: Array<{ scanId: string; target: string; stage: string; headline: string }>;
}

interface HistoryScanRow {
  id: string;
  target: string;
  status: string;
  mode: string;
  depth: string;
  runtime: string;
  startedAt: string;
  durationMs?: number | null;
  summary?: string | null;
}

interface FindingsRow {
  id: string;
  scanId: string;
  title: string;
  severity: string;
  category: string;
  status: string;
  fingerprint?: string | null;
  triageStatus?: string | null;
  triageNote?: string | null;
  timestamp: number;
  score?: number | null;
  templateId: string;
  description: string;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis?: string | null;
}

interface FindingsScreenOptions {
  dbPath?: string;
  scan?: string;
  severity?: string;
  category?: string;
  status?: string;
  triage?: string;
  limit: number;
  all?: boolean;
}

interface FindingGroup {
  fingerprint: string;
  latest: FindingsRow;
  count: number;
  scans: number;
}

interface DoctorState {
  nodeOk: boolean;
  nodeVersion: string;
  hasApiKey: boolean;
  availableRuntimes: string[];
  apiRuntime: Awaited<ReturnType<typeof getRuntimeAvailability>>["apiRuntime"];
}

interface ReplayScanRow {
  id: string;
  target: string;
  status: string;
  mode: string;
  depth: string;
  runtime: string;
  durationMs?: number | null;
  summary?: string | null;
  startedAt: string;
}

interface ReplayEventRow {
  id: string;
  stage: string;
  eventType: string;
  payload: string;
  timestamp: number;
}

interface PaletteCommand {
  id: string;
  title: string;
  category: string;
  description: string;
  keybind?: string;
  suggested?: boolean;
  action: () => void;
}

function isImmediateAction(value: HomeAction): boolean {
  return value === "tui" || value === "doctor" || value === "replay" || value === "history" || value === "findings";
}

function formatDuration(ms?: number | null): string {
  if (!ms || ms <= 0) return "-";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function parseSummary(summary?: string | null): { totalFindings?: number } {
  if (!summary) return {};
  try {
    return JSON.parse(summary) as { totalFindings?: number };
  } catch {
    return {};
  }
}

function groupFindings(rows: FindingsRow[]): FindingGroup[] {
  const groups = new Map<string, FindingsRow[]>();
  for (const row of rows) {
    const key = row.fingerprint ?? row.id;
    const list = groups.get(key) ?? [];
    list.push(row);
    groups.set(key, list);
  }

  return [...groups.entries()]
    .map(([fingerprint, items]) => {
      const sorted = items.sort((a, b) => b.timestamp - a.timestamp);
      return {
        fingerprint,
        latest: sorted[0],
        count: sorted.length,
        scans: new Set(sorted.map((item) => item.scanId)).size,
      };
    })
    .sort((a, b) => b.latest.timestamp - a.latest.timestamp);
}

function cycleChoice<T extends string>(items: readonly T[], current: T, delta: 1 | -1): T {
  const index = items.indexOf(current);
  const next = index < 0 ? 0 : (index + delta + items.length) % items.length;
  return items[next];
}

function describeEventPayload(payload: string): string {
  try {
    const parsed = JSON.parse(payload) as Record<string, unknown>;
    if (typeof parsed.summary === "string") return fitTuiText(parsed.summary, 120);
    if (typeof parsed.message === "string") return fitTuiText(parsed.message, 120);
    if (typeof parsed.error === "string") return fitTuiText(parsed.error, 120);
    if (typeof parsed.action === "string") return fitTuiText(parsed.action, 120);
    if (typeof parsed.target === "string") return fitTuiUrl(parsed.target, 120);
  } catch {
    // fall through
  }
  return fitTuiText(payload, 120);
}

function createShellCommands(shell?: ShellNav): PaletteCommand[] {
  if (!shell) return [];
  return [
    {
      id: "nav-launcher",
      title: "Open launcher",
      category: "Navigate",
      description: "Go to the launcher home screen",
      keybind: "1",
      suggested: true,
      action: shell.openLauncher,
    },
    {
      id: "nav-ops",
      title: "Open mission control",
      category: "Navigate",
      description: "Go to the operations overview",
      keybind: "2",
      suggested: true,
      action: shell.openOps,
    },
    {
      id: "nav-history",
      title: "Open history",
      category: "Navigate",
      description: "Browse previous scans",
      keybind: "3",
      suggested: true,
      action: shell.openHistory,
    },
    {
      id: "nav-findings",
      title: "Open findings",
      category: "Navigate",
      description: "Browse finding families and triage state",
      keybind: "4",
      suggested: true,
      action: shell.openFindings,
    },
    {
      id: "nav-doctor",
      title: "Open doctor",
      category: "Navigate",
      description: "Inspect runtime readiness",
      keybind: "5",
      suggested: true,
      action: shell.openDoctor,
    },
    {
      id: "nav-replay",
      title: "Open latest replay",
      category: "Navigate",
      description: "Review the most recent scan replay",
      keybind: "6",
      suggested: true,
      action: () => shell.openReplay(),
    },
    {
      id: "nav-back",
      title: "Go back",
      category: "Navigate",
      description: "Return to the previous console route",
      keybind: "[",
      suggested: true,
      action: shell.goBack,
    },
    {
      id: "nav-forward",
      title: "Go forward",
      category: "Navigate",
      description: "Move to the next console route",
      keybind: "]",
      suggested: true,
      action: shell.goForward,
    },
  ];
}

function describeFindingsFilters(options: FindingsScreenOptions): string {
  const filters = [
    options.scan ? `scan:${options.scan}` : null,
    options.severity ? `severity:${options.severity}` : null,
    options.category ? `category:${options.category}` : null,
    options.status ? `status:${options.status}` : null,
    options.triage ? `triage:${options.triage}` : null,
  ].filter(Boolean);
  return filters.length > 0 ? filters.join(" · ") : "all findings";
}

function filterCommands(commands: PaletteCommand[], query: string): PaletteCommand[] {
  const q = query.trim().toLowerCase();
  if (!q) return commands;
  return commands.filter((command) => `${command.title} ${command.category} ${command.description}`.toLowerCase().includes(q));
}

function usePaletteController(commands: PaletteCommand[]) {
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState("");
  const [paletteSelected, setPaletteSelected] = useState(0);

  const filteredPalette = useMemo(() => {
    const base = paletteQuery.trim() ? commands : commands.filter((command) => command.suggested);
    return filterCommands(base, paletteQuery);
  }, [commands, paletteQuery]);

  const handlePaletteKey = (key: { ctrl?: boolean; meta?: boolean; name?: string; sequence?: string }): boolean => {
    if (key.ctrl && (key.name === "p" || key.name === "k")) {
      setPaletteOpen((current) => !current);
      setPaletteQuery("");
      setPaletteSelected(0);
      return true;
    }

    if (!paletteOpen) return false;

    if (key.name === "escape") {
      setPaletteOpen(false);
      setPaletteQuery("");
      setPaletteSelected(0);
      return true;
    }
    if (key.name === "up") {
      setPaletteSelected((current) => Math.max(0, current - 1));
      return true;
    }
    if (key.name === "down") {
      setPaletteSelected((current) => Math.min(Math.max(filteredPalette.length - 1, 0), current + 1));
      return true;
    }
    if (key.name === "return") {
      filteredPalette[paletteSelected]?.action();
      setPaletteOpen(false);
      return true;
    }
    if (key.name === "backspace") {
      setPaletteQuery((current) => current.slice(0, -1));
      return true;
    }
    if (key.sequence && !key.ctrl && !key.meta && key.name !== "return") {
      setPaletteQuery((current) => current + key.sequence);
      setPaletteSelected(0);
      return true;
    }
    return true;
  };

  return {
    paletteOpen,
    paletteQuery,
    paletteSelected,
    filteredPalette,
    handlePaletteKey,
  };
}

function OverlayFrame({
  title,
  footer,
  children,
}: {
  title: string;
  footer: string;
  children: React.ReactNode;
}) {
  return (
    <box position="absolute" top="12%" left="18%" width="64%" border borderColor={PRIMARY} backgroundColor={PANEL_ALT} paddingX={1} paddingY={0} zIndex={10}>
      <box flexDirection="column" width="100%">
        <text fg={PRIMARY}>{fitTuiText(title, 54)}</text>
        {children}
        <text fg={MUTED}>{fitTuiText(footer, 64)}</text>
      </box>
    </box>
  );
}

function PaletteOverlay({
  title,
  query,
  selected,
  commands,
}: {
  title: string;
  query: string;
  selected: number;
  commands: PaletteCommand[];
}) {
  return (
    <OverlayFrame title={title} footer="ctrl+p close · enter run · esc cancel">
        <box flexDirection="row">
          <text fg={MUTED}>query </text>
          <text fg={TEXT}>{fitTuiText(query || "type to filter commands", 56)}</text>
          <text fg={INFO}>█</text>
        </box>
        {commands.slice(0, 8).map((command, index) => {
          const active = index === selected;
          return (
            <box key={command.id} flexDirection="row">
              <RailBar tone={active ? PRIMARY : BORDER} />
              <box flexDirection="column" marginLeft={1} width="100%">
                <box justifyContent="space-between">
                  <text fg={active ? TEXT : "#CCCCCC"}>{fitTuiText(command.title, 42)}</text>
                  <text fg={MUTED}>{fitTuiText(command.keybind ?? command.category, 16)}</text>
                </box>
                <text fg={active ? ACCENT : MUTED}>{fitTuiText(command.description, 64)}</text>
              </box>
            </box>
          );
        })}
    </OverlayFrame>
  );
}

function parseToolAction(action: string): {
  kind: "http" | "crawl" | "bash" | "save" | "read" | "run" | "install" | "summary" | "generic";
  title: string;
  meta?: string;
  tone: string;
} {
  if (action.startsWith("http_request:")) {
    const rest = action.slice("http_request:".length).trim();
    const parts = rest.split(/\s+/);
    const method = parts[0] ?? "GET";
    const url = parts.slice(1).join(" ");
    return {
      kind: "http",
      title: `${method} ${url || "request"}`,
      meta: "http request",
      tone: PRIMARY,
    };
  }
  if (action.startsWith("crawl:")) {
    return {
      kind: "crawl",
      title: action.slice("crawl:".length).trim() || "crawl",
      meta: "crawl",
      tone: PRIMARY,
    };
  }
  if (action.startsWith("bash:")) {
    return {
      kind: "bash",
      title: action.slice("bash:".length).trim() || "shell",
      meta: "shell",
      tone: PRIMARY,
    };
  }
  if (action.startsWith("save_finding:")) {
    return {
      kind: "save",
      title: action.slice("save_finding:".length).trim() || "saved finding",
      meta: "finding",
      tone: SUCCESS,
    };
  }
  if (action.startsWith("read_file:")) {
    return {
      kind: "read",
      title: action.slice("read_file:".length).trim() || "source file",
      meta: "reading source",
      tone: INFO,
    };
  }
  if (action.startsWith("run_command:")) {
    return {
      kind: "run",
      title: action.slice("run_command:".length).trim() || "command",
      meta: "running command",
      tone: PRIMARY,
    };
  }
  if (action.startsWith("Reading ")) {
    return {
      kind: "read",
      title: action.slice("Reading ".length).trim() || "source file",
      meta: "reading source",
      tone: INFO,
    };
  }
  if (action.startsWith("Running: ")) {
    return {
      kind: "run",
      title: action.slice("Running: ".length).trim() || "command",
      meta: "running command",
      tone: PRIMARY,
    };
  }
  if (action.startsWith("Installing ") || action.startsWith("Installed ")) {
    return {
      kind: "install",
      title: action,
      meta: "preparing package",
      tone: ACCENT,
    };
  }
  if (action.startsWith("Target ready:") || action.startsWith("Analysis complete:") || action.startsWith("done:")) {
    return {
      kind: "summary",
      title: action,
      meta: "stage summary",
      tone: MUTED,
    };
  }
  return {
      kind: "generic",
      title: action,
      meta: undefined,
      tone: TEXT,
    };
}

function renderToolActionLine(action: string, key: string) {
  const parsed = parseToolAction(action);
  return (
    <box key={key} flexDirection="row">
      <text fg={parsed.tone}>•</text>
      <box flexDirection="column" marginLeft={1}>
        <text fg={parsed.tone}>{fitTuiText(parsed.title, 96)}</text>
        {parsed.meta ? <text fg={MUTED}>{fitTuiText(parsed.meta, 32)}</text> : null}
      </box>
    </box>
  );
}

function TimelineOverlay({
  selected,
  turns,
}: {
  selected: number;
  turns: TranscriptItem[];
}) {
  return (
    <OverlayFrame title="TURN TIMELINE" footer="ctrl+j close · enter jump · esc cancel">
        {turns.slice(0, 10).map((turn, index) => {
          const active = index === selected;
          return (
            <box key={turn.id} flexDirection="row">
              <RailBar tone={active ? PRIMARY : BORDER} />
              <box flexDirection="column" marginLeft={1}>
                <text fg={active ? TEXT : "#CCCCCC"}>{fitTuiText(turn.text, 46)}</text>
                <text fg={active ? ACCENT : MUTED}>{fitTuiText(`${turn.stage ?? "session"}${turn.turn !== undefined ? ` · turn ${turn.turn}` : ""}`, 46)}</text>
              </box>
            </box>
          );
        })}
    </OverlayFrame>
  );
}

function ComposeOverlay({ text }: { text: string }) {
  return (
    <OverlayFrame title="MESSAGE TO AGENT" footer="enter send · esc cancel">
      <text fg={MUTED}>will be injected at next turn boundary</text>
      <box flexDirection="row" marginTop={1}>
        <text fg={PRIMARY}>&gt; </text>
        <text fg={TEXT}>{fitTuiText(text || " ", 84)}</text>
        <text fg={INFO}>█</text>
      </box>
    </OverlayFrame>
  );
}

const BRAND_WORD_FRAMES = [
  "pwnkit",
  "pwnkit",
  "pwnk1t",
  "pwnkit",
  "pwnk!t",
  "pwnkit",
  "pw_nit",
  "pwnkit",
  "pwnkit",
  "pwnkit",
];

function useAnimatedBrand(enabled: boolean) {
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    if (!enabled) {
      setFrame(0);
      return;
    }

    const timer = setInterval(() => {
      setFrame((current) => (current + 1) % BRAND_WORD_FRAMES.length);
    }, 260);

    return () => clearInterval(timer);
  }, [enabled]);

  return {
    frame,
    word: BRAND_WORD_FRAMES[frame],
  };
}

function BrandSignature({
  muted = false,
  subtitle,
  animated = false,
}: {
  muted?: boolean;
  subtitle?: string;
  animated?: boolean;
}) {
  const brand = useAnimatedBrand(animated && !muted);

  return (
    <box flexDirection="column" alignItems="flex-end">
      <box flexDirection="row">
        <text fg={muted ? MUTED : PRIMARY}>{animated && !muted ? brand.word : "pwnkit"}</text>
        <text fg={MUTED}>{` v${VERSION}`}</text>
      </box>
      {subtitle ? <text fg={MUTED}>{fitTuiText(subtitle, 36)}</text> : null}
    </box>
  );
}

function BrandStamp({ animated = false }: { animated?: boolean }) {
  const brand = useAnimatedBrand(animated);

  return (
    <box flexDirection="row">
      <text fg={MUTED}>{animated ? brand.word : "pwnkit"}</text>
      <text fg={MUTED}>{` v${VERSION}`}</text>
    </box>
  );
}

function RailBar({ tone }: { tone: string }) {
  return <box width={1} alignSelf="stretch" backgroundColor={tone} />;
}

function HeaderBar({
  view,
  status,
}: {
  view: string;
  status?: React.ReactNode;
}) {
  return (
    <box border borderColor={BORDER} backgroundColor={PANEL} paddingX={1} paddingY={0} marginBottom={1}>
      <box flexDirection="column" width="100%">
        <box flexDirection="row" justifyContent="space-between" width="100%">
          <text fg={TEXT}>PWNKIT TUI CONSOLE</text>
          <text fg={PRIMARY}>{fitTuiText(view.toUpperCase(), 28)}</text>
        </box>
        <box flexDirection="row" justifyContent="space-between" width="100%">
          <text fg={MUTED}>{fitTuiText("Launch targets, monitor sessions, and review findings.", 68)}</text>
          {status ? <box>{typeof status === "string" ? <text fg={MUTED}>{fitTuiText(status, 36)}</text> : status}</box> : null}
        </box>
      </box>
    </box>
  );
}

function FooterBar({ hint, status }: { hint: string; status?: React.ReactNode }) {
  return (
    <box flexDirection="row" justifyContent="space-between">
      <text fg={MUTED}>{fitTuiText(hint, 72)}</text>
      <box flexDirection="row">
        {status ? <box marginRight={2}>{typeof status === "string" ? <text fg={MUTED}>{fitTuiText(status, 36)}</text> : status}</box> : null}
        <BrandStamp animated />
      </box>
    </box>
  );
}

function LiveBadge({ label, active = true }: { label: string; active?: boolean }) {
  return (
    <box flexDirection="row">
      <text fg={active ? SUCCESS : MUTED}>●</text>
      <text fg={MUTED}> {label}</text>
    </box>
  );
}

function ShimmerLabel({ text }: { text: string }) {
  const [frame, setFrame] = useState(0);
  const chars = useMemo(() => Array.from(text), [text]);
  const padding = 10;

  useEffect(() => {
    const timer = setInterval(() => {
      setFrame((current) => (current + 1) % Math.max(chars.length + padding * 2, 1));
    }, 90);
    return () => clearInterval(timer);
  }, [chars.length]);

  return (
    <box flexDirection="row">
      {chars.map((char, index) => {
        const center = frame - padding;
        const distance = Math.abs(index - center);
        const fg = distance < 1.5 ? ACCENT : distance < 3.5 ? TEXT : MUTED;
        return <text key={`${index}-${char}`} fg={fg}>{char}</text>;
      })}
    </box>
  );
}

function WorkingPulse({ label, detail }: { label: string; detail?: string }) {
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setFrame((current) => (current + 1) % 6);
    }, 120);
    return () => clearInterval(timer);
  }, []);

  const loader = ["[   ]", "[=  ]", "[== ]", "[===]", "[ ==]", "[  =]"][frame] ?? "[   ]";

  return (
    <box flexDirection="row" marginTop={1}>
      <RailBar tone={PRIMARY} />
      <box flexDirection="column" marginLeft={1} backgroundColor={PANEL_ALT} paddingX={1} width="100%">
        <box flexDirection="row">
          <text fg={ACCENT}>{loader}</text>
          <box marginLeft={1}>
            <ShimmerLabel text={fitTuiText(label, 42)} />
          </box>
        </box>
        {detail ? <text fg={MUTED}>{fitTuiText(detail, 96)}</text> : null}
      </box>
    </box>
  );
}

function formatLiveActivity(state: SessionState, runningStage: SessionState["stages"][number] | null, latestRunningAction?: string): {
  label: string;
  detail?: string;
} {
  if (state.thinking) {
    return {
      label: "thinking",
      detail: state.thinking,
    };
  }

  const liveTool = formatActiveToolLabel(latestRunningAction);
  return {
    label: liveTool.label,
    detail: latestRunningAction ? liveTool.detail : (runningStage?.detail ?? "waiting for the next tool result"),
  };
}

function formatActiveToolLabel(action?: string): { label: string; detail?: string } {
  if (!action) return { label: "agent working", detail: "waiting for the next tool result" };

  const parsed = parseToolAction(action);
  switch (parsed.kind) {
    case "http":
      return { label: "http request in flight", detail: parsed.title };
    case "crawl":
      return { label: "crawl in progress", detail: parsed.title };
    case "bash":
      return { label: "shell tool running", detail: parsed.title };
    case "save":
      return { label: "saving finding", detail: parsed.title };
    case "read":
      return { label: "reading source", detail: parsed.title };
    case "run":
      return { label: "running command", detail: parsed.title };
    case "install":
      return { label: "preparing target", detail: parsed.title };
    case "summary":
      return { label: "stage update", detail: parsed.title };
    default:
      return { label: "tool call in progress", detail: parsed.title };
  }
}

function railTone(item: TranscriptItem): string {
  switch (item.tone) {
    case "primary": return PRIMARY;
    case "success": return SUCCESS;
    case "warning": return WARNING;
    case "error": return ERROR;
    case "info": return INFO;
    default: return BORDER;
  }
}

function textTone(item: TranscriptItem): string {
  switch (item.tone) {
    case "primary": return TEXT;
    case "success": return SUCCESS;
    case "warning": return WARNING;
    case "error": return ERROR;
    case "info": return INFO;
    default: return item.kind === "finding" ? PRIMARY : item.kind === "thinking" ? MUTED : TEXT;
  }
}

function renderTranscriptItem(
  item: TranscriptItem,
  options: {
    expanded: Set<string>;
    toggleExpanded: (id: string) => void;
    hoveredToolId: string | null;
    setHoveredToolId: (id: string | null) => void;
  },
) {
  if (item.kind === "turn") {
    return (
      <box key={item.id} flexDirection="row" marginTop={1}>
        <RailBar tone={PRIMARY} />
        <box flexDirection="column" marginLeft={1} backgroundColor={PANEL_ALT} paddingX={1} width="100%">
          <text fg={TEXT}>{fitTuiText(item.text.toUpperCase(), 84)}</text>
          <text fg={MUTED}>{fitTuiText(`${item.stage ?? "session"}${item.turn !== undefined ? ` · operator turn ${item.turn}` : ""}`, 84)}</text>
        </box>
      </box>
    );
  }

  if (item.kind === "tool-group") {
    const actions = item.actions ?? [];
    const preview = actions.slice(0, Math.min(actions.length, 2));
    const isExpandable = actions.length > preview.length;
    const isExpanded = isExpandable && options.expanded.has(item.id);
    const isHovered = isExpandable && options.hoveredToolId === item.id;
    return (
      <box key={item.id} flexDirection="row">
        <RailBar tone={isHovered ? PRIMARY : railTone(item)} />
        <box
          flexDirection="column"
          marginLeft={1}
          backgroundColor={isHovered ? PANEL : PANEL_ALT}
          border
          borderColor={isHovered || isExpanded ? PRIMARY : BORDER}
          paddingX={1}
          paddingY={0}
          width="100%"
          onMouseDown={isExpandable ? () => options.toggleExpanded(item.id) : undefined}
          onMouseOver={isExpandable ? () => options.setHoveredToolId(item.id) : undefined}
          onMouseOut={isExpandable ? () => options.setHoveredToolId(null) : undefined}
        >
          <box justifyContent="space-between">
            <text fg={isHovered ? PRIMARY : TEXT}>{fitTuiText((item.label ?? "Actions").toUpperCase(), 48)}</text>
            <text fg={isExpandable ? (isHovered ? ACCENT : MUTED) : MUTED}>
              {isExpandable ? (isExpanded ? "click to collapse" : "click to expand") : ""}
            </text>
          </box>
          <text fg={MUTED}>{fitTuiText(`${item.stage}${item.turn !== undefined ? ` · turn ${item.turn}` : ""}`, 48)}</text>
          <text fg={MUTED}>{fitTuiText(item.text, 96)}</text>
          {(isExpanded ? actions : preview).map((action, index) => renderToolActionLine(action, `${item.id}-${index}`))}
          {isExpandable && !isExpanded ? <text fg={MUTED}>{`${actions.length - preview.length} more hidden`}</text> : null}
        </box>
      </box>
    );
  }

  if (item.kind === "user-inject") {
    return (
      <box key={item.id} flexDirection="row">
        <RailBar tone={ACCENT} />
        <box flexDirection="column" marginLeft={1}>
          <text fg={ACCENT}>USER MESSAGE INJECTED</text>
          <text fg={TEXT}>{fitTuiText(item.text, 96)}</text>
        </box>
      </box>
    );
  }

  return (
    <box key={item.id} flexDirection="row">
      <RailBar tone={railTone(item)} />
      <box flexDirection="column" marginLeft={1}>
        {item.stage ? <text fg={MUTED}>{fitTuiText(item.stage, 32)}</text> : null}
        <text fg={textTone(item)}>{fitTuiText(item.text, 96)}</text>
      </box>
    </box>
  );
}

function PanelSection({
  title,
  tone,
  children,
}: {
  title: string;
  tone: string;
  children: React.ReactNode;
}) {
  return (
    <box flexDirection="column" border borderColor={tone} backgroundColor={PANEL} paddingX={1} paddingY={0}>
      <text fg={tone}>{fitTuiText(title.toUpperCase(), 44)}</text>
      <box flexDirection="column">
        {children}
      </box>
    </box>
  );
}

function ShellFrame({
  view,
  status,
  meta,
  children,
}: {
  view: string;
  status?: React.ReactNode;
  meta?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <box flexDirection="column" width="100%" height="100%" paddingLeft={2} paddingRight={2} paddingTop={1} backgroundColor={CANVAS}>
      <HeaderBar view={view} status={status ?? meta} />
      {children}
    </box>
  );
}

function HomeScreen({ onResolve, onExit }: { onResolve: (selection: HomeSelection) => void; onExit: () => void }) {
  const [phase, setPhase] = useState<"menu" | "compose">("menu");
  const [selected, setSelected] = useState(0);
  const [action, setAction] = useState<HomeAction>("scan");
  const [inputValue, setInputValue] = useState("");
  const [focusIndex, setFocusIndex] = useState(0);
  const [runtime, setRuntime] = useState<LaunchRuntime>("auto");
  const [depth, setDepth] = useState<LaunchDepth>("default");
  const [scanMode, setScanMode] = useState<LaunchScanMode>("auto");
  const [ecosystem, setEcosystem] = useState<LaunchEcosystem>("npm");

  const palette = usePaletteController(HOME_OPTIONS.map((option, index) => ({
    id: option.value,
    title: option.label,
    category: index < 3 ? "Run" : "System",
    description: option.hint,
    keybind: option.value === "tui" ? "tui" : undefined,
    suggested: index < 5,
    action: () => {
      if (isImmediateAction(option.value)) {
        onResolve({ action: option.value });
        return;
      }
      setAction(option.value);
      setInputValue("");
      setFocusIndex(0);
      setRuntime("auto");
      setDepth("default");
      setScanMode("auto");
      setEcosystem("npm");
      setPhase("compose");
    },
  })));

  const composeFields = useMemo(() => {
    const fields: Array<{ key: string; label: string; value: string; editable?: boolean }> = [
      {
        key: "target",
        label: action === "scan"
          ? "Target URL (e.g. app.example.com)"
          : action === "audit"
            ? "Package name (e.g. express)"
            : "Repo path or URL (e.g. ./my-project)",
        value: inputValue,
        editable: true,
      },
      { key: "runtime", label: "Runtime", value: runtime },
      { key: "depth", label: "Depth", value: depth },
    ];
    if (action === "scan") fields.push({ key: "mode", label: "Mode", value: scanMode });
    if (action === "audit") fields.push({ key: "ecosystem", label: "Ecosystem", value: ecosystem });
    return fields;
  }, [action, depth, ecosystem, inputValue, runtime, scanMode]);

  const adjustFocusedOption = (delta: 1 | -1) => {
    const field = composeFields[focusIndex]?.key;
    if (field === "runtime") setRuntime((current) => cycleChoice(RUNTIME_OPTIONS, current, delta));
    if (field === "depth") setDepth((current) => cycleChoice(DEPTH_OPTIONS, current, delta));
    if (field === "mode") setScanMode((current) => cycleChoice(SCAN_MODE_OPTIONS, current, delta));
    if (field === "ecosystem") setEcosystem((current) => cycleChoice(ECOSYSTEM_OPTIONS, current, delta));
  };

  const submitLaunch = () => {
    if (!inputValue.trim()) return;
    onResolve({
      action,
      target: inputValue.trim(),
      runtime,
      depth,
      mode: scanMode,
      ecosystem,
    });
  };

  useKeyboard((key) => {
    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }
    if (palette.handlePaletteKey(key)) return;

    if (key.name === "escape") {
      if (phase === "compose") {
        setPhase("menu");
        setInputValue("");
        setFocusIndex(0);
        return;
      }
      onExit();
      return;
    }

    if (phase === "menu") {
      if (key.name === "up") {
        setSelected((current) => Math.max(0, current - 1));
        return;
      }
      if (key.name === "down") {
        setSelected((current) => Math.min(HOME_OPTIONS.length - 1, current + 1));
        return;
      }
      if (key.name === "return") {
        const nextAction = HOME_OPTIONS[selected].value;
        if (isImmediateAction(nextAction)) {
          onResolve({ action: nextAction });
          return;
        }
        setAction(nextAction);
        setInputValue("");
        setFocusIndex(0);
        setRuntime("auto");
        setDepth("default");
        setScanMode("auto");
        setEcosystem("npm");
        setPhase("compose");
      }
      return;
    }

    if (key.name === "up") {
      setFocusIndex((current) => Math.max(0, current - 1));
      return;
    }
    if (key.name === "down" || key.name === "tab") {
      setFocusIndex((current) => Math.min(composeFields.length - 1, current + 1));
      return;
    }
    if (key.name === "left") {
      adjustFocusedOption(-1);
      return;
    }
    if (key.name === "right") {
      adjustFocusedOption(1);
      return;
    }
    if (key.name === "return") {
      submitLaunch();
      return;
    }
    if (key.name === "backspace") {
      if (composeFields[focusIndex]?.key === "target") {
        setInputValue((current) => current.slice(0, -1));
      }
      return;
    }
    if (composeFields[focusIndex]?.key === "target" && key.sequence && !key.ctrl && !key.meta && key.name !== "return") {
      setInputValue((current) => current + key.sequence);
    }
  });

  return (
    <ShellFrame view="launcher">
      {palette.paletteOpen ? <PaletteOverlay title="Console commands" query={palette.paletteQuery} selected={palette.paletteSelected} commands={palette.filteredPalette} /> : null}
      <box flexDirection="column">
        {phase === "menu" ? (
          <box flexDirection="column" border borderColor={BORDER} backgroundColor={PANEL} paddingX={1} paddingY={0}>
            {HOME_OPTIONS.map((option, index) => {
              const active = index === selected;
              return (
                <box key={option.value} flexDirection="row">
                  <RailBar tone={active ? PRIMARY : BORDER} />
                  <box flexDirection="column" marginLeft={1}>
                    <text fg={active ? TEXT : "#CCCCCC"}>{fitTuiText(active ? option.label.toUpperCase() : option.label, 64)}</text>
                    <text fg={active ? ACCENT : MUTED}>{fitTuiText(option.hint, 64)}</text>
                  </box>
                </box>
              );
            })}
          </box>
        ) : (
          <box flexDirection="column" border borderColor={PRIMARY} backgroundColor={PANEL} paddingX={1} paddingY={0}>
            {composeFields.map((field, fieldIndex) => {
              const active = fieldIndex === focusIndex;
              return (
                <box key={field.key} flexDirection="row">
                  <RailBar tone={active ? PRIMARY : BORDER} />
                  <box flexDirection="column" marginLeft={1} width="100%">
                    <text fg={active ? TEXT : MUTED}>{field.label}</text>
                    <box flexDirection="row" justifyContent="space-between" width="100%">
                      <box flexDirection="row">
                        <text fg={field.value ? (active ? TEXT : "#CCCCCC") : MUTED}>{fitTuiText(field.value || "", 78, { mode: field.key === "target" ? "middle" : "end" })}</text>
                        {active && field.editable ? <text fg={INFO}>█</text> : null}
                      </box>
                      <text fg={active ? ACCENT : MUTED}>{field.editable ? "type" : "left/right"}</text>
                    </box>
                  </box>
                </box>
              );
            })}
            <text fg={MUTED}>enter launch · esc back · ctrl+p commands · up/down focus</text>
          </box>
        )}
        <FooterBar hint="ctrl+p commands and shortcuts" />
      </box>
    </ShellFrame>
  );
}

function OpsScreen({ dbPath, refreshMs, onExit, shell }: { dbPath?: string; refreshMs: number; onExit: () => void; shell?: ShellNav }) {
  const [snapshot, setSnapshot] = useState<OpsSnapshot>({ scans: [], findings: [], incidents: [] });
  const [error, setError] = useState<string | null>(null);
  const palette = usePaletteController([
    {
      id: "close-ops",
      title: "Close mission control",
      category: "System",
      description: "Leave the operator overview",
      keybind: "esc",
      suggested: true,
      action: onExit,
    },
    ...createShellCommands(shell),
  ]);

  useEffect(() => {
    let alive = true;
    const refresh = async () => {
      try {
        const { pwnkitDB } = await import("@pwnkit/db");
        const db = new pwnkitDB(dbPath);
        try {
          const scans = db.listScans(12) as OpsSnapshot["scans"];
          const findings = db.listFindings({ limit: 12 }) as OpsSnapshot["findings"];
          const events = db.listRecentEvents(30) as Array<{ scanId: string; scanTarget?: string; stage: string; eventType: string; payload: string }>;
          const incidents = events
            .filter((event) => ["agent_error", "scan_error", "worker_failed"].includes(event.eventType))
            .slice(0, 6)
            .map((event) => ({ scanId: event.scanId, target: event.scanTarget ?? event.scanId, stage: event.stage, headline: event.payload }));
          if (!alive) return;
          setSnapshot({ scans, findings, incidents });
          setError(null);
        } finally {
          db.close();
        }
      } catch (err) {
        if (!alive) return;
        setError(err instanceof Error ? err.message : String(err));
      }
    };

    void refresh();
    const timer = setInterval(() => void refresh(), refreshMs);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [dbPath, refreshMs]);

  useKeyboard((key) => {
    if (palette.handlePaletteKey(key)) return;
    if ((key.ctrl && key.name === "c") || key.name === "escape" || key.name === "q") {
      onExit();
      return;
    }
    if (shell && key.sequence === "[") {
      shell.goBack();
      return;
    }
    if (shell && key.sequence === "]") {
      shell.goForward();
    }
  });

  return (
    <ShellFrame view="mission control">
      {palette.paletteOpen ? <PaletteOverlay title="Mission control commands" query={palette.paletteQuery} selected={palette.paletteSelected} commands={palette.filteredPalette} /> : null}
      <box flexDirection="row" gap={1} marginBottom={1}>
        <box border borderColor={PRIMARY} backgroundColor={PANEL} paddingX={1}><box><text fg={TEXT}>runs </text><text fg={PRIMARY}>{String(snapshot.scans.length)}</text></box></box>
        <box border borderColor={PRIMARY} backgroundColor={PANEL} paddingX={1}><box><text fg={TEXT}>findings </text><text fg={PRIMARY}>{String(snapshot.findings.length)}</text></box></box>
        <box border borderColor={snapshot.incidents.length > 0 ? ERROR : BORDER} backgroundColor={PANEL} paddingX={1}><box><text fg={TEXT}>incidents </text><text fg={snapshot.incidents.length > 0 ? ERROR : MUTED}>{String(snapshot.incidents.length)}</text></box></box>
      </box>
      {error ? <text fg={ERROR}>{fitTuiText(error, 120)}</text> : null}
      <box flexDirection="row" gap={2} flexGrow={1}>
        <PanelSection title="Recent runs" tone={BORDER}>
          {snapshot.scans.length === 0 ? <text fg={MUTED}>No local scans yet.</text> : snapshot.scans.map((scan) => {
            const summary = parseSummary(scan.summary);
            return (
              <box key={scan.id} flexDirection="column">
                <text fg={TEXT}>{fitTuiUrl(scan.target, 72)}</text>
                <text fg={MUTED}>{scan.mode}/{scan.depth} · {scan.runtime} · {scan.status}</text>
                <text fg={MUTED}>{summary.totalFindings ?? 0} findings · {formatDuration(scan.durationMs)}</text>
              </box>
            );
          })}
        </PanelSection>
        <PanelSection title="Recent incidents" tone={snapshot.incidents.length > 0 ? ERROR : BORDER}>
          {snapshot.incidents.length === 0 ? <text fg={SUCCESS}>No recent runtime incidents.</text> : snapshot.incidents.map((incident, index) => (
            <box key={`${incident.scanId}-${index}`} flexDirection="column">
              <text fg={TEXT}>{fitTuiUrl(incident.target, 72)}</text>
              <text fg={ERROR}>{fitTuiText(incident.headline, 96)}</text>
              <text fg={MUTED}>{fitTuiText(incident.stage, 32)}</text>
            </box>
          ))}
        </PanelSection>
      </box>
      <FooterBar hint="ctrl+p commands and shortcuts" />
    </ShellFrame>
  );
}

function DoctorScreen({ onExit, shell }: { onExit: () => void; shell?: ShellNav }) {
  const [state, setState] = useState<DoctorState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const palette = usePaletteController([
    {
      id: "close-doctor",
      title: "Close doctor",
      category: "System",
      description: "Leave the runtime diagnostics screen",
      keybind: "esc",
      suggested: true,
      action: onExit,
    },
    ...createShellCommands(shell),
  ]);

  useEffect(() => {
    let alive = true;
    void getRuntimeAvailability()
      .then((result) => {
        if (!alive) return;
        const nodeMajor = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
        setState({
          nodeOk: nodeMajor >= 20,
          nodeVersion: process.version,
          ...result,
        });
      })
      .catch((err) => {
        if (!alive) return;
        setError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      alive = false;
    };
  }, []);

  useKeyboard((key) => {
    if (palette.handlePaletteKey(key)) return;
    if ((key.ctrl && key.name === "c") || key.name === "escape" || key.name === "q") {
      onExit();
      return;
    }
    if (shell && key.sequence === "[") {
      shell.goBack();
      return;
    }
    if (shell && key.sequence === "]") {
      shell.goForward();
    }
  });

  const nextStep = !state
    ? "Checking environment"
    : !state.nodeOk
      ? "Upgrade to Node 20+ before running pwnkit."
      : state.apiRuntime.configured && !state.apiRuntime.valid && state.apiRuntime.error
        ? "Repair the configured API runtime before scanning."
        : state.hasApiKey || state.availableRuntimes.length > 0
          ? "Ready to scan. Try scan, review, or audit from the launcher."
          : "Install Claude/Codex/Gemini CLI or set an API key.";

  return (
    <ShellFrame view="doctor">
      {palette.paletteOpen ? <PaletteOverlay title="Doctor commands" query={palette.paletteQuery} selected={palette.paletteSelected} commands={palette.filteredPalette} /> : null}
      <box flexDirection="row" gap={1} marginBottom={1}>
        <box border borderColor={state?.nodeOk ? SUCCESS : ERROR} backgroundColor={PANEL} paddingX={1}><box><text fg={TEXT}>node </text><text fg={state?.nodeOk ? SUCCESS : ERROR}>{state?.nodeVersion ?? "checking"}</text></box></box>
        <box border borderColor={state?.hasApiKey ? SUCCESS : state?.apiRuntime.configured ? ERROR : WARNING} backgroundColor={PANEL} paddingX={1}><box><text fg={TEXT}>api </text><text fg={state?.hasApiKey ? SUCCESS : state?.apiRuntime.configured ? ERROR : WARNING}>{state?.apiRuntime.providerLabel ?? "checking"}</text></box></box>
        <box border borderColor={state && state.availableRuntimes.length > 0 ? SUCCESS : WARNING} backgroundColor={PANEL} paddingX={1}><box><text fg={TEXT}>cli </text><text fg={state && state.availableRuntimes.length > 0 ? SUCCESS : WARNING}>{state ? (state.availableRuntimes.join(", ") || "none") : "checking"}</text></box></box>
      </box>
      {error ? <text fg={ERROR}>{fitTuiText(error, 120)}</text> : null}
      <box flexDirection="row" gap={2} flexGrow={1}>
        <PanelSection title="Environment" tone={BORDER}>
          <box flexDirection="column">
            <text fg={TEXT}>Node.js</text>
            <text fg={MUTED}>{state ? `${state.nodeOk ? "ok" : "bad"} · ${state.nodeVersion}` : "checking"}</text>
            <text fg={TEXT}>API runtime</text>
            <text fg={MUTED}>{fitTuiText(state ? `${state.hasApiKey ? "ok" : state.apiRuntime.configured ? "bad" : "missing"} · ${state.apiRuntime.providerLabel}` : "checking", 68)}</text>
            <text fg={TEXT}>CLI runtimes</text>
            <text fg={MUTED}>{fitTuiText(state ? `${state.availableRuntimes.length > 0 ? "ok" : "missing"} · ${state.availableRuntimes.join(", ") || "none"}` : "checking", 68)}</text>
          </box>
        </PanelSection>
        <PanelSection title="Next steps" tone={PRIMARY}>
          <box flexDirection="column">
            <text fg={TEXT}>{fitTuiText(nextStep, 68)}</text>
            {state?.hasApiKey || (state && state.availableRuntimes.length > 0) ? (
              <>
                <text fg={MUTED}>pwnkit scan --target https://example.com --mode web</text>
                <text fg={MUTED}>pwnkit review .</text>
                <text fg={MUTED}>pwnkit audit express</text>
              </>
            ) : null}
            {state?.apiRuntime.error ? <text fg={ERROR}>{fitTuiText(state.apiRuntime.error, 68)}</text> : null}
          </box>
        </PanelSection>
      </box>
      <FooterBar hint="ctrl+p commands and shortcuts" />
    </ShellFrame>
  );
}

function HistoryScreen({ dbPath, limit, onResolve, onExit, shell }: { dbPath?: string; limit: number; onResolve?: (selection: HistorySelection) => void; onExit: () => void; shell?: ShellNav }) {
  const [scans, setScans] = useState<HistoryScanRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [index, setIndex] = useState(0);
  const selected = scans[index] ?? null;
  const palette = usePaletteController([
    {
      id: "replay-scan",
      title: "Replay selected scan",
      category: "Session",
      description: "Hand off the selected run to the replay view",
      keybind: "r",
      suggested: true,
      action: () => {
        if (!selected) return;
        if (shell) {
          shell.openReplay(selected.id);
          return;
        }
        onResolve?.({ action: "replay", scanId: selected.id });
        onExit();
      },
    },
    {
      id: "close-history",
      title: "Close history",
      category: "System",
      description: "Leave scan history",
      keybind: "esc",
      suggested: true,
      action: onExit,
    },
    ...createShellCommands(shell),
  ]);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const { pwnkitDB } = await import("@pwnkit/db");
        const db = new pwnkitDB(dbPath);
        try {
          const rows = db.listScans(limit) as HistoryScanRow[];
          if (!alive) return;
          setScans(rows);
          setError(null);
        } finally {
          db.close();
        }
      } catch (err) {
        if (!alive) return;
        setError(err instanceof Error ? err.message : String(err));
      }
    };
    void load();
    return () => {
      alive = false;
    };
  }, [dbPath, limit]);

  useKeyboard((key) => {
    if (palette.handlePaletteKey(key)) return;
    if ((key.ctrl && key.name === "c") || key.name === "escape" || key.name === "q") {
      onExit();
      return;
    }
    if (shell && key.sequence === "[") {
      shell.goBack();
      return;
    }
    if (shell && key.sequence === "]") {
      shell.goForward();
      return;
    }
    if (key.sequence === "r" && selected) {
      if (shell) {
        shell.openReplay(selected.id);
      } else {
        onResolve?.({ action: "replay", scanId: selected.id });
        onExit();
      }
      return;
    }
    if (key.name === "up") setIndex((current) => Math.max(0, current - 1));
    if (key.name === "down") setIndex((current) => Math.min(Math.max(scans.length - 1, 0), current + 1));
  });

  const summary = selected ? parseSummary(selected.summary) : {};

  return (
    <ShellFrame view="history">
      {palette.paletteOpen ? <PaletteOverlay title="History commands" query={palette.paletteQuery} selected={palette.paletteSelected} commands={palette.filteredPalette} /> : null}
      {error ? <text fg={ERROR}>{fitTuiText(error, 120)}</text> : null}
      <box flexDirection="row" gap={2} flexGrow={1}>
        <scrollbox width="58%" flexGrow={1} border borderColor={BORDER} focusedBorderColor={BORDER} backgroundColor={PANEL} paddingX={1} paddingY={0}>
          <box flexDirection="column">
            {scans.length === 0 ? <text fg={MUTED}>No scan history found.</text> : scans.map((scan, scanIndex) => {
              const active = scanIndex === index;
              const scanSummary = parseSummary(scan.summary);
              return (
                <box key={scan.id} flexDirection="row">
                  <RailBar tone={active ? PRIMARY : BORDER} />
                  <box flexDirection="column" marginLeft={1}>
                    <text fg={active ? TEXT : "#CCCCCC"}>{fitTuiUrl(scan.target, 72)}</text>
                    <text fg={MUTED}>{scan.mode}/{scan.depth} · {scan.runtime} · {scan.status}</text>
                    <text fg={MUTED}>{fitTuiText(`${scanSummary.totalFindings ?? 0} findings · ${formatDuration(scan.durationMs)} · ${scan.startedAt}`, 72)}</text>
                  </box>
                </box>
              );
            })}
          </box>
        </scrollbox>
        <box flexDirection="column" width={40}>
          <PanelSection title="Selected run" tone={PRIMARY}>
            <box flexDirection="column">
              <text fg={TEXT}>{selected ? fitTuiUrl(selected.target, 36) : "No run selected"}</text>
              {selected ? <text fg={MUTED}>{selected.mode}/{selected.depth} · {selected.runtime}</text> : null}
              {selected ? <text fg={MUTED}>{selected.status} · {formatDuration(selected.durationMs)}</text> : null}
            </box>
          </PanelSection>
          <PanelSection title="Summary" tone={BORDER}>
            <box flexDirection="column">
              <text fg={MUTED}>findings {summary.totalFindings ?? 0}</text>
              <text fg={MUTED}>started {selected?.startedAt ?? "-"}</text>
              <text fg={MUTED}>scan {selected?.id.slice(0, 8) ?? "-"}</text>
              <text fg={MUTED}>key r replay selected</text>
            </box>
          </PanelSection>
        </box>
      </box>
      <FooterBar hint="ctrl+p commands and shortcuts" />
    </ShellFrame>
  );
}

function FindingsScreen({ options, onExit, shell }: { options: FindingsScreenOptions; onExit: () => void; shell?: ShellNav }) {
  const [rows, setRows] = useState<FindingsRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [index, setIndex] = useState(0);
  const [reloadNonce, setReloadNonce] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);
  const [triageBusy, setTriageBusy] = useState<FindingTriageStatus | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const { pwnkitDB } = await import("@pwnkit/db");
        const db = new pwnkitDB(options.dbPath);
        try {
          const findings = db.listFindings({
            scanId: options.scan,
            severity: options.severity,
            category: options.category,
            status: options.status,
            triageStatus: options.triage,
            limit: options.all ? options.limit : 1000,
          }) as FindingsRow[];
          if (!alive) return;
          setRows(findings);
          setIndex(0);
          setError(null);
        } finally {
          db.close();
        }
      } catch (err) {
        if (!alive) return;
        setError(err instanceof Error ? err.message : String(err));
      }
    };
    void load();
    return () => {
      alive = false;
    };
  }, [options, reloadNonce]);

  const groups = useMemo(() => groupFindings(rows).slice(0, options.limit), [rows, options.limit]);
  const items = options.all ? rows.slice(0, options.limit) : groups;
  const itemCount = items.length;
  const selectedGroup = !options.all ? groups[index] ?? null : null;
  const selectedRow = options.all ? rows[index] ?? null : selectedGroup?.latest ?? null;
  const selectedFingerprint = selectedRow ? (selectedRow.fingerprint ?? selectedRow.id) : null;
  const filterSummary = describeFindingsFilters(options);
  const palette = usePaletteController([
    {
      id: "accept-finding",
      title: "Accept finding family",
      category: "Triage",
      description: "Mark the selected fingerprint family as accepted",
      keybind: "a",
      suggested: true,
      action: () => { void mutateTriage("accepted"); },
    },
    {
      id: "suppress-finding",
      title: "Suppress finding family",
      category: "Triage",
      description: "Suppress the selected fingerprint family",
      keybind: "s",
      suggested: true,
      action: () => { void mutateTriage("suppressed"); },
    },
    {
      id: "reopen-finding",
      title: "Reopen finding family",
      category: "Triage",
      description: "Reset the selected fingerprint family back to new",
      keybind: "r",
      suggested: true,
      action: () => { void mutateTriage("new"); },
    },
    {
      id: "close-findings",
      title: "Close findings",
      category: "System",
      description: "Leave findings review",
      keybind: "esc",
      suggested: true,
      action: onExit,
    },
    ...createShellCommands(shell),
  ]);

  useEffect(() => {
    if (index >= itemCount && itemCount > 0) {
      setIndex(itemCount - 1);
    }
  }, [index, itemCount]);

  const mutateTriage = async (triageStatus: FindingTriageStatus) => {
    if (!selectedRow || triageBusy) return;
    if (!selectedRow.fingerprint) {
      setError(`Finding ${selectedRow.id} has no fingerprint and cannot be triaged as a family.`);
      return;
    }

    setTriageBusy(triageStatus);
    setError(null);
    setNotice(`Updating ${selectedRow.fingerprint.slice(0, 10)} to ${triageStatus}...`);

    try {
      const { pwnkitDB } = await import("@pwnkit/db");
      const db = new pwnkitDB(options.dbPath);
      try {
        db.updateFindingTriageByFingerprint(selectedRow.fingerprint, triageStatus);
      } finally {
        db.close();
      }
      setNotice(`Updated ${selectedRow.fingerprint.slice(0, 10)} to ${triageStatus}.`);
      setReloadNonce((current) => current + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setTriageBusy(null);
    }
  };

  useKeyboard((key) => {
    if (palette.handlePaletteKey(key)) return;
    if ((key.ctrl && key.name === "c") || key.name === "escape" || key.name === "q") {
      onExit();
      return;
    }
    if (shell && key.sequence === "[") {
      shell.goBack();
      return;
    }
    if (shell && key.sequence === "]") {
      shell.goForward();
      return;
    }
    if (key.name === "up") setIndex((current) => Math.max(0, current - 1));
    if (key.name === "down") setIndex((current) => Math.min(Math.max(itemCount - 1, 0), current + 1));
    if (key.sequence === "a") void mutateTriage("accepted");
    if (key.sequence === "s") void mutateTriage("suppressed");
    if (key.sequence === "r") void mutateTriage("new");
  });

  return (
    <ShellFrame view="findings" status={<text fg={MUTED}>{triageBusy ? `updating ${triageBusy}` : options.all ? "raw rows" : "grouped families"}</text>}>
      {palette.paletteOpen ? <PaletteOverlay title="Findings commands" query={palette.paletteQuery} selected={palette.paletteSelected} commands={palette.filteredPalette} /> : null}
      {error ? <text fg={ERROR}>{fitTuiText(error, 120)}</text> : null}
      {notice ? <text fg={ACCENT}>{fitTuiText(notice, 120)}</text> : null}
      <box flexDirection="row" gap={1} marginBottom={1}>
        <box border borderColor={PRIMARY} backgroundColor={PANEL} paddingX={1}><box><text fg={TEXT}>scope </text><text fg={PRIMARY}>{fitTuiText(filterSummary, 64)}</text></box></box>
        <box border borderColor={BORDER} backgroundColor={PANEL} paddingX={1}><box><text fg={TEXT}>{options.all ? "rows " : "families "}</text><text fg={MUTED}>{String(itemCount)}</text></box></box>
        <box border borderColor={BORDER} backgroundColor={PANEL} paddingX={1}><box><text fg={TEXT}>loaded </text><text fg={MUTED}>{String(rows.length)}</text></box></box>
      </box>
      <box flexDirection="row" gap={2} flexGrow={1}>
        <scrollbox width="42%" flexGrow={1} border borderColor={BORDER} focusedBorderColor={BORDER} backgroundColor={PANEL} paddingX={1} paddingY={0}>
          <box flexDirection="column">
            {itemCount === 0 ? <text fg={MUTED}>No findings found.</text> : options.all
              ? rows.slice(0, options.limit).map((row, rowIndex) => {
                  const active = rowIndex === index;
                  const fingerprint = row.fingerprint ?? row.id;
                  return (
                    <box key={row.id} flexDirection="row">
                      <RailBar tone={active ? PRIMARY : BORDER} />
                      <box flexDirection="column" marginLeft={1}>
                        <text fg={severityTone(row.severity)}>{fitTuiText(`${row.severity.toUpperCase()} · ${row.title}`, 68)}</text>
                        <text fg={MUTED}>{fitTuiText(`${row.category} · ${row.status} · ${row.triageStatus ?? "new"}`, 68)}</text>
                        <text fg={MUTED}>scan:{row.scanId.slice(0, 8)} · fp:{fingerprint.slice(0, 10)}</text>
                      </box>
                    </box>
                  );
                })
              : groups.map((group, groupIndex) => {
                  const active = groupIndex === index;
                  const latest = group.latest;
                  return (
                    <box key={group.fingerprint} flexDirection="row">
                      <RailBar tone={active ? PRIMARY : BORDER} />
                      <box flexDirection="column" marginLeft={1}>
                        <text fg={severityTone(latest.severity)}>{fitTuiText(`${latest.severity.toUpperCase()} · ${latest.title}`, 68)}</text>
                        <text fg={MUTED}>{fitTuiText(`${latest.category} · ${latest.status} · ${latest.triageStatus ?? "new"}`, 68)}</text>
                        <text fg={MUTED}>{group.count} hits / {group.scans} scans · fp:{group.fingerprint.slice(0, 10)}</text>
                      </box>
                    </box>
                  );
                })}
          </box>
        </scrollbox>
        <box flexDirection="column" width={56}>
          <PanelSection title={options.all ? "Finding" : "Family"} tone={selectedRow ? severityTone(selectedRow.severity) : BORDER}>
            <box flexDirection="column">
              <text fg={TEXT}>{selectedRow ? fitTuiText(selectedRow.title, 52) : "No finding selected"}</text>
              {selectedRow ? <text fg={MUTED}>{selectedRow.severity} · {selectedRow.status} · {selectedRow.triageStatus ?? "new"}</text> : null}
              {selectedGroup ? <text fg={MUTED}>{selectedGroup.count} hits / {selectedGroup.scans} scans</text> : null}
              {selectedRow ? <text fg={MUTED}>scan {selectedRow.scanId.slice(0, 8)} · fp:{selectedFingerprint?.slice(0, 10)}</text> : null}
              {selectedRow?.triageNote ? <text fg={ACCENT}>{fitTuiText(selectedRow.triageNote, 52)}</text> : null}
            </box>
          </PanelSection>
          <PanelSection title="Filters" tone={BORDER}>
            <box flexDirection="column">
              <text fg={MUTED}>{fitTuiText(filterSummary, 52)}</text>
              <text fg={MUTED}>limit {options.limit}</text>
              <text fg={MUTED}>mode {options.all ? "raw rows" : "grouped families"}</text>
              <text fg={MUTED}>keys a accept · s suppress · r reopen</text>
            </box>
          </PanelSection>
          <PanelSection title="Description" tone={BORDER}>
            <box flexDirection="column">
              <text fg={MUTED}>{selectedRow ? fitTuiText(selectedRow.description, 160) : "-"}</text>
            </box>
          </PanelSection>
          <PanelSection title="Evidence" tone={BORDER}>
            <box flexDirection="column">
              <text fg={TEXT}>request</text>
              <text fg={MUTED}>{selectedRow ? fitTuiText(selectedRow.evidenceRequest, 160) : "-"}</text>
              <text fg={TEXT}>response</text>
              <text fg={MUTED}>{selectedRow ? fitTuiText(selectedRow.evidenceResponse, 160) : "-"}</text>
            </box>
          </PanelSection>
        </box>
      </box>
      <FooterBar hint="ctrl+p commands and shortcuts" />
    </ShellFrame>
  );
}

function ReplayScreen({ dbPath, scanId, onExit, shell }: { dbPath?: string; scanId?: string; onExit: () => void; shell?: ShellNav }) {
  const [scan, setScan] = useState<ReplayScanRow | null>(null);
  const [findings, setFindings] = useState<FindingsRow[]>([]);
  const [events, setEvents] = useState<ReplayEventRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [eventIndex, setEventIndex] = useState(0);

  const palette = usePaletteController([
    {
      id: "close-replay",
      title: "Close replay",
      category: "System",
      description: "Leave the replay screen",
      keybind: "esc",
      suggested: true,
      action: onExit,
    },
    ...createShellCommands(shell),
  ]);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const { pwnkitDB } = await import("@pwnkit/db");
        const db = new pwnkitDB(dbPath);
        try {
          let selected = scanId ? db.getScan(scanId) as ReplayScanRow | undefined : undefined;
          if (!selected && scanId) {
            const scans = db.listScans(100) as ReplayScanRow[];
            selected = scans.find((row) => row.id.startsWith(scanId));
          }
          if (!selected) {
            const scans = db.listScans(1) as ReplayScanRow[];
            selected = scans[0];
          }
          if (!selected) throw new Error("No scan history found. Run a scan first.");
          const nextFindings = db.getFindings(selected.id) as FindingsRow[];
          const nextEvents = db.getEvents(selected.id) as ReplayEventRow[];
          if (!alive) return;
          setScan(selected);
          setFindings(nextFindings);
          setEvents(nextEvents);
          setEventIndex(0);
          setError(null);
        } finally {
          db.close();
        }
      } catch (err) {
        if (!alive) return;
        setError(err instanceof Error ? err.message : String(err));
      }
    };
    void load();
    return () => {
      alive = false;
    };
  }, [dbPath, scanId]);

  const summary = parseSummary(scan?.summary);
  const verifiedFindings = findings.filter((finding) => finding.status !== "false-positive");
  const selectedEvent = events[eventIndex] ?? null;

  useKeyboard((key) => {
    if (palette.handlePaletteKey(key)) return;
    if ((key.ctrl && key.name === "c") || key.name === "escape" || key.name === "q") {
      onExit();
      return;
    }
    if (shell && key.sequence === "[") {
      shell.goBack();
      return;
    }
    if (shell && key.sequence === "]") {
      shell.goForward();
      return;
    }
    if (key.name === "up") setEventIndex((current) => Math.max(0, current - 1));
    if (key.name === "down") setEventIndex((current) => Math.min(Math.max(events.length - 1, 0), current + 1));
  });

  return (
    <ShellFrame view="replay" status={<text fg={MUTED}>{scan ? scan.id.slice(0, 8) : "latest scan"}</text>}>
      {palette.paletteOpen ? <PaletteOverlay title="Replay commands" query={palette.paletteQuery} selected={palette.paletteSelected} commands={palette.filteredPalette} /> : null}
      {error ? <text fg={ERROR}>{fitTuiText(error, 120)}</text> : null}
      <box flexDirection="row" gap={1} marginBottom={1}>
        <box border borderColor={PRIMARY} backgroundColor={PANEL} paddingX={1}><box><text fg={TEXT}>target </text><text fg={PRIMARY}>{scan ? fitTuiUrl(scan.target, 72) : "loading"}</text></box></box>
        <box border borderColor={BORDER} backgroundColor={PANEL} paddingX={1}><box><text fg={TEXT}>findings </text><text fg={MUTED}>{String(summary.totalFindings ?? verifiedFindings.length)}</text></box></box>
        <box border borderColor={BORDER} backgroundColor={PANEL} paddingX={1}><box><text fg={TEXT}>events </text><text fg={MUTED}>{String(events.length)}</text></box></box>
      </box>
      <box flexDirection="row" gap={2} flexGrow={1}>
        <box flexDirection="column" width="46%">
          <PanelSection title="Replay lane" tone={PRIMARY}>
            <box flexDirection="column">
              <text fg={TEXT}>DISCOVER</text>
              <text fg={MUTED}>{scan ? `${scan.mode}/${scan.depth} via ${scan.runtime}` : "loading"}</text>
              <text fg={TEXT}>ATTACK</text>
              <text fg={MUTED}>{verifiedFindings.length > 0 ? `${verifiedFindings.length} findings survived triage` : "No confirmed findings recorded"}</text>
              <text fg={TEXT}>VERIFY</text>
              <text fg={MUTED}>{findings.filter((finding) => finding.status === "false-positive").length} false positives removed</text>
              <text fg={TEXT}>REPORT</text>
              <text fg={MUTED}>{formatDuration(scan?.durationMs)} total runtime</text>
            </box>
          </PanelSection>
          <PanelSection title="Findings" tone={verifiedFindings.length > 0 ? WARNING : BORDER}>
            <box flexDirection="column">
              {verifiedFindings.length === 0 ? <text fg={MUTED}>No findings recorded for this scan.</text> : verifiedFindings.slice(0, 8).map((finding) => (
                <text key={finding.id} fg={severityTone(finding.severity)}>{fitTuiText(`${finding.severity} · ${finding.title}`, 68)}</text>
              ))}
            </box>
          </PanelSection>
        </box>
        <scrollbox width="54%" flexGrow={1} border borderColor={BORDER} focusedBorderColor={BORDER} backgroundColor={PANEL} paddingX={1} paddingY={0}>
          <box flexDirection="column">
            {events.length === 0 ? <text fg={MUTED}>No pipeline events captured for this scan.</text> : events.map((event, index) => {
              const active = index === eventIndex;
              return (
                <box key={event.id} flexDirection="row">
                  <RailBar tone={active ? PRIMARY : BORDER} />
                  <box flexDirection="column" marginLeft={1} width="100%">
                    <box justifyContent="space-between">
                      <text fg={active ? TEXT : "#CCCCCC"}>{fitTuiText(`${event.stage} · ${event.eventType}`, 52)}</text>
                      <text fg={MUTED}>{new Date(event.timestamp).toISOString()}</text>
                    </box>
                    <text fg={active ? ACCENT : MUTED}>{describeEventPayload(event.payload)}</text>
                  </box>
                </box>
              );
            })}
          </box>
        </scrollbox>
      </box>
      {selectedEvent ? <text fg={MUTED}>{fitTuiText(`${selectedEvent.stage} · ${selectedEvent.eventType} · up/down browse events`, 96)}</text> : null}
      <FooterBar hint="ctrl+p commands and shortcuts" />
    </ShellFrame>
  );
}

function ConsoleSessionRoute({ route, shell }: { route: Extract<ConsoleRoute, { type: "session" }>; shell: ShellNav }) {
  const [state, setState] = useState(route.initialState);
  useEffect(() => route.subscribe(setState), [route]);
  return <SessionScreen state={state} onExit={route.onClose} shell={shell} queueUserMessage={route.queueUserMessage} />;
}

function SessionScreen({ state, onExit, shell, queueUserMessage }: { state: SessionState; onExit: () => void; shell?: ShellNav; queueUserMessage?: (text: string) => void }) {
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState("");
  const [paletteSelected, setPaletteSelected] = useState(0);
  const [timelineOpen, setTimelineOpen] = useState(false);
  const [timelineSelected, setTimelineSelected] = useState(0);
  const [composeOpen, setComposeOpen] = useState(false);
  const [composeText, setComposeText] = useState("");
  const [sidebarVisible, setSidebarVisible] = useState(true);
  const [expandedToolCards, setExpandedToolCards] = useState<Set<string>>(new Set());
  const [hoveredToolId, setHoveredToolId] = useState<string | null>(null);
  const [visibleFromTurnId, setVisibleFromTurnId] = useState<string | null>(null);

  const toggleToolCard = (id: string) => {
    setExpandedToolCards((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toolCardIds = useMemo(
    () => state.transcript.filter((item) => item.kind === "tool-group").map((item) => item.id),
    [state.transcript],
  );
  const turnItems = useMemo(
    () => state.transcript.filter((item) => item.kind === "turn"),
    [state.transcript],
  );
  const visibleTranscript = useMemo(() => {
    if (!visibleFromTurnId) return state.transcript;
    const index = state.transcript.findIndex((item) => item.id === visibleFromTurnId);
    return index >= 0 ? state.transcript.slice(index) : state.transcript;
  }, [state.transcript, visibleFromTurnId]);

  const paletteCommands = useMemo<PaletteCommand[]>(() => [
    {
      id: "expand-tools",
      title: "Expand tool cards",
      category: "Display",
      description: "Show full details for grouped tool activity",
      keybind: "e",
      suggested: true,
      action: () => setExpandedToolCards(new Set(toolCardIds)),
    },
    {
      id: "collapse-tools",
      title: "Collapse tool cards",
      category: "Display",
      description: "Return grouped tool activity to compact previews",
      keybind: "shift+e",
      suggested: true,
      action: () => setExpandedToolCards(new Set()),
    },
    {
      id: "toggle-sidebar",
      title: sidebarVisible ? "Hide sidebar" : "Show sidebar",
      category: "Display",
      description: "Toggle the right-hand session sidebar",
      keybind: "ctrl+\\",
      suggested: true,
      action: () => setSidebarVisible((current) => !current),
    },
    {
      id: "open-timeline",
      title: "Open turn timeline",
      category: "Session",
      description: "Jump directly to a transcript turn",
      keybind: "ctrl+j",
      suggested: true,
      action: () => {
        setTimelineOpen(true);
        setTimelineSelected(0);
      },
    },
    {
      id: "clear-turn-focus",
      title: "Show full transcript",
      category: "Session",
      description: "Clear the current turn jump focus",
      suggested: true,
      action: () => setVisibleFromTurnId(null),
    },
    ...(!state.summary && queueUserMessage ? [{
      id: "inject-message",
      title: "Send message to agent",
      category: "Session",
      description: "Inject a message at the next turn boundary",
      keybind: "i",
      suggested: true,
      action: () => { setComposeOpen(true); setComposeText(""); },
    }] : []),
    {
      id: "close-session",
      title: "Close session",
      category: "Session",
      description: "Leave the live terminal session",
      keybind: "esc",
      suggested: true,
      action: onExit,
    },
    ...createShellCommands(shell),
  ], [onExit, shell, sidebarVisible, toolCardIds]);

  const filteredPalette = useMemo(() => {
    const base = paletteQuery.trim() ? paletteCommands : paletteCommands.filter((command) => command.suggested);
    return filterCommands(base, paletteQuery);
  }, [paletteCommands, paletteQuery]);

  useKeyboard((key) => {
    if (key.ctrl && (key.name === "p" || key.name === "k")) {
      setPaletteOpen((current) => !current);
      setPaletteQuery("");
      setPaletteSelected(0);
      return;
    }

    if (key.ctrl && key.name === "j") {
      setTimelineOpen((current) => !current);
      setTimelineSelected(0);
      return;
    }

    if (key.ctrl && key.sequence === "\\") {
      setSidebarVisible((current) => !current);
      return;
    }

    if (shell && key.sequence === "[") {
      shell.goBack();
      return;
    }
    if (shell && key.sequence === "]") {
      shell.goForward();
      return;
    }

    if (composeOpen) {
      if (key.name === "escape") {
        setComposeOpen(false);
        setComposeText("");
        return;
      }
      if (key.name === "return") {
        const trimmed = composeText.trim();
        if (trimmed && queueUserMessage) {
          queueUserMessage(trimmed);
        }
        setComposeOpen(false);
        setComposeText("");
        return;
      }
      if (key.name === "backspace") {
        setComposeText((current) => current.slice(0, -1));
        return;
      }
      if (key.sequence && !key.ctrl && !key.meta && key.name !== "return") {
        setComposeText((current) => current + key.sequence);
      }
      return;
    }

    if (timelineOpen) {
      if (key.name === "escape") {
        setTimelineOpen(false);
        return;
      }
      if (key.name === "up") {
        setTimelineSelected((current) => Math.max(0, current - 1));
        return;
      }
      if (key.name === "down") {
        setTimelineSelected((current) => Math.min(Math.max(turnItems.length - 1, 0), current + 1));
        return;
      }
      if (key.name === "return") {
        const target = turnItems[timelineSelected];
        if (target) setVisibleFromTurnId(target.id);
        setTimelineOpen(false);
        return;
      }
      return;
    }

    if (paletteOpen) {
      if (key.name === "escape") {
        setPaletteOpen(false);
        setPaletteQuery("");
        setPaletteSelected(0);
        return;
      }
      if (key.name === "up") {
        setPaletteSelected((current) => Math.max(0, current - 1));
        return;
      }
      if (key.name === "down") {
        setPaletteSelected((current) => Math.min(Math.max(filteredPalette.length - 1, 0), current + 1));
        return;
      }
      if (key.name === "return") {
        filteredPalette[paletteSelected]?.action();
        setPaletteOpen(false);
        return;
      }
      if (key.name === "backspace") {
        setPaletteQuery((current) => current.slice(0, -1));
        return;
      }
      if (key.sequence && !key.ctrl && !key.meta && key.name !== "return") {
        setPaletteQuery((current) => current + key.sequence);
        setPaletteSelected(0);
      }
      return;
    }

    if (key.sequence === "e") {
      setExpandedToolCards(new Set(toolCardIds));
      return;
    }
    if (key.sequence === "E") {
      setExpandedToolCards(new Set());
      return;
    }
    if (key.sequence === "i" && !state.summary && queueUserMessage) {
      setComposeOpen(true);
      setComposeText("");
      return;
    }
    if ((key.ctrl && key.name === "c") || (state.summary && (key.name === "escape" || key.name === "q" || key.name === "return"))) {
      onExit();
    }
  });

  const summary = state.summary;
  const totalFindings = state.stages.reduce((count, stage) => count + stage.findings.length, 0);
  const runningStage = state.stages.find((stage) => stage.status === "running") ?? null;
  const latestRunningAction = runningStage?.actions.at(-1);
  const liveActivity = formatLiveActivity(state, runningStage, latestRunningAction);

  return (
    <ShellFrame view={summary ? "report" : "live session"} status={<text fg={MUTED}>{state.mode}</text>}>
      {paletteOpen ? <PaletteOverlay title="Session commands" query={paletteQuery} selected={paletteSelected} commands={filteredPalette} /> : null}
      {timelineOpen ? <TimelineOverlay selected={timelineSelected} turns={turnItems} /> : null}
      {composeOpen ? <ComposeOverlay text={composeText} /> : null}
      <box flexDirection="row" gap={2} flexGrow={1}>
        <scrollbox
          width="68%"
          flexGrow={1}
          stickyScroll
          stickyStart="bottom"
          border
          borderColor={BORDER}
          focusedBorderColor={BORDER}
          backgroundColor={PANEL}
          paddingX={1}
          paddingY={0}
          verticalScrollbarOptions={{
            trackOptions: {
              backgroundColor: PANEL_ALT,
              foregroundColor: PRIMARY,
            },
            arrowOptions: {
              foregroundColor: MUTED,
              backgroundColor: PANEL,
            },
          }}
        >
          <box flexDirection="column">
            {visibleTranscript.map((item) => renderTranscriptItem(item, {
              expanded: expandedToolCards,
              toggleExpanded: toggleToolCard,
              hoveredToolId,
              setHoveredToolId,
            }))}
            {!summary ? (
              <WorkingPulse
                label={liveActivity.label}
                detail={liveActivity.detail}
              />
            ) : null}
          </box>
        </scrollbox>
        {sidebarVisible ? <box flexDirection="column" width={38}>
          <PanelSection title="Target" tone={PRIMARY}>
            <box flexDirection="column">
              <text fg={TEXT}>{fitTuiUrl(state.target, 34)}</text>
              <text fg={MUTED}>{state.mode} · {state.depth}</text>
            </box>
          </PanelSection>
          <PanelSection title="Runtime" tone={state.connection.apiConnected ? SUCCESS : state.connection.apiConfigured ? WARNING : BORDER}>
            <box flexDirection="column">
              <text fg={TEXT}>selected {state.connection.runtime}</text>
              <box flexDirection="row">
                <text fg={TEXT}>api {state.connection.apiConnected ? "connected" : state.connection.apiConfigured ? "configured" : "missing"} </text>
                <text fg={MUTED}>· {state.connection.apiProviderLabel ?? "unknown"}</text>
              </box>
              <box flexDirection="row">
                <text fg={TEXT}>local </text>
                <text fg={MUTED}>{fitTuiText(state.connection.localRuntimes.length > 0 ? state.connection.localRuntimes.join(", ") : "none", 28)}</text>
              </box>
              {state.usage.inputTokens > 0 || state.usage.outputTokens > 0 ? (
                <>
                  <box flexDirection="row">
                    <text fg={TEXT}>tokens </text>
                    <text fg={MUTED}>{state.usage.inputTokens}/{state.usage.outputTokens}</text>
                  </box>
                  <box flexDirection="row">
                    <text fg={TEXT}>cost </text>
                    <text fg={MUTED}>${state.usage.estimatedCostUsd.toFixed(4)}</text>
                  </box>
                </>
              ) : (
                <text fg={MUTED}>usage awaiting first model response</text>
              )}
              {state.connection.model ? (
                <box flexDirection="row">
                  <text fg={TEXT}>model </text>
                  <text fg={MUTED}>{fitTuiText(state.connection.model, 28)}</text>
                </box>
              ) : null}
            </box>
          </PanelSection>
          <PanelSection title="Session" tone={BORDER}>
            <box flexDirection="column">
              <box flexDirection="row">
                <text fg={TEXT}>transcript </text>
                <text fg={MUTED}>{state.transcript.length} items</text>
              </box>
              <box flexDirection="row">
                <text fg={TEXT}>turns </text>
                <text fg={MUTED}>{turnItems.length}</text>
              </box>
              <box flexDirection="row">
                <text fg={TEXT}>findings </text>
                <text fg={MUTED}>{totalFindings}</text>
              </box>
              <text fg={summary ? SUCCESS : PRIMARY}>{summary ? "completed" : "running"}</text>
              {visibleFromTurnId ? <text fg={ACCENT}>timeline focus active</text> : null}
            </box>
          </PanelSection>
          <PanelSection title="Pipeline" tone={state.stages.some((stage) => stage.status === "running") ? PRIMARY : BORDER}>
            <box flexDirection="column">
              {state.stages.map((stage) => (
                <box key={stage.id} flexDirection="column">
                  <text fg={stage.status === "running" ? PRIMARY : stage.status === "done" ? SUCCESS : stage.status === "error" ? ERROR : MUTED}>
                    {stage.label} · {stage.status}
                  </text>
                  {stage.detail ? <text fg={TEXT}>{fitTuiText(stage.detail, 34)}</text> : stage.status === "pending" ? <text fg={MUTED}>waiting for stage handoff</text> : null}
                </box>
              ))}
            </box>
          </PanelSection>
          <PanelSection title="Findings" tone={totalFindings > 0 ? WARNING : BORDER}>
            <box flexDirection="column">
              {state.stages.flatMap((stage) => stage.findings).length === 0 ? (
                <text fg={TEXT}>No findings yet.</text>
              ) : state.stages.flatMap((stage) => stage.findings).slice(0, 8).map((finding, index) => (
                <text key={`${finding.title}-${index}`} fg={severityTone(finding.severity)}>{fitTuiText(`${finding.severity} · ${finding.title}`, 34)}</text>
              ))}
            </box>
          </PanelSection>
          {summary ? (
            <PanelSection title="Report" tone={summary.critical > 0 || summary.high > 0 ? ERROR : SUCCESS}>
              <box flexDirection="column">
                <box flexDirection="row">
                  <text fg={summary.critical > 0 ? ERROR : TEXT}>critical </text>
                  <text fg={MUTED}>{summary.critical}</text>
                </box>
                <box flexDirection="row">
                  <text fg={summary.high > 0 ? ERROR : TEXT}>high </text>
                  <text fg={MUTED}>{summary.high}</text>
                </box>
                <box flexDirection="row">
                  <text fg={summary.medium > 0 ? WARNING : TEXT}>medium </text>
                  <text fg={MUTED}>{summary.medium}</text>
                </box>
                <box flexDirection="row">
                  <text fg={TEXT}>low </text>
                  <text fg={MUTED}>{summary.low}</text>
                </box>
                <box flexDirection="row">
                  <text fg={TEXT}>info </text>
                  <text fg={MUTED}>{summary.info ?? 0}</text>
                </box>
                {summary.shareUrl ? <text fg={ACCENT}>{fitTuiUrl(summary.shareUrl, 34)}</text> : null}
              </box>
            </PanelSection>
          ) : null}
        </box> : null}
      </box>
      <FooterBar
        hint={state.pendingUserMessages.length > 0
          ? `message queued (${state.pendingUserMessages.length}) · ctrl+p commands`
          : "i inject message · ctrl+p commands"}
        status={summary ? <LiveBadge label={`ready · ${state.mode}`} active={false} /> : <LiveBadge label={`running · ${state.mode}`} />}
      />
    </ShellFrame>
  );
}

type AppMode =
  | { type: "home"; onResolve: (selection: HomeSelection) => void; onExit: () => void }
  | { type: "ops"; dbPath?: string; refreshMs: number; onExit: () => void }
  | { type: "doctor"; onExit: () => void }
  | { type: "history"; dbPath?: string; limit: number; onResolve: (selection: HistorySelection) => void; onExit: () => void }
  | { type: "findings"; options: FindingsScreenOptions; onExit: () => void }
  | { type: "replay"; dbPath?: string; scanId?: string; onExit: () => void }
  | { type: "console"; initialRoute: ConsoleRoute; onResolve?: (selection: HomeSelection) => void; onExit: () => void }
  | { type: "session"; initialState: SessionState; subscribe: (listener: (state: SessionState) => void) => () => void; queueUserMessage?: (text: string) => void; onExit: () => void };

function ConsoleApp({ initialRoute, onResolve, onExit }: { initialRoute: ConsoleRoute; onResolve?: (selection: HomeSelection) => void; onExit: () => void }) {
  const [routes, setRoutes] = useState<ConsoleRoute[]>([initialRoute]);
  const [routeIndex, setRouteIndex] = useState(0);

  const navigate = (route: ConsoleRoute) => {
    setRoutes((current) => {
      const next = [...current.slice(0, routeIndex + 1), route];
      setRouteIndex(next.length - 1);
      return next;
    });
  };

  const currentRoute = routes[routeIndex] ?? initialRoute;
  const shell: ShellNav = {
    canGoBack: routeIndex > 0,
    canGoForward: routeIndex < routes.length - 1,
    goBack: () => setRouteIndex((current) => Math.max(0, current - 1)),
    goForward: () => setRouteIndex((current) => Math.min(routes.length - 1, current + 1)),
    openLauncher: () => navigate({ type: "launcher" }),
    openOps: () => navigate({ type: "ops", refreshMs: 4000 }),
    openDoctor: () => navigate({ type: "doctor" }),
    openHistory: () => navigate({ type: "history", limit: 12 }),
    openFindings: () => navigate({ type: "findings", options: { limit: 50 } }),
    openReplay: (scanId) => navigate({ type: "replay", scanId }),
  };

  const launchSelection = async (selection: HomeSelection) => {
    if (!selection.target) return;
    const mode = selection.action === "audit" ? "audit" : selection.action === "review" ? "review" : "scan";
    const depth = selection.depth ?? "default";
    const runtime = selection.runtime ?? "auto";
    const availability = await getRuntimeAvailability();
    let state = createInitialSessionState(selection.target, depth, mode, {
      runtime,
      apiProviderLabel: availability.apiRuntime.providerLabel,
      apiConfigured: availability.apiRuntime.configured,
      apiConnected: availability.hasApiKey && availability.apiRuntime.valid,
      localRuntimes: availability.availableRuntimes,
    });
    const listeners = new Set<(value: SessionState) => void>();
    let resolveExit: (() => void) | null = null;
    const subscribe = (listener: (value: SessionState) => void) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    };
    const emit = () => {
      for (const listener of listeners) listener(state);
    };
    navigate({
      type: "session",
      initialState: state,
      subscribe,
      onClose: () => {
        resolveExit?.();
        resolveExit = null;
        shell.goBack();
      },
    });

    const { runUnified } = await import("../commands/run.js");
    const previousStartupLogSetting = process.env.PWNKIT_SUPPRESS_PROVIDER_STARTUP_LOG;
    const previousNativeTracePath = process.env.PWNKIT_TRACE_NATIVE_RESPONSES;
    const previousTuiTracePath = process.env.PWNKIT_TRACE_TUI_EVENTS;
    process.env.PWNKIT_SUPPRESS_PROVIDER_STARTUP_LOG = "1";
    process.env.PWNKIT_TRACE_NATIVE_RESPONSES = `/tmp/pwnkit-native-responses-${Date.now()}.ndjson`;
    process.env.PWNKIT_TRACE_TUI_EVENTS = `/tmp/pwnkit-tui-events-${Date.now()}.ndjson`;
    appendTuiTrace({
      kind: "session-start",
      target: selection.target,
      mode,
      runtime,
      depth,
      nativeTrace: process.env.PWNKIT_TRACE_NATIVE_RESPONSES,
    });
    try {
      await runUnified({
        target: selection.target,
        targetType: selection.action === "review"
          ? "source-code"
          : selection.action === "audit"
            ? selection.ecosystem === "pypi"
              ? "pypi-package"
              : selection.ecosystem === "cargo"
                ? "cargo-package"
                : selection.ecosystem === "oci"
                  ? "oci-image"
                  : "npm-package"
            : "url",
        mode: selection.action === "scan" && selection.mode && selection.mode !== "auto" ? selection.mode : undefined,
        depth,
        format: "terminal",
        runtime,
        timeout: selection.action === "scan" ? 30000 : 600000,
        verbose: false,
        packageVersion: undefined,
        sessionUiFactory: async () => ({
          onEvent: (event) => {
            appendTuiTrace({ kind: "session-event", event });
            try {
              state = applySessionEvent(state, event);
              appendTuiTrace({
                kind: "session-state",
                usage: state.usage,
                thinking: state.thinking,
                lastTranscript: state.transcript.at(-1)?.text,
                transcriptCount: state.transcript.length,
              });
              emit();
              appendTuiTrace({ kind: "session-emit-complete", transcriptCount: state.transcript.length });
            } catch (error) {
              appendTuiCrash({
                source: "session-onEvent",
                event,
                state: {
                  thinking: state.thinking,
                  usage: state.usage,
                  transcriptCount: state.transcript.length,
                  lastTranscript: state.transcript.at(-1)?.text,
                },
                error: serializeError(error),
              });
              throw error;
            }
          },
          setReport: (report) => {
            try {
              state = applySessionReport(state, report);
              appendTuiTrace({ kind: "session-report", summary: state.summary, transcriptCount: state.transcript.length });
              emit();
            } catch (error) {
              appendTuiCrash({
                source: "session-setReport",
                report,
                error: serializeError(error),
              });
              throw error;
            }
          },
          waitForExit: () => new Promise<void>((resolve) => { resolveExit = resolve; }),
        }),
      });
    } finally {
      if (previousStartupLogSetting === undefined) delete process.env.PWNKIT_SUPPRESS_PROVIDER_STARTUP_LOG;
      else process.env.PWNKIT_SUPPRESS_PROVIDER_STARTUP_LOG = previousStartupLogSetting;
      if (previousNativeTracePath === undefined) delete process.env.PWNKIT_TRACE_NATIVE_RESPONSES;
      else process.env.PWNKIT_TRACE_NATIVE_RESPONSES = previousNativeTracePath;
      if (previousTuiTracePath === undefined) delete process.env.PWNKIT_TRACE_TUI_EVENTS;
      else process.env.PWNKIT_TRACE_TUI_EVENTS = previousTuiTracePath;
    }
  };

  if (currentRoute.type === "launcher") {
    return <HomeScreen onResolve={(selection) => {
      if (selection.action === "tui") {
        shell.openOps();
        return;
      }
      if (selection.action === "doctor") {
        shell.openDoctor();
        return;
      }
      if (selection.action === "history") {
        shell.openHistory();
        return;
      }
      if (selection.action === "findings") {
        shell.openFindings();
        return;
      }
      if (selection.action === "replay") {
        shell.openReplay();
        return;
      }
      if (onResolve) {
        onResolve(selection);
        onExit();
        return;
      }
      void launchSelection(selection);
    }} onExit={onExit} />;
  }
  if (currentRoute.type === "ops") return <OpsScreen dbPath={currentRoute.dbPath} refreshMs={currentRoute.refreshMs} onExit={onExit} shell={shell} />;
  if (currentRoute.type === "doctor") return <DoctorScreen onExit={onExit} shell={shell} />;
  if (currentRoute.type === "history") return <HistoryScreen dbPath={currentRoute.dbPath} limit={currentRoute.limit} onExit={onExit} shell={shell} />;
  if (currentRoute.type === "findings") return <FindingsScreen options={currentRoute.options} onExit={onExit} shell={shell} />;
  if (currentRoute.type === "session") return <ConsoleSessionRoute route={currentRoute} shell={shell} />;
  return <ReplayScreen dbPath={currentRoute.dbPath} scanId={currentRoute.scanId} onExit={onExit} shell={shell} />;
}

function UnifiedApp({ mode }: { mode: AppMode }) {
  if (mode.type === "home") return <HomeScreen onResolve={mode.onResolve} onExit={mode.onExit} />;
  if (mode.type === "ops") return <OpsScreen dbPath={mode.dbPath} refreshMs={mode.refreshMs} onExit={mode.onExit} />;
  if (mode.type === "doctor") return <DoctorScreen onExit={mode.onExit} />;
  if (mode.type === "history") return <HistoryScreen dbPath={mode.dbPath} limit={mode.limit} onResolve={mode.onResolve} onExit={mode.onExit} />;
  if (mode.type === "findings") return <FindingsScreen options={mode.options} onExit={mode.onExit} />;
  if (mode.type === "replay") return <ReplayScreen dbPath={mode.dbPath} scanId={mode.scanId} onExit={mode.onExit} />;
  if (mode.type === "console") return <ConsoleApp initialRoute={mode.initialRoute} onResolve={mode.onResolve} onExit={mode.onExit} />;

  const [state, setState] = useState(mode.initialState);
  useEffect(() => mode.subscribe(setState), [mode]);
  return <SessionScreen state={state} onExit={mode.onExit} queueUserMessage={mode.queueUserMessage} />;
}

async function mountApp(mode: AppMode): Promise<void> {
  installTuiCrashHandlers();
  const renderer = await createCliRenderer({ exitOnCtrlC: false });
  const root = createRoot(renderer);
  await new Promise<void>((resolve) => {
    const close = () => {
      root.unmount();
      renderer.destroy();
      resolve();
    };
    try {
      root.render(
        <TuiErrorBoundary>
          <UnifiedApp mode={{ ...mode, onExit: close } as AppMode} />
        </TuiErrorBoundary>,
      );
    } catch (error) {
      appendTuiCrash({
        source: "mountApp.render",
        error: serializeError(error),
      });
      throw error;
    }
  });
}

export async function showOpenTuiHome(): Promise<void> {
  await mountApp({
    type: "console",
    initialRoute: { type: "launcher" },
    onExit: () => {},
  });
}

export async function showOpenTuiOps(options: { dbPath?: string; refreshMs: number }): Promise<void> {
  await mountApp({ type: "console", initialRoute: { type: "ops", dbPath: options.dbPath, refreshMs: options.refreshMs }, onResolve: () => {}, onExit: () => {} });
}

export async function showOpenTuiDoctor(): Promise<void> {
  await mountApp({ type: "console", initialRoute: { type: "doctor" }, onResolve: () => {}, onExit: () => {} });
}

export async function showOpenTuiHistory(options: { dbPath?: string; limit: number }): Promise<void> {
  await mountApp({ type: "console", initialRoute: { type: "history", dbPath: options.dbPath, limit: options.limit }, onResolve: () => {}, onExit: () => {} });
}

export async function showOpenTuiFindings(options: FindingsScreenOptions): Promise<void> {
  await mountApp({ type: "console", initialRoute: { type: "findings", options }, onResolve: () => {}, onExit: () => {} });
}

export async function showOpenTuiReplay(options: { dbPath?: string; scanId?: string }): Promise<void> {
  await mountApp({ type: "console", initialRoute: { type: "replay", dbPath: options.dbPath, scanId: options.scanId }, onResolve: () => {}, onExit: () => {} });
}

export async function createOpenTuiSession(options: {
  target: string;
  depth: string;
  mode: SessionMode;
  runtime?: string;
  apiProviderLabel?: string;
  apiConfigured?: boolean;
  apiConnected?: boolean;
  localRuntimes?: string[];
  model?: string;
}): Promise<{
  onEvent: (event: SessionEvent) => void;
  setReport: (report: Record<string, unknown>) => void;
  waitForExit: () => Promise<void>;
  /** Drain and return all pending user messages (called by the agent loop at turn boundaries). */
  getPendingUserMessages: () => string[];
}> {
  let state = createInitialSessionState(options.target, options.depth, options.mode, {
    runtime: options.runtime,
    apiProviderLabel: options.apiProviderLabel,
    apiConfigured: options.apiConfigured,
    apiConnected: options.apiConnected,
    localRuntimes: options.localRuntimes,
    model: options.model,
  });
  const listeners = new Set<(value: SessionState) => void>();
  let resolveExit: (() => void) | null = null;
  const subscribe = (listener: (value: SessionState) => void) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  };
  const emit = () => {
    for (const listener of listeners) listener(state);
  };

  const queueUserMessage = (text: string) => {
    state = { ...state, pendingUserMessages: [...state.pendingUserMessages, text] };
    state = {
      ...state,
      transcript: [
        ...state.transcript,
        {
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          kind: "status" as const,
          text: `message queued: ${text.length > 60 ? text.slice(0, 60) + "..." : text}`,
          tone: "info" as const,
        },
      ],
    };
    emit();
  };

  void mountApp({
    type: "session",
    initialState: state,
    subscribe,
    queueUserMessage,
    onExit: () => {
      resolveExit?.();
      resolveExit = null;
    },
  });

  return {
    onEvent: (event) => {
      state = applySessionEvent(state, event);
      emit();
    },
    setReport: (report) => {
      state = applySessionReport(state, report);
      emit();
    },
    waitForExit: () => new Promise<void>((resolve) => { resolveExit = resolve; }),
    getPendingUserMessages: () => {
      const msgs = state.pendingUserMessages;
      if (msgs.length > 0) {
        state = { ...state, pendingUserMessages: [] };
        emit();
      }
      return msgs;
    },
  };
}

export function isBunRuntime(): boolean {
  return typeof globalThis === "object" && globalThis !== null && "Bun" in globalThis;
}
