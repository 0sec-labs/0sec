/** @jsxImportSource @opentui/react */
import { appendFileSync } from "node:fs";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { createCliRenderer } from "@opentui/core";
import { createRoot, useKeyboard, useTerminalDimensions } from "@opentui/react";
import { VERSION, type Finding, type FindingTriageStatus } from "@0sec/shared";
import type { NativeRuntime, SourceFixResult, SourceFixStatus } from "@0sec/core";
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
  describeFixStatus,
  findingSourcePath,
  fixEligibility,
  fixInputEligibility,
  fixResultLines,
} from "./fix-action.js";
import { ChatScreen, type ChatScreenOptions } from "./chat-screen.js";
import { SettingsScreen } from "./settings-screen.js";
import { createSessionCloseGate } from "./session-close-gate.js";
import { installTuiOutputGuard } from "./output-guard.js";
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
  | { type: "chat"; options?: ChatScreenOptions }
  | { type: "launcher" }
  | { type: "ops"; dbPath?: string; refreshMs: number }
  | { type: "doctor" }
  | { type: "history"; dbPath?: string; limit: number }
  | { type: "findings"; options: FindingsScreenOptions }
  | { type: "replay"; dbPath?: string; scanId?: string }
  | { type: "settings" }
  | { type: "session"; initialState: SessionState; subscribe: (listener: (state: SessionState) => void) => () => void; queueUserMessage?: (text: string) => void; onClose: () => void };

interface ShellNav {
  canGoBack: boolean;
  canGoForward: boolean;
  goBack: () => void;
  goForward: () => void;
  openChat: () => void;
  openLauncher: () => void;
  openOps: () => void;
  openDoctor: () => void;
  openHistory: () => void;
  openFindings: () => void;
  openReplay: (scanId?: string) => void;
  openSettings: () => void;
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
  const file = process.env["0SEC_TRACE_TUI_EVENTS"];
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
  const file = process.env["0SEC_TRACE_TUI_EVENTS"] ?? "/tmp/0sec-tui-crashes.ndjson";
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
      return <CrashPanel message={this.state.error} />;
    }

    return this.props.children;
  }
}

// The boundary itself is a class component and cannot read terminal
// dimensions, so the panel does it: a crash message is arbitrary length and
// a guessed 96-column budget spills past the frame on a narrow terminal.
function CrashPanel({ message }: { message: string }) {
  const { width } = useTerminalDimensions();
  const contentWidth = Math.max(1, width - SHELL_HORIZONTAL_PADDING * 2 - PANEL_HORIZONTAL_CHROME);
  const tracePath = process.env["0SEC_TRACE_TUI_EVENTS"] ?? "/tmp/0sec-tui-crashes.ndjson";

  return (
    <ShellFrame view="crash">
      <box flexDirection="column" width="100%" minWidth={0}>
        <text fg={ERROR}>{fitTuiText("TUI crashed while rendering the current screen.", contentWidth)}</text>
        <text fg={MUTED} wrapMode="word">{fitTuiText(message, contentWidth)}</text>
        <text fg={MUTED}>{fitTuiUrl(`Trace file: ${tracePath}`, contentWidth)}</text>
      </box>
    </ShellFrame>
  );
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
  /**
   * JSON-stringified VerificationSpec as stored by `@0sec/db`. NULL for
   * findings that carry no machine-executable re-check contract. The
   * source-fix action parses it back before asking `fixEligibility`.
   */
  verificationSpec?: string | null;
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

// ── Source-fix action (`f` on the Findings screen) ──
//
// These mirror the defaults of `0sec fix` (packages/cli/src/commands/fix.ts)
// so the TUI and the CLI behave identically. `apply` is deliberately absent:
// the CLI defaults `--apply` to false and applying stays an explicit,
// separate operator action.
const FIX_MODEL_TIMEOUT_MS = 600_000;
const FIX_TEST_TIMEOUT_MS = 300_000;
const FIX_MAX_ATTEMPTS = 3;
/** Operator-owned regression command; `0sec fix` requires --test-command. */
const FIX_TEST_COMMAND_ENV = "0SEC_FIX_TEST_COMMAND";
/** Overrides the scan target as the repo to fix in; `0sec fix` takes <repo>. */
const FIX_REPO_ENV = "0SEC_FIX_REPO";

interface FixRunState {
  findingId: string;
  status: SourceFixStatus | "running";
  result?: SourceFixResult;
  error?: string;
}

function parseVerificationSpec(raw: string | null | undefined): unknown {
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    // A spec that will not parse is the same as no spec for eligibility
    // purposes; `fixEligibility` reports it as a missing contract.
    return undefined;
  }
}

/**
 * Rebuild the `Finding` shape `runSourceFix` reads from a persisted findings
 * row. Only fields the findings table actually stores are populated — in
 * particular `verification_result` and `reviewAnnotation` have no columns, so
 * a row that never carried them stays honestly ineligible.
 */
function findingFromRow(row: FindingsRow): Finding {
  const record: Record<string, unknown> = {
    id: row.id,
    templateId: row.templateId,
    title: row.title,
    description: row.description,
    severity: row.severity,
    category: row.category,
    status: row.status,
    fingerprint: row.fingerprint ?? undefined,
    triageStatus: row.triageStatus ?? undefined,
    timestamp: row.timestamp,
    evidence: {
      request: row.evidenceRequest,
      response: row.evidenceResponse,
      analysis: row.evidenceAnalysis ?? undefined,
    },
    verificationSpec: parseVerificationSpec(row.verificationSpec),
  };
  return record as unknown as Finding;
}

function isNativeRuntime(runtime: unknown): runtime is NativeRuntime {
  return typeof (runtime as Partial<NativeRuntime>)?.executeNative === "function";
}

/** A scan target that carries a scheme is a live host, not a checkout. */
const REMOTE_TARGET_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Where a source fix for this finding would run. `0SEC_FIX_REPO` wins so an
 * operator can point at a checkout that is not the recorded scan target;
 * otherwise the scan target is used, but only when it looks like a path.
 */
function resolveFixRepoRoot(
  row: FindingsRow | null,
  scanTargets: Record<string, string>,
): string | undefined {
  const override = process.env[FIX_REPO_ENV]?.trim();
  if (override) return override;
  if (!row) return undefined;
  const target = scanTargets[row.scanId];
  if (!target || REMOTE_TARGET_PATTERN.test(target)) return undefined;
  return target;
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
      id: "nav-chat",
      title: "Open chat",
      category: "Navigate",
      description: "Return to the operator conversation",
      keybind: "1",
      suggested: true,
      action: shell.openChat,
    },
    {
      id: "nav-launcher",
      title: "Open task launcher",
      category: "Navigate",
      description: "Choose a structured scan, audit, or review",
      keybind: "7",
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
      id: "nav-settings",
      title: "Open settings",
      category: "Navigate",
      description: "Console display, transcript and security toggles",
      keybind: "8",
      suggested: true,
      action: shell.openSettings,
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

function leaveCurrentScreen(shell: ShellNav | undefined, onExit: () => void): void {
  if (shell) {
    shell.goBack();
    return;
  }
  onExit();
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

const SHELL_HORIZONTAL_PADDING = 2;
const PANEL_HORIZONTAL_CHROME = 4;
const OVERLAY_MIN_GUTTER = 2;
const OVERLAY_MAX_WIDTH = 84;
const SESSION_LAYOUT_GAP = 2;
const SESSION_MIN_TRANSCRIPT_WIDTH = 56;
const SESSION_MIN_SIDEBAR_WIDTH = 28;
const SESSION_MAX_SIDEBAR_WIDTH = 40;
const SESSION_MIN_SIDEBAR_HEIGHT = 22;
// BrandStamp paints "0sec" and " v<version>" as two adjacent auto-width
// <text> nodes. VERSION is a build-time string, so a prerelease suffix
// silently widens the stamp; without reserving those cells up front the
// footer hint next to it is shrunk and the two fuse.
const BRAND_STAMP_WIDTH = "0sec".length + " v".length + VERSION.length;
// Below this HeaderBar stacks its two columns, which costs two extra rows.
const HEADER_COMPACT_WIDTH = 88;
// Overlays are anchored at 12% of the terminal height.
const OVERLAY_TOP_RATIO = 0.12;
// Historic caps on overlay list length, kept so a tall terminal renders
// exactly what it did before; the height budget only ever lowers them.
const PALETTE_MAX_COMMANDS = 8;
const TIMELINE_MAX_TURNS = 10;
// Upper bound on how far a wrapped finding detail may run inside its
// scrolling pane, expressed in rows of the pane's own width.
const FINDING_DETAIL_MAX_WRAPPED_ROWS = 40;
// Historic cap on the replay findings list, kept so a tall terminal renders
// what it did before; the height budget only ever lowers it.
const REPLAY_MAX_FINDINGS = 8;
// Historic cap on the live session's sidebar findings list.
const SESSION_MAX_SIDEBAR_FINDINGS = 8;
// A scrollbox reveals its vertical scrollbar the moment its content
// overflows, and the bar takes a column out of the viewport. That is exactly
// the case a list has to survive, so every scrolled column budgets for it.
const SCROLLBAR_COLUMN = 1;

/**
 * Rows ShellFrame spends before a screen's own content: one row of top
 * padding, the bordered header (two border rows, its content rows and a
 * bottom margin) and FooterBar's single row. Screens that render a
 * bordered list need this to know how many rows they may actually claim —
 * a box that asks for more is shrunk by Yoga and then draws its own bottom
 * border straight through its last row.
 */
function getShellChromeHeight(terminalWidth: number): number {
  const headerContentWidth = terminalWidth - SHELL_HORIZONTAL_PADDING * 2 - PANEL_HORIZONTAL_CHROME;
  const headerContentRows = headerContentWidth < HEADER_COMPACT_WIDTH ? 4 : 2;
  return 1 + (headerContentRows + 3) + 1;
}

/** Rows an overlay may fill between its title row and its footer row. */
function getOverlayBodyRows(terminalHeight: number): number {
  // 2 border rows + title row + footer row.
  return Math.max(1, terminalHeight - Math.floor(terminalHeight * OVERLAY_TOP_RATIO) - 4);
}

function getOverlayLayout(terminalWidth: number): {
  left: number;
  width: number;
  contentWidth: number;
} {
  const availableWidth = Math.max(1, terminalWidth - OVERLAY_MIN_GUTTER * 2);
  const width = Math.min(OVERLAY_MAX_WIDTH, availableWidth);
  return {
    left: Math.max(0, Math.floor((terminalWidth - width) / 2)),
    width,
    contentWidth: Math.max(1, width - PANEL_HORIZONTAL_CHROME),
  };
}

function getSessionLayout(terminalWidth: number, terminalHeight: number): {
  contentWidth: number;
  transcriptWidth: number;
  sidebarWidth: number;
  sidebarCanFit: boolean;
} {
  const contentWidth = Math.max(1, terminalWidth - SHELL_HORIZONTAL_PADDING * 2);
  const sidebarWidth = Math.max(
    SESSION_MIN_SIDEBAR_WIDTH,
    Math.min(SESSION_MAX_SIDEBAR_WIDTH, Math.floor(contentWidth * 0.3)),
  );
  const transcriptWidth = Math.max(1, contentWidth - SESSION_LAYOUT_GAP - sidebarWidth);

  return {
    contentWidth,
    transcriptWidth,
    sidebarWidth,
    sidebarCanFit: terminalHeight >= SESSION_MIN_SIDEBAR_HEIGHT
      && transcriptWidth >= SESSION_MIN_TRANSCRIPT_WIDTH,
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
  const { width } = useTerminalDimensions();
  const overlay = getOverlayLayout(width);

  return (
    <box position="absolute" top="12%" left={overlay.left} width={overlay.width} border borderColor={PRIMARY} backgroundColor={PANEL_ALT} paddingX={1} paddingY={0} zIndex={10}>
      <box flexDirection="column" width="100%" minWidth={0}>
        <text fg={PRIMARY}>{fitTuiText(title, overlay.contentWidth)}</text>
        {children}
        <text fg={MUTED}>{fitTuiText(footer, overlay.contentWidth)}</text>
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
  const { width, height } = useTerminalDimensions();
  const contentWidth = getOverlayLayout(width).contentWidth;
  // Every command row is a one-cell rail plus a one-cell margin before its
  // text column, so the title/keybind pair has to be budgeted against what
  // is left after that gutter. Budgeting against contentWidth overspent the
  // row by two cells, and space-between then fused title into keybind.
  const rowWidth = Math.max(1, contentWidth - 2);
  const commandMetaGap = 1;
  const commandTitleWidth = Math.max(1, Math.min(rowWidth - commandMetaGap, Math.floor(rowWidth * 0.62)));
  const commandMetaWidth = Math.max(0, rowWidth - commandTitleWidth - commandMetaGap);
  const queryLabel = "query ";
  const queryWidth = Math.max(1, contentWidth - queryLabel.length - 1);
  // The overlay box has no height of its own: hand it more rows than the
  // terminal has left below its 12% anchor and it is shrunk until the
  // bottom border lands on the last command. One row goes to the query
  // line, and each command renders a title row plus a description row.
  const visibleCommands = Math.max(
    1,
    Math.min(PALETTE_MAX_COMMANDS, Math.floor((getOverlayBodyRows(height) - 1) / 2)),
  );

  return (
    <OverlayFrame title={title} footer="ctrl+p close · enter run · esc cancel">
        <box flexDirection="row" width="100%" minWidth={0}>
          <text flexShrink={0} fg={MUTED}>{queryLabel}</text>
          <box width={queryWidth} flexShrink={0} minWidth={0}>
            <text fg={TEXT}>{fitTuiText(query || "type to filter commands", queryWidth)}</text>
          </box>
          <text width={1} flexShrink={0} fg={INFO}>█</text>
        </box>
        {commands.slice(0, visibleCommands).map((command, index) => {
          const active = index === selected;
          return (
            <box key={command.id} flexDirection="row" width="100%" minWidth={0}>
              <RailBar tone={active ? PRIMARY : BORDER} />
              <box flexDirection="column" marginLeft={1} flexGrow={1} minWidth={0}>
                <box flexDirection="row" width={rowWidth} minWidth={0} gap={commandMetaGap}>
                  <box width={commandTitleWidth} flexShrink={0} minWidth={0}>
                    <text fg={active ? TEXT : "#CCCCCC"}>{fitTuiText(command.title, commandTitleWidth)}</text>
                  </box>
                  {commandMetaWidth > 0 ? (
                    <box width={commandMetaWidth} flexShrink={0} minWidth={0} alignItems="flex-end">
                      <text fg={MUTED}>{fitTuiText(command.keybind ?? command.category, commandMetaWidth)}</text>
                    </box>
                  ) : null}
                </box>
                <text fg={active ? ACCENT : MUTED} wrapMode="word">{fitTuiText(command.description, rowWidth)}</text>
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

function renderToolActionLine(action: string, key: string, maxWidth: number) {
  const parsed = parseToolAction(action);
  const contentWidth = Math.max(8, maxWidth - 2);
  return (
    <box key={key} flexDirection="row" width="100%" minWidth={0}>
      <text width={1} flexShrink={0} fg={parsed.tone}>•</text>
      <box flexDirection="column" marginLeft={1} flexGrow={1} minWidth={0}>
        <text fg={parsed.tone} wrapMode="word">{fitTuiText(parsed.title, contentWidth)}</text>
        {parsed.meta ? <text fg={MUTED}>{fitTuiText(parsed.meta, contentWidth)}</text> : null}
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
  const { width, height } = useTerminalDimensions();
  const contentWidth = Math.max(8, getOverlayLayout(width).contentWidth - 2);
  // Same unbordered-overflow trap as the palette: each turn costs two rows
  // (text plus stage line), so only take the turns the frame can hold.
  const visibleTurns = Math.max(
    1,
    Math.min(TIMELINE_MAX_TURNS, Math.floor(getOverlayBodyRows(height) / 2)),
  );

  return (
    <OverlayFrame title="TURN TIMELINE" footer="ctrl+j close · enter jump · esc cancel">
        {turns.slice(0, visibleTurns).map((turn, index) => {
          const active = index === selected;
          return (
            <box key={turn.id} flexDirection="row" width="100%" minWidth={0}>
              <RailBar tone={active ? PRIMARY : BORDER} />
              <box flexDirection="column" marginLeft={1} flexGrow={1} minWidth={0}>
                <text fg={active ? TEXT : "#CCCCCC"} wrapMode="word">{fitTuiText(turn.text, contentWidth)}</text>
                <text fg={active ? ACCENT : MUTED}>{fitTuiText(`${turn.stage ?? "session"}${turn.turn !== undefined ? ` · turn ${turn.turn}` : ""}`, contentWidth)}</text>
              </box>
            </box>
          );
        })}
    </OverlayFrame>
  );
}

function ComposeOverlay({ text }: { text: string }) {
  const { width } = useTerminalDimensions();
  const contentWidth = getOverlayLayout(width).contentWidth;
  const inputWidth = Math.max(1, contentWidth - 3);

  return (
    <OverlayFrame title="MESSAGE TO AGENT" footer="enter send · esc cancel">
      <text fg={MUTED} wrapMode="word">{fitTuiText("will be injected at next turn boundary", contentWidth)}</text>
      <box flexDirection="row" marginTop={1} width="100%" minWidth={0}>
        <text width={2} flexShrink={0} fg={PRIMARY}>&gt; </text>
        <box width={inputWidth} flexShrink={0} minWidth={0}>
          <text fg={TEXT} wrapMode="word">{fitTuiText(text || " ", inputWidth)}</text>
        </box>
        <text width={1} flexShrink={0} fg={INFO}>█</text>
      </box>
    </OverlayFrame>
  );
}

// Keep every frame four cells wide so the footer never jitters. The animation
// may glitch the wordmark, but it must remain recognizably 0sec.
const BRAND_WORD_FRAMES = [
  "0sec",
  "0sec",
  "0S3c",
  "0sEc",
  "0s3c",
  "0s.c",
  "0sec",
  "0sec",
  "0sec",
  "0sec",
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
      <box flexDirection="row" width={BRAND_STAMP_WIDTH} flexShrink={0}>
        <text width={4} flexShrink={0} fg={muted ? MUTED : PRIMARY}>{animated && !muted ? brand.word : "0sec"}</text>
        <text flexShrink={0} fg={MUTED}>{` v${VERSION}`}</text>
      </box>
      {subtitle ? <text fg={MUTED}>{fitTuiText(subtitle, 36)}</text> : null}
    </box>
  );
}

function BrandStamp({ animated = false }: { animated?: boolean }) {
  const brand = useAnimatedBrand(animated);

  return (
    <box flexDirection="row" width={BRAND_STAMP_WIDTH} flexShrink={0}>
      <text width={4} flexShrink={0} fg={MUTED}>{animated ? brand.word : "0sec"}</text>
      <text flexShrink={0} fg={MUTED}>{` v${VERSION}`}</text>
    </box>
  );
}

function RailBar({ tone }: { tone: string }) {
  return <box width={1} flexShrink={0} alignSelf="stretch" backgroundColor={tone} />;
}

function HeaderBar({
  view,
  status,
}: {
  view: string;
  status?: React.ReactNode;
}) {
  const { width } = useTerminalDimensions();
  const contentWidth = Math.max(1, width - SHELL_HORIZONTAL_PADDING * 2 - PANEL_HORIZONTAL_CHROME);
  const compact = contentWidth < HEADER_COMPACT_WIDTH;
  const inlineViewWidth = Math.max(1, Math.floor(contentWidth * 0.36));
  const inlineStatusWidth = Math.max(1, Math.floor(contentWidth * 0.42));
  const viewWidth = compact ? contentWidth : Math.min(inlineViewWidth, view.toUpperCase().length);
  const titleWidth = compact ? contentWidth : Math.max(1, contentWidth - viewWidth);
  const statusWidth = compact
    ? contentWidth
    : typeof status === "string"
      ? Math.min(inlineStatusWidth, status.length)
      : inlineStatusWidth;
  const descriptionWidth = compact || !status
    ? contentWidth
    : Math.max(1, contentWidth - statusWidth);
  const statusContent = typeof status === "string"
    ? <text fg={MUTED}>{fitTuiText(status, statusWidth)}</text>
    : status;

  return (
    <box border borderColor={BORDER} backgroundColor={PANEL} paddingX={1} paddingY={0} marginBottom={1} width="100%" minWidth={0}>
      <box flexDirection="column" width="100%" minWidth={0}>
        {compact ? (
          <>
            <text fg={TEXT}>{fitTuiText("0SEC TUI CONSOLE", titleWidth)}</text>
            <text fg={PRIMARY}>{fitTuiText(view.toUpperCase(), viewWidth)}</text>
            <text fg={MUTED}>{fitTuiText("Launch targets, monitor sessions, and review findings.", descriptionWidth)}</text>
            {status ? <box width={statusWidth} flexShrink={0} minWidth={0}>{statusContent}</box> : null}
          </>
        ) : (
          <>
            <box flexDirection="row" width="100%" minWidth={0}>
              <box flexGrow={1} minWidth={0}>
                <text fg={TEXT}>{fitTuiText("0SEC TUI CONSOLE", titleWidth)}</text>
              </box>
              <box width={viewWidth} flexShrink={0} flexDirection="column" alignItems="flex-end" minWidth={0}>
                <text fg={PRIMARY}>{fitTuiText(view.toUpperCase(), viewWidth)}</text>
              </box>
            </box>
            <box flexDirection="row" width="100%" minWidth={0}>
              <box flexGrow={1} minWidth={0}>
                <text fg={MUTED}>{fitTuiText("Launch targets, monitor sessions, and review findings.", descriptionWidth)}</text>
              </box>
              {status ? <box width={statusWidth} flexShrink={0} flexDirection="column" alignItems="flex-end" minWidth={0}>{statusContent}</box> : null}
            </box>
          </>
        )}
      </box>
    </box>
  );
}

/**
 * Cell budget for the footer row. The brand stamp is the one sibling that
 * must never be clipped, so it is reserved first and everything else is
 * derived from the remainder. The previous budget subtracted a flat 30
 * cells for the status but then handed the status text `contentWidth - 12`
 * to fill, so a long counter was painted straight through the wordmark.
 */
function getFooterLayout(terminalWidth: number, hasStatus: boolean): {
  inline: boolean;
  contentWidth: number;
  hintWidth: number;
  statusWidth: number;
  statusGap: number;
} {
  const contentWidth = Math.max(1, terminalWidth - SHELL_HORIZONTAL_PADDING * 2);
  const inline = contentWidth >= 64;
  const statusGap = hasStatus ? 2 : 0;
  // Inline, the hint keeps at least eight cells; stacked, the status owns a
  // row of its own and only has to leave room for the stamp beside it.
  const statusRoom = Math.max(1, contentWidth - BRAND_STAMP_WIDTH - statusGap - (inline ? 8 : 0));
  const statusWidth = hasStatus
    ? Math.max(1, Math.min(Math.floor(contentWidth * 0.4), statusRoom))
    : 0;
  const hintWidth = inline
    ? Math.max(1, contentWidth - BRAND_STAMP_WIDTH - statusWidth - statusGap)
    : contentWidth;

  return { inline, contentWidth, hintWidth, statusWidth, statusGap };
}

function FooterBar({ hint, status }: { hint: string; status?: React.ReactNode }) {
  const { width } = useTerminalDimensions();
  const footer = getFooterLayout(width, Boolean(status));

  return (
    <box flexDirection={footer.inline ? "row" : "column"} width="100%" minWidth={0}>
      <box width={footer.inline ? footer.hintWidth : "100%"} flexShrink={0} minWidth={0}>
        <text fg={MUTED} wrapMode="word">{fitTuiText(hint, footer.hintWidth)}</text>
      </box>
      <box flexDirection="row" flexShrink={0} marginTop={footer.inline ? 0 : 1}>
        {status ? (
          <box width={footer.statusWidth} flexShrink={0} minWidth={0} marginRight={footer.statusGap}>
            {typeof status === "string" ? <text fg={MUTED}>{fitTuiText(status, footer.statusWidth)}</text> : status}
          </box>
        ) : null}
        <box width={BRAND_STAMP_WIDTH} flexShrink={0} minWidth={0}>
          <BrandStamp animated />
        </box>
      </box>
    </box>
  );
}

function LiveBadge({ label, active = true }: { label: string; active?: boolean }) {
  const { width } = useTerminalDimensions();
  // The badge is only ever rendered as FooterBar's status, so it spends the
  // cells the footer reserved for that slot — the dot and the space in front
  // of the label come out of that allowance rather than being added to it.
  const labelWidth = Math.max(1, getFooterLayout(width, true).statusWidth - 2);

  return (
    <box flexDirection="row" width="100%" minWidth={0}>
      <text width={1} flexShrink={0} fg={active ? SUCCESS : MUTED}>●</text>
      <text flexShrink={0} fg={MUTED}>{` ${fitTuiText(label, labelWidth)}`}</text>
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
        return <text key={`${index}-${char}`} width={1} flexShrink={0} fg={fg}>{char}</text>;
      })}
    </box>
  );
}

function WorkingPulse({ label, detail, maxWidth }: { label: string; detail?: string; maxWidth: number }) {
  const [frame, setFrame] = useState(0);
  const contentWidth = Math.max(12, maxWidth);

  useEffect(() => {
    const timer = setInterval(() => {
      setFrame((current) => (current + 1) % 6);
    }, 120);
    return () => clearInterval(timer);
  }, []);

  const loader = ["[   ]", "[=  ]", "[== ]", "[===]", "[ ==]", "[  =]"][frame] ?? "[   ]";
  // The rail cell, its margin and the panel's own horizontal padding are
  // spent before any text is drawn, and the loader block plus its margin
  // take another six from the label row. The detail line used to be budgeted
  // against the full transcript width and ran past the panel edge.
  const innerWidth = Math.max(8, contentWidth - 4);
  const labelWidth = Math.max(1, innerWidth - loader.length - 1);

  return (
    <box flexDirection="row" marginTop={1} width="100%" minWidth={0}>
      <RailBar tone={PRIMARY} />
      <box flexDirection="column" marginLeft={1} backgroundColor={PANEL_ALT} paddingX={1} flexGrow={1} minWidth={0}>
        <box flexDirection="row" width="100%" minWidth={0}>
          <text width={loader.length} flexShrink={0} fg={ACCENT}>{loader}</text>
          <box width={labelWidth} flexShrink={0} marginLeft={1} minWidth={0}>
            <ShimmerLabel text={fitTuiText(label, labelWidth)} />
          </box>
        </box>
        {detail ? <text fg={MUTED} wrapMode="word">{fitTuiText(detail, innerWidth)}</text> : null}
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
    contentWidth: number;
  },
) {
  const contentWidth = Math.max(12, options.contentWidth);
  // Every variant starts with a one-cell rail and a one-cell margin, and the
  // padded and bordered variants spend more on top of that. Budgeting all of
  // them against the raw transcript width let each one overrun its own box —
  // and on the bordered tool card that meant the header row fused.
  const railedWidth = Math.max(8, contentWidth - 2);
  const paddedWidth = Math.max(8, railedWidth - 2);
  const cardWidth = Math.max(8, railedWidth - 4);

  if (item.kind === "turn") {
    return (
      <box key={item.id} flexDirection="row" marginTop={1} width="100%" minWidth={0}>
        <RailBar tone={PRIMARY} />
        <box flexDirection="column" marginLeft={1} backgroundColor={PANEL_ALT} paddingX={1} flexGrow={1} minWidth={0}>
          <text fg={TEXT} wrapMode="word">{fitTuiText(item.text.toUpperCase(), paddedWidth)}</text>
          <text fg={MUTED}>{fitTuiText(`${item.stage ?? "session"}${item.turn !== undefined ? ` · operator turn ${item.turn}` : ""}`, paddedWidth)}</text>
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
    const controlWidth = isExpandable && cardWidth >= 40
      ? Math.min(22, Math.floor(cardWidth * 0.4))
      : 0;
    const controlGap = controlWidth > 0 ? 1 : 0;
    const titleWidth = Math.max(1, cardWidth - controlWidth - controlGap);
    return (
      <box key={item.id} flexDirection="row" width="100%" minWidth={0}>
        <RailBar tone={isHovered ? PRIMARY : railTone(item)} />
        <box
          flexDirection="column"
          marginLeft={1}
          backgroundColor={isHovered ? PANEL : PANEL_ALT}
          border
          borderColor={isHovered || isExpanded ? PRIMARY : BORDER}
          paddingX={1}
          paddingY={0}
          flexGrow={1}
          minWidth={0}
          onMouseDown={isExpandable ? () => options.toggleExpanded(item.id) : undefined}
          onMouseOver={isExpandable ? () => options.setHoveredToolId(item.id) : undefined}
          onMouseOut={isExpandable ? () => options.setHoveredToolId(null) : undefined}
        >
          <box flexDirection="row" width={cardWidth} minWidth={0} gap={controlGap}>
            <box width={titleWidth} flexShrink={0} minWidth={0}>
              <text fg={isHovered ? PRIMARY : TEXT}>{fitTuiText((item.label ?? "Actions").toUpperCase(), titleWidth)}</text>
            </box>
            {controlWidth > 0 ? (
              <box width={controlWidth} flexShrink={0} minWidth={0} alignItems="flex-end">
                <text fg={isHovered ? ACCENT : MUTED}>{fitTuiText(isExpanded ? "click to collapse" : "click to expand", controlWidth)}</text>
              </box>
            ) : null}
          </box>
          <text fg={MUTED}>{fitTuiText(`${item.stage}${item.turn !== undefined ? ` · turn ${item.turn}` : ""}`, cardWidth)}</text>
          <text fg={MUTED} wrapMode="word">{fitTuiText(item.text, cardWidth)}</text>
          {(isExpanded ? actions : preview).map((action, index) => renderToolActionLine(action, `${item.id}-${index}`, cardWidth))}
          {isExpandable && !isExpanded ? <text fg={MUTED}>{fitTuiText(`${actions.length - preview.length} more hidden`, cardWidth)}</text> : null}
        </box>
      </box>
    );
  }

  if (item.kind === "user-inject") {
    return (
      <box key={item.id} flexDirection="row" width="100%" minWidth={0}>
        <RailBar tone={ACCENT} />
        <box flexDirection="column" marginLeft={1} flexGrow={1} minWidth={0}>
          <text fg={ACCENT}>{fitTuiText("USER MESSAGE INJECTED", railedWidth)}</text>
          <text fg={TEXT} wrapMode="word">{fitTuiText(item.text, railedWidth)}</text>
        </box>
      </box>
    );
  }

  return (
    <box key={item.id} flexDirection="row" width="100%" minWidth={0}>
      <RailBar tone={railTone(item)} />
      <box flexDirection="column" marginLeft={1} flexGrow={1} minWidth={0}>
        {item.stage ? <text fg={MUTED}>{fitTuiText(item.stage, railedWidth)}</text> : null}
        <text fg={textTone(item)} wrapMode="word">{fitTuiText(item.text, railedWidth)}</text>
      </box>
    </box>
  );
}

function PanelSection({
  title,
  tone,
  contentWidth,
  children,
}: {
  title: string;
  tone: string;
  /** Inner cells the section was given; the title is budgeted against it. */
  contentWidth?: number;
  children: React.ReactNode;
}) {
  return (
    // flexShrink is off because the section draws its own border: squeeze it
    // and Yoga paints that bottom border straight through the last row of
    // content. Overflowing off-screen is recoverable; a corrupt frame is not.
    <box flexDirection="column" flexShrink={0} minWidth={0} border borderColor={tone} backgroundColor={PANEL} paddingX={1} paddingY={0}>
      <text fg={tone}>{fitTuiText(title.toUpperCase(), contentWidth ?? 44)}</text>
      <box flexDirection="column" minWidth={0}>
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

function HomeScreen({ onResolve, onExit, shell }: { onResolve: (selection: HomeSelection) => void; onExit: () => void; shell?: ShellNav }) {
  const [phase, setPhase] = useState<"menu" | "compose">("menu");
  const [selected, setSelected] = useState(0);
  const [action, setAction] = useState<HomeAction>("scan");
  const [inputValue, setInputValue] = useState("");
  const [focusIndex, setFocusIndex] = useState(0);
  const [runtime, setRuntime] = useState<LaunchRuntime>("auto");
  const [depth, setDepth] = useState<LaunchDepth>("default");
  const [scanMode, setScanMode] = useState<LaunchScanMode>("auto");
  const [ecosystem, setEcosystem] = useState<LaunchEcosystem>("npm");
  const { width, height } = useTerminalDimensions();
  const homeContentWidth = Math.max(1, width - SHELL_HORIZONTAL_PADDING * 2);
  const homePanelContentWidth = Math.max(0, homeContentWidth - PANEL_HORIZONTAL_CHROME);
  const homeRowContentWidth = Math.max(0, homePanelContentWidth - 2);
  // Both phases render a bordered box whose rows are fixed by its contents:
  // two rows per option/field, plus a hint row while composing. Yoga shrinks
  // a box that wants more rows than the column has and then paints the
  // box's own bottom border through its last row, which is how the menu
  // turned into `-/clear--------/new-`. Take only the rows the frame can
  // actually spare, and window the list so the cursor stays on screen.
  const homeBodyRows = Math.max(2, height - getShellChromeHeight(width) - 2);

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
      shell?.goBack();
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

  const visibleOptionCount = Math.max(1, Math.min(HOME_OPTIONS.length, Math.floor(homeBodyRows / 2)));
  const optionWindowStart = Math.max(
    0,
    Math.min(selected - visibleOptionCount + 1, HOME_OPTIONS.length - visibleOptionCount),
  );
  // The compose panel spends one of its rows on the key hint under the fields.
  const visibleFieldCount = Math.max(1, Math.min(composeFields.length, Math.floor((homeBodyRows - 1) / 2)));
  const fieldWindowStart = Math.max(
    0,
    Math.min(focusIndex - visibleFieldCount + 1, composeFields.length - visibleFieldCount),
  );

  return (
    <ShellFrame view="launcher">
      {palette.paletteOpen ? <PaletteOverlay title="Console commands" query={palette.paletteQuery} selected={palette.paletteSelected} commands={palette.filteredPalette} /> : null}
      <box flexDirection="column" width="100%" minWidth={0}>
        {phase === "menu" ? (
          <box flexDirection="column" width="100%" minWidth={0} height={visibleOptionCount * 2 + 2} flexShrink={0} border borderColor={BORDER} backgroundColor={PANEL} paddingX={1} paddingY={0}>
            {HOME_OPTIONS.slice(optionWindowStart, optionWindowStart + visibleOptionCount).map((option, windowIndex) => {
              const index = optionWindowStart + windowIndex;
              const active = index === selected;
              return (
                <box key={option.value} flexDirection="row" width="100%" minWidth={0}>
                  <RailBar tone={active ? PRIMARY : BORDER} />
                  <box flexDirection="column" marginLeft={1} flexGrow={1} minWidth={0}>
                    <text fg={active ? TEXT : "#CCCCCC"}>{fitTuiText(active ? option.label.toUpperCase() : option.label, homeRowContentWidth)}</text>
                    <text fg={active ? ACCENT : MUTED}>{fitTuiText(option.hint, homeRowContentWidth)}</text>
                  </box>
                </box>
              );
            })}
          </box>
        ) : (
          <box flexDirection="column" width="100%" minWidth={0} height={visibleFieldCount * 2 + 3} flexShrink={0} border borderColor={PRIMARY} backgroundColor={PANEL} paddingX={1} paddingY={0}>
            {composeFields.slice(fieldWindowStart, fieldWindowStart + visibleFieldCount).map((field, windowIndex) => {
              const fieldIndex = fieldWindowStart + windowIndex;
              const active = fieldIndex === focusIndex;
              const fieldHelp = field.editable ? "type" : "left/right";
              const cursorWidth = active && field.editable ? 1 : 0;
              const fieldHelpWidth = Math.min(fieldHelp.length, Math.floor(homeRowContentWidth / 3));
              const fieldGapWidth = fieldHelpWidth > 0 ? 1 : 0;
              const fieldValueWidth = Math.max(0, homeRowContentWidth - fieldHelpWidth - cursorWidth - fieldGapWidth);
              return (
                <box key={field.key} flexDirection="row" width="100%" minWidth={0}>
                  <RailBar tone={active ? PRIMARY : BORDER} />
                  <box flexDirection="column" marginLeft={1} flexGrow={1} minWidth={0}>
                    <text fg={active ? TEXT : MUTED}>{fitTuiText(field.label, homeRowContentWidth)}</text>
                    <box flexDirection="row" width={homeRowContentWidth} minWidth={0} gap={fieldGapWidth}>
                      <box flexDirection="row" width={fieldValueWidth + cursorWidth} flexShrink={0} minWidth={0}>
                        <box width={fieldValueWidth} flexShrink={0} minWidth={0}>
                          <text fg={field.value ? (active ? TEXT : "#CCCCCC") : MUTED}>{fitTuiText(field.value || "", fieldValueWidth, { mode: field.key === "target" ? "middle" : "end" })}</text>
                        </box>
                        {active && field.editable ? <text width={1} flexShrink={0} fg={INFO}>█</text> : null}
                      </box>
                      {fieldHelpWidth > 0 ? (
                        <box width={fieldHelpWidth} flexShrink={0} minWidth={0} alignItems="flex-end">
                          <text fg={active ? ACCENT : MUTED}>{fitTuiText(fieldHelp, fieldHelpWidth)}</text>
                        </box>
                      ) : null}
                    </box>
                  </box>
                </box>
              );
            })}
            <text fg={MUTED}>{fitTuiText("enter launch · esc back · ctrl+p commands · up/down focus", homePanelContentWidth)}</text>
          </box>
        )}
        <FooterBar hint="esc back · ctrl+p commands · ctrl+c exit" />
      </box>
    </ShellFrame>
  );
}

function OpsScreen({ dbPath, refreshMs, onExit, shell }: { dbPath?: string; refreshMs: number; onExit: () => void; shell?: ShellNav }) {
  const [snapshot, setSnapshot] = useState<OpsSnapshot>({ scans: [], findings: [], incidents: [] });
  const [error, setError] = useState<string | null>(null);
  const { width, height } = useTerminalDimensions();
  const contentWidth = Math.max(1, width - SHELL_HORIZONTAL_PADDING * 2);
  const metricsInline = contentWidth >= 84;
  const metricGap = 1;
  const metricWidth = metricsInline
    ? Math.max(1, Math.floor((contentWidth - metricGap * 2) / 3))
    : contentWidth;
  const metricContentWidth = Math.max(1, metricWidth - PANEL_HORIZONTAL_CHROME);
  // fitTuiText sanitizes before it truncates, and sanitizing trims: a label
  // handed in as "runs " came back as "runs" and the value fused onto it
  // ("runs12"). The separator is a row gap now, and the label budget stops
  // pretending to own that cell.
  const metricLabelGap = 1;
  const runsLabelWidth = Math.min("runs".length, Math.max(0, metricContentWidth - metricLabelGap - 1));
  const findingsLabelWidth = Math.min("findings".length, Math.max(0, metricContentWidth - metricLabelGap - 1));
  const incidentsLabelWidth = Math.min("incidents".length, Math.max(0, metricContentWidth - metricLabelGap - 1));
  const panelsInline = contentWidth >= 96;
  const panelGap = panelsInline ? 2 : 1;
  const panelWidth = panelsInline
    ? Math.max(1, Math.floor((contentWidth - panelGap) / 2))
    : contentWidth;
  const panelContentWidth = Math.max(1, panelWidth - PANEL_HORIZONTAL_CHROME);
  // Neither panel scrolls, so the row count has to come from the frame: a
  // section handed more rows than the column has is shrunk until its own
  // bottom border is painted through its last entry. The metric strip above
  // is three rows plus a margin inline, or three chips deep when stacked;
  // each section then spends two border rows and a title row before content,
  // and every run/incident renders on three lines.
  const metricsBlockRows = metricsInline ? 4 : 3 * 3 + metricGap * 2 + 1;
  const panelRows = Math.max(4, height - getShellChromeHeight(width) - metricsBlockRows - (error ? 1 : 0));
  const panelBodyRows = Math.max(1, (panelsInline ? panelRows : Math.floor((panelRows - panelGap) / 2)) - 3);
  const visiblePanelEntries = Math.max(1, Math.floor(panelBodyRows / 3));
  const palette = usePaletteController([
    {
      id: "back-ops",
      title: "Go back",
      category: "Navigate",
      description: "Return to the previous console screen",
      keybind: "esc",
      suggested: true,
      action: () => leaveCurrentScreen(shell, onExit),
    },
    ...createShellCommands(shell),
  ]);

  useEffect(() => {
    let alive = true;
    const refresh = async () => {
      try {
        const { osecDB } = await import("@0sec/db");
        const db = new osecDB(dbPath);
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
    if ((key.ctrl && key.name === "c") || key.name === "q") {
      onExit();
      return;
    }
    if (key.name === "escape") {
      leaveCurrentScreen(shell, onExit);
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
      <box flexDirection={metricsInline ? "row" : "column"} gap={metricGap} marginBottom={1} width="100%" minWidth={0}>
        <box width={metricWidth} flexGrow={metricsInline ? 1 : 0} flexShrink={0} minWidth={0}>
          <box border borderColor={PRIMARY} backgroundColor={PANEL} paddingX={1} width="100%" minWidth={0}>
            <box flexDirection="row" width="100%" minWidth={0} gap={metricLabelGap}>
              {runsLabelWidth > 0 ? <text width={runsLabelWidth} flexShrink={0} fg={TEXT}>{fitTuiText("runs", runsLabelWidth)}</text> : null}
              <text fg={PRIMARY}>{fitTuiText(String(snapshot.scans.length), Math.max(1, metricContentWidth - runsLabelWidth - metricLabelGap))}</text>
            </box>
          </box>
        </box>
        <box width={metricWidth} flexGrow={metricsInline ? 1 : 0} flexShrink={0} minWidth={0}>
          <box border borderColor={PRIMARY} backgroundColor={PANEL} paddingX={1} width="100%" minWidth={0}>
            <box flexDirection="row" width="100%" minWidth={0} gap={metricLabelGap}>
              {findingsLabelWidth > 0 ? <text width={findingsLabelWidth} flexShrink={0} fg={TEXT}>{fitTuiText("findings", findingsLabelWidth)}</text> : null}
              <text fg={PRIMARY}>{fitTuiText(String(snapshot.findings.length), Math.max(1, metricContentWidth - findingsLabelWidth - metricLabelGap))}</text>
            </box>
          </box>
        </box>
        <box width={metricWidth} flexGrow={metricsInline ? 1 : 0} flexShrink={0} minWidth={0}>
          <box border borderColor={snapshot.incidents.length > 0 ? ERROR : BORDER} backgroundColor={PANEL} paddingX={1} width="100%" minWidth={0}>
            <box flexDirection="row" width="100%" minWidth={0} gap={metricLabelGap}>
              {incidentsLabelWidth > 0 ? <text width={incidentsLabelWidth} flexShrink={0} fg={TEXT}>{fitTuiText("incidents", incidentsLabelWidth)}</text> : null}
              <text fg={snapshot.incidents.length > 0 ? ERROR : MUTED}>{fitTuiText(String(snapshot.incidents.length), Math.max(1, metricContentWidth - incidentsLabelWidth - metricLabelGap))}</text>
            </box>
          </box>
        </box>
      </box>
      {error ? <text fg={ERROR}>{fitTuiText(error, contentWidth)}</text> : null}
      <box flexDirection={panelsInline ? "row" : "column"} gap={panelGap} flexGrow={1} width="100%" minWidth={0}>
        <box width={panelWidth} flexGrow={panelsInline ? 1 : 0} flexShrink={0} minWidth={0}>
          <PanelSection title="Recent runs" contentWidth={panelContentWidth} tone={BORDER}>
            {snapshot.scans.length === 0 ? <text fg={MUTED}>{fitTuiText("No local scans yet.", panelContentWidth)}</text> : snapshot.scans.slice(0, visiblePanelEntries).map((scan) => {
              const summary = parseSummary(scan.summary);
              return (
                <box key={scan.id} flexDirection="column" minWidth={0}>
                  <text fg={TEXT}>{fitTuiUrl(scan.target, panelContentWidth)}</text>
                  <text fg={MUTED}>{fitTuiText(`${scan.mode}/${scan.depth} · ${scan.runtime} · ${scan.status}`, panelContentWidth)}</text>
                  <text fg={MUTED}>{fitTuiText(`${summary.totalFindings ?? 0} findings · ${formatDuration(scan.durationMs)}`, panelContentWidth)}</text>
                </box>
              );
            })}
          </PanelSection>
        </box>
        <box width={panelWidth} flexGrow={panelsInline ? 1 : 0} flexShrink={0} minWidth={0}>
          <PanelSection title="Recent incidents" contentWidth={panelContentWidth} tone={snapshot.incidents.length > 0 ? ERROR : BORDER}>
            {snapshot.incidents.length === 0 ? <text fg={SUCCESS}>{fitTuiText("No recent runtime incidents.", panelContentWidth)}</text> : snapshot.incidents.slice(0, visiblePanelEntries).map((incident, index) => (
              <box key={`${incident.scanId}-${index}`} flexDirection="column" minWidth={0}>
                <text fg={TEXT}>{fitTuiUrl(incident.target, panelContentWidth)}</text>
                <text fg={ERROR}>{fitTuiText(incident.headline, panelContentWidth)}</text>
                <text fg={MUTED}>{fitTuiText(incident.stage, panelContentWidth)}</text>
              </box>
            ))}
          </PanelSection>
        </box>
      </box>
      <FooterBar hint="esc back · ctrl+p commands · ctrl+c exit" />
    </ShellFrame>
  );
}

function DoctorScreen({ onExit, shell }: { onExit: () => void; shell?: ShellNav }) {
  const [state, setState] = useState<DoctorState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { width, height } = useTerminalDimensions();
  const contentWidth = Math.max(1, width - SHELL_HORIZONTAL_PADDING * 2);
  const metricsInline = contentWidth >= 84;
  const metricGap = 1;
  const metricWidth = metricsInline
    ? Math.max(1, Math.floor((contentWidth - metricGap * 2) / 3))
    : contentWidth;
  const metricContentWidth = Math.max(1, metricWidth - PANEL_HORIZONTAL_CHROME);
  // As in mission control: fitTuiText trims, so labels carrying their own
  // trailing space came back without one and fused onto the value
  // ("nodev22.4.1"). The gap between them is a layout gap now.
  const metricLabelGap = 1;
  const nodeLabelWidth = Math.min("node".length, Math.max(0, metricContentWidth - metricLabelGap - 1));
  const apiLabelWidth = Math.min("api".length, Math.max(0, metricContentWidth - metricLabelGap - 1));
  const cliLabelWidth = Math.min("cli".length, Math.max(0, metricContentWidth - metricLabelGap - 1));
  const panelsInline = contentWidth >= 96;
  const panelGap = panelsInline ? 2 : 1;
  const panelWidth = panelsInline
    ? Math.max(1, Math.floor((contentWidth - panelGap) / 2))
    : contentWidth;
  const panelContentWidth = Math.max(1, panelWidth - PANEL_HORIZONTAL_CHROME);
  // Same unscrolled-section arithmetic as mission control. Only the sample
  // command block is optional, so that is what gives when the frame is short.
  const metricsBlockRows = metricsInline ? 4 : 3 * 3 + metricGap * 2 + 1;
  const panelRows = Math.max(4, height - getShellChromeHeight(width) - metricsBlockRows - (error ? 1 : 0));
  const panelBodyRows = Math.max(1, (panelsInline ? panelRows : Math.floor((panelRows - panelGap) / 2)) - 3);
  const showNextStepExamples = panelBodyRows >= 4;
  const palette = usePaletteController([
    {
      id: "back-doctor",
      title: "Go back",
      category: "Navigate",
      description: "Return to the previous console screen",
      keybind: "esc",
      suggested: true,
      action: () => leaveCurrentScreen(shell, onExit),
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
    if ((key.ctrl && key.name === "c") || key.name === "q") {
      onExit();
      return;
    }
    if (key.name === "escape") {
      leaveCurrentScreen(shell, onExit);
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
      ? "Upgrade to Node 20+ before running 0sec."
      : state.apiRuntime.configured && !state.apiRuntime.valid && state.apiRuntime.error
        ? "Repair the configured API runtime before scanning."
        : state.hasApiKey || state.availableRuntimes.length > 0
          ? "Ready to scan. Try scan, review, or audit from the launcher."
          : "Install Claude/Codex/Gemini CLI or set an API key.";

  return (
    <ShellFrame view="doctor">
      {palette.paletteOpen ? <PaletteOverlay title="Doctor commands" query={palette.paletteQuery} selected={palette.paletteSelected} commands={palette.filteredPalette} /> : null}
      <box flexDirection={metricsInline ? "row" : "column"} gap={metricGap} marginBottom={1} width="100%" minWidth={0}>
        <box width={metricWidth} flexGrow={metricsInline ? 1 : 0} flexShrink={0} minWidth={0}>
          <box border borderColor={state?.nodeOk ? SUCCESS : ERROR} backgroundColor={PANEL} paddingX={1} width="100%" minWidth={0}>
            <box flexDirection="row" width="100%" minWidth={0} gap={metricLabelGap}>
              {nodeLabelWidth > 0 ? <text width={nodeLabelWidth} flexShrink={0} fg={TEXT}>{fitTuiText("node", nodeLabelWidth)}</text> : null}
              <text fg={state?.nodeOk ? SUCCESS : ERROR}>{fitTuiText(state?.nodeVersion ?? "checking", Math.max(1, metricContentWidth - nodeLabelWidth - metricLabelGap))}</text>
            </box>
          </box>
        </box>
        <box width={metricWidth} flexGrow={metricsInline ? 1 : 0} flexShrink={0} minWidth={0}>
          <box border borderColor={state?.hasApiKey ? SUCCESS : state?.apiRuntime.configured ? ERROR : WARNING} backgroundColor={PANEL} paddingX={1} width="100%" minWidth={0}>
            <box flexDirection="row" width="100%" minWidth={0} gap={metricLabelGap}>
              {apiLabelWidth > 0 ? <text width={apiLabelWidth} flexShrink={0} fg={TEXT}>{fitTuiText("api", apiLabelWidth)}</text> : null}
              <text fg={state?.hasApiKey ? SUCCESS : state?.apiRuntime.configured ? ERROR : WARNING}>{fitTuiText(state?.apiRuntime.providerLabel ?? "checking", Math.max(1, metricContentWidth - apiLabelWidth - metricLabelGap))}</text>
            </box>
          </box>
        </box>
        <box width={metricWidth} flexGrow={metricsInline ? 1 : 0} flexShrink={0} minWidth={0}>
          <box border borderColor={state && state.availableRuntimes.length > 0 ? SUCCESS : WARNING} backgroundColor={PANEL} paddingX={1} width="100%" minWidth={0}>
            <box flexDirection="row" width="100%" minWidth={0} gap={metricLabelGap}>
              {cliLabelWidth > 0 ? <text width={cliLabelWidth} flexShrink={0} fg={TEXT}>{fitTuiText("cli", cliLabelWidth)}</text> : null}
              <text fg={state && state.availableRuntimes.length > 0 ? SUCCESS : WARNING}>{fitTuiText(state ? (state.availableRuntimes.join(", ") || "none") : "checking", Math.max(1, metricContentWidth - cliLabelWidth - metricLabelGap))}</text>
            </box>
          </box>
        </box>
      </box>
      {error ? <text fg={ERROR}>{fitTuiText(error, contentWidth)}</text> : null}
      <box flexDirection={panelsInline ? "row" : "column"} gap={panelGap} flexGrow={1} width="100%" minWidth={0}>
        <box width={panelWidth} flexGrow={panelsInline ? 1 : 0} flexShrink={0} minWidth={0}>
          <PanelSection title="Environment" contentWidth={panelContentWidth} tone={BORDER}>
            <box flexDirection="column" minWidth={0}>
              <text fg={TEXT}>{fitTuiText("Node.js", panelContentWidth)}</text>
              <text fg={MUTED}>{fitTuiText(state ? `${state.nodeOk ? "ok" : "bad"} · ${state.nodeVersion}` : "checking", panelContentWidth)}</text>
              <text fg={TEXT}>{fitTuiText("API runtime", panelContentWidth)}</text>
              <text fg={MUTED}>{fitTuiText(state ? `${state.hasApiKey ? "ok" : state.apiRuntime.configured ? "bad" : "missing"} · ${state.apiRuntime.providerLabel}` : "checking", panelContentWidth)}</text>
              <text fg={TEXT}>{fitTuiText("CLI runtimes", panelContentWidth)}</text>
              <text fg={MUTED}>{fitTuiText(state ? `${state.availableRuntimes.length > 0 ? "ok" : "missing"} · ${state.availableRuntimes.join(", ") || "none"}` : "checking", panelContentWidth)}</text>
            </box>
          </PanelSection>
        </box>
        <box width={panelWidth} flexGrow={panelsInline ? 1 : 0} flexShrink={0} minWidth={0}>
          <PanelSection title="Next steps" contentWidth={panelContentWidth} tone={PRIMARY}>
            <box flexDirection="column" minWidth={0}>
              <text fg={TEXT}>{fitTuiText(nextStep, panelContentWidth)}</text>
              {showNextStepExamples && (state?.hasApiKey || (state && state.availableRuntimes.length > 0)) ? (
                <>
                  <text fg={MUTED}>{fitTuiText("0sec scan --target https://example.com --mode web", panelContentWidth)}</text>
                  <text fg={MUTED}>{fitTuiText("0sec review .", panelContentWidth)}</text>
                  <text fg={MUTED}>{fitTuiText("0sec audit express", panelContentWidth)}</text>
                </>
              ) : null}
              {state?.apiRuntime.error ? <text fg={ERROR}>{fitTuiText(state.apiRuntime.error, panelContentWidth)}</text> : null}
            </box>
          </PanelSection>
        </box>
      </box>
      <FooterBar hint="esc back · ctrl+p commands · ctrl+c exit" />
    </ShellFrame>
  );
}

function HistoryScreen({ dbPath, limit, onResolve, onExit, shell }: { dbPath?: string; limit: number; onResolve?: (selection: HistorySelection) => void; onExit: () => void; shell?: ShellNav }) {
  const [scans, setScans] = useState<HistoryScanRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [index, setIndex] = useState(0);
  const { width, height } = useTerminalDimensions();
  const historyLayout = getSessionLayout(width, height);
  const historyUsesSideBySideLayout = historyLayout.sidebarCanFit;
  const historyListWidth = historyUsesSideBySideLayout
    ? historyLayout.transcriptWidth
    : historyLayout.contentWidth;
  const historyDetailWidth = historyUsesSideBySideLayout
    ? historyLayout.sidebarWidth
    : historyLayout.contentWidth;
  const historyListContentWidth = Math.max(0, historyListWidth - PANEL_HORIZONTAL_CHROME - SCROLLBAR_COLUMN);
  const historyListRowWidth = Math.max(0, historyListContentWidth - 2);
  const historyDetailContentWidth = Math.max(0, historyDetailWidth - PANEL_HORIZONTAL_CHROME);
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
      id: "back-history",
      title: "Go back",
      category: "Navigate",
      description: "Return to the previous console screen",
      keybind: "esc",
      suggested: true,
      action: () => leaveCurrentScreen(shell, onExit),
    },
    ...createShellCommands(shell),
  ]);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const { osecDB } = await import("@0sec/db");
        const db = new osecDB(dbPath);
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
    if ((key.ctrl && key.name === "c") || key.name === "q") {
      onExit();
      return;
    }
    if (key.name === "escape") {
      leaveCurrentScreen(shell, onExit);
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
      {error ? <text fg={ERROR}>{fitTuiText(error, historyLayout.contentWidth)}</text> : null}
      <box
        flexDirection={historyUsesSideBySideLayout ? "row" : "column"}
        gap={historyUsesSideBySideLayout ? SESSION_LAYOUT_GAP : 1}
        flexGrow={1}
        width="100%"
        minWidth={0}
      >
        <scrollbox flexGrow={1} minWidth={0} border borderColor={BORDER} focusedBorderColor={BORDER} backgroundColor={PANEL} paddingX={1} paddingY={0}>
          <box flexDirection="column" width="100%" minWidth={0}>
            {scans.length === 0 ? <text fg={MUTED}>{fitTuiText("No scan history found.", historyListContentWidth)}</text> : scans.map((scan, scanIndex) => {
              const active = scanIndex === index;
              const scanSummary = parseSummary(scan.summary);
              return (
                <box key={scan.id} flexDirection="row" width="100%" minWidth={0}>
                  <RailBar tone={active ? PRIMARY : BORDER} />
                  <box flexDirection="column" marginLeft={1} flexGrow={1} minWidth={0}>
                    <text fg={active ? TEXT : "#CCCCCC"}>{fitTuiUrl(scan.target, historyListRowWidth)}</text>
                    <text fg={MUTED}>{fitTuiText(`${scan.mode}/${scan.depth} · ${scan.runtime} · ${scan.status}`, historyListRowWidth)}</text>
                    <text fg={MUTED}>{fitTuiText(`${scanSummary.totalFindings ?? 0} findings · ${formatDuration(scan.durationMs)} · ${scan.startedAt}`, historyListRowWidth)}</text>
                  </box>
                </box>
              );
            })}
          </box>
        </scrollbox>
        <box flexDirection="column" width={historyUsesSideBySideLayout ? historyLayout.sidebarWidth : "100%"} flexShrink={0} minWidth={0}>
          <PanelSection title="Selected run" contentWidth={historyDetailContentWidth} tone={PRIMARY}>
            <box flexDirection="column">
              <text fg={TEXT}>{selected ? fitTuiUrl(selected.target, historyDetailContentWidth) : fitTuiText("No run selected", historyDetailContentWidth)}</text>
              {selected ? <text fg={MUTED}>{fitTuiText(`${selected.mode}/${selected.depth} · ${selected.runtime}`, historyDetailContentWidth)}</text> : null}
              {selected ? <text fg={MUTED}>{fitTuiText(`${selected.status} · ${formatDuration(selected.durationMs)}`, historyDetailContentWidth)}</text> : null}
            </box>
          </PanelSection>
          <PanelSection title="Summary" contentWidth={historyDetailContentWidth} tone={BORDER}>
            <box flexDirection="column">
              <text fg={MUTED}>{fitTuiText(`findings ${summary.totalFindings ?? 0}`, historyDetailContentWidth)}</text>
              <text fg={MUTED}>{fitTuiText(`started ${selected?.startedAt ?? "-"}`, historyDetailContentWidth)}</text>
              <text fg={MUTED}>{fitTuiText(`scan ${selected?.id.slice(0, 8) ?? "-"}`, historyDetailContentWidth)}</text>
              <text fg={MUTED}>{fitTuiText("key r replay selected", historyDetailContentWidth)}</text>
            </box>
          </PanelSection>
        </box>
      </box>
      <FooterBar hint="esc back · ctrl+p commands · ctrl+c exit" />
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
  const [scanTargets, setScanTargets] = useState<Record<string, string>>({});
  const [fixRun, setFixRun] = useState<FixRunState | null>(null);
  const [fixNotice, setFixNotice] = useState<string | null>(null);
  // State updates are batched, so the re-entry guard cannot read `fixRun`:
  // two `f` presses in the same frame would both see `null`. The ref flips
  // synchronously inside the key handler instead.
  const fixBusyRef = useRef(false);
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);
  const { width, height } = useTerminalDimensions();
  const findingsLayout = getSessionLayout(width, height);
  const findingsUsesSideBySideLayout = findingsLayout.sidebarCanFit;
  const findingsListWidth = findingsUsesSideBySideLayout
    ? findingsLayout.transcriptWidth
    : findingsLayout.contentWidth;
  const findingsDetailWidth = findingsUsesSideBySideLayout
    ? findingsLayout.sidebarWidth
    : findingsLayout.contentWidth;
  const findingsListContentWidth = Math.max(1, findingsListWidth - PANEL_HORIZONTAL_CHROME - SCROLLBAR_COLUMN);
  const findingsListRowWidth = Math.max(1, findingsListContentWidth - 2);
  // The detail pane has no border or padding of its own; its PanelSections
  // supply the chrome, and the pane's scrollbar takes the remaining column.
  const findingsDetailContentWidth = Math.max(1, findingsDetailWidth - PANEL_HORIZONTAL_CHROME - SCROLLBAR_COLUMN);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const { osecDB } = await import("@0sec/db");
        const db = new osecDB(options.dbPath);
        try {
          const findings = db.listFindings({
            scanId: options.scan,
            severity: options.severity,
            category: options.category,
            status: options.status,
            triageStatus: options.triage,
            limit: options.all ? options.limit : 1000,
          }) as FindingsRow[];
          // The scan's target doubles as the repo the source-fix action runs
          // in, mirroring the `<repo>` argument of `0sec fix`.
          const targets: Record<string, string> = {};
          for (const scanId of new Set(findings.map((row) => row.scanId))) {
            const scan = db.getScan(scanId);
            if (scan?.target) targets[scanId] = scan.target;
          }
          if (!alive) return;
          setRows(findings);
          setScanTargets(targets);
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
  const summaryBarGap = 1;
  const itemCountLabel = options.all ? "rows " : "families ";
  const itemCountChipWidth = PANEL_HORIZONTAL_CHROME + itemCountLabel.length + String(itemCount).length;
  const loadedChipWidth = PANEL_HORIZONTAL_CHROME + "loaded ".length + String(rows.length).length;
  const scopeChipWidth = findingsUsesSideBySideLayout
    ? Math.max(1, findingsLayout.contentWidth - summaryBarGap * 2 - itemCountChipWidth - loadedChipWidth)
    : findingsLayout.contentWidth;
  const scopeSummaryWidth = Math.max(1, scopeChipWidth - PANEL_HORIZONTAL_CHROME - "scope ".length);
  // These wrap rather than truncate — the pane scrolls, so a description is
  // worth reading in full. `Math.max(width, value.length)` made that budget
  // unbounded though, and a finding's evidence can be an entire HTTP
  // response, so cap it at the rows the pane can plausibly be scrolled over.
  const detailWrapWidth = findingsDetailContentWidth * FINDING_DETAIL_MAX_WRAPPED_ROWS;
  const descriptionText = selectedRow ? fitTuiText(selectedRow.description, detailWrapWidth) : "-";
  const evidenceRequestText = selectedRow ? fitTuiText(selectedRow.evidenceRequest, detailWrapWidth) : "-";
  const evidenceResponseText = selectedRow ? fitTuiText(selectedRow.evidenceResponse, detailWrapWidth) : "-";
  const selectedTitleText = selectedRow
    ? fitTuiText(selectedRow.title, detailWrapWidth)
    : "No finding selected";
  const triageNoteText = selectedRow?.triageNote ? fitTuiText(selectedRow.triageNote, detailWrapWidth) : null;

  // ── Source fix (`f`) ──
  const selectedFinding = useMemo(() => (selectedRow ? findingFromRow(selectedRow) : null), [selectedRow]);
  const fixRepoRoot = useMemo(() => resolveFixRepoRoot(selectedRow, scanTargets), [selectedRow, scanTargets]);
  const fixTestCommand = process.env[FIX_TEST_COMMAND_ENV] ?? "";
  const fixSourceFile = useMemo(() => findingSourcePath(selectedFinding), [selectedFinding]);
  // The finding-level predicate runs first so the operator sees the same
  // reason `0sec fix` would report first.
  const fixReadiness = useMemo(() => {
    const findingCheck = fixEligibility(selectedFinding);
    if (!findingCheck.eligible) return findingCheck;
    return fixInputEligibility({ repoRoot: fixRepoRoot, testCommand: fixTestCommand });
  }, [selectedFinding, fixRepoRoot, fixTestCommand]);
  const activeFixRun = fixRun && selectedRow && fixRun.findingId === selectedRow.id ? fixRun : null;
  const fixRunning = fixRun?.status === "running";
  const fixPanelTone = !activeFixRun
    ? BORDER
    : activeFixRun.status === "running"
      ? PRIMARY
      : activeFixRun.status === "validated_candidate" || activeFixRun.status === "applied_and_retested"
        ? SUCCESS
        : ERROR;

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
      id: "fix-finding",
      title: "Generate source fix",
      category: "Remediation",
      description: "Generate and re-test a candidate source patch; never applies it",
      keybind: "f",
      suggested: true,
      action: () => { requestSourceFix(); },
    },
    {
      id: "back-findings",
      title: "Go back",
      category: "Navigate",
      description: "Return to the previous console screen",
      keybind: "esc",
      suggested: true,
      action: () => leaveCurrentScreen(shell, onExit),
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
      const { osecDB } = await import("@0sec/db");
      const db = new osecDB(options.dbPath);
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

  /**
   * Run `runSourceFix` exactly as `0sec fix` does, minus `--apply`. The await
   * chain yields to the event loop, so the renderer keeps painting while the
   * model call and the regression command run.
   */
  const runSourceFixForRow = async (
    row: FindingsRow,
    finding: Finding,
    repoRoot: string,
    testCommand: string,
  ): Promise<void> => {
    try {
      const { createRuntime, runSourceFix } = await import("@0sec/core");
      const runtime = createRuntime({ type: "api", timeout: FIX_MODEL_TIMEOUT_MS });
      if (!isNativeRuntime(runtime)) {
        throw new Error("runtime 'api' does not support structured source remediation");
      }
      if (!(await runtime.isAvailable())) {
        throw new Error("runtime 'api' is not available");
      }
      const result = await runSourceFix({
        repoRoot,
        finding,
        runtime,
        testCommand,
        // `0sec fix` defaults --apply to false. Applying a validated patch
        // stays an explicit, separate operator action; the TUI never widens
        // that gate.
        apply: false,
        maxAttempts: FIX_MAX_ATTEMPTS,
        testTimeoutMs: FIX_TEST_TIMEOUT_MS,
      });
      if (!mountedRef.current) return;
      setFixRun({ findingId: row.id, status: result.status, result });
    } catch (err) {
      if (!mountedRef.current) return;
      setFixRun({
        findingId: row.id,
        status: "error",
        error: err instanceof Error ? err.message : String(err),
      });
    } finally {
      fixBusyRef.current = false;
    }
  };

  const requestSourceFix = (): void => {
    if (fixBusyRef.current) {
      setFixNotice("a fix run is already in progress");
      return;
    }
    if (!selectedRow || !selectedFinding) {
      setFixNotice("no finding selected");
      return;
    }
    if (!fixReadiness.eligible) {
      setFixNotice(fixReadiness.reason);
      return;
    }
    const repoRoot = fixRepoRoot;
    const testCommand = fixTestCommand;
    if (!repoRoot || !testCommand) {
      setFixNotice("fix inputs went missing before the run started");
      return;
    }
    fixBusyRef.current = true;
    setFixNotice(null);
    setFixRun({ findingId: selectedRow.id, status: "running" });
    void runSourceFixForRow(selectedRow, selectedFinding, repoRoot, testCommand);
  };

  useKeyboard((key) => {
    if (palette.handlePaletteKey(key)) return;
    if ((key.ctrl && key.name === "c") || key.name === "q") {
      onExit();
      return;
    }
    if (key.name === "escape") {
      leaveCurrentScreen(shell, onExit);
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
    if (key.sequence === "f") requestSourceFix();
  });

  // The status goes in as a string so HeaderBar can budget it against the
  // cells it reserved: a <text> node passed straight through is auto-width
  // and paints past the header's right-hand column.
  return (
    <ShellFrame view="findings" status={fixRunning ? "generating fix" : triageBusy ? `updating ${triageBusy}` : options.all ? "raw rows" : "grouped families"}>
      {palette.paletteOpen ? <PaletteOverlay title="Findings commands" query={palette.paletteQuery} selected={palette.paletteSelected} commands={palette.filteredPalette} /> : null}
      {error ? <text fg={ERROR} wrapMode="word">{fitTuiText(error, findingsLayout.contentWidth)}</text> : null}
      {notice ? <text fg={ACCENT} wrapMode="word">{fitTuiText(notice, findingsLayout.contentWidth)}</text> : null}
      <box
        flexDirection={findingsUsesSideBySideLayout ? "row" : "column"}
        gap={summaryBarGap}
        marginBottom={1}
        width="100%"
        minWidth={0}
      >
        <box border borderColor={PRIMARY} backgroundColor={PANEL} paddingX={1} width={scopeChipWidth} flexGrow={findingsUsesSideBySideLayout ? 1 : 0} flexShrink={0} minWidth={0}>
          <box flexDirection="row" width="100%" minWidth={0}>
            <text flexShrink={0} fg={TEXT}>scope </text>
            <text fg={PRIMARY}>{fitTuiText(filterSummary, scopeSummaryWidth)}</text>
          </box>
        </box>
        <box border borderColor={BORDER} backgroundColor={PANEL} paddingX={1} width={findingsUsesSideBySideLayout ? itemCountChipWidth : "100%"} flexShrink={0} minWidth={0}>
          <box flexDirection="row" width="100%" minWidth={0}>
            <text flexShrink={0} fg={TEXT}>{itemCountLabel}</text>
            <text flexShrink={0} fg={MUTED}>{String(itemCount)}</text>
          </box>
        </box>
        <box border borderColor={BORDER} backgroundColor={PANEL} paddingX={1} width={findingsUsesSideBySideLayout ? loadedChipWidth : "100%"} flexShrink={0} minWidth={0}>
          <box flexDirection="row" width="100%" minWidth={0}>
            <text flexShrink={0} fg={TEXT}>loaded </text>
            <text flexShrink={0} fg={MUTED}>{String(rows.length)}</text>
          </box>
        </box>
      </box>
      <box
        flexDirection={findingsUsesSideBySideLayout ? "row" : "column"}
        gap={findingsUsesSideBySideLayout ? SESSION_LAYOUT_GAP : summaryBarGap}
        flexGrow={1}
        width="100%"
        minWidth={0}
        minHeight={0}
      >
        <scrollbox
          flexGrow={1}
          minWidth={0}
          minHeight={0}
          border
          borderColor={BORDER}
          focusedBorderColor={BORDER}
          backgroundColor={PANEL}
          paddingX={1}
          paddingY={0}
        >
          <box flexDirection="column" width="100%" minWidth={0}>
            {itemCount === 0 ? <text fg={MUTED}>{fitTuiText("No findings found.", findingsListContentWidth)}</text> : options.all
              ? rows.slice(0, options.limit).map((row, rowIndex) => {
                  const active = rowIndex === index;
                  const fingerprint = row.fingerprint ?? row.id;
                  return (
                    <box key={row.id} flexDirection="row" width="100%" minWidth={0}>
                      <RailBar tone={active ? PRIMARY : BORDER} />
                      <box flexDirection="column" marginLeft={1} flexGrow={1} minWidth={0}>
                        <text fg={severityTone(row.severity)}>{fitTuiText(`${row.severity.toUpperCase()} · ${row.title}`, findingsListRowWidth)}</text>
                        <text fg={MUTED}>{fitTuiText(`${row.category} · ${row.status} · ${row.triageStatus ?? "new"}`, findingsListRowWidth)}</text>
                        <text fg={MUTED}>{fitTuiText(`scan:${row.scanId.slice(0, 8)} · fp:${fingerprint.slice(0, 10)}`, findingsListRowWidth)}</text>
                      </box>
                    </box>
                  );
                })
              : groups.map((group, groupIndex) => {
                  const active = groupIndex === index;
                  const latest = group.latest;
                  return (
                    <box key={group.fingerprint} flexDirection="row" width="100%" minWidth={0}>
                      <RailBar tone={active ? PRIMARY : BORDER} />
                      <box flexDirection="column" marginLeft={1} flexGrow={1} minWidth={0}>
                        <text fg={severityTone(latest.severity)}>{fitTuiText(`${latest.severity.toUpperCase()} · ${latest.title}`, findingsListRowWidth)}</text>
                        <text fg={MUTED}>{fitTuiText(`${latest.category} · ${latest.status} · ${latest.triageStatus ?? "new"}`, findingsListRowWidth)}</text>
                        <text fg={MUTED}>{fitTuiText(`${group.count} hits / ${group.scans} scans · fp:${group.fingerprint.slice(0, 10)}`, findingsListRowWidth)}</text>
                      </box>
                    </box>
                  );
                })}
          </box>
        </scrollbox>
        <scrollbox
          width={findingsUsesSideBySideLayout ? findingsDetailWidth : "100%"}
          flexGrow={findingsUsesSideBySideLayout ? 0 : 1}
          flexShrink={0}
          minWidth={0}
          minHeight={0}
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
          <PanelSection title={options.all ? "Finding" : "Family"} contentWidth={findingsDetailContentWidth} tone={selectedRow ? severityTone(selectedRow.severity) : BORDER}>
            <box flexDirection="column" width="100%" minWidth={0}>
              <text fg={TEXT} wrapMode="word">{selectedTitleText}</text>
              {selectedRow ? <text fg={MUTED}>{fitTuiText(`${selectedRow.severity} · ${selectedRow.status} · ${selectedRow.triageStatus ?? "new"}`, findingsDetailContentWidth)}</text> : null}
              {selectedGroup ? <text fg={MUTED}>{fitTuiText(`${selectedGroup.count} hits / ${selectedGroup.scans} scans`, findingsDetailContentWidth)}</text> : null}
              {selectedRow ? <text fg={MUTED}>{fitTuiText(`scan ${selectedRow.scanId.slice(0, 8)} · fp:${selectedFingerprint?.slice(0, 10)}`, findingsDetailContentWidth)}</text> : null}
              {triageNoteText ? <text fg={ACCENT} wrapMode="word">{triageNoteText}</text> : null}
            </box>
          </PanelSection>
          {/*
            Every row here is a single full-width <text>, so there are no
            sibling columns to overflow the pane. The candidate patch body is
            deliberately not rendered: it is an unbounded apply_patch envelope
            that reads as noise in a narrow column, and `0sec fix --output` is
            the supported way to get it on disk. `precondition` / `postcondition`
            are omitted for the same reason — they are predicate arrays, not
            one-liners.
          */}
          <PanelSection title="Source fix" contentWidth={findingsDetailContentWidth} tone={fixPanelTone}>
            <box flexDirection="column" width="100%" minWidth={0}>
              <text fg={fixReadiness.eligible ? SUCCESS : MUTED} wrapMode="word">
                {fitTuiText(
                  fixReadiness.eligible
                    ? "ready — press f to generate a candidate fix"
                    : `unavailable — ${fixReadiness.reason}`,
                  detailWrapWidth,
                )}
              </text>
              {fixSourceFile ? <text fg={MUTED} wrapMode="word">{fitTuiText(`source ${fixSourceFile}`, detailWrapWidth)}</text> : null}
              {fixRepoRoot ? <text fg={MUTED} wrapMode="word">{fitTuiText(`repo ${fixRepoRoot}`, detailWrapWidth)}</text> : null}
              {fixNotice ? <text fg={WARNING} wrapMode="word">{fitTuiText(fixNotice, detailWrapWidth)}</text> : null}
              {activeFixRun ? (
                <text fg={fixPanelTone} wrapMode="word">
                  {fitTuiText(describeFixStatus(activeFixRun.status, activeFixRun.result), detailWrapWidth)}
                </text>
              ) : null}
              {activeFixRun?.error ? <text fg={ERROR} wrapMode="word">{fitTuiText(`error ${activeFixRun.error}`, detailWrapWidth)}</text> : null}
              {activeFixRun?.result
                ? fixResultLines(activeFixRun.result).map((line, lineIndex) => (
                    <text key={`fix-line-${lineIndex}`} fg={MUTED} wrapMode="word">{fitTuiText(line, detailWrapWidth)}</text>
                  ))
                : null}
              {fixRunning && !activeFixRun ? <text fg={MUTED} wrapMode="word">{fitTuiText("a fix is running for another finding", detailWrapWidth)}</text> : null}
            </box>
          </PanelSection>
          <PanelSection title="Filters" contentWidth={findingsDetailContentWidth} tone={BORDER}>
            <box flexDirection="column" width="100%" minWidth={0}>
              <text fg={MUTED} wrapMode="word">{fitTuiText(filterSummary, findingsDetailContentWidth)}</text>
              <text fg={MUTED}>{fitTuiText(`limit ${options.limit}`, findingsDetailContentWidth)}</text>
              <text fg={MUTED}>{fitTuiText(`mode ${options.all ? "raw rows" : "grouped families"}`, findingsDetailContentWidth)}</text>
              <text fg={MUTED} wrapMode="word">{fitTuiText("keys a accept · s suppress · r reopen · f fix", findingsDetailContentWidth)}</text>
            </box>
          </PanelSection>
          <PanelSection title="Description" contentWidth={findingsDetailContentWidth} tone={BORDER}>
            <box flexDirection="column" width="100%" minWidth={0}>
              <text fg={MUTED} wrapMode="word">{descriptionText}</text>
            </box>
          </PanelSection>
          <PanelSection title="Evidence" contentWidth={findingsDetailContentWidth} tone={BORDER}>
            <box flexDirection="column" width="100%" minWidth={0}>
              <text fg={TEXT}>{fitTuiText("request", findingsDetailContentWidth)}</text>
              <text fg={MUTED} wrapMode="word">{evidenceRequestText}</text>
              <text fg={TEXT}>{fitTuiText("response", findingsDetailContentWidth)}</text>
              <text fg={MUTED} wrapMode="word">{evidenceResponseText}</text>
            </box>
          </PanelSection>
        </scrollbox>
      </box>
      <FooterBar hint="esc back · ctrl+p commands · ctrl+c exit" />
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
      id: "back-replay",
      title: "Go back",
      category: "Navigate",
      description: "Return to the previous console screen",
      keybind: "esc",
      suggested: true,
      action: () => leaveCurrentScreen(shell, onExit),
    },
    ...createShellCommands(shell),
  ]);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const { osecDB } = await import("@0sec/db");
        const db = new osecDB(dbPath);
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
  const { width, height } = useTerminalDimensions();
  const contentWidth = Math.max(1, width - SHELL_HORIZONTAL_PADDING * 2);
  const panesStacked = contentWidth < 96;
  const paneGap = panesStacked ? 1 : 2;
  const findingsPaneWidth = panesStacked
    ? contentWidth
    : Math.max(1, Math.floor((contentWidth - paneGap) * 0.46));
  const eventsPaneWidth = panesStacked
    ? contentWidth
    : Math.max(1, contentWidth - findingsPaneWidth - paneGap);
  const findingsContentWidth = Math.max(1, findingsPaneWidth - PANEL_HORIZONTAL_CHROME);
  const eventContentWidth = Math.max(1, eventsPaneWidth - PANEL_HORIZONTAL_CHROME - SCROLLBAR_COLUMN);
  const eventDetailWidth = Math.max(1, eventContentWidth - 2);
  const eventTimestampWidth = 24;
  const eventTitleMinWidth = 16;
  const eventHeaderInline = eventDetailWidth >= eventTimestampWidth + eventTitleMinWidth + 1;
  const eventHeaderGap = eventHeaderInline ? 1 : 0;
  const eventTitleWidth = eventHeaderInline
    ? Math.max(1, eventDetailWidth - eventTimestampWidth - eventHeaderGap)
    : eventDetailWidth;
  const eventTimestampFitWidth = eventHeaderInline ? eventTimestampWidth : eventDetailWidth;

  // The three summary chips were auto-width in a plain row, so a long target
  // pushed the row past the frame and Yoga shrank all three into each other.
  // The two counters need only their digits; the target gets the remainder.
  const chipGap = 1;
  const findingsChipValue = String(summary.totalFindings ?? verifiedFindings.length);
  const eventsChipValue = String(events.length);
  const findingsChipWidth = PANEL_HORIZONTAL_CHROME + "findings ".length + findingsChipValue.length;
  const eventsChipWidth = PANEL_HORIZONTAL_CHROME + "events ".length + eventsChipValue.length;
  const targetChipWidth = Math.max(
    PANEL_HORIZONTAL_CHROME + "target ".length + 1,
    contentWidth - chipGap * 2 - findingsChipWidth - eventsChipWidth,
  );
  const targetChipTextWidth = Math.max(1, targetChipWidth - PANEL_HORIZONTAL_CHROME - "target ".length);

  // The left column's two sections draw their own borders and do not scroll,
  // so the findings list has to fit the rows the frame can actually spare.
  // The chip strip costs three rows plus its margin; the lane section is a
  // fixed eight rows of content inside a border and a title.
  const replayChipRows = 4;
  const replayLaneSectionRows = 3 + 8;
  const replayColumnRows = Math.max(
    4,
    height - getShellChromeHeight(width) - replayChipRows - (error ? 1 : 0) - (selectedEvent ? 1 : 0),
  );
  const replayLeftPaneRows = panesStacked
    ? Math.max(4, Math.floor((replayColumnRows - paneGap) / 2))
    : replayColumnRows;
  const visibleReplayFindings = Math.max(
    1,
    Math.min(REPLAY_MAX_FINDINGS, replayLeftPaneRows - replayLaneSectionRows - 3),
  );


  useKeyboard((key) => {
    if (palette.handlePaletteKey(key)) return;
    if ((key.ctrl && key.name === "c") || key.name === "q") {
      onExit();
      return;
    }
    if (key.name === "escape") {
      leaveCurrentScreen(shell, onExit);
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
    <ShellFrame view="replay" status={scan ? scan.id.slice(0, 8) : "latest scan"}>
      {palette.paletteOpen ? <PaletteOverlay title="Replay commands" query={palette.paletteQuery} selected={palette.paletteSelected} commands={palette.filteredPalette} /> : null}
      {error ? <text fg={ERROR} wrapMode="word">{fitTuiText(error, contentWidth)}</text> : null}
      <box flexDirection="row" gap={chipGap} marginBottom={1} width="100%" minWidth={0}>
        <box border borderColor={PRIMARY} backgroundColor={PANEL} paddingX={1} width={targetChipWidth} flexGrow={1} flexShrink={0} minWidth={0}>
          <box flexDirection="row" width="100%" minWidth={0}>
            <text flexShrink={0} fg={TEXT}>target </text>
            <text fg={PRIMARY}>{scan ? fitTuiUrl(scan.target, targetChipTextWidth) : fitTuiText("loading", targetChipTextWidth)}</text>
          </box>
        </box>
        <box border borderColor={BORDER} backgroundColor={PANEL} paddingX={1} width={findingsChipWidth} flexShrink={0} minWidth={0}>
          <box flexDirection="row" width="100%" minWidth={0}>
            <text flexShrink={0} fg={TEXT}>findings </text>
            <text flexShrink={0} fg={MUTED}>{findingsChipValue}</text>
          </box>
        </box>
        <box border borderColor={BORDER} backgroundColor={PANEL} paddingX={1} width={eventsChipWidth} flexShrink={0} minWidth={0}>
          <box flexDirection="row" width="100%" minWidth={0}>
            <text flexShrink={0} fg={TEXT}>events </text>
            <text flexShrink={0} fg={MUTED}>{eventsChipValue}</text>
          </box>
        </box>
      </box>
      <box flexDirection={panesStacked ? "column" : "row"} gap={paneGap} flexGrow={1} width="100%" minWidth={0}>
        <box flexDirection="column" width={findingsPaneWidth} flexGrow={panesStacked ? 0 : 1} flexShrink={0} minWidth={0}>
          <PanelSection title="Replay lane" contentWidth={findingsContentWidth} tone={PRIMARY}>
            <box flexDirection="column" minWidth={0}>
              <text fg={TEXT}>{fitTuiText("DISCOVER", findingsContentWidth)}</text>
              <text fg={MUTED}>{fitTuiText(scan ? `${scan.mode}/${scan.depth} via ${scan.runtime}` : "loading", findingsContentWidth)}</text>
              <text fg={TEXT}>{fitTuiText("ATTACK", findingsContentWidth)}</text>
              <text fg={MUTED}>{fitTuiText(verifiedFindings.length > 0 ? `${verifiedFindings.length} findings survived triage` : "No confirmed findings recorded", findingsContentWidth)}</text>
              <text fg={TEXT}>{fitTuiText("VERIFY", findingsContentWidth)}</text>
              <text fg={MUTED}>{fitTuiText(`${findings.filter((finding) => finding.status === "false-positive").length} false positives removed`, findingsContentWidth)}</text>
              <text fg={TEXT}>{fitTuiText("REPORT", findingsContentWidth)}</text>
              <text fg={MUTED}>{fitTuiText(`${formatDuration(scan?.durationMs)} total runtime`, findingsContentWidth)}</text>
            </box>
          </PanelSection>
          <PanelSection title="Findings" contentWidth={findingsContentWidth} tone={verifiedFindings.length > 0 ? WARNING : BORDER}>
            <box flexDirection="column" minWidth={0}>
              {verifiedFindings.length === 0 ? <text fg={MUTED}>{fitTuiText("No findings recorded for this scan.", findingsContentWidth)}</text> : verifiedFindings.slice(0, visibleReplayFindings).map((finding) => (
                <text key={finding.id} fg={severityTone(finding.severity)}>{fitTuiText(`${finding.severity} · ${finding.title}`, findingsContentWidth)}</text>
              ))}
            </box>
          </PanelSection>
        </box>
        <scrollbox
          width={eventsPaneWidth}
          flexGrow={1}
          minWidth={0}
          minHeight={0}
          border
          borderColor={BORDER}
          focusedBorderColor={BORDER}
          backgroundColor={PANEL}
          paddingX={1}
          paddingY={0}
        >
          <box flexDirection="column" width="100%" minWidth={0}>
            {events.length === 0 ? <text fg={MUTED}>{fitTuiText("No pipeline events captured for this scan.", eventContentWidth)}</text> : events.map((event, index) => {
              const active = index === eventIndex;
              return (
                <box key={event.id} flexDirection="row" width="100%" minWidth={0}>
                  <RailBar tone={active ? PRIMARY : BORDER} />
                  <box flexDirection="column" marginLeft={1} flexGrow={1} minWidth={0}>
                    <box flexDirection={eventHeaderInline ? "row" : "column"} width={eventDetailWidth} minWidth={0} gap={eventHeaderGap}>
                      <box width={eventTitleWidth} flexShrink={0} minWidth={0}>
                        <text fg={active ? TEXT : "#CCCCCC"}>{fitTuiText(`${event.stage} · ${event.eventType}`, eventTitleWidth)}</text>
                      </box>
                      <box width={eventTimestampFitWidth} flexShrink={0} minWidth={0} alignItems={eventHeaderInline ? "flex-end" : "flex-start"}>
                        <text fg={MUTED}>{fitTuiText(new Date(event.timestamp).toISOString(), eventTimestampFitWidth)}</text>
                      </box>
                    </box>
                    <text fg={active ? ACCENT : MUTED} wrapMode="word">{fitTuiText(describeEventPayload(event.payload), eventDetailWidth)}</text>
                  </box>
                </box>
              );
            })}
          </box>
        </scrollbox>
      </box>
      {selectedEvent ? <text fg={MUTED}>{fitTuiText(`${selectedEvent.stage} · ${selectedEvent.eventType} · up/down browse events`, contentWidth)}</text> : null}
      <FooterBar hint="esc back · ctrl+p commands · ctrl+c exit" />
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
  const { width, height } = useTerminalDimensions();
  const sessionLayout = getSessionLayout(width, height);
  const sidebarOpen = sidebarVisible && sessionLayout.sidebarCanFit;
  const sidebarTextWidth = Math.max(12, sessionLayout.sidebarWidth - PANEL_HORIZONTAL_CHROME - SCROLLBAR_COLUMN);
  const apiStatus = state.connection.apiConnected
    ? "connected"
    : state.connection.apiConfigured
      ? "configured"
      : "missing";
  const apiProviderLabel = state.connection.apiProviderLabel ?? "unknown";
  const apiProviderWidth = Math.max(1, sidebarTextWidth - `api ${apiStatus} · `.length);
  const localRuntimesWidth = Math.max(1, sidebarTextWidth - "local ".length);
  const modelWidth = Math.max(1, sidebarTextWidth - "model ".length);
  // Counters were interpolated raw next to their labels. The sidebar is only
  // ~24 cells wide, so a six-figure token count or a long transcript ran the
  // pair past the panel border; budget each value against its own label.
  const tokensValueWidth = Math.max(1, sidebarTextWidth - "tokens ".length);
  const costValueWidth = Math.max(1, sidebarTextWidth - "cost ".length);
  const transcriptCountWidth = Math.max(1, sidebarTextWidth - "transcript ".length);
  const turnsCountWidth = Math.max(1, sidebarTextWidth - "turns ".length);
  const findingsCountWidth = Math.max(1, sidebarTextWidth - "findings ".length);
  const transcriptContentWidth = Math.max(
    12,
    (sidebarOpen ? sessionLayout.transcriptWidth : sessionLayout.contentWidth)
      - PANEL_HORIZONTAL_CHROME
      - SCROLLBAR_COLUMN,
  );

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
      title: sidebarOpen ? "Hide sidebar" : "Show sidebar",
      category: "Display",
      description: sidebarOpen
        ? "Hide the right-hand session context"
        : sessionLayout.sidebarCanFit
          ? "Show target, runtime, and pipeline context"
          : "Sidebar is available on a wider terminal",
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
  ], [onExit, sessionLayout.sidebarCanFit, shell, sidebarOpen, toolCardIds]);

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
    <ShellFrame
      view={summary ? "report" : "live session"}
      status={sidebarOpen ? state.mode : `${state.mode} · compact`}
    >
      {paletteOpen ? <PaletteOverlay title="Session commands" query={paletteQuery} selected={paletteSelected} commands={filteredPalette} /> : null}
      {timelineOpen ? <TimelineOverlay selected={timelineSelected} turns={turnItems} /> : null}
      {composeOpen ? <ComposeOverlay text={composeText} /> : null}
      <box flexDirection="row" gap={sidebarOpen ? SESSION_LAYOUT_GAP : 0} flexGrow={1} width="100%" minWidth={0} minHeight={0}>
        <scrollbox
          width={sidebarOpen ? sessionLayout.transcriptWidth : "100%"}
          flexGrow={sidebarOpen ? 0 : 1}
          flexShrink={0}
          minWidth={0}
          minHeight={0}
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
          <box flexDirection="column" width="100%" minWidth={0}>
            {visibleTranscript.map((item) => renderTranscriptItem(item, {
              expanded: expandedToolCards,
              toggleExpanded: toggleToolCard,
              hoveredToolId,
              setHoveredToolId,
              contentWidth: transcriptContentWidth,
            }))}
            {!summary ? (
              <WorkingPulse
                label={liveActivity.label}
                detail={liveActivity.detail}
                maxWidth={transcriptContentWidth}
              />
            ) : null}
          </box>
        </scrollbox>
        {sidebarOpen ? <scrollbox
          width={sessionLayout.sidebarWidth}
          flexShrink={0}
          minWidth={0}
          minHeight={0}
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
          <PanelSection title="Target" contentWidth={sidebarTextWidth} tone={PRIMARY}>
            <box flexDirection="column" minWidth={0}>
              <text fg={TEXT}>{fitTuiUrl(state.target, sidebarTextWidth)}</text>
              <text fg={MUTED}>{fitTuiText(`${state.mode} · ${state.depth}`, sidebarTextWidth)}</text>
            </box>
          </PanelSection>
          <PanelSection title="Runtime" contentWidth={sidebarTextWidth} tone={state.connection.apiConnected ? SUCCESS : state.connection.apiConfigured ? WARNING : BORDER}>
            <box flexDirection="column" minWidth={0}>
              <text fg={TEXT}>selected {fitTuiText(state.connection.runtime, Math.max(1, sidebarTextWidth - "selected ".length))}</text>
              <box flexDirection="row" width="100%" minWidth={0}>
                <text flexShrink={0} fg={TEXT}>api {apiStatus} </text>
                <text fg={MUTED}>· {fitTuiText(apiProviderLabel, apiProviderWidth)}</text>
              </box>
              <box flexDirection="row" width="100%" minWidth={0}>
                <text flexShrink={0} fg={TEXT}>local </text>
                <text fg={MUTED}>{fitTuiText(state.connection.localRuntimes.length > 0 ? state.connection.localRuntimes.join(", ") : "none", localRuntimesWidth)}</text>
              </box>
              {state.usage.inputTokens > 0 || state.usage.outputTokens > 0 ? (
                <>
                  <box flexDirection="row" width="100%" minWidth={0}>
                    <text flexShrink={0} fg={TEXT}>tokens </text>
                    <text fg={MUTED}>{fitTuiText(`${state.usage.inputTokens}/${state.usage.outputTokens}`, tokensValueWidth)}</text>
                  </box>
                  <box flexDirection="row" width="100%" minWidth={0}>
                    <text flexShrink={0} fg={TEXT}>cost </text>
                    <text fg={MUTED}>{fitTuiText(`$${state.usage.estimatedCostUsd.toFixed(4)}`, costValueWidth)}</text>
                  </box>
                </>
              ) : (
                <text fg={MUTED}>{fitTuiText("usage awaiting first model response", sidebarTextWidth)}</text>
              )}
              {state.connection.model ? (
                <box flexDirection="row" width="100%" minWidth={0}>
                  <text flexShrink={0} fg={TEXT}>model </text>
                  <text fg={MUTED}>{fitTuiText(state.connection.model, modelWidth)}</text>
                </box>
              ) : null}
            </box>
          </PanelSection>
          <PanelSection title="Session" contentWidth={sidebarTextWidth} tone={BORDER}>
            <box flexDirection="column" minWidth={0}>
              <box flexDirection="row" width="100%" minWidth={0}>
                <text flexShrink={0} fg={TEXT}>transcript </text>
                <text fg={MUTED}>{fitTuiText(`${state.transcript.length} items`, transcriptCountWidth)}</text>
              </box>
              <box flexDirection="row" width="100%" minWidth={0}>
                <text flexShrink={0} fg={TEXT}>turns </text>
                <text fg={MUTED}>{fitTuiText(String(turnItems.length), turnsCountWidth)}</text>
              </box>
              <box flexDirection="row" width="100%" minWidth={0}>
                <text flexShrink={0} fg={TEXT}>findings </text>
                <text fg={MUTED}>{fitTuiText(String(totalFindings), findingsCountWidth)}</text>
              </box>
              <text fg={summary ? SUCCESS : PRIMARY}>{fitTuiText(summary ? "completed" : "running", sidebarTextWidth)}</text>
              {visibleFromTurnId ? <text fg={ACCENT}>{fitTuiText("timeline focus active", sidebarTextWidth)}</text> : null}
            </box>
          </PanelSection>
          <PanelSection title="Pipeline" contentWidth={sidebarTextWidth} tone={state.stages.some((stage) => stage.status === "running") ? PRIMARY : BORDER}>
            <box flexDirection="column" minWidth={0}>
              {state.stages.map((stage) => (
                <box key={stage.id} flexDirection="column" minWidth={0}>
                  <text fg={stage.status === "running" ? PRIMARY : stage.status === "done" ? SUCCESS : stage.status === "error" ? ERROR : MUTED}>
                    {fitTuiText(`${stage.label} · ${stage.status}`, sidebarTextWidth)}
                  </text>
                  {stage.detail ? <text fg={TEXT} wrapMode="word">{fitTuiText(stage.detail, sidebarTextWidth)}</text> : stage.status === "pending" ? <text fg={MUTED}>{fitTuiText("waiting for stage handoff", sidebarTextWidth)}</text> : null}
                </box>
              ))}
            </box>
          </PanelSection>
          <PanelSection title="Findings" contentWidth={sidebarTextWidth} tone={totalFindings > 0 ? WARNING : BORDER}>
            <box flexDirection="column" minWidth={0}>
              {state.stages.flatMap((stage) => stage.findings).length === 0 ? (
                <text fg={TEXT}>{fitTuiText("No findings yet.", sidebarTextWidth)}</text>
              ) : state.stages.flatMap((stage) => stage.findings).slice(0, SESSION_MAX_SIDEBAR_FINDINGS).map((finding, index) => (
                <text key={`${finding.title}-${index}`} fg={severityTone(finding.severity)}>{fitTuiText(`${finding.severity} · ${finding.title}`, sidebarTextWidth)}</text>
              ))}
            </box>
          </PanelSection>
          {summary ? (
            <PanelSection title="Report" contentWidth={sidebarTextWidth} tone={summary.critical > 0 || summary.high > 0 ? ERROR : SUCCESS}>
              <box flexDirection="column" minWidth={0}>
                <box flexDirection="row" width="100%" minWidth={0}>
                  <text flexShrink={0} fg={summary.critical > 0 ? ERROR : TEXT}>critical </text>
                  <text fg={MUTED}>{fitTuiText(String(summary.critical), Math.max(1, sidebarTextWidth - "critical ".length))}</text>
                </box>
                <box flexDirection="row" width="100%" minWidth={0}>
                  <text flexShrink={0} fg={summary.high > 0 ? ERROR : TEXT}>high </text>
                  <text fg={MUTED}>{fitTuiText(String(summary.high), Math.max(1, sidebarTextWidth - "high ".length))}</text>
                </box>
                <box flexDirection="row" width="100%" minWidth={0}>
                  <text flexShrink={0} fg={summary.medium > 0 ? WARNING : TEXT}>medium </text>
                  <text fg={MUTED}>{fitTuiText(String(summary.medium), Math.max(1, sidebarTextWidth - "medium ".length))}</text>
                </box>
                <box flexDirection="row" width="100%" minWidth={0}>
                  <text flexShrink={0} fg={TEXT}>low </text>
                  <text fg={MUTED}>{fitTuiText(String(summary.low), Math.max(1, sidebarTextWidth - "low ".length))}</text>
                </box>
                <box flexDirection="row" width="100%" minWidth={0}>
                  <text flexShrink={0} fg={TEXT}>info </text>
                  <text fg={MUTED}>{fitTuiText(String(summary.info ?? 0), Math.max(1, sidebarTextWidth - "info ".length))}</text>
                </box>
                {summary.shareUrl ? <text fg={ACCENT}>{fitTuiUrl(summary.shareUrl, sidebarTextWidth)}</text> : null}
              </box>
            </PanelSection>
          ) : null}
        </scrollbox> : null}
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

/**
 * Routes the settings screen, supplying the console shell around it.
 *
 * `SettingsScreen` takes the frame as a prop rather than importing
 * `ShellFrame` so that `settings-screen.tsx` does not have to import this
 * module — which owns every other screen — just to draw a header. The footer
 * text is handed back per render because the hint changes with the screen's
 * mode: browsing, filtering, and confirming a reset each bind different keys.
 *
 * The command palette is deliberately not mounted here. Every printable key
 * on this screen filters the list, so a second `useKeyboard` competing for
 * those keystrokes would make `p` both a filter character and a palette
 * toggle. Esc leaves, which is the binding the palette was mostly used for.
 */
function SettingsRoute({ onExit, shell }: { onExit: () => void; shell?: ShellNav }) {
  return (
    <SettingsScreen
      onBack={() => leaveCurrentScreen(shell, onExit)}
      onExit={onExit}
      frame={({ body, hint }) => (
        <ShellFrame view="settings">
          {body}
          <FooterBar hint={hint} />
        </ShellFrame>
      )}
    />
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
  const rootRoute: ConsoleRoute = initialRoute.type === "chat" ? initialRoute : { type: "chat" };
  const hasChatRoot = initialRoute.type === "chat";
  const [routes, setRoutes] = useState<ConsoleRoute[]>(() =>
    hasChatRoot ? [initialRoute] : [rootRoute, initialRoute],
  );
  const [routeIndex, setRouteIndex] = useState(() => hasChatRoot ? 0 : 1);

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
    openChat: () => navigate({ type: "chat" }),
    openLauncher: () => navigate({ type: "launcher" }),
    openOps: () => navigate({ type: "ops", refreshMs: 4000 }),
    openDoctor: () => navigate({ type: "doctor" }),
    openHistory: () => navigate({ type: "history", limit: 12 }),
    openFindings: () => navigate({ type: "findings", options: { limit: 50 } }),
    openReplay: (scanId) => navigate({ type: "replay", scanId }),
    openSettings: () => navigate({ type: "settings" }),
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
    const sessionGate = createSessionCloseGate();
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
        if (!sessionGate.close()) return;
        shell.goBack();
      },
    });

    const { runUnified } = await import("../commands/run.js");
    const previousStartupLogSetting = process.env["0SEC_SUPPRESS_PROVIDER_STARTUP_LOG"];
    const previousNativeTracePath = process.env["0SEC_TRACE_NATIVE_RESPONSES"];
    const previousTuiTracePath = process.env["0SEC_TRACE_TUI_EVENTS"];
    process.env["0SEC_SUPPRESS_PROVIDER_STARTUP_LOG"] = "1";
    process.env["0SEC_TRACE_NATIVE_RESPONSES"] = `/tmp/0sec-native-responses-${Date.now()}.ndjson`;
    process.env["0SEC_TRACE_TUI_EVENTS"] = `/tmp/0sec-tui-events-${Date.now()}.ndjson`;
    appendTuiTrace({
      kind: "session-start",
      target: selection.target,
      mode,
      runtime,
      depth,
      nativeTrace: process.env["0SEC_TRACE_NATIVE_RESPONSES"],
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
            if (sessionGate.closed) return;
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
            if (sessionGate.closed) return;
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
          waitForExit: () => sessionGate.wait(),
        }),
      });
    } finally {
      if (previousStartupLogSetting === undefined) delete process.env["0SEC_SUPPRESS_PROVIDER_STARTUP_LOG"];
      else process.env["0SEC_SUPPRESS_PROVIDER_STARTUP_LOG"] = previousStartupLogSetting;
      if (previousNativeTracePath === undefined) delete process.env["0SEC_TRACE_NATIVE_RESPONSES"];
      else process.env["0SEC_TRACE_NATIVE_RESPONSES"] = previousNativeTracePath;
      if (previousTuiTracePath === undefined) delete process.env["0SEC_TRACE_TUI_EVENTS"];
      else process.env["0SEC_TRACE_TUI_EVENTS"] = previousTuiTracePath;
    }
  };

  if (currentRoute.type === "chat") {
    return (
      <ChatScreen
        options={currentRoute.options}
        onGoBack={shell.goBack}
        onNavigate={(destination) => {
          switch (destination) {
            case "launcher":
              shell.openLauncher();
              return;
            case "ops":
              shell.openOps();
              return;
            case "history":
              shell.openHistory();
              return;
            case "findings":
              shell.openFindings();
              return;
            case "doctor":
              shell.openDoctor();
              return;
            case "replay":
              shell.openReplay();
              return;
            case "settings":
              shell.openSettings();
              return;
          }
        }}
        onExit={onExit}
      />
    );
  }

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
    }} onExit={onExit} shell={shell} />;
  }
  if (currentRoute.type === "ops") return <OpsScreen dbPath={currentRoute.dbPath} refreshMs={currentRoute.refreshMs} onExit={onExit} shell={shell} />;
  if (currentRoute.type === "doctor") return <DoctorScreen onExit={onExit} shell={shell} />;
  if (currentRoute.type === "history") return <HistoryScreen dbPath={currentRoute.dbPath} limit={currentRoute.limit} onExit={onExit} shell={shell} />;
  if (currentRoute.type === "findings") return <FindingsScreen options={currentRoute.options} onExit={onExit} shell={shell} />;
  if (currentRoute.type === "session") return <ConsoleSessionRoute route={currentRoute} shell={shell} />;
  if (currentRoute.type === "replay") {
    return <ReplayScreen dbPath={currentRoute.dbPath} scanId={currentRoute.scanId} onExit={onExit} shell={shell} />;
  }
  if (currentRoute.type === "settings") return <SettingsRoute onExit={onExit} shell={shell} />;
  return null;
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
  // Claim stdout/stderr only AFTER the renderer exists. opentui saves the
  // real `stdout.write` in its constructor and emits every frame through
  // that saved reference, so installing here leaves rendering untouched
  // and captures just the application-level writes that would otherwise
  // overprint the framebuffer and desynchronize its differential repaint.
  const outputGuard = installTuiOutputGuard();
  const root = createRoot(renderer);
  await new Promise<void>((resolve) => {
    let closed = false;
    const close = () => {
      if (closed) return;
      closed = true;
      mode.onExit?.();
      root.unmount();
      renderer.destroy();
      // Released after destroy(): opentui resets the stream itself, and
      // the guard only reinstalls originals it still owns.
      outputGuard.restore();
      // Anything captured during the session is replayed to the real
      // terminal on the way out, so an operator never loses a quota or
      // failure notice just because the TUI was on screen.
      const captured = outputGuard.drain();
      const dropped = outputGuard.droppedCount();
      if (captured.length > 0 || dropped > 0) {
        // Labelled so the replay reads as a session log rather than a
        // duplicate of what the transcript already showed.
        process.stderr.write(`[0sec] runtime output captured during this session:\n`);
      }
      if (dropped > 0) {
        process.stderr.write(`[0sec] ${dropped} earlier line(s) dropped (buffer full)\n`);
      }
      for (const line of captured) {
        const stream = line.stream === "stderr" ? process.stderr : process.stdout;
        stream.write(`${line.text}\n`);
      }
      resolve();
    };
    try {
      root.render(
        <TuiErrorBoundary>
          <UnifiedApp mode={{ ...mode, onExit: close } as AppMode} />
        </TuiErrorBoundary>,
      );
    } catch (error) {
      // Never leave the process with patched streams: the crash report
      // below and anything after it must reach the real terminal.
      outputGuard.restore();
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
    initialRoute: { type: "chat" },
    onExit: () => {},
  });
}

export async function showOpenTuiConsole(options: ChatScreenOptions = {}): Promise<void> {
  await mountApp({
    type: "console",
    initialRoute: { type: "chat", options },
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

/** Opens the console straight onto the settings screen. */
export async function showOpenTuiSettings(): Promise<void> {
  await mountApp({ type: "console", initialRoute: { type: "settings" }, onResolve: () => {}, onExit: () => {} });
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
  const sessionGate = createSessionCloseGate();
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
      sessionGate.close();
    },
  });

  return {
    onEvent: (event) => {
      if (sessionGate.closed) return;
      state = applySessionEvent(state, event);
      emit();
    },
    setReport: (report) => {
      if (sessionGate.closed) return;
      state = applySessionReport(state, report);
      emit();
    },
    waitForExit: () => sessionGate.wait(),
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
