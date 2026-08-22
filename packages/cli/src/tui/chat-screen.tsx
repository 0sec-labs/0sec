/** @jsxImportSource @opentui/react */
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import {
  ScopePolicy,
  createConsoleRuntime,
  createConsoleSession,
  eventBus,
  type ConsoleAutonomyMode,
  type ConsoleScopeRequest,
  type ConsoleScopeResolution,
  claimDiagnostics,
  type ConsoleLocalScopeRequest,
  type ConsoleLocalScopeResolution,
  type ScopedAuditEscalationRequest,
  type ConsoleSession,
  type NativeMessage,
  type SubagentLifecyclePayload,
  type ToolCall,
  type ToolResult,
} from "@0sec/core";
import { TextAttributes } from "@opentui/core";
import type { ScrollBoxRenderable } from "@opentui/core";
import { useSettings, updateSetting } from "./settings-store.js";
import { useTheme, type Theme } from "./theme-context.js";
import { MODEL_PRICING, modelProvider, type ModelRates } from "@0sec/shared";
import { homedir } from "node:os";
import { readGitStatus, type GitStatus } from "./git-status.js";
import { buildStatusSegments, fitStatusSegments } from "./status-bar.js";
import {
  createSelectorState,
  highlighted,
  reduceSelector,
  visibleItems,
  windowFor,
  type SelectorItem,
  type SelectorState,
} from "./selector.js";
import { modelSelectorItems } from "./model-catalog.js";
import { appendFeedback } from "./feedback.js";
import { formatToolArgs, formatToolResult, toolResultDetail } from "./tool-format.js";
import {
  listSessions,
  loadSession,
  pruneSessions,
  saveSession,
} from "./session-store.js";
import { reportOperatorGate } from "../herdr-state.js";
import {
  listItemGutterWidth,
  renderMarkdown,
  TABLE_COLUMN_GAP,
  TABLE_JOIN_GLYPH,
  type MdBlock,
  type MdSpan,
} from "./markdown.js";
import { GLYPH_CELLS, formatElapsed, frameAt, frameIntervalMs, type AnimationKind } from "./animation.js";
import { PROVIDERS, providerStates } from "./provider-status.js";
import {
  credentialEnvPatch,
  loadCredentials,
  redactSecret,
  saveCredentials,
} from "./credential-store.js";
import { VERSION } from "@0sec/shared";
import {
  SETTING_DEFS,
  describeSetting,
  saveSettings,
  toggleSetting,
  type TuiSettings,
} from "./settings.js";
import { pushHistory, recallNext, recallPrev } from "./composer-history.js";
import {
  buildHelpPanel,
  buildScopePanel,
  buildStatusPanel,
  buildToolsPanel,
  panelColumns,
  type PanelData,
} from "./panels.js";
import { fitTuiText, sanitizeTuiText } from "./text.js";
import { parseSubagentCard, reduceActiveSubagents } from "./subagent-card.js";
import { onTuiOutputLine } from "./output-guard.js";
import {
  COMPOSER_QUEUE_LIMIT,
  classifyComposerInput,
  composerQueueLabel,
  dequeueComposerInput,
  enqueueComposerInput,
} from "./composer-queue.js";
import {
  LEDGER_MARK_ROWS,
  commandMenuBoxHeight,
  computeChatLayout,
  computeCommandMenuHeight,
  computeCommandMenuLayout,
  computeLedgerRows,
} from "./chat-layout.js";
import {
  SLASH_COMMANDS,
  filterCommands,
  findCommand,
  type SlashCommand,
} from "./slash-commands.js";
import { deletePreviousWord, deleteToLineStart } from "./composer-edit.js";
import { appendTranscriptEntry, repeatSuffix } from "./transcript.js";
import {
  foldSummary,
  planTranscript,
  resolveTranscriptStyleSettings,
  roleLabelText,
  speechFrame,
  toolCompactLine,
  toolDetailWidth,
  toolFrame,
  toolGlyphState,
  toolHeaderColumns,
  toolHeaderPrefix,
  type RoleLabelStyle,
  type ToolCardStyle,
  type TranscriptDetail,
  type TranscriptPlanItem,
  type TranscriptStyle,
} from "./transcript-style.js";

export type ChatDestination = "launcher" | "ops" | "history" | "findings" | "doctor" | "replay" | "settings" | "models" | "market";


export interface ChatScreenOptions {
  target?: string;
  scope?: ScopePolicy;
  model?: string;
  role?: "discovery" | "attack" | "verify" | "report" | "audit" | "review";
  maxToolIterations?: number;
  allowScanners?: boolean;
  autonomyMode?: ConsoleAutonomyMode;
}

export interface ChatScreenProps {
  options?: ChatScreenOptions;
  onGoBack: () => void;
  onNavigate: (destination: ChatDestination) => void;
  onExit: () => void;
}

type ChatEntry = {
  id: string;
  /**
   * The transcript speaks in distinct voices, because a slash-command
   * listing is not conversation and reasoning is not an answer. Rendering
   * them all as the same muted bullet is what made command output read as
   * an undifferentiated dump.
   */
  kind: "user" | "assistant" | "reasoning" | "tool" | "subagent" | "notice" | "panel" | "error";
  text: string;
  detail?: string;
  success?: boolean;
  turn: number;
  subagentOutcome?: "completed" | "failed";
  subagentTurns?: number;
  subagentFindings?: number;
  subagentSummary?: string;
  subagentError?: string;
  panel?: PanelData;
  /**
   * A concise, human one-liner of the call's arguments (from `formatToolArgs`),
   * so a compact tool card can read `run_command · npm test · ok` instead of
   * just the bare tool name.
   */
  toolArgs?: string;
  /** Epoch ms the entry was appended, for relative timestamps. */
  at?: number;
  /**
   * Wall-clock duration of the turn this assistant answer belongs to, stamped
   * when the turn ends. Rendered as the elapsed in the AI turn's footer.
   */
  durationMs?: number;
  /**
   * Per-turn model usage, stamped onto the turn's assistant answer(s) when the
   * turn settles. Drives the optional in→out token and cost segments on the AI
   * footer (gated by `showTokenUsage` / `showCost`).
   */
  usageInput?: number;
  usageOutput?: number;
  /**
   * How many consecutive identical entries this row stands for; see
   * `appendTranscriptEntry`. Rendered as a trailing "(xN)".
   */
  repeat?: number;
};

type PendingScope = {
  request: ConsoleScopeRequest;
  resolve: (resolution: ConsoleScopeResolution | null) => void;
};

type PendingLocalScope = {
  request: ConsoleLocalScopeRequest;
  resolve: (resolution: ConsoleLocalScopeResolution | null) => void;
};

type PendingEscalation = {
  request: ScopedAuditEscalationRequest;
  resolve: (approved: boolean) => void;
};

type PendingToolApproval = {
  call: ToolCall;
  resolve: (approved: boolean) => void;
};

/**
 * The 0sec block mark as a per-cell colour grid, one string per row over a
 * three-letter alphabet: ' ' is an empty cell, '#' a white (`theme.TEXT`)
 * block, '/' a red (`theme.ERROR`) block. The "0" is drawn wider than the
 * other letters so its interior has room for a two-cell-thick red diagonal
 * slash — lower-left to upper-right — that clears the white outline on both
 * sides: a slashed zero. "SEC" stays white. `logoCellRuns` groups each row's cells into
 * runs of one colour so the render can draw each as an explicitly-sized
 * `<text>` (their widths sum to exactly `TERMINAL_BLOCK_LOGO_WIDTH`), which is
 * what keeps a row's segments from overflowing and fusing.
 */
const TERMINAL_BLOCK_LOGO = [
  " ######   #######  #######   ######",
  "##  //##  ##       ##       ##     ",
  "## // ##  #######  #####    ##     ",
  "##//  ##       ##  ##       ##     ",
  " ######   #######  #######   ######",
] as const;
const TERMINAL_BLOCK_LOGO_WIDTH = 35;

/** One same-colour run of logo cells: its display text and which token paints it. */
type LogoCellRun = { text: string; kind: " " | "#" | "/" };

/**
 * Split a logo grid row into consecutive same-colour runs. Empty cells stay
 * spaces; '#' and '/' both draw the full block glyph (█) and differ only in
 * colour, so the run's `kind` — not its text — chooses the token at render.
 */
function logoCellRuns(row: string): LogoCellRun[] {
  const runs: LogoCellRun[] = [];
  for (const ch of row) {
    const kind: LogoCellRun["kind"] = ch === "#" ? "#" : ch === "/" ? "/" : " ";
    const glyph = kind === " " ? " " : "█";
    const last = runs[runs.length - 1];
    if (last && last.kind === kind) last.text += glyph;
    else runs.push({ text: glyph, kind });
  }
  return runs;
}

function modeLabel(mode: ConsoleAutonomyMode): string {
  if (mode === "standard") return "Standard";
  if (mode === "recon") return "Recon";
  return mode === "copilot" ? "Co-pilot" : "YOLO";
}

/**
 * Colour for an autonomy mode, shared by the header indicator and any other
 * place the mode is shown: Standard=white (neutral), Recon=blue (passive),
 * Co-pilot=purple (the brand accent), YOLO=red (no prompts).
 */
function modeColorFor(mode: ConsoleAutonomyMode, theme: Theme): string {
  if (mode === "recon") return theme.INFO;
  if (mode === "copilot") return theme.BRAND;
  if (mode === "yolo") return theme.ERROR;
  return theme.TEXT;
}

function completionFor(command: SlashCommand, args = ""): string {
  const base = `/${command.name}`;
  if (args) return `${base} ${args}`;
  return command.usage?.includes(" ") ? `${base} ` : base;
}

function commandMatchesPrefix(command: SlashCommand, rawName: string): boolean {
  return rawName.length === 0
    || command.name.startsWith(rawName)
    || command.aliases.some((alias) => alias.startsWith(rawName));
}

/**
 * Normalize a reasoning stream for display.
 *
 * Reasoning summaries arrive as a sequence of bold headers with no
 * separator between them, so the raw text reads `**A****B****C**`. Four
 * adjacent asterisks are never a single intended run — it is always one
 * bold closing and the next opening — so split them onto their own lines.
 */
function normalizeReasoning(text: string): string {
  return text.replace(/\*\*\*\*/g, "**\n\n**");
}

/**
 * Rebuild visible transcript entries from a stored conversation.
 *
 * Resuming used to restore the model's history but leave the ledger empty,
 * so the operator saw a blank screen and had no idea what the session was
 * about. These messages come off disk and may be malformed or from an
 * older shape, so every branch is defensive: anything unrecognised is
 * skipped rather than rendered as a raw blob, and nothing here throws.
 *
 * Nothing is invented — an assistant message with no text produces no
 * entry rather than a placeholder.
 */
export function entriesFromStoredMessages(messages: readonly unknown[]): ChatEntry[] {
  const out: ChatEntry[] = [];
  // tool_use ids are matched to their results so a call renders as one
  // card with its outcome, the same shape a live turn produces.
  const pendingCalls = new Map<string, { name: string; input: unknown }>();
  let seq = 0;
  const id = () => `restored-${seq++}`;

  for (const raw of messages) {
    if (!raw || typeof raw !== "object") continue;
    const message = raw as { role?: unknown; content?: unknown };
    const blocks = Array.isArray(message.content) ? message.content : [];
    for (const block of blocks) {
      if (!block || typeof block !== "object") continue;
      const b = block as Record<string, unknown>;
      if (b.type === "text" && typeof b.text === "string" && b.text.trim()) {
        out.push({
          id: id(),
          kind: message.role === "user" ? "user" : "assistant",
          text: b.text,
          turn: 0,
        });
      } else if (b.type === "tool_use" && typeof b.name === "string") {
        if (typeof b.id === "string") {
          pendingCalls.set(b.id, { name: b.name, input: b.input });
        }
      } else if (b.type === "tool_result" && typeof b.tool_use_id === "string") {
        const call = pendingCalls.get(b.tool_use_id);
        pendingCalls.delete(b.tool_use_id);
        const name = call?.name ?? "tool";
        const success = b.is_error !== true;
        // Stored results are serialized, so the summariser would otherwise
        // see an opaque string and report "N lines" instead of the counted
        // summary a live turn produces. Parse when it looks like JSON.
        let output: unknown = b.content;
        if (typeof output === "string") {
          const trimmed = output.trim();
          if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
              output = JSON.parse(trimmed);
            } catch {
              // Not JSON after all; the raw string is still a fine summary input.
            }
          }
        }
        out.push({
          id: id(),
          kind: "tool",
          text: name,
          detail: formatToolResult(
            { name, arguments: call?.input },
            { success, output, error: success ? null : String(b.content ?? "") },
          ),
          success,
          turn: 0,
        });
      }
    }
  }

  // A call with no recorded result still happened; show it as unresolved
  // rather than dropping evidence silently.
  for (const [, call] of pendingCalls) {
    out.push({
      id: id(),
      kind: "tool",
      text: call.name,
      detail: formatToolArgs({ name: call.name, arguments: call.input }),
      turn: 0,
    });
  }
  return out;
}

/** Compact relative age, e.g. "12s" / "4m" / "2h". */
function relativeAge(at: number | undefined, now: number): string {
  // Restored entries carry no timestamp; return empty so the caller can omit
  // the separator entirely rather than rendering a dangling "0sec ·".
  if (!at) return "";
  const seconds = Math.max(0, Math.floor((now - at) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  return `${Math.floor(minutes / 60)}h`;
}

interface EntryDisplay {
  /** "comfortable" separates entries with a blank line; "compact" does not. */
  spacing: number;
  showTimestamps: boolean;
  now: number;
  /** Framing of a speaking turn (rail / bubble / plain / compact / document). */
  transcriptStyle: TranscriptStyle;
  /** How the "who said this" label is drawn (full / short / glyph / off). */
  roleLabelStyle: RoleLabelStyle;
  /** How a tool / subagent call is drawn (rail / inline / compact / hidden). */
  toolCardStyle: ToolCardStyle;
  /** Current autonomy mode label, for the AI turn footer ("Standard · …"). */
  mode: string;
  /** Resolved model id, for the AI turn footer ("… · gpt-…"). */
  model: string;
  /** Show the model name on the AI footer (settings.modelDisplay === "message"). */
  modelInFooter: boolean;
  /** Show the per-turn "in→out tok" segment on the AI footer. */
  showTokenUsage: boolean;
  /** Show the estimated per-turn dollar cost on the AI footer. */
  showCost: boolean;
  /** How the transcript folds turn detail; drives the fold planner. */
  transcriptDetail: TranscriptDetail;
}

/**
 * Priced rate rows by lower-cased model id, mirroring status-bar.ts. "default"
 * is excluded on purpose: it is shared's fallback for an UNKNOWN model, and
 * pricing an unrecognised id at it would put a fabricated figure on screen.
 * Kept local (rather than importing status-bar's private map) so the footer's
 * cost estimate never routes through shared's `estimateCost`, which
 * `console.warn`s on an unknown id — forbidden inside a TUI that owns stdout.
 */
const FOOTER_RATES_BY_LOWER: ReadonlyMap<string, ModelRates> = new Map(
  Object.entries(MODEL_PRICING)
    .filter(([key]) => key !== "default")
    .map(([key, rates]) => [key.toLowerCase(), rates]),
);

const FOOTER_VENDOR_PREFIXES = [
  "openai/", "anthropic/", "google/", "deepseek/", "meta/", "mistral/",
  "z-ai/", "zai/", "kimi/", "moonshot/", "openrouter/", "xai/", "x-ai/",
];

function footerRates(model: string): ModelRates | undefined {
  const lower = model.toLowerCase();
  const direct = FOOTER_RATES_BY_LOWER.get(lower);
  if (direct) return direct;
  for (const prefix of FOOTER_VENDOR_PREFIXES) {
    if (lower.startsWith(prefix)) return FOOTER_RATES_BY_LOWER.get(lower.slice(prefix.length));
  }
  return undefined;
}

/**
 * A quiet per-turn cost string for the AI footer, or "$—" when the model's rate
 * is unknown (never a figure at a rate the model was not billed). Mirrors the
 * status-bar's arithmetic and formatting.
 */
function formatTurnCost(model: string, inputTokens: number, outputTokens: number): string {
  const rates = model ? footerRates(model) : undefined;
  if (!rates) return "$—";
  const usd =
    (Math.max(0, inputTokens) / 1_000_000) * rates.input +
    (Math.max(0, outputTokens) / 1_000_000) * rates.output;
  if (!Number.isFinite(usd) || usd <= 0) return "$0.00";
  if (usd < 0.01) return "<$0.01";
  return `$${usd.toFixed(2)}`;
}

/**
 * Terminal text ATTRIBUTES for a markdown span — the real weight, not just a
 * colour. A bold run gets TextAttributes.BOLD so it renders visibly heavier;
 * italic gets ITALIC, strike gets STRIKETHROUGH, and a muted run is dimmed.
 * Applied by every inline renderer (paragraphs, list items, table cells) so
 * `**bold**` looks bold wherever it appears.
 */
function spanAttributes(style: MdSpan["style"]): number | undefined {
  switch (style) {
    case "bold":
      return TextAttributes.BOLD;
    case "italic":
      return TextAttributes.ITALIC;
    case "strike":
      return TextAttributes.STRIKETHROUGH;
    case "muted":
      return TextAttributes.DIM;
    default:
      return undefined;
  }
}

/** Map a markdown span style onto the theme. */
function spanColor(style: MdSpan["style"], theme: Theme, tone?: string): string {
  const { ACCENT, INFO, MUTED, TEXT } = theme;
  // A tone override keeps a whole block in one voice (e.g. reasoning stays
  // muted) while still honouring structure like code and links.
  if (tone && style !== "code" && style !== "link") return tone;
  if (style === "code") return ACCENT;
  if (style === "link") return INFO;
  if (style === "muted" || style === "strike") return MUTED;
  return TEXT;
}

/**
 * Render parsed markdown blocks.
 *
 * Models emit markdown constantly, and showing `**bold**` literally is the
 * single most visible way a terminal agent looks unfinished. Every line is
 * pre-wrapped to an exact width by `renderMarkdown`, so nothing here needs
 * to guess at widths — which is also what keeps a long span from
 * overflowing its row.
 */
function renderMarkdownBlocks(blocks: readonly MdBlock[], key: string, theme: Theme, tone?: string) {
  const { MUTED, ACCENT, PRIMARY, TEXT } = theme;
  return blocks.map((block, index) => {
    const id = `${key}-b${index}`;
    if (block.kind === "rule") {
      return <text key={id} fg={tone ?? MUTED}>{"─".repeat(8)}</text>;
    }
    if (block.kind === "table") {
      // Each cell is a styled inline-span run (bold/italic/code render just as
      // they do in a paragraph). Every column is a fixed-width box, so the
      // separators line up regardless of the cell content, and alignment inside
      // a column is done with leading/trailing padding spans. Widths were chosen
      // by `renderMarkdown` from the marker-stripped display text, so the whole
      // row fits the content column.
      const { widths } = block;
      const renderRow = (cells: readonly MdSpan[][], rowKey: string, header: boolean) => (
        <box key={rowKey} flexDirection="row" minWidth={0}>
          {cells.map((cell, c) => {
            const w = widths[c] ?? 1;
            const disp = cell.reduce((n, s) => n + Array.from(s.text).length, 0);
            const pad = Math.max(0, w - disp);
            const align = block.align[c] ?? "left";
            const lead = align === "right" ? pad : align === "center" ? Math.floor(pad / 2) : 0;
            const trail = pad - lead;
            return (
              <React.Fragment key={`${rowKey}-c${c}`}>
                {c > 0 ? <text flexShrink={0} fg={MUTED}>{TABLE_COLUMN_GAP}</text> : null}
                <box width={w} flexShrink={0} minWidth={0} flexDirection="row">
                  {lead > 0 ? <text flexShrink={0} fg={MUTED}>{" ".repeat(lead)}</text> : null}
                  {cell.map((span, j) => (
                    <text key={`${rowKey}-c${c}-s${j}`} flexShrink={0} fg={spanColor(span.style, theme, header ? (tone ?? PRIMARY) : tone)} attributes={spanAttributes(span.style) ?? (header ? TextAttributes.BOLD : undefined)}>{span.text}</text>
                  ))}
                  {trail > 0 ? <text flexShrink={0} fg={MUTED}>{" ".repeat(trail)}</text> : null}
                </box>
              </React.Fragment>
            );
          })}
        </box>
      );
      const separatorLine = widths.map((w) => "─".repeat(Math.max(1, w))).join(TABLE_JOIN_GLYPH);
      return (
        <box key={id} flexDirection="column" minWidth={0}>
          {renderRow(block.header, `${id}-h`, true)}
          <text fg={MUTED}>{separatorLine}</text>
          {block.rows.map((row, i) => renderRow(row, `${id}-r${i}`, false))}
        </box>
      );
    }
    if (block.kind === "code") {
      return (
        <box key={id} flexDirection="column" marginLeft={2}>
          {block.lines.map((line, i) => (
            <text key={`${id}-${i}`} fg={ACCENT}>{line}</text>
          ))}
        </box>
      );
    }
    if (block.kind === "heading") {
      return (
        <box key={id} flexDirection="column" minWidth={0}>
          {block.lines.map((line, i) => (
            <text key={`${id}-${i}`} fg={tone ?? PRIMARY} attributes={TextAttributes.BOLD}>{line.map((span) => span.text).join("")}</text>
          ))}
        </box>
      );
    }
    if (block.kind === "listItem") {
      const gutter = listItemGutterWidth(block);
      return (
        <box key={id} flexDirection="row" minWidth={0}>
          <box width={gutter} flexShrink={0} minWidth={0}>
            <text fg={MUTED}>{`${" ".repeat(block.indent)}${block.marker}`}</text>
          </box>
          <box flexDirection="column" flexGrow={1} minWidth={0}>
            {block.lines.map((line, i) => (
              <box key={`${id}-${i}`} flexDirection="row" minWidth={0}>
                {line.map((span, j) => (
                  <text key={`${id}-${i}-${j}`} fg={spanColor(span.style, theme, tone)} attributes={spanAttributes(span.style)}>{span.text}</text>
                ))}
              </box>
            ))}
          </box>
        </box>
      );
    }
    // paragraph | quote — a quote is always muted, otherwise inherit the
    // caller's tone override (if any).
    const blockTone = block.kind === "quote" ? MUTED : tone;
    return (
      <box key={id} flexDirection="column" minWidth={0} marginLeft={block.kind === "quote" ? 2 : 0}>
        {block.lines.map((line, i) => (
          <box key={`${id}-${i}`} flexDirection="row" minWidth={0}>
            {line.map((span, j) => (
              <text key={`${id}-${i}-${j}`} fg={spanColor(span.style, theme, blockTone)} attributes={spanAttributes(span.style)}>{span.text}</text>
            ))}
          </box>
        ))}
      </box>
    );
  });
}

function renderEntry(entry: ChatEntry, maxWidth: number, display: EntryDisplay, theme: Theme) {
  const { ACCENT, PRIMARY, TEXT, MUTED, ERROR, SUCCESS, BORDER, PANEL_ALT, BRAND } = theme;
  const detailWidth = Math.max(20, maxWidth - 8);
  const { transcriptStyle, roleLabelStyle, toolCardStyle } = display;
  // A row that stands for several collapsed repeats says so. The count is
  // appended at render time and never written into `entry.text`, so the next
  // repeat still compares equal and keeps collapsing.
  const repeat = repeatSuffix(entry.repeat);

  if (entry.kind === "user" || entry.kind === "assistant") {
    const isUser = entry.kind === "user";
    // Frame accents (a bubble border, the inline label gap) stay in the
    // speaker's own tone. The LABEL, however, carries the brand: the assistant
    // "0sec" label renders in the brand purple (theme.BRAND); the operator label
    // stays the neutral accent. Body text is never tinted by this — it keeps
    // TEXT / PRIMARY via renderMarkdownBlocks below.
    const tone = isUser ? ACCENT : PRIMARY;
    const labelTone = isUser ? ACCENT : BRAND;
    const frame = speechFrame(transcriptStyle, entry.kind, maxWidth);
    const marginTop = display.spacing + frame.extraMarginTop;
    const age = display.showTimestamps ? relativeAge(entry.at, display.now) : "";
    const label = roleLabelText(isUser ? "user" : "assistant", roleLabelStyle, age);
    // With the old full-height rail gone, an unbordered turn hands the whole
    // pane to its body: the two cells the rail and its gap used to spend are
    // reclaimed for text. A bordered turn still wraps to its inner width.
    const bodyWidth = frame.bordered ? frame.markdownWidth : Math.max(8, maxWidth);
    // Body: raw text for the operator, rendered markdown for the model.
    const body = isUser
      ? <text fg={TEXT} wrapMode="word">{sanitizeTuiText(entry.text)}</text>
      : renderMarkdownBlocks(renderMarkdown(entry.text, bodyWidth), entry.id, theme);

    if (frame.bordered) {
      // The grouped style: a subtle surface plus a border frames the turn,
      // never a tall left bar. A bordered turn MUST carry an explicit numeric
      // width plus flexShrink=0: width="100%" leaves flexShrink at 1, so under
      // column pressure the box collapses and paints its own border through the
      // message (PRIMITIVES.md).
      return (
        <box key={entry.id} flexDirection="column" width={maxWidth} flexShrink={0} minWidth={0} marginTop={marginTop} border borderColor={tone} backgroundColor={PANEL_ALT} paddingX={1}>
          {label ? <text fg={labelTone}>{label}</text> : null}
          {body}
        </box>
      );
    }

    // The clean DEFAULT look (transcriptStyle "rail"): the two voices are told
    // apart by their frame, not by a tinted label. The OPERATOR turn is drawn
    // like the input that produced it — a thin accent rail down the left plus a
    // faint panel background, so it reads as "what you said" the same way the
    // composer reads as "what you're saying". The AI turn is PLAIN body text
    // followed by a compact muted footer (a red brand marker, then mode · model
    // · elapsed), so the answer itself is unadorned and the provenance sits
    // quietly beneath it.
    if (transcriptStyle === "rail") {
      if (isUser) {
        return (
          <box key={entry.id} flexDirection="row" width={maxWidth} flexShrink={0} minWidth={0} marginTop={marginTop} backgroundColor={PANEL_ALT}>
            <box width={1} flexShrink={0} alignSelf="stretch" backgroundColor={ACCENT} />
            <box flexDirection="column" flexGrow={1} minWidth={0} paddingX={1}>
              {body}
            </box>
          </box>
        );
      }
      // The footer is composed from the mode plus whatever telemetry the
      // operator opted into: the model only when `modelDisplay` routes it here
      // (otherwise it lives in the bottom bar), the per-turn tokens under
      // `showTokenUsage`, the per-turn cost under `showCost`, and the elapsed.
      const footerParts: string[] = [display.mode];
      if (display.modelInFooter && display.model) footerParts.push(display.model);
      if (display.showTokenUsage && entry.usageInput !== undefined) {
        footerParts.push(`${entry.usageInput}→${entry.usageOutput ?? 0} tok`);
      }
      if (display.showCost && entry.usageInput !== undefined) {
        footerParts.push(formatTurnCost(display.model, entry.usageInput, entry.usageOutput ?? 0));
      }
      const elapsed = entry.durationMs ? formatElapsed(entry.durationMs) : "";
      if (elapsed) footerParts.push(elapsed);
      const footer = footerParts.join(" · ");
      return (
        <box key={entry.id} flexDirection="column" marginTop={marginTop} minWidth={0}>
          {body}
          <box flexDirection="row" minWidth={0}>
            <box width={2} flexShrink={0} minWidth={0}>
              <text fg={ERROR}>▪ </text>
            </box>
            <box flexGrow={1} minWidth={0}>
              <text fg={MUTED}>{fitTuiText(footer, Math.max(1, maxWidth - 2))}</text>
            </box>
          </box>
        </box>
      );
    }

    // compact inlines a one-line operator message next to its label.
    if (!frame.labelOwnRow && isUser) {
      return (
        <box key={entry.id} flexDirection="row" marginTop={marginTop} minWidth={0}>
          {label ? <box flexShrink={0}><text fg={labelTone}>{label}</text></box> : null}
          <box flexGrow={1} minWidth={0} marginLeft={label ? 1 : 0}>
            {body}
          </box>
        </box>
      );
    }

    // The default separation, OpenCode-style: consecutive turns are set apart
    // by whitespace (marginTop) and a compact coloured speaker label on its own
    // row — NOT a full-height rail down the left of every message. The body
    // then takes every cell of the pane, flush left.
    return (
      <box key={entry.id} flexDirection="column" marginTop={marginTop} minWidth={0}>
        {label ? <text fg={labelTone}>{label}</text> : null}
        {body}
      </box>
    );
  }

  if (entry.kind === "tool") {
    const tone = entry.success === false ? ERROR : entry.success ? SUCCESS : PRIMARY;
    const { icon, state } = toolGlyphState(entry.success);
    const frame = toolFrame(toolCardStyle, maxWidth, entry.success);
    if (!frame.render) return null;
    const toolDetail = toolDetailWidth(frame.contentWidth, maxWidth);

    // compact / hidden: a single clean summary line — no rail, mono palette,
    // the colour carried only by the icon. The concise args ride on the name
    // (`run_command · npm test · complete`) so the operator sees WHAT ran, not
    // just that something did; `toolCompactLine` drops the state first and then
    // truncates from the tail, so the tool's identity always survives. Detail
    // (the result summary) is shown only on failure, where the reason matters.
    if (frame.singleLine) {
      const compactName = entry.toolArgs
        ? `${entry.text}${repeat} · ${entry.toolArgs}`
        : `${entry.text}${repeat}`;
      return (
        <box key={entry.id} flexDirection="column" marginTop={display.spacing} minWidth={0}>
          <text fg={tone}>{toolCompactLine(icon, compactName, state, frame.contentWidth)}</text>
          {frame.showDetail && entry.detail ? (
            <text fg={MUTED} wrapMode="word">{fitTuiText(entry.detail, frame.contentWidth)}</text>
          ) : null}
        </box>
      );
    }

    // rail / inline: icon, muted prefix and name are siblings on one row; the
    // name is budgeted against the prefix's real length or the row overruns its
    // container and the renderer paints the columns into each other.
    const toolPrefix = toolHeaderPrefix(state);
    const cols = toolHeaderColumns(frame.contentWidth, toolPrefix.length, toolDetail);
    const header = (
      <box flexDirection="column" flexGrow={1} minWidth={0} marginLeft={frame.contentGap}>
        <box flexDirection="row" minWidth={0}>
          <text fg={tone}>{icon}</text>
          <text fg={MUTED}>{toolPrefix}</text>
          <text fg={TEXT}>{fitTuiText(`${entry.text}${repeat}`, cols.nameWidth)}</text>
        </box>
        {frame.showDetail && entry.detail ? <text fg={MUTED} wrapMode="word">{fitTuiText(entry.detail, toolDetail)}</text> : null}
      </box>
    );
    return (
      <box key={entry.id} flexDirection="row" marginTop={display.spacing} marginLeft={frame.outerMarginLeft} minWidth={0}>
        {frame.railKind === "solid" ? <box width={1} alignSelf="stretch" backgroundColor={tone} /> : null}
        {header}
      </box>
    );
  }

  if (entry.kind === "subagent") {
    const outcome = entry.subagentOutcome ?? "failed";
    const ok = outcome === "completed";
    const tone = ok ? SUCCESS : ERROR;
    const frame = toolFrame(toolCardStyle, maxWidth, ok);
    if (!frame.render) return null;
    const subDetailWidth = toolDetailWidth(frame.contentWidth, maxWidth);
    const statusParts: string[] = [];
    if (entry.subagentTurns !== undefined) statusParts.push(`turns ${entry.subagentTurns}`);
    if (entry.subagentFindings !== undefined) statusParts.push(`findings ${entry.subagentFindings}`);
    const statusLine = statusParts.length > 0 ? statusParts.join(" · ") : null;

    if (frame.singleLine) {
      return (
        <box key={entry.id} flexDirection="column" marginTop={display.spacing} minWidth={0}>
          <text fg={tone}>{toolCompactLine(ok ? "✓" : "×", "subagent", ok ? "completed" : "failed", frame.contentWidth)}</text>
          {frame.showDetail && entry.subagentError ? (
            <text fg={ERROR} wrapMode="word">{fitTuiText(entry.subagentError, frame.contentWidth)}</text>
          ) : null}
        </box>
      );
    }

    return (
      <box key={entry.id} flexDirection="row" marginTop={display.spacing} marginLeft={frame.outerMarginLeft} minWidth={0}>
        {frame.railKind === "solid" ? <box width={1} alignSelf="stretch" backgroundColor={tone} /> : null}
        <box flexDirection="column" flexGrow={1} minWidth={0} marginLeft={frame.contentGap}>
          <box flexDirection="row">
            <text fg={tone}>{ok ? "✓" : "×"}</text>
            <text fg={BRAND}> evidence / subagent</text>
            <text fg={MUTED}> · {ok ? "completed" : "failed"}</text>
          </box>
          {frame.showDetail && statusLine ? <text fg={MUTED}>{fitTuiText(statusLine, subDetailWidth)}</text> : null}
          {frame.showDetail && entry.subagentSummary ? <text fg={TEXT} wrapMode="word">{fitTuiText(entry.subagentSummary, subDetailWidth)}</text> : null}
          {entry.subagentError ? <text fg={ERROR} wrapMode="word">{fitTuiText(entry.subagentError, subDetailWidth)}</text> : null}
        </box>
      </box>
    );
  }

  if (entry.kind === "error") {
    // Failures get the same rail treatment as speech, in the error tone: an
    // operator must be able to see at a glance that the turn did not produce an
    // answer, and why. `bubble` frames it as a bordered ERROR block instead.
    const frame = speechFrame(transcriptStyle, "error", maxWidth);
    const marginTop = display.spacing + frame.extraMarginTop;
    if (frame.bordered) {
      return (
        <box key={entry.id} flexDirection="column" width={maxWidth} flexShrink={0} minWidth={0} marginTop={marginTop} border borderColor={ERROR} paddingX={1}>
          <text fg={ERROR}>{fitTuiText(`${entry.text}${repeat}`, frame.contentWidth)}</text>
          {entry.detail ? <text fg={MUTED} wrapMode="word">{fitTuiText(entry.detail, frame.contentWidth)}</text> : null}
        </box>
      );
    }
    // A failed turn reads as speech in the error tone: a compact red marker and
    // label, the body beneath it, and the same whitespace separation as any
    // other turn — no full-height bar.
    return (
      <box key={entry.id} flexDirection="column" marginTop={marginTop} minWidth={0}>
        <text fg={ERROR}>{fitTuiText(`▌ ${entry.text}${repeat}`, Math.max(1, maxWidth))}</text>
        {entry.detail ? (
          <text fg={MUTED} wrapMode="word">{fitTuiText(entry.detail, detailWidth)}</text>
        ) : null}
      </box>
    );
  }

  if (entry.kind === "reasoning") {
    // Thinking is deliberately quieter than the answer: a dotted rail and
    // muted text, so it reads as working-out rather than a conclusion.
    return (
      <box key={entry.id} flexDirection="row" marginTop={display.spacing} minWidth={0}>
        <box width={1} flexShrink={0} alignSelf="stretch">
          <text fg={MUTED}>┊</text>
        </box>
        <box flexDirection="column" flexGrow={1} minWidth={0} marginLeft={1}>
          <text fg={MUTED}>thinking</text>
          {renderMarkdownBlocks(
            renderMarkdown(normalizeReasoning(entry.text), Math.max(8, maxWidth - 2)),
            entry.id,
            theme,
            MUTED,
          )}
        </box>
      </box>
    );
  }

  if (entry.kind === "panel" && entry.panel) {
    // Command output is not dialogue, so it gets a bordered block with
    // aligned columns instead of one muted bullet per line. Column widths
    // come from panelColumns so the two columns can never overspend the
    // panel and paint into each other.
    const panel = entry.panel;
    // Two border cells plus one padding cell on each side.
    const innerWidth = Math.max(1, maxWidth - 4);
    const columns = panelColumns(panel.rows, innerWidth);
    return (
      <box key={entry.id} flexDirection="column" width="100%" minWidth={0} flexShrink={0} marginTop={display.spacing} border borderColor={BORDER} paddingX={1}>
        <box flexDirection="row" width="100%" minWidth={0}>
          <text fg={PRIMARY}>{fitTuiText(panel.title, innerWidth)}</text>
        </box>
        {panel.subtitle ? (
          <text fg={MUTED}>{fitTuiText(panel.subtitle, innerWidth)}</text>
        ) : null}
        {panel.rows.map((row, index) => {
          if (row.heading) {
            return (
              <text key={`h-${index}`} fg={ACCENT}>{fitTuiText(row.value, innerWidth)}</text>
            );
          }
          if (!row.label || columns.labelWidth === 0) {
            return (
              <text key={`r-${index}`} fg={TEXT} wrapMode="word">{fitTuiText(row.value, innerWidth)}</text>
            );
          }
          return (
            <box key={`r-${index}`} flexDirection="row" width="100%" minWidth={0} gap={columns.gap}>
              <box width={columns.labelWidth} flexShrink={0} minWidth={0}>
                <text fg={TEXT}>{fitTuiText(row.label, columns.labelWidth)}</text>
              </box>
              <box width={columns.valueWidth} flexShrink={0} minWidth={0}>
                <text fg={MUTED}>{fitTuiText(row.value, columns.valueWidth)}</text>
              </box>
            </box>
          );
        })}
      </box>
    );
  }

  return (
    <box key={entry.id} flexDirection="row" marginTop={display.spacing} minWidth={0}>
      <text fg={MUTED}>·</text>
      <box flexDirection="column" flexGrow={1} minWidth={0} marginLeft={1}>
        <text fg={MUTED} wrapMode="word">{fitTuiText(`${entry.text}${repeat}`, maxWidth - 2)}</text>
        {entry.detail ? <text fg={MUTED} wrapMode="word">{fitTuiText(entry.detail, maxWidth - 2)}</text> : null}
      </box>
    </box>
  );
}

/**
 * A folded run of collapsed detail: one quiet line, a ▸ disclosure glyph then
 * the summary. The planner never folds a failure into a run, so the muted tone
 * is always correct — every entry behind this line succeeded (or is reasoning).
 * Expanding the transcript (Ctrl+R) restores the full cards.
 */
function renderFold(
  item: Extract<TranscriptPlanItem<ChatEntry>, { type: "fold" }>,
  maxWidth: number,
  display: EntryDisplay,
  theme: Theme,
) {
  const { MUTED } = theme;
  const key = `fold-${item.entries[0]?.id ?? item.turn}`;
  // `toolCardStyle: "hidden"` means "don't show me successful tool activity";
  // honour it inside a fold too by dropping the tool/subagent steps from the
  // summary (reasoning still folds). A fold left with nothing renders nothing.
  const shown =
    display.toolCardStyle === "hidden"
      ? item.entries.filter((entry) => entry.kind !== "tool" && entry.kind !== "subagent")
      : item.entries;
  if (shown.length === 0) return null;
  const summary = shown.length === item.entries.length ? item.summary : foldSummary(shown);
  return (
    <box key={key} flexDirection="row" marginTop={display.spacing} minWidth={0}>
      <box width={2} flexShrink={0} minWidth={0}>
        <text fg={MUTED}>▸ </text>
      </box>
      <box flexGrow={1} minWidth={0}>
        <text fg={MUTED}>{fitTuiText(summary, Math.max(1, maxWidth - 2))}</text>
      </box>
    </box>
  );
}

function buildScopeResolution(request: ConsoleScopeRequest): ConsoleScopeResolution | null {
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

/**
 * Composer chrome, selected by the `composerStyle` setting.
 *
 * Deliberately three distinct elements instead of one box with toggled
 * props: opentui renders a frame whenever `border` is present at all, so a
 * falsy value does not remove it.
 */
function ComposerFrame({
  style,
  active,
  theme,
  padY = 0,
  children,
}: {
  style: TuiSettings["composerStyle"];
  active: boolean;
  theme: Theme;
  /**
   * Extra rows of vertical padding inside the frame. Used ONLY by the centered
   * hero composer, so the start-screen input reads as a comfortable card rather
   * than a thin sliver; the pinned chat composer leaves it at 0 so its height
   * matches the COMPOSER_ROWS the column reserves.
   */
  padY?: number;
  children: React.ReactNode;
}) {
  const { PRIMARY, MUTED, BORDER, PANEL_ALT } = theme;
  if (style === "border") {
    return (
      <box flexDirection="column" flexGrow={1} minWidth={0} flexShrink={0} border borderColor={active ? PRIMARY : BORDER} backgroundColor={PANEL_ALT} paddingX={1} paddingTop={padY} paddingBottom={padY}>
        {children}
      </box>
    );
  }
  if (style === "rail") {
    return (
      <box flexDirection="column" flexGrow={1} minWidth={0} flexShrink={0} marginLeft={1} backgroundColor={PANEL_ALT} paddingTop={padY} paddingBottom={padY}>
        {children}
      </box>
    );
  }
  return (
    <box flexDirection="column" flexGrow={1} minWidth={0} flexShrink={0} paddingTop={padY} paddingBottom={padY}>
      {children}
    </box>
  );
}

interface KeyHint {
  key: string;
  label: string;
}

/** Plain rendered length of a key-hint row, for a fits-the-column guard. */
function keyHintsLength(pairs: readonly KeyHint[], sep: string): number {
  let n = 0;
  pairs.forEach((p, i) => {
    if (i > 0) n += sep.length;
    n += p.key.length + 1 + p.label.length;
  });
  return n;
}

/**
 * A keybind hint row: the KEY glyphs render in TEXT (white) and the labels in
 * MUTED, so `shift+tab mode · ctrl+p palette` reads as chords, not prose. Each
 * segment is flexShrink={0}, so the caller must only render this where it fits
 * (see keyHintsLength); a squeezed row of siblings overpaints in this TUI.
 */
function KeyHints({
  pairs,
  theme,
  sep = " · ",
}: {
  pairs: readonly KeyHint[];
  theme: Theme;
  sep?: string;
}) {
  const { TEXT, MUTED } = theme;
  const nodes: React.ReactNode[] = [];
  pairs.forEach((p, i) => {
    if (i > 0) nodes.push(<text key={`sep-${i}`} flexShrink={0} fg={MUTED}>{sep}</text>);
    nodes.push(<text key={`key-${i}`} flexShrink={0} fg={TEXT}>{p.key}</text>);
    nodes.push(<text key={`lbl-${i}`} flexShrink={0} fg={MUTED}>{` ${p.label}`}</text>);
  });
  return <box flexDirection="row" minWidth={0} flexShrink={0}>{nodes}</box>;
}

/**
 * How many rows a selector panel may spend, and on what.
 *
 * The panel is a bordered box stacked above the composer with an EXPLICIT
 * height, so whatever it claims here is exactly what it paints. `budget` is
 * the number of content rows the column can spare (from
 * `computeCommandMenuHeight`, which already reserves the composer, the
 * header and a minimum transcript).
 *
 * The optional lines are bought in priority order out of that budget rather
 * than added on top of it: at least one item row always survives, then the
 * context line (which says WHAT is being decided), then the detail line for
 * the highlighted item. A panel that cannot afford them drops them instead
 * of growing past its budget and over-subscribing the column — which is the
 * exact failure that painted four `<text>` children onto one another and
 * through the box border.
 */
function selectorPanelBudget({
  budget,
  hasContext,
  hasDetail,
}: {
  budget: number;
  hasContext: boolean;
  hasDetail: boolean;
}): { maxItemRows: number; showContext: boolean; showDetail: boolean } {
  const total = Math.max(1, budget);
  let remaining = total - 1; // one item row is non-negotiable
  const showContext = hasContext && remaining > 0;
  if (showContext) remaining -= 1;
  const showDetail = hasDetail && remaining > 0;
  if (showDetail) remaining -= 1;
  return { maxItemRows: 1 + remaining, showContext, showDetail };
}

/**
 * Total rows a selector panel occupies for the rows it actually renders.
 * `commandMenuBoxHeight` covers the two border rows, the header and the
 * hint footer; the optional lines are added explicitly.
 */
function selectorPanelHeight(itemRows: number, showContext: boolean, showDetail: boolean): number {
  return commandMenuBoxHeight(Math.max(itemRows, 1), 1)
    + (showContext ? 1 : 0)
    + (showDetail ? 1 : 0);
}

/**
 * THE decision surface.
 *
 * `/model`, `/mode`, `/settings`, `/providers`, `/resume` and every
 * authorization prompt render through this one component, driven by the same
 * `SelectorState` reducer and the same key bindings. Approvals used to be
 * four bespoke bordered boxes of loose `<text>` children; opentui defaults
 * `flexShrink` to 1 for any box without a numeric width/height, so under
 * column pressure Yoga collapsed those boxes while their children kept their
 * intrinsic size — every line, and the border, painted onto one row.
 *
 * Two properties prevent that here and are the reason approvals were moved
 * onto this component rather than patched in place:
 *   - an explicit `height` plus `flexShrink={0}`, so the box is clipped by
 *     the layout rather than squeezed under its own contents;
 *   - every child given an explicit cell width, so no row can overspend the
 *     panel's inner width and paint into the border.
 */
function SelectorPanel({
  title,
  subtitle,
  context,
  contextColor,
  rows,
  windowStart,
  activeIndex,
  detail,
  hint,
  emptyText,
  borderColor,
  titleColor,
  contentWidth,
  height,
  theme,
}: {
  title: string;
  subtitle: string;
  context?: string;
  contextColor?: string;
  rows: SelectorItem[];
  windowStart: number;
  activeIndex: number;
  detail?: string;
  hint: string;
  emptyText: string;
  borderColor: string;
  titleColor: string;
  contentWidth: number;
  height: number;
  theme: Theme;
}) {
  const { PANEL_ALT, MUTED, TEXT, PRIMARY, ACCENT, ERROR } = theme;
  // Deliberately conservative: the real inner width is 2 (compact) to 4
  // (wide) cells more than this, so every explicit allocation below fits
  // with room to spare and can never reach the border.
  const innerWidth = Math.max(1, contentWidth - 4);
  const headerGap = innerWidth > 12 ? 1 : 0;
  const headerTitleWidth = Math.max(1, Math.min(innerWidth - headerGap, Math.floor(innerWidth * 0.55)));
  const headerSubtitleWidth = Math.max(0, innerWidth - headerTitleWidth - headerGap);
  // Marker cell + its gap, then label, then whatever is left for the meta
  // column. Widths and margins sum to exactly `innerWidth`; the old picker
  // used `gap={1}` on top of widths that already spent the full row, which
  // overspent it by two cells.
  const labelWidth = Math.max(1, Math.min(Math.max(1, innerWidth - 2), Math.floor(innerWidth * 0.45)));
  const afterLabel = innerWidth - 2 - labelWidth;
  const metaGap = afterLabel > 1 ? 1 : 0;
  const metaWidth = Math.max(0, afterLabel - metaGap);

  return (
    <box flexDirection="column" width="100%" minWidth={0} height={height} flexShrink={0} marginTop={1} border borderColor={borderColor} backgroundColor={PANEL_ALT} paddingX={1}>
      <box flexDirection="row" width={innerWidth} flexShrink={0} minWidth={0}>
        <box width={headerTitleWidth} flexShrink={0} minWidth={0}>
          <text fg={titleColor}>{fitTuiText(title, headerTitleWidth)}</text>
        </box>
        {headerSubtitleWidth > 0 ? (
          <box width={headerSubtitleWidth} flexShrink={0} minWidth={0} marginLeft={headerGap}>
            <text fg={MUTED}>{fitTuiText(subtitle, headerSubtitleWidth, { mode: "middle" })}</text>
          </box>
        ) : null}
      </box>
      {context ? (
        <box width={innerWidth} flexShrink={0} minWidth={0}>
          {/* Truncated, never wrapped: a wrapping line has an unpredictable
              height, and an unpredictable height is what over-subscribes the
              column in the first place. */}
          <text fg={contextColor ?? TEXT}>{fitTuiText(context, innerWidth, { mode: "middle" })}</text>
        </box>
      ) : null}
      {rows.length > 0 ? rows.map((item, offset) => {
        const index = windowStart + offset;
        const active = index === activeIndex;
        return (
          <box key={item.id} flexDirection="row" width={innerWidth} flexShrink={0} minWidth={0}>
            <text width={1} flexShrink={0} fg={active ? PRIMARY : MUTED}>{active ? "›" : " "}</text>
            <box width={labelWidth} flexShrink={0} minWidth={0} marginLeft={1}>
              <text fg={item.disabled ? MUTED : active ? TEXT : MUTED}>{fitTuiText(`${item.current ? "● " : "  "}${item.label}`, labelWidth)}</text>
            </box>
            {metaWidth > 0 ? (
              <box width={metaWidth} flexShrink={0} minWidth={0} marginLeft={metaGap}>
                <text fg={active ? ACCENT : MUTED}>{fitTuiText(item.meta ?? "", metaWidth, { mode: "middle" })}</text>
              </box>
            ) : null}
          </box>
        );
      }) : (
        <box width={innerWidth} flexShrink={0} minWidth={0}>
          <text fg={ERROR}>{fitTuiText(emptyText, innerWidth)}</text>
        </box>
      )}
      {detail ? (
        <box width={innerWidth} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText(detail, innerWidth, { mode: "middle" })}</text>
        </box>
      ) : null}
      <box width={innerWidth} flexShrink={0} minWidth={0}>
        <text fg={MUTED}>{fitTuiText(hint, innerWidth)}</text>
      </box>
    </box>
  );
}

/**
 * Turn a tool call's arguments into readable `key: value` lines — one per row,
 * so the approval card can show WHAT is being authorized instead of a truncated
 * one-line JSON blob. A scalar becomes its own line; a nested object/array is
 * compacted to JSON on that key's line (still readable, still one row). The
 * per-row truncation happens at render time against the panel width, which is
 * what keeps the card's height predictable.
 */
function argumentSummaryLines(args: unknown): string[] {
  if (args === undefined || args === null) return [];
  if (typeof args !== "object") return [sanitizeTuiText(String(args))];
  const entries = Array.isArray(args)
    ? args.map((value, index) => [String(index), value] as const)
    : Object.entries(args as Record<string, unknown>);
  if (entries.length === 0) return [];
  return entries.map(([key, value]) => {
    const rendered = typeof value === "string" ? value : JSON.stringify(value) ?? String(value);
    return sanitizeTuiText(`${key}: ${rendered}`);
  });
}

/**
 * One pending authorization decision, projected onto the selector.
 *
 * The pending promise itself stays in the `pending*` state it always lived
 * in — this is only a presentation + dispatch view over it, so the unmount
 * cleanup that resolves every outstanding prompt to a DENIAL keeps working
 * untouched.
 */
type ApprovalPrompt = {
  /**
   * The pending record this prompt speaks for. Object identity, so a new
   * request gets a fresh selector position and a repeat of an identical
   * request is still its own decision.
   */
  owner: object;
  title: string;
  /** What is being decided — tool name, hosts, path, reason. */
  context: string;
  /** The subject of the decision, shown prominently (e.g. the tool name). */
  subject?: string;
  /**
   * Readable, one-per-row detail lines (pretty-printed `key: value` arguments,
   * or a short human summary) — never a truncated single-line JSON blob. Each
   * line is truncated (not wrapped) to the panel width so the card's height
   * stays predictable.
   */
  bodyLines?: string[];
  items: SelectorItem[];
  borderColor: string;
  titleColor: string;
  /** Applies the chosen item. Guarded to run at most once per `owner`. */
  decide: (id: string) => void;
  /**
   * Esc / dismissal. ALWAYS the declining outcome: an operator must never be
   * able to grant authority by walking away from the prompt.
   */
  decline: () => void;
};

/**
 * Total rows an {@link ApprovalCard} occupies for the content it will render.
 *
 * The card is a rail + background block (no top/bottom border and no vertical
 * padding), so its height is exactly its content rows. Stating it as a pure
 * function lets the column reserve precisely what the card paints — the same
 * anti-collapse contract every other stacked panel obeys.
 */
function approvalCardRows({
  hasSubject,
  bodyRows,
  choiceRows,
}: {
  hasSubject: boolean;
  bodyRows: number;
  choiceRows: number;
}): number {
  return 1 /* title */
    + (hasSubject ? 1 : 0)
    + (bodyRows > 0 ? bodyRows + 1 /* blank spacer under the args */ : 0)
    + 1 /* blank spacer above the choices */
    + Math.max(1, choiceRows)
    + 1 /* hint */;
}

/**
 * A pending authorization decision, drawn as a prominent-but-calm card.
 *
 * This replaces the old cramped bordered picker for approvals: it keeps the
 * SAME selector reducer, dispatch and key bindings (the caller owns those),
 * and only changes the surface. A decision is an important moment, so the tool
 * name and its arguments are shown READABLY — one `key: value` row each, each
 * truncated (never wrapped) so the card's height is exactly what was reserved —
 * and the two choices read as clean rows with a single accent on the selected
 * one, its consequence aligned to the right. The framing is the same thin
 * accent rail + faint panel background as the composer and the operator's own
 * turns, not a heavy four-sided box; `red` stays reserved for errors.
 */
function ApprovalCard({
  title,
  progress,
  subject,
  body,
  choices,
  activeIndex,
  hint,
  accent,
  contentWidth,
  height,
  theme,
}: {
  title: string;
  progress: string;
  subject?: string;
  /** Already-sliced, render-ready detail rows (may end in a "+N more" line). */
  body: string[];
  choices: SelectorItem[];
  activeIndex: number;
  hint: string;
  /** The card's tone — WARNING for scope gates, INFO for the co-pilot gate. */
  accent: string;
  contentWidth: number;
  height: number;
  theme: Theme;
}) {
  const { PANEL_ALT, MUTED, TEXT, PRIMARY } = theme;
  // Conservative inner width: rail (1) + paddingX (1 each side) = 3 cells of
  // chrome, rounded up to 4 so every explicit allocation clears the edge.
  const innerWidth = Math.max(1, contentWidth - 4);
  const progressWidth = Math.min(innerWidth, progress.length);
  const titleGap = progressWidth > 0 && innerWidth - progressWidth > 1 ? 1 : 0;
  const titleWidth = Math.max(1, innerWidth - progressWidth - titleGap);
  const labelWidth = Math.max(1, Math.min(Math.max(1, innerWidth - 2), Math.floor(innerWidth * 0.5)));
  const afterLabel = innerWidth - 2 - labelWidth;
  const metaGap = afterLabel > 1 ? 1 : 0;
  const metaWidth = Math.max(0, afterLabel - metaGap);

  return (
    <box flexDirection="row" width={contentWidth} minWidth={0} height={height} flexShrink={0} marginTop={1} backgroundColor={PANEL_ALT}>
      <box width={1} flexShrink={0} alignSelf="stretch" backgroundColor={accent} />
      <box flexDirection="column" flexGrow={1} minWidth={0} paddingX={1}>
        <box flexDirection="row" width={innerWidth} flexShrink={0} minWidth={0}>
          <box width={titleWidth} flexShrink={0} minWidth={0}>
            <text fg={accent}>{fitTuiText(title, titleWidth)}</text>
          </box>
          {progressWidth > 0 ? (
            <box width={progressWidth} flexShrink={0} minWidth={0} marginLeft={titleGap}>
              <text fg={MUTED}>{fitTuiText(progress, progressWidth, { mode: "middle" })}</text>
            </box>
          ) : null}
        </box>
        {subject ? (
          <box width={innerWidth} flexShrink={0} minWidth={0}>
            <text fg={TEXT}>{fitTuiText(subject, innerWidth)}</text>
          </box>
        ) : null}
        {body.length > 0 ? (
          <>
            {body.map((line, index) => (
              <box key={`body-${index}`} width={innerWidth} flexShrink={0} minWidth={0}>
                <text fg={MUTED}>{fitTuiText(line, innerWidth, { mode: "middle" })}</text>
              </box>
            ))}
            <text fg={MUTED}> </text>
          </>
        ) : null}
        <text fg={MUTED}> </text>
        {choices.map((item, offset) => {
          const active = offset === activeIndex;
          return (
            <box key={item.id} flexDirection="row" width={innerWidth} flexShrink={0} minWidth={0}>
              <text width={1} flexShrink={0} fg={active ? PRIMARY : MUTED}>{active ? "›" : " "}</text>
              <box width={labelWidth} flexShrink={0} minWidth={0} marginLeft={1}>
                <text fg={active ? PRIMARY : TEXT}>{fitTuiText(item.label, labelWidth)}</text>
              </box>
              {metaWidth > 0 ? (
                <box width={metaWidth} flexShrink={0} minWidth={0} marginLeft={metaGap}>
                  <text fg={MUTED}>{fitTuiText(item.meta ?? "", metaWidth, { mode: "middle" })}</text>
                </box>
              ) : null}
            </box>
          );
        })}
        <box width={innerWidth} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText(hint, innerWidth)}</text>
        </box>
      </box>
    </box>
  );
}

/** The item id that grants. Everything else declines. */
const APPROVAL_GRANT_ID = "grant";
const APPROVAL_DENY_ID = "deny";

/**
 * Most subagent rows the ACTIVE SUBAGENTS block will paint.
 *
 * `spawn_agents` fans out up to 8 agents with 4 concurrent, so 4 covers the
 * steady-state fan-out and the 5th-and-beyond are reported as a count. The
 * block sits between the transcript and the composer; letting it grow to
 * eight rows would eat the transcript on any normal terminal, and the block
 * is not where an operator reads detail — `/agents` is.
 */
const SUBAGENT_MAX_VISIBLE = 4;

export function ChatScreen({ options, onGoBack, onNavigate, onExit }: ChatScreenProps) {
  const [entries, setEntries] = useState<ChatEntry[]>([]);
  const entriesRef = useRef<ChatEntry[]>([]);
  entriesRef.current = entries;
  const [session, setSession] = useState<ConsoleSession | null>(null);
  const [modelId, setModelId] = useState<string | null>(null);
  const [git, setGit] = useState<GitStatus | null>(null);
  const [clockTick, setClockTick] = useState(() => Date.now());
  const [animTick, setAnimTick] = useState(0);
  /** When the current busy/blocked state began, for elapsed display. */
  const activitySince = useRef<number>(Date.now());
  /**
   * Masked credential entry. Held in component state only, written
   * straight to the 0600 store, and never appended to the transcript —
   * a secret must not end up in scrollback or an evidence record.
   */
  const [secretPrompt, setSecretPrompt] = useState<
    { providerId: string; label: string; envVar: string; value: string } | null
  >(null);
  // Live settings from the process-wide store: every screen subscribes to the
  // same source, so a change made in the settings screen re-renders chat
  // immediately instead of waiting for a remount that (now chat stays mounted
  // for the whole session) never comes.
  const settings = useSettings();
  // Live colour palette, derived from `settings.theme` and delivered
  // subscribably. Read once at the top of the component (hook rules) and
  // threaded into the module-level render helpers that cannot call the hook.
  const theme = useTheme();
  const {
    PRIMARY,
    MUTED,
    TEXT,
    ERROR,
    WARNING,
    SUCCESS,
    INFO,
    ACCENT,
    PANEL,
    PANEL_ALT,
    CANVAS,
    BORDER,
  } = theme;
  // The output-guard subscription is registered once; a ref lets it read
  // the live setting without tearing down and re-adding the listener.
  const settingsRef = useRef(settings);
  settingsRef.current = settings;
  /**
   * Open picker overlay. `commit` runs with the chosen item id; the
   * overlay owns no domain logic so the same component serves /model,
   * /mode and anything added later.
   */
  const [picker, setPicker] = useState<
    { state: SelectorState; commit: (id: string) => void } | null
  >(null);
  const [sessionTokens, setSessionTokens] = useState({ input: 0, output: 0 });
  /** Live turn-budget consumption, updated per model call. */
  const [turnBudget, setTurnBudget] = useState<{ used: number; limit: number } | null>(null);
  const [startupError, setStartupError] = useState<string | null>(null);
  const [mode, setMode] = useState<ConsoleAutonomyMode>(options?.autonomyMode ?? "standard");
  /**
   * The live autonomy mode, for callbacks that must not be rebuilt when it
   * changes. `buildSession` in particular is a `useCallback` that reruns on
   * `/model`; reading the ref is what keeps a model switch from silently
   * reverting the operator's mode.
   */
  const modeRef = useRef<ConsoleAutonomyMode>(options?.autonomyMode ?? "standard");
  modeRef.current = mode;
  const [target, setTarget] = useState(options?.target ?? "");
  const [scopeRules, setScopeRules] = useState<string[]>(options?.scope?.raw.in_scope ?? []);
  const [busy, setBusy] = useState(false);
  /**
   * Messages typed while a turn was in flight, delivered FIFO once it ends.
   * A ref rather than state because the keyboard handler writes it
   * synchronously; `queuedMessages` mirrors it (not just a count) so the sticky
   * queue block near the composer can show WHAT is parked, not only how much.
   */
  const queuedRef = useRef<string[]>([]);
  const [queuedMessages, setQueuedMessages] = useState<string[]>([]);
  const queuedCount = queuedMessages.length;
  const [composer, setComposer] = useState("");
  const [composing, setComposing] = useState(false);
  const [commandMenuOpen, setCommandMenuOpen] = useState(false);
  const [slashSelected, setSlashSelected] = useState(0);
  const [pendingScope, setPendingScope] = useState<PendingScope | null>(null);
  const [pendingLocalScope, setPendingLocalScope] = useState<PendingLocalScope | null>(null);
  const [pendingEscalation, setPendingEscalation] = useState<PendingEscalation | null>(null);
  const [pendingToolApproval, setPendingToolApproval] = useState<PendingToolApproval | null>(null);
  const [activeSubagents, setActiveSubagents] = useState<Record<string, SubagentLifecyclePayload>>({});
  const { width, height } = useTerminalDimensions();
  const alive = useRef(true);
  const turn = useRef(0);
  const statusText = session
    ? `${turn.current} turns · ${session.tools.length} tools`
    : "connecting";
  // All row/column cell budgets live in chat-layout.ts, where the
  // "a row never claims more cells than its container" invariant is
  // covered by tests instead of by inspection.
  const layout = computeChatLayout({ width, height, statusTextLength: statusText.length });
  const {
    compact,
    contentWidth,
    headerTargetWidth,
    headerScopeWidth,
    headerGap,
    composerTextWidth,
    approvalWidth,
    controlsWidth,
    statusWidth,
    statusGap,
  } = layout;
  const composerRef = useRef("");
  const composingRef = useRef(false);
  const commandMenuOpenRef = useRef(false);
  /**
   * Shell-style recall of submitted operator messages. `historyRef` is the
   * ring (oldest first), `historyIndexRef` the cursor (>= length means "editing
   * the live draft, not browsing") and `historyDraftRef` the draft saved on the
   * first Up so Down can restore it. The pure transitions live in
   * composer-history.ts; these refs are written synchronously from the keyboard
   * handler, so they are refs rather than state.
   */
  const historyRef = useRef<string[]>([]);
  const historyIndexRef = useRef(0);
  const historyDraftRef = useRef("");
  /**
   * The transcript scrollbox, so PageUp/PageDown can drive it directly. The box
   * is deliberately NOT focusable (see the `focusable={false}` prop): plain
   * Up/Down belong to composer history, never to scrolling.
   */
  const transcriptRef = useRef<ScrollBoxRenderable | null>(null);
  const commandCatalog: readonly SlashCommand[] = SLASH_COMMANDS;
  const isSlashComposer = composer.trimStart().startsWith("/");
  const slashQuery = isSlashComposer ? composer.trimStart().slice(1).split(/\s+/, 1)[0] ?? "" : "";
  // A wide menu prints a description under each command; a compact one
  // does not. The row cost per entry therefore differs, and the visible
  // count has to be derived from the real height instead of a constant —
  // over-allocating is what painted the menu's bottom border through the
  // last two command rows.
  const commandRowsPerCommand = compact ? 1 : 2;
  const commandMenuLimit = computeCommandMenuHeight({
    height,
    compact,
    rowsPerCommand: commandRowsPerCommand,
  }).maxCommands;
  const filteredSlashCommands = useMemo(
    () => isSlashComposer ? filterCommands(slashQuery) : [],
    [isSlashComposer, slashQuery],
  );
  const menuCommands = filteredSlashCommands.slice(0, commandMenuLimit);
  const selectedSlashCommand = menuCommands[slashSelected];
  const scopeLabel = scopeRules.length > 0
    ? scopeRules.join(", ")
    : mode === "yolo" ? "not configured" : "scope on demand";

  useEffect(() => {
    setSlashSelected((current) => Math.min(current, Math.max(menuCommands.length - 1, 0)));
  }, [menuCommands.length]);

  const setCommandMenuVisible = useCallback((visible: boolean) => {
    commandMenuOpenRef.current = visible;
    setCommandMenuOpen(visible);
  }, []);

  const setComposerText = useCallback((value: string) => {
    composerRef.current = value;
    setComposer(value);
    setSlashSelected(0);
    setCommandMenuVisible(value.trimStart().startsWith("/"));
    // Any composer edit leaves history browsing and re-bases the cursor on the
    // live draft. A recall re-sets the cursor immediately after calling this.
    historyIndexRef.current = historyRef.current.length;
  }, [setCommandMenuVisible]);

  /**
   * Recall a previously submitted message into the composer. Up walks toward
   * older entries (saving the live draft on the first step), Down walks back
   * toward that draft. A no-op step leaves everything untouched; a real step
   * enters composing so the recalled text is editable.
   */
  const recallComposerHistory = useCallback((direction: "up" | "down") => {
    const entries = historyRef.current;
    const result = direction === "up"
      ? recallPrev(entries, historyIndexRef.current, historyDraftRef.current, composerRef.current)
      : recallNext(entries, historyIndexRef.current, historyDraftRef.current);
    if (!result.changed) return;
    if (!composingRef.current) {
      composingRef.current = true;
      setComposing(true);
    }
    setComposerText(result.value);
    // setComposerText re-based the cursor on the draft; restore the recall
    // position and remembered draft so the next step continues the walk.
    historyIndexRef.current = result.index;
    historyDraftRef.current = result.draft;
  }, [setComposerText]);

  const appendEntry = useCallback((entry: Omit<ChatEntry, "id">) => {
    setEntries((current) => appendTranscriptEntry<ChatEntry>(current, {
      at: Date.now(),
      ...entry,
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    }));
  }, []);

  /**
   * Build a console session.
   *
   * Extracted from the mount effect because `/model` rebuilds the session
   * against a different runtime: the model is fixed when the runtime is
   * constructed, so switching means a new runtime, and the engagement
   * context has to be carried across via `initialMessages` rather than
   * silently discarded mid-engagement.
   */
  const buildSession = useCallback((
    opts: { model?: string; initialMessages?: NativeMessage[] } = {},
  ): { session: ConsoleSession; model: string } => {
    // Apply stored provider credentials before the runtime resolves any.
    // credentialEnvPatch never overrides a variable the shell already set,
    // so an explicit export always beats the file.
    const patch = credentialEnvPatch(loadCredentials(), process.env);
    for (const [key, value] of Object.entries(patch)) process.env[key] = value;
    const runtime = createConsoleRuntime({ model: opts.model ?? options?.model });
    const created = createConsoleSession({
      runtime,
      target: options?.target,
      scope: options?.scope,
      role: options?.role,
      maxToolIterations: options?.maxToolIterations,
      allowScanners: options?.allowScanners,
      // The LAUNCH mode is only the seed. Rebuilds trigger on /model and on
      // resume, and reseeding from options there would drop the operator back
      // to standard while the header kept showing the mode they chose.
      autonomyMode: modeRef.current,
      initialMessages: opts.initialMessages,
      // The parent messaging runtime. WITHOUT this, no subagent gets the
      // send_message/check_messages tools and the model correctly reports it
      // cannot coordinate — which is exactly what an operator was seeing.
      //
      // The console IS the operator's session, so the parent and the operator
      // are the same peer: operatorId is left undefined (child->operator would
      // just be child->parent, which is always on). Children address "Main"
      // and each other; sibling messaging flows child->child directly through
      // the mailbox spool, so it needs no console-side draining to work.
      agentMessaging: {
        selfId: "Main",
        selfRole: "parent" as const,
        siblingChannelEnabled: settingsRef.current.allowSubagentPeerMessaging,
        operatorChannelEnabled: settingsRef.current.allowSubagentOperatorMessaging,
        projectPath: process.cwd(),
      },
      requestScope: (request) => {
        const deferred = Promise.withResolvers<ConsoleScopeResolution | null>();
        if (!alive.current) {
          deferred.resolve(null);
          return deferred.promise;
        }
        setPendingScope({ request, resolve: deferred.resolve });
        return deferred.promise;
      },
      requestLocalScope: (request) => {
        const deferred = Promise.withResolvers<ConsoleLocalScopeResolution | null>();
        if (!alive.current) {
          deferred.resolve(null);
          return deferred.promise;
        }
        setPendingLocalScope({ request, resolve: deferred.resolve });
        return deferred.promise;
      },
      escalateScopedAudit: (request) => {
        const deferred = Promise.withResolvers<boolean>();
        if (!alive.current) {
          deferred.resolve(false);
          return deferred.promise;
        }
        setPendingEscalation({ request, resolve: deferred.resolve });
        return deferred.promise;
      },
      approveTool: (call) => {
        const deferred = Promise.withResolvers<boolean>();
        if (!alive.current) {
          deferred.resolve(false);
          return deferred.promise;
        }
        setPendingToolApproval({ call, resolve: deferred.resolve });
        return deferred.promise;
      },
    });
    // resolvedModel() is the id the runtime actually settled on after
    // provider detection — not necessarily what was requested — so it is
    // the only value honest enough to display.
    return { session: created, model: runtime.resolvedModel() };
  }, [options]);

  useEffect(() => {
    let created: ConsoleSession | null = null;
    alive.current = true;

    try {
      const built = buildSession();
      created = built.session;
      setModelId(built.model);
      setSession(created);
    } catch (error) {
      setStartupError(error instanceof Error ? error.message : String(error));
    }

    return () => {
      alive.current = false;
      setPendingScope((pending) => {
        pending?.resolve(null);
        return null;
      });
      setPendingLocalScope((pending) => {
        pending?.resolve(null);
        return null;
      });
      setPendingEscalation((pending) => {
        pending?.resolve(false);
        return null;
      });
      setPendingToolApproval((pending) => {
        pending?.resolve(false);
        return null;
      });
      setActiveSubagents({});
      void created?.cleanup();
    };
  }, []);

  /**
   * Claim the structured diagnostics channel while the console is mounted.
   *
   * The channel writes to stderr by default, which is right for a CLI run
   * but would paint straight over this renderer. Claiming redirects those
   * messages into the transcript, and `replay: true` picks up anything
   * emitted during startup before this effect ran.
   *
   * The stream-level output guard stays installed regardless: only part of
   * core has been migrated to the channel, so un-migrated call sites can
   * still write directly (see diagnostics/MIGRATION.md).
   */
  useEffect(() => {
    return claimDiagnostics(
      {
        emit: (event) => {
          if (!alive.current) return;
          if (!settingsRef.current.showRuntimeNotices) return;
          appendEntry({
            kind: event.level === "error" ? "error" : "notice",
            text: `runtime: ${event.message}`,
            detail: event.fields && Object.keys(event.fields).length > 0
              ? Object.entries(event.fields).map(([k, v]) => `${k}=${String(v)}`).join(" ")
              : undefined,
            turn: turn.current,
          });
        },
      },
      { replay: true },
    );
  }, [appendEntry]);

  // Surface anything the runtime wrote to stdout/stderr while the TUI owns
  // the screen. The output guard has already intercepted it (so it cannot
  // corrupt the framebuffer); showing it here keeps operationally important
  // notices — plan quota exhausted, retry budget spent, scanner warnings —
  // visible instead of silently swallowed.
  useEffect(() => {
    return onTuiOutputLine((line) => {
      if (!alive.current) return;
      if (!settingsRef.current.showRuntimeNotices) return;
      appendEntry({
        kind: "notice",
        text: line.stream === "stderr" ? `runtime: ${line.text}` : line.text,
        turn: turn.current,
      });
    });
  }, [appendEntry]);

  // Tell herdr when 0sec is parked on a human decision, so the pane joins
  // its attention queue instead of looking busy. No-op outside herdr.
  useEffect(() => {
    reportOperatorGate(Boolean(pendingScope || pendingLocalScope || pendingEscalation || pendingToolApproval || secretPrompt));
  }, [pendingScope, pendingLocalScope, pendingEscalation, pendingToolApproval, secretPrompt]);

  useEffect(() => {
    if (!settings.showTimestamps) return;
    const timer = setInterval(() => setClockTick(Date.now()), 15_000);
    return () => clearInterval(timer);
  }, [settings.showTimestamps]);

  // Refresh the git context behind the status bar. readGitStatus never
  // throws and is time-boxed, so a huge or broken repo degrades to
  // "not a repo" instead of stalling a frame.
  useEffect(() => {
    let cancelled = false;
    const refresh = () => {
      void readGitStatus(process.cwd()).then((next) => {
        if (!cancelled) setGit(next);
      });
    };
    refresh();
    const timer = setInterval(refresh, 5_000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  // Subscribe to subagent lifecycle events from the core event bus.
  // Filter by this session's scanId; remove active entries on terminal state.
  useEffect(() => {
    if (!session) return;
    const scanId = session.scanId;
    const unsub = eventBus.subscribe({
      emit: (type, payload) => {
        if (type !== "subagent_lifecycle") return;
        const event = payload as unknown as SubagentLifecyclePayload;
        if (event.parent_scan_id !== scanId) return;
        setActiveSubagents((prev) => reduceActiveSubagents(prev, event));
      },
    });
    return unsub;
  }, [session]);

  const resolveScope = useCallback((approved: boolean) => {
    const pending = pendingScope;
    if (!pending) return;
    setPendingScope(null);
    if (!approved) {
      pending.resolve(null);
      appendEntry({ kind: "notice", text: "scope extension rejected; the requested tool did not run", turn: turn.current });
      return;
    }

    const resolution = buildScopeResolution(pending.request);
    if (!resolution) {
      pending.resolve(null);
      appendEntry({ kind: "notice", text: "scope extension could not be safely constructed", turn: turn.current });
      return;
    }

    pending.resolve(resolution);
    setTarget(resolution.target);
    setScopeRules(resolution.scope.raw.in_scope ?? []);
    appendEntry({ kind: "notice", text: `session scope approved: ${(resolution.scope.raw.in_scope ?? []).join(", ")}`, turn: turn.current });
  }, [appendEntry, pendingScope]);

  const resolveLocalScope = useCallback((approved: boolean) => {
    const pending = pendingLocalScope;
    if (!pending) return;
    setPendingLocalScope(null);
    if (!approved) {
      pending.resolve(null);
      appendEntry({
        kind: "notice",
        text: "local directory access declined; the tool did not run",
        turn: turn.current,
      });
      return;
    }
    // Authorize the directory the operator was actually shown. The engine
    // re-canonicalizes and re-checks it, so a symlink swapped between the
    // prompt and the apply cannot widen what was approved.
    pending.resolve({ scopePath: pending.request.requestedPath });
    appendEntry({
      kind: "notice",
      text: `local scope approved: ${pending.request.requestedPath}`,
      detail: "This directory subtree only, for this session. Nothing is written to disk.",
      turn: turn.current,
    });
  }, [appendEntry, pendingLocalScope]);

  const resolveEscalation = useCallback((approved: boolean) => {
    const pending = pendingEscalation;
    if (!pending) return;
    setPendingEscalation(null);
    pending.resolve(approved);
    appendEntry({
      kind: "notice",
      text: approved
        ? `${pending.request.call.name} enabled for this session`
        : `${pending.request.call.name} left disabled`,
      detail: approved
        ? "Scope and approval rules still apply to it — this only lifts the source-audit tool restriction."
        : undefined,
      turn: turn.current,
    });
  }, [appendEntry, pendingEscalation]);

  const resolveToolApproval = useCallback((approved: boolean) => {
    const pending = pendingToolApproval;
    if (!pending) return;
    setPendingToolApproval(null);
    pending.resolve(approved);
    appendEntry({
      kind: "notice",
      text: approved ? `${pending.call.name} approved` : `${pending.call.name} rejected`,
      turn: turn.current,
    });
  }, [appendEntry, pendingToolApproval]);

  /**
   * Records whose decision has already been dispatched.
   *
   * `resolve*` above reads `pending*` from the render it was built in, so two
   * key events delivered in the same tick — before React has re-rendered with
   * the cleared state — would both see a non-null pending record and run the
   * grant twice: two transcript notices, and a scope resolution applied
   * twice. The promise itself is idempotent, but the side effects are not.
   * Keying on the pending record's identity makes "exactly once" a property
   * of the dispatcher rather than of event timing. A WeakSet so a resolved
   * record is collectable.
   */
  const dispatched = useRef<WeakSet<object>>(new WeakSet());
  const dispatchOnce = useCallback((owner: object, run: () => void) => {
    if (dispatched.current.has(owner)) return;
    dispatched.current.add(owner);
    run();
  }, []);

  /**
   * The single authorization prompt currently in front of the operator.
   *
   * Only the topmost is shown. Four independently-rendered panels could
   * previously stack in the same column at once; each one that appears is a
   * decision the operator has to take in order anyway, and a stack of them
   * is precisely what over-subscribes the column.
   *
   * Precedence matches the order the old keyboard handler used, so which
   * prompt answers a keystroke has not changed.
   */
  const approvalPrompt = useMemo<ApprovalPrompt | null>(() => {
    if (pendingScope) {
      const owner = pendingScope;
      return {
        owner,
        title: "Authorize session scope",
        context: `${owner.request.call.name} requests ${owner.request.requestedUrls.join(", ")}`,
        subject: owner.request.call.name,
        bodyLines: owner.request.requestedUrls.map((url) => `requests: ${url}`),
        borderColor: WARNING,
        titleColor: WARNING,
        items: [
          {
            id: APPROVAL_GRANT_ID,
            label: "Approve for this session",
            meta: "adds the exact hosts",
            detail: "Exact hosts apply only to this session. Existing deny rules still win.",
          },
          {
            id: APPROVAL_DENY_ID,
            label: "Reject",
            meta: "tool does not run",
            detail: "Scope is unchanged and the requested tool call is refused.",
          },
        ],
        decide: (id) => dispatchOnce(owner, () => resolveScope(id === APPROVAL_GRANT_ID)),
        decline: () => dispatchOnce(owner, () => resolveScope(false)),
      };
    }
    if (pendingLocalScope) {
      const owner = pendingLocalScope;
      return {
        owner,
        title: "Authorize local directory",
        context: `${owner.request.call.name} wants to read ${owner.request.requestedPath}`,
        subject: owner.request.call.name,
        bodyLines: [`wants to read: ${owner.request.requestedPath}`],
        borderColor: WARNING,
        titleColor: WARNING,
        items: [
          {
            id: APPROVAL_GRANT_ID,
            label: "Approve this directory",
            meta: "this subtree, this session",
            detail: "Grants this directory subtree for this session only. Nothing is written to disk.",
          },
          {
            id: APPROVAL_DENY_ID,
            label: "Decline",
            meta: "tool does not run",
            detail: "No filesystem access is granted and the tool call is refused.",
          },
        ],
        decide: (id) => dispatchOnce(owner, () => resolveLocalScope(id === APPROVAL_GRANT_ID)),
        decline: () => dispatchOnce(owner, () => resolveLocalScope(false)),
      };
    }
    if (pendingEscalation) {
      const owner = pendingEscalation;
      return {
        owner,
        title: "Enable additional tool",
        context: `${owner.request.call.name} — ${owner.request.reason}`,
        subject: owner.request.call.name,
        bodyLines: [owner.request.reason],
        borderColor: WARNING,
        titleColor: WARNING,
        items: [
          {
            id: APPROVAL_GRANT_ID,
            label: "Enable for this session",
            meta: "lifts the audit restriction",
            detail: "Scope approval and the Co-pilot gate still apply to it.",
          },
          {
            id: APPROVAL_DENY_ID,
            label: "Keep disabled",
            meta: "tool stays blocked",
            detail: "The source-audit tool restriction stays in force for this session.",
          },
        ],
        decide: (id) => dispatchOnce(owner, () => resolveEscalation(id === APPROVAL_GRANT_ID)),
        decline: () => dispatchOnce(owner, () => resolveEscalation(false)),
      };
    }
    if (pendingToolApproval) {
      const owner = pendingToolApproval;
      return {
        owner,
        title: `${modeLabel(modeRef.current)} approval`,
        context: `${owner.call.name} ${JSON.stringify(owner.call.arguments)}`,
        subject: owner.call.name,
        bodyLines: argumentSummaryLines(owner.call.arguments),
        borderColor: INFO,
        titleColor: INFO,
        items: [
          {
            id: APPROVAL_GRANT_ID,
            label: "Approve this call",
            meta: "runs once",
            detail: "Approves only this call. The next one asks again.",
          },
          {
            id: APPROVAL_DENY_ID,
            label: "Reject",
            meta: "call does not run",
            detail: "The model is told the operator refused, and continues without it.",
          },
        ],
        decide: (id) => dispatchOnce(owner, () => resolveToolApproval(id === APPROVAL_GRANT_ID)),
        decline: () => dispatchOnce(owner, () => resolveToolApproval(false)),
      };
    }
    return null;
  }, [
    dispatchOnce,
    pendingEscalation,
    pendingLocalScope,
    pendingScope,
    pendingToolApproval,
    resolveEscalation,
    resolveLocalScope,
    resolveScope,
    resolveToolApproval,
  ]);

  /**
   * Selector position for the open approval, keyed by the pending record it
   * belongs to. Derived rather than pushed through an effect: an effect would
   * leave one frame in which the prompt is up and its selector is not, and
   * that frame is a keystroke the operator could lose.
   */
  const [approvalCursor, setApprovalCursor] = useState<{ owner: object; state: SelectorState } | null>(null);
  const approvalState: SelectorState | null = approvalPrompt
    ? (approvalCursor && approvalCursor.owner === approvalPrompt.owner
        ? approvalCursor.state
        // The grant is highlighted first, exactly as Enter used to approve
        // directly — the semantics of the default answer are unchanged.
        : createSelectorState(approvalPrompt.title, approvalPrompt.items, APPROVAL_GRANT_ID))
    : null;
  const stepApproval = useCallback((action: "up" | "down") => {
    setApprovalCursor((current) => {
      if (!approvalPrompt) return current;
      // Prefer the queued state over the rendered one, so two arrow presses
      // delivered in the same tick step twice instead of collapsing to one.
      const base = current && current.owner === approvalPrompt.owner ? current.state : approvalState;
      if (!base) return current;
      return { owner: approvalPrompt.owner, state: reduceSelector(base, { type: action }) };
    });
  }, [approvalPrompt, approvalState]);

  /**
   * `send` is declared after the command router, but /explain needs to
   * submit a real turn. A ref breaks the cycle without reordering two
   * large callbacks or making either depend on the other's identity.
   */
  const submitRef = useRef<((text: string) => Promise<void>) | null>(null);
  /** True once the model has produced visible tokens in this turn. */
  const streamingRef = useRef(false);
  /** Name of the tool currently executing, for the tool animation. */
  const [runningTool, setRunningTool] = useState<string | null>(null);
  /**
   * Interrupt handle for the turn in flight, or null when none is running.
   * Held in a ref because the keyboard handler must reach the CURRENT turn's
   * controller, not the one captured when the handler was built.
   */
  const abortRef = useRef<AbortController | null>(null);

  /**
   * Operator interrupt (Esc while a turn is running).
   *
   * The engine honours the signal at checkpoints — before the next model
   * call and before dispatching each tool — so a tool or a request already
   * in flight still runs to completion. The notice says exactly that rather
   * than claiming the turn stopped dead; the definitive entry, with the
   * tokens actually spent, is written when the turn returns with
   * `stopReason: "cancelled"`.
   */
  const interruptTurn = useCallback(() => {
    const controller = abortRef.current;
    if (!controller || controller.signal.aborted) return false;
    controller.abort();
    appendEntry({
      kind: "notice",
      text: "interrupting the current turn…",
      detail: "Stops before the next tool call or model request. Anything already in flight finishes first.",
      turn: turn.current,
    });
    return true;
  }, [appendEntry]);

  const routeSlashCommand = useCallback((raw: string): boolean => {
    const parsed = findCommand(raw);
    if (!parsed.isSlash) return false;

    if (!parsed.isKnown || !parsed.command) {
      appendEntry({
        kind: "notice",
        text: parsed.rawName ? `unknown command: /${parsed.rawName}` : "choose a slash command",
        detail: "Type /help to browse local commands.",
        turn: turn.current,
      });
      return true;
    }

    const args = parsed.args.trim();
    switch (parsed.command) {
      case "help": {
        const query = args.startsWith("/") ? args.slice(1) : args;
        const commands = query ? filterCommands(query) : commandCatalog;
        appendEntry({
          kind: "panel",
          text: "help",
          panel: buildHelpPanel(commands, query || undefined),
          turn: turn.current,
        });
        return true;
      }
      case "status":
        appendEntry({
          kind: "panel",
          text: "status",
          panel: buildStatusPanel({
            model: modelId ?? undefined,
            provider: modelId ? modelProvider(modelId) : undefined,
            mode: modeLabel(mode),
            target: target || undefined,
            scopeRules,
            toolCount: session?.tools.length ?? 0,
            turns: turn.current,
            inputTokens: sessionTokens.input,
            outputTokens: sessionTokens.output,
          }),
          turn: turn.current,
        });
        return true;
      case "scope":
        appendEntry({
          kind: "panel",
          text: "scope",
          panel: buildScopePanel({
            target: target || undefined,
            scopeRules,
            mode: modeLabel(mode),
          }),
          turn: turn.current,
        });
        return true;
      // `/clear` (and its `/new` alias) was in the registry and in the
      // palette but had no handler, so it fell through to `default:` and
      // answered "unknown command: /clear".
      case "clear": {
        if (busy) {
          appendEntry({
            kind: "notice",
            text: "wait for the active turn before clearing",
            detail: "The turn in flight is still appending to the conversation this would empty.",
            turn: turn.current,
          });
          return true;
        }
        // Conversation only. Scope, target, autonomy mode, granted
        // escalations and the denied-host / denied-path memory all live on
        // the session and are deliberately LEFT ALONE: they are
        // authorization state, and dropping a *denial* because the operator
        // tidied their screen would silently re-open something they already
        // refused. `clearConversation()` empties the message array and
        // nothing else — see ConsoleSession in turn-engine.ts.
        session?.clearConversation();
        setEntries([]);
        entriesRef.current = [];
        turn.current = 0;
        setTurnBudget(null);
        appendEntry({
          kind: "notice",
          text: "conversation cleared",
          detail: session
            ? "The model starts from an empty history. Scope, target and mode are unchanged, and nothing you previously denied has been re-allowed."
            : "The transcript is empty. The runtime is not connected, so there was no model history to clear.",
          turn: turn.current,
        });
        return true;
      }
      case "resume": {
        // Every project, not just this directory: an operator moving between
        // checkouts still wants the session they were in.
        const here = process.cwd();
        const saved = listSessions(undefined, { limit: 50 });
        saved.sort((a, b) => Number(b.cwd === here) - Number(a.cwd === here));
        if (saved.length === 0) {
          appendEntry({
            kind: "notice",
            text: "no saved sessions yet",
            detail: "A session is stored after each turn; this list appears once you have run one.",
            turn: turn.current,
          });
          return true;
        }
        if (busy) {
          appendEntry({ kind: "notice", text: "wait for the active turn before resuming", turn: turn.current });
          return true;
        }
        const items: SelectorItem[] = saved.map((meta) => ({
          id: meta.id,
          label: meta.preview || "(no prompt recorded)",
          meta: `${meta.messageCount} msg${meta.messageCount === 1 ? "" : "s"}${meta.model ? ` · ${meta.model}` : ""}`,
          detail: `${meta.cwd === here ? "this project" : meta.cwd} · ${meta.target ? `target ${meta.target} · ` : ""}saved ${new Date(meta.savedAt).toISOString()}`,
          current: session?.scanId === meta.id,
        }));
        setPicker({
          state: createSelectorState("Resume a session", items),
          commit: (id) => {
            const stored = loadSession(id);
            if (!stored) {
              appendEntry({
                kind: "error",
                text: "could not read that session",
                detail: "The file is missing or unreadable; nothing was changed.",
                turn: turn.current,
              });
              return;
            }
            const previous = session;
            let built: { session: ConsoleSession; model: string };
            try {
              // Rebuild around the stored transcript. A failed rebuild must
              // leave the operator exactly where they were.
              built = buildSession({
                initialMessages: stored.messages as never,
                model: stored.model,
              });
            } catch (error) {
              appendEntry({
                kind: "error",
                text: "could not resume that session",
                detail: error instanceof Error ? error.message : String(error),
                turn: turn.current,
              });
              return;
            }
            setSession(built.session);
            setModelId(built.model);
            if (previous) void previous.cleanup();
            turn.current = 0;
            // Rehydrate the transcript silently: the restored messages ARE the
            // context, and a banner announcing "this is replayed history" was
            // just noise stacked on top of the conversation it described.
            setEntries(entriesFromStoredMessages(stored.messages));
          },
        });
        return true;
      }
      case "providers": {
        const states = providerStates(process.env);
        const items: SelectorItem[] = states.map((provider) => ({
          id: provider.id,
          label: provider.label,
          meta: provider.configured
            ? `configured${provider.via ? ` via ${provider.via}` : ""}`
            : "not configured",
          detail: provider.configured
            ? `Credentials found. Select to replace the stored key.`
            : provider.hint,
          current: provider.configured,
        }));
        setPicker({
          state: createSelectorState("Providers · select one to set a key", items),
          commit: (providerId) => {
            const info = PROVIDERS.find((provider) => provider.id === providerId);
            if (!info) return;
            setSecretPrompt({
              providerId,
              label: info.label,
              envVar: info.envVars[0] ?? "",
              value: "",
            });
          },
        });
        return true;
      }
      case "feedback": {
        const message = args.trim();
        if (!message) {
          appendEntry({
            kind: "notice",
            text: "usage: /feedback <message>",
            detail: "Feedback is written to a local file. Nothing is transmitted.",
            turn: turn.current,
          });
          return true;
        }
        const written = appendFeedback({
          message,
          timestamp: new Date().toISOString(),
          version: VERSION,
          model: modelId ?? undefined,
          mode: modeLabel(mode),
        });
        appendEntry({
          kind: written.ok ? "notice" : "error",
          text: written.ok ? "feedback recorded locally" : "could not write feedback",
          detail: written.ok
            ? `Saved to ${written.path}. Nothing was transmitted — share it if and when you choose.`
            : written.error,
          turn: turn.current,
        });
        return true;
      }
      case "explain": {
        if (!session) {
          appendEntry({ kind: "notice", text: "runtime is not ready", turn: turn.current });
          return true;
        }
        if (busy) {
          appendEntry({ kind: "notice", text: "wait for the active turn before asking for an explanation", turn: turn.current });
          return true;
        }
        const topic = args.trim();
        if (entries.length === 0 && !topic) {
          appendEntry({
            kind: "notice",
            text: "nothing to explain yet",
            detail: "Run something first, or use /explain <topic>.",
            turn: turn.current,
          });
          return true;
        }
        // Sent as a normal turn so the explanation is a real model answer
        // grounded in this conversation, not a canned local string.
        const prompt = topic
          ? `Explain "${topic}" in plain language for a non-technical reader. Avoid jargon; when a security term is unavoidable, define it in one short clause. Be concrete about impact and what someone should actually do.`
          : `Explain your previous result in plain language for a non-technical reader. Avoid jargon; when a security term is unavoidable, define it in one short clause. Cover what was found, why it matters, and what to do next. Do not overstate certainty — say plainly if something is unconfirmed.`;
        void submitRef.current?.(prompt);
        return true;
      }
      case "settings":
        // The full screen, not the composer picker: settings want grouping,
        // real descriptions and reset affordances, none of which fit in a
        // list squeezed above the composer.
        onNavigate("settings");
        return true;
      case "model": {
        const requested = args.trim();
        if (!requested) {
          // The full screen, not the composer picker: the model list wants
          // provider grouping, per-provider credential state and setup hints,
          // none of which fit above the composer. `/model <id>` below still
          // switches in place without leaving chat.
          onNavigate("models");
          return true;
        }
        if (busy) {
          appendEntry({
            kind: "notice",
            text: "wait for the active turn before switching model",
            turn: turn.current,
          });
          return true;
        }
        if (!session) {
          appendEntry({
            kind: "notice",
            text: "runtime is not ready; model is unchanged",
            turn: turn.current,
          });
          return true;
        }
        if (requested === modelId) {
          appendEntry({ kind: "notice", text: `Model is already ${requested}`, turn: turn.current });
          return true;
        }
        // The model is fixed when the runtime is constructed, so switching
        // means building a new session. Carry the conversation across so an
        // engagement does not lose its context, and keep the old session
        // alive until the new one is built — a failed switch must leave the
        // operator exactly where they were.
        const previous = session;
        let built: { session: ConsoleSession; model: string };
        try {
          built = buildSession({ model: requested, initialMessages: previous.messages });
        } catch (error) {
          appendEntry({
            kind: "notice",
            text: `could not switch to ${requested}; model is unchanged`,
            detail: error instanceof Error ? error.message : String(error),
            turn: turn.current,
          });
          return true;
        }
        setSession(built.session);
        setModelId(built.model);
        void previous.cleanup();
        appendEntry({
          kind: "notice",
          text: `Model: ${built.model} (${modelProvider(built.model)})`,
          detail: `${previous.messages.length} prior message(s) carried over.`,
          turn: turn.current,
        });
        return true;
      }
      case "mode": {
        const modeArg = args.toLowerCase();
        if (!modeArg) {
          const modeItems: SelectorItem[] = [
            {
              id: "standard",
              label: "Standard",
              meta: "approve each action",
              detail: "You approve each action before it runs; asks to extend scope.",
              current: mode === "standard",
            },
            {
              id: "recon",
              label: "Recon",
              meta: "passive, read-only",
              detail: "Passive, in-scope reconnaissance only; effectful tools are refused.",
              current: mode === "recon",
            },
            {
              id: "copilot",
              label: "Co-pilot",
              meta: "autonomous in scope",
              detail: "Full autonomy inside the engagement; scope expands to discovered targets.",
              current: mode === "copilot",
            },
            {
              id: "yolo",
              label: "YOLO",
              meta: scopeRules.length === 0 ? "needs a scope" : "no prompts in scope",
              detail: "No prompts, but only inside an already-configured scope.",
              current: mode === "yolo",
              // Selecting YOLO without a scope cannot be honoured, so it is
              // shown greyed rather than silently failing on commit.
              disabled: scopeRules.length === 0,
            },
          ];
          setPicker({
            state: createSelectorState("Engagement mode", modeItems, mode),
            commit: (id) => void routeSlashCommand(`/mode ${id}`),
          });
          return true;
        }
        if (modeArg !== "standard" && modeArg !== "recon" && modeArg !== "copilot" && modeArg !== "yolo") {
          appendEntry({
            kind: "notice",
            text: "invalid mode",
            detail: "Use /mode standard, /mode recon, /mode copilot, or /mode yolo.",
            turn: turn.current,
          });
          return true;
        }
        // NO busy guard. `autonomyMode` is a scalar on the shared tool
        // context, re-read fresh at every gate — maybeResolveScope,
        // maybeApproveTool and the scoped-audit gate in agent/tools.ts all
        // look it up at dispatch time — so there is no torn state to protect
        // and a change simply applies from the next tool call. It is also
        // operator-initiated authority, and tightening mid-turn (standard →
        // copilot) is exactly when an operator wants it.
        //
        // This licence is for the MODE SCALAR ONLY. Anything that mutates
        // the tool set or the gate maps must still refuse mid-turn: a tool
        // could otherwise be gated under one policy at scope resolution and
        // a different one at approval.
        if (!session) {
          appendEntry({
            kind: "notice",
            text: "runtime is not ready; mode is unchanged",
            turn: turn.current,
          });
          return true;
        }
        const next: ConsoleAutonomyMode = modeArg === "standard"
          ? "standard"
          : modeArg === "recon"
            ? "recon"
            : modeArg === "copilot"
              ? "copilot"
              : "yolo";
        session.setAutonomyMode(next);
        setMode(next);
        const modeMeaning = next === "standard"
          ? "0sec asks you to approve each action before it runs."
          : next === "recon"
            ? "0sec runs passive, in-scope reconnaissance only — read-only and passive-recon tools; effectful and exploitation tools are refused, and scope is never auto-expanded."
            : next === "copilot"
              ? "0sec runs autonomously inside scope and expands scope to in-engagement hosts without asking."
              : "0sec runs with no prompts on your target and everything reachable from it — still bounded to that target.";
        appendEntry({
          kind: "notice",
          text: `Mode: ${modeLabel(next)}`,
          // Changed mid-turn, the new mode governs the NEXT tool call. It
          // does not reach back into work already dispatched, and saying so
          // is the difference between an honest notice and a claim that it
          // stopped something.
          detail: busy
            ? `Applies from the next tool call in the turn already running; work already dispatched is unaffected. ${modeMeaning}`
            : modeMeaning,
          turn: turn.current,
        });
        return true;
      }
      case "tools": {
        const toolNames = session?.tools.map((tool) => tool.name) ?? [];
        appendEntry({
          kind: "panel",
          text: "tools",
          panel: buildToolsPanel(toolNames),
          turn: turn.current,
        });
        return true;
      }
      case "agents": {
        const agents = Object.values(activeSubagents);
        appendEntry({
          kind: "notice",
          text: agents.length > 0 ? `${agents.length} active subagent${agents.length === 1 ? "" : "s"}` : "No active subagents",
          detail: agents.length > 0
            ? agents.map((agent) => agent.task).join(" · ")
            : "Subagents appear here when 0sec delegates work.",
          turn: turn.current,
        });
        return true;
      }
      case "chat":
        appendEntry({
          kind: "notice",
          text: "Chat is already active",
          detail: "Type a request to continue the current conversation.",
          turn: turn.current,
        });
        return true;
      case "launcher":
        onNavigate("launcher");
        return true;
      case "ops":
        onNavigate("ops");
        return true;
      case "market":
        // run.tsx already routes the "market" destination to the marketplace
        // screen; chat just needs the nav entry (mirrors "/ops"/"/settings").
        onNavigate("market");
        return true;
      case "history":
        onNavigate("history");
        return true;
      case "findings":
        onNavigate("findings");
        return true;
      case "doctor":
        onNavigate("doctor");
        return true;
      case "replay":
        onNavigate("replay");
        return true;
      case "back":
        onGoBack();
        return true;
      case "exit":
        onExit();
        return true;
      default:
        appendEntry({
          kind: "notice",
          text: `unknown command: /${parsed.rawName}`,
          turn: turn.current,
        });
        return true;
    }
  }, [
    activeSubagents,
    appendEntry,
    busy,
    commandCatalog,
    mode,
    onExit,
    onGoBack,
    onNavigate,
    scopeLabel,
    scopeRules,
    session,
    target,
  ]);

  const send = useCallback(async (raw: string) => {
    const text = raw.trim();
    if (!text) return;
    if (routeSlashCommand(text)) return;
    if (busy || !session) return;

    const currentTurn = ++turn.current;
    const turnStartedAt = Date.now();
    setBusy(true);
    appendEntry({ kind: "user", text, turn: currentTurn });
    let assistantText = "";
    // Reasoning is a separate stream from the answer and gets its own
    // accumulator so the two never interleave into one entry.
    let reasoningText = "";
    // The turn's usage, captured from the outcome so `finally` can stamp it onto
    // the answer alongside the elapsed. Null until the turn returns, so a turn
    // that throws before reporting usage simply stamps nothing.
    let turnUsage: { inputTokens: number; outputTokens: number } | null = null;
    streamingRef.current = false;
    // One controller per turn, published so Esc can reach it. It is cleared
    // in `finally`, so an Esc after the turn ended aborts nothing.
    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const outcome = await session.send(text, {
        onAssistantDelta: (chunk) => {
          assistantText += chunk;
          streamingRef.current = true;
          setEntries((current) => {
            const last = current.at(-1);
            if (last?.kind === "assistant" && last.turn === currentTurn) {
              return [...current.slice(0, -1), { ...last, text: assistantText }];
            }
            return [...current, {
              id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
              kind: "assistant",
              text: assistantText,
              turn: currentTurn,
            }];
          });
        },
        onReasoningDelta: (chunk) => {
          reasoningText += chunk;
          setEntries((current) => {
            const last = current.at(-1);
            if (last?.kind === "reasoning" && last.turn === currentTurn) {
              return [...current.slice(0, -1), { ...last, text: reasoningText }];
            }
            return [...current, {
              id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
              kind: "reasoning",
              text: reasoningText,
              turn: currentTurn,
            }];
          });
        },
        onToolStart: (call) => {
          setRunningTool(call.name);
          // A tool call ends the current thought. Reset the accumulator so
          // the NEXT reasoning entry contains only new reasoning: without
          // this, the coalescing check below sees a tool entry as `last`,
          // starts a fresh entry, and re-prints the entire thought history.
          reasoningText = "";
          appendEntry({
          kind: "tool",
          text: call.name,
          detail: formatToolArgs(call),
          toolArgs: formatToolArgs(call),
          turn: currentTurn,
          });
        },
        onToolResult: (call, result) => {
          setRunningTool(null);
          if (call.name === "spawn_agent") {
            const card = parseSubagentCard(result.success, result.output, result.error);
            if (card) {
              appendEntry({
                kind: "subagent",
                text: call.name,
                success: result.success,
                turn: currentTurn,
                subagentOutcome: card.outcome,
                subagentTurns: card.turns,
                subagentFindings: card.findings,
                subagentSummary: card.summary,
                subagentError: card.error ?? "",
              });
              return;
            }
            // malformed output — fall through to generic tool card
          }
          // A counted summary ("4 matches in 3 files") beats a truncated JSON
          // blob: the operator needs to know what happened, and the raw
          // payload is already in the model's context, not theirs.
          appendEntry({
            kind: "tool",
            text: call.name,
            detail: formatToolResult(call, result),
            toolArgs: formatToolArgs(call),
            success: result.success,
            turn: currentTurn,
          });
        },
        onUsage: (usage) => {
          // Fires once per model call, so the operator watches the budget
          // being consumed instead of discovering it at the stop.
          setTurnBudget({ used: usage.turnTokensUsed, limit: usage.turnTokenBudget });
        },
        onNotice: (notice) => appendEntry({ kind: "notice", text: notice, turn: currentTurn }),
      }, { signal: controller.signal });

      if (!assistantText && outcome.assistantText) {
        appendEntry({ kind: "assistant", text: outcome.assistantText, turn: currentTurn });
      }
      setSessionTokens((prev) => ({
        input: prev.input + outcome.usage.inputTokens,
        output: prev.output + outcome.usage.outputTokens,
      }));
      turnUsage = { inputTokens: outcome.usage.inputTokens, outputTokens: outcome.usage.outputTokens };

      // A turn that fails must say so. The engine reports failure through
      // `stopReason`/`error`, and neither was surfaced before: a provider
      // rejection rendered as "0 tool calls · 0→0 tok" and nothing else,
      // which reads as the agent having simply ignored the operator.
      const producedText = Boolean(assistantText || outcome.assistantText);
      if (outcome.stopReason === "cancelled") {
        // The operator stopped this turn. Report what it cost before it
        // stopped: an interrupt that hides the spend is an interrupt the
        // operator cannot reason about.
        const used = Math.round(outcome.budget.tokensUsed / 1000);
        const limit = Math.round(outcome.budget.tokenBudget / 1000);
        appendEntry({
          kind: "error",
          text: "turn interrupted by the operator",
          detail: `Ran ${outcome.budget.iterations} tool call${outcome.budget.iterations === 1 ? "" : "s"} · ${used}k of ${limit}k tokens spent. The conversation is kept; send another message to continue.`,
          turn: currentTurn,
        });
      } else if (outcome.stopReason === "error") {
        appendEntry({
          kind: "error",
          text: "turn failed",
          detail: outcome.error ?? "The runtime reported an error but gave no message.",
          turn: currentTurn,
        });
      } else if (outcome.stopReason === "max_turn_tokens") {
        // Report the real numbers: "paused" plus a budget the operator can
        // see is far more actionable than a bare limit message.
        const used = Math.round(outcome.budget.tokensUsed / 1000);
        const limit = Math.round(outcome.budget.tokenBudget / 1000);
        appendEntry({
          kind: "error",
          text: `paused at the turn token budget (${used}k of ${limit}k)`,
          detail: `Ran ${outcome.budget.iterations} tool call${outcome.budget.iterations === 1 ? "" : "s"}. Send another message to continue — the conversation is kept, and nothing re-runs.`,
          turn: currentTurn,
        });
      } else if (outcome.stopReason === "max_tool_iterations") {
        appendEntry({
          kind: "error",
          text: `paused at the tool-call backstop (${outcome.budget.iterations} of ${outcome.budget.maxToolIterations})`,
          detail: outcome.error
            ?? "This guard only trips when calls report no token cost. Send another message to continue from here.",
          turn: currentTurn,
        });
      } else if (!producedText && outcome.toolCalls.length === 0) {
        // Not an error, but silence is never a useful answer.
        appendEntry({
          kind: "error",
          text: "no response from the model",
          detail: outcome.usage.inputTokens === 0 && outcome.usage.outputTokens === 0
            ? "The request consumed no tokens, which usually means the provider rejected it — check /doctor and the model's credentials."
            : "The model returned an empty reply. Try rephrasing, or /model to switch.",
          turn: currentTurn,
        });
      }

      if (settings.showTurnSummary) {
        appendEntry({
          kind: "notice",
          text: `${outcome.toolCalls.length} tool call${outcome.toolCalls.length === 1 ? "" : "s"} · ${outcome.usage.inputTokens}→${outcome.usage.outputTokens} tok`,
          turn: currentTurn,
        });
      }
    } catch (error) {
      appendEntry({
        kind: "error",
        text: "turn failed",
        detail: error instanceof Error ? error.message : String(error),
        turn: currentTurn,
      });
      setTurnBudget(null);
    } finally {
      // Drop the controller before clearing `busy`, so Esc can never abort a
      // turn that has already returned.
      if (abortRef.current === controller) abortRef.current = null;
      setBusy(false);
      // Stamp the turn's wall-clock duration onto its assistant answer(s) so
      // the AI footer can show a real elapsed. Done once the turn has settled,
      // and only for entries that do not already carry one, so a later repaint
      // never re-times an old answer.
      const turnDuration = Date.now() - turnStartedAt;
      const usage = turnUsage;
      setEntries((current) => current.some(
        (e) => e.kind === "assistant" && e.turn === currentTurn && e.durationMs === undefined,
      )
        ? current.map((e) =>
            e.kind === "assistant" && e.turn === currentTurn && e.durationMs === undefined
              ? {
                  ...e,
                  durationMs: turnDuration,
                  // Stamp per-turn usage alongside the elapsed so the footer's
                  // token/cost segments have a real figure to render.
                  ...(usage
                    ? { usageInput: usage.inputTokens, usageOutput: usage.outputTokens }
                    : {}),
                }
              : e)
        : current);
      // Persist in `finally`, not in the success path and not in `catch`:
      // a turn that failed is exactly the one an operator wants to resume,
      // and this previously sat inside `catch`, so a SUCCESSFUL turn saved
      // nothing at all and /resume always reported an empty history.
      if (session) {
        const firstUser = entriesRef.current.find((entry) => entry.kind === "user");
        saveSession({
          id: session.scanId,
          savedAt: Date.now(),
          target: session.target || undefined,
          model: modelId ?? undefined,
          mode: modeLabel(mode),
          cwd: process.cwd(),
          messageCount: session.messages.length,
          preview: firstUser?.text ?? "",
          messages: session.messages as unknown[],
        });
        pruneSessions();
      }
    }
  }, [appendEntry, busy, routeSlashCommand, session, settings.showTurnSummary]);
  submitRef.current = send;

  // Deliver one parked message per idle transition. One at a time rather than a
  // loop: delivering makes the console busy again, so the NEXT idle drains the
  // one after it. That preserves FIFO order without the drain re-entering
  // itself, and it means a queued message never races the turn it was typed
  // during.
  useEffect(() => {
    if (busy || !session) return;
    const { next, rest } = dequeueComposerInput(queuedRef.current);
    if (next === undefined) return;
    queuedRef.current = rest;
    setQueuedMessages(rest);
    void submitRef.current?.(next);
  }, [busy, session]);

  useKeyboard((key) => {
    // Authorization prompts are modal and drive the SAME selector reducer the
    // command pickers use, so ↑↓/enter/esc mean one thing everywhere. Ctrl+C
    // still exits — a modal must never trap the operator — and takes the
    // declining path on the way out rather than dropping the promise.
    if (approvalPrompt) {
      if (key.ctrl && key.name === "c") {
        approvalPrompt.decline();
        onExit();
        return;
      }
      if (key.name === "escape") {
        approvalPrompt.decline();
        return;
      }
      if (key.name === "return") {
        const choice = approvalState ? highlighted(approvalState) : undefined;
        // No highlighted row (the filter matched nothing) is NOT a grant:
        // the prompt simply stays open.
        if (choice && !choice.disabled) approvalPrompt.decide(choice.id);
        return;
      }
      if (key.name === "up" || key.name === "down") {
        stepApproval(key.name);
        return;
      }
      return;
    }
    // The picker is modal: while it is open it owns navigation, typing and
    // Enter, so a stray keystroke cannot leak into the composer behind it.
    // Ctrl+C still exits, because a modal must never trap the operator.
    if (secretPrompt) {
      if (key.ctrl && key.name === "c") {
        onExit();
        return;
      }
      if (key.name === "escape") {
        setSecretPrompt(null);
        return;
      }
      if (key.name === "return") {
        const entry = secretPrompt;
        setSecretPrompt(null);
        const secret = entry.value.trim();
        if (!secret) {
          appendEntry({ kind: "notice", text: "no credential entered; nothing was saved", turn: turn.current });
          return;
        }
        const stored = loadCredentials();
        const ok = saveCredentials({ ...stored, [entry.providerId]: secret });
        // The secret itself is never echoed back into the transcript.
        appendEntry({
          kind: ok ? "notice" : "error",
          text: ok
            ? `${entry.label} credential saved (${redactSecret(secret)})`
            : `could not save the ${entry.label} credential`,
          detail: ok
            ? `Stored owner-only and exported as ${entry.envVar}. Use /model to switch to one of its models.`
            : "The credentials file could not be written.",
          turn: turn.current,
        });
        if (ok) process.env[entry.envVar] = secret;
        return;
      }
      if (key.name === "backspace") {
        setSecretPrompt((p) => (p ? { ...p, value: p.value.slice(0, -1) } : p));
        return;
      }
      if (key.sequence && key.sequence.length === 1 && !key.ctrl && !key.meta && key.sequence >= " ") {
        const char = key.sequence;
        setSecretPrompt((p) => (p ? { ...p, value: p.value + char } : p));
        return;
      }
      return;
    }
    if (picker) {
      if (key.ctrl && key.name === "c") {
        onExit();
        return;
      }
      if (key.name === "escape") {
        setPicker(null);
        return;
      }
      if (key.name === "return") {
        const choice = highlighted(picker.state);
        const commit = picker.commit;
        setPicker(null);
        if (choice && !choice.disabled) commit(choice.id);
        return;
      }
      if (key.name === "up") {
        setPicker((p) => (p ? { ...p, state: reduceSelector(p.state, { type: "up" }) } : p));
        return;
      }
      if (key.name === "down") {
        setPicker((p) => (p ? { ...p, state: reduceSelector(p.state, { type: "down" }) } : p));
        return;
      }
      if (key.name === "backspace") {
        setPicker((p) => (p ? { ...p, state: reduceSelector(p.state, { type: "backspace" }) } : p));
        return;
      }
      if (key.sequence && key.sequence.length === 1 && !key.ctrl && !key.meta && key.sequence >= " ") {
        const char = key.sequence;
        setPicker((p) => (p ? { ...p, state: reduceSelector(p.state, { type: "append", char }) } : p));
        return;
      }
      return;
    }
    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }
    // Transcript scrolling lives on PageUp/PageDown (and Ctrl+Up/Ctrl+Down
    // where the terminal distinguishes them), NOT on plain Up/Down — those
    // recall composer history. The box is non-focusable, so it never grabs the
    // arrows itself; we drive it explicitly here. Sticky-bottom auto-scroll
    // keeps the newest evidence in view the rest of the time.
    if (key.name === "pageup" || (key.ctrl && key.name === "up")) {
      transcriptRef.current?.scrollBy(-0.5, "viewport");
      return;
    }
    if (key.name === "pagedown" || (key.ctrl && key.name === "down")) {
      transcriptRef.current?.scrollBy(0.5, "viewport");
      return;
    }
    // Ctrl+R flips the whole transcript between collapsed and expanded detail —
    // the global disclosure toggle for the folded tool/reasoning summaries. It
    // persists via the settings store (same layer `/settings` would write), so
    // the choice survives the session; the store notifies subscribers, so the
    // transcript repaints immediately with no remount.
    if (key.ctrl && key.name === "r") {
      updateSetting(
        "transcriptDetail",
        settingsRef.current.transcriptDetail === "collapsed" ? "expanded" : "collapsed",
      );
      return;
    }
    // Ctrl+Y pulls the most recently queued message back into the composer for
    // editing — which doubles as cancel: it leaves the queue, and dropping it
    // (Esc) or re-sending it (Enter, re-queued at the back while still busy) is
    // then just normal composer editing. Newest-first so a hurried operator can
    // fix the last thing they typed without disturbing earlier parked lines.
    if (key.ctrl && key.name === "y" && queuedRef.current.length > 0) {
      const queue = queuedRef.current;
      const last = queue[queue.length - 1];
      const rest = queue.slice(0, -1);
      queuedRef.current = rest;
      setQueuedMessages(rest);
      composingRef.current = true;
      setComposing(true);
      setComposerText(last);
      return;
    }
    // Shift+Tab cycles the autonomy mode. It is handled ABOVE the composing
    // block for two reasons: it should work while the operator is mid-sentence,
    // and the composing block's catch-all appends `key.sequence` for anything
    // without ctrl/meta — which meant Shift+Tab used to paste its own raw
    // escape sequence (`\x1b[Z`, or `\x1b[9;2u` under the kitty protocol) into
    // the composer.
    //
    // The cycle delegates to `/mode` rather than calling `setAutonomyMode`
    // directly, so it inherits that command's preconditions for free: refuse
    // mid-turn, refuse without a runtime, and refuse YOLO without a scope. YOLO
    // is skipped entirely when no scope is configured, so the cycle degrades to
    // a two-state toggle instead of stopping on a mode it cannot enter.
    if (key.name === "tab" && key.shift) {
      const cycle: ConsoleAutonomyMode[] = ["standard", "copilot", "yolo", "recon"];
      const at = cycle.indexOf(mode);
      const next = cycle[(at + 1) % cycle.length] ?? "standard";
      routeSlashCommand(`/mode ${next}`);
      return;
    }
    if (key.ctrl && (key.name === "p" || key.name === "k")) {
      composingRef.current = true;
      setComposing(true);
      setComposerText("/");
      return;
    }
    if (key.name === "escape") {
      if (commandMenuOpenRef.current && composerRef.current.trimStart().startsWith("/")) {
        setCommandMenuVisible(false);
        return;
      }
      if (composingRef.current) {
        composingRef.current = false;
        setComposerText("");
        setComposing(false);
        return;
      }
      // With no overlay and no draft to discard, Esc means "stop" while a
      // turn is running and "go back" when nothing is. Interrupting takes
      // the place of navigation ONLY while a turn is actually in flight, so
      // the menu → draft → back precedence is unchanged when idle.
      if (interruptTurn()) return;
      onGoBack();
      return;
    }
    if (composingRef.current) {
      if (commandMenuOpenRef.current && composerRef.current.trimStart().startsWith("/")) {
        if (key.name === "up") {
          setSlashSelected((current) => Math.max(0, current - 1));
          return;
        }
        if (key.name === "down") {
          setSlashSelected((current) => Math.min(Math.max(menuCommands.length - 1, 0), current + 1));
          return;
        }
        if (key.name === "tab") {
          if (selectedSlashCommand) {
            setComposerText(completionFor(selectedSlashCommand, findCommand(composerRef.current).args));
            setCommandMenuVisible(true);
          }
          return;
        }
      }
      // Outside the command menu, Up/Down recall submitted-message history into
      // the composer (readline semantics) rather than scrolling the transcript.
      if (key.name === "up") {
        recallComposerHistory("up");
        return;
      }
      if (key.name === "down") {
        recallComposerHistory("down");
        return;
      }
      // Shift+Enter inserts a newline; plain Enter submits. Terminals that
      // cannot distinguish the two (no kitty keyboard protocol) fall through to
      // submit, which is the safe default. The multi-line composer renders the
      // newlines and grows to fit.
      if (key.name === "return" && key.shift) {
        setComposerText(`${composerRef.current}\n`);
        return;
      }
      if (key.name === "return") {
        const currentComposer = composerRef.current;
        const parsed = findCommand(currentComposer);
        const useSelectedCommand = commandMenuOpenRef.current
          && composerRef.current.trimStart().startsWith("/")
          && selectedSlashCommand !== undefined
          && (!parsed.rawName || (!parsed.isKnown && commandMatchesPrefix(selectedSlashCommand, parsed.rawName)));
        const input = useSelectedCommand && selectedSlashCommand
          ? completionFor(selectedSlashCommand, parsed.args)
          : currentComposer;
        if (!input.trim()) {
          composingRef.current = false;
          setComposerText("");
          setComposing(false);
          return;
        }
        // Remember every submitted message (sent or queued) for Up/Down recall.
        // Done before the setComposerText("") below, which re-bases the history
        // cursor onto the freshly-grown ring.
        historyRef.current = pushHistory(historyRef.current, input);
        const disposition = classifyComposerInput({
          input,
          isSlash: findCommand(input).isSlash,
          busy,
          hasSession: Boolean(session),
        });
        if (disposition === "queue") {
          // A turn is in flight, or the session is still connecting. Park the
          // message rather than dropping it. Before this, Enter here was a bare
          // `return`: the text was discarded AND left in the composer, which is
          // indistinguishable from a dead keyboard.
          const { queue, accepted } = enqueueComposerInput(queuedRef.current, input);
          queuedRef.current = queue;
          setQueuedMessages(queue);
          appendEntry({
            kind: accepted ? "notice" : "error",
            text: accepted
              ? `queued — will send when the current turn ends: ${input}`
              : `queue is full (${COMPOSER_QUEUE_LIMIT} messages); not queued: ${input}`,
            turn: turn.current,
          });
        } else if (disposition === "send") {
          void send(input);
        }
        composingRef.current = false;
        setComposerText("");
        setComposing(false);
        setCommandMenuVisible(false);
        return;
      }
      // Line editing. The composer is append-only — there is no caret to
      // move — so the kill verbs that operate on the tail of the buffer are
      // implemented and the caret-relative ones (Ctrl+A / Ctrl+E / Ctrl+K,
      // arrows) deliberately are not; faking them would be worse than their
      // absence. The transforms live in composer-edit.ts so word-boundary
      // handling is unit-tested rather than inlined here.
      //
      // Ctrl+U — delete to start of line. This is where macOS maps
      // Cmd+Backspace, which is the key the operator reported dead.
      if (key.ctrl && key.name === "u") {
        setComposerText(deleteToLineStart(composerRef.current));
        return;
      }
      // Ctrl+W, and Alt/Option+Backspace (`\x1b\x7f`, parsed as backspace
      // with meta/option set) — delete the previous word.
      if (key.ctrl && key.name === "w") {
        setComposerText(deletePreviousWord(composerRef.current));
        return;
      }
      if (key.name === "backspace" && (key.meta || key.option || key.ctrl)) {
        setComposerText(deletePreviousWord(composerRef.current));
        return;
      }
      if (key.name === "backspace") {
        setComposerText(composerRef.current.slice(0, -1));
        return;
      }
      if (key.sequence && !key.ctrl && !key.meta) {
        setComposerText(`${composerRef.current}${key.sequence}`);
      }
      return;
    }
    // Idle composer (nothing typed yet): Up recalls the most recent submission
    // into the composer; Down is a no-op until browsing has begun. Neither
    // scrolls the transcript.
    if (key.name === "up") {
      recallComposerHistory("up");
      return;
    }
    if (key.name === "down") {
      recallComposerHistory("down");
      return;
    }
    if (key.sequence && !key.ctrl && !key.meta && key.sequence.length === 1 && key.sequence.charCodeAt(0) >= 32) {
      composingRef.current = true;
      setComposing(true);
      setComposerText(key.sequence);
    }
  });

  const empty = entries.length === 0;
  // Parked messages are surfaced next to the working indicator, because that is
  // exactly where the operator is looking while they wait.
  const queueLabel = composerQueueLabel(queuedCount);
  // The status bar is built from data the session actually reports: the
  // resolved model id, the real git tree, and accumulated turn usage. No
  // context percentage is produced, because no context-window size is
  // available anywhere in the codebase and inventing one would be worse
  // than omitting it.
  // Built at every width now: the bottom bar is the only place this state
  // appears, so a compact terminal still gets the degraded version rather
  // than nothing (fitStatusSegments drops low-priority segments to fit).
  const statusBarText = fitStatusSegments(
    buildStatusSegments({
      model: modelId ?? undefined,
      mode: modeLabel(mode),
      cwd: process.cwd(),
      home: homedir(),
      branch: git?.isRepo ? git.branch ?? git.detachedSha : undefined,
      modified: git?.modified,
      untracked: git?.untracked,
      inputTokens: sessionTokens.input,
      outputTokens: sessionTokens.output,
      // The per-turn token budget, shown only while a turn is actually
      // running. This is the turn budget, NOT a model context window —
      // nothing in the codebase knows context-window sizes.
      contextWindow: turnBudget?.limit,
      contextUsed: turnBudget?.used,
      // Telemetry toggles: where the model name is surfaced, whether the
      // context reading renders as a visual meter, and whether an estimated
      // dollar cost is appended. status-bar.ts honours each and invents no
      // number it was not given.
      modelDisplay: settings.modelDisplay,
      showContextMeter: settings.showContextMeter,
      showCost: settings.showCost,
    }),
    contentWidth,
  );
  // The picker reuses the menu's vertical budget: it occupies the same slot
  // above the composer, so it must obey the same "leave the transcript real
  // rows" rule rather than growing to the size of the model catalogue.
  //
  // The picker and an approval panel share that slot, so both are budgeted
  // the same way: ask the column what it can spare, then buy the optional
  // lines out of that budget rather than adding them on top of it.
  const selectorBudget = computeCommandMenuHeight({ height, compact, rowsPerCommand: 1 }).maxCommands;

  const pickerVisible = picker ? visibleItems(picker.state) : [];
  const pickerDetail = picker ? highlighted(picker.state)?.detail ?? "" : "";
  const pickerPlan = selectorPanelBudget({
    budget: selectorBudget,
    hasContext: false,
    hasDetail: Boolean(pickerDetail),
  });
  const pickerWindow = picker
    ? windowFor(picker.state, pickerPlan.maxItemRows)
    : { start: 0, end: 0 };
  const pickerRows = pickerVisible.slice(pickerWindow.start, pickerWindow.end);
  const pickerBoxHeight = selectorPanelHeight(pickerRows.length, false, pickerPlan.showDetail);

  // The approval card shows its choices in full (there are only ever two) and
  // spends the rest of its budget on READABLE argument rows. A long arg list is
  // truncated with a "+N more" tail rather than wrapped, so the card's height is
  // exactly what the column reserves for it.
  const approvalItems = approvalPrompt?.items ?? [];
  const approvalHasSubject = Boolean(approvalPrompt?.subject);
  const approvalBodyAll = approvalPrompt?.bodyLines ?? [];
  const approvalMaxBody = compact ? 2 : 5;
  const approvalBodyShown = approvalBodyAll.length > approvalMaxBody
    ? [
        ...approvalBodyAll.slice(0, Math.max(0, approvalMaxBody - 1)),
        `+${approvalBodyAll.length - Math.max(0, approvalMaxBody - 1)} more`,
      ]
    : approvalBodyAll;
  const approvalBoxHeight = approvalPrompt
    ? approvalCardRows({
        hasSubject: approvalHasSubject,
        bodyRows: approvalBodyShown.length,
        choiceRows: approvalItems.length,
      })
    : 0;
  // The masked credential panel stays a typed field — a secret is entered,
  // not chosen — but it gets the same treatment that stops a panel from
  // collapsing: four content lines plus two border rows, stated explicitly.
  const SECRET_PANEL_HEIGHT = 6;
  // Usable width INSIDE the transcript panel: the ledger box adds its own
  // paddingX, which an entry's own border must live within.
  const transcriptWidth = Math.max(8, contentWidth - (compact ? 2 : 4));
  // "0sec" is 4 cells; the mode label is right-sized to its own text so
  // the engagement summary gets every remaining cell.
  const headerModeWidth = Math.min(10, Math.max(1, contentWidth - 8));
  const headerEngagementWidth = Math.max(1, contentWidth - 4 - headerModeWidth - 2);
  // Relative ages need a clock, but the transcript must not repaint every
  // second just to age a label. Tick only while timestamps are enabled, and
  // only at the granularity the format actually shows.
  // Density stays the spacing knob; the three visual knobs are resolved
  // separately and are orthogonal to it. An env override lets a style be pinned
  // for a preview or a capture without touching the settings file.
  const transcriptStyleSettings = resolveTranscriptStyleSettings(settings, process.env);
  const entryDisplay: EntryDisplay = {
    spacing: settings.density === "compact" ? 0 : 1,
    showTimestamps: settings.showTimestamps,
    now: clockTick,
    transcriptStyle: transcriptStyleSettings.transcriptStyle,
    roleLabelStyle: transcriptStyleSettings.roleLabelStyle,
    toolCardStyle: transcriptStyleSettings.toolCardStyle,
    mode: modeLabel(mode),
    model: modelId ?? "",
    modelInFooter: settings.modelDisplay === "message",
    showTokenUsage: settings.showTokenUsage,
    showCost: settings.showCost,
    transcriptDetail: settings.transcriptDetail,
  };
  // One animation kind per real state. `awaiting-operator` is deliberately
  // NOT a busy spinner: when the human is the bottleneck the surface should
  // look expectant, not like it is grinding.
  const gateOpen = Boolean(pendingScope || pendingLocalScope || pendingEscalation || pendingToolApproval || secretPrompt);
  const animationKind: AnimationKind | null = gateOpen
    ? "awaiting-operator"
    : runningTool
      ? "tool"
      : !session
        ? "connecting"
        : busy
          ? streamingRef.current
            ? "streaming"
            : "thinking"
          : null;
  // animTick is read only to make the frame recompute on each interval.
  void animTick;
  const animation = animationKind
    ? frameAt(animationKind, Date.now() - activitySince.current, {
        label: animationKind === "tool" ? runningTool ?? undefined : undefined,
      })
    : null;

  // Drive the animation at the kind's own interval; stop entirely when
  // nothing is animating so an idle console costs no repaints.
  useEffect(() => {
    if (!animationKind) return;
    const timer = setInterval(
      () => setAnimTick((n) => n + 1),
      frameIntervalMs(animationKind),
    );
    return () => clearInterval(timer);
  }, [animationKind]);

  // Restart the elapsed clock whenever the kind of activity changes.
  useEffect(() => {
    activitySince.current = Date.now();
  }, [animationKind]);

  const menu = computeCommandMenuLayout({ width, compact });
  // Height is stated explicitly so the border is drawn where the content
  // actually ends, and flexShrink is disabled so the column cannot squeeze
  // the box out from under its own children. The no-match state still needs a
  // single content row for its "No command matches" line — without it the box
  // is one row short and the hint footer overprints the bottom border.
  const commandMenuHeight = menuCommands.length > 0
    ? commandMenuBoxHeight(menuCommands.length, commandRowsPerCommand)
    : commandMenuBoxHeight(0, commandRowsPerCommand) + 1;

  const commandMenuVisible = composing && commandMenuOpen && isSlashComposer;
  // Every overlay — command menu, picker, approval panel — already prints
  // its own key hints inside its border. Repeating them down here is the
  // duplication that made the old two-line composer read as noise. So the
  // bar yields to contextual keys ONLY while composing plain text, where
  // "enter send · esc cancel" appears nowhere else on screen.
  const showContextualKeys = composing && !commandMenuVisible && !picker && !approvalPrompt && !secretPrompt;

  // ACTIVE SUBAGENTS. `spawn_agents` fans out up to 8 with 4 running at
  // once, so this block is genuinely multi-row and genuinely unbounded —
  // and it was neither height-capped nor `flexShrink={0}`, so under column
  // pressure Yoga collapsed it and its rows painted into each other and
  // into the title. Cap what is shown, state the overflow, and reserve
  // EXACTLY what is rendered.
  const subagentEntries = settings.showSubagents ? Object.values(activeSubagents) : [];
  const subagentVisible = subagentEntries.slice(0, SUBAGENT_MAX_VISIBLE);
  const subagentOverflow = subagentEntries.length - subagentVisible.length;
  const subagentOverflowRow = subagentOverflow > 0 ? 1 : 0;
  // Title + rows + optional overflow line. Zero when nothing is running.
  const subagentBlockRows = subagentVisible.length > 0
    ? 1 + subagentVisible.length + subagentOverflowRow
    : 0;

  // Every other region in the column is flexShrink={0}, so the transcript
  // absorbs all the pressure. Compute what it actually has left: a
  // scrollbox squeezed below its content still paints that content, and
  // the empty state then interleaves into itself.
  //
  // Each reservation below is the panel's REAL rendered height plus its
  // marginTop, not a guess. The approval slot used to be a fixed 6 while
  // the panel it stood for wrapped its text — a long tool name or reason
  // made the box taller than the rows reserved, the column over-subscribed,
  // and everything downstream of that (the fused approval card, the fused
  // subagent rows, the transcript that would not scroll to the bottom)
  // followed from the same miscount.
  const ledgerRows = computeLedgerRows({
    height,
    compact,
    // The picker and the command menu occupy the same slot and both carry a
    // marginTop, which computeLedgerRows adds for a non-zero menuRows.
    menuRows: commandMenuVisible ? commandMenuHeight : picker ? pickerBoxHeight : 0,
    subagentRows: subagentBlockRows > 0 ? subagentBlockRows + 1 : 0,
    approvalRows: (approvalPrompt ? approvalBoxHeight + 1 : 0)
      + (secretPrompt ? SECRET_PANEL_HEIGHT + 1 : 0),
  });
  // Optional empty-state lines are dropped from the bottom up rather than
  // overprinted. The mark needs the most room, so it goes first.
  // The block mark shows whenever the column can hold it — width for the glyph,
  // height for the mark rows — regardless of the compact flag, so a narrow-but-
  // tall terminal still gets the real logo instead of the text fallback.
  const showTerminalMark =
    settings.showLogo && empty && ledgerRows >= LEDGER_MARK_ROWS && contentWidth >= TERMINAL_BLOCK_LOGO_WIDTH;
  const showEmptyStateTagline = empty && ledgerRows >= 3;
  const sessionState = startupError ? "unavailable" : busy ? "working" : session ? "ready" : "connecting";
  // The header's engagement summary is assembled from opt-out segments so a
  // hidden one leaves no dangling " · ": target and scope are each gated on
  // their setting, and the session state (connecting/working/ready) always
  // rides along — it is status, not scope, and stays visible even when both
  // labels are off.
  const targetSummary = target ? `target: ${target}` : "target: none";
  const scopeSummary = `scope: ${scopeLabel}`;
  const headerSegments: string[] = [];
  if (settings.showTarget) headerSegments.push(targetSummary);
  if (settings.showScope) headerSegments.push(scopeSummary);
  headerSegments.push(sessionState);
  const headerEngagement = headerSegments.join(" · ");

  const controls = approvalPrompt
    ? "↑↓ choose · enter confirm · esc decline"
    : commandMenuVisible
      ? "↑↓ select · tab complete · enter run · esc close"
      : composing
        ? "enter send · esc cancel"
        : "type to chat · / commands · shift+tab mode · ctrl+p / ctrl+k palette · esc back";
  const commandMenuInnerWidth = menu.innerWidth;
  const commandRowWidth = menu.rowWidth;
  const commandNameWidth = menu.nameWidth;
  const commandMetaWidth = menu.metaWidth;
  const commandHeaderTitleWidth = menu.headerTitleWidth;
  const commandHeaderQueryWidth = menu.headerQueryWidth;
  const commandHeaderGap = menu.headerGap;
  const modeColor = modeColorFor(mode, theme);

  // ── The single working / waiting indicator ────────────────────────────────
  // There must be exactly ONE. It used to render in the composer placeholder
  // AND in the transcript tail (and, after the hero rework, in both the
  // centered and the scrollbox branches), so a running turn showed the spinner
  // twice. It now lives in one place per state — the centered hero when empty,
  // the scrollbox tail when not — and never in the composer. And when a
  // reasoning ("thinking") entry is the tail it is suppressed entirely: that
  // entry already prints "thinking" while it streams, so a second "thinking"
  // spinner beside it is the double-label the operator reported.
  const tailKind = entries.length > 0 ? entries[entries.length - 1]?.kind : undefined;
  const workingAnimation = animation && tailKind !== "reasoning" ? animation : null;
  const workingGlyphColor = animationKind === "awaiting-operator" ? WARNING : ACCENT;
  // Glyph in its own fixed GLYPH_CELLS cell so motion never shifts the label;
  // label + elapsed + any queue note collapse into ONE muted, fitted line so
  // two siblings can never fuse under width pressure. Calm mono palette —
  // neutral accent for work, WARNING only for "your move", red never here.
  const workingLine = workingAnimation
    ? `${workingAnimation.label}${workingAnimation.elapsedLabel ? `  ${workingAnimation.elapsedLabel}` : ""}${queueLabel ? ` · ${queueLabel}` : ""}`
    : "";
  const workingIndicator = workingAnimation ? (
    <box flexDirection="row" minWidth={0} marginTop={1} gap={1}>
      <box width={GLYPH_CELLS} flexShrink={0}>
        <text fg={workingGlyphColor}>{workingAnimation.glyph}</text>
      </box>
      <box flexGrow={1} minWidth={0}>
        <text fg={MUTED}>{fitTuiText(workingLine, Math.max(1, contentWidth - GLYPH_CELLS - 1))}</text>
      </box>
    </box>
  ) : null;

  // ── The composer, single-sourced ──────────────────────────────────────────
  // ONE element, rendered in the centered hero when empty and pinned above the
  // status bar otherwise; the keyboard handler (composer text, submit, history,
  // slash menu) is the module-level `useKeyboard` above and does not move, so
  // the input wiring is identical in both positions — only this frame's
  // placement changes. The clean left-rail is the effective default in BOTH the
  // centered hero AND the pinned chat state (the start-screen look the operator
  // asked for everywhere): the stored "border" resolves to "rail", while an
  // explicit "plain" — or any deliberate non-border choice — is still honoured.
  const composerStyle: TuiSettings["composerStyle"] =
    settings.composerStyle === "border" ? "rail" : settings.composerStyle;
  const composerActive = composing || commandMenuVisible;
  // Real operator input is TEXT-bright; the placeholder and the parked-message
  // note are MUTED so neither reads as something typed. The working spinner is
  // deliberately NOT here — it lives once, in the transcript/hero — so the
  // composer never double-prints it.
  //
  // While composing, the input is MULTI-LINE: it splits on the newlines that
  // Shift+Enter inserts and grows downward, up to COMPOSER_MAX_ROWS rows, after
  // which it shows the last rows (an internal scroll that keeps the cursor in
  // view). The block cursor sits at the end of the LAST row.
  const COMPOSER_MAX_ROWS = 8;
  const composerInput = (textWidth: number) => {
    if (composing) {
      const lines = composer.split("\n");
      const visible = lines.length > COMPOSER_MAX_ROWS
        ? lines.slice(lines.length - COMPOSER_MAX_ROWS)
        : lines;
      return (
        <box flexDirection="column" minWidth={0}>
          {visible.map((line, i) => {
            const isLast = i === visible.length - 1;
            const shown = fitTuiText(line, Math.max(1, textWidth - (isLast ? 1 : 0)));
            return <text key={`composer-line-${i}`} fg={TEXT}>{isLast ? `${shown}█` : shown}</text>;
          })}
        </box>
      );
    }
    return startupError ? (
      <text fg={ERROR}>{fitTuiText("runtime unavailable", textWidth)}</text>
    ) : queueLabel ? (
      <text fg={MUTED}>{fitTuiText(queueLabel, textWidth)}</text>
    ) : (
      <text fg={MUTED}>{fitTuiText("type to chat or / for commands", textWidth)}</text>
    );
  };
  // ONE composer builder, two call sites: full-width at the bottom of a chat,
  // and a constrained, centered card under the hero logo. `outerWidth` omitted
  // means width:"100%" (the pinned chat composer); a number gives the hero its
  // fixed card width. `textWidth` is always budgeted against that outer width so
  // the input can never overrun the frame. The keyboard handler is untouched by
  // either — placement is the only thing that changes.
  const buildComposer = ({
    textWidth,
    outerWidth,
    padY = 0,
  }: {
    textWidth: number;
    outerWidth?: number;
    padY?: number;
  }) => (
    <box flexDirection="row" width={outerWidth ?? "100%"} flexShrink={0} marginTop={1} minWidth={0}>
      {composerStyle === "rail" ? (
        <box width={1} flexShrink={0} alignSelf="stretch" backgroundColor={composerActive ? PRIMARY : BORDER} />
      ) : null}
      <ComposerFrame style={composerStyle} active={composerActive} theme={theme} padY={padY}>
        <box flexDirection="row" width="100%" minWidth={0}>
          <text width={1} flexShrink={0} fg={composing ? PRIMARY : MUTED}>›</text>
          <text width={1} flexShrink={0} fg={MUTED}> </text>
          <box width={textWidth} flexShrink={0} minWidth={0}>
            {composerInput(textWidth)}
          </box>
        </box>
      </ComposerFrame>
    </box>
  );
  const composerNode = buildComposer({ textWidth: composerTextWidth });

  // ── Sticky context above the composer ──────────────────────────────────────
  // Two things must stay on screen while the transcript scrolls and the agent
  // works: the request currently being answered, and anything the operator has
  // parked for the next round. Both live in a flexShrink={0} block pinned
  // directly above the composer, so the transcript (flexGrow) absorbs the rows
  // and nothing overflows. Bounded on purpose — the parked list caps at a few
  // rows with a "+N more" tail — so it can never crowd out the transcript.
  const lastUserRequest = (() => {
    for (let i = entries.length - 1; i >= 0; i -= 1) {
      if (entries[i].kind === "user") return entries[i].text;
    }
    return "";
  })();
  const STICKY_QUEUE_ROWS = 3;
  const stickyWidth = Math.max(1, contentWidth - 2);
  const showStickyRequest = busy && Boolean(lastUserRequest);
  const stickyNode =
    showStickyRequest || queuedMessages.length > 0 ? (
      <box flexDirection="column" width="100%" flexShrink={0} minWidth={0} marginTop={1}>
        {showStickyRequest ? (
          <box flexDirection="row" minWidth={0}>
            <box width={2} flexShrink={0} minWidth={0}>
              <text fg={ACCENT}>▎</text>
            </box>
            <box flexGrow={1} minWidth={0}>
              <text fg={MUTED}>{fitTuiText(`request · ${lastUserRequest}`, stickyWidth)}</text>
            </box>
          </box>
        ) : null}
        {queuedMessages.length > 0 ? (
          <box flexDirection="column" minWidth={0}>
            <text fg={WARNING}>
              {fitTuiText(
                `${composerQueueLabel(queuedMessages.length)} · sent on the next round · ctrl+y edit`,
                contentWidth,
              )}
            </text>
            {queuedMessages.slice(0, STICKY_QUEUE_ROWS).map((message, index) => (
              <box key={`queued-${index}`} flexDirection="row" minWidth={0}>
                <box width={2} flexShrink={0} minWidth={0}>
                  <text fg={MUTED}>{`${index + 1} `}</text>
                </box>
                <box flexGrow={1} minWidth={0}>
                  <text fg={MUTED}>{fitTuiText(message, stickyWidth)}</text>
                </box>
              </box>
            ))}
            {queuedMessages.length > STICKY_QUEUE_ROWS ? (
              <text fg={MUTED}>
                {fitTuiText(`+${queuedMessages.length - STICKY_QUEUE_ROWS} more`, contentWidth)}
              </text>
            ) : null}
          </box>
        ) : null}
      </box>
    ) : null;
  // The hero composer is a centered card, not a full-bleed bar: ~60% of the
  // content column, clamped to a comfortable 40..72 cells and never wider than
  // the column itself. Four cells of chrome (rail + its gap + the "› " prefix)
  // come off the width for the input field.
  const heroComposerWidth = Math.min(contentWidth, Math.max(40, Math.min(72, Math.floor(contentWidth * 0.6))));
  const heroComposerTextWidth = Math.max(8, heroComposerWidth - 4);
  const heroComposerNode = buildComposer({
    textWidth: heroComposerTextWidth,
    outerWidth: heroComposerWidth,
    padY: 1,
  });
  // A FIXED bottom spacer (not a flexGrow) is what actually anchors the hero
  // composer: with it fixed and the region above it flexGrow, the composer's
  // distance from the bottom never changes, so opening the slash menu (which
  // grows upward in the region above) cannot move the composer. Sized to put the
  // composer near the vertical centre when the menu is closed — roughly the same
  // number of rows sit below it as the composer/hint block spends.
  // The space ABOVE the composer must hold the tallest the command menu can get
  // (not the current filtered count — that changes as the query narrows, and the
  // composer must not move), so an open overlay grows into that space instead of
  // overflowing upward into the header. Reserve for the stable max menu height
  // plus the composer card, hint and header chrome, then centre what is left.
  const heroMenuMaxRows = commandMenuBoxHeight(commandMenuLimit, commandRowsPerCommand);
  const heroBottomSpacer = Math.max(
    1,
    Math.min(Math.floor((height - 6) / 2), height - 12 - heroMenuMaxRows),
  );

  // ── Overlays that share the slot directly above the composer ───────────────
  // Extracted so the SAME nodes render whether the composer is centered (hero)
  // or pinned (chat). Each is already height-budgeted and flexShrink={0}.
  // ONE command-menu builder, sized by whichever CommandMenuLayout it is handed:
  // the full-width `menu` for the pinned chat composer, and a narrower layout for
  // the hero so the menu aligns to the centered composer card above it. `boxWidth`
  // matches the layout — "100%" in chat, the card width in the hero.
  const buildCommandMenu = (ml: typeof menu, boxWidth: number | "100%") => (
    <box flexDirection="column" width={boxWidth} minWidth={0} height={commandMenuHeight} flexShrink={0} marginTop={1} border borderColor={BORDER} backgroundColor={PANEL_ALT} paddingX={1}>
      <box flexDirection="row" width={ml.innerWidth} minWidth={0} gap={ml.headerGap}>
        <box width={ml.headerTitleWidth} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText("COMMANDS", ml.headerTitleWidth)}</text>
        </box>
        {ml.headerQueryWidth > 0 ? (
          <box width={ml.headerQueryWidth} flexShrink={0} minWidth={0}>
            <text fg={MUTED}>{fitTuiText(slashQuery ? `/${slashQuery}` : "all commands", ml.headerQueryWidth, { mode: "middle" })}</text>
          </box>
        ) : null}
      </box>
      {menuCommands.length > 0 ? menuCommands.map((command, index) => {
        const active = index === slashSelected;
        const meta = command.aliases.length > 0
          ? command.aliases.map((alias) => `/${alias}`).join(" ")
          : command.category;
        return (
          <box key={command.name} flexDirection="row" width={ml.innerWidth} minWidth={0}>
            <text width={1} flexShrink={0} fg={active ? PRIMARY : MUTED}>{active ? "›" : " "}</text>
            <box flexDirection="column" width={ml.rowWidth} flexGrow={0} flexShrink={0} minWidth={0} marginLeft={1}>
              <box flexDirection="row" width={ml.rowWidth} minWidth={0} gap={1}>
                <box width={ml.nameWidth} flexShrink={0} minWidth={0}>
                  <text fg={active ? PRIMARY : TEXT}>{fitTuiText(`/${command.name}`, ml.nameWidth)}</text>
                </box>
                {ml.metaWidth > 0 ? (
                  <box width={ml.metaWidth} flexShrink={0} minWidth={0}>
                    <text fg={MUTED}>{fitTuiText(meta, ml.metaWidth)}</text>
                  </box>
                ) : null}
              </box>
              {!compact ? (
                <box width={ml.rowWidth} minWidth={0}>
                  <text fg={MUTED} wrapMode="word">{fitTuiText(command.description, ml.rowWidth)}</text>
                </box>
              ) : null}
            </box>
          </box>
        );
      }) : (
        <box width={ml.innerWidth} flexShrink={0} minWidth={0}>
          <text fg={ERROR}>{fitTuiText(`No command matches /${slashQuery}`, Math.max(1, ml.innerWidth))}</text>
        </box>
      )}
      <box width={ml.innerWidth} flexShrink={0} minWidth={0}>
        <text fg={MUTED}>{fitTuiText("↑↓ select · tab complete · enter run · esc close", Math.max(1, ml.innerWidth))}</text>
      </box>
    </box>
  );
  const commandMenuNode = commandMenuVisible ? buildCommandMenu(menu, "100%") : null;
  // The hero menu is sized so its box is exactly the composer card's width: the
  // layout's inner width is `boxWidth - chrome`, so we ask computeCommandMenuLayout
  // for a width that yields the same inner span the card border/padding leaves.
  const heroMenu = computeCommandMenuLayout({ width: heroComposerWidth + (compact ? 4 : 6), compact });
  const heroCommandMenuNode = commandMenuVisible ? buildCommandMenu(heroMenu, heroComposerWidth) : null;

  const secretNode = secretPrompt ? (
    <box flexDirection="column" width="100%" minWidth={0} height={SECRET_PANEL_HEIGHT} flexShrink={0} marginTop={1} border borderColor={WARNING} backgroundColor={PANEL_ALT} paddingX={1}>
      <box width={approvalWidth} flexShrink={0} minWidth={0}>
        <text fg={WARNING}>{fitTuiText(`${secretPrompt.label} credential`, approvalWidth)}</text>
      </box>
      <box width={approvalWidth} flexShrink={0} minWidth={0}>
        <text fg={TEXT}>{fitTuiText(`${"•".repeat(Math.min(secretPrompt.value.length, 40))}█`, approvalWidth)}</text>
      </box>
      <box width={approvalWidth} flexShrink={0} minWidth={0}>
        <text fg={MUTED}>{fitTuiText(`Stored owner-only in your 0sec state dir and exported as ${secretPrompt.envVar}. Never transmitted by 0sec.`, approvalWidth, { mode: "middle" })}</text>
      </box>
      <box width={approvalWidth} flexShrink={0} minWidth={0}>
        <text fg={MUTED}>{fitTuiText("enter save · esc cancel", approvalWidth)}</text>
      </box>
    </box>
  ) : null;

  const pickerNode = picker ? (
    <SelectorPanel
      title={picker.state.title}
      subtitle={picker.state.query ? picker.state.query : `${pickerVisible.length} available`}
      rows={pickerRows}
      windowStart={pickerWindow.start}
      activeIndex={picker.state.index}
      detail={pickerPlan.showDetail ? pickerDetail : undefined}
      hint="↑↓ select · type to filter · enter apply · esc cancel"
      emptyText={`no match for "${picker.state.query}"`}
      borderColor={MUTED}
      titleColor={PRIMARY}
      contentWidth={contentWidth}
      height={pickerBoxHeight}
      theme={theme}
    />
  ) : null;

  const approvalNode = approvalPrompt && approvalState ? (
    <ApprovalCard
      title={approvalPrompt.title}
      progress={`${approvalState.index + 1}/${approvalItems.length}`}
      subject={approvalPrompt.subject}
      body={approvalBodyShown}
      choices={approvalItems}
      activeIndex={approvalState.index}
      hint="↑↓ choose · enter confirm · esc decline"
      accent={approvalPrompt.borderColor}
      contentWidth={contentWidth}
      height={approvalBoxHeight}
      theme={theme}
    />
  ) : null;

  const overlaysNode = (
    <>
      {commandMenuNode}
      {secretNode}
      {pickerNode}
      {approvalNode}
    </>
  );
  // The hero overlays match the centered composer's width (the slash menu) and
  // sit in the anchored region directly above it, so opening the menu never
  // shifts the composer or the logo group.
  const heroOverlaysNode = (
    <>
      {heroCommandMenuNode}
      {secretNode}
      {pickerNode}
      {approvalNode}
    </>
  );

  const subagentNode = subagentBlockRows > 0 ? (
    <box flexDirection="column" width="100%" minWidth={0} height={subagentBlockRows} flexShrink={0} marginTop={1}>
      <box width={contentWidth} flexShrink={0} minWidth={0}>
        <text fg={MUTED}>{fitTuiText(`ACTIVE SUBAGENTS · ${subagentEntries.length}`, contentWidth)}</text>
      </box>
      {subagentVisible.map((sa) => {
        const running = sa.status === "running";
        const turnsInfo = sa.turns !== undefined ? ` (${sa.turns}/${sa.max_turns})` : "";
        const labelWidth = Math.max(1, contentWidth - 2 - turnsInfo.length);
        return (
          <box key={sa.agent_id} flexDirection="row" width={contentWidth} flexShrink={0} minWidth={0}>
            <text width={1} flexShrink={0} fg={running ? PRIMARY : WARNING}>{running ? "◉" : "◌"}</text>
            <box width={labelWidth} flexShrink={0} minWidth={0} marginLeft={1}>
              <text fg={TEXT}>{fitTuiText(sa.task, labelWidth)}</text>
            </box>
            {turnsInfo ? (
              <box width={turnsInfo.length} flexShrink={0} minWidth={0}>
                <text fg={MUTED}>{turnsInfo}</text>
              </box>
            ) : null}
          </box>
        );
      })}
      {subagentOverflowRow > 0 ? (
        <box width={contentWidth} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText(`  +${subagentOverflow} more · /agents to list them`, contentWidth)}</text>
        </box>
      ) : null}
    </box>
  ) : null;

  // The compact dim hint under the hero composer — keybind chords only. The
  // "type to chat · / commands" half is dropped: the composer placeholder above
  // already says it. Keys render white, labels muted (see KeyHints).
  const heroHintPairs: KeyHint[] = [
    { key: "shift+tab", label: "mode" },
    { key: "ctrl+p", label: "palette" },
  ];
  // The contextual keys shown in the bottom bar while composing plain text.
  const composeHintPairs: KeyHint[] = [
    { key: "enter", label: "send" },
    { key: "esc", label: "cancel" },
  ];
  // Any overlay open in the hero (slash menu, picker, an approval, the secret
  // prompt): the masthead is hidden so the tall menu + logo cannot overflow
  // upward into the header. The composer stays put — it is anchored by the
  // fixed bottom spacer regardless of what the region above it holds.
  const heroOverlayOpen = commandMenuVisible || Boolean(picker) || Boolean(approvalPrompt) || Boolean(secretPrompt);
  const showMasthead = !heroOverlayOpen;

  return (
    <box flexDirection="column" width="100%" height="100%" paddingLeft={compact ? 1 : 2} paddingRight={compact ? 1 : 2} paddingTop={1} backgroundColor={CANVAS}>
      {/*
        * flexShrink is disabled because this box is two stacked rows with
        * no explicit height: when the column is over-subscribed Yoga
        * collapses it to one row and the two lines overlap, which is how
        * "0sec / chat" bled into "target: none" as "target:cnone".
        */}
      {/*
        * ONE header row. It carries identity plus the two facts that are
        * security-relevant at a glance — the engagement target and the
        * scope state — and the autonomy mode on the right. Everything
        * environmental (model, cwd, branch, counters) moved to the bottom
        * bar, where it sits next to the input the operator is looking at.
        */}
      <box flexDirection="row" width="100%" minWidth={0} flexShrink={0} marginBottom={1} gap={1}>
        <box flexDirection="row" flexShrink={0} minWidth={0}>
          <text fg={PRIMARY}>0sec</text>
        </box>
        <box width={headerEngagementWidth} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText(headerEngagement, headerEngagementWidth, { mode: "middle" })}</text>
        </box>
        <box width={headerModeWidth} flexShrink={0} minWidth={0}>
          <text fg={modeColor}>{fitTuiText(modeLabel(mode), headerModeWidth)}</text>
        </box>
      </box>

      {empty ? (
        /*
         * The centered start screen: logo + captions + the COMPOSER + a dim
         * hint line render as ONE vertically-centered group (OpenCode's clean
         * hero). The composer here is the very same `composerNode` used at the
         * bottom in a real conversation — only its placement moves; the input
         * wiring is single-sourced in the module-level keyboard handler. Any
         * open overlay (slash menu, picker, an approval) sits directly above it,
         * exactly where it sits above the pinned composer. The bottom status bar
         * stays pinned below, outside this group.
         */
        <box flexDirection="column" flexGrow={1} minHeight={0} width="100%" minWidth={0} alignItems="center">
          {/*
            * Region A holds everything above the composer and is BOTTOM-anchored
            * (justifyContent flex-end). Region A and Region B both flexGrow={1},
            * so they split the vertical slack equally and the composer card sits
            * at the centre — a fixed position that does NOT move when the slash
            * menu opens: the menu is the last child of this bottom-anchored
            * region, so it appears directly above the composer and grows UPWARD
            * into the empty space, pushing the logo up rather than the composer
            * down. No layout jump on open/close.
            */}
          <box flexDirection="column" flexGrow={1} minHeight={0} width="100%" minWidth={0} justifyContent="flex-end" alignItems="center">
            {/*
              * The masthead: a muted EYEBROW (the lab name) sits ABOVE the block
              * mark, then the mark, then the tagline. Hidden entirely while an
              * overlay is open in the hero so the tall menu + logo cannot
              * overflow upward into the header (the composer stays anchored by
              * the fixed bottom spacer regardless).
              */}
            {showMasthead && showTerminalMark ? (
              <text fg={MUTED} marginBottom={1}>{fitTuiText("Swiss Applied AI Cybersecurity Research Lab", contentWidth, { mode: "middle" })}</text>
            ) : null}
            {showMasthead ? (
              showTerminalMark ? (
                <box flexDirection="column" width={TERMINAL_BLOCK_LOGO_WIDTH} minWidth={TERMINAL_BLOCK_LOGO_WIDTH} flexShrink={0}>
                  {/*
                    * 0sec brand mark: a slashed zero — a white "0" outline with a
                    * red diagonal slash through its hollow — then white "SEC".
                    * Each row is a sequence of same-colour runs (logoCellRuns)
                    * with explicit widths summing to TERMINAL_BLOCK_LOGO_WIDTH, so
                    * no run overflows and the slash keeps its own colour.
                    * Rendered verbatim — never through fitTuiText, which trims.
                    */}
                  {TERMINAL_BLOCK_LOGO.map((line, index) => (
                    <box key={`logo-${index}`} flexDirection="row" width={TERMINAL_BLOCK_LOGO_WIDTH} flexShrink={0} minWidth={0}>
                      {logoCellRuns(line).map((run, runIndex) => (
                        <text
                          key={`logo-${index}-${runIndex}`}
                          width={run.text.length}
                          flexShrink={0}
                          fg={run.kind === "/" ? ERROR : TEXT}
                        >{run.text}</text>
                      ))}
                    </box>
                  ))}
                </box>
              ) : (
                <box flexDirection="row" flexShrink={0}>
                  <text fg={TEXT}>0SEC · OPERATOR CONSOLE</text>
                </box>
              )
            ) : null}
            {showMasthead && showEmptyStateTagline ? (
              <text fg={TEXT} marginTop={1}>{fitTuiText("The open, extensible & self-evolving cybersecurity harness", contentWidth, { mode: "middle" })}</text>
            ) : null}
            {workingIndicator}
            {startupError ? <text fg={ERROR} marginTop={1}>{fitTuiText(startupError, contentWidth)}</text> : null}
            {heroOverlaysNode}
          </box>
          {/* The composer card — fixed vertical centre; the menu above never shifts it. */}
          <box flexDirection="column" width={heroComposerWidth} minWidth={0} flexShrink={0}>
            {heroComposerNode}
          </box>
          <box flexShrink={0} minWidth={0} marginTop={1}>
            {keyHintsLength(heroHintPairs, " · ") <= contentWidth ? (
              <KeyHints pairs={heroHintPairs} theme={theme} />
            ) : (
              <text fg={MUTED}>{fitTuiText("shift+tab mode · ctrl+p palette", contentWidth, { mode: "middle" })}</text>
            )}
          </box>
          {/* Region B: a FIXED spacer, so the composer's position is constant. */}
          <box height={heroBottomSpacer} flexShrink={0} minWidth={0} />
        </box>
      ) : (
        <>
          <box flexDirection="column" flexGrow={1} minHeight={0} width="100%" backgroundColor={PANEL} paddingX={compact ? 1 : 2} paddingY={1}>
            <scrollbox ref={transcriptRef} focusable={false} width="100%" flexGrow={1} minHeight={0} stickyScroll stickyStart="bottom">
              <box flexDirection="column" width="100%">
                {planTranscript(entries, entryDisplay.transcriptDetail).map((item) =>
                  item.type === "fold"
                    ? renderFold(item, transcriptWidth, entryDisplay, theme)
                    : renderEntry(item.entry, transcriptWidth, entryDisplay, theme),
                )}
                {workingIndicator}
                {startupError ? <text fg={ERROR}>{fitTuiText(startupError, contentWidth)}</text> : null}
              </box>
            </scrollbox>
          </box>

          {/*
            * Explicit height AND flexShrink={0}. Without both, opentui defaults
            * flexShrink to 1 for any box with no numeric width or height, so a
            * squeezed column collapsed this block to a single row while its
            * children kept painting. `subagentBlockRows` is the reserved count.
            */}
          {subagentNode}
          {overlaysNode}
          {stickyNode}
          {composerNode}
        </>
      )}

      {/*
        * The bottom bar is its own row BELOW the composer, not a second
        * line inside it. The composer's placeholder already says "type to
        * chat or / for commands"; repeating that verbatim underneath was
        * pure noise. What goes here instead is state the operator cannot
        * otherwise see — model, mode, working tree, counters — replaced by
        * contextual keys only while an overlay is actually open, when the
        * keys genuinely are the useful thing.
        */}
      {settings.showStatusBar ? (
        <box flexDirection="row" width="100%" minWidth={0} flexShrink={0} gap={statusGap}>
          <box width={controlsWidth} flexShrink={0} minWidth={0}>
            {showContextualKeys && keyHintsLength(composeHintPairs, " · ") <= controlsWidth ? (
              <KeyHints pairs={composeHintPairs} theme={theme} />
            ) : (
              <text fg={MUTED}>{fitTuiText(showContextualKeys ? controls : statusBarText, controlsWidth)}</text>
            )}
          </box>
          {statusWidth > 0 ? (
            <box width={statusWidth} flexShrink={0} minWidth={0}>
              <text fg={MUTED}>{fitTuiText(statusText, statusWidth, { mode: "middle" })}</text>
            </box>
          ) : null}
        </box>
      ) : null}
    </box>
  );
}
