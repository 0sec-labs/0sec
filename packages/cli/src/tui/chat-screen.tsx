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
import {
  ACCENT,
  BORDER,
  CANVAS,
  ERROR,
  INFO,
  MUTED,
  PANEL,
  PANEL_ALT,
  PRIMARY,
  SUCCESS,
  TEXT,
  WARNING,
} from "../ui/theme.js";
import { modelProvider } from "@0sec/shared";
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
import { listItemGutterWidth, renderMarkdown, type MdBlock, type MdSpan } from "./markdown.js";
import { GLYPH_CELLS, frameAt, frameIntervalMs, type AnimationKind } from "./animation.js";
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
  loadSettings,
  saveSettings,
  toggleSetting,
  type TuiSettings,
} from "./settings.js";
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

export type ChatDestination = "launcher" | "ops" | "history" | "findings" | "doctor" | "replay";


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
  /** Epoch ms the entry was appended, for relative timestamps. */
  at?: number;
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

const TERMINAL_BLOCK_LOGO = [
  " ██████   ███████  ███████   ██████  ",
  "██    ██  ██       ██       ██       ",
  "██    ██  ███████  █████    ██       ",
  "██    ██       ██  ██       ██       ",
  " ██████   ███████  ███████   ██████  ",
] as const;
const TERMINAL_BLOCK_LOGO_WIDTH = 37;

function modeLabel(mode: ConsoleAutonomyMode): string {
  if (mode === "standard") return "Standard";
  return mode === "copilot" ? "Co-pilot" : "YOLO";
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
}

/** Map a markdown span style onto the theme. */
function spanColor(style: MdSpan["style"], tone?: string): string {
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
function renderMarkdownBlocks(blocks: readonly MdBlock[], key: string, tone?: string) {
  return blocks.map((block, index) => {
    const id = `${key}-b${index}`;
    if (block.kind === "rule") {
      return <text key={id} fg={tone ?? MUTED}>{"─".repeat(8)}</text>;
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
            <text key={`${id}-${i}`} fg={tone ?? PRIMARY}>{line.map((span) => span.text).join("")}</text>
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
                  <text key={`${id}-${i}-${j}`} fg={spanColor(span.style, tone)}>{span.text}</text>
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
              <text key={`${id}-${i}-${j}`} fg={spanColor(span.style, blockTone)}>{span.text}</text>
            ))}
          </box>
        ))}
      </box>
    );
  });
}

function renderEntry(entry: ChatEntry, maxWidth: number, display: EntryDisplay) {
  const detailWidth = Math.max(20, maxWidth - 8);
  // A row that stands for several collapsed repeats says so. The count is
  // appended at render time and never written into `entry.text`, so the next
  // repeat still compares equal and keeps collapsing.
  const repeat = repeatSuffix(entry.repeat);
  if (entry.kind === "user") {
    return (
      <box key={entry.id} flexDirection="row" marginTop={display.spacing}>
        <box width={1} alignSelf="stretch" backgroundColor={ACCENT} />
        <box flexDirection="column" flexGrow={1} minWidth={0} marginLeft={1}>
          <text fg={ACCENT}>{`▌ operator${display.showTimestamps && relativeAge(entry.at, display.now) ? ` · ${relativeAge(entry.at, display.now)}` : ""}`}</text>
          <text fg={TEXT} wrapMode="word">{sanitizeTuiText(entry.text)}</text>
        </box>
      </box>
    );
  }

  if (entry.kind === "assistant") {
    return (
      <box key={entry.id} flexDirection="row" marginTop={display.spacing}>
        <box width={1} alignSelf="stretch" backgroundColor={PRIMARY} />
        <box flexDirection="column" flexGrow={1} minWidth={0} marginLeft={1}>
          <text fg={PRIMARY}>{`▌ 0sec${display.showTimestamps && relativeAge(entry.at, display.now) ? ` · ${relativeAge(entry.at, display.now)}` : ""}`}</text>
          {renderMarkdownBlocks(renderMarkdown(entry.text, Math.max(8, maxWidth - 2)), entry.id)}
        </box>
      </box>
    );
  }

  if (entry.kind === "tool") {
    const tone = entry.success === false ? ERROR : entry.success ? SUCCESS : PRIMARY;
    const state = entry.success === false ? "failed" : entry.success ? "complete" : "running";
    const icon = entry.success === false ? "×" : entry.success ? "✓" : "◌";
    // Icon, label and name are siblings on one row; the name must be
    // budgeted against the label's real length or the row overruns its
    // container and the renderer paints the columns into each other.
    const toolPrefix = ` evidence / tool · ${state} · `;
    return (
      <box key={entry.id} flexDirection="row" marginTop={display.spacing} marginLeft={maxWidth < 56 ? 0 : 2}>
        <box width={1} alignSelf="stretch" backgroundColor={tone} />
        <box flexDirection="column" flexGrow={1} minWidth={0} marginLeft={1}>
          <box flexDirection="row" minWidth={0}>
            <text fg={tone}>{icon}</text>
            <text fg={MUTED}>{toolPrefix}</text>
            <text fg={TEXT}>{fitTuiText(`${entry.text}${repeat}`, Math.max(1, detailWidth - toolPrefix.length - 1))}</text>
          </box>
          {entry.detail ? <text fg={MUTED} wrapMode="word">{fitTuiText(entry.detail, detailWidth)}</text> : null}
        </box>
      </box>
    );
  }

  if (entry.kind === "subagent") {
    const outcome = entry.subagentOutcome ?? "failed";
    const ok = outcome === "completed";
    const tone = ok ? SUCCESS : ERROR;
    const statusParts: string[] = [];
    if (entry.subagentTurns !== undefined) statusParts.push(`turns ${entry.subagentTurns}`);
    if (entry.subagentFindings !== undefined) statusParts.push(`findings ${entry.subagentFindings}`);
    const statusLine = statusParts.length > 0 ? statusParts.join(" · ") : null;

    return (
      <box key={entry.id} flexDirection="row" marginTop={display.spacing} marginLeft={maxWidth < 56 ? 0 : 2}>
        <box width={1} alignSelf="stretch" backgroundColor={tone} />
        <box flexDirection="column" flexGrow={1} minWidth={0} marginLeft={1}>
          <box flexDirection="row">
            <text fg={tone}>{ok ? "✓" : "×"}</text>
            <text fg={MUTED}> evidence / subagent · {ok ? "completed" : "failed"}</text>
          </box>
          {statusLine ? <text fg={MUTED}>{fitTuiText(statusLine, detailWidth)}</text> : null}
          {entry.subagentSummary ? <text fg={TEXT} wrapMode="word">{fitTuiText(entry.subagentSummary, detailWidth)}</text> : null}
          {entry.subagentError ? <text fg={ERROR} wrapMode="word">{fitTuiText(entry.subagentError, detailWidth)}</text> : null}
        </box>
      </box>
    );
  }

  if (entry.kind === "error") {
    // Failures get the same rail treatment as speech, in the error tone:
    // an operator must be able to see at a glance that the turn did not
    // produce an answer, and why.
    return (
      <box key={entry.id} flexDirection="row" marginTop={display.spacing} minWidth={0}>
        <box width={1} flexShrink={0} alignSelf="stretch" backgroundColor={ERROR} />
        <box flexDirection="column" flexGrow={1} minWidth={0} marginLeft={1}>
          <text fg={ERROR}>▌ {fitTuiText(`${entry.text}${repeat}`, Math.max(1, maxWidth - 3))}</text>
          {entry.detail ? (
            <text fg={MUTED} wrapMode="word">{fitTuiText(entry.detail, detailWidth)}</text>
          ) : null}
        </box>
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
  children,
}: {
  style: TuiSettings["composerStyle"];
  active: boolean;
  children: React.ReactNode;
}) {
  if (style === "border") {
    return (
      <box flexDirection="column" flexGrow={1} minWidth={0} flexShrink={0} border borderColor={active ? PRIMARY : BORDER} backgroundColor={PANEL_ALT} paddingX={1}>
        {children}
      </box>
    );
  }
  if (style === "rail") {
    return (
      <box flexDirection="column" flexGrow={1} minWidth={0} flexShrink={0} marginLeft={1} backgroundColor={PANEL_ALT}>
        {children}
      </box>
    );
  }
  return (
    <box flexDirection="column" flexGrow={1} minWidth={0} flexShrink={0}>
      {children}
    </box>
  );
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
}) {
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
  // Loaded once from disk; a failed read yields defaults rather than
  // blocking startup, so a corrupt settings file can never brick the TUI.
  const [settings, setSettings] = useState<TuiSettings>(() => loadSettings());
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
   * synchronously; `queuedCount` mirrors its length purely so the composer can
   * show the operator that the text went somewhere.
   */
  const queuedRef = useRef<string[]>([]);
  const [queuedCount, setQueuedCount] = useState(0);
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
  }, [setCommandMenuVisible]);

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
        title: "AUTHORIZE SESSION SCOPE",
        context: `${owner.request.call.name} requests ${owner.request.requestedUrls.join(", ")}`,
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
        title: "AUTHORIZE LOCAL DIRECTORY",
        context: `${owner.request.call.name} wants to read ${owner.request.requestedPath}`,
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
        title: "ENABLE ADDITIONAL TOOL",
        context: `${owner.request.call.name} — ${owner.request.reason}`,
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
        title: "CO-PILOT APPROVAL",
        context: `${owner.call.name} ${JSON.stringify(owner.call.arguments)}`,
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
            const restored = entriesFromStoredMessages(stored.messages);
            setEntries(restored);
            appendEntry({
              kind: "notice",
              text: restored.length > 0
                ? `— end of resumed session ${id} · new messages continue below —`
                : `resumed session ${id}`,
              detail: restored.length > 0
                ? `${stored.messageCount} prior message(s) restored. Everything above is replayed history, not new activity.`
                : `${stored.messageCount} prior message(s) restored, but none could be rendered. The model still has the history.`,
              turn: turn.current,
            });
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
      case "settings": {
        const openSettings = (live: TuiSettings) => {
          const values = live as unknown as Record<string, unknown>;
          const items: SelectorItem[] = SETTING_DEFS.map((def) => {
            const value = values[def.key];
            return {
              id: def.key,
              label: def.label,
              meta: typeof value === "boolean" ? (value ? "on" : "off") : String(value),
              detail: def.description,
            };
          });
          setPicker({
            state: createSelectorState("Console settings", items),
            commit: (key) => {
              const next = toggleSetting(live, key);
              setSettings(next);
              if (!saveSettings(next)) {
                appendEntry({
                  kind: "notice",
                  text: "settings changed for this session only",
                  detail: "The settings file could not be written.",
                  turn: turn.current,
                });
              }
              // Reopen against the updated values so the meta column shows
              // the new state immediately.
              openSettings(next);
            },
          });
        };
        openSettings(settings);
        return true;
      }
      case "model": {
        const requested = args.trim();
        if (!requested) {
          if (!session) {
            appendEntry({ kind: "notice", text: "runtime is not ready", turn: turn.current });
            return true;
          }
          // Deliberately NOT annotating each row with "no credentials".
          // The catalogue's provider comes from the pricing table, while
          // the runtime resolves a model's provider through its own
          // detection and failover order (`providerForModel`, which core
          // does not export). Those disagree — an OpenAI-named model can
          // in fact be served by the ChatGPT/Codex backend — so a per-row
          // verdict would flag working models as broken. Report only what
          // is verifiable: which providers hold credentials.
          const configured = providerStates(process.env)
            .filter((provider) => provider.configured)
            .map((provider) => provider.label);
          setPicker({
            state: createSelectorState(
              configured.length > 0
                ? `Select model · credentials: ${configured.join(", ")}`
                : "Select model · no provider credentials found",
              modelSelectorItems(modelId ?? undefined),
              modelId ?? undefined,
            ),
            commit: (id) => void routeSlashCommand(`/model ${id}`),
          });
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
              meta: "automatic in scope",
              detail: "Runs automatically inside scope; asks only to extend it.",
              current: mode === "standard",
            },
            {
              id: "copilot",
              label: "Co-pilot",
              meta: "approve each action",
              detail: "Asks before every non-read-only tool call.",
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
        if (modeArg !== "standard" && modeArg !== "copilot" && modeArg !== "yolo") {
          appendEntry({
            kind: "notice",
            text: "invalid mode",
            detail: "Use /mode standard, /mode copilot, or /mode yolo.",
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
          : modeArg === "copilot"
            ? "copilot"
            : "yolo";
        if (next === "yolo" && scopeRules.length === 0) {
          appendEntry({
            kind: "notice",
            text: "YOLO requires a configured scope; mode is unchanged",
            detail: "Use Standard or Co-pilot to approve a narrow session-only scope extension first.",
            turn: turn.current,
          });
          return true;
        }
        session.setAutonomyMode(next);
        setMode(next);
        const modeMeaning = next === "standard"
          ? "0sec works automatically inside scope and requests approval only for narrow session-only scope extensions."
          : next === "copilot"
            ? "0sec asks before each non-read-only tool and before narrow session-only scope extensions."
            : "0sec works without prompts only inside the configured scope; missing or out-of-scope work is denied.";
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
    setBusy(true);
    appendEntry({ kind: "user", text, turn: currentTurn });
    let assistantText = "";
    // Reasoning is a separate stream from the answer and gets its own
    // accumulator so the two never interleave into one entry.
    let reasoningText = "";
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
    setQueuedCount(rest.length);
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
      const cycle: ConsoleAutonomyMode[] = scopeRules.length === 0
        ? ["standard", "copilot"]
        : ["standard", "copilot", "yolo"];
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
          setQueuedCount(queue.length);
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

  const approvalDetail = approvalState ? highlighted(approvalState)?.detail ?? "" : "";
  const approvalPlan = selectorPanelBudget({
    budget: selectorBudget,
    hasContext: Boolean(approvalPrompt?.context),
    hasDetail: Boolean(approvalDetail),
  });
  const approvalVisible = approvalState ? visibleItems(approvalState) : [];
  const approvalWindow = approvalState
    ? windowFor(approvalState, approvalPlan.maxItemRows)
    : { start: 0, end: 0 };
  const approvalItemRows = approvalVisible.slice(approvalWindow.start, approvalWindow.end);
  const approvalBoxHeight = approvalPrompt
    ? selectorPanelHeight(approvalItemRows.length, approvalPlan.showContext, approvalPlan.showDetail)
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
  const entryDisplay = {
    spacing: settings.density === "compact" ? 0 : 1,
    showTimestamps: settings.showTimestamps,
    now: clockTick,
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
  // the box out from under its own children.
  const commandMenuHeight = commandMenuBoxHeight(menuCommands.length, commandRowsPerCommand);

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
  const showTerminalMark = settings.showLogo && empty && !compact && ledgerRows >= LEDGER_MARK_ROWS;
  const showEmptyStateHint = empty && ledgerRows >= 4;
  const showEmptyStateTagline = empty && ledgerRows >= 3;
  const sessionState = startupError ? "unavailable" : busy ? "working" : session ? "ready" : "connecting";
  const targetSummary = target ? `target: ${target}` : "target: none";
  const scopeSummary = `scope: ${scopeLabel} · ${sessionState}`;
  const headerEngagement = `${targetSummary} · ${scopeSummary}`;

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
  const modeColor = mode === "yolo" ? SUCCESS : mode === "copilot" ? INFO : PRIMARY;

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

      <box flexDirection="column" flexGrow={1} minHeight={0} width="100%" backgroundColor={PANEL} paddingX={compact ? 1 : 2} paddingY={1}>
        {/*
          * flexShrink={0}: this title shares the ledger box with a
          * flexGrow scrollbox. Without it a tight column collapses the
          * title to zero height while it still paints, so the transcript's
          * first visible row lands on top of it.
          */}
        <box flexDirection="row" width="100%" minWidth={0} flexShrink={0}>
          <text fg={MUTED}>EVIDENCE LEDGER</text>
          <text fg={MUTED}> · {empty ? "awaiting an objective" : `${entries.length} records`}</text>
        </box>
        <scrollbox width="100%" flexGrow={1} minHeight={0} stickyScroll stickyStart="bottom">
          <box flexDirection="column" width="100%">
            {empty ? (
              <box flexDirection="column" alignItems={showTerminalMark ? "center" : "flex-start"} paddingTop={showTerminalMark ? 3 : 1}>
                {showTerminalMark ? (
                  <box flexDirection="column" width={TERMINAL_BLOCK_LOGO_WIDTH} minWidth={TERMINAL_BLOCK_LOGO_WIDTH} flexShrink={0}>
                    {/* Row 0 and row 4 are identical, so the line cannot be the key. */}
                    {TERMINAL_BLOCK_LOGO.map((line, index) => <text key={`logo-${index}`} fg={PRIMARY}>{line}</text>)}
                  </box>
                ) : <text fg={PRIMARY}>0SEC · OPERATOR CONSOLE</text>}
                {showEmptyStateTagline ? <text fg={TEXT}>evidence-first security research</text> : null}
                {showEmptyStateHint ? <text fg={MUTED}>{fitTuiText("Describe an objective. 0sec enforces engagement scope before egress.", contentWidth)}</text> : null}
                {!compact && showTerminalMark ? <text fg={MUTED}>{fitTuiText("Type / for local commands. Standard works in scope; Co-pilot confirms active work; YOLO requires a configured scope.", contentWidth)}</text> : null}
              </box>
            ) : entries.map((entry) => renderEntry(entry, transcriptWidth, entryDisplay))}
            {animation ? (
              <box flexDirection="row" minWidth={0} marginTop={entryDisplay.spacing} gap={1}>
                {/* Rendered verbatim in a fixed-width cell: fitTuiText trims,
                    and every frame is exactly GLYPH_CELLS wide by contract. */}
                <box width={GLYPH_CELLS} flexShrink={0}>
                  <text fg={animationKind === "awaiting-operator" ? WARNING : PRIMARY}>{animation.glyph}</text>
                </box>
                <text fg={MUTED}>{animation.label}</text>
                {animation.elapsedLabel ? <text fg={MUTED}>{animation.elapsedLabel}</text> : null}
              </box>
            ) : null}
            {startupError ? <text fg={ERROR}>{fitTuiText(startupError, contentWidth)}</text> : null}
          </box>
        </scrollbox>
      </box>

      {/*
        * Explicit height AND flexShrink={0}. Without both, opentui defaults
        * flexShrink to 1 for any box with no numeric width or height (see
        * setupYogaProperties), so a squeezed column collapsed this block to
        * a single row while its children kept painting — which is how two
        * subagent tasks became one line of interleaved characters.
        * `subagentBlockRows` is the same count the ledger reserved.
        */}
      {subagentBlockRows > 0 ? (
        <box flexDirection="column" width="100%" minWidth={0} height={subagentBlockRows} flexShrink={0} marginTop={1}>
          <box width={contentWidth} flexShrink={0} minWidth={0}>
            <text fg={MUTED}>{fitTuiText(`ACTIVE SUBAGENTS · ${subagentEntries.length}`, contentWidth)}</text>
          </box>
          {subagentVisible.map((sa) => {
            const running = sa.status === "running";
            const turnsInfo = sa.turns !== undefined ? ` (${sa.turns}/${sa.max_turns})` : "";
            // Budget against the marker cell, its gap and the counter text.
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
      ) : null}

      {commandMenuVisible ? (
        <box flexDirection="column" width="100%" minWidth={0} height={commandMenuHeight} flexShrink={0} marginTop={1} border borderColor={PRIMARY} backgroundColor={PANEL_ALT} paddingX={1}>
          <box flexDirection="row" width={commandMenuInnerWidth} minWidth={0} gap={commandHeaderGap}>
            <box width={commandHeaderTitleWidth} flexShrink={0} minWidth={0}>
              <text fg={PRIMARY}>{fitTuiText("COMMANDS", commandHeaderTitleWidth)}</text>
            </box>
            {commandHeaderQueryWidth > 0 ? (
              <box width={commandHeaderQueryWidth} flexShrink={0} minWidth={0}>
                <text fg={MUTED}>{fitTuiText(slashQuery ? `/${slashQuery}` : "all commands", commandHeaderQueryWidth, { mode: "middle" })}</text>
              </box>
            ) : null}
          </box>
          {menuCommands.length > 0 ? menuCommands.map((command, index) => {
            const active = index === slashSelected;
            const meta = command.aliases.length > 0
              ? command.aliases.map((alias) => `/${alias}`).join(" ")
              : command.category;
            return (
              <box key={command.name} flexDirection="row" width={commandMenuInnerWidth} minWidth={0}>
                <text width={1} flexShrink={0} fg={active ? PRIMARY : MUTED}>{active ? "›" : " "}</text>
                <box flexDirection="column" width={commandRowWidth} flexGrow={0} flexShrink={0} minWidth={0} marginLeft={1}>
                  <box flexDirection="row" width={commandRowWidth} minWidth={0} gap={1}>
                    <box width={commandNameWidth} flexShrink={0} minWidth={0}>
                      <text fg={active ? TEXT : MUTED}>{fitTuiText(`/${command.name}`, commandNameWidth)}</text>
                    </box>
                    {commandMetaWidth > 0 ? (
                      <box width={commandMetaWidth} flexShrink={0} minWidth={0}>
                        <text fg={active ? ACCENT : MUTED}>{fitTuiText(meta, commandMetaWidth)}</text>
                      </box>
                    ) : null}
                  </box>
                  {!compact ? (
                    <box width={commandRowWidth} minWidth={0}>
                      <text fg={active ? ACCENT : MUTED} wrapMode="word">{fitTuiText(command.description, commandRowWidth)}</text>
                    </box>
                  ) : null}
                </box>
              </box>
            );
          }) : <text fg={ERROR}>{fitTuiText(`No command matches /${slashQuery}`, Math.max(1, commandMenuInnerWidth))}</text>}
          <text fg={MUTED}>{fitTuiText("↑↓ select · tab complete · enter run · esc close", Math.max(1, commandMenuInnerWidth))}</text>
        </box>
      ) : null}

      {/*
        * The masked credential field is the ONE prompt that stays a typed
        * panel: a secret is entered, not chosen from a list. It gets the
        * same anti-collapse treatment as everything else in this column —
        * an explicit height matching its four content lines plus the two
        * border rows, flexShrink disabled, and every child budgeted to a
        * fixed cell width so no line can reach the border.
        */}
      {secretPrompt ? (
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
      ) : null}

      {picker ? (
        <SelectorPanel
          title={picker.state.title}
          subtitle={picker.state.query ? picker.state.query : `${pickerVisible.length} available`}
          rows={pickerRows}
          windowStart={pickerWindow.start}
          activeIndex={picker.state.index}
          detail={pickerPlan.showDetail ? pickerDetail : undefined}
          hint="↑↓ select · type to filter · enter apply · esc cancel"
          emptyText={`no match for "${picker.state.query}"`}
          borderColor={PRIMARY}
          titleColor={PRIMARY}
          contentWidth={contentWidth}
          height={pickerBoxHeight}
        />
      ) : null}

      {/*
        * Authorization prompts live directly above the composer rather than
        * as a centered overlay. The operator's eyes are already on the input
        * line, the answer is given there, and an in-flow panel cannot cover
        * the transcript evidence the decision is based on.
        *
        * All four prompts — session scope, local directory, scoped-audit
        * escalation and the Co-pilot tool gate — render through the SAME
        * component and the SAME selector reducer as /model and /mode. One
        * decision surface, one code path, one set of key bindings. Esc
        * always declines; it can never grant.
        */}
      {approvalPrompt && approvalState ? (
        <SelectorPanel
          title={approvalPrompt.title}
          subtitle={`${approvalState.index + 1}/${approvalVisible.length}`}
          context={approvalPlan.showContext ? approvalPrompt.context : undefined}
          contextColor={TEXT}
          rows={approvalItemRows}
          windowStart={approvalWindow.start}
          activeIndex={approvalState.index}
          detail={approvalPlan.showDetail ? approvalDetail : undefined}
          hint="↑↓ choose · enter confirm · esc decline"
          emptyText="no choice available"
          borderColor={approvalPrompt.borderColor}
          titleColor={approvalPrompt.titleColor}
          contentWidth={contentWidth}
          height={approvalBoxHeight}
        />
      ) : null}

      {/*
        * The composer frame is a preference, not a hardcode: "border" draws
        * the box, "rail" replaces it with a single accent column, "plain"
        * drops the chrome entirely for operators who want maximum rows.
        */}
      <box flexDirection="row" width="100%" flexShrink={0} marginTop={1} minWidth={0}>
        {settings.composerStyle === "rail" ? (
          <box width={1} flexShrink={0} alignSelf="stretch" backgroundColor={composing ? PRIMARY : BORDER} />
        ) : null}
      {/*
        * Two separate elements rather than `border={...}` on one: opentui
        * draws the frame whenever the `border` prop is present, so
        * `border={false}` still renders a box. Branching on the element
        * keeps "no chrome" actually meaning no chrome.
        */}
      <ComposerFrame style={settings.composerStyle} active={composing || commandMenuVisible}>
        <box flexDirection="row" width="100%" minWidth={0}>
          <text width={1} flexShrink={0} fg={PRIMARY}>›</text>
          <text width={1} flexShrink={0} fg={MUTED}> </text>
          <box width={composerTextWidth} flexShrink={0} minWidth={0}>
            <text fg={TEXT}>{composing
              ? `${fitTuiText(composer || " ", composerTextWidth - 1, { mode: "middle" })}█`
              : startupError
                ? fitTuiText("runtime unavailable", composerTextWidth)
                : animation
                  // The frame already carries its own state word and elapsed
                  // time, so the composer echoes it rather than inventing a
                  // second, possibly contradictory, status string.
                  ? fitTuiText(`${animation.glyph} ${animation.label}${animation.elapsedLabel ? ` ${animation.elapsedLabel}` : ""}${queueLabel ? ` · ${queueLabel}` : ""}`, composerTextWidth)
                  : fitTuiText("type to chat or / for commands", composerTextWidth)}</text>
          </box>
        </box>
      </ComposerFrame>
      </box>

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
            <text fg={MUTED}>{fitTuiText(showContextualKeys ? controls : statusBarText, controlsWidth)}</text>
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
