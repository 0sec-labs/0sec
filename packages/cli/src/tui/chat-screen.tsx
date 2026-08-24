/** @jsxImportSource @opentui/react */
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  useKeyboard,
  useRenderer,
  useTerminalDimensions,
} from "@opentui/react";
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
  type OperatorQuestionRequest,
  type OperatorQuestionAnswer,
  type SubagentLifecyclePayload,
  type TodosEventPayload,
  type SessionObjectivePayload,
  type ToolCall,
} from "@0sec/core";
import type { ScrollBoxRenderable } from "@opentui/core";
import {
  useSettings,
  updateSetting,
  previewSetting,
  reloadSettings,
} from "./settings-store.js";
import { useTheme, type Theme } from "./theme-context.js";
import { modelProvider } from "@0sec/shared";
import { homedir } from "node:os";
import {
  readGitStatus,
  type GitStatus,
} from "./git-status.js";
import {
  buildStatusSegments,
  fitStatusSegments,
  fitStatusPills,
  pillText,
  type StatusSegment,
  type StatusColorRole,
} from "./status-bar.js";
import { SHIMMER_TEXT_INTERVAL_MS } from "./animations.js";
import { ShimmerText } from "./chat/shimmer.js";
import {
  createSelectorState,
  highlighted,
  reduceSelector,
  visibleItems,
  windowFor,
  type SelectorItem,
  type SelectorState,
} from "./selector.js";
import { appendFeedback } from "./feedback.js";
import {
  formatToolArgs,
  formatToolResult,
} from "./tool-format.js";
import {
  listSessions,
  loadSession,
  pruneSessions,
  relativeAge,
  saveSession,
  type StoredSessionMeta,
} from "./session-store.js";
import type { SessionPluginHostManager } from "./session-plugin-host.js";
import { reportOperatorGate } from "../herdr-state.js";
import {
  GLYPH_CELLS,
  frameAt,
  frameIntervalMs,
  type AnimationKind,
} from "./animation.js";
import {
  PROVIDERS,
  providerStates,
} from "./provider-status.js";
import {
  credentialEnvPatch,
  loadCredentials,
  redactSecret,
  saveCredentials,
} from "./credential-store.js";
import { VERSION } from "@0sec/shared";
import {
  type TuiSettings,
} from "./settings.js";
import {
  pushHistory,
  recallNext,
  recallPrev,
} from "./composer-history.js";
import {
  buildHelpPanel,
  buildScopePanel,
  buildStatusPanel,
  buildToolsPanel,
} from "./panels.js";
import { fitTuiText } from "./text.js";
import { severityToneFor, THEME_NAMES, getThemeEntry, isThemeName } from "./themes.js";
import {
  parseSubagentCard,
  reduceActiveSubagents,
} from "./subagent-card.js";
import { onTuiOutputLine } from "./output-guard.js";
import {
  COMPOSER_QUEUE_LIMIT,
  classifyComposerInput,
  composerQueueLabel,
  dequeueComposerInput,
  enqueueComposerInput,
  shouldFlushQueuedInput,
} from "./composer-queue.js";
import {
  LEDGER_MARK_ROWS,
  clampAgentSelection,
  commandMenuBoxHeight,
  commandMenuWindowStart,
  computeChatLayout,
  computeSidebarsLayout,
  computeCommandMenuHeight,
  computeCommandMenuLayout,
  computeLedgerRows,
  moveAgentSelection,
} from "./chat-layout.js";
import {
  applySubagentLifecycle,
  applySubagentProgress,
  clipDetailLines,
  computeHerdFocusLayout,
  focusHeaderLines,
  herdFocusTranscriptTitle,
  renderFocusActivity,
  shellChromeRows,
  subagentPeers,
  windowFocusTail,
  HERD_FOCUS_EMPTY_TEXT,
  type HerdSubagentMap,
} from "./herd-layout.js";
import {
  computeLogoFrame,
  logoAnimationFrameCount,
  logoAnimationLoops,
} from "./logo-animation.js";
import {
  buildOperatorAnswer,
  createOperatorQuestionState,
  operatorActiveDisplayIndex,
  operatorActiveRow,
  operatorAppend,
  operatorBackspace,
  operatorHasOptions,
  operatorMove,
  operatorToggle,
  planOperatorRows,
  type OperatorDisplayRow,
  type OperatorQuestionState,
} from "./operator-question.js";
import {
  SLASH_COMMANDS,
  filterCommands,
  findCommand,
  type SlashCommand,
} from "./slash-commands.js";
import {
  deletePreviousWord,
  deleteToLineStart,
} from "./composer-edit.js";
import { appendTranscriptEntry } from "./transcript.js";
import {
  planTranscript,
  resolveTranscriptStyleSettings,
} from "./transcript-style.js";
import { useSelectionCopy, type SelectionCopyFn } from "./use-selection-copy.js";
import { useToast, Toast } from "./toast.js";
import {
  copyToClipboard,
  defaultSpawn,
  defaultWhich,
} from "./clipboard.js";
import type {
  ChatEntry,
  EntryDisplay,
  KeyHint,
} from "./chat/types.js";
import {
  TERMINAL_BLOCK_LOGO,
  TERMINAL_BLOCK_LOGO_WIDTH,
  LOGO_FRAME_INTERVAL_MS,
} from "./chat/logo.js";
import {
  modeLabel,
  modeColorFor,
  herdToneColor,
  completionFor,
  commandMatchesPrefix,
  buildScopeResolution,
} from "./chat/helpers.js";
import {
  renderEntry,
  renderFold,
} from "./chat/TranscriptEntry.js";
import { Todos, TodosSidebar } from "./chat/Todos.js";
import { FindingsSidebar, FINDINGS_SIDEBAR_HEADER_ROWS } from "./chat/FindingsSidebar.js";
import { ComposerFrame, ComposerInput } from "./chat/Composer.js";
import {
  KeyHints,
  keyHintsLength,
} from "./chat/KeyHints.js";
import {
  SelectorPanel,
  selectorPanelBudget,
  selectorPanelHeight,
} from "./chat/SelectorPanel.js";
import {
  ApprovalCard,
  approvalCardRows,
  argumentSummaryLines,
  APPROVAL_GRANT_ID,
  APPROVAL_DENY_ID,
  type ApprovalPrompt,
} from "./chat/ApprovalCard.js";
import { OperatorQuestionCard } from "./chat/OperatorQuestionCard.js";
import { Masthead } from "./chat/Masthead.js";
import { CommandMenu } from "./chat/CommandMenu.js";
import {
  AGENT_SIDEBAR_ROWS,
  AgentSidebarRow,
  AgentTreeRow,
  shortAgentName,
  type AgentRowView,
} from "./chat/AgentRow.js";

export type ChatDestination = "launcher" | "ops" | "history" | "findings" | "doctor" | "replay" | "settings" | "models" | "market" | "usage" | "connect" | "finding" | "resume";

/**
 * Map a status pill's semantic colour role onto the live palette. Kept theme-
 * aware here (status-bar.ts is pure/theme-free): each band gets its own colour so
 * the bar reads as segmented OMP-style pills. `mode` resolves through
 * `modeColorFor` so the mode colour is IDENTICAL to the header and the turn
 * footer (Co-pilot purple, YOLO red, Recon blue, Standard neutral). The only red
 * ever produced is YOLO's, honouring the "red = errors/failures" invariant — a
 * dirty tree is WARNING (amber), not red.
 */
/**
 * The display-only `ToolResult.meta` sidecar (never seen by the model) a tool
 * may attach — bash / run_command → a command card, apply_patch → an edit card.
 * Typed structurally so this module needs no extra core-type import.
 */
interface ToolCardMeta {
  kind?: "command" | "edit" | "web";
  command?: string;
  exitCode?: number | null;
  durationMs?: number;
  timeoutMs?: number;
  timedOut?: boolean;
  stdout?: string;
  path?: string;
  added?: number;
  removed?: number;
  diff?: string;
  provider?: string;
  query?: string;
  answer?: string;
  sources?: Array<{ title?: string; url: string; age?: string }>;
}

/**
 * Map a tool result's display-only `meta` sidecar onto the rich-card fields of
 * a `ChatEntry`, for BOTH a live turn and a restored one. Returns an empty
 * object when there is no card to draw, so a spread leaves the entry untouched.
 */
function toolCardFieldsFromMeta(meta: ToolCardMeta | undefined): Partial<ChatEntry> {
  if (!meta || (meta.kind !== "command" && meta.kind !== "edit" && meta.kind !== "web")) return {};
  if (meta.kind === "command") {
    return {
      metaKind: "command",
      command: meta.command,
      commandOutput: meta.stdout,
      exitCode: meta.exitCode ?? null,
      wallMs: meta.durationMs,
      timeoutMs: meta.timeoutMs,
      timedOut: meta.timedOut,
    };
  }
  if (meta.kind === "web") {
    return {
      metaKind: "web",
      webProvider: meta.provider,
      webQuery: meta.query,
      webAnswer: meta.answer,
      webSources: meta.sources,
    };
  }
  return {
    metaKind: "edit",
    editPath: meta.path,
    editAdded: meta.added,
    editRemoved: meta.removed,
    editDiff: meta.diff,
  };
}

/**
 * Reconstruct a rich card's `ChatEntry` fields from a SERIALIZED tool result
 * (a restored session). The display-only `meta` is gone (it never reached the
 * model transcript), so a command card recovers only its command + output, and
 * an edit card its path / +/- counts / hunk diff from the patch envelope. No
 * wall or timeout footer survives a restore.
 */
function restoredToolCardFields(
  name: string,
  input: unknown,
  content: unknown,
  success: boolean,
): Partial<ChatEntry> {
  const args = input && typeof input === "object" ? (input as Record<string, unknown>) : {};
  if (name === "bash" || name === "run_command") {
    const command = typeof args.command === "string" ? args.command.trim() : undefined;
    if (!command) return {};
    return {
      metaKind: "command",
      command,
      commandOutput: typeof content === "string" ? content : undefined,
      exitCode: success ? 0 : 1,
      timedOut: false,
    };
  }
  if (name === "apply_patch") {
    const patch = typeof args.patch === "string" ? args.patch : undefined;
    if (!patch) return {};
    let added = 0;
    let removed = 0;
    const diffLines: string[] = [];
    const paths: string[] = [];
    for (const line of patch.split("\n")) {
      const fileMatch = /^\*\*\* (?:Update|Add|Delete|Replace) File: (.+)$/.exec(line);
      if (fileMatch) {
        if (!paths.includes(fileMatch[1])) paths.push(fileMatch[1]);
        continue;
      }
      if (line.startsWith("*** ") || line.startsWith("@@")) continue;
      if (line.startsWith("+")) {
        added += 1;
        diffLines.push(line);
      } else if (line.startsWith("-")) {
        removed += 1;
        diffLines.push(line);
      } else {
        diffLines.push(line);
      }
    }
    return {
      metaKind: "edit",
      editPath: paths.length > 0 ? paths.join(", ") : "(patch)",
      editAdded: added,
      editRemoved: removed,
      editDiff: diffLines.join("\n").trim(),
    };
  }
  return {};
}

function statusRoleColor(
  role: StatusColorRole,
  theme: Theme,
  mode: ConsoleAutonomyMode,
): string {
  switch (role) {
    case "model":
      return theme.PRIMARY;
    case "mode":
      return modeColorFor(mode, theme);
    case "cwd":
      return theme.INFO;
    case "branch":
      return theme.BRAND;
    case "dirty":
      return theme.WARNING;
    case "tokens":
      return theme.INFO;
    case "cost":
      return theme.SUCCESS;
    case "context":
      return theme.ACCENT;
    case "effort":
    case "plan":
    default:
      return theme.MUTED;
  }
}


export interface ChatScreenOptions {
  target?: string;
  scope?: ScopePolicy;
  model?: string;
  role?: "discovery" | "attack" | "verify" | "report" | "audit" | "review";
  maxToolIterations?: number;
  allowScanners?: boolean;
  autonomyMode?: ConsoleAutonomyMode;
  /**
   * A stored session's transcript to resume into on mount — the full-screen
   * resume browser (run.tsx ResumeRoute) opens the chat with these, so the new
   * ChatScreen builds its console around the restored history and rehydrates the
   * transcript. Absent for a fresh chat.
   */
  initialMessages?: NativeMessage[];
}

export interface ChatScreenProps {
  options?: ChatScreenOptions;
  onGoBack: () => void;
  onNavigate: (destination: ChatDestination, id?: string) => void;
  onExit: () => void;
  /**
   * A handle the coordinator populates with a function that submits an operator
   * message into the SAME composer-submit path a typed message takes (queue if a
   * turn is in flight, otherwise send). Used by the finding-detail overlay's
   * "Fix" action to route the fix intent through a normal agent turn without
   * reaching into core tools. Null while the chat is unmounted.
   */
  submitHandle?: React.MutableRefObject<((text: string) => void) | null>;
  /**
   * The shell-level plugin-host manager, if the shell wired one. Its `current()`
   * host is handed to the console session so ENABLED marketplace plugins'
   * tools are available in chat. This screen subscribes to the manager's
   * onChanged and rebuilds its session IN PLACE — carrying the transcript, like
   * /model — so a plugin enabled in the market takes effect WITHOUT wiping the
   * live engagement. Absent → no plugin tools (the default).
   */
  pluginHostManager?: SessionPluginHostManager;
}


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
 * A pending `ask_operator` question. It authorizes NOTHING — it is the model
 * asking the human for a decision/value — so it lives apart from the approval
 * gates above and resolves an {@link OperatorQuestionAnswer} (or `null` when the
 * operator dismisses it with Esc).
 */
type PendingOperatorQuestion = {
  request: OperatorQuestionRequest;
  resolve: (answer: OperatorQuestionAnswer | null) => void;
};


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
          // Carry the argument one-liner too (as a live turn does), so a
          // restored session's `save_finding` calls feed the findings sidebar.
          toolArgs: formatToolArgs({ name, arguments: call?.input }),
          success,
          turn: 0,
          // Rebuild the rich-card fields from the serialized transcript. The
          // display-only `meta` was never serialized (it never reaches the
          // model), so a restored card carries only what the model transcript
          // holds — the command + its output, or the patch envelope — and no
          // wall/timeout footer.
          ...restoredToolCardFields(name, call?.input, b.content, success),
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

/** A finding surfaced this run: a title, a normalised severity, and — when the
 * `save_finding` result reported one — the persisted finding id so the sidebar
 * row can open the full detail view. */
export interface RunFinding {
  title: string;
  severity: string;
  /** Persisted finding id, when the tool result carried one. */
  id?: string;
}

/**
 * This run's findings, read from the transcript itself: every successful
 * `save_finding` tool call, newest last. The argument one-liner is
 * `"<severity> <category>: <title>"` (see tool-format), so the leading word is
 * the severity and the text after the colon is the title. Deriving from the
 * entries the screen already holds means the right sidebar needs no new event
 * plumbing and works identically for a live turn and a restored session.
 */
export function runFindingsFromEntries(entries: readonly ChatEntry[]): RunFinding[] {
  const out: RunFinding[] = [];
  for (const entry of entries) {
    if (entry.kind !== "tool" || entry.text !== "save_finding") continue;
    if (entry.success === false) continue;
    const raw = (entry.toolArgs ?? entry.detail ?? "").trim();
    if (!raw) continue;
    const colon = raw.indexOf(": ");
    const head = colon >= 0 ? raw.slice(0, colon) : "";
    const title = (colon >= 0 ? raw.slice(colon + 2) : raw).trim();
    const severity = (head.split(/\s+/)[0] || "info").toLowerCase();
    // The formatted result one-liner is "saved <id>" (see tool-format.ts), so
    // the persisted id can be recovered without new event plumbing. Missing on
    // a restored session whose result text was not stored — the row then falls
    // back to a non-clickable entry.
    const idMatch = (entry.detail ?? "").match(/^saved\s+(\S+)/);
    out.push({ title: title || "(untitled finding)", severity, id: idMatch?.[1] });
  }
  return out;
}

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

/** Window after a first Ctrl+C in which a second Ctrl+C confirms the quit. */
const EXIT_CONFIRM_MS = 3000;

export function ChatScreen({ options, onGoBack, onNavigate, onExit, submitHandle, pluginHostManager }: ChatScreenProps) {
  const [entries, setEntries] = useState<ChatEntry[]>([]);
  const entriesRef = useRef<ChatEntry[]>([]);
  entriesRef.current = entries;
  const [session, setSession] = useState<ConsoleSession | null>(null);
  const [modelId, setModelId] = useState<string | null>(null);
  const [git, setGit] = useState<GitStatus | null>(null);
  const [clockTick, setClockTick] = useState(() => Date.now());
  const [animTick, setAnimTick] = useState(0);
  /**
   * One shared frame counter for the loading shimmer, ticked at
   * `SHIMMER_TEXT_INTERVAL_MS` while a turn is running (see the effect below).
   * The thinking indicator and every running tool/subagent row read the SAME
   * frame, so their sweeps stay in phase; it is only advanced when there is
   * something to shimmer, so an idle console costs no repaints.
   */
  const [shimmerFrame, setShimmerFrame] = useState(0);
  /** Frame counter for the empty-state logo intro; driven by the ticker below. */
  const [logoFrame, setLogoFrame] = useState(0);
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
    BRAND,
    PANEL,
    PANEL_ALT,
    CANVAS,
    BORDER,
  } = theme;
  // The OpenTUI renderer, for the OSC-52 clipboard path (copy-on-highlight).
  // OpenTUI owns the framebuffer, so the terminal's native mouse-selection is
  // off; we re-add copy-on-highlight ourselves and must never touch raw stdout.
  const renderer = useRenderer();
  // The transient "Copied N bytes" pill. reduceMotion collapses its fade to a
  // single appear/dismiss (the toast module honours the flag).
  const { showToast, frame: toastFrame } = useToast({ reduceMotion: settings.reduceMotion });
  /**
   * Clipboard writer for copy-on-highlight.
   *
   * The renderer exposes `copyToClipboardOSC52(text)` — its own SAFE OSC-52
   * writer: it builds the escape sequence AND writes it through the renderer's
   * output path (never process.stdout), returning whether the terminal
   * accepted it. That is a different shape from clipboard.ts's `emit` (which
   * takes a PRE-BUILT sequence and returns void), so we adapt it as a `copy`
   * instead: OSC-52 via the renderer when supported, otherwise the platform
   * subprocess (defaultSpawn/defaultWhich, forwarded by the hook). Every branch
   * is feature-detected and swallows failure, so a renderer without the API —
   * or a host with no clipboard tool — degrades to "no copy", never a crash.
   */
  const copySelection = useCallback<SelectionCopyFn>((text, opts) => {
    const bytes = Buffer.byteLength(text, "utf8");
    try {
      if (
        renderer &&
        typeof renderer.isOsc52Supported === "function" &&
        renderer.isOsc52Supported() &&
        typeof renderer.copyToClipboardOSC52 === "function" &&
        renderer.copyToClipboardOSC52(text)
      ) {
        return Promise.resolve({ ok: true, method: "osc52", bytes });
      }
    } catch {
      // Fall through to the subprocess path below.
    }
    return copyToClipboard(text, {
      spawn: opts?.spawn,
      which: opts?.which,
      platform: opts?.platform,
      osc52: opts?.osc52,
    });
  }, [renderer]);
  useSelectionCopy({
    copy: copySelection,
    spawn: defaultSpawn,
    which: defaultWhich,
    onCopied: ({ bytes }) => showToast(`Copied ${bytes} bytes`),
  });
  /**
   * Per-turn transcript expansion. In collapsed mode each turn's successful
   * tool/reasoning steps fold to one ▸ line; clicking that line adds the turn
   * here so `planTranscript` renders it in full (and the steps show a ▾
   * affordance whose click removes it again). Independent of the global Ctrl+R
   * detail toggle, which flips every turn at once via the settings store.
   */
  const [expandedTurns, setExpandedTurns] = useState<Set<number>>(() => new Set());
  /** The turn currently under the mouse, for the subtle hover highlight. */
  const [hoveredTurn, setHoveredTurn] = useState<number | null>(null);
  const toggleTurnExpanded = useCallback((turn: number) => {
    setExpandedTurns((prev) => {
      const next = new Set(prev);
      if (next.has(turn)) next.delete(turn);
      else next.add(turn);
      return next;
    });
  }, []);
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
    {
      state: SelectorState;
      commit: (id: string) => void;
      // Live preview as the highlight moves (e.g. /theme repaints the console);
      // onCancel reverts a preview when the picker is dismissed with Esc.
      onHighlight?: (id: string) => void;
      onCancel?: () => void;
    } | null
  >(null);
  const pickerRef = useRef(picker);
  pickerRef.current = picker;
  // Fire onHighlight whenever the highlighted row changes (incl. on open), so a
  // picker can preview the highlighted choice without committing it.
  const pickerHighlightId = picker ? highlighted(picker.state)?.id : undefined;
  useEffect(() => {
    if (pickerHighlightId) pickerRef.current?.onHighlight?.(pickerHighlightId);
  }, [pickerHighlightId]);
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
  const [pendingOperatorQuestion, setPendingOperatorQuestion] = useState<PendingOperatorQuestion | null>(null);
  /**
   * Live edit state for the `ask_operator` modal (cursor, selections, custom
   * text). Reset from the pending request whenever a new question arrives; the
   * keyboard handler mutates it through the pure operator-question reducers.
   */
  const [operatorState, setOperatorState] = useState<OperatorQuestionState | null>(null);
  const [activeSubagents, setActiveSubagents] = useState<Record<string, SubagentLifecyclePayload>>({});
  /**
   * Two-press quit. Ctrl+C used to exit immediately; now the first press ARMS
   * (a toast warns, noting any running subagents that would be stopped) and a
   * second Ctrl+C within the window actually quits. Ref-based so the many
   * keyboard branches can call it without re-subscribing the handler.
   */
  const exitArmedRef = useRef(0);
  const requestExit = useCallback((cleanup?: () => void) => {
    const now = Date.now();
    if (now - exitArmedRef.current < EXIT_CONFIRM_MS) {
      cleanup?.();
      onExit();
      return;
    }
    exitArmedRef.current = now;
    const running = Object.keys(activeSubagents).length;
    showToast(
      running > 0
        ? `Press Ctrl+C again to quit — ${running} subagent${running === 1 ? "" : "s"} will be stopped`
        : "Press Ctrl+C again to quit",
    );
  }, [onExit, showToast, activeSubagents]);
  const requestExitRef = useRef(requestExit);
  requestExitRef.current = requestExit;
  /** Latest plan snapshot from the `update_todos` tool (the `todos` bus event). */
  const [todos, setTodos] = useState<TodosEventPayload | null>(null);
  // The OMP-style "what am I working on" objective for the bottom-bar pill.
  // Empty ("") hides the pill; the session-objective service replaces it in
  // place (heuristic first, model-refined when/if it lands).
  const [objective, setObjective] = useState<string>("");
  // Read the latest objective from `send`'s finally (which is a useCallback and
  // would otherwise close over a stale value) without re-subscribing it.
  const objectiveRef = useRef(objective);
  objectiveRef.current = objective;
  /**
   * The richer live-subagent model the herd view is built on: latest snapshot
   * plus a bounded activity ring per agent, keyed by `agent_id`, fed by the SAME
   * pure reducers herd-layout exposes. This is the single source for BOTH the
   * right rail and the inline focus view, so neither reimplements the plumbing.
   */
  const [herdAgents, setHerdAgents] = useState<HerdSubagentMap>({});
  /**
   * Recent resumable sessions for the LEFT sidebar's "SESSIONS" block. Loaded
   * from the on-disk session store (a directory read), refreshed whenever the
   * live session changes — a new turn saves the transcript, so the listing
   * should pick the current run up once it exists.
   */
  const [recentSessions, setRecentSessions] = useState<StoredSessionMeta[]>([]);
  /**
   * Active-subagent navigation from the composer. -1 means the composer has
   * focus; >= 0 selects a row in the ACTIVE SUBAGENTS block. Entered with Down
   * on an empty composer (only when agents are running), left with Left/Esc.
   */
  const [agentNavIndex, setAgentNavIndex] = useState(-1);
  /**
   * The subagent the operator drilled INTO, or null in list/composer mode. When
   * set, the transcript region is replaced by the inline focus view (the same
   * live meta + activity panes the herd screen's focus mode renders).
   */
  const [focusAgentId, setFocusAgentId] = useState<string | null>(null);
  /** How far the inline focus transcript is scrolled back from its tail. */
  const [focusScrollOffset, setFocusScrollOffset] = useState(0);
  const { width, height } = useTerminalDimensions();
  const alive = useRef(true);
  // Mirror the latest render values so the plugin-host effect can rebuild the
  // session in place without re-subscribing on every state change.
  const sessionRef = useRef(session);
  sessionRef.current = session;
  const busyRef = useRef(busy);
  busyRef.current = busy;
  const modelIdRef = useRef(modelId);
  modelIdRef.current = modelId;
  const pendingHostRebuild = useRef(false);
  const turn = useRef(0);
  // The bottom bar's right cell (a "N turns · M tools" counter + sidebar toggle
  // glyphs) was removed: the counter was noise and the closed-state toggle
  // hairlines read as stray "| |". The sidebars stay on Ctrl+B / Ctrl+L, and the
  // coloured state pills now take the full bar width.
  // All row/column cell budgets live in chat-layout.ts, where the
  // "a row never claims more cells than its container" invariant is
  // covered by tests instead of by inspection.
  const layout = computeChatLayout({ width, height, statusTextLength: 0 });
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
  /**
   * The slash-command list scrollbox, so the selected row can be scrolled into
   * view as the operator arrows past the height-clamped window. Not focusable —
   * navigation stays with the module-level keyboard handler.
   */
  const commandMenuScrollRef = useRef<ScrollBoxRenderable | null>(null);
  /** The `ask_operator` modal body scrollbox, scrolled to keep the active row visible. */
  const operatorScrollRef = useRef<ScrollBoxRenderable | null>(null);
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
  // Every matching command is selectable — the list is no longer truncated to
  // what fits. The height-clamped box shows a window of `commandMenuLimit`
  // entries and the rows live in a <scrollbox> the selection scrolls (below), so
  // commands past the visible window are still reachable by arrowing down.
  const menuCommands = filteredSlashCommands;
  const visibleCommandRows = Math.min(menuCommands.length, commandMenuLimit);
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
      // Self-evolving: when the operator has opted in, the interactive console
      // turn loop builds the gated self-extension registry and offers self_extend
      // (default OFF). Read from the live settings ref so a /settings toggle
      // applies on the next session build. (pluginHost — the other injectable
      // ConsoleSessionConfig field — is a documented follow-up: it needs a
      // shell-level host whose lifecycle spans the chat↔market screen swap.)
      allowModelSelfExtension: settingsRef.current.allowModelSelfExtension,
      // Marketplace → live console: the shell's plugin-host manager hands its
      // current host so ENABLED plugins' tools are in the console's tool set.
      // Undefined when the shell wired no manager (the default) — no plugin
      // tools, exactly as before. The console reads the host at turn boundaries.
      pluginHost: pluginHostManager?.current(),
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
      // The `ask_operator` question channel. Unlike the gates above it grants
      // nothing — it surfaces the model's structured question, waits for the
      // operator's answer, and resolves it (or null on Esc / a dead console).
      askOperator: (request) => {
        const deferred = Promise.withResolvers<OperatorQuestionAnswer | null>();
        if (!alive.current) {
          deferred.resolve(null);
          return deferred.promise;
        }
        setPendingOperatorQuestion({ request, resolve: deferred.resolve });
        return deferred.promise;
      },
    });
    // resolvedModel() is the id the runtime actually settled on after
    // provider detection — not necessarily what was requested — so it is
    // the only value honest enough to display.
    return { session: created, model: runtime.resolvedModel() };
  }, [options, pluginHostManager]);

  useEffect(() => {
    let created: ConsoleSession | null = null;
    alive.current = true;

    try {
      // Resume: when the full-screen browser opened this chat with a stored
      // transcript, build the console around it and rehydrate the transcript
      // silently (the restored messages ARE the context — see the /resume
      // in-place path, which does the same).
      const resumeMessages = options?.initialMessages;
      const built = buildSession(
        resumeMessages && resumeMessages.length > 0 ? { initialMessages: resumeMessages } : {},
      );
      created = built.session;
      setModelId(built.model);
      setSession(created);
      if (resumeMessages && resumeMessages.length > 0) {
        setEntries(entriesFromStoredMessages(resumeMessages));
      }
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
      setPendingOperatorQuestion((pending) => {
        pending?.resolve(null);
        return null;
      });
      setActiveSubagents({});
      void created?.cleanup();
    };
  }, []);

  // ── Marketplace → live console ────────────────────────────────────────────
  // Enabling/disabling a plugin in the market RECONSTRUCTS the shared host (a
  // new object) and fires onChanged; a session that captured the old host is
  // stale. Rebuild the session IN PLACE carrying the transcript — exactly as
  // /model does — rather than remounting the chat, which would wipe the
  // engagement. Deferred while a turn is running and flushed at the boundary.
  const rebuildForHost = useCallback(() => {
    const previous = sessionRef.current;
    if (!previous) return; // the mount effect will build with the current host
    if (busyRef.current) {
      pendingHostRebuild.current = true;
      return;
    }
    let built: { session: ConsoleSession; model: string };
    try {
      built = buildSession({
        model: modelIdRef.current ?? undefined,
        initialMessages: previous.messages,
      });
    } catch {
      return; // a failed rebuild leaves the operator exactly where they were
    }
    setSession(built.session);
    setModelId(built.model);
    void previous.cleanup();
  }, [buildSession]);

  useEffect(() => {
    const mgr = pluginHostManager;
    if (!mgr) return;
    // Cold start: the manager may have primed its host AFTER this chat mounted,
    // and priming does not fire onChanged — so adopt the current host once now
    // (this effect re-runs when the async manager first becomes available).
    rebuildForHost();
    return mgr.onChanged(rebuildForHost);
  }, [pluginHostManager, rebuildForHost]);

  // Flush a rebuild that was deferred because a turn was in flight.
  useEffect(() => {
    if (!busy && pendingHostRebuild.current) {
      pendingHostRebuild.current = false;
      rebuildForHost();
    }
  }, [busy, rebuildForHost]);

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

  // Seed the ask_operator modal's live edit state from each incoming request,
  // and clear it when the question is answered or dismissed.
  useEffect(() => {
    setOperatorState(
      pendingOperatorQuestion
        ? createOperatorQuestionState(pendingOperatorQuestion.request)
        : null,
    );
  }, [pendingOperatorQuestion]);

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

  // Subscribe to subagent lifecycle + progress events from the core event bus.
  // Filter by this session's scanId. `activeSubagents` drives the compact
  // ACTIVE SUBAGENTS block (terminal states removed); `herdAgents` is the
  // richer model the rail and the inline focus view read — fed by the SAME pure
  // reducers the herd screen uses, and KEEPING terminal records so a completed
  // agent's summary/error stays readable in focus and its ✓/× glyph in the rail.
  useEffect(() => {
    if (!session) return;
    const scanId = session.scanId;
    const unsub = eventBus.subscribe({
      emit: (type, payload) => {
        if (type === "subagent_lifecycle") {
          const event = payload as unknown as SubagentLifecyclePayload;
          if (event.parent_scan_id !== scanId) return;
          setActiveSubagents((prev) => reduceActiveSubagents(prev, event));
          setHerdAgents((prev) =>
            applySubagentLifecycle(prev, payload as Record<string, unknown>, Date.now()),
          );
        } else if (type === "subagent_progress") {
          if ((payload as Record<string, unknown>)["parent_scan_id"] !== scanId) return;
          setHerdAgents((prev) =>
            applySubagentProgress(prev, payload as Record<string, unknown>, Date.now()),
          );
        } else if (type === "todos") {
          // The plan is the main agent's, not a subagent's, so it carries no
          // scanId to filter on; the latest snapshot simply replaces the tree.
          setTodos(payload as unknown as TodosEventPayload);
        } else if (type === "session_objective") {
          const p = payload as unknown as SessionObjectivePayload;
          if (p.scanId !== scanId) return;
          setObjective(p.objective);
        }
      },
    });
    return unsub;
  }, [session]);

  // The LEFT sidebar's recent-sessions list. A disk read, so it only runs while
  // the sidebar is actually enabled, and re-runs when the live session changes —
  // each turn saves the transcript, so the current run appears once it is
  // stored. Sessions from THIS working directory sort first, then by recency.
  useEffect(() => {
    if (!settings.showLeftSidebar) {
      setRecentSessions([]);
      return;
    }
    const here = process.cwd();
    const saved = listSessions(undefined, { limit: 50 });
    saved.sort(
      (a, b) => Number(b.cwd === here) - Number(a.cwd === here) || b.savedAt - a.savedAt,
    );
    setRecentSessions(saved);
  }, [settings.showLeftSidebar, session]);

  // A focused agent that leaves the live map (never observed, or the session
  // reset) drops focus rather than staring at a stale record.
  useEffect(() => {
    if (focusAgentId && !herdAgents[focusAgentId]) {
      setFocusAgentId(null);
      setFocusScrollOffset(0);
    }
  }, [focusAgentId, herdAgents]);

  // List navigation ends the moment there is nothing left to navigate — an
  // empty selection is never shown.
  useEffect(() => {
    if (agentNavIndex < 0) return;
    const count = settings.showSubagents ? Object.keys(activeSubagents).length : 0;
    if (count === 0) setAgentNavIndex(-1);
  }, [agentNavIndex, activeSubagents, settings.showSubagents]);

  // Capture / preview seed ONLY. Guarded by an env var and never populated in a
  // normal session: it plants a deterministic set of sample agents so the right
  // rail, the list navigation and the inline focus view can be captured without
  // a live `spawn_agents` fan-out — the same discipline `OSEC_TRANSCRIPT_STYLE`
  // uses to pin a style for a render capture.
  useEffect(() => {
    if (!process.env["OSEC_TUI_DEMO_AGENTS"]) return;
    const now = Date.now();
    setHerdAgents({
      "agent-recon": {
        agentId: "agent-recon",
        parentScanId: "demo",
        task: "recon web tier",
        status: "running",
        maxTurns: 8,
        turn: 3,
        findings: 1,
        tool: "http_probe",
        note: "enumerating /api endpoints",
        lastSeen: now,
        activity: [
          { kind: "lifecycle", ts: now - 8000, status: "queued" },
          { kind: "lifecycle", ts: now - 7000, status: "running" },
          { kind: "progress", ts: now - 5000, turn: 1, maxTurns: 8, tool: "dns_lookup" },
          { kind: "progress", ts: now - 3000, turn: 2, maxTurns: 8, tool: "http_probe", note: "200 on /api" },
          { kind: "progress", ts: now - 1000, turn: 3, maxTurns: 8, tool: "http_probe", note: "enumerating /api endpoints" },
        ],
      },
      "agent-authz": {
        agentId: "agent-authz",
        parentScanId: "demo",
        task: "auth & session fuzzing",
        status: "running",
        maxTurns: 8,
        turn: 2,
        findings: 0,
        tool: "replay",
        lastSeen: now,
        activity: [
          { kind: "lifecycle", ts: now - 6000, status: "running" },
          { kind: "progress", ts: now - 2000, turn: 2, maxTurns: 8, tool: "replay", note: "cookie tampering" },
        ],
      },
      "agent-secrets": {
        agentId: "agent-secrets",
        parentScanId: "demo",
        task: "secret scanning",
        status: "completed",
        maxTurns: 5,
        turns: 5,
        findings: 2,
        summary: "2 leaked API keys in JS bundles",
        lastSeen: now,
        activity: [
          { kind: "lifecycle", ts: now - 9000, status: "running" },
          { kind: "lifecycle", ts: now - 500, status: "completed", turns: 5, findings: 2 },
        ],
      },
    });
    setActiveSubagents({
      "agent-recon": {
        agent_id: "agent-recon",
        parent_scan_id: "demo",
        status: "running",
        task: "recon web tier",
        max_turns: 8,
        turns: 3,
      },
      "agent-authz": {
        agent_id: "agent-authz",
        parent_scan_id: "demo",
        status: "running",
        task: "auth & session fuzzing",
        max_turns: 8,
        turns: 2,
      },
    });
  }, []);

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
        // The live plan tree belongs to the conversation being emptied.
        setTodos(null);
        // The objective describes the conversation being emptied; drop it so a
        // stale title doesn't ride on the fresh session's bottom bar.
        setObjective("");
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
        if (busy) {
          appendEntry({ kind: "notice", text: "wait for the active turn before resuming", turn: turn.current });
          return true;
        }
        // The full-screen resume BROWSER (run.tsx ResumeRoute) owns listing with
        // per-chat summaries, search and delete; picking one reopens the chat
        // around that stored transcript (via openChat's initialMessages →
        // mount-restore above). Replaces the old cramped overlay picker.
        onNavigate("resume");
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
      case "theme": {
        const current = settingsRef.current.theme;
        const arg = args.trim().toLowerCase();
        if (arg) {
          if (!isThemeName(arg)) {
            appendEntry({
              kind: "notice",
              text: "unknown theme",
              detail: `Run /theme with no argument to pick from ${THEME_NAMES.length}.`,
              turn: turn.current,
            });
            return true;
          }
          updateSetting("theme", arg);
          appendEntry({ kind: "notice", text: `Theme: ${getThemeEntry(arg).label}`, turn: turn.current });
          return true;
        }
        const items: SelectorItem[] = THEME_NAMES.map((name) => {
          const entry = getThemeEntry(name);
          return {
            id: name,
            label: entry.label,
            meta: entry.mode,
            detail: entry.description,
            current: name === current,
          };
        });
        setPicker({
          state: createSelectorState("Theme · live preview", items, current),
          // Preview in memory as the operator arrows — no disk write per row.
          onHighlight: (id) => { if (isThemeName(id)) previewSetting("theme", id); },
          // Enter keeps the highlighted theme (persist it).
          commit: (id) => { if (isThemeName(id)) updateSetting("theme", id); },
          // Esc restores the theme that was active before the picker opened.
          onCancel: () => { reloadSettings(); },
        });
        return true;
      }
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
        // A mode switch is transient STATE, not conversation. The operator
        // cycles modes constantly with Shift+Tab, and the current mode is
        // already shown (coloured) in the bottom bar — appending a persistent
        // "Mode: X" notice for every flip just spammed the transcript. Confirm
        // the switch with an ephemeral toast instead; mid-turn it still only
        // governs the NEXT tool call, so say so briefly.
        showToast(`${modeLabel(next)} mode${busy ? " · from the next tool call" : ""}`);
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
      case "usage":
        // run.tsx routes "usage" to the usage screen (with the live token
        // snapshot); this nav entry turns the registered "/usage" command from a
        // palette-only stub into a working route.
        onNavigate("usage");
        return true;
      case "connect":
        // Likewise for "/connect": run.tsx already routes the destination.
        onNavigate("connect");
        return true;
      case "history":
        onNavigate("history");
        return true;
      case "findings":
        onNavigate("findings");
        return true;
      case "finding":
        // `/finding [id]` opens the full-screen detail view. run.tsx routes the
        // "finding" destination via its cast-guard + ShellNav.openFindingDetail;
        // an id (when the operator typed one) is resolved from the store there.
        onNavigate("finding", args || undefined);
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
          // SETTLE the running row `onToolStart` appended IN PLACE rather than
          // appending a second row. Without this, the running row (success
          // undefined) never resolved, so it kept SHIMMERING until the turn
          // ended and the settled card printed as a duplicate beneath it. We
          // replace the last still-running tool row for this call (LIFO, matched
          // on name + turn), preserving its id/timestamp; if somehow none is
          // pending we append (old behaviour, so nothing is ever dropped).
          const settleRunningTool = (settled: Omit<ChatEntry, "id">) => {
            setEntries((current) => {
              for (let i = current.length - 1; i >= 0; i -= 1) {
                const e = current[i];
                if (
                  e.turn === currentTurn &&
                  e.kind === "tool" &&
                  e.success === undefined &&
                  e.text === call.name
                ) {
                  const next = [...current];
                  next[i] = { ...settled, id: e.id, at: e.at };
                  return next;
                }
              }
              return appendTranscriptEntry<ChatEntry>(current, {
                at: Date.now(),
                ...settled,
                id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
              });
            });
          };
          if (call.name === "spawn_agent") {
            const card = parseSubagentCard(result.success, result.output, result.error);
            if (card) {
              settleRunningTool({
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
          //
          // A rich card's display-only `result.meta` sidecar (never seen by the
          // model) rides onto the entry so TranscriptEntry can draw a bordered
          // command / edit card. Absent meta, the entry renders as before.
          settleRunningTool({
            kind: "tool",
            text: call.name,
            detail: formatToolResult(call, result),
            toolArgs: formatToolArgs(call),
            success: result.success,
            turn: currentTurn,
            ...toolCardFieldsFromMeta(result.meta),
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
      // The turn is over: stop the tool spinner and SETTLE any tool/subagent
      // rows still in flight when it ended (interrupt, error, or a budget stop).
      // `animationKind` reads `runningTool` BEFORE `busy`, so a stale runningTool
      // would keep the shimmer alive after the turn; and an unsettled row
      // (success/outcome undefined) reads as "running" forever. Clearing both
      // stops the shimmer the instant the turn exits. No-op on a clean turn —
      // onToolResult has already settled every row.
      setRunningTool(null);
      setEntries((current) =>
        current.some(
          (e) =>
            e.turn === currentTurn &&
            ((e.kind === "tool" && e.success === undefined) ||
              (e.kind === "subagent" && e.subagentOutcome === undefined)),
        )
          ? current.map((e) =>
              e.turn === currentTurn && e.kind === "tool" && e.success === undefined
                ? { ...e, success: false, detail: e.detail || "interrupted before it returned" }
                : e.turn === currentTurn && e.kind === "subagent" && e.subagentOutcome === undefined
                  ? {
                      ...e,
                      subagentOutcome: "failed" as const,
                      subagentError: e.subagentError || "interrupted before it returned",
                    }
                  : e,
            )
          : current,
      );
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
          // The async objective ("what am I working on") is stored as the
          // session summary so the resume browser can say what each chat was
          // FOR, not just how it opened. Empty until the objective service
          // emits; session-store drops a blank one.
          summary: objectiveRef.current || undefined,
          messages: session.messages as unknown[],
        });
        pruneSessions();
      }
    }
  }, [appendEntry, busy, routeSlashCommand, session, settings.showTurnSummary]);
  submitRef.current = send;

  // The programmatic operator-submit path, exposed to the coordinator via
  // `submitHandle` (the finding-detail "Fix" action rides this). It takes the
  // EXACT disposition a typed Enter takes — a slash command routes, a message
  // sent while a turn is in flight is parked in the same queue, and an idle
  // console sends immediately — so a fix request never reaches into core tools
  // and never races the running turn. Not wired to composer history: it is not
  // something the operator typed.
  const submitOperatorMessage = useCallback((raw: string) => {
    const input = raw.trim();
    if (!input) return;
    const disposition = classifyComposerInput({
      input,
      isSlash: findCommand(input).isSlash,
      busy,
      hasSession: Boolean(session),
    });
    if (disposition === "queue") {
      const { queue, accepted } = enqueueComposerInput(queuedRef.current, input);
      queuedRef.current = queue;
      setQueuedMessages(queue);
      // Enter during a running turn INTERRUPTS it, so the just-submitted message
      // sends right away: interruptTurn() aborts the turn, the console goes idle,
      // and the idle-drain effect delivers this queued message immediately.
      // interruptTurn() returns false when there is nothing abortable, in which
      // case it stays a plain queue.
      const interrupting = accepted && interruptTurn();
      if (!interrupting) {
        appendEntry({
          kind: accepted ? "notice" : "error",
          text: accepted
            ? `queued — will send when the current turn ends: ${input}`
            : `queue is full (${COMPOSER_QUEUE_LIMIT} messages); not queued: ${input}`,
          turn: turn.current,
        });
      }
      // When interrupting, interruptTurn() already posts an "interrupting…"
      // notice; the message then drains on the next idle transition.
    } else if (disposition === "send") {
      void send(input);
    }
  }, [appendEntry, busy, send, session, interruptTurn]);

  useEffect(() => {
    if (!submitHandle) return;
    submitHandle.current = submitOperatorMessage;
    return () => {
      submitHandle.current = null;
    };
  }, [submitHandle, submitOperatorMessage]);

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
    // The `ask_operator` modal takes precedence exactly like an approval prompt,
    // but it AUTHORIZES NOTHING — Esc resolves a `null` answer (the tool renders
    // that as "dismissed, nothing authorized"), Enter resolves the collected
    // selections + custom text. Space toggles the highlighted option (or types a
    // space into an active free-text field); other printable keys type into it.
    // Ctrl+C still exits, resolving null first so the awaiting turn is released.
    if (pendingOperatorQuestion) {
      if (key.ctrl && key.name === "c") {
        requestExitRef.current(() => pendingOperatorQuestion.resolve(null));
        return;
      }
      if (key.name === "escape") {
        pendingOperatorQuestion.resolve(null);
        setPendingOperatorQuestion(null);
        return;
      }
      if (key.name === "return") {
        pendingOperatorQuestion.resolve(operatorState ? buildOperatorAnswer(operatorState) : null);
        setPendingOperatorQuestion(null);
        return;
      }
      if (key.name === "up" || key.name === "down") {
        const dir = key.name;
        setOperatorState((s) => (s ? operatorMove(s, dir) : s));
        return;
      }
      if (key.name === "space" || key.sequence === " ") {
        setOperatorState((s) => {
          if (!s) return s;
          return operatorActiveRow(s)?.kind === "custom" ? operatorAppend(s, " ") : operatorToggle(s);
        });
        return;
      }
      if (key.name === "backspace") {
        setOperatorState((s) => (s ? operatorBackspace(s) : s));
        return;
      }
      if (key.sequence && key.sequence.length === 1 && !key.ctrl && !key.meta && key.sequence >= " ") {
        const char = key.sequence;
        setOperatorState((s) => (s ? operatorAppend(s, char) : s));
        return;
      }
      return;
    }
    // Authorization prompts are modal and drive the SAME selector reducer the
    // command pickers use, so ↑↓/enter/esc mean one thing everywhere. Ctrl+C
    // still exits — a modal must never trap the operator — and takes the
    // declining path on the way out rather than dropping the promise.
    if (approvalPrompt) {
      if (key.ctrl && key.name === "c") {
        requestExitRef.current(() => approvalPrompt.decline());
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
        requestExitRef.current();
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
        requestExitRef.current();
        return;
      }
      if (key.name === "escape") {
        picker.onCancel?.();
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
      requestExitRef.current();
      return;
    }
    // ── Inline subagent focus view (modal) ─────────────────────────────────────
    // Drilled into ONE subagent: the live meta + activity panes replace the
    // transcript. Read-only — Up/Down (and PageUp/PageDown) scroll the activity
    // back from its tail; Left or Esc returns to the agents list. Swallows every
    // other key so a keystroke cannot leak into the composer behind it.
    if (focusAgentId) {
      if (key.name === "escape" || key.name === "left") {
        setFocusAgentId(null);
        setFocusScrollOffset(0);
        setAgentNavIndex(0);
        return;
      }
      if (key.name === "up") {
        setFocusScrollOffset((offset) => offset + 1);
        return;
      }
      if (key.name === "down") {
        setFocusScrollOffset((offset) => Math.max(0, offset - 1));
        return;
      }
      if (key.name === "pageup") {
        setFocusScrollOffset((offset) => offset + 5);
        return;
      }
      if (key.name === "pagedown") {
        setFocusScrollOffset((offset) => Math.max(0, offset - 5));
        return;
      }
      return;
    }
    // ── Active-subagent list navigation (modal) ────────────────────────────────
    // Selection has moved out of the composer and INTO the ACTIVE SUBAGENTS
    // block. Up/Down move (wrapping) within the visible rows; Enter drills into
    // the highlighted agent; Left or Esc returns focus to the composer. The list
    // is the block's own visible subset, so the highlight is always on screen.
    if (agentNavIndex >= 0) {
      const navList = (settings.showSubagents ? Object.values(activeSubagents) : []).slice(
        0,
        SUBAGENT_MAX_VISIBLE,
      );
      if (navList.length === 0) {
        setAgentNavIndex(-1);
        return;
      }
      if (key.name === "escape" || key.name === "left") {
        setAgentNavIndex(-1);
        return;
      }
      if (key.name === "up") {
        setAgentNavIndex((index) => moveAgentSelection(navList.length, index, -1));
        return;
      }
      if (key.name === "down") {
        setAgentNavIndex((index) => moveAgentSelection(navList.length, index, 1));
        return;
      }
      if (key.name === "return") {
        const selected = clampAgentSelection(navList.length, agentNavIndex);
        const agent = selected >= 0 ? navList[selected] : undefined;
        if (agent) {
          setFocusAgentId(agent.agent_id);
          setFocusScrollOffset(0);
          setAgentNavIndex(-1);
        }
        return;
      }
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
    // Ctrl+B / Ctrl+L collapse the LEFT / RIGHT chat sidebars. Both persist via
    // the settings store (the same layer `/settings` writes), so the choice
    // survives the session and the store's subscribers repaint immediately.
    // Handled above the composing block so the chord never reaches the
    // composer's text catch-all (which only appends non-ctrl sequences anyway).
    if (key.ctrl && key.name === "b") {
      updateSetting("showLeftSidebar", !settingsRef.current.showLeftSidebar);
      return;
    }
    if (key.ctrl && key.name === "l") {
      updateSetting("showRightSidebar", !settingsRef.current.showRightSidebar);
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
        // The composer is append-only: the caret always sits on the LAST line,
        // so "Down with nothing below the cursor" is the steady state while
        // composing. When the operator is NOT browsing history back through the
        // draft, and workers are running, that Down drops INTO the agents list —
        // the same affordance the empty composer offers — rather than doing
        // nothing. While browsing history, Down still walks forward toward the
        // live draft first.
        const browsingHistory = historyIndexRef.current < historyRef.current.length;
        if (!browsingHistory) {
          const navList = settings.showSubagents ? Object.values(activeSubagents) : [];
          if (navList.length > 0) {
            setAgentNavIndex(0);
            return;
          }
        }
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
        if (shouldFlushQueuedInput({
          input,
          busy,
          hasSession: Boolean(session),
          queuedCount: queuedRef.current.length,
        })) {
          const { next, rest } = dequeueComposerInput(queuedRef.current);
          queuedRef.current = rest;
          setQueuedMessages(rest);
          composingRef.current = false;
          setComposerText("");
          setComposing(false);
          if (next !== undefined) void send(next);
          return;
        }
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
    // into the composer; Down moves INTO the active-subagents list when workers
    // are running, otherwise recalls history. The trigger sits in the idle branch
    // only, so it never fights the multiline composer, history browsing or the
    // slash menu (all of which own Down while composing).
    if (key.name === "up") {
      recallComposerHistory("up");
      return;
    }
    if (key.name === "down") {
      const navList = settings.showSubagents ? Object.values(activeSubagents) : [];
      if (navList.length > 0) {
        setAgentNavIndex(0);
        return;
      }
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
  const statusSegments = buildStatusSegments({
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
  });
  // The OMP-style pill row: the SAME segments, kept/dropped at the bar's real
  // width, each painted as its own coloured glyph+text with a subtle separator
  // between (rendered below via `renderStatusPills`). `statusBarText` remains as
  // the plain single-string fallback the bar degrades to if pills ever cannot
  // be drawn.
  const statusPills = fitStatusPills(statusSegments, controlsWidth);
  const statusBarText = fitStatusSegments(statusSegments, controlsWidth);
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

  // ── The ask_operator modal: budget, body window, footer hint ───────────────
  // The body (headers + prose + option/custom rows) lives in a fixed-height
  // scrollbox, so it is bought out of the SAME column budget the picker/approval
  // use and can never over-subscribe the column, however many questions arrive.
  const operatorQuestionOpen = Boolean(pendingOperatorQuestion && operatorState);
  const operatorRows: OperatorDisplayRow[] = operatorState ? planOperatorRows(operatorState) : [];
  // Title + footer + two border rows on top of the body viewport.
  const OPERATOR_CHROME_ROWS = 4;
  const operatorBodyViewport = operatorQuestionOpen
    ? Math.max(1, Math.min(operatorRows.length, Math.max(1, selectorBudget - (OPERATOR_CHROME_ROWS - 2))))
    : 0;
  const operatorBoxHeight = operatorQuestionOpen ? operatorBodyViewport + OPERATOR_CHROME_ROWS : 0;
  const operatorHintPairs: KeyHint[] = [
    { key: "↑↓", label: "move" },
    ...(operatorState && operatorHasOptions(operatorState) ? [{ key: "space", label: "toggle" }] : []),
    { key: "enter", label: "confirm" },
    { key: "esc", label: "dismiss" },
  ];
  // The masked credential panel stays a typed field — a secret is entered,
  // not chosen — but it gets the same treatment that stops a panel from
  // collapsing: four content lines plus two border rows, stated explicitly.
  const SECRET_PANEL_HEIGHT = 6;
  // The live focus subject: the drilled-into agent's rich record and its roster
  // peer, both looked up from the SAME herd map. `focused` gates the inline
  // focus view and suppresses the rail / subagent block while it is open.
  const nowMs = Date.now();
  const focusRecord = focusAgentId ? herdAgents[focusAgentId] : undefined;
  const focusPeer = focusAgentId
    ? subagentPeers(herdAgents, nowMs).find((peer) => peer.id === focusAgentId)
    : undefined;
  const focused = focusAgentId != null && focusRecord != null && focusPeer != null;
  // The two sidebars' budget: each hidden while focused, on a narrow terminal,
  // or when its setting is off — all folded into `computeSidebarsLayout`, which
  // gives the transcript priority (it keeps its minimum width; the RIGHT
  // sidebar wins the last column when only one fits) and hands back the
  // transcript's text-wrap width for the frame it leaves between them.
  const sidebars = computeSidebarsLayout({
    width,
    contentWidth,
    compact,
    showLeft: settings.showLeftSidebar && !focused,
    showRight: settings.showRightSidebar && !focused,
  });
  // Usable width INSIDE the transcript panel: the ledger box adds its own
  // paddingX (folded into the sidebar layout), which an entry's own border must
  // live within. Shrinks to make room when a sidebar is shown.
  const transcriptWidth = sidebars.transcriptWidth;
  // "0sec" is 4 cells; the mode label is right-sized to its own text. The
  // OMP-style OBJECTIVE (the async "what am I working on" summary) sits at the
  // TOP-RIGHT, just left of the mode, taking up to ~45% of the header when
  // present; the engagement summary gets whatever remains.
  const headerModeWidth = Math.min(10, Math.max(1, contentWidth - 8));
  const headerObjective = !compact && settings.showObjective ? objective.trim() : "";
  const headerObjectiveWidth = headerObjective
    ? Math.max(0, Math.min(headerObjective.length, Math.floor((contentWidth - 4 - headerModeWidth) * 0.45)))
    : 0;
  const headerGapCells = headerObjectiveWidth > 0 ? 3 : 2;
  const headerEngagementWidth = Math.max(
    1,
    contentWidth - 4 - headerModeWidth - headerObjectiveWidth - headerGapCells,
  );
  // Relative ages need a clock, but the transcript must not repaint every
  // second just to age a label. Tick only while timestamps are enabled, and
  // only at the granularity the format actually shows.
  // Density stays the spacing knob; the three visual knobs are resolved
  // separately and are orthogonal to it. An env override lets a style be pinned
  // for a preview or a capture without touching the settings file.
  const transcriptStyleSettings = resolveTranscriptStyleSettings(settings, process.env);
  // One animation kind per real state. `awaiting-operator` is deliberately
  // NOT a busy spinner: when the human is the bottleneck the surface should
  // look expectant, not like it is grinding. Derived above `entryDisplay` so the
  // shimmer frame it carries can be gated on the same running-state read.
  const gateOpen = Boolean(pendingScope || pendingLocalScope || pendingEscalation || pendingToolApproval || secretPrompt || operatorQuestionOpen);
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
  // The loading shimmer is alive only while a turn is genuinely WORKING —
  // thinking, streaming, connecting or running a tool. `awaiting-operator` is
  // the human's turn, not the machine's, so it stays static (expectant, not
  // grinding); an idle console has nothing to shimmer. reduceMotion stills it.
  const shimmerActive =
    !settings.reduceMotion && animationKind !== null && animationKind !== "awaiting-operator";
  const entryDisplay: EntryDisplay = {
    spacing: settings.density === "compact" ? 0 : 1,
    showTimestamps: settings.showTimestamps,
    now: clockTick,
    transcriptStyle: transcriptStyleSettings.transcriptStyle,
    roleLabelStyle: transcriptStyleSettings.roleLabelStyle,
    toolCardStyle: transcriptStyleSettings.toolCardStyle,
    richToolCards: settings.richToolCards,
    mode: modeLabel(mode),
    modeColor: modeColorFor(mode, theme),
    model: modelId ?? "",
    modelInFooter: settings.modelDisplay === "message",
    showTokenUsage: settings.showTokenUsage,
    showCost: settings.showCost,
    transcriptDetail: settings.transcriptDetail,
    // A number only while a turn is working (and reduceMotion is off), so running
    // tool/subagent rows shimmer in phase with the thinking indicator and render
    // static the instant they settle.
    shimmerFrame: shimmerActive ? shimmerFrame : undefined,
    // The turn currently in flight, so a collapsed fold for the WORKING turn
    // shimmers while every past turn's stays static. Undefined when idle.
    activeTurn: busy ? turn.current : undefined,
    // The live tail entry — only its reasoning row shimmers, so a working turn
    // shows ONE shimmering "thinking", not every past thinking block at once.
    activeEntryId: busy ? entries[entries.length - 1]?.id : undefined,
  };
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

  // One shared ticker for every shimmering label, at the shimmer cadence. Only
  // runs while `shimmerActive`, so a settled or idle surface costs no repaints.
  useEffect(() => {
    if (!shimmerActive) return;
    const timer = setInterval(() => setShimmerFrame((n) => n + 1), SHIMMER_TEXT_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [shimmerActive]);

  const menu = computeCommandMenuLayout({ width, compact });
  // Height is stated explicitly so the border is drawn where the content
  // actually ends, and flexShrink is disabled so the column cannot squeeze
  // the box out from under its own children. The no-match state still needs a
  // single content row for its "No command matches" line — without it the box
  // is one row short and the hint footer overprints the bottom border.
  const commandMenuHeight = menuCommands.length > 0
    ? commandMenuBoxHeight(visibleCommandRows, commandRowsPerCommand)
    : commandMenuBoxHeight(0, commandRowsPerCommand) + 1;

  const commandMenuVisible = composing && commandMenuOpen && isSlashComposer;
  // Every overlay — command menu, picker, approval panel — already prints
  // its own key hints inside its border. Repeating them down here is the
  // duplication that made the old two-line composer read as noise. So the
  // bar yields to contextual keys ONLY while composing plain text, where
  // "enter send · esc cancel" appears nowhere else on screen.
  const showContextualKeys = composing && !commandMenuVisible && !picker && !approvalPrompt && !secretPrompt && !operatorQuestionOpen;

  // ACTIVE SUBAGENTS. `spawn_agents` fans out up to 8 with 4 running at
  // once, so this block is genuinely multi-row and genuinely unbounded —
  // and it was neither height-capped nor `flexShrink={0}`, so under column
  // pressure Yoga collapsed it and its rows painted into each other and
  // into the title. Cap what is shown, state the overflow, and reserve
  // EXACTLY what is rendered.
  // The compact ACTIVE SUBAGENTS block is suppressed while a subagent is
  // focused — the focus view IS the detail — so it neither reserves rows nor
  // competes for the arrows.
  const subagentEntries = settings.showSubagents && !focused ? Object.values(activeSubagents) : [];
  const subagentVisible = subagentEntries.slice(0, SUBAGENT_MAX_VISIBLE);
  const subagentOverflow = subagentEntries.length - subagentVisible.length;
  const subagentOverflowRow = subagentOverflow > 0 ? 1 : 0;
  // Title + rows + optional overflow line. Zero when nothing is running.
  const subagentBlockRows = subagentVisible.length > 0
    ? 1 + subagentVisible.length + subagentOverflowRow
    : 0;
  // Selection within the block while navigating into it. Clamped every render so
  // an index left dangling by a finished agent lands back on a live row.
  const agentNavSelected =
    agentNavIndex >= 0 ? clampAgentSelection(subagentVisible.length, agentNavIndex) : -1;
  // The agent-nav hint sits one flexShrink={0} row below the list, so it is
  // reserved in the ledger budget exactly when it renders. Only the ACTIVE
  // states earn their own row now: while navigating the list, or while focused
  // on an agent. The idle "go down into the list" affordance no longer takes a
  // stray row — it rides on the ACTIVE SUBAGENTS header instead (below).
  const showAgentNavHint =
    settings.showComposerHints && !empty && (focused || agentNavIndex >= 0);

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
      + (secretPrompt ? SECRET_PANEL_HEIGHT + 1 : 0)
      + (operatorQuestionOpen ? operatorBoxHeight + 1 : 0),
    // The agent-nav hint row (+ its marginTop) below the composer.
    hintRows: showAgentNavHint ? 2 : 0,
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
  // Version rides at the far left of the top bar, like the startup masthead.
  const headerEngagement = [`v${VERSION}`, ...headerSegments].join(" · ");

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
  // While the turn is working the label SHIMMERS (a bright sweep over the muted
  // base, MUTED->TEXT); the instant the state settles — or under reduceMotion,
  // or while awaiting the operator — it renders as the calm static muted line.
  const workingLineFitted = fitTuiText(workingLine, Math.max(1, contentWidth - GLYPH_CELLS - 1));
  const workingIndicator = workingAnimation ? (
    <box flexDirection="row" minWidth={0} marginTop={1} gap={1}>
      <box width={GLYPH_CELLS} flexShrink={0}>
        <text fg={workingGlyphColor}>{workingAnimation.glyph}</text>
      </box>
      <box flexGrow={1} minWidth={0}>
        {shimmerActive ? (
          <ShimmerText label={workingLineFitted} frame={shimmerFrame} base={MUTED} peak={ERROR} />
        ) : (
          <text fg={MUTED}>{workingLineFitted}</text>
        )}
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
  // While composing, the input is MULTI-LINE and SOFT-WRAPS: `ComposerInput`
  // (chat/Composer.tsx) wraps the buffer on word boundaries to `textWidth`
  // cells and grows downward up to COMPOSER_MAX_ROWS, then scrolls the oldest
  // rows out to keep the tail cursor in view. The block cursor is FILLED when
  // the composer is focused (`composerActive`) and HOLLOW when it is not.
  const composerInput = (textWidth: number) => {
    const placeholder = startupError
      ? "runtime unavailable"
      : queueLabel
        ? queueLabel
        : "type to chat or / for commands";
    return (
      <ComposerInput
        composing={composing}
        active={composerActive}
        text={composer}
        textWidth={textWidth}
        placeholder={placeholder}
        placeholderTone={startupError ? ERROR : MUTED}
        theme={theme}
      />
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
  // Only messages the operator has PARKED for the next round stay pinned
  // directly above the composer (flexShrink={0}), so the transcript (flexGrow)
  // absorbs the scroll and nothing overflows. Bounded on purpose — capped at a
  // few rows with a "+N more" tail — so it can never crowd out the transcript.
  // The "request · …" echo of the in-flight turn used to sit here too, but it
  // just restated the transcript's own last user turn, so it was removed.
  const STICKY_QUEUE_ROWS = 3;
  const stickyWidth = Math.max(1, contentWidth - 2);
  const stickyNode =
    queuedMessages.length > 0 ? (
      <box flexDirection="column" width="100%" flexShrink={0} minWidth={0} marginTop={1}>
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
    <CommandMenu
      layout={ml}
      boxWidth={boxWidth}
      height={commandMenuHeight}
      scrollRef={commandMenuScrollRef}
      commands={menuCommands}
      selectedIndex={slashSelected}
      visibleRows={visibleCommandRows}
      rowsPerCommand={commandRowsPerCommand}
      query={slashQuery}
      compact={compact}
      theme={theme}
    />
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

  const operatorQuestionNode = operatorQuestionOpen && operatorState ? (
    <OperatorQuestionCard
      rows={operatorRows}
      cursor={operatorState.index}
      hintPairs={operatorHintPairs}
      bodyViewportRows={operatorBodyViewport}
      scrollRef={operatorScrollRef}
      contentWidth={contentWidth}
      height={operatorBoxHeight}
      theme={theme}
    />
  ) : null;

  const overlaysNode = (
    <>
      {commandMenuNode}
      {secretNode}
      {pickerNode}
      {approvalNode}
      {operatorQuestionNode}
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
      {operatorQuestionNode}
    </>
  );

  const subagentNode = subagentBlockRows > 0 ? (
    <box flexDirection="column" width="100%" minWidth={0} height={subagentBlockRows} flexShrink={0} marginTop={1}>
      {(() => {
        // The header carries the idle "↓ select" affordance inline (key white,
        // label muted), so the down-into-agents hint no longer costs its own
        // row. Shown only when idle (not already navigating) and hints are on,
        // and only when the pair actually fits beside the title.
        const subTitle = `ACTIVE SUBAGENTS · ${subagentEntries.length}`;
        const showSelectHint =
          settings.showComposerHints && agentNavIndex < 0 && !focused;
        const selectPairs: KeyHint[] = [{ key: "↓", label: "select" }];
        const fits =
          subTitle.length + 3 + keyHintsLength(selectPairs, " · ") <= contentWidth;
        return (
          <box flexDirection="row" width={contentWidth} flexShrink={0} minWidth={0}>
            <box flexShrink={0} minWidth={0}>
              <text fg={MUTED}>{fitTuiText(subTitle, contentWidth)}</text>
            </box>
            {showSelectHint && fits ? (
              <box flexDirection="row" flexShrink={0} minWidth={0} marginLeft={3}>
                <KeyHints pairs={selectPairs} theme={theme} />
              </box>
            ) : null}
          </box>
        );
      })()}
      {subagentVisible.map((sa, index) => {
        // A shared tree row (bold accent name : muted task, red glyph on
        // failure), with the last row's connector closing the tree and the
        // selected row wearing the highlight bar + accent marker.
        const view: AgentRowView = {
          id: sa.agent_id,
          name: shortAgentName(sa.agent_id),
          task: sa.task ?? "",
          status: sa.status,
          meta: sa.turns !== undefined ? `${sa.turns}/${sa.max_turns}` : undefined,
        };
        const isLast = index === subagentVisible.length - 1 && subagentOverflowRow === 0;
        return (
          <AgentTreeRow
            key={sa.agent_id}
            view={view}
            width={contentWidth}
            theme={theme}
            selected={index === agentNavSelected}
            isLast={isLast}
          />
        );
      })}
      {subagentOverflowRow > 0 ? (
        <box width={contentWidth} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText(`  +${subagentOverflow} more · /agents to list them`, contentWidth)}</text>
        </box>
      ) : null}
    </box>
  ) : null;

  // ── The RIGHT sidebar: the current run (agents + findings) ─────────────────
  // "What's happening now": the OMP-style AGENTS tree on top, then this run's
  // FINDINGS (title + severity, severity-coloured — red reserved for
  // high/critical). Each section has a small muted header and is bounded to its
  // share of the region's rows with a "+N" tail, so nothing can overflow or
  // fuse. Whole thing flexShrink={0}. The context strip lives in the bottom
  // status bar, not here — no duplication.
  const rightInner = sidebars.rightInnerWidth;
  const railRecords = Object.values(herdAgents);
  const runFindings = runFindingsFromEntries(entries);
  // Split the column between the two sections. Titles cost three rows total:
  // AGENTS(1) + FINDINGS(1 + its marginTop). Agents take the larger share
  // because their rows are two lines each.
  const rightSectionRows = Math.max(0, ledgerRows - 3);
  // A PLAN (todos) section joins AGENTS + FINDINGS in this column when a plan
  // exists: it takes a modest share off the top, then agents/findings split the
  // rest. Each section self-bounds with a "+N more" tail, so none can overflow.
  const hasPlan = Boolean(todos && todos.total > 0);
  const rightPlanBudget = hasPlan
    ? Math.min(rightSectionRows, Math.max(2, Math.floor(rightSectionRows * 0.25)))
    : 0;
  const rightBodyRows = Math.max(0, rightSectionRows - rightPlanBudget);
  const agentsBudget = Math.max(0, Math.floor(rightBodyRows * 0.6));
  const rightFindingsBudget = Math.max(0, rightBodyRows - agentsBudget);
  const railMaxAgents = Math.floor(agentsBudget / AGENT_SIDEBAR_ROWS);
  const railCapacity =
    railRecords.length > railMaxAgents
      ? Math.max(0, Math.floor((agentsBudget - 1) / AGENT_SIDEBAR_ROWS))
      : railMaxAgents;
  const railVisible = railRecords.slice(0, railCapacity);
  const railOverflow = railRecords.length - railVisible.length;
  // FINDINGS rendering (wrapping to ≤2 lines, budget, "+N more") now lives in
  // the FindingsSidebar component; it owns its 1-row header, so it is handed the
  // item budget PLUS that header row.
  const rightSidebarNode = sidebars.rightVisible ? (
    <box
      flexDirection="row"
      width={sidebars.rightWidth}
      flexShrink={0}
      minWidth={0}
      alignSelf="stretch"
      marginLeft={sidebars.rightGap}
    >
      <box width={1} flexShrink={0} alignSelf="stretch" backgroundColor={BORDER} />
      <box flexDirection="column" flexGrow={1} minHeight={0} minWidth={0} paddingLeft={1} backgroundColor={PANEL}>
        <box width={rightInner} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText(`AGENTS ${railRecords.length}`, rightInner)}</text>
        </box>
        {railVisible.length === 0 ? (
          <box width={rightInner} flexShrink={0} minWidth={0}>
            <text fg={MUTED}>{fitTuiText("no active agents", rightInner)}</text>
          </box>
        ) : (
          railVisible.map((rec) => {
            // The SAME agent-row look as the inline list, in the sidebar's
            // two-line variant (name over task). Turns + findings ride along as
            // the right-aligned meta; findings never colour the label.
            const turnValue =
              typeof rec.turn === "number"
                ? rec.turn
                : typeof rec.turns === "number"
                  ? rec.turns
                  : undefined;
            const meta: string[] = [];
            if (typeof turnValue === "number") {
              meta.push(rec.maxTurns > 0 ? `${turnValue}/${rec.maxTurns}` : `t${turnValue}`);
            }
            if (typeof rec.findings === "number") meta.push(`${rec.findings}f`);
            const view: AgentRowView = {
              id: rec.agentId,
              name: shortAgentName(rec.agentId),
              task: rec.task || rec.agentId,
              status: rec.status,
              meta: meta.length > 0 ? meta.join(" · ") : undefined,
            };
            return (
              <AgentSidebarRow
                key={rec.agentId}
                view={view}
                width={rightInner}
                theme={theme}
                selected={false}
              />
            );
          })
        )}
        {railOverflow > 0 ? (
          <box width={rightInner} flexShrink={0} minWidth={0}>
            <text fg={MUTED}>{fitTuiText(`+${railOverflow} more`, rightInner)}</text>
          </box>
        ) : null}
        <FindingsSidebar
          findings={runFindings}
          width={rightInner}
          rows={rightFindingsBudget + FINDINGS_SIDEBAR_HEADER_ROWS}
          theme={theme}
          onOpenFinding={(id) => onNavigate("finding", id)}
        />
        {hasPlan ? (
          <TodosSidebar payload={todos!} width={rightInner} rows={rightPlanBudget} theme={theme} />
        ) : null}
        <box flexGrow={1} minHeight={0} flexShrink={1} />
        <box width={rightInner} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText("ctrl+l hide", rightInner)}</text>
        </box>
      </box>
    </box>
  ) : null;

  // ── The LEFT sidebar: history (recent sessions) ────────────────────────────
  // "What you have": recent resumable sessions from the session store. History
  // only — findings moved to the RIGHT sidebar (they are live output of the
  // current run). Bounded to the region's rows with a "+N" tail so it can never
  // overflow. Whole thing flexShrink={0}.
  const leftInner = sidebars.leftInnerWidth;
  const leftBodyBudget = Math.max(0, ledgerRows - 1); // one title row
  const sessionsCap =
    recentSessions.length > leftBodyBudget ? Math.max(0, leftBodyBudget - 1) : leftBodyBudget;
  const sessionsVisible = recentSessions.slice(0, sessionsCap);
  const sessionsOverflow = recentSessions.length - sessionsVisible.length;
  const leftSidebarNode = sidebars.leftVisible ? (
    <box
      flexDirection="row"
      width={sidebars.leftWidth}
      flexShrink={0}
      minWidth={0}
      alignSelf="stretch"
      marginRight={sidebars.leftGap}
    >
      <box flexDirection="column" flexGrow={1} minHeight={0} minWidth={0} paddingRight={1} backgroundColor={PANEL}>
        <box width={leftInner} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText(`SESSIONS ${recentSessions.length}`, leftInner)}</text>
        </box>
        {sessionsVisible.length === 0 ? (
          <box width={leftInner} flexShrink={0} minWidth={0}>
            <text fg={MUTED}>{fitTuiText("no saved sessions", leftInner)}</text>
          </box>
        ) : (
          sessionsVisible.map((meta) => {
            const current = session?.scanId === meta.id;
            const label = meta.preview || meta.target || "(no prompt)";
            return (
              <box key={meta.id} flexDirection="row" width={leftInner} flexShrink={0} minWidth={0}>
                <text width={1} flexShrink={0} fg={current ? ACCENT : MUTED}>{current ? "◉" : "•"}</text>
                <box width={Math.max(1, leftInner - 2)} flexShrink={0} minWidth={0} marginLeft={1}>
                  <text fg={current ? TEXT : MUTED}>{fitTuiText(label, Math.max(1, leftInner - 2))}</text>
                </box>
              </box>
            );
          })
        )}
        {sessionsOverflow > 0 ? (
          <box width={leftInner} flexShrink={0} minWidth={0}>
            <text fg={MUTED}>{fitTuiText(`+${sessionsOverflow} more`, leftInner)}</text>
          </box>
        ) : null}
        <box flexGrow={1} minHeight={0} flexShrink={1} />
      </box>
      <box width={1} flexShrink={0} alignSelf="stretch" backgroundColor={BORDER} />
    </box>
  ) : null;

  // ── The inline focus view ──────────────────────────────────────────────────
  // Reuses the herd focus PLUMBING verbatim — computeHerdFocusLayout for the
  // vertical meta/transcript split, focusHeaderLines + renderFocusActivity for
  // the tone-tagged lines, windowFocusTail for the scroll-back window — but
  // wears the chat's own minimal skin: a PANEL-backed region (no bordered
  // boxes) exactly like the transcript it replaces, so there is no border to
  // paint a line through and no exact-fit fragility. The meta header is a
  // flexShrink={0} block; the live transcript flexGrows to fill the rest.
  const focusLayout = computeHerdFocusLayout({
    width,
    height: ledgerRows + shellChromeRows(width),
    noticeRows: 0,
  });
  // The panes render inside the PANEL region's own paddingX, so the wrap width
  // is the transcript's full-width value (the rail is always hidden in focus).
  const focusInner = Math.max(8, contentWidth - (compact ? 2 : 4));
  const focusMetaLines = focused
    ? clipDetailLines(
        focusHeaderLines(focusPeer, focusRecord, focusInner, nowMs, { compact: true }),
        Math.max(1, focusLayout.meta.bodyRows),
        focusInner,
      )
    : [];
  const focusActivityLines =
    focused && focusRecord ? renderFocusActivity(focusRecord.activity, focusInner) : [];
  // Rows left for the live transcript once the meta header (title + its lines)
  // and the transcript's own title row have taken theirs, out of the region's
  // `ledgerRows` budget.
  const focusMetaRows = focusMetaLines.length + 1;
  const focusTranscriptCap = Math.max(1, ledgerRows - focusMetaRows - 2);
  const focusTail = windowFocusTail(
    focusActivityLines.length,
    focusTranscriptCap,
    focusScrollOffset,
  );
  const focusVisibleActivity = focusActivityLines.slice(focusTail.start, focusTail.end);
  const focusViewNode = (
    <box
      flexDirection="column"
      flexGrow={1}
      minHeight={0}
      width="100%"
      minWidth={0}
      backgroundColor={PANEL}
      paddingX={compact ? 1 : 2}
      paddingY={1}
    >
      <box flexDirection="column" flexShrink={0} minWidth={0}>
        <text fg={MUTED}>{fitTuiText("FOCUS", focusInner)}</text>
        {focusMetaLines.map((line, index) => (
          <text key={`focus-meta-${index}`} fg={herdToneColor(theme, line.tone)}>
            {fitTuiText(line.text, focusInner)}
          </text>
        ))}
      </box>
      <box flexDirection="column" flexGrow={1} minHeight={0} minWidth={0} marginTop={1}>
        <text fg={MUTED}>{fitTuiText(herdFocusTranscriptTitle(focusActivityLines.length), focusInner)}</text>
        {focusVisibleActivity.length === 0 ? (
          <text fg={MUTED}>{fitTuiText(HERD_FOCUS_EMPTY_TEXT, focusInner)}</text>
        ) : (
          focusVisibleActivity.map((line, index) => (
            <text key={`focus-live-${focusTail.start + index}`} fg={herdToneColor(theme, line.tone)}>
              {fitTuiText(line.text, focusInner)}
            </text>
          ))
        )}
      </box>
    </box>
  );

  // ── The conversation region ────────────────────────────────────────────────
  // Either the drilled-in focus view, or the transcript column between the two
  // optional sidebars: [left][transcript][right]. The transcript column
  // flexGrows; each sidebar is flexShrink={0} and only present when the layout
  // found room for it, so with both hidden the transcript takes the full width
  // exactly as before.
  const conversationRegion = focused ? (
    focusViewNode
  ) : (
    <box flexDirection="row" flexGrow={1} minHeight={0} width="100%" minWidth={0}>
      {leftSidebarNode}
      <box
        flexDirection="column"
        flexGrow={1}
        minHeight={0}
        minWidth={0}
        backgroundColor={PANEL}
        paddingX={compact ? 1 : 2}
        paddingY={1}
      >
        <scrollbox ref={transcriptRef} focusable={false} width="100%" flexGrow={1} minHeight={0} stickyScroll stickyStart="bottom">
          <box flexDirection="column" width="100%">
            {planTranscript(entries, entryDisplay.transcriptDetail, expandedTurns).map((item) => {
              if (item.type === "fold") {
                // A collapsed fold: click to expand its turn, hover to tint.
                return renderFold(item, transcriptWidth, entryDisplay, theme, {
                  hovered: hoveredTurn === item.turn,
                  onToggle: () => toggleTurnExpanded(item.turn),
                  onHover: (h) => setHoveredTurn(h ? item.turn : null),
                });
              }
              const entry = item.entry;
              // Only the collapsible kinds of a turn the operator has expanded
              // are clickable (to re-collapse) and hoverable; everything else
              // renders exactly as before, so keyboard-only use is untouched.
              const collapsible =
                entry.kind === "tool" ||
                entry.kind === "subagent" ||
                entry.kind === "reasoning";
              const interactive = collapsible && expandedTurns.has(entry.turn);
              return renderEntry(
                entry,
                transcriptWidth,
                entryDisplay,
                theme,
                interactive
                  ? {
                      hovered: hoveredTurn === entry.turn,
                      onToggle: () => toggleTurnExpanded(entry.turn),
                      onHover: (h) => setHoveredTurn(h ? entry.turn : null),
                    }
                  : undefined,
              );
            })}
            {/* The plan lives in the RIGHT sidebar now; this inline card is only
                a fallback for when that sidebar is hidden, so the todos are
                always visible somewhere. */}
            {!sidebars.rightVisible && todos && todos.total > 0 ? (
              <Todos payload={todos} width={transcriptWidth} theme={theme} />
            ) : null}
            {workingIndicator}
            {startupError ? <text fg={ERROR}>{fitTuiText(startupError, contentWidth)}</text> : null}
          </box>
        </scrollbox>
      </box>
      {rightSidebarNode}
    </box>
  );

  // ── The agent-nav / focus hint row (below the composer) ─────────────────────
  // Keys white, labels muted (KeyHints). Contextual: the down-into-agents
  // affordance when idle, the list keys while navigating, the scroll keys while
  // focused. Reserved in the ledger via `hintRows` exactly when it renders.
  const agentNavHintPairs: KeyHint[] = focused
    ? [
        { key: "↑↓", label: "scroll" },
        { key: "esc", label: "back" },
      ]
    : agentNavIndex >= 0
      ? [
          { key: "↑↓", label: "move" },
          { key: "enter", label: "open" },
          { key: "esc", label: "back" },
        ]
      : [{ key: "↓", label: "agents" }];
  const agentNavHintNode = showAgentNavHint ? (
    <box flexDirection="row" width="100%" minWidth={0} flexShrink={0} marginTop={1}>
      {keyHintsLength(agentNavHintPairs, " · ") <= contentWidth ? (
        <KeyHints pairs={agentNavHintPairs} theme={theme} />
      ) : (
        <text fg={MUTED}>{fitTuiText(agentNavHintPairs.map((p) => `${p.key} ${p.label}`).join(" · "), contentWidth)}</text>
      )}
    </box>
  ) : null;

  // The compact dim hint under the hero composer — keybind chords only. The
  // "type to chat · / commands" half is dropped: the composer placeholder above
  // already says it. Keys render white, labels muted (see KeyHints).
  // The empty start screen has no transcript, no sessions and no agents yet, so
  // the sidebar toggles (ctrl+b / ctrl+l) have nothing to reveal — they'd only
  // read as noise before the first turn. The hero keeps just the two chords that
  // matter here (switch mode, open the palette); the sidebar affordances live in
  // the bottom bar once a conversation exists.
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
  const heroOverlayOpen = commandMenuVisible || Boolean(picker) || Boolean(approvalPrompt) || Boolean(secretPrompt) || operatorQuestionOpen;
  const showMasthead = !heroOverlayOpen;

  // ── Command-menu selection scroll ──────────────────────────────────────────
  // Keep the highlighted command inside the height-clamped window: the rows live
  // in a scrollbox, so scrolling — not slicing — is what makes entries past the
  // visible window reachable. Centred, clamped flush to the ends (chat-layout).
  useEffect(() => {
    const box = commandMenuScrollRef.current;
    if (!box || !commandMenuVisible || menuCommands.length === 0) return;
    const start = commandMenuWindowStart(slashSelected, visibleCommandRows, menuCommands.length);
    box.scrollTop = start * commandRowsPerCommand;
  }, [commandMenuVisible, slashSelected, visibleCommandRows, menuCommands.length, commandRowsPerCommand]);

  // ── ask_operator body scroll ───────────────────────────────────────────────
  // Scroll the active answerable row into view within the fixed-height body.
  useEffect(() => {
    const box = operatorScrollRef.current;
    if (!box || !operatorQuestionOpen || !operatorState) return;
    const activeY = operatorActiveDisplayIndex(operatorRows, operatorState.index);
    box.scrollTop = commandMenuWindowStart(activeY, operatorBodyViewport, operatorRows.length);
  }, [operatorQuestionOpen, operatorState, operatorRows, operatorBodyViewport]);

  // ── Logo intro ticker ──────────────────────────────────────────────────────
  // computeLogoFrame is pure; this only advances the frame counter. A one-shot
  // style stops once it settles (frame >= count-1); a looping style (shimmer)
  // keeps ticking. reduceMotion / "off" never start a ticker — the frame is
  // rendered statically as finalLogoFrame by computeLogoFrame regardless.
  const logoStyle = settings.logoAnimation;
  const logoAnimating =
    showMasthead && showTerminalMark && !settings.reduceMotion && logoStyle !== "off";
  useEffect(() => {
    if (!logoAnimating) return;
    setLogoFrame(0);
    const count = logoAnimationFrameCount(logoStyle);
    const loops = logoAnimationLoops(logoStyle);
    let frame = 0;
    const timer = setInterval(() => {
      frame += 1;
      if (!loops && frame >= count - 1) {
        setLogoFrame(count - 1);
        clearInterval(timer);
        return;
      }
      setLogoFrame(frame);
    }, LOGO_FRAME_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [logoAnimating, logoStyle]);
  // The per-cell frame the masthead paints. computeLogoFrame folds reduceMotion
  // and "off" into the settled final frame internally, so this one call covers
  // both the animated and the static case.
  const logoFrameGrid = computeLogoFrame(TERMINAL_BLOCK_LOGO, logoStyle, logoFrame, {
    reduceMotion: settings.reduceMotion,
  });

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
        {headerObjectiveWidth > 0 ? (
          // The async AI objective summary, right-aligned at the top-right in the
          // 0sec voice (BRAND). Empty/compact hides it and the engagement
          // summary reclaims the cells.
          <box width={headerObjectiveWidth} flexShrink={0} minWidth={0} flexDirection="row" justifyContent="flex-end">
            <text fg={BRAND}>{fitTuiText(headerObjective, headerObjectiveWidth, { mode: "end" })}</text>
          </box>
        ) : null}
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
            {showMasthead ? (
              <Masthead
                showTerminalMark={showTerminalMark}
                showTagline={showEmptyStateTagline}
                contentWidth={contentWidth}
                logoFrameGrid={logoFrameGrid}
                theme={theme}
              />
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
          {/*
            * The conversation region: the drilled-in focus view, or the
            * transcript column beside the optional agent rail. The transcript
            * flexGrows; the rail is flexShrink={0} and sized by chat-layout.
            */}
          {conversationRegion}

          {overlaysNode}
          {stickyNode}
          {composerNode}
          {/*
            * The inline ACTIVE SUBAGENTS list sits directly BELOW the composer,
            * so pressing Down FROM the composer reads as moving DOWN into the
            * list (the keyboard nav target). Explicit height AND flexShrink={0}:
            * without both, opentui defaults flexShrink to 1 for any box with no
            * numeric width/height, so a squeezed column collapsed this block to a
            * single row while its children kept painting. `subagentBlockRows` is
            * the reserved count, budgeted in `computeLedgerRows` regardless of
            * where the block is painted.
            */}
          {subagentNode}
          {agentNavHintNode}
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
            {showContextualKeys ? (
              keyHintsLength(composeHintPairs, " · ") <= controlsWidth ? (
                <KeyHints pairs={composeHintPairs} theme={theme} />
              ) : (
                <text fg={MUTED}>{fitTuiText(controls, controlsWidth)}</text>
              )
            ) : statusPills.length > 0 ? (
              // OMP-style coloured pills: each segment its own glyph+text in its
              // role colour, a subtle muted dot between. Widths come from
              // `fitStatusPills`, so the row's children sum to <= controlsWidth
              // and never overprint (chat-layout invariant).
              <box flexDirection="row" flexShrink={0} minWidth={0}>
                {statusPills.map((segment, index) => (
                  <React.Fragment key={segment.kind}>
                    {index > 0 ? <text fg={MUTED}> · </text> : null}
                    <text fg={statusRoleColor(segment.colorRole, theme, mode)}>
                      {pillText(segment)}
                    </text>
                  </React.Fragment>
                ))}
              </box>
            ) : (
              <text fg={MUTED}>{fitTuiText(statusBarText, controlsWidth)}</text>
            )}
          </box>
        </box>
      ) : null}
      {/*
        * The copy-on-highlight toast. Positioned absolutely with a high
        * zIndex (see toast.tsx), so it floats over the transcript without
        * participating in — or shifting — the column layout above.
        */}
      <Toast frame={toastFrame} />
    </box>
  );
}
