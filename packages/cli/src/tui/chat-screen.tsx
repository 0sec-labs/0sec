/** @jsxImportSource @opentui/react */
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createLocalConsoleSession } from "../console-session.js";
import type { AuditActivity } from "./audit-workspace.js";
import { HarnessPresentation, useHarness } from "./harness-context.js";
import { loadFindingFocus, buildFindingChatPrompt } from "../finding-focus.js";
import { exportChatConversation } from "./chat-export.js";
import { hostedBalanceState, formatHostedBalance, type HostedBalanceState } from "./hosted-balance.js";
import {
  useKeyboard,
  usePaste,
  useRenderer,
  useTerminalDimensions,
} from "@opentui/react";
import { DEFAULT_AUTONOMY_MODE } from "@0sec/shared";
import {
  ScopePolicy,
  CloudClient,
  loadCloudCredentials,
  createConsoleRuntime,
  eventBus,
  type ConsoleAutonomyMode,
  type ConsoleScopeRequest,
  type ConsoleScopeResolution,
  claimDiagnostics,
  type ConsoleLocalScopeRequest,
  type ConsoleLocalScopeResolution,
  type ScopedAuditEscalationRequest,
  type ConsoleSession,
  type RuntimeConfig,
  type NativeMessage,
  type OperatorQuestionRequest,
  type OperatorQuestionAnswer,
  type SubagentLifecyclePayload,
  type SubagentMessagePayload,
  type PeerMessagePayload,
  type TodosEventPayload,
  type SessionObjectivePayload,
  type ToolCall,
  type ToolRisk,
  describeDestructiveCategory,
  sendOperatorMessage,
  renderInboundMessage,
  type MessagingRuntime,
  type McpHost,
} from "@0sec/core";
import { decodePasteBytes, type ScrollBoxRenderable } from "@opentui/core";
import {
  useSettings,
  updateSetting,
  previewSetting,
  reloadSettings,
} from "./settings-store.js";
import { useTheme, type Theme } from "./theme-context.js";
import { createTranscriptDocument, modelProvider } from "@0sec/shared";
import { homedir } from "node:os";
import {
  createPresentationEmitter,
  type PresentationEmitter,
} from "../presentation/event-bus.js";
import {
  readGitStatus,
  type GitStatus,
} from "./git-status.js";
import {
  buildStatusSegments,
  fitStatusSegments,
  fitStatusPills,
  pillText,
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
import {
  appendFeedback,
  buildDiagnosticFeedback,
  buildSubmitPreview,
  submitFeedback,
  submissionBlockedReason,
  describeSkip,
  parseFeedbackCommand,
  type FeedbackPayload,
} from "./feedback.js";
import {
  base64ByteLength,
  formatToolArgs,
  formatToolResult,
  projectToolPreview,
} from "./tool-format.js";
import {

  pruneSessions,
  saveSession,
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
} from "./provider-status.js";
import {
  credentialEnvPatch,
  loadCredentials,
  redactSecret,
  saveCredentials,
} from "./credential-store.js";
import {
  connectionRecoveryForError,
  type ConnectionRecovery,
} from "./connection-recovery.js";
import { VERSION } from "@0sec/shared";
import {
  type TuiSettings,
} from "./settings.js";
import {
  pushHistory,
  recallNext,
  recallPrev,
} from "./composer-history.js";
import { suggestCompletion } from "./composer-suggest.js";
import {
  buildCapabilityPanel,
  buildHelpPanel,
  buildScopePanel,
  buildStatusPanel,
  buildToolsPanel,
} from "./panels.js";
import { getAllCapabilities } from "./capability-registry.js";
import { fitTuiText, sanitizeComposerText } from "./text.js";
import { THEME_NAMES, getThemeEntry, isThemeName } from "./themes.js";
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
  queuedInputAction,
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
import { clampScrollOffset, wheelOffsetStep } from "./mouse.js";
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
  deletePreviousCharacter,
  deletePreviousWord,
  deleteToLineStart,
} from "./composer-edit.js";
import { appendTranscriptEntry } from "./transcript.js";
import {
  applyStreamPatches,
  enqueueStreamPatch,
  type StreamPatch,
} from "./stream-coalescer.js";
import {
  planTranscript,
  resolveTranscriptStyleSettings,
} from "./transcript-style.js";
import { useSelectionCopy, type SelectionCopyFn } from "./use-selection-copy.js";
import { useToast, Toast } from "./toast.js";
import { ContextMenu } from "./context-menu.js";
import {
  useContextMenu,
  isRightClick,
  type ContextMenuItem,
} from "./use-context-menu.js";
import { firstCodeBlock } from "./markdown.js";
import {
  copyToClipboard,
  defaultSpawn,
  defaultWhich,
} from "./clipboard.js";
import type {
  ChatEntry,
  ChatImageAttachment,
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
import { TranscriptReview } from "./chat/TranscriptReview.js";
import type { TranscriptReviewRenderable } from "./transcript-review-renderable.js";
import { Todos, TodosSidebar } from "./chat/Todos.js";
import { FindingsSidebar, FINDINGS_SIDEBAR_HEADER_ROWS } from "./chat/FindingsSidebar.js";
import { ComposerFrame, ComposerInput, composerContentRows } from "./chat/Composer.js";
import { autonomyFooterText, isAutonomyCycleKey, nextAutonomyMode } from "./composer-mode.js";
import { matchesBinding } from "./keybindings.js";
import { resolveContextLimit } from "./context-window.js";
import { buildHostedModelCatalog, type HostedCatalogModel } from "./model-catalog.js";
import { CloudHintCard, shouldOfferCloudHint } from "./chat/CloudHintCard.js";
import { textCells } from "./primitives.js";
import { buildSidebarSectionHeader } from "./chat/todos-sidebar-layout.js";
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
  type AgentRowView,
} from "./chat/AgentRow.js";
import { agentAccentFor } from "./agent-color.js";
import { summarizeAgentActivity, summarizeRoster } from "./agents-panel-model.js";
import { appendTuiCrash, appendTuiEvent, serializeError, logProblem, describeErrorForSurface, tuiLogPath } from "./tui-crash.js";

export type ChatDestination = "launcher" | "ops" | "history" | "findings" | "doctor" | "replay" | "settings" | "keybindings" | "harness" | "new-chat" | "models" | "market" | "usage" | "connect" | "herd" | "comms" | "finding" | "resume" | "audits" | "onboard";

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
  kind?: "command" | "edit" | "web" | "task" | "code" | "image";
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
  // task card
  taskLabel?: string;
  taskContext?: string;
  goal?: string;
  constraints?: string;
  contract?: string;
  assignment?: string;
  subReports?: Array<{ name: string; agent?: string; brief?: string; isolated?: boolean }>;
  todos?: Array<{ id: string; content: string; status: "pending" | "in_progress" | "completed"; group?: string }>;
  // code card
  language?: "javascript" | "python";
  code?: string;
  output?: string;
  // image card (browser screenshot)
  image?: {
    imageBase64: string;
    mimeType: string;
    width: number;
    height: number;
    caption?: string;
  };
}

/**
 * Map a tool result's display-only `meta` sidecar onto the rich-card fields of
 * a `ChatEntry`, for BOTH a live turn and a restored one. Returns an empty
 * object when there is no card to draw, so a spread leaves the entry untouched.
 */
function toolCardFieldsFromMeta(meta: ToolCardMeta | undefined): Partial<ChatEntry> {
  if (
    !meta ||
    (meta.kind !== "command" &&
      meta.kind !== "edit" &&
      meta.kind !== "web" &&
      meta.kind !== "task" &&
      meta.kind !== "code" &&
      meta.kind !== "image")
  ) {
    return {};
  }
  if (meta.kind === "code") {
    return {
      metaKind: "code",
      codeLanguage: meta.language,
      codeSource: meta.code,
      codeOutput: meta.output,
      exitCode: meta.exitCode ?? null,
      wallMs: meta.durationMs,
    };
  }
  if (meta.kind === "image") {
    // Reuse the existing inline-image path: an ImageCard is drawn from
    // `entry.images` (ChatImageAttachment = ToolPreviewImage + origin). The
    // pixel size + media type come straight from the meta the tool decoded, so
    // OpenTUI can draw the PNG where the terminal supports it and falls back to
    // a captioned dimensions placeholder otherwise.
    const img = meta.image;
    if (!img) return { metaKind: "image" };
    const byteSize = base64ByteLength(img.imageBase64);
    const attachment: ChatImageAttachment = {
      index: 1,
      data: img.imageBase64,
      mimeType: img.mimeType,
      format: img.mimeType.split("/")[1],
      pixelWidth: img.width > 0 ? img.width : undefined,
      pixelHeight: img.height > 0 ? img.height : undefined,
      byteSize,
      alt: img.caption,
      origin: "browser",
    };
    return { metaKind: "image", images: [attachment] };
  }
  if (meta.kind === "task") {
    return {
      metaKind: "task",
      taskLabel: meta.taskLabel,
      taskContext: meta.taskContext,
      taskGoal: meta.goal,
      taskConstraints: meta.constraints,
      taskContract: meta.contract,
      taskAssignment: meta.assignment,
      subReports: meta.subReports,
      taskTodos: meta.todos,
    };
  }
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
  if (name === "spawn_agents") {
    // The live plan/TODO snapshot and per-agent names were carried on the
    // (now-gone) meta; from the serialized args we can still recover the shared
    // context and each task's brief so the launch card survives a restore.
    const rawTasks = Array.isArray(args.tasks) ? (args.tasks as Array<Record<string, unknown>>) : [];
    const subReports = rawTasks.map((entry, i) => {
      const task = typeof entry?.task === "string" ? entry.task.trim() : "";
      const brief = task ? task.split("\n")[0].slice(0, 64) : "";
      const agent = typeof entry?.role === "string" ? entry.role : undefined;
      return {
        name: typeof entry?.name === "string" && entry.name.trim() ? entry.name.trim() : `#${i + 1}`,
        ...(agent ? { agent } : {}),
        ...(brief ? { brief } : {}),
      };
    });
    if (subReports.length === 0) return {};
    return {
      metaKind: "task",
      taskLabel: `${subReports.length} ${subReports.length === 1 ? "agent" : "agents"}`,
      taskContext: typeof args.context === "string" && args.context.trim() ? args.context : undefined,
      subReports,
    };
  }
  if (name === "js_eval" || name === "python_eval") {
    // The display-only meta (language / code / output / duration) is gone on a
    // restore; recover the source from args and the output from the serialized
    // result text so the code card still draws.
    const code = typeof args.code === "string" ? args.code : undefined;
    if (!code) return {};
    return {
      metaKind: "code",
      codeLanguage: name === "python_eval" ? "python" : "javascript",
      codeSource: code,
      codeOutput: typeof content === "string" ? content : undefined,
      exitCode: success ? 0 : 1,
    };
  }
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
    case "evolution":
      return theme.SUCCESS;
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
    case "activity":
      return theme.ACCENT;
    case "effort":
    case "elapsed":
    case "plan":
    default:
      return theme.MUTED;
  }
}

function startupRecoveryText(detail: string): string {
  if (/no provider credential found/i.test(detail)) {
    return "Use /connect to sign in to 0sec Cloud, or use your own API key or provider subscription.";
  }
  const recovery = connectionRecoveryForError(detail);
  if (recovery?.providerId === "chatgpt-codex") {
    return "ChatGPT Codex needs device OAuth. Use /connect; do not paste an OpenAI API key.";
  }
  return detail;
}


export interface ChatScreenOptions {
  target?: string;
  dbPath?: string;
  scope?: ScopePolicy;
  model?: string;
  /** Explicit provider choice, applied only when constructing a new runtime. */
  providerId?: RuntimeConfig["provider"];
  /** Operator-approved role/model choices for new runtimes, never agent-authored consent. */
  agentModels?: Readonly<Record<string, string>>;
  singleModel?: boolean;
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
  /** A one-shot finding workflow request submitted after the session is ready. */
  initialPrompt?: string;
  /**
   * A connected MCP host whose registered tools join the console's tool set
   * (network-gated, `mcp__`-fenced as untrusted). The CLI connects it before
   * launching the TUI and threads it down here, so the session build stays
   * synchronous — no async connect inside React. The session closes the host on
   * cleanup. Absent when no `0SEC_MCP` servers are configured.
   */
  mcpHost?: McpHost;
}

export interface ChatScreenProps {
  options?: ChatScreenOptions;
  onGoBack: () => void;
  onNavigate: (destination: ChatDestination, id?: string) => void;
  onExit: () => void;
  /**
   * Opens the provider recovery screen after a recognized credential failure.
   * Tool and target errors stay in the transcript instead of misrouting here.
   * REQUIRED: it was previously optional and the sole call site (run.tsx) forgot
   * to wire it, so a Codex 401 only printed "turn failed" and the device-auth
   * pane never opened. Keeping it required makes that omission a compile error.
   */
  onConnectionFailure: (recovery: ConnectionRecovery) => void;
  /**
   * A handle the coordinator populates with a function that submits an operator
   * message into the SAME composer-submit path a typed message takes (queue if a
   * turn is in flight, otherwise send). Finding handoffs use this path so their
   * evidence, approval gates, and transcript stay in one session.
   */
  submitHandle?: React.MutableRefObject<((text: string) => void) | null>;
  /** Generated prompts are drafts for review, never automatic turns. */
  stagePromptHandle?: React.MutableRefObject<((text: string) => void) | null>;
  /** Save a future connection choice, or retry when no session was constructed. */
  reconnectHandle?: React.MutableRefObject<((providerId: string) => void) | null>;
  /** Share the existing session host with contextual controls; never create another. */
  onSessionChange?: (session: ConsoleSession | null) => void;
  onWorkingChange?: (busy: boolean) => void;
  onNextChatOptions?: (selection: Pick<ChatScreenOptions, "model" | "providerId" | "agentModels" | "singleModel">) => void;
  /**
   * The shell-level marketplace host manager. A session leases its initial
   * host until cleanup; changed enablement applies to the next explicit chat.
   */
  pluginHostManager?: SessionPluginHostManager;
  /** Compact status of the configured self-evolving finder-lens worker. */
  evolutionStatus?: string;
  interactive: boolean;
  messagingHomeDir: string;
  protectedSessionIds: ReadonlySet<string>;
  onAuditActivity: (activity: AuditActivity) => void;
  closeHandle: React.MutableRefObject<(() => Promise<void>) | null>;
  herdHandle: React.MutableRefObject<(() => Readonly<HerdSubagentMap>) | null>;
  runtimeInfoHandle: React.MutableRefObject<{
    model: () => string;
    providerId: () => string;
  } | null>;
  renderAuditSwitcher?: (width: number, rows: number) => React.ReactNode;
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
  /** Presentation-only risk, from the core classifier at the approval boundary. */
  risk?: ToolRisk;
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
          if (trimmed.length <= 32_768 && (trimmed.startsWith("{") || trimmed.startsWith("["))) {
            try {
              output = JSON.parse(trimmed);
            } catch {
              // Not JSON after all; the raw string is still a fine summary input.
            }
          }
        }
        const restoredCall = { name, arguments: call?.input };
        const restoredResult = { success, output, error: success ? null : String(b.content ?? "") };
        out.push({
          id: id(),
          kind: "tool",
          text: name,
          detail: formatToolResult(restoredCall, restoredResult),
          toolPreview: projectToolPreview(restoredCall, restoredResult),
          // Carry the argument one-liner too (as a live turn does), so a
          // restored session's `save_finding` calls feed the findings sidebar.
          toolArgs: formatToolArgs(restoredCall),
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

/**
 * Below this content width the inline AGENTS panel auto-collapses to its
 * one-line summary: a per-agent row needs room for a name, a status glyph and a
 * live-activity tail, and under ~44 cells those fuse into noise. The operator
 * can still drill in (Down) to browse the roster one selection at a time.
 */
const SUBAGENT_PANEL_MIN_WIDTH = 44;

/** Window after a first Ctrl+C in which a second Ctrl+C confirms the quit. */
const EXIT_CONFIRM_MS = 3000;

/** Upper bound for model-token publication; input and approvals stay immediate. */
const STREAM_PRESENTATION_INTERVAL_MS = 33;

/** Max transcript entries retained per subagent — the tail is all the focus
 * view can show anyway, and it bounds memory across a large child fleet. */
const SUBAGENT_TRANSCRIPT_MAX = 300;

const EMPTY_EXPANDED_TURNS: ReadonlySet<number> = new Set();

export function ChatScreen({
  options,
  onGoBack,
  onNavigate,
  onExit,
  onConnectionFailure,
  submitHandle,
  stagePromptHandle,
  reconnectHandle,

  onSessionChange,
  onWorkingChange,
  onNextChatOptions,
  pluginHostManager,
  evolutionStatus,
  interactive,
  messagingHomeDir,
  protectedSessionIds,
  onAuditActivity,
  closeHandle,
  herdHandle,
  runtimeInfoHandle,
  renderAuditSwitcher,
}: ChatScreenProps) {
  const harness = useHarness();
  const connectionFailureRef = useRef(onConnectionFailure);
  connectionFailureRef.current = onConnectionFailure;
  const [entries, setEntries] = useState<ChatEntry[]>([]);
  const entriesRef = useRef<ChatEntry[]>([]);
  entriesRef.current = entries;
  const pendingStreamPatches = useRef<StreamPatch[]>([]);
  const streamPresentationTimer = useRef<NodeJS.Timeout | undefined>(undefined);
  const flushStreamPatches = useCallback(() => {
    const pending = pendingStreamPatches.current;
    if (streamPresentationTimer.current) {
      clearTimeout(streamPresentationTimer.current);
      streamPresentationTimer.current = undefined;
    }
    if (pending.length === 0) return;

    pendingStreamPatches.current = [];
    setEntries((current) => applyStreamPatches(current, pending, (patch) => ({
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      kind: patch.kind,
      text: patch.text,
      turn: patch.turn,
      at: patch.at,
    })));
  }, []);
  const queueStreamPatch = useCallback((patch: StreamPatch) => {
    pendingStreamPatches.current = enqueueStreamPatch(pendingStreamPatches.current, patch);
    if (streamPresentationTimer.current) return;

    streamPresentationTimer.current = setTimeout(() => {
      streamPresentationTimer.current = undefined;
      flushStreamPatches();
    }, STREAM_PRESENTATION_INTERVAL_MS);
  }, [flushStreamPatches]);
  const discardStreamPatches = useCallback(() => {
    pendingStreamPatches.current = [];
    if (!streamPresentationTimer.current) return;
    clearTimeout(streamPresentationTimer.current);
    streamPresentationTimer.current = undefined;
  }, []);
  useEffect(() => discardStreamPatches, [discardStreamPatches]);
  const [session, setSession] = useState<ConsoleSession | null>(null);
  const cloudSource = useRef<{ owner: ConsoleSession; isHosted: () => boolean; env: NodeJS.ProcessEnv } | null>(null);
  const [cloudBalance, setCloudBalance] = useState<{ owner: ConsoleSession; state: HostedBalanceState } | null>(null);
  const [hostedCatalog, setHostedCatalog] = useState<{ owner: ConsoleSession; models: readonly HostedCatalogModel[]; expiresAt: number } | null>(null);
  const [cloudConfigured, setCloudConfigured] = useState<boolean>();
  const [cloudHintDismissed, setCloudHintDismissed] = useState(false);
  const initialPromptRef = useRef(options?.initialPrompt?.trim() || null);
  const presentationEmitterRef = useRef<PresentationEmitter | null>(null);
  if (!presentationEmitterRef.current) {
    presentationEmitterRef.current = createPresentationEmitter();
  }
  const presentedEntriesRef = useRef(new Map<string, ChatEntry>());
  const presentedSessionIdRef = useRef<string | undefined>(undefined);
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
  // Right-click context menu over the transcript. Purely additive: it opens
  // only on a right press (button 2) and only when mouse support is on, so the
  // left-click / drag-to-select / keyboard paths are untouched.
  const transcriptMenu = useContextMenu();
  const copyMenuText = useCallback(
    (text: string, label: string) => {
      void copySelection(text, { spawn: defaultSpawn, which: defaultWhich }).then(
        (result) => showToast(result.ok ? `Copied ${label}` : "Copy failed"),
      );
    },
    [copySelection, showToast],
  );
  const buildMessageMenuItems = useCallback(
    (entry: ChatEntry): ContextMenuItem[] => {
      const text = entry.text ?? "";
      const items: ContextMenuItem[] = [
        {
          label: "Copy message",
          disabled: text.trim().length === 0,
          onSelect: () => copyMenuText(text, "message"),
        },
      ];
      const code = firstCodeBlock(text);
      if (code) {
        items.push({
          label: "Copy code block",
          onSelect: () => copyMenuText(code, "code block"),
        });
      }
      return items;
    },
    [copyMenuText],
  );
  /**
   * Per-turn transcript expansion. In collapsed mode each turn's successful
   * tool/reasoning steps fold to one ▸ line; clicking that line adds the turn
   * here so `planTranscript` renders it in full (and the steps show a ▾
   * affordance whose click removes it again). Independent of the global Ctrl+R
   * detail toggle, which flips every turn at once via the settings store.
   */
  const [expandedTurnsByAgent, setExpandedTurnsByAgent] = useState<ReadonlyMap<string | null, ReadonlySet<number>>>(() => new Map());
  const [reviewOpen, setReviewOpen] = useState(false);
  const reviewRenderableRef = useRef<TranscriptReviewRenderable | null>(null);
  const reviewEventOpenRef = useRef(false);
  useEffect(() => {
    const emitter = presentationEmitterRef.current!;
    if (!session) return;
    const correlation = { sessionId: session.scanId };
    emitter.emit("session.opened", {
      target: session.target,
    }, correlation);
    return () => {
      emitter.emit("session.closed", {}, correlation);
    };
  }, [session]);
  useEffect(() => {
    const emitter = presentationEmitterRef.current!;
    const sessionId = session?.scanId;
    if (!sessionId) return;
    if (presentedSessionIdRef.current !== sessionId) {
      presentedSessionIdRef.current = sessionId;
      presentedEntriesRef.current.clear();
    }
    const previous = presentedEntriesRef.current;
    const next = new Map<string, ChatEntry>();
    for (const entry of entries) {
      const prior = previous.get(entry.id);
      if (!prior) {
        emitter.emit("session.transcript.append", { entry }, { sessionId });
      } else if (prior !== entry) {
        emitter.emit("session.transcript.replace", { entry }, { sessionId });
      }
      next.set(entry.id, entry);
    }
    presentedEntriesRef.current = next;
  }, [entries, session?.scanId]);
  useEffect(() => {
    const emitter = presentationEmitterRef.current!;
    const sessionId = session?.scanId;
    if (!sessionId || reviewOpen === reviewEventOpenRef.current) return;
    reviewEventOpenRef.current = reviewOpen;
    emitter.emit(reviewOpen ? "review.opened" : "review.closed", {}, { sessionId });
  }, [reviewOpen, session?.scanId]);
  /** The turn currently under the mouse, for the subtle hover highlight. */
  const [hoveredTurn, setHoveredTurn] = useState<number | null>(null);
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
  const [mode, setMode] = useState<ConsoleAutonomyMode>(options?.autonomyMode ?? DEFAULT_AUTONOMY_MODE);
  /**
   * The live autonomy mode, for callbacks that must not be rebuilt when it
   * changes. `buildSession` in particular is a `useCallback` that reruns on
   * `/model`; reading the ref is what keeps a model switch from silently
   * reverting the operator's mode.
   */
  const modeRef = useRef<ConsoleAutonomyMode>(options?.autonomyMode ?? DEFAULT_AUTONOMY_MODE);
  modeRef.current = mode;
  const target = session?.target ?? options?.target ?? "";
  const [scopeRules, setScopeRules] = useState<string[]>(options?.scope?.raw.in_scope ?? []);
  const [busy, setBusy] = useState(false);
  const activeTurnStartedAt = useRef<number | null>(null);
  useEffect(() => {
    onSessionChange?.(session);
    return () => onSessionChange?.(null);
  }, [onSessionChange, session]);
  useEffect(() => {
    onWorkingChange?.(busy);
    return () => onWorkingChange?.(false);
  }, [onWorkingChange, busy]);
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
  const paletteDraftRef = useRef<{ text: string; composing: boolean } | null>(null);
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
  // Live id → display-name map for agents, fed from lifecycle events. Used by the
  // peer_message (IRC) handler to resolve a message's from/to ids to the same
  // AdjectiveNoun names the roster shows, without re-reading React state inside
  // the bus callback. Main is always itself.
  const agentNamesRef = useRef<Map<string, string>>(new Map());
  // Per-subagent live transcript (assistant prose + tool cards), assembled from
  // `subagent_message` events. Keyed by agent_id; rendered by the focus view via
  // the SAME planTranscript/renderEntry as the main transcript, so a drilled-in
  // child reads exactly like the main agent. Bounded per agent (the tail is what
  // fits on screen anyway).
  const [subagentTranscripts, setSubagentTranscripts] = useState<Record<string, ChatEntry[]>>({});
  const [workerTelemetry, setWorkerTelemetry] = useState<Record<string, SubagentMessagePayload>>({});
  const [workerOutcomes, setWorkerOutcomes] = useState<Record<string, SubagentLifecyclePayload>>({});
  const [lastContext, setLastContext] = useState<number>();
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
  /** Feedback staged for /feedback send (submitPreview is null when blocked). */
  const [pendingFeedback, setPendingFeedback] = useState<{
    payload: FeedbackPayload;
    preview: { url: string; body: string; headers: Record<string, string>; warnings: string[] } | null;
  } | null>(null);
  const latestProblemRef = useRef<FeedbackPayload | null>(null);
  const reportedProblemsRef = useRef(new Set<string>());
  const [problemReview, setProblemReview] = useState<FeedbackPayload | null>(null);
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
  const [herdAgents, setHerdAgentsState] = useState<HerdSubagentMap>({});
  const [operatorStopped, setOperatorStopped] = useState<ReadonlySet<string>>(() => new Set());
  const workerEpochsRef = useRef(new Map<string, number>());
  const herdAgentsRef = useRef(herdAgents);
  const setHerdAgents = useCallback((next: HerdSubagentMap) => {
    herdAgentsRef.current = next;
    setHerdAgentsState(next);
  }, []);
  const projectedHerdAgents = useMemo(() => {
    let projected: HerdSubagentMap | undefined;
    for (const id in herdAgents) {
      const worker = herdAgents[id];
      const done = workerOutcomes[id]?.done;
      const stopped = operatorStopped.has(id);
      if (worker.done === done && Boolean(worker.operatorStopped) === stopped) continue;
      (projected ??= { ...herdAgents })[id] = { ...worker, done, operatorStopped: stopped };
    }
    return projected ?? herdAgents;
  }, [herdAgents, operatorStopped, workerOutcomes]);
  const projectedHerdRef = useRef(projectedHerdAgents);
  projectedHerdRef.current = projectedHerdAgents;
  herdHandle.current = useCallback(() => projectedHerdRef.current, []);
  const workerRoster = useMemo(() => Object.values(herdAgents).map((agent) => ({
    ...workerOutcomes[agent.agentId],
    agent_id: agent.agentId, parent_scan_id: agent.parentScanId,
    name: agent.name, task: agent.task, status: agent.status,
    max_turns: agent.maxTurns, turns: agent.turns ?? agent.turn,
  })), [herdAgents, workerOutcomes]);
  useEffect(() => {
    let runningWorkers = 0;
    let parkedWorkers = 0;
    for (const worker of workerRoster) {
      if (operatorStopped.has(worker.agent_id)) continue;
      if (worker.status === "running" || worker.status === "queued") runningWorkers += 1;
      else if (worker.status === "parked") parkedWorkers += 1;
    }
    onAuditActivity({
      workers: runningWorkers + parkedWorkers,
      waiting: Boolean(pendingScope || pendingLocalScope || pendingEscalation || pendingToolApproval || pendingOperatorQuestion)
        || (!busy && runningWorkers === 0 && parkedWorkers > 0),
    });
  }, [busy, entries, workerRoster, operatorStopped, pendingScope, pendingLocalScope, pendingEscalation, pendingToolApproval, pendingOperatorQuestion, onAuditActivity]);
  /**
   * Active-subagent navigation from the composer. -1 means the composer has
   * focus; >= 0 selects a row in the ACTIVE SUBAGENTS block. Entered with Down
   * on an empty composer (only when agents are running), left with Left/Esc.
   */
  const [agentNavIndex, setAgentNavIndex] = useState(-1);
  /**
   * Collapse toggle for the inline AGENTS panel. The panel is EXPANDED by
   * default (running agents are visible without arrowing in); the operator can
   * collapse it to a single summary line via its corner control (mouse) or the
   * existing keyboard path. Session-scoped state — the choice is remembered for
   * the life of the screen but is not persisted to disk.
   */
  const [agentsPanelCollapsed, setAgentsPanelCollapsed] = useState(false);
  /**
   * The subagent the operator drilled INTO, or null in list/composer mode. When
   * set, the transcript region is replaced by the inline focus view (the same
   * live meta + activity panes the herd screen's focus mode renders).
   */
  const [focusAgentId, setFocusAgentId] = useState<string | null>(null);
  const expandedTurns = expandedTurnsByAgent.get(focusAgentId) ?? EMPTY_EXPANDED_TURNS;
  const toggleTurnExpanded = useCallback((turn: number) => {
    setExpandedTurnsByAgent((previous) => {
      const turns = new Set(previous.get(focusAgentId));
      if (turns.has(turn)) turns.delete(turn);
      else turns.add(turn);
      const next = new Map(previous);
      next.set(focusAgentId, turns);
      return next;
    });
  }, [focusAgentId]);
  const focusEntries = focusAgentId ? subagentTranscripts[focusAgentId] : undefined;
  const focusTask = focusAgentId ? herdAgents[focusAgentId]?.task : undefined;
  const focusedTranscript = useMemo<ChatEntry[]>(() => [
    ...(focusTask ? [{ id: `${focusAgentId}-task`, kind: "user" as const, text: focusTask, turn: 0 }] : []),
    ...(focusEntries ?? []),
  ], [focusAgentId, focusTask, focusEntries]);
  const transcriptDocument = useMemo(
    () => createTranscriptDocument(focusAgentId ? focusedTranscript : entries),
    [focusAgentId, focusedTranscript, entries],
  );
  /** How far the inline focus transcript is scrolled back from its tail. */
  const [focusScrollOffset, setFocusScrollOffset] = useState(0);
  const { width, height } = useTerminalDimensions();
  const alive = useRef(true);
  const closingRef = useRef(false);
  const pendingCancellationsRef = useRef(new Set<() => void>());
  const trackedRequest = useCallback(<T,>(denied: T) => {
    const deferred = Promise.withResolvers<T>();
    const cancel = () => deferred.resolve(denied);
    pendingCancellationsRef.current.add(cancel);
    void deferred.promise.then(() => pendingCancellationsRef.current.delete(cancel));
    return deferred;
  }, []);
  // Mirror the latest render values so the plugin-host effect can rebuild the
  // session in place without re-subscribing on every state change.
  const sessionRef = useRef(session);
  sessionRef.current = session;
  const busyRef = useRef(busy);
  busyRef.current = busy;
  const modelIdRef = useRef(modelId);
  modelIdRef.current = modelId;
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
    composerTextWidth,
    approvalWidth,
    controlsWidth,
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
  // The drilled-in subagent's transcript scrollbox (auto-follows newest, like
  // the main one); pageup/pagedown scroll it while focused.
  const focusTranscriptRef = useRef<ScrollBoxRenderable | null>(null);
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
  const displayedScope = session ? session.scope : options?.scope;
  const scopeIncludes = displayedScope?.raw.in_scope ?? [];
  const scopeExcludes = displayedScope?.raw.out_of_scope ?? [];
  const scopeLabel = displayedScope === undefined
    ? "not configured"
    : `${scopeIncludes.length ? scopeIncludes.join(", ") : "empty · deny all"}${scopeExcludes.length ? `; excludes ${scopeExcludes.join(", ")}` : ""}`;

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

  const restorePaletteDraft = useCallback(() => {
    const draft = paletteDraftRef.current;
    if (!draft) return false;
    paletteDraftRef.current = null;
    composingRef.current = draft.composing;
    setComposerText(draft.text);
    setComposing(draft.composing);
    return true;
  }, [setComposerText]);

  useEffect(() => {
    if (!stagePromptHandle) return;
    stagePromptHandle.current = (text) => {
      if (!text.trim()) return;
      restorePaletteDraft();
      const draft = composerRef.current;
      setComposerText(draft ? `${draft}\n\n${text}` : text);
      composingRef.current = true;
      setComposing(true);
    };
    return () => { stagePromptHandle.current = null; };
  }, [stagePromptHandle, restorePaletteDraft, setComposerText]);

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
    flushStreamPatches();
    setEntries((current) => appendTranscriptEntry<ChatEntry>(current, {
      at: Date.now(),
      ...entry,
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    }));
  }, [flushStreamPatches]);

  const stageFeedback = useCallback((payload: FeedbackPayload) => {
    const written = appendFeedback(payload);
    if (!written.ok) {
      appendEntry({ kind: "error", text: "could not save feedback", detail: written.error, turn: turn.current });
      return;
    }
    const preview = buildSubmitPreview(payload);
    setPendingFeedback({ payload, preview });
    if (!preview) {
      const blocked = submissionBlockedReason();
      appendEntry({
        kind: "notice",
        text: "feedback saved locally",
        detail: blocked ? describeSkip(blocked) : "Submission is unavailable.",
        turn: turn.current,
      });
      return;
    }
    appendEntry({
      kind: "notice",
      text: "review feedback",
      detail: `Endpoint: ${preview.url}\nHeaders: ${JSON.stringify(preview.headers)}\nBody: ${preview.body}`
        + (preview.warnings.length ? `\n\nWarnings:\n${preview.warnings.join("\n")}` : "")
        + "\n\n/feedback send to submit · /feedback cancel to discard",
      turn: turn.current,
    });
  }, [appendEntry]);

  const chooseReporting = useCallback((choice: string) => {
    if (choice !== "off" && choice !== "ask" && choice !== "automatic") return;
    const saved = updateSetting("diagnosticReporting", choice, { scope: "global" });
    const recorded = updateSetting("diagnosticReportingPrompted", true, { scope: "global" });
    showToast(saved && recorded ? `Problem reports: ${choice}` : "Privacy choice changed for this session; could not save it.");
  }, [showToast]);

  const openReportingChoices = useCallback(() => {
    const current = settingsRef.current.diagnosticReporting;
    setPicker({
      state: createSelectorState("Problem reports · optional", [
        { id: "off", label: "Keep reports local", detail: "No automatic submission. You can still review and send individual reports with /feedback.", current: current === "off" },
        { id: "ask", label: "Ask before sending", detail: "Offer to review limited diagnostics after a problem. Nothing is sent until you confirm.", current: current === "ask" },
        { id: "automatic", label: "Send limited diagnostics automatically", detail: "Version, platform, runtime and problem category only. No prompts, tool arguments, output, paths or credentials. Uses your configured feedback endpoint; offline policies still win.", current: current === "automatic" },
      ], current),
      commit: chooseReporting,
      onCancel: () => { restorePaletteDraft(); },
    });
  }, [chooseReporting, restorePaletteDraft]);

  const recordProblem = useCallback((kind: "tool" | "runtime", error: unknown, toolName?: string) => {
    if (!alive.current || abortRef.current?.signal.aborted) return;
    if (error instanceof Error && error.name === "AbortError") return;
    if (typeof error === "string" && /^(?:aborted|cancelled|canceled)\b|(?:operator|user).*(?:declined|rejected)|(?:was )?(?:already )?(?:declined|rejected) by (?:the )?(?:operator|user)\b|previously declined/i.test(error)) return;
    // Always capture the FULL error (stack included) to the always-on local log
    // by default — no env flag — so a failure is learnable even when the
    // surfaced line and the transmitted diagnostic are both bounded/coarse.
    // Local only; nothing here crosses a network wire.
    logProblem(kind, error, toolName);
    const payload = buildDiagnosticFeedback({
      kind, error, toolName, version: VERSION, platform: process.platform, arch: process.arch,
      runtime: process.versions.bun ? "bun" : "node",
      runtimeVersion: process.versions.bun ?? process.versions.node,
    });
    latestProblemRef.current = payload;
    const policy = settingsRef.current.diagnosticReporting;
    if (policy === "off" || submissionBlockedReason(process.env, { allowCloud: false }) === "opt-out") return;
    const key = `${policy}:${payload.message}`;
    const seen = reportedProblemsRef.current;
    if (seen.has(key)) return;
    if (seen.size >= 64) seen.delete(seen.values().next().value!);
    seen.add(key);
    if (policy === "ask") {
      setProblemReview(payload);
      return;
    }
    const written = appendFeedback(payload);
    if (!written.ok) {
      showToast("Could not save the diagnostic report.");
      return;
    }
    void submitFeedback(payload).then((result) => {
      if (alive.current) showToast(result.ok ? "Problem report submitted" : "Problem report saved locally; submission unavailable.");
    });
  }, [showToast]);

  useEffect(() => {
    if (!problemReview) return;
    if (settings.diagnosticReporting !== "ask") {
      setProblemReview(null);
      return;
    }
    if (busy || picker || pendingScope || pendingLocalScope || pendingToolApproval || pendingOperatorQuestion) return;
    const payload = problemReview;
    setProblemReview(null);
    setPicker({
      state: createSelectorState("Report this problem?", [
        { id: "review", label: "Review report", detail: "Inspect the limited diagnostics and destination before deciding whether to send." },
        { id: "local", label: "Keep it local", detail: "Save this diagnostic report locally without sending it." },
        { id: "off", label: "Stop asking", detail: "Turn off automatic problem-report prompts in your user settings." },
      ]),
      commit: (id) => {
        if (id === "review") stageFeedback(payload);
        else if (id === "off") chooseReporting("off");
        else if (id === "local") {
          const saved = appendFeedback(payload);
          showToast(saved.ok ? "Problem report saved locally" : "Could not save the problem report.");
        }
      },
    });
  }, [problemReview, settings.diagnosticReporting, busy, picker, pendingScope, pendingLocalScope, pendingToolApproval, pendingOperatorQuestion, stageFeedback, chooseReporting, showToast]);
  /** Construct only at initial startup, explicit new chat, or failed-start recovery. */
  const buildSession = useCallback((
    opts: { model?: string; providerId?: RuntimeConfig["provider"]; initialMessages?: NativeMessage[] } = {},
  ): { session: ConsoleSession; model: string } => {
    if (closingRef.current || stoppingAuditRef.current) throw new Error("This audit is stopping.");
    // Resolve credentials into this construction only. Explicit shell exports
    // win, and changing a connection never mutates a live runtime's environment.
    const env = credentialEnvPatch(loadCredentials(), process.env);
    const runtime = createConsoleRuntime({
      model: opts.model ?? options?.model,
      provider: opts.providerId ?? options?.providerId,
      agentModels: options?.agentModels,
      singleModel: options?.singleModel,
      env,
    });
    const resolvedModel = runtime.resolvedModel();
    const pluginLease = pluginHostManager?.acquire();
    let created: ConsoleSession;
    try {
    created = createLocalConsoleSession({
      runtime,
      costModel: resolvedModel,
      target: options?.target,
      scope: options?.scope,
      role: options?.role,
      maxToolIterations: options?.maxToolIterations,
      allowScanners: options?.allowScanners,
      // New sessions use the shared default; an existing disabled session is
      // never reconstructed merely because its preference changes.
      allowModelSelfExtension: settingsRef.current.allowModelSelfExtension,
      // The session's approved marketplace host remains pinned through cleanup.
      pluginHost: pluginLease?.host,
      // Configured MCP servers (connected by the CLI before the TUI launched).
      // Their tools are network-gated + fenced as untrusted; the session closes
      // the host on cleanup.
      ...(options?.mcpHost ? { mcpHost: options.mcpHost } : {}),
      // Capture the operator's current mode when a session is first constructed.
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
        homeDir: messagingHomeDir,
      },
      requestScope: (request) => {
        const deferred = trackedRequest<ConsoleScopeResolution | null>(null);
        if (!alive.current || stoppingAuditRef.current) {
          deferred.resolve(null);
          return deferred.promise;
        }
        setPendingScope({ request, resolve: deferred.resolve });
        return deferred.promise;
      },
      requestLocalScope: (request) => {
        const deferred = trackedRequest<ConsoleLocalScopeResolution | null>(null);
        if (!alive.current || stoppingAuditRef.current) {
          deferred.resolve(null);
          return deferred.promise;
        }
        setPendingLocalScope({ request, resolve: deferred.resolve });
        return deferred.promise;
      },
      escalateScopedAudit: (request) => {
        const deferred = trackedRequest<boolean>(false);
        if (!alive.current || stoppingAuditRef.current) {
          deferred.resolve(false);
          return deferred.promise;
        }
        setPendingEscalation({ request, resolve: deferred.resolve });
        return deferred.promise;
      },
      approveTool: (call, risk) => {
        const deferred = trackedRequest<boolean>(false);
        if (!alive.current || stoppingAuditRef.current) {
          deferred.resolve(false);
          return deferred.promise;
        }
        setPendingToolApproval({ call, risk, resolve: deferred.resolve });
        return deferred.promise;
      },
      // The `ask_operator` question channel. Unlike the gates above it grants
      // nothing — it surfaces the model's structured question, waits for the
      // operator's answer, and resolves it (or null on Esc / a dead console).
      askOperator: (request) => {
        const deferred = trackedRequest<OperatorQuestionAnswer | null>(null);
        if (!alive.current || stoppingAuditRef.current) {
          deferred.resolve(null);
          return deferred.promise;
        }
        setPendingOperatorQuestion({ request, resolve: deferred.resolve });
        return deferred.promise;
      },
    }, options?.dbPath);
    } catch (error) {
      pluginLease?.release();
      throw error;
    }
    const cleanup = created.cleanup;
    let cleanupPromise: Promise<void> | undefined;
    created.cleanup = () => cleanupPromise ??= (async () => {
      appendTuiEvent({ kind: "wrap-cleanup", stage: "enter", cached: Boolean(cleanupPromise) });
      try { await cleanup(); appendTuiEvent({ kind: "wrap-cleanup", stage: "core-done" }); }
      finally { pluginLease?.release(); appendTuiEvent({ kind: "wrap-cleanup", stage: "lease-released" }); }
    })().catch((error: unknown) => {
      cleanupPromise = undefined;
      throw error;
    });
    cloudSource.current = { owner: created, isHosted: () => runtime.getConfigurationDiagnostics().provider === "hosted", env };
    runtimeInfoHandle.current = {
      model: () => runtime.resolvedModel(),
      providerId: () => runtime.getConfigurationDiagnostics().provider,
    };
    // resolvedModel() is the id the runtime actually settled on after
    // provider detection — not necessarily what was requested — so it is
    // the only value honest enough to display.
    return { session: created, model: runtime.resolvedModel() };
  }, [options, pluginHostManager, messagingHomeDir, trackedRequest, runtimeInfoHandle]);

  useEffect(() => {
    if (closingRef.current) return;
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
      sessionRef.current = created;
      setModelId(built.model);
      setSession(created);
      if (resumeMessages && resumeMessages.length > 0) {
        setEntries(entriesFromStoredMessages(resumeMessages));
      }
    } catch (error) {
      recordProblem("runtime", error);
      const detail = error instanceof Error ? error.message : String(error);
      setStartupError(startupRecoveryText(detail));
      const recovery = connectionRecoveryForError(detail);
      if (recovery) connectionFailureRef.current?.(recovery);
    }

    return () => {
      alive.current = false;
      void closeHandle.current?.().catch((error: unknown) => {
        appendTuiCrash({ source: "audit-cleanup", error: serializeError(error) });
      });
    };
  }, []);
  useEffect(() => {
    if (!interactive) return;
    try {
      const source = cloudSource.current;
      const env = source && source.owner === session ? source.env : credentialEnvPatch(loadCredentials(), process.env);
      loadCloudCredentials({ env, warn: () => {} });
      setCloudConfigured(true);
    } catch (error) {
      setCloudConfigured(error instanceof Error && error.name === "CloudAuthMissingError" ? false : undefined);
    }
  }, [session, startupError, interactive]);

  useEffect(() => {
    if (!interactive) return;
    const source = cloudSource.current;
    if (!session || !source || source.owner !== session || !source.isHosted()) {
      setCloudBalance(null);
      setHostedCatalog(null);
      return;
    }
    let active = true;
    let pending = false;
    const refresh = async () => {
      if (pending || !active) return;
      setHostedCatalog(null);
      if (!source.isHosted()) { setCloudBalance(null); return; }
      pending = true;
      setCloudBalance({ owner: session, state: { status: "loading" } });
      try {
        const credentials = loadCloudCredentials({ env: source.env, warn: () => {} });
        const client = new CloudClient({ host: credentials.host, token: credentials.token });
        const [account, catalog] = await Promise.all([
          client.getInferenceAccount(),
          settings.showContextMeter ? client.getInferenceModels().catch(() => null) : Promise.resolve(null),
        ]);
        if (!active || cloudSource.current !== source) return;
        const current = loadCloudCredentials({ env: source.env, warn: () => {} });
        if (!source.isHosted()) { setCloudBalance(null); return; }
        const sameCredentials = current.host === credentials.host && current.token === credentials.token;
        setCloudBalance({ owner: session, state: sameCredentials ? hostedBalanceState(account) : { status: "unavailable" } });
        if (sameCredentials && catalog) {
          try {
            setHostedCatalog({ owner: session, models: buildHostedModelCatalog(catalog.data, account), expiresAt: Date.now() + 60_000 });
          } catch { /* Malformed catalog metadata cannot establish a context limit. */ }
        }
      } catch {
        if (active && cloudSource.current === source) {
          setCloudBalance(source.isHosted() ? { owner: session, state: { status: "unavailable" } } : null);
        }
      } finally { pending = false; }
    };
    void refresh();
    const interval = setInterval(() => { void refresh(); }, 30_000);
    return () => { active = false; clearInterval(interval); };
  }, [session, busy, interactive, settings.showContextMeter]);
  // Marketplace changes never replace this session's runtime or live harness.
  // Its leased host remains usable until cleanup; new chats acquire the new set.
  useEffect(() => {
    if (!pluginHostManager) return;
    return pluginHostManager.onChanged(() => {
      appendEntry({
        kind: "notice",
        text: "Marketplace updated for new audits",
        detail: "Use /new to load the changed plugins. This audit keeps its current tools and live harness.",
        turn: turn.current,
      });
    });
  }, [pluginHostManager, appendEntry]);

  const reconnectProvider = useCallback((providerId: string) => {
    const knownProvider = PROVIDERS.find((candidate) => candidate.id === providerId);
    if (providerId !== "hosted" && !knownProvider) {
      appendEntry({ kind: "error", text: "Unknown connection", detail: providerId, turn: turn.current });
      return;
    }
    const provider = providerId as NonNullable<RuntimeConfig["provider"]>;
    const providerLabel = providerId === "hosted"
      ? "0sec Cloud"
      : knownProvider?.label ?? providerId;
    onNextChatOptions?.({ providerId: provider });
    if (sessionRef.current) {
      appendEntry({
        kind: "notice",
        text: `${providerLabel} saved for new audits`,
        detail: "Use /new to use this connection. The current runtime, conversation and live harness are unchanged.",
        turn: turn.current,
      });
      return;
    }
    try {
      const built = buildSession({ providerId: provider, model: options?.model, initialMessages: options?.initialMessages });
      sessionRef.current = built.session;
      modelIdRef.current = built.model;
      setSession(built.session);
      setModelId(built.model);
      setStartupError(null);
      appendEntry({ kind: "notice", text: `${providerLabel} configured`, turn: turn.current });
    } catch (error) {
      appendEntry({
        kind: "error",
        text: `${providerLabel} is not connected yet`,
        detail: error instanceof Error ? error.message : String(error),
        turn: turn.current,
      });
    }
  }, [appendEntry, buildSession, options?.model, options?.initialMessages, onNextChatOptions]);

  useEffect(() => {
    if (!reconnectHandle) return;
    reconnectHandle.current = reconnectProvider;
    return () => {
      reconnectHandle.current = null;
    };
  }, [reconnectHandle, reconnectProvider]);

  const selectModel = useCallback((requested: string) => {
    onNextChatOptions?.({ model: requested });
    if (sessionRef.current) {
      appendEntry({
        kind: "notice",
        text: `Next-audit model: ${requested}`,
        detail: "Use /new to start with this model. This audit keeps its runtime, accounting and live harness.",
        turn: turn.current,
      });
      return;
    }
    try {
      const built = buildSession({ model: requested, initialMessages: options?.initialMessages });
      sessionRef.current = built.session;
      modelIdRef.current = built.model;
      setSession(built.session);
      setModelId(built.model);
      setStartupError(null);
      appendEntry({ kind: "notice", text: `Model: ${built.model} (${modelProvider(built.model)})`, turn: turn.current });
    } catch (error) {
      appendEntry({
        kind: "notice",
        text: `Could not start ${requested}`,
        detail: error instanceof Error ? error.message : String(error),
        turn: turn.current,
      });
    }
  }, [appendEntry, buildSession, options?.initialMessages, onNextChatOptions]);




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
    if (!interactive || !settings.showTimestamps) return;
    const timer = setInterval(() => setClockTick(Date.now()), 15_000);
    return () => clearInterval(timer);
  }, [settings.showTimestamps, interactive]);

  // Refresh the git context behind the status bar. readGitStatus never
  // throws and is time-boxed, so a huge or broken repo degrades to
  // "not a repo" instead of stalling a frame.
  useEffect(() => {
    if (!interactive) return;
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
  }, [interactive]);

  // Subscribe to subagent lifecycle + progress events from the core event bus.
  // Filter by this session's scanId. `activeSubagents` drives the compact
  // ACTIVE SUBAGENTS block (terminal states removed); `herdAgents` is the
  // richer model the rail and the inline focus view read — fed by the SAME pure
  // reducers the herd screen uses, and KEEPING terminal records so a completed
  // agent's summary/error stays readable in focus and its ✓/× glyph in the rail.
  useEffect(() => {
    if (!session) return;
    const scanId = session.scanId;
    const ownedScanIds = new Set([scanId]);
    const knownAgents = Object.values(herdAgentsRef.current);
    let extended: boolean;
    do {
      extended = false;
      for (const agent of knownAgents) {
        if (ownedScanIds.has(agent.parentScanId) && !ownedScanIds.has(agent.agentId)) {
          ownedScanIds.add(agent.agentId);
          extended = true;
        }
      }
    } while (extended);
    const unsub = eventBus.subscribe({
      emit: (type, payload) => {
        if (!payload || typeof payload !== "object") return;
        const eventData = payload as Record<string, unknown>;
        const parentScanId = eventData["parent_scan_id"];
        const producerScanId = eventData["scan_id"] ?? eventData["scanId"];
        if (producerScanId !== undefined && (typeof producerScanId !== "string" || !ownedScanIds.has(producerScanId))) return;
        if (typeof parentScanId === "string") {
          if (!ownedScanIds.has(parentScanId)) return;
        } else if (typeof producerScanId !== "string" || !ownedScanIds.has(producerScanId)) {
          return;
        }
        if (type === "subagent_lifecycle") {
          const event = payload as unknown as SubagentLifecyclePayload;
          ownedScanIds.add(event.agent_id);
          const previousStatus = herdAgentsRef.current[event.agent_id]?.status;
          const startsLife = event.status === "queued"
            ? previousStatus !== "queued"
            : event.status === "running" && previousStatus !== "queued" && previousStatus !== "running" && previousStatus !== "parked";
          if (startsLife) {
            workerEpochsRef.current.set(event.agent_id, (workerEpochsRef.current.get(event.agent_id) ?? 0) + 1);
            setOperatorStopped((previous) => {
              if (!previous.has(event.agent_id)) return previous;
              const next = new Set(previous);
              next.delete(event.agent_id);
              return next;
            });
          }
          setWorkerOutcomes((prev) => ({ ...prev, [event.agent_id]: event }));
          if (event.summary || event.error) {
            const answer = event.error || event.summary!;
            setSubagentTranscripts((prev) => {
              const existing = prev[event.agent_id] ?? [];
              if (existing.some((entry) => entry.kind === "assistant" && entry.text.includes(answer))) return prev;
              const result: ChatEntry = { id: `${event.agent_id}-result-${event.turns ?? 0}`, kind: event.error ? "error" : "assistant", text: answer, turn: event.turns ?? 0, at: Date.now() };
              return { ...prev, [event.agent_id]: [...existing, result].slice(-SUBAGENT_TRANSCRIPT_MAX) };
            });
          }
          if (event.name) agentNamesRef.current.set(event.agent_id, event.name);
          setActiveSubagents((prev) => reduceActiveSubagents(prev, event));
          setHerdAgents(applySubagentLifecycle(herdAgentsRef.current, eventData, Date.now()));
        } else if (type === "peer_message") {
          // An inter-agent message crossed the hub — render it as an IRC line in
          // the transcript. Resolve both endpoints to the roster's display names
          // (Main is itself; "all" is a broadcast); the accent colouring happens
          // in the renderer.
          const p = payload as unknown as PeerMessagePayload;
          const nameFor = (id: string): string =>
            id === "Main" || id === "all"
              ? id
              : agentNamesRef.current.get(id) ?? "Unnamed worker";
          appendEntry({
            kind: "peer",
            text: p.body,
            peerFrom: nameFor(p.from),
            peerTo: nameFor(p.to),
            at: p.ts,
            turn: turn.current,
          });
        } else if (type === "subagent_progress") {
          setHerdAgents(applySubagentProgress(herdAgentsRef.current, eventData, Date.now()));
        } else if (type === "subagent_message") {
          const p = payload as unknown as SubagentMessagePayload;
          setWorkerTelemetry((prev) => ({ ...prev, [p.agent_id]: p }));
          // Use the main conversation's argument formatting and rich cards,
          // retaining the complete bounded public result rather than reducing
          // tools without rich metadata to a one-line summary.
          const fresh: ChatEntry[] = [];
          if (p.assistant) {
            fresh.push({
              id: `${p.agent_id}-t${p.turn}-a`,
              kind: "assistant",
              text: p.assistant,
              turn: p.turn,
              at: p.ts,
            });
          }
          (p.tools ?? []).forEach((t, i) => {
            if (!t.running && !t.result.success) recordProblem("tool", t.result.error, t.call.name);
            fresh.push({
              id: `${p.agent_id}-t${p.turn}-x${i}`,
              kind: "tool",
              text: t.call.name,
              detail: t.running ? undefined : formatToolResult(t.call, t.result),
              toolPreview: t.running ? undefined : projectToolPreview(t.call, t.result),
              toolArgs: formatToolArgs(t.call),
              success: t.running ? undefined : t.result.success,
              ...toolCardFieldsFromMeta(t.result.meta),
              turn: p.turn,
              at: p.ts,
            });
          });
          if (fresh.length > 0) {
            setSubagentTranscripts((prev) => {
              const existing = prev[p.agent_id] ?? [];
              return {
                ...prev,
                [p.agent_id]: [...existing.filter((entry) => !fresh.some((next) => next.id === entry.id)), ...fresh].slice(-SUBAGENT_TRANSCRIPT_MAX),
              };
            });
          }
        } else if (type === "todos") {
          // A worker's plan must not replace this audit's root plan.
          if (producerScanId === scanId) setTodos(payload as unknown as TodosEventPayload);
        } else if (type === "session_objective") {
          const p = payload as unknown as SessionObjectivePayload;
          if (p.scanId !== scanId) return;
          setObjective(p.objective);
          if (p.objective.trim()) onAuditActivity({ title: p.objective.trim() });
        }
      },
    });
    return unsub;
  }, [session, setHerdAgents, recordProblem]);


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
    const count = settings.showSubagents ? workerRoster.length : 0;
    if (count === 0) setAgentNavIndex(-1);
  }, [agentNavIndex, workerRoster, settings.showSubagents]);

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
    setScopeRules(resolution.scope.raw.in_scope ?? []);
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
        title: "Authorize audit scope",
        context: `${owner.request.call.name} requests ${owner.request.requestedUrls.join(", ")}`,
        subject: owner.request.call.name,
        bodyLines: owner.request.requestedUrls.map((url) => `requests: ${url}`),
        borderColor: WARNING,
        titleColor: WARNING,
        items: [
          {
            id: APPROVAL_GRANT_ID,
            label: "Approve for this audit",
            meta: "adds the exact hosts",
            detail: "Exact hosts apply only to this audit. Existing deny rules still win.",
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
            label: "Enable for this audit",
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
      // A positively-classified destructive call is dressed as DANGER: the ERROR
      // tone, the card's danger glyph (severity), a static category line, and a
      // deny-first selection (below). This never changes that the gate fires or
      // what it authorizes — an unclassified/obfuscated call is simply calm.
      const danger = owner.risk?.level === "destructive";
      const dangerLabel = danger && owner.risk?.category
        ? describeDestructiveCategory(owner.risk.category)
        : undefined;
      const bodyLines = dangerLabel
        ? [`Destructive action: ${dangerLabel}`, ...argumentSummaryLines(owner.call.arguments)]
        : argumentSummaryLines(owner.call.arguments);
      return {
        owner,
        title: `${modeLabel(modeRef.current)} approval`,
        context: `${owner.call.name} ${JSON.stringify(owner.call.arguments)}`,
        subject: owner.call.name,
        bodyLines,
        borderColor: danger ? ERROR : INFO,
        titleColor: danger ? ERROR : INFO,
        severity: danger ? "danger" : undefined,
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
        // directly — the semantics of the default answer are unchanged. The ONE
        // exception is a DANGER prompt: it opens on the declining choice, so a
        // reflexive Enter denies rather than runs a destructive call.
        : createSelectorState(
            approvalPrompt.title,
            approvalPrompt.items,
            approvalPrompt.severity === "danger" ? APPROVAL_DENY_ID : APPROVAL_GRANT_ID,
          ))
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
  useEffect(() => {
    onAuditActivity({ activity: runningTool ? `Running ${runningTool}` : busy ? "Working on audit" : "" });
  }, [runningTool, busy, onAuditActivity]);
  /**
   * Interrupt handle for the turn in flight, or null when none is running.
   * Held in a ref because the keyboard handler must reach the CURRENT turn's
   * controller, not the one captured when the handler was built.
   */
  const abortRef = useRef<AbortController | null>(null);
  const turnSettledRef = useRef<Promise<void> | null>(null);
  const stopAuditPromiseRef = useRef<Promise<void> | null>(null);
  const closePromiseRef = useRef<Promise<void> | null>(null);
  const stoppingAuditRef = useRef(false);

  // Cancellation is checkpoint-based. Keep its feedback out of the transcript.
  const interruptTurn = useCallback(() => {
    const controller = abortRef.current;
    if (!controller || controller.signal.aborted) return false;
    controller.abort();
    showToast("Interrupting main turn…");
    return true;
  }, [showToast]);
  const captureStopScope = useCallback((workerId?: string): Map<string, number> => {
    const rootId = workerId ?? sessionRef.current?.scanId;
    const captured = new Map<string, number>();
    if (!rootId) return captured;
    const family = new Set([rootId]);
    const records = Object.values(herdAgentsRef.current);
    let extended: boolean;
    do {
      extended = false;
      for (const record of records) {
        if (family.has(record.parentScanId) && !family.has(record.agentId)) {
          family.add(record.agentId);
          extended = true;
        }
      }
    } while (extended);
    for (const record of records) {
      if (family.has(record.agentId) && (record.status === "queued" || record.status === "running" || record.status === "parked")) {
        captured.set(record.agentId, workerEpochsRef.current.get(record.agentId) ?? 0);
      }
    }
    return captured;
  }, []);

  const confirmStopped = useCallback((captured: ReadonlyMap<string, number>) => {
    setOperatorStopped((previous) => {
      let next: Set<string> | undefined;
      for (const [id, epoch] of captured) {
        if ((workerEpochsRef.current.get(id) ?? 0) !== epoch || previous.has(id)) continue;
        (next ??= new Set(previous)).add(id);
      }
      return next ?? previous;
    });
  }, []);

  const stopAudit = useCallback((): Promise<void> => {
    if (stopAuditPromiseRef.current) return stopAuditPromiseRef.current;
    const ownedSession = sessionRef.current;
    const captured = captureStopScope();
    const activeTurn = turnSettledRef.current;
    stoppingAuditRef.current = true;
    onAuditActivity({ stopping: true });
    queuedRef.current = [];
    setQueuedMessages([]);
    abortRef.current?.abort();
    for (const cancel of pendingCancellationsRef.current) cancel();
    pendingCancellationsRef.current.clear();
    setPendingScope(null);
    setPendingLocalScope(null);
    setPendingEscalation(null);
    setPendingToolApproval(null);
    setPendingOperatorQuestion(null);
    const stopping = Promise.resolve().then(async () => {
      const t0 = Date.now();
      appendTuiEvent({ kind: "stop-audit", stage: "await-turn" });
      await activeTurn;
      appendTuiEvent({ kind: "stop-audit", stage: "turn-settled", ms: Date.now() - t0 });
      await ownedSession?.stopPersistentAgents();
      appendTuiEvent({ kind: "stop-audit", stage: "agents-stopped", ms: Date.now() - t0 });
      confirmStopped(captured);
      onAuditActivity({ outcome: "stopped", workers: 0, waiting: false });
    }).finally(() => {
      stoppingAuditRef.current = false;
      stopAuditPromiseRef.current = null;
      onAuditActivity({ stopping: false });
    });
    stopAuditPromiseRef.current = stopping;
    return stopping;
  }, [captureStopScope, confirmStopped, onAuditActivity]);

  closeHandle.current = () => closePromiseRef.current ??= (async () => {
    closingRef.current = true;
    alive.current = false;
    const t0 = Date.now();
    appendTuiEvent({ kind: "close-handle", stage: "stop-audit" });
    await stopAudit();
    appendTuiEvent({ kind: "close-handle", stage: "audit-stopped", ms: Date.now() - t0, hasSession: Boolean(sessionRef.current) });
    if (sessionRef.current) await sessionRef.current.cleanup();
    else await options?.mcpHost?.closeAll();
    appendTuiEvent({ kind: "close-handle", stage: "cleaned-up", ms: Date.now() - t0 });
  })().catch((error: unknown) => {
    // Failed cleanup keeps the audit visible for the existing explicit retry.
    closePromiseRef.current = null;
    throw error;
  });

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
      case "capabilities":
        appendEntry({
          kind: "panel",
          text: "capabilities",
          panel: buildCapabilityPanel(getAllCapabilities()),
          turn: turn.current,
        });
        return true;
      case "status": {
        const panel = buildStatusPanel({
          model: modelId ?? undefined,
          provider: modelId ? modelProvider(modelId) : undefined,
          mode: modeLabel(mode),
          target: target || undefined,
          scopeRules,
          toolCount: session?.tools.length ?? 0,
          turns: turn.current,
          inputTokens: sessionTokens.input,
          outputTokens: sessionTokens.output,
        });
        if (lastContext !== undefined) {
          panel.rows.push({ label: "last model input", value: `${lastContext} tokens` });
        }
        if (turnBudget) {
          panel.rows.push({
            label: "turn usage",
            value: `${turnBudget.used} reported tokens${turnBudget.limit > 0 ? ` / ${turnBudget.limit} limit` : ""}`,
          });
        }
        appendEntry({ kind: "panel", text: "status", panel, turn: turn.current });
        return true;
      }
      case "scope":
        appendEntry({
          kind: "panel",
          text: "scope",
          panel: buildScopePanel({
            scopeRules: scopeIncludes,
            outOfScope: scopeExcludes,
            scopeConfigured: displayedScope !== undefined,
            mode: modeLabel(mode),
          }),
          turn: turn.current,
        });
        return true;
      case "new-chat":
        onNavigate("new-chat");
        return true;
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
        discardStreamPatches();
        setEntries([]);
        entriesRef.current = [];
        turn.current = 0;
        setTurnBudget(null);
        setLastContext(undefined);
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
        onNavigate("resume");
        return true;
      }
      case "providers":
        // Provider credentials, especially ChatGPT Codex device OAuth, belong
        // to the chat-owned OpenTUI connection pane. Keeping a second inline
        // key picker here created a divergent flow and could treat OAuth as a
        // generic API-key field.
        onNavigate("connect");
        return true;
      case "feedback": {
        const feedbackCommand = parseFeedbackCommand(args);
        if (feedbackCommand.kind === "usage") {
          setPicker({
            state: createSelectorState("Feedback", [
              { id: "write", label: "Write feedback", detail: "Save locally and review the exact message and destination before sending." },
              { id: "problem", label: "Review latest problem", detail: "Limited diagnostics only; no prompt or tool output.", disabled: latestProblemRef.current === null },
              { id: "privacy", label: "Problem-report preferences", meta: settingsRef.current.diagnosticReporting, detail: "Choose local-only, ask before sending, or automatic limited diagnostics." },
            ]),
            commit: (id) => {
              if (id === "privacy") openReportingChoices();
              else if (id === "problem" && latestProblemRef.current) stageFeedback(latestProblemRef.current);
              else if (id === "write") {
                restorePaletteDraft();
                if (composerRef.current.trim()) {
                  showToast("Draft kept · use /feedback submit <message> when ready.");
                } else {
                  setComposerText("/feedback submit ");
                  composingRef.current = true;
                  setComposing(true);
                }
              }
            },
            onCancel: () => { restorePaletteDraft(); },
          });
          return true;
        }

        if (feedbackCommand.kind === "submit") {
          const message = feedbackCommand.message;
          if (!message) {
            appendEntry({
              kind: "notice",
              text: "usage: /feedback submit <message>",
              detail: "Write feedback locally and show a preview before sending.",
              turn: turn.current,
            });
            return true;
          }

          const payload: FeedbackPayload = {
            message,
            timestamp: new Date().toISOString(),
            version: VERSION,
            model: modelId ?? undefined,
            mode: modeLabel(mode),
          };

          stageFeedback(payload);
          return true;
        }

        if (feedbackCommand.kind === "send") {
          if (!pendingFeedback) {
            appendEntry({
              kind: "notice",
              text: "no feedback to send",
              detail: "Use /feedback submit <message> first.",
              turn: turn.current,
            });
            return true;
          }

          if (pendingFeedback.preview === null) {
            appendEntry({
              kind: "notice",
              text: "cannot send feedback",
              detail: "Submission is blocked; the message was still saved locally. Use /feedback cancel to clear.",
              turn: turn.current,
            });
            return true;
          }

          // Fire-and-forget: show immediate notice, append result asynchronously
          const preview = pendingFeedback.preview;
          const payload = pendingFeedback.payload;
          setPendingFeedback(null);

          appendEntry({
            kind: "notice",
            text: "sending feedback…",
            detail: `Transmitting to ${preview.url}.`,
            turn: turn.current,
          });

          submitFeedback(payload, process.env, { expectedPreview: preview }).then((result) => {
            appendEntry({
              kind: result.ok ? "notice" : "error",
              text: result.ok ? "feedback sent" : "feedback not sent",
              detail: result.ok
                ? `Sent to ${preview.url}. Status: ${result.status}.`
                : (result.error ?? "unknown error"),
              turn: turn.current,
            });
          });

          return true;
        }

        if (feedbackCommand.kind === "cancel") {
          if (!pendingFeedback) {
            appendEntry({
              kind: "notice",
              text: "no pending feedback to cancel",
              turn: turn.current,
            });
            return true;
          }
          setPendingFeedback(null);
          appendEntry({
            kind: "notice",
            text: "pending feedback cancelled",
            detail: "The local copy remains saved; nothing was transmitted.",
            turn: turn.current,
          });
          return true;
        }

        // Plain /feedback <message> — local-only (existing behaviour)
        const written = appendFeedback({
          message: feedbackCommand.message,
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
      case "copy": {
        if (!session || busy) {
          showToast(busy ? "Wait for the active turn before exporting the complete conversation." : "No conversation is available to export.");
          return true;
        }
        try {
          const exported = exportChatConversation(session.messages);
          void copySelection(exported.text, { spawn: defaultSpawn, which: defaultWhich }).then((result) => {
            appendEntry({
              kind: result.ok ? "notice" : "error",
              text: result.ok
                ? result.method === "osc52" ? "Conversation sent to terminal clipboard; clipboard contents are not verified." : "Conversation copied."
                : "Clipboard unavailable; conversation JSON was saved.",
              detail: `Private JSON: ${exported.path}`,
              turn: turn.current,
            });
          }).catch(() => {
            appendEntry({ kind: "error", text: "Clipboard failed; conversation JSON was saved.", detail: exported.path, turn: turn.current });
          });
        } catch (error) {
          appendEntry({ kind: "error", text: "Could not export the conversation.", detail: error instanceof Error ? error.message : String(error), turn: turn.current });
        }
        return true;
      }
      case "impact": {
        if (!session || busy) {
          showToast(busy ? "Wait for the active turn before requesting an impact analysis." : "Connect a provider before requesting an impact analysis.");
          return true;
        }
        const explainImpact = (id: string) => {
          try {
            const focus = loadFindingFocus(id, { dbPath: options?.dbPath });
            void submitRef.current?.(buildFindingChatPrompt(focus, "impact"));
          } catch (error) {
            appendEntry({ kind: "error", text: "Could not load that finding.", detail: error instanceof Error ? error.message : String(error), turn: turn.current });
          }
        };
        if (args.trim()) {
          explainImpact(args.trim());
        } else {
          const findings = runFindingsFromEntries(entries).filter((finding) => finding.id);
          if (!findings.length) {
            appendEntry({ kind: "notice", text: "No saved findings in this conversation.", detail: "Use /impact <finding-id> for a saved finding, or /findings to choose one.", turn: turn.current });
          } else {
            setPicker({
              state: createSelectorState("Explain finding impact", findings.map((finding) => ({
                id: finding.id!, label: finding.title, detail: finding.severity,
              }))),
              commit: explainImpact,
              onCancel: restorePaletteDraft,
            });
          }
        }
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
          ? `Explain "${topic}" like I am five years old. Use 3–5 very short sentences, mostly under 12 words each. Use familiar everyday words and one simple comparison. No jargon, acronyms, code, headings, or baby talk. Say what happened, why it matters, and one thing to do next. Keep the facts accurate and say plainly what is not yet confirmed. Explain only; do not run new tests or tools.`
          : `Explain your previous result like I am five years old. Use 3–5 very short sentences, mostly under 12 words each. Use familiar everyday words and one simple comparison. No jargon, acronyms, code, headings, or baby talk. Say what happened, why it matters, and one thing to do next. Keep the facts accurate and say plainly what is not yet confirmed. Explain only; do not run new tests or tools.`;
        void submitRef.current?.(prompt);
        return true;
      }
      case "harness":
        onNavigate("harness");
        return true;
      case "settings":
        // The full screen, not the composer picker: settings want grouping,
        // real descriptions and reset affordances, none of which fit in a
        // list squeezed above the composer.
        onNavigate("settings");
        return true;
      case "keybindings":
        // run.tsx routes the "keybindings" destination to the rebinding editor;
        // chat just needs the nav entry (mirrors "/settings").
        onNavigate("keybindings");
        return true;
      case "audits":
      case "onboard":
        onNavigate(parsed.command);
        return true;
      case "stop": {
        if (args === "audit") {
          void stopAudit().catch((error: unknown) => {
            appendEntry({ kind: "error", text: "Audit stop failed", detail: error instanceof Error ? error.message : String(error), turn: turn.current });
          });
          return true;
        }
        if (args !== "worker" && !args.startsWith("worker ")) {
          appendEntry({ kind: "notice", text: "Use /stop audit or /stop worker <exact name or id>.", turn: turn.current });
          return true;
        }
        const requested = args.startsWith("worker ") ? args.slice(7).trim() : "";
        const id = requested || focusAgentId;
        const matches = id
          ? Object.values(herdAgentsRef.current).filter((record) => record.agentId === id || record.name === id)
          : [];
        if (matches.length !== 1 || !sessionRef.current) {
          appendEntry({ kind: "notice", text: "Use /stop audit or /stop worker <exact name or id>.", detail: matches.length > 1 ? "That name is ambiguous; use the worker id from its details." : "No unique owned worker selected.", turn: turn.current });
          return true;
        }
        const worker = matches[0]!;
        const captured = captureStopScope(worker.agentId);
        const ownedSession = sessionRef.current;
        void ownedSession.stopPersistentAgent(worker.agentId).then((stopped) => {
          if (stopped) {
            confirmStopped(captured);
            showToast(`Stopped ${worker.name || "worker"} and its descendants.`);
          } else {
            showToast("That worker is no longer live; no stop was confirmed.");
          }
        }).catch((error: unknown) => {
          appendEntry({ kind: "error", text: "Worker stop failed", detail: error instanceof Error ? error.message : String(error), turn: turn.current });
        });
        return true;
      }
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
        selectModel(requested);
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
              meta: "full autonomy",
              detail: "No per-action prompts. Asks before accessing a new target.",
              current: mode === "yolo",
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
        modeRef.current = next;
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
        setFocusAgentId(null);
        setAgentNavIndex(workerRoster.length ? 0 : -1);
        if (!workerRoster.length) appendEntry({ kind: "notice", text: "No workers yet. Delegated tasks will appear here.", turn: turn.current });
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
      case "herd":
        onNavigate("herd");
        return true;
      case "comms":
        // run.tsx routes the "comms" destination to the Agents Comms view (the
        // live fleet + inter-agent message stream); chat just needs the nav
        // entry (mirrors "/herd"/"/ops").
        onNavigate("comms");
        return true;
      case "ops":
        onNavigate("ops");
        return true;
      case "hackstore":
        // run.tsx routes the "market" destination to the Hackstore screen
        // (kept as the internal route id); chat just needs the nav entry
        // (mirrors "/ops"/"/settings").
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
      case "transcript":
        setReviewOpen(true);
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
    captureStopScope,
    confirmStopped,
    focusAgentId,
    stopAudit,
    commandCatalog,
    discardStreamPatches,
    lastContext,
    mode,
    modelId,
    onExit,
    onGoBack,
    onNavigate,
    openReportingChoices,
    restorePaletteDraft,
    setComposerText,
    showToast,
    stageFeedback,
    pendingFeedback,
    scopeLabel,
    scopeRules,
    displayedScope,
    scopeIncludes,
    scopeExcludes,
    copySelection,
    options?.dbPath,
    selectModel,
    session,
    sessionTokens,
    setPendingFeedback,
    target,
    turnBudget,
  ]);

  const send = useCallback(async (raw: string) => {
    const text = raw.trim();
    if (!text) return;
    if (routeSlashCommand(text)) return;
    if (busy || abortRef.current || stoppingAuditRef.current || !alive.current || !session) return;

    const currentTurn = ++turn.current;
    const turnStartedAt = Date.now();
    activeTurnStartedAt.current = turnStartedAt;
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
    const settled = Promise.withResolvers<void>();
    turnSettledRef.current = settled.promise;
    onAuditActivity({ title: objectiveRef.current || (entriesRef.current.find((entry) => entry.kind === "user")?.text || text).split("\n", 1)[0].slice(0, 100) });

    try {
      const outcome = await session.send(text, {
        onAssistantDelta: (chunk) => {
          assistantText += chunk;
          streamingRef.current = true;
          queueStreamPatch({
            kind: "assistant",
            text: assistantText,
            turn: currentTurn,
            at: Date.now(),
          });
        },
        onReasoningDelta: (chunk) => {
          reasoningText += chunk;
          queueStreamPatch({
            kind: "reasoning",
            text: reasoningText,
            turn: currentTurn,
            at: Date.now(),
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
          flushStreamPatches();
          setRunningTool(null);
          if (!result.success) recordProblem("tool", result.error, call.name);
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
                  // Give every settled tool an honest measured wall span so the
                  // duration can ride the top of its card (command cards keep
                  // their precise meta.durationMs via `settled`; every other tool
                  // gets Date.now() - start). The append-fallback below has no
                  // start stamp and legitimately stays duration-less.
                  next[i] = { ...settled, id: e.id, at: e.at, wallMs: settled.wallMs ?? (e.at != null ? Date.now() - e.at : undefined) };
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
          // Preserve rich metadata and a bounded projection of the actual output.
          settleRunningTool({
            kind: "tool",
            text: call.name,
            detail: formatToolResult(call, result),
            toolArgs: formatToolArgs(call),
            toolPreview: projectToolPreview(call, result),
            success: result.success,
            turn: currentTurn,
            ...toolCardFieldsFromMeta(result.meta),
          });
        },
        onUsage: (usage) => {
          // Only explicit finite caps belong in the budget meter. Cumulative
          // usage remains accounted separately from current context occupancy.
          setTurnBudget(Number.isFinite(usage.turnTokenBudget)
            ? { used: usage.turnTokensUsed, limit: usage.turnTokenBudget }
            : null);
          if (usage.kind === "planner") {
            setLastContext(Number.isFinite(usage.inputTokens) && usage.inputTokens > 0 ? usage.inputTokens : undefined);
          }
        },
        onNotice: (notice) => {
          setScopeRules(session.scope?.raw.in_scope ?? []);
          appendEntry({ kind: "notice", text: notice, turn: currentTurn });
        },

      }, { signal: controller.signal });
      onAuditActivity({
        outcome: outcome.stopReason === "cancelled" ? "stopped"
          : outcome.stopReason === "error" ? "failed"
          : outcome.stopReason === "max_turn_tokens" || outcome.stopReason === "max_tool_iterations" ? "waiting"
          : !assistantText && !outcome.assistantText && outcome.toolCalls.length === 0 ? "failed"
          : "completed",
      });

      if (!assistantText && outcome.assistantText) {
        appendEntry({ kind: "assistant", text: outcome.assistantText, turn: currentTurn });
      }
      setSessionTokens((prev) => ({
        input: prev.input + outcome.usage.inputTokens,
        output: prev.output + outcome.usage.outputTokens,
      }));
      // Context occupancy = the tokens the last model call actually sent (the
      // whole conversation resent). Some backends (e.g. the ChatGPT/Codex wire)
      // report usage only on the RETURN value, not through the streaming
      // `onUsage(kind:"planner")` callback above — so without this the meter
      // stayed at 0% for a full conversation. Fall back to the turn's final
      // input count whenever it is a real, positive measurement.
      if (Number.isFinite(outcome.usage.inputTokens) && outcome.usage.inputTokens > 0) {
        setLastContext(outcome.usage.inputTokens);
      }
      turnUsage = { inputTokens: outcome.usage.inputTokens, outputTokens: outcome.usage.outputTokens };

      // A turn that fails must say so. The engine reports failure through
      // `stopReason`/`error`, and neither was surfaced before: a provider
      // rejection rendered as "0 tool calls · 0→0 tok" and nothing else,
      // which reads as the agent having simply ignored the operator.
      const producedText = Boolean(assistantText || outcome.assistantText);
      if (outcome.stopReason === "error") {
        const trimmed = outcome.error?.trim();
        const detail = trimmed
          ? trimmed
          : `The runtime reported an error but gave no message — see ${tuiLogPath()}.`;
        recordProblem("runtime", outcome.error);
        appendEntry({
          kind: "error",
          text: "turn failed",
          detail,
          turn: currentTurn,
        });
        const recovery = connectionRecoveryForError(detail);
        if (recovery) onConnectionFailure?.(recovery);
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
            ?? "The tool-round backstop was reached. History is preserved; review the progress before continuing.",
          turn: currentTurn,
        });
      } else if (outcome.stopReason !== "cancelled" && !producedText && outcome.toolCalls.length === 0) {
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

      if (settings.showTurnSummary && outcome.stopReason !== "cancelled") {
        appendEntry({
          kind: "notice",
          text: `${outcome.toolCalls.length} tool call${outcome.toolCalls.length === 1 ? "" : "s"} · ${outcome.usage.inputTokens}→${outcome.usage.outputTokens} tok`,
          turn: currentTurn,
        });
      }
    } catch (error) {
      onAuditActivity({ outcome: controller.signal.aborted ? "stopped" : "failed" });
      recordProblem("runtime", error);
      // Never surface a bare "unknown"/empty: an Error with no message falls
      // back to its name + first stack frame and a pointer to the always-on log
      // (where recordProblem just wrote the full stack).
      const detail = describeErrorForSurface(error);
      appendEntry({
        kind: "error",
        text: "turn failed",
        detail,
        turn: currentTurn,
      });
      const recovery = connectionRecoveryForError(detail);
      if (recovery) onConnectionFailure?.(recovery);
      setTurnBudget(null);
    } finally {
      try {
      // Drop the controller before clearing `busy`, so Esc can never abort a
      // turn that has already returned.
      if (abortRef.current === controller) abortRef.current = null;
      flushStreamPatches();
      activeTurnStartedAt.current = null;
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
        pruneSessions(undefined, { protectedIds: protectedSessionIds });
      }
      } finally {
      settled.resolve();
      if (turnSettledRef.current === settled.promise) turnSettledRef.current = null;
      }
    }
  }, [
    appendEntry,
    busy,
    flushStreamPatches,
    queueStreamPatch,
    onConnectionFailure,
    onAuditActivity,
    protectedSessionIds,
    recordProblem,
    routeSlashCommand,
    session,
    settings.showTurnSummary,
  ]);
  submitRef.current = send;

  // Steer a running subagent from the chat composer while drilled into it: build
  // an `operator` messaging runtime pinned to the live roster (so a dead id is
  // refused) and hand it to `sendOperatorMessage`, which re-checks addressing and
  // spools into the hub mailbox the child drains. The console session IS "Main"
  // (the parent/operator), so `selfId` matches the parent identity children reply
  // to. Honors the same operator-channel setting the session was built with.
  const deliverToSubagent = useCallback(
    (agentId: string, body: string): { ok: boolean; reason?: string } => {
      if (!settingsRef.current.allowSubagentOperatorMessaging) {
        return { ok: false, reason: "operator→subagent messaging is off (see /settings)" };
      }
      const runtime: MessagingRuntime = {
        selfId: "Main",
        selfRole: "operator",
        siblingChannelEnabled: false,
        operatorChannelEnabled: true,
        projectPath: process.cwd(),
        homeDir: messagingHomeDir,
        knownPeerIds: Object.keys(activeSubagents),
      };
      const result = sendOperatorMessage(runtime, agentId, body.trim(), Date.now());
      if (result.ok) {
        // sendOperatorMessage is pure (no bus), so surface the operator's steer in
        // the IRC log here — Main → the addressed agent — the same way an
        // agent↔agent send appears via the peer_message event.
        appendEntry({
          kind: "peer",
          text: body.trim(),
          peerFrom: "Main",
          peerTo: agentNamesRef.current.get(agentId) ?? "Unnamed worker",
          at: Date.now(),
          turn: turn.current,
        });
      }
      return { ok: result.ok, reason: result.reason };
    },
    [settingsRef, activeSubagents, appendEntry, messagingHomeDir],
  );

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
      busy: busy || abortRef.current !== null,
      hasSession: Boolean(session),
    });
    if (disposition === "queue") {
      const { queue, accepted } = enqueueComposerInput(queuedRef.current, input);
      queuedRef.current = queue;
      setQueuedMessages(queue);
      // Steer interrupts only the main turn. Detached workers own their lifetime.
      // Queue mode waits unless the user explicitly presses empty Enter.
      const interrupting = accepted && settings.busyInputMode === "steer" && interruptTurn();
      if (!interrupting) {
        appendEntry({
          kind: accepted ? "notice" : "error",
          text: accepted
            ? `queued — will send when the current turn ends: ${input}`
            : `queue is full (${COMPOSER_QUEUE_LIMIT} messages); not queued: ${input}`,
          turn: turn.current,
        });
      }
      // The transient stopping status covers the wait until the idle drain.
    } else if (disposition === "send") {
      void send(input);
    }
  }, [appendEntry, busy, send, session, interruptTurn, settings.busyInputMode]);

  useEffect(() => {
    if (!submitHandle) return;
    submitHandle.current = submitOperatorMessage;
    return () => {
      submitHandle.current = null;
    };
  }, [submitHandle, submitOperatorMessage]);
  useEffect(() => {
    const prompt = initialPromptRef.current;
    if (!prompt || !session) return;
    initialPromptRef.current = null;
    submitOperatorMessage(prompt);
  }, [session, submitOperatorMessage]);


  // Deliver one parked message per idle transition. One at a time rather than a
  // loop: delivering makes the console busy again, so the NEXT idle drains the
  // one after it. That preserves FIFO order without the drain re-entering
  // itself, and it means a queued message never races the turn it was typed
  // during.
  useEffect(() => {
    if (busy || abortRef.current || stoppingAuditRef.current || !alive.current || !session) return;
    const { next, rest } = dequeueComposerInput(queuedRef.current);
    if (next === undefined) return;
    queuedRef.current = rest;
    setQueuedMessages(rest);
    void submitRef.current?.(next);
  }, [busy, session]);

  // usePaste shares AppContext.keyHandler with useKeyboard, so an overlay
  // owns the paste exclusively while the persistent chat remains mounted.
  usePaste((event) => {
    if (!interactive || stoppingAuditRef.current) return;
    const text = sanitizeComposerText(decodePasteBytes(event.bytes).replace(/\r\n?/g, "\n"));
    if (!text) return;
    if (secretPrompt) {
      setSecretPrompt((prompt) => prompt ? { ...prompt, value: prompt.value + text } : prompt);
      return;
    }
    if (pendingOperatorQuestion) {
      setOperatorState((state) => state ? operatorAppend(state, text) : state);
      return;
    }
    if (approvalPrompt || picker || reviewOpen) return;
    composingRef.current = true;
    setComposing(true);
    setComposerText(composerRef.current + text);
  });

  useKeyboard((key) => {
    if (!interactive || stoppingAuditRef.current) return;
    // While the right-click context menu is open it owns the keyboard (its own
    // handler moves the highlight / activates / closes); bail so the transcript
    // beneath does not also act on Up/Down/Enter/Esc.
    if (transcriptMenu.state.open) return;
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
    // The rebindable set resolves its chord through `matchesBinding` against the
    // operator's persisted overrides rather than a hard-coded `key.name` literal,
    // so `/keybindings` remaps actually take effect. `matchesBinding` falls back
    // to the registry default when there is no override. The protected set
    // (arrows, Enter, Esc, Ctrl+C, the modal scroll verbs, the review extremes
    // and Right→accept-suggestion) keeps its literal guards on purpose.
    const keybindingOverrides = settingsRef.current.keybindings;
    if (reviewOpen) {
      // review-toggle is rebindable, so its close chord is resolved too (Esc
      // always closes as well). The overlay's own scroll verbs stay literal —
      // they are the protected modal Page/Ctrl+Home/End set.
      if (key.name === "escape" || matchesBinding(key, "overlay.review-toggle", keybindingOverrides)) {
        setReviewOpen(false);
        return;
      }

      const review = reviewRenderableRef.current;
      if (!review) return;
      const pageRows = Math.max(1, Math.floor(review.height / 2));
      if (key.name === "pageup" || (key.ctrl && key.name === "up")) {
        review.scrollY -= pageRows;
        return;
      }
      if (key.name === "pagedown" || (key.ctrl && key.name === "down")) {
        review.scrollY += pageRows;
        return;
      }
      if (key.ctrl && key.name === "home") {
        review.scrollY = 0;
        return;
      }
      if (key.ctrl && key.name === "end") {
        review.scrollY = review.maxScrollY;
      }
      return;
    }
    if (matchesBinding(key, "overlay.review-toggle", keybindingOverrides)) {
      setReviewOpen(true);
      return;
    }
    // ── Inline subagent focus view (modal) ─────────────────────────────────────
    // Drilled into ONE subagent: the live meta + activity panes replace the
    // transcript. While the composer is IDLE, Up/Down (and PageUp/PageDown)
    // scroll the activity back from its tail and Left/Esc returns to the agents
    // list. A printable key falls through to the idle→compose transition below,
    // so the operator can type a message straight to the focused subagent
    // (delivered on Enter by the composing block, which routes to it when
    // `focusAgentId` is set). Once composing, this branch yields entirely so the
    // composer owns typing/editing/Enter exactly as it does on the main screen.
    if (focusAgentId && !composingRef.current) {
      if (key.name === "escape" || key.name === "left") {
        setFocusAgentId(null);
        setFocusScrollOffset(0);
        setAgentNavIndex(0);
        return;
      }
      if (key.name === "up") {
        if (focusTranscriptRef.current) focusTranscriptRef.current.scrollBy(-1);
        else setFocusScrollOffset((offset) => offset + 1);
        return;
      }
      if (key.name === "down") {
        if (focusTranscriptRef.current) focusTranscriptRef.current.scrollBy(1);
        else setFocusScrollOffset((offset) => Math.max(0, offset - 1));
        return;
      }
      if (key.name === "pageup") {
        // Real transcript → scroll its scrollbox (like the main transcript);
        // activity-ring fallback → step the windowed offset.
        if (focusTranscriptRef.current) focusTranscriptRef.current.scrollBy(-0.5, "viewport");
        else setFocusScrollOffset((offset) => offset + 5);
        return;
      }
      if (key.name === "pagedown") {
        if (focusTranscriptRef.current) focusTranscriptRef.current.scrollBy(0.5, "viewport");
        else setFocusScrollOffset((offset) => Math.max(0, offset - 5));
        return;
      }
      // No blanket return: a printable key drops through to the compose
      // transition so typing to the subagent Just Works.
    }
    // ── Active-subagent list navigation (modal) ────────────────────────────────
    // Selection has moved out of the composer and INTO the ACTIVE SUBAGENTS
    // block. Up/Down move (wrapping) within the visible rows; Enter drills into
    // the highlighted agent; Left or Esc returns focus to the composer. The list
    // is the block's own visible subset, so the highlight is always on screen.
    if (agentNavIndex >= 0) {
      const navList = settings.showSubagents ? workerRoster : [];
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
    // Main-transcript scrolling is rebindable (nav.scroll-up / nav.scroll-down).
    // The default answers PageUp/Ctrl+Up and PageDown/Ctrl+Down; an override
    // replaces those with the operator's chord. The MODAL scroll handlers inside
    // the review overlay and the focus view above keep their literal Page/Ctrl
    // guards — those scroll a different surface and are protected.
    if (matchesBinding(key, "nav.scroll-up", keybindingOverrides)) {
      transcriptRef.current?.scrollBy(-0.5, "viewport");
      return;
    }
    if (matchesBinding(key, "nav.scroll-down", keybindingOverrides)) {
      transcriptRef.current?.scrollBy(0.5, "viewport");
      return;
    }
    // The rebindable global chords, resolved through `matchesBinding` (see the
    // const above) so `/keybindings` remaps take effect. They are handled above
    // the composing block so a chord never reaches the composer's text catch-all
    // (which only appends non-ctrl sequences anyway).
    //
    // transcript-detail flips the whole transcript between collapsed and
    // expanded detail; both sidebars toggle their pane. All three persist via
    // the settings store (the same layer `/settings` writes), so the choice
    // survives the session and the store's subscribers repaint immediately.
    if (matchesBinding(key, "view.transcript-detail", keybindingOverrides)) {
      updateSetting(
        "transcriptDetail",
        settingsRef.current.transcriptDetail === "collapsed" ? "expanded" : "collapsed",
      );
      return;
    }
    if (matchesBinding(key, "view.left-sidebar", keybindingOverrides)) {
      updateSetting("showLeftSidebar", !settingsRef.current.showLeftSidebar);
      return;
    }
    if (matchesBinding(key, "view.right-sidebar", keybindingOverrides)) {
      updateSetting("showRightSidebar", !settingsRef.current.showRightSidebar);
      return;
    }
    // nav.jump-agents (Ctrl+G) drops straight into the active-subagents list —
    // the same affordance Down offers on an empty composer, reachable directly
    // and while composing. Only acts when there are workers to jump to;
    // otherwise it falls through so the chord is a harmless no-op.
    if (matchesBinding(key, "nav.jump-agents", keybindingOverrides)) {
      const navList = settings.showSubagents ? workerRoster : [];
      if (navList.length > 0) {
        setAgentNavIndex(0);
        return;
      }
    }
    // nav.open-comms (Ctrl+T) opens the agent comms view via the shell nav.
    if (matchesBinding(key, "nav.open-comms", keybindingOverrides)) {
      onNavigate("comms");
      return;
    }
    // Ctrl+Y pulls the most recently queued message back into the composer for
    // editing — which doubles as cancel: it leaves the queue, and dropping it
    // (Esc) or re-sending it (Enter, re-queued at the back while still busy) is
    // then just normal composer editing. Newest-first so a hurried operator can
    // fix the last thing they typed without disturbing earlier parked lines.
    if (matchesBinding(key, "composer.edit-queued", keybindingOverrides) && queuedRef.current.length > 0) {
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
    // directly, so it uses the same live-mode transition and runtime readiness
    // checks. All four modes are available without a preconfigured scope.
    if (isAutonomyCycleKey(key)) {
      routeSlashCommand(`/mode ${nextAutonomyMode(modeRef.current)}`);
      return;
    }
    if (matchesBinding(key, "nav.palette", keybindingOverrides)) {
      if (restorePaletteDraft()) return;
      paletteDraftRef.current = { text: composerRef.current, composing: composingRef.current };
      composingRef.current = true;
      setComposing(true);
      setComposerText("/");
      return;
    }
    if (key.name === "escape") {
      if (restorePaletteDraft()) return;
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
      // Esc interrupts the main turn, not its independently running workers.
      // Overlay and draft dismissal keep precedence over turn interruption.
      if (interruptTurn()) return;
      onGoBack();
      return;
    }
    if (key.name === "return" && !key.shift && !focusAgentId) {
      const action = queuedInputAction({
        input: composerRef.current,
        busy: busy || abortRef.current !== null,
        hasSession: Boolean(session),
        queuedCount: queuedRef.current.length,
      });
      if (action !== "none") {
        if (action === "interrupt") {
          // Keep the queue intact until the interrupted send has settled.
          interruptTurn();
        } else {
          const { next, rest } = dequeueComposerInput(queuedRef.current);
          queuedRef.current = rest;
          setQueuedMessages(rest);
          if (next !== undefined) void send(next);
        }
        composingRef.current = false;
        setComposerText("");
        setComposing(false);
        return;
      }
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
          const navList = settings.showSubagents ? workerRoster : [];
          if (navList.length > 0) {
            setAgentNavIndex(0);
            return;
          }
        }
        recallComposerHistory("down");
        return;
      }
      // Right arrow accepts the inline autosuggestion (fish / Claude Code
      // style). The composer is append-only, so the caret is ALWAYS at
      // end-of-input while composing — the precondition for accepting — and →
      // fills the ghost suffix into the draft WITHOUT submitting, then leaves
      // the caret at the new end (setComposerText re-bases it there). With the
      // feature off, a slash draft, or no matching suggestion, → falls through
      // to its previous behaviour: a no-op, since the append-only composer has
      // no caret to move right. Arrows are protected (non-rebindable) keys, so
      // this is a literal key.name check like the Up/Down/Left handlers, not a
      // matchesBinding lookup.
      if (key.name === "right") {
        const suffix = settingsRef.current.composerSuggestions
          && !composerRef.current.trimStart().startsWith("/")
          ? suggestCompletion(composerRef.current, historyRef.current)
          : null;
        if (suffix) {
          setComposerText(`${composerRef.current}${suffix}`);
          return;
        }
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
        // Drilled into a subagent: a plain message is steered straight to it via
        // the hub mailbox, not sent to the main agent. Slash commands still run
        // as commands (they fall through), so /agents, /settings, etc. keep
        // working while focused.
        if (focusAgentId && !findCommand(input).isSlash) {
          const worker = herdAgents[focusAgentId];
          if (worker?.status === "completed" || worker?.status === "failed") {
            const result = renderInboundMessage({ id: `${focusAgentId}-followup`, from: focusAgentId, to: "Main", ts: Date.now(), body: worker.summary ?? worker.error ?? "" }).text;
            submitOperatorMessage(`Follow up on ${worker.name ?? focusAgentId}.\nTask: ${worker.task}\n${result}\n\nOperator request: ${input}`);
            setFocusAgentId(null);
            setAgentNavIndex(-1);
          } else {
            const res = deliverToSubagent(focusAgentId, input);
            setSubagentTranscripts((prev) => ({ ...prev, [focusAgentId]: [...(prev[focusAgentId] ?? []), { id: `${focusAgentId}-operator-${Date.now()}`, kind: res.ok ? "user" : "error", text: res.ok ? input : `${res.reason ?? "Message could not be delivered"}. Your draft is retained; Escape returns to Main.`, turn: worker?.turn ?? 0, at: Date.now() }] }));
            if (!res.ok) return;
          }
          historyRef.current = pushHistory(historyRef.current, input);
          composingRef.current = false;
          setComposerText("");
          setComposing(false);
          setCommandMenuVisible(false);
          return;
        }
        // Remember every submitted message (sent or queued) for Up/Down recall.
        // Done before the setComposerText("") below, which re-bases the history
        // cursor onto the freshly-grown ring.
        historyRef.current = pushHistory(historyRef.current, input);
        submitOperatorMessage(input);
        if (!restorePaletteDraft()) {
          composingRef.current = false;
          setComposerText("");
          setComposing(false);
          setCommandMenuVisible(false);
        }
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
        setComposerText(deletePreviousCharacter(composerRef.current));
        return;
      }
      if (key.sequence && !key.ctrl && !key.meta && !/[\x00-\x1f\x7f]/.test(key.sequence)) {
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
      const navList = settings.showSubagents ? workerRoster : [];
      if (navList.length > 0) {
        setAgentNavIndex(0);
        return;
      }
      recallComposerHistory("down");
      return;
    }
    if (key.sequence && !key.ctrl && !key.meta && !/[\x00-\x1f\x7f]/.test(key.sequence)) {
      composingRef.current = true;
      setComposing(true);
      setComposerText(key.sequence);
    }
  });

  const hasHarnessPresentation = !harness.showConversation && harness.workspaceTrusted &&
    harness.snapshot?.trusted === true && harness.snapshot.trustedUi.some((entry) => entry.tui);
  const empty = entries.length === 0 && Object.keys(herdAgents).length === 0 && !hasHarnessPresentation;
  // Parked messages are surfaced next to the working indicator, because that is
  // exactly where the operator is looking while they wait.
  const queueLabel = composerQueueLabel(queuedCount);
  // The header owns engagement posture: target, scope, session state, and the
  // optional objective. Autonomy mode belongs beside model and workspace state
  // in the bottom bar, where it is available without competing with the target.
  const focusedTelemetry = focusAgentId ? workerTelemetry[focusAgentId] : undefined;
  const activeModel = session ? runtimeInfoHandle.current?.model() : undefined;
  const activeProvider = session ? runtimeInfoHandle.current?.providerId() : undefined;
  const currentHostedCatalog = hostedCatalog && hostedCatalog.owner === session && hostedCatalog.expiresAt > Date.now() ? hostedCatalog.models : null;
  const contextLimit = useMemo(() => !focusAgentId && settings.showContextMeter
    ? resolveContextLimit({ modelId: activeModel, providerId: activeProvider, hosted: activeProvider === "hosted" }, { hostedCatalog: currentHostedCatalog })
    : null, [focusAgentId, settings.showContextMeter, activeModel, activeProvider, currentHostedCatalog]);
  // The live "what it's doing" one-liner: the active tool + its args, truthfully
  // (never fabricated). Only while the root turn is running and not focused on a
  // worker. Computed here because the status bar is built above the later
  // `runningEntry`.
  const statusRunningEntry = busy && !focusAgentId && runningTool
    ? entries.findLast((entry) => entry.kind === "tool" && entry.text === runningTool && entry.success === undefined)
    : undefined;
  const statusActivity = busy && !focusAgentId && runningTool
    ? (statusRunningEntry?.toolArgs ? `${runningTool} · ${statusRunningEntry.toolArgs}` : runningTool)
    : undefined;
  const statusSegments = buildStatusSegments({
    model: focusAgentId ? focusedTelemetry?.model : modelId ?? undefined,
    mode: autonomyFooterText(mode),
    activity: statusActivity,
    turnElapsedMs: settings.elapsedTimer !== "off" && !focusAgentId && busy && activeTurnStartedAt.current !== null
      ? Date.now() - activeTurnStartedAt.current : undefined,
    evolution: evolutionStatus,
    cwd: process.cwd(),
    home: homedir(),
    branch: git?.isRepo ? git.branch ?? git.detachedSha : undefined,
    modified: git?.modified,
    untracked: git?.untracked,
    inputTokens: focusAgentId ? focusedTelemetry?.usage?.inputTokens : sessionTokens.input,
    outputTokens: focusAgentId ? focusedTelemetry?.usage?.outputTokens : sessionTokens.output,
    cachedInputTokens: focusAgentId ? focusedTelemetry?.usage?.cachedInputTokens : undefined,
    showTokenUsage: settings.showTokenUsage,
    // Telemetry toggles: where the model name is surfaced, whether the
    // context reading renders as a visual meter, and whether an estimated
    // dollar cost is appended. status-bar.ts honours each and invents no
    // number it was not given.
    modelDisplay: settings.modelDisplay,
    showContextMeter: settings.showContextMeter,
    contextWindow: contextLimit?.tokens,
    contextUsed: !focusAgentId ? lastContext : undefined,
    showCost: settings.showCost,
    hostedBalance: !focusAgentId && cloudBalance && cloudBalance.owner === session && cloudSource.current?.isHosted()
      ? formatHostedBalance(cloudBalance.state) : undefined,
  });
  const runningWorkers = Object.values(herdAgents).filter((agent) => agent.status === "running" || agent.status === "queued").length;
  // The OMP-style pill row: the SAME segments, kept/dropped at the bar's real
  // width, each painted as its own coloured glyph+text with a subtle separator
  // between (rendered below via `renderStatusPills`). `statusBarText` remains as
  // the plain single-string fallback the bar degrades to if pills ever cannot
  // be drawn.
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
  const focusRecord = focusAgentId ? projectedHerdAgents[focusAgentId] : undefined;
  const focusPeer = focusAgentId
    ? subagentPeers(projectedHerdAgents, nowMs).find((peer) => peer.id === focusAgentId)
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
    showLeft: settings.showLeftSidebar && !focused && interactive && Boolean(renderAuditSwitcher),
    showRight: settings.showRightSidebar && !focused,
  });
  // Usable width INSIDE the transcript panel: the ledger box adds its own
  // paddingX (folded into the sidebar layout), which an entry's own border must
  // live within. Shrinks to make room when a sidebar is shown.
  const transcriptWidth = sidebars.transcriptWidth;
  // "0sec" is 4 cells. The optional objective sits at the top-right; target,
  // scope, and readiness take the remaining header cells. Autonomy mode lives
  // in the bottom status bar rather than competing with engagement posture.
  const sidebarControlWidth = contentWidth >= 64 ? 24 : 8;
  const headerObjective = !compact && settings.showObjective ? objective.trim() : "";
  const headerObjectiveWidth = headerObjective
    ? Math.max(0, Math.min(headerObjective.length, Math.floor((contentWidth - 4 - sidebarControlWidth) * 0.35)))
    : 0;
  const headerGapCells = headerObjectiveWidth > 0 ? 2 : 1;
  const headerEngagementWidth = Math.max(
    1,
    contentWidth - 4 - headerObjectiveWidth - headerGapCells - sidebarControlWidth - 1,
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
  useEffect(() => {
    if (reviewOpen && gateOpen) setReviewOpen(false);
  }, [gateOpen, reviewOpen]);
  const animationKind: AnimationKind | null = startupError ? null : gateOpen
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
  // Reset before painting so a new activity never inherits the previous timer.
  const activitySince = useMemo(() => Date.now(), [animationKind]);
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
    ? frameAt(animationKind, Date.now() - activitySince, {
        label: animationKind === "tool" ? runningTool ?? undefined : undefined,
        motion: !settings.reduceMotion && animationKind !== "awaiting-operator",
      })
    : null;
  const loadingLabel = animation?.glyph ?? "";
  const loadingWidth = loadingLabel ? textCells(loadingLabel) + 3 : 0;
  const statusContentWidth = Math.max(0, controlsWidth - loadingWidth);
  const visibleStatusSegments = settings.showStatusBar ? statusSegments
    : statusSegments.filter((segment) => segment.kind === "mode" || segment.kind === "elapsed");
  const statusPills = fitStatusPills(visibleStatusSegments, statusContentWidth);
  const statusBarText = fitStatusSegments(visibleStatusSegments, statusContentWidth);

  // Drive the animation at the kind's own interval; stop entirely when
  // nothing is animating so an idle console costs no repaints.
  useEffect(() => {
    if (!interactive || (!animationKind && runningWorkers === 0)) return;
    const timer = setInterval(
      () => setAnimTick((n) => n + 1),
      settings.reduceMotion || animationKind === "awaiting-operator" ? 1000 : animationKind ? frameIntervalMs(animationKind) : 120,
    );
    return () => clearInterval(timer);
  }, [animationKind, settings.reduceMotion, runningWorkers, interactive]);

  // One shared ticker for every shimmering label, at the shimmer cadence. Only
  // runs while `shimmerActive`, so a settled or idle surface costs no repaints.
  useEffect(() => {
    if (!interactive || !shimmerActive) return;
    const timer = setInterval(() => setShimmerFrame((n) => n + 1), SHIMMER_TEXT_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [shimmerActive, interactive]);

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

  // ACTIVE SUBAGENTS. `spawn_agents` fans out up to 8 with 4 running at
  // once, so this block is genuinely multi-row and genuinely unbounded —
  // and it was neither height-capped nor `flexShrink={0}`, so under column
  // pressure Yoga collapsed it and its rows painted into each other and
  // into the title. Cap what is shown, state the overflow, and reserve
  // EXACTLY what is rendered.
  // The compact ACTIVE SUBAGENTS block stays visible even while a subagent is
  // focused, so the operator keeps sight of the whole fleet and which one they
  // are drilled into (the focused row wears the highlight below). Its rows are
  // reserved in the ledger via computeLedgerRows regardless of focus, so the
  // focus transcript makes room for it.
  const subagentEntries = settings.showSubagents ? workerRoster : [];
  const hasSubagents = subagentEntries.length > 0;
  const visibleRosterLimit = Math.max(1, Math.min(SUBAGENT_MAX_VISIBLE, Math.floor(height / 5)));
  // The panel is EXPANDED by default so running agents are visible without the
  // operator arrowing in (the OMP-style "always show what the herd is doing").
  // It collapses to a one-line summary when the operator toggles the corner
  // control, and AUTO-collapses on a very narrow terminal where per-agent rows
  // would not fit. Drilling in (agentNavIndex >= 0) always forces it open so the
  // selection is on screen — the existing Down-arrow path keeps working.
  const subagentPanelNarrow = contentWidth < SUBAGENT_PANEL_MIN_WIDTH;
  const subagentPanelCollapsed = hasSubagents && agentNavIndex < 0 && (agentsPanelCollapsed || subagentPanelNarrow);
  const rosterStart = agentNavIndex >= 0 ? Math.max(0, agentNavIndex - visibleRosterLimit + 1) : 0;
  const subagentVisible = subagentPanelCollapsed
    ? []
    : agentNavIndex >= 0
      ? subagentEntries.slice(rosterStart, rosterStart + visibleRosterLimit)
      : subagentEntries.slice(0, visibleRosterLimit);
  const subagentOverflow = subagentEntries.length - subagentVisible.length;
  // Below the header: the visible rows plus a "+N more" tail whenever the
  // roster outruns the window (both when navigating and when resting expanded).
  const subagentOverflowRow = !subagentPanelCollapsed && subagentOverflow > 0 ? 1 : 0;
  // Collapsed → the single summary line (the header itself). Expanded → header
  // + rows + overflow tail.
  const subagentBlockRows = !hasSubagents
    ? 0
    : subagentPanelCollapsed
      ? 1
      : 1 + subagentVisible.length + subagentOverflowRow;
  // Selection within the block while navigating into it. Clamped every render so
  // an index left dangling by a finished agent lands back on a live row.
  const agentNavSelected =
    agentNavIndex >= 0 ? clampAgentSelection(subagentEntries.length, agentNavIndex) : -1;
  // The focused transcript already carries its own controls; reserve the
  // extra hint row only while navigating the roster.
  const showAgentNavHint = false;

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
  const composerStyle: TuiSettings["composerStyle"] =
    settings.composerStyle === "border" ? "rail" : settings.composerStyle;
  const composerInnerTextWidth = Math.max(1, sidebars.transcriptWidth - (composerStyle === "rail" ? 5 : 3));
  const composerInputRows = composing
    ? composerContentRows(sanitizeComposerText(composer).replace(/\t/g, "    "), composerInnerTextWidth).length : 1;
  const ledgerRows = computeLedgerRows({
    height,
    compact,
    composerRows: composerInputRows + (composerStyle === "plain" ? 0 : 2) + 1,
    // The picker and the command menu occupy the same slot and both carry a
    // marginTop, which computeLedgerRows adds for a non-zero menuRows.
    menuRows: commandMenuVisible ? commandMenuHeight : picker ? pickerBoxHeight : 0,
    subagentRows: subagentBlockRows > 0 ? subagentBlockRows + 1 : 0,
    approvalRows: (approvalPrompt ? approvalBoxHeight + 1 : 0)
      + (secretPrompt ? SECRET_PANEL_HEIGHT + 1 : 0)
      + (operatorQuestionOpen ? operatorBoxHeight + 1 : 0),
    // The agent-nav hint row (+ its marginTop) below the composer.
    hintRows: (showAgentNavHint ? 2 : 0) + 1 + (animation ? 2 : 0),
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
  const headerSegments: string[] = [];
  if (settings.showScope) headerSegments.push(`Scope: ${scopeLabel}`);
  headerSegments.push(sessionState);
  // Version rides at the far left of the top bar, like the startup masthead.
  const headerEngagement = [`v${VERSION}`, ...headerSegments].join(" · ");


  // Activity comes from the real in-flight call, not an invented model intent.
  // Its spinner lives once, below the composer in the loading/status row.
  const runningEntry = runningTool ? entries.findLast((entry) => entry.kind === "tool" && entry.text === runningTool && entry.success === undefined) : undefined;
  const workingLine = runningEntry?.toolArgs
    ? `${runningTool} · ${runningEntry.toolArgs}`
    : animation?.label ?? "";
  const canInterrupt = busy && !composing && !gateOpen && !picker && !commandMenuVisible && !reviewOpen;
  const workingLineFitted = fitTuiText(`${canInterrupt ? "Esc · " : ""}${workingLine}`, controlsWidth);
  const workingIndicator = animation ? (
    <box width="100%" height={1} flexShrink={0} marginTop={1} overflow="hidden">
      {shimmerActive
        ? <ShimmerText label={workingLineFitted} frame={shimmerFrame} base={MUTED} peak={TEXT} />
        : <text fg={animationKind === "awaiting-operator" ? WARNING : MUTED}>{workingLineFitted}</text>}
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
  // The inline autosuggestion shown as dimmed ghost text after the caret. Only
  // while composing a non-slash draft with the feature enabled; the pure prefix
  // match over submitted-message history lives in composer-suggest.ts. `null`
  // (empty draft, no match, or a draft equal to a full entry) shows nothing.
  const composerSuggestion = settings.composerSuggestions && composing && !isSlashComposer
    ? suggestCompletion(composer, historyRef.current)
    : null;
  const composerInput = (textWidth: number) => {
    const placeholder = startupError
      ? "type / for setup and commands"
      : queueLabel
        ? queueLabel
        : busy
          ? settings.busyInputMode === "queue"
            ? "type a follow-up · enter queues"
            : "type a follow-up · enter steers main"
          : !session
            ? "connecting · type to queue a message"
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
        suggestion={composerSuggestion}
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
    edgeToEdge = false,
    inputInset = 0,
  }: {
    textWidth: number;
    outerWidth?: number;
    padY?: number;
    edgeToEdge?: boolean;
    inputInset?: number;
  }) => (
    <box flexDirection="row" width={outerWidth ?? "100%"} flexShrink={0} marginTop={1} marginLeft={edgeToEdge ? -(compact ? 1 : 2) : 0} minWidth={0}>
      <ComposerFrame style={composerStyle} active={composerActive} theme={theme} padY={padY}>
        <box flexDirection="row" width="100%" minWidth={0} paddingLeft={inputInset}>
          <text width={1} flexShrink={0} fg={composing ? PRIMARY : MUTED}>›</text>
          <text width={1} flexShrink={0} fg={MUTED}> </text>
          <box width={textWidth} flexShrink={0} minWidth={0}>
            {composerInput(textWidth)}
          </box>
        </box>
      </ComposerFrame>
    </box>
  );
  const composerNode = buildComposer({
    textWidth: composerInnerTextWidth,
    outerWidth: width,
    edgeToEdge: true,
    inputInset: (compact ? 1 : 2) + (sidebars.leftVisible ? sidebars.leftWidth + sidebars.leftGap : 0),
  });

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
                `${composerQueueLabel(queuedMessages.length)} · enter sends next · ctrl+y edit`,
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
  const heroContentWidth = sidebars.rightVisible ? sidebars.transcriptWidth : contentWidth;
  const heroComposerWidth = Math.min(heroContentWidth, Math.max(40, Math.min(72, Math.floor(heroContentWidth * 0.6))));
  const heroComposerTextWidth = Math.max(1, heroComposerWidth - (composerStyle === "rail" ? 5 : 3));
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
      severity={approvalPrompt.severity}
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

  // Effective status per roster row (operator-stop and incomplete folded in),
  // reused by the row views and the collapsed summary so both read identically.
  const subagentEffectiveStatus = (sa: (typeof subagentEntries)[number]): string =>
    operatorStopped.has(sa.agent_id)
      ? "cancelled"
      : sa.status === "completed" && sa.done === false
        ? "incomplete"
        : sa.status;
  // The corner control is the "small button to expand": ▸ collapsed / ▾ open.
  // Clicking the header toggles it (or, while navigating, backs out to the
  // composer — the same exit the Left/Esc keys give). Collapsed, the header IS
  // the one-line summary; expanded, it carries the roster count and hints.
  const subagentToggleGlyph = subagentPanelCollapsed ? "▸" : "▾";
  const subagentHeaderText = subagentPanelCollapsed
    ? `${subagentToggleGlyph} ${summarizeRoster(subagentEntries.map(subagentEffectiveStatus))}`
    : agentNavIndex >= 0
      ? `${subagentToggleGlyph} agents (${subagentEntries.length}) · ↑↓ select · enter open · esc back`
      : `${subagentToggleGlyph} agents (${subagentEntries.length}) · ${runningWorkers} running · ↓ select`;
  const subagentNode = subagentBlockRows > 0 ? (
    <box flexDirection="column" width="100%" minWidth={0} height={subagentBlockRows} flexShrink={0} marginTop={1}>
      <box width={contentWidth} flexShrink={0} onMouseDown={() => {
        if (agentNavIndex >= 0) setAgentNavIndex(-1);
        else setAgentsPanelCollapsed((collapsed) => !collapsed);
      }}>
        <text fg={agentNavIndex >= 0 ? ACCENT : MUTED}>{fitTuiText(subagentHeaderText, contentWidth)}</text>
      </box>
      {subagentVisible.map((sa, index) => {
        const rec = herdAgents[sa.agent_id];
        const status = subagentEffectiveStatus(sa);
        const view: AgentRowView = {
          id: sa.agent_id,
          name: sa.name ?? rec?.name ?? agentNamesRef.current.get(sa.agent_id) ?? "Unnamed worker",
          task: sa.task ?? "",
          activity: summarizeAgentActivity({ status, tool: rec?.tool, note: rec?.note, turn: rec?.turn, maxTurns: rec?.maxTurns ?? sa.max_turns }),
          status,
          animationFrame: settings.reduceMotion ? undefined : animTick,
          accent: agentAccentFor(sa.agent_id, theme.CANVAS),
        };
        return <AgentTreeRow key={sa.agent_id} view={view} width={contentWidth} theme={theme}
          selected={index + rosterStart === agentNavSelected || sa.agent_id === focusAgentId}
          isLast={index === subagentVisible.length - 1}
          onSelect={() => { setFocusAgentId(sa.agent_id); setAgentNavIndex(-1); }} />;
      })}
      {subagentOverflowRow > 0 ? (
        <text fg={MUTED}>{fitTuiText(
          agentNavIndex >= 0
            ? `${rosterStart + 1}–${rosterStart + subagentVisible.length}/${subagentEntries.length} · ↑↓ browse all`
            : `+${subagentOverflow} more · ↓ browse all`,
          contentWidth,
        )}</text>
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
  const sidebarContentRows = Math.max(0, ledgerRows - 2);
  const cloudHintRows = !cloudHintDismissed && shouldOfferCloudHint({ hostedConnected: cloudConfigured, rows: sidebarContentRows, width: rightInner })
    ? Math.min(5, Math.max(0, sidebarContentRows - 8)) : 0;
  const railRecords = Object.values(herdAgents);
  const runFindings = runFindingsFromEntries(entries);
  // Header rows: AGENTS(1), FINDINGS(1 + separator), and the hide control(1).
  // Vertical padding was deducted above. Empty sections consume only their
  // actual placeholder rows, leaving that space available for the live plan.
  const rightSectionRows = Math.max(0, sidebarContentRows - 4 - cloudHintRows);
  const hasPlan = Boolean(todos?.todos.length);
  const planMinimum = hasPlan ? Math.min(3, rightSectionRows) : 0;
  const rightBodyRows = rightSectionRows - planMinimum;
  const agentRowsNeeded = railRecords.length ? railRecords.length * AGENT_SIDEBAR_ROWS : 2;
  const findingRowsNeeded = Math.max(1, runFindings.length * 2);
  const findingsShare = Math.min(findingRowsNeeded, Math.floor(rightBodyRows * 0.4));
  const agentsBudget = Math.min(agentRowsNeeded, Math.max(0, rightBodyRows - findingsShare));
  const rightFindingsBudget = Math.min(findingRowsNeeded, Math.max(0, rightBodyRows - agentsBudget));
  const rightPlanBudget = hasPlan ? rightSectionRows - agentsBudget - rightFindingsBudget : 0;
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
      <box flexDirection="column" flexGrow={1} alignSelf="stretch" minHeight={0} minWidth={0} paddingX={1} paddingY={1} backgroundColor={PANEL}>
        <box width={rightInner} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{buildSidebarSectionHeader("AGENTS", railRecords.length, rightInner)}</text>
        </box>
        {railVisible.length === 0 ? (
          <box width={rightInner} flexDirection="column" flexShrink={0} minWidth={0}>
            <text fg={MUTED}>{fitTuiText(
              railRecords.length > 0 ? "Open /agents" : agentsBudget >= 2 ? "Want extra eyes?" : 'Ask: "Use subagents"',
              rightInner,
            )}</text>
            {railRecords.length === 0 && agentsBudget >= 2 ? (
              <text fg={MUTED}>{fitTuiText('Ask: "Use subagents"', rightInner)}</text>
            ) : null}
          </box>
        ) : (
          railVisible.map((rec) => {
            // Share the inline worker identity and truthful status presentation.
            const view: AgentRowView = {
              id: rec.agentId,
              name: rec.name ?? agentNamesRef.current.get(rec.agentId) ?? "Unnamed worker",
              task: rec.task || "No task reported",
              activity: summarizeAgentActivity({
                status: operatorStopped.has(rec.agentId) ? "cancelled" : rec.status === "completed" && workerOutcomes[rec.agentId]?.done === false ? "incomplete" : rec.status,
                tool: rec.tool, note: rec.note, turn: rec.turn, maxTurns: rec.maxTurns,
              }),
              status: operatorStopped.has(rec.agentId) ? "cancelled" : rec.status === "completed" && workerOutcomes[rec.agentId]?.done === false ? "incomplete" : rec.status,
              animationFrame: settings.reduceMotion ? undefined : animTick,
              accent: agentAccentFor(rec.agentId, theme.CANVAS),
            };
            return (
              <AgentSidebarRow
                key={rec.agentId}
                view={view}
                width={rightInner}
                theme={theme}
                selected={workerRoster[agentNavIndex]?.agent_id === rec.agentId}
                onSelect={() => { setFocusAgentId(rec.agentId); setAgentNavIndex(-1); }}
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
        <CloudHintCard hostedConnected={cloudConfigured} width={rightInner} rows={cloudHintRows} theme={theme}
          dismissed={cloudHintDismissed} onDismiss={() => setCloudHintDismissed(true)} onConnect={() => onNavigate("connect")} />
        <box width={rightInner} flexShrink={0} minWidth={0} onMouseDown={() => updateSetting("showRightSidebar", false)}>
          <text fg={MUTED}>{fitTuiText("Hide agents · ctrl+l", rightInner)}</text>
        </box>
      </box>
    </box>
  ) : null;

  const leftSidebarNode = sidebars.leftVisible && renderAuditSwitcher ? (
    <box width={sidebars.leftWidth} flexShrink={0} minWidth={0} marginRight={sidebars.leftGap}>
      {renderAuditSwitcher(sidebars.leftWidth, ledgerRows)}
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
  // Reserve panel padding and the vertical scrollbar, including when a card expands.
  const focusInner = Math.max(8, contentWidth - (compact ? 2 : 4) - 1);
  const focusMetaLines = focused
    ? clipDetailLines(
        focusHeaderLines(focusPeer, focusRecord, focusInner, nowMs, { compact: true }).slice(focusRecord ? 1 : 0),
        Math.max(1, focusLayout.meta.bodyRows),
        focusInner,
      )
    : [];
  const focusActivityLines =
    focused && focusRecord ? renderFocusActivity(focusRecord.activity, focusInner) : [];
  // The focused child's REAL transcript (assistant prose + tool cards) streamed
  // via subagent_message. When present, the focus view renders it through the
  // SAME planTranscript/renderEntry as the main agent — so a drilled-in child
  // reads identically. Until the first message arrives (or for a peer session
  // with no stream), it falls back to the coarse activity ring below.
  const workerDisplay: EntryDisplay = {
    ...entryDisplay,
    model: focusedTelemetry?.model ?? "",
    shimmerFrame: focusRecord?.status === "running" && !settings.reduceMotion ? Math.floor(nowMs / 120) : undefined,
    activeTurn: focusRecord?.status === "running" ? focusedTelemetry?.turn : undefined,
    activeEntryId: focusRecord?.status === "running" ? focusEntries?.[focusEntries.length - 1]?.id : undefined,
  };
  // Per-agent LIVE telemetry for the Task launch card's sub-report rows, keyed
  // by the fleet-unique agent NAME (the card's `subReports` carry `name`, not an
  // `agent_id`). Every value is the SAME truthful producer the AGENTS rail reads
  // — final/last tokens (usage in+out+cached) and durationMs from
  // `workerTelemetry`, status + latest tool/report_status note from
  // `herdAgents`. It NEVER reads the whole-turn timer. Missing fields stay
  // undefined so the card shows only what is real.
  const taskAgentTelemetryByName = useMemo(() => {
    const byName = new Map<
      string,
      {
        id: string;
        status: string;
        tokens?: number;
        contextTokens?: number;
        durationMs?: number;
        model?: string;
        tool?: string;
        note?: string;
      }
    >();
    for (const id in herdAgents) {
      const rec = herdAgents[id];
      const name = rec.name ?? agentNamesRef.current.get(id);
      if (!name) continue;
      const tel = workerTelemetry[id];
      const usage = tel?.usage;
      byName.set(name, {
        id,
        status: operatorStopped.has(id) ? "cancelled" : rec.status,
        tokens: usage ? usage.inputTokens + usage.outputTokens + usage.cachedInputTokens : undefined,
        contextTokens: tel?.contextTokens,
        durationMs: tel?.durationMs,
        model: tel?.model,
        tool: rec.tool,
        note: rec.note,
      });
    }
    return byName;
  }, [herdAgents, workerTelemetry, operatorStopped]);
  const renderTranscriptEntries = (transcript: readonly ChatEntry[], width: number, display: EntryDisplay) => {
    // "thinking" is a per-TURN label, not a per-entry one. Walk the plan once
    // (it is already in transcript order) and record which turns have shown it,
    // so both the expanded reasoning rows and the folded summaries emit it at
    // most once per turn. O(1) per item — no rescans.
    const thinkingShownForTurn = new Set<number>();
    // The live "thinking…" indicator: the streaming reasoning entry is the tail
    // of the transcript, so its turn is the one that should shimmer.
    const tail = transcript[transcript.length - 1];
    const liveReasoningTurn =
      tail && tail.id === display.activeEntryId && tail.kind === "reasoning" ? tail.turn : undefined;
    return planTranscript(transcript, display.transcriptDetail, expandedTurns).map((item) => {
      if (item.type === "fold") {
        const hasReasoning = item.entries.some((entry) => entry.kind === "reasoning");
        let hideReasoningLabel = false;
        if (hasReasoning) {
          if (thinkingShownForTurn.has(item.turn)) hideReasoningLabel = true;
          else thinkingShownForTurn.add(item.turn);
        }
        return renderFold(
          item,
          width,
          display,
          theme,
          {
            hovered: hoveredTurn === item.turn,
            onToggle: () => toggleTurnExpanded(item.turn),
            onHover: (hovered) => setHoveredTurn(hovered ? item.turn : null),
          },
          { hideReasoningLabel },
        );
      }
      const rawEntry = item.entry;
      // Join the live per-agent telemetry onto a Task card's sub-report rows so
      // the launch card shows each child's real tokens / duration / model +
      // status + intent (matching the AGENTS rail). Additive and lossless: an
      // agent with no telemetry (or a restored session with none) keeps its
      // static launch row untouched.
      const entry =
        rawEntry.kind === "tool" && rawEntry.metaKind === "task" && rawEntry.subReports?.length
          ? {
              ...rawEntry,
              subReports: rawEntry.subReports.map((sr) => {
                const tel = taskAgentTelemetryByName.get(sr.name);
                return tel ? { ...sr, ...tel } : sr;
              }),
            }
          : rawEntry;
      const expanded = expandedTurns.has(entry.turn);
      const interactive = expanded && (
        entry.kind === "tool" || entry.kind === "subagent" || entry.kind === "reasoning"
      );
      let reasoningLabel: "shimmer" | "static" | "none" = "static";
      if (entry.kind === "reasoning") {
        if (thinkingShownForTurn.has(entry.turn)) {
          reasoningLabel = "none";
        } else {
          thinkingShownForTurn.add(entry.turn);
          reasoningLabel =
            entry.turn === liveReasoningTurn && typeof display.shimmerFrame === "number"
              ? "shimmer"
              : "static";
        }
      }
      const node = renderEntry(
        entry,
        width,
        expanded ? { ...display, transcriptDetail: "expanded" } : display,
        theme,
        interactive ? {
          expanded,
          hovered: hoveredTurn === entry.turn,
          onToggle: () => toggleTurnExpanded(entry.turn),
          onHover: (hovered) => setHoveredTurn(hovered ? entry.turn : null),
        } : undefined,
        reasoningLabel,
      );
      // A right-click on an operator/model message pops its actions at the
      // cursor. The wrapper is a layout-neutral column and its handler fires
      // ONLY for a right press (button 2), so left-click / drag-select / the
      // fold-toggle handlers inside `node` are all untouched. Gated on
      // `mouseSupport`, matching every other mouse affordance.
      const isMessage = entry.kind === "user" || entry.kind === "assistant";
      if (settings.mouseSupport && isMessage && (entry.text ?? "").length > 0) {
        return (
          <box
            key={entry.id}
            flexDirection="column"
            flexShrink={0}
            minWidth={0}
            onMouseDown={(event) => {
              if (!isRightClick(event)) return;
              event.stopPropagation?.();
              event.preventDefault?.();
              transcriptMenu.open(event.x, event.y, buildMessageMenuItems(entry));
            }}
          >
            {node}
          </box>
        );
      }
      return node;
    });
  };
  const focusHasTranscript = focused && Boolean(focusEntries?.length);
  // The coarse activity fallback is row-windowed. Rich transcripts use their
  // actual viewport and measured content extent instead of this estimate.
  const focusMetaRows = focusMetaLines.length + 1;
  const focusTranscriptCap = Math.max(1, ledgerRows - focusMetaRows - (compact ? 1 : 3));
  const focusTail = windowFocusTail(
    focusActivityLines.length,
    focusTranscriptCap,
    focusScrollOffset,
  );
  const focusVisibleActivity = focusActivityLines.slice(focusTail.start, focusTail.end);
  const focusViewNode = (
    <box
      key={`worker-${focusAgentId}`}
      flexDirection="column"
      flexGrow={1}
      minHeight={0}
      width="100%"
      minWidth={0}
      overflow="hidden"
      backgroundColor={PANEL}
      paddingX={compact ? 1 : 2}
      paddingY={compact ? 0 : 1}
    >
      <box flexDirection="column" flexShrink={0} minWidth={0}>
        <text fg={ACCENT}>{fitTuiText(`Main › ${focusRecord?.name ?? agentNamesRef.current.get(focusAgentId ?? "") ?? "Unnamed worker"}`, focusInner)}</text>
        {focusMetaLines.map((line, index) => (
          <text key={`focus-meta-${index}`} fg={herdToneColor(theme, line.tone)}>
            {fitTuiText(line.text, focusInner)}
          </text>
        ))}
      </box>
      {focusHasTranscript ? (
        <box flexDirection="column" height={0} flexGrow={1} minHeight={0} minWidth={0} marginTop={1} overflow="hidden">
          <scrollbox
            ref={focusTranscriptRef}
            focusable={false}
            width="100%"
            height={0}
            flexGrow={1}
            minHeight={0}
            backgroundColor={PANEL}
            verticalScrollbarOptions={{ trackOptions: { backgroundColor: PANEL, foregroundColor: MUTED }, arrowOptions: { foregroundColor: MUTED, backgroundColor: PANEL } }}
            contentOptions={{ flexDirection: "column" }}
            stickyScroll
            stickyStart="bottom"
          >
            <box flexDirection="column" width="100%" flexShrink={0} onSizeChange={function () {
              // Nested tool/markdown rows can reflow after the scroll content was measured.
              if (focusTranscriptRef.current) focusTranscriptRef.current.content.height = this.height;
            }}>
              {renderTranscriptEntries(focusedTranscript, focusInner, workerDisplay)}
            </box>
          </scrollbox>
        </box>
      ) : (
        <box
          flexDirection="column"
          flexGrow={1}
          minHeight={0}
          minWidth={0}
          marginTop={1}
          onMouseScroll={(event) =>
            setFocusScrollOffset((offset) => clampScrollOffset(offset + wheelOffsetStep(event.scroll)))
          }
        >
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
      )}
      <text fg={MUTED} marginTop={1}>
        {fitTuiText(`ctrl+o transcript · ctrl+r ${workerDisplay.transcriptDetail === "expanded" ? "collapse" : "expand"} details · esc/← Main`, focusInner)}
      </text>
    </box>
  );

  // ── The conversation region ────────────────────────────────────────────────
  // Either the drilled-in focus view, or the transcript column between the two
  // optional sidebars: [left][transcript][right]. The transcript column
  // flexGrows; each sidebar is flexShrink={0} and only present when the layout
  // found room for it, so with both hidden the transcript takes the full width
  // exactly as before.
  const conversationRegion = reviewOpen ? (
    <TranscriptReview
      transcript={transcriptDocument}
      width={transcriptWidth}
      detail={entryDisplay.transcriptDetail}
      expandedTurns={expandedTurns}
      theme={theme}
      renderableRef={reviewRenderableRef}
    />
  ) : focused ? (
    focusViewNode
  ) : (
    <box key="main-transcript" flexDirection="row" flexGrow={1} minHeight={0} width="100%" minWidth={0}>
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
        <scrollbox ref={transcriptRef} focusable={false} width="100%" flexGrow={1} minHeight={0} backgroundColor={PANEL} stickyScroll stickyStart="bottom" verticalScrollbarOptions={{ trackOptions: { backgroundColor: PANEL, foregroundColor: MUTED }, arrowOptions: { foregroundColor: MUTED, backgroundColor: PANEL } }}>
          <box flexDirection="column" width="100%">
            {renderTranscriptEntries(entries, transcriptWidth, entryDisplay)}
            {/* The plan lives in the RIGHT sidebar now; this inline card is only
                a fallback for when that sidebar is hidden, so the todos are
                always visible somewhere. */}
            {!sidebars.rightVisible && todos && todos.total > 0 ? (
              <Todos payload={todos} width={transcriptWidth} theme={theme} />
            ) : null}
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

  // Keep first-use actions visible without opening a second navigation surface.
  const heroHintPairs: KeyHint[] = [
    { key: "/connect", label: "connection" },
    { key: "/resume", label: "saved audits" },
    { key: "ctrl+p", label: "commands" },
  ];
  // Any overlay open in the hero (slash menu, picker, an approval, the secret
  // prompt): the masthead is hidden so the tall menu + logo cannot overflow
  // upward into the header. The composer stays put — it is anchored by the
  // fixed bottom spacer regardless of what the region above it holds.
  const heroOverlayOpen = commandMenuVisible || Boolean(picker) || Boolean(approvalPrompt) || Boolean(secretPrompt) || operatorQuestionOpen;
  const showMasthead = !heroOverlayOpen && !startupError;

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
    interactive && showMasthead && showTerminalMark && !settings.reduceMotion && logoStyle !== "off";
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
        <box width={sidebarControlWidth} flexDirection="row" flexShrink={0} gap={1}>
          <box width={Math.floor((sidebarControlWidth - 1) / 2)} flexShrink={0} onMouseDown={() => updateSetting("showLeftSidebar", !settingsRef.current.showLeftSidebar)}>
            <text fg={settings.showLeftSidebar ? ACCENT : MUTED}>{sidebarControlWidth > 8 ? `${settings.showLeftSidebar ? "▾" : "▸"} Audits` : "◀"}</text>
          </box>
          <box width={Math.floor(sidebarControlWidth / 2)} flexShrink={0} onMouseDown={() => updateSetting("showRightSidebar", !settingsRef.current.showRightSidebar)}>
            <text fg={settings.showRightSidebar ? ACCENT : MUTED}>{sidebarControlWidth > 8 ? `${settings.showRightSidebar ? "▾" : "▸"} Agents` : "▶"}</text>
          </box>
        </box>
      </box>

      {empty && !reviewOpen && !leftSidebarNode ? (
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
        <box flexDirection="row" flexGrow={1} minHeight={0} width="100%" minWidth={0}>
          <box flexDirection="column" flexGrow={1} minHeight={0} width={heroContentWidth} minWidth={0} alignItems="center">
            <box flexDirection="column" flexGrow={1} minHeight={0} width="100%" minWidth={0} justifyContent="flex-end" alignItems="center">
              {showMasthead ? (
                <Masthead
                  showTerminalMark={showTerminalMark && heroContentWidth >= TERMINAL_BLOCK_LOGO_WIDTH}
                  showTagline={showEmptyStateTagline}
                  contentWidth={heroContentWidth}
                  logoFrameGrid={logoFrameGrid}
                  theme={theme}
                />
              ) : null}
              {workingIndicator}
              {startupError && !heroOverlayOpen ? (
                <box flexDirection="column" width={heroComposerWidth} minWidth={0} flexShrink={0} marginBottom={1}>
                  <text fg={TEXT}>Chat needs setup</text>
                  <text fg={MUTED} wrapMode="word">{startupError}</text>
                </box>
              ) : null}
              {heroOverlaysNode}
            </box>
            <box flexDirection="column" width={heroComposerWidth} minWidth={0} flexShrink={0}>
              {heroComposerNode}
            </box>
            <box flexShrink={0} minWidth={0} marginTop={1}>
              {keyHintsLength(heroHintPairs, " · ") <= heroContentWidth ? (
                <KeyHints pairs={heroHintPairs} theme={theme} />
              ) : (
                <text fg={MUTED}>{fitTuiText("/connect · /resume · ctrl+p", heroContentWidth)}</text>
              )}
            </box>
            <box height={heroBottomSpacer} flexShrink={0} minWidth={0} />
          </box>
          {rightSidebarNode}
        </box>
      ) : reviewOpen ? (
        conversationRegion
      ) : (
        <>
          {/*
            * The conversation region: the drilled-in focus view, or the
            * transcript column beside the optional agent rail. The transcript
            * flexGrows; the rail is flexShrink={0} and sized by chat-layout.
            */}
          <HarnessPresentation fallback={conversationRegion} />

          {overlaysNode}
          {stickyNode}
          {workingIndicator}
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
        * The shared bottom row keeps permission mode visible in both hero and
        * conversation layouts. showStatusBar controls the extra environmental
        * telemetry, not the only indicator of the operator's approval mode.
        */}
        <box flexDirection="row" width={controlsWidth} height={1} flexShrink={0} minWidth={0} overflow="hidden">
          {loadingLabel ? <text fg={animationKind === "awaiting-operator" ? WARNING : ACCENT}>{`${loadingLabel} · `}</text> : null}
          {statusPills.length > 0 ? (
            <box flexDirection="row" flexShrink={0} minWidth={0}>
              {statusPills.map((segment, index) => (
                <React.Fragment key={segment.kind}>
                  {index > 0 ? <text fg={MUTED}> · </text> : null}
                  <text fg={statusRoleColor(segment.colorRole, theme, mode)}>{pillText(segment)}</text>
                </React.Fragment>
              ))}
            </box>
          ) : <text fg={MUTED}>{fitTuiText(statusBarText, statusContentWidth)}</text>}
        </box>
      {/*
        * The copy-on-highlight toast. Positioned absolutely with a high
        * zIndex (see toast.tsx), so it floats over the transcript without
        * participating in — or shifting — the column layout above.
        */}
      {interactive ? <Toast frame={toastFrame} /> : null}
      {interactive && transcriptMenu.state.open ? (
        <ContextMenu
          items={transcriptMenu.state.items}
          x={transcriptMenu.state.x}
          y={transcriptMenu.state.y}
          onClose={transcriptMenu.close}
        />
      ) : null}
    </box>
  );
}
