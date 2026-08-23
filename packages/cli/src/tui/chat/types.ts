import type { PanelData } from "../panels.js";
import type {
  RoleLabelStyle,
  ToolCardStyle,
  TranscriptDetail,
  TranscriptStyle,
} from "../transcript-style.js";

export type ChatEntry = {
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

export interface EntryDisplay {
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

export interface KeyHint {
  key: string;
  label: string;
}
