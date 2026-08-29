/** @jsxImportSource @opentui/react */
import React from "react";
import { TextAttributes } from "@opentui/core";
import { MODEL_PRICING, type ModelRates } from "@0sec/shared";
import { fitTuiText, sanitizeTuiText } from "../text.js";
import { ShimmerText } from "./shimmer.js";
import { renderMarkdown } from "../markdown.js";
import { formatElapsed } from "../animation.js";
import { repeatSuffix } from "../transcript.js";
import { panelColumns } from "../panels.js";
import {
  commandCardFooter,
  commandCardFrame,
  editCardFrame,
  webCardFrame,
  webSourceHost,
  foldBodyLines,
  foldSummary,
  roleLabelText,
  speechFrame,
  toolCompactLine,
  toolDetailWidth,
  toolFrame,
  toolGlyphState,
  toolHeaderColumns,
  toolHeaderPrefix,
  type TranscriptPlanItem,
} from "../transcript-style.js";
import { renderMarkdownBlocks } from "./markdown-blocks.js";
import type { Theme } from "../theme-context.js";
import type { ChatEntry, EntryDisplay } from "./types.js";

/**
 * Mouse affordances for a clickable transcript row (a collapsed fold, or a
 * collapsible step inside an expanded turn). Entirely optional: when omitted,
 * the row renders exactly as before with no handlers, so keyboard-only use and
 * restored transcripts are untouched. Chat-screen supplies these only for the
 * rows that participate in per-turn expand/collapse.
 */
export interface TranscriptRowInteraction {
  /** True when this row's turn is currently hover-highlighted. */
  hovered?: boolean;
  /** Toggle this turn between folded and fully expanded. */
  onToggle?: () => void;
  /** Report pointer enter (true) / leave (false) for this row's turn. */
  onHover?: (hovering: boolean) => void;
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

/** Max output lines a command card shows before the middle-out fold kicks in. */
const COMMAND_CARD_MAX_LINES = 14;
/** Max diff lines an edit card shows before the middle-out fold kicks in. */
const EDIT_CARD_MAX_LINES = 20;
/** Max answer lines a web card shows before the middle-out fold kicks in. */
const WEB_CARD_ANSWER_MAX_LINES = 6;
/** Max source rows a web card shows before capping with a `+N more` line. */
const WEB_CARD_MAX_SOURCES = 6;

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

/**
 * Word-wrap a prose blob into at most `maxLines` lines of `width` cells, for the
 * web card's answer block. The source is sanitized first (newlines collapse to
 * spaces), then greedily packed; a word longer than the line is hard-split. When
 * the text overruns the line budget the last shown line is ellipsised so the
 * fold is visible. Every returned line is <= `width`, so the caller's per-line
 * `fitTuiText` is a no-op safety net rather than a truncation. Pure.
 */
function wrapAnswerLines(text: string, width: number, maxLines: number): string[] {
  const clean = sanitizeTuiText(text);
  if (width <= 0 || maxLines <= 0 || clean.length === 0) return [];
  const words = clean.split(" ").filter((w) => w.length > 0);
  const lines: string[] = [];
  let cur = "";
  let overflowed = false;
  for (const word of words) {
    const next = cur ? `${cur} ${word}` : word;
    if (next.length <= width) {
      cur = next;
      continue;
    }
    if (cur) lines.push(cur);
    if (lines.length >= maxLines) { overflowed = true; cur = ""; break; }
    if (word.length > width) {
      let rest = word;
      while (rest.length > width && lines.length < maxLines) {
        lines.push(rest.slice(0, width));
        rest = rest.slice(width);
      }
      if (lines.length >= maxLines) { overflowed = rest.length > 0; cur = ""; break; }
      cur = rest;
    } else {
      cur = word;
    }
  }
  if (cur) {
    if (lines.length < maxLines) lines.push(cur);
    else overflowed = true;
  }
  if (overflowed && lines.length > 0) {
    const last = lines[lines.length - 1]!;
    lines[lines.length - 1] = last.endsWith("…") ? last : fitTuiText(`${last} …`, width);
  }
  return lines;
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

export function renderEntry(
  entry: ChatEntry,
  maxWidthOuter: number,
  display: EntryDisplay,
  theme: Theme,
  interaction?: TranscriptRowInteraction,
) {
  const { ACCENT, PRIMARY, TEXT, MUTED, ERROR, SUCCESS, BORDER, PANEL_ALT, BRAND } = theme;
  // Interaction is only ever handed to the collapsible kinds (tool / subagent /
  // reasoning) of an EXPANDED turn. When present we reserve a two-cell
  // disclosure gutter and shrink the content budget so the wrapped row still
  // fits its column — the 80-col invariant holds exactly as the fold's does.
  const interactive = Boolean(interaction);
  const maxWidth = interactive ? Math.max(8, maxWidthOuter - 2) : maxWidthOuter;
  const finish = (node: React.ReactNode): React.ReactNode => {
    if (!interaction) return node;
    return (
      <box
        key={entry.id}
        flexDirection="row"
        minWidth={0}
        backgroundColor={interaction.hovered ? PANEL_ALT : undefined}
        onMouseDown={interaction.onToggle}
        onMouseOver={interaction.onHover ? () => interaction.onHover?.(true) : undefined}
        onMouseOut={interaction.onHover ? () => interaction.onHover?.(false) : undefined}
      >
        <box width={2} flexShrink={0} minWidth={0} marginTop={display.spacing}>
          <text fg={MUTED}>▾ </text>
        </box>
        <box flexDirection="column" flexGrow={1} minWidth={0}>
          {node}
        </box>
      </box>
    );
  };
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
      // The footer is quiet provenance only — the per-turn telemetry the operator
      // opted into: the model when `modelDisplay` routes it here (otherwise it
      // lives in the bottom bar), the per-turn tokens under `showTokenUsage`, the
      // per-turn cost under `showCost`, and the elapsed. The AUTONOMY MODE is NOT
      // repeated here: it is a session-wide state, already shown persistently in
      // the masthead and the bottom status bar, so tagging every single answer
      // with "YOLO"/"Co-pilot" was redundant noise.
      const footerParts: string[] = [];
      if (display.modelInFooter && display.model) footerParts.push(display.model);
      if (display.showTokenUsage && entry.usageInput !== undefined) {
        footerParts.push(`${entry.usageInput}→${entry.usageOutput ?? 0} tok`);
      }
      if (display.showCost && entry.usageInput !== undefined) {
        footerParts.push(formatTurnCost(display.model, entry.usageInput, entry.usageOutput ?? 0));
      }
      const elapsed = entry.durationMs ? formatElapsed(entry.durationMs) : "";
      if (elapsed) footerParts.push(elapsed);
      const footerBudget = Math.max(1, maxWidth - 2);
      const restFitted = footerParts.length
        ? fitTuiText(footerParts.join(" · "), footerBudget)
        : "";
      // No telemetry at all → no footer row, rather than a bare marker.
      if (!restFitted) {
        return (
          <box key={entry.id} flexDirection="column" marginTop={marginTop} minWidth={0}>
            {body}
          </box>
        );
      }
      return (
        <box key={entry.id} flexDirection="column" marginTop={marginTop} minWidth={0}>
          {body}
          <box flexDirection="row" minWidth={0}>
            <box width={2} flexShrink={0} minWidth={0}>
              <text fg={ERROR}>▪ </text>
            </box>
            <box flexGrow={1} minWidth={0} flexDirection="row">
              <text fg={MUTED}>{restFitted}</text>
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
    const failed = entry.success === false;
    const running = entry.success === undefined;
    const tone = failed ? ERROR : entry.success ? SUCCESS : PRIMARY;
    const { icon, state } = toolGlyphState(entry.success);

    // ── Rich cards (OMP-style): a bordered command / edit card. Gated on the
    // richToolCards display flag (defaults ON when unset) and the presence of
    // the meta the tool attached. `toolCardStyle: "hidden"` still drops a
    // SUCCESSFUL card — a failure always renders. A pane too narrow for the
    // border chrome falls through to the plain line below. ──
    const richCards = display.richToolCards !== false;
    const cardFailed =
      entry.success === false ||
      entry.timedOut === true ||
      (typeof entry.exitCode === "number" && entry.exitCode !== 0);
    const hideSuccessCard = toolCardStyle === "hidden" && !cardFailed;

    if (richCards && entry.metaKind === "command" && typeof entry.command === "string" && !hideSuccessCard) {
      const cardFrame = commandCardFrame(maxWidth);
      if (cardFrame.render) {
        const cardTone = cardFailed ? ERROR : BORDER;
        const footer = commandCardFooter({
          wallMs: entry.wallMs,
          timeoutMs: entry.timeoutMs,
          exitCode: entry.exitCode ?? undefined,
          timedOut: entry.timedOut,
        });
        // The header `$ ` + command; the command is fitted to whatever the
        // inner width can pay for after the two-cell prompt.
        const cmdText = fitTuiText(entry.command, Math.max(1, cardFrame.innerWidth - 2));
        const body = entry.commandOutput ?? "";
        const bodyLines = body.trim().length > 0 ? foldBodyLines(body, COMMAND_CARD_MAX_LINES) : [];
        return finish(
          <box
            key={entry.id}
            flexDirection="column"
            width={cardFrame.outerWidth}
            flexShrink={0}
            minWidth={0}
            marginTop={display.spacing}
            border
            borderColor={cardTone}
            paddingX={1}
          >
            <box flexDirection="row" minWidth={0}>
              <text fg={MUTED}>$ </text>
              <text fg={PRIMARY} attributes={TextAttributes.BOLD}>{cmdText}</text>
            </box>
            {bodyLines.length > 0 ? (
              <box flexDirection="column" minWidth={0} marginTop={1}>
                <text fg={MUTED}>Output</text>
                {bodyLines.map((line, i) => (
                  <text key={`o-${i}`} fg={line.startsWith("… ") ? MUTED : TEXT}>
                    {fitTuiText(line, cardFrame.innerWidth)}
                  </text>
                ))}
              </box>
            ) : null}
            {footer ? (
              <box minWidth={0} marginTop={bodyLines.length > 0 ? 1 : 0}>
                <text fg={cardFailed ? ERROR : MUTED}>{fitTuiText(footer, cardFrame.innerWidth)}</text>
              </box>
            ) : null}
          </box>,
        );
      }
    }

    if (richCards && entry.metaKind === "edit" && typeof entry.editPath === "string" && !hideSuccessCard) {
      const cardFrame = editCardFrame(maxWidth);
      if (cardFrame.render) {
        const cardTone = cardFailed ? ERROR : BORDER;
        const added = entry.editAdded ?? 0;
        const removed = entry.editRemoved ?? 0;
        const header = `✎ Edit: ${entry.editPath} (+${added}/-${removed})`;
        const diff = entry.editDiff ?? "";
        const diffLines = diff.trim().length > 0 ? foldBodyLines(diff, EDIT_CARD_MAX_LINES) : [];
        return finish(
          <box
            key={entry.id}
            flexDirection="column"
            width={cardFrame.outerWidth}
            flexShrink={0}
            minWidth={0}
            marginTop={display.spacing}
            border
            borderColor={cardTone}
            paddingX={1}
          >
            <box minWidth={0}>
              <text fg={PRIMARY} attributes={TextAttributes.BOLD}>{fitTuiText(header, cardFrame.innerWidth)}</text>
            </box>
            {diffLines.length > 0 ? (
              <box flexDirection="column" minWidth={0} marginTop={1}>
                {diffLines.map((line, i) => {
                  const diffTone = line.startsWith("+")
                    ? SUCCESS
                    : line.startsWith("-")
                      ? ERROR
                      : line.startsWith("… ")
                        ? MUTED
                        : TEXT;
                  return (
                    <text key={`d-${i}`} fg={diffTone}>
                      {fitTuiText(line, cardFrame.innerWidth)}
                    </text>
                  );
                })}
              </box>
            ) : null}
          </box>,
        );
      }
    }

    // ── Web-search card (OMP-style): a bordered card with the provider +
    // source count header, the query, an optional answer/summary, and a bounded
    // sources list (title + host + optional age). Display-only, driven by the
    // web `meta` sidecar; a failed search carries no meta so this only fires on
    // success. Degrades gracefully when answer/age/title are absent. ──
    if (richCards && entry.metaKind === "web" && !hideSuccessCard) {
      const cardFrame = webCardFrame(maxWidth);
      if (cardFrame.render) {
        const inner = cardFrame.innerWidth;
        const cardTone = failed ? ERROR : BORDER;
        const provider = entry.webProvider?.trim() || "web";
        const sources = entry.webSources ?? [];
        const query = entry.webQuery?.trim() ?? "";
        const answer = entry.webAnswer?.trim() ?? "";
        const answerLines = answer.length > 0 ? wrapAnswerLines(answer, inner, WEB_CARD_ANSWER_MAX_LINES) : [];
        const shownSources = sources.slice(0, WEB_CARD_MAX_SOURCES);
        const hiddenSources = sources.length - shownSources.length;
        const header = `⌕ Web Search: ${provider} · ${sources.length} source${sources.length === 1 ? "" : "s"}`;
        const QUERY_LABEL = "Query ";
        return finish(
          <box
            key={entry.id}
            flexDirection="column"
            width={cardFrame.outerWidth}
            flexShrink={0}
            minWidth={0}
            marginTop={display.spacing}
            border
            borderColor={cardTone}
            paddingX={1}
          >
            <box minWidth={0}>
              <text fg={PRIMARY} attributes={TextAttributes.BOLD}>{fitTuiText(header, inner)}</text>
            </box>
            {query ? (
              <box flexDirection="row" minWidth={0} marginTop={1}>
                <text fg={MUTED}>{QUERY_LABEL}</text>
                <text fg={TEXT}>{fitTuiText(query, Math.max(1, inner - QUERY_LABEL.length))}</text>
              </box>
            ) : null}
            {answerLines.length > 0 ? (
              <box flexDirection="column" minWidth={0} marginTop={1}>
                <text fg={MUTED}>Answer</text>
                {answerLines.map((line, i) => (
                  <text key={`a-${i}`} fg={line.endsWith("…") ? MUTED : TEXT}>{fitTuiText(line, inner)}</text>
                ))}
              </box>
            ) : null}
            {shownSources.length > 0 ? (
              <box flexDirection="column" minWidth={0} marginTop={1}>
                <text fg={MUTED}>Sources</text>
                {shownSources.map((source, i) => {
                  const host = webSourceHost(source.url);
                  const title = (source.title ?? "").trim() || host || source.url;
                  const age = source.age?.trim() ? ` · ${source.age.trim()}` : "";
                  const titleMax = Math.max(1, Math.ceil(inner * 0.6));
                  const fittedTitle = fitTuiText(title, titleMax);
                  const metaBudget = Math.max(0, inner - fittedTitle.length);
                  const metaText = metaBudget > 0 ? fitTuiText(` · ${host}${age}`, metaBudget) : "";
                  return (
                    <box key={`s-${i}`} flexDirection="row" minWidth={0}>
                      <text fg={TEXT}>{fittedTitle}</text>
                      {metaText ? <text fg={MUTED}>{metaText}</text> : null}
                    </box>
                  );
                })}
                {hiddenSources > 0 ? (
                  <text fg={MUTED}>{fitTuiText(`+${hiddenSources} more`, inner)}</text>
                ) : null}
              </box>
            ) : null}
            <box minWidth={0} marginTop={1}>
              <text fg={MUTED}>{fitTuiText(`(${provider})`, inner)}</text>
            </box>
          </box>,
        );
      }
    }

    const frame = toolFrame(toolCardStyle, maxWidth, entry.success);
    if (!frame.render) return null;
    const toolDetail = toolDetailWidth(frame.contentWidth, maxWidth);
    // A running row SHIMMERS its label (bright sweep over the muted base) while
    // the call is in flight; the moment it settles or fails it renders static.
    // A failed row is loud: a bold ERROR header and a READABLE (non-muted)
    // detail line, so the reason is legible rather than dimmed into the chrome.
    const shimmerRunning = running && typeof display.shimmerFrame === "number";

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
      const compactLine = toolCompactLine(icon, compactName, state, frame.contentWidth);
      return finish(
        <box key={entry.id} flexDirection="column" minWidth={0} marginTop={display.spacing}>
          {shimmerRunning ? (
            <ShimmerText label={compactLine} frame={display.shimmerFrame!} base={MUTED} peak={ERROR} />
          ) : (
            <text fg={tone} attributes={failed ? TextAttributes.BOLD : undefined}>{compactLine}</text>
          )}
          {frame.showDetail && entry.detail ? (
            <text fg={failed ? TEXT : MUTED} wrapMode="word">{fitTuiText(entry.detail, frame.contentWidth)}</text>
          ) : null}
        </box>,
      );
    }

    // rail / inline: icon, muted prefix and name are siblings on one row; the
    // name is budgeted against the prefix's real length or the row overruns its
    // container and the renderer paints the columns into each other.
    const toolPrefix = toolHeaderPrefix(state);
    const cols = toolHeaderColumns(frame.contentWidth, toolPrefix.length, toolDetail);
    const toolName = fitTuiText(`${entry.text}${repeat}`, cols.nameWidth);
    const header = (
      <box flexDirection="column" flexGrow={1} minWidth={0} marginLeft={frame.contentGap}>
        <box flexDirection="row" minWidth={0}>
          <text fg={tone} attributes={failed ? TextAttributes.BOLD : undefined}>{icon}</text>
          <text fg={MUTED}>{toolPrefix}</text>
          {shimmerRunning ? (
            <ShimmerText label={toolName} frame={display.shimmerFrame!} base={MUTED} peak={ERROR} />
          ) : (
            <text fg={failed ? ERROR : TEXT} attributes={failed ? TextAttributes.BOLD : undefined}>{toolName}</text>
          )}
        </box>
        {frame.showDetail && entry.detail ? <text fg={failed ? TEXT : MUTED} wrapMode="word">{fitTuiText(entry.detail, toolDetail)}</text> : null}
      </box>
    );
    return finish(
      <box key={entry.id} flexDirection="row" marginTop={display.spacing} marginLeft={frame.outerMarginLeft} minWidth={0}>
        {frame.railKind === "solid" ? <box width={1} alignSelf="stretch" backgroundColor={tone} /> : null}
        {header}
      </box>,
    );
  }

  if (entry.kind === "subagent") {
    // A subagent still in flight (no recorded outcome) reads as RUNNING — a
    // shimmering label over the muted base — rather than being defaulted to a
    // red "failed" it never was. Terminal records keep their rendering.
    const running = entry.subagentOutcome === undefined;
    const ok = entry.subagentOutcome === "completed";
    const failed = entry.subagentOutcome === "failed";
    const tone = running ? PRIMARY : ok ? SUCCESS : ERROR;
    const glyph = running ? "◌" : ok ? "✓" : "×";
    const stateWord = running ? "running" : ok ? "completed" : "failed";
    const shimmerRunning = running && typeof display.shimmerFrame === "number";
    const frame = toolFrame(toolCardStyle, maxWidth, running ? undefined : ok);
    if (!frame.render) return null;
    const subDetailWidth = toolDetailWidth(frame.contentWidth, maxWidth);
    const statusParts: string[] = [];
    if (entry.subagentTurns !== undefined) statusParts.push(`turns ${entry.subagentTurns}`);
    if (entry.subagentFindings !== undefined) statusParts.push(`findings ${entry.subagentFindings}`);
    const statusLine = statusParts.length > 0 ? statusParts.join(" · ") : null;

    if (frame.singleLine) {
      const compactLine = toolCompactLine(glyph, "subagent", stateWord, frame.contentWidth);
      return finish(
        <box key={entry.id} flexDirection="column" marginTop={display.spacing} minWidth={0}>
          {shimmerRunning ? (
            <ShimmerText label={compactLine} frame={display.shimmerFrame!} base={MUTED} peak={ERROR} />
          ) : (
            <text fg={tone} attributes={failed ? TextAttributes.BOLD : undefined}>{compactLine}</text>
          )}
          {frame.showDetail && entry.subagentError ? (
            <text fg={ERROR} wrapMode="word">{fitTuiText(entry.subagentError, frame.contentWidth)}</text>
          ) : null}
        </box>,
      );
    }

    return finish(
      <box key={entry.id} flexDirection="row" marginTop={display.spacing} marginLeft={frame.outerMarginLeft} minWidth={0}>
        {frame.railKind === "solid" ? <box width={1} alignSelf="stretch" backgroundColor={tone} /> : null}
        <box flexDirection="column" flexGrow={1} minWidth={0} marginLeft={frame.contentGap}>
          <box flexDirection="row" minWidth={0}>
            <text fg={tone} attributes={failed ? TextAttributes.BOLD : undefined}>{glyph}</text>
            <text fg={MUTED}> </text>
            {shimmerRunning ? (
              <ShimmerText label="evidence / subagent" frame={display.shimmerFrame!} base={MUTED} peak={ERROR} />
            ) : (
              <text fg={BRAND}>evidence / subagent</text>
            )}
            <text fg={MUTED}> · {stateWord}</text>
          </box>
          {frame.showDetail && statusLine ? <text fg={MUTED}>{fitTuiText(statusLine, subDetailWidth)}</text> : null}
          {frame.showDetail && entry.subagentSummary ? <text fg={TEXT} wrapMode="word">{fitTuiText(entry.subagentSummary, subDetailWidth)}</text> : null}
          {entry.subagentError ? <text fg={ERROR} wrapMode="word">{fitTuiText(entry.subagentError, subDetailWidth)}</text> : null}
        </box>
      </box>,
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
    // muted text, so it reads as working-out rather than a conclusion. While the
    // reasoning belongs to the turn STILL IN FLIGHT the "thinking" label shimmers
    // (a bright sweep over the muted base) so a working turn always reads as
    // alive — even when its answer hasn't started streaming yet; the instant the
    // turn settles (or on a past turn's reasoning) it renders static/muted.
    // Gated on BOTH `activeTurn` matching and a numeric `shimmerFrame`, so
    // reduceMotion / settled turns keep the flat label.
    // Only the LIVE TAIL reasoning shimmers — not every past thinking block in
    // the working turn — so a turn shows one shimmering "thinking", not many.
    const shimmerThinking =
      entry.id === display.activeEntryId && typeof display.shimmerFrame === "number";
    return finish(
      <box key={entry.id} flexDirection="row" marginTop={display.spacing} minWidth={0}>
        <box width={1} flexShrink={0} alignSelf="stretch">
          <text fg={MUTED}>┊</text>
        </box>
        <box flexDirection="column" flexGrow={1} minWidth={0} marginLeft={1}>
          {shimmerThinking ? (
            <ShimmerText label="thinking" frame={display.shimmerFrame!} base={MUTED} peak={ERROR} />
          ) : (
            <text fg={MUTED}>thinking</text>
          )}
          {renderMarkdownBlocks(
            renderMarkdown(normalizeReasoning(entry.text), Math.max(8, maxWidth - 2)),
            entry.id,
            theme,
            MUTED,
          )}
        </box>
      </box>,
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
export function renderFold(
  item: Extract<TranscriptPlanItem<ChatEntry>, { type: "fold" }>,
  maxWidth: number,
  display: EntryDisplay,
  theme: Theme,
  interaction?: TranscriptRowInteraction,
) {
  const { MUTED, TEXT, PANEL_ALT, ERROR } = theme;
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
  // A fold standing for the turn STILL IN FLIGHT must read as active even though
  // its steps are collapsed to one line: shimmer the summary (bright sweep over
  // the muted base) so a working-but-collapsed turn — e.g. "▸ 12 steps ·
  // thinking, run_command" — still signals "running". A completed/past fold
  // (its turn is not `activeTurn`) stays static muted, exactly as before. Gated
  // on BOTH the turn match and a numeric `shimmerFrame`, so reduceMotion /
  // settled turns keep the flat summary.
  const summaryFitted = fitTuiText(summary, Math.max(1, maxWidth - 2));
  const shimmerFold =
    item.turn === display.activeTurn && typeof display.shimmerFrame === "number";
  // A collapsed fold is clickable: mousing down toggles its turn into the
  // expanded set (chat-screen owns that state), and hovering tints the row so
  // the disclosure reads as interactive. Handlers are wired only when
  // chat-screen supplies `interaction`; keyboard-only use (Ctrl+R) is
  // unaffected. The ▸ glyph is the "collapsed" affordance; an expanded turn
  // instead renders its steps with the ▾ affordance (see renderEntry).
  return (
    <box
      key={key}
      flexDirection="row"
      marginTop={display.spacing}
      minWidth={0}
      backgroundColor={interaction?.hovered ? PANEL_ALT : undefined}
      onMouseDown={interaction?.onToggle}
      onMouseOver={interaction?.onHover ? () => interaction.onHover?.(true) : undefined}
      onMouseOut={interaction?.onHover ? () => interaction.onHover?.(false) : undefined}
    >
      <box width={2} flexShrink={0} minWidth={0}>
        <text fg={MUTED}>▸ </text>
      </box>
      <box flexGrow={1} minWidth={0}>
        {shimmerFold ? (
          <ShimmerText label={summaryFitted} frame={display.shimmerFrame!} base={MUTED} peak={ERROR} />
        ) : (
          <text fg={MUTED}>{summaryFitted}</text>
        )}
      </box>
    </box>
  );
}
