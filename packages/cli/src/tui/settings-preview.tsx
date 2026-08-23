/** @jsxImportSource @opentui/react */
/**
 * Live visual previews for the settings DETAIL pane.
 *
 * The DETAIL pane used to describe a setting in prose only — "Current: rail",
 * "Allowed: rail, inline, compact, hidden". For a purely *visual* knob (how a
 * tool card is drawn, how a turn is framed, which palette is active) that turns
 * choosing into guessing: the words name a shape the operator cannot see until
 * they leave the screen. This module renders a faithful mini-sample of the
 * highlighted setting's CURRENT value so the choice is see-it, not read-it.
 *
 * Two properties keep it honest and safe:
 *
 * 1. **Faithful, not re-implemented.** The tool-card and transcript samples are
 *    laid out by the very same pure resolvers the chat surface uses
 *    (`transcript-style.ts`: `toolFrame`, `speechFrame`, `roleLabelText`, …),
 *    so a preview cannot drift from the real thing. `chat-screen.tsx` internals
 *    are deliberately NOT imported — they are not exported and that file is free
 *    to change; only the shared, swept style library is.
 *
 * 2. **It cannot overflow its pane.** Every sample is a list of `PreviewBlock`s
 *    that each declares its own row height, and the caller fits that list into a
 *    row budget carved out of `settings-layout`'s `detail.bodyRows` — the same
 *    "state your height, never let Yoga shrink you" discipline the rest of the
 *    TUI uses (see `PRIMITIVES.md`). Row counts here are the single source of
 *    truth: `previewRowCount` sums the very blocks the component renders, so the
 *    budget the screen reserves and the rows the component paints can never
 *    disagree.
 */

import type { ReactNode } from "react";

import { Cells, Columns, toCells } from "./primitives.js";
import type { SettingDef, TuiSettings } from "./settings.js";
import type { Theme } from "./theme-context.js";
import {
  roleLabelText,
  speechFrame,
  toolCompactLine,
  toolDetailWidth,
  toolFrame,
  toolGlyphState,
  toolHeaderColumns,
  toolHeaderPrefix,
  type TranscriptStyle,
} from "./transcript-style.js";

// ---------------------------------------------------------------------------
// Sample content
// ---------------------------------------------------------------------------

/** A tool call the operator will recognise, reused across the tool-card sample. */
const TOOL_NAME = "run_command";
const TOOL_DETAIL = "3 ok · 0 issues";
/** Speech samples, kept short so a single body line is representative. */
const OPERATOR_LINE = "scan the target host";
const ASSISTANT_LINE = "Found 2 findings — triaging.";

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

/**
 * One vertical piece of a preview, with the exact number of rows it will paint.
 *
 * `render` is a thunk taking the live theme so the row COUNT can be summed
 * (`previewRowCount`) without a palette — the screen needs the height before it
 * knows how many rows to lend the preview, and the palette only matters once it
 * has decided to paint.
 */
export interface PreviewBlock {
  readonly key: string;
  readonly rows: number;
  readonly render: (theme: Theme) => ReactNode;
}

/** A theme token read defensively, so a palette missing a forward-added token
 *  degrades to a fallback rather than painting `undefined`. */
function token(theme: Theme, name: string, fallback: string): string {
  const value = (theme as unknown as Record<string, unknown>)[name];
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

/** A plain one-line row, fitted to the pane width. */
function line(key: string, width: number, text: string, fg: (t: Theme) => string): PreviewBlock {
  return {
    key,
    rows: 1,
    render: (theme) => (
      <Cells width={width} fg={fg(theme)}>
        {text}
      </Cells>
    ),
  };
}

/** The "PREVIEW" sub-heading that separates the sample from the prose above. */
function headerBlock(width: number): PreviewBlock {
  return line("preview-header", width, "PREVIEW", (t) => t.PRIMARY);
}

// ---------------------------------------------------------------------------
// Per-setting samples
// ---------------------------------------------------------------------------

/**
 * The tool-card sample: the CURRENT style rendered large, plus a one-line
 * thumbnail of the four styles with the active one bracketed, so the difference
 * between rail / inline / compact / hidden is visible at a glance.
 */
function toolCardBlocks(value: string, width: number): PreviewBlock[] {
  const blocks: PreviewBlock[] = [];

  if (value === "hidden") {
    // A successful/running call is omitted entirely under `hidden`; the honest
    // preview is to say so and show that a FAILURE is never hidden.
    const failFrame = toolFrame("hidden", width, false);
    const { icon, state } = toolGlyphState(false);
    blocks.push(
      line("tool-hidden-note", width, "success calls hidden", (t) => t.MUTED),
      {
        key: "tool-hidden-fail",
        rows: 1,
        render: (theme) => (
          <Cells width={width} fg={theme.ERROR}>
            {toolCompactLine(icon, TOOL_NAME, state, failFrame.contentWidth)}
          </Cells>
        ),
      },
    );
  } else {
    const frame = toolFrame(value as never, width, true);
    const { icon, state } = toolGlyphState(true);

    if (frame.singleLine) {
      // compact: one line, `icon name · state`.
      blocks.push({
        key: "tool-compact",
        rows: 1,
        render: (theme) => (
          <Cells width={width} fg={theme.SUCCESS}>
            {toolCompactLine(icon, TOOL_NAME, state, frame.contentWidth)}
          </Cells>
        ),
      });
    } else {
      // rail / inline: an icon + muted prefix + name header, then a detail line.
      // The rail style also draws a coloured left rail and (on a wide pane) an
      // indent — reproduced exactly from the same frame the chat surface uses.
      const prefix = toolHeaderPrefix(state);
      const detailW = toolDetailWidth(frame.contentWidth, width);
      const cols = toolHeaderColumns(frame.contentWidth, prefix.length, detailW);
      const hasRail = frame.railKind === "solid";
      blocks.push({
        key: "tool-card",
        rows: 2,
        render: (theme) => (
          <box
            flexDirection="row"
            width={width}
            flexShrink={0}
            minWidth={0}
            marginLeft={frame.outerMarginLeft}
          >
            {hasRail ? (
              <box width={frame.railWidth} flexShrink={0} alignSelf="stretch" backgroundColor={theme.SUCCESS} />
            ) : null}
            <box
              flexDirection="column"
              width={frame.contentWidth}
              flexShrink={0}
              minWidth={0}
              marginLeft={frame.contentGap}
            >
              <box flexDirection="row" width={frame.contentWidth} flexShrink={0} minWidth={0}>
                <Cells width={cols.iconWidth} fg={theme.SUCCESS}>
                  {icon}
                </Cells>
                <Cells width={cols.prefixWidth} fg={theme.MUTED}>
                  {prefix}
                </Cells>
                <Cells width={cols.nameWidth} fg={theme.TEXT}>
                  {TOOL_NAME}
                </Cells>
              </box>
              <Cells width={frame.contentWidth} fg={theme.MUTED}>
                {TOOL_DETAIL}
              </Cells>
            </box>
          </box>
        ),
      });
    }
  }

  blocks.push(choiceStripBlock("tool-choices", width, ["compact", "rail", "inline", "hidden"], value));
  return blocks;
}

/** A muted strip of every choice with the active one bracketed: `rail [inline] compact`. */
function choiceStripBlock(
  key: string,
  width: number,
  choices: readonly string[],
  active: string,
): PreviewBlock {
  return {
    key,
    rows: 1,
    render: (theme) => (
      <Columns
        available={width}
        gap={1}
        columns={choices.map((choice) => ({
          content: choice === active ? `[${choice}]` : choice,
          fg: choice === active ? theme.ACCENT : theme.MUTED,
          key: choice,
        }))}
      />
    ),
  };
}

/** One speaking turn, framed by `speechFrame` exactly as the chat surface does. */
function speechTurnBlock(
  key: string,
  kind: "user" | "assistant",
  style: TranscriptStyle,
  roleStyle: TuiSettings["roleLabelStyle"],
  width: number,
): PreviewBlock {
  const frame = speechFrame(style, kind, width);
  const label = roleLabelText(kind, roleStyle);
  const body = kind === "user" ? OPERATOR_LINE : ASSISTANT_LINE;
  const toneOf = (t: Theme) => (kind === "user" ? t.ACCENT : t.PRIMARY);

  if (frame.bordered) {
    const rows = 2 + (label ? 1 : 0) + 1;
    return {
      key,
      rows,
      render: (theme) => (
        <box
          flexDirection="column"
          width={width}
          flexShrink={0}
          minWidth={0}
          border
          borderColor={toneOf(theme)}
          paddingX={1}
        >
          {label ? (
            <Cells width={frame.contentWidth} fg={toneOf(theme)}>
              {label}
            </Cells>
          ) : null}
          <Cells width={frame.contentWidth} fg={theme.TEXT}>
            {body}
          </Cells>
        </box>
      ),
    };
  }

  // compact inlines the operator's label onto the body row; every other
  // unbordered frame keeps the label above the body (assistant markdown can
  // never share a row, matching the chat surface).
  if (!frame.labelOwnRow && kind === "user" && label) {
    return {
      key,
      rows: 1,
      render: (theme) => (
        <Columns
          available={width}
          gap={1}
          columns={[
            { content: label, fg: toneOf(theme), key: "label" },
            { flex: 1, min: 1, text: body, fg: theme.TEXT, key: "body" },
          ]}
        />
      ),
    };
  }

  const rows = (label ? 1 : 0) + 1;
  const hasRail = frame.railKind === "solid";
  const railGlyph = frame.railKind === "dotted" ? "┊" : frame.railKind === "marker" ? "·" : "";
  return {
    key,
    rows,
    render: (theme) => (
      <box flexDirection="row" width={width} flexShrink={0} minWidth={0}>
        {hasRail ? (
          <box width={frame.railWidth} flexShrink={0} alignSelf="stretch" backgroundColor={toneOf(theme)} />
        ) : railGlyph ? (
          <Cells width={frame.railWidth} fg={theme.MUTED}>
            {railGlyph}
          </Cells>
        ) : null}
        <box
          flexDirection="column"
          width={frame.contentWidth}
          flexShrink={0}
          minWidth={0}
          marginLeft={frame.contentGap}
        >
          {label ? (
            <Cells width={frame.contentWidth} fg={toneOf(theme)}>
              {label}
            </Cells>
          ) : null}
          <Cells width={frame.contentWidth} fg={theme.TEXT}>
            {body}
          </Cells>
        </box>
      </box>
    ),
  };
}

/** The transcript sample: an operator turn and a 0sec turn in the chosen frame. */
function transcriptBlocks(
  value: string,
  width: number,
  settings: TuiSettings,
): PreviewBlock[] {
  const style = value as TranscriptStyle;
  return [
    speechTurnBlock("turn-user", "user", style, settings.roleLabelStyle, width),
    speechTurnBlock("turn-0sec", "assistant", style, settings.roleLabelStyle, width),
  ];
}

/** The role-label sample: how each speaker is stamped at the current style. */
function roleLabelBlocks(value: string, width: number): PreviewBlock[] {
  const style = value as TuiSettings["roleLabelStyle"];
  const opLabel = roleLabelText("user", style);
  const botLabel = roleLabelText("assistant", style);
  if (style === "off") {
    return [line("role-off", width, "no speaker label row", (t) => t.MUTED)];
  }
  const row = (key: string, label: string | null, body: string, tone: (t: Theme) => string): PreviewBlock => ({
    key,
    rows: 1,
    render: (theme) => (
      <Columns
        available={width}
        gap={1}
        columns={[
          { content: label ?? "", fg: tone(theme), key: "label" },
          { flex: 1, min: 1, text: body, fg: theme.MUTED, key: "body" },
        ]}
      />
    ),
  });
  return [
    row("role-op", opLabel, OPERATOR_LINE, (t) => t.ACCENT),
    row("role-bot", botLabel, ASSISTANT_LINE, (t) => t.PRIMARY),
  ];
}

/** The composer sample: the input frame as `border` / `rail` / `plain` draw it. */
function composerBlocks(value: string, width: number): PreviewBlock[] {
  const sample = "type to chat or / for commands";
  if (value === "border") {
    return [
      {
        key: "composer-border",
        rows: 3,
        render: (theme) => (
          <box
            flexDirection="column"
            width={width}
            flexShrink={0}
            minWidth={0}
            border
            borderColor={theme.BORDER}
            backgroundColor={theme.PANEL_ALT}
            paddingX={1}
          >
            <Cells width={Math.max(1, width - 4)} fg={theme.MUTED}>
              {`› ${sample}`}
            </Cells>
          </box>
        ),
      },
    ];
  }
  if (value === "rail") {
    return [
      {
        key: "composer-rail",
        rows: 1,
        render: (theme) => (
          <box flexDirection="row" width={width} flexShrink={0} minWidth={0}>
            <box width={1} flexShrink={0} alignSelf="stretch" backgroundColor={theme.PRIMARY} />
            <box width={Math.max(1, width - 2)} flexShrink={0} minWidth={0} marginLeft={1} backgroundColor={theme.PANEL_ALT}>
              <Cells width={Math.max(1, width - 2)} fg={theme.MUTED}>
                {`› ${sample}`}
              </Cells>
            </box>
          </box>
        ),
      },
    ];
  }
  return [line("composer-plain", width, `› ${sample}`, (t) => t.MUTED)];
}

/** The density sample: two entries with the blank-line spacing density implies. */
function densityBlocks(value: string, width: number): PreviewBlock[] {
  const comfortable = value !== "compact";
  const blocks: PreviewBlock[] = [
    line("density-a", width, "✓ run_command · complete", (t) => t.SUCCESS),
  ];
  if (comfortable) blocks.push(line("density-gap", width, "", (t) => t.MUTED));
  blocks.push(line("density-b", width, "▌ 0sec  Finding confirmed", (t) => t.PRIMARY));
  return blocks;
}

/**
 * The model-display sample: a one-line mock of WHERE the model name lands for
 * the current value — in the bottom bar, on a message header, or nowhere — plus
 * the choice strip with the active value bracketed.
 */
function modelDisplayBlocks(value: string, width: number): PreviewBlock[] {
  const MODEL = "claude-opus-5";
  const blocks: PreviewBlock[] = [];

  if (value === "statusbar") {
    blocks.push({
      key: "model-statusbar",
      rows: 1,
      render: (theme) => (
        <Columns
          available={width}
          gap={1}
          columns={[
            { content: MODEL, fg: theme.ACCENT, key: "model" },
            { content: "·", fg: theme.MUTED, key: "sep" },
            { flex: 1, min: 1, text: "Standard · ~/proj", fg: theme.MUTED, key: "rest" },
          ]}
        />
      ),
    });
  } else if (value === "message") {
    blocks.push({
      key: "model-message",
      rows: 1,
      render: (theme) => (
        <Columns
          available={width}
          gap={1}
          columns={[
            { content: "▌ 0sec", fg: theme.PRIMARY, key: "label" },
            { content: MODEL, fg: theme.MUTED, key: "model" },
          ]}
        />
      ),
    });
  } else {
    blocks.push(line("model-off", width, "model name hidden", (t) => t.MUTED));
  }

  blocks.push(
    choiceStripBlock("model-display-choices", width, ["statusbar", "message", "off"], value),
  );
  return blocks;
}

/**
 * The logo-animation sample: a one-line description of the HIGHLIGHTED style
 * (the preview cannot actually animate here) plus the choice strip with the
 * active value bracketed, consistent with the other enum previews.
 */
function logoAnimationBlocks(value: string, width: number): PreviewBlock[] {
  const DESCRIPTIONS: Record<string, string> = {
    glitch: "glitch — a neon-flecked scramble that resolves (default)",
    rainbow: "rainbow — a looping hue sweep cycling across the mark",
    matrix: "matrix — a green matrix-rain cascade reveals the mark",
    wave: "wave — a rippling cyan wavefront wipes the mark in",
    neon: "neon — a neon-sign warm-up flicker, then it settles",
    shimmer: "shimmer — a bright comet with a gradient tail sweeps",
    pulse: "pulse — the red slash breathes red↔purple",
    strike: "strike — the red slash strikes through the 0",
    draw: "draw — the letters draw in behind a bright pen tip",
    fade: "fade — the mark blooms in from the centre",
    typein: "typein — cells reveal one by one, purple leading glow",
    sweep: "sweep — a bright bar wipes L→R revealing the mark",
    off: "off — the mark is drawn static, no intro",
  };
  const choices = [
    "glitch",
    "rainbow",
    "matrix",
    "wave",
    "neon",
    "shimmer",
    "pulse",
    "strike",
    "draw",
    "fade",
    "typein",
    "sweep",
    "off",
  ];
  const description = DESCRIPTIONS[value] ?? `current: ${value}`;
  return [
    line("logo-anim-desc", width, description, (t) => t.ACCENT),
    choiceStripBlock("logo-anim-choices", width, choices, value),
  ];
}

/**
 * The context-meter sample: the real bottom-bar glyphs when ON so the operator
 * sees the bar they are enabling, an on/off chip when OFF.
 */
/**
 * The transcript-detail sample: the same turn shown the way this value renders
 * it. "collapsed" folds the successful tool calls and reasoning into one ▸ line
 * (a failure would still show); "expanded" lists every step.
 */
function transcriptDetailBlocks(value: string, width: number): PreviewBlock[] {
  if (value === "expanded") {
    return [
      line("td-think", width, "▸ thinking", (t) => t.MUTED),
      line("td-a", width, "✓ run_command · nmap -sV", (t) => t.SUCCESS),
      line("td-b", width, "✓ read_file · report.md", (t) => t.SUCCESS),
      line("td-ans", width, "▌ 0sec  Two services exposed.", (t) => t.PRIMARY),
    ];
  }
  return [
    line("td-fold", width, "▸ 3 steps · thinking, run_command, read_file", (t) => t.MUTED),
    line("td-ans", width, "▌ 0sec  Two services exposed.", (t) => t.PRIMARY),
  ];
}

function contextMeterBlocks(value: boolean, width: number): PreviewBlock[] {
  if (!value) return stateChipBlocks(false, width);
  return [
    {
      key: "meter-sample",
      rows: 1,
      render: (theme) => (
        <Columns
          available={width}
          gap={1}
          columns={[
            { content: "▰▰▰▱▱▱", fg: theme.ACCENT, key: "bar" },
            { flex: 1, min: 1, text: "42% of 1M", fg: theme.MUTED, key: "pct" },
          ]}
        />
      ),
    },
  ];
}

/** The theme sample: a swatch strip of the palette's key colours + a live line. */
function themeBlocks(width: number): PreviewBlock[] {
  // Ordered so the tokens an operator judges a palette by come first, and the
  // strip is trimmed to the chips that actually fit the pane.
  const order: readonly string[] = [
    "TEXT",
    "MUTED",
    "PRIMARY",
    "ACCENT",
    "SUCCESS",
    "WARNING",
    "ERROR",
    "INFO",
    "BORDER",
    "PANEL",
  ];
  const CHIP = 2;
  const maxChips = Math.max(0, Math.floor((width + 1) / (CHIP + 1)));

  const swatch: PreviewBlock = {
    key: "theme-swatch",
    rows: 1,
    render: (theme) => {
      const chips = order
        .map((name) => ({ name, color: token(theme, name, theme.TEXT) }))
        .slice(0, maxChips);
      return (
        <box flexDirection="row" width={width} flexShrink={0} minWidth={0} gap={1}>
          {chips.map((chip) => (
            <box key={chip.name} width={CHIP} height={1} flexShrink={0} backgroundColor={chip.color} />
          ))}
        </box>
      );
    },
  };

  const sample: PreviewBlock = {
    key: "theme-sample",
    rows: 1,
    render: (theme) => (
      <Columns
        available={width}
        gap={1}
        columns={[
          { content: "0sec", fg: theme.PRIMARY, key: "primary" },
          { content: "operator", fg: theme.ACCENT, key: "accent" },
          { content: "warn", fg: theme.WARNING, key: "warn" },
          { content: "error", fg: theme.ERROR, key: "error" },
        ]}
      />
    ),
  };

  return [swatch, sample];
}

/**
 * The agent-rail sample: an on/off chip when OFF; a faithful mini-sidebar when
 * ON so the operator sees the sidebar they are enabling — a dim AGENTS heading
 * over a couple of agent rows (status glyph, short label, turns), the same
 * shape the chat rail paints. Red is reserved for a failure glyph, exactly as
 * the live rail reserves it.
 */
function rightSidebarBlocks(value: boolean, width: number): PreviewBlock[] {
  if (!value) return stateChipBlocks(false, width);
  return [
    line("rail-title", width, "AGENTS 2", (t) => t.MUTED),
    {
      key: "rail-a",
      rows: 1,
      render: (theme) => (
        <Columns
          available={width}
          gap={1}
          columns={[
            { content: "◉", fg: theme.ACCENT, key: "glyph" },
            { flex: 1, min: 1, text: "recon web tier", fg: theme.TEXT, key: "task" },
            { content: "3/8", fg: theme.MUTED, key: "turns" },
          ]}
        />
      ),
    },
    {
      key: "rail-b",
      rows: 1,
      render: (theme) => (
        <Columns
          available={width}
          gap={1}
          columns={[
            { content: "✓", fg: theme.SUCCESS, key: "glyph" },
            { flex: 1, min: 1, text: "auth fuzzing", fg: theme.MUTED, key: "task" },
            { content: "5/5", fg: theme.MUTED, key: "turns" },
          ]}
        />
      ),
    },
    line("rail-findings-title", width, "FINDINGS 2", (t) => t.MUTED),
    {
      key: "rail-finding",
      rows: 1,
      render: (theme) => (
        <Columns
          available={width}
          gap={1}
          columns={[
            { flex: 1, min: 1, text: "Auth bypass on /reset", fg: theme.TEXT, key: "title" },
            { content: "high", fg: theme.ERROR, key: "sev" },
          ]}
        />
      ),
    },
  ];
}

function leftSidebarBlocks(value: boolean, width: number): PreviewBlock[] {
  if (!value) return stateChipBlocks(false, width);
  return [
    line("left-sessions-title", width, "SESSIONS", (t) => t.MUTED),
    {
      key: "left-session",
      rows: 1,
      render: (theme) => (
        <Columns
          available={width}
          gap={1}
          columns={[
            { content: "•", fg: theme.ACCENT, key: "glyph" },
            { flex: 1, min: 1, text: "Audit the login flow", fg: theme.TEXT, key: "preview" },
          ]}
        />
      ),
    },
    {
      key: "left-session-2",
      rows: 1,
      render: (theme) => (
        <Columns
          available={width}
          gap={1}
          columns={[
            { content: "•", fg: theme.MUTED, key: "glyph" },
            { flex: 1, min: 1, text: "Deep pass for RCE", fg: theme.MUTED, key: "preview" },
          ]}
        />
      ),
    },
  ];
}

/** Booleans and any non-visual setting: an on/off state chip, no faked sample. */
function stateChipBlocks(value: boolean, width: number): PreviewBlock[] {
  return [
    {
      key: "state-chip",
      rows: 1,
      render: (theme) => (
        <Columns
          available={width}
          gap={1}
          columns={[
            {
              content: value ? " on " : " off ",
              fg: theme.CANVAS,
              bg: value ? theme.SUCCESS : theme.MUTED,
              key: "chip",
            },
            { flex: 1, min: 1, text: "no visual sample", fg: theme.MUTED, key: "note" },
          ]}
        />
      ),
    },
  ];
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

export interface PreviewInput {
  def: SettingDef | undefined;
  value: unknown;
  /** The detail pane's inner text width. */
  width: number;
  settings: TuiSettings;
}

/**
 * The full, un-clipped block list for a setting, `PREVIEW` header first.
 *
 * Returns an empty list when there is nothing to preview (no active setting, or
 * a pane too narrow to render into), so the caller reserves no rows for it.
 */
export function previewBlocks({ def, value, width, settings }: PreviewInput): PreviewBlock[] {
  const w = toCells(width);
  if (!def || w <= 0) return [];

  let body: PreviewBlock[];
  switch (def.key) {
    case "toolCardStyle":
      body = toolCardBlocks(String(value), w);
      break;
    case "transcriptDetail":
      body = transcriptDetailBlocks(String(value), w);
      break;
    case "transcriptStyle":
      body = transcriptBlocks(String(value), w, settings);
      break;
    case "roleLabelStyle":
      body = roleLabelBlocks(String(value), w);
      break;
    case "composerStyle":
      body = composerBlocks(String(value), w);
      break;
    case "density":
      body = densityBlocks(String(value), w);
      break;
    case "modelDisplay":
      body = modelDisplayBlocks(String(value), w);
      break;
    case "logoAnimation":
      body = logoAnimationBlocks(String(value), w);
      break;
    case "showContextMeter":
      body = contextMeterBlocks(value === true, w);
      break;
    case "showRightSidebar":
      body = rightSidebarBlocks(value === true, w);
      break;
    case "showLeftSidebar":
      body = leftSidebarBlocks(value === true, w);
      break;
    case "theme":
      body = themeBlocks(w);
      break;
    default:
      body =
        def.kind === "boolean"
          ? stateChipBlocks(value === true, w)
          : [line("value", w, `current: ${String(value)}`, (t) => t.ACCENT)];
  }

  if (body.length === 0) return [];
  return [headerBlock(w), ...body];
}

/** Total rows the full preview wants — the sum of the very blocks it renders. */
export function previewRowCount(input: PreviewInput): number {
  return previewBlocks(input).reduce((sum, block) => sum + block.rows, 0);
}

/**
 * Include blocks in order while they fit `rowBudget`, header first.
 *
 * A block is taken whole or not at all — painting half a bordered box is the
 * exact border-through-content corruption `PRIMITIVES.md` warns about — so the
 * greedy fit stops at the first block that would overrun rather than squeezing
 * one in.
 */
export function fitPreviewBlocks(blocks: readonly PreviewBlock[], rowBudget: number): PreviewBlock[] {
  const budget = toCells(rowBudget);
  const kept: PreviewBlock[] = [];
  let used = 0;
  for (const block of blocks) {
    if (used + block.rows > budget) break;
    kept.push(block);
    used += block.rows;
  }
  return kept;
}

export interface SettingsPreviewProps extends PreviewInput {
  /** Rows the screen has carved out of the detail pane for the preview. */
  rowBudget: number;
  theme: Theme;
}

/**
 * The rendered preview: the fitted blocks, stacked, each stating its own height.
 *
 * Nothing here shrinks: the block list was already trimmed to `rowBudget` by
 * `fitPreviewBlocks`, and every block paints exactly the rows it declared, so
 * the detail pane's border can never be pushed through the sample.
 */
export function SettingsPreview({ rowBudget, theme, ...input }: SettingsPreviewProps) {
  const kept = fitPreviewBlocks(previewBlocks(input), rowBudget);
  if (kept.length === 0) return null;
  return (
    <>
      {kept.map((block) => (
        <box key={block.key} flexShrink={0} minWidth={0}>
          {block.render(theme)}
        </box>
      ))}
    </>
  );
}
