/**
 * Column budgeting for the chat surface.
 *
 * OpenTUI lays rows out with Yoga. A row of auto-width `<text>` siblings
 * does not clip — if the children want more cells than the row has, they
 * are shrunk and painted over one another, which is how "Show available
 * slash commands" became "Showpavailableenslash commands" and how the
 * composer's hint line fused with the session counters.
 *
 * The fix is to allocate explicit cells for every sibling in a row and to
 * budget the text against the cells it was actually given. Keeping that
 * arithmetic here — rather than inline in the component — means the
 * invariant "a row never claims more cells than its container" is a unit
 * test instead of a code review.
 */

export interface ChatLayoutInput {
  width: number;
  height: number;
  /** Rendered length of the right-hand session counter, in cells. */
  statusTextLength: number;
}

export interface ChatLayout {
  compact: boolean;
  /** Usable inner width of the screen's padded content column. */
  contentWidth: number;
  /** Header: left "target: …" cell allocation. 0 when hidden. */
  headerTargetWidth: number;
  /** Header: right "scope: …" cell allocation. 0 when hidden. */
  headerScopeWidth: number;
  /** Gap between the two header columns. 0 when the header is hidden. */
  headerGap: number;
  /** Composer text cells, excluding the "> " prefix and cursor block. */
  composerTextWidth: number;
  /** Approval panel inner text width. */
  approvalWidth: number;
  /** Composer footer: left hint cells. */
  controlsWidth: number;
  /** Composer footer: right counter cells. 0 when hidden. */
  statusWidth: number;
  /** Gap between hint and counter. 0 when the counter is hidden. */
  statusGap: number;
}

/** Below this the header metadata and session counters are dropped. */
const COMPACT_WIDTH = 88;
const COMPACT_HEIGHT = 20;
const MIN_CONTENT_WIDTH = 28;

export function computeChatLayout({
  width,
  height,
  statusTextLength,
}: ChatLayoutInput): ChatLayout {
  const compact = width < COMPACT_WIDTH || height < COMPACT_HEIGHT;
  const contentWidth = Math.max(MIN_CONTENT_WIDTH, width - (compact ? 4 : 8));

  // The header is ONE row. It previously spent three rows on identity,
  // target/scope and an environment line, which is a third of a short
  // terminal's height before any content exists. Environment state now
  // lives in the bottom bar, and engagement state (target/scope) shares
  // this single row with the identity and mode.
  const headerGap = compact ? 0 : 2;
  const headerTargetWidth = compact
    ? 0
    : Math.max(1, Math.min(contentWidth - headerGap - 1, Math.floor(contentWidth * 0.52)));
  const headerScopeWidth = compact
    ? 0
    : Math.max(0, contentWidth - headerTargetWidth - headerGap);

  // The composer row is "› " + text + a one-cell cursor block.
  const composerTextWidth = Math.max(1, contentWidth - 3);
  // Approval panels share the composer's border and horizontal padding.
  const approvalWidth = Math.max(1, contentWidth - 2);

  // The counter never takes more than it needs, and never more than 40%
  // of the row — the hint on the left is the more useful of the two.
  const statusWidth = compact
    ? 0
    : Math.max(0, Math.min(statusTextLength, Math.floor(contentWidth * 0.4)));
  const statusGap = statusWidth > 0 ? 1 : 0;
  const controlsWidth = Math.max(1, contentWidth - statusWidth - statusGap);

  return {
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
  };
}

export interface CommandMenuLayoutInput {
  width: number;
  compact: boolean;
}

export interface CommandMenuLayout {
  innerWidth: number;
  rowWidth: number;
  nameWidth: number;
  metaWidth: number;
  nameGap: number;
  headerTitleWidth: number;
  headerQueryWidth: number;
  headerGap: number;
}

export function computeCommandMenuLayout({
  width,
  compact,
}: CommandMenuLayoutInput): CommandMenuLayout {
  const innerWidth = Math.max(0, width - (compact ? 8 : 10));
  // One cell for the selection marker, one for the gap after it.
  const rowWidth = Math.max(0, innerWidth - 2);
  const nameGap = rowWidth > 0 ? 1 : 0;
  const nameWidth = Math.max(
    0,
    Math.min(
      Math.max(0, rowWidth - nameGap),
      Math.max(compact ? 8 : 12, Math.floor(rowWidth * (compact ? 0.52 : 0.35))),
    ),
  );
  const metaWidth = Math.max(0, rowWidth - nameWidth - nameGap);

  const headerTitleWidth = Math.min(8, innerWidth);
  const headerGap = innerWidth - headerTitleWidth > 0 ? 1 : 0;
  const headerQueryWidth = Math.max(0, innerWidth - headerTitleWidth - headerGap);

  return {
    innerWidth,
    rowWidth,
    nameWidth,
    metaWidth,
    nameGap,
    headerTitleWidth,
    headerQueryWidth,
    headerGap,
  };
}

/**
 * Vertical budget for the slash-command menu.
 *
 * The menu is a bordered box stacked directly above the composer. If its
 * children ask for more rows than the column can spare, Yoga shrinks the
 * box but not its contents, and the box's own bottom border is painted
 * through the last command rows — the `-/clear--------/new-` corruption.
 *
 * So the visible item count must be derived from the terminal height
 * rather than guessed with a hardcoded constant. Every row consumed by
 * surrounding chrome is named below so the arithmetic can be checked and
 * tested rather than tuned by trial and error.
 */

/** Root padding above the header. */
const ROOT_PADDING_ROWS = 1;
/** A single header row plus its margin, at every width. */
const HEADER_ROWS_COMPACT = 1 + 1;
const HEADER_ROWS_WIDE = 1 + 1;
/**
 * Composer: top border, the input row, bottom border, plus its margin,
 * plus the bottom status bar that sits under it. The permanent hint row
 * is gone — it repeated the composer's own placeholder verbatim.
 */
const COMPOSER_ROWS = 3 + 1 + 1;
/** The transcript must keep at least its title and a line of content. */
const MIN_LEDGER_ROWS = 3;
/** Menu chrome: two border rows, the COMMANDS header, the hint footer. */
const MENU_CHROME_ROWS = 4;
/** The menu's own marginTop. */
const MENU_MARGIN_ROWS = 1;

export interface CommandMenuHeightInput {
  height: number;
  compact: boolean;
  /** Rows each entry renders: name row, plus a description row when wide. */
  rowsPerCommand: number;
}

export interface CommandMenuHeight {
  /** Maximum entries that fit without colliding with the border. */
  maxCommands: number;
  /** Rows available to the list body. */
  listRows: number;
}

/**
 * The menu may never take more than this share of the screen.
 *
 * Fitting the menu is necessary but not sufficient: a menu sized purely
 * by "what is left over" can grow to a dozen entries and squeeze the
 * transcript down to a couple of rows. The transcript does not clip when
 * it is squeezed — its children overflow and paint over one another —
 * so the menu has to leave real room behind, not just avoid overlapping
 * the composer.
 */
const MENU_MAX_HEIGHT_SHARE = 0.45;

export function computeCommandMenuHeight({
  height,
  compact,
  rowsPerCommand,
}: CommandMenuHeightInput): CommandMenuHeight {
  const perCommand = Math.max(1, rowsPerCommand);
  const chrome =
    ROOT_PADDING_ROWS +
    (compact ? HEADER_ROWS_COMPACT : HEADER_ROWS_WIDE) +
    COMPOSER_ROWS +
    MIN_LEDGER_ROWS +
    MENU_CHROME_ROWS +
    MENU_MARGIN_ROWS;
  const shareCap = Math.max(
    0,
    Math.floor(height * MENU_MAX_HEIGHT_SHARE) - MENU_CHROME_ROWS,
  );
  const listRows = Math.max(0, Math.min(height - chrome, shareCap));
  // At least one entry is always offered: a menu showing nothing is worse
  // than a menu one row shorter than ideal, and the box is clipped rather
  // than overlapped because it is rendered with an explicit height.
  const maxCommands = Math.max(1, Math.floor(listRows / perCommand));
  return { maxCommands, listRows };
}

/** Total rows the menu box occupies for a given number of visible entries. */
export function commandMenuBoxHeight(visibleCommands: number, rowsPerCommand: number): number {
  return MENU_CHROME_ROWS + Math.max(0, visibleCommands) * Math.max(1, rowsPerCommand);
}

/**
 * First entry index a scrolling command-menu viewport should show so the
 * highlighted row is on screen.
 *
 * The menu box is height-clamped to `visibleRows` entries but the filtered
 * list can be longer, so the rows live in a `<scrollbox>` and this decides how
 * far it is scrolled. The highlight is centred (context above and below) and
 * then pulled flush against the ends so the last page is never padded with
 * blank rows — the same viewport rule as {@link SelectorState}'s `windowFor`,
 * expressed over plain indices so it is unit-testable without a selector.
 */
export function commandMenuWindowStart(
  selectedIndex: number,
  visibleRows: number,
  totalRows: number,
): number {
  if (visibleRows <= 0 || totalRows <= 0) return 0;
  if (visibleRows >= totalRows) return 0;
  const index = Math.min(Math.max(selectedIndex, 0), totalRows - 1);
  const centred = index - Math.floor((visibleRows - 1) / 2);
  return Math.min(Math.max(centred, 0), totalRows - visibleRows);
}

export interface LedgerRowsInput {
  height: number;
  compact: boolean;
  /** Total rows the command menu box occupies, or 0 when it is closed. */
  menuRows: number;
  /** Rows taken by the active-subagent block, including its title. */
  subagentRows: number;
  /** Rows taken by an open approval panel, including its border. */
  approvalRows: number;
  /**
   * Extra flexShrink={0} rows pinned below the composer (e.g. the agent-nav
   * hint line). Defaults to 0 so existing callers are unaffected; when a hint
   * row is rendered the transcript must give up exactly that row or the column
   * over-subscribes and the row paints through the status bar.
   */
  hintRows?: number;
}

/**
 * Rows genuinely available to the transcript.
 *
 * Everything else in the column is declared `flexShrink={0}`, so the
 * transcript is the one region that absorbs pressure. It must therefore
 * know its own budget: a scrollbox whose height collapses below its
 * content still paints that content, which is how the empty state
 * interleaved into `Describe-anrobjective.y0seceenforces...`. Callers use
 * this to drop optional lines instead of overprinting them.
 */
export function computeLedgerRows({
  height,
  compact,
  menuRows,
  subagentRows,
  approvalRows,
  hintRows = 0,
}: LedgerRowsInput): number {
  const chrome =
    ROOT_PADDING_ROWS +
    (compact ? HEADER_ROWS_COMPACT : HEADER_ROWS_WIDE) +
    COMPOSER_ROWS +
    (menuRows > 0 ? menuRows + MENU_MARGIN_ROWS : 0) +
    subagentRows +
    approvalRows +
    Math.max(0, Math.trunc(hintRows) || 0);
  return Math.max(0, height - chrome);
}

/** Rows the empty-state hero needs: the block mark plus its three captions. */
export const LEDGER_MARK_ROWS = 5 + 3 + 3;

// ---------------------------------------------------------------------------
// Agent rail (chat right sidebar) + active-subagent navigation
// ---------------------------------------------------------------------------

/**
 * Below this TERMINAL width the rail is hidden even when the setting is on:
 * a sidebar that leaves the transcript too narrow to read is worse than no
 * sidebar, and a chat is transcript-first.
 */
export const AGENT_RAIL_MIN_TERMINAL_WIDTH = 100;
const AGENT_RAIL_MIN_WIDTH = 22;
const AGENT_RAIL_MAX_WIDTH = 34;
const AGENT_RAIL_WIDTH_SHARE = 0.28;
/** The transcript must keep at least this many text cells beside the rail. */
const AGENT_RAIL_MIN_TRANSCRIPT = 44;

export interface AgentRailLayoutInput {
  /** Raw terminal width, gated against {@link AGENT_RAIL_MIN_TERMINAL_WIDTH}. */
  width: number;
  /** The screen's padded content column width (from {@link computeChatLayout}). */
  contentWidth: number;
  compact: boolean;
  /** The `showAgentRail` setting. */
  showAgentRail: boolean;
}

export interface AgentRailLayout {
  /** The rail is actually painted this frame. */
  visible: boolean;
  /** Outer cells the rail occupies in the row. 0 when hidden. */
  railWidth: number;
  /** Text cells inside the rail (after its divider + padding). 0 when hidden. */
  railInnerWidth: number;
  /** Gap cells between the transcript column and the rail. 0 when hidden. */
  gap: number;
  /**
   * Text-wrap width for transcript entries. Equal to the full-width transcript
   * inner width when the rail is hidden, and the shrunken width beside the rail
   * when it is shown, so a caller passes ONE number to `renderEntry` either way.
   */
  transcriptWidth: number;
}

/**
 * Budget the chat body between the transcript column and the optional agent
 * rail. Pure, and total over any geometry: a narrow terminal, a cleared toggle,
 * or a rail that would starve the transcript all collapse to the hidden result
 * (rail 0, transcript full-width), so the caller never has to special-case the
 * off state. The rail is a fixed-share column clamped to a sane band; the two
 * cells of divider + padding it spends on chrome come off its inner width, and
 * the transcript keeps the same paddingX (`compact ? 2 : 4`) it has without the
 * rail. Widths never exceed `contentWidth` — swept in the tests.
 */
export function computeAgentRailLayout({
  width,
  contentWidth,
  compact,
  showAgentRail,
}: AgentRailLayoutInput): AgentRailLayout {
  const cw = Math.max(0, Math.trunc(Number.isFinite(contentWidth) ? contentWidth : 0));
  const pad = compact ? 2 : 4;
  const fullTranscript = Math.max(8, cw - pad);
  const hidden: AgentRailLayout = {
    visible: false,
    railWidth: 0,
    railInnerWidth: 0,
    gap: 0,
    transcriptWidth: fullTranscript,
  };
  if (!showAgentRail) return hidden;
  const terminalWidth = Math.max(0, Math.trunc(Number.isFinite(width) ? width : 0));
  if (terminalWidth < AGENT_RAIL_MIN_TERMINAL_WIDTH) return hidden;

  const gap = 1;
  const railWidth = Math.min(
    AGENT_RAIL_MAX_WIDTH,
    Math.max(AGENT_RAIL_MIN_WIDTH, Math.floor(cw * AGENT_RAIL_WIDTH_SHARE)),
  );
  const transcriptOuter = cw - railWidth - gap;
  const transcriptWidth = transcriptOuter - pad;
  if (transcriptWidth < AGENT_RAIL_MIN_TRANSCRIPT) return hidden;

  // One divider cell + one padding cell inside the rail.
  const railInnerWidth = Math.max(1, railWidth - 2);
  return {
    visible: true,
    railWidth,
    railInnerWidth,
    gap,
    transcriptWidth: Math.max(8, transcriptWidth),
  };
}

// ---------------------------------------------------------------------------
// Collapsible LEFT + RIGHT sidebars (the chat's two-rail layout)
// ---------------------------------------------------------------------------

/**
 * Below this TERMINAL width a sidebar is hidden even when its setting is on —
 * the same "a chat is transcript-first" rule the single rail obeyed, applied to
 * each side independently. Aliases the rail's threshold so the two agree.
 */
export const SIDEBAR_MIN_TERMINAL_WIDTH = AGENT_RAIL_MIN_TERMINAL_WIDTH;
const SIDEBAR_MIN_WIDTH = AGENT_RAIL_MIN_WIDTH;
const SIDEBAR_MAX_WIDTH = AGENT_RAIL_MAX_WIDTH;
const SIDEBAR_WIDTH_SHARE = AGENT_RAIL_WIDTH_SHARE;
/** The transcript must keep at least this many text cells between the sidebars. */
const SIDEBAR_MIN_TRANSCRIPT = AGENT_RAIL_MIN_TRANSCRIPT;

export interface SidebarsLayoutInput {
  /** Raw terminal width, gated against {@link SIDEBAR_MIN_TERMINAL_WIDTH}. */
  width: number;
  /** The screen's padded content column width (from {@link computeChatLayout}). */
  contentWidth: number;
  compact: boolean;
  /** The `showLeftSidebar` setting. */
  showLeft: boolean;
  /** The `showRightSidebar` setting (the promoted agent rail). */
  showRight: boolean;
}

export interface SidebarsLayout {
  leftVisible: boolean;
  rightVisible: boolean;
  /** Outer cells the left sidebar occupies. 0 when hidden. */
  leftWidth: number;
  /** Text cells inside the left sidebar (after its divider + padding). 0 when hidden. */
  leftInnerWidth: number;
  /** Outer cells the right sidebar occupies. 0 when hidden. */
  rightWidth: number;
  /** Text cells inside the right sidebar (after its divider + padding). 0 when hidden. */
  rightInnerWidth: number;
  /** Gap cells between the left sidebar and the transcript. 0 when the left is hidden. */
  leftGap: number;
  /** Gap cells between the transcript and the right sidebar. 0 when the right is hidden. */
  rightGap: number;
  /**
   * Text-wrap width for transcript entries — the full-width value when both
   * sidebars are hidden, and the shrunken value between them otherwise, so the
   * caller passes ONE number to `renderEntry` either way.
   */
  transcriptWidth: number;
}

/**
 * Budget the chat body between an optional LEFT sidebar, the transcript, and an
 * optional RIGHT sidebar. Pure, and total over any geometry.
 *
 * The transcript takes priority: each sidebar is only granted its column while
 * the transcript keeps {@link SIDEBAR_MIN_TRANSCRIPT} cells. When both are
 * requested but only one fits, the RIGHT sidebar ("what's happening now") is
 * kept and the LEFT is dropped, so the live view wins the last column. A narrow
 * terminal, a cleared toggle, or a pair that would starve the transcript all
 * collapse to fewer (or no) sidebars — the caller never special-cases the off
 * state. Each sidebar spends two cells (divider + padding) on chrome off its
 * inner width, and the transcript keeps its usual paddingX (`compact ? 2 : 4`).
 * Widths never exceed `contentWidth` — swept in the tests.
 */
export function computeSidebarsLayout({
  width,
  contentWidth,
  compact,
  showLeft,
  showRight,
}: SidebarsLayoutInput): SidebarsLayout {
  const cw = Math.max(0, Math.trunc(Number.isFinite(contentWidth) ? contentWidth : 0));
  const pad = compact ? 2 : 4;
  const fullTranscript = Math.max(8, cw - pad);
  const hidden: SidebarsLayout = {
    leftVisible: false,
    rightVisible: false,
    leftWidth: 0,
    leftInnerWidth: 0,
    rightWidth: 0,
    rightInnerWidth: 0,
    leftGap: 0,
    rightGap: 0,
    transcriptWidth: fullTranscript,
  };
  const terminalWidth = Math.max(0, Math.trunc(Number.isFinite(width) ? width : 0));
  const narrow = terminalWidth < SIDEBAR_MIN_TERMINAL_WIDTH;
  const canLeft = showLeft && !narrow;
  const canRight = showRight && !narrow;
  if (!canLeft && !canRight) return hidden;

  const sidebarWidth = Math.min(
    SIDEBAR_MAX_WIDTH,
    Math.max(SIDEBAR_MIN_WIDTH, Math.floor(cw * SIDEBAR_WIDTH_SHARE)),
  );
  const gap = 1;

  // Priority order: both, then right-only, then left-only. The transcript keeps
  // its minimum in every accepted case, so a pair that would starve it falls
  // through to a single sidebar (right wins), then to none.
  const attempts: { l: boolean; r: boolean }[] = [];
  if (canLeft && canRight) attempts.push({ l: true, r: true });
  if (canRight) attempts.push({ l: false, r: true });
  if (canLeft) attempts.push({ l: true, r: false });

  for (const attempt of attempts) {
    const leftWidth = attempt.l ? sidebarWidth : 0;
    const rightWidth = attempt.r ? sidebarWidth : 0;
    const leftGap = attempt.l ? gap : 0;
    const rightGap = attempt.r ? gap : 0;
    const transcriptOuter = cw - leftWidth - rightWidth - leftGap - rightGap;
    const transcriptWidth = transcriptOuter - pad;
    if (transcriptWidth < SIDEBAR_MIN_TRANSCRIPT) continue;
    return {
      leftVisible: attempt.l,
      rightVisible: attempt.r,
      leftWidth,
      leftInnerWidth: attempt.l ? Math.max(1, leftWidth - 2) : 0,
      rightWidth,
      rightInnerWidth: attempt.r ? Math.max(1, rightWidth - 2) : 0,
      leftGap,
      rightGap,
      transcriptWidth: Math.max(8, transcriptWidth),
    };
  }
  return hidden;
}

/**
 * Clamp a selection index onto a list of `count` items, or -1 when the list is
 * empty. The pure core of the active-subagent navigation: the list reshuffles
 * as agents spawn and finish, so a stored index must be pulled back onto a
 * valid row (or dropped) every render.
 */
export function clampAgentSelection(count: number, index: number): number {
  const total = Math.max(0, Math.trunc(Number.isFinite(count) ? count : 0));
  if (total <= 0) return -1;
  const i = Math.trunc(Number.isFinite(index) ? index : 0);
  return Math.min(Math.max(i, 0), total - 1);
}

/**
 * Move the active-subagent selection by `delta`, wrapping at both ends. Returns
 * -1 for an empty list so the caller drops out of nav mode. Pure — mirrors the
 * herd list's `moveHerdSelection` but over a flat index (no headings to skip).
 */
export function moveAgentSelection(count: number, index: number, delta: number): number {
  const total = Math.max(0, Math.trunc(Number.isFinite(count) ? count : 0));
  if (total <= 0) return -1;
  const cur = clampAgentSelection(total, index);
  const step = Math.trunc(Number.isFinite(delta) ? delta : 0);
  return (((cur + step) % total) + total) % total;
}
