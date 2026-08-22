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
}: LedgerRowsInput): number {
  const chrome =
    ROOT_PADDING_ROWS +
    (compact ? HEADER_ROWS_COMPACT : HEADER_ROWS_WIDE) +
    COMPOSER_ROWS +
    (menuRows > 0 ? menuRows + MENU_MARGIN_ROWS : 0) +
    subagentRows +
    approvalRows;
  return Math.max(0, height - chrome);
}

/** Rows the empty-state hero needs: the block mark plus its three captions. */
export const LEDGER_MARK_ROWS = 5 + 3 + 3;
