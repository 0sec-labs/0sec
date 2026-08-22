/**
 * Structured console panels — the data layer behind slash-command output.
 *
 * Slash commands used to append one flat "notice" entry per line into the
 * chat transcript, so `/help` produced ~20 bullets that were visually
 * indistinguishable from the conversation. A panel is instead a single
 * titled block with aligned label/value rows, rendered as one unit.
 *
 * Everything here is pure: builders return full, untruncated strings and a
 * column allocation. Truncation and painting belong to the renderer — a
 * builder that truncated would bake a terminal width into data that is also
 * used by the readline console and by tests.
 *
 * Portable — no React, OpenTUI, or @0sec/core imports, no I/O.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PanelRow {
  /** Left column, e.g. "/mode" or "target". Omit for a full-width line. */
  label?: string;
  /** Right column text. */
  value: string;
  /** Renders as a section heading inside the panel rather than a row. */
  heading?: boolean;
}

export interface PanelData {
  title: string;
  subtitle?: string;
  rows: PanelRow[];
}

export interface PanelColumns {
  labelWidth: number;
  valueWidth: number;
  gap: number;
}

// ---------------------------------------------------------------------------
// Column arithmetic
// ---------------------------------------------------------------------------

/** The label column never takes more than this share of the panel body. */
const LABEL_WIDTH_SHARE = 0.4;
const LABEL_VALUE_GAP = 1;

/**
 * Column allocation for a panel body of a given inner width.
 *
 * OpenTUI lays a row of `<text>` siblings out with Yoga, which shrinks rather
 * than clips: two siblings that together claim more cells than their row was
 * given get painted over one another. So the contract this function upholds is
 * `labelWidth + gap + valueWidth <= innerWidth` for *every* input, including
 * the degenerate widths 0, 1 and 2 that a narrow terminal really does produce.
 *
 * The 40% cap exists because a single pathological label (a long `usage`
 * string) must not starve the descriptions next to it — better to truncate one
 * label in the renderer than to lose every value in the panel.
 */
export function panelColumns(
  rows: readonly PanelRow[],
  innerWidth: number,
): PanelColumns {
  // Callers derive innerWidth from terminal geometry, which can arrive
  // negative or fractional during a resize; normalise before any arithmetic.
  const width = Number.isFinite(innerWidth) ? Math.max(0, Math.floor(innerWidth)) : 0;

  let longestLabel = 0;
  for (const row of rows) {
    // Headings span the whole body, so their text must not widen the label
    // column that the ordinary rows are aligned against.
    if (row.heading) continue;
    if (row.label) longestLabel = Math.max(longestLabel, row.label.length);
  }

  if (longestLabel === 0) {
    return { labelWidth: 0, gap: 0, valueWidth: width };
  }

  const cap = Math.floor(width * LABEL_WIDTH_SHARE);
  // Leave at least the gap plus one value cell; below that the label column
  // cannot pay for itself and the value takes the whole body.
  const affordable = Math.max(0, width - LABEL_VALUE_GAP - 1);
  const labelWidth = Math.max(0, Math.min(longestLabel, cap, affordable));
  const gap = labelWidth > 0 ? LABEL_VALUE_GAP : 0;
  const valueWidth = Math.max(0, width - labelWidth - gap);

  return { labelWidth, gap, valueWidth };
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

export interface HelpCommand {
  readonly name: string;
  readonly aliases: readonly string[];
  readonly description: string;
  readonly usage?: string;
  readonly category: string;
}

/**
 * Categories are emitted in this order rather than in vocabulary order so the
 * panel reads the same no matter how SLASH_COMMANDS is edited. Anything not
 * listed here is appended in first-seen order instead of being dropped.
 */
const CATEGORY_ORDER: readonly string[] = [
  "info",
  "session",
  "mode",
  "navigation",
  "system",
];

const CATEGORY_TITLES: Record<string, string> = {
  info: "Info",
  session: "Session",
  mode: "Mode",
  navigation: "Navigation",
  system: "System",
};

function categoryTitle(category: string): string {
  const known = CATEGORY_TITLES[category];
  if (known) return known;
  if (!category) return "Other";
  return category.charAt(0).toUpperCase() + category.slice(1);
}

function matchesQuery(command: HelpCommand, query: string): boolean {
  if (command.name.toLowerCase().includes(query)) return true;
  if (command.aliases.some((a) => a.toLowerCase().includes(query))) return true;
  return command.description.toLowerCase().includes(query);
}

function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return count === 1 ? `1 ${singular}` : `${count} ${pluralForm}`;
}

export function buildHelpPanel(
  commands: readonly HelpCommand[],
  query?: string,
): PanelData {
  const trimmedQuery = (query ?? "").trim();
  const needle = trimmedQuery.toLowerCase();
  const matched = needle
    ? commands.filter((cmd) => matchesQuery(cmd, needle))
    : [...commands];

  if (matched.length === 0) {
    // An empty `rows` array would render as a bare title with a blank body,
    // which reads like a bug. Say what happened instead.
    const reason = trimmedQuery
      ? `No commands match "${trimmedQuery}". Run /help with no argument to see all commands.`
      : "No slash commands are registered.";
    return {
      title: "Slash commands",
      subtitle: trimmedQuery ? `0 commands matching "${trimmedQuery}"` : "0 commands",
      rows: [{ value: reason }],
    };
  }

  const byCategory = new Map<string, HelpCommand[]>();
  for (const cmd of matched) {
    const bucket = byCategory.get(cmd.category);
    if (bucket) bucket.push(cmd);
    else byCategory.set(cmd.category, [cmd]);
  }

  const ordered = [
    ...CATEGORY_ORDER.filter((c) => byCategory.has(c)),
    ...[...byCategory.keys()].filter((c) => !CATEGORY_ORDER.includes(c)),
  ];

  const rows: PanelRow[] = [];
  for (const category of ordered) {
    const group = byCategory.get(category);
    if (!group || group.length === 0) continue;
    rows.push({ value: categoryTitle(category), heading: true });
    for (const cmd of group) {
      // `usage` carries the argument hint ("/mode [standard|copilot|yolo]"),
      // which is the more useful left column when a command takes arguments.
      const label = cmd.usage && cmd.usage.trim() ? cmd.usage.trim() : `/${cmd.name}`;
      const aliases = cmd.aliases.length
        ? ` (${cmd.aliases.map((a) => `/${a}`).join(", ")})`
        : "";
      rows.push({ label, value: `${cmd.description}${aliases}` });
    }
  }

  const subtitle = trimmedQuery
    ? `${plural(matched.length, "command")} matching "${trimmedQuery}"`
    : plural(matched.length, "command");

  return { title: "Slash commands", subtitle, rows };
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

export function buildToolsPanel(toolNames: readonly string[]): PanelData {
  if (toolNames.length === 0) {
    return {
      title: "Tools",
      subtitle: "0 tools",
      rows: [{ value: "No tools are registered for this session." }],
    };
  }

  return {
    title: "Tools",
    subtitle: plural(toolNames.length, "tool"),
    // Full-width rows: tool names are a single column, so a label column here
    // would only shrink the text it is describing.
    rows: toolNames.map((name) => ({ value: name })),
  };
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

export interface StatusPanelInput {
  model?: string;
  provider?: string;
  mode: string;
  target?: string;
  scopeRules: readonly string[];
  toolCount: number;
  turns: number;
  inputTokens: number;
  outputTokens: number;
}

const NOT_SET = "not set";

export function buildStatusPanel(input: StatusPanelInput): PanelData {
  // Missing optional inputs are stated as missing rather than dropped: a row
  // that silently disappears reads as "not applicable", which is a different
  // claim from "we do not know", and operators act on the difference.
  const modelBase = input.model?.trim() ? input.model.trim() : NOT_SET;
  const provider = input.provider?.trim();
  const model = provider ? `${modelBase} (${provider})` : modelBase;

  const rows: PanelRow[] = [
    { label: "model", value: model },
    { label: "mode", value: input.mode?.trim() ? input.mode.trim() : NOT_SET },
    { label: "target", value: input.target?.trim() ? input.target.trim() : NOT_SET },
    {
      label: "scope",
      value: input.scopeRules.length
        ? input.scopeRules.join(", ")
        : "scope on demand",
    },
    { label: "tools", value: String(input.toolCount) },
    { label: "turns", value: String(input.turns) },
    { label: "tokens", value: `${input.inputTokens}→${input.outputTokens}` },
  ];

  return { title: "Session status", rows };
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

export interface ScopePanelInput {
  target?: string;
  scopeRules: readonly string[];
  mode: string;
}

export function buildScopePanel(input: ScopePanelInput): PanelData {
  const rows: PanelRow[] = [
    { label: "target", value: input.target?.trim() ? input.target.trim() : NOT_SET },
    { label: "mode", value: input.mode?.trim() ? input.mode.trim() : NOT_SET },
  ];

  if (input.scopeRules.length === 0) {
    // Scope is a security surface. With no rules configured the panel must not
    // read as permissive by omission — an empty list is "nothing authorized",
    // never "everything allowed", and widening it is an operator decision.
    rows.push({ value: "No engagement scope is configured.", heading: true });
    rows.push({
      value:
        "Nothing is authorized for testing until an operator configures scope. " +
        "Any scope extension requires explicit operator approval.",
    });
    return {
      title: "Engagement scope",
      subtitle: "no scope configured",
      rows,
    };
  }

  rows.push({ value: "Rules", heading: true });
  for (const rule of input.scopeRules) {
    rows.push({ value: rule });
  }

  return {
    title: "Engagement scope",
    subtitle: `${plural(input.scopeRules.length, "rule")}; extensions require operator approval`,
    rows,
  };
}
