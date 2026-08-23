/**
 * Shared pure slash-command registry, parser, and filter.
 *
 * Portable — no React, OpenTUI, or @0sec/core imports. Usable by both
 * the Bun TUI (ChatScreen) and the Node readline console.
 *
 * A "slash command" is any input starting with `/` followed by a name
 * (alphanumeric, digits, hyphens, underscores). The parser detects
 * whether the input is a slash invocation, extracts the name and
 * argument string, and resolves it against the built-in vocabulary.
 *
 * Unknown slash commands produce `{ isSlash: true, isUnknown: true }`
 * so consumers can show a local notice — they MUST NOT reach the LLM.
 * Non-slash input is left for the engine as a normal operator message.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CommandCategory =
  | "navigation"
  | "session"
  | "info"
  | "mode"
  | "system";

export interface SlashCommand {
  /** Canonical name (without leading `/`). */
  readonly name: string;
  /** Alternate names (without leading `/`). */
  readonly aliases: readonly string[];
  readonly category: CommandCategory;
  /** One-line description for help output. */
  readonly description: string;
  /** Usage hint, e.g. "/mode [standard|copilot|yolo]". Omitted when blank. */
  readonly usage?: string;
  /**
   * Commands that only make sense in the Bun TUI (navigation/routing).
   * The readline console explains that the TUI is required.
   */
  readonly tuiOnly?: boolean;
}

export interface ParsedSlashInput {
  /** True when the raw input starts with `/`. */
  readonly isSlash: boolean;
  /**
   * The canonical command name when the slash input resolves to a known
   * command. `undefined` for unknown slash commands or non-slash input.
   */
  readonly command: string | undefined;
  /**
   * The raw name extracted from input: everything between the leading `/`
   * and the first space (or end of string). E.g. "/mode copilot" → "mode".
   */
  readonly rawName: string;
  /**
   * Everything after the first space following the command name (trimmed).
   * Empty string when there are no arguments.
   */
  readonly args: string;
  /** True when a known command was matched. */
  readonly isKnown: boolean;
  /** True when input starts with `/` but does NOT match a known command. */
  readonly isUnknown: boolean;
}

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

export const SLASH_COMMANDS: readonly SlashCommand[] = [
  // ── info ────────────────────────────────────────────────────────────────
  {
    name: "help",
    aliases: ["?", "commands"],
    category: "info",
    description: "Show available slash commands",
    usage: "/help [command]",
  },
  {
    name: "status",
    aliases: [],
    category: "info",
    description: "Show session status, mode, and tool count",
  },
  {
    name: "tools",
    aliases: [],
    category: "info",
    description: "List available tools",
  },
  {
    name: "agents",
    aliases: [],
    category: "info",
    description: "List available agents",
    tuiOnly: true,
  },

  // ── session ─────────────────────────────────────────────────────────────
  {
    name: "clear",
    aliases: ["new"],
    category: "session",
    description: "Clear the conversation history",
  },
  {
    name: "history",
    aliases: [],
    category: "session",
    description: "Review previous conversation turns",
    tuiOnly: true,
  },
  {
    name: "findings",
    aliases: ["finds"],
    category: "session",
    description: "Display session findings",
    tuiOnly: true,
  },
  {
    name: "replay",
    aliases: [],
    category: "session",
    description: "Replay a previous turn or session",
    tuiOnly: true,
  },

  // ── mode ────────────────────────────────────────────────────────────────
  {
    name: "mode",
    aliases: [],
    category: "mode",
    description: "Set Standard (automatic in scope), Co-pilot (approve non-read-only tools), or YOLO (configured scope only)",
    usage: "/mode [standard|copilot|yolo]",
  },
  {
    name: "resume",
    aliases: ["sessions"],
    category: "session",
    description: "List saved sessions and resume one, keeping its conversation",
    usage: "/resume",
  },
  {
    name: "providers",
    aliases: [],
    category: "info",
    description: "Show which model providers have credentials on this machine",
    usage: "/providers",
  },
  {
    name: "explain",
    aliases: ["eli5"],
    category: "session",
    description: "Explain the last result in plain language, without jargon",
    usage: "/explain [topic]",
  },
  {
    name: "feedback",
    aliases: [],
    category: "system",
    description: "Record feedback about 0sec to a local file you control",
    usage: "/feedback <message>",
  },
  {
    name: "settings",
    aliases: ["config", "prefs"],
    category: "system",
    description: "Toggle console display settings; changes persist between sessions",
    usage: "/settings",
  },
  {
    name: "model",
    aliases: ["models"],
    category: "mode",
    description: "Show the active model, or switch to another for this session",
    usage: "/model [id]",
  },

  // ── navigation ──────────────────────────────────────────────────────────
  {
    name: "chat",
    aliases: [],
    category: "navigation",
    description: "Return to the main chat view",
    tuiOnly: true,
  },
  {
    name: "launcher",
    aliases: ["home"],
    category: "navigation",
    description: "Open the session launcher / home screen",
    tuiOnly: true,
  },
  {
    name: "ops",
    aliases: ["runs"],
    category: "navigation",
    description: "View active and recent operations",
    tuiOnly: true,
  },
  {
    name: "market",
    aliases: ["marketplace"],
    category: "navigation",
    description: "Browse the extension marketplace",
    tuiOnly: true,
  },
  {
    name: "connect",
    aliases: ["login", "auth"],
    category: "navigation",
    description: "Connect a model provider: add an API key or subscription sign-in",
    usage: "/connect",
    tuiOnly: true,
  },
  {
    name: "back",
    aliases: [],
    category: "navigation",
    description: "Navigate to the previous screen",
    tuiOnly: true,
  },
  {
    name: "scope",
    aliases: [],
    category: "navigation",
    description: "Show engagement scope; extensions require approval",
    tuiOnly: true,
  },

  // ── system ──────────────────────────────────────────────────────────────
  {
    name: "doctor",
    aliases: [],
    category: "system",
    description: "Run diagnostics on runtime and configuration",
    tuiOnly: true,
  },
  {
    name: "exit",
    aliases: ["quit"],
    category: "system",
    description: "End the session and return to the shell",
  },
];

// ---------------------------------------------------------------------------
// Index — static string-keyed lookup table
// ---------------------------------------------------------------------------

/** Maps every canonical name and alias → canonical name (lowercase). */
const NAME_INDEX: Record<string, string> = {};
for (const cmd of SLASH_COMMANDS) {
  NAME_INDEX[cmd.name] = cmd.name;
  for (const alias of cmd.aliases) {
    NAME_INDEX[alias] = cmd.name;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Look up a command by canonical name or alias (case-sensitive, lower-case
 * only). Returns `undefined` when no match exists.
 */
export function getCommandByName(name: string): SlashCommand | undefined {
  const canonical = NAME_INDEX[name];
  if (!canonical) return undefined;
  // Linear scan over the small static array — fine at this scale.
  // Swap to a canonical-indexed Record if the list grows past ~50.
  for (const cmd of SLASH_COMMANDS) {
    if (cmd.name === canonical) return cmd;
  }
  return undefined;
}

/**
 * Parse a raw input line and resolve it against the command vocabulary.
 *
 * Non-slash inputs return `{ isSlash: false, isKnown: false, isUnknown: false }`.
 * Unknown slash commands (e.g. "/blarg") return `{ isSlash: true, isUnknown: true }`.
 * Known commands populate `command`, `rawName`, and `args`.
 *
 * Consumers MUST check `isUnknown` before sending to the LLM — unknown
 * slash commands produce a local notice and MUST NOT reach the engine.
 */
export function findCommand(input: string): ParsedSlashInput {
  const trimmed = input.trimStart();

  if (!trimmed.startsWith("/")) {
    return {
      isSlash: false,
      command: undefined,
      rawName: "",
      args: "",
      isKnown: false,
      isUnknown: false,
    };
  }

  // Strip the leading "/" and split on first space
  const afterSlash = trimmed.slice(1);
  const spaceIndex = afterSlash.indexOf(" ");
  const rawName = spaceIndex >= 0 ? afterSlash.slice(0, spaceIndex) : afterSlash;
  const args = spaceIndex >= 0 ? afterSlash.slice(spaceIndex + 1).trim() : "";

  const canonical = NAME_INDEX[rawName];
  if (canonical) {
    return {
      isSlash: true,
      command: canonical,
      rawName,
      args,
      isKnown: true,
      isUnknown: false,
    };
  }

  return {
    isSlash: true,
    command: undefined,
    rawName,
    args,
    isKnown: false,
    isUnknown: true,
  };
}

/**
 * Filter the command vocabulary by a query string. Matches against
 * canonical names and aliases (case-insensitive prefix match).
 *
 * Returns all commands when query is empty. Commands are ordered by
 * category, then alphabetically by canonical name.
 */
export function filterCommands(query: string): SlashCommand[] {
  const trimmed = query.trim().toLowerCase();
  if (!trimmed) return [...SLASH_COMMANDS];

  return SLASH_COMMANDS.filter((cmd) => {
    if (cmd.name.startsWith(trimmed)) return true;
    return cmd.aliases.some((a) => a.startsWith(trimmed));
  });
}