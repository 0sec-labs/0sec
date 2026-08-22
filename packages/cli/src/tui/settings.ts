/**
 * User-configurable display settings for the interactive console, persisted
 * to `~/.0sec/tui-settings.json`.
 *
 * The trigger was "let me hide the status bar", but a single boolean would
 * have been the wrong shape: every chrome element in the TUI (logo, hints,
 * turn summaries, timestamps, subagent list) is something somebody wants
 * gone, and adding a bespoke flag per element means a new persistence path,
 * a new default, and a new migration each time. So the settings are a *table*
 * — `SETTING_DEFS` — and everything else (the settings UI, `/settings`
 * toggling, normalisation of a file on disk) is driven off that table. Adding
 * a toggle is one entry plus one field on `TuiSettings`, and the tests refuse
 * to let those two drift apart.
 *
 * Two hard rules follow from where this code runs. First, the file is
 * user-visible and therefore hand-editable and therefore corruptible:
 * `normalizeSettings` is total, accepting literally any parsed JSON value and
 * always producing a complete, valid object, so a stray comma or a `true`
 * where a string belongs degrades to a default instead of crashing a session.
 * Second, this runs inside a TUI that owns the terminal — nothing here may
 * print, and nothing here may throw on an I/O failure, because a read-only
 * `$HOME` is an inconvenience, not a reason to lose the console.
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { homeStateDir } from "@0sec/shared";

export type SettingKind = "boolean" | "enum";

export interface SettingDef<T = unknown> {
  key: string;
  label: string;
  description: string;
  kind: SettingKind;
  default: T;
  /** Allowed values for kind === "enum". */
  choices?: readonly string[];
  /** Grouping label for the settings UI, e.g. "Display". */
  group: string;
}

export interface TuiSettings {
  /** Bottom status bar with model, path, git and token counters. */
  showStatusBar: boolean;
  /** Keyboard-hint line under the composer input. */
  showComposerHints: boolean;
  /** Block "0SEC" mark on the empty transcript. */
  showLogo: boolean;
  /** Surface runtime stdout/stderr as transcript notices. */
  showRuntimeNotices: boolean;
  /** Per-turn "N tool calls - in->out tok" summary line. */
  showTurnSummary: boolean;
  /** Show the active subagent list while workers run. */
  showSubagents: boolean;
  /** Relative timestamps on transcript entries. */
  showTimestamps: boolean;
  /** Density of the transcript: "comfortable" adds blank lines. */
  density: "comfortable" | "compact";
  /** How the composer frame is drawn. */
  composerStyle: "border" | "rail" | "plain";
  /** Let sibling subagents message each other directly (child↔child channel). */
  allowSubagentPeerMessaging: boolean;
  /** Let a subagent send a message to the operator's transcript (child→operator). */
  allowSubagentOperatorMessaging: boolean;
}

/** Keys of `TuiSettings` whose value is a boolean. */
type BooleanKey = {
  [K in keyof TuiSettings]: TuiSettings[K] extends boolean ? K : never;
}[keyof TuiSettings];

/** Keys of `TuiSettings` whose value is one of a fixed set of strings. */
type EnumKey = Exclude<keyof TuiSettings, BooleanKey>;

interface BooleanSettingDef extends SettingDef<boolean> {
  key: BooleanKey;
  kind: "boolean";
  choices?: undefined;
}

interface EnumSettingDef<K extends EnumKey = EnumKey> extends SettingDef<TuiSettings[K]> {
  key: K;
  kind: "enum";
  /** Non-optional here even though `SettingDef` allows it: an enum without
   *  choices cannot be normalised or cycled, so the table may not contain one. */
  choices: readonly TuiSettings[K][];
}

type TuiSettingDef = BooleanSettingDef | EnumSettingDef<"density"> | EnumSettingDef<"composerStyle">;

/**
 * The narrowly-typed table. `SETTING_DEFS` re-exports it under the public,
 * deliberately loose `SettingDef` type; internally we keep the literal key and
 * value types so the compiler — not a test — catches a typo in a choice list.
 */
const DEFS: readonly TuiSettingDef[] = [
  {
    key: "showStatusBar",
    label: "Status bar",
    description: "Bottom bar with model, working directory, git state and token counters.",
    kind: "boolean",
    default: true,
    group: "Display",
  },
  {
    key: "showComposerHints",
    label: "Composer hints",
    description: "Keyboard-hint line under the input box.",
    kind: "boolean",
    default: true,
    group: "Display",
  },
  {
    key: "showLogo",
    label: "Logo",
    description: 'Block "0SEC" mark shown on an empty transcript.',
    kind: "boolean",
    default: true,
    group: "Display",
  },
  {
    key: "showRuntimeNotices",
    label: "Runtime notices",
    description: "Surface runtime stdout/stderr as transcript notices.",
    kind: "boolean",
    default: true,
    group: "Transcript",
  },
  {
    key: "showTurnSummary",
    label: "Turn summary",
    description: 'Per-turn "N tool calls - in->out tok" line after each answer.',
    kind: "boolean",
    default: true,
    group: "Transcript",
  },
  {
    key: "showSubagents",
    label: "Subagent list",
    description: "List the active subagents while workers are running.",
    kind: "boolean",
    default: true,
    group: "Transcript",
  },
  {
    key: "showTimestamps",
    label: "Timestamps",
    description: "Relative timestamps on transcript entries.",
    kind: "boolean",
    default: false,
    group: "Transcript",
  },
  {
    key: "density",
    label: "Density",
    description: 'Transcript spacing: "comfortable" adds blank lines between entries.',
    kind: "enum",
    default: "comfortable",
    choices: ["comfortable", "compact"],
    group: "Display",
  },
  {
    key: "composerStyle",
    label: "Composer style",
    description: "How the composer frame is drawn around the input.",
    kind: "enum",
    default: "border",
    choices: ["border", "rail", "plain"],
    group: "Display",
  },
  {
    key: "allowSubagentPeerMessaging",
    label: "Subagent peer messaging",
    description:
      "A subagent runs attacker-influenced code, so a direct sibling channel is how one compromised subagent reaches another's context.",
    kind: "boolean",
    default: true,
    group: "Security",
  },
  {
    key: "allowSubagentOperatorMessaging",
    label: "Subagent messages to you",
    description:
      "Messages arrive in your transcript sanitized and attributed, but a compromised subagent can use this channel to say things to you.",
    kind: "boolean",
    default: true,
    group: "Security",
  },
];

export const SETTING_DEFS: readonly SettingDef[] = DEFS;

const DEF_BY_KEY = new Map<string, TuiSettingDef>(DEFS.map((def) => [def.key, def]));

export const DEFAULT_SETTINGS: TuiSettings = {
  showStatusBar: true,
  showComposerHints: true,
  showLogo: true,
  showRuntimeNotices: true,
  showTurnSummary: true,
  showSubagents: true,
  showTimestamps: false,
  density: "comfortable",
  composerStyle: "border",
  allowSubagentPeerMessaging: true,
  allowSubagentOperatorMessaging: true,
};

/** Basename of the settings file inside the 0sec state directory. */
const SETTINGS_FILENAME = "tui-settings.json";

/**
 * Settings live beside the rest of the per-user engine state (scan DB,
 * journals, credentials) rather than in a TUI-specific directory, so
 * `homeStateDir` from `@0sec/shared` — not a local `".0sec"` literal — decides
 * where that is. One definition of the state root means a future relocation or
 * an `$XDG_STATE_HOME` migration happens in one place.
 */
export function settingsFilePath(homeDir?: string): string {
  return join(homeStateDir(homeDir), SETTINGS_FILENAME);
}

/** Reads `key` off a raw object, tolerating any value shape. */
function rawValue(raw: unknown, key: string): unknown {
  // Arrays and `null` are typeof "object" too; neither can carry our keys, and
  // treating them as an empty bag is exactly the "fall back to defaults"
  // behaviour we want rather than a special case.
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return undefined;
  return (raw as Record<string, unknown>)[key];
}

function booleanAt(raw: unknown, key: BooleanKey): boolean {
  const value = rawValue(raw, key);
  return typeof value === "boolean" ? value : DEFAULT_SETTINGS[key];
}

function enumAt<K extends EnumKey>(raw: unknown, key: K): TuiSettings[K] {
  const def = DEF_BY_KEY.get(key);
  const value = rawValue(raw, key);
  const choices: readonly string[] = def?.choices ?? [];
  // `includes` narrows to `string`, not to this key's literal union, so the
  // assertion carries the fact the membership check just established.
  return typeof value === "string" && choices.includes(value)
    ? (value as TuiSettings[K])
    : DEFAULT_SETTINGS[key];
}

/**
 * Total, pure coercion of anything at all into a valid `TuiSettings`.
 *
 * Building a fresh literal rather than merging over the input is what drops
 * unknown keys: a hand-edited file that grew a stale or misspelled key cannot
 * smuggle it back into memory or, via `saveSettings`, back onto disk.
 */
export function normalizeSettings(raw: unknown): TuiSettings {
  return {
    showStatusBar: booleanAt(raw, "showStatusBar"),
    showComposerHints: booleanAt(raw, "showComposerHints"),
    showLogo: booleanAt(raw, "showLogo"),
    showRuntimeNotices: booleanAt(raw, "showRuntimeNotices"),
    showTurnSummary: booleanAt(raw, "showTurnSummary"),
    showSubagents: booleanAt(raw, "showSubagents"),
    showTimestamps: booleanAt(raw, "showTimestamps"),
    density: enumAt(raw, "density"),
    composerStyle: enumAt(raw, "composerStyle"),
    allowSubagentPeerMessaging: booleanAt(raw, "allowSubagentPeerMessaging"),
    allowSubagentOperatorMessaging: booleanAt(raw, "allowSubagentOperatorMessaging"),
  };
}

/**
 * Loads settings, or the defaults. Never throws and never reports: a missing
 * file is the common case (first run), and an unreadable or malformed one is
 * still not worth interrupting a session over — the user sees default chrome
 * and can re-toggle, which rewrites the file cleanly.
 */
export function loadSettings(homeDir?: string): TuiSettings {
  try {
    const text = readFileSync(settingsFilePath(homeDir), "utf8");
    return normalizeSettings(JSON.parse(text));
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

/**
 * Persists settings, reporting success as a return value rather than an
 * exception. Callers render "could not save" in the transcript; a read-only or
 * full home directory must not take the console down with it.
 *
 * The payload is normalised on the way out and pretty-printed with a trailing
 * newline because this file is meant to be opened and edited by hand.
 */
export function saveSettings(settings: TuiSettings, homeDir?: string): boolean {
  try {
    const path = settingsFilePath(homeDir);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(normalizeSettings(settings), null, 2)}\n`, "utf8");
    return true;
  } catch {
    return false;
  }
}

/**
 * Advances one setting: booleans flip, enums step to the next choice and wrap.
 *
 * Enums cycle rather than open a picker because the settings UI binds a single
 * key (enter/space) to "change this row", and a three-value enum is faster to
 * cycle than to select. An unknown key is returned unchanged instead of
 * throwing so a stale keybinding or slash-command argument is inert.
 */
export function toggleSetting(settings: TuiSettings, key: string): TuiSettings {
  const def = DEF_BY_KEY.get(key);
  if (!def) return settings;

  if (def.kind === "boolean") {
    return { ...settings, [def.key]: !settings[def.key] };
  }

  const choices: readonly string[] = def.choices;
  // indexOf returning -1 (current value not in choices, i.e. a corrupt object
  // was passed straight in) lands on index 0 — the first choice — which is a
  // sane repair rather than an out-of-range read.
  const next = choices[(choices.indexOf(settings[def.key]) + 1) % choices.length];
  // The computed key is a union of enum keys, so TS cannot prove `next` fits
  // whichever one this is; the choice list it came from is that key's own.
  const patch = { [def.key]: next } as Partial<TuiSettings>;
  return { ...settings, ...patch };
}

/** One-line "Label: value - description" for the settings UI and `/settings`. */
export function describeSetting(settings: TuiSettings, key: string): string {
  const def = DEF_BY_KEY.get(key);
  if (!def) return "";
  const value = normalizeSettings(settings)[def.key];
  const rendered = def.kind === "boolean" ? (value ? "on" : "off") : String(value);
  return `${def.label}: ${rendered} - ${def.description}`;
}
