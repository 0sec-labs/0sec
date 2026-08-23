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

import {
  THEME_NAMES,
  ensureInstalledThemesLoaded,
  isKnownTheme,
  type ThemeName,
} from "./themes.js";

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
  /** Right sidebar in the chat view listing the active agents (wide terminals). */
  showAgentRail: boolean;
  /** Relative timestamps on transcript entries. */
  showTimestamps: boolean;
  /** Header "target: …" segment (chat-screen gates the header target on this). */
  showTarget: boolean;
  /** Header "scope: …" segment (chat-screen gates the header scope on this). */
  showScope: boolean;
  /** Density of the transcript: "comfortable" adds blank lines. */
  density: "comfortable" | "compact";
  /** How the composer frame is drawn. */
  composerStyle: "border" | "rail" | "plain";
  /** Let sibling subagents message each other directly (child↔child channel). */
  allowSubagentPeerMessaging: boolean;
  /** Let a subagent send a message to the operator's transcript (child→operator). */
  allowSubagentOperatorMessaging: boolean;
  /** How a conversation turn is framed. */
  transcriptStyle: "rail" | "bubble" | "plain" | "compact" | "document";
  /** How the speaker label is drawn. */
  roleLabelStyle: "full" | "short" | "glyph" | "off";
  /** How a tool/subagent call is drawn (failures always show). */
  toolCardStyle: "rail" | "inline" | "compact" | "hidden";
  /**
   * Transcript detail. "collapsed" folds each turn's successful tool calls and
   * reasoning into one-line summaries so the transcript reads as input + answer;
   * "expanded" shows every detail. Failures are never folded. Consumed by
   * chat-screen's transcript planner.
   */
  transcriptDetail: "collapsed" | "expanded";
  /**
   * Colour palette. A built-in theme name OR an installed theme id (themes.ts).
   * Typed loosely on purpose: an installed theme's id is an arbitrary safe
   * string, and `normalizeSettings` validates it with `isKnownTheme` (built-in
   * or installed) rather than the static built-in choice list, so applying an
   * installed theme survives a normalise. The `& {}` keeps built-in-name
   * autocomplete while still admitting any string.
   */
  theme: ThemeName | (string & {});
  /** Let the model add tools to its own session (off by default). */
  allowModelSelfExtension: boolean;
  /**
   * Per-turn "in→out tok" line under each answer. Consumed by chat-screen's
   * per-message footer (wired by the coordinator); this module only declares it.
   */
  showTokenUsage: boolean;
  /** Estimated dollar cost — per turn (chat-screen) and in the bottom bar. */
  showCost: boolean;
  /** Visual context-usage meter (a compact bar + percent) in the bottom bar. */
  showContextMeter: boolean;
  /**
   * Where the model name is surfaced: the bottom status bar ("statusbar"),
   * per message ("message", drawn by chat-screen), or nowhere ("off").
   */
  modelDisplay: "statusbar" | "message" | "off";
  /**
   * Intro animation style for the "0SEC" logo. One-shot reveals: "glitch" (a
   * neon-flecked scramble that resolves — the default), "matrix" (a green
   * matrix-rain cascade), "wave" (a rippling cyan wavefront), "neon" (a
   * neon-sign warm-up flicker), "strike" (a red slash strikes through the 0),
   * "draw" (letters draw in L→R behind a bright pen tip), "fade" (a centre-out
   * bloom), "typein" (per-cell reveal with a purple glow), "sweep" (a bright bar
   * wipes across). Looping idle effects: "rainbow" (a hue sweep cycling colours
   * across the mark), "shimmer" (a bright comet with a gradient tail) and
   * "pulse" (the slash breathes). "off" is static. Consumed by the masthead.
   */
  logoAnimation:
    | "glitch"
    | "rainbow"
    | "matrix"
    | "wave"
    | "neon"
    | "shimmer"
    | "pulse"
    | "strike"
    | "draw"
    | "fade"
    | "typein"
    | "sweep"
    | "off";
  /**
   * Master reduce-motion. When true the console keeps essential feedback but
   * disables decorative animations (logo intro, shimmers, sweeps).
   */
  reduceMotion: boolean;
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

type TuiSettingDef =
  | BooleanSettingDef
  | EnumSettingDef<"density">
  | EnumSettingDef<"composerStyle">
  | EnumSettingDef<"transcriptStyle">
  | EnumSettingDef<"roleLabelStyle">
  | EnumSettingDef<"toolCardStyle">
  | EnumSettingDef<"transcriptDetail">
  | EnumSettingDef<"modelDisplay">
  | EnumSettingDef<"logoAnimation">
  | EnumSettingDef<"theme">;

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
    default: false,
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
    key: "showAgentRail",
    label: "Agent rail",
    description:
      "Right sidebar in the chat view listing the active agents (task, status, turns, findings). Hidden on narrow terminals.",
    kind: "boolean",
    default: false,
    group: "Display",
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
    key: "showTarget",
    label: "Target",
    description: 'Header "target: …" segment naming the host or app under assessment.',
    kind: "boolean",
    default: true,
    group: "Display",
  },
  {
    key: "showScope",
    label: "Scope",
    description: 'Header "scope: …" segment showing the boundary the run is confined to.',
    kind: "boolean",
    default: true,
    group: "Display",
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
  {
    key: "transcriptStyle",
    label: "Transcript style",
    description: "How a conversation turn is framed: rail, bubble, plain, compact or document.",
    kind: "enum",
    default: "rail",
    choices: ["rail", "bubble", "plain", "compact", "document"],
    group: "Display",
  },
  {
    key: "roleLabelStyle",
    label: "Role label",
    description: 'How the speaker label is drawn: full ("\u258c operator"), short ("op"), glyph ("\u258c") or off.',
    kind: "enum",
    default: "full",
    choices: ["full", "short", "glyph", "off"],
    group: "Display",
  },
  {
    key: "toolCardStyle",
    label: "Tool card",
    description: "How a tool or subagent call is drawn: compact, rail, inline or hidden (failures always show).",
    kind: "enum",
    default: "compact",
    choices: ["compact", "rail", "inline", "hidden"],
    group: "Display",
  },
  {
    key: "transcriptDetail",
    label: "Transcript detail",
    description:
      "Collapsed folds each turn's successful tool calls and reasoning into one-line summaries; expanded shows every detail (failures always show).",
    kind: "enum",
    default: "collapsed",
    choices: ["collapsed", "expanded"],
    group: "Transcript",
  },
  {
    key: "theme",
    label: "Theme",
    description:
      "Colour palette. Carbon (dark, default) and Standard/Paper (light), plus Contrast, Midnight, Slate, Mono Dim and ANSI 16 for 16-colour terminals.",
    kind: "enum",
    default: "dark",
    choices: [...THEME_NAMES],
    group: "Display",
  },
  {
    key: "allowModelSelfExtension",
    label: "Model self-extension",
    description:
      "Enabling this lets the model add tools to its own session, and a prompt-injected model can therefore author tools you did not write.",
    kind: "boolean",
    default: false,
    group: "Security",
  },
  {
    key: "showTokenUsage",
    label: "Token usage",
    description: 'Per-turn "in→out tok" line under each answer.',
    kind: "boolean",
    default: false,
    group: "Telemetry",
  },
  {
    key: "showCost",
    label: "Cost",
    description: "Estimated dollar cost, per turn and in the status bar.",
    kind: "boolean",
    default: false,
    group: "Telemetry",
  },
  {
    key: "showContextMeter",
    label: "Context meter",
    description: "Visual context-usage bar in the status bar.",
    kind: "boolean",
    default: false,
    group: "Telemetry",
  },
  {
    key: "modelDisplay",
    label: "Model display",
    description: "Where the model name appears: status bar, per message, or hidden.",
    kind: "enum",
    default: "statusbar",
    choices: ["statusbar", "message", "off"],
    group: "Telemetry",
  },
  {
    key: "logoAnimation",
    label: "Logo animation",
    description:
      'Intro animation for the "0SEC" logo: glitch (a neon-flecked scramble that resolves — the default), rainbow (a looping hue sweep), matrix (a green matrix-rain cascade), wave (a rippling cyan wavefront), neon (a neon-sign warm-up flicker), shimmer (a bright comet with a gradient tail), pulse (the slash breathes), strike (a red slash strikes through the 0), draw (letters draw in behind a pen tip), fade (a centre-out bloom), typein (per-cell reveal), sweep (a bright bar wipes across) or off (static).',
    kind: "enum",
    default: "glitch",
    choices: [
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
    ],
    group: "Motion",
  },
  {
    key: "reduceMotion",
    label: "Reduce motion",
    description:
      "Master reduce-motion: the console keeps essential feedback but disables decorative animations like the logo intro, shimmers and sweeps.",
    kind: "boolean",
    default: false,
    group: "Motion",
  },
];

export const SETTING_DEFS: readonly SettingDef[] = DEFS;

const DEF_BY_KEY = new Map<string, TuiSettingDef>(DEFS.map((def) => [def.key, def]));

export const DEFAULT_SETTINGS: TuiSettings = {
  showStatusBar: true,
  showComposerHints: true,
  showLogo: true,
  showRuntimeNotices: true,
  showTurnSummary: false,
  showSubagents: true,
  showAgentRail: false,
  showTimestamps: false,
  showTarget: true,
  showScope: true,
  density: "comfortable",
  composerStyle: "border",
  allowSubagentPeerMessaging: true,
  allowSubagentOperatorMessaging: true,
  transcriptStyle: "rail",
  roleLabelStyle: "full",
  toolCardStyle: "compact",
  transcriptDetail: "collapsed",
  theme: "dark",
  allowModelSelfExtension: false,
  showTokenUsage: false,
  showCost: false,
  showContextMeter: false,
  modelDisplay: "statusbar",
  logoAnimation: "glitch",
  reduceMotion: false,
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

/**
 * Two-level configuration: a per-user GLOBAL file and a per-project OVERRIDE.
 *
 * The global file (`~/.0sec/tui-settings.json`) is the base. A project may add a
 * local `<cwd>/.0sec/tui-settings.json` whose SET keys override the global ones;
 * a key absent from the project file falls through to global, and a key absent
 * from both falls through to the built-in default. Precedence, highest first:
 *
 *     project  >  global  >  default
 *
 * The layering is resolved per KEY, not per file: a project file that sets only
 * `theme` overrides only the theme and leaves every other key to the global
 * layer. And it is total — a corrupt project file (bad JSON, wrong shape) or a
 * single out-of-range value degrades to the lower layer instead of crashing.
 */
export type SettingLayer = "default" | "global" | "project";

/** The `.0sec` directory inside a project working tree. */
export function projectStateDir(projectDir: string = process.cwd()): string {
  return join(projectDir, ".0sec");
}

/** The per-project override settings file (may not exist; that is the norm). */
export function projectSettingsFilePath(projectDir: string = process.cwd()): string {
  return join(projectStateDir(projectDir), SETTINGS_FILENAME);
}

/** Read + parse a settings file into a raw value, or `undefined`. Never throws:
 *  a missing/unreadable/malformed file is simply "no layer here". */
function readRawSettingsFile(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return undefined;
  }
}

/** True when a project override file exists and parses to an object we can layer
 *  over. Used to decide the default write target. */
export function projectSettingsExist(projectDir: string = process.cwd()): boolean {
  const raw = readRawSettingsFile(projectSettingsFilePath(projectDir));
  return typeof raw === "object" && raw !== null && !Array.isArray(raw);
}

/**
 * Strict per-key extractor: the valid value this key holds in `raw`, or
 * `undefined` when the key is absent or its value is not valid for the key. This
 * is what makes the layering per-key — a layer "has" a key only when it carries
 * a usable value for it, so an invalid project value falls through to global
 * rather than masking it.
 */
function strictValueAt<K extends keyof TuiSettings>(raw: unknown, key: K): TuiSettings[K] | undefined {
  const value = rawValue(raw, key);
  if (value === undefined) return undefined;
  if (key === "theme") {
    return typeof value === "string" && isKnownTheme(value)
      ? (value as TuiSettings[K])
      : undefined;
  }
  const def = DEF_BY_KEY.get(key);
  if (def?.kind === "boolean") {
    return typeof value === "boolean" ? (value as TuiSettings[K]) : undefined;
  }
  const choices: readonly string[] = def?.choices ?? [];
  return typeof value === "string" && choices.includes(value)
    ? (value as TuiSettings[K])
    : undefined;
}

export interface LayeredSettings {
  /** The effective, fully-populated, valid settings object. */
  settings: TuiSettings;
  /** Which layer each key's effective value came from. */
  sources: Record<keyof TuiSettings, SettingLayer>;
}

/**
 * Resolve two raw layers (already parsed) plus the built-in defaults into the
 * effective settings and per-key provenance. Pure and total.
 */
export function resolveLayeredSettings(globalRaw: unknown, projectRaw: unknown): LayeredSettings {
  const settings = {} as Record<string, unknown>;
  const sources = {} as Record<keyof TuiSettings, SettingLayer>;
  for (const key of Object.keys(DEFAULT_SETTINGS) as (keyof TuiSettings)[]) {
    const projectValue = strictValueAt(projectRaw, key);
    if (projectValue !== undefined) {
      settings[key] = projectValue;
      sources[key] = "project";
      continue;
    }
    const globalValue = strictValueAt(globalRaw, key);
    if (globalValue !== undefined) {
      settings[key] = globalValue;
      sources[key] = "global";
      continue;
    }
    settings[key] = DEFAULT_SETTINGS[key];
    sources[key] = "default";
  }
  return { settings: settings as unknown as TuiSettings, sources };
}

/**
 * Load the effective settings AND their provenance, merging the project override
 * over the global file over the defaults. Ensures installed themes are loaded
 * first so an installed theme id in either layer validates rather than resetting.
 */
export function loadLayeredSettings(opts: { homeDir?: string; projectDir?: string } = {}): LayeredSettings {
  ensureInstalledThemesLoaded(opts.homeDir);
  const globalRaw = readRawSettingsFile(settingsFilePath(opts.homeDir));
  const projectRaw = readRawSettingsFile(projectSettingsFilePath(opts.projectDir));
  return resolveLayeredSettings(globalRaw, projectRaw);
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
 * The `theme` key is validated against `isKnownTheme` (a built-in name OR a
 * currently-loaded installed theme id) rather than the static built-in choice
 * list, so a `theme apply`/`config import` of an installed theme is not reset to
 * the default on the next normalise. `isKnownTheme` performs no I/O — it reads
 * the installed-theme cache, which the load path populates before it normalises
 * — so this stays pure and total.
 */
function themeAt(raw: unknown): TuiSettings["theme"] {
  const value = rawValue(raw, "theme");
  return typeof value === "string" && isKnownTheme(value) ? value : DEFAULT_SETTINGS.theme;
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
    showAgentRail: booleanAt(raw, "showAgentRail"),
    showTimestamps: booleanAt(raw, "showTimestamps"),
    showTarget: booleanAt(raw, "showTarget"),
    showScope: booleanAt(raw, "showScope"),
    density: enumAt(raw, "density"),
    composerStyle: enumAt(raw, "composerStyle"),
    allowSubagentPeerMessaging: booleanAt(raw, "allowSubagentPeerMessaging"),
    allowSubagentOperatorMessaging: booleanAt(raw, "allowSubagentOperatorMessaging"),
    transcriptStyle: enumAt(raw, "transcriptStyle"),
    roleLabelStyle: enumAt(raw, "roleLabelStyle"),
    toolCardStyle: enumAt(raw, "toolCardStyle"),
    transcriptDetail: enumAt(raw, "transcriptDetail"),
    theme: themeAt(raw),
    allowModelSelfExtension: booleanAt(raw, "allowModelSelfExtension"),
    showTokenUsage: booleanAt(raw, "showTokenUsage"),
    showCost: booleanAt(raw, "showCost"),
    showContextMeter: booleanAt(raw, "showContextMeter"),
    modelDisplay: enumAt(raw, "modelDisplay"),
    logoAnimation: enumAt(raw, "logoAnimation"),
    reduceMotion: booleanAt(raw, "reduceMotion"),
  };
}

/**
 * Loads settings, or the defaults. Never throws and never reports: a missing
 * file is the common case (first run), and an unreadable or malformed one is
 * still not worth interrupting a session over — the user sees default chrome
 * and can re-toggle, which rewrites the file cleanly.
 */
export function loadSettings(homeDir?: string, projectDir?: string): TuiSettings {
  return loadLayeredSettings({ homeDir, projectDir }).settings;
}

/**
 * The GLOBAL layer alone, as a complete normalised object (ignoring any project
 * override). Used by `config import --global`, which merges into the global file
 * rather than the effective view. Ensures installed themes are loaded so a global
 * theme id validates rather than resetting.
 */
export function loadGlobalSettings(homeDir?: string): TuiSettings {
  ensureInstalledThemesLoaded(homeDir);
  return normalizeSettings(readRawSettingsFile(settingsFilePath(homeDir)));
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

/* --------------------------------------------------- project override writes */

/**
 * Keep only known keys that carry a valid value for their key, dropping unknown
 * or malformed entries — the same "build a clean literal" discipline
 * `normalizeSettings` uses, but SPARSE: keys not present stay absent so they keep
 * falling through to the global layer. This is what a project override file is
 * allowed to contain.
 */
export function sanitizeOverrides(raw: unknown): Partial<TuiSettings> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(DEFAULT_SETTINGS) as (keyof TuiSettings)[]) {
    const value = strictValueAt(raw, key);
    if (value !== undefined) out[key] = value;
  }
  return out as Partial<TuiSettings>;
}

/** Read the current project override file as a sanitised sparse patch. */
export function readProjectOverrides(projectDir?: string): Partial<TuiSettings> {
  return sanitizeOverrides(readRawSettingsFile(projectSettingsFilePath(projectDir)));
}

/**
 * Write a sparse project override file. The patch is sanitised on the way out so
 * a project file can never carry an unknown or invalid key. Reports success as a
 * return value; never throws on an I/O failure.
 */
export function saveProjectOverrides(patch: Partial<TuiSettings>, projectDir?: string): boolean {
  try {
    const path = projectSettingsFilePath(projectDir);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(sanitizeOverrides(patch), null, 2)}\n`, "utf8");
    return true;
  } catch {
    return false;
  }
}

/**
 * Merge one key into the project override file, preserving the other overrides.
 * The value is validated (via the sanitiser) before it lands, so an out-of-range
 * value is simply not written. Reports success as a return value.
 */
export function setProjectOverride<K extends keyof TuiSettings>(
  key: K,
  value: TuiSettings[K],
  projectDir?: string,
): boolean {
  const current = readProjectOverrides(projectDir);
  return saveProjectOverrides({ ...current, [key]: value }, projectDir);
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
