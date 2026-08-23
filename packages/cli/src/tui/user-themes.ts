/**
 * Diagnostic loader for user-supplied themes.
 *
 * A user drops theme JSON files into their per-user themes directory
 * (`~/.0sec/themes/<id>.json` — the same dir `themes.ts` calls "installed
 * themes"; this module is the human-facing view over it). Each file is a
 * palette (a token->hex map under `palette`) plus optional display metadata.
 *
 * `themes.ts` already reads that directory into a resolvable cache, but it does
 * so *fail-soft and silent*: a malformed or low-contrast file is simply skipped,
 * with no way to tell the user *why* their theme did not show up. This module
 * fills that gap with a PURE loader that, given a directory, returns both the
 * valid `ThemeEntry`s AND a `rejected` list carrying a clear, specific reason
 * per bad file — so `theme list`/settings can explain "your `neon.json` was
 * rejected: ERROR on CANVAS is 2.1:1, below 4.5:1" instead of silently dropping
 * it.
 *
 * It is the single source of truth for what a valid user theme is: `themes.ts`
 * builds its resolvable cache from THIS loader's `valid` list (see
 * `readInstalledThemes`), so a theme that resolves is exactly a theme this
 * loader accepts, and one this loader rejects never becomes selectable. That is
 * how the invariant "never apply an invalid/low-contrast theme" is upheld: the
 * validation gate is here, ahead of resolution.
 *
 * Purity: the loader takes the directory as an argument and does no other I/O;
 * it consults no clock and no RNG, so the same directory contents always yield
 * the same result (valid entries are returned sorted by name). The only side
 * effect is reading the files it is pointed at, which is inherent to a loader.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import {
  installedThemesDir,
  isSafeThemeId,
  isThemeName,
  validateTheme,
  type Theme,
  type ThemeEntry,
  type ThemeMode,
} from "./themes.js";

/**
 * Absolute path to the per-user themes directory. Deliberately the SAME dir
 * `themes.ts` resolves installed themes from (`~/.0sec/themes`), so "user
 * theme" and "installed theme" are one concept, resolved from one place —
 * mirroring the per-user state-dir convention that plugins and the session
 * store use (`homeStateDir` -> `~/.0sec`).
 */
export function userThemesDir(homeDir?: string): string {
  return installedThemesDir(homeDir);
}

/** A user theme file that could not be loaded, and the reason it was rejected. */
export interface RejectedUserTheme {
  /** The theme name we tried to load (the file's basename, sans `.json`). */
  readonly name: string;
  /** The originating file name, for a precise error message. */
  readonly file: string;
  /** A human-readable, specific reason the file was not accepted. */
  readonly reason: string;
}

/** The outcome of scanning a directory of user theme files. */
export interface UserThemeLoadResult {
  /** Valid, resolvable theme entries, sorted by name for determinism. */
  readonly valid: ThemeEntry[];
  /** Every file that was a theme candidate but could not be accepted. */
  readonly rejected: RejectedUserTheme[];
}

/**
 * Build a validated `ThemeEntry` from one parsed theme file, or a rejection
 * reason. The palette must pass the FULL `validateTheme` (completeness +
 * well-formedness + text/chrome contrast + colour-blind semantic separation),
 * with NO waivers — waivers exist only for the preserved built-in default, so a
 * user theme is held to the same legibility bar as a shipped one. Fail closed:
 * any problem yields a reason, never a partial theme.
 */
function coerceUserTheme(
  id: string,
  raw: unknown,
): { ok: true; entry: ThemeEntry } | { ok: false; reason: string } {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: "file is not a JSON object" };
  }
  const record = raw as Record<string, unknown>;
  const issues = validateTheme(record.palette);
  if (issues.length > 0) {
    return { ok: false, reason: issues.map((i) => i.message).join("; ") };
  }
  const label =
    typeof record.label === "string" && record.label.length > 0 ? record.label : id;
  const description =
    typeof record.description === "string" ? record.description : "User theme.";
  const mode: ThemeMode = record.mode === "light" ? "light" : "dark";
  return {
    ok: true,
    entry: { name: id, label, description, mode, palette: record.palette as Theme },
  };
}

/**
 * Load and validate every theme file in `dir`.
 *
 * Rules, applied per `*.json` file:
 *   - The basename (sans `.json`) is the theme's resolvable name (`id`). Only
 *     `.json` files are considered; anything else is ignored, not rejected.
 *   - An id that is not a safe single path segment (lowercase dotted/hyphenated
 *     identifier, <=64 chars, no separators/traversal) is REJECTED.
 *   - An id that collides with a built-in theme name is REJECTED (a user theme
 *     never shadows a built-in; rename the file). This is the name-collision
 *     policy: reject, not namespace — so the operator sees the clash explicitly.
 *   - A file that cannot be read, is not JSON, or whose palette fails
 *     `validateTheme` (missing/extra/malformed token, sub-4.5:1 text contrast,
 *     sub-3:1 border, or a colour-blind-ambiguous semantic pair) is REJECTED
 *     with the specific reason.
 *
 * Total and pure: a missing/unreadable directory yields an empty result rather
 * than throwing, and the output depends only on the directory's contents.
 */
export function loadUserThemes(dir: string): UserThemeLoadResult {
  const valid: ThemeEntry[] = [];
  const rejected: RejectedUserTheme[] = [];

  let files: string[];
  try {
    files = readdirSync(dir);
  } catch {
    return { valid, rejected }; // no dir yet, or unreadable — no user themes
  }

  for (const file of [...files].sort()) {
    if (!file.endsWith(".json")) continue;
    const id = file.slice(0, -".json".length);

    if (!isSafeThemeId(id)) {
      rejected.push({
        name: id,
        file,
        reason:
          "invalid theme name — must be a lowercase dotted/hyphenated identifier " +
          "of at most 64 characters, with no path separators",
      });
      continue;
    }
    if (isThemeName(id)) {
      rejected.push({
        name: id,
        file,
        reason: `"${id}" is a built-in theme name and cannot be overridden — rename the file`,
      });
      continue;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(join(dir, file), "utf8"));
    } catch (err) {
      rejected.push({
        name: id,
        file,
        reason: `could not read or parse: ${err instanceof Error ? err.message : String(err)}`,
      });
      continue;
    }

    const result = coerceUserTheme(id, parsed);
    if (result.ok) valid.push(result.entry);
    else rejected.push({ name: id, file, reason: result.reason });
  }

  valid.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { valid, rejected };
}

/**
 * Convenience: load the user themes for a given home directory (defaults to the
 * real per-user dir). Thin wrapper over `loadUserThemes(userThemesDir(homeDir))`.
 */
export function loadUserThemesForHome(homeDir?: string): UserThemeLoadResult {
  return loadUserThemes(userThemesDir(homeDir));
}
