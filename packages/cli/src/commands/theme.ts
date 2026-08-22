// `0sec theme` — list the console's colour themes, and the honest state of
// theme *distribution*.
//
// WHAT WORKS TODAY
// ────────────────
// `theme list` is real: it enumerates the built-in palettes shipped in
// `tui/themes.ts` (`THEMES` / `THEME_NAMES`), with their labels and one-line
// descriptions, and marks the default.
//
// WHAT DOES NOT (and why `theme install` is a stub, not a fake)
// ────────────────────────────────────────────────────────────
// The plugin system distributes TOOLS: a `PluginManifest` models an id, a
// version, and a `tools[]` array with capabilities — there is NO "theme" kind
// and no way for a manifest to carry a palette or any other config asset. So a
// theme cannot ride the herdr.dev/plugins-style install path the way a tool
// plugin can.
//
// On the console side, `ThemeName` is a CLOSED union (`"dark" | "light" |
// "high-contrast" | "ansi"`) and `THEMES` is a hardcoded table. There is a
// `validateTheme()` that could vet an operator-supplied palette, but nothing
// reads a palette off disk or a registry and registers it at runtime.
//
// Making `theme install` real therefore needs TWO changes this command is not
// allowed to make here:
//   1. extend the plugin manifest with a "theme"/config kind (or a parallel
//      theme-package descriptor) so a palette can be packaged + validated +
//      signature-checked exactly like a tool plugin, and
//   2. add a disk/registry theme-loading path in `tui/themes.ts` that turns a
//      validated palette into a selectable theme without recompiling.
// Until both exist, `install` refuses clearly rather than pretending.

import chalk from "chalk";
import type { Command } from "commander";

import {
  DEFAULT_THEME_NAME,
  THEMES,
  THEME_NAMES,
  type ThemeName,
} from "../tui/themes.js";

const EXIT_OK = 0;
const EXIT_USER_ERROR = 1;

export interface ThemeCommandDeps {
  out?: (line: string) => void;
  err?: (line: string) => void;
}

function outOf(deps: ThemeCommandDeps): (line: string) => void {
  return deps.out ?? ((l) => console.log(l));
}
function errOf(deps: ThemeCommandDeps): (line: string) => void {
  return deps.err ?? ((l) => console.error(l));
}

/** List the built-in themes with their labels and descriptions. Real. */
export function runThemeList(deps: ThemeCommandDeps = {}): void {
  const out = outOf(deps);
  out(chalk.bold("Built-in console themes"));
  for (const name of THEME_NAMES) {
    const entry = THEMES[name as ThemeName];
    const isDefault = name === DEFAULT_THEME_NAME;
    const tag = isDefault ? chalk.green("  (default)") : "";
    out(`  ${name}${tag}`);
    out(chalk.dim(`      ${entry.label} — ${entry.description}`));
  }
  out("");
  out(
    chalk.dim(
      "Select one with the console theme setting. Installing THIRD-PARTY themes " +
        "is not yet available — see `0sec theme install --help`.",
    ),
  );
  process.exitCode = EXIT_OK;
}

/**
 * Honest stub: third-party theme distribution is not available. States exactly
 * what is missing rather than faking an install.
 */
export function runThemeInstall(id: string, deps: ThemeCommandDeps = {}): void {
  const err = errOf(deps);
  const out = outOf(deps);
  err(chalk.yellow(`Installing themes is not yet available (requested "${id}").`));
  out("");
  out("Themes are NOT modeled as a plugin kind, so they cannot be installed from");
  out("the marketplace the way tool plugins are. Two things are missing:");
  out(
    "  1. the plugin manifest has no \"theme\"/config kind — a PluginManifest only",
  );
  out("     carries tool definitions, not a palette or config asset;");
  out(
    "  2. the console's themes are a closed set with no runtime disk/registry",
  );
  out("     loading path (a palette validator exists, but nothing loads one).");
  out("");
  out("Until both land, use one of the built-in themes:");
  out(`  0sec theme list`);
  process.exitCode = EXIT_USER_ERROR;
}

export function registerThemeCommand(program: Command): void {
  const theme = program
    .command("theme")
    .description("List console colour themes (third-party theme install is not yet available)");

  theme
    .command("list")
    .description("List the built-in console themes")
    .action(() => {
      runThemeList();
    });

  theme
    .command("install <id>")
    .description("Install a third-party theme (NOT YET AVAILABLE — themes are not a plugin kind)")
    .action((id: string) => {
      runThemeInstall(id);
    });
}
