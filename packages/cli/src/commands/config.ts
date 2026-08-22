// `0sec config` — inspect, export, and import the console configuration.
//
// Configuration is TWO-LEVEL (see tui/settings.ts): a per-user GLOBAL file
// (`~/.0sec/tui-settings.json`) with a per-project OVERRIDE
// (`<cwd>/.0sec/tui-settings.json`) layered on top, per key, falling through to
// the built-in defaults. This command is the operator surface over that model:
//
//   show           the effective config, each key labelled default/global/project
//   export [file]  write the effective (or --global) config as shareable JSON
//   import <file>  merge a shared config into the global (default) or --project layer
//
// SECURITY: import never silently enables a security-sensitive setting. If an
// imported config would change any Security-group key (allowModelSelfExtension or
// a subagent-messaging toggle), the import is refused unless --yes is passed, and
// the specific change is printed. Unknown keys are dropped, never blindly written,
// and every value is validated via the settings sanitiser/normaliser before it
// lands on disk.

import { readFileSync, writeFileSync } from "node:fs";

import chalk from "chalk";
import type { Command } from "commander";

import {
  DEFAULT_SETTINGS,
  SETTING_DEFS,
  loadGlobalSettings,
  loadLayeredSettings,
  projectSettingsFilePath,
  readProjectOverrides,
  sanitizeOverrides,
  saveProjectOverrides,
  saveSettings,
  settingsFilePath,
  normalizeSettings,
  type SettingLayer,
  type TuiSettings,
} from "../tui/settings.js";

const EXIT_OK = 0;
const EXIT_USER_ERROR = 1;

/** The security-sensitive keys, derived from the settings table's Security group
 *  so a new gated setting is covered automatically. */
const SECURITY_KEYS: readonly (keyof TuiSettings)[] = SETTING_DEFS.filter(
  (d) => d.group === "Security",
).map((d) => d.key as keyof TuiSettings);

export interface ConfigCommandDeps {
  out?: (line: string) => void;
  err?: (line: string) => void;
  homeDir?: string;
  projectDir?: string;
}

function outOf(deps: ConfigCommandDeps): (line: string) => void {
  return deps.out ?? ((l) => console.log(l));
}
function errOf(deps: ConfigCommandDeps): (line: string) => void {
  return deps.err ?? ((l) => console.error(l));
}

function renderValue(value: unknown): string {
  return typeof value === "boolean" ? (value ? "on" : "off") : String(value);
}

// ── show ──────────────────────────────────────────────────────────────────────

export function runConfigShow(deps: ConfigCommandDeps = {}): void {
  const out = outOf(deps);
  const { settings, sources } = loadLayeredSettings({
    homeDir: deps.homeDir,
    projectDir: deps.projectDir,
  });

  out(chalk.bold("Effective console configuration"));
  out(chalk.dim(`  global:  ${settingsFilePath(deps.homeDir)}`));
  out(chalk.dim(`  project: ${projectSettingsFilePath(deps.projectDir)}`));
  out("");
  const keys = Object.keys(settings) as (keyof TuiSettings)[];
  const width = Math.max(...keys.map((k) => k.length));
  for (const key of keys) {
    const layer = sources[key];
    const tag =
      layer === "project"
        ? chalk.cyan("[project]")
        : layer === "global"
          ? chalk.green("[global]")
          : chalk.dim("[default]");
    out(`  ${key.padEnd(width)}  ${renderValue(settings[key]).padEnd(11)} ${tag}`);
  }
  process.exitCode = EXIT_OK;
}

// ── export ──────────────────────────────────────────────────────────────────

export function runConfigExport(
  file: string | undefined,
  deps: ConfigCommandDeps & { global?: boolean } = {},
): void {
  const out = outOf(deps);
  const err = errOf(deps);
  const settings = deps.global
    ? loadGlobalSettings(deps.homeDir)
    : loadLayeredSettings({ homeDir: deps.homeDir, projectDir: deps.projectDir }).settings;

  const json = `${JSON.stringify(settings, null, 2)}\n`;
  if (!file) {
    out(json.trimEnd());
    process.exitCode = EXIT_OK;
    return;
  }
  try {
    writeFileSync(file, json, "utf8");
    out(chalk.green(`Exported ${deps.global ? "global" : "effective"} config to ${file}.`));
    process.exitCode = EXIT_OK;
  } catch (e) {
    err(chalk.red(`Could not write ${file}: ${e instanceof Error ? e.message : String(e)}`));
    process.exitCode = EXIT_USER_ERROR;
  }
}

// ── import ────────────────────────────────────────────────────────────────────

/** Pull the settings bag out of an imported file: a config artifact manifest
 *  (`{ kind: "config", config: {…} }`) or a plain settings object. */
function extractConfigBag(parsed: unknown): unknown {
  if (
    typeof parsed === "object" &&
    parsed !== null &&
    !Array.isArray(parsed) &&
    (parsed as Record<string, unknown>).kind === "config" &&
    typeof (parsed as Record<string, unknown>).config === "object"
  ) {
    return (parsed as Record<string, unknown>).config;
  }
  return parsed;
}

export function runConfigImport(
  file: string,
  deps: ConfigCommandDeps & { scope?: Exclude<SettingLayer, "default">; yes?: boolean } = {},
): void {
  const out = outOf(deps);
  const err = errOf(deps);
  const scope: Exclude<SettingLayer, "default"> = deps.scope ?? "global";

  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    err(chalk.red(`Could not read ${file}: ${e instanceof Error ? e.message : String(e)}`));
    process.exitCode = EXIT_USER_ERROR;
    return;
  }

  const bag = extractConfigBag(parsed);
  // Drop unknown/invalid keys up front — never blindly overwrite. What survives
  // is a sparse, validated patch of known settings.
  const patch = sanitizeOverrides(bag);
  const patchKeys = Object.keys(patch) as (keyof TuiSettings)[];
  const skipped =
    typeof bag === "object" && bag !== null && !Array.isArray(bag)
      ? Object.keys(bag).filter((k) => !patchKeys.includes(k as keyof TuiSettings))
      : [];

  if (patchKeys.length === 0) {
    err(chalk.red(`Nothing to import: ${file} contains no recognised settings.`));
    if (skipped.length > 0) err(chalk.dim(`  Skipped unknown/invalid keys: ${skipped.join(", ")}`));
    process.exitCode = EXIT_USER_ERROR;
    return;
  }

  // Diff against the current EFFECTIVE config so the report and the security gate
  // reflect what would actually change.
  const current = loadLayeredSettings({ homeDir: deps.homeDir, projectDir: deps.projectDir }).settings;
  const changes = patchKeys.filter((k) => current[k] !== patch[k]);
  const securityChanges = changes.filter((k) => SECURITY_KEYS.includes(k));

  if (securityChanges.length > 0 && deps.yes !== true) {
    err(chalk.yellow("Refusing to import: this would change security-sensitive settings."));
    for (const k of securityChanges) {
      err(`  ${k}: ${renderValue(current[k])} -> ${renderValue(patch[k])}`);
    }
    err("  Re-run with --yes to accept these changes. Nothing was written.");
    process.exitCode = EXIT_USER_ERROR;
    return;
  }

  // Apply to the chosen layer.
  let saved: boolean;
  if (scope === "global") {
    const merged = normalizeSettings({ ...loadGlobalSettings(deps.homeDir), ...patch });
    saved = saveSettings(merged, deps.homeDir);
  } else {
    const merged = { ...readProjectOverrides(deps.projectDir), ...patch };
    saved = saveProjectOverrides(merged, deps.projectDir);
  }
  if (!saved) {
    err(chalk.red(`Could not write the ${scope} config layer.`));
    process.exitCode = EXIT_USER_ERROR;
    return;
  }

  out(chalk.green(`Imported ${changes.length} change(s) into the ${scope} config.`));
  for (const k of changes) {
    const tag = SECURITY_KEYS.includes(k) ? chalk.yellow(" (security)") : "";
    out(`  ${k}: ${renderValue(current[k])} -> ${renderValue(patch[k])}${tag}`);
  }
  if (changes.length === 0) out(chalk.dim("  (all imported values already matched the current config)"));
  if (skipped.length > 0) out(chalk.dim(`  Skipped unknown/invalid keys: ${skipped.join(", ")}`));
  process.exitCode = EXIT_OK;
}

// ── commander wiring ───────────────────────────────────────────────────────────

export function registerConfigCommand(program: Command): void {
  const config = program
    .command("config")
    .description("Inspect, export, and import the two-level console configuration");

  config
    .command("show")
    .description("Show the effective config with the source layer (default/global/project) per key")
    .action(() => {
      runConfigShow();
    });

  config
    .command("export [file]")
    .description("Write the effective (or --global) config as shareable JSON (stdout if no file)")
    .option("--global", "Export only the global layer instead of the effective config")
    .action((file: string | undefined, opts: { global?: boolean }) => {
      runConfigExport(file, { global: opts.global });
    });

  config
    .command("import <file>")
    .description("Merge a shared config into the global (default) or --project layer")
    .option("--project", "Import into the per-project override instead of the global config")
    .option("--global", "Import into the global config (default)")
    .option("--yes", "Accept changes to security-sensitive settings (required to flip them)")
    .action((file: string, opts: { project?: boolean; global?: boolean; yes?: boolean }) => {
      const scope: Exclude<SettingLayer, "default"> = opts.project ? "project" : "global";
      runConfigImport(file, { scope, yes: opts.yes === true });
    });
}
