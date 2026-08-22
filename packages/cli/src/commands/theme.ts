// `0sec theme` — list, install, apply, export, and remove console colour themes.
//
// Themes are shareable ARTIFACTS, not code. A theme is a colour palette (a token
// → #RRGGBB map) plus display metadata. It rides the same registry the plugin
// system uses, but as pure DATA: an entry with `kind: "theme"` in the index is
// validated, its palette is checked against the FULL WCAG `validateTheme`, and
// its bytes are written to `~/.0sec/themes/<id>.json`. Nothing is ever executed
// — a theme has no `source` files, no tools, no capabilities, and can never
// reach the tool loader or a capability gate.
//
//   list     built-in + installed themes, marking the active + default one
//   install  fetch a theme from the configured registry, validate, write to disk
//   apply    persist it as the console theme (survives normalise as an installed id)
//   export   emit a built-in or installed theme as a shareable theme manifest JSON
//   remove   delete an installed theme file
//
// No marketplace ships: the registry URL is empty by default (same discipline as
// the plugin registry). `install` is a clear no-op until an operator points
// --registry (or $0SEC_REGISTRY_URL) at a URL they trust.
//
// DEPENDENCY NOTE (mirrors commands/plugin.ts): the core registry client is
// consumed through an injected port whose shapes are declared LOCALLY, so this
// command type-checks against @0sec/core's published surface without depending on
// in-flight core d.ts changes, and unit tests inject a fake port (no network).

import { writeFileSync } from "node:fs";

import chalk from "chalk";
import type { Command } from "commander";

import {
  DEFAULT_THEME_NAME,
  THEMES,
  THEME_NAMES,
  installedThemeEntries,
  installedThemesDir,
  isKnownTheme,
  isSafeThemeId,
  reloadInstalledThemes,
  removeInstalledTheme,
  validateTheme,
  writeInstalledTheme,
  type ThemeEntry,
  type ThemeMode,
} from "../tui/themes.js";
import { loadSettings } from "../tui/settings.js";
import { configureSettingsStore, updateSetting } from "../tui/settings-store.js";

const EXIT_OK = 0;
const EXIT_USER_ERROR = 1;

// ── Local structural views of the core registry shapes ────────────────────────

interface ThemeArtifactManifestView {
  kind: "theme";
  id: string;
  name: string;
  version: string;
  minCoreVersion?: string;
  theme: {
    label?: string;
    description?: string;
    mode?: ThemeMode;
    palette: Record<string, string>;
  };
}
interface InstallableThemeArtifactView {
  kind: "theme";
  id: string;
  version: string;
  manifest: ThemeArtifactManifestView;
  signature?: string;
  signatureState: "verified" | "unverified";
}
interface RegistryResultView {
  entries: unknown[];
  artifacts: { kind: string; id: string }[];
  dropped: { id?: string; reason: string }[];
}
type FetchRegistryResultView =
  | { ok: true; result: RegistryResultView }
  | { ok: false; error: string };
interface SignatureVerifierView {
  readonly keyConfigured: boolean;
  verify(canonicalPayload: string, signature: string): boolean;
}

/** Everything this command needs from @0sec/core. Injected; the default lazily
 *  imports the real barrel and casts through this view. */
export interface ThemeCorePort {
  fetchRegistryIndex(
    url: string,
    opts: { fetchImpl: typeof fetch; verifier?: SignatureVerifierView; reservedToolNames?: readonly string[] },
  ): Promise<FetchRegistryResultView>;
  unconfiguredVerifier: SignatureVerifierView;
  readonly DEFAULT_REGISTRY_URL: string;
}

let cachedCore: ThemeCorePort | undefined;
async function defaultThemeCorePort(): Promise<ThemeCorePort> {
  if (cachedCore) return cachedCore;
  const mod = (await import("@0sec/core")) as unknown as ThemeCorePort;
  cachedCore = mod;
  return mod;
}

// ── Deps ──────────────────────────────────────────────────────────────────────

export interface ThemeCommandDeps {
  out?: (line: string) => void;
  err?: (line: string) => void;
  homeDir?: string;
  projectDir?: string;
  /** Registry index URL (https). Defaults to $0SEC_REGISTRY_URL then the (empty)
   *  core default, so no endpoint ships. */
  registryUrl?: string;
  /** Injected fetch; NEVER the real one in tests. */
  fetchImpl?: typeof fetch;
  verifier?: SignatureVerifierView;
  /** Injected core port; defaults to the lazy real barrel. */
  core?: ThemeCorePort;
  /** Which config layer `apply` persists to; defaults to the store's rule. */
  scope?: "global" | "project";
}

function outOf(deps: ThemeCommandDeps): (line: string) => void {
  return deps.out ?? ((l) => console.log(l));
}
function errOf(deps: ThemeCommandDeps): (line: string) => void {
  return deps.err ?? ((l) => console.error(l));
}
function registryUrlOf(deps: ThemeCommandDeps, core: ThemeCorePort): string {
  return (deps.registryUrl ?? process.env["0SEC_REGISTRY_URL"] ?? core.DEFAULT_REGISTRY_URL ?? "").trim();
}

// ── list ────────────────────────────────────────────────────────────────────

/** List built-in + installed themes, marking the active + default. */
export function runThemeList(deps: ThemeCommandDeps = {}): void {
  const out = outOf(deps);
  reloadInstalledThemes(deps.homeDir);
  const active = loadSettings(deps.homeDir, deps.projectDir).theme;

  const mark = (name: string): string => {
    const tags: string[] = [];
    if (name === active) tags.push(chalk.cyan("active"));
    if (name === DEFAULT_THEME_NAME) tags.push(chalk.green("default"));
    return tags.length > 0 ? `  (${tags.join(", ")})` : "";
  };
  const line = (entry: ThemeEntry): void => {
    out(`  ${entry.name}${mark(entry.name)}`);
    out(chalk.dim(`      ${entry.label} — ${entry.description}`));
  };

  out(chalk.bold("Built-in console themes"));
  for (const name of THEME_NAMES) line(THEMES[name]);

  const installed = installedThemeEntries(deps.homeDir);
  out("");
  if (installed.length === 0) {
    out(chalk.dim(`Installed themes: none (${installedThemesDir(deps.homeDir)})`));
  } else {
    out(chalk.bold(`Installed themes (${installedThemesDir(deps.homeDir)})`));
    for (const entry of installed) line(entry);
  }
  out("");
  out(chalk.dim("Apply one with `0sec theme apply <id>`; install more with `0sec theme install <id>`."));
  process.exitCode = EXIT_OK;
}

// ── install ───────────────────────────────────────────────────────────────────

export async function runThemeInstall(id: string, deps: ThemeCommandDeps = {}): Promise<void> {
  const out = outOf(deps);
  const err = errOf(deps);
  const core = deps.core ?? (await defaultThemeCorePort());

  if (!isSafeThemeId(id)) {
    err(chalk.red(`"${id}" is not a valid theme id; refused before any filesystem access.`));
    process.exitCode = EXIT_USER_ERROR;
    return;
  }
  const registryUrl = registryUrlOf(deps, core);
  if (registryUrl.length === 0) {
    err(chalk.red("No registry is configured, so nothing can be installed."));
    err("  Point --registry (or $0SEC_REGISTRY_URL) at a theme registry index URL you trust.");
    err(chalk.dim("  (No registry endpoint ships by default — DEFAULT_REGISTRY_URL is empty.)"));
    process.exitCode = EXIT_USER_ERROR;
    return;
  }

  const fetched = await core.fetchRegistryIndex(registryUrl, {
    fetchImpl: deps.fetchImpl ?? fetch,
    verifier: deps.verifier ?? core.unconfiguredVerifier,
  });
  if (!fetched.ok) {
    err(chalk.red(`Registry error: ${fetched.error}`));
    process.exitCode = EXIT_USER_ERROR;
    return;
  }

  const artifact = fetched.result.artifacts.find(
    (a): a is InstallableThemeArtifactView => a.kind === "theme" && a.id === id,
  );
  if (!artifact) {
    err(chalk.red(`Theme "${id}" is not available in the configured registry.`));
    process.exitCode = EXIT_USER_ERROR;
    return;
  }

  // Fail closed on an invalid palette — the registry validated the SHAPE; the
  // legibility bar (completeness + WCAG contrast) is enforced here at install.
  const palette = artifact.manifest.theme.palette;
  const issues = validateTheme(palette);
  if (issues.length > 0) {
    err(chalk.red(`Theme "${id}" has an invalid palette; refusing to install:`));
    for (const issue of issues) err(chalk.dim(`  - ${issue.message}`));
    process.exitCode = EXIT_USER_ERROR;
    return;
  }

  const written = writeInstalledTheme(
    {
      id,
      label: artifact.manifest.theme.label,
      description: artifact.manifest.theme.description,
      mode: artifact.manifest.theme.mode,
      palette: palette as ThemeEntry["palette"],
    },
    deps.homeDir,
  );
  if (!written.ok) {
    err(chalk.red(`Could not install "${id}": ${written.error}`));
    process.exitCode = EXIT_USER_ERROR;
    return;
  }
  reloadInstalledThemes(deps.homeDir);

  out(chalk.green(`Installed theme ${id}@${artifact.version}.`));
  out(`  Written to: ${written.path}`);
  out(`  Signature: ${artifact.signatureState}`);
  out(chalk.dim("  No code ran — a theme is data (a palette), never an executable plugin."));
  out(`  Apply it with:`);
  out(chalk.cyan(`    0sec theme apply ${id}`));
  process.exitCode = EXIT_OK;
}

// ── apply ───────────────────────────────────────────────────────────────────

export function runThemeApply(id: string, deps: ThemeCommandDeps = {}): void {
  const out = outOf(deps);
  const err = errOf(deps);

  // Point the store at the requested dirs and make installed themes resolvable
  // so `isKnownTheme(id)` — which the save path's normalise consults — is true.
  configureSettingsStore({ homeDir: deps.homeDir, projectDir: deps.projectDir });
  reloadInstalledThemes(deps.homeDir);

  if (!isKnownTheme(id)) {
    err(chalk.red(`"${id}" is not a known theme (neither a built-in nor an installed id).`));
    err("  See `0sec theme list`, or install it with `0sec theme install <id>`.");
    process.exitCode = EXIT_USER_ERROR;
    return;
  }

  const saved = updateSetting("theme", id, deps.scope ? { scope: deps.scope } : {});
  if (!saved) {
    err(chalk.yellow(`Applied "${id}" for this session, but could not persist it to disk.`));
    process.exitCode = EXIT_USER_ERROR;
    return;
  }
  out(chalk.green(`Theme set to "${id}".`));
  process.exitCode = EXIT_OK;
}

// ── export ────────────────────────────────────────────────────────────────────

/** Build a shareable theme manifest for a built-in or installed theme. */
export function themeManifestFor(id: string, homeDir?: string): ThemeArtifactManifestView | null {
  reloadInstalledThemes(homeDir);
  if (!isKnownTheme(id)) return null;
  // getThemeEntry resolves both built-ins and installed ids.
  const entry =
    THEME_NAMES.includes(id as (typeof THEME_NAMES)[number])
      ? THEMES[id as (typeof THEME_NAMES)[number]]
      : installedThemeEntries(homeDir).find((e) => e.name === id);
  if (!entry) return null;
  return {
    kind: "theme",
    id,
    name: entry.label,
    version: "1.0.0",
    theme: {
      label: entry.label,
      description: entry.description,
      mode: entry.mode,
      palette: { ...entry.palette },
    },
  };
}

export function runThemeExport(id: string, file: string | undefined, deps: ThemeCommandDeps = {}): void {
  const out = outOf(deps);
  const err = errOf(deps);
  const manifest = themeManifestFor(id, deps.homeDir);
  if (!manifest) {
    err(chalk.red(`"${id}" is not a known theme.`));
    process.exitCode = EXIT_USER_ERROR;
    return;
  }
  const json = `${JSON.stringify(manifest, null, 2)}\n`;
  if (!file) {
    out(json.trimEnd());
    process.exitCode = EXIT_OK;
    return;
  }
  try {
    writeFileSync(file, json, "utf8");
    out(chalk.green(`Exported theme "${id}" to ${file}.`));
    process.exitCode = EXIT_OK;
  } catch (e) {
    err(chalk.red(`Could not write ${file}: ${e instanceof Error ? e.message : String(e)}`));
    process.exitCode = EXIT_USER_ERROR;
  }
}

// ── remove ────────────────────────────────────────────────────────────────────

export function runThemeRemove(id: string, deps: ThemeCommandDeps = {}): void {
  const out = outOf(deps);
  const err = errOf(deps);
  reloadInstalledThemes(deps.homeDir);
  const result = removeInstalledTheme(id, deps.homeDir);
  if (!result.ok) {
    err(chalk.red(`Could not remove "${id}": ${result.error}`));
    process.exitCode = EXIT_USER_ERROR;
    return;
  }
  reloadInstalledThemes(deps.homeDir);
  out(chalk.green(`Removed installed theme "${id}".`));
  out(chalk.dim("  If it was the active theme, the console falls back to the default until you apply another."));
  process.exitCode = EXIT_OK;
}

// ── commander wiring ───────────────────────────────────────────────────────────

export function registerThemeCommand(program: Command): void {
  const theme = program
    .command("theme")
    .description("List, install, apply, export, and remove console colour themes");

  theme
    .command("list")
    .description("List built-in and installed themes (marks the active + default)")
    .action(() => {
      runThemeList();
    });

  theme
    .command("install <id>")
    .description("Fetch + validate + write a theme from the configured registry (installs data; runs no code)")
    .option("--registry <url>", "Theme registry index URL (https)")
    .action(async (id: string, opts: { registry?: string }) => {
      await runThemeInstall(id, { registryUrl: opts.registry });
    });

  theme
    .command("apply <id>")
    .description("Set the console theme (a built-in name or an installed id)")
    .option("--project", "Write the choice to the per-project override instead of the global config")
    .option("--global", "Write the choice to the global config")
    .action((id: string, opts: { project?: boolean; global?: boolean }) => {
      const scope = opts.project ? "project" : opts.global ? "global" : undefined;
      runThemeApply(id, scope ? { scope } : {});
    });

  theme
    .command("export <id> [file]")
    .description("Emit a built-in or installed theme as a shareable theme manifest JSON (stdout if no file)")
    .action((id: string, file: string | undefined) => {
      runThemeExport(id, file);
    });

  theme
    .command("remove <id>")
    .description("Delete an installed theme (built-ins cannot be removed)")
    .action((id: string) => {
      runThemeRemove(id);
    });
}
