/**
 * Run-scoped `CODEX_HOME` for agent runs whose working directory is code we
 * just downloaded.
 *
 * ## The problem
 *
 * The package-audit pipeline installs an arbitrary third-party package into
 * `$TMPDIR/pwnkit-audit-<uuid>` (`package-ecosystems.ts`) and then runs the
 * analysis agent with `cwd` set to `<tempDir>/node_modules/<pkg>`
 * (`agent-runner.ts` → `runtime/process.ts`, which spawns `codex exec`). The
 * Codex CLI records a trust decision for whatever directory it runs in, into
 * the operator's own `~/.codex/config.toml`:
 *
 *     [projects."/private/var/folders/…/pwnkit-audit-8103b3c8/node_modules/lodash"]
 *     trust_level = "trusted"
 *
 * Sixteen such entries were found on the dev host — one per audited package.
 *
 * Trust is not cosmetic. It gates project-local `.codex/config.toml`, hooks,
 * exec policies and MCP server definitions. A hostile package that ships
 * `node_modules/<pkg>/.codex/config.toml` with a hook gets execution, and the
 * host runs `sandbox_mode = "danger-full-access"`, so there is no OS sandbox
 * underneath. Codex's AGENTS.md discovery walks project-root→cwd, which is
 * normally why a buried AGENTS.md never loads — but this pipeline puts cwd
 * *inside* the dependency tree, which is exactly the case that does load.
 *
 * ## The fix
 *
 * Give that subprocess its own throwaway `CODEX_HOME`, seeded with the
 * operator's provider configuration but no trust entries, and delete it when
 * the run ends. Any trust decision, project-local config or hook the run picks
 * up dies with the directory.
 *
 * ## What crosses the boundary
 *
 * IN: `config.toml` with every `[projects.…]` section stripped, and
 * `auth.json` verbatim (the run has to be able to authenticate).
 *
 * OUT: `auth.json` ONLY, and only when it changed and still parses as
 * credentials. Codex rotates the OAuth refresh token on use and invalidates
 * the old one, so discarding a rotated token would silently break the
 * operator's interactive login. Nothing else comes back — not trust, not
 * config, not hooks, not history. Copy-back is not a new exposure: a run that
 * reached code execution under `danger-full-access` could already write the
 * real `~/.codex/auth.json` directly.
 *
 * Note this covers the `codex` SUBPROCESS only. `llm-api.ts` resolves its own
 * credentials from `homedir()` (`readChatGptCodexAuthFile`) and `$HOME`
 * (`parseCodexAzureConfig`), never from `CODEX_HOME`, so setting it here
 * cannot break the in-process API path — and those readers never write, so
 * they are not a persistence vector.
 */

import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, sep } from "node:path";

/** The Codex home the operator's own CLI uses. */
function operatorCodexHome(): string {
  const fromEnv = process.env.CODEX_HOME;
  return fromEnv && fromEnv.trim().length > 0 ? fromEnv.trim() : join(homedir(), ".codex");
}

/**
 * Drop every `[projects.…]` / `[projects]` section from a Codex config.
 *
 * Line-based rather than a TOML parse: we need to preserve the rest of the
 * file byte-for-byte (comments, ordering, plugin and MCP blocks the operator
 * relies on) and only remove whole sections. A `projects = { … }` inline
 * top-level key would not be caught, but Codex does not write one.
 */
export function stripProjectTrust(toml: string): string {
  const kept: string[] = [];
  let dropping = false;
  for (const line of toml.split("\n")) {
    if (/^\s*\[/.test(line)) {
      // `[projects]` and `[projects."…"]`, but not `[projects_extra]`.
      dropping = /^\s*\[\[?\s*projects\s*[\].]/.test(line);
      if (dropping) continue;
    }
    if (!dropping) kept.push(line);
  }
  return kept.join("\n");
}

/**
 * Whether `scopePath` is inside the OS temp directory — i.e. a tree this
 * process downloaded rather than the operator's own checkout.
 *
 * Real-paths both sides: on macOS `tmpdir()` is `/var/folders/…`, a symlink
 * into `/private/var/folders/…`, and the two spellings never compare equal.
 * Fails closed (returns false) when either path cannot be resolved.
 */
export function isEphemeralScope(scopePath: string): boolean {
  try {
    const temp = realpathSync(tmpdir());
    const scope = realpathSync(scopePath);
    return scope === temp || scope.startsWith(temp.endsWith(sep) ? temp : temp + sep);
  } catch {
    return false;
  }
}

export interface EphemeralCodexHome {
  /** Value to pass as `CODEX_HOME` to the subprocess. */
  path: string;
  /** Sync back the credential (if rotated) and delete the directory. Never throws. */
  dispose(): void;
}

/** Whether `raw` still looks like a Codex credential file worth keeping. */
function looksLikeCodexAuth(raw: string): boolean {
  try {
    const parsed = JSON.parse(raw) as {
      OPENAI_API_KEY?: unknown;
      tokens?: { access_token?: unknown; refresh_token?: unknown };
    };
    const apiKey = typeof parsed.OPENAI_API_KEY === "string" && parsed.OPENAI_API_KEY.length > 0;
    const access = typeof parsed.tokens?.access_token === "string" && parsed.tokens.access_token.length > 0;
    const refresh = typeof parsed.tokens?.refresh_token === "string" && parsed.tokens.refresh_token.length > 0;
    return apiKey || access || refresh;
  } catch {
    return false;
  }
}

/**
 * Create a throwaway `CODEX_HOME` seeded from the operator's.
 *
 * Returns undefined if the directory cannot be created — callers then run
 * exactly as before rather than failing the scan over a hardening measure.
 */
export function createEphemeralCodexHome(): EphemeralCodexHome | undefined {
  const source = operatorCodexHome();
  let dir: string;
  try {
    dir = mkdtempSync(join(tmpdir(), "pwnkit-codex-home-"));
  } catch {
    return undefined;
  }

  try {
    const sourceConfig = join(source, "config.toml");
    if (existsSync(sourceConfig)) {
      writeFileSync(
        join(dir, "config.toml"),
        stripProjectTrust(readFileSync(sourceConfig, "utf8")),
        { mode: 0o600 },
      );
    }

    const sourceAuth = join(source, "auth.json");
    let seededAuth: string | undefined;
    if (existsSync(sourceAuth)) {
      seededAuth = readFileSync(sourceAuth, "utf8");
      writeFileSync(join(dir, "auth.json"), seededAuth, { mode: 0o600 });
    }

    return {
      path: dir,
      dispose: () => disposeEphemeralCodexHome(dir, sourceAuth, seededAuth),
    };
  } catch {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
    return undefined;
  }
}

function disposeEphemeralCodexHome(
  dir: string,
  sourceAuth: string,
  seededAuth: string | undefined,
): void {
  // Credential sync-back — see the module header for why this one file, and
  // only this one file, travels back out.
  try {
    const scopedAuth = join(dir, "auth.json");
    if (seededAuth !== undefined && existsSync(scopedAuth)) {
      const current = readFileSync(scopedAuth, "utf8");
      if (current !== seededAuth && looksLikeCodexAuth(current)) {
        writeFileSync(sourceAuth, current, { mode: 0o600 });
      }
    }
  } catch {
    /* best-effort: a failed sync-back must never fail the scan */
  }

  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
}
