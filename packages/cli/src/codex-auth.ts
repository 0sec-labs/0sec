import { readFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** Injection seams so the loader is testable without mutating the real env/home. */
export interface CodexAuthOptions {
  /** Environment to read AND write. Defaults to the live `process.env`. */
  env?: Record<string, string | undefined>;
  /** Home directory used for the default `~/.codex/auth.json` path. */
  home?: string;
}

/**
 * Canonical override for the codex auth-file path. This is the variable the
 * engine reads (`packages/core/src/runtime/llm-api.ts` readChatGptCodexAuthFile)
 * and the one documented in docs/api-keys.md and the `/providers` hint, so the
 * CLI loader has to agree with it — otherwise an operator who sets the
 * documented variable is silently ignored on this path.
 */
const AUTH_FILE_ENV = "0SEC_CHATGPT_AUTH_FILE";

/**
 * @deprecated CLI-only legacy spelling that never matched the runtime. Still
 * honoured as a fallback so anyone currently relying on it keeps working;
 * `0SEC_CHATGPT_AUTH_FILE` wins when both are set. Remove once the deprecation
 * window closes.
 */
const LEGACY_AUTH_FILE_ENV = "0SEC_CODEX_AUTH_JSON_PATH";

/**
 * Local-dev convenience: when no ChatGPT-Codex token is in the env but the
 * user has run `codex login` (so `~/.codex/auth.json` exists), plumb its
 * tokens into `0SEC_CHATGPT_*` — the same wiring the cloud
 * worker-controller does for sandbox runs.
 *
 * The engine's provider priority (`llm-api.ts` detectProvider) ranks
 * `chatgpt-codex` HIGHEST, above `AZURE_OPENAI_API_KEY` / `OPENAI_API_KEY`.
 * So loading the codex token here means a logged-in `codex` session wins over
 * stale Azure/OpenAI keys left in a dev shell — `0sec review` "just works"
 * on the subscription backend instead of silently falling through to a dead
 * Azure endpoint.
 *
 * Path precedence: `0SEC_CHATGPT_AUTH_FILE` (canonical, matches the runtime)
 * ?? `0SEC_CODEX_AUTH_JSON_PATH` (deprecated) ?? `~/.codex/auth.json`.
 *
 * No-op if a `0SEC_CHATGPT_*` token is already set (respects an explicit
 * override) or the auth file is absent/unreadable. Best-effort: any failure
 * leaves the env untouched and the engine falls back to other providers.
 */
export function maybeLoadCodexAuth(options: CodexAuthOptions = {}): void {
  const env = options.env ?? process.env;
  if (
    env["0SEC_CHATGPT_ACCESS_TOKEN"] ||
    env["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"]
  ) {
    return;
  }
  const home = options.home ?? homedir();
  // An exported-but-empty override is not a path: fall through to the next
  // candidate rather than stat'ing "" and giving up on the default.
  const override = nonEmpty(env[AUTH_FILE_ENV]) ?? nonEmpty(env[LEGACY_AUTH_FILE_ENV]);
  const path = override ?? join(home, ".codex", "auth.json");
  if (!existsSync(path)) return;
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as {
      tokens?: { access_token?: unknown; refresh_token?: unknown };
    };
    // A hand-edited auth.json can carry a null/number/object where a token
    // string belongs; narrow rather than trusting the cast, so a junk value
    // never lands in the env as "null" and gets sent as a bearer.
    const accessToken = nonEmpty(asString(raw.tokens?.access_token));
    const refreshToken = nonEmpty(asString(raw.tokens?.refresh_token));
    if (!accessToken && !refreshToken) return;
    if (accessToken) {
      env["0SEC_CHATGPT_ACCESS_TOKEN"] = accessToken;
    }
    if (refreshToken) {
      env["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"] = refreshToken;
    }
  } catch {
    // best-effort only — leave env untouched, engine falls back to other providers
  }
}

function nonEmpty(value: string | undefined): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}
