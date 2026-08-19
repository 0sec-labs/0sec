import { readFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

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
 * No-op if a `0SEC_CHATGPT_*` token is already set (respects an explicit
 * override) or the auth file is absent/unreadable. Best-effort: any failure
 * leaves the env untouched and the engine falls back to other providers.
 */
export function maybeLoadCodexAuth(): void {
  if (
    process.env["0SEC_CHATGPT_ACCESS_TOKEN"] ||
    process.env["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"]
  ) {
    return;
  }
  const path =
    process.env["0SEC_CODEX_AUTH_JSON_PATH"] || join(homedir(), ".codex", "auth.json");
  if (!existsSync(path)) return;
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as {
      tokens?: { access_token?: string; refresh_token?: string };
    };
    const tokens = raw.tokens;
    if (!tokens?.access_token && !tokens?.refresh_token) return;
    if (tokens.access_token) {
      process.env["0SEC_CHATGPT_ACCESS_TOKEN"] = tokens.access_token;
    }
    if (tokens.refresh_token) {
      process.env["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"] = tokens.refresh_token;
    }
  } catch {
    // best-effort only — leave env untouched, engine falls back to other providers
  }
}
