import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  getChatGptCodexAccessToken,
  __resetChatGptCodexAuthStateForTests,
} from "./llm-api.js";

/**
 * Regression: OpenAI rotates the Codex refresh_token on every refresh. If the
 * rotated token is not written back to ~/.codex/auth.json, the NEXT process
 * replays the now-spent token and 401s with "refresh token has already been
 * used". These tests pin the write-back behaviour.
 */
describe("Codex refresh-token rotation write-back", () => {
  let dir: string;
  let authPath: string;

  const CODEX_ENV = [
    "0SEC_CHATGPT_ACCESS_TOKEN",
    "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN",
    "0SEC_CHATGPT_ACCOUNT_ID",
    "0SEC_CHATGPT_AUTH_FILE",
  ];

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "0sec-codex-auth-"));
    authPath = join(dir, "auth.json");
    for (const k of CODEX_ENV) delete process.env[k];
    __resetChatGptCodexAuthStateForTests();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    for (const k of CODEX_ENV) delete process.env[k];
    __resetChatGptCodexAuthStateForTests();
    rmSync(dir, { recursive: true, force: true });
  });

  const mockRefresh = (refreshToken = "new-refresh") =>
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (String(url).includes("oauth/token")) {
          return {
            ok: true,
            json: async () => ({
              access_token: "new-access",
              refresh_token: refreshToken,
              expires_in: 3600,
            }),
          } as unknown as Response;
        }
        throw new Error(`unexpected fetch: ${url}`);
      }),
    );

  it("writes the rotated refresh token back to auth.json, preserving other fields", async () => {
    writeFileSync(
      authPath,
      JSON.stringify({
        OPENAI_API_KEY: null,
        tokens: { refresh_token: "old-refresh", account_id: "acct-123" },
      }),
    );
    process.env["0SEC_CHATGPT_AUTH_FILE"] = authPath;
    mockRefresh("rotated-refresh-1");

    const out = await getChatGptCodexAccessToken();
    expect(out.accessToken).toBe("new-access");

    const persisted = JSON.parse(readFileSync(authPath, "utf8"));
    expect(persisted.tokens.refresh_token).toBe("rotated-refresh-1"); // rotated, not old
    expect(persisted.tokens.access_token).toBe("new-access");
    expect(persisted.tokens.account_id).toBe("acct-123"); // preserved
    expect(persisted.OPENAI_API_KEY).toBeNull(); // unrelated field preserved
    expect(typeof persisted.last_refresh).toBe("string");
  });

  it("a subsequent refresh uses the rotated token (no replay of the spent one)", async () => {
    writeFileSync(
      authPath,
      JSON.stringify({ tokens: { refresh_token: "old-refresh" } }),
    );
    process.env["0SEC_CHATGPT_AUTH_FILE"] = authPath;

    const seen: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, opts: { body?: string }) => {
        if (String(url).includes("oauth/token")) {
          const params = new URLSearchParams(opts?.body ?? "");
          seen.push(params.get("refresh_token") ?? "");
          const n = seen.length;
          return {
            ok: true,
            json: async () => ({
              access_token: "acc",
              refresh_token: `rotated-${n}`,
              expires_in: -1, // already expired → forces the next call to refresh again
            }),
          } as unknown as Response;
        }
        throw new Error("unexpected");
      }),
    );

    await getChatGptCodexAccessToken();
    await getChatGptCodexAccessToken();
    // First refresh used the on-disk token; the second used the ROTATED one.
    expect(seen[0]).toBe("old-refresh");
    expect(seen[1]).toBe("rotated-1");
  });

  it("does NOT write a file on the env-forwarded path (no authFilePath)", async () => {
    // Env-forwarded refresh token (worker-controller/cloud path).
    process.env["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"] = "env-refresh";
    process.env["0SEC_CHATGPT_AUTH_FILE"] = authPath; // present but must stay untouched
    mockRefresh("rotated-env");

    await getChatGptCodexAccessToken();
    // The env path has nothing to persist — the auth file is never created.
    expect(existsSync(authPath)).toBe(false);
  });
});
