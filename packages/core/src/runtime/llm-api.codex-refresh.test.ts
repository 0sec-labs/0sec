import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  getChatGptCodexAccessToken,
  LlmApiRuntime,
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

  it("isolates two credential snapshots while sharing refresh for the same credential", async () => {
    process.env["0SEC_CHATGPT_AUTH_FILE"] = authPath;
    const refreshes: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
      const refresh = new URLSearchParams(String(init.body)).get("refresh_token")!;
      refreshes.push(refresh);
      await Promise.resolve();
      return new Response(JSON.stringify({
        access_token: `access-for-${refresh}`, refresh_token: `rotated-${refresh}`, expires_in: 3600,
      }), { headers: { "content-type": "application/json" } });
    }));
    const firstEnv = { "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN": "first-fixture", "0SEC_CHATGPT_ACCOUNT_ID": "first-account" };
    const secondEnv = { "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN": "second-fixture", "0SEC_CHATGPT_ACCOUNT_ID": "second-account" };
    const [first, same, second] = await Promise.all([
      getChatGptCodexAccessToken(firstEnv),
      getChatGptCodexAccessToken({ ...firstEnv }),
      getChatGptCodexAccessToken(secondEnv),
    ]);
    expect(first).toEqual({ accessToken: "access-for-first-fixture", accountId: "first-account" });
    expect(same).toEqual(first);
    expect(second).toEqual({ accessToken: "access-for-second-fixture", accountId: "second-account" });
    expect(refreshes).toEqual(["first-fixture", "second-fixture"]);
    expect(existsSync(authPath)).toBe(false);
  });

  it("keeps an existing runtime identity without overwriting a later file login", async () => {
    writeFileSync(authPath, JSON.stringify({ tokens: { refresh_token: "older-fixture", account_id: "older-account" } }));
    const runtime = new LlmApiRuntime({
      type: "api", timeout: 5000, provider: "chatgpt-codex", model: "gpt-fixture",
      env: {
        "0SEC_CHATGPT_AUTH_FILE": authPath, "0SEC_CHATGPT_ACCESS_TOKEN": "",
        "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN": "", "0SEC_FORCE_PROVIDER": "",
        "0SEC_LLM_FALLBACK": "", "0SEC_SKIP_PROVIDER_BANNER": "1",
      },
    });
    const laterLogin = JSON.stringify({ tokens: { refresh_token: "later-fixture", account_id: "later-account" } });
    writeFileSync(authPath, laterLogin);
    const requests: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
      if (String(url).includes("oauth/token")) {
        requests.push(new URLSearchParams(String(init.body)).get("refresh_token")!);
        return new Response(JSON.stringify({
          access_token: "older-access", refresh_token: "older-rotated", expires_in: 3600,
        }), { headers: { "content-type": "application/json" } });
      }
      requests.push(new Headers(init.headers).get("authorization")!);
      return new Response('{"error":"fixture-stop"}', { status: 401 });
    }));
    await runtime.executeNative("sys", [{ role: "user", content: [{ type: "text", text: "hello" }] }], []);
    expect(requests).toEqual(["older-fixture", "Bearer older-access"]);
    expect(readFileSync(authPath, "utf8")).toBe(laterLogin);
  });

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
