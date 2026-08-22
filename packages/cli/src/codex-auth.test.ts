import { mkdtempSync, mkdirSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { maybeLoadCodexAuth } from "./codex-auth.js";

let dir: string;

/** A fresh env per test — nothing leaks in from the ambient shell. */
function env(overrides: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return { ...overrides };
}

/** Write an auth.json with the given tokens and return its path. */
function writeAuth(name: string, tokens: unknown): string {
  const path = join(dir, name);
  writeFileSync(path, JSON.stringify({ tokens }), "utf8");
  return path;
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "0sec-codex-auth-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("maybeLoadCodexAuth", () => {
  it("honours 0SEC_CHATGPT_AUTH_FILE — the variable the runtime and docs use", () => {
    const e = env({ "0SEC_CHATGPT_AUTH_FILE": writeAuth("primary.json", { access_token: "acc-primary" }) });
    maybeLoadCodexAuth({ env: e, home: dir });
    expect(e["0SEC_CHATGPT_ACCESS_TOKEN"]).toBe("acc-primary");
  });

  it("still accepts the deprecated 0SEC_CODEX_AUTH_JSON_PATH when the primary is unset", () => {
    const e = env({ "0SEC_CODEX_AUTH_JSON_PATH": writeAuth("legacy.json", { refresh_token: "ref-legacy" }) });
    maybeLoadCodexAuth({ env: e, home: dir });
    expect(e["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"]).toBe("ref-legacy");
  });

  it("prefers the primary over the deprecated variable when both are set", () => {
    const e = env({
      "0SEC_CHATGPT_AUTH_FILE": writeAuth("primary.json", { access_token: "acc-primary" }),
      "0SEC_CODEX_AUTH_JSON_PATH": writeAuth("legacy.json", { access_token: "acc-legacy" }),
    });
    maybeLoadCodexAuth({ env: e, home: dir });
    expect(e["0SEC_CHATGPT_ACCESS_TOKEN"]).toBe("acc-primary");
  });

  it("falls back to ~/.codex/auth.json when neither override is set", () => {
    mkdirSync(join(dir, ".codex"));
    writeAuth(join(".codex", "auth.json"), { access_token: "acc-home", refresh_token: "ref-home" });
    const e = env();
    maybeLoadCodexAuth({ env: e, home: dir });
    expect(e["0SEC_CHATGPT_ACCESS_TOKEN"]).toBe("acc-home");
    expect(e["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"]).toBe("ref-home");
  });

  it("treats an empty override as unset instead of stat'ing the empty path", () => {
    mkdirSync(join(dir, ".codex"));
    writeAuth(join(".codex", "auth.json"), { access_token: "acc-home" });
    const e = env({ "0SEC_CHATGPT_AUTH_FILE": "" });
    maybeLoadCodexAuth({ env: e, home: dir });
    expect(e["0SEC_CHATGPT_ACCESS_TOKEN"]).toBe("acc-home");
  });

  it("does not overwrite an access token that is already exported", () => {
    const e = env({
      "0SEC_CHATGPT_ACCESS_TOKEN": "acc-from-shell",
      "0SEC_CHATGPT_AUTH_FILE": writeAuth("primary.json", { access_token: "acc-file", refresh_token: "ref-file" }),
    });
    maybeLoadCodexAuth({ env: e, home: dir });
    expect(e["0SEC_CHATGPT_ACCESS_TOKEN"]).toBe("acc-from-shell");
    // An explicit export wins wholesale: the file's refresh token must not be
    // spliced in alongside, or the process would mix credentials from two
    // different logins.
    expect(e["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"]).toBeUndefined();
  });

  it("does not overwrite a refresh token that is already exported", () => {
    const e = env({
      "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN": "ref-from-shell",
      "0SEC_CHATGPT_AUTH_FILE": writeAuth("primary.json", { access_token: "acc-file" }),
    });
    maybeLoadCodexAuth({ env: e, home: dir });
    expect(e["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"]).toBe("ref-from-shell");
    expect(e["0SEC_CHATGPT_ACCESS_TOKEN"]).toBeUndefined();
  });

  it("is a silent no-op when the file is missing", () => {
    const e = env({ "0SEC_CHATGPT_AUTH_FILE": join(dir, "nope.json") });
    expect(() => maybeLoadCodexAuth({ env: e, home: dir })).not.toThrow();
    expect(e["0SEC_CHATGPT_ACCESS_TOKEN"]).toBeUndefined();
    expect(e["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"]).toBeUndefined();
  });

  it("is a silent no-op when the home default does not exist either", () => {
    const e = env();
    expect(() => maybeLoadCodexAuth({ env: e, home: join(dir, "no-such-home") })).not.toThrow();
    expect(e["0SEC_CHATGPT_ACCESS_TOKEN"]).toBeUndefined();
  });

  it("is a silent no-op on malformed JSON", () => {
    const path = join(dir, "broken.json");
    writeFileSync(path, "{not json", "utf8");
    const e = env({ "0SEC_CHATGPT_AUTH_FILE": path });
    expect(() => maybeLoadCodexAuth({ env: e, home: dir })).not.toThrow();
    expect(e["0SEC_CHATGPT_ACCESS_TOKEN"]).toBeUndefined();
  });

  it("is a silent no-op when the file carries no tokens object", () => {
    const path = join(dir, "empty.json");
    writeFileSync(path, JSON.stringify({ OPENAI_API_KEY: "sk-unrelated" }), "utf8");
    const e = env({ "0SEC_CHATGPT_AUTH_FILE": path });
    maybeLoadCodexAuth({ env: e, home: dir });
    expect(e["0SEC_CHATGPT_ACCESS_TOKEN"]).toBeUndefined();
  });

  it("ignores non-string token values rather than exporting them", () => {
    const e = env({ "0SEC_CHATGPT_AUTH_FILE": writeAuth("junk.json", { access_token: null, refresh_token: 42 }) });
    maybeLoadCodexAuth({ env: e, home: dir });
    expect(e["0SEC_CHATGPT_ACCESS_TOKEN"]).toBeUndefined();
    expect(e["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"]).toBeUndefined();
  });

  it("is a silent no-op when the file is unreadable", () => {
    const path = writeAuth("locked.json", { access_token: "acc-locked" });
    chmodSync(path, 0o000);
    const e = env({ "0SEC_CHATGPT_AUTH_FILE": path });
    let threw = false;
    try {
      maybeLoadCodexAuth({ env: e, home: dir });
    } catch {
      threw = true;
    } finally {
      chmodSync(path, 0o600);
    }
    expect(threw).toBe(false);
    // Running as root defeats the permission bit, so only assert the env is
    // untouched when the chmod actually denied us.
    if (process.getuid?.() !== 0) {
      expect(e["0SEC_CHATGPT_ACCESS_TOKEN"]).toBeUndefined();
    }
  });

  it("defaults to the real process.env when called with no arguments", () => {
    // The call site in index.ts is zero-arg; the options must stay optional.
    const saved = {
      access: process.env["0SEC_CHATGPT_ACCESS_TOKEN"],
      refresh: process.env["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"],
      file: process.env["0SEC_CHATGPT_AUTH_FILE"],
      legacy: process.env["0SEC_CODEX_AUTH_JSON_PATH"],
    };
    try {
      delete process.env["0SEC_CHATGPT_ACCESS_TOKEN"];
      delete process.env["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"];
      delete process.env["0SEC_CODEX_AUTH_JSON_PATH"];
      process.env["0SEC_CHATGPT_AUTH_FILE"] = writeAuth("ambient.json", { access_token: "acc-ambient" });
      maybeLoadCodexAuth();
      expect(process.env["0SEC_CHATGPT_ACCESS_TOKEN"]).toBe("acc-ambient");
    } finally {
      restore("0SEC_CHATGPT_ACCESS_TOKEN", saved.access);
      restore("0SEC_CHATGPT_OAUTH_REFRESH_TOKEN", saved.refresh);
      restore("0SEC_CHATGPT_AUTH_FILE", saved.file);
      restore("0SEC_CODEX_AUTH_JSON_PATH", saved.legacy);
    }
  });
});

function restore(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
