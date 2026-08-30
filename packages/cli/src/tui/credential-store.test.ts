import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  credentialEnvPatch,
  credentialsFilePath,
  loadCredentials,
  normalizeCredentials,
  redactSecret,
  saveCredentials,
  type StoredCredentials,
} from "./credential-store.js";
import { PROVIDERS } from "./provider-status.js";

/** Temp homes created by a test, torn down after it regardless of outcome. */
const tempHomes: string[] = [];

function makeHome(): string {
  const dir = mkdtempSync(join(tmpdir(), "0sec-credential-store-"));
  tempHomes.push(dir);
  return dir;
}

/** Permission bits only — the file-type bits in `mode` are not ours to assert. */
function permissionsOf(path: string): number {
  return statSync(path).mode & 0o777;
}

afterEach(() => {
  while (tempHomes.length > 0) {
    const dir = tempHomes.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

describe("credentialsFilePath", () => {
  it("places the file inside the shared 0sec state directory", () => {
    expect(credentialsFilePath("/home/someone")).toBe("/home/someone/.0sec/credentials.json");
  });

  it("defaults the home directory when none is given", () => {
    expect(credentialsFilePath().endsWith(join(".0sec", "credentials.json"))).toBe(true);
  });
});

describe("normalizeCredentials", () => {
  // The file is hand-editable and therefore corruptible; each of these has to
  // produce a usable map rather than an exception inside a running console.
  it.each([
    ["null", null],
    ["undefined", undefined],
    ["a number", 42],
    ["a string", "anthropic=sk-ant-secret"],
    ["an array", ["anthropic", "sk-ant-secret"]],
    ["an array of objects", [{ anthropic: "sk-ant-secret" }]],
    ["a boolean", true],
  ])("returns an empty map for %s", (_label, raw) => {
    expect(normalizeCredentials(raw)).toEqual({});
  });

  it("keeps known providers with non-blank string values", () => {
    expect(normalizeCredentials({ anthropic: "sk-ant-secret", openai: "sk-openai-secret" })).toEqual({
      anthropic: "sk-ant-secret",
      openai: "sk-openai-secret",
    });
  });

  it("drops provider ids the runtime cannot authenticate", () => {
    // "google" and "mistral" exist in the pricing table but have no env-var
    // path in PROVIDERS, so a key stored under them could never be used.
    expect(normalizeCredentials({ google: "key", mistral: "key", anthropic: "sk-ant-secret" })).toEqual({
      anthropic: "sk-ant-secret",
    });
  });

  it("drops non-string values, including nested objects", () => {
    expect(
      normalizeCredentials({
        anthropic: { key: "sk-ant-secret" },
        openai: ["sk-openai-secret"],
        deepseek: 12345,
        xai: null,
        qwen: true,
        kimi: "kimi-secret",
      }),
    ).toEqual({ kimi: "kimi-secret" });
  });

  it("drops empty and whitespace-only values", () => {
    // A `$(cat key.txt)` newline or an `export KEY=` is not a credential;
    // keeping it would show the provider as configured and fail every call.
    expect(normalizeCredentials({ anthropic: "", openai: "   ", xai: "\n\t ", kimi: "kimi-secret" })).toEqual({
      kimi: "kimi-secret",
    });
  });

  it("trims surrounding whitespace off a pasted secret", () => {
    expect(normalizeCredentials({ anthropic: "  sk-ant-secret\n" })).toEqual({ anthropic: "sk-ant-secret" });
  });

  it("does not let a prototype-shaped key through", () => {
    const parsed: unknown = JSON.parse('{"__proto__": "polluted", "constructor": "polluted"}');
    const result = normalizeCredentials(parsed);
    expect(result).toEqual({});
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("does not mutate its input", () => {
    const raw = { anthropic: " sk-ant-secret ", google: "dropped" };
    normalizeCredentials(raw);
    expect(raw).toEqual({ anthropic: " sk-ant-secret ", google: "dropped" });
  });
});

describe("saveCredentials / loadCredentials", () => {
  it("round-trips through a real file", () => {
    const home = makeHome();
    const creds: StoredCredentials = { anthropic: "sk-ant-secret", openrouter: "sk-or-secret" };

    expect(saveCredentials(creds, home)).toBe(true);
    expect(loadCredentials(home)).toEqual(creds);
  });

  it("normalises on the way out so an unknown provider never reaches disk", () => {
    const home = makeHome();
    saveCredentials({ anthropic: "sk-ant-secret", google: "unusable", openai: "  " }, home);

    const written: unknown = JSON.parse(readFileSync(credentialsFilePath(home), "utf8"));
    expect(written).toEqual({ anthropic: "sk-ant-secret" });
  });

  it("writes the file owner-only (0600) and the directory owner-only (0700)", () => {
    const home = makeHome();
    expect(saveCredentials({ anthropic: "sk-ant-secret" }, home)).toBe(true);

    const path = credentialsFilePath(home);
    expect(permissionsOf(path)).toBe(0o600);
    expect(permissionsOf(join(home, ".0sec"))).toBe(0o700);
  });

  it("tightens a pre-existing world-readable file instead of leaving it alone", () => {
    const home = makeHome();
    const dir = join(home, ".0sec");
    const path = join(dir, "credentials.json");
    // An older build, a restored backup or a hand-edit can leave the secret
    // readable by every local account; `mode` on writeFileSync does nothing
    // for a file that already exists, so the explicit chmod is what saves us.
    mkdirSync(dir, { recursive: true });
    chmodSync(dir, 0o755);
    writeFileSync(path, '{"anthropic":"sk-ant-old"}\n', "utf8");
    chmodSync(path, 0o644);
    expect(permissionsOf(path)).toBe(0o644);

    expect(saveCredentials({ anthropic: "sk-ant-new" }, home)).toBe(true);
    expect(permissionsOf(path)).toBe(0o600);
    expect(permissionsOf(dir)).toBe(0o700);
    expect(loadCredentials(home)).toEqual({ anthropic: "sk-ant-new" });
  });

  it("returns an empty map when the file does not exist", () => {
    expect(loadCredentials(makeHome())).toEqual({});
  });

  it("returns an empty map for invalid JSON rather than throwing", () => {
    const home = makeHome();
    mkdirSync(join(home, ".0sec"), { recursive: true });
    writeFileSync(credentialsFilePath(home), "{ not json,,, ", "utf8");

    expect(() => loadCredentials(home)).not.toThrow();
    expect(loadCredentials(home)).toEqual({});
  });

  it("returns an empty map for well-formed JSON of the wrong shape", () => {
    const home = makeHome();
    mkdirSync(join(home, ".0sec"), { recursive: true });
    writeFileSync(credentialsFilePath(home), '["anthropic","sk-ant-secret"]', "utf8");

    expect(loadCredentials(home)).toEqual({});
  });

  it("returns false instead of throwing when the path is unwritable", () => {
    // A regular file where the state directory belongs makes mkdir fail with
    // ENOTDIR for any user, including root — unlike a chmod-based trap, which
    // a root test runner would walk straight through.
    const parent = makeHome();
    const blocked = join(parent, "home-that-is-a-file");
    writeFileSync(blocked, "not a directory", "utf8");

    expect(() => saveCredentials({ anthropic: "sk-ant-secret" }, blocked)).not.toThrow();
    expect(saveCredentials({ anthropic: "sk-ant-secret" }, blocked)).toBe(false);
  });
});

describe("credentialEnvPatch", () => {
  it("refuses to map an OAuth subscription through the generic API-key store", () => {
    expect(credentialEnvPatch({ "chatgpt-codex": "oauth-secret" }, {})).toEqual({});
  });

  it("covers every API-key provider in the table", () => {
    const creds: StoredCredentials = Object.fromEntries(
      PROVIDERS.map((info) => [info.id, `secret-for-${info.id}`]),
    );
    const patch = credentialEnvPatch(creds, {});

    expect(Object.keys(patch).sort()).toEqual(
      PROVIDERS.filter((info) => info.auth === "api-key").map((info) => info.envVars[0]).sort(),
    );
  });

  it("never overrides an env var that already carries a credential", () => {
    // The shell export is an explicit choice; a stored key shadowing it would
    // make "which key did that run use?" unanswerable after a 401.
    const patch = credentialEnvPatch(
      { anthropic: "sk-ant-stored", openai: "sk-openai-stored" },
      { ANTHROPIC_API_KEY: "sk-ant-from-shell" },
    );

    expect(patch).toEqual({ OPENAI_API_KEY: "sk-openai-stored" });
  });

  it("fills a variable that is exported but empty", () => {
    expect(credentialEnvPatch({ anthropic: "sk-ant-stored" }, { ANTHROPIC_API_KEY: "" })).toEqual({
      ANTHROPIC_API_KEY: "sk-ant-stored",
    });
  });

  it("fills a variable that is exported but whitespace-only", () => {
    expect(credentialEnvPatch({ anthropic: "sk-ant-stored" }, { ANTHROPIC_API_KEY: " \n" })).toEqual({
      ANTHROPIC_API_KEY: "sk-ant-stored",
    });
  });

  it("leaves a provider alone when a lower-preference var of its own is set", () => {
    // The shell already configured chatgpt-codex via the refresh token;
    // injecting a stored access token would mix two credential sources into
    // one auth attempt, with ours winning — the silent override we forbid.
    expect(
      credentialEnvPatch(
        { "chatgpt-codex": "stored-access-token" },
        { "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN": "shell-refresh-token" },
      ),
    ).toEqual({});
  });

  it("ignores stored entries for unknown providers and blank values", () => {
    expect(credentialEnvPatch({ google: "unusable", anthropic: "   " }, {})).toEqual({});
  });

  it("returns an empty patch for an empty store", () => {
    expect(credentialEnvPatch({}, { ANTHROPIC_API_KEY: "sk-ant-from-shell" })).toEqual({});
  });

  it("does not mutate either input", () => {
    const creds: StoredCredentials = { anthropic: "sk-ant-stored", openai: "sk-openai-stored" };
    const env: Record<string, string | undefined> = { OPENAI_API_KEY: "sk-openai-from-shell", PATH: "/usr/bin" };

    credentialEnvPatch(creds, env);

    expect(creds).toEqual({ anthropic: "sk-ant-stored", openai: "sk-openai-stored" });
    expect(env).toEqual({ OPENAI_API_KEY: "sk-openai-from-shell", PATH: "/usr/bin" });
  });

  it("reads only the passed environment, never process.env", () => {
    const previous = process.env.ANTHROPIC_API_KEY;
    process.env.ANTHROPIC_API_KEY = "sk-ant-ambient";
    try {
      expect(credentialEnvPatch({ anthropic: "sk-ant-stored" }, {})).toEqual({
        ANTHROPIC_API_KEY: "sk-ant-stored",
      });
    } finally {
      if (previous === undefined) delete process.env.ANTHROPIC_API_KEY;
      else process.env.ANTHROPIC_API_KEY = previous;
    }
  });
});

describe("redactSecret", () => {
  it.each([
    ["an empty string", ""],
    ["one character", "a"],
    ["three characters", "abc"],
    ["four characters", "abcd"],
    ["eleven characters", "abcdefghijk"],
  ])("fully masks %s", (_label, secret) => {
    const redacted = redactSecret(secret);
    expect(redacted).not.toContain(secret === "" ? " " : secret);
    expect(redacted).toBe("••••••••");
  });

  it("masks short inputs to a constant width so length does not leak", () => {
    expect(redactSecret("a")).toBe(redactSecret("abcdefghijk"));
  });

  it("shows only a tail for a mid-length secret", () => {
    const secret = "abcdefghijklmno";
    const redacted = redactSecret(secret);

    expect(redacted).toBe("••••••••lmno");
    expect(redacted).not.toContain(secret);
    expect(redacted).not.toContain("abcdef");
  });

  it("shows a short prefix and the last four characters of a real key", () => {
    expect(redactSecret("sk-ant-api03-0123456789abcdefa4f2")).toBe("sk-ant…a4f2");
  });

  it("never returns the full secret, at any length", () => {
    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
    const lengths = [1, 3, 4, 8, 11, 12, 15, 19, 20, 40, 108];
    for (const length of lengths) {
      const secret = Array.from({ length }, (_unused, index) => alphabet[index % alphabet.length]).join("");
      const redacted = redactSecret(secret);
      expect(redacted).not.toBe(secret);
      expect(redacted.length).toBeLessThan(secret.length + 8);
      expect(redacted).not.toContain(secret);
    }
  });

  it("ignores surrounding whitespace rather than counting it as entropy", () => {
    expect(redactSecret("  abcd  ")).toBe("••••••••");
  });
});
