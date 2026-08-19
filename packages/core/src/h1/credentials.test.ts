import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadH1Credentials, H1AuthMissingError } from "./credentials.js";

function makeFakeHome(content: string | null, mode: number = 0o600): string {
  const home = mkdtempSync(join(tmpdir(), "0sec-h1-creds-"));
  if (content !== null) {
    mkdirSync(join(home, ".0sec"), { recursive: true, mode: 0o700 });
    const path = join(home, ".0sec", "h1.env");
    writeFileSync(path, content, { mode });
    chmodSync(path, mode);
  }
  return home;
}

describe("loadH1Credentials", () => {
  it("prefers env over file when both are set", () => {
    const home = makeFakeHome("H1_API_IDENTIFIER=fileid\nH1_API_TOKEN=filetok\n");
    const creds = loadH1Credentials({
      env: { H1_API_IDENTIFIER: "envid", H1_API_TOKEN: "envtok" },
      homeDir: home,
    });
    expect(creds).toEqual({ identifier: "envid", token: "envtok", source: "env" });
  });

  it("loads from env-only", () => {
    const home = makeFakeHome(null);
    const creds = loadH1Credentials({
      env: { H1_API_IDENTIFIER: "bot", H1_API_TOKEN: "tok" },
      homeDir: home,
    });
    expect(creds.source).toBe("env");
    expect(creds.identifier).toBe("bot");
  });

  it("loads from file when env is unset", () => {
    const home = makeFakeHome(
      "# header comment\nH1_API_IDENTIFIER=mybot\nH1_API_TOKEN=tokenvalue\n",
    );
    const creds = loadH1Credentials({ env: {}, homeDir: home });
    expect(creds).toEqual({ identifier: "mybot", token: "tokenvalue", source: "file" });
  });

  it("warns when h1.env mode is not 600", () => {
    const home = makeFakeHome(
      "H1_API_IDENTIFIER=mybot\nH1_API_TOKEN=tok\n",
      0o644,
    );
    const warnings: string[] = [];
    const creds = loadH1Credentials({
      env: {},
      homeDir: home,
      warn: (m) => warnings.push(m),
    });
    expect(creds.identifier).toBe("mybot");
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toMatch(/mode is 644/);
    expect(warnings[0]).toMatch(/chmod 600/);
  });

  it("does NOT warn when h1.env mode is 600", () => {
    const home = makeFakeHome(
      "H1_API_IDENTIFIER=mybot\nH1_API_TOKEN=tok\n",
      0o600,
    );
    const warnings: string[] = [];
    loadH1Credentials({ env: {}, homeDir: home, warn: (m) => warnings.push(m) });
    expect(warnings).toEqual([]);
  });

  it("throws H1AuthMissingError when neither source has creds", () => {
    const home = makeFakeHome(null);
    expect(() => loadH1Credentials({ env: {}, homeDir: home })).toThrow(H1AuthMissingError);
  });

  it("throws H1AuthMissingError when file has only one of the two keys", () => {
    const home = makeFakeHome("H1_API_IDENTIFIER=mybot\n");
    expect(() => loadH1Credentials({ env: {}, homeDir: home })).toThrow(/incomplete/);
  });

  it("rejects malformed lines in h1.env", () => {
    const home = makeFakeHome("just a banner line\nH1_API_IDENTIFIER=x\nH1_API_TOKEN=y\n");
    expect(() => loadH1Credentials({ env: {}, homeDir: home })).toThrow(/Malformed h1\.env/);
  });

  it("rejects an identifier that doesn't match the regex", () => {
    expect(() =>
      loadH1Credentials({ env: { H1_API_IDENTIFIER: "-bad", H1_API_TOKEN: "t" } }),
    ).toThrow(/H1_API_IDENTIFIER.*invalid/);
  });

  it("rejects an identifier with disallowed characters", () => {
    expect(() =>
      loadH1Credentials({ env: { H1_API_IDENTIFIER: "bad name", H1_API_TOKEN: "t" } }),
    ).toThrow(/invalid/);
  });

  it("accepts identifiers with letters, numbers, hyphens, underscores", () => {
    const home = makeFakeHome(null);
    const c = loadH1Credentials({
      env: { H1_API_IDENTIFIER: "abc-123_def", H1_API_TOKEN: "t" },
      homeDir: home,
    });
    expect(c.identifier).toBe("abc-123_def");
  });

  it("error messages never echo the token value", () => {
    const home = makeFakeHome(null);
    const secret = "S3CR3T_TOKEN_VALUE_DO_NOT_LEAK";
    let caught: unknown;
    try {
      loadH1Credentials({
        env: { H1_API_IDENTIFIER: "-bad-id", H1_API_TOKEN: secret },
        homeDir: home,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(H1AuthMissingError);
    expect(String((caught as Error).message)).not.toContain(secret);
  });
});
