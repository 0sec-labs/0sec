import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  loadCloudCredentials,
  CloudAuthMissingError,
  DEFAULT_CLOUD_HOST,
} from "./credentials.js";

function makeFakeHome(content: string | null, mode: number = 0o600): string {
  const home = mkdtempSync(join(tmpdir(), "pwnkit-cloud-creds-"));
  if (content !== null) {
    mkdirSync(join(home, ".pwnkit"), { recursive: true, mode: 0o700 });
    const path = join(home, ".pwnkit", "cloud.env");
    writeFileSync(path, content, { mode });
    chmodSync(path, mode);
  }
  return home;
}

describe("loadCloudCredentials", () => {
  it("prefers env over file when both are set", () => {
    const home = makeFakeHome("PWNKIT_CLOUD_TOKEN=filetok\nPWNKIT_CLOUD_HOST=https://file.example\n");
    const creds = loadCloudCredentials({
      env: { PWNKIT_CLOUD_TOKEN: "envtok", PWNKIT_CLOUD_HOST: "https://env.example" },
      homeDir: home,
    });
    expect(creds).toEqual({ host: "https://env.example", token: "envtok", source: "env" });
  });

  it("loads from env-only, falling back to default host", () => {
    const home = makeFakeHome(null);
    const creds = loadCloudCredentials({
      env: { PWNKIT_CLOUD_TOKEN: "tok" },
      homeDir: home,
    });
    expect(creds.source).toBe("env");
    expect(creds.token).toBe("tok");
    expect(creds.host).toBe(DEFAULT_CLOUD_HOST);
  });

  it("loads from file when env is unset", () => {
    const home = makeFakeHome(
      "# header comment\nPWNKIT_CLOUD_HOST=https://staging.example\nPWNKIT_CLOUD_TOKEN=tokenvalue\n",
    );
    const creds = loadCloudCredentials({ env: {}, homeDir: home });
    expect(creds).toEqual({
      host: "https://staging.example",
      token: "tokenvalue",
      source: "file",
    });
  });

  it("falls back to default host when cloud.env omits PWNKIT_CLOUD_HOST", () => {
    const home = makeFakeHome("PWNKIT_CLOUD_TOKEN=onlytok\n");
    const creds = loadCloudCredentials({ env: {}, homeDir: home });
    expect(creds.host).toBe(DEFAULT_CLOUD_HOST);
    expect(creds.token).toBe("onlytok");
    expect(creds.source).toBe("file");
  });

  it("strips trailing slash from host", () => {
    const home = makeFakeHome(null);
    const creds = loadCloudCredentials({
      env: { PWNKIT_CLOUD_TOKEN: "t", PWNKIT_CLOUD_HOST: "https://example.com/" },
      homeDir: home,
    });
    expect(creds.host).toBe("https://example.com");
  });

  it("warns when cloud.env mode is not 600", () => {
    const home = makeFakeHome("PWNKIT_CLOUD_TOKEN=tok\n", 0o644);
    const warnings: string[] = [];
    const creds = loadCloudCredentials({
      env: {},
      homeDir: home,
      warn: (m) => warnings.push(m),
    });
    expect(creds.token).toBe("tok");
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toMatch(/mode is 644/);
    expect(warnings[0]).toMatch(/chmod 600/);
  });

  it("does NOT warn when cloud.env mode is 600", () => {
    const home = makeFakeHome("PWNKIT_CLOUD_TOKEN=tok\n", 0o600);
    const warnings: string[] = [];
    loadCloudCredentials({ env: {}, homeDir: home, warn: (m) => warnings.push(m) });
    expect(warnings).toEqual([]);
  });

  it("throws CloudAuthMissingError when neither source has creds", () => {
    const home = makeFakeHome(null);
    expect(() => loadCloudCredentials({ env: {}, homeDir: home })).toThrow(CloudAuthMissingError);
  });

  it("throws CloudAuthMissingError when file is missing the token", () => {
    const home = makeFakeHome("PWNKIT_CLOUD_HOST=https://example.com\n");
    expect(() => loadCloudCredentials({ env: {}, homeDir: home })).toThrow(/incomplete/);
  });

  it("rejects malformed lines in cloud.env", () => {
    const home = makeFakeHome("just a banner line\nPWNKIT_CLOUD_TOKEN=x\n");
    expect(() => loadCloudCredentials({ env: {}, homeDir: home })).toThrow(/Malformed cloud\.env/);
  });

  it("rejects a host that isn't http(s)", () => {
    expect(() =>
      loadCloudCredentials({
        env: { PWNKIT_CLOUD_TOKEN: "t", PWNKIT_CLOUD_HOST: "app.example.com" },
      }),
    ).toThrow(/must be an http\(s\) URL/);
  });

  it("error messages never echo the token value", () => {
    const home = makeFakeHome(null);
    const secret = "S3CR3T_CLOUD_TOKEN_DO_NOT_LEAK";
    let caught: unknown;
    try {
      loadCloudCredentials({
        env: { PWNKIT_CLOUD_TOKEN: secret, PWNKIT_CLOUD_HOST: "not-a-url" },
        homeDir: home,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(CloudAuthMissingError);
    expect(String((caught as Error).message)).not.toContain(secret);
  });
});
