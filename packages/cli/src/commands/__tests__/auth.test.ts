/**
 * `0sec auth` CLI smoke tests. Pattern-matches h1.test.ts: we drive
 * the action functions directly (exported from auth.ts) so we can pass
 * test seams for fetch / sleep / homeDir / openBrowser without having to
 * thread them through Commander. The argv → exit code shape is covered
 * by the commander register call at the end.
 *
 * The browser-open path is mocked — we never actually shell out to
 * `open` / `xdg-open` / `cmd start`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, existsSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { registerAuthCommand, runLogin, runLogout, runStatus } from "../auth.js";

const SECRET = "S3CR3T_CLOUD_TOKEN_DO_NOT_LEAK_999";
const HOST = "https://app.example.com";

interface CapturedIO {
  stdout: string[];
  stderr: string[];
}

function freshHome(): string {
  return mkdtempSync(join(tmpdir(), "0sec-cloud-cli-"));
}

function seedHomeWithCreds(home: string, host: string = HOST, token: string = SECRET): string {
  mkdirSync(join(home, ".0sec"), { recursive: true, mode: 0o700 });
  const path = join(home, ".0sec", "cloud.env");
  writeFileSync(path, `0SEC_CLOUD_HOST=${host}\n0SEC_CLOUD_TOKEN=${token}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
}

function captureIO(): CapturedIO & { restore: () => void } {
  const captured: CapturedIO = { stdout: [], stderr: [] };
  const stdoutSpy = vi.spyOn(console, "log").mockImplementation((...args) => {
    captured.stdout.push(args.map((a) => String(a)).join(" "));
  });
  const stderrSpy = vi.spyOn(console, "error").mockImplementation((...args) => {
    captured.stderr.push(args.map((a) => String(a)).join(" "));
  });
  return {
    ...captured,
    get stdout() {
      return captured.stdout;
    },
    get stderr() {
      return captured.stderr;
    },
    restore: () => {
      stdoutSpy.mockRestore();
      stderrSpy.mockRestore();
    },
  };
}

describe("0sec auth login", () => {
  let home: string;
  let originalEnvHost: string | undefined;
  let originalEnvTok: string | undefined;
  let io: ReturnType<typeof captureIO>;

  beforeEach(() => {
    home = freshHome();
    originalEnvHost = process.env["0SEC_CLOUD_HOST"];
    originalEnvTok = process.env["0SEC_CLOUD_TOKEN"];
    delete process.env["0SEC_CLOUD_HOST"];
    delete process.env["0SEC_CLOUD_TOKEN"];
    process.exitCode = undefined;
    io = captureIO();
  });

  afterEach(() => {
    if (originalEnvHost !== undefined) process.env["0SEC_CLOUD_HOST"] = originalEnvHost;
    if (originalEnvTok !== undefined) process.env["0SEC_CLOUD_TOKEN"] = originalEnvTok;
    process.exitCode = undefined;
    io.restore();
  });

  it("--token escape-hatch persists creds and exits 0", async () => {
    await runLogin({ host: HOST, token: SECRET, homeDir: home });
    expect(process.exitCode).toBe(0);
    const path = join(home, ".0sec", "cloud.env");
    expect(existsSync(path)).toBe(true);
    const body = readFileSync(path, "utf-8");
    expect(body).toContain(`0SEC_CLOUD_HOST=${HOST}`);
    expect(body).toContain(`0SEC_CLOUD_TOKEN=${SECRET}`);
    expect((statSync(path).mode & 0o777).toString(8)).toBe("600");
    expect(io.stdout.join("\n")).toContain(`Logged in (host=${HOST})`);
  });

  it("--token empty value → exit 1", async () => {
    await runLogin({ host: HOST, token: "   ", homeDir: home });
    expect(process.exitCode).toBe(1);
    expect(io.stderr.join("\n")).toMatch(/--token cannot be empty/);
  });

  it("rejects non-http(s) --host", async () => {
    await runLogin({ host: "ftp://bad.example", token: SECRET, homeDir: home });
    expect(process.exitCode).toBe(1);
    expect(io.stderr.join("\n")).toMatch(/must be an http\(s\) URL/);
  });

  it("browser flow polls and persists when server returns 200 with a token", async () => {
    const openCalls: string[] = [];
    let polls = 0;
    const fetchImpl = (async (url: string | URL | Request) => {
      polls += 1;
      const u = String(url);
      expect(u).toMatch(/\/cli-auth\/sessions\//);
      if (polls < 3) return new Response("not yet", { status: 404 });
      return jsonResponse({ token: SECRET });
    }) as typeof fetch;

    await runLogin({
      host: HOST,
      homeDir: home,
      pollAttempts: 5,
      pollIntervalMs: 0,
      openBrowser: (url) => openCalls.push(url),
      fetchImpl,
      sleep: async () => {},
    });

    expect(process.exitCode).toBe(0);
    expect(openCalls.length).toBe(1);
    expect(openCalls[0]).toMatch(/\/cli-auth\?session=/);
    expect(polls).toBe(3);
    const path = join(home, ".0sec", "cloud.env");
    expect(readFileSync(path, "utf-8")).toContain(`0SEC_CLOUD_TOKEN=${SECRET}`);
  });

  it("browser flow times out cleanly when server never responds 200", async () => {
    let polls = 0;
    const fetchImpl = (async () => {
      polls += 1;
      return new Response("not yet", { status: 404 });
    }) as typeof fetch;
    await runLogin({
      host: HOST,
      homeDir: home,
      pollAttempts: 3,
      pollIntervalMs: 0,
      openBrowser: () => {},
      fetchImpl,
      sleep: async () => {},
    });
    expect(process.exitCode).toBe(3);
    expect(polls).toBe(3);
    expect(io.stderr.join("\n")).toMatch(/timed out/);
    expect(io.stderr.join("\n")).toMatch(/--token/);
    expect(existsSync(join(home, ".0sec", "cloud.env"))).toBe(false);
  });

  it("browser flow rejects a 200 body that has no token field", async () => {
    const fetchImpl = (async () => jsonResponse({ status: "ok" })) as typeof fetch;
    await runLogin({
      host: HOST,
      homeDir: home,
      pollAttempts: 1,
      pollIntervalMs: 0,
      openBrowser: () => {},
      fetchImpl,
      sleep: async () => {},
    });
    expect(process.exitCode).toBe(1);
    expect(io.stderr.join("\n")).toMatch(/did not contain a token/);
  });

  it("never leaks the token to stdout/stderr on the --token happy path", async () => {
    await runLogin({ host: HOST, token: SECRET, homeDir: home });
    const all = io.stdout.join("\n") + "\n" + io.stderr.join("\n");
    expect(all).not.toContain(SECRET);
  });
});

describe("0sec auth logout", () => {
  let home: string;
  let io: ReturnType<typeof captureIO>;

  beforeEach(() => {
    home = freshHome();
    process.exitCode = undefined;
    io = captureIO();
  });

  afterEach(() => {
    process.exitCode = undefined;
    io.restore();
  });

  it("deletes ~/.0sec/cloud.env and prints 'Logged out'", () => {
    const path = seedHomeWithCreds(home);
    expect(existsSync(path)).toBe(true);
    runLogout({ homeDir: home });
    expect(process.exitCode).toBe(0);
    expect(existsSync(path)).toBe(false);
    expect(io.stdout.join("\n")).toMatch(/^Logged out$/m);
  });

  it("treats missing cloud.env as already-logged-out (exit 0)", () => {
    runLogout({ homeDir: home });
    expect(process.exitCode).toBe(0);
    expect(io.stdout.join("\n")).toMatch(/no credentials file/);
  });
});

describe("0sec auth status", () => {
  let home: string;
  let originalHome: string | undefined;
  let originalEnvHost: string | undefined;
  let originalEnvTok: string | undefined;
  let io: ReturnType<typeof captureIO>;

  beforeEach(() => {
    home = freshHome();
    originalHome = process.env.HOME;
    originalEnvHost = process.env["0SEC_CLOUD_HOST"];
    originalEnvTok = process.env["0SEC_CLOUD_TOKEN"];
    process.env.HOME = home;
    delete process.env["0SEC_CLOUD_HOST"];
    delete process.env["0SEC_CLOUD_TOKEN"];
    process.exitCode = undefined;
    io = captureIO();
  });

  afterEach(() => {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalEnvHost !== undefined) process.env["0SEC_CLOUD_HOST"] = originalEnvHost;
    if (originalEnvTok !== undefined) process.env["0SEC_CLOUD_TOKEN"] = originalEnvTok;
    process.exitCode = undefined;
    io.restore();
  });

  it("prints OK with host on 200, exit 0", async () => {
    seedHomeWithCreds(home);
    const fetchImpl = (async () => jsonResponse({ status: "ok" })) as typeof fetch;
    await runStatus({ fetchImpl });
    expect(process.exitCode).toBe(0);
    expect(io.stdout.join("\n")).toContain(`OK (host=${HOST})`);
    expect(io.stdout.join("\n") + io.stderr.join("\n")).not.toContain(SECRET);
  });

  it("exit 2 on missing creds, stderr explains how to fix", async () => {
    // No cloud.env in this home.
    await runStatus({});
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toMatch(/0sec auth login/);
  });

  it("exit 2 on 401, stderr does NOT contain token", async () => {
    seedHomeWithCreds(home);
    const fetchImpl = (async () => new Response("nope", { status: 401 })) as typeof fetch;
    await runStatus({ fetchImpl });
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("FAIL (HTTP 401)");
    const all = io.stdout.join("\n") + io.stderr.join("\n");
    expect(all).not.toContain(SECRET);
  });

  it("exit 3 on network error", async () => {
    seedHomeWithCreds(home);
    const fetchImpl = (async () => {
      throw new Error("ECONNRESET");
    }) as typeof fetch;
    await runStatus({ fetchImpl });
    expect(process.exitCode).toBe(3);
    expect(io.stderr.join("\n")).toContain("FAIL (network)");
  });
});

describe("0sec auth — command registration", () => {
  it("registers login / logout / status under `auth`", () => {
    const program = new Command();
    program.exitOverride();
    registerAuthCommand(program);
    const auth = program.commands.find((c) => c.name() === "auth");
    expect(auth).toBeDefined();
    const subs = auth!.commands.map((c) => c.name()).sort();
    expect(subs).toEqual(["login", "logout", "status"]);
  });
});
