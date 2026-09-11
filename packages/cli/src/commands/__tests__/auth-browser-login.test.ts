import { afterEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { hostedBrowserLoginFlow, type HostedBrowserLoginOptions } from "../auth.js";

const browserProcess = vi.hoisted(() => ({ platform: "linux", spawn: vi.fn() }));
vi.mock("node:os", async (importOriginal) => ({
  ...await importOriginal<typeof import("node:os")>(),
  platform: () => browserProcess.platform,
}));
vi.mock("node:child_process", async (importOriginal) => ({
  ...await importOriginal<typeof import("node:child_process")>(),
  spawn: browserProcess.spawn,
}));

const homes: string[] = [];
const token = "fixture-cloud-token-never-expose";
function options(): HostedBrowserLoginOptions & { homeDir: string } {
  const homeDir = mkdtempSync(join(tmpdir(), "cloud-login-regression-"));
  homes.push(homeDir);
  return { host: "https://fixture.invalid", homeDir, openBrowser: () => {}, sleep: async () => {}, pollAttempts: 3, pollIntervalMs: 0 };
}
function expectNoCredentials(home: string) {
  expect(existsSync(join(home, ".0sec", "cloud.env"))).toBe(false);
  expect(existsSync(join(home, ".0cloud", "credentials.json"))).toBe(false);
}
afterEach(() => {
  for (const home of homes.splice(0)) rmSync(home, { recursive: true, force: true });
  browserProcess.platform = "linux";
  browserProcess.spawn.mockReset();
});

describe("neutral Cloud login", () => {
  it("keeps a Windows sign-in URL out of command-interpreter source", async () => {
    browserProcess.platform = "win32";
    browserProcess.spawn.mockImplementation(() => {
      const child = Object.assign(new EventEmitter(), { unref() {} });
      queueMicrotask(() => child.emit("spawn"));
      return child;
    });
    const opts = options();
    const host = "https://fixture.invalid/&calc&";
    const result = await hostedBrowserLoginFlow({
      ...opts,
      host,
      openBrowser: undefined,
      fetchImpl: async () => Response.json({ status: "ready", token }),
    });
    expect(result.ok).toBe(true);
    const [executable, args, spawnOptions] = browserProcess.spawn.mock.calls[0]!;
    expect(executable).not.toMatch(/^cmd(?:\.exe)?$/i);
    expect(args.join(" ")).not.toContain("&calc&");
    expect(spawnOptions.env.OSEC_BROWSER_LOGIN_URL).toMatch(
      /^https:\/\/fixture\.invalid\/&calc&\/cli-auth\?session=[A-Za-z0-9_-]+$/,
    );
  });

  it.each(["sleep", "fetch", "body"] as const)("cancels a pending %s without waiting for that operation or persisting credentials", async (boundary) => {
    const opts = options();
    const entered = Promise.withResolvers<void>();
    const pending = Promise.withResolvers<never>();
    const controller = new AbortController();
    const block = () => { entered.resolve(); return pending.promise; };
    const response = Response.json({ status: "ready", token });
    if (boundary === "body") response.json = block;
    const result = hostedBrowserLoginFlow({ ...opts, signal: controller.signal,
      sleep: boundary === "sleep" ? block : opts.sleep,
      fetchImpl: boundary === "fetch" ? block : async () => boundary === "sleep" ? Response.json({ status: "pending" }) : response,
    });
    await entered.promise;
    controller.abort();
    expect(await result).toMatchObject({ ok: false, cancelled: true, recoverable: true });
    expectNoCredentials(opts.homeDir);
  });

  it("persists a ready token privately without exposing it to the renderer or changing process exit status", async () => {
    const opts = options();
    const status: unknown[] = [];
    const exitCode = process.exitCode;
    const result = await hostedBrowserLoginFlow({ ...opts,
      openBrowser: async () => { throw new Error("No local browser"); },
      fetchImpl: async () => Response.json({ status: "ready", token }),
      onStatus: (...event) => { status.push(event); },
    });
    expect(result).toEqual({ ok: true, host: opts.host });
    expect(JSON.stringify({ result, status })).not.toContain(token);
    const credentials = join(opts.homeDir, ".0sec", "cloud.env");
    expect(readFileSync(credentials, "utf8")).toContain(`0SEC_CLOUD_TOKEN=${token}`);
    expect(statSync(credentials).mode & 0o777).toBe(0o600);
    expect(process.exitCode).toBe(exitCode);
  });

  it("does not persist a token before authorization is ready", async () => {
    const opts = options();
    const result = await hostedBrowserLoginFlow({ ...opts, fetchImpl: async () => Response.json({ status: "pending", token }) });
    expect(result.ok).toBe(false);
    expectNoCredentials(opts.homeDir);
  });

  it("fails a service outage without replaying polling or changing process exit status", async () => {
    const opts = options();
    const exitCode = process.exitCode;
    let requests = 0;
    const result = await hostedBrowserLoginFlow({ ...opts, fetchImpl: async () => { requests++; return new Response(null, { status: 503 }); } });
    expect(result).toMatchObject({ ok: false, recoverable: true });
    expect(requests).toBe(1);
    expect(process.exitCode).toBe(exitCode);
    expectNoCredentials(opts.homeDir);
  });
});
