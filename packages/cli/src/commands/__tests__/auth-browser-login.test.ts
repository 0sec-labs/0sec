import { afterEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hostedBrowserLoginFlow, type HostedBrowserLoginOptions } from "../auth.js";

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
afterEach(() => { for (const home of homes.splice(0)) rmSync(home, { recursive: true, force: true }); });

describe("neutral Cloud login", () => {
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
