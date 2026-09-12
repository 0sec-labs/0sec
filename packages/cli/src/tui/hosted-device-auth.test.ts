import { afterEach, expect, it, vi } from "vitest";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readHostedConnection, startHostedDeviceAuth, type HostedDeviceAuthUpdate } from "./hosted-device-auth.js";

const homes: string[] = [];
function home() { const value = mkdtempSync(join(tmpdir(), "cloud-connect-")); homes.push(value); return value; }
afterEach(() => { vi.unstubAllEnvs(); for (const value of homes.splice(0)) rmSync(value, { recursive: true, force: true }); });

it("leaves polling on an unavailable service without selecting Cloud or writing credentials", async () => {
  const homeDir = home();
  const updates: HostedDeviceAuthUpdate[] = [];
  const finished = Promise.withResolvers<void>();
  let requests = 0;
  let selected = false;
  startHostedDeviceAuth({ homeDir, host: "http://localhost:1", openBrowser: () => {}, sleep: async () => {},
    fetchImpl: async () => { requests++; return new Response(null, { status: 503 }); },
    onUpdate: (update) => updates.push(update), onConnected: () => { selected = true; }, onSettled: () => finished.resolve(),
  });
  await finished.promise;
  expect(updates.at(-1)?.phase).toBe("failed");
  expect(requests).toBe(1);
  expect(selected).toBe(false);
  expect(existsSync(join(homeDir, ".0sec", "cloud.env"))).toBe(false);
});

it("prevents a cancelled late login from persisting or selecting Cloud", async () => {
  const homeDir = home();
  const entered = Promise.withResolvers<void>();
  const response = Promise.withResolvers<Response>();
  const updates: HostedDeviceAuthUpdate[] = [];
  let selected = false;
  const session = startHostedDeviceAuth({ homeDir, host: "http://localhost:1", openBrowser: () => {}, sleep: async () => {},
    fetchImpl: () => { entered.resolve(); return response.promise; },
    onUpdate: (update) => updates.push(update), onConnected: () => { selected = true; },
  });
  await entered.promise;
  session.cancel();
  const count = updates.length;
  response.resolve(Response.json({ status: "ready", token: "late-fixture-token" }));
  await new Promise<void>((resolve) => setImmediate(resolve));
  expect(selected).toBe(false);
  expect(updates.length).toBe(count);
  expect(existsSync(join(homeDir, ".0sec", "cloud.env"))).toBe(false);
});

it("reads only the supplied credential environment and returns no secret metadata", () => {
  const homeDir = home();
  vi.stubEnv("0SEC_CLOUD_TOKEN", "ambient-must-not-leak");
  expect(readHostedConnection({}, homeDir)).toEqual({ configured: false });
  const result = readHostedConnection({ "0SEC_CLOUD_TOKEN": "explicit-fixture-token", "0SEC_CLOUD_HOST": "http://localhost:41000" }, homeDir);
  expect(result).toMatchObject({ configured: true, host: "http://localhost:41000" });
  expect(JSON.stringify(result)).not.toContain("token");
});
