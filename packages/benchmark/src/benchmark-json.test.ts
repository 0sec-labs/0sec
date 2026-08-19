import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { installBenchmarkJsonHandling } from "./benchmark-json.js";

const servers: Server[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  })));
});

async function startApp() {
  const app = express();
  installBenchmarkJsonHandling(app);
  app.post("/challenge", (req, res) => res.json({ messages: req.body?.messages ?? [] }));
  const server = app.listen(0);
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}/challenge`;
}

describe("installBenchmarkJsonHandling", () => {
  it("returns a concise 400 for malformed JSON and preserves subsequent requests", async () => {
    const url = await startApp();

    // foxguard: ignore[js/no-ssrf] URL is an ephemeral loopback server from startApp().
    const malformed = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not-json",
    });
    expect(malformed.status).toBe(400);
    await expect(malformed.json()).resolves.toEqual({ error: "malformed_json" });

    // foxguard: ignore[js/no-ssrf] URL is an ephemeral loopback server from startApp().
    const valid = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: ["still running"] }),
    });
    expect(valid.status).toBe(200);
    await expect(valid.json()).resolves.toEqual({ messages: ["still running"] });
  });
});
