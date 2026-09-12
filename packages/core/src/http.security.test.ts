import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { gzipSync } from "node:zlib";
import { fetchScoped } from "./http.js";
import { ScopePolicy } from "./scope/scope.js";

const dns = vi.hoisted(() => ({ lookup: vi.fn() }));
vi.mock("node:dns/promises", () => dns);

let server: Server;
let base: string;
let hits: Array<{ url: string; host?: string; authorization?: string; key?: string }>;
let serve: (req: IncomingMessage, res: ServerResponse) => void;

beforeEach(async () => {
  hits = [];
  dns.lookup.mockReset().mockResolvedValue([{ address: "127.0.0.1", family: 4 }]);
  serve = (_req, res) => { res.end("fixture"); };
  server = createServer((req, res) => {
    hits.push({ url: req.url!, host: req.headers.host, authorization: req.headers.authorization, key: req.headers["x-api-key"] as string | undefined });
    serve(req, res);
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});

afterEach(async () => {
  server.closeAllConnections();
  await new Promise<void>(resolve => server.close(() => resolve()));
});

describe("scoped HTTP physical network boundary", () => {
  it("binds absent scope to the base origin before resolving foreign hosts", async () => {
    await expect(fetchScoped("http://foreign.invalid/", {}, { baseUrl: base })).rejects.toThrow(/Cross-origin/);
    expect(dns.lookup).not.toHaveBeenCalled();
    expect(hits).toEqual([]);
  });

  it("admits no-target public HTTP only with host opt-in, without granting private DNS access", async () => {
    const admitted = new Error("admitted public DNS answer");
    dns.lookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    await expect(fetchScoped("https://public.invalid/", {}, {
      baseUrl: "", allowPublicNetwork: true,
      beforeRequest: () => { throw admitted; },
    })).rejects.toBe(admitted);
    dns.lookup.mockClear();
    await expect(fetchScoped("https://public.invalid/", {}, { baseUrl: "" })).rejects.toThrow();
    expect(dns.lookup).not.toHaveBeenCalled();
    dns.lookup.mockResolvedValue([{ address: "127.0.0.1", family: 4 }]);
    await expect(fetchScoped("https://public.invalid/", {}, {
      baseUrl: "", allowPublicNetwork: true,
    })).rejects.toThrow(/Local\/internal DNS/);
    await expect(fetchScoped(base, {}, { baseUrl: "", allowPublicNetwork: true })).rejects.toThrow(/Local\/internal HTTP/);
    expect(hits).toEqual([]);
  });

  it("enforces explicit restrictions and denial memory at redirects under public opt-in", async () => {
    serve = (_req, res) => { res.writeHead(302, { Location: "https://denied.invalid/" }).end(); };
    await expect(fetchScoped(base, { redirect: "follow" }, {
      baseUrl: base, allowPublicNetwork: true, deniedHosts: new Set(["denied.invalid"]),
    })).rejects.toThrow(/Operator-denied/);
    expect(hits.map(hit => hit.url)).toEqual(["/"]);
    await expect(fetchScoped("https://outside.invalid/", {}, {
      baseUrl: "", allowPublicNetwork: true,
      scope: ScopePolicy.fromJson({ in_scope: ["allowed.invalid"] }),
    })).rejects.toThrow(/Scope violation/);
    expect(dns.lookup).not.toHaveBeenCalled();
  });

  it("rejects public-looking DNS targets with any private answer before a socket", async () => {
    dns.lookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }, { address: "127.0.0.1", family: 4 }]);
    const target = `http://public.invalid:${new URL(base).port}/`;
    await expect(fetchScoped(target, {}, { baseUrl: target, timeoutMs: 500 })).rejects.toThrow(/Local\/internal DNS/);
    expect(hits).toEqual([]);
  });

  it("blocks unspecified DNS destinations instead of reaching a local listener", async () => {
    dns.lookup.mockResolvedValue([{ address: "0.0.0.0", family: 4 }]);
    const target = `http://public.invalid:${new URL(base).port}/`;
    await expect(fetchScoped(target, {}, { baseUrl: target })).rejects.toThrow(/Local\/internal DNS/);
    expect(hits).toEqual([]);
  });

  it("keeps the private floor for IPv4 addresses encoded as IPv6 DNS answers", async () => {
    dns.lookup.mockResolvedValue([{ address: "::ffff:7f00:1", family: 6 }]);
    const target = `http://public.invalid:${new URL(base).port}/`;
    await expect(fetchScoped(target, {}, { baseUrl: target })).rejects.toThrow(/Local\/internal DNS/);
    expect(hits).toEqual([]);
  });

  it("honors equivalent native IPv6 exclusions before dispatch admission", async () => {
    dns.lookup.mockResolvedValue([{ address: "2606:4700:4700::1111", family: 6 }]);
    const target = "http://public.invalid/";
    const scope = ScopePolicy.fromJson({
      in_scope: ["public.invalid"],
      out_of_scope: ["2606:4700:4700::1111"],
    });
    await expect(fetchScoped(target, {}, {
      baseUrl: target, scope,
      beforeRequest: () => { throw new Error("excluded address reached dispatch admission"); },
    })).rejects.toThrow(/excluded by scope/);
    expect(hits).toEqual([]);
  });

  it("pins the validated answer and keeps URL Host authority, not caller Host", async () => {
    dns.lookup.mockResolvedValueOnce([{ address: "127.0.0.1", family: 4 }]).mockRejectedValue(new Error("DNS changed after authorization"));
    const target = `http://pinned.invalid:${new URL(base).port}/`;
    const scope = ScopePolicy.fromJson({ in_scope: ["pinned.invalid"] });
    const response = await fetchScoped(target, { headers: { Host: "foreign.invalid" } }, { baseUrl: base, scope });
    expect(await response.text()).toBe("fixture");
    expect(hits).toEqual([{ url: "/", host: new URL(target).host, authorization: undefined, key: undefined }]);
    expect(dns.lookup).toHaveBeenCalledTimes(1);
  });

  it("keeps explicit private anchors usable but honors mapped-address exclusions", async () => {
    expect(await (await fetchScoped(base, {}, { baseUrl: base })).text()).toBe("fixture");
    const target = `http://[::ffff:127.0.0.1]:${new URL(base).port}/denied`;
    const scope = ScopePolicy.fromJson({ in_scope: [new URL(target).hostname], out_of_scope: ["127.0.0.1"] });
    await expect(fetchScoped(target, {}, { baseUrl: base, scope })).rejects.toThrow(/excluded by scope/);
    expect(hits).toHaveLength(1);
  });

  it("blocks a redirect before the denied destination receives a request", async () => {
    serve = (_req, res) => { res.writeHead(302, { Location: `http://foreign.invalid:${new URL(base).port}/outside` }).end(); };
    const scope = ScopePolicy.fromJson({ in_scope: ["127.0.0.1"], out_of_scope: ["foreign.invalid"] });
    await expect(fetchScoped(base, { redirect: "follow" }, { baseUrl: base, scope })).rejects.toThrow(/Scope violation/);
    expect(hits.map(hit => hit.url)).toEqual(["/"]);
    expect(dns.lookup).not.toHaveBeenCalled();
  });

  it("strips standard and custom credentials on approved cross-origin redirects", async () => {
    serve = (req, res) => {
      if (req.url === "/") res.writeHead(302, { Location: `http://second.invalid:${new URL(base).port}/final` }).end();
      else res.end("approved final response");
    };
    const scope = ScopePolicy.fromJson({ in_scope: ["127.0.0.1", "second.invalid"] });
    const response = await fetchScoped(base, { redirect: "follow", headers: { Authorization: "Bearer fixture", "X-Api-Key": "fixture-key" } }, { baseUrl: base, scope });
    expect(await response.text()).toBe("approved final response");
    expect(response.url).toBe(`http://second.invalid:${new URL(base).port}/final`);
    expect(hits.map(hit => [hit.authorization, hit.key])).toEqual([["Bearer fixture", "fixture-key"], [undefined, undefined]]);
  });

  it("rejects decoded response overflow without returning a truncated success", async () => {
    serve = (_req, res) => { res.writeHead(200, { "Content-Encoding": "gzip" }).end(gzipSync("x".repeat(1000))); };
    const response = await fetchScoped(base, {}, { baseUrl: base, maxResponseBytes: 32 });
    await expect(response.text()).rejects.toThrow(/exceeds 32 decoded bytes/);
  });

  it("decodes stacked content encodings and limits the fully decoded body", async () => {
    serve = (req, res) => {
      const text = req.url === "/large" ? "x".repeat(8192) : "stacked response";
      res.writeHead(200, { "Content-Encoding": "gzip, gzip" }).end(gzipSync(gzipSync(text)));
    };
    expect(await (await fetchScoped(base, {}, { baseUrl: base })).text()).toBe("stacked response");
    const response = await fetchScoped(`${base}/large`, {}, { baseUrl: base, maxResponseBytes: 128 });
    await expect(response.text()).rejects.toThrow(/exceeds 128 decoded bytes/);
  });

  it("closes the connection when response metadata cannot be represented", async () => {
    let closed = false;
    serve = (_req, res) => {
      res.once("close", () => { closed = true; });
      res.writeHead(600, { "Content-Length": "1000" });
      res.write("partial");
    };
    await expect(fetchScoped(base, {}, { baseUrl: base, timeoutMs: 20 })).rejects.toThrow();
    await new Promise(resolve => setTimeout(resolve, 50));
    expect(closed).toBe(true);
    expect(hits.map(hit => hit.url)).toEqual(["/"]);
  });

  it("propagates operator cancellation through a held body without replay", async () => {
    serve = (_req, res) => { res.writeHead(200); res.write("partial"); };
    const controller = new AbortController();
    const response = await fetchScoped(base, { signal: controller.signal }, { baseUrl: base });
    const body = response.text();
    controller.abort(new Error("operator cancelled fixture"));
    await expect(body).rejects.toThrow();
    expect(hits.map(hit => hit.url)).toEqual(["/"]);
  });

  it("ends a stalled DNS lookup at the request deadline without later dispatch", async () => {
    let release!: (value: Array<{ address: string; family: number }>) => void;
    dns.lookup.mockImplementation(() => new Promise(resolve => { release = resolve; }));
    const target = `http://delayed.invalid:${new URL(base).port}/`;
    const pending = fetchScoped(target, {}, { baseUrl: base, scope: ScopePolicy.fromJson({ in_scope: ["delayed.invalid"] }), timeoutMs: 20 });
    await expect(pending).rejects.toThrow(/timed out/);
    release([{ address: "127.0.0.1", family: 4 }]);
    await new Promise(resolve => setImmediate(resolve));
    expect(hits).toEqual([]);
  });

  it("rechecks caller authority after asynchronous admission before connecting", async () => {
    let authorized = true;
    await expect(fetchScoped(base, {}, {
      baseUrl: base,
      validateUrl: () => { if (!authorized) throw new Error("authority revoked"); },
      beforeRequest: async () => { authorized = false; },
    })).rejects.toThrow(/authority revoked/);
    expect(hits).toEqual([]);
  });
});
