import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { AddressInfo } from "node:net";
import { request as httpRequest } from "node:http";
import {
  OastStore,
  InMemoryCollaborator,
  HttpCollaborator,
  createCollaborator,
  deriveProbe,
} from "./collaborator.js";
import { handleOastRequest, createOastServer } from "./server.js";
import { confirmOast } from "./oracle.js";
import type { OastHandle } from "./types.js";

/** Deterministic token minter for reproducible tests. */
function seqMint(): () => string {
  let n = 0;
  return () => `tok${(++n).toString().padStart(4, "0")}`;
}

describe("OastStore", () => {
  it("mints unique handles under the base domain", () => {
    const store = new OastStore({ baseDomain: "oast.test", mintToken: seqMint() });
    const h1 = store.register();
    const h2 = store.register();
    expect(h1.host).toBe("tok0001.oast.test");
    expect(h2.host).toBe("tok0002.oast.test");
    expect(h1.httpUrl).toBe("http://tok0001.oast.test/");
    expect(h1.id).not.toBe(h2.id);
  });

  it("routes a recorded interaction to the handle whose token it carries", () => {
    const store = new OastStore({ baseDomain: "oast.test", mintToken: seqMint() });
    const h1 = store.register();
    const h2 = store.register();
    store.record({ protocol: "dns", timestamp: "t", queryName: `${h1.token}.oast.test` });
    expect(store.poll(h1.token)).toHaveLength(1);
    expect(store.poll(h2.token)).toHaveLength(0);
  });

  it("routes a callback carrying a per-candidate nonce label to the base handle", () => {
    const store = new OastStore({ baseDomain: "oast.test", mintToken: seqMint() });
    const h = store.register();
    const probe = deriveProbe(h, "cand-9");
    store.record({ protocol: "http", timestamp: "t", queryName: probe.host, path: `/${probe.nonce}` });
    expect(store.poll(h.token)).toHaveLength(1);
  });
});

describe("deriveProbe", () => {
  it("builds a nonce-labelled sub-host and path", () => {
    const handle: OastHandle = {
      id: "oast-1",
      token: "tok0001",
      host: "tok0001.oast.test",
      httpUrl: "http://tok0001.oast.test/",
      dnsHost: "tok0001.oast.test",
      createdAt: "t",
    };
    const p = deriveProbe(handle, "Cand_9!");
    expect(p.nonce).toBe("cand9");
    expect(p.host).toBe("cand9.tok0001.oast.test");
    expect(p.httpUrl).toBe("http://cand9.tok0001.oast.test/cand9");
  });
});

describe("InMemoryCollaborator", () => {
  it("registers, records an injected hit, and confirms via the oracle", async () => {
    const c = new InMemoryCollaborator({ baseDomain: "oast.test", mintToken: seqMint() });
    const handle = await c.register();
    // no hit yet
    expect(await c.poll(handle)).toHaveLength(0);
    // simulate the server recording a DNS callback for this handle
    c.inject({ protocol: "dns", timestamp: "t", queryName: `${handle.token}.oast.test` });
    const interactions = await c.poll(handle);
    const verdict = confirmOast({ oastClass: "blind-ssrf", token: handle.token, interactions });
    expect(verdict.verified).toBe(true);
  });
});

describe("handleOastRequest (server router)", () => {
  it("serves /register and /poll and records a wildcard HTTP callback", () => {
    const store = new OastStore({ baseDomain: "oast.test", mintToken: seqMint() });

    const reg = handleOastRequest(store, { method: "POST", url: "/register", host: "oast.test" });
    expect(reg.status).toBe(200);
    const handle = reg.json as OastHandle;
    expect(handle.token).toBe("tok0001");

    // a blind HTTP callback hits the wildcard vhost
    const cb = handleOastRequest(store, {
      method: "GET",
      url: "/beacon",
      host: `${handle.token}.oast.test`,
      remoteAddress: "203.0.113.9",
    });
    expect(cb.status).toBe(200);

    const poll = handleOastRequest(store, {
      method: "GET",
      url: `/poll/${handle.token}`,
      host: "oast.test",
    });
    const { interactions } = poll.json as { interactions: unknown[] };
    expect(interactions).toHaveLength(1);
  });

  it("ingests a DNS log line from the front-end", () => {
    const store = new OastStore({ baseDomain: "oast.test", mintToken: seqMint() });
    const handle = store.register();
    const res = handleOastRequest(store, {
      method: "POST",
      url: "/ingest/dns",
      host: "oast.test",
      body: { queryName: `${handle.token}.oast.test`, remoteAddress: "198.51.100.2" },
    });
    expect(res.status).toBe(200);
    expect(store.poll(handle.token)).toHaveLength(1);
  });

  it("rejects a DNS ingest without a queryName", () => {
    const store = new OastStore({ baseDomain: "oast.test" });
    const res = handleOastRequest(store, { method: "POST", url: "/ingest/dns", host: "oast.test", body: {} });
    expect(res.status).toBe(400);
  });
});

describe("HttpCollaborator", () => {
  it("registers and polls against a fake server over the REST contract", async () => {
    const store = new OastStore({ baseDomain: "oast.test", mintToken: seqMint() });
    // Wire a fake fetch straight into the pure server router.
    const fakeFetch = (async (input: string | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      const res = handleOastRequest(store, {
        method: init?.method ?? "GET",
        url: url.pathname,
        host: url.host,
      });
      return new Response(JSON.stringify(res.json), {
        status: res.status,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;

    const c = new HttpCollaborator({
      serverUrl: "http://collab.test",
      baseDomain: "oast.test",
      fetchImpl: fakeFetch,
    });
    const handle = await c.register();
    expect(handle.token).toBe("tok0001");
    // record a callback directly, then poll through the adapter
    store.record({ protocol: "http", timestamp: "t", queryName: `${handle.token}.oast.test`, path: "/x" });
    const interactions = await c.poll(handle);
    expect(interactions).toHaveLength(1);
  });

  it("throws HTTP errors so the tool layer can degrade gracefully", async () => {
    const failing = (async () => new Response("nope", { status: 502 })) as unknown as typeof fetch;
    const c = new HttpCollaborator({ serverUrl: "http://collab.test", fetchImpl: failing });
    await expect(c.register()).rejects.toThrow(/HTTP 502/);
  });
});

describe("createCollaborator", () => {
  it("returns undefined when nothing is configured", () => {
    const prev = process.env.PWNKIT_OAST_URL;
    delete process.env.PWNKIT_OAST_URL;
    expect(createCollaborator()).toBeUndefined();
    if (prev !== undefined) process.env.PWNKIT_OAST_URL = prev;
  });

  it("builds an HttpCollaborator when a server URL is given", () => {
    const c = createCollaborator({ serverUrl: "https://oast.0sec.ai", baseDomain: "oast.0sec.ai" });
    expect(c).toBeInstanceOf(HttpCollaborator);
    expect(c?.baseDomain).toBe("oast.0sec.ai");
  });
});

// End-to-end over a REAL listening node-http server. Beyond covering the true
// network path (register → blind HTTP callback → poll → confirm), this pins the
// server's cleanup contract: afterAll awaits `close()`, so a regression that
// leaked the listening socket would surface as a hung/timed-out worker here
// rather than silently keeping a vitest worker alive.
describe("createOastServer end-to-end (lifecycle + no leaked handle)", () => {
  let handle: { server: import("node:http").Server; close: () => Promise<void>; store: OastStore };
  let port: number;

  beforeAll(async () => {
    handle = createOastServer({ baseDomain: "oast.test" });
    await new Promise<void>((resolve) => handle.server.listen(0, "127.0.0.1", resolve));
    port = (handle.server.address() as AddressInfo).port;
  });

  afterAll(async () => {
    // Force-destroy any lingering sockets before close so teardown can't stall
    // past vitest's worker timeout ("Timeout calling onTaskUpdate") and no
    // handle outlives the suite.
    handle.server.closeAllConnections?.();
    await handle.close();
  });

  // Fire a GET at the loopback server via node:http with an options object (no
  // dynamic-URL fetch — keeps this off foxguard's SSRF rule) and the default
  // non-keep-alive agent, so the socket closes right after the response.
  function beacon(path: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const req = httpRequest({ host: "127.0.0.1", port, path, method: "GET" }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode ?? 0));
      });
      req.on("error", reject);
      req.end();
    });
  }

  it("registers, records a real HTTP callback, and confirms via the adapter", async () => {
    const collaborator = new HttpCollaborator({ serverUrl: `http://127.0.0.1:${port}`, baseDomain: "oast.test" });
    const registered = await collaborator.register();

    // No callback yet.
    expect(await collaborator.poll(registered)).toHaveLength(0);

    // Blind HTTP callback carrying the token in the path (a real beacon carries
    // it as a Host subdomain; the store/oracle match the token across the path
    // too, which is what a curl'd `http://<token>.oast.test/` collapses to once
    // recorded).
    expect(await beacon(`/${registered.token}/beacon`)).toBe(200);

    const interactions = await collaborator.poll(registered);
    expect(interactions).toHaveLength(1);
    const verdict = confirmOast({
      oastClass: "blind-ssrf",
      token: registered.token,
      interactions,
    });
    expect(verdict.verified).toBe(true);
    expect(verdict.protocol).toBe("http");
  });
});
