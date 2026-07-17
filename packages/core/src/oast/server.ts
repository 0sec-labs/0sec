/**
 * Self-hostable OAST collaborator server — SCAFFOLD (pwnkit#659).
 *
 * This is the server side of the `HttpCollaborator` REST contract plus the
 * wildcard HTTP-vhost that records blind callbacks. It is intentionally a
 * scaffold: the *routing + correlation* logic is complete and unit-tested via
 * the pure `handleOastRequest`, but a production deployment still needs, as
 * FOLLOW-UP (out of scope for this PR):
 *
 *   - A wildcard DNS zone `*.oast.0sec.ai` delegated to an authoritative
 *     resolver that logs every QNAME and POSTs it to `/ingest/dns` (the DNS
 *     channel that confirms OOB-SQLi / DNS-only SSRF). A pure Node HTTP server
 *     cannot answer DNS; that front-end is a separate process.
 *   - TLS + a real hostname, run where verify sandboxes can egress to it.
 *   - Durable storage + eviction (this scaffold keeps interactions in memory).
 *
 * REST contract (mirrors `collaborator.ts` HttpCollaborator):
 *   POST /register          → { id, token, host, httpUrl, dnsHost, createdAt }
 *   GET  /poll/<token>      → { interactions: OastInteraction[] }
 *   POST /ingest/dns        → { queryName, remoteAddress?, raw?, timestamp? }
 *                             (called by the DNS front-end) → { recorded }
 *   ANY  /<anything>        → treated as a blind HTTP callback to the wildcard
 *                             vhost; the Host header carries the token as a
 *                             subdomain and is recorded as an http interaction.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import type { OastInteraction } from "./types.js";
import { OastStore } from "./collaborator.js";

export interface OastRequest {
  method: string;
  /** Request path + query (`req.url`). */
  url: string;
  /** Host header — carries the token/nonce subdomain for wildcard callbacks. */
  host: string;
  remoteAddress?: string;
  /** Parsed JSON body, for POST /ingest/dns. */
  body?: unknown;
}

export interface OastServerResponse {
  status: number;
  json: unknown;
}

/**
 * Pure request router. No sockets — takes a normalized request, mutates the
 * store, returns a status + JSON. This is the unit-testable heart of the
 * server; `createOastServer` is a thin node-http shell over it.
 */
export function handleOastRequest(store: OastStore, req: OastRequest): OastServerResponse {
  const path = req.url.split("?")[0];

  if (req.method === "POST" && path === "/register") {
    return { status: 200, json: store.register() };
  }

  if (req.method === "GET" && path.startsWith("/poll/")) {
    const token = decodeURIComponent(path.slice("/poll/".length));
    return { status: 200, json: { interactions: store.poll(token) } };
  }

  if (req.method === "POST" && path === "/ingest/dns") {
    const body = (req.body ?? {}) as Partial<OastInteraction>;
    if (!body.queryName) {
      return { status: 400, json: { error: "queryName required" } };
    }
    const interaction: OastInteraction = {
      protocol: "dns",
      timestamp: body.timestamp ?? new Date().toISOString(),
      queryName: body.queryName,
      remoteAddress: body.remoteAddress,
      raw: body.raw ?? `DNS ${body.queryName}`,
    };
    store.record(interaction);
    return { status: 200, json: { recorded: true } };
  }

  // Anything else is a blind HTTP callback to the wildcard vhost. The Host
  // header carries the token (and any nonce) as subdomain labels; record it.
  const interaction: OastInteraction = {
    protocol: "http",
    timestamp: new Date().toISOString(),
    queryName: req.host,
    path: req.url,
    method: req.method,
    remoteAddress: req.remoteAddress,
    raw: `${req.method} ${req.url} Host: ${req.host}`,
  };
  store.record(interaction);
  return { status: 200, json: { ok: true } };
}

/** Read a request body as JSON (best-effort; empty/invalid → undefined). */
function readJsonBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > 1_000_000) return; // 1 MB guard
      chunks.push(c);
    });
    req.on("end", () => {
      if (chunks.length === 0) return resolve(undefined);
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        resolve(undefined);
      }
    });
    req.on("error", () => resolve(undefined));
  });
}

/**
 * Build (but do not listen on) a node-http collaborator server over `store`.
 * Callers `.listen()` it, then `close()` to tear it down — the returned
 * `close()` awaits the socket fully closing, so tests/callers never leak an
 * open handle. Deployment concerns (TLS, DNS front-end, persistence) are
 * follow-up — see the file header.
 */
export function createOastServer(opts: { baseDomain?: string; store?: OastStore } = {}): {
  server: Server;
  store: OastStore;
  close: () => Promise<void>;
} {
  const store = opts.store ?? new OastStore({ baseDomain: opts.baseDomain });
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      const body = req.method === "POST" ? await readJsonBody(req) : undefined;
      const result = handleOastRequest(store, {
        method: req.method ?? "GET",
        url: req.url ?? "/",
        host: req.headers.host ?? "",
        remoteAddress: req.socket.remoteAddress ?? undefined,
        body,
      });
      res.writeHead(result.status, { "content-type": "application/json" });
      res.end(JSON.stringify(result.json));
    })();
  });
  const close = (): Promise<void> =>
    new Promise((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
  return { server, store, close };
}
