/**
 * OAST collaborator implementations (pwnkit#659).
 *
 * Three shapes behind the one `OastCollaborator` interface:
 *
 *  - `OastStore` — the in-memory register/record/poll core. Shared by the
 *    in-memory collaborator (tests, single-host loopback scans) AND the
 *    self-hostable server in `server.ts`, so both agree on token minting and
 *    correlation.
 *  - `InMemoryCollaborator` — reference implementation + test double. Lets unit
 *    tests inject interactions and exercise the oracle end-to-end with no
 *    network. Also usable for same-host verify sandboxes that can reach the
 *    engine process directly.
 *  - `HttpCollaborator` — the deployable adapter. Talks to a self-hosted
 *    collaborator server (see `server.ts`) over a tiny documented REST contract.
 *    This is what production uses once the server is deployed with a wildcard
 *    DNS zone; the URL comes from `PWNKIT_OAST_URL`.
 *
 * `createCollaborator()` picks the adapter from config/env and returns
 * `undefined` when nothing is configured — the feature stays dark until a real
 * collaborator is deployed, rather than silently pretending to work.
 */

import { randomUUID } from "node:crypto";
import type {
  OastCollaborator,
  OastHandle,
  OastInteraction,
  OastProbe,
} from "./types.js";
import { normalizeLabel } from "./oracle.js";

const DEFAULT_BASE_DOMAIN = "oast.0sec.ai";

/** Mint a lowercase [a-z0-9] correlation token. */
function mintToken(): string {
  return randomUUID().replace(/-/g, "").slice(0, 20);
}

/**
 * Derive a per-candidate probe from a handle. Pure string-building: the agent
 * embeds `nonce` as an extra leading label + path segment so a later hit is
 * provably tied to THIS candidate (see `oracle.confirmOast`). Nonce is
 * normalized to the same DNS label the oracle matches on.
 */
export function deriveProbe(handle: OastHandle, nonce: string): OastProbe {
  const label = normalizeLabel(nonce) || "x";
  const host = `${label}.${handle.host}`;
  return {
    nonce: label,
    host,
    httpUrl: `http://${host}/${label}`,
    dnsHost: host,
  };
}

/**
 * In-memory register/record/poll core. Not an `OastCollaborator` itself (it's
 * synchronous and record-capable); the collaborator + server wrap it.
 */
export class OastStore {
  private readonly baseDomain: string;
  private counter = 0;
  private readonly mint: () => string;
  /** token → handle. */
  private readonly handles = new Map<string, OastHandle>();
  /** token → interactions recorded under it (or any of its sub-labels). */
  private readonly interactions = new Map<string, OastInteraction[]>();

  constructor(opts: { baseDomain?: string; mintToken?: () => string } = {}) {
    this.baseDomain = opts.baseDomain ?? DEFAULT_BASE_DOMAIN;
    this.mint = opts.mintToken ?? mintToken;
  }

  register(): OastHandle {
    const token = this.mint();
    const host = `${token}.${this.baseDomain}`;
    const handle: OastHandle = {
      id: `oast-${++this.counter}`,
      token,
      host,
      httpUrl: `http://${host}/`,
      dnsHost: host,
      createdAt: new Date().toISOString(),
    };
    this.handles.set(token, handle);
    this.interactions.set(token, []);
    return handle;
  }

  /**
   * Record an interaction. Routing is by token substring: any registered token
   * that appears in the interaction's addressable fields gets the hit. This
   * mirrors what a real DNS/HTTP collaborator does — it can't know which handle
   * a QNAME belongs to except by the embedded token — and lets one recorded
   * callback confirm a handle even when the agent added per-candidate labels.
   */
  record(interaction: OastInteraction): void {
    const text = [interaction.queryName, interaction.path ?? "", interaction.raw ?? ""]
      .join(" ")
      .toLowerCase();
    for (const token of this.handles.keys()) {
      if (text.includes(token)) {
        this.interactions.get(token)!.push(interaction);
      }
    }
  }

  poll(token: string): OastInteraction[] {
    return [...(this.interactions.get(token) ?? [])];
  }

  get domain(): string {
    return this.baseDomain;
  }
}

/**
 * Reference collaborator backed by an in-process `OastStore`. Tests use
 * `inject()` to simulate a callback the hosted server would have recorded.
 */
export class InMemoryCollaborator implements OastCollaborator {
  private readonly store: OastStore;

  constructor(opts: { baseDomain?: string; mintToken?: () => string } = {}) {
    this.store = new OastStore(opts);
  }

  get baseDomain(): string {
    return this.store.domain;
  }

  async register(): Promise<OastHandle> {
    return this.store.register();
  }

  async poll(handle: OastHandle): Promise<OastInteraction[]> {
    return this.store.poll(handle.token);
  }

  /** Test/local helper: feed in an interaction the way a real server would. */
  inject(interaction: OastInteraction): void {
    this.store.record(interaction);
  }
}

/**
 * Adapter to a self-hosted collaborator server (see `server.ts`) over a tiny
 * REST contract:
 *
 *   POST <base>/register            → { token, host, httpUrl?, dnsHost?, id?, createdAt? }
 *   GET  <base>/poll/<token>        → { interactions: OastInteraction[] }
 *
 * Fields the server omits are filled in client-side, so the adapter tolerates a
 * minimal server. Network/parse errors surface as thrown errors the tool layer
 * turns into a graceful "collaborator unreachable" result.
 */
export class HttpCollaborator implements OastCollaborator {
  readonly baseDomain: string;
  private readonly base: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: {
    serverUrl: string;
    baseDomain?: string;
    fetchImpl?: typeof fetch;
    timeoutMs?: number;
  }) {
    this.base = opts.serverUrl.replace(/\/+$/, "");
    // If the caller didn't state the callback domain explicitly, fall back to
    // the server URL's host — the collaborator answers DNS for its own zone.
    this.baseDomain = opts.baseDomain ?? hostOf(this.base) ?? DEFAULT_BASE_DOMAIN;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
  }

  async register(): Promise<OastHandle> {
    const data = await this.request<Partial<OastHandle> & { token?: string; host?: string }>(
      "POST",
      "/register",
    );
    const token = data.token;
    if (!token) throw new Error("collaborator /register returned no token");
    const host = data.host ?? `${token}.${this.baseDomain}`;
    return {
      id: data.id ?? `oast-${token.slice(0, 8)}`,
      token,
      host,
      httpUrl: data.httpUrl ?? `http://${host}/`,
      dnsHost: data.dnsHost ?? host,
      createdAt: data.createdAt ?? new Date().toISOString(),
    };
  }

  async poll(handle: OastHandle): Promise<OastInteraction[]> {
    const data = await this.request<{ interactions?: OastInteraction[] }>(
      "GET",
      `/poll/${encodeURIComponent(handle.token)}`,
    );
    return Array.isArray(data.interactions) ? data.interactions : [];
  }

  private async request<T>(method: string, path: string): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    // Never let this guard timer keep the event loop (or a vitest worker) alive
    // on its own; it's cleared in `finally` anyway, this is belt-and-suspenders.
    timer.unref?.();
    try {
      const res = await this.fetchImpl(`${this.base}${path}`, {
        method,
        signal: controller.signal,
        headers: { accept: "application/json" },
      });
      if (!res.ok) {
        throw new Error(`collaborator ${method} ${path} → HTTP ${res.status}`);
      }
      return (await res.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Build the collaborator for a scan from config/env. Precedence:
 *  1. explicit `serverUrl` (or `PWNKIT_OAST_URL`) → `HttpCollaborator`
 *  2. otherwise `undefined` — no collaborator; blind-class tools return a
 *     graceful "not deployed" result instead of faking hits.
 *
 * `PWNKIT_OAST_DOMAIN` overrides the callback base domain when the server's
 * DNS zone differs from its HTTP host (the common deployment shape).
 */
export function createCollaborator(opts: {
  serverUrl?: string;
  baseDomain?: string;
} = {}): OastCollaborator | undefined {
  const serverUrl = opts.serverUrl ?? process.env.PWNKIT_OAST_URL;
  if (!serverUrl) return undefined;
  const baseDomain = opts.baseDomain ?? process.env.PWNKIT_OAST_DOMAIN;
  return new HttpCollaborator({ serverUrl, baseDomain });
}
