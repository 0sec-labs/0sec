/**
 * Live OSV.dev advisory lookup — the production wiring for the dedup seam
 * (`AdvisoryLookup` in `./dedup.ts`).
 *
 * The dedup step needs to answer "does a PUBLIC advisory already cover this
 * confirmed bug?" so a real-but-known finding is not disclosed as novel. This
 * module implements that against the OSV.dev batch API
 * (`POST https://api.osv.dev/v1/querybatch`) — one HTTP round-trip per package
 * (plus any derivable fork/rename siblings), returning the advisory ids
 * (CVE/GHSA/OSV) that cover `name@version`.
 *
 * Design contract (load-bearing, mirrors the operator's calibration):
 *   - **Injectable transport.** `createOsvAdvisoryLookup({ fetchImpl })` takes an
 *     injectable `fetch`, so tests stay hermetic/offline and the live lookup is
 *     the production default. The detector stage / CLI wire
 *     `createOsvAdvisoryLookup()` (real `globalThis.fetch`); vitest passes a stub.
 *   - **Fail CLOSED, never blind-novel.** A rate-limit, timeout, non-2xx, or
 *     malformed response must NOT be reported as "no advisory found" (which the
 *     dedup would read as `novel`). On any unrecoverable lookup failure this
 *     THROWS `OsvLookupError`; `dedupConfirmation` catches it and records the
 *     verdict as `source: "unknown"` (possibly-known), identical to the offline
 *     path — a network hiccup can never manufacture a false novelty claim.
 *   - **Fork-twin coverage.** The sspp prototype learned the hard way that a
 *     fork/rename (`radash` ↔ `radashi` CVE-2025-48054) carries an advisory only
 *     under the sibling's name, so a name-scoped advisory DB gives a false
 *     all-clear. When obvious siblings are derivable, we ALSO query them and
 *     return their advisory ids (prefixed `sibling:<name>:<id>`) so the dedup
 *     marks the finding known. The reliable channel remains the detector's
 *     explicit `dedupHints.forkTwins`; this is a best-effort live net on top.
 *     `deriveForkSiblings` is intentionally conservative — over-suppression
 *     (a genuinely-novel bug getting a second look) is the safe failure
 *     direction here, blind-novel is not.
 */

import type { AdvisoryLookup } from "./dedup.js";

const DEFAULT_ENDPOINT = "https://api.osv.dev/v1/querybatch";
const DEFAULT_TIMEOUT_MS = 8_000;
/** Retries for transient failures (429 / 5xx / network) before failing closed. */
const DEFAULT_RETRIES = 1;
const RETRY_BACKOFF_MS = 400;

/** Thrown on any unrecoverable lookup failure. dedup treats this as "unknown". */
export class OsvLookupError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "OsvLookupError";
  }
}

export interface OsvLookupOptions {
  /** Injectable transport. Default: `globalThis.fetch`. Tests pass a stub. */
  fetchImpl?: typeof fetch;
  /** OSV batch endpoint. Default: `https://api.osv.dev/v1/querybatch`. */
  endpoint?: string;
  /** Per-request timeout (ms). Default 8000. */
  timeoutMs?: number;
  /** Transient-failure retries (429/5xx/network) before failing closed. Default 1. */
  retries?: number;
  /**
   * Derive obvious fork/rename siblings to ALSO query for the fork-twin case.
   * Default: {@link deriveForkSiblings}. Return `[]` to disable sibling querying.
   */
  deriveSiblings?: (name: string) => string[];
}

/** One `querybatch` query entry. `version` omitted ⇒ OSV returns all advisories. */
interface OsvBatchQuery {
  package: { ecosystem: "npm"; name: string };
  version?: string;
}

/** `querybatch` returns per-query results, index-aligned with the request. */
interface OsvBatchResponse {
  results?: Array<{ vulns?: Array<{ id?: string }> } | null | undefined>;
}

/**
 * Derive obvious fork/rename siblings whose PUBLIC advisory may cover identical
 * code that carries none under `name`. Conservative on purpose:
 *   - `lodash.merge` / `lodash.set` → `lodash` — the split single-method
 *     packages mirror the monorepo parent's advisories (a real, common pattern).
 *   - `@scope/pkg` → `pkg` — a scoped re-publish of an unscoped original. Never
 *     for `@types/*` (type stubs, not code twins).
 * Never returns `name` itself. Callers may override via `deriveSiblings`.
 */
export function deriveForkSiblings(name: string): string[] {
  const out = new Set<string>();

  // lodash-style dotted single-method packages: `lodash.merge` → `lodash`.
  const dotted = /^([a-z0-9][a-z0-9-]*)\.[a-z0-9.-]+$/.exec(name);
  if (dotted) out.add(dotted[1]);

  // Scoped re-publish: `@scope/pkg` → `pkg` (skip @types/* — not code twins).
  const scoped = /^@([a-z0-9][a-z0-9-]*)\/([a-z0-9][a-z0-9._-]*)$/.exec(name);
  if (scoped && scoped[1] !== "types") out.add(scoped[2]);

  out.delete(name);
  return [...out];
}

/**
 * Build a live OSV `AdvisoryLookup`. Returns advisory ids covering
 * `name@version` (empty ⇒ genuinely no advisory found ⇒ dedup may treat as
 * novel). THROWS `OsvLookupError` on any unrecoverable failure so the dedup
 * fails closed to `unknown` rather than blind-novel.
 */
export function createOsvAdvisoryLookup(options: OsvLookupOptions = {}): AdvisoryLookup {
  const endpoint = options.endpoint ?? DEFAULT_ENDPOINT;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const retries = options.retries ?? DEFAULT_RETRIES;
  const deriveSiblings = options.deriveSiblings ?? deriveForkSiblings;

  return async (name: string, version: string | undefined, _cwe: string): Promise<string[]> => {
    const fetchImpl = options.fetchImpl ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new OsvLookupError("no fetch implementation available for OSV lookup");
    }

    const siblings = deriveSiblings(name).filter((s) => s && s !== name);
    const queries: OsvBatchQuery[] = [
      { package: { ecosystem: "npm", name }, ...(version ? { version } : {}) },
      ...siblings.map((s) => ({ package: { ecosystem: "npm" as const, name: s } })),
    ];

    const data = await postBatch(fetchImpl, endpoint, { queries }, timeoutMs, retries);
    const results = data.results ?? [];

    const advisories: string[] = [];
    // Index 0 is always the primary package.
    for (const v of results[0]?.vulns ?? []) {
      if (v?.id) advisories.push(v.id);
    }
    // Remaining indices align with `siblings` order; tag so provenance is clear.
    siblings.forEach((sib, i) => {
      for (const v of results[i + 1]?.vulns ?? []) {
        if (v?.id) advisories.push(`sibling:${sib}:${v.id}`);
      }
    });

    return [...new Set(advisories)];
  };
}

async function postBatch(
  fetchImpl: typeof fetch,
  endpoint: string,
  body: { queries: OsvBatchQuery[] },
  timeoutMs: number,
  retries: number,
): Promise<OsvBatchResponse> {
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchImpl(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      // 429 / 5xx are transient — retry with backoff, then fail closed.
      if (res.status === 429 || res.status >= 500) {
        lastErr = new OsvLookupError(`OSV transient status ${res.status}`);
        if (attempt < retries) {
          await delay(RETRY_BACKOFF_MS * (attempt + 1));
          continue;
        }
        throw lastErr;
      }
      if (!res.ok) {
        throw new OsvLookupError(`OSV lookup failed: HTTP ${res.status}`);
      }
      const json = (await res.json()) as unknown;
      if (!json || typeof json !== "object" || !("results" in json)) {
        throw new OsvLookupError("OSV lookup returned a malformed response (no `results`)");
      }
      return json as OsvBatchResponse;
    } catch (err) {
      // Abort (timeout) and network errors are transient — retry, then fail closed.
      lastErr = err;
      const transient = isAbortOrNetwork(err);
      if (transient && attempt < retries) {
        await delay(RETRY_BACKOFF_MS * (attempt + 1));
        continue;
      }
      if (err instanceof OsvLookupError) throw err;
      throw new OsvLookupError(`OSV lookup errored: ${errMsg(err)}`, err);
    } finally {
      clearTimeout(timer);
    }
  }
  // Unreachable in practice, but keeps control-flow total.
  throw new OsvLookupError(`OSV lookup exhausted retries: ${errMsg(lastErr)}`, lastErr);
}

function isAbortOrNetwork(err: unknown): boolean {
  if (err instanceof OsvLookupError) return false;
  const name = (err as { name?: string })?.name;
  return name === "AbortError" || name === "TypeError" || err instanceof Error;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message.split("\n")[0].slice(0, 160) : String(e);
}
