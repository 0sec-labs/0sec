/**
 * Issue #272 v0 — PoC fetcher.
 *
 * Pulls a CVE PoC artifact from one of three sources:
 *   - `github-raw` — `raw.githubusercontent.com` (or GitHub raw mirror)
 *   - `gist` — Gist `raw_url`
 *   - `inline-writeup` — an HTML writeup that embeds the PoC in the first
 *      fenced code block. The fetcher extracts that block.
 *
 * Safety budget (tested):
 *   1. Refuse files > 1 MiB (`MAX_POC_BYTES`).
 *   2. Refuse non-text content (`Content-Type` must start with `text/` or
 *      be a known JSON/JS/Python/shell type; binary types are blocked).
 *   3. Sandbox the extension to one of `.c`, `.py`, `.sh`, `.syz` based on
 *      the candidate's declared language.
 *
 * Caching:
 *   - One file per (url → sha256) under `<cacheDir>/<sha256>.<ext>`.
 *   - A sidecar `<sha256>.meta.json` records the fetched-at timestamp and
 *     source URL so re-fetches across runs are cheap.
 *   - If a re-fetch produces a different sha than the cached version, we
 *     overwrite the cache entry and log it (a callable mismatch handler).
 *
 * Network: respects `GITHUB_TOKEN`, otherwise unauthenticated.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { FetchedPoc, PocCandidate } from "./types.js";

/** Hard cap on a fetched PoC. v0 PoCs are tiny (~few KB) — 1 MiB is generous. */
export const MAX_POC_BYTES = 1 * 1024 * 1024;

/** Allowed extensions per declared language. Keeps writes off-path-safe. */
const LANG_EXT: Record<PocCandidate["language"], string> = {
  c: "c",
  py: "py",
  sh: "sh",
  syz: "syz",
};

/** Text-ish content types we accept from the wire. Anything else → reject. */
const TEXT_CONTENT_TYPES = [
  "text/",
  "application/json",
  "application/javascript",
  "application/x-sh",
  "application/x-shellscript",
  "application/x-python",
  "application/octet-stream", // GitHub raw sometimes serves this for plaintext
];

export interface FetchPocOptions {
  cacheDir?: string;
  /** Injection point for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Called when a re-fetch produces a different sha than the cached copy. */
  onShaMismatch?: (info: { url: string; oldSha: string; newSha: string }) => void;
  /** Override the GitHub token used for auth (defaults to `GITHUB_TOKEN`). */
  githubToken?: string;
  /** Override `Date.now()` for deterministic timestamps in tests. */
  now?: () => Date;
}

export class PocFetchError extends Error {
  readonly kind:
    | "too-large"
    | "non-text"
    | "http"
    | "no-inline-block"
    | "extract"
    | "network";
  constructor(kind: PocFetchError["kind"], message: string) {
    super(message);
    this.name = "PocFetchError";
    this.kind = kind;
  }
}

function defaultCacheDir(): string {
  return process.env.PWNKIT_CVE_POC_CACHE?.trim() || join(homedir(), ".pwnkit", "cve-pocs");
}

function buildHeaders(token?: string): Record<string, string> {
  const headers: Record<string, string> = {
    "Accept": "*/*",
    "User-Agent": "pwnkit-cve-adapt/0.1",
  };
  const resolved = token ?? process.env.GITHUB_TOKEN?.trim();
  if (resolved) headers["Authorization"] = `Bearer ${resolved}`;
  return headers;
}

function isTextContentType(contentType: string | null): boolean {
  if (!contentType) return true; // many raw hosts don't set content-type
  const lower = contentType.toLowerCase();
  return TEXT_CONTENT_TYPES.some((prefix) => lower.includes(prefix));
}

/**
 * Pull the first fenced code block out of an HTML writeup.
 *
 * Matches both `<pre><code>…</code></pre>` and triple-backtick markdown
 * blocks served inline. Returns the decoded text or throws.
 */
export function extractInlineCodeBlock(html: string): string {
  // Markdown-style first: ```lang\n …code… \n```
  const fenced = /```(?:[a-zA-Z0-9_+-]*)\n([\s\S]*?)\n?```/m.exec(html);
  if (fenced && fenced[1]) {
    return fenced[1];
  }
  // HTML <pre><code>…</code></pre>
  const htmlBlock = /<pre[^>]*>\s*<code[^>]*>([\s\S]*?)<\/code>\s*<\/pre>/i.exec(html);
  if (htmlBlock && htmlBlock[1]) {
    return decodeHtmlEntities(htmlBlock[1]);
  }
  // Bare <pre>…</pre>
  const preBlock = /<pre[^>]*>([\s\S]*?)<\/pre>/i.exec(html);
  if (preBlock && preBlock[1]) {
    return decodeHtmlEntities(preBlock[1]);
  }
  throw new PocFetchError("no-inline-block", "no fenced code block found in writeup");
}

function decodeHtmlEntities(input: string): string {
  return input
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&");
}

function sha256(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function cacheEntryPaths(cacheDir: string, sha: string, ext: string): { source: string; meta: string } {
  return {
    source: join(cacheDir, `${sha}.${ext}`),
    meta: join(cacheDir, `${sha}.meta.json`),
  };
}

/**
 * Look up a cache entry by URL (not sha). The cache is sha-keyed for
 * content integrity, but callers identify by URL — so we maintain a
 * `<urlHash>.url.json` pointer that stores the most recent sha for a URL.
 */
function urlPointerPath(cacheDir: string, url: string): string {
  return join(cacheDir, `${sha256(url).slice(0, 24)}.url.json`);
}

interface UrlPointer {
  url: string;
  sha256: string;
  ext: string;
  fetched_at: string;
}

function readUrlPointer(cacheDir: string, url: string): UrlPointer | null {
  const path = urlPointerPath(cacheDir, url);
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf-8")) as UrlPointer;
    if (parsed.url !== url) return null;
    return parsed;
  } catch {
    return null;
  }
}

function writeUrlPointer(cacheDir: string, pointer: UrlPointer): void {
  writeFileSync(urlPointerPath(cacheDir, pointer.url), JSON.stringify(pointer, null, 2), "utf-8");
}

/**
 * Fetch a PoC candidate, honoring the safety budget. Returns the on-disk
 * `local_path` (sha-keyed inside `cacheDir`) plus metadata.
 */
export async function fetchPoc(
  candidate: PocCandidate,
  opts: FetchPocOptions = {},
): Promise<FetchedPoc> {
  const cacheDir = opts.cacheDir ?? defaultCacheDir();
  mkdirSync(cacheDir, { recursive: true });
  const now = opts.now ?? (() => new Date());
  const fetchImpl = opts.fetchImpl ?? fetch;

  // Cache hit lookup (by URL, then validate sha on disk).
  const pointer = readUrlPointer(cacheDir, candidate.url);
  if (pointer) {
    const { source } = cacheEntryPaths(cacheDir, pointer.sha256, pointer.ext);
    if (existsSync(source)) {
      const bytes = readFileSync(source);
      if (sha256(bytes) === pointer.sha256) {
        return {
          local_path: source,
          language: candidate.language,
          sha256: pointer.sha256,
          source_url: candidate.url,
          fetched_at: pointer.fetched_at,
        };
      }
      // sha mismatch on disk — drop through to refetch
    }
  }

  // ── Network fetch ─────────────────────────────────────────────
  let response: Response;
  try {
    response = await fetchImpl(candidate.url, {
      method: "GET",
      headers: buildHeaders(opts.githubToken),
    });
  } catch (err) {
    throw new PocFetchError(
      "network",
      `network error fetching ${candidate.url}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (!response.ok) {
    throw new PocFetchError(
      "http",
      `HTTP ${response.status} fetching ${candidate.url}: ${response.statusText}`,
    );
  }

  // Early reject: declared content length is over budget. (Some hosts
  // omit Content-Length; we still check the actual bytes below.)
  const contentLength = response.headers.get("content-length");
  if (contentLength && parseInt(contentLength, 10) > MAX_POC_BYTES) {
    throw new PocFetchError(
      "too-large",
      `PoC at ${candidate.url} is ${contentLength} bytes (cap ${MAX_POC_BYTES})`,
    );
  }

  const contentType = response.headers.get("content-type");
  if (!isTextContentType(contentType)) {
    throw new PocFetchError(
      "non-text",
      `PoC at ${candidate.url} has non-text content-type: ${contentType}`,
    );
  }

  const buf = Buffer.from(await response.arrayBuffer());
  if (buf.byteLength > MAX_POC_BYTES) {
    throw new PocFetchError(
      "too-large",
      `PoC at ${candidate.url} is ${buf.byteLength} bytes (cap ${MAX_POC_BYTES})`,
    );
  }

  let payload = buf.toString("utf-8");
  if (candidate.source === "inline-writeup") {
    try {
      payload = extractInlineCodeBlock(payload);
    } catch (err) {
      if (err instanceof PocFetchError) throw err;
      throw new PocFetchError("extract", `failed to extract inline code block: ${String(err)}`);
    }
  }

  const newSha = sha256(payload);
  const ext = LANG_EXT[candidate.language];
  const { source } = cacheEntryPaths(cacheDir, newSha, ext);

  if (pointer && pointer.sha256 !== newSha && opts.onShaMismatch) {
    opts.onShaMismatch({ url: candidate.url, oldSha: pointer.sha256, newSha });
  }

  writeFileSync(source, payload, "utf-8");
  const fetched_at = now().toISOString();
  writeUrlPointer(cacheDir, { url: candidate.url, sha256: newSha, ext, fetched_at });

  return {
    local_path: source,
    language: candidate.language,
    sha256: newSha,
    source_url: candidate.url,
    fetched_at,
  };
}
