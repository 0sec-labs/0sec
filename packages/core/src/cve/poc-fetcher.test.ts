import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fetchPoc, extractInlineCodeBlock, MAX_POC_BYTES, PocFetchError } from "./poc-fetcher.js";
import type { PocCandidate } from "./types.js";

function mockResponse(body: string, opts: { status?: number; contentType?: string; contentLength?: string } = {}): Response {
  const headers = new Headers();
  if (opts.contentType) headers.set("content-type", opts.contentType);
  if (opts.contentLength) headers.set("content-length", opts.contentLength);
  return new Response(body, { status: opts.status ?? 200, headers });
}

describe("fetchPoc", () => {
  const originalEnv = { ...process.env };
  let cacheDir: string;

  beforeEach(() => {
    cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-cve-cache-"));
    process.env = { ...originalEnv };
    delete process.env.GITHUB_TOKEN;
    delete process.env.PWNKIT_CVE_POC_CACHE;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("fetches a GitHub raw C PoC and caches it", async () => {
    const candidate: PocCandidate = {
      url: "https://raw.githubusercontent.com/example/poc/main/CVE-2024-1086.c",
      source: "github-raw",
      language: "c",
      confidence: 0.9,
    };
    const body = "int main(void) { return 0; }\n";
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls += 1;
      return mockResponse(body, { contentType: "text/plain; charset=utf-8" });
    };

    const result = await fetchPoc(candidate, { cacheDir, fetchImpl });
    expect(result.language).toBe("c");
    expect(result.source_url).toBe(candidate.url);
    expect(result.local_path.endsWith(".c")).toBe(true);
    expect(readFileSync(result.local_path, "utf-8")).toBe(body);
    expect(calls).toBe(1);

    // Second call should hit the cache (no network).
    const again = await fetchPoc(candidate, { cacheDir, fetchImpl });
    expect(again.sha256).toBe(result.sha256);
    expect(calls).toBe(1);
  });

  it("rejects files larger than the cap (header)", async () => {
    const candidate: PocCandidate = {
      url: "https://raw.githubusercontent.com/x/big.c",
      source: "github-raw",
      language: "c",
      confidence: 0.5,
    };
    const fetchImpl: typeof fetch = async () =>
      mockResponse("x", { contentLength: String(MAX_POC_BYTES + 1), contentType: "text/plain" });

    await expect(fetchPoc(candidate, { cacheDir, fetchImpl })).rejects.toMatchObject({
      name: "PocFetchError",
      kind: "too-large",
    });
  });

  it("rejects files larger than the cap (body)", async () => {
    const candidate: PocCandidate = {
      url: "https://raw.githubusercontent.com/x/big-body.c",
      source: "github-raw",
      language: "c",
      confidence: 0.5,
    };
    const huge = "x".repeat(MAX_POC_BYTES + 16);
    const fetchImpl: typeof fetch = async () => mockResponse(huge, { contentType: "text/plain" });

    await expect(fetchPoc(candidate, { cacheDir, fetchImpl })).rejects.toMatchObject({
      kind: "too-large",
    });
  });

  it("rejects non-text content types", async () => {
    const candidate: PocCandidate = {
      url: "https://example.test/poc.bin",
      source: "github-raw",
      language: "c",
      confidence: 0.5,
    };
    const fetchImpl: typeof fetch = async () => mockResponse("x", { contentType: "image/png" });

    await expect(fetchPoc(candidate, { cacheDir, fetchImpl })).rejects.toMatchObject({
      kind: "non-text",
    });
  });

  it("propagates HTTP errors as PocFetchError", async () => {
    const candidate: PocCandidate = {
      url: "https://example.test/missing.c",
      source: "github-raw",
      language: "c",
      confidence: 0.1,
    };
    const fetchImpl: typeof fetch = async () =>
      new Response("not found", { status: 404, statusText: "Not Found" });

    await expect(fetchPoc(candidate, { cacheDir, fetchImpl })).rejects.toMatchObject({
      kind: "http",
    });
  });

  it("handles inline writeup by extracting the first fenced block", async () => {
    const candidate: PocCandidate = {
      url: "https://writeup.example/cve-2024-1086.html",
      source: "inline-writeup",
      language: "c",
      confidence: 0.4,
    };
    const html = [
      "<h1>CVE-2024-1086 deep dive</h1>",
      "<p>Here is the PoC:</p>",
      "```c",
      "#include <stdio.h>",
      "int main() { puts(\"x\"); return 0; }",
      "```",
      "<p>more prose</p>",
    ].join("\n");
    const fetchImpl: typeof fetch = async () => mockResponse(html, { contentType: "text/html" });

    const result = await fetchPoc(candidate, { cacheDir, fetchImpl });
    const content = readFileSync(result.local_path, "utf-8");
    expect(content).toContain("#include <stdio.h>");
    expect(content).not.toContain("<h1>");
  });

  it("calls onShaMismatch when the same URL re-fetches different bytes", async () => {
    const candidate: PocCandidate = {
      url: "https://raw.example/drifting.c",
      source: "github-raw",
      language: "c",
      confidence: 0.7,
    };

    let body = "int main(void) { return 0; }\n";
    const fetchImpl: typeof fetch = async () => mockResponse(body, { contentType: "text/plain" });
    const first = await fetchPoc(candidate, { cacheDir, fetchImpl });

    // Mutate the cached on-disk artifact to force the cache-validation
    // path to fall through to a re-fetch. (Cache-hit lookup verifies the
    // on-disk sha matches the pointer's sha; if not, we refetch.)
    writeFileSync(first.local_path, "tampered\n", "utf-8");

    body = "int main(void) { return 1; }\n";
    const mismatches: Array<{ url: string; oldSha: string; newSha: string }> = [];
    const second = await fetchPoc(candidate, {
      cacheDir,
      fetchImpl,
      onShaMismatch: (info) => mismatches.push(info),
    });

    expect(second.sha256).not.toBe(first.sha256);
    expect(mismatches.length).toBe(1);
    expect(mismatches[0].oldSha).toBe(first.sha256);
    expect(mismatches[0].newSha).toBe(second.sha256);
  });

  it("respects GITHUB_TOKEN for auth headers", async () => {
    process.env.GITHUB_TOKEN = "ghp_test_token";
    let seenAuth: string | null = null;
    const fetchImpl: typeof fetch = async (_url, init) => {
      const h = new Headers(init?.headers);
      seenAuth = h.get("authorization");
      return mockResponse("int main(void){return 0;}", { contentType: "text/plain" });
    };
    await fetchPoc(
      { url: "https://raw.example/with-token.c", source: "github-raw", language: "c", confidence: 0.9 },
      { cacheDir, fetchImpl },
    );
    expect(seenAuth).toBe("Bearer ghp_test_token");
  });

  it("writes files with the sandboxed extension matching the candidate's language", async () => {
    const fetchImpl: typeof fetch = async () => mockResponse("print('x')", { contentType: "text/plain" });
    const result = await fetchPoc(
      { url: "https://raw.example/py-poc.py", source: "github-raw", language: "py", confidence: 0.5 },
      { cacheDir, fetchImpl },
    );
    expect(result.local_path.endsWith(".py")).toBe(true);
    expect(statSync(result.local_path).isFile()).toBe(true);
  });
});

describe("extractInlineCodeBlock", () => {
  it("prefers markdown fences over <pre>", () => {
    const html = "<pre>old</pre>\n```\nnew\n```";
    expect(extractInlineCodeBlock(html)).toBe("new");
  });

  it("falls back to <pre><code>", () => {
    const html = "<pre><code>int x = 1;</code></pre>";
    expect(extractInlineCodeBlock(html)).toBe("int x = 1;");
  });

  it("decodes HTML entities", () => {
    const html = "<pre>if (a &lt; b) &amp;&amp; foo()</pre>";
    expect(extractInlineCodeBlock(html)).toBe("if (a < b) && foo()");
  });

  it("throws when nothing is found", () => {
    expect(() => extractInlineCodeBlock("<p>just prose</p>")).toThrow(PocFetchError);
  });
});
