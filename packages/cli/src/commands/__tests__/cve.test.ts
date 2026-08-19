/**
 * `pwnkit cve` CLI tests. The parent command groups two subcommands:
 *
 *   - `cve find`  — issue #272 v0 part 1 (artifact scraper). Tested
 *     end-to-end against a stubbed `globalThis.fetch`, asserting argv →
 *     exit code → output shape → cache-dir.
 *   - `cve adapt` — issue #272 v0 part 2 (adaptation loop). Tested by
 *     mocking only the `adaptAndVerify` export from `@pwnkit/core` so
 *     the surrounding helpers (`runCveAdapt`, `parseDurationToMs`,
 *     `parseAttempts`, `renderTable`) exercise their real code paths.
 *
 * Deep parser tests for the scraper live in
 * `packages/core/src/cve/artifact-scraper.test.ts`. Deep tests for the
 * adapt loop live in `packages/core/src/cve/adapt-loop.test.ts`. The
 * tests below are CLI-shape only.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import { mkdtempSync, readdirSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AdaptationResult, CveArtifactProvider } from "@pwnkit/core";

// ── `cve adapt` mock setup ──────────────────────────────────────────
//
// The adapt subcommand calls `adaptAndVerify` from `@pwnkit/core`. We
// mock only that one export and forward everything else (including the
// scraper's `findCveArtifacts`, which the `cve find` tests rely on)
// via `vi.importActual`.

const adaptAndVerifyMock = vi.fn<
  (cveId: string, opts: { artifactProvider: CveArtifactProvider; [k: string]: unknown }) => Promise<AdaptationResult>
>();

vi.mock("@pwnkit/core", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@pwnkit/core")>();
  return {
    ...actual,
    adaptAndVerify: adaptAndVerifyMock,
  };
});

// Import the command module AFTER `vi.mock` is registered so the mock
// is applied to the `@pwnkit/core` resolution.
const cve = await import("../cve.js");
const { registerCveCommand } = cve;

// ── shared CLI test helpers ────────────────────────────────────────

interface CapturedIO {
  stdout: string[];
  stderr: string[];
}

function captureIO(): CapturedIO & { restore: () => void } {
  const captured: CapturedIO = { stdout: [], stderr: [] };
  const stdoutSpy = vi.spyOn(console, "log").mockImplementation((...args) => {
    captured.stdout.push(args.map((a) => String(a)).join(" "));
  });
  const stderrSpy = vi.spyOn(console, "error").mockImplementation((...args) => {
    captured.stderr.push(args.map((a) => String(a)).join(" "));
  });
  return {
    ...captured,
    get stdout() {
      return captured.stdout;
    },
    get stderr() {
      return captured.stderr;
    },
    restore: () => {
      stdoutSpy.mockRestore();
      stderrSpy.mockRestore();
    },
  };
}

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  registerCveCommand(program);
  await program.parseAsync(["node", "pwnkit-cli", ...argv]);
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
}

function notFoundResponse(): Response {
  return new Response("not found", { status: 404 });
}

const NVD_JSON_OK = {
  vulnerabilities: [
    {
      cve: {
        id: "CVE-2024-1086",
        published: "2024-01-31T00:00:00.000",
        descriptions: [{ lang: "en", value: "UAF in nf_tables" }],
        references: [
          { url: "https://github.com/Notselwyn/CVE-2024-1086", tags: ["Exploit"] },
        ],
        configurations: [
          {
            nodes: [
              {
                cpeMatch: [
                  {
                    vulnerable: true,
                    criteria: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                    versionEndExcluding: "6.6.46",
                  },
                ],
              },
            ],
          },
        ],
      },
    },
  ],
};

// ── `pwnkit cve find` tests ────────────────────────────────────────

describe("pwnkit cve find", () => {
  let io: ReturnType<typeof captureIO>;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    process.exitCode = undefined;
    io = captureIO();
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    process.exitCode = undefined;
    io.restore();
  });

  it("rejects malformed CVE ids with exit 1", async () => {
    globalThis.fetch = (async () => jsonResponse({})) as typeof fetch;
    await runCli(["cve", "find", "not-a-cve"]);
    expect(process.exitCode).toBe(1);
    expect(io.stderr.join("\n")).toContain("invalid CVE id");
  });

  it("emits JSON by default and exits 0 on happy path", async () => {
    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = String(input);
      if (url.startsWith("https://services.nvd.nist.gov/")) {
        return jsonResponse(NVD_JSON_OK);
      }
      if (url.startsWith("https://api.github.com/advisories")) {
        return jsonResponse([]);
      }
      if (url.startsWith("https://api.osv.dev/")) {
        return notFoundResponse();
      }
      if (url.startsWith("https://api.github.com/search/repositories")) {
        return jsonResponse({ items: [] });
      }
      if (url.startsWith("https://access.redhat.com/")) {
        return notFoundResponse();
      }
      return notFoundResponse();
    }) as typeof fetch;

    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-cve-cli-"));
    await runCli([
      "cve",
      "find",
      "CVE-2024-1086",
      "--cache-dir",
      cacheDir,
      "--skip-github-poc-search",
    ]);
    expect(process.exitCode).toBe(0);
    const out = io.stdout.join("\n");
    // The output is a single JSON document. Parse to verify shape.
    const parsed = JSON.parse(out);
    expect(parsed.cve_id).toBe("CVE-2024-1086");
    expect(parsed.description).toBe("UAF in nf_tables");
    expect(Array.isArray(parsed.poc_urls)).toBe(true);
    expect(Array.isArray(parsed.sources)).toBe(true);
  });

  it("--format table renders chalkable output with key sections", async () => {
    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = String(input);
      if (url.startsWith("https://services.nvd.nist.gov/")) {
        return jsonResponse(NVD_JSON_OK);
      }
      if (url.startsWith("https://api.github.com/advisories")) {
        return jsonResponse([]);
      }
      if (url.startsWith("https://api.osv.dev/")) {
        return notFoundResponse();
      }
      if (url.startsWith("https://api.github.com/search/repositories")) {
        return jsonResponse({ items: [] });
      }
      return notFoundResponse();
    }) as typeof fetch;

    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-cve-cli-"));
    await runCli([
      "cve",
      "find",
      "CVE-2024-1086",
      "--format",
      "table",
      "--cache-dir",
      cacheDir,
      "--skip-github-poc-search",
    ]);
    expect(process.exitCode).toBe(0);
    const out = io.stdout.join("\n");
    expect(out).toContain("CVE-2024-1086");
    expect(out).toContain("Affected versions");
    expect(out).toContain("PoC candidates");
    expect(out).toContain("Sources");
  });

  it("--cache-dir is honored and persists cache entries between runs", async () => {
    let nvdHits = 0;
    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = String(input);
      if (url.startsWith("https://services.nvd.nist.gov/")) {
        nvdHits += 1;
        return jsonResponse(NVD_JSON_OK);
      }
      if (url.startsWith("https://api.github.com/advisories")) {
        return jsonResponse([]);
      }
      if (url.startsWith("https://api.osv.dev/")) {
        return notFoundResponse();
      }
      if (url.startsWith("https://api.github.com/search/repositories")) {
        return jsonResponse({ items: [] });
      }
      return notFoundResponse();
    }) as typeof fetch;

    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-cve-cli-"));
    await runCli([
      "cve",
      "find",
      "CVE-2024-1086",
      "--cache-dir",
      cacheDir,
      "--skip-github-poc-search",
    ]);
    expect(process.exitCode).toBe(0);
    expect(nvdHits).toBe(1);
    expect(existsSync(join(cacheDir, "nvd"))).toBe(true);
    expect(readdirSync(join(cacheDir, "nvd")).length).toBeGreaterThan(0);

    // Reset captured stdout for the second run
    io.stdout.length = 0;
    await runCli([
      "cve",
      "find",
      "CVE-2024-1086",
      "--cache-dir",
      cacheDir,
      "--skip-github-poc-search",
    ]);
    expect(process.exitCode).toBe(0);
    // NVD must not have been hit a second time
    expect(nvdHits).toBe(1);
  });

  it("--no-cache bypasses the on-disk cache", async () => {
    let nvdHits = 0;
    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = String(input);
      if (url.startsWith("https://services.nvd.nist.gov/")) {
        nvdHits += 1;
        return jsonResponse(NVD_JSON_OK);
      }
      if (url.startsWith("https://api.github.com/advisories")) {
        return jsonResponse([]);
      }
      if (url.startsWith("https://api.osv.dev/")) {
        return notFoundResponse();
      }
      if (url.startsWith("https://api.github.com/search/repositories")) {
        return jsonResponse({ items: [] });
      }
      return notFoundResponse();
    }) as typeof fetch;

    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-cve-cli-"));
    await runCli([
      "cve",
      "find",
      "CVE-2024-1086",
      "--cache-dir",
      cacheDir,
      "--no-cache",
      "--skip-github-poc-search",
    ]);
    io.stdout.length = 0;
    await runCli([
      "cve",
      "find",
      "CVE-2024-1086",
      "--cache-dir",
      cacheDir,
      "--no-cache",
      "--skip-github-poc-search",
    ]);
    expect(nvdHits).toBe(2);
  });

  it("exits non-zero when every source misses and nothing is collected", async () => {
    globalThis.fetch = (async () => notFoundResponse()) as typeof fetch;
    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-cve-cli-"));
    await runCli([
      "cve",
      "find",
      "CVE-2099-9999",
      "--cache-dir",
      cacheDir,
      "--skip-github-poc-search",
    ]);
    // Every source returned 404 / no data → EXIT_NO_ARTIFACTS (2)
    expect(process.exitCode).toBe(2);
  });

  it("rejects an invalid --format value", async () => {
    globalThis.fetch = (async () => jsonResponse({})) as typeof fetch;
    await runCli([
      "cve",
      "find",
      "CVE-2024-1086",
      "--format",
      "yaml",
    ]);
    expect(process.exitCode).toBe(1);
    expect(io.stderr.join("\n")).toContain("invalid --format");
  });
});

// ── `pwnkit cve adapt` tests ───────────────────────────────────────

function makeResult(overrides: Partial<AdaptationResult> = {}): AdaptationResult {
  return {
    status: "confirmed",
    cveId: "CVE-2024-1086",
    attempts: [],
    total_ms: 100,
    ...overrides,
  };
}

describe("parseDurationToMs", () => {
  it("parses minutes", () => {
    expect(cve.parseDurationToMs("30m")).toBe(30 * 60_000);
  });
  it("parses seconds", () => {
    expect(cve.parseDurationToMs("90s")).toBe(90_000);
  });
  it("parses bare milliseconds", () => {
    expect(cve.parseDurationToMs("500ms")).toBe(500);
    expect(cve.parseDurationToMs("500")).toBe(500);
  });
  it("rejects garbage", () => {
    expect(() => cve.parseDurationToMs("abc")).toThrow();
  });
});

describe("parseAttempts", () => {
  it("falls back when undefined", () => {
    expect(cve.parseAttempts(undefined)).toBe(5);
  });
  it("parses integers", () => {
    expect(cve.parseAttempts("3")).toBe(3);
  });
  it("rejects zero / negative", () => {
    expect(() => cve.parseAttempts("0")).toThrow();
    expect(() => cve.parseAttempts("-1")).toThrow();
  });
});

describe("runCveAdapt — exit codes", () => {
  beforeEach(() => {
    adaptAndVerifyMock.mockReset();
  });

  it("returns exit 0 on confirmed", async () => {
    adaptAndVerifyMock.mockResolvedValue(makeResult({ status: "confirmed", signature: "kasan-uaf" }));
    const outcome = await cve.runCveAdapt({
      cveId: "CVE-2024-1086",
      opts: { kernelTree: "/linux" },
      providerOverride: async () => ({ cveId: "CVE-2024-1086", pocCandidates: [] }),
    });
    expect(outcome.exitCode).toBe(0);
    expect(outcome.result.status).toBe("confirmed");
  });

  it("returns exit 1 on unreproduced", async () => {
    adaptAndVerifyMock.mockResolvedValue(makeResult({ status: "unreproduced" }));
    const outcome = await cve.runCveAdapt({
      cveId: "CVE-2024-1086",
      opts: { kernelTree: "/linux" },
      providerOverride: async () => ({ cveId: "CVE-2024-1086", pocCandidates: [] }),
    });
    expect(outcome.exitCode).toBe(1);
  });

  it("returns exit 2 on no_artifact", async () => {
    adaptAndVerifyMock.mockResolvedValue(makeResult({ status: "no_artifact" }));
    const outcome = await cve.runCveAdapt({
      cveId: "CVE-2024-1086",
      opts: { kernelTree: "/linux" },
      providerOverride: async () => ({ cveId: "CVE-2024-1086", pocCandidates: [] }),
    });
    expect(outcome.exitCode).toBe(2);
  });

  it("returns exit 3 on budget_exhausted", async () => {
    adaptAndVerifyMock.mockResolvedValue(makeResult({ status: "budget_exhausted" }));
    const outcome = await cve.runCveAdapt({
      cveId: "CVE-2024-1086",
      opts: { kernelTree: "/linux" },
      providerOverride: async () => ({ cveId: "CVE-2024-1086", pocCandidates: [] }),
    });
    expect(outcome.exitCode).toBe(3);
  });
});

describe("runCveAdapt — arg parsing", () => {
  beforeEach(() => {
    adaptAndVerifyMock.mockReset();
  });

  it("requires --kernel-tree", async () => {
    await expect(
      cve.runCveAdapt({
        cveId: "CVE-X",
        opts: {} as { kernelTree: string },
        providerOverride: async () => ({ cveId: "CVE-X", pocCandidates: [] }),
      }),
    ).rejects.toThrow(/kernel-tree/);
  });

  it("requires either --artifacts or a providerOverride", async () => {
    await expect(
      cve.runCveAdapt({
        cveId: "CVE-X",
        opts: { kernelTree: "/linux" },
      }),
    ).rejects.toThrow(/artifact provider/);
  });

  it("parses --attempts / --wall-clock and forwards to adaptAndVerify", async () => {
    adaptAndVerifyMock.mockResolvedValue(makeResult({ status: "confirmed" }));
    await cve.runCveAdapt({
      cveId: "CVE-X",
      opts: { kernelTree: "/linux", attempts: "3", wallClock: "2m" },
      providerOverride: async () => ({ cveId: "CVE-X", pocCandidates: [] }),
    });
    expect(adaptAndVerifyMock).toHaveBeenCalledTimes(1);
    const call = adaptAndVerifyMock.mock.calls[0]!;
    expect(call[0]).toBe("CVE-X");
    expect(call[1].attempts).toBe(3);
    expect(call[1].wallClockMs).toBe(120_000);
  });

  it("loads --artifacts from disk and forwards as the provider", async () => {
    const dir = mkdtempSync(join(tmpdir(), "pwnkit-cve-artifacts-"));
    const path = join(dir, "artifacts.json");
    writeFileSync(
      path,
      JSON.stringify({
        cveId: "CVE-2024-1086",
        pocCandidates: [{ url: "https://x", source: "github-raw", language: "c", confidence: 0.9 }],
      }),
      "utf-8",
    );

    let receivedArtifacts: { pocCandidates: unknown[] } | null = null;
    adaptAndVerifyMock.mockImplementation(async (_cveId, opts) => {
      const provider = opts.artifactProvider as CveArtifactProvider;
      const data = await provider("CVE-2024-1086");
      receivedArtifacts = data as { pocCandidates: unknown[] };
      return makeResult({ status: "confirmed" });
    });

    const outcome = await cve.runCveAdapt({
      cveId: "CVE-2024-1086",
      opts: { kernelTree: "/linux", artifacts: path },
    });
    expect(outcome.exitCode).toBe(0);
    expect(receivedArtifacts).toBeDefined();
    expect(receivedArtifacts!.pocCandidates.length).toBe(1);
  });

  it("rejects --artifacts files that do not match the schema", async () => {
    const dir = mkdtempSync(join(tmpdir(), "pwnkit-cve-bad-"));
    const path = join(dir, "bad.json");
    writeFileSync(path, JSON.stringify({ not_what_we_want: true }), "utf-8");
    await expect(
      cve.runCveAdapt({
        cveId: "CVE-X",
        opts: { kernelTree: "/linux", artifacts: path },
      }),
    ).rejects.toThrow(/pocCandidates/);
  });
});

describe("renderTable", () => {
  it("renders without throwing for confirmed result", () => {
    const out = cve.renderTable(
      makeResult({
        status: "confirmed",
        signature: "kasan-uaf",
        attempts: [
          {
            attemptIndex: 0,
            candidate: { url: "https://x", source: "github-raw", language: "c", confidence: 0.9 },
            fetched: null,
            verification: { status: "reproduced", dmesg_path: "/tmp/d", build_cache_hit: true },
            diffApplied: false,
            durationMs: 1234,
          },
        ],
        total_ms: 5_000,
        final_poc_path: "/tmp/poc.c",
      }),
    );
    expect(out).toContain("CVE-2024-1086");
    expect(out).toContain("confirmed");
    expect(out).toContain("reproduced");
  });
});

afterEach(() => {
  vi.clearAllMocks();
});
