/**
 * Coverage seed for `pwnkit-cli`'s `run.ts` entry point. The two files
 * (`run.ts` + `scan.ts`) are the on-ramp every CLI user hits, yet they
 * had zero tests prior to this seed.
 *
 * Strategy: mock `@pwnkit/core` at the module boundary (the same boundary
 * `loadCoreModule` resolves), drive `runUnified` directly, and assert
 * on (a) which core entry point gets dispatched given `targetType`,
 * (b) how the runtime gate handles invalid runtime names, and
 * (c) the result-line + cost-summary shapes that downstream relays parse.
 *
 * Anything that requires real subprocesses (Ink/OpenTUI), real network
 * (cloud sink), or real LLM runtimes is intentionally out of scope.
 * The internal pure helpers (`toScanReport`, `printCostSummary`,
 * `emitResultLine`, `getCloudFinalSinkConfig`) are not exported from
 * `run.ts`, so we exercise them through their observable side effects
 * (stdout shape, dispatch routing, exit code). Promoting them to
 * exports would let us drop the mocks, but that's a refactor, not a
 * test seed.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ScanReport } from "@pwnkit/shared";

// ── Module-level mocks ──────────────────────────────────────────────────────
//
// `runUnified` calls `loadCoreModule()` which does a dynamic
// `import("@pwnkit/core")`. Vitest hoists `vi.mock` so both static and
// dynamic imports see the stub.
//
// We expose four shims:
//   • agenticScan      — for url / web-app dispatch
//   • runPipeline      — for everything else (npm / pypi / source-code / …)
//   • createRuntime    — non-{api,auto} runtime availability probe
//   • eventBus         — the cost-summary subscription happens here
//
// Each test resets the mocks in beforeEach so call counts don't leak.

const agenticScanMock = vi.fn();
const runPipelineMock = vi.fn();
const createRuntimeMock = vi.fn();
let eventBusListener:
  | { emit: (type: string, payload: unknown) => void }
  | null = null;
const eventBusMock = {
  subscribe(listener: { emit: (type: string, payload: unknown) => void }) {
    eventBusListener = listener;
    return () => {
      eventBusListener = null;
    };
  },
};

vi.mock("@pwnkit/core", () => ({
  agenticScan: agenticScanMock,
  runPipeline: runPipelineMock,
  createRuntime: createRuntimeMock,
  eventBus: eventBusMock,
}));

// `runUnified` calls `checkRuntimeAvailability` for terminal format. We
// stub it to a no-op so tests don't probe the user's environment.
vi.mock("../../utils.js", () => ({
  checkRuntimeAvailability: vi.fn().mockResolvedValue(undefined),
  getRuntimeAvailability: vi.fn().mockResolvedValue({
    hasApiKey: false,
    availableRuntimes: [],
    apiRuntime: { providerLabel: "stub", configured: false, valid: false },
  }),
  buildShareUrl: vi.fn(),
}));

// Formatters: short-circuit to a fixed string so we don't import pdfkit
// / chalk-heavy renderers for a test that only cares about dispatch.
vi.mock("../../formatters/index.js", () => ({
  formatAuditReport: vi.fn(() => "FORMATTED_AUDIT"),
  formatReviewReport: vi.fn(() => "FORMATTED_REVIEW"),
  formatReport: vi.fn(() => "FORMATTED_REPORT"),
  generatePdfReport: vi.fn().mockResolvedValue(undefined),
}));

const { runUnified } = await import("../run.js");

// ── Test fixtures ───────────────────────────────────────────────────────────

function emptySummary(): ScanReport["summary"] {
  return {
    totalAttacks: 0,
    totalFindings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
}

function cleanReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    target: "https://example.com",
    scanDepth: "default",
    startedAt: "2026-05-13T00:00:00.000Z",
    completedAt: "2026-05-13T00:00:01.000Z",
    durationMs: 1000,
    summary: emptySummary(),
    findings: [],
    warnings: [],
    ...overrides,
  };
}

interface ExitThrown extends Error {
  __exit: true;
  code: number;
}
/**
 * Stub `process.exit` so it throws a sentinel error (lets us inspect
 * the would-be exit code from the test). We also record the first
 * exit code on a shared marker — `run.ts` has a top-level catch that
 * calls `process.exit(2)` again when our throw re-raises out of the
 * try, so the *thrown* code we ultimately see can be 2 even when the
 * intended exit code is 1 or 4. The marker captures the original.
 */
interface ExitTracker {
  firstCode?: number;
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function makeExitMock(tracker: ExitTracker): any {
  return vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
    const c = (code ?? 0) as number;
    if (tracker.firstCode === undefined) tracker.firstCode = c;
    const err = new Error(`__exit__:${c}`) as ExitThrown;
    err.__exit = true;
    err.code = c;
    throw err;
  }) as never);
}

// ── Tests ───────────────────────────────────────────────────────────────────

/**
 * Module-shared tracker; replaced freshly in every `beforeEach` so a
 * leaked tracker can't bleed exit codes between tests.
 */
let tracker: ExitTracker;

describe("runUnified — runtime gating", () => {
  let exitSpy: { mockRestore: () => void };
  let errSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    agenticScanMock.mockReset();
    runPipelineMock.mockReset();
    createRuntimeMock.mockReset();
    eventBusListener = null;
    tracker = {};
    exitSpy = makeExitMock(tracker);
    errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errSpy.mockRestore();
    logSpy.mockRestore();
  });

  it("rejects an unknown runtime with exit code 2", async () => {
    try {
      await runUnified({
        target: "https://example.com",
        targetType: "url",
        depth: "default",
        format: "json",
        // intentionally invalid; the valid set is api|claude|codex|gemini|auto
        runtime: "definitely-not-a-runtime" as never,
        timeout: 30000,
        verbose: false,
      });
    } catch {
      // process.exit throws by design — swallow
    }
    expect(tracker.firstCode).toBe(2);
    expect(errSpy.mock.calls.map((c) => String(c[0])).join("\n")).toMatch(
      /Unknown runtime/,
    );
  });

  it("probes runtime availability for non-auto/non-api runtimes (exit 2 when missing)", async () => {
    createRuntimeMock.mockReturnValueOnce({
      isAvailable: vi.fn().mockResolvedValue(false),
    });
    try {
      await runUnified({
        target: "https://example.com",
        targetType: "url",
        depth: "default",
        format: "json",
        runtime: "claude",
        timeout: 30000,
        verbose: false,
      });
    } catch {
      // expected
    }
    expect(createRuntimeMock).toHaveBeenCalledWith({ type: "claude", timeout: 30000 });
    expect(tracker.firstCode).toBe(2);
    expect(errSpy.mock.calls.map((c) => String(c[0])).join("\n")).toMatch(
      /Runtime 'claude' not available/,
    );
  });

  it("skips the availability probe for 'auto' and 'api'", async () => {
    agenticScanMock.mockResolvedValueOnce(cleanReport());
    await runUnified({
      target: "https://example.com",
      targetType: "url",
      depth: "default",
      format: "json",
      runtime: "auto",
      timeout: 30000,
      verbose: false,
    });
    expect(createRuntimeMock).not.toHaveBeenCalled();
    expect(agenticScanMock).toHaveBeenCalledOnce();
  });

  it("skips the Codex CLI availability probe when direct ChatGPT Codex auth is configured", async () => {
    const oldRefreshToken = process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN;
    process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN = "fake-refresh-token";
    try {
      agenticScanMock.mockResolvedValueOnce(cleanReport());
      await runUnified({
        target: "https://example.com",
        targetType: "url",
        depth: "default",
        format: "json",
        runtime: "codex",
        timeout: 30000,
        verbose: false,
      });
    } finally {
      if (oldRefreshToken === undefined) {
        delete process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN;
      } else {
        process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN = oldRefreshToken;
      }
    }

    expect(createRuntimeMock).not.toHaveBeenCalled();
    expect(agenticScanMock).toHaveBeenCalledOnce();
    expect(agenticScanMock.mock.calls[0]?.[0]?.config.runtime).toBe("codex");
  });

  it("skips the Codex CLI availability probe when only PWNKIT_CHATGPT_ACCESS_TOKEN is set (cloud sandbox path)", async () => {
    // The pwnkit-cloud worker forwards PWNKIT_CHATGPT_ACCESS_TOKEN to
    // sandboxes — NOT the refresh token — so the gate must accept the
    // access token alone, otherwise the CLI preflight tries to find a
    // Codex binary the sandbox image doesn't ship.
    const oldRefreshToken = process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN;
    const oldAccessToken = process.env.PWNKIT_CHATGPT_ACCESS_TOKEN;
    delete process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN;
    process.env.PWNKIT_CHATGPT_ACCESS_TOKEN = "fake-access-token";
    try {
      agenticScanMock.mockResolvedValueOnce(cleanReport());
      await runUnified({
        target: "https://example.com",
        targetType: "url",
        depth: "default",
        format: "json",
        runtime: "codex",
        timeout: 30000,
        verbose: false,
      });
    } finally {
      if (oldRefreshToken === undefined) {
        delete process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN;
      } else {
        process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN = oldRefreshToken;
      }
      if (oldAccessToken === undefined) {
        delete process.env.PWNKIT_CHATGPT_ACCESS_TOKEN;
      } else {
        process.env.PWNKIT_CHATGPT_ACCESS_TOKEN = oldAccessToken;
      }
    }

    expect(createRuntimeMock).not.toHaveBeenCalled();
    expect(agenticScanMock).toHaveBeenCalledOnce();
    expect(agenticScanMock.mock.calls[0]?.[0]?.config.runtime).toBe("codex");
  });

  it("still probes the Codex CLI when neither ChatGPT env var is set (no direct provider)", async () => {
    const oldRefreshToken = process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN;
    const oldAccessToken = process.env.PWNKIT_CHATGPT_ACCESS_TOKEN;
    delete process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN;
    delete process.env.PWNKIT_CHATGPT_ACCESS_TOKEN;
    createRuntimeMock.mockReturnValueOnce({
      isAvailable: vi.fn().mockResolvedValue(false),
    });
    try {
      await runUnified({
        target: "https://example.com",
        targetType: "url",
        depth: "default",
        format: "json",
        runtime: "codex",
        timeout: 30000,
        verbose: false,
      });
    } catch {
      // expected — process.exit throws by design
    } finally {
      if (oldRefreshToken !== undefined) {
        process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN = oldRefreshToken;
      }
      if (oldAccessToken !== undefined) {
        process.env.PWNKIT_CHATGPT_ACCESS_TOKEN = oldAccessToken;
      }
    }

    expect(createRuntimeMock).toHaveBeenCalledWith({ type: "codex", timeout: 30000 });
    expect(tracker.firstCode).toBe(2);
  });
});

describe("runUnified — dispatch routing on targetType", () => {
  let exitSpy: { mockRestore: () => void };
  let errSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    agenticScanMock.mockReset();
    runPipelineMock.mockReset();
    createRuntimeMock.mockReset();
    eventBusListener = null;
    tracker = {};
    exitSpy = makeExitMock(tracker);
    errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errSpy.mockRestore();
    logSpy.mockRestore();
  });

  it("routes targetType=url to agenticScan with full config payload", async () => {
    agenticScanMock.mockResolvedValueOnce(cleanReport());
    await runUnified({
      target: "https://example.com",
      targetType: "url",
      depth: "deep",
      format: "json",
      runtime: "auto",
      mode: "web",
      timeout: 30000,
      verbose: false,
      apiKey: "sk-fake",
      model: "gpt-4o",
      scopeFile: "/tmp/scope.json",
      rateLimit: "5",
      dispatchMode: "xml",
    });
    expect(agenticScanMock).toHaveBeenCalledOnce();
    expect(runPipelineMock).not.toHaveBeenCalled();
    const callArg = agenticScanMock.mock.calls[0]![0];
    expect(callArg.config.target).toBe("https://example.com");
    expect(callArg.config.mode).toBe("web");
    expect(callArg.config.runtime).toBe("auto");
    expect(callArg.config.dispatchMode).toBe("xml");
    expect(callArg.config.scopeFile).toBe("/tmp/scope.json");
  });

  it("routes targetType=web-app to agenticScan (not runPipeline)", async () => {
    agenticScanMock.mockResolvedValueOnce(cleanReport());
    await runUnified({
      target: "https://example.com",
      targetType: "web-app",
      depth: "default",
      format: "json",
      runtime: "auto",
      timeout: 30000,
      verbose: false,
    });
    expect(agenticScanMock).toHaveBeenCalledOnce();
    expect(runPipelineMock).not.toHaveBeenCalled();
  });

  it("routes targetType=npm-package to runPipeline", async () => {
    runPipelineMock.mockResolvedValueOnce({
      ...cleanReport(),
      targetType: "npm-package",
      package: "lodash",
      version: "1.0.0",
    } as never);
    await runUnified({
      target: "lodash",
      targetType: "npm-package",
      depth: "default",
      format: "json",
      runtime: "auto",
      timeout: 30000,
      verbose: false,
      packageVersion: "1.0.0",
    });
    expect(runPipelineMock).toHaveBeenCalledOnce();
    expect(agenticScanMock).not.toHaveBeenCalled();
    const callArg = runPipelineMock.mock.calls[0]![0];
    expect(callArg.target).toBe("lodash");
    expect(callArg.targetType).toBe("npm-package");
    expect(callArg.packageVersion).toBe("1.0.0");
  });

  it("routes targetType=source-code to runPipeline and forwards reviewProfile", async () => {
    runPipelineMock.mockResolvedValueOnce({
      ...cleanReport(),
      targetType: "source-code",
      repo: "/tmp/repo",
    } as never);
    await runUnified({
      target: "/tmp/repo",
      targetType: "source-code",
      depth: "default",
      format: "json",
      runtime: "auto",
      timeout: 30000,
      verbose: false,
      reviewProfile: "c-library",
    });
    expect(runPipelineMock).toHaveBeenCalledOnce();
    const callArg = runPipelineMock.mock.calls[0]![0];
    expect(callArg.targetType).toBe("source-code");
    expect(callArg.reviewProfile).toBe("c-library");
  });
});

describe("runUnified — exit codes", () => {
  let exitSpy: { mockRestore: () => void };
  let errSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    agenticScanMock.mockReset();
    runPipelineMock.mockReset();
    createRuntimeMock.mockReset();
    eventBusListener = null;
    tracker = {};
    exitSpy = makeExitMock(tracker);
    errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errSpy.mockRestore();
    logSpy.mockRestore();
  });

  it("exit code 1 when high-severity findings are present", async () => {
    agenticScanMock.mockResolvedValueOnce(
      cleanReport({
        summary: { ...emptySummary(), totalFindings: 1, high: 1 },
      }),
    );
    try {
      await runUnified({
        target: "https://example.com",
        targetType: "url",
        depth: "default",
        format: "json",
        runtime: "auto",
        timeout: 30000,
        verbose: false,
      });
    } catch {
      // expected — process.exit(1) is mocked to throw
    }
    expect(tracker.firstCode).toBe(1);
  });

  it("exit code 4 when costCeilingExceeded is set on the report", async () => {
    agenticScanMock.mockResolvedValueOnce(
      cleanReport({ costCeilingExceeded: true }),
    );
    try {
      await runUnified({
        target: "https://example.com",
        targetType: "url",
        depth: "default",
        format: "json",
        runtime: "auto",
        timeout: 30000,
        verbose: false,
      });
    } catch {
      // expected
    }
    expect(tracker.firstCode).toBe(4);
    expect(errSpy.mock.calls.map((c) => String(c[0])).join("\n")).toMatch(
      /cost ceiling exceeded/i,
    );
  });

  it("exit code 2 on a core-thrown error", async () => {
    agenticScanMock.mockRejectedValueOnce(new Error("kaboom"));
    try {
      await runUnified({
        target: "https://example.com",
        targetType: "url",
        depth: "default",
        format: "json",
        runtime: "auto",
        timeout: 30000,
        verbose: false,
      });
    } catch {
      // expected
    }
    expect(tracker.firstCode).toBe(2);
    expect(errSpy.mock.calls.map((c) => String(c[0])).join("\n")).toMatch(
      /kaboom/,
    );
  });
});

describe("runUnified — emitResultLine env gate", () => {
  let exitSpy: { mockRestore: () => void };
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errSpy: ReturnType<typeof vi.spyOn>;
  const envSnapshot: Record<string, string | undefined> = {};

  beforeEach(() => {
    agenticScanMock.mockReset();
    runPipelineMock.mockReset();
    createRuntimeMock.mockReset();
    eventBusListener = null;
    tracker = {};
    exitSpy = makeExitMock(tracker);
    errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    envSnapshot.PWNKIT_EMIT_RESULT_LINE = process.env.PWNKIT_EMIT_RESULT_LINE;
    envSnapshot.PWNKIT_CLOUD_SINK = process.env.PWNKIT_CLOUD_SINK;
    delete process.env.PWNKIT_EMIT_RESULT_LINE;
    delete process.env.PWNKIT_CLOUD_SINK;
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errSpy.mockRestore();
    logSpy.mockRestore();
    for (const [k, v] of Object.entries(envSnapshot)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  it("does NOT emit PWNKIT_RESULT line when neither env var is set", async () => {
    agenticScanMock.mockResolvedValueOnce(cleanReport());
    await runUnified({
      target: "https://example.com",
      targetType: "url",
      depth: "default",
      format: "json",
      runtime: "auto",
      timeout: 30000,
      verbose: false,
    });
    const all = logSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(all).not.toMatch(/PWNKIT_RESULT=/);
  });

  it("emits PWNKIT_RESULT line when PWNKIT_EMIT_RESULT_LINE=1", async () => {
    process.env.PWNKIT_EMIT_RESULT_LINE = "1";
    agenticScanMock.mockResolvedValueOnce(cleanReport());
    await runUnified({
      target: "https://example.com",
      targetType: "url",
      depth: "default",
      format: "json",
      runtime: "auto",
      timeout: 30000,
      verbose: false,
    });
    const line = logSpy.mock.calls
      .map((c) => String(c[0]))
      .find((s) => s.startsWith("PWNKIT_RESULT="));
    expect(line).toBeTruthy();
    const payload = JSON.parse(line!.slice("PWNKIT_RESULT=".length));
    expect(payload.ok).toBe(true);
    expect(payload.exitCode).toBe(0);
    expect(payload.exit_reason).toBe("completed");
    expect(payload.target).toBe("https://example.com");
    expect(payload.runtime).toBe("auto");
    expect(payload.format).toBe("json");
  });

  it("emits exit_reason=findings on the result line when findings raise exit 1", async () => {
    process.env.PWNKIT_EMIT_RESULT_LINE = "1";
    agenticScanMock.mockResolvedValueOnce(
      cleanReport({
        summary: { ...emptySummary(), totalFindings: 1, critical: 1 },
      }),
    );
    try {
      await runUnified({
        target: "https://example.com",
        targetType: "url",
        depth: "default",
        format: "json",
        runtime: "auto",
        timeout: 30000,
        verbose: false,
      });
    } catch {
      // expected — process.exit(1) is mocked to throw
    }
    const line = logSpy.mock.calls
      .map((c) => String(c[0]))
      .find((s) => s.startsWith("PWNKIT_RESULT="));
    expect(line).toBeTruthy();
    const payload = JSON.parse(line!.slice("PWNKIT_RESULT=".length));
    expect(payload.exitCode).toBe(1);
    expect(payload.exit_reason).toBe("findings");
    expect(payload.summary.critical).toBe(1);
  });
});

describe("runUnified — cost summary (pwnkit#231)", () => {
  let exitSpy: { mockRestore: () => void };
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    agenticScanMock.mockReset();
    runPipelineMock.mockReset();
    createRuntimeMock.mockReset();
    eventBusListener = null;
    tracker = {};
    exitSpy = makeExitMock(tracker);
    errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errSpy.mockRestore();
    logSpy.mockRestore();
  });

  it("prints cost-summary line when scan_completed payload carries cost_usd", async () => {
    // Tap the event bus mid-flight: agenticScan emits scan_completed via
    // the bus before resolving. We simulate that by firing into the bus
    // from the mocked agenticScan.
    agenticScanMock.mockImplementationOnce(async () => {
      eventBusListener?.emit("scan_completed", {
        cost_usd: 0.42,
        cost_per_flag: 0.42,
        cost_breakdown: [
          { provider: "anthropic", model: "claude", cost_in: 0.18, cost_out: 0.2, cost_cache_read: 0.04 },
        ],
      });
      return cleanReport();
    });
    await runUnified({
      target: "https://example.com",
      targetType: "url",
      depth: "default",
      format: "json",
      runtime: "auto",
      timeout: 30000,
      verbose: false,
    });
    const all = logSpy.mock.calls.map((c) => String(c[0])).join("\n");
    // chalk.gray wraps with ANSI; strip for matching.
    // eslint-disable-next-line no-control-regex
    const plain = all.replace(/\x1b\[\d+m/g, "");
    expect(plain).toMatch(/cost: \$0\.42/);
    expect(plain).toMatch(/in: \$0\.18/);
    expect(plain).toMatch(/out: \$0\.20/);
    expect(plain).toMatch(/cache: \$0\.04/);
    expect(plain).toMatch(/\$0\.42\/flag/);
  });

  it("omits cache and /flag suffix when the runtime didn't report them", async () => {
    agenticScanMock.mockImplementationOnce(async () => {
      eventBusListener?.emit("scan_completed", {
        cost_usd: 0.1,
        cost_breakdown: [
          { provider: "openai", model: "gpt-4o", cost_in: 0.05, cost_out: 0.05 },
        ],
        // no cost_per_flag → no /flag suffix
      });
      return cleanReport();
    });
    await runUnified({
      target: "https://example.com",
      targetType: "url",
      depth: "default",
      format: "json",
      runtime: "auto",
      timeout: 30000,
      verbose: false,
    });
    const all = logSpy.mock.calls.map((c) => String(c[0])).join("\n");
    // eslint-disable-next-line no-control-regex
    const plain = all.replace(/\x1b\[\d+m/g, "");
    expect(plain).toMatch(/cost: \$0\.10/);
    expect(plain).not.toMatch(/cache:/);
    expect(plain).not.toMatch(/\/flag/);
  });

  it("does not print the cost line when no scan_completed cost arrives", async () => {
    agenticScanMock.mockResolvedValueOnce(cleanReport());
    await runUnified({
      target: "https://example.com",
      targetType: "url",
      depth: "default",
      format: "json",
      runtime: "auto",
      timeout: 30000,
      verbose: false,
    });
    const all = logSpy.mock.calls.map((c) => String(c[0])).join("\n");
    // eslint-disable-next-line no-control-regex
    const plain = all.replace(/\x1b\[\d+m/g, "");
    expect(plain).not.toMatch(/cost: \$/);
  });
});

describe("runUnified — resume / branch (pwnkit#374)", () => {
  let exitSpy: { mockRestore: () => void };
  let errSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    agenticScanMock.mockReset();
    runPipelineMock.mockReset();
    createRuntimeMock.mockReset();
    eventBusListener = null;
    tracker = {};
    exitSpy = makeExitMock(tracker);
    errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errSpy.mockRestore();
    logSpy.mockRestore();
  });

  it("threads resumeScanId through to agenticScan for url targets", async () => {
    agenticScanMock.mockResolvedValueOnce(cleanReport());
    await runUnified({
      target: "https://example.com",
      targetType: "url",
      depth: "default",
      format: "json",
      runtime: "auto",
      timeout: 30000,
      verbose: false,
      resumeScanId: "scan-abc-123",
    });
    expect(agenticScanMock).toHaveBeenCalledOnce();
    expect(agenticScanMock.mock.calls[0]![0].resumeScanId).toBe("scan-abc-123");
  });

  it("threads resumeScanId through to runPipeline for source-code targets", async () => {
    runPipelineMock.mockResolvedValueOnce({
      ...cleanReport(),
      targetType: "source-code",
      repo: "/tmp/repo",
    } as never);
    await runUnified({
      target: "/tmp/repo",
      targetType: "source-code",
      depth: "default",
      format: "json",
      runtime: "auto",
      timeout: 30000,
      verbose: false,
      resumeScanId: "scan-def-456",
    });
    expect(runPipelineMock).toHaveBeenCalledOnce();
    expect(runPipelineMock.mock.calls[0]![0].resumeScanId).toBe("scan-def-456");
  });

});
