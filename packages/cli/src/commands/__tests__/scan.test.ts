/**
 * Coverage seed for `pwnkit-cli`'s `scan` command. We register the
 * subcommand on a fresh Commander program, mock the heavy collaborators
 * (`runUnified` from `./run.js`, plus the `@pwnkit/core` scope/
 * attribution helpers), and assert on (a) invalid-input exit codes, and
 * (b) the option payload threaded down to `runUnified`.
 *
 * Anything that actually scans the web is out of scope: `runUnified` is
 * mocked to a noop, so we never reach the LLM runtime or the network.
 *
 * Notes on coverage gaps:
 *   • The internal `parseAuthFlag` helper is not exported, so we exercise
 *     it through the `--auth` flag.
 *   • `--replay` opens `@pwnkit/db`'s WASM SQLite shim — exercising that
 *     path needs a temp DB file, so we skip it in the seed.
 */

import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { Command } from "commander";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ScanReport } from "@pwnkit/shared";

// ── Module-level mocks ──────────────────────────────────────────────────────

const runUnifiedMock = vi.fn();
vi.mock("../run.js", () => ({
  runUnified: runUnifiedMock,
}));

const loadScopeMock = vi.fn();
const parseRateLimitFlagMock = vi.fn();
const resolveAttributionMock = vi.fn();
const extractAttributionFromScopeJsonMock = vi.fn();
const resolveEngagementProfileMock = vi.fn();
const extractEngagementFromScopeJsonMock = vi.fn();
const targetRequiresScopeMock = vi.fn((target: string) => /^https?:\/\//.test(target));
const networkScopeRequiredRefusalMock = vi.fn((target: string) => `scope required for ${target}`);
vi.mock("@pwnkit/core", () => ({
  loadScope: loadScopeMock,
  parseRateLimitFlag: parseRateLimitFlagMock,
  resolveAttribution: resolveAttributionMock,
  extractAttributionFromScopeJson: extractAttributionFromScopeJsonMock,
  resolveEngagementProfile: resolveEngagementProfileMock,
  extractEngagementFromScopeJson: extractEngagementFromScopeJsonMock,
  targetRequiresScope: targetRequiresScopeMock,
  networkScopeRequiredRefusal: networkScopeRequiredRefusalMock,
}));

const { registerScanCommand } = await import("../scan.js");

// ── Helpers ─────────────────────────────────────────────────────────────────

interface ExitTracker {
  firstCode?: number;
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function makeExitMock(tracker: ExitTracker): any {
  return vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
    const c = (code ?? 0) as number;
    if (tracker.firstCode === undefined) tracker.firstCode = c;
    const err = new Error(`__exit__:${c}`);
    throw err;
  }) as never);
}

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  // Commander writes usage errors directly to process.stderr (bypassing
  // console.error). Redirect to a no-op so test output stays quiet on
  // missing-required-option tests.
  program.configureOutput({
    writeOut: () => undefined,
    writeErr: () => undefined,
  });
  registerScanCommand(program);

  const effectiveArgv = [...argv];
  const targetIndex = effectiveArgv.indexOf("--target");
  const target = targetIndex === -1 ? undefined : effectiveArgv[targetIndex + 1];
  const isHttpAudit = effectiveArgv.includes("--mode")
    && effectiveArgv[effectiveArgv.indexOf("--mode") + 1] === "http_audit";
  if (
    effectiveArgv[0] === "scan"
    && target
    && targetRequiresScopeMock(target)
    && !isHttpAudit
    && !effectiveArgv.includes("--scope")
  ) {
    effectiveArgv.push("--scope", defaultScopePath);
  }

  try {
    await program.parseAsync(["node", "pwnkit", ...effectiveArgv]);
  } catch {
    // commander.exitOverride() throws CommanderError on usage errors,
    // and our process.exit mock throws on hard exits. Both are expected.
  }
}

// ── Tests ───────────────────────────────────────────────────────────────────

let tracker: ExitTracker;
let exitSpy: { mockRestore: () => void };
let errSpy: MockInstance;
let logSpy: MockInstance;
let tmpRoot: string;
let defaultScopePath = "";

beforeEach(() => {
  runUnifiedMock.mockReset().mockResolvedValue(undefined);
  loadScopeMock.mockReset().mockReturnValue({
    raw: {},
    match: () => ({ allowed: true }),
  });
  parseRateLimitFlagMock.mockReset();
  resolveAttributionMock.mockReset();
  extractAttributionFromScopeJsonMock.mockReset();
  resolveEngagementProfileMock.mockReset();
  extractEngagementFromScopeJsonMock.mockReset();
  targetRequiresScopeMock.mockClear();
  networkScopeRequiredRefusalMock.mockClear();
  tracker = {};
  exitSpy = makeExitMock(tracker);
  errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
  tmpRoot = mkdtempSync(join(tmpdir(), "pwnkit-scan-test-"));
  defaultScopePath = join(tmpRoot, "scope.json");
  writeFileSync(defaultScopePath, "{}");
});

afterEach(() => {
  exitSpy.mockRestore();
  errSpy.mockRestore();
  logSpy.mockRestore();
  rmSync(tmpRoot, { recursive: true, force: true });
});

describe("scan — happy path option-threading", () => {
  it("forwards defaults to runUnified (auto runtime, depth=default, mode auto-detected to 'web')", async () => {
    await runCli(["scan", "--target", "https://example.com"]);
    expect(runUnifiedMock).toHaveBeenCalledOnce();
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.target).toBe("https://example.com");
    expect(opts.targetType).toBe("url");
    expect(opts.runtime).toBe("auto");
    expect(opts.depth).toBe("default");
    // pwnkit#... http(s) → mode "web" by default
    expect(opts.mode).toBe("web");
    expect(opts.format).toBe("terminal");
    expect(opts.timeout).toBe(30000);
    expect(opts.race).toBe(false);
  });

  it("keeps benchmark racing as an explicit opt-in mode", async () => {
    await runCli(["scan", "--target", "https://example.com", "--race"]);
    const opts = runUnifiedMock.mock.calls[0]![0];

    expect(opts.mode).toBe("web");
    expect(opts.race).toBe(true);
  });

  it("auto-detects mode=mcp for mcp:// targets", async () => {
    await runCli(["scan", "--target", "mcp://localhost:3000"]);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.mode).toBe("mcp");
  });

  it("auto-detects mode=deep for non-http/non-mcp targets", async () => {
    await runCli(["scan", "--target", "some-internal-host"]);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.mode).toBe("deep");
  });

  it("normalises --format md to 'markdown' for runUnified", async () => {
    await runCli(["scan", "--target", "https://example.com", "--format", "md"]);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.format).toBe("markdown");
  });

  it("forwards --depth, --runtime, --timeout, --model verbatim", async () => {
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--depth",
      "deep",
      "--runtime",
      "claude",
      "--timeout",
      "60000",
      "--model",
      "claude-opus",
    ]);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.depth).toBe("deep");
    expect(opts.runtime).toBe("claude");
    expect(opts.timeout).toBe(60000);
    expect(opts.model).toBe("claude-opus");
  });
});

describe("scan — --auth parsing", () => {
  it("parses inline JSON --auth into AuthConfig", async () => {
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--auth",
      '{"type":"bearer","token":"abc"}',
    ]);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.auth).toEqual({ type: "bearer", token: "abc" });
  });

  it("loads --auth from a JSON file path", async () => {
    const path = join(tmpRoot, "auth.json");
    writeFileSync(path, JSON.stringify({ type: "cookie", value: "session=xyz" }));
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--auth",
      path,
    ]);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.auth).toEqual({ type: "cookie", value: "session=xyz" });
  });

  it("rejects invalid --auth JSON with exit code 2", async () => {
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--auth",
      "{not valid",
    ]);
    expect(tracker.firstCode).toBe(2);
    expect(errSpy.mock.calls.map((c) => String(c[0])).join("\n")).toMatch(
      /Invalid --auth/,
    );
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });

  it("rejects --auth with unknown type", async () => {
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--auth",
      '{"type":"oauth2","token":"x"}',
    ]);
    expect(tracker.firstCode).toBe(2);
    expect(errSpy.mock.calls.map((c) => String(c[0])).join("\n")).toMatch(
      /must be one of/,
    );
  });
});

describe("scan — --scope validation", () => {
  it("exits 2 when --scope file is missing", async () => {
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--scope",
      "/nonexistent/scope.json",
    ]);
    expect(tracker.firstCode).toBe(2);
    expect(errSpy.mock.calls.map((c) => String(c[0])).join("\n")).toMatch(
      /file not found/,
    );
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });

  it("exits 2 when --target is out of scope per the loaded scope file", async () => {
    const scopePath = join(tmpRoot, "scope.json");
    writeFileSync(scopePath, "{}");
    loadScopeMock.mockReturnValue({
      raw: {},
      match: () => ({ allowed: false, reason: "host not in scope" }),
    });
    await runCli([
      "scan",
      "--target",
      "https://evil.example.com",
      "--scope",
      scopePath,
    ]);
    expect(tracker.firstCode).toBe(2);
    expect(errSpy.mock.calls.map((c) => String(c[0])).join("\n")).toMatch(
      /out of scope/,
    );
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });

  it("threads scope file + allowScanners through to runUnified on the happy path", async () => {
    const scopePath = join(tmpRoot, "scope.json");
    writeFileSync(scopePath, "{}");
    loadScopeMock.mockReturnValue({
      raw: {},
      match: () => ({ allowed: true }),
    });
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--scope",
      scopePath,
      "--allow-scanners",
    ]);
    expect(runUnifiedMock).toHaveBeenCalledOnce();
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.scopeFile).toBe(scopePath);
    expect(opts.allowScanners).toBe(true);
  });
});

describe("scan — engagement hardening profile", () => {
  it("threads --engagement-profile through to runUnified", async () => {
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--engagement-profile",
      "conservative",
    ]);
    expect(runUnifiedMock).toHaveBeenCalledOnce();
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.engagementProfile).toBe("conservative");
    // The posture is pre-validated at boot, through the core resolver.
    expect(resolveEngagementProfileMock).toHaveBeenCalledWith(
      expect.objectContaining({ cliProfile: "conservative" }),
    );
  });

  it("--no-waf-evasion sets wafEvasion=false; absence leaves it unset", async () => {
    await runCli(["scan", "--target", "https://example.com", "--no-waf-evasion"]);
    expect(runUnifiedMock.mock.calls[0]![0].wafEvasion).toBe(false);

    runUnifiedMock.mockClear();
    await runCli(["scan", "--target", "https://example.com"]);
    const opts = runUnifiedMock.mock.calls[0]![0];
    // Unset, NOT `true` — so the scope file / env keep their precedence.
    expect(opts.wafEvasion).toBeUndefined();
    expect(opts.engagementProfile).toBeUndefined();
  });

  it("exits 2 when the profile fails validation in core", async () => {
    resolveEngagementProfileMock.mockImplementation(() => {
      throw new Error("Unknown engagement profile 'stealth'. Supported: standard, conservative.");
    });
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--engagement-profile",
      "stealth",
    ]);
    expect(tracker.firstCode).toBe(2);
    expect(errSpy.mock.calls.map((c) => String(c[0])).join("\n")).toMatch(
      /Unknown engagement profile/,
    );
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });
});

describe("scan — --cost-ceiling validation", () => {
  it("accepts a positive number", async () => {
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--cost-ceiling",
      "12.5",
    ]);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.costCeilingUsd).toBe(12.5);
  });

  it("rejects zero or negative values with exit 2", async () => {
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--cost-ceiling",
      "0",
    ]);
    expect(tracker.firstCode).toBe(2);
    expect(errSpy.mock.calls.map((c) => String(c[0])).join("\n")).toMatch(
      /Invalid cost ceiling/,
    );
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });

  it("rejects non-numeric values", async () => {
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--cost-ceiling",
      "lots",
    ]);
    expect(tracker.firstCode).toBe(2);
    expect(errSpy.mock.calls.map((c) => String(c[0])).join("\n")).toMatch(
      /Invalid cost ceiling/,
    );
  });
});

describe("scan — --rate-limit pre-flight", () => {
  it("calls parseRateLimitFlag for validation, threads value through on success", async () => {
    parseRateLimitFlagMock.mockReturnValueOnce({ default: 5 });
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--rate-limit",
      "5",
    ]);
    expect(parseRateLimitFlagMock).toHaveBeenCalledWith("5");
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.rateLimit).toBe("5");
  });

  it("exits 2 when parseRateLimitFlag throws", async () => {
    parseRateLimitFlagMock.mockImplementationOnce(() => {
      throw new Error("malformed rate-limit spec");
    });
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--rate-limit",
      "garbage:::",
    ]);
    expect(tracker.firstCode).toBe(2);
    expect(errSpy.mock.calls.map((c) => String(c[0])).join("\n")).toMatch(
      /malformed rate-limit/,
    );
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });
});

describe("scan — --features and --no-decoy-detection toggle env vars", () => {
  const envSnapshot: Record<string, string | undefined> = {};

  beforeEach(() => {
    envSnapshot.PWNKIT_FEATURE_WP_FINGERPRINT = process.env.PWNKIT_FEATURE_WP_FINGERPRINT;
    envSnapshot.PWNKIT_FEATURE_WEB_SEARCH = process.env.PWNKIT_FEATURE_WEB_SEARCH;
    envSnapshot.PWNKIT_FEATURE_DECOY_DETECTION = process.env.PWNKIT_FEATURE_DECOY_DETECTION;
    delete process.env.PWNKIT_FEATURE_WP_FINGERPRINT;
    delete process.env.PWNKIT_FEATURE_WEB_SEARCH;
    delete process.env.PWNKIT_FEATURE_DECOY_DETECTION;
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(envSnapshot)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  it("--features wp_fingerprint,web_search sets PWNKIT_FEATURE_* env vars", async () => {
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--features",
      "wp_fingerprint,web_search",
    ]);
    expect(process.env.PWNKIT_FEATURE_WP_FINGERPRINT).toBe("1");
    expect(process.env.PWNKIT_FEATURE_WEB_SEARCH).toBe("1");
  });

  it("--no-decoy-detection sets PWNKIT_FEATURE_DECOY_DETECTION=0", async () => {
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--no-decoy-detection",
    ]);
    expect(process.env.PWNKIT_FEATURE_DECOY_DETECTION).toBe("0");
  });
});

describe("scan — --emit pr (pwnkit#377)", () => {
  it("threads --emit pr + --base + --dry-run into runUnified", async () => {
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--emit",
      "pr",
      "--base",
      "develop",
      "--dry-run",
    ]);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.emit).toBe("pr");
    expect(opts.emitPrBase).toBe("develop");
    expect(opts.emitPrDryRun).toBe(true);
  });

  it("rejects an unknown --emit target with exit code 2", async () => {
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--emit",
      "junk",
    ]);
    expect(tracker.firstCode).toBe(2);
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });
});

describe("scan — required --target", () => {
  it("commander rejects when --target is missing", async () => {
    // We don't assert exit code (commander's exitOverride throws), but
    // runUnified must NOT be called.
    await runCli(["scan"]);
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });
});

describe("scan — --resume (pwnkit#374)", () => {
  it("threads --resume into runUnified as resumeScanId", async () => {
    await runCli([
      "scan",
      "--target",
      "https://example.com",
      "--resume",
      "run-abc-123",
    ]);
    expect(runUnifiedMock).toHaveBeenCalledOnce();
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.resumeScanId).toBe("run-abc-123");
  });

  it("does not set resumeScanId when --resume is omitted", async () => {
    await runCli(["scan", "--target", "https://example.com"]);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.resumeScanId).toBeUndefined();
  });
});

describe("scan — http_audit env bridge (FROZEN CONTRACT)", () => {
  const TARGET_ENV = [
    "PWNKIT_TARGET_BASE_URL",
    "PWNKIT_TARGET_AUTH_JSON",
    "PWNKIT_TARGET_ALLOWED_HOSTS",
    "PWNKIT_TARGET_ALLOWED_PATHS",
    "PWNKIT_TARGET_RATE_LIMIT_RPS",
    "PWNKIT_TARGET_KILL_AFTER_SEC",
  ];
  const saved: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const k of TARGET_ENV) { saved[k] = process.env[k]; delete process.env[k]; }
  });
  afterEach(() => {
    for (const k of TARGET_ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  it("threads env-derived hosts/paths/rps/kill + auth into runUnified", async () => {
    process.env.PWNKIT_TARGET_BASE_URL = "https://api.example.com";
    process.env.PWNKIT_TARGET_AUTH_JSON = JSON.stringify({ type: "bearer", token: "SECRET" });
    process.env.PWNKIT_TARGET_ALLOWED_HOSTS = JSON.stringify(["api.example.com", "cdn.example.com"]);
    process.env.PWNKIT_TARGET_ALLOWED_PATHS = JSON.stringify(["/api"]);
    process.env.PWNKIT_TARGET_RATE_LIMIT_RPS = "3";
    process.env.PWNKIT_TARGET_KILL_AFTER_SEC = "600";
    await runCli(["scan", "--target", "https://api.example.com", "--mode", "http_audit", "--format", "json"]);
    expect(runUnifiedMock).toHaveBeenCalledOnce();
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.mode).toBe("http_audit");
    expect(opts.httpAuditAllowedHosts).toEqual(["api.example.com", "cdn.example.com"]);
    expect(opts.httpAuditAllowedPaths).toEqual(["/api"]);
    expect(opts.httpAuditRateLimitRps).toBe(3);
    expect(opts.httpAuditKillAfterSec).toBe(600);
    expect(opts.auth).toEqual({ type: "bearer", token: "SECRET" });
  });

  it("defaults allowed hosts to the base host and applies rps/kill defaults", async () => {
    process.env.PWNKIT_TARGET_BASE_URL = "https://only.example.com";
    await runCli(["scan", "--target", "https://only.example.com", "--mode", "http_audit", "--format", "json"]);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.httpAuditAllowedHosts).toEqual(["only.example.com"]);
    expect(opts.httpAuditAllowedPaths).toEqual([]); // empty = allow all paths
    expect(opts.httpAuditRateLimitRps).toBe(5);
    expect(opts.httpAuditKillAfterSec).toBe(1800);
  });

  it("fails fast (exit 2, no scan) on malformed PWNKIT_TARGET_ALLOWED_HOSTS", async () => {
    process.env.PWNKIT_TARGET_BASE_URL = "https://api.example.com";
    process.env.PWNKIT_TARGET_ALLOWED_HOSTS = "{not json}";
    await runCli(["scan", "--target", "https://api.example.com", "--mode", "http_audit", "--format", "json"]);
    expect(tracker.firstCode).toBe(2);
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });

  it("fails fast on a non-integer PWNKIT_TARGET_RATE_LIMIT_RPS", async () => {
    process.env.PWNKIT_TARGET_BASE_URL = "https://api.example.com";
    process.env.PWNKIT_TARGET_RATE_LIMIT_RPS = "5.5";
    await runCli(["scan", "--target", "https://api.example.com", "--mode", "http_audit", "--format", "json"]);
    expect(tracker.firstCode).toBe(2);
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });

  it("does NOT set http_audit fields for a normal web scan", async () => {
    await runCli(["scan", "--target", "https://example.com", "--mode", "web"]);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.mode).toBe("web");
    expect(opts.httpAuditAllowedHosts).toBeUndefined();
    expect(opts.httpAuditAllowedPaths).toBeUndefined();
  });
});

// Silence "unused" warnings for the imported ScanReport type (kept for
// readers who want to extend these tests with report-shape assertions).
void ({} as ScanReport | undefined);
