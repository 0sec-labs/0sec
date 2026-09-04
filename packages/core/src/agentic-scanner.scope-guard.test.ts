/**
 * Scope admission for the public engine.
 *
 * Live network targets must fail before scan initialization without a scope.
 * Explicitly local modes retain the existing opt-in global strictness switch.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { agenticScan } from "./agentic-scanner.js";
import { LlmApiRuntime } from "./runtime/llm-api.js";
import type { ScanConfig } from "@0sec/shared";
import type { ScanEvent } from "./scanner.js";

function tmpDbPath(): string {
  return path.join(
    os.tmpdir(),
    `0sec-scope-guard-${Date.now()}-${Math.random().toString(36).slice(2)}.db`,
  );
}

function baseConfig(overrides: Partial<ScanConfig> = {}): ScanConfig {
  return {
    target: "https://target.example.invalid",
    depth: "quick",
    format: "json",
    runtime: "api",
    ...overrides,
  } as ScanConfig;
}

describe("agenticScan — scope-guard visibility (0sec#133)", () => {
  let dbPath: string;
  let events: ScanEvent[];
  const ORIGINAL_REQUIRE_SCOPE = process.env["0SEC_REQUIRE_SCOPE"];

  beforeEach(() => {
    dbPath = tmpDbPath();
    events = [];
    delete process.env["0SEC_REQUIRE_SCOPE"];
    // Don't let a developer's persisted provider login turn these into live
    // native scans (same guard as agentic-scanner.events.test.ts).
    vi.spyOn(LlmApiRuntime.prototype, "getConfigurationDiagnostics").mockReturnValue({
      valid: false,
      provider: "openrouter",
      providerLabel: "OpenRouter",
      reason: "missing_key",
    });
  });

  afterEach(() => {
    try { fs.unlinkSync(dbPath); } catch { /* ignore */ }
    if (ORIGINAL_REQUIRE_SCOPE === undefined) delete process.env["0SEC_REQUIRE_SCOPE"];
    else process.env["0SEC_REQUIRE_SCOPE"] = ORIGINAL_REQUIRE_SCOPE;
    vi.restoreAllMocks();
  });

  async function runUnscopedScan(config: ScanConfig = baseConfig()): Promise<void> {
    await expect(
      agenticScan({ config, dbPath, onEvent: (e) => { events.push(e); } }),
    ).rejects.toThrow();
  }

  it("refuses an unscoped live target before scan initialization", async () => {
    await expect(
      agenticScan({ config: baseConfig(), dbPath, onEvent: (e) => { events.push(e); } }),
    ).rejects.toThrow(/live network target .* requires an engagement scope/);

    expect(events).toEqual([]);
    expect(fs.existsSync(dbPath)).toBe(false);
  });

  it("keeps the global strictness switch for unscoped local modes", async () => {
    process.env["0SEC_REQUIRE_SCOPE"] = "1";
    await expect(
      agenticScan({
        config: baseConfig({ target: "lodash" }),
        dbPath,
        onEvent: (e) => { events.push(e); },
      }),
    ).rejects.toThrow(/0SEC_REQUIRE_SCOPE is set but no engagement scope is configured/);
  });

  it("stays silent when http_audit synthesises a host policy (guards active)", async () => {
    // http_audit is the one cloud mode that DOES get a ScopePolicy — built
    // in-memory from httpAuditAllowedHosts rather than from a --scope file.
    // It must not be warned at.
    await runUnscopedScan(
      baseConfig({
        mode: "http_audit",
        httpAuditAllowedHosts: ["target.example.invalid"],
      } as Partial<ScanConfig>),
    );

    expect(events.find((e) => /No engagement scope is configured/.test(e.message))).toBeUndefined();
  });
});
