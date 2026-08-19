/**
 * Dispatch-level scope-guard visibility (pwnkit#133).
 *
 * `ctx.scope` is undefined on every local run without `--scope` and on every
 * cloud scan mode except `http_audit` — the worker-controller dispatcher emits
 * no `--scope` at all. That silently disables the bash egress guards nested in
 * `if (this.ctx.scope)` in `agent/tools.ts`.
 *
 * We deliberately do NOT fail closed by default (it would break every scan
 * mode we ship today). What we DO require is that the absence is impossible to
 * miss: `agenticScan` must emit an operator-facing warning AND write a
 * `scope_guards_inert` event to the scan's own event log at boot. These tests
 * fail if either signal is removed.
 *
 * The scans below are driven onto the early `runtime: "codex"` rejection path
 * — the cheapest way to reach the boot sequence without an LLM provider. The
 * scope-guard block runs before that throw.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { agenticScan } from "./agentic-scanner.js";
import { LlmApiRuntime } from "./runtime/llm-api.js";
import type { ScanConfig } from "@pwnkit/shared";
import type { ScanEvent } from "./scanner.js";

function tmpDbPath(): string {
  return path.join(
    os.tmpdir(),
    `pwnkit-scope-guard-${Date.now()}-${Math.random().toString(36).slice(2)}.db`,
  );
}

function baseConfig(overrides: Partial<ScanConfig> = {}): ScanConfig {
  return {
    target: "https://target.example.invalid",
    depth: "quick",
    format: "json",
    runtime: "codex",
    ...overrides,
  } as ScanConfig;
}

describe("agenticScan — scope-guard visibility (pwnkit#133)", () => {
  let dbPath: string;
  let events: ScanEvent[];
  const ORIGINAL_REQUIRE_SCOPE = process.env.PWNKIT_REQUIRE_SCOPE;

  beforeEach(() => {
    dbPath = tmpDbPath();
    events = [];
    delete process.env.PWNKIT_REQUIRE_SCOPE;
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
    if (ORIGINAL_REQUIRE_SCOPE === undefined) delete process.env.PWNKIT_REQUIRE_SCOPE;
    else process.env.PWNKIT_REQUIRE_SCOPE = ORIGINAL_REQUIRE_SCOPE;
    vi.restoreAllMocks();
  });

  async function runUnscopedScan(config: ScanConfig = baseConfig()): Promise<void> {
    await expect(
      agenticScan({ config, dbPath, onEvent: (e) => { events.push(e); } }),
    ).rejects.toThrow();
  }

  it("warns the operator that the bash egress guards are inert", async () => {
    await runUnscopedScan();

    const warning = events.find((e) => /No engagement scope is configured/.test(e.message));
    expect(warning).toBeDefined();
    expect(warning!.message).toMatch(/INERT/);
    // The remediation has to be in the message or the warning is untriageable.
    expect(warning!.message).toMatch(/--scope/);
    expect(warning!.message).toMatch(/PWNKIT_REQUIRE_SCOPE/);
  });

  it("writes a queryable scope_guards_inert event into the scan's event log", async () => {
    await runUnscopedScan();

    // Cloud scans have no console. The DB event is the durable half of the
    // signal — without it "did the guards run on scan X?" is unanswerable.
    const { pwnkitDB } = await import("@pwnkit/db");
    const db = new pwnkitDB(dbPath);
    const scans = db.listScans();
    expect(scans.length).toBeGreaterThan(0);
    const logged = db.getEvents(scans[0]!.id);
    const inert = logged.find((e: { eventType: string }) => e.eventType === "scope_guards_inert");
    expect(inert).toBeDefined();
    // `payload` round-trips through the DB as JSON.
    const raw = (inert as { payload: unknown }).payload;
    const payload = (typeof raw === "string" ? JSON.parse(raw) : raw) as Record<string, unknown>;
    expect(Array.isArray(payload.inert_guards)).toBe(true);
    expect((payload.inert_guards as string[]).length).toBeGreaterThan(0);
    expect(payload.inert_guards).toContain("bash_out_of_scope_url_refusal");
  });

  it("refuses to start at all under PWNKIT_REQUIRE_SCOPE=1", async () => {
    process.env.PWNKIT_REQUIRE_SCOPE = "1";
    await expect(
      agenticScan({ config: baseConfig(), dbPath, onEvent: (e) => { events.push(e); } }),
    ).rejects.toThrow(/PWNKIT_REQUIRE_SCOPE is set but no engagement scope is configured/);
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
