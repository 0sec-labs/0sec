import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { getMaxTurns } from "./agent-runner.js";

/**
 * Turn-budget resolution. The raised defaults are only safe because prompt
 * caching removed the per-turn history re-prefill cost that motivated the old
 * caps, and because `costCeilingUsd` — not the turn count — is the real spend
 * guard. These tests pin both the numbers and the override precedence so a
 * sweep can move them without a rebuild.
 */
describe("getMaxTurns defaults", () => {
  const origEnv = { ...process.env };

  beforeEach(() => {
    delete process.env["0SEC_MAX_TURNS"];
    delete process.env["0SEC_MAX_TURNS_VERIFY"];
    delete process.env["0SEC_MAX_TURNS_AUDIT"];
    delete process.env["0SEC_MAX_TURNS_REVIEW"];
  });

  afterEach(() => {
    Object.assign(process.env, origEnv);
  });

  it("gives verify enough turns to actually debug a PoC", () => {
    // Reproducing a finding costs ~6 turns with zero slack (read → write PoC →
    // run → read failure → fix → re-run). The old cap of 8 turned a mid-debug
    // truncation into a "could not reproduce" verdict.
    expect(getMaxTurns("review", "default", "native", "verify")).toBe(20);
    expect(getMaxTurns("audit", "deep", "native", "verify")).toBe(20);
  });

  it("caps verify independently of depth", () => {
    const depths = [undefined, "quick", "default", "deep"];
    const budgets = depths.map((d) => getMaxTurns("review", d, "native", "verify"));
    expect(new Set(budgets).size).toBe(1);
  });

  it("raises native research budgets", () => {
    expect(getMaxTurns("audit", "deep", "native")).toBe(60);
    expect(getMaxTurns("audit", "default", "native")).toBe(40);
    expect(getMaxTurns("audit", "quick", "native")).toBe(15);

    expect(getMaxTurns("review", "deep", "native")).toBe(150);
    expect(getMaxTurns("review", "default", "native")).toBe(60);
    expect(getMaxTurns("review", "quick", "native")).toBe(20);
  });

  it("leaves the legacy branch alone — it has no prompt caching", () => {
    // Legacy goes through execute() (prompt-in/text-out); caching is only on
    // the native path, so the argument for raising these does not apply.
    expect(getMaxTurns("audit", "deep", "legacy")).toBe(50);
    expect(getMaxTurns("audit", "default", "legacy")).toBe(50);
    expect(getMaxTurns("audit", "quick", "legacy")).toBe(15);
    expect(getMaxTurns("review", "deep", "legacy")).toBe(100);
    expect(getMaxTurns("review", "default", "legacy")).toBe(50);
    expect(getMaxTurns("review", "quick", "legacy")).toBe(15);
  });

  it("defaults to the research budget when purpose is omitted", () => {
    expect(getMaxTurns("review", "deep", "native")).toBe(
      getMaxTurns("review", "deep", "native", "research"),
    );
  });

  it("stays at or below the ~169-turn competitive reference", () => {
    for (const role of ["audit", "review"] as const) {
      for (const depth of ["quick", "default", "deep"]) {
        for (const branch of ["native", "legacy"] as const) {
          expect(getMaxTurns(role, depth, branch)).toBeLessThanOrEqual(169);
        }
      }
    }
  });
});

describe("getMaxTurns env overrides", () => {
  const origEnv = { ...process.env };

  beforeEach(() => {
    delete process.env["0SEC_MAX_TURNS"];
    delete process.env["0SEC_MAX_TURNS_VERIFY"];
    delete process.env["0SEC_MAX_TURNS_AUDIT"];
    delete process.env["0SEC_MAX_TURNS_REVIEW"];
  });

  afterEach(() => {
    Object.assign(process.env, origEnv);
  });

  it("0SEC_MAX_TURNS overrides every role, depth, and branch", () => {
    process.env["0SEC_MAX_TURNS"] = "7";
    expect(getMaxTurns("audit", "deep", "native")).toBe(7);
    expect(getMaxTurns("review", "quick", "legacy")).toBe(7);
    expect(getMaxTurns("review", "default", "native", "verify")).toBe(7);
  });

  it("0SEC_MAX_TURNS_VERIFY scopes to verify runs only", () => {
    process.env["0SEC_MAX_TURNS_VERIFY"] = "33";
    expect(getMaxTurns("review", "deep", "native", "verify")).toBe(33);
    expect(getMaxTurns("review", "deep", "native", "research")).toBe(150);
  });

  it("0SEC_MAX_TURNS_AUDIT and _REVIEW scope to their role", () => {
    process.env["0SEC_MAX_TURNS_AUDIT"] = "11";
    process.env["0SEC_MAX_TURNS_REVIEW"] = "22";
    expect(getMaxTurns("audit", "deep", "native")).toBe(11);
    expect(getMaxTurns("review", "deep", "native")).toBe(22);
    // Verify has its own scope and is untouched by the role overrides.
    expect(getMaxTurns("audit", "deep", "native", "verify")).toBe(20);
  });

  it("the specific override wins over the global one", () => {
    process.env["0SEC_MAX_TURNS"] = "5";
    process.env["0SEC_MAX_TURNS_VERIFY"] = "50";
    process.env["0SEC_MAX_TURNS_REVIEW"] = "60";
    expect(getMaxTurns("review", "deep", "native", "verify")).toBe(50);
    expect(getMaxTurns("review", "deep", "native")).toBe(60);
    // Audit has no specific override set, so it falls through to the global.
    expect(getMaxTurns("audit", "deep", "native")).toBe(5);
  });

  it("ignores invalid values rather than clamping them", () => {
    // A typo'd sweep parameter must fall back to the tuned default, not pin the
    // agent to a single turn.
    for (const bad of ["0", "-4", "abc", "", "  ", "3.5", "NaN"]) {
      process.env["0SEC_MAX_TURNS_VERIFY"] = bad;
      expect(getMaxTurns("review", "default", "native", "verify")).toBe(20);
    }
  });

  it("allows raising budgets well past the defaults for sweeps", () => {
    process.env["0SEC_MAX_TURNS_REVIEW"] = "400";
    expect(getMaxTurns("review", "deep", "native")).toBe(400);
  });
});
