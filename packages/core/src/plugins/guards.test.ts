import { describe, it, expect } from "vitest";
import {
  evaluateGuards,
  composeGuards,
  sanitizeReason,
  guardNetworkRequiresScope,
  guardApprovalUnavailable,
  guardUnresolvedCapabilities,
  BUILTIN_GUARDS,
  type ToolGuard,
  type GuardContext,
} from "./guards.js";

// A permissive, valid context so each test perturbs exactly one field. Chosen so
// that ALL built-in guards abstain — a clean baseline that the gates above would
// let through, against which we introduce single denials.
function ctx(overrides: Partial<GuardContext> = {}): GuardContext {
  return {
    toolName: "acme_probe",
    networkCapable: false,
    localScope: false,
    readOnly: true,
    autonomyMode: "standard",
    hasScope: true,
    approvalAvailable: true,
    capabilitiesResolved: true,
    ...overrides,
  };
}

// Guard building blocks used across tests.
const abstainNull: ToolGuard = () => null;
const abstainUndef: ToolGuard = () => undefined;
const denyA: ToolGuard = () => "reason A";
const denyB: ToolGuard = () => "reason B";
const throwing: ToolGuard = () => {
  throw new Error("kaboom");
};

// ── deny-only, all-reasons-collected, empty-list, throw ───────────────────────

describe("evaluateGuards — deny-only semantics", () => {
  it("an empty guard list allows (the name-keyed gates above still run)", () => {
    // WHY correct: the guard layer is an ADDITIONAL floor beneath the console's
    // name-keyed gates. An empty floor contributes no denials; it does not (and
    // cannot) remove the gates above it, so allowing here is the right default.
    const v = evaluateGuards([], ctx());
    expect(v.allowed).toBe(true);
    expect(v.reasons).toEqual([]);
  });

  it("abstaining guards (null/undefined) allow", () => {
    const v = evaluateGuards([abstainNull, abstainUndef], ctx());
    expect(v.allowed).toBe(true);
    expect(v.reasons).toEqual([]);
  });

  it("a single string return denies", () => {
    const v = evaluateGuards([denyA], ctx());
    expect(v.allowed).toBe(false);
    expect(v.reasons).toEqual(["reason A"]);
  });

  it("collects EVERY denial reason, not first-wins", () => {
    const v = evaluateGuards([denyA, abstainNull, denyB], ctx());
    expect(v.allowed).toBe(false);
    expect(v.reasons).toEqual(["reason A", "reason B"]);
  });

  it("a throwing guard is a DENIAL (fail closed), naming the failure", () => {
    const v = evaluateGuards([throwing], ctx());
    expect(v.allowed).toBe(false);
    expect(v.reasons).toHaveLength(1);
    expect(v.reasons[0]).toContain("threw during evaluation");
    expect(v.reasons[0]).toContain("kaboom");
  });

  it("a throwing guard does not suppress other guards' denials", () => {
    const v = evaluateGuards([throwing, denyA], ctx());
    expect(v.allowed).toBe(false);
    expect(v.reasons).toHaveLength(2);
    expect(v.reasons[1]).toBe("reason A");
  });

  it("a non-callable entry is a DENIAL (fail closed), never an abstention", () => {
    // A loosely typed JS caller might slip a non-function into the array. It must
    // never be read as 'abstain' (which would silently widen access).
    const junk = [123 as unknown as ToolGuard, denyA];
    const v = evaluateGuards(junk, ctx());
    expect(v.allowed).toBe(false);
    expect(v.reasons).toHaveLength(2);
    expect(v.reasons[0]).toContain("is not callable");
  });

  it("an empty/whitespace string still denies (allow is inexpressible via blank)", () => {
    const blank: ToolGuard = () => "   ";
    const v = evaluateGuards([blank], ctx());
    expect(v.allowed).toBe(false);
    expect(v.reasons).toHaveLength(1);
    expect(v.reasons[0]).toContain("denied without a stated reason");
  });

  it("a guard returning a non-string, non-null value abstains (defensive)", () => {
    // Only a string denies; a stray number/object from an untyped caller is not
    // a denial reason and is treated as abstention. It cannot force-allow others.
    const weird = (() => 42) as unknown as ToolGuard;
    const v = evaluateGuards([weird, denyA], ctx());
    expect(v.allowed).toBe(false);
    expect(v.reasons).toEqual(["reason A"]);
  });
});

// ── reason sanitization ───────────────────────────────────────────────────────

describe("sanitizeReason", () => {
  it("collapses newlines/tabs/CR into a single line", () => {
    const out = sanitizeReason("line1\nline2\r\n\tline3");
    expect(out).not.toMatch(/[\n\r\t]/);
    expect(out).toBe("line1 line2 line3");
  });

  it("strips C0 control chars, DEL, and C1 controls (incl. ANSI ESC)", () => {
    const dirty = "a\u0000b\u001b[31mc\u007fd\u009fe";
    const out = sanitizeReason(dirty);
    // eslint-disable-next-line no-control-regex
    expect(out).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/);
    // The ESC is gone; the residual "[31m" text is inert (no control byte).
    expect(out).toContain("a");
    expect(out).toContain("e");
  });

  it("bounds the length and marks truncation with an ellipsis", () => {
    const out = sanitizeReason("x".repeat(1000));
    expect(out.length).toBeLessThanOrEqual(200);
    expect(out.endsWith("…")).toBe(true);
  });

  it("leaves a clean short string unchanged", () => {
    expect(sanitizeReason("already clean")).toBe("already clean");
  });

  it("reasons surfaced by evaluateGuards are sanitized (single-line, bounded)", () => {
    const nasty: ToolGuard = () => "danger\nzone\u001b[0m" + "y".repeat(1000);
    const v = evaluateGuards([nasty], ctx());
    const r = v.reasons[0];
    expect(r).not.toMatch(/[\n\r\t]/);
    expect(r.length).toBeLessThanOrEqual(200);
  });
});

// ── built-in guards: true/false cases derived from turn-engine gate semantics ──

describe("guardUnresolvedCapabilities", () => {
  it("denies when capability flags are unresolved (danger-by-omission)", () => {
    expect(guardUnresolvedCapabilities(ctx({ capabilitiesResolved: false }))).toMatch(
      /unresolved capability/i,
    );
  });
  it("abstains when capabilities are resolved", () => {
    expect(guardUnresolvedCapabilities(ctx({ capabilitiesResolved: true }))).toBeNull();
  });
  it("fails closed when the flag is missing entirely", () => {
    const bad = { ...ctx(), capabilitiesResolved: undefined } as unknown as GuardContext;
    expect(typeof guardUnresolvedCapabilities(bad)).toBe("string");
  });
});

// RETIRED guard: no longer in BUILTIN_GUARDS nor the console's WIRED_GUARDS
// (its "network requires a preconfigured scope" invariant no longer holds in
// any mode — see the function doc). Its BODY is unchanged, so these unit tests
// still pin its pure behaviour for the backward-compat export; they do NOT
// imply it is wired anywhere.
describe("guardNetworkRequiresScope (RETIRED — pure-behaviour pin only)", () => {
  it("denies a network-capable tool with no scope in yolo mode", () => {
    expect(
      guardNetworkRequiresScope(ctx({ autonomyMode: "yolo", networkCapable: true, hasScope: false })),
    ).toMatch(/network-capable/i);
  });
  it("abstains in yolo when a scope IS configured", () => {
    expect(
      guardNetworkRequiresScope(ctx({ autonomyMode: "yolo", networkCapable: true, hasScope: true })),
    ).toBeNull();
  });
  it("abstains for a non-network tool in yolo with no scope", () => {
    expect(
      guardNetworkRequiresScope(ctx({ autonomyMode: "yolo", networkCapable: false, hasScope: false })),
    ).toBeNull();
  });
  it("abstains in standard/copilot (those modes are NOT hard-deny — no contradiction)", () => {
    // The real gate only hard-denies in yolo; standard/copilot run scope-on-demand
    // or same-origin fallback. Denying here would contradict turn-engine.
    expect(
      guardNetworkRequiresScope(ctx({ autonomyMode: "standard", networkCapable: true, hasScope: false })),
    ).toBeNull();
    expect(
      guardNetworkRequiresScope(ctx({ autonomyMode: "copilot", networkCapable: true, hasScope: false })),
    ).toBeNull();
  });
  it("fails closed on missing flags in yolo", () => {
    const bad = {
      ...ctx({ autonomyMode: "yolo" }),
      networkCapable: undefined,
      hasScope: undefined,
    } as unknown as GuardContext;
    expect(typeof guardNetworkRequiresScope(bad)).toBe("string");
  });
});

describe("guardApprovalUnavailable (standard approval gate, fail-closed)", () => {
  it("denies a non-read-only tool in standard when approval is unavailable", () => {
    expect(
      guardApprovalUnavailable(ctx({ autonomyMode: "standard", readOnly: false, approvalAvailable: false })),
    ).toMatch(/approval/i);
  });
  it("abstains in standard when approval IS available", () => {
    expect(
      guardApprovalUnavailable(ctx({ autonomyMode: "standard", readOnly: false, approvalAvailable: true })),
    ).toBeNull();
  });
  it("abstains for a read-only tool in standard even without approval", () => {
    expect(
      guardApprovalUnavailable(ctx({ autonomyMode: "standard", readOnly: true, approvalAvailable: false })),
    ).toBeNull();
  });
  it("abstains in copilot/yolo/recon (no per-action approval gate there)", () => {
    // copilot and yolo run prompt-free; recon refuses effectful tools via its
    // own capability gate, never via per-action approval. None of them couple
    // dispatch to an approveTool channel, so this guard must not fire there.
    expect(
      guardApprovalUnavailable(ctx({ autonomyMode: "copilot", readOnly: false, approvalAvailable: false })),
    ).toBeNull();
    expect(
      guardApprovalUnavailable(ctx({ autonomyMode: "yolo", readOnly: false, approvalAvailable: false })),
    ).toBeNull();
    expect(
      guardApprovalUnavailable(ctx({ autonomyMode: "recon", readOnly: false, approvalAvailable: false })),
    ).toBeNull();
  });
  it("fails closed on missing flags in standard", () => {
    const bad = {
      ...ctx({ autonomyMode: "standard" }),
      readOnly: undefined,
      approvalAvailable: undefined,
    } as unknown as GuardContext;
    expect(typeof guardApprovalUnavailable(bad)).toBe("string");
  });
});

describe("BUILTIN_GUARDS", () => {
  it("is frozen so the shared default policy cannot be mutated in place", () => {
    expect(Object.isFrozen(BUILTIN_GUARDS)).toBe(true);
  });
  it("passes a clean context and denies a dirty one", () => {
    expect(evaluateGuards(BUILTIN_GUARDS, ctx()).allowed).toBe(true);
    // A context that trips BOTH wired guards: capabilities unresolved
    // (guardUnresolvedCapabilities) AND a standard-mode effectful tool with no
    // approval channel (guardApprovalUnavailable).
    const dirty = evaluateGuards(
      BUILTIN_GUARDS,
      ctx({
        capabilitiesResolved: false,
        autonomyMode: "standard",
        readOnly: false,
        approvalAvailable: false,
      }),
    );
    expect(dirty.allowed).toBe(false);
    // BOTH applicable guards fire — reasons are collected, not first-wins.
    expect(dirty.reasons.length).toBeGreaterThanOrEqual(2);
  });
});

// ── composeGuards ─────────────────────────────────────────────────────────────

describe("composeGuards", () => {
  it("unions groups in order", () => {
    const composed = composeGuards([denyA], [abstainNull, denyB]);
    expect(composed).toHaveLength(3);
    const v = evaluateGuards(composed, ctx());
    expect(v.reasons).toEqual(["reason A", "reason B"]);
  });
  it("skips non-array groups defensively (cannot widen)", () => {
    const composed = composeGuards([denyA], undefined as unknown as ToolGuard[]);
    expect(composed).toEqual([denyA]);
  });
  it("composition is at least as restrictive as any single group", () => {
    const g1 = [abstainNull];
    const g2 = [denyA];
    expect(evaluateGuards(g1, ctx()).allowed).toBe(true);
    expect(evaluateGuards(composeGuards(g1, g2), ctx()).allowed).toBe(false);
  });
});

// ── purity: inputs unmutated ──────────────────────────────────────────────────

describe("purity", () => {
  it("does not mutate the guards array or the context", () => {
    const guards = Object.freeze([denyA, abstainNull, throwing]);
    const c = Object.freeze(ctx({ toolName: "frozen" }));
    // Object.freeze makes an in-place mutation throw; a successful run proves
    // evaluateGuards touched neither input.
    expect(() => evaluateGuards(guards, c)).not.toThrow();
    const v = evaluateGuards(guards, c);
    expect(c.toolName).toBe("frozen");
    expect(guards).toHaveLength(3);
    // Determinism: same inputs → identical verdict.
    expect(evaluateGuards(guards, c)).toEqual(v);
  });
});

// ── THE CENTREPIECE: monotonicity property sweep ──────────────────────────────
//
// A seeded PRNG (mulberry32) keeps this deterministic — no clock, no external
// dependency, reproducible on every run. We generate many random guard sets and
// contexts, evaluate, then evaluate again with an arbitrary extra guard APPENDED,
// and assert the result is never LESS restrictive: a denied verdict can never
// become allowed, and the reason set can only grow.

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe("monotonicity — the central property", () => {
  it("appending any guard never turns a denial into an allowance (10k trials)", () => {
    const rand = mulberry32(0x05ecf00d);
    const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)];

    // A pool of arbitrary guards spanning every behaviour: abstain, deny with
    // varied (and hostile) reasons, throw, and non-callable junk.
    const pool: ToolGuard[] = [
      () => null,
      () => undefined,
      () => "deny-1",
      () => "deny-2",
      () => "",
      () => "reason\nwith\u001b[31m控制" + "z".repeat(300),
      () => {
        throw new Error("boom");
      },
      () => {
        throw "string-throw";
      },
      123 as unknown as ToolGuard,
      // Real built-ins, so the sweep also exercises actual policy.
      guardUnresolvedCapabilities,
      guardNetworkRequiresScope,
      guardApprovalUnavailable,
    ];

    const modes: GuardContext["autonomyMode"][] = ["standard", "copilot", "yolo"];
    const bool = (): boolean => rand() < 0.5;
    const randCtx = (): GuardContext => ({
      toolName: "t" + Math.floor(rand() * 1000),
      networkCapable: bool(),
      localScope: bool(),
      readOnly: bool(),
      autonomyMode: pick(modes),
      hasScope: bool(),
      approvalAvailable: bool(),
      capabilitiesResolved: bool(),
    });

    const TRIALS = 10_000;
    let violation: string | undefined;
    for (let i = 0; i < TRIALS; i++) {
      const n = Math.floor(rand() * 5); // 0..4 base guards
      const base: ToolGuard[] = [];
      for (let j = 0; j < n; j++) base.push(pick(pool));
      const extra = pick(pool);
      const c = randCtx();

      const before = evaluateGuards(base, c);
      const after = evaluateGuards([...base, extra], c);

      // (1) Monotone allow: if the extended set allows, the base must too.
      //     Equivalently, a base denial can never become an extended allowance.
      if (after.allowed && !before.allowed) {
        violation = `trial ${i}: an appended guard widened access`;
        break;
      }

      // (2) Reasons only grow: base reasons are a PREFIX of the extended reasons
      //     (append-only, order-preserving), so the reason SET can never shrink.
      if (
        after.reasons.length < before.reasons.length ||
        before.reasons.some((reason, index) => after.reasons[index] !== reason)
      ) {
        violation = `trial ${i}: an appended guard removed or reordered a denial reason`;
        break;
      }
    }

    expect(violation).toBeUndefined();
  });

  it("no guard can force-allow another guard's denial (adding an 'allow-ish' guard)", () => {
    // There is no allow value, but even the most permissive-looking guard (always
    // abstains) cannot rescue a denied call.
    const alwaysAbstain: ToolGuard = () => null;
    const v = evaluateGuards([denyA, alwaysAbstain, abstainUndef], ctx());
    expect(v.allowed).toBe(false);
    expect(v.reasons).toContain("reason A");
  });
});
