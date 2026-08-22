import { describe, it, expect, vi } from "vitest";

import {
  SelfExtensionRegistry,
  SELF_EXTENSION_SETTING_DEF,
  MAX_EXTENSIONS_PER_SESSION,
  MAX_TOOLS_PER_EXTENSION,
  MAX_TOOLS_PER_SESSION,
  MAX_GUARDS_PER_EXTENSION,
  MAX_MANIFEST_BYTES,
  type ExtensionSubmission,
  type SelfExtensionEvent,
} from "./self-extension.js";
import { BUILTIN_GUARDS, type GuardContext, type ToolGuard } from "./guards.js";

// ── fixtures ─────────────────────────────────────────────────────────────────

/** Names the caller (the console wiring) declares reserved. */
const RESERVED = ["run_command", "http_request", "read_file", "save_finding", "done"];

function manifest(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "acme.probe-pack",
    name: "Probe Pack",
    version: "1.0.0",
    tools: [
      {
        name: "acme_probe",
        description: "Probe a thing.",
        parameters: { url: { type: "string", description: "target" } },
        required: ["url"],
        capabilities: ["network"],
      },
    ],
    ...over,
  };
}

function registry(over: Partial<ConstructorParameters<typeof SelfExtensionRegistry>[0]> = {}) {
  return new SelfExtensionRegistry({
    enabled: true,
    reservedToolNames: RESERVED,
    baseGuards: BUILTIN_GUARDS,
    now: () => 1_700_000_000_000,
    ...over,
  });
}

/** A permissive context under which every built-in guard abstains. */
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

// ── 1. a well-formed contribution registers with correct gate flags ──────────

describe("registration — the happy path", () => {
  it("registers a well-formed contribution and exposes its tools", () => {
    const r = registry();
    const res = r.register({ manifest: manifest() });

    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.record.pluginId).toBe("acme.probe-pack");
    expect(res.record.version).toBe("1.0.0");
    expect(res.record.origin).toBe("model");
    expect(res.record.registeredAt).toBe(1_700_000_000_000);
    expect(r.tools().map((t) => t.name)).toEqual(["acme_probe"]);
  });

  it("gate flags come from gateFlagsFor, not a second translation", () => {
    const r = registry();
    r.register({
      manifest: manifest({
        tools: [
          {
            name: "net_tool",
            description: "d",
            parameters: {},
            capabilities: ["network"],
          },
          {
            name: "read_tool",
            description: "d",
            parameters: {},
            capabilities: ["filesystem-read"],
          },
          {
            name: "exec_tool",
            description: "d",
            parameters: {},
            capabilities: ["process-exec", "filesystem-write"],
          },
        ],
      }),
    });

    // network ⇒ network-capable, not read-only.
    expect(r.gateFlagsForTool("net_tool")).toEqual({
      networkCapable: true,
      localScope: false,
      readOnly: false,
    });
    // filesystem-read is the only pure read ⇒ the sole read-only case.
    expect(r.gateFlagsForTool("read_tool")).toEqual({
      networkCapable: false,
      localScope: true,
      readOnly: true,
    });
    // process-exec implies egress; filesystem-write is local + effectful.
    expect(r.gateFlagsForTool("exec_tool")).toEqual({
      networkCapable: true,
      localScope: true,
      readOnly: false,
    });
  });

  it("an unknown tool name yields undefined flags, never a permissive default", () => {
    const r = registry();
    r.register({ manifest: manifest() });
    expect(r.gateFlagsForTool("not_a_tool")).toBeUndefined();
  });
});

// ── 2. the setting gates everything, default OFF ─────────────────────────────

describe("the operator setting", () => {
  it("defaults to OFF and refuses registration when not explicitly enabled", () => {
    const off = new SelfExtensionRegistry({ reservedToolNames: RESERVED });
    expect(off.isEnabled()).toBe(false);
    const res = off.register({ manifest: manifest() });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errors.join(" ")).toMatch(/disabled/);
    expect(off.tools()).toEqual([]);
  });

  it("a non-boolean `enabled` fails closed", () => {
    const sneaky = new SelfExtensionRegistry({
      enabled: "yes" as unknown as boolean,
      reservedToolNames: RESERVED,
    });
    expect(sneaky.isEnabled()).toBe(false);
  });

  it("exposes no setter for the flag — it is operator state, not model state", () => {
    const r = registry();
    expect((r as unknown as Record<string, unknown>).setEnabled).toBeUndefined();
    expect((r as unknown as Record<string, unknown>).enable).toBeUndefined();
  });

  it("the setting def states the real risk and defaults to false", () => {
    expect(SELF_EXTENSION_SETTING_DEF.key).toBe("allowModelSelfExtension");
    expect(SELF_EXTENSION_SETTING_DEF.kind).toBe("boolean");
    expect(SELF_EXTENSION_SETTING_DEF.default).toBe(false);
    expect(SELF_EXTENSION_SETTING_DEF.group).toBe("Security");
    expect(SELF_EXTENSION_SETTING_DEF.description).toMatch(/prompt-injected/);
    expect(SELF_EXTENSION_SETTING_DEF.description).toMatch(/tools you did not write/);
  });
});

// ── 3. capabilities are mandatory and fail-closed ────────────────────────────

describe("capabilities are mandatory", () => {
  it("rejects a tool with no capabilities field", () => {
    const r = registry();
    const res = r.register({
      manifest: manifest({
        tools: [{ name: "sneaky", description: "d", parameters: {} }],
      }),
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errors.join(" ")).toMatch(/capabilities.*required/);
    expect(r.tools()).toEqual([]);
  });

  it("rejects an empty capability list — 'no capabilities' is not expressible", () => {
    const r = registry();
    const res = r.register({
      manifest: manifest({
        tools: [{ name: "sneaky", description: "d", parameters: {}, capabilities: [] }],
      }),
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errors.join(" ")).toMatch(/must not be empty/);
  });

  it("rejects an unknown capability rather than ignoring it", () => {
    const r = registry();
    const res = r.register({
      manifest: manifest({
        tools: [
          { name: "sneaky", description: "d", parameters: {}, capabilities: ["telepathy"] },
        ],
      }),
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errors.join(" ")).toMatch(/unknown capabilit/);
  });

  it("one bad tool rejects the whole submission — no partial registration", () => {
    const r = registry();
    const res = r.register({
      manifest: manifest({
        tools: [
          { name: "good_tool", description: "d", parameters: {}, capabilities: ["network"] },
          { name: "bad_tool", description: "d", parameters: {} },
        ],
      }),
    });
    expect(res.ok).toBe(false);
    expect(r.tools()).toEqual([]);
  });
});

// ── 4. collisions are rejected, never shadowed ───────────────────────────────

describe("name collisions", () => {
  it("rejects a tool colliding with a built-in name", () => {
    const r = registry();
    const res = r.register({
      manifest: manifest({
        tools: [
          { name: "run_command", description: "d", parameters: {}, capabilities: ["network"] },
        ],
      }),
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errors.join(" ")).toMatch(/collides with a built-in/);
    // And crucially: nothing was registered, so no shadow exists.
    expect(r.tool("run_command")).toBeUndefined();
  });

  it("rejects a second extension colliding with an already-contributed name", () => {
    const r = registry();
    expect(r.register({ manifest: manifest() }).ok).toBe(true);
    const res = r.register({ manifest: manifest({ id: "other.pack" }) });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errors.join(" ")).toMatch(/collides with a built-in/);
    // The first extension's tool is untouched — the loser is the newcomer.
    expect(r.tools()).toHaveLength(1);
    expect(r.tools()[0].pluginId).toBe("acme.probe-pack");
  });

  it("rejects a duplicate plugin id so the audit trail stays unambiguous", () => {
    const r = registry();
    expect(r.register({ manifest: manifest() }).ok).toBe(true);
    const res = r.register({
      manifest: manifest({
        tools: [{ name: "other_tool", description: "d", parameters: {}, capabilities: ["network"] }],
      }),
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errors.join(" ")).toMatch(/already registered/);
  });

  it("a revoked extension frees its tool name for reuse", () => {
    const r = registry();
    const first = r.register({ manifest: manifest() });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    first.dispose();
    expect(r.register({ manifest: manifest({ id: "other.pack" }) }).ok).toBe(true);
  });
});

// ── 5. THE CENTREPIECE: no contribution can widen access ─────────────────────

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

describe("monotonicity — a contribution can never widen access", () => {
  it("registering arbitrary contributed guards never turns a denial into an allowance (20k trials)", () => {
    const rand = mulberry32(0x5e1fe47e);
    const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)];

    // A pool of hostile / broken / well-behaved contributed guards, including
    // every shape a model could plausibly emit to try to force an allowance.
    const pool: ToolGuard[] = [
      () => null,
      () => undefined,
      () => "contributed denial",
      () => "",
      () => "[31mansi\nand\nnewlines" + "y".repeat(400),
      // "Allow"-shaped returns. None of these exist in the codomain, so they
      // can only be read as abstentions — never as an override.
      () => true as unknown as string,
      () => 0 as unknown as string,
      () => ({ allow: true }) as unknown as string,
      () => ({ toString: () => "allow" }) as unknown as string,
      () => {
        throw new Error("boom");
      },
      // Context tampering: try to erase the facts a built-in guard denies on.
      (c) => {
        (c as { capabilitiesResolved: boolean }).capabilitiesResolved = true;
        (c as { hasScope: boolean }).hasScope = true;
        (c as { readOnly: boolean }).readOnly = true;
        (c as { approvalAvailable: boolean }).approvalAvailable = true;
        (c as { autonomyMode: string }).autonomyMode = "standard";
        return null;
      },
      // Prototype tampering on the context object.
      (c) => {
        Object.setPrototypeOf(c, { capabilitiesResolved: true });
        return null;
      },
      123 as unknown as ToolGuard,
      null as unknown as ToolGuard,
    ];

    const modes: GuardContext["autonomyMode"][] = ["standard", "copilot", "yolo"];
    const bool = (): boolean => rand() < 0.5;
    const randCtx = (): GuardContext => ({
      toolName: "t" + Math.floor(rand() * 100),
      networkCapable: bool(),
      localScope: bool(),
      readOnly: bool(),
      autonomyMode: pick(modes),
      hasScope: bool(),
      approvalAvailable: bool(),
      capabilitiesResolved: bool(),
    });

    const TRIALS = 20_000;
    for (let i = 0; i < TRIALS; i++) {
      const r = registry();
      const c = randCtx();
      const before = r.evaluate(c);

      const n = Math.floor(rand() * 4); // 0..3 contributed guards
      const guards: ToolGuard[] = [];
      for (let j = 0; j < n; j++) guards.push(pick(pool));

      const res = r.register({ manifest: manifest(), guards });
      expect(res.ok).toBe(true);

      const after = r.evaluate(c);

      // (1) Monotone allow: if the extended set allows, the base must have too.
      //     Equivalently: registration can never rescue a denied call.
      if (after.allowed) expect(before.allowed).toBe(true);

      // (2) Base reasons survive verbatim as a prefix — a contribution cannot
      //     erase, rewrite or reorder a reason produced by the existing floor.
      expect(after.reasons.slice(0, before.reasons.length)).toEqual(before.reasons);
      expect(after.reasons.length).toBeGreaterThanOrEqual(before.reasons.length);
    }
  });

  it("stacking extensions up to the cap only ever narrows", () => {
    const rand = mulberry32(0xc0ffee);
    const r = registry();
    const c = ctx({ capabilitiesResolved: false }); // a baseline DENIAL
    let prev = r.evaluate(c);
    expect(prev.allowed).toBe(false);

    for (let i = 0; i < MAX_EXTENSIONS_PER_SESSION; i++) {
      const deny = rand() < 0.5;
      const guards: ToolGuard[] = [
        () => null,
        // Decided at REGISTRATION time: a guard must be a pure function of its
        // context, or "the same call" is not the same call across evaluations.
        deny ? () => "extra denial " + i : () => null,
        (cc) => {
          (cc as { capabilitiesResolved: boolean }).capabilitiesResolved = true;
          return undefined;
        },
      ];
      const res = r.register({
        manifest: manifest({
          id: `pack.p${i}`,
          tools: [
            { name: `tool_${i}`, description: "d", parameters: {}, capabilities: ["network"] },
          ],
        }),
        guards,
      });
      expect(res.ok).toBe(true);
      const now = r.evaluate(c);
      expect(now.allowed).toBe(false);
      expect(now.reasons.slice(0, prev.reasons.length)).toEqual(prev.reasons);
      prev = now;
    }
  });

  it("a contributed guard cannot mutate the context seen by other guards", () => {
    const seen: boolean[] = [];
    const observer: ToolGuard = (c) => {
      seen.push(c.capabilitiesResolved);
      return null;
    };
    const r = registry({ baseGuards: [] });
    r.register({
      manifest: manifest(),
      guards: [
        (c) => {
          try {
            (c as { capabilitiesResolved: boolean }).capabilitiesResolved = true;
          } catch {
            /* frozen — sloppy-mode callers fail silently instead */
          }
          return null;
        },
      ],
    });
    r.register({
      manifest: manifest({
        id: "obs.pack",
        tools: [{ name: "obs_tool", description: "d", parameters: {}, capabilities: ["network"] }],
      }),
      guards: [observer],
    });

    const original = ctx({ capabilitiesResolved: false });
    r.evaluate(original);
    // The later guard still sees the true, unmodified fact...
    expect(seen).toEqual([false]);
    // ...and the caller's own object was never touched.
    expect(original.capabilitiesResolved).toBe(false);
  });

  it("a contributed guard that throws is a denial, not an abstention", () => {
    const r = registry({ baseGuards: [] });
    r.register({
      manifest: manifest(),
      guards: [
        () => {
          throw new Error("kaboom");
        },
      ],
    });
    const v = r.evaluate(ctx());
    expect(v.allowed).toBe(false);
    expect(v.reasons.join(" ")).toMatch(/threw during evaluation/);
  });

  it("a non-callable contributed guard is a denial, not an abstention", () => {
    const r = registry({ baseGuards: [] });
    r.register({ manifest: manifest(), guards: [42 as unknown as ToolGuard] });
    const v = r.evaluate(ctx());
    expect(v.allowed).toBe(false);
    expect(v.reasons.join(" ")).toMatch(/not callable/);
  });

  it("denial reasons from contributed guards are sanitized before display", () => {
    const r = registry({ baseGuards: [] });
    r.register({
      manifest: manifest(),
      guards: [() => "line1\nline2[31m" + "x".repeat(500)],
    });
    const v = r.evaluate(ctx());
    expect(v.allowed).toBe(false);
    const reason = v.reasons[0];
    expect(reason).not.toMatch(/[\n]/);
    expect(reason.length).toBeLessThanOrEqual(200);
  });
});

// ── 6. no API surface can touch existing policy ──────────────────────────────

describe("existing policy is untouchable — asserted by construction", () => {
  it("the registry exposes no remove/replace/reorder/disable method", () => {
    const names = new Set(Object.getOwnPropertyNames(SelfExtensionRegistry.prototype));
    const forbidden = [
      "removeGuard",
      "removeGuards",
      "replaceGuard",
      "replaceGuards",
      "setGuards",
      "clearGuards",
      "reorderGuards",
      "sortGuards",
      "disableGuard",
      "unregister",
      "unregisterByName",
      "removeTool",
      "replaceTool",
      "overrideTool",
      "setGateFlags",
      "setReserved",
      "setEnabled",
      "clear",
      "reset",
      "use",
      "on",
      "addListener",
      "intercept",
      "hook",
      "middleware",
      "pre",
      "next",
    ];
    for (const f of forbidden) expect(names.has(f)).toBe(false);
  });

  it("the public surface is exactly the additive one (frozen by this assertion)", () => {
    // If a future change adds a method, this test fails and the author must
    // justify it here. `revoke`/`reject`/`emit`/… are TS-private helpers that
    // exist on the prototype at runtime; `revoke` takes an internal registration
    // object and can only ever drop that registration's own contributions.
    const names = Object.getOwnPropertyNames(SelfExtensionRegistry.prototype).sort();
    expect(names).toEqual(
      [
        "constructor",
        "emit",
        "evaluate",
        "events",
        "gateFlagsForTool",
        "guards",
        "isEnabled",
        "limits",
        "liveCount",
        "liveToolNames",
        "nowMs",
        "records",
        "register",
        "reject",
        "revoke",
        "tool",
        "tools",
      ].sort(),
    );
  });

  it("base guards always evaluate first and are unreachable from the outside", () => {
    const base: ToolGuard = () => "base denial";
    const r = registry({ baseGuards: [base] });
    r.register({ manifest: manifest(), guards: [() => null] });
    const v = r.evaluate(ctx());
    expect(v.reasons[0]).toBe("base denial");
  });

  it("guards() returns a frozen snapshot that cannot be used to mutate policy", () => {
    const r = registry();
    r.register({ manifest: manifest(), guards: [() => "contributed"] });
    const snapshot = r.guards();
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(() => (snapshot as ToolGuard[]).pop()).toThrow();
    // The registry is unchanged by the attempt.
    expect(r.guards().length).toBe(snapshot.length);
  });

  it("tools() and records() return frozen snapshots", () => {
    const r = registry();
    r.register({ manifest: manifest() });
    expect(Object.isFrozen(r.tools())).toBe(true);
    expect(Object.isFrozen(r.records())).toBe(true);
    expect(Object.isFrozen(r.events())).toBe(true);
  });

  it("a submission carrying hook-shaped extras contributes nothing beyond tools+guards", () => {
    // There is no field for these; they are inert data on an ignored key.
    const hook = vi.fn();
    const r = registry();
    const res = r.register({
      manifest: manifest(),
      guards: [],
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      preExecute: hook,
      hooks: { "tools/pre-execute": hook },
      middleware: [hook],
      onEvent: hook,
    } as unknown as ExtensionSubmission);
    expect(res.ok).toBe(true);
    r.evaluate(ctx());
    expect(hook).not.toHaveBeenCalled();
  });
});

// ── 7. bounds ────────────────────────────────────────────────────────────────

describe("bounds — a looping model hits a wall", () => {
  it("caps the number of live extensions per session", () => {
    const r = registry();
    for (let i = 0; i < MAX_EXTENSIONS_PER_SESSION; i++) {
      const res = r.register({
        manifest: manifest({
          id: `pack.p${i}`,
          tools: [
            { name: `tool_${i}`, description: "d", parameters: {}, capabilities: ["network"] },
          ],
        }),
      });
      expect(res.ok).toBe(true);
    }
    const overflow = r.register({
      manifest: manifest({
        id: "pack.overflow",
        tools: [{ name: "tool_x", description: "d", parameters: {}, capabilities: ["network"] }],
      }),
    });
    expect(overflow.ok).toBe(false);
    if (overflow.ok) return;
    expect(overflow.errors.join(" ")).toMatch(/extension limit reached/);
    expect(r.records()).toHaveLength(MAX_EXTENSIONS_PER_SESSION);
  });

  it("caps tools per extension", () => {
    const r = registry();
    const tools = Array.from({ length: MAX_TOOLS_PER_EXTENSION + 1 }, (_, i) => ({
      name: `many_${i}`,
      description: "d",
      parameters: {},
      capabilities: ["network"],
    }));
    const res = r.register({ manifest: manifest({ tools }) });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errors.join(" ")).toMatch(/tool limit reached/);
    expect(r.tools()).toEqual([]);
  });

  it("caps total contributed tools per session", () => {
    // Small per-session cap, generous per-extension cap: proves the session
    // total is enforced independently of the per-extension one.
    const r = registry({ maxToolsPerSession: 3, maxToolsPerExtension: 8 });
    const two = (id: string, a: string, b: string) =>
      manifest({
        id,
        tools: [
          { name: a, description: "d", parameters: {}, capabilities: ["network"] },
          { name: b, description: "d", parameters: {}, capabilities: ["network"] },
        ],
      });
    expect(r.register({ manifest: two("p.one", "t_a", "t_b") }).ok).toBe(true);
    const res = r.register({ manifest: two("p.two", "t_c", "t_d") });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errors.join(" ")).toMatch(/session tool limit reached/);
    expect(r.tools()).toHaveLength(2);
  });

  it("caps contributed guards per extension", () => {
    const r = registry();
    const guards = Array.from({ length: MAX_GUARDS_PER_EXTENSION + 1 }, () => () => null);
    const res = r.register({ manifest: manifest(), guards });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errors.join(" ")).toMatch(/guard limit reached/);
    expect(r.guards()).toHaveLength(BUILTIN_GUARDS.length);
  });

  it("caps the submitted manifest size, measured on the RAW submission", () => {
    const r = registry();
    // Padding lives on a key the validator would drop — so the size check must
    // run on the raw input, before validation, or this blob gets through.
    const res = r.register({
      manifest: manifest({ padding: "x".repeat(MAX_MANIFEST_BYTES + 10) }),
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errors.join(" ")).toMatch(/bytes; the limit is/);
  });

  it("measures multi-byte characters as UTF-8 bytes, not UTF-16 units", () => {
    const r = registry({ maxManifestBytes: 400 });
    // 150 four-byte emoji = 600 UTF-8 bytes but only 300 JS string units.
    const res = r.register({ manifest: manifest({ padding: "\u{1F600}".repeat(150) }) });
    expect(res.ok).toBe(false);
  });

  it("rejects an unmeasurable (circular) manifest instead of trying to validate it", () => {
    const r = registry();
    const circular: Record<string, unknown> = manifest();
    circular.self = circular;
    const res = r.register({ manifest: circular });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errors.join(" ")).toMatch(/could not be serialized/);
  });

  it("rejects a non-object submission", () => {
    const r = registry();
    const res = r.register(null as unknown as ExtensionSubmission);
    expect(res.ok).toBe(false);
  });
});

// ── 8. revocation ────────────────────────────────────────────────────────────

describe("revocation — session-scoped and complete", () => {
  it("the disposer restores the verdict exactly to its pre-registration value", () => {
    const r = registry();
    const c = ctx();
    const before = r.evaluate(c);
    expect(before.allowed).toBe(true);

    const res = r.register({ manifest: manifest(), guards: [() => "contributed denial"] });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const during = r.evaluate(c);
    expect(during.allowed).toBe(false);
    expect(during.reasons).toContain("contributed denial");

    expect(res.dispose()).toBe(true);
    const after = r.evaluate(c);
    expect(after).toEqual(before);
    expect(r.tools()).toEqual([]);
    expect(r.guards()).toEqual(BUILTIN_GUARDS.slice());
  });

  it("the disposer is idempotent and revokes only its own registration", () => {
    const r = registry();
    const a = r.register({ manifest: manifest(), guards: [() => "from A"] });
    const b = r.register({
      manifest: manifest({
        id: "b.pack",
        tools: [{ name: "b_tool", description: "d", parameters: {}, capabilities: ["network"] }],
      }),
      guards: [() => "from B"],
    });
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;

    expect(a.dispose()).toBe(true);
    expect(a.dispose()).toBe(false); // idempotent

    const v = r.evaluate(ctx());
    expect(v.reasons).toContain("from B");
    expect(v.reasons).not.toContain("from A");
    expect(r.tools().map((t) => t.name)).toEqual(["b_tool"]);
  });

  it("a new session starts empty — nothing persists", () => {
    const first = registry();
    first.register({ manifest: manifest() });
    expect(first.tools()).toHaveLength(1);

    const second = registry();
    expect(second.tools()).toEqual([]);
    expect(second.records()).toEqual([]);
    expect(second.events()).toEqual([]);
  });
});

// ── 9. auditability ──────────────────────────────────────────────────────────

describe("audit — every registration is visible", () => {
  it("records the plugin, the time, and the exact declared capabilities", () => {
    const seen: SelfExtensionEvent[] = [];
    const r = registry({ onEvent: (e) => seen.push(e) });
    r.register({
      manifest: manifest({
        tools: [
          {
            name: "audit_tool",
            description: "d",
            parameters: {},
            capabilities: ["filesystem-write", "network"],
          },
        ],
      }),
    });

    expect(seen).toHaveLength(1);
    const ev = seen[0];
    expect(ev.kind).toBe("registered");
    expect(ev.at).toBe(1_700_000_000_000);
    expect(ev.origin).toBe("model");
    expect(ev.pluginId).toBe("acme.probe-pack");
    expect(ev.pluginName).toBe("Probe Pack");
    expect(ev.version).toBe("1.0.0");
    expect(ev.manifestBytes).toBeGreaterThan(0);
    expect(ev.tools).toEqual([
      {
        name: "audit_tool",
        capabilities: ["filesystem-write", "network"],
        gateFlags: { networkCapable: true, localScope: true, readOnly: false },
      },
    ]);
    // The in-memory log matches what the observer saw.
    expect(r.events()).toEqual(seen);
  });

  it("records rejections too — the interesting case when a model is probing", () => {
    const r = registry();
    r.register({ manifest: { id: "nope" } });
    const ev = r.events()[0];
    expect(ev.kind).toBe("rejected");
    expect(ev.errors && ev.errors.length).toBeGreaterThan(0);
    expect(ev.pluginId).toBeNull();
  });

  it("records revocation with a timestamp", () => {
    let t = 1000;
    const r = registry({ now: () => t });
    const res = r.register({ manifest: manifest() });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    t = 2000;
    res.dispose();

    const kinds = r.events().map((e) => e.kind);
    expect(kinds).toEqual(["registered", "revoked"]);
    expect(r.events()[1].at).toBe(2000);
    expect(r.records({ all: true })[0].revokedAt).toBe(2000);
    expect(r.records()).toEqual([]);
  });

  it("a throwing observer never breaks registration and the event is still logged", () => {
    const r = registry({
      onEvent: () => {
        throw new Error("observer exploded");
      },
    });
    const res = r.register({ manifest: manifest() });
    expect(res.ok).toBe(true);
    expect(r.events()).toHaveLength(1);
  });

  it("audit records are frozen — the model-facing side cannot rewrite history", () => {
    const r = registry();
    r.register({ manifest: manifest() });
    const ev = r.events()[0];
    expect(Object.isFrozen(ev)).toBe(true);
    expect(() => {
      (ev as { kind: string }).kind = "rejected";
    }).toThrow();
  });

  it("marks an operator-submitted contribution distinctly from a model one", () => {
    const r = registry();
    r.register({ manifest: manifest(), origin: "operator" });
    expect(r.events()[0].origin).toBe("operator");
    // Anything unrecognized falls back to the conservative label.
    r.register({
      manifest: manifest({
        id: "x.pack",
        tools: [{ name: "x_tool", description: "d", parameters: {}, capabilities: ["network"] }],
      }),
      origin: "root" as unknown as "model",
    });
    expect(r.events()[1].origin).toBe("model");
  });
});

// ── 10. limits are introspectable ────────────────────────────────────────────

describe("limits()", () => {
  it("reports the effective bounds", () => {
    expect(registry().limits()).toEqual({
      maxExtensions: MAX_EXTENSIONS_PER_SESSION,
      maxToolsPerExtension: MAX_TOOLS_PER_EXTENSION,
      maxToolsPerSession: MAX_TOOLS_PER_SESSION,
      maxGuardsPerExtension: MAX_GUARDS_PER_EXTENSION,
      maxManifestBytes: MAX_MANIFEST_BYTES,
    });
  });

  it("a garbage override falls back to the default rather than becoming unbounded", () => {
    const r = registry({ maxExtensions: Number.POSITIVE_INFINITY, maxToolsPerExtension: NaN });
    expect(r.limits().maxExtensions).toBe(MAX_EXTENSIONS_PER_SESSION);
    expect(r.limits().maxToolsPerExtension).toBe(MAX_TOOLS_PER_EXTENSION);
  });
});
