import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  ToolExecutor,
  TOOL_DEFINITIONS,
  SELF_EXTENSION_RESERVED_TOOL_NAMES,
  validateSelfExtendArgs,
  selfExtensionRegistryOf,
} from "./tools.js";
import { runNativeAgentLoop } from "./native-loop.js";
import type { ToolContext } from "./types.js";
import type {
  NativeRuntime,
  NativeRuntimeResult,
  NativeMessage,
  NativeToolDef,
} from "../runtime/types.js";
import {
  SelfExtensionRegistry,
  MAX_EXTENSIONS_PER_SESSION,
  MAX_TOOLS_PER_EXTENSION,
  MAX_TOOLS_PER_SESSION,
  MAX_GUARDS_PER_EXTENSION,
  MAX_MANIFEST_BYTES,
} from "../plugins/self-extension.js";
import { BUILTIN_GUARDS, type ToolGuard } from "../plugins/guards.js";
import type { PluginCapability } from "../plugins/manifest.js";

// The self-extension registry is pure in-memory and never touches disk, but the
// native-loop integration tests boot the full loop, which enables hunt memory by
// default — keep the suite from writing to the real ~/.0sec store.
beforeEach(() => {
  process.env["0SEC_DISABLE_HUNT_MEMORY"] = "1";
});
afterEach(() => {
  delete process.env["0SEC_DISABLE_HUNT_MEMORY"];
});

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeCtx(): ToolContext {
  return {
    target: "https://example.com",
    scanId: "self-extend-test",
    findings: [],
    attackResults: [],
    targetInfo: {},
  };
}

/** An enabled registry wired exactly as native-loop wires it. */
function enabledRegistry(): SelfExtensionRegistry {
  return new SelfExtensionRegistry({
    enabled: true,
    baseGuards: BUILTIN_GUARDS,
    reservedToolNames: SELF_EXTENSION_RESERVED_TOOL_NAMES,
  });
}

function executorWith(registry: SelfExtensionRegistry | undefined): {
  exec: ToolExecutor;
  ctx: ToolContext;
} {
  const ctx = makeCtx();
  if (registry) {
    (ctx as ToolContext & { selfExtension?: SelfExtensionRegistry }).selfExtension = registry;
  }
  return { exec: new ToolExecutor(ctx, null), ctx };
}

/** Build a well-formed tool manifest with `n` uniquely-named tools. */
function manifestWith(
  id: string,
  toolNames: string[],
  caps: PluginCapability[] = ["filesystem-read"],
): Record<string, unknown> {
  return {
    id,
    name: `Plugin ${id}`,
    version: "1.0.0",
    tools: toolNames.map((n) => ({
      name: n,
      description: `does ${n}`,
      parameters: { input: { type: "string", description: "an input" } },
      capabilities: caps,
    })),
  };
}

// ── The Zod front door: validate-then-reject ─────────────────────────────────

describe("validateSelfExtendArgs (kernel_run discipline)", () => {
  it("rejects non-object args", () => {
    expect(validateSelfExtendArgs(null).ok).toBe(false);
    expect(validateSelfExtendArgs("nope").ok).toBe(false);
    expect(validateSelfExtendArgs([]).ok).toBe(false);
  });

  it("rejects a missing or non-object manifest", () => {
    expect(validateSelfExtendArgs({}).ok).toBe(false);
    expect(validateSelfExtendArgs({ manifest: "x" }).ok).toBe(false);
    expect(validateSelfExtendArgs({ manifest: [] }).ok).toBe(false);
  });

  it("strips every non-manifest top-level key (no `guards`/`origin` smuggling)", () => {
    const parsed = validateSelfExtendArgs({
      manifest: { id: "a.b" },
      guards: [() => "deny"],
      origin: "operator",
      code: "rm -rf /",
    });
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(Object.keys(parsed.args)).toEqual(["manifest"]);
      expect(parsed.args.manifest).toEqual({ id: "a.b" });
    }
  });
});

// ── The `self_extend` tool handler ────────────────────────────────────────────

describe("self_extend tool handler", () => {
  it("registers a valid submission and makes the tools live in the registry", async () => {
    const registry = enabledRegistry();
    const { exec } = executorWith(registry);

    const res = await exec.execute({
      name: "self_extend",
      arguments: { manifest: manifestWith("scan.alpha", ["myext_reader"]) },
    });

    expect(res.success).toBe(true);
    const out = res.output as { registered: boolean; registrationId: string; tools: unknown[] };
    expect(out.registered).toBe(true);
    expect(out.registrationId).toBe("ext-1");

    // The registry — the source native-loop injects the model-facing tool set
    // from — now carries the tool.
    expect(registry.tools().map((t) => t.name)).toContain("myext_reader");
    expect(registry.records()).toHaveLength(1);
  });

  it("routes a registered tool's call through the registry, guarded by DECLARED gate flags", async () => {
    const registry = enabledRegistry();
    const { exec } = executorWith(registry);

    // A read-only tool passes the deny-only guard floor, but there is no body to
    // run — registration is not execution.
    await exec.execute({
      name: "self_extend",
      arguments: { manifest: manifestWith("scan.reader", ["myext_reader"], ["filesystem-read"]) },
    });
    const readCall = await exec.execute({ name: "myext_reader", arguments: {} });
    expect(readCall.success).toBe(false);
    expect(readCall.error).toMatch(/no executable implementation/i);

    // An effectful (network) tool in standard mode with no approval mechanism is
    // DENIED by the guard floor — a self-authored tool cannot exceed the
    // capability its declared gate flags allow.
    await exec.execute({
      name: "self_extend",
      arguments: { manifest: manifestWith("scan.net", ["myext_egress"], ["network"]) },
    });
    const netCall = await exec.execute({ name: "myext_egress", arguments: {} });
    expect(netCall.success).toBe(false);
    expect(netCall.error).toMatch(/denied by the guard floor/i);
  });

  it("delegates deep manifest validation to the registry (capabilities mandatory)", async () => {
    const registry = enabledRegistry();
    const { exec } = executorWith(registry);

    // A tool with no capabilities is rejected by the ONE validator.
    const res = await exec.execute({
      name: "self_extend",
      arguments: {
        manifest: {
          id: "scan.bad",
          name: "bad",
          version: "1.0.0",
          tools: [{ name: "myext_nocaps", description: "x", parameters: {} }],
        },
      },
    });
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/capabilit/i);
    expect(registry.tools()).toHaveLength(0);
  });

  it("refuses to let a contributed tool shadow a built-in", async () => {
    const registry = enabledRegistry();
    const { exec } = executorWith(registry);
    const res = await exec.execute({
      name: "self_extend",
      arguments: { manifest: manifestWith("scan.shadow", ["http_request"]) },
    });
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/built-in/i);
    expect(registry.tools()).toHaveLength(0);
  });

  // Regression: the reserved set must cover child-only dispatch routes
  // (report_status / send_message / check_messages) that live in
  // CHILD_LOCAL_DISPATCH but NOT in TOOL_DEFINITIONS. Reserving only
  // TOOL_DEFINITIONS let a contributed tool shadow these dispatchable built-ins
  // and, in the console, flip their operator-approval gate.
  it.each(["send_message", "check_messages", "report_status"])(
    "refuses a contributed tool that shadows the child-dispatch built-in %s",
    async (name) => {
      const registry = enabledRegistry();
      const { exec } = executorWith(registry);
      const res = await exec.execute({
        name: "self_extend",
        arguments: { manifest: manifestWith("scan.shadow", [name]) },
      });
      expect(res.success).toBe(false);
      expect(res.error).toMatch(/built-in/i);
      expect(registry.tools()).toHaveLength(0);
    },
  );
});

// ── Malformed → rejected with NO side effect and NO budget slot ───────────────

describe("self_extend rejects malformed submissions with no side effect", () => {
  it("rejects a malformed payload without touching the registry (no event, no slot)", async () => {
    const registry = enabledRegistry();
    const { exec } = executorWith(registry);

    const bad = await exec.execute({ name: "self_extend", arguments: { manifest: "not-an-object" } });
    expect(bad.success).toBe(false);
    // Zod rejected BEFORE the registry: no audit event, nothing registered.
    expect(registry.events()).toHaveLength(0);
    expect(registry.tools()).toHaveLength(0);
    expect(registry.records()).toHaveLength(0);

    // Proof no budget slot was consumed: the next VALID submission is still
    // registration #1 (the malformed attempt did not advance the seq counter).
    const ok = await exec.execute({
      name: "self_extend",
      arguments: { manifest: manifestWith("scan.first", ["myext_first"]) },
    });
    expect(ok.success).toBe(true);
    expect((ok.output as { registrationId: string }).registrationId).toBe("ext-1");
  });
});

// ── Every limit is enforced via the registry ─────────────────────────────────

describe("self_extend enforces every registry limit", () => {
  it(`rejects a manifest exceeding MAX_TOOLS_PER_EXTENSION (${MAX_TOOLS_PER_EXTENSION})`, async () => {
    const registry = enabledRegistry();
    const { exec } = executorWith(registry);
    const names = Array.from({ length: MAX_TOOLS_PER_EXTENSION + 1 }, (_, i) => `myext_t${i}`);
    const res = await exec.execute({
      name: "self_extend",
      arguments: { manifest: manifestWith("scan.big", names) },
    });
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/tool limit/i);
    expect(registry.tools()).toHaveLength(0);
  });

  it(`rejects a manifest exceeding MAX_MANIFEST_BYTES (${MAX_MANIFEST_BYTES})`, async () => {
    const registry = enabledRegistry();
    const { exec } = executorWith(registry);
    const huge = manifestWith("scan.huge", ["myext_huge"]);
    (huge.tools as Array<{ description: string }>)[0].description = "x".repeat(MAX_MANIFEST_BYTES + 10);
    const res = await exec.execute({ name: "self_extend", arguments: { manifest: huge } });
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/bytes|limit/i);
    expect(registry.tools()).toHaveLength(0);
  });

  it(`rejects past MAX_EXTENSIONS_PER_SESSION (${MAX_EXTENSIONS_PER_SESSION})`, async () => {
    const registry = enabledRegistry();
    const { exec } = executorWith(registry);
    for (let i = 0; i < MAX_EXTENSIONS_PER_SESSION; i++) {
      const res = await exec.execute({
        name: "self_extend",
        arguments: { manifest: manifestWith(`scan.e${i}`, [`myext_e${i}`]) },
      });
      expect(res.success).toBe(true);
    }
    const overflow = await exec.execute({
      name: "self_extend",
      arguments: { manifest: manifestWith("scan.over", ["myext_over"]) },
    });
    expect(overflow.success).toBe(false);
    expect(overflow.error).toMatch(/extension limit/i);
  });

  it(`rejects past MAX_TOOLS_PER_SESSION (${MAX_TOOLS_PER_SESSION})`, async () => {
    const registry = enabledRegistry();
    const { exec } = executorWith(registry);
    // 4 extensions × 8 tools = 32 live tools (the session cap), all within the
    // 8-extension limit.
    const perExt = MAX_TOOLS_PER_EXTENSION;
    const exts = Math.floor(MAX_TOOLS_PER_SESSION / perExt);
    for (let e = 0; e < exts; e++) {
      const names = Array.from({ length: perExt }, (_, i) => `myext_s${e}_${i}`);
      const res = await exec.execute({
        name: "self_extend",
        arguments: { manifest: manifestWith(`scan.s${e}`, names) },
      });
      expect(res.success).toBe(true);
    }
    expect(registry.tools()).toHaveLength(MAX_TOOLS_PER_SESSION);
    // One more tool would push the session total over the cap.
    const overflow = await exec.execute({
      name: "self_extend",
      arguments: { manifest: manifestWith("scan.s_over", ["myext_s_over"]) },
    });
    expect(overflow.success).toBe(false);
    expect(overflow.error).toMatch(/session tool limit/i);
  });

  it(`enforces MAX_GUARDS_PER_EXTENSION (${MAX_GUARDS_PER_EXTENSION}) at the registry`, () => {
    // Guards are FUNCTIONS and cannot arrive over a JSON tool call (the front
    // door strips them). The limit is still enforced by the registry for any
    // programmatic/operator submission — assert it directly.
    const registry = enabledRegistry();
    const guards: ToolGuard[] = Array.from(
      { length: MAX_GUARDS_PER_EXTENSION + 1 },
      () => () => null,
    );
    const res = registry.register({ manifest: manifestWith("scan.g", ["myext_g"]), guards });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.errors.join(" ")).toMatch(/guard limit/i);
  });
});

// ── Gating: disabled by default ──────────────────────────────────────────────

describe("self_extend gating on allowModelSelfExtension", () => {
  it("refuses when the registry is disabled (default OFF)", async () => {
    const disabled = new SelfExtensionRegistry({
      enabled: false,
      baseGuards: BUILTIN_GUARDS,
      reservedToolNames: SELF_EXTENSION_RESERVED_TOOL_NAMES,
    });
    const { exec } = executorWith(disabled);
    const res = await exec.execute({
      name: "self_extend",
      arguments: { manifest: manifestWith("scan.x", ["myext_x"]) },
    });
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/disabled|unavailable/i);
    expect(disabled.tools()).toHaveLength(0);
  });

  it("refuses when no registry is wired at all", async () => {
    const { exec, ctx } = executorWith(undefined);
    expect(selfExtensionRegistryOf(ctx)).toBeUndefined();
    const res = await exec.execute({
      name: "self_extend",
      arguments: { manifest: manifestWith("scan.x", ["myext_x"]) },
    });
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/disabled|unavailable/i);
  });
});

// ── Session-scoped and never persisted ───────────────────────────────────────

describe("self_extend is session-scoped", () => {
  it("does not leak a registration into another session's registry", async () => {
    const sessionA = enabledRegistry();
    const sessionB = enabledRegistry();
    const { exec: execA } = executorWith(sessionA);

    await execA.execute({
      name: "self_extend",
      arguments: { manifest: manifestWith("scan.a", ["myext_a"]) },
    });

    expect(sessionA.tools().map((t) => t.name)).toContain("myext_a");
    // A separate session starts empty — nothing crossed over, nothing persisted.
    expect(sessionB.tools()).toHaveLength(0);
    expect(sessionB.records()).toHaveLength(0);
  });
});

// ── native-loop integration: injection + gating end-to-end ───────────────────

function createCapturingRuntime(
  responses: NativeRuntimeResult[],
  captured: NativeToolDef[][],
): NativeRuntime {
  let i = 0;
  return {
    type: "api" as const,
    async executeNative(
      _system: string,
      _messages: NativeMessage[],
      tools: NativeToolDef[],
    ): Promise<NativeRuntimeResult> {
      captured.push(tools);
      const r = responses[i] ?? responses[responses.length - 1];
      i++;
      return r;
    },
    async isAvailable() {
      return true;
    },
  };
}

describe("native-loop self-extension wiring", () => {
  it("enabled: self_extend is offered and registered tools appear on the next turn", async () => {
    const captured: NativeToolDef[][] = [];
    const runtime = createCapturingRuntime(
      [
        {
          content: [
            {
              type: "tool_use",
              id: "tc1",
              name: "self_extend",
              input: { manifest: manifestWith("scan.loop", ["myext_loop"]) },
            },
          ],
          stopReason: "tool_use",
          durationMs: 10,
        },
        {
          content: [{ type: "tool_use", id: "tc2", name: "done", input: { summary: "done" } }],
          stopReason: "tool_use",
          durationMs: 10,
        },
      ],
      captured,
    );

    const events: string[] = [];
    const state = await runNativeAgentLoop({
      config: {
        role: "discovery",
        systemPrompt: "test",
        tools: [],
        maxTurns: 5,
        target: "https://example.com",
        scanId: "self-extend-loop",
        allowModelSelfExtension: true,
      },
      runtime,
      db: null,
      onEvent: (type) => events.push(type),
    });

    expect(state.done).toBe(true);
    // Turn 1 offered self_extend but NOT the not-yet-registered tool.
    const turn1 = captured[0].map((t) => t.name);
    expect(turn1).toContain("self_extend");
    expect(turn1).not.toContain("myext_loop");
    // Turn 2 offers the freshly-registered tool.
    const turn2 = captured[1].map((t) => t.name);
    expect(turn2).toContain("myext_loop");
    // A SelfExtensionEvent was emitted for the operator surface.
    expect(events).toContain("self_extension");
  });

  it("disabled (default): self_extend is absent and a call to it refuses", async () => {
    const captured: NativeToolDef[][] = [];
    const runtime = createCapturingRuntime(
      [
        {
          content: [
            {
              type: "tool_use",
              id: "tc1",
              name: "self_extend",
              input: { manifest: manifestWith("scan.loop", ["myext_loop"]) },
            },
          ],
          stopReason: "tool_use",
          durationMs: 10,
        },
        {
          content: [{ type: "tool_use", id: "tc2", name: "done", input: { summary: "done" } }],
          stopReason: "tool_use",
          durationMs: 10,
        },
      ],
      captured,
    );

    await runNativeAgentLoop({
      config: {
        role: "discovery",
        systemPrompt: "test",
        tools: [],
        maxTurns: 5,
        target: "https://example.com",
        scanId: "self-extend-loop-off",
        // allowModelSelfExtension omitted → default OFF
      },
      runtime,
      db: null,
    });

    // self_extend never advertised, and the registered tool never appears.
    expect(captured[0].map((t) => t.name)).not.toContain("self_extend");
    expect(captured[1].map((t) => t.name)).not.toContain("myext_loop");
  });
});
