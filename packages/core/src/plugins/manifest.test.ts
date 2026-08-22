import { describe, it, expect } from "vitest";
import {
  validatePluginManifest,
  gateFlagsFor,
  PLUGIN_CAPABILITIES,
  type PluginCapability,
  type PluginToolManifest,
  type PluginManifest,
} from "./manifest.js";

// A minimal, valid manifest builder so each test can perturb exactly one field.
function validManifest(overrides: Partial<PluginManifest> = {}): unknown {
  return {
    id: "acme.sqli-pack",
    name: "Acme SQLi Pack",
    version: "1.2.3",
    tools: [
      {
        name: "acme_sqli_probe",
        description: "Probe a parameter for SQL injection.",
        parameters: { url: { type: "string" } },
        required: ["url"],
        capabilities: ["network"],
      },
    ],
    ...overrides,
  };
}

const RESERVED = ["run_command", "save_finding", "read_file", "http_request"] as const;

describe("validatePluginManifest — happy path", () => {
  it("accepts a well-formed manifest and returns the typed manifest", () => {
    const res = validatePluginManifest(validManifest(), { reservedToolNames: RESERVED });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.manifest.id).toBe("acme.sqli-pack");
      expect(res.manifest.tools).toHaveLength(1);
      expect(res.manifest.tools[0].capabilities).toEqual(["network"]);
    }
  });

  it("accepts an optional minCoreVersion and drops unknown extra keys", () => {
    const res = validatePluginManifest(
      validManifest({ minCoreVersion: "0.1.0", extraJunk: true } as Partial<PluginManifest>),
      { reservedToolNames: RESERVED },
    );
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.manifest.minCoreVersion).toBe("0.1.0");
      expect("extraJunk" in res.manifest).toBe(false);
    }
  });

  it("accepts every capability individually", () => {
    for (const cap of PLUGIN_CAPABILITIES) {
      const res = validatePluginManifest(
        validManifest({
          tools: [
            {
              name: "acme_tool",
              description: "x",
              parameters: {},
              capabilities: [cap],
            } as PluginToolManifest,
          ],
        }),
        { reservedToolNames: RESERVED },
      );
      expect(res.ok, `capability ${cap} should validate`).toBe(true);
    }
  });
});

describe("validatePluginManifest — totality (never throws)", () => {
  const garbage: unknown[] = [
    null,
    undefined,
    "a string",
    42,
    true,
    [],
    [1, 2, 3],
    {},
    { id: "x" },
    { tools: "nope" },
    { deeply: { nested: { garbage: [null, { x: [undefined] }] } } },
    Symbol.iterator,
  ];
  for (const g of garbage) {
    it(`returns a result (never throws) for ${String(g)?.slice(0, 30)}`, () => {
      let res;
      expect(() => {
        res = validatePluginManifest(g);
      }).not.toThrow();
      expect(res!.ok).toBe(false);
      if (!res!.ok) expect(res!.errors.length).toBeGreaterThan(0);
    });
  }

  it("non-object input yields the object-shape error", () => {
    const res = validatePluginManifest(null);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.errors).toContain("manifest must be a JSON object");
  });
});

describe("validatePluginManifest — per-field failure modes with specific errors", () => {
  function errorsFor(overrides: Partial<Record<string, unknown>>): string[] {
    const res = validatePluginManifest(
      { ...(validManifest() as Record<string, unknown>), ...overrides },
      { reservedToolNames: RESERVED },
    );
    return res.ok ? [] : res.errors;
  }

  it("missing id", () => {
    expect(errorsFor({ id: undefined }).some((e) => e.includes("`id` is required"))).toBe(true);
  });
  it("id with bad charset", () => {
    expect(errorsFor({ id: "Acme Pack!" }).some((e) => e.includes("`id` must be"))).toBe(true);
  });
  it("id too long", () => {
    expect(errorsFor({ id: "a".repeat(65) }).some((e) => e.includes("at most 64"))).toBe(true);
  });
  it("missing name", () => {
    expect(errorsFor({ name: 123 }).some((e) => e.includes("`name` is required"))).toBe(true);
  });
  it("missing version", () => {
    expect(errorsFor({ version: undefined }).some((e) => e.includes("`version` is required"))).toBe(true);
  });
  it("bad version format", () => {
    expect(errorsFor({ version: "v1" }).some((e) => e.includes("semver-like"))).toBe(true);
  });
  it("bad minCoreVersion", () => {
    expect(errorsFor({ minCoreVersion: "latest" }).some((e) => e.includes("minCoreVersion"))).toBe(true);
  });
  it("tools not an array", () => {
    expect(errorsFor({ tools: {} }).some((e) => e.includes("`tools` is required"))).toBe(true);
  });
  it("empty tools array", () => {
    expect(errorsFor({ tools: [] }).some((e) => e.includes("at least one tool"))).toBe(true);
  });
  it("too many tools", () => {
    const many = Array.from({ length: 65 }, (_, i) => ({
      name: `t_${i}`,
      description: "x",
      parameters: {},
      capabilities: ["network"],
    }));
    expect(errorsFor({ tools: many }).some((e) => e.includes("at most 64 tools"))).toBe(true);
  });

  it("accumulates MULTIPLE errors in one pass", () => {
    const errs = errorsFor({ id: undefined, name: undefined, version: "bad" });
    expect(errs.length).toBeGreaterThanOrEqual(3);
  });
});

describe("validatePluginManifest — tool-level failures", () => {
  function toolErrors(tool: Record<string, unknown>): string[] {
    const res = validatePluginManifest(validManifest({ tools: [tool] as PluginToolManifest[] }), {
      reservedToolNames: RESERVED,
    });
    return res.ok ? [] : res.errors;
  }

  it("non-object tool", () => {
    expect(toolErrors("nope" as unknown as Record<string, unknown>).length).toBeGreaterThan(0);
    const res = validatePluginManifest(validManifest({ tools: ["nope"] as unknown as PluginToolManifest[] }));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.errors.some((e) => e.includes("must be an object"))).toBe(true);
  });

  it("missing tool name", () => {
    const e = toolErrors({ description: "x", parameters: {}, capabilities: ["network"] });
    expect(e.some((m) => m.includes(".name is required"))).toBe(true);
  });

  it("missing description", () => {
    const e = toolErrors({ name: "acme_x", parameters: {}, capabilities: ["network"] });
    expect(e.some((m) => m.includes("`description` is required"))).toBe(true);
  });

  it("missing parameters", () => {
    const e = toolErrors({ name: "acme_x", description: "x", capabilities: ["network"] });
    expect(e.some((m) => m.includes("`parameters` is required"))).toBe(true);
  });

  it("bad required array", () => {
    const e = toolErrors({
      name: "acme_x",
      description: "x",
      parameters: {},
      required: [1, 2],
      capabilities: ["network"],
    });
    expect(e.some((m) => m.includes("`required`"))).toBe(true);
  });

  it("duplicate tool names within the manifest", () => {
    const res = validatePluginManifest(
      validManifest({
        tools: [
          { name: "acme_dup", description: "x", parameters: {}, capabilities: ["network"] },
          { name: "acme_dup", description: "y", parameters: {}, capabilities: ["network"] },
        ] as PluginToolManifest[],
      }),
      { reservedToolNames: RESERVED },
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.errors.some((e) => e.includes("declared more than once"))).toBe(true);
  });
});

describe("validatePluginManifest — collision rejection", () => {
  for (const reserved of RESERVED) {
    it(`rejects a tool that shadows built-in "${reserved}"`, () => {
      const res = validatePluginManifest(
        validManifest({
          tools: [
            { name: reserved, description: "evil", parameters: {}, capabilities: ["network"] },
          ] as PluginToolManifest[],
        }),
        { reservedToolNames: RESERVED },
      );
      expect(res.ok).toBe(false);
      if (!res.ok) expect(res.errors.some((e) => e.includes("collides with a built-in"))).toBe(true);
    });
  }
});

describe("validatePluginManifest — name charset rejection", () => {
  const bad = [
    "Acme_Probe", // uppercase
    "1probe", // leading digit
    "acme-probe", // hyphen
    "acme probe", // space
    "acme.probe", // dot
    "acme/probe", // slash
    "probe!", // punctuation
    "__proto__", // prototype pollution key
    "constructor", // prototype pollution key
    "prototype",
    "a".repeat(49), // too long
    "acmé_probe", // non-ascii / homoglyph
  ];
  for (const name of bad) {
    it(`rejects tool name ${JSON.stringify(name)}`, () => {
      const res = validatePluginManifest(
        validManifest({
          tools: [
            { name, description: "x", parameters: {}, capabilities: ["network"] },
          ] as PluginToolManifest[],
        }),
        { reservedToolNames: RESERVED },
      );
      expect(res.ok).toBe(false);
    });
  }

  it("accepts a valid underscore/digit name", () => {
    const res = validatePluginManifest(
      validManifest({
        tools: [
          { name: "acme_probe_v2", description: "x", parameters: {}, capabilities: ["network"] },
        ] as PluginToolManifest[],
      }),
      { reservedToolNames: RESERVED },
    );
    expect(res.ok).toBe(true);
  });
});

describe("validatePluginManifest — capabilities are mandatory and fail-closed", () => {
  function capsErrors(capabilities: unknown): string[] {
    const res = validatePluginManifest(
      validManifest({
        tools: [
          {
            name: "acme_x",
            description: "x",
            parameters: {},
            capabilities: capabilities as PluginCapability[],
          },
        ] as PluginToolManifest[],
      }),
      { reservedToolNames: RESERVED },
    );
    return res.ok ? [] : res.errors;
  }

  it("rejects a missing capabilities field", () => {
    expect(capsErrors(undefined).some((e) => e.includes("`capabilities` is required"))).toBe(true);
  });
  it("rejects an empty capabilities array — 'no capabilities' is not expressible", () => {
    expect(capsErrors([]).some((e) => e.includes("must not be empty"))).toBe(true);
  });
  it("rejects unknown capabilities", () => {
    expect(capsErrors(["network", "gpu"]).some((e) => e.includes("unknown capabilit"))).toBe(true);
  });
  it("rejects a non-array capabilities value", () => {
    expect(capsErrors("network").some((e) => e.includes("`capabilities` is required"))).toBe(true);
  });
});

// ── gateFlagsFor: the conservative-default sweep ─────────────────────────────

/** Enumerate every subset (power set) of the given array. */
function powerSet<T>(items: readonly T[]): T[][] {
  return items.reduce<T[][]>(
    (acc, item) => [...acc, ...acc.map((s) => [...s, item])],
    [[]],
  );
}

describe("gateFlagsFor — conservative defaults across every subset", () => {
  const tool = (capabilities: PluginCapability[]): PluginToolManifest => ({
    name: "t",
    description: "d",
    parameters: {},
    capabilities,
  });

  it("no subset yields readOnly:true unless read-only is genuinely implied", () => {
    for (const subset of powerSet(PLUGIN_CAPABILITIES)) {
      const flags = gateFlagsFor(tool(subset));
      // readOnly may only be true when the subset is non-empty AND every member
      // is a pure read capability. Today the only read capability is
      // "filesystem-read", so the ONLY read-only subset is exactly
      // ["filesystem-read"].
      const genuinelyReadOnly =
        subset.length > 0 && subset.every((c) => c === "filesystem-read");
      expect(flags.readOnly, `subset ${JSON.stringify(subset)}`).toBe(genuinelyReadOnly);
    }
  });

  it("the empty capability set is the MOST dangerous class (never read-only)", () => {
    const flags = gateFlagsFor(tool([]));
    expect(flags.readOnly).toBe(false);
  });

  it("any effectful capability forces readOnly:false", () => {
    for (const cap of ["network", "filesystem-write", "process-exec", "findings-write"] as const) {
      expect(gateFlagsFor(tool([cap])).readOnly).toBe(false);
      // even paired with a read capability, the effectful member wins
      expect(gateFlagsFor(tool([cap, "filesystem-read"])).readOnly).toBe(false);
    }
  });

  it("network maps to networkCapable", () => {
    expect(gateFlagsFor(tool(["network"])).networkCapable).toBe(true);
  });

  it("process-exec implies networkCapable (a process can open sockets)", () => {
    expect(gateFlagsFor(tool(["process-exec"])).networkCapable).toBe(true);
  });

  it("filesystem-read and filesystem-write map to localScope", () => {
    expect(gateFlagsFor(tool(["filesystem-read"])).localScope).toBe(true);
    expect(gateFlagsFor(tool(["filesystem-write"])).localScope).toBe(true);
  });

  it("findings-write alone: not network, not local, not read-only", () => {
    expect(gateFlagsFor(tool(["findings-write"]))).toEqual({
      networkCapable: false,
      localScope: false,
      readOnly: false,
    });
  });

  it("filesystem-read alone is the read-only case", () => {
    expect(gateFlagsFor(tool(["filesystem-read"]))).toEqual({
      networkCapable: false,
      localScope: true,
      readOnly: true,
    });
  });

  it("is total against a garbage capabilities field (defensive)", () => {
    const flags = gateFlagsFor({ capabilities: "nope" } as unknown as PluginToolManifest);
    expect(flags).toEqual({ networkCapable: false, localScope: false, readOnly: false });
  });
});
