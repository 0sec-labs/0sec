// #774/#775 — detection tools registry + async-driver parity.
//
// The dispatch.test.ts suite already guards definition↔dispatch↔handler
// consistency for every tool. Here we pin (a) the two new tools are in the
// canonical registry, and (b) runStructuralSqliProbeAsync is byte-identical to
// the tested sync runStructuralSqliProbe over the same oracle sequence — so the
// live HTTP tool inherits the sync version's verified decision logic.

import { describe, it, expect, vi } from "vitest";
import { TOOL_DEFINITIONS } from "./index.js";
import { ToolExecutor } from "../tools.js";
import type { ToolContext } from "../types.js";
import {
  runStructuralSqliProbe,
  runStructuralSqliProbeAsync,
  type KeyPayload,
  type ProbeObservation,
} from "../structural-sqli.js";
import { fetchScoped } from "../../http.js";

vi.mock("../../http.js", async (importOriginal) => ({
  ...(await importOriginal<object>()),
  fetchScoped: vi.fn(),
}));

// An oracle for a genuinely injectable JSON-key surface: a broken (unbalanced)
// key triggers a MySQL parse error; a balanced key parses cleanly.
function injectableOracle(payload: KeyPayload): ProbeObservation {
  return {
    payloadKey: payload.key,
    responseText: payload.balanced
      ? '{"ok":true,"rows":[]}'
      : "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
  };
}

// A non-injectable (parameterised) surface: never errors.
function safeOracle(payload: KeyPayload): ProbeObservation {
  return { payloadKey: payload.key, responseText: '{"ok":true}' };
}

describe("detection tools registry (#774/#775)", () => {
  it("registers structural_sqli_probe and prompt_layer_probe", () => {
    expect(TOOL_DEFINITIONS.structural_sqli_probe).toBeDefined();
    expect(TOOL_DEFINITIONS.structural_sqli_probe.required).toContain("url");
    expect(TOOL_DEFINITIONS.structural_sqli_probe.required).toContain("base_key");
    expect(TOOL_DEFINITIONS.auth_boundary_probe).toBeDefined();
    expect(TOOL_DEFINITIONS.auth_boundary_probe.required).toContain("endpoints");
    expect(TOOL_DEFINITIONS.prompt_layer_probe).toBeDefined();
    expect(TOOL_DEFINITIONS.prompt_layer_probe.required).toContain("writable");
  });
});

describe("runStructuralSqliProbeAsync parity with sync", () => {
  it("confirms structural SQLi on an injectable surface, identically to sync", async () => {
    const sync = runStructuralSqliProbe({ baseKey: "sort" }, injectableOracle);
    const async = await runStructuralSqliProbeAsync(
      { baseKey: "sort" },
      async (p) => injectableOracle(p),
    );
    expect(sync.verdict).toBe("confirmed");
    expect(async.verdict).toBe("confirmed");
    expect(async.dialect).toBe(sync.dialect);
    expect(async.dialect).toBe("mysql");
    expect(async.trail.length).toBe(sync.trail.length);
  });

  it("exhausts on a non-injectable surface, identically to sync", async () => {
    const sync = runStructuralSqliProbe({ baseKey: "sort", maxIterations: 4 }, safeOracle);
    const async = await runStructuralSqliProbeAsync(
      { baseKey: "sort", maxIterations: 4 },
      async (p) => safeOracle(p),
    );
    expect(sync.verdict).toBe("exhausted");
    expect(async.verdict).toBe("exhausted");
    expect(async.trail.length).toBe(sync.trail.length);
  });

  it("propagates the iteration cap (bounded loop)", async () => {
    const res = await runStructuralSqliProbeAsync(
      { baseKey: "sort", maxIterations: 3 },
      async (p) => safeOracle(p),
    );
    expect(res.trail.length).toBeLessThanOrEqual(3);
  });
});

describe("auth_boundary_probe tool (#770)", () => {
  function ctx(): ToolContext {
    return {
      target: "https://example.com",
      scanId: "ab-test",
      findings: [],
      attackResults: [],
      targetInfo: {},
    };
  }

  it("flags an unauthenticated-reachable endpoint through the executor", async () => {
    // No scan auth configured → unauth-only run; a 200 means reachable.
    vi.mocked(fetchScoped).mockImplementation(async () => new Response('{"users":[{"id":1}]}', {
      headers: { "content-type": "application/json" },
    }));
    try {
      const exec = new ToolExecutor(ctx(), null);
      const res = await exec.execute({
        name: "auth_boundary_probe",
        arguments: { endpoints: ["https://example.com/api/users"] },
      });
      expect(res.success).toBe(true);
      const out = res.output as {
        unauth_reachable_count: number;
        results: Array<{ unauthReachable: boolean; verdict: string }>;
      };
      expect(out.unauth_reachable_count).toBe(1);
      expect(out.results[0]!.unauthReachable).toBe(true);
      expect(out.results[0]!.verdict).toBe("unauth-reachable");
    } finally {
      vi.mocked(fetchScoped).mockReset();
    }
  });

  it("reports a 401 endpoint as auth-required (boundary holds)", async () => {
    vi.mocked(fetchScoped).mockImplementation(async () => new Response('{"error":"unauthorized"}', {
      status: 401, headers: { "content-type": "application/json" },
    }));
    try {
      const exec = new ToolExecutor(ctx(), null);
      const res = await exec.execute({
        name: "auth_boundary_probe",
        arguments: { endpoints: ["https://example.com/api/admin"] },
      });
      const out = res.output as {
        unauth_reachable_count: number;
        results: Array<{ verdict: string }>;
      };
      expect(out.unauth_reachable_count).toBe(0);
      expect(out.results[0]!.verdict).toBe("auth-required");
    } finally {
      vi.mocked(fetchScoped).mockReset();
    }
  });

  it("rejects a missing endpoints array", async () => {
    const exec = new ToolExecutor(ctx(), null);
    const res = await exec.execute({ name: "auth_boundary_probe", arguments: {} });
    expect(res.success).toBe(false);
  });
});

describe("discover_api_surface tool (#769)", () => {
  function ctx(): ToolContext {
    return {
      target: "https://example.com",
      scanId: "disc-test",
      findings: [],
      attackResults: [],
      targetInfo: {},
    };
  }

  it("registers in the canonical registry", () => {
    expect(TOOL_DEFINITIONS.discover_api_surface).toBeDefined();
  });

  it("discovers an OpenAPI spec + its endpoints through the executor", async () => {
    const spec = JSON.stringify({
      openapi: "3.0.0",
      info: { title: "Test API" },
      paths: { "/users": { get: {} }, "/orders": { post: {} } },
    });
    vi.mocked(fetchScoped).mockImplementation(async (url) => {
      if (url.endsWith("/openapi.json")) {
        return new Response(spec, { headers: { "content-type": "application/json" } });
      }
      return new Response("not found", { status: 404 });
    });
    try {
      const exec = new ToolExecutor(ctx(), null);
      const res = await exec.execute({
        name: "discover_api_surface",
        arguments: { domain: "https://example.com" },
      });
      expect(res.success).toBe(true);
      const out = res.output as {
        by_kind: Record<string, number>;
        assets: Array<{ kind: string; value: string }>;
      };
      expect(out.by_kind.openapi_spec).toBeGreaterThanOrEqual(1);
      expect(out.by_kind.endpoint).toBeGreaterThanOrEqual(2);
      const endpointValues = out.assets.filter((a) => a.kind === "endpoint").map((a) => a.value);
      expect(endpointValues.join(" ")).toContain("/users");
      expect(endpointValues.join(" ")).toContain("/orders");
    } finally {
      vi.mocked(fetchScoped).mockReset();
    }
  });
});

describe("suggested_finding evidence drafts", () => {
  function ctx(): ToolContext {
    return { target: "https://example.com", scanId: "sf-test", findings: [], attackResults: [], targetInfo: {} };
  }

  it("prompt_layer_probe drafts a finding on a writable, re-read asset (high)", async () => {
    const exec = new ToolExecutor(ctx(), null);
    const res = await exec.execute({
      name: "prompt_layer_probe",
      arguments: { table: "system_prompts", column: "content", sample: "You are a helpful assistant", writable: true, re_read_at_inference: true },
    });
    const out = res.output as { severity: string; suggested_finding: { category: string; severity: string } | null };
    expect(out.severity).toBe("high");
    expect(out.suggested_finding).not.toBeNull();
    expect(out.suggested_finding!.category).toBe("prompt_injection");
  });

  it("prompt_layer_probe does NOT draft a finding for a non-writable asset", async () => {
    const exec = new ToolExecutor(ctx(), null);
    const res = await exec.execute({
      name: "prompt_layer_probe",
      arguments: { table: "system_prompts", column: "content", writable: false },
    });
    const out = res.output as { suggested_finding: unknown };
    expect(out.suggested_finding).toBeNull();
  });

  it("auth_boundary_probe drafts a finding per unauth-reachable endpoint", async () => {
    vi.mocked(fetchScoped).mockImplementation(async () => new Response('{"x":1}', {
      headers: { "content-type": "application/json" },
    }));
    try {
      const exec = new ToolExecutor(ctx(), null);
      const res = await exec.execute({ name: "auth_boundary_probe", arguments: { endpoints: ["https://example.com/api/users"] } });
      const out = res.output as { suggested_findings: Array<{ category: string }> };
      expect(out.suggested_findings).toHaveLength(1);
      expect(out.suggested_findings[0]!.category).toBe("broken_access_control");
    } finally {
      vi.mocked(fetchScoped).mockReset();
    }
  });
});

describe("surface_sweep tool (#761)", () => {
  function ctx(): ToolContext {
    return { target: "https://example.com", scanId: "sweep-test", findings: [], attackResults: [], targetInfo: {} };
  }

  it("registers in the canonical registry", () => {
    expect(TOOL_DEFINITIONS.surface_sweep).toBeDefined();
  });

  it("maps the surface AND flags unauth-reachable endpoints in one call", async () => {
    const spec = JSON.stringify({
      openapi: "3.0.0",
      info: { title: "Test API" },
      paths: { "/users": { get: {} }, "/orders": { post: {} } },
    });
    vi.mocked(fetchScoped).mockImplementation(async (url) => {
      if (url.endsWith("/openapi.json")) {
        return new Response(spec, { headers: { "content-type": "application/json" } });
      }
      // Discovered endpoints answer 200 unauthenticated → reachable.
      if (url.includes("/users") || url.includes("/orders")) {
        return new Response('{"data":[]}', { headers: { "content-type": "application/json" } });
      }
      return new Response("nf", { status: 404 });
    });
    try {
      const exec = new ToolExecutor(ctx(), null);
      const res = await exec.execute({ name: "surface_sweep", arguments: { domain: "https://example.com" } });
      expect(res.success).toBe(true);
      const out = res.output as {
        endpoint_count: number;
        unauth_reachable_count: number;
        suggested_findings: Array<{ category: string }>;
      };
      expect(out.endpoint_count).toBeGreaterThanOrEqual(2);
      expect(out.unauth_reachable_count).toBeGreaterThanOrEqual(2);
      expect(out.suggested_findings.length).toBeGreaterThanOrEqual(2);
      expect(out.suggested_findings[0]!.category).toBe("broken_access_control");
    } finally {
      vi.mocked(fetchScoped).mockReset();
    }
  });
});
