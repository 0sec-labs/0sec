import { describe, it, expect } from "vitest";
import { TOOL_DISPATCH } from "./dispatch.js";
import { TOOL_DEFINITIONS } from "./index.js";
import { ToolExecutor } from "../tools.js";
import type { ToolContext } from "../types.js";

describe("TOOL_DISPATCH (0sec#614)", () => {
  it("covers exactly the registry — no orphan routes, no unrouted tools", () => {
    expect(Object.keys(TOOL_DISPATCH).sort()).toEqual(Object.keys(TOOL_DEFINITIONS).sort());
  });

  it("maps every tool to a real ToolExecutor handler method (rename guard)", () => {
    const ctx: ToolContext = {
      target: "https://example.com",
      scanId: "dispatch-test",
      findings: [],
      attackResults: [],
      targetInfo: {},
    };
    const executor = new ToolExecutor(ctx, null);
    for (const [tool, method] of Object.entries(TOOL_DISPATCH)) {
      expect(
        typeof (executor as unknown as Record<string, unknown>)[method],
        `tool "${tool}" routes to missing method "${method}"`,
      ).toBe("function");
    }
  });

  it("routes update_todos and its write_todos alias to the plan tracker", async () => {
    const ctx: ToolContext = {
      target: "https://example.com",
      scanId: "dispatch-test",
      findings: [],
      attackResults: [],
      targetInfo: {},
    };
    const executor = new ToolExecutor(ctx, null);

    const first = await executor.execute({
      name: "update_todos",
      arguments: { todos: [{ content: "recon", status: "completed" }, { content: "attack" }] },
    });
    expect(first.success).toBe(true);
    expect((first.output as { message: string }).message).toBe("plan: 2 tasks, 1 done");

    // The alias resolves to the same handler and performs a full replace.
    const second = await executor.execute({
      name: "write_todos",
      arguments: { todos: [{ content: "only-one" }] },
    });
    expect(second.success).toBe(true);
    expect((second.output as { total: number }).total).toBe(1);

    // Malformed payload is rejected as an is_error result, not thrown.
    const bad = await executor.execute({ name: "update_todos", arguments: { todos: [{ content: "" }] } });
    expect(bad.success).toBe(false);
    expect(bad.error).toMatch(/content/i);
  });

  it("returns the original 'Unknown tool' result for an unmapped name", async () => {
    const ctx: ToolContext = {
      target: "https://example.com",
      scanId: "dispatch-test",
      findings: [],
      attackResults: [],
      targetInfo: {},
    };
    const executor = new ToolExecutor(ctx, null);
    const result = await executor.execute({ name: "does_not_exist", arguments: {} });
    expect(result).toEqual({
      success: false,
      output: null,
      error: "Unknown tool: does_not_exist",
    });
  });
});
