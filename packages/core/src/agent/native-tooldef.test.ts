import { describe, it, expect } from "vitest";
import { toNativeToolDef, toNativeExtensionToolDef } from "./native-tooldef.js";
import type { ToolDefinition } from "./types.js";

describe("toNativeToolDef", () => {
  it("propagates array `items` (regression: the console copy used to drop it)", () => {
    const tool: ToolDefinition = {
      name: "with_array",
      description: "d",
      parameters: {
        hosts: {
          type: "array",
          description: "list",
          items: { type: "string" },
        } as ToolDefinition["parameters"][string],
      },
      required: ["hosts"],
    };
    const native = toNativeToolDef(tool);
    const prop = native.input_schema.properties.hosts as Record<string, unknown>;
    expect(prop.items).toEqual({ type: "string" });
    expect(native.input_schema.required).toEqual(["hosts"]);
  });

  it("carries enum and basic shape; defaults required to []", () => {
    const tool: ToolDefinition = {
      name: "t",
      description: "desc",
      parameters: { mode: { type: "string", description: "m", enum: ["a", "b"] } },
    };
    const native = toNativeToolDef(tool);
    expect(native.name).toBe("t");
    expect(native.description).toBe("desc");
    expect((native.input_schema.properties.mode as Record<string, unknown>).enum).toEqual(["a", "b"]);
    expect(native.input_schema.required).toEqual([]);
  });
});

describe("toNativeExtensionToolDef", () => {
  it("passes the frozen parameters bag through and copies required", () => {
    const native = toNativeExtensionToolDef({
      name: "ext",
      description: "e",
      parameters: { x: { type: "string" } },
      required: ["x"],
    } as Parameters<typeof toNativeExtensionToolDef>[0]);
    expect(native.name).toBe("ext");
    expect(native.input_schema.properties).toEqual({ x: { type: "string" } });
    expect(native.input_schema.required).toEqual(["x"]);
  });
});
