import { describe, expect, it } from "vitest";

import {
  MCP_TOOL_PREFIX,
  isSafeMcpServerId,
  mcpToolName,
  parseMcpToolName,
  mcpToolToDefinition,
  mcpToolsToDefinitions,
  mcpResultText,
  type McpToolSpec,
} from "./mcp-adapt.js";

describe("namespacing", () => {
  it("round-trips server + tool through the mcp__ prefix", () => {
    const name = mcpToolName("github", "search_issues");
    expect(name).toBe("mcp__github__search_issues");
    expect(parseMcpToolName(name)).toEqual({ server: "github", tool: "search_issues" });
  });

  it("keeps a tool name that itself contains __", () => {
    expect(parseMcpToolName("mcp__srv__do__thing")).toEqual({ server: "srv", tool: "do__thing" });
  });

  it("rejects non-mcp / malformed names", () => {
    expect(parseMcpToolName("bash")).toBeNull();
    expect(parseMcpToolName("mcp__onlyserver")).toBeNull();
    expect(parseMcpToolName("mcp____notool")).toBeNull();
    expect(parseMcpToolName("mcp__bad server__t")).toBeNull();
  });

  it("uses the same prefix isUntrustedSourceTool matches", () => {
    expect(mcpToolName("x", "y").startsWith(MCP_TOOL_PREFIX)).toBe(true);
  });

  it("validates server ids", () => {
    expect(isSafeMcpServerId("acme.recon")).toBe(true);
    expect(isSafeMcpServerId("a b")).toBe(false);
    expect(isSafeMcpServerId("")).toBe(false);
    expect(isSafeMcpServerId("../etc")).toBe(false);
  });
});

describe("mcpToolToDefinition", () => {
  const spec: McpToolSpec = {
    name: "lookup",
    description: "Look something up",
    inputSchema: { type: "object", properties: { q: { type: "string" } }, required: ["q"] },
  };

  it("namespaces the name, carries params + required, marks it untrusted+external", () => {
    const def = mcpToolToDefinition("intelsrv", spec);
    expect(def.name).toBe("mcp__intelsrv__lookup");
    expect(def.parameters).toEqual({ q: { type: "string" } });
    expect(def.required).toEqual(["q"]);
    expect(def.description).toContain("external MCP tool");
    expect(def.description).toContain("untrusted");
  });

  it("clamps a hostile giant description", () => {
    const def = mcpToolToDefinition("s", { name: "t", description: "x".repeat(5000) });
    expect(def.description.length).toBeLessThan(1200);
  });

  it("omits required when the schema declares none", () => {
    const def = mcpToolToDefinition("s", { name: "t" });
    expect(def.required).toBeUndefined();
    expect(def.parameters).toEqual({});
  });
});

describe("mcpToolsToDefinitions", () => {
  it("maps a list, drops nameless entries, and caps the count", () => {
    const specs: McpToolSpec[] = [
      { name: "a" },
      { name: "" },
      { name: "b" },
    ];
    expect(mcpToolsToDefinitions("s", specs).map((d) => d.name)).toEqual(["mcp__s__a", "mcp__s__b"]);
    const many = Array.from({ length: 100 }, (_, i) => ({ name: `t${i}` }));
    expect(mcpToolsToDefinitions("s", many, 10)).toHaveLength(10);
  });
});

describe("mcpResultText", () => {
  it("concatenates text blocks and summarizes non-text", () => {
    expect(mcpResultText([{ type: "text", text: "line1" }, { type: "text", text: "line2" }])).toBe("line1\nline2");
    expect(mcpResultText([{ type: "image", data: "..." }])).toBe("[image content omitted]");
  });
  it("is safe on odd shapes", () => {
    expect(mcpResultText("plain")).toBe("plain");
    expect(mcpResultText(undefined)).toBe("");
  });
});
