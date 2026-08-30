import { describe, expect, it } from "vitest";

import {
  DeferredToolRegistry,
  DEFERRED_TOOLS_MIN,
  LIST_TOOLS_NAME,
  LOAD_TOOL_NAME,
  listToolsDef,
  loadToolDef,
  formatToolCatalog,
  formatLoadResult,
} from "./deferred-tools.js";
import type { ToolDefinition } from "./types.js";

const def = (name: string, description = `desc for ${name}`): ToolDefinition => ({
  name,
  description,
  parameters: {},
  required: [],
});

describe("DeferredToolRegistry", () => {
  it("seeds a catalog, nothing loaded initially", () => {
    const r = new DeferredToolRegistry();
    r.seed([def("a"), def("b")]);
    expect(r.size()).toBe(2);
    expect(r.isLoaded("a")).toBe(false);
    expect(r.loadedDefinitions()).toEqual([]);
  });

  it("loads known tools, reports unknown, is idempotent", () => {
    const r = new DeferredToolRegistry();
    r.seed([def("a"), def("b")]);
    expect(r.load(["a", "nope"])).toEqual({ loaded: ["a"], unknown: ["nope"] });
    expect(r.isLoaded("a")).toBe(true);
    // idempotent re-load
    expect(r.load(["a"])).toEqual({ loaded: ["a"], unknown: [] });
    expect(r.loadedDefinitions().map((d) => d.name)).toEqual(["a"]);
  });

  it("trims and ignores blank names", () => {
    const r = new DeferredToolRegistry();
    r.seed([def("a")]);
    expect(r.load([" a ", "", "   "])).toEqual({ loaded: ["a"], unknown: [] });
  });

  it("re-seeding prunes vanished tools from catalog and loaded set", () => {
    const r = new DeferredToolRegistry();
    r.seed([def("a"), def("b")]);
    r.load(["a", "b"]);
    r.seed([def("a")]); // b vanished (server dropped)
    expect(r.size()).toBe(1);
    expect(r.isLoaded("b")).toBe(false);
    expect(r.loadedDefinitions().map((d) => d.name)).toEqual(["a"]);
  });

  it("catalogEntries filters by name or description, sorted, marks loaded", () => {
    const r = new DeferredToolRegistry();
    r.seed([def("send_mail", "send an email"), def("nmap_scan", "port scan a host")]);
    r.load(["send_mail"]);
    const all = r.catalogEntries();
    expect(all.map((e) => e.name)).toEqual(["nmap_scan", "send_mail"]);
    expect(all.find((e) => e.name === "send_mail")?.loaded).toBe(true);
    // filter by description keyword
    expect(r.catalogEntries("email").map((e) => e.name)).toEqual(["send_mail"]);
    // filter by name substring
    expect(r.catalogEntries("nmap").map((e) => e.name)).toEqual(["nmap_scan"]);
  });

  it("recognizes its control tools", () => {
    const r = new DeferredToolRegistry();
    expect(r.isControlTool(LIST_TOOLS_NAME)).toBe(true);
    expect(r.isControlTool(LOAD_TOOL_NAME)).toBe(true);
    expect(r.isControlTool("bash")).toBe(false);
  });
});

describe("control tool definitions", () => {
  it("expose stable names", () => {
    expect(listToolsDef.name).toBe(LIST_TOOLS_NAME);
    expect(loadToolDef.name).toBe(LOAD_TOOL_NAME);
    expect(loadToolDef.required).toContain("names");
  });
});

describe("formatToolCatalog", () => {
  it("reports emptiness distinctly with/without a query", () => {
    expect(formatToolCatalog([])).toMatch(/No additional loadable tools/);
    expect(formatToolCatalog([], "xyz")).toMatch(/No loadable tools match "xyz"/);
  });

  it("lists entries and flags loaded ones", () => {
    const out = formatToolCatalog([
      { name: "a", description: "alpha", loaded: false },
      { name: "b", description: "beta", loaded: true },
    ]);
    expect(out).toContain("- a — alpha");
    expect(out).toContain("- b [loaded] — beta");
  });

  it("truncates long descriptions", () => {
    const out = formatToolCatalog([{ name: "a", description: "x".repeat(500), loaded: false }]);
    expect(out).toContain("…");
    expect(out.length).toBeLessThan(300);
  });
});

describe("formatLoadResult", () => {
  it("summarizes loaded and unknown", () => {
    expect(formatLoadResult({ loaded: ["a", "b"], unknown: [] })).toMatch(/Loaded 2 tool/);
    expect(formatLoadResult({ loaded: [], unknown: ["z"] })).toMatch(/Not found.*z/);
    expect(formatLoadResult({ loaded: [], unknown: [] })).toMatch(/No tool names/);
  });
});

describe("threshold", () => {
  it("is a sane positive floor", () => {
    expect(DEFERRED_TOOLS_MIN).toBeGreaterThan(0);
  });
});
