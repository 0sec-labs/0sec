import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const { executeNative } = vi.hoisted(() => ({ executeNative: vi.fn() }));

vi.mock("../runtime/llm-api.js", () => ({
  LlmApiRuntime: class {
    executeNative = executeNative;
  },
  LOOP_SERVER_COMPACTION_TOKENS: 20_000,
}));

import { buildCraftCpgContext, extractCraftCpgTargets } from "./craft-cpg-context.js";
import { runCraftScan } from "./craft-scan.js";

const roots: string[] = [];
afterEach(() => {
  executeNative.mockReset();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function property(value: string | number): unknown {
  return { "@value": { "@value": [value] } };
}

function graphFixture(): unknown {
  const method = (id: number, name: string, file: string) => ({
    id: { "@value": id },
    label: "METHOD",
    properties: {
      NAME: property(name),
      FULL_NAME: property(name),
      FILENAME: property(file),
      LINE_NUMBER: property(1),
      LINE_NUMBER_END: property(10),
    },
  });
  const call = {
    id: { "@value": 101 },
    label: "CALL",
    properties: { CODE: property("helper()"), NAME: property("helper"), METHOD_FULL_NAME: property("helper") },
  };
  const edge = (label: string, out: number, inn: number) => ({
    label,
    outV: { "@value": out },
    inV: { "@value": inn },
  });
  return {
    "@value": {
      vertices: [method(1, "entry", "src/entry.c"), method(2, "helper", "src/helper.c"), call],
      edges: [edge("CONTAINS", 1, 101), edge("CALL", 101, 2)],
    },
  };
}

function fixture(): { sourceRoot: string; cpgPath: string } {
  const root = mkdtempSync(join(tmpdir(), "craft-cpg-"));
  roots.push(root);
  const cpgPath = join(root, "target.graphson.json");
  writeFileSync(cpgPath, JSON.stringify(graphFixture()));
  return { sourceRoot: root, cpgPath };
}

describe("craft CPG context", () => {
  it("derives description anchors and renders a bounded interprocedural slice", () => {
    const { cpgPath } = fixture();
    expect(extractCraftCpgTargets("Overflow in `entry()` after helper().")).toEqual(["entry", "helper"]);

    const context = buildCraftCpgContext("Overflow in `entry()` after helper().", { cpgPath });
    expect(context?.targetFunctions).toEqual(["entry", "helper"]);
    expect(context?.resolvedTargets).toBe(2);
    expect(context?.promptBlock).toContain("CPG reachability map");
    expect(context?.promptBlock).toContain("helper");
    expect(context?.promptBlock).toContain("evidence, not a verdict");
  });

  it("fails open when no trusted CPG export is available", () => {
    const messages: string[] = [];
    const context = buildCraftCpgContext("Overflow in `entry()`.", {
      cpgPath: "/definitely/not/a/cpg.json",
    }, (message) => messages.push(message));
    expect(context).toBeUndefined();
    expect(messages.join(" ")).toContain("using source tools without a CPG slice");
  });

  it("includes CPG evidence in the craft trajectory prompt", async () => {
    const { sourceRoot, cpgPath } = fixture();
    executeNative.mockResolvedValueOnce({ content: [], stopReason: "end_turn" });

    await runCraftScan({
      target: {
        sourceRoot,
        description: "Overflow in `entry()` after helper().",
        language: "c",
        cpg: { cpgPath },
      },
      runtime: "api",
      maxSteps: 1,
      evaluatePoc: async () => ({ triggered: false, output: "" }),
    });

    expect(JSON.stringify(executeNative.mock.calls[0])).toContain("CPG reachability map");
    expect(JSON.stringify(executeNative.mock.calls[0])).toContain("helper");
  });
});
