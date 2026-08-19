import { afterEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  buildCraftTargetSpec,
  findCraftFuzzerEntrypoints,
  renderCraftTargetSpec,
} from "./craft-target-spec.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(): string {
  const root = mkdtempSync(join(tmpdir(), "craft-target-spec-"));
  roots.push(root);
  mkdirSync(join(root, "fuzz"));
  writeFileSync(
    join(root, "fuzz", "entry.cc"),
    "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return 0; }\n",
  );
  return root;
}

describe("craft target specification", () => {
  it("records description anchors and concrete fuzzer locations before any model call", () => {
    const sourceRoot = fixture();
    const spec = buildCraftTargetSpec({
      sourceRoot,
      taskId: "arvo:example",
      description: "Overflow in `parse_header()` after decode().",
    });

    expect(spec.taskId).toBe("arvo:example");
    expect(spec.descriptionAnchors).toEqual(["parse_header", "decode"]);
    expect(spec.fuzzerEntrypoints).toEqual([
      { path: "fuzz/entry.cc", line: 1, symbol: "LLVMFuzzerTestOneInput" },
    ]);
    expect(spec.unresolved).toEqual([]);
    expect(renderCraftTargetSpec(spec)).toContain("fuzz/entry.cc:1");
  });

  it("makes absent discovery facts explicit instead of inventing a target", () => {
    const sourceRoot = mkdtempSync(join(tmpdir(), "craft-target-spec-empty-"));
    roots.push(sourceRoot);
    const spec = buildCraftTargetSpec({ sourceRoot, description: "Parser crashes on a malformed input." });

    expect(findCraftFuzzerEntrypoints(sourceRoot)).toEqual([]);
    expect(spec.descriptionAnchors).toEqual([]);
    expect(spec.unresolved).toEqual([
      "description names no callable function anchor",
      "no LLVMFuzzerTestOneInput entrypoint found in the source tree",
    ]);
    expect(renderCraftTargetSpec(spec)).toContain("none resolved");
  });
});
