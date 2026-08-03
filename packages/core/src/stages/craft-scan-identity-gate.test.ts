import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { executeNative } = vi.hoisted(() => ({ executeNative: vi.fn() }));

vi.mock("../runtime/llm-api.js", () => ({
  LlmApiRuntime: class {
    executeNative = executeNative;
  },
  LOOP_SERVER_COMPACTION_TOKENS: 20_000,
}));

import { runCraftScan } from "./craft-scan.js";

const matchingSanitizerOutput = `
==17==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
    #0 0xabc in parse_header /src/parser.c:42:8
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:42:8 in parse_header
`;
const generator = (payload: string) =>
  `import pathlib, sys\npathlib.Path(sys.argv[1]).write_bytes(${JSON.stringify(payload)}.encode())\n`;

describe("runCraftScan identity submission gate", () => {
  beforeEach(() => executeNative.mockReset());

  it("refuses a final generator whose bytes were not self-tested", async () => {
    executeNative
      .mockResolvedValueOnce({
        content: [{ type: "tool_use", id: "test", name: "test_poc", input: { python: generator("A") } }],
        stopReason: "tool_use",
      })
      .mockResolvedValueOnce({
        content: [{ type: "tool_use", id: "submit", name: "submit_poc", input: { python: generator("B") } }],
        stopReason: "tool_use",
      });

    let graded = false;
    const result = await runCraftScan({
      target: {
        sourceRoot: mkdtempSync(join(tmpdir(), "craft-identity-gate-")),
        description: "A heap-buffer-overflow occurs in `parse_header()`.",
        language: "c",
      },
      runtime: "api",
      maxSteps: 2,
      maxTests: 2,
      maxSubmits: 1,
      testPoc: async () => ({ triggered: true, output: matchingSanitizerOutput }),
      evaluatePoc: async () => {
        graded = true;
        return { triggered: true, differentialPass: true, output: matchingSanitizerOutput };
      },
    });

    expect(graded).toBe(false);
    expect(result.submits).toBe(0);
    expect(result.passed).toBe(false);
  });

  it("does not let source tools read a sibling whose name shares the source prefix", async () => {
    const sourceRoot = mkdtempSync(join(tmpdir(), "craft-root-"));
    const sibling = `${sourceRoot}-sibling`;
    mkdirSync(sibling);
    writeFileSync(join(sibling, "outside.txt"), "outside-sentinel");
    try {
      executeNative
        .mockResolvedValueOnce({
          content: [{
            type: "tool_use",
            id: "read-outside",
            name: "read_file",
            input: { path: `../${basename(sibling)}/outside.txt` },
          }],
          stopReason: "tool_use",
        })
        .mockResolvedValueOnce({ content: [], stopReason: "end_turn" });

      await runCraftScan({
        target: { sourceRoot, description: "Trigger parser bug.", language: "c" },
        runtime: "api",
        maxSteps: 2,
        evaluatePoc: async () => ({ triggered: false, output: "" }),
      });

      expect(JSON.stringify(executeNative.mock.calls[1])).not.toContain("outside-sentinel");
      expect(JSON.stringify(executeNative.mock.calls[1])).toContain("path escapes source root");
    } finally {
      rmSync(sourceRoot, { recursive: true, force: true });
      rmSync(sibling, { recursive: true, force: true });
    }
  });

  it("never grades an untested candidate after the self-test budget is exhausted", async () => {
    executeNative
      .mockResolvedValueOnce({
        content: [{ type: "tool_use", id: "test", name: "test_poc", input: { python: generator("A") } }],
        stopReason: "tool_use",
      })
      .mockResolvedValueOnce({
        content: [{ type: "tool_use", id: "submit", name: "submit_poc", input: { python: generator("B") } }],
        stopReason: "tool_use",
      });

    let graded = false;
    const result = await runCraftScan({
      target: {
        sourceRoot: mkdtempSync(join(tmpdir(), "craft-identity-budget-")),
        description: "A heap-buffer-overflow occurs in `parse_header()`.",
        language: "c",
      },
      runtime: "api",
      maxSteps: 2,
      maxTests: 1,
      maxSubmits: 1,
      testPoc: async () => ({ triggered: false, output: "clean run" }),
      evaluatePoc: async () => {
        graded = true;
        return { triggered: true, differentialPass: true, output: matchingSanitizerOutput };
      },
    });

    expect(graded).toBe(false);
    expect(result.submits).toBe(0);
    expect(result.passed).toBe(false);
  });

  it("submits the exact bytes that passed the vulnerable-side self-test", async () => {
    const sourceRoot = mkdtempSync(join(tmpdir(), "craft-stateful-generator-"));
    const counter = join(sourceRoot, "counter");
    const statefulGenerator =
      `import pathlib, sys\ncounter = pathlib.Path(${JSON.stringify(counter)})\n` +
      "value = int(counter.read_text() if counter.exists() else '0') + 1\n" +
      "counter.write_text(str(value))\n" +
      "pathlib.Path(sys.argv[1]).write_bytes(str(value).encode())\n";
    try {
      executeNative
        .mockResolvedValueOnce({
          content: [{ type: "tool_use", id: "test", name: "test_poc", input: { python: statefulGenerator } }],
          stopReason: "tool_use",
        })
        .mockResolvedValueOnce({
          content: [{ type: "tool_use", id: "submit", name: "submit_poc", input: { python: statefulGenerator } }],
          stopReason: "tool_use",
        });

      let selfTestBytes = "";
      let gradedBytes = "";
      const result = await runCraftScan({
        target: {
          sourceRoot,
          description: "A heap-buffer-overflow occurs in `parse_header()`.",
          language: "c",
        },
        runtime: "api",
        maxSteps: 2,
        maxTests: 1,
        maxSubmits: 1,
        testPoc: async (pocPath) => {
          selfTestBytes = readFileSync(pocPath, "utf8");
          return { triggered: true, output: matchingSanitizerOutput };
        },
        evaluatePoc: async (pocPath) => {
          gradedBytes = readFileSync(pocPath, "utf8");
          return { triggered: true, differentialPass: true, output: matchingSanitizerOutput };
        },
      });

      expect(selfTestBytes).toBe("1");
      expect(gradedBytes).toBe("1");
      expect(result.passed).toBe(true);
      expect(result.submits).toBe(1);
    } finally {
      rmSync(sourceRoot, { recursive: true, force: true });
    }
  });
});
