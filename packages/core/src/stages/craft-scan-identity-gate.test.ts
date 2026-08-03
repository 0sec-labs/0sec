import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
});
