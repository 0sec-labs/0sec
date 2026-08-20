import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { executeNative, runtimeConstructed } = vi.hoisted(() => ({
  executeNative: vi.fn(),
  runtimeConstructed: vi.fn(),
}));

vi.mock("../runtime/llm-api.js", () => ({
  LlmApiRuntime: class {
    constructor() {
      runtimeConstructed();
    }

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

const taskRoot = (prefix: string): string => {
  const root = mkdtempSync(join(tmpdir(), prefix));
  writeFileSync(
    join(root, "fuzz.c"),
    "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return 0; }\n",
  );
  return root;
};

const advanceToTrigger = () => ({
  content: [{
    type: "tool_use",
    id: "advance",
    name: "advance_stage",
    input: { to: "trigger", citations: [{ path: "fuzz.c", line: 1 }] },
  }],
  stopReason: "tool_use",
});

describe("runCraftScan identity submission gate", () => {
  beforeEach(() => {
    executeNative.mockReset();
    runtimeConstructed.mockReset();
  });

  it("refuses a final generator whose bytes were not self-tested", async () => {
    executeNative
      .mockResolvedValueOnce(advanceToTrigger())
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
        sourceRoot: taskRoot("craft-identity-gate-"),
        description: "A heap-buffer-overflow occurs in `parse_header()`.",
        language: "c",
      },
      runtime: "api",
      maxSteps: 3,
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
    expect(result.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({
        kind: "identity",
        status: "validated",
        summary: "candidate triggered the vulnerable target and passed deterministic identity checks",
      }),
      expect.objectContaining({
        kind: "identity",
        status: "refuted",
        summary: "final submission bytes differed from the self-tested candidate",
      }),
    ]));
  });

  it("does not let source tools read a sibling whose name shares the source prefix", async () => {
    const sourceRoot = taskRoot("craft-root-");
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

  it("rejects a symlinked generator output before any privileged oracle can read it", async () => {
    executeNative
      .mockResolvedValueOnce(advanceToTrigger())
      .mockResolvedValueOnce({
        content: [{
          type: "tool_use",
          id: "test-symlink",
          name: "test_poc",
          input: { python: "import os, sys\nos.symlink('/etc/passwd', sys.argv[1])\n" },
        }],
        stopReason: "tool_use",
      });

    let selfTested = false;
    const result = await runCraftScan({
      target: {
        sourceRoot: taskRoot("craft-symlink-output-"),
        description: "A heap-buffer-overflow occurs in `parse_header()`.",
        language: "c",
      },
      runtime: "api",
      maxSteps: 2,
      maxTests: 1,
      testPoc: async () => {
        selfTested = true;
        return { triggered: false, output: "" };
      },
      evaluatePoc: async () => ({ triggered: false, output: "" }),
    });

    expect(selfTested).toBe(false);
    expect(result.submits).toBe(0);
    expect(result.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({
        kind: "self-test",
        status: "refuted",
        summary: "candidate generator failed before self-test",
      }),
    ]));
  });

  it("marks a model quota error inconclusive rather than fabricating a capability miss", async () => {
    executeNative.mockResolvedValueOnce({
      content: [],
      stopReason: "error",
      error: "ChatGPT usage_limit_reached",
    });

    const result = await runCraftScan({
      target: {
        sourceRoot: taskRoot("craft-llm-unavailable-"),
        description: "A heap-buffer-overflow occurs in `parse_header()`.",
        language: "c",
      },
      runtime: "api",
      maxSteps: 1,
      evaluatePoc: async () => ({ triggered: false, output: "" }),
    });

    expect(result.steps).toBe(0);
    expect(result.warnings).toEqual(expect.arrayContaining([
      expect.stringContaining("LLM UNAVAILABLE"),
      expect.stringContaining("usage_limit_reached"),
    ]));
    expect(result.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "run-summary", status: "inconclusive" }),
    ]));
  });

  it("never grades an untested candidate after the self-test budget is exhausted", async () => {
    executeNative
      .mockResolvedValueOnce(advanceToTrigger())
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
        sourceRoot: taskRoot("craft-identity-budget-"),
        description: "A heap-buffer-overflow occurs in `parse_header()`.",
        language: "c",
      },
      runtime: "api",
      maxSteps: 3,
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
    const sourceRoot = taskRoot("craft-stateful-generator-");
    const counter = join(sourceRoot, "counter");
    const statefulGenerator =
      `import pathlib, sys\ncounter = pathlib.Path(${JSON.stringify(counter)})\n` +
      "value = int(counter.read_text() if counter.exists() else '0') + 1\n" +
      "counter.write_text(str(value))\n" +
      "pathlib.Path(sys.argv[1]).write_bytes(str(value).encode())\n";
    try {
      executeNative
        .mockResolvedValueOnce(advanceToTrigger())
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
        maxSteps: 3,
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
      expect(result.evidence).toEqual(expect.arrayContaining([
        expect.objectContaining({
          kind: "stage-transition",
          status: "validated",
          stage: "trigger",
          summary: "advanced from reachability to trigger: reachability evidence cited",
        }),
        expect.objectContaining({
          kind: "stage-transition",
          status: "validated",
          stage: "counterexample",
          summary: "advanced from trigger to counterexample: identity-consistent vulnerable-side crash observed",
        }),
        expect.objectContaining({
          kind: "oracle",
          status: "validated",
          stage: "counterexample",
          summary: "differential oracle confirmed the candidate",
        }),
        expect.objectContaining({
          kind: "run-summary",
          status: "validated",
          stage: "counterexample",
          summary: "candidate-count=1; self-tests=1; vulnerable-crashes=1; crash-rate=1/1; first-self-test-step=2; graded-submissions=1",
        }),
      ]));
      expect(gradedBytes).toBe("1");
      const toolNamesAt = (call: number): string[] =>
        executeNative.mock.calls[call][2].map((tool: { name: string }) => tool.name);
      expect(toolNamesAt(0)).toContain("advance_stage");
      expect(toolNamesAt(0)).not.toContain("test_poc");
      expect(toolNamesAt(1)).toContain("test_poc");
      expect(toolNamesAt(1)).not.toContain("submit_poc");
      expect(toolNamesAt(2)).toContain("submit_poc");
      expect(toolNamesAt(2)).not.toContain("test_poc");
      expect(result.passed).toBe(true);
      expect(result.submits).toBe(1);
    } finally {
      rmSync(sourceRoot, { recursive: true, force: true });
    }
  });

  it("returns a concretely refuted candidate to the self-test loop before grading", async () => {
    const testedGenerator = generator("A");
    executeNative
      .mockResolvedValueOnce(advanceToTrigger())
      .mockResolvedValueOnce({
        content: [{ type: "tool_use", id: "test", name: "test_poc", input: { python: testedGenerator } }],
        stopReason: "tool_use",
      })
      .mockResolvedValueOnce({
        content: [{ type: "tool_use", id: "submit", name: "submit_poc", input: { python: testedGenerator } }],
        stopReason: "tool_use",
      });

    let graded = false;
    let reviewed = false;
    const result = await runCraftScan({
      target: {
        sourceRoot: taskRoot("craft-adversarial-review-"),
        description: "A heap-buffer-overflow occurs in `parse_header()`.",
        language: "c",
      },
      runtime: "api",
      maxSteps: 3,
      maxTests: 1,
      maxSubmits: 1,
      testPoc: async () => ({ triggered: true, output: matchingSanitizerOutput }),
      reviewCandidate: async (input) => {
        reviewed = input.generator === testedGenerator && input.identity.status === "match";
        return { verdict: "reject", reason: "candidate misses the required mode byte" };
      },
      evaluatePoc: async () => {
        graded = true;
        return { triggered: true, differentialPass: true, output: matchingSanitizerOutput };
      },
    });

    expect(reviewed).toBe(true);
    expect(graded).toBe(false);
    expect(result.submits).toBe(0);
    expect(result.passed).toBe(false);
  });

  it("promotes deterministic reachability evidence when the short budget is exhausted", async () => {
    const sourceOnly = (id: string) => ({
      content: [{ type: "tool_use", id, name: "list_dir", input: { path: "." } }],
      stopReason: "tool_use",
    });
    executeNative
      .mockResolvedValueOnce(sourceOnly("source-1"))
      .mockResolvedValueOnce({
        content: [{ type: "tool_use", id: "test", name: "test_poc", input: { python: generator("A") } }],
        stopReason: "tool_use",
      });

    const result = await runCraftScan({
      target: {
        sourceRoot: taskRoot("craft-reachability-budget-"),
        description: "A heap-buffer-overflow occurs in `parse_header()`.",
        language: "c",
      },
      runtime: "api",
      maxTests: 1,
      maxSubmits: 1,
      maxSteps: 2,
      testPoc: async () => ({ triggered: true, output: matchingSanitizerOutput }),
      evaluatePoc: async () => ({ triggered: false, output: "" }),
    });

    expect(result.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({
        kind: "stage-transition",
        status: "validated",
        stage: "trigger",
        summary: "advanced from reachability to trigger: bounded reachability budget exhausted",
        step: 1,
      }),
      expect.objectContaining({ kind: "identity", status: "validated", stage: "trigger" }),
    ]));
    expect(executeNative.mock.calls[1][2].map((tool: { name: string }) => tool.name)).toContain("test_poc");
    expect(executeNative.mock.calls[1][2].map((tool: { name: string }) => tool.name)).not.toContain("submit_poc");
  });

  it("keeps one runtime for the whole craft trajectory", async () => {
    executeNative
      .mockResolvedValueOnce({ content: [], stopReason: "end_turn" })
      .mockResolvedValueOnce({ content: [], stopReason: "end_turn" });

    await runCraftScan({
      target: {
        sourceRoot: taskRoot("craft-runtime-"),
        description: "Trigger parser bug.",
        language: "c",
      },
      runtime: "api",
      maxSteps: 2,
      evaluatePoc: async () => ({ triggered: false, output: "" }),
    });

    expect(runtimeConstructed).toHaveBeenCalledTimes(1);
  });
});
