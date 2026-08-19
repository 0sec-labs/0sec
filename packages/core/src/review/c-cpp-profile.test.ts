import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import {
  buildTier1Harness,
  cppReviewAgentPrompt,
  scaffoldTier1Harness,
  scaffoldTier2Harness,
} from "./c-cpp-profile.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

describe("buildTier1Harness", () => {
  it("emits a libFuzzer entry point that calls the target with (data, size)", () => {
    const harness = buildTier1Harness({
      header: "decoder.h",
      functionName: "decode_payload",
      declaration: "int decode_payload(const uint8_t *data, size_t size, uint8_t **out, size_t *out_size);",
    });
    expect(harness).toContain("LLVMFuzzerTestOneInput");
    expect(harness).toContain('#include "decoder.h"');
    // Default `bytesAndLen` shape passes both data and size.
    expect(harness).toMatch(/decode_payload\(data, size\);/);
    // Comment block carries the build + run hints so the agent doesn't
    // have to re-derive them.
    expect(harness).toContain("clang -O1 -g -fsanitize=address,undefined,fuzzer");
    expect(harness).toContain("-runs=100000 -timeout=10");
  });

  it("emits a single-arg call when inputShape is bytesPtr", () => {
    const harness = buildTier1Harness({
      header: "parser.h",
      functionName: "parse_blob",
      declaration: "void parse_blob(const uint8_t *data);",
      inputShape: "bytesPtr",
    });
    expect(harness).toMatch(/parse_blob\(data\);/);
    expect(harness).not.toMatch(/parse_blob\(data, size\)/);
  });

  it("emits out-buffer cleanup for bytesAndLenOut targets", () => {
    const harness = buildTier1Harness({
      header: "decoder.h",
      functionName: "decode_payload",
      declaration: "int decode_payload(const uint8_t *data, size_t size, uint8_t **out, size_t *out_size);",
      inputShape: "bytesAndLenOut",
    });
    expect(harness).toContain("uint8_t *out = NULL;");
    expect(harness).toMatch(/decode_payload\(data, size, &out, &out_size\);/);
    expect(harness).toContain("free(out);");
  });

  it("does not include any external network or filesystem side-effects in the harness", () => {
    // The harness must be self-contained — no curl, no wget, no
    // exfiltration paths. Defenders may run this on sensitive code.
    const harness = buildTier1Harness({
      header: "x.h",
      functionName: "f",
      declaration: "void f(const uint8_t *, size_t);",
    });
    expect(harness).not.toMatch(/curl|wget|fetch|http:|https:|fopen/i);
    expect(harness).not.toMatch(/exec|system|popen/);
  });
});

describe("cppReviewAgentPrompt — hypothesis seeding (#467)", () => {
  it("injects operator hypothesis as a primary research direction", () => {
    const hypothesis = "Check whether the JPEG decoder validates Huffman table lengths before writing into the fixed-size decode array";
    const prompt = cppReviewAgentPrompt("/tmp/libfoo", [], hypothesis);

    expect(prompt).toContain("OPERATOR HYPOTHESIS");
    expect(prompt).toContain("PRIMARY RESEARCH DIRECTION");
    expect(prompt).toContain(hypothesis);
    expect(prompt).toContain("60%");
  });

  it("omits the hypothesis block when no hypothesis is provided", () => {
    const prompt = cppReviewAgentPrompt("/tmp/libfoo", []);
    expect(prompt).not.toContain("OPERATOR HYPOTHESIS");
    expect(prompt).not.toContain("PRIMARY RESEARCH DIRECTION");
  });

  it("requires self-contained poc_steps that replay in a fresh sandbox", () => {
    // The tier-1 false-refute root cause: poc_steps referenced ephemeral
    // scan-sandbox paths (/tmp/0sec-harness/<id>/harness.c) that don't exist
    // when verify replays in a fresh sandbox → cc1 'No such file' → false refute.
    const prompt = cppReviewAgentPrompt("/tmp/libfoo", []);
    expect(prompt).toContain("SELF-CONTAINED");
    expect(prompt).toContain("FRESH sandbox");
    expect(prompt).toMatch(/git clone/);
    expect(prompt).toMatch(/0SEC_EOF/);
    expect(prompt).toContain("No such file");
  });
});

describe("scaffoldTier1Harness", () => {
  it("writes a harness file and returns clang build/run commands", async () => {
    const fixtureRoot = join(__dirname, "__fixtures__", "c-library-demo");
    const outDir = await mkdtemp(join(tmpdir(), "0sec-tier1-"));
    try {
      const scaffold = await scaffoldTier1Harness({
        srcDir: fixtureRoot,
        outputDir: outDir,
        includeDirs: ["include"],
        sourceFiles: ["src/decoder.c"],
        checkToolchain: false,
        entryFn: {
          header: "decoder.h",
          functionName: "decode_payload",
          declaration: "int decode_payload(const uint8_t *data, size_t size, uint8_t **out, size_t *out_size);",
          inputShape: "bytesAndLenOut",
        },
      });

      expect(scaffold.harnessPath).toBe(join(outDir, "fuzz_target.c"));
      expect(existsSync(scaffold.harnessPath)).toBe(true);
      expect(await readFile(scaffold.harnessPath, "utf8")).toContain(
        "LLVMFuzzerTestOneInput",
      );
      expect(scaffold.buildCmd).toContain("-fsanitize=address,undefined,fuzzer");
      expect(scaffold.buildCmd).toContain(join(fixtureRoot, "include"));
      expect(scaffold.buildCmd).toContain(join(fixtureRoot, "src", "decoder.c"));
      expect(scaffold.runCmd).toContain("-runs=100000");
      expect(scaffold.runCmd).toContain("-max_total_time=60");
      expect(scaffold.runCmd).toContain("-timeout=10");
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("refuses clearly when clang/libFuzzer support is unavailable", async () => {
    const fixtureRoot = join(__dirname, "__fixtures__", "c-library-demo");
    await expect(
      scaffoldTier1Harness({
        srcDir: fixtureRoot,
        clangPath: "/definitely/missing/clang",
        entryFn: {
          header: "decoder.h",
          functionName: "decode_payload",
          declaration: "int decode_payload(const uint8_t *data, size_t size, uint8_t **out, size_t *out_size);",
          inputShape: "bytesAndLenOut",
        },
      }),
    ).rejects.toThrow(/clang\/libFuzzer toolchain is unavailable/);
  });

  it("can build the fixture harness and produce an ASan heap-buffer-overflow when libFuzzer is available", async () => {
    if (!(await hasLibFuzzerToolchain())) return;

    const fixtureRoot = join(__dirname, "__fixtures__", "c-library-demo");
    const outDir = await mkdtemp(join(tmpdir(), "0sec-tier1-run-"));
    try {
      const scaffold = await scaffoldTier1Harness({
        srcDir: fixtureRoot,
        outputDir: outDir,
        includeDirs: ["include"],
        sourceFiles: ["src/decoder.c"],
        entryFn: {
          header: "decoder.h",
          functionName: "decode_payload",
          declaration: "int decode_payload(const uint8_t *data, size_t size, uint8_t **out, size_t *out_size);",
          inputShape: "bytesAndLenOut",
        },
      });
      await runShell(scaffold.buildCmd);

      const crashInput = join(outDir, "crash-input");
      const data = Buffer.alloc(8 + 65536, 0x41);
      data.writeUInt32LE(1024, 0);
      data.writeUInt32LE(64, 4);
      await writeFile(crashInput, data);

      const result = await execFileResult(join(outDir, "fuzz_target"), [crashInput]);
      expect(result.code).not.toBe(0);
      expect(`${result.stdout}\n${result.stderr}`).toMatch(
        /AddressSanitizer|heap-buffer-overflow/,
      );
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });
});

describe("scaffoldTier2Harness", () => {
  it("links an explicit component subset and optional seed corpus directories", async () => {
    const fixtureRoot = join(__dirname, "__fixtures__", "c-library-demo");
    const outDir = await mkdtemp(join(tmpdir(), "0sec-tier2-"));
    try {
      const scaffold = await scaffoldTier2Harness({
        srcDir: fixtureRoot,
        outputDir: outDir,
        includeDirs: ["include"],
        componentFiles: ["src/decoder.c"],
        seedCorpusDirs: ["corpus"],
        checkToolchain: false,
        entryFn: {
          header: "decoder.h",
          functionName: "decode_payload",
          declaration: "int decode_payload(const uint8_t *data, size_t size, uint8_t **out, size_t *out_size);",
          inputShape: "bytesAndLenOut",
        },
      });

      expect(scaffold.tier).toBe(2);
      expect(scaffold.harnessPath).toBe(join(outDir, "fuzz_target.c"));
      expect(scaffold.componentFiles).toEqual([join(fixtureRoot, "src", "decoder.c")]);
      expect(scaffold.seedCorpusDirs).toEqual([join(fixtureRoot, "corpus")]);
      expect(scaffold.buildCmd).toContain(join(fixtureRoot, "src", "decoder.c"));
      expect(scaffold.runCmd).toContain("-max_total_time=180");
      expect(scaffold.runCmd).toContain(join(fixtureRoot, "corpus"));
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("requires an explicit minimal component subset", async () => {
    const fixtureRoot = join(__dirname, "__fixtures__", "c-library-demo");

    await expect(
      scaffoldTier2Harness({
        srcDir: fixtureRoot,
        componentFiles: [],
        checkToolchain: false,
        entryFn: {
          header: "decoder.h",
          functionName: "decode_payload",
          declaration: "int decode_payload(const uint8_t *data, size_t size, uint8_t **out, size_t *out_size);",
        },
      }),
    ).rejects.toThrow(/requires at least one component/);
  });
});

describe("cppReviewAgentPrompt", () => {
  it("instructs the agent to validate findings with sanitizer logs", () => {
    const prompt = cppReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/sanitizer log/i);
    expect(prompt).toMatch(/static-analysis-only finding is a hypothesis/i);
  });

  it("calls out the tier-1/2/3 ladder explicitly", () => {
    const prompt = cppReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/Tier 1/);
    expect(prompt).toMatch(/Tier 2/);
    expect(prompt).toMatch(/Tier 3/);
  });

  it("lists integer arithmetic on allocation paths as a top hypothesis class", () => {
    const prompt = cppReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/Integer arithmetic on allocation paths/i);
    expect(prompt).toMatch(/malloc\(count \* size\)/);
  });

  it("requires findings to be persisted via save_finding tool calls", () => {
    const prompt = cppReviewAgentPrompt("/tmp/repo", []);
    // The prompt instructs the agent to use save_finding, not text blocks.
    expect(prompt).toContain("save_finding");
    expect(prompt).toContain("MANDATORY");
    // Key fields the agent must include in save_finding calls.
    expect(prompt).toMatch(/severity:/);
    expect(prompt).toMatch(/category:/);
    expect(prompt).toMatch(/evidence_analysis:/);
  });
});

describe("c-library-demo fixture", () => {
  it("is shaped like a tier-1 candidate (single decode entry point on bytes+len)", () => {
    const headerPath = join(
      __dirname,
      "__fixtures__",
      "c-library-demo",
      "include",
      "decoder.h",
    );
    const header = readFileSync(headerPath, "utf-8");
    // The function signature the harness scaffolder will target.
    expect(header).toMatch(
      /int decode_payload\(const uint8_t \*data, size_t size,/,
    );
  });

  it("has the deliberate unchecked-multiplication pattern in the implementation", () => {
    const srcPath = join(
      __dirname,
      "__fixtures__",
      "c-library-demo",
      "src",
      "decoder.c",
    );
    const src = readFileSync(srcPath, "utf-8");
    // The fixture's whole point is the unchecked multiplication. If
    // someone "fixes" it, the C/C++ review tests stop being meaningful.
    expect(src).toMatch(/\(uint16_t\)\(count \* element_size\)/);
    // And the BUG: comment is the trail of intent for future readers.
    expect(src).toMatch(/BUG: unchecked multiplication/);
  });
});

async function hasLibFuzzerToolchain(): Promise<boolean> {
  const outDir = await mkdtemp(join(tmpdir(), "0sec-fuzzer-check-"));
  try {
    const source = join(outDir, "check.c");
    const binary = join(outDir, "check");
    await writeFile(
      source,
      `#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  (void)data;
  (void)size;
  return 0;
}
`,
      "utf8",
    );
    const result = await execFileResult("clang", [
      "-O1",
      "-g",
      "-fsanitize=address,undefined,fuzzer",
      source,
      "-o",
      binary,
    ]);
    return result.code === 0;
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
}

function runShell(command: string): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile("sh", ["-c", command], (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`${command}\n${stdout}\n${stderr}`));
      } else {
        resolve();
      }
    });
  });
}

function execFileResult(
  command: string,
  args: string[],
): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolveResult) => {
    execFile(command, args, (error, stdout, stderr) => {
      resolveResult({
        code: typeof error?.code === "number" ? error.code : error ? 1 : 0,
        stdout,
        stderr,
      });
    });
  });
}
