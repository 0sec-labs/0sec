import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "@0sec/shared";
import type { NativeMessage, NativeRuntime } from "../runtime/types.js";
import { runSourceFix } from "./source-fix.js";

const tempRepos: string[] = [];

function createRepository(): string {
  const root = mkdtempSync(join(tmpdir(), "0sec-source-fix-"));
  tempRepos.push(root);
  mkdirSync(join(root, "src"));
  writeFileSync(
    join(root, "src", "auth.js"),
    [
      "export function parse(input) {",
      "  return input; // VULNERABLE",
      "}",
      "",
    ].join("\n"),
  );
  writeFileSync(
    join(root, "test.js"),
    [
      "import { readFileSync } from 'node:fs';",
      "const source = readFileSync('src/auth.js', 'utf8');",
      "if (!source.includes('typeof input !== \"string\"')) process.exit(1);",
      "",
    ].join("\n"),
  );
  execFileSync("git", ["init", "-q"], { cwd: root });
  execFileSync("git", ["add", "."], { cwd: root });
  execFileSync(
    "git",
    ["-c", "user.name=0sec-test", "-c", "user.email=0sec@example.test", "commit", "-qm", "fixture"],
    { cwd: root },
  );
  return root;
}

function finding(): Finding {
  const result: Finding = {
    id: "source-fix-001",
    templateId: "manual",
    title: "Missing input validation",
    description: "input parameter reaches the return path without validation",
    severity: "high",
    category: "missing-validation",
    status: "confirmed",
    evidence: {
      request: "src/auth.js:1",
      response: "parse(42)",
      analysis: "src/auth.js:1 accepts parameter input without validating its type",
    },
    reviewAnnotation: { path: "src/auth.js", startLine: 1 },
    verificationSpec: {
      code: [
        {
          kind: "file-contains",
          file: "src/auth.js",
          pattern: "return input; // VULNERABLE",
        },
      ],
    },
    timestamp: 1,
  };
  Object.assign(result as unknown as Record<string, unknown>, {
    verification_result: { status: "reproduced" },
  });
  return result;
}

function patch(): string {
  return [
    "*** Begin Patch",
    "*** Update File: src/auth.js",
    "@@ export function parse(input) {",
    " export function parse(input) {",
    '+  if (typeof input !== "string") throw new TypeError("input must be string");',
    "-  return input; // VULNERABLE",
    "+  return input;",
    " }",
    "*** End Patch",
  ].join("\n");
}

function runtimeFor(patches: string[], observedMessages?: NativeMessage[][]): NativeRuntime {
  let calls = 0;
  return {
    type: "api",
    async executeNative(_system, messages) {
      observedMessages?.push(messages.map((message) => ({
        ...message,
        content: [...message.content],
      })));
      const candidate = patches[Math.min(calls, patches.length - 1)]!;
      calls += 1;
      return {
        content: [
          {
            type: "tool_use",
            id: `proposal-${calls}`,
            name: "propose_fix",
            input: { patch: candidate, rationale: "Validate input before returning it." },
          },
        ],
        stopReason: "tool_use",
        durationMs: 1,
      };
    },
    async isAvailable() {
      return true;
    },
  };
}

afterEach(() => {
  for (const root of tempRepos.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("runSourceFix", () => {
  it("validates a generated patch in an isolated worktree without changing the source repo", async () => {
    const repoRoot = createRepository();

    const result = await runSourceFix({
      repoRoot,
      finding: finding(),
      runtime: runtimeFor([patch()]),
      testCommand: "node test.js",
    });

    expect(result.status).toBe("validated_candidate");
    expect(result.applied).toBe(false);
    expect(result.precondition?.passed).toBe(true);
    expect(result.postcondition?.passed).toBe(false);
    expect(result.test?.exitCode).toBe(0);
    expect(readFileSync(join(repoRoot, "src", "auth.js"), "utf8")).toContain("VULNERABLE");
  });

  it("applies only a candidate that passes its source recheck and test command", async () => {
    const repoRoot = createRepository();

    const result = await runSourceFix({
      repoRoot,
      finding: finding(),
      runtime: runtimeFor([patch()]),
      testCommand: "node test.js",
      apply: true,
    });

    expect(result.status).toBe("applied_and_retested");
    expect(result.applied).toBe(true);
    const source = readFileSync(join(repoRoot, "src", "auth.js"), "utf8");
    expect(source).toContain('typeof input !== "string"');
    expect(source).not.toContain("VULNERABLE");
  });


  it("never applies a patch when the isolated regression command fails", async () => {
    const repoRoot = createRepository();

    const result = await runSourceFix({
      repoRoot,
      finding: finding(),
      runtime: runtimeFor([patch()]),
      testCommand: "node -e 'process.exit(1)'",
      apply: true,
    });

    expect(result.status).toBe("not_fixed");
    expect(result.applied).toBe(false);
    expect(readFileSync(join(repoRoot, "src", "auth.js"), "utf8")).toContain("VULNERABLE");
  });
  it("rejects a bad patch, resets the candidate, and retries with the next proposal", async () => {
    const repoRoot = createRepository();
    const invalidPatch = patch().replace("src/auth.js", "src/other.js");
    const observedMessages: NativeMessage[][] = [];

    const result = await runSourceFix({
      repoRoot,
      finding: finding(),
      runtime: runtimeFor([invalidPatch, patch()], observedMessages),
      testCommand: "node test.js",
    });

    expect(result.status).toBe("validated_candidate");
    expect(result.attempts).toEqual([
      expect.objectContaining({ attempt: 1, reason: expect.stringContaining("expected only src/auth.js") }),
    ]);
    expect(observedMessages).toHaveLength(2);
    expect(observedMessages[1]!.at(-1)?.content).toEqual([
      expect.objectContaining({
        type: "tool_result",
        tool_use_id: "proposal-1",
        is_error: true,
      }),
    ]);
  });

  it("refuses to generate a patch when the finding was not independently reproduced", async () => {
    const repoRoot = createRepository();
    const unreproduced = finding();
    delete (unreproduced as unknown as Record<string, unknown>).verification_result;

    const result = await runSourceFix({
      repoRoot,
      finding: unreproduced,
      runtime: runtimeFor([patch()]),
      testCommand: "node test.js",
    });

    expect(result.status).toBe("precondition_failed");
    expect(result.error).toMatch(/reproduced/);
    expect(readFileSync(join(repoRoot, "src", "auth.js"), "utf8")).toContain("VULNERABLE");
  });
});
