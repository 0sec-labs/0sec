/**
 * 0sec#193 — Deterministic replay runner tests.
 *
 * Covers:
 *   • LocalShellRunner: timeout enforcement, exit-code capture, excerpt
 *     truncation, working-dir isolation.
 *   • Assertion evaluation: all four canonical kinds (exit_code,
 *     string_in_output, file_exists, http_status), pass + fail.
 *   • End-to-end: a fixture finding with a one-step `echo hello && exit 0`
 *     PoC and a `string_in_output: hello` assertion produces
 *     `status: reproduced` and a result that re-parses through the shared
 *     zod schema.
 *
 * These tests run on POSIX hosts only (the runner spawns `/bin/sh -c`); CI
 * macOS / Linux is the target.
 */

import { describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { VerificationResultSchema, type Finding, type PocStep } from "@0sec/shared";
import {
  LocalShellRunner,
  DockerRunner,
  QemuRunner,
  NotImplementedError,
  STREAM_EXCERPT_BYTES,
  argvForStep,
  assertionFromStepExpect,
  evaluateAssertion,
  excerpt,
  runDeterministicReplay,
} from "./replay-runner.js";

function makeFinding(steps: PocStep[]): Finding {
  return {
    id: "finding-test-1",
    templateId: "tpl-test",
    title: "Test finding",
    description: "Synthetic test finding for replay runner",
    severity: "high",
    category: "command-injection",
    status: "verified",
    evidence: { request: "test", response: "test" },
    pocSteps: steps,
    timestamp: Date.now(),
  };
}

describe("LocalShellRunner", () => {
  it("captures stdout and exit code for a successful command", async () => {
    const runner = new LocalShellRunner();
    const runDir = mkdtempSync(join(tmpdir(), "0sec-runner-test-"));
    const step: PocStep = {
      id: "s1",
      kind: "exploit",
      summary: "echo a marker",
      action: { type: "shell", cmd: "echo HELLO_MARKER" },
    };
    const r = await runner.exec(step, { runDir, stepTimeoutMs: 5000 });
    expect(r.exitCode).toBe(0);
    expect(r.stdoutFull).toContain("HELLO_MARKER");
    expect(r.argv).toEqual(["/bin/sh", "-c", "echo HELLO_MARKER"]);
    expect(r.timedOut).toBeFalsy();
  });

  it("captures non-zero exit codes faithfully", async () => {
    const runner = new LocalShellRunner();
    const runDir = mkdtempSync(join(tmpdir(), "0sec-runner-test-"));
    const step: PocStep = {
      id: "s1",
      kind: "exploit",
      summary: "exit with code 42",
      action: { type: "shell", cmd: "exit 42" },
    };
    const r = await runner.exec(step, { runDir, stepTimeoutMs: 5000 });
    expect(r.exitCode).toBe(42);
  });

  it("enforces the per-step wallclock timeout", async () => {
    const runner = new LocalShellRunner();
    const runDir = mkdtempSync(join(tmpdir(), "0sec-runner-test-"));
    const step: PocStep = {
      id: "s1",
      kind: "exploit",
      summary: "sleep too long",
      action: { type: "shell", cmd: "sleep 5" },
    };
    const t0 = Date.now();
    const r = await runner.exec(step, { runDir, stepTimeoutMs: 100 });
    const elapsed = Date.now() - t0;
    // Generous slack: timeout is 100ms; we should be well under the 5s sleep.
    expect(elapsed).toBeLessThan(2000);
    expect(r.timedOut).toBe(true);
    // SIGKILL: exit code is null on Node when killed by signal.
    expect(r.exitCode).toBeNull();
  });

  it("isolates working directory to the supplied runDir", async () => {
    const runner = new LocalShellRunner();
    const runDir = mkdtempSync(join(tmpdir(), "0sec-runner-test-"));
    const step: PocStep = {
      id: "s1",
      kind: "exploit",
      summary: "print pwd",
      action: { type: "shell", cmd: "pwd" },
    };
    const r = await runner.exec(step, { runDir, stepTimeoutMs: 5000 });
    // The shell may report the path with a resolved symlink (macOS
    // /var/folders → /private/var/folders), so compare via realpath.
    const actualPwd = r.stdoutFull.trim();
    expect(actualPwd.endsWith(runDir.replace(/^\/var\//, "/private/var/"))
      || actualPwd === runDir).toBe(true);
  });

  it("ignores absolute step.action.cwd and falls back to runDir", async () => {
    const runner = new LocalShellRunner();
    const runDir = mkdtempSync(join(tmpdir(), "0sec-runner-test-"));
    const step: PocStep = {
      id: "s1",
      kind: "exploit",
      summary: "print pwd",
      // Absolute cwd is refused (defence-in-depth); runner falls back to runDir.
      action: { type: "shell", cmd: "pwd", cwd: "/etc" },
    };
    const r = await runner.exec(step, { runDir, stepTimeoutMs: 5000 });
    expect(r.stdoutFull.trim()).not.toBe("/etc");
  });

  it("records non-shell step kinds with a launchError marker", async () => {
    const runner = new LocalShellRunner();
    const runDir = mkdtempSync(join(tmpdir(), "0sec-runner-test-"));
    const step: PocStep = {
      id: "s1",
      kind: "exploit",
      summary: "operator note",
      action: { type: "note", text: "this step is informational" },
    };
    const r = await runner.exec(step, { runDir, stepTimeoutMs: 5000 });
    expect(r.exitCode).toBeNull();
    expect(r.launchError).toMatch(/only executes shell steps/);
  });
});

describe("excerpt truncation", () => {
  it("returns the input when smaller than the cap", () => {
    expect(excerpt("hello", 100)).toBe("hello");
  });
  it("truncates with a stable marker when over the cap", () => {
    const big = "x".repeat(STREAM_EXCERPT_BYTES + 100);
    const out = excerpt(big);
    expect(out.length).toBeLessThan(big.length);
    expect(out.endsWith("[truncated]")).toBe(true);
  });
  it("handles empty strings", () => {
    expect(excerpt("")).toBe("");
  });
});

describe("argvForStep", () => {
  it("emits a deterministic argv per action kind", () => {
    expect(
      argvForStep({
        id: "x",
        kind: "exploit",
        summary: "",
        action: { type: "shell", cmd: "id" },
      }),
    ).toEqual(["/bin/sh", "-c", "id"]);
    expect(
      argvForStep({
        id: "x",
        kind: "exploit",
        summary: "",
        action: { type: "http", method: "POST", url: "http://x/y" },
      }),
    ).toEqual(["POST", "http://x/y"]);
    expect(
      argvForStep({
        id: "x",
        kind: "exploit",
        summary: "",
        action: { type: "docker", image: "alpine", args: ["sh", "-c", "id"] },
      }),
    ).toEqual(["docker", "run", "--rm", "sh", "-c", "id", "alpine"]);
    expect(
      argvForStep({
        id: "n1",
        kind: "exploit",
        summary: "",
        action: { type: "note", text: "x" },
      }),
    ).toEqual(["note", "n1"]);
  });
});

describe("assertion evaluation — pass + fail per kind", () => {
  const step: PocStep = {
    id: "step-1",
    kind: "exploit",
    summary: "",
    action: { type: "shell", cmd: "echo hi" },
  };

  it("exit_code pass + fail", () => {
    const passResult = {
      argv: ["/bin/sh", "-c", "exit 0"],
      exitCode: 0,
      stdoutFull: "",
      stderrFull: "",
      durationMs: 1,
    };
    const failResult = { ...passResult, exitCode: 1 };
    const pass = assertionFromStepExpect(step, { type: "exit-zero" }, passResult);
    expect(pass).toMatchObject({ kind: "exit_code", expected: 0, passed: true });
    const fail = assertionFromStepExpect(step, { type: "exit-zero" }, failResult);
    expect(fail.passed).toBe(false);
  });

  it("string_in_output pass + fail", () => {
    const result = {
      argv: [],
      exitCode: 0,
      stdoutFull: "the quick brown fox",
      stderrFull: "",
      durationMs: 1,
    };
    expect(
      assertionFromStepExpect(step, { type: "body-contains", text: "brown" }, result).passed,
    ).toBe(true);
    expect(
      assertionFromStepExpect(step, { type: "body-contains", text: "purple" }, result).passed,
    ).toBe(false);
  });

  it("file_exists pass + fail", () => {
    const runDir = mkdtempSync(join(tmpdir(), "0sec-runner-assert-"));
    const target = join(runDir, "loot.txt");
    writeFileSync(target, "stolen");
    const passResult = {
      argv: [],
      exitCode: 0,
      stdoutFull: "",
      stderrFull: "",
      durationMs: 1,
    };
    expect(
      assertionFromStepExpect(step, { type: "file-exists", path: target }, passResult).passed,
    ).toBe(true);
    expect(
      assertionFromStepExpect(
        step,
        { type: "file-exists", path: join(runDir, "missing") },
        passResult,
      ).passed,
    ).toBe(false);
  });

  it("http_status assertion via evaluateAssertion is unevaluated by local runner", () => {
    // Local runner doesn't speak HTTP; the assertion records actual=null
    // so a downstream consumer can tell the kind wasn't supported.
    const r = evaluateAssertion(
      {
        kind: "http_status",
        target: "GET /admin",
        expected: 401,
      },
      { lastExitCode: 0, aggregatedStdout: "", runDir: "/tmp" },
    );
    expect(r.passed).toBe(false);
    expect(r.actual).toBeNull();
  });

  it("evaluateAssertion handles string_in_output across aggregated stdout", () => {
    const pass = evaluateAssertion(
      { kind: "string_in_output", target: "any", expected: "magic" },
      { lastExitCode: 0, aggregatedStdout: "the magic word", runDir: "/tmp" },
    );
    expect(pass.passed).toBe(true);
    const fail = evaluateAssertion(
      { kind: "string_in_output", target: "any", expected: "missing" },
      { lastExitCode: 0, aggregatedStdout: "the magic word", runDir: "/tmp" },
    );
    expect(fail.passed).toBe(false);
  });

  it("evaluateAssertion handles file_exists relative to runDir", () => {
    const runDir = mkdtempSync(join(tmpdir(), "0sec-runner-assert-"));
    writeFileSync(join(runDir, "marker"), "x");
    const pass = evaluateAssertion(
      { kind: "file_exists", target: "marker", expected: true },
      { lastExitCode: 0, aggregatedStdout: "", runDir },
    );
    expect(pass.passed).toBe(true);
  });
});

describe("DockerRunner / QemuRunner stubs", () => {
  it("DockerRunner.exec throws NotImplementedError", async () => {
    const runner = new DockerRunner();
    await expect(
      runner.exec(
        { id: "s", kind: "exploit", summary: "", action: { type: "shell", cmd: "id" } },
        { runDir: "/tmp", stepTimeoutMs: 1000 },
      ),
    ).rejects.toBeInstanceOf(NotImplementedError);
  });
  it("QemuRunner.exec throws NotImplementedError", async () => {
    const runner = new QemuRunner();
    await expect(
      runner.exec(
        { id: "s", kind: "exploit", summary: "", action: { type: "shell", cmd: "id" } },
        { runDir: "/tmp", stepTimeoutMs: 1000 },
      ),
    ).rejects.toBeInstanceOf(NotImplementedError);
  });
});

describe("runDeterministicReplay — end-to-end", () => {
  it("produces status='reproduced' for a single-step echo PoC with a passing assertion", async () => {
    const finding = makeFinding([
      {
        id: "exploit-1",
        kind: "exploit",
        summary: "echo hello",
        action: { type: "shell", cmd: "echo hello && exit 0" },
        expect: { type: "body-contains", text: "hello" },
      },
    ]);
    const { result, runDir } = await runDeterministicReplay(finding);

    expect(result.status).toBe("reproduced");
    expect(result.mode).toBe("deterministic_replay");
    expect(result.finding_id).toBe(finding.id);
    expect(result.commands).toHaveLength(1);
    expect(result.commands[0].exit_code).toBe(0);
    expect(result.commands[0].stdout_excerpt).toContain("hello");
    expect(result.assertions).toHaveLength(1);
    expect(result.assertions[0]).toMatchObject({
      kind: "string_in_output",
      expected: "hello",
      passed: true,
    });
    expect(result.engine_metadata.runner).toBe("local");
    expect(result.duration_ms).toBeGreaterThanOrEqual(0);

    // The result must validate against the canonical shared schema.
    const parsed = VerificationResultSchema.parse(result);
    expect(parsed).toEqual(result);

    // The full stdout was persisted as an artifact under runDir.
    expect(result.evidence_artifacts.length).toBeGreaterThanOrEqual(1);
    const stdoutArt = result.evidence_artifacts.find((a) => a.kind === "stdout");
    expect(stdoutArt).toBeDefined();
    expect(existsSync(join(runDir, stdoutArt!.path))).toBe(true);
  });

  it("returns status='not_reproduced' when an assertion fails", async () => {
    const finding = makeFinding([
      {
        id: "exploit-1",
        kind: "exploit",
        summary: "echo something else",
        action: { type: "shell", cmd: "echo goodbye" },
        expect: { type: "body-contains", text: "hello" },
      },
    ]);
    const { result } = await runDeterministicReplay(finding);
    expect(result.status).toBe("not_reproduced");
    expect(result.assertions[0].passed).toBe(false);
  });

  it("returns status='skipped' when the finding has no pocSteps", async () => {
    const finding = makeFinding([]);
    const { result } = await runDeterministicReplay(finding);
    expect(result.status).toBe("skipped");
    expect(result.commands).toHaveLength(0);
    expect(result.assertions).toHaveLength(0);
  });

  it("uses freestanding opts.assertions in addition to per-step expectations", async () => {
    const finding = makeFinding([
      {
        id: "exploit-1",
        kind: "exploit",
        summary: "echo and drop a file",
        action: {
          type: "shell",
          cmd: "echo loot > marker && echo done",
        },
      },
    ]);
    const { result, runDir } = await runDeterministicReplay(finding, {
      assertions: [
        { kind: "exit_code", target: "exploit-1", expected: 0 },
        { kind: "file_exists", target: "marker", expected: true },
        { kind: "string_in_output", target: "exploit-1", expected: "done" },
      ],
    });
    expect(result.status).toBe("reproduced");
    expect(result.assertions).toHaveLength(3);
    expect(result.assertions.every((a) => a.passed)).toBe(true);
    expect(existsSync(join(runDir, "marker"))).toBe(true);
  });

  it("returns status='error' when the runner itself throws", async () => {
    const finding = makeFinding([
      {
        id: "exploit-1",
        kind: "exploit",
        summary: "shell op",
        action: { type: "shell", cmd: "echo hi" },
      },
    ]);
    const { result } = await runDeterministicReplay(finding, {
      runner: new DockerRunner(),
    });
    expect(result.status).toBe("error");
    expect(result.error_reason).toMatch(/not implemented/i);
  });

  it("caps stdout excerpts at STREAM_EXCERPT_BYTES while persisting full payload", async () => {
    // Generate ~32 KiB of stdout via printf
    const bytes = STREAM_EXCERPT_BYTES * 4;
    const finding = makeFinding([
      {
        id: "exploit-1",
        kind: "exploit",
        summary: "produce lots of bytes",
        action: {
          type: "shell",
          // Use printf to emit a known byte volume; portable across BSD/GNU shells.
          cmd: `head -c ${bytes} /dev/urandom | base64 | head -c ${bytes}`,
        },
      },
    ]);
    const { result, runDir } = await runDeterministicReplay(finding, {
      stepTimeoutMs: 10000,
    });
    expect(result.commands[0].stdout_excerpt!.length).toBeLessThanOrEqual(
      STREAM_EXCERPT_BYTES + "[truncated]".length + 5,
    );
    const stdoutArt = result.evidence_artifacts.find((a) => a.kind === "stdout");
    expect(stdoutArt).toBeDefined();
    const onDisk = readFileSync(join(runDir, stdoutArt!.path), "utf8");
    expect(onDisk.length).toBeGreaterThan(STREAM_EXCERPT_BYTES);
  });
});
