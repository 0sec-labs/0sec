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
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { VerificationResultSchema, type Finding, type PocStep } from "@0sec/shared";
import { ScopePolicy } from "../scope/scope.js";
import {
  LocalShellRunner,
  DockerRunner,
  QemuRunner,
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

function writeFakeExecutable(runDir: string, name: string, body: string): string {
  const path = join(runDir, name);
  writeFileSync(path, `#!/bin/sh\n${body}`, "utf8");
  chmodSync(path, 0o755);
  return path;
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

  it("does not leak harness credentials into the PoC shell, but keeps PATH + 0SEC_VERIFY", async () => {
    const prevAnthropic = process.env.ANTHROPIC_API_KEY;
    const prevGithub = process.env.GITHUB_TOKEN;
    process.env.ANTHROPIC_API_KEY = "sk-ant-should-not-leak";
    process.env.GITHUB_TOKEN = "ghp_should_not_leak";
    try {
      const runner = new LocalShellRunner();
      const runDir = mkdtempSync(join(tmpdir(), "0sec-runner-env-"));
      const step: PocStep = {
        id: "s-env",
        kind: "exploit",
        summary: "print sensitive + required env vars",
        action: {
          // `env` lists the child's full environment. `0SEC_VERIFY` cannot be
          // referenced via `$`-expansion (identifiers may not start with a
          // digit), so we inspect the raw listing instead.
          type: "shell",
          cmd: "env",
        },
      };
      const r = await runner.exec(step, { runDir, stepTimeoutMs: 5000 });
      expect(r.exitCode).toBe(0);
      // Harness credentials must NOT reach a PoC-authored shell step.
      expect(r.stdoutFull).not.toContain("ANTHROPIC_API_KEY");
      expect(r.stdoutFull).not.toContain("GITHUB_TOKEN");
      expect(r.stdoutFull).not.toContain("sk-ant-should-not-leak");
      expect(r.stdoutFull).not.toContain("ghp_should_not_leak");
      // What the child legitimately needs is still present. (Note: 0SEC_VERIFY
      // is passed to the spawn but /bin/sh strips digit-prefixed names on
      // startup, so it is deliberately not asserted via `env` here.)
      expect(r.stdoutFull).toMatch(/^PATH=/m);
    } finally {
      if (prevAnthropic === undefined) delete process.env.ANTHROPIC_API_KEY;
      else process.env.ANTHROPIC_API_KEY = prevAnthropic;
      if (prevGithub === undefined) delete process.env.GITHUB_TOKEN;
      else process.env.GITHUB_TOKEN = prevGithub;
    }
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
      { lastExitCode: 0, lastHttpStatus: null, aggregatedStdout: "", runDir: "/tmp" },
    );
    expect(r.passed).toBe(false);
    expect(r.actual).toBeNull();
  });

  it("evaluateAssertion handles string_in_output across aggregated stdout", () => {
    const pass = evaluateAssertion(
      { kind: "string_in_output", target: "any", expected: "magic" },
      { lastExitCode: 0, lastHttpStatus: null, aggregatedStdout: "the magic word", runDir: "/tmp" },
    );
    expect(pass.passed).toBe(true);
    const fail = evaluateAssertion(
      { kind: "string_in_output", target: "any", expected: "missing" },
      { lastExitCode: 0, lastHttpStatus: null, aggregatedStdout: "the magic word", runDir: "/tmp" },
    );
    expect(fail.passed).toBe(false);
  });

  it("evaluateAssertion handles file_exists relative to runDir", () => {
    const runDir = mkdtempSync(join(tmpdir(), "0sec-runner-assert-"));
    writeFileSync(join(runDir, "marker"), "x");
    const pass = evaluateAssertion(
      { kind: "file_exists", target: "marker", expected: true },
      { lastExitCode: 0, lastHttpStatus: null, aggregatedStdout: "", runDir },
    );
    expect(pass.passed).toBe(true);
  });
});

describe("sandbox replay runners", () => {
  it("builds a credential-free, hardened, offline Docker invocation", async () => {
    const runDir = mkdtempSync(join(tmpdir(), "0sec-docker-runner-"));
    const docker = writeFakeExecutable(
      runDir,
      "fake-docker",
      String.raw`
printf '%s\n' "$@" > "$PWD/docker.args"
env > "$PWD/docker.env"
if [ "$1" = "run" ]; then
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "--cidfile" ]; then
      shift
      printf '%s\n' 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef > "$1"
      break
    fi
    shift
  done
  printf '%s\n' "SANDBOX_OK"
fi
`,
    );
    const originalKey = process.env.ANTHROPIC_API_KEY;
    process.env.ANTHROPIC_API_KEY = "must-not-reach-docker";
    try {
      const result = await new DockerRunner({ dockerBinary: docker }).exec(
        {
          id: "shell",
          kind: "exploit",
          summary: "print a marker",
          action: { type: "shell", cmd: "echo SANDBOX_OK" },
        },
        { runDir, stepTimeoutMs: 1_000 },
      );
      expect(result.exitCode).toBe(0);
      expect(result.stdoutFull).toContain("SANDBOX_OK");
      const argv = readFileSync(join(runDir, "docker.args"), "utf8").trim().split("\n");
      expect(argv).toEqual(
        expect.arrayContaining([
          "run",
          "--pull",
          "never",
          "--read-only",
          "--cap-drop",
          "ALL",
          "--security-opt",
          "no-new-privileges:true",
          "--network",
          "none",
          "--tmpfs",
          "/tmp:rw,noexec,nosuid,size=64m",
          "alpine:3.20",
          "/bin/sh",
          "-lc",
          "echo SANDBOX_OK",
        ]),
      );
      expect(readFileSync(join(runDir, "docker.env"), "utf8")).not.toContain(
        "must-not-reach-docker",
      );
    } finally {
      if (originalKey === undefined) delete process.env.ANTHROPIC_API_KEY;
      else process.env.ANTHROPIC_API_KEY = originalKey;
    }
  });

  it("replays scoped HTTP actions in a networked Docker sandbox", async () => {
    const runDir = mkdtempSync(join(tmpdir(), "0sec-docker-http-"));
    const docker = writeFakeExecutable(
      runDir,
      "fake-docker",
      String.raw`
printf '%s\n' "$@" > "$PWD/http-docker.args"
if [ "$1" = "run" ]; then
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "--cidfile" ]; then
      shift
      printf '%s\n' 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef > "$1"
      break
    fi
    shift
  done
  printf 'response-body\n__0SEC_HTTP_STATUS__:201\n'
fi
`,
    );
    const finding = makeFinding([
      {
        id: "http",
        kind: "verify",
        summary: "verify the scoped endpoint",
        action: { type: "http", method: "POST", url: "https://api.example.test/check" },
        expect: { type: "http-status", status: 201 },
      },
    ]);
    const { result } = await runDeterministicReplay(finding, {
      runner: new DockerRunner({ dockerBinary: docker, network: "bridge" }),
      runDir,
      scope: ScopePolicy.fromJson({ in_scope: ["api.example.test"] }),
    });
    expect(result.status).toBe("reproduced");
    expect(result.commands[0].stdout_excerpt).toContain("response-body");
    expect(result.assertions[0]).toMatchObject({
      kind: "http_status",
      actual: 201,
      passed: true,
    });
    const argv = readFileSync(join(runDir, "http-docker.args"), "utf8").split("\n");
    expect(argv).toEqual(expect.arrayContaining(["--entrypoint", "curl"]));
  });

  it("refuses networked Docker replay without an engagement scope", async () => {
    const runDir = mkdtempSync(join(tmpdir(), "0sec-docker-scope-"));
    const docker = writeFakeExecutable(runDir, "fake-docker", "touch should-not-run");
    const result = await new DockerRunner({ dockerBinary: docker, network: "bridge" }).exec(
      {
        id: "http",
        kind: "verify",
        summary: "unscoped request",
        action: { type: "http", method: "GET", url: "https://api.example.test/check" },
      },
      { runDir, stepTimeoutMs: 1_000 },
    );
    expect(result.launchError).toMatch(/engagement scope/);
    expect(existsSync(join(runDir, "should-not-run"))).toBe(false);
  });

  it("kills a timed-out Docker container through its cidfile", async () => {
    const runDir = mkdtempSync(join(tmpdir(), "0sec-docker-timeout-"));
    const docker = writeFakeExecutable(
      runDir,
      "fake-docker",
      String.raw`
printf '%s\n' "$1" >> "$PWD/docker.calls"
if [ "$1" = "run" ]; then
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "--cidfile" ]; then
      shift
      printf '%s\n' 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef > "$1"
      break
    fi
    shift
  done
  sleep 5
fi
`,
    );
    const startedAt = Date.now();
    const result = await new DockerRunner({ dockerBinary: docker }).exec(
      {
        id: "slow",
        kind: "exploit",
        summary: "sleep",
        action: { type: "shell", cmd: "sleep 5" },
      },
      { runDir, stepTimeoutMs: 50 },
    );
    expect(Date.now() - startedAt).toBeLessThan(2_000);
    expect(result.timedOut).toBe(true);
    expect(readFileSync(join(runDir, "docker.calls"), "utf8")).toContain("kill");
  });

  it("runs shell PoCs in a configured, offline QEMU guest", async () => {
    const runDir = mkdtempSync(join(tmpdir(), "0sec-qemu-runner-"));
    const kernelImage = join(runDir, "vmlinuz");
    const busybox = join(runDir, "busybox");
    writeFileSync(kernelImage, "synthetic kernel");
    writeFileSync(busybox, "synthetic busybox");
    const qemu = writeFakeExecutable(
      runDir,
      "fake-qemu",
      String.raw`
share=
previous=
for arg in "$@"; do
  if [ "$previous" = "-virtfs" ]; then
    share="$arg"
    break
  fi
  previous="$arg"
done
share=$(printf '%s' "$share" | sed 's/^local,path=//; s/,.*$//')
printf '%s\n' "$@" > "$share/qemu.args"
workspace=
for candidate in "$share"/.0sec-qemu-*; do
  if [ -d "$candidate" ]; then
    workspace="$candidate"
    break
  fi
done
[ -n "$workspace" ] || exit 2
printf '%s\n' "QEMU_GUEST_OK" > "$workspace/stdout.log"
printf '%s\n' "guest stderr" > "$workspace/stderr.log"
printf '%s\n' "0" > "$workspace/exit-code"
printf '%s\n' "serial boot evidence"
`,
    );
    const finding = makeFinding([
      {
        id: "guest",
        kind: "exploit",
        summary: "run inside the guest",
        action: { type: "shell", cmd: "echo QEMU_GUEST_OK" },
        expect: { type: "body-contains", text: "QEMU_GUEST_OK" },
      },
    ]);
    const { result } = await runDeterministicReplay(finding, {
      runner: new QemuRunner({ qemuBinary: qemu, kernelImage, busyboxPath: busybox }),
      runDir,
    });
    expect(result.status).toBe("reproduced");
    expect(result.engine_metadata.runner).toBe("qemu");
    expect(result.commands[0].stderr_excerpt).toContain("serial boot evidence");
    const argv = readFileSync(join(runDir, "qemu.args"), "utf8").split("\n");
    expect(argv).toEqual(expect.arrayContaining(["-net", "none", "-sandbox"]));
  });

  it("reports missing QEMU guest prerequisites as a structured launch error", async () => {
    const result = await new QemuRunner().exec(
      { id: "guest", kind: "exploit", summary: "", action: { type: "shell", cmd: "id" } },
      { runDir: mkdtempSync(join(tmpdir(), "0sec-qemu-unconfigured-")), stepTimeoutMs: 1_000 },
    );
    expect(result.launchError).toMatch(/requires kernelImage and busyboxPath/);
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
      runner: {
        kind: "docker",
        async exec() {
          throw new Error("injected runner failure");
        },
      },
    });
    expect(result.status).toBe("error");
    expect(result.error_reason).toMatch(/injected runner failure/);

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
