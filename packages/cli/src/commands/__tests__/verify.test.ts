/**
 * pwnkit#194 — `pwnkit verify` CLI tests.
 *
 * Strategy: drive `runVerify` directly (the same entry point the commander
 * action uses) and assert on (a) the resolved {@link VerificationResult}
 * object and (b) the exit code resolver. We do NOT spawn a subprocess —
 * the runtime's deps (spawn/fetch) are stubbed via `setRuntimeDeps`, so
 * tests run hermetically.
 *
 * The runtime itself has its own coverage in
 * `packages/core/src/disclose/poc-runtime.test.ts`; here we only verify the
 * CLI's argument handling, exit-code mapping, and JSON shape.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync, mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { Command } from "commander";
import { setRuntimeDeps } from "@pwnkit/core";
import {
  VerificationResultSchema,
  type Finding,
  type LayerVerdict,
  type PocStep,
  type VerificationResult,
} from "@pwnkit/shared";
import {
  runVerify,
  registerVerifyCommand,
  exitCodeForStatus,
  statusFromVerdict,
  buildVerificationResult,
  buildNoStepsResult,
  buildErrorResult,
  parseDurationMs,
  findingOastConfirmed,
  oastEvidenceFields,
} from "../verify.js";

// ── Test fixture helpers ────────────────────────────────────────────────────

let tmpRoot: string;

beforeEach(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), "pwnkit-verify-test-"));
});

afterEach(() => {
  rmSync(tmpRoot, { recursive: true, force: true });
});

function makeFinding(pocSteps?: PocStep[]): Finding {
  const f: Finding = {
    id: "finding-cafe1234",
    templateId: "tpl-test",
    title: "Test finding",
    description: "Synthetic finding for verify CLI tests",
    severity: "high",
    category: "command-injection",
    status: "discovered",
    evidence: { request: "GET /", response: "200 OK" },
    timestamp: 1714521600000,
  };
  if (pocSteps) f.pocSteps = pocSteps;
  return f;
}

function writeFinding(finding: Finding): string {
  const path = join(tmpRoot, "finding.json");
  writeFileSync(path, JSON.stringify(finding, null, 2), "utf8");
  return path;
}

function writeTestExportCli(): string {
  const path = join(tmpRoot, "test-export-cli.mjs");
  writeFileSync(
    path,
    `#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) out[argv[i].slice(2)] = argv[i + 1];
  return out;
}
function isInside(root, candidate) {
  return candidate === root || candidate.startsWith(root + sep);
}

const args = parseArgs(process.argv.slice(2));
const body = await fetch(new URL("/company/export", args.api)).then((r) => r.json());
const root = resolve(args.output);
await mkdir(root, { recursive: true });
let blocked = false;
for (const [name, content] of Object.entries(body.files || {})) {
  const destination = resolve(root, name);
  if (args.mode === "patched" && !isInside(root, destination)) {
    console.error("blocked path traversal: " + name);
    blocked = true;
    continue;
  }
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(destination, String(content), "utf8");
  console.log("wrote " + destination);
}
if (blocked) process.exitCode = 1;
`,
    { encoding: "utf8", mode: 0o755 },
  );
  return path;
}

function testExportCliArgv(): string[] {
  return [
    process.execPath,
    writeTestExportCli(),
    "--api",
    "{{apiUrl}}",
    "--output",
    "{{exportDir}}",
    "--mode",
    "{{fixtureMode}}",
  ];
}

// ── Fake spawn helper ───────────────────────────────────────────────────────

class FakeChild extends EventEmitter {
  stdout = new EventEmitter();
  stderr = new EventEmitter();
  kill() {
    setImmediate(() => this.emit("close", null));
    return true;
  }
}

interface FakeShellSpec {
  exitCode: number;
  stdout?: string;
  stderr?: string;
}

/** Build a spawn fake that maps the shell command (the body passed to
 *  `/bin/sh -c <body>`) to a scripted exit code / stdout. Anything
 *  unmatched returns exit 0 with no captured output. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- spawn shim is loose by design
function fakeSpawnFromMap(map: Record<string, FakeShellSpec>): any {
  return (cmd: string, args: string[]) => {
    const child = new FakeChild();
    // The runtime invokes `/bin/sh` as `spawn("/bin/sh", ["-c", cmd], ...)` —
    // so the script body is at `args[1]`. Map lookup is keyed on that body.
    const sh = args[0] === "-c" && args.length >= 2 ? args[1] : args.join(" ");
    const spec = map[sh] ?? { exitCode: 0 };
    setImmediate(() => {
      if (spec.stdout) child.stdout.emit("data", Buffer.from(spec.stdout, "utf8"));
      if (spec.stderr) child.stderr.emit("data", Buffer.from(spec.stderr, "utf8"));
      child.emit("close", spec.exitCode);
    });
    void cmd;
    return child;
  };
}

// ── Pure helper tests ───────────────────────────────────────────────────────

describe("verify pure helpers", () => {
  it("statusFromVerdict maps the three runtime verdicts", () => {
    expect(statusFromVerdict("exploit_still_works")).toBe("reproduced");
    expect(statusFromVerdict("exploit_broken")).toBe("not_reproduced");
    expect(statusFromVerdict("could_not_run")).toBe("skipped");
  });

  it("exitCodeForStatus follows pwnkit#194 spec", () => {
    expect(exitCodeForStatus("reproduced")).toBe(0);
    expect(exitCodeForStatus("not_reproduced")).toBe(1);
    expect(exitCodeForStatus("skipped")).toBe(2);
    expect(exitCodeForStatus("error")).toBe(3);
  });

  it("buildNoStepsResult returns skipped with the canonical summary", () => {
    const finding = makeFinding();
    const result = buildNoStepsResult({
      finding,
      startedAt: "2026-05-01T00:00:00.000Z",
      completedAt: "2026-05-01T00:00:00.001Z",
    });
    expect(result.status).toBe("skipped");
    expect(result.summary).toBe("No PoC steps to execute");
    expect(VerificationResultSchema.parse(result)).toEqual(result);
  });

  it("buildErrorResult preserves the error message in error_reason", () => {
    const result = buildErrorResult({
      finding: null,
      startedAt: "2026-05-01T00:00:00.000Z",
      completedAt: "2026-05-01T00:00:00.001Z",
      error: new Error("kaboom"),
    });
    expect(result.status).toBe("error");
    expect(result.error_reason).toBe("kaboom");
    expect(result.finding_id).toBe("unknown");
    expect(VerificationResultSchema.parse(result)).toEqual(result);
  });

  it("buildVerificationResult records assertions only for steps with predicates", () => {
    const finding = makeFinding([
      {
        id: "s1",
        kind: "exploit",
        summary: "exploit",
        action: { type: "shell", cmd: "echo hi" },
        expect: { type: "exit-zero" },
      },
      {
        id: "s2",
        kind: "setup",
        summary: "setup with no predicate",
        action: { type: "shell", cmd: "true" },
      },
    ]);
    const result = buildVerificationResult({
      finding,
      report: {
        findingId: finding.id,
        startedAt: "2026-05-01T00:00:00.000Z",
        endedAt: "2026-05-01T00:00:00.005Z",
        steps: [
          { stepId: "s1", kind: "passed", durationMs: 1, observedExit: 0, observedStdout: "hi" },
          { stepId: "s2", kind: "passed", durationMs: 1, observedExit: 0, observedStdout: "" },
        ],
        overallVerdict: "exploit_still_works",
      },
      startedAt: "2026-05-01T00:00:00.000Z",
      completedAt: "2026-05-01T00:00:00.005Z",
    });
    expect(result.assertions.length).toBe(1);
    expect(result.assertions[0].kind).toBe("exit_code");
    expect(result.assertions[0].passed).toBe(true);
    expect(VerificationResultSchema.parse(result)).toEqual(result);
  });
});

// ── OAST out-of-band evidence provenance (pwnkit#659 / #1278) ────────────────
//
// The deterministic replay can't re-fire an out-of-band callback, so an OAST
// proof is scan-time provenance carried on the finding. These lock the two
// recognition paths (explicit flag + pov_oracle bucketing) and the additive
// VerificationResult fields the 0cloud verify writeback (#1302) reads.
describe("OAST evidence provenance", () => {
  // command-injection (makeFinding's default) maps to the oast-callback oracle.
  // Typed as LayerVerdict so `layer` narrows to TriageLayerName (not widened to
  // string) — pwnkit main tightened LayerVerdict.layer to the closed enum.
  const passLayerVerdict: LayerVerdict = {
    layer: "pov_gate",
    verdict: "pass" as const,
    reason: "pov_verified(curl): oast callback",
    durationMs: 5,
    costUsd: 0,
  };

  it("findingOastConfirmed: honours an explicit oastConfirmed flag", () => {
    const f = makeFinding();
    (f as { oastConfirmed?: boolean }).oastConfirmed = true;
    expect(findingOastConfirmed(f)).toBe(true);
  });

  it("findingOastConfirmed: true for an oast-category finding with a PoV pass", () => {
    const f = makeFinding();
    f.layerVerdicts = [passLayerVerdict];
    expect(findingOastConfirmed(f)).toBe(true);
  });

  it("findingOastConfirmed: never fires on category alone (no PoV pass)", () => {
    // command-injection, but no pov_gate/oracle pass → not proven out-of-band.
    expect(findingOastConfirmed(makeFinding())).toBe(false);
    const rejected = makeFinding();
    rejected.layerVerdicts = [{ ...passLayerVerdict, verdict: "reject" as const }];
    expect(findingOastConfirmed(rejected)).toBe(false);
  });

  it("findingOastConfirmed: false for a non-oast category even with a PoV pass", () => {
    const f = makeFinding();
    f.category = "sql-injection"; // regex-fallback oracle, not oast-callback
    f.layerVerdicts = [passLayerVerdict];
    expect(findingOastConfirmed(f)).toBe(false);
  });

  it("oastEvidenceFields: folds an OAST hit to reproduced-poc + oast_confirmed", () => {
    const f = makeFinding();
    f.layerVerdicts = [passLayerVerdict];
    expect(oastEvidenceFields(f)).toEqual({
      evidence_kind: "reproduced-poc",
      oast_confirmed: true,
    });
  });

  it("oastEvidenceFields: emits nothing for a source-only finding (no downgrade)", () => {
    // No OAST, no reproduced provenance → both fields omitted so the consumer
    // keeps its own status-based default (a reproduced replay stays reproduced).
    expect(oastEvidenceFields(makeFinding())).toEqual({});
  });

  it("buildVerificationResult stamps the OAST provenance even when the replay did NOT reproduce", () => {
    // The blind-only case: the in-band replay says not_reproduced, but the
    // scan-time OAST callback proved it. #1302's mapPwnkitResult reads
    // oast_confirmed BEFORE the status switch and promotes it.
    const finding = makeFinding([
      {
        id: "s1",
        kind: "exploit",
        summary: "inject oast payload",
        action: { type: "http", method: "GET", url: "http://t/?u=http://x.oast.0sec.ai" },
        expect: { type: "http-status", status: 200 },
      },
    ]);
    finding.layerVerdicts = [passLayerVerdict];
    const result = buildVerificationResult({
      finding,
      report: {
        findingId: finding.id,
        startedAt: "2026-05-01T00:00:00.000Z",
        endedAt: "2026-05-01T00:00:00.005Z",
        steps: [
          { stepId: "s1", kind: "failed", durationMs: 1, observedStatus: 500, observedResponseBody: "" },
        ],
        overallVerdict: "exploit_broken",
      },
      startedAt: "2026-05-01T00:00:00.000Z",
      completedAt: "2026-05-01T00:00:00.005Z",
    });
    expect(result.status).toBe("not_reproduced");
    expect(result.evidence_kind).toBe("reproduced-poc");
    expect(result.oast_confirmed).toBe(true);
    // Round-trips through the shared schema (the field #1302 reads off the wire).
    expect(VerificationResultSchema.parse(result)).toEqual(result);
  });

  it("buildVerificationResult leaves the fields undefined for a non-OAST finding (behavior-preserving)", () => {
    const finding = makeFinding([
      {
        id: "s1",
        kind: "exploit",
        summary: "exploit",
        action: { type: "shell", cmd: "echo hi" },
        expect: { type: "exit-zero" },
      },
    ]);
    const result = buildVerificationResult({
      finding,
      report: {
        findingId: finding.id,
        startedAt: "2026-05-01T00:00:00.000Z",
        endedAt: "2026-05-01T00:00:00.005Z",
        steps: [{ stepId: "s1", kind: "passed", durationMs: 1, observedExit: 0, observedStdout: "hi" }],
        overallVerdict: "exploit_still_works",
      },
      startedAt: "2026-05-01T00:00:00.000Z",
      completedAt: "2026-05-01T00:00:00.005Z",
    });
    expect(result.status).toBe("reproduced");
    expect(result.evidence_kind).toBeUndefined();
    expect(result.oast_confirmed).toBeUndefined();
  });

  it("buildNoStepsResult carries the OAST proof for a finding with no runnable pocSteps", () => {
    const finding = makeFinding();
    finding.layerVerdicts = [passLayerVerdict];
    const result = buildNoStepsResult({
      finding,
      startedAt: "2026-05-01T00:00:00.000Z",
      completedAt: "2026-05-01T00:00:00.001Z",
    });
    expect(result.status).toBe("skipped");
    expect(result.evidence_kind).toBe("reproduced-poc");
    expect(result.oast_confirmed).toBe(true);
    expect(VerificationResultSchema.parse(result)).toEqual(result);
  });
});

// ── runVerify (integration) tests ───────────────────────────────────────────

describe("runVerify", () => {
  let restore: (() => void) | undefined;
  afterEach(() => {
    if (restore) {
      restore();
      restore = undefined;
    }
  });

  it("happy path — in-scope HTTP proof passes → exit 0, status=reproduced", async () => {
    const finding = makeFinding([
      {
        id: "s1",
        kind: "exploit",
        summary: "exploit",
        action: { type: "http", method: "GET", url: "/" },
        expect: { type: "http-status", status: 200 },
      },
      {
        id: "s2",
        kind: "verify",
        summary: "verify",
        action: { type: "http", method: "GET", url: "/verify" },
        expect: { type: "http-status", status: 200 },
      },
    ]);
    restore = setRuntimeDeps({
      fetch: async () => new Response("verified", { status: 200 }),
    });
    const targetPath = join(tmpRoot, "target.json");
    writeFileSync(targetPath, JSON.stringify({ baseUrl: "https://example.com", scopeAllowlist: ["example.com"] }), "utf8");
    const outcome = await runVerify({ findingPath: writeFinding(finding), targetPath });
    expect(outcome.exitCode).toBe(0);
    expect(outcome.result.status).toBe("reproduced");
    expect(outcome.result.finding_id).toBe(finding.id);
    expect(outcome.result.commands).toHaveLength(2);
    expect(outcome.result.commands[0].argv).toEqual(["GET", "/"]);
    expect(outcome.result.commands[0].exit_code).toBe(200);
    expect(outcome.result.commands[0].stdout_excerpt).toContain("verified");
    expect(outcome.result.assertions.every((assertion) => assertion.passed)).toBe(true);
    expect(VerificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("negative path — an HTTP verify step fails → exit 1, status=not_reproduced", async () => {
    const finding = makeFinding([
      {
        id: "s1",
        kind: "verify",
        summary: "verify",
        action: { type: "http", method: "GET", url: "/" },
        expect: { type: "http-status", status: 200 },
      },
    ]);
    restore = setRuntimeDeps({
      fetch: async () => new Response("blocked", { status: 403 }),
    });
    const targetPath = join(tmpRoot, "target.json");
    writeFileSync(targetPath, JSON.stringify({ baseUrl: "https://example.com", scopeAllowlist: ["example.com"] }), "utf8");
    const outcome = await runVerify({ findingPath: writeFinding(finding), targetPath });
    expect(outcome.exitCode).toBe(1);
    expect(outcome.result.status).toBe("not_reproduced");
    expect(outcome.result.assertions).toHaveLength(1);
    expect(outcome.result.assertions[0].passed).toBe(false);
    expect(outcome.result.commands[0].exit_code).toBe(403);
    expect(VerificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("no pocSteps → exit 2, status=skipped, canonical summary", async () => {
    const finding = makeFinding();
    const findingPath = writeFinding(finding);
    const outcome = await runVerify({ findingPath });
    expect(outcome.exitCode).toBe(2);
    expect(outcome.result.status).toBe("skipped");
    expect(outcome.result.summary).toBe("No PoC steps to execute");
    expect(outcome.result.commands.length).toBe(0);
    expect(outcome.result.assertions.length).toBe(0);
    expect(VerificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("missing finding file → exit 3, status=error, error_reason populated", async () => {
    const outcome = await runVerify({ findingPath: "/nonexistent/finding.json" });
    expect(outcome.exitCode).toBe(3);
    expect(outcome.result.status).toBe("error");
    expect(outcome.result.error_reason).toBeTruthy();
    expect(outcome.result.error_reason).toMatch(/finding/);
    expect(VerificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("malformed finding JSON → exit 3, status=error", async () => {
    const path = join(tmpRoot, "bad.json");
    writeFileSync(path, "{not valid json", "utf8");
    const outcome = await runVerify({ findingPath: path });
    expect(outcome.exitCode).toBe(3);
    expect(outcome.result.status).toBe("error");
    expect(outcome.result.error_reason).toMatch(/parse/i);
  });

  it("writes a JSON file that round-trips through the zod schema", async () => {
    const finding = makeFinding([
      {
        id: "s1",
        kind: "verify",
        summary: "verify",
        action: { type: "shell", cmd: "true" },
        expect: { type: "exit-zero" },
      },
    ]);
    restore = setRuntimeDeps({
      spawn: fakeSpawnFromMap({ true: { exitCode: 0 } }),
    });
    const findingPath = writeFinding(finding);
    const outcome = await runVerify({ findingPath });
    const outPath = join(tmpRoot, "result.json");
    writeFileSync(outPath, JSON.stringify(outcome.result, null, 2), "utf8");
    const parsed: VerificationResult = JSON.parse(readFileSync(outPath, "utf8"));
    expect(VerificationResultSchema.parse(parsed)).toEqual(parsed);
  });

  it("runs the built-in cli-path-traversal fixture and reports reproduced", async () => {
    const outcome = await runVerify({
      fixture: "cli-path-traversal",
      fixtureCommand: testExportCliArgv(),
      fixtureMode: "vulnerable",
    });

    expect(outcome.exitCode).toBe(0);
    expect(outcome.result.status).toBe("reproduced");
    expect(outcome.result.finding_id).toBe("fixture:cli-path-traversal");
    expect(outcome.result.commands).toHaveLength(1);
    expect(outcome.result.assertions.some((a) => a.kind === "file_exists" && a.passed)).toBe(true);
    expect(outcome.result.assertions.some((a) => a.kind === "string_in_output" && a.passed)).toBe(true);
    expect(VerificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("runs the patched cli-path-traversal fixture as the negative control", async () => {
    const outcome = await runVerify({
      fixture: "cli-path-traversal",
      fixtureCommand: testExportCliArgv(),
      fixtureMode: "patched",
    });

    expect(outcome.exitCode).toBe(1);
    expect(outcome.result.status).toBe("not_reproduced");
    expect(outcome.result.commands[0].stderr_excerpt).toContain("blocked path traversal");
    expect(outcome.result.assertions.some((a) => a.kind === "file_exists" && !a.passed)).toBe(true);
    expect(VerificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("retains fixture artifacts when requested", async () => {
    const artifactDir = join(tmpRoot, "retained-fixture");
    const outcome = await runVerify({
      fixture: "cli-path-traversal",
      fixtureCommand: testExportCliArgv(),
      retainArtifacts: true,
      artifactDir,
    });

    expect(outcome.exitCode).toBe(0);
    const artifactPaths = outcome.result.evidence_artifacts.map((artifact) => artifact.path);
    expect(outcome.result.evidence_artifacts.map((artifact) => artifact.kind)).toEqual(
      expect.arrayContaining(["harness", "stdout", "stderr"]),
    );
    expect(artifactPaths.some((path) => path.startsWith(artifactDir))).toBe(true);
    expect(artifactPaths.every((path) => existsSync(path))).toBe(true);
    expect(VerificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("requires --fixture-command when --fixture is set", async () => {
    const outcome = await runVerify({
      fixture: "cli-path-traversal",
    });

    expect(outcome.exitCode).toBe(3);
    expect(outcome.result.status).toBe("error");
    expect(outcome.result.error_reason).toBe("--fixture-command is required with --fixture");
    expect(VerificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("rejects --fixture-mode when --fixture is not set", async () => {
    const findingPath = writeFinding(makeFinding());
    const outcome = await runVerify({
      findingPath,
      fixtureMode: "patched",
    });

    expect(outcome.exitCode).toBe(3);
    expect(outcome.result.status).toBe("error");
    expect(outcome.result.error_reason).toBe("--fixture-mode is only supported with --fixture");
    expect(VerificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("reserved --bundle path emits the shared VerificationResult error shape", async () => {
    const previousExitCode = process.exitCode;
    const outPath = join(tmpRoot, "bundle-error.json");
    const program = new Command();
    program.exitOverride();
    registerVerifyCommand(program);

    try {
      await program.parseAsync(
        ["verify", "--bundle", "bundle.zip", "--finding-id", "finding-1", "--output", outPath],
        { from: "user" },
      );
      expect(process.exitCode).toBe(3);
      const parsed = VerificationResultSchema.parse(
        JSON.parse(readFileSync(outPath, "utf8")),
      );
      expect(parsed.status).toBe("error");
      expect(parsed.finding_id).toBe("unknown");
      expect(parsed.error_reason).toMatch(/reserved for a follow-up/);
    } finally {
      process.exitCode = previousExitCode;
    }
  });
});

// ── Public process-action containment ────────────────────────────────────────

describe("runVerify process-action containment", () => {
  let restore: (() => void) | undefined;

  afterEach(() => {
    restore?.();
    restore = undefined;
  });

  function shellFinding() {
    return makeFinding([
      {
        id: "s1",
        kind: "verify",
        summary: "verify",
        action: { type: "shell", cmd: "echo should-not-run" },
        expect: { type: "exit-zero" },
      },
    ]);
  }

  it("does not spawn a persisted shell PoC without a target file", async () => {
    const calls: string[] = [];
    restore = setRuntimeDeps({
      spawn: ((cmd: string) => {
        calls.push(cmd);
        return new FakeChild();
      }) as never,
    });

    await runVerify({ findingPath: writeFinding(shellFinding()) });

    expect(calls).toEqual([]);
  });

  it("does not let a target file re-enable persisted shell execution", async () => {
    const callerCwd = mkdtempSync(join(tmpdir(), "pwnkit-verify-caller-"));
    try {
      const calls: string[] = [];
      restore = setRuntimeDeps({
        spawn: ((cmd: string) => {
          calls.push(cmd);
          return new FakeChild();
        }) as never,
      });
      const targetPath = join(tmpRoot, "target.json");
      writeFileSync(targetPath, JSON.stringify({ cwd: callerCwd, allowProcessActions: true }), "utf8");

      await runVerify({ findingPath: writeFinding(shellFinding()), targetPath });

      expect(calls).toEqual([]);
    } finally {
      rmSync(callerCwd, { recursive: true, force: true });
    }
  });
});

// ── process.exit / exitCode tests (CodeRabbit #194 — flush stdout) ──────────
//
// We can't easily import `verifyAction` directly (it's not exported), so we
// validate the property by introspection of the verify.ts source: the
// invariant is that the file must not contain `process.exit(` calls. This
// is mechanical but it's exactly what CodeRabbit flagged — `process.exit`
// can truncate pending stdout writes; we use `process.exitCode` instead.

describe("verify.ts uses process.exitCode (no process.exit in the action)", () => {
  it("source file does not call process.exit() (uses process.exitCode instead)", () => {
    // Resolve verify.ts relative to this test file.
    const verifySrc = readFileSync(
      join(__dirname, "..", "verify.ts"),
      "utf8",
    );
    // Strip block + line comments so commentary mentioning `process.exit`
    // doesn't trip the assertion.
    const stripped = verifySrc
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
    expect(stripped).not.toMatch(/\bprocess\.exit\s*\(/);
    // And it *should* be using process.exitCode at least once (the
    // success/error paths each set it).
    expect(stripped).toMatch(/\bprocess\.exitCode\s*=/);
  });
});

describe("parseDurationMs (pwnkit#271)", () => {
  it("parses bare integers as milliseconds", () => {
    expect(parseDurationMs("1500")).toBe(1500);
  });
  it("parses second / minute / hour suffixes", () => {
    expect(parseDurationMs("90s")).toBe(90 * 1000);
    expect(parseDurationMs("5m")).toBe(5 * 60 * 1000);
    expect(parseDurationMs("2h")).toBe(2 * 60 * 60 * 1000);
  });
  it("supports fractional values", () => {
    expect(parseDurationMs("0.5h")).toBe(30 * 60 * 1000);
  });
  it("throws on garbage", () => {
    expect(() => parseDurationMs("twelve")).toThrow();
    expect(() => parseDurationMs("")).toThrow();
    expect(() => parseDurationMs("10z")).toThrow();
  });
});
