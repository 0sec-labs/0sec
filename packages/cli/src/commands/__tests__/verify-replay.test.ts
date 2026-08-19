/**
 * pwnkit#193 — CLI tests for the deterministic-replay path.
 *
 * Separate from the existing `verify.test.ts` (#194) so the two contracts
 * stay legible. Strategy: drive `runDeterministicReplayCli` directly with
 * a temp-file fixture finding, assert on (a) the shared-schema-validated
 * VerificationResult shape and (b) the per-status exit code mapping.
 */

import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { VerificationResultSchema } from "@pwnkit/shared";
import type { Finding } from "@pwnkit/shared";
import { runDeterministicReplayCli, parseRunnerKind } from "../verify.js";

let tmpRoot: string;

beforeEach(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), "pwnkit-verify-replay-test-"));
});

afterEach(() => {
  rmSync(tmpRoot, { recursive: true, force: true });
});

function writeFindingFixture(finding: Finding): string {
  const path = join(tmpRoot, "finding.json");
  writeFileSync(path, JSON.stringify(finding, null, 2));
  return path;
}

const baseFinding: Finding = {
  id: "finding-193-happy",
  templateId: "tpl-test",
  title: "Deterministic replay happy path",
  description: "Smoke fixture",
  severity: "high",
  category: "command-injection",
  status: "verified",
  evidence: { request: "echo hello", response: "hello" },
  pocSteps: [
    {
      id: "exploit-1",
      kind: "exploit",
      summary: "echo hello",
      action: { type: "shell", cmd: "echo hello && exit 0" },
      expect: { type: "body-contains", text: "hello" },
    },
  ],
  timestamp: 1716393600000,
};

describe("parseRunnerKind", () => {
  it("defaults to local when unset", () => {
    expect(parseRunnerKind(undefined)).toBe("local");
  });
  it("accepts local / docker / qemu", () => {
    expect(parseRunnerKind("local")).toBe("local");
    expect(parseRunnerKind("docker")).toBe("docker");
    expect(parseRunnerKind("qemu")).toBe("qemu");
  });
  it("rejects unknown values", () => {
    expect(() => parseRunnerKind("wasm")).toThrow(/unsupported --runner/);
  });
});

describe("runDeterministicReplayCli — local runner", () => {
  it("happy path: echo hello finding produces status=reproduced + exit 0", async () => {
    const findingPath = writeFindingFixture(baseFinding);
    const { result, exitCode } = await runDeterministicReplayCli({
      findingPath,
      runner: "local",
    });
    expect(exitCode).toBe(0);
    expect(result.status).toBe("reproduced");
    expect(result.mode).toBe("deterministic_replay");
    expect(result.finding_id).toBe(baseFinding.id);
    expect(result.engine_metadata.runner).toBe("local");
    expect(result.commands).toHaveLength(1);
    expect(result.commands[0].exit_code).toBe(0);
    expect(result.commands[0].stdout_excerpt).toContain("hello");
    expect(result.assertions[0].passed).toBe(true);
    // Must survive a strict schema parse — that's the cross-package contract.
    expect(() => VerificationResultSchema.parse(result)).not.toThrow();
  });

  it("returns status=not_reproduced + exit 1 when assertion fails", async () => {
    const finding: Finding = {
      ...baseFinding,
      id: "finding-193-broken",
      pocSteps: [
        {
          id: "exploit-1",
          kind: "exploit",
          summary: "echo something",
          action: { type: "shell", cmd: "echo goodbye" },
          expect: { type: "body-contains", text: "hello" },
        },
      ],
    };
    const findingPath = writeFindingFixture(finding);
    const { result, exitCode } = await runDeterministicReplayCli({
      findingPath,
      runner: "local",
    });
    expect(exitCode).toBe(1);
    expect(result.status).toBe("not_reproduced");
  });

  it("returns status=skipped + exit 2 when finding has no pocSteps", async () => {
    const finding: Finding = { ...baseFinding, id: "no-steps", pocSteps: [] };
    const findingPath = writeFindingFixture(finding);
    const { result, exitCode } = await runDeterministicReplayCli({
      findingPath,
      runner: "local",
    });
    expect(exitCode).toBe(2);
    expect(result.status).toBe("skipped");
  });

  it("--out directs the runner to use the supplied dir", async () => {
    const outDir = join(tmpRoot, "custom-run-dir");
    const findingPath = writeFindingFixture(baseFinding);
    const { result } = await runDeterministicReplayCli({
      findingPath,
      runner: "local",
      outDir,
    });
    expect(result.status).toBe("reproduced");
    expect(result.evidence_artifacts.length).toBeGreaterThan(0);
  });

  it("rejects a malformed finding JSON with a Zod-flavoured error", async () => {
    const path = join(tmpRoot, "bad.json");
    writeFileSync(path, JSON.stringify({ totally: "not a finding" }));
    await expect(
      runDeterministicReplayCli({ findingPath: path, runner: "local" }),
    ).rejects.toThrow(/finding JSON/);
  });
});

describe("runDeterministicReplayCli — docker / qemu stubs", () => {
  it("docker runner returns exit 4 + NotImplemented error_reason without consuming the finding", async () => {
    const findingPath = writeFindingFixture(baseFinding);
    const { result, exitCode } = await runDeterministicReplayCli({
      findingPath,
      runner: "docker",
    });
    expect(exitCode).toBe(4);
    expect(result.status).toBe("error");
    expect(result.engine_metadata.runner).toBe("docker");
    expect(result.error_reason).toMatch(/not implemented/i);
    // Result is still schema-valid — cloud ingest must be able to parse it.
    expect(() => VerificationResultSchema.parse(result)).not.toThrow();
  });

  it("qemu runner returns exit 4 + NotImplemented error_reason", async () => {
    const findingPath = writeFindingFixture(baseFinding);
    const { result, exitCode } = await runDeterministicReplayCli({
      findingPath,
      runner: "qemu",
    });
    expect(exitCode).toBe(4);
    expect(result.status).toBe("error");
    expect(result.engine_metadata.runner).toBe("qemu");
    expect(result.error_reason).toMatch(/not implemented/i);
  });
});
