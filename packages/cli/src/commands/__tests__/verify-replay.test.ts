/**
 * 0sec#193 — CLI tests for the deterministic-replay path.
 *
 * Separate from the existing `verify.test.ts` (#194) so the two contracts
 * stay legible. Strategy: drive `runDeterministicReplayCli` directly with
 * a temp-file fixture finding, assert on (a) the shared-schema-validated
 * VerificationResult shape and (b) the per-status exit code mapping.
 */

import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { VerificationResultSchema } from "@0sec/shared";
import type { Finding } from "@0sec/shared";
import { runDeterministicReplayCli, parseRunnerKind } from "../verify.js";

let tmpRoot: string;

beforeEach(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), "0sec-verify-replay-test-"));
});

afterEach(() => {
  rmSync(tmpRoot, { recursive: true, force: true });
});

function writeFindingFixture(finding: Finding): string {
  const path = join(tmpRoot, "finding.json");
  writeFileSync(path, JSON.stringify(finding, null, 2));
  return path;
}

function writeFakeExecutable(name: string, body: string): string {
  const path = join(tmpRoot, name);
  writeFileSync(path, `#!/bin/sh\n${body}`, "utf8");
  chmodSync(path, 0o755);
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

describe("runDeterministicReplayCli — sandbox runners", () => {
  it("runs the Docker backend through the CLI contract", async () => {
    const docker = writeFakeExecutable(
      "docker",
      String.raw`
if [ "$1" = "run" ]; then
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "--cidfile" ]; then
      shift
      printf '%s\n' 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef > "$1"
      break
    fi
    shift
  done
  printf '%s\n' "hello"
fi
`,
    );
    const previousPath = process.env.PATH;
    process.env.PATH = `${tmpRoot}:${previousPath ?? ""}`;
    try {
      const findingPath = writeFindingFixture(baseFinding);
      const { result, exitCode } = await runDeterministicReplayCli({
        findingPath,
        runner: "docker",
      });
      expect(exitCode).toBe(0);
      expect(result.status).toBe("reproduced");
      expect(result.engine_metadata.runner).toBe("docker");
      expect(result.commands[0].argv[0]).toBe("docker");
      expect(() => VerificationResultSchema.parse(result)).not.toThrow();
    } finally {
      process.env.PATH = previousPath;
      void docker;
    }
  });

  it("runs the QEMU backend through the CLI contract", async () => {
    const kernelImage = join(tmpRoot, "vmlinuz");
    const busybox = join(tmpRoot, "busybox");
    writeFileSync(kernelImage, "synthetic kernel");
    writeFileSync(busybox, "synthetic busybox");
    const qemu = writeFakeExecutable(
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
workspace=
for candidate in "$share"/.0sec-qemu-*; do
  if [ -d "$candidate" ]; then
    workspace="$candidate"
    break
  fi
done
[ -n "$workspace" ] || exit 2
printf '%s\n' "hello" > "$workspace/stdout.log"
printf '%s\n' "0" > "$workspace/exit-code"
`,
    );
    const findingPath = writeFindingFixture(baseFinding);
    const { result, exitCode } = await runDeterministicReplayCli({
      findingPath,
      runner: "qemu",
      outDir: join(tmpRoot, "qemu-run"),
      qemuBinary: qemu,
      qemuKernel: kernelImage,
      qemuBusybox: busybox,
    });
    expect(exitCode).toBe(0);
    expect(result.status).toBe("reproduced");
    expect(result.engine_metadata.runner).toBe("qemu");
    expect(() => VerificationResultSchema.parse(result)).not.toThrow();
  });
});
