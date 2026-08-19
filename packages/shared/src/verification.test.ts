/**
 * 0sec#193 — `VerificationResultSchema` tests.
 *
 * Two contracts to lock in:
 *   1. A valid result round-trips: parse → re-stringify → parse again
 *      produces the same object. This is the cloud-ingest sanity check.
 *   2. Missing required fields are rejected with a clear, locatable Zod
 *      error. A drifting producer (cli, core, cloud) should surface as
 *      a test failure here before it lands on disk.
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  AssertionKindSchema,
  RunnerKindSchema,
  VerificationAssertionSchema,
  VerificationCommandSchema,
  VerificationResultSchema,
  type VerificationResult,
} from "./verification.js";

function validResult(): VerificationResult {
  return {
    status: "reproduced",
    mode: "deterministic_replay",
    finding_id: "finding-abc-1",
    engine_version: "0.11.1",
    started_at: "2026-05-22T12:00:00.000Z",
    completed_at: "2026-05-22T12:00:00.500Z",
    duration_ms: 500,
    commands: [
      {
        argv: ["/bin/sh", "-c", "echo hello"],
        exit_code: 0,
        stdout_excerpt: "hello\n",
        stderr_excerpt: "",
        duration_ms: 12,
      },
    ],
    assertions: [
      {
        kind: "string_in_output",
        target: "step-1",
        expected: "hello",
        actual: "hello",
        passed: true,
      },
    ],
    evidence_artifacts: [
      {
        kind: "stdout",
        path: "artifacts/step-1.stdout-0123456789abcdef",
        sha256: "a".repeat(64),
        bytes: 6,
      },
    ],
    engine_metadata: { os: "darwin", arch: "arm64", runner: "local" },
    error_reason: null,
    summary: "replay reproduced the finding (1/1 steps executed)",
  };
}

describe("VerificationResultSchema", () => {
  it("accepts a fully populated, valid result and round-trips through JSON", () => {
    const result = validResult();
    const parsed = VerificationResultSchema.parse(result);
    expect(parsed).toEqual(result);

    // JSON round-trip — cloud's persistence layer is JSON-typed, so the
    // schema must survive serialise → deserialise without losing fields.
    const roundTripped = VerificationResultSchema.parse(
      JSON.parse(JSON.stringify(result)),
    );
    expect(roundTripped).toEqual(result);
  });

  it("accepts a minimal result without optional fields", () => {
    const minimal: VerificationResult = {
      status: "skipped",
      mode: "deterministic_replay",
      finding_id: "f1",
      engine_version: "0.0.0-dev",
      started_at: "2026-05-22T00:00:00Z",
      completed_at: "2026-05-22T00:00:01Z",
      duration_ms: 0,
      commands: [],
      assertions: [],
      evidence_artifacts: [],
      engine_metadata: { os: "linux", arch: "x64", runner: "docker" },
    };
    expect(() => VerificationResultSchema.parse(minimal)).not.toThrow();
  });

  it("rejects a result with a missing required field and yields a locatable error", () => {
    const { finding_id, ...withoutId } = validResult();
    void finding_id;
    const r = VerificationResultSchema.safeParse(withoutId);
    expect(r.success).toBe(false);
    if (!r.success) {
      // The error must point at the missing field — that's the contract
      // a producer needs to debug a drift.
      const issue = r.error.issues.find((i) => i.path.join(".") === "finding_id");
      expect(issue, "expected finding_id issue").toBeTruthy();
      expect(issue?.code).toBe(z.ZodIssueCode.invalid_type);
    }
  });

  it("rejects an unknown status enum value", () => {
    const bad = { ...validResult(), status: "definitely_not_a_status" };
    expect(() => VerificationResultSchema.parse(bad)).toThrow(z.ZodError);
  });

  it("rejects an evidence artifact with a malformed sha256", () => {
    const bad = {
      ...validResult(),
      evidence_artifacts: [
        {
          kind: "stdout",
          path: "artifacts/x",
          sha256: "deadbeef", // too short
        },
      ],
    };
    expect(() => VerificationResultSchema.parse(bad)).toThrow(z.ZodError);
  });

  it("rejects negative duration_ms", () => {
    expect(() =>
      VerificationResultSchema.parse({ ...validResult(), duration_ms: -1 }),
    ).toThrow(z.ZodError);
  });

  it("exposes the four canonical assertion kinds", () => {
    // Lock in the enum so a future PR that adds a kind has to update both
    // schema and consumers in lockstep.
    expect(AssertionKindSchema.options.sort()).toEqual(
      ["exit_code", "file_exists", "http_status", "string_in_output"].sort(),
    );
  });

  it("exposes the three runner kinds", () => {
    expect(RunnerKindSchema.options.sort()).toEqual(
      ["docker", "local", "qemu"].sort(),
    );
  });

  it("VerificationCommandSchema requires argv to be non-empty", () => {
    expect(() =>
      VerificationCommandSchema.parse({
        argv: [],
        exit_code: 0,
        duration_ms: 1,
      }),
    ).toThrow(z.ZodError);
  });

  it("VerificationAssertionSchema accepts mixed expected/actual scalar shapes", () => {
    expect(() =>
      VerificationAssertionSchema.parse({
        kind: "http_status",
        target: "GET /admin",
        expected: 200,
        actual: 403,
        passed: false,
      }),
    ).not.toThrow();
    expect(() =>
      VerificationAssertionSchema.parse({
        kind: "file_exists",
        target: "/tmp/loot",
        expected: true,
        actual: false,
        passed: false,
      }),
    ).not.toThrow();
  });
});
