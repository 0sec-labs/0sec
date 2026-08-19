/**
 * #151 — Deterministic tests for the reproducibility manifest.
 *
 * Covers:
 *   • Deterministic output for a known timestamp + input
 *   • Rejection of non-verified findings
 *   • Rejection of findings with incomplete evidence (no PoC exec, no layer verdicts)
 *   • Redaction-before-hash invariance
 *   • Evidence hash computation after redaction
 *   • Render output contains all sections
 */

import { describe, it, expect } from "vitest";
import type {
  Finding,
  PocStep,
  LayerVerdict,
  Evidence,
  VerificationResult,
} from "@pwnkit/shared";
import {
  assembleReproducibilityManifest,
  renderReproducibilityManifest,
  UnverifiedFindingError,
  IncompleteEvidenceError,
} from "./reproducibility-manifest.js";

// ── Fixtures ────────────────────────────────────────────────────────────────

const FIXED_TIMESTAMP = "2026-08-02T12:00:00.000Z";
const FIXED_TOOL_VERSION = "pwnkit/0.1.0";

function layerVerdicts(overrides: Partial<LayerVerdict>[] = []): LayerVerdict[] {
  return [
    {
      layer: "oracle" as const,
      verdict: "pass" as const,
      reason: "PoC oracle confirms reachability",
      durationMs: 42,
      costUsd: 0,
      ...(overrides[0] ?? {}),
    },
    {
      layer: "skeptic" as const,
      verdict: "pass" as const,
      reason: "Skeptic could not refute",
      durationMs: 120,
      costUsd: 0,
      ...(overrides[1] ?? {}),
    },
  ];
}

function pocSteps(): PocStep[] {
  return [
    {
      id: "exploit",
      kind: "exploit",
      summary: "SQL injection in GET /api/reports",
      action: {
        type: "shell" as const,
        cmd: "curl -X GET 'https://target.example/api/reports?date=2024-01-01' -H 'Authorization: Bearer secret-bearer-token'",
      },
    },
  ];
}

function evidence(): Evidence {
  return {
    request: "GET /api/reports?date=2024-01-01 HTTP/1.1\nAuthorization: Bearer secret-bearer-token\nHost: target.example",
    response: "HTTP/1.1 200 OK\nSet-Cookie: session=deadbeef\nContent-Type: application/json\n\n[{\"id\":1,\"ssn\":\"redacted\"}]",
  };
}

function verifiedFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f-verify-001",
    templateId: "tpl-sqli",
    title: "SQL injection in /api/reports",
    description: "Time-based SQL injection via the date parameter",
    severity: "critical",
    category: "sqli",
    status: "verified",
    evidence: evidence(),
    pocSteps: pocSteps(),
    pocExecution: {
      findingId: "f-verify-001",
      startedAt: "2026-08-02T11:00:00.000Z",
      endedAt: "2026-08-02T11:00:05.000Z",
      steps: [
        {
          stepId: "exploit",
          kind: "passed" as const,
          durationMs: 3200,
          observedExit: 0,
          observedStdout: "200 OK",
        },
      ],
      overallVerdict: "exploit_still_works" as const,
    },
    layerVerdicts: layerVerdicts(),
    ...overrides,
  };
}


function verificationResult(
  overrides: Partial<VerificationResult> = {},
): VerificationResult {
  return {
    status: "reproduced",
    mode: "deterministic_replay",
    finding_id: "f-verify-001",
    engine_version: "pwnkit/0.1.0",
    started_at: FIXED_TIMESTAMP,
    completed_at: FIXED_TIMESTAMP,
    duration_ms: 1,
    commands: [],
    assertions: [],
    evidence_artifacts: [],
    engine_metadata: { os: "linux", arch: "x64", runner: "local" },
    ...overrides,
  };
}

const TARGET_IDENTIFIER = "https://target.example";

// ── assembleReproducibilityManifest ─────────────────────────────────────────

describe("assembleReproducibilityManifest", () => {
  it("produces a deterministic manifest for a known timestamp + input", () => {
    const manifest = assembleReproducibilityManifest(verifiedFinding(), {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });

    expect(manifest.manifestVersion).toBe(1);
    expect(manifest.generatedAt).toBe(FIXED_TIMESTAMP);
    expect(manifest.findingId).toBe("f-verify-001");
    expect(manifest.findingTitle).toBe("SQL injection in /api/reports");
    expect(manifest.findingSeverity).toBe("critical");
    expect(manifest.findingCategory).toBe("sqli");
    expect(manifest.findingStatus).toBe("verified");
    expect(manifest.targetIdentifier).toBe(TARGET_IDENTIFIER);
    expect(manifest.toolVersion).toBe(FIXED_TOOL_VERSION);
    expect(manifest.harnessRevision).toBeTruthy();
    expect(typeof manifest.harnessRevision).toBe("string");
    expect(manifest.harnessRevision!.length).toBe(64); // SHA-256 hex

    // Environment fingerprint is populated from process (not stubbed — this
    // test runs on the CI machine, so values are dynamic but present).
    expect(manifest.environmentFingerprint.platform).toBeTruthy();
    expect(manifest.environmentFingerprint.arch).toBeTruthy();
    expect(manifest.environmentFingerprint.nodeVersion).toBeTruthy();

    // Evidence hashes are deterministic: same input → same hex digest.
    expect(manifest.evidenceHashes.requestHash).toBeTruthy();
    expect(manifest.evidenceHashes.requestHash!.length).toBe(64);
    expect(manifest.evidenceHashes.responseHash).toBeTruthy();
    expect(manifest.evidenceHashes.responseHash!.length).toBe(64);

    // Verification section populated from the fixture.
    expect(manifest.verification.pocVerdict).toBe("exploit_still_works");
    expect(manifest.verification.layerVerdictCount).toBe(2);
    expect(manifest.verification.passedLayerCount).toBe(2);
    expect(manifest.verification.verifiedAt).toBe("2026-08-02T11:00:00.000Z");
    expect(manifest.verification.replayVerdict).toBeNull();
  });


  it("changes the harness revision when a nested PoC action changes", () => {
    const original = assembleReproducibilityManifest(verifiedFinding(), {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
    });
    const changed = assembleReproducibilityManifest(
      verifiedFinding({
        pocSteps: [
          {
            ...pocSteps()[0],
            action: {
              type: "shell",
              cmd: "curl https://target.example/api/reports?date=2024-02-01",
            },
          },
        ],
      }),
      { timestamp: FIXED_TIMESTAMP, toolVersion: FIXED_TOOL_VERSION },
    );

    expect(changed.harnessRevision).not.toBe(original.harnessRevision);
  });


  it("redacts secrets in an explicit target override", () => {
    const manifest = assembleReproducibilityManifest(verifiedFinding(), {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: "https://target.example/?token=secret-bearer-token",
    });

    expect(manifest.targetIdentifier).not.toContain("secret-bearer-token");
  });

  it("produces the same manifest on repeated calls (determinism)", () => {
    const finding = verifiedFinding();
    const a = assembleReproducibilityManifest(finding, {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });
    const b = assembleReproducibilityManifest(finding, {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });

    expect(a).toEqual(b);
  });

  it("redacts evidence content before hashing", () => {
    // The fixture has "Bearer secret-bearer-token" in the request evidence.
    // The resulting request hash MUST be computed from the REDACTED content,
    // not the raw content (otherwise the hash would leak secret existence).
    const manifest = assembleReproducibilityManifest(verifiedFinding(), {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });

    // The hash should be a 64-char hex string — can't reverse to secrets.
    expect(manifest.evidenceHashes.requestHash).toMatch(/^[a-f0-9]{64}$/);

    // Redactions applied should include both core sweeps plus the
    // all-field redaction and userinfo stripping.
    expect(manifest.redactionsApplied).toContain("redact-sensitive-headers");
    expect(manifest.redactionsApplied).toContain("redact-pii");
    expect(manifest.redactionsApplied).toContain("redact-all-text-fields");
    expect(manifest.redactionsApplied).toContain("strip-url-userinfo");
  });

  it("does not include raw secret content in any manifest field", () => {
    const manifest = assembleReproducibilityManifest(verifiedFinding(), {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });

    // Check that raw strings are not present.
    const json = JSON.stringify(manifest);
    expect(json).not.toContain("secret-bearer-token");
    expect(json).not.toContain("deadbeef");
  });

  it("refuses a non-verified finding with UnverifiedFindingError", () => {
    const finding = verifiedFinding({ status: "discovered" });
    expect(() =>
      assembleReproducibilityManifest(finding, {
        timestamp: FIXED_TIMESTAMP,
        toolVersion: FIXED_TOOL_VERSION,
      }),
    ).toThrow(UnverifiedFindingError);
  });

  it("refuses a false-positive finding with UnverifiedFindingError", () => {
    const finding = verifiedFinding({ status: "false-positive" });
    expect(() =>
      assembleReproducibilityManifest(finding, {
        timestamp: FIXED_TIMESTAMP,
        toolVersion: FIXED_TOOL_VERSION,
      }),
    ).toThrow(UnverifiedFindingError);
  });

  it("refuses a finding with no PoC execution and no layer verdicts", () => {
    const finding = verifiedFinding({
      pocExecution: undefined,
      layerVerdicts: [],
    });
    expect(() =>
      assembleReproducibilityManifest(finding, {
        timestamp: FIXED_TIMESTAMP,
        toolVersion: FIXED_TOOL_VERSION,
      }),
    ).toThrow(IncompleteEvidenceError);
  });


  it("refuses a verified finding without successful impact evidence", () => {
    const finding = verifiedFinding({
      pocExecution: {
        ...verifiedFinding().pocExecution!,
        overallVerdict: "could_not_run",
      },
      layerVerdicts: layerVerdicts([
        { verdict: "error" },
        { verdict: "error" },
      ]),
    });

    expect(() =>
      assembleReproducibilityManifest(finding, {
        timestamp: FIXED_TIMESTAMP,
        toolVersion: FIXED_TOOL_VERSION,
      }),
    ).toThrow(IncompleteEvidenceError);
  });


  it("sets harnessRevision to null when no pocSteps exist", () => {
    const finding = verifiedFinding({ pocSteps: undefined });
    const manifest = assembleReproducibilityManifest(finding, {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });
    expect(manifest.harnessRevision).toBeNull();
  });

  it("includes modelConfig when provided", () => {
    const manifest = assembleReproducibilityManifest(verifiedFinding(), {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
      modelConfig: "anthropic/claude-sonnet-4",
    });
    expect(manifest.modelConfig).toBe("anthropic/claude-sonnet-4");
  });

  it("sets modelConfig to null when omitted", () => {
    const manifest = assembleReproducibilityManifest(verifiedFinding(), {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });
    expect(manifest.modelConfig).toBeNull();
  });

  it("preserves the canonical replay status when present", () => {
    const finding = verifiedFinding({
      verification_result: verificationResult(),
    });
    const manifest = assembleReproducibilityManifest(finding, {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });
    expect(manifest.verification.replayVerdict).toBe("reproduced");
  });

  it("sets replayVerdict to null when verification_result is absent", () => {
    // verification_result is undefined
    const manifest = assembleReproducibilityManifest(verifiedFinding(), {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });
    expect(manifest.verification.replayVerdict).toBeNull();
  });

  it("accepts a finding with OAST-confirmed replay when PoC execution is absent", () => {
    // The gate allows OAST-confirmed replays even without a successful
    // behavioural PoC execution. pocVerdict should be null (no exec ran),
    // replayVerdict should come from the verification_result.
    const finding = verifiedFinding({
      pocExecution: undefined,
      verification_result: verificationResult({
        status: "reproduced",
        oast_confirmed: true,
      }),
    });
    const manifest = assembleReproducibilityManifest(finding, {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });

    expect(manifest.verification.pocVerdict).toBeNull();
    expect(manifest.verification.replayVerdict).toBe("reproduced");
    expect(manifest.redactionsApplied).toContain("replay-verified-impact");
    expect(manifest.redactionsApplied).not.toContain("poc-verified-impact");
  });

  it("sets evidence hashes to null when evidence request or response is absent", () => {
    const withoutEvidence = verifiedFinding({ evidence: {} });
    const manifest = assembleReproducibilityManifest(withoutEvidence, {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });

    expect(manifest.evidenceHashes.requestHash).toBeNull();
    expect(manifest.evidenceHashes.responseHash).toBeNull();
  });

  it("accepts a finding with OAST-confirmed replay but absent status field", () => {
    // oast_confirmed can be true even when the replay status is absent/null.
    const finding = verifiedFinding({
      pocExecution: undefined,
      verification_result: verificationResult({
        status: null as unknown as string,
        oast_confirmed: true,
      }),
    });
    const manifest = assembleReproducibilityManifest(finding, {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });

    expect(manifest.verification.pocVerdict).toBeNull();
    expect(manifest.redactionsApplied).toContain("replay-verified-impact");
  });

  // ── Injection and sanitization resistance ────────────────────────────────

  it("strips URL userinfo from target identifier", () => {
    const manifest = assembleReproducibilityManifest(verifiedFinding(), {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: "https://admin:supersecret@internal.corp.example/api",
    });
    expect(manifest.targetIdentifier).not.toContain("admin");
    expect(manifest.targetIdentifier).not.toContain("supersecret");
    expect(manifest.targetIdentifier).toContain("[REDACTED-USER]");
  });

  it("redacts client_secret and password query parameters", () => {
    const manifest = assembleReproducibilityManifest(verifiedFinding(), {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier:
        "https://api.example.com/token?client_id=app&client_secret=sk-secret&password=hunter2",
    });
    expect(manifest.targetIdentifier).not.toContain("sk-secret");
    expect(manifest.targetIdentifier).not.toContain("hunter2");
    expect(manifest.targetIdentifier).toContain("[REDACTED]");
  });

  it("redacts externally controlled finding metadata fields", () => {
    // The finding ID, severity, category, and status all come from the
    // Finding which is under external control — they must be redacted.
    const finding = verifiedFinding({
      id: "f-email@evil.com-attack",
      severity: "critical-client_secret=sk-leaked",
      category: "sqli?password=mysecretpass",
      status: "confirmed",
    });
    const manifest = assembleReproducibilityManifest(finding, {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });
    const rendered = renderReproducibilityManifest(manifest);
    // The email-like ID should be PII-redacted.
    expect(manifest.findingId).not.toContain("@evil.com");
    // A secret-like severity value should be sanitized.
    expect(manifest.findingSeverity).not.toContain("sk-leaked");
    // A key=value in category should be sanitized.
    expect(manifest.findingCategory).not.toContain("mysecretpass");
    // The rendered output should also be clean.
    expect(rendered).not.toContain("@evil.com");
    expect(rendered).not.toContain("sk-leaked");
    expect(rendered).not.toContain("mysecretpass");
  });

  it("redacts externally controlled verification field strings", () => {
    // PocVerdict, replayVerdict, and verifiedAt all come from finding data
    // and must be redacted before appearing in the manifest.
    // We inject secrets into pocExecution.startedAt (becomes verifiedAt)
    // and verification_result.status (becomes replayVerdict) while keeping
    // the gate-passing conditions intact.
    const finding = verifiedFinding({
      pocExecution: {
        findingId: "f-001",
        startedAt: "2026-08-02T11:00:00.000Z?token=mysecrettoken",
        endedAt: "2026-08-02T11:00:05.000Z",
        steps: [
          {
            stepId: "exploit",
            kind: "passed" as const,
            durationMs: 3200,
            observedExit: 0,
            observedStdout: "200 OK",
          },
        ],
        overallVerdict: "exploit_still_works" as const,
      },
      verification_result: {
        status: "reproduced",
        oast_confirmed: false,
        mode: "deterministic_replay",
        finding_id: "f-001",
        engine_version: "pwnkit/0.1.0",
        started_at: "2026-08-02T11:00:00.000Z",
        completed_at: "2026-08-02T11:00:05.000Z?client_secret=sk-xxx",
        duration_ms: 1,
        commands: [],
        assertions: [],
        evidence_artifacts: [],
        engine_metadata: { os: "linux", arch: "x64", runner: "local" },
      },
    });
    const manifest = assembleReproducibilityManifest(finding, {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });

    // pocVerdict = "exploit_still_works" — should not have been modified.
    expect(manifest.verification.pocVerdict).toBe("exploit_still_works");
    // verifiedAt comes from startedAt which had ?token=... appended.
    expect(manifest.verification.verifiedAt).not.toContain("mysecrettoken");
    // verifiedAt also from completed_at with client_secret
    expect(manifest.verification.verifiedAt).not.toContain("sk-xxx");
    // replayVerdict = "reproduced" — should pass through clean.
    expect(manifest.verification.replayVerdict).toBe("reproduced");
  });

  it("redacts externally controlled tool-version and timestamp strings", () => {
    const manifest = assembleReproducibilityManifest(verifiedFinding(), {
      timestamp: "2026-08-02T12:00:00.000Z?token=injected",
      toolVersion: "pwnkit/0.1.0?password=pass123",
      targetIdentifier: TARGET_IDENTIFIER,
    });
    expect(manifest.generatedAt).not.toContain("injected");
    expect(manifest.toolVersion).not.toContain("pass123");
  });

  it("end-to-end: rendered output contains no raw secrets from any field", () => {
    const finding = verifiedFinding({
      id: "f-ssn-leak",
      title: "User data leak?token=myapitoken",
      severity: "critical",
      category: "sqli?password=hunter2",
      evidence: {
        request:
          "GET /api/users?password=hunter2 HTTP/1.1\nAuthorization: Bearer my-jwt-token\nCookie: session=abc123",
        response:
          "HTTP/1.1 200 OK\nSet-Cookie: session=deadbeef\nContent-Type: application/json\n\n{\"ssn\":\"123-45-6789\"}",
      },
    });
    const manifest = assembleReproducibilityManifest(finding, {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: "https://admin:secret@api.example.com/users?token=xxx",
    });
    const rendered = renderReproducibilityManifest(manifest);

    // Raw secrets from different field sources are redacted.
    expect(rendered).not.toContain("hunter2");
    expect(rendered).not.toContain("my-jwt-token");
    expect(rendered).not.toContain("123-45-6789");
    expect(rendered).not.toContain("abc123");
    expect(rendered).not.toContain("admin");
    expect(rendered).not.toContain("myapitoken");
    // Evidence section shows only hashes, not raw content.
    expect(rendered).toMatch(/Request \(SHA-256\)\s+[a-f0-9]{64}/);
    expect(rendered).toMatch(/Response \(SHA-256\)\s+[a-f0-9]{64}/);
  });
});

// ── renderReproducibilityManifest ───────────────────────────────────────────

describe("renderReproducibilityManifest", () => {
  it("includes all top-level sections", () => {
    const manifest = assembleReproducibilityManifest(verifiedFinding(), {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });
    const text = renderReproducibilityManifest(manifest);

    expect(text).toContain("REPRODUCIBILITY MANIFEST");
    expect(text).toContain("Target");
    expect(text).toContain("Environment");
    expect(text).toContain("Evidence");
    expect(text).toContain("Verification");
    expect(text).toContain("Redactions applied");
    expect(text).toContain("FOR HUMAN REVIEW ONLY");
  });

  it("includes specific field values in the output", () => {
    const manifest = assembleReproducibilityManifest(verifiedFinding(), {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });
    const text = renderReproducibilityManifest(manifest);

    expect(text).toContain(FIXED_TIMESTAMP);
    expect(text).toContain("f-verify-001");
    expect(text).toContain("SQL injection in /api/reports");
    expect(text).toContain(FIXED_TOOL_VERSION);
    expect(text).toContain(TARGET_IDENTIFIER);
  });

  it("never leaks secrets into the rendered output", () => {
    const manifest = assembleReproducibilityManifest(verifiedFinding(), {
      timestamp: FIXED_TIMESTAMP,
      toolVersion: FIXED_TOOL_VERSION,
      targetIdentifier: TARGET_IDENTIFIER,
    });
    const text = renderReproducibilityManifest(manifest);

    expect(text).not.toContain("secret-bearer-token");
    expect(text).not.toContain("deadbeef");
  });
});