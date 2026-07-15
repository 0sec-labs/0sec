import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  WINDOWS_IOCTL_FOXGUARD_BASELINE_PROOF_LIMIT,
  WINDOWS_IOCTL_FOXGUARD_BASELINE_SCHEMA,
  WINDOWS_IOCTL_FOXGUARD_VERSION,
  WINDOWS_IOCTL_LOCATION_PROJECTION_VERDICT_SCHEMA,
  validateWindowsIoctlFoxguardBaseline,
  type VerifiedWindowsIoctlLocationProjection,
  type WindowsIoctlFoxguardBaselineContext,
  type WindowsIoctlFoxguardBaselineObservation,
} from "./windows-ioctl-foxguard-baseline.js";
import { wilsonIntervalTuple } from "./wilson.js";

function sha(character: string): string {
  return character.repeat(64);
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function copy<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

const SITE_IDS = ["a", "b", "c", "d", "e"].map(sha);

function finding(
  line: number,
  severity: "low" | "medium" | "high" | "critical",
  confidence: number,
  endLine = line,
  column = 3,
  endColumn = 12,
) {
  return {
    rule_id: `c/windows-ioctl-${line}`,
    severity,
    cwe: "CWE-120",
    description: `Finding at line ${line}`,
    file: "src/driver.c",
    line,
    column,
    end_line: endLine,
    end_column: endColumn,
    snippet: `copy_at_${line}();`,
    confidence,
    future_additive_field: { preserved: true },
  };
}

function reportRecord() {
  const findings = [
    finding(10, "critical", 0.9),
    finding(20, "high", 0.95),
    finding(50, "medium", 0.8),
    finding(99, "low", 0.7),
    finding(30, "low", 0.6, 40),
  ];
  return {
    schema_version: "1.0.0",
    finding_schema_version: "1.0.0",
    scanner: { name: "foxguard", version: "0.12.0", command: "scan" },
    config: { source: "none" },
    target: {
      path: "/evidence/scanned-input",
      kind: "directory",
      changed_only: false,
      files_scanned: 1,
    },
    timing: { duration_ms: 1_000 },
    finding_counts: {
      total: findings.length,
      by_severity: { low: 2, medium: 1, high: 1, critical: 1 },
    },
    findings,
    future_envelope_field: true,
  };
}

function projection(): VerifiedWindowsIoctlLocationProjection {
  return {
    schemaVersion: WINDOWS_IOCTL_LOCATION_PROJECTION_VERDICT_SCHEMA,
    signatureVerified: true,
    driverSha256: sha("1"),
    analysisSha256: sha("2"),
    analysisReceiptSha256: sha("3"),
    siteUniverseManifestSha256: sha("4"),
    siteUniverseSha256: sha("5"),
    siteCount: 5,
    locationProjectionManifestSha256: sha("6"),
    locationProjectionSignatureSha256: sha("7"),
    sites: SITE_IDS.map((siteId, index) => ({
      siteId,
      file: "src/driver.c",
      startLine: (index + 1) * 10,
      startColumn: 1,
      endLine: (index + 1) * 10,
      endColumn: 20,
    })),
  };
}

function validFixture(): {
  observation: WindowsIoctlFoxguardBaselineObservation;
  context: WindowsIoctlFoxguardBaselineContext;
  report: ReturnType<typeof reportRecord>;
} {
  const report = reportRecord();
  const bytes = Buffer.from(JSON.stringify(report));
  const reportDigest = digest(bytes);
  const verifiedProjection = projection();
  const expectedFoxguard = {
    executableSha256: sha("8"),
    rulesSha256: sha("9"),
    configSha256: sha("0"),
    argvSha256: sha("f"),
    inputSha256: sha("d"),
    reportSha256: reportDigest,
    stdoutSha256: reportDigest,
  };
  const {
    schemaVersion: _schemaVersion,
    signatureVerified: _signatureVerified,
    sites: _sites,
    ...upstream
  } = verifiedProjection;
  return {
    report,
    observation: {
      schemaVersion: WINDOWS_IOCTL_FOXGUARD_BASELINE_SCHEMA,
      upstream,
      foxguard: {
        version: WINDOWS_IOCTL_FOXGUARD_VERSION,
        findingSchemaVersion: "1.0.0",
        findingCount: report.findings.length,
        ...expectedFoxguard,
      },
      timing: {
        startedAt: "2026-07-15T18:00:00.000Z",
        completedAt: "2026-07-15T18:00:01.000Z",
        durationMs: 1_000,
      },
      cost: { modelCalls: 0, inputTokens: 0, outputTokens: 0, estimatedUsd: 0.002 },
      safety: {
        evaluatorPrivate: true,
        agentVisible: false,
        benchmarkOnly: true,
        staticOnly: true,
        executionPerformed: false,
        executionAuthorized: false,
        runtimeConsumable: false,
        deviceIoctlAttempts: 0,
        researchFindingCreated: false,
        capabilityMeasure: false,
        reachabilityEstablished: false,
        vulnerabilityEstablished: false,
        impactEstablished: false,
        noveltyEstablished: false,
        claimEligible: false,
        bountyEligible: false,
        weaponization: false,
        automaticDisclosure: false,
        humanPromotionGate: true,
        humanReportGate: true,
      },
      proofLimit: WINDOWS_IOCTL_FOXGUARD_BASELINE_PROOF_LIMIT,
    },
    context: {
      verifiedProjection,
      expectedFoxguard,
      reportBytes: bytes,
      stdoutBytes: bytes,
      evaluatorPolicy: {
        rankCutoff: 2,
        siteRoles: [
          { siteId: SITE_IDS[0]!, role: "expected" },
          { siteId: SITE_IDS[1]!, role: "expected" },
          { siteId: SITE_IDS[2]!, role: "control" },
          { siteId: SITE_IDS[3]!, role: "control" },
          { siteId: SITE_IDS[4]!, role: "abstention" },
        ],
      },
    },
  };
}

function refreshReport(
  fixture: ReturnType<typeof validFixture>,
  transform: (report: ReturnType<typeof reportRecord>) => void,
): void {
  transform(fixture.report);
  const bytes = Buffer.from(JSON.stringify(fixture.report));
  const reportDigest = digest(bytes);
  fixture.context.reportBytes = bytes;
  fixture.context.stdoutBytes = bytes;
  fixture.context.expectedFoxguard.reportSha256 = reportDigest;
  fixture.context.expectedFoxguard.stdoutSha256 = reportDigest;
  fixture.observation.foxguard.reportSha256 = reportDigest;
  fixture.observation.foxguard.stdoutSha256 = reportDigest;
  fixture.observation.foxguard.findingCount = fixture.report.findings.length;
}

describe("Windows IOCTL Foxguard baseline", () => {
  it("projects only exact region overlaps and derives label-private baseline contributions", () => {
    const { observation, context } = validFixture();
    const result = validateWindowsIoctlFoxguardBaseline(observation, context);

    expect(result.accounting).toEqual({
      siteUniverseCount: 5,
      findingCount: 5,
      mappedFindingCount: 3,
      unmappedFindingCount: 1,
      ambiguousFindingCount: 1,
      mappedSiteCount: 3,
      emittedSiteCount: 3,
    });
    expect(result.rankRows).toEqual([
      { siteId: SITE_IDS[0], severity: "critical", confidence: 0.9, findingCount: 1, rank: 1 },
      { siteId: SITE_IDS[1], severity: "high", confidence: 0.95, findingCount: 1, rank: 2 },
      { siteId: SITE_IDS[4], severity: "medium", confidence: 0.8, findingCount: 1, rank: 3 },
    ]);
    expect(result.evaluatorAggregate).toEqual({
      rankCutoff: 2,
      firstExpectedRank: 1,
      expectedCount: 2,
      expectedFoundAtCutoff: 2,
      controlCount: 2,
      controlsEmitted: 0,
      abstentionCount: 1,
      emittedAbstentionCount: 1,
    });
    expect(result.metrics).toEqual({
      recallAtCutoff: 1,
      recallAtCutoffCi95: wilsonIntervalTuple(2, 2),
      mrrContributionPpm: 1_000_000,
      controlSuppression: 1,
      controlSuppressionCi95: wilsonIntervalTuple(2, 2),
    });
    expect(result.timing.durationMs).toBe(1_000);
    expect(result.cost.estimatedUsd).toBe(0.002);
    expect(JSON.stringify(result)).not.toMatch(/siteRoles|expectedSiteIds|controlSiteIds|groundTruth|ResearchFinding/);
  });

  it("deduplicates mapped sites and ranks severity, confidence, then site ID without labels", () => {
    const fixture = validFixture();
    refreshReport(fixture, (report) => {
      report.findings = [
        finding(20, "high", 0.5),
        { ...finding(20, "critical", 0.2), rule_id: "c/second" },
        finding(10, "critical", 0.2),
      ];
      report.finding_counts = {
        total: 3,
        by_severity: { low: 0, medium: 0, high: 1, critical: 2 },
      };
    });
    const result = validateWindowsIoctlFoxguardBaseline(fixture.observation, fixture.context);
    expect(result.rankRows).toEqual([
      { siteId: SITE_IDS[0], severity: "critical", confidence: 0.2, findingCount: 1, rank: 1 },
      { siteId: SITE_IDS[1], severity: "critical", confidence: 0.2, findingCount: 2, rank: 2 },
    ]);
    expect(result.accounting.mappedFindingCount).toBe(3);
    expect(result.accounting.mappedSiteCount).toBe(2);
  });

  it("requires every observation commitment to match independently verified context", () => {
    const fields = [
      "driverSha256", "analysisSha256", "analysisReceiptSha256", "siteUniverseManifestSha256",
      "siteUniverseSha256", "locationProjectionManifestSha256", "locationProjectionSignatureSha256",
    ] as const;
    for (const field of fields) {
      const fixture = validFixture();
      fixture.observation.upstream[field] = sha("c");
      expect(
        () => validateWindowsIoctlFoxguardBaseline(fixture.observation, fixture.context),
        field,
      ).toThrow(/upstream-verified/);
    }
    const evidenceFields = [
      "executableSha256", "rulesSha256", "configSha256", "argvSha256", "inputSha256",
    ] as const;
    for (const field of evidenceFields) {
      const fixture = validFixture();
      fixture.observation.foxguard[field] = sha("c");
      expect(
        () => validateWindowsIoctlFoxguardBaseline(fixture.observation, fixture.context),
        field,
      ).toThrow(/independently verified Foxguard/);
    }
  });

  it("rejects an unsigned, incomplete, aliased, or unsorted location projection", () => {
    const unsigned = validFixture();
    (unsigned.context.verifiedProjection as { signatureVerified: boolean }).signatureVerified = false;
    expect(() => validateWindowsIoctlFoxguardBaseline(unsigned.observation, unsigned.context)).toThrow(/signed verdict/);

    const incomplete = validFixture();
    incomplete.context.verifiedProjection.sites.pop();
    expect(() => validateWindowsIoctlFoxguardBaseline(incomplete.observation, incomplete.context)).toThrow(/cover siteCount/);

    const alias = validFixture();
    alias.context.verifiedProjection.analysisSha256 = alias.context.verifiedProjection.driverSha256;
    expect(() => validateWindowsIoctlFoxguardBaseline(alias.observation, alias.context)).toThrow(/must not alias/);

    const unsorted = validFixture();
    unsorted.context.verifiedProjection.sites.reverse();
    expect(() => validateWindowsIoctlFoxguardBaseline(unsorted.observation, unsorted.context)).toThrow(/sorted/);
  });

  it("rehashes exact report/stdout bytes and rejects split or tampered evidence", () => {
    const split = validFixture();
    split.context.stdoutBytes = Buffer.from(`${Buffer.from(split.context.reportBytes).toString("utf8")}\n`);
    expect(() => validateWindowsIoctlFoxguardBaseline(split.observation, split.context)).toThrow(/exact stdout/);

    const tampered = validFixture();
    tampered.context.reportBytes = Buffer.from("{}");
    tampered.context.stdoutBytes = Buffer.from("{}");
    expect(() => validateWindowsIoctlFoxguardBaseline(tampered.observation, tampered.context)).toThrow(/do not match/);

    const alias = validFixture();
    alias.context.expectedFoxguard.rulesSha256 = alias.context.expectedFoxguard.executableSha256;
    expect(() => validateWindowsIoctlFoxguardBaseline(alias.observation, alias.context)).toThrow(/must not alias/);
  });

  it("strictly validates native finding-v1 regions, counts, versions, and duplicate keys", () => {
    const zero = validFixture();
    refreshReport(zero, (report) => { report.findings[0]!.line = 0; });
    expect(() => validateWindowsIoctlFoxguardBaseline(zero.observation, zero.context)).toThrow(/integer in \[1/);

    const reversed = validFixture();
    refreshReport(reversed, (report) => { report.findings[0]!.end_column = 1; });
    expect(() => validateWindowsIoctlFoxguardBaseline(reversed.observation, reversed.context)).toThrow(/must not precede/);

    const wrongVersion = validFixture();
    refreshReport(wrongVersion, (report) => { report.scanner.version = "0.11.0"; });
    expect(() => validateWindowsIoctlFoxguardBaseline(wrongVersion.observation, wrongVersion.context)).toThrow(/exact v0.12/);

    const counts = validFixture();
    refreshReport(counts, (report) => { report.finding_counts.total += 1; });
    expect(() => validateWindowsIoctlFoxguardBaseline(counts.observation, counts.context)).toThrow(/total does not match/);

    const missingConfigSource = validFixture();
    refreshReport(missingConfigSource, (report) => { delete (report.config as { source?: string }).source; });
    expect(() => validateWindowsIoctlFoxguardBaseline(missingConfigSource.observation, missingConfigSource.context))
      .toThrow(/config\.source/);

    const missingTargetPath = validFixture();
    refreshReport(missingTargetPath, (report) => { delete (report.target as { path?: string }).path; });
    expect(() => validateWindowsIoctlFoxguardBaseline(missingTargetPath.observation, missingTargetPath.context))
      .toThrow(/target\.path/);

    const duplicate = validFixture();
    const raw = Buffer.from(duplicate.context.reportBytes).toString("utf8").replace(
      '"schema_version":"1.0.0"',
      '"schema_version":"1.0.0","schema_version":"1.0.0"',
    );
    const bytes = Buffer.from(raw);
    const reportDigest = digest(bytes);
    duplicate.context.reportBytes = bytes;
    duplicate.context.stdoutBytes = bytes;
    duplicate.context.expectedFoxguard.reportSha256 = reportDigest;
    duplicate.context.expectedFoxguard.stdoutSha256 = reportDigest;
    duplicate.observation.foxguard.reportSha256 = reportDigest;
    duplicate.observation.foxguard.stdoutSha256 = reportDigest;
    expect(() => validateWindowsIoctlFoxguardBaseline(duplicate.observation, duplicate.context)).toThrow(/duplicate JSON key/);

    const oversized = validFixture();
    oversized.context.reportBytes = new Uint8Array(8 * 1024 * 1024 + 1);
    oversized.context.stdoutBytes = oversized.context.reportBytes;
    expect(() => validateWindowsIoctlFoxguardBaseline(oversized.observation, oversized.context)).toThrow(/nonempty and bounded/);
  });

  it("uses exact overlap only: adjacency and path mismatch remain unmapped", () => {
    const fixture = validFixture();
    refreshReport(fixture, (report) => {
      report.findings = [
        finding(10, "high", 0.9, 10, 21, 30),
        { ...finding(10, "high", 0.8), file: "src/other.c", rule_id: "c/other" },
      ];
      report.finding_counts = {
        total: 2,
        by_severity: { low: 0, medium: 0, high: 2, critical: 0 },
      };
    });
    const result = validateWindowsIoctlFoxguardBaseline(fixture.observation, fixture.context);
    expect(result.accounting).toMatchObject({ mappedFindingCount: 0, unmappedFindingCount: 2, ambiguousFindingCount: 0 });
    expect(result.rankRows).toEqual([]);
  });

  it("requires evaluator-private roles to exactly partition the verified universe", () => {
    const missing = validFixture();
    missing.context.evaluatorPolicy.siteRoles.pop();
    expect(() => validateWindowsIoctlFoxguardBaseline(missing.observation, missing.context)).toThrow(/exactly partition/);

    const foreign = validFixture();
    foreign.context.evaluatorPolicy.siteRoles[0]!.siteId = sha("8");
    expect(() => validateWindowsIoctlFoxguardBaseline(foreign.observation, foreign.context)).toThrow(/do not match/);

    const noControls = validFixture();
    noControls.context.evaluatorPolicy.siteRoles = noControls.context.evaluatorPolicy.siteRoles.map((row) => ({
      ...row,
      role: row.role === "control" ? "abstention" : row.role,
    }));
    expect(() => validateWindowsIoctlFoxguardBaseline(noControls.observation, noControls.context)).toThrow(/expected and control/);
  });

  it("fails closed on every safety, proof-limit, timing, and model-cost mutation", () => {
    const base = validFixture();
    for (const [field, value] of Object.entries(base.observation.safety)) {
      const fixture = validFixture();
      (fixture.observation.safety as unknown as Record<string, unknown>)[field] =
        typeof value === "boolean" ? !value : 1;
      expect(
        () => validateWindowsIoctlFoxguardBaseline(fixture.observation, fixture.context),
        field,
      ).toThrow(/fail-closed/);
    }
    const proof = validFixture();
    proof.observation.proofLimit = "stronger claim" as typeof WINDOWS_IOCTL_FOXGUARD_BASELINE_PROOF_LIMIT;
    expect(() => validateWindowsIoctlFoxguardBaseline(proof.observation, proof.context)).toThrow(/proof limit/);

    const timing = validFixture();
    timing.observation.timing.durationMs = 999;
    expect(() => validateWindowsIoctlFoxguardBaseline(timing.observation, timing.context)).toThrow(/exactly bind/);

    const model = validFixture();
    (model.observation.cost as { modelCalls: number }).modelCalls = 1;
    expect(() => validateWindowsIoctlFoxguardBaseline(model.observation, model.context)).toThrow(/cannot declare model/);
  });

  it("keeps the implementation free of runners, subprocesses, and Finding adapters", () => {
    const source = readFileSync(new URL("./windows-ioctl-foxguard-baseline.ts", import.meta.url), "utf8");
    expect(source).not.toMatch(/from ["']node:child_process|execFile\s*\(|spawn\s*\(|foxguardFindingToCloudFinding|runFoxguard/i);
  });
});
