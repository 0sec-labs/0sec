import { describe, expect, it } from "vitest";
import type { AuditReport } from "@0sec/shared";
import { auditReportToBenchResult, createDockerWebProvisioner } from "./adapters.js";
import type { BenchCase } from "./manifest.js";

const auditReport: AuditReport = {
  package: "sequelize",
  version: "6.37.8",
  ecosystem: "npm",
  startedAt: "2026-05-31T00:00:00.000Z",
  completedAt: "2026-05-31T00:00:01.000Z",
  durationMs: 1000,
  semgrepFindings: 0,
  npmAuditFindings: [],
  summary: {
    totalAttacks: 0,
    totalFindings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  },
  findings: [],
  usage: { inputTokens: 10, outputTokens: 20 },
  estimatedCostUsd: 0.42,
};

const auditReportWithSource: AuditReport = {
  ...auditReport,
  sourceProvenance: {
    registry: "https://registry.npmjs.org",
    tarballUrl: "https://registry.npmjs.org/sequelize/-/sequelize-6.37.8.tgz",
    integrity: "sha512-test",
    integrityVerified: true,
    requestedSpec: "sequelize@6.37.8",
    resolvedFrom: "npm-package-lock",
  },
};

const sourceAuditTarget: Extract<BenchCase["target"], { kind: "source-audit" }> = {
  kind: "source-audit",
  package: "sequelize",
  version: "6.37.8",
  ecosystem: "npm",
};

describe("auditReportToBenchResult", () => {
  it("threads source-audit target provenance into benchmark metadata", () => {
    const result = auditReportToBenchResult(auditReportWithSource, sourceAuditTarget);
    expect(result.benchmarkMeta?.estimatedCostUsd).toBe(0.42);
    expect(result.benchmarkMeta?.totalTokens).toBe(30);
    expect(result.benchmarkMeta?.targetProvenance).toMatchObject({
      kind: "source-audit",
      ecosystem: "npm",
      package: "sequelize",
      requestedVersion: "6.37.8",
      resolvedVersion: "6.37.8",
      registry: "https://registry.npmjs.org",
      tarballUrl: "https://registry.npmjs.org/sequelize/-/sequelize-6.37.8.tgz",
      integrity: "sha512-test",
      integrityVerified: true,
      reproducibilityStatus: "complete",
    });
    expect(result.benchmarkMeta?.targetProvenance?.notes?.join(" ")).not.toMatch(/not captured yet/);
  });

  it("keeps unverified integrity out of complete provenance", () => {
    const result = auditReportToBenchResult(
      {
        ...auditReport,
        sourceProvenance: {
          registry: "https://registry.npmjs.org",
          tarballUrl: "https://registry.npmjs.org/sequelize/-/sequelize-6.37.8.tgz",
          integrity: "sha512-test",
          requestedSpec: "sequelize@6.37.8",
          resolvedFrom: "npm-package-lock",
        },
      },
      sourceAuditTarget,
    );

    expect(result.benchmarkMeta?.targetProvenance?.reproducibilityStatus).toBe("partial");
    expect(result.benchmarkMeta?.targetProvenance?.notes?.join(" ")).toMatch(/not been verified/);
  });

  it("marks version drift in provenance notes", () => {
    const result = auditReportToBenchResult(
      { ...auditReport, version: "6.37.9" },
      sourceAuditTarget,
    );
    expect(result.benchmarkMeta?.targetProvenance?.resolvedVersion).toBe("6.37.9");
    expect(result.benchmarkMeta?.targetProvenance?.notes?.join(" ")).toMatch(
      /Requested version 6\.37\.8 resolved as 6\.37\.9/,
    );
  });
});

describe("createDockerWebProvisioner", () => {
  it("passes source-audit cases through without Docker", async () => {
    const provisioner = createDockerWebProvisioner();
    const provisioned = await provisioner.up(
      {
        id: "src-sequelize-set-sqli",
        target: sourceAuditTarget,
        objective: {
          type: "finding-match",
          vulnClass: "sql-injection",
          sinkMarkers: ["Sequelize.prototype.set"],
        },
        knownNegative: false,
        tags: [],
      },
      0,
    );

    expect(provisioned).toEqual({ target: "npm:sequelize@6.37.8" });
  });
});
