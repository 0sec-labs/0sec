import type { ScanReport, Finding, Severity } from "@pwnkit/shared";
import { VERSION } from "@pwnkit/shared";

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number };
    };
  }>;
  properties?: Record<string, unknown>;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: "error" | "warning" | "note" };
  properties?: Record<string, unknown>;
}

function severityToLevel(severity: Severity): "error" | "warning" | "note" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
      return "note";
  }
}

function findingToResult(finding: Finding, target: string): SarifResult {
  const result: SarifResult = {
    ruleId: finding.templateId,
    level: severityToLevel(finding.severity),
    message: { text: finding.description },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: target },
        },
      },
    ],
  };

  if (finding.cvssScore !== undefined || finding.confidence !== undefined) {
    result.properties = {};
    if (finding.cvssScore !== undefined) result.properties["cvssScore"] = finding.cvssScore;
    if (finding.cvssVector) result.properties["cvssVector"] = finding.cvssVector;
    if (finding.confidence !== undefined) result.properties["confidence"] = finding.confidence;
  }

  return result;
}

function findingToRule(finding: Finding): SarifRule {
  return {
    id: finding.templateId,
    name: finding.title,
    shortDescription: { text: finding.title },
    defaultConfiguration: { level: severityToLevel(finding.severity) },
    properties: {
      category: finding.category,
      severity: finding.severity,
    },
  };
}

export function formatSarif(report: ScanReport): string {
  // Deduplicate rules by templateId
  const rulesMap = new Map<string, SarifRule>();
  for (const finding of report.findings) {
    if (!rulesMap.has(finding.templateId)) {
      rulesMap.set(finding.templateId, findingToRule(finding));
    }
  }

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0" as const,
    runs: [
      {
        tool: {
          driver: {
            name: "pwnkit",
            version: VERSION,
            informationUri: "https://github.com/0sec-labs/pwnkit",
            rules: Array.from(rulesMap.values()),
          },
        },
        results: report.findings.map((f) => findingToResult(f, report.target)),
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: report.startedAt,
            endTimeUtc: report.completedAt,
          },
        ],
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
