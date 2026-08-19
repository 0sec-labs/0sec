import type { PocStep, ScanReport, Finding, Severity } from "@pwnkit/shared";
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
  partialFingerprints?: Record<string, string>;
  codeFlows?: Array<{
    threadFlows: Array<{
      locations: Array<{
        location: {
          message: { text: string };
          properties?: Record<string, unknown>;
        };
      }>;
    }>;
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

function stableFingerprint(finding: Finding, target: string): string {
  return [
    finding.fingerprint,
    finding.templateId,
    finding.category,
    finding.title,
    target,
  ].filter(Boolean).join("|");
}

function actionSummary(step: PocStep): Record<string, unknown> {
  switch (step.action.type) {
    case "shell":
      return { type: "shell", command: step.action.cmd, cwd: step.action.cwd };
    case "http":
      return {
        type: "http",
        method: step.action.method,
        url: step.action.url,
        headers: step.action.headers,
      };
    case "docker":
      return { type: "docker", image: step.action.image, args: step.action.args };
    case "note":
      return { type: "note" };
  }
}

function pocStepsToCodeFlows(pocSteps: PocStep[] | undefined): SarifResult["codeFlows"] {
  if (!pocSteps || pocSteps.length === 0) return undefined;
  return [
    {
      threadFlows: [
        {
          locations: pocSteps.map((step) => ({
            location: {
              message: { text: `${step.kind}: ${step.summary}` },
              properties: {
                stepId: step.id,
                kind: step.kind,
                action: actionSummary(step),
                expect: step.expect,
              },
            },
          })),
        },
      ],
    },
  ];
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
    partialFingerprints: {
      primary: stableFingerprint(finding, target),
    },
  };

  const codeFlows = pocStepsToCodeFlows(finding.pocSteps);
  if (codeFlows) result.codeFlows = codeFlows;

  result.properties = {
    findingId: finding.id,
    category: finding.category,
    severity: finding.severity,
    status: finding.status,
    evidence: finding.evidence,
  };
  if (finding.cvssScore !== undefined) result.properties["cvssScore"] = finding.cvssScore;
  if (finding.cvssVector) result.properties["cvssVector"] = finding.cvssVector;
  if (finding.confidence !== undefined) result.properties["confidence"] = finding.confidence;
  if (finding.publishability) result.properties["publishability"] = finding.publishability;
  if (finding.noveltyVerdict) result.properties["noveltyVerdict"] = finding.noveltyVerdict;
  if (finding.dedupRefs) result.properties["dedupRefs"] = finding.dedupRefs;
  if (finding.advisoryMatches) result.properties["advisoryMatches"] = finding.advisoryMatches;
  if (finding.verification_result) result.properties["verificationResult"] = finding.verification_result;
  if (finding.inlineValidation) result.properties["inlineValidation"] = finding.inlineValidation;
  if (finding.supplyChain) result.properties["supplyChain"] = finding.supplyChain;
  if (finding.kernelExploit) result.properties["kernelExploit"] = finding.kernelExploit;
  if (finding.semanticDedupe) result.properties["semanticDedupe"] = finding.semanticDedupe;
  if (finding.findingRank !== undefined) result.properties["findingRank"] = finding.findingRank;

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
            informationUri: "https://github.com/0sec-labs/0sec",
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
