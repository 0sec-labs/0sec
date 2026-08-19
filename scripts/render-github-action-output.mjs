import fs from "node:fs";
import path from "node:path";

const [jsonReportPath, sarifReportPath, primaryFormat, mode, targetLabel, severityThreshold, countThresholdRaw] = process.argv.slice(2);

if (!jsonReportPath || !sarifReportPath || !primaryFormat || !mode || !targetLabel || !severityThreshold || !countThresholdRaw) {
  throw new Error("Missing required arguments.");
}

const report = JSON.parse(fs.readFileSync(jsonReportPath, "utf8"));
const findings = Array.isArray(report.findings) ? report.findings : [];
const warnings = Array.isArray(report.warnings) ? report.warnings : [];
const summary = report.summary ?? {};
const severityOrder = ["info", "low", "medium", "high", "critical"];
const countThreshold = Number.parseInt(countThresholdRaw, 10);

function severityToLevel(severity) {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
    default:
      return "note";
  }
}

function escapeCell(value) {
  return String(value ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

const thresholdIndex = severityThreshold === "none" ? Number.POSITIVE_INFINITY : severityOrder.indexOf(severityThreshold);
if (thresholdIndex === -1) {
  throw new Error(`Unsupported severity threshold: ${severityThreshold}`);
}

const sortedFindings = findings.slice().sort((left, right) => {
  return severityOrder.indexOf(right.severity) - severityOrder.indexOf(left.severity);
});

const qualifyingFindings = thresholdIndex === Number.POSITIVE_INFINITY
  ? []
  : sortedFindings.filter((finding) => severityOrder.indexOf(finding.severity) >= thresholdIndex);

const shouldFail = qualifyingFindings.length > countThreshold;

const rulesById = new Map();
for (const finding of sortedFindings) {
  const ruleId = finding.templateId || finding.id || "pwnkit-finding";
  if (!rulesById.has(ruleId)) {
    rulesById.set(ruleId, {
      id: ruleId,
      name: finding.title || ruleId,
      shortDescription: {
        text: finding.title || "pwnkit finding",
      },
      fullDescription: {
        text: finding.description || "pwnkit detected a potential security issue.",
      },
      defaultConfiguration: {
        level: severityToLevel(finding.severity),
      },
      properties: {
        category: finding.category || "unknown",
        severity: finding.severity || "info",
      },
    });
  }
}

const sarif = {
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "pwnkit",
          informationUri: "https://github.com/0sec-labs/pwnkit",
          rules: Array.from(rulesById.values()),
        },
      },
      automationDetails: {
        id: `pwnkit/${mode}`,
      },
      properties: {
        mode,
        target: report.target || targetLabel,
        startedAt: report.startedAt || null,
        completedAt: report.completedAt || null,
      },
      results: sortedFindings.map((finding) => ({
        ruleId: finding.templateId || finding.id || "pwnkit-finding",
        level: severityToLevel(finding.severity),
        message: {
          text: [finding.description, finding.evidence?.analysis].filter(Boolean).join("\n\n") || finding.title || "pwnkit finding",
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: report.target || targetLabel,
              },
            },
          },
        ],
        properties: {
          severity: finding.severity || "info",
          category: finding.category || "unknown",
          findingId: finding.id || null,
        },
      })),
    },
  ],
};

fs.writeFileSync(sarifReportPath, JSON.stringify(sarif, null, 2));

const totalFindings = Number(summary.totalFindings ?? sortedFindings.length);
const critical = Number(summary.critical ?? 0);
const high = Number(summary.high ?? 0);
const medium = Number(summary.medium ?? 0);
const low = Number(summary.low ?? 0);
const info = Number(summary.info ?? 0);
const durationSeconds = typeof report.durationMs === "number" ? (report.durationMs / 1000).toFixed(1) : "0.0";
const reportFile = primaryFormat === "sarif" ? path.resolve(sarifReportPath) : path.resolve(jsonReportPath);
const gateMessage = severityThreshold === "none"
  ? "Threshold gate disabled."
  : `pwnkit found ${qualifyingFindings.length} finding(s) at or above ${severityThreshold}; threshold allows ${countThreshold}.`;

const topFindings = sortedFindings.slice(0, 5);
const lines = [
  "<!-- pwnkit-action -->",
  `## pwnkit ${mode} report`,
  "",
  `**Target:** \`${report.target || targetLabel}\``,
  `**Duration:** ${durationSeconds}s`,
  `**Gate:** ${severityThreshold === "none" ? "disabled" : `fail when findings at or above \`${severityThreshold}\` exceed \`${countThreshold}\``}`,
  "",
  "| Severity | Count |",
  "|----------|-------|",
  `| Critical | ${critical} |`,
  `| High | ${high} |`,
  `| Medium | ${medium} |`,
  `| Low | ${low} |`,
  `| Info | ${info} |`,
  `| **Total** | **${totalFindings}** |`,
  "",
];

if (topFindings.length > 0) {
  lines.push("### Top findings");
  lines.push("");
  lines.push("| Severity | Finding | Category |");
  lines.push("|----------|---------|----------|");
  for (const finding of topFindings) {
    lines.push(`| ${escapeCell(String(finding.severity).toUpperCase())} | ${escapeCell(finding.title)} | ${escapeCell(finding.category)} |`);
  }
  lines.push("");
} else {
  lines.push("No confirmed vulnerabilities found.");
  lines.push("");
}

if (warnings.length > 0) {
  lines.push("### Warnings");
  lines.push("");
  for (const warning of warnings.slice(0, 3)) {
    lines.push(`- **${escapeCell(warning.stage)}:** ${escapeCell(warning.message)}`);
  }
  lines.push("");
}

lines.push("---");
lines.push("*Generated by [pwnkit](https://github.com/0sec-labs/pwnkit)*");

const githubOutput = process.env.GITHUB_OUTPUT;
if (!githubOutput) {
  throw new Error("GITHUB_OUTPUT is not set.");
}

const outputLines = [
  `report-file=${reportFile}`,
  `json-report-file=${path.resolve(jsonReportPath)}`,
  `sarif-report-file=${path.resolve(sarifReportPath)}`,
  `total-findings=${totalFindings}`,
  `qualifying-findings=${qualifyingFindings.length}`,
  `should-fail=${shouldFail ? "true" : "false"}`,
  `gate-message=${gateMessage}`,
  "comment-body<<__PWNKIT_COMMENT__",
  ...lines,
  "__PWNKIT_COMMENT__",
];

fs.appendFileSync(githubOutput, `${outputLines.join("\n")}\n`);
