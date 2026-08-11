import type { IntelTargetHistory } from "./types.js";

export function formatTargetHistoryForPrompt(history: IntelTargetHistory): string | null {
  if (history.summary.advisoryCount === 0 && history.playbooks.length === 0) return null;

  const label = history.target.repository
    ?? history.target.packageName
    ?? history.target.product
    ?? history.target.target
    ?? history.target.repoPath
    ?? "target";
  const lines = [
    "## Prior Vulnerability Audit Graph",
    `Target: ${label}`,
    `Historical advisories: ${history.summary.advisoryCount}; playbooks: ${history.summary.playbookCount}; audit graph: ${history.auditGraph.nodes.length} nodes / ${history.auditGraph.edges.length} edges.`,
  ];
  if (history.summary.matchedHints.length > 0) {
    lines.push(`Matched hints: ${history.summary.matchedHints.slice(0, 8).join(", ")}`);
  }
  lines.push(
    "The playbooks below document ground already covered by prior analysis. These known bug classes and their prior findings will be automatically deduplicated. DO NOT re-derive or re-report them. Instead treat this as a coverage map: focus effort on UNEXPLORED attack surface -- files, entry points, and vulnerability classes not represented in the list below.",
  );

  for (const playbook of history.playbooks.slice(0, 4)) {
    lines.push("", `### ${playbook.bugClass}`);
    if (playbook.cwes.length > 0) lines.push(`CWE: ${playbook.cwes.slice(0, 5).join(", ")}`);
    lines.push(`Prior IDs: ${playbook.priorVulnerabilityIds.slice(0, 8).join(", ")}`);
    lines.push(`Relevance: ${playbook.relevance}`);
    for (const [index, step] of playbook.steps.slice(0, 4).entries()) {
      lines.push(`${index + 1}. ${step.title}`);
      lines.push(`   Rationale: ${step.rationale}`);
      if (step.expectedEvidence.length > 0) {
        lines.push(`   Evidence to collect: ${step.expectedEvidence.slice(0, 3).join(" | ")}`);
      }
    }
  }

  return lines.join("\n");
}
