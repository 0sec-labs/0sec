import type {
  IntelPriorVulnerabilityAuditEdge,
  IntelPriorVulnerabilityAuditGraph,
  IntelPriorVulnerabilityAuditNode,
  IntelPriorVulnerabilityPlaybook,
} from "./types.js";

export function buildPriorVulnerabilityAuditGraph(
  playbooks: IntelPriorVulnerabilityPlaybook[],
): IntelPriorVulnerabilityAuditGraph {
  const nodes = new Map<string, IntelPriorVulnerabilityAuditNode>();
  const edges = new Map<string, IntelPriorVulnerabilityAuditEdge>();
  const entrypointNodeIds: string[] = [];

  const addNode = (node: IntelPriorVulnerabilityAuditNode) => {
    if (!nodes.has(node.id)) nodes.set(node.id, node);
  };
  const addEdge = (edge: IntelPriorVulnerabilityAuditEdge) => {
    edges.set(`${edge.from}\0${edge.kind}\0${edge.to}`, edge);
  };

  for (const playbook of playbooks) {
    const playbookId = stableNodeId("bug-class", playbook.id);
    entrypointNodeIds.push(playbookId);
    addNode({
      id: playbookId,
      kind: "bug_class",
      key: playbook.id,
      title: playbook.bugClass,
      data: {
        cwes: playbook.cwes,
        relevance: playbook.relevance,
      },
    });

    for (const priorId of playbook.priorVulnerabilityIds) {
      const priorNodeId = stableNodeId("prior", priorId);
      addNode({
        id: priorNodeId,
        kind: "prior_vulnerability",
        key: priorId,
        title: priorId,
      });
      addEdge({ from: priorNodeId, to: playbookId, kind: "INFORMS" });
    }

    let previousStepId: string | undefined;
    for (const [index, step] of playbook.steps.entries()) {
      const stepNodeId = stableNodeId(playbookId, "step", step.id);
      addNode({
        id: stepNodeId,
        kind: "investigation_step",
        key: step.id,
        title: step.title,
        data: {
          order: index + 1,
          rationale: step.rationale,
          actions: step.actions,
        },
      });
      addEdge({ from: playbookId, to: stepNodeId, kind: "HAS_STEP", data: { order: index + 1 } });
      if (previousStepId) {
        addEdge({ from: previousStepId, to: stepNodeId, kind: "NEXT_STEP" });
      }
      previousStepId = stepNodeId;

      for (const [evidenceIndex, expectedEvidence] of step.expectedEvidence.entries()) {
        const evidenceNodeId = stableNodeId(stepNodeId, "evidence", String(evidenceIndex + 1), expectedEvidence);
        addNode({
          id: evidenceNodeId,
          kind: "evidence_query",
          key: expectedEvidence,
          title: expectedEvidence,
          data: { order: evidenceIndex + 1 },
        });
        addEdge({
          from: stepNodeId,
          to: evidenceNodeId,
          kind: "SEEKS_EVIDENCE",
          data: { order: evidenceIndex + 1 },
        });
      }
    }
  }

  return {
    entrypointNodeIds,
    nodes: [...nodes.values()],
    edges: [...edges.values()],
  };
}

function stableNodeId(...parts: string[]): string {
  return parts.map((part) => part.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "node").join(":");
}
