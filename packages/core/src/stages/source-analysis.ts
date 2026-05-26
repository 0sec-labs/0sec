import type {
  ScanContext,
  StageResult,
  AttackTemplate,
  Finding,
  Severity,
  AttackCategory,
} from "@pwnkit/shared";
import type { Runtime, RuntimeContext } from "../runtime/types.js";
import { buildSourceAnalysisPrompt } from "../prompts.js";

export interface SourceAnalysisResult {
  findings: Finding[];
  templatesAnalyzed: number;
}

/**
 * Run source code analysis by spawning Claude Code / Codex against the
 * target repository. Iterates unique template categories so the agent
 * gets one focused prompt per attack surface rather than per-payload.
 */
export async function runSourceAnalysis(
  ctx: ScanContext,
  templates: AttackTemplate[],
  runtime: Runtime,
  repoPath: string
): Promise<StageResult<SourceAnalysisResult>> {
  const start = Date.now();
  const findings: Finding[] = [];

  // Deduplicate by category — one source analysis pass per category
  const seen = new Set<string>();
  const uniqueTemplates: AttackTemplate[] = [];
  for (const t of templates) {
    if (!seen.has(t.category)) {
      seen.add(t.category);
      uniqueTemplates.push(t);
    }
  }

  for (const template of uniqueTemplates) {
    try {
      const prompt = buildSourceAnalysisPrompt(repoPath, template);

      const runtimeCtx: RuntimeContext = {
        target: ctx.config.target,
        templateId: template.id,
        findings: findings.length > 0
          ? JSON.stringify(findings.map((f) => ({ id: f.id, title: f.title, severity: f.severity })))
          : undefined,
      };

      const result = await runtime.execute(prompt, runtimeCtx);

      if (result.error && !result.output) {
        continue;
      }

      const parsed = parseSourceAnalysisOutput(result.output, template);
      if (parsed) {
        findings.push(parsed);
        ctx.findings.push(parsed);
      }
    } catch {
      // Non-fatal — source analysis is best-effort enrichment
      continue;
    }
  }

  return {
    stage: "source-analysis",
    success: true,
    data: {
      findings,
      templatesAnalyzed: uniqueTemplates.length,
    },
    durationMs: Date.now() - start,
  };
}

/**
 * Parse the structured output from the source analysis agent.
 * Expects OUTCOME/FILE/LINE/EVIDENCE/ANALYSIS markers.
 */
function parseSourceAnalysisOutput(
  output: string,
  template: AttackTemplate
): Finding | null {
  const outcomeMatch = output.match(/OUTCOME:\s*(vulnerable|safe|inconclusive)/i);
  if (!outcomeMatch || outcomeMatch[1].toLowerCase() !== "vulnerable") {
    return null;
  }

  const fileMatch = output.match(/FILE:\s*(.+)/i);
  const lineMatch = output.match(/LINE:\s*(\d+)/i);
  const evidenceMatch = output.match(/EVIDENCE:\s*([\s\S]*?)(?=\nANALYSIS:|$)/i);
  const analysisMatch = output.match(/ANALYSIS:\s*([\s\S]*?)$/i);

  const location = fileMatch
    ? `${fileMatch[1].trim()}${lineMatch ? `:${lineMatch[1].trim()}` : ""}`
    : "unknown";

  return {
    id: `src-${template.id}-${Date.now()}`,
    templateId: template.id,
    title: `[Source] ${template.name} in ${location}`,
    description: analysisMatch?.[1]?.trim() ?? template.description,
    severity: template.severity as Severity,
    category: template.category as AttackCategory,
    status: "discovered",
    evidence: {
      request: `Source analysis of ${location}`,
      response: evidenceMatch?.[1]?.trim() ?? output.slice(0, 500),
      analysis: analysisMatch?.[1]?.trim(),
    },
    timestamp: Date.now(),
  };
}
