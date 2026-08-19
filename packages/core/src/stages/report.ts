import type { ScanContext, StageResult, ScanReport, ReportSummary } from "@pwnkit/shared";

export async function generateReport(
  ctx: ScanContext
): Promise<StageResult<ScanReport>> {
  const start = Date.now();
  const completedAt = ctx.completedAt ?? Date.now();

  const summary: ReportSummary = {
    totalAttacks: ctx.attacks.length,
    totalFindings: ctx.findings.length,
    critical: ctx.findings.filter((f) => f.severity === "critical").length,
    high: ctx.findings.filter((f) => f.severity === "high").length,
    medium: ctx.findings.filter((f) => f.severity === "medium").length,
    low: ctx.findings.filter((f) => f.severity === "low").length,
    info: ctx.findings.filter((f) => f.severity === "info").length,
  };

  const report: ScanReport = {
    target: ctx.config.target,
    scanDepth: ctx.config.depth,
    startedAt: new Date(ctx.startedAt).toISOString(),
    completedAt: new Date(completedAt).toISOString(),
    durationMs: completedAt - ctx.startedAt,
    summary,
    findings: ctx.findings,
    warnings: ctx.warnings,
  };

  return {
    stage: "report",
    success: true,
    data: report,
    durationMs: Date.now() - start,
  };
}
