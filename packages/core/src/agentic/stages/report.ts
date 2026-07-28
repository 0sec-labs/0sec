import type { ScanConfig, ScanReport, Finding } from "@pwnkit/shared";
import type { ScanListener } from "../../scanner.js";
import type { AgentOutput } from "../../agentic-scanner.js";
import { features } from "../../agent/features.js";
import { appendRoutingTraceRecord, type RoutingDecision } from "../../triage/index.js";
import { resolveJournalPaths } from "../../agent/journal/writer.js";
import { postFinalReport } from "../../cloud-sink.js";

/**
 * Inputs the report stage reads from the scan closure. Everything here is
 * produced by the earlier stages (discovery, attack, triage, verify) and is
 * read-only from the report stage's perspective — the stage assembles the
 * final `ScanReport` and drains the terminal events; it does not mutate the
 * scan's finding set.
 */
export interface ReportStageState {
  allFindings: Finding[];
  attackState: AgentOutput;
  discoveryState: AgentOutput;
  config: ScanConfig;
  scanId: string;
  routingDecisions: Map<string, RoutingDecision>;
}

/**
 * Signature of `agenticScan`'s `emitScanCompleted` closure. It closes over the
 * scan's event bus, start time, and per-scan metrics tally, so it cannot be
 * moved out of the scanner — the report stage receives it via `ctx`.
 */
export type EmitScanCompleted = (
  exit_reason: "completed" | "failed" | "cost_exceeded" | "max_turns" | "early_stop",
  findings_count: number,
  metrics?: {
    turnsUsed?: number;
    summary?: string;
    stages?: Array<{
      usage: {
        inputTokens: number;
        outputTokens: number;
        cachedInputTokens?: number;
      };
      model?: string;
    }>;
    flagsExtracted?: number;
    findingsForFlagCount?: Finding[];
  },
) => void;

/**
 * Side-effecting collaborators the report stage needs but that stay owned by
 * the scanner: the per-scan DB handle, the event listener, the terminal
 * `scan_completed` emitter, and the http_audit enforcement-summary attacher
 * (which reads the scanner's per-config enforcement cache).
 */
export interface ReportStageCtx {
  db: any;
  emit: ScanListener;
  emitScanCompleted: EmitScanCompleted;
  attachEnforcementSummary: (report: ScanReport, config: ScanConfig) => void;
  /**
   * Attaches the engagement-posture audit record when a hardening profile was
   * applied (`scope/engagement-profile.ts`). Optional so existing callers /
   * fixtures that build a ctx without it keep working — a scan that never
   * requested a profile has nothing to attach anyway.
   */
  attachEngagementPosture?: (report: ScanReport, config: ScanConfig) => void;
}

/**
 * Stage 4: Report. Assembles the final `ScanReport` from the accumulated
 * findings and per-stage agent output, persists scan completion, emits the
 * routing-trace dataset, streams the report to the opt-in webhook sink, and
 * fires the terminal `scan_completed` event. Behaviour-preserving extraction
 * of the inline Stage 4 block from `agenticScan`.
 */
export async function runReportStage(
  state: ReportStageState,
  ctx: ReportStageCtx,
): Promise<ScanReport> {
  const { allFindings, attackState, discoveryState, config, scanId, routingDecisions } = state;
  const { db, emit, emitScanCompleted, attachEnforcementSummary } = ctx;

  emit({ type: "stage:start", stage: "report", message: "Generating report..." });

  const confirmed = allFindings.filter(
    (f) => f.status !== "false-positive" && f.status !== "discovered",
  ).length;
  const summary = {
    totalAttacks: attackState.turnCount,
    totalFindings: allFindings.length,
    critical: allFindings.filter((f) => f.severity === "critical").length,
    high: allFindings.filter((f) => f.severity === "high").length,
    medium: allFindings.filter((f) => f.severity === "medium").length,
    low: allFindings.filter((f) => f.severity === "low").length,
    info: allFindings.filter((f) => f.severity === "info").length,
  };

  db.completeScan(scanId, summary);

  // ── Routing trace emission (pwnkit#113 dataset) ──
  // When dynamic triage routing was enabled, dump one record per
  // finding to `routing-trace.jsonl` under the journal sidecar dir
  // so the offline learned-router trainer can pick it up.
  if (features.dynamicTriageRouting && routingDecisions.size > 0) {
    try {
      const { runDir } = resolveJournalPaths({ runId: scanId });
      for (const finding of allFindings) {
        const decision = routingDecisions.get(finding.id);
        if (!decision) continue;
        appendRoutingTraceRecord(
          scanId,
          { finding, decision },
          { outputDir: runDir },
        );
      }
    } catch (err) {
      // Trace emission is best-effort — never fail a scan over it.
      db.logEvent?.({
        scanId,
        stage: "report",
        eventType: "routing_trace_emit_error",
        payload: { error: (err as Error).message },
        timestamp: Date.now(),
      });
    }
  }

  const report: ScanReport = {
    target: config.target,
    scanDepth: config.depth,
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    durationMs: 0,
    summary,
    findings: allFindings.filter((f) => f.status !== "false-positive"),
    warnings: [],
    benchmarkMeta: {
      attackTurns: attackState.turnCount,
      estimatedCostUsd: attackState.estimatedCostUsd,
      inputTokens: attackState.totalUsage?.inputTokens,
      outputTokens: attackState.totalUsage?.outputTokens,
      totalTokens:
        attackState.totalUsage
          ? attackState.totalUsage.inputTokens + attackState.totalUsage.outputTokens
          : undefined,
      model: config.model,
    },
  };
  attachEnforcementSummary(report, config);
  ctx.attachEngagementPosture?.(report, config);

  // Attach conversation trace (discovery + attack) when available.
  // Only native-mode runs produce messages; legacy CLI runs don't.
  const traceMessages = [
    ...(discoveryState.messages ?? []),
    ...(attackState.messages ?? []),
  ];
  if (traceMessages.length > 0) {
    report.trace = traceMessages;
  }

  // Compute actual duration from DB
  const dbScan = db.getScan(scanId);
  if (dbScan) {
    report.startedAt = dbScan.startedAt;
    report.completedAt = dbScan.completedAt ?? report.completedAt;
    report.durationMs = dbScan.durationMs ?? 0;
  }

  db.logEvent({
    scanId,
    stage: "report",
    eventType: "scan_complete",
    payload: { ...summary, durationMs: report.durationMs },
    timestamp: Date.now(),
  });

  emit({
    type: "stage:end",
    stage: "report",
    message: `Report: ${summary.totalFindings} findings (${confirmed} confirmed)`,
  });

  // Stream final report to the opt-in webhook sink (no-op when unset).
  await postFinalReport(report);

  // If either stage's agent loop bailed because the planner LLM
  // returned an error (e.g. transient Azure OpenAI 5xx), the loop
  // already drained and produced an empty/partial report — but the
  // exit_reason MUST surface as "failed" to the cloud, not
  // "completed". Without this, the cloud persists status='complete'
  // and shows the raw "Error: ..." string as the scan summary,
  // mislabeling a legitimate failure as a clean pass. See
  // pwnkit-cloud scan 3abdf5b7-873d-449b-ab3f-e9a38f05a778 for the
  // reproducer that motivated this branch.
  // Build per-(stage, model) usage records once — both planError and
  // happy paths consume the same shape. We pull from each
  // AgentOutput's `totalUsage`, falling back to inferring tokens from
  // `estimatedCostUsd` is NOT done because we'd lose the in/out split.
  // Stages with no usage (legacy CLI runtime) are skipped by
  // `emitScanCompleted` itself.
  const stages = [
    ...(discoveryState
      ? [{ usage: discoveryState.totalUsage ?? { inputTokens: 0, outputTokens: 0 }, model: config.model }]
      : []),
    ...(attackState
      ? [{ usage: attackState.totalUsage ?? { inputTokens: 0, outputTokens: 0 }, model: config.model }]
      : []),
  ];

  const planError = attackState?.errorExit ?? discoveryState?.errorExit;
  if (planError) {
    emitScanCompleted("failed", report.findings.length, {
      turnsUsed:
        (discoveryState?.turnCount ?? 0) + (attackState?.turnCount ?? 0),
      summary: planError.error,
      stages,
      findingsForFlagCount: report.findings,
    });
  } else {
    emitScanCompleted("completed", report.findings.length, {
      turnsUsed:
        (discoveryState?.turnCount ?? 0) + (attackState?.turnCount ?? 0),
      // `attackState.summary` is the loop's free-text narrative
      // ("Audited lodash, no exploitable sinks found"). `report.summary`
      // is severity counts ({critical, high, medium, low, info}), not
      // narrative — it goes to `findings` field instead.
      summary: attackState?.summary ?? discoveryState?.summary,
      stages,
      findingsForFlagCount: report.findings,
    });
  }
  return report;
}
