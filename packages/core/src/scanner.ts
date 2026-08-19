import type { ScanConfig, ScanContext, ScanReport, PipelineStage } from "@0sec/shared";
import { loadTemplates } from "@0sec/templates";
import { createScanContext, finalize } from "./context.js";
import { createRuntime } from "./runtime/index.js";
import type { Runtime, RuntimeType } from "./runtime/index.js";
import { pickRuntimeForStage, detectAvailableRuntimes } from "./runtime/registry.js";
import { runDiscovery } from "./stages/discovery.js";
import { runSourceAnalysis } from "./stages/source-analysis.js";
import { runAttacks } from "./stages/attack.js";
import { runVerification } from "./stages/blind-reexploit.js";
import { generateReport } from "./stages/report.js";
import { eventBus } from "./events/bus.js";
// Lazy-load DB to avoid native module issues when DB isn't needed
let _db: any = null;

function isRepairableDbError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /database disk image is malformed|file is not a database|malformed|invalid page number|database main|btree|b-tree|database corrupt/i.test(message);
}

async function getDB(dbPath?: string) {
  if (!_db) {
    try {
      const { osecDB, repairOsecDatabase } = await import("@0sec/db");
      try {
        _db = new osecDB(dbPath);
      } catch (error) {
        if (!isRepairableDbError(error)) throw error;
        const repaired = repairOsecDatabase(dbPath);
        process.stderr.write(
          `[0sec] Recovered local scan database${repaired.backupPath ? ` (backup: ${repaired.backupPath})` : ""}.\n`,
        );
        _db = new osecDB(dbPath);
      }
    } catch (e) {
      console.error('Warning: database unavailable — scan results will not be persisted');
      console.error('Cause:', e);
      // DB unavailable (native module issue) — continue without persistence
      _db = null;
    }
  }
  return _db;
}

export type ScanEventType =
  | "stage:start"
  | "stage:end"
  | "attack:start"
  | "attack:end"
  | "finding"
  | "verify:result"
  | "thinking"
  | "usage"
  | "error"
  | "user:injected";

export interface ScanEvent {
  type: ScanEventType;
  stage?: string;
  message: string;
  data?: unknown;
}

export type ScanListener = (event: ScanEvent) => void;

export async function scan(
  config: ScanConfig,
  onEvent?: ScanListener,
  dbPath?: string
): Promise<ScanReport> {
  const baseEmit = onEvent ?? (() => {});
  // Wrap the user-provided ScanListener so every legacy `ScanEvent`
  // also fans out to the pluggable event bus (cloud relay, dashboard
  // tracer, test spies, …). The mapping preserves the legacy shape
  // 1:1 — the external ScanListener API is unchanged.
  const emit: ScanListener = (event) => {
    baseEmit(event);
    relayScanEventToBus(event);
  };
  const ctx: ScanContext = createScanContext(config);

  // Initialize DB for persistence (optional — graceful fallback if native module unavailable)
  const db = await getDB(dbPath);
  const scanId = db?.createScan(config) ?? "no-db";
  ctx.scanId = scanId;

  try {
  // For --runtime auto, detect available runtimes and pick per-stage
  const isAuto = config.runtime === "auto";
  let availableRuntimes: Set<RuntimeType> | undefined;
  if (isAuto) {
    availableRuntimes = await detectAvailableRuntimes();
    if (availableRuntimes.size === 0) {
      throw new Error("--runtime auto: no CLI runtimes (claude, codex, gemini) detected. Install at least one or use --runtime api.");
    }
  }

  function getRuntimeForStage(stage: PipelineStage): Runtime {
    const type = isAuto
      ? pickRuntimeForStage(stage, availableRuntimes!)
      : (config.runtime ?? "api") as RuntimeType;
    return createRuntime({ type, timeout: config.timeout ?? 30_000 });
  }

  // Default runtime for non-auto mode (and stages that don't need per-stage selection)
  const runtime = getRuntimeForStage("attack");

  // Stage 1: Discovery
  emit({ type: "stage:start", stage: "discovery", message: "Probing target..." });
  const discovery = await runDiscovery(ctx);
  emit({
    type: "stage:end",
    stage: "discovery",
    message: discovery.success
      ? `Target identified as ${ctx.target.type} (${discovery.durationMs}ms)`
      : `Discovery failed: ${discovery.error}`,
    data: discovery,
  });
  if (!discovery.success && discovery.error) {
    ctx.warnings.push({
      stage: "discovery",
      message: `Initial target validation failed: ${discovery.error}`,
    });
  }

  // Stage 1.5: Source Analysis (when --repo is provided with a process runtime)
  const templates = loadTemplates(config.depth);
  const sourceRuntime = isAuto ? getRuntimeForStage("source-analysis") : runtime;
  if (config.repoPath && sourceRuntime.type !== "api") {
    emit({
      type: "stage:start",
      stage: "source-analysis",
      message: `Analyzing source code in ${config.repoPath}${isAuto ? ` (runtime: ${sourceRuntime.type})` : ""}...`,
    });
    const sourceResult = await runSourceAnalysis(ctx, templates, sourceRuntime, config.repoPath);
    emit({
      type: "stage:end",
      stage: "source-analysis",
      message: sourceResult.data.findings.length > 0
        ? `Found ${sourceResult.data.findings.length} source-level issues across ${sourceResult.data.templatesAnalyzed} categories (${sourceResult.durationMs}ms)`
        : `No source-level issues found across ${sourceResult.data.templatesAnalyzed} categories (${sourceResult.durationMs}ms)`,
      data: sourceResult,
    });
  }

  // Stage 2: Attack
  const attackRuntime = isAuto ? getRuntimeForStage("attack") : runtime;
  emit({
    type: "stage:start",
    stage: "attack",
    message: `Running ${templates.length} templates${isAuto ? ` (runtime: ${attackRuntime.type})` : ""}...`,
  });

  const attackResult = await runAttacks(ctx, templates, attackRuntime);
  emit({
    type: "stage:end",
    stage: "attack",
    message: `Executed ${attackResult.data.payloadsRun} payloads across ${attackResult.data.templatesRun} templates (${attackResult.durationMs}ms)`,
    data: attackResult,
  });
  if (
    attackResult.data.payloadsRun > 0 &&
    attackResult.data.results.length > 0 &&
    attackResult.data.results.every((result) => result.outcome === "error")
  ) {
    const firstError = attackResult.data.results.find((result) => result.error)?.error;
    ctx.warnings.push({
      stage: "attack",
      message: firstError
        ? `All attack probes failed: ${firstError}`
        : "All attack probes failed before the target could be validated.",
    });
  }

  // Stage 3: Verify
  emit({ type: "stage:start", stage: "verify", message: "Verifying findings..." });
  const verifyResult = await runVerification(ctx, db);
  emit({
    type: "stage:end",
    stage: "verify",
    message: `${verifyResult.data.confirmed} confirmed, ${verifyResult.data.findings.length} total findings (${verifyResult.durationMs}ms)`,
    data: verifyResult,
  });

  // Persist findings to DB after verification (if DB available)
  if (db) {
    db.transaction(() => {
      db.upsertTarget(ctx.target);
      for (const finding of verifyResult.data.findings) {
        db.saveFinding(scanId, finding);
      }
      for (const result of ctx.attacks) {
        db.saveAttackResult(scanId, result);
      }
    });
  }

  // Emit individual findings
  for (const finding of verifyResult.data.findings) {
    emit({
      type: "finding",
      message: `[${finding.severity.toUpperCase()}] ${finding.title}`,
      data: finding,
    });
  }

  // Stage 4: Report
  emit({ type: "stage:start", stage: "report", message: "Generating report..." });
  finalize(ctx);
  const reportResult = await generateReport(ctx);
  emit({
    type: "stage:end",
    stage: "report",
    message: `Report generated (${reportResult.durationMs}ms)`,
    data: reportResult,
  });

  // Mark scan complete in DB (if available)
  if (db) {
    db.completeScan(scanId, reportResult.data.summary as unknown as Record<string, unknown>);
  }

  // Bus event: canonical scan_completed — picked up by the cloud relay
  // so the worker-controller can transition the pod to done, and by any
  // dashboard tracer that wants to render the final frame.
  eventBus.emit("scan_completed", {
    exit_reason: "completed",
    findings: reportResult.data.findings.length,
    duration_ms: reportResult.durationMs,
  });

  return reportResult.data;
  } finally {
    if (db) {
      db.close();
      // Reset the singleton so subsequent scans open a fresh connection
      _db = null;
    }
  }
}

/**
 * Map a legacy `ScanEvent` onto the richer bus vocabulary. This preserves
 * the existing ScanListener API 1:1 while letting bus sinks (cloud relay,
 * dashboard tracer) observe the same stage/finding/usage signal.
 */
function relayScanEventToBus(event: ScanEvent): void {
  switch (event.type) {
    case "stage:start":
      eventBus.emit("step_started", {
        step: event.stage ?? "unknown",
      });
      return;
    case "stage:end":
      eventBus.emit("step_completed", {
        step: event.stage ?? "unknown",
        message: event.message,
      });
      return;
    case "finding": {
      const f = (event.data ?? {}) as Record<string, unknown>;
      eventBus.emit("finding_ingested", {
        finding_id: typeof f.id === "string" ? f.id : undefined,
        severity: typeof f.severity === "string" ? f.severity : undefined,
        title: typeof f.title === "string" ? f.title : undefined,
        description: typeof f.description === "string" ? f.description : undefined,
        category: typeof f.category === "string" ? f.category : undefined,
        confidence:
          typeof f.confidence === "number" && Number.isFinite(f.confidence)
            ? f.confidence
            : undefined,
        evidence_request:
          typeof f.evidence_request === "string" && f.evidence_request.trim()
            ? f.evidence_request
            : undefined,
        evidence_response:
          typeof f.evidence_response === "string" && f.evidence_response.trim()
            ? f.evidence_response
            : undefined,
        evidence_analysis:
          typeof f.evidence_analysis === "string" && f.evidence_analysis.trim()
            ? f.evidence_analysis
            : undefined,
        source_path:
          typeof f.source_path === "string" && f.source_path.trim()
            ? f.source_path
            : undefined,
        source_start_line:
          typeof f.source_start_line === "number" && Number.isInteger(f.source_start_line)
            ? f.source_start_line
            : undefined,
        source_end_line:
          typeof f.source_end_line === "number" && Number.isInteger(f.source_end_line)
            ? f.source_end_line
            : undefined,
        poc_steps:
          typeof f.poc_steps === "string" && f.poc_steps.trim()
            ? f.poc_steps
            : undefined,
      });
      return;
    }
    case "usage": {
      const u = (event.data ?? {}) as Record<string, unknown>;
      const inputTokens = typeof u.inputTokens === "number" ? u.inputTokens : undefined;
      const outputTokens = typeof u.outputTokens === "number" ? u.outputTokens : undefined;
      eventBus.emit("cost_update", {
        cost_usd: typeof u.estimatedCostUsd === "number" ? u.estimatedCostUsd : undefined,
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        // Dual-spelling mirrors — the orchestrator's scan_jobs segment-sum
        // keys on token_input/token_output (see bus.ts CostUpdatePayload).
        token_input: inputTokens,
        token_output: outputTokens,
        turn: typeof u.turn === "number" ? u.turn : undefined,
      });
      return;
    }
    default:
      // thinking / attack:* / verify:result / error / user:injected have no
      // current cloud-side consumer — intentionally dropped by the relay.
      return;
  }
}
