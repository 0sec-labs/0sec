import type { Command } from "commander";
import chalk from "chalk";
import { renderReplay } from "../formatters/replay.js";
import { writePresentationErrorLine } from "../presentation/process-output.js";

export async function replayScan(opts: { dbPath?: string; scan?: string }): Promise<void> {
  const { osecDB } = await import("@0sec/db");
  const db = new osecDB(opts.dbPath);
  const requestedScan = opts.scan;

  let scanRecord;
  if (requestedScan) {
    scanRecord = db.getScan(requestedScan);
    if (!scanRecord) {
      const all = db.listScans(100);
      scanRecord = all.find((s: { id: string }) => s.id.startsWith(requestedScan));
    }
    if (!scanRecord) {
      db.close();
      throw new Error(`Scan '${requestedScan}' not found.`);
    }
  } else {
    const scans = db.listScans(1);
    if (scans.length === 0) {
      db.close();
      throw new Error("No scan history found. Run a scan first.");
    }
    scanRecord = scans[0];
  }

  const dbFindings = db.getFindings(scanRecord.id);
  const target = db.getTarget(scanRecord.target);
  db.close();

  const summary = scanRecord.summary ? JSON.parse(scanRecord.summary) : {
    totalAttacks: 0, totalFindings: 0,
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };

  const findings = dbFindings.map((f) => ({
    id: f.id,
    templateId: f.templateId,
    title: f.title,
    description: f.description,
    severity: f.severity as import("@0sec/shared").Severity,
    category: f.category as import("@0sec/shared").AttackCategory,
    status: f.status as import("@0sec/shared").FindingStatus,
    evidence: {
      request: f.evidenceRequest,
      response: f.evidenceResponse,
      analysis: f.evidenceAnalysis ?? undefined,
    },
    timestamp: f.timestamp,
  }));

  const targetInfo = target
    ? {
        url: target.url,
        type: target.type as import("@0sec/shared").TargetInfo["type"],
        systemPrompt: target.systemPrompt ?? undefined,
        detectedFeatures: target.detectedFeatures
          ? JSON.parse(target.detectedFeatures)
          : undefined,
        endpoints: target.endpoints ? JSON.parse(target.endpoints) : undefined,
      }
    : undefined;

  await renderReplay({
    target: scanRecord.target,
    targetInfo,
    findings,
    summary,
    durationMs: scanRecord.durationMs ?? 0,
  });
}

export function registerReplayCommand(program: Command): void {
  program
    .command("replay")
    .description("Replay the last scan's attack chain as an animated terminal sequence")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--scan <scanId>", "Replay a specific scan by ID (default: last scan)")
    .action(async (opts) => {
      try {
        const { isBunRuntime, canUseOpenTui } = await import("../tui/runtime.js");
        if (isBunRuntime() && canUseOpenTui()) {
          const { showOpenTuiReplay } = await import("../tui/run.js");
          await showOpenTuiReplay({ dbPath: opts.dbPath as string | undefined, scanId: opts.scan as string | undefined });
          return;
        }
        await replayScan(opts);
      } catch (err) {
        console.error(
          chalk.red("Failed to replay: " + (err instanceof Error ? err.message : String(err)))
        );
        process.exit(2);
      }
    });
}
