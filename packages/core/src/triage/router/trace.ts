/**
 * Routing trace emitter.
 *
 * At the end of each scan we emit one JSONL record per finding to
 * `routing-trace.jsonl` under the scan's journal sidecar directory.
 * That file is the dataset the phase-2 learned router (pwnkit#113)
 * trains on. The shape is documented in `RoutingTraceRecord` in
 * `router.ts`.
 *
 * No external dependencies — sync writes via node:fs so the function
 * is callable from the scan teardown path without async plumbing.
 */

import { mkdirSync, writeFileSync, existsSync, appendFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Finding } from "@pwnkit/shared";
import { extractRoutingFeatures } from "./features.js";
import {
  buildTraceRecord,
  type RoutingTraceRecord,
  type RoutingDecision,
} from "./router.js";

export interface TraceEmitOptions {
  /** Directory the JSONL file is written to. Created if absent. */
  outputDir: string;
  /** File name; defaults to `routing-trace.jsonl`. */
  fileName?: string;
}

/**
 * Per-finding routing decision the dispatch site retained for the
 * trace. We store the decision separately from the finding because
 * `agentic-scanner.ts` does NOT add the routing decision to the
 * finding itself (that would change the on-disk Finding schema, which
 * other consumers depend on).
 */
export interface DecisionForTrace {
  finding: Finding;
  decision: RoutingDecision;
  groundTruth?: "true_positive" | "false_positive";
}

/**
 * Write a JSONL file containing one record per finding. Overwrites any
 * existing file at the same path. Returns the absolute path written.
 */
export function emitRoutingTrace(
  scanId: string,
  decisions: DecisionForTrace[],
  options: TraceEmitOptions,
): string {
  const fileName = options.fileName ?? "routing-trace.jsonl";
  const fullPath = join(options.outputDir, fileName);

  mkdirSync(dirname(fullPath), { recursive: true });

  const lines = decisions.map((d) => {
    const features = extractRoutingFeatures(d.finding);
    const record: RoutingTraceRecord = buildTraceRecord({
      scanId,
      finding: d.finding,
      features,
      decision: d.decision,
      groundTruth: d.groundTruth,
    });
    return JSON.stringify(record);
  });

  writeFileSync(fullPath, lines.length === 0 ? "" : `${lines.join("\n")}\n`);
  return fullPath;
}

/**
 * Append a single decision to the routing trace file. Useful for
 * in-flight emission (one record per finding as it routes), rather
 * than batched at scan teardown.
 *
 * Creates the file if it doesn't exist.
 */
export function appendRoutingTraceRecord(
  scanId: string,
  decision: DecisionForTrace,
  options: TraceEmitOptions,
): string {
  const fileName = options.fileName ?? "routing-trace.jsonl";
  const fullPath = join(options.outputDir, fileName);

  mkdirSync(dirname(fullPath), { recursive: true });

  const features = extractRoutingFeatures(decision.finding);
  const record: RoutingTraceRecord = buildTraceRecord({
    scanId,
    finding: decision.finding,
    features,
    decision: decision.decision,
    groundTruth: decision.groundTruth,
  });

  const line = `${JSON.stringify(record)}\n`;
  if (existsSync(fullPath)) {
    appendFileSync(fullPath, line);
  } else {
    writeFileSync(fullPath, line);
  }
  return fullPath;
}
