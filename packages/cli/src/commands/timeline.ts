/**
 * `pwnkit timeline <scanId>` — forensic timeline export.
 *
 * Every other command in the CLI is finding-centric: it answers "what did we
 * find?". This one answers "what did we DO, and when?" — the question a client
 * SOC asks when it wants to line our activity up against its own detections
 * after an engagement.
 *
 * The data is already there and already immutable: `pipeline_events` is the
 * audit trail the engine writes as it runs, and `db.getEvents(scanId)` returns
 * it in timestamp order. This command reads it, derives a human-readable
 * action summary per event, tags each with MITRE ATT&CK techniques, and renders
 * it as markdown (report appendix), CSV (spreadsheet / SIEM import) or JSON.
 *
 * Read-only. It opens the database, reads, and closes. It never writes to the
 * audit trail it is exporting.
 */

import type { Command } from "commander";
import chalk from "chalk";
import { techniquesForEvent, type AttackTechnique } from "@pwnkit/core";
import {
  formatTimeline,
  isTimelineFormat,
  TIMELINE_FORMATS,
  type TimelineEntry,
  type TimelineExport,
} from "../formatters/timeline.js";

/** Row shape of `pipeline_events` as returned by `pwnkitDB.getEvents`. */
export interface TimelineEventRow {
  id?: string;
  scanId?: string;
  stage: string;
  eventType: string;
  findingId?: string | null;
  agentRole?: string | null;
  payload: string;
  timestamp: number;
}

/**
 * `tool_calls` records only tool *names*; the matching `tool_artifact` carries
 * the URL / method / command that actually went out. There is no correlation id
 * between them, so we match on (same scan, same tool name, adjacent timestamp).
 * The artifact is written inside the tool call and the `tool_calls` event after
 * the turn's tools have all run, so a few seconds of slack covers it. This is
 * best-effort enrichment of a summary string — a miss costs detail, never
 * correctness, and both rows are emitted either way.
 */
const ARTIFACT_MATCH_WINDOW_MS = 5_000;

/** Action summaries live in a table cell; past this length they stop being readable. */
const MAX_ACTION_LENGTH = 400;

interface TimelineOptions {
  format?: string;
  since?: string;
  until?: string;
  attackOnly?: boolean;
  dbPath?: string;
}

export function registerTimelineCommand(program: Command): void {
  program
    .command("timeline")
    .description(
      "Export a scan's immutable pipeline-event audit trail as a chronological, MITRE ATT&CK-tagged forensic record — UTC ISO-8601 timestamps, per-event action summaries, ready to hand to a client SOC for detection cross-referencing.",
    )
    .argument("<scanId>", "Scan id to export (see `pwnkit history`)")
    .option("--format <format>", `Output format: ${TIMELINE_FORMATS.join(", ")}`, "markdown")
    .option("--since <iso>", "Only include events at or after this timestamp (ISO-8601, e.g. 2026-07-28T09:00:00Z)")
    .option("--until <iso>", "Only include events at or before this timestamp (ISO-8601)")
    .option(
      "--attack-only",
      "Only include events that map to a MITRE ATT&CK technique, dropping pipeline lifecycle noise",
    )
    .option("--db-path <path>", "Path to SQLite database")
    .action(async (scanId: string, opts: TimelineOptions) => {
      const id = scanId?.trim();
      if (!id) {
        console.error(chalk.red("Invalid <scanId>: expected a non-empty scan id."));
        process.exitCode = 2;
        return;
      }

      const format = (opts.format ?? "markdown").trim().toLowerCase();
      if (!isTimelineFormat(format)) {
        console.error(chalk.red(`Invalid --format '${opts.format}': expected one of ${TIMELINE_FORMATS.join(", ")}.`));
        process.exitCode = 2;
        return;
      }

      let sinceMs: number | undefined;
      let untilMs: number | undefined;
      try {
        sinceMs = parseInstant(opts.since, "--since");
        untilMs = parseInstant(opts.until, "--until");
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exitCode = 2;
        return;
      }
      if (sinceMs !== undefined && untilMs !== undefined && sinceMs > untilMs) {
        console.error(chalk.red(`Empty window: --since ${opts.since} is after --until ${opts.until}.`));
        process.exitCode = 2;
        return;
      }

      const { pwnkitDB } = await import("@pwnkit/db");
      const db = new pwnkitDB(opts.dbPath);
      let scan: { id: string; target?: string | null } | undefined;
      let rows: TimelineEventRow[];
      try {
        scan = db.getScan(id) as { id: string; target?: string | null } | undefined;
        if (!scan) {
          console.error(
            chalk.red(`No scan '${id}' in the database. Run \`pwnkit history\` to list known scan ids.`),
          );
          process.exitCode = 2;
          return;
        }
        rows = db.getEvents(id) as TimelineEventRow[];
      } finally {
        db.close();
      }

      const entries = buildTimelineEntries(rows, {
        sinceMs,
        untilMs,
        attackOnly: opts.attackOnly === true,
      });

      const record: TimelineExport = {
        scanId: id,
        ...(scan.target ? { target: scan.target } : {}),
        generatedAt: toUtcIso(Date.now()),
        filters: {
          ...(sinceMs !== undefined ? { since: toUtcIso(sinceMs) } : {}),
          ...(untilMs !== undefined ? { until: toUtcIso(untilMs) } : {}),
          attackOnly: opts.attackOnly === true,
        },
        eventCount: entries.length,
        totalEventCount: rows.length,
        entries,
      };

      console.log(formatTimeline(record, format).trimEnd());
    });
}

// ── Entry construction ──

export interface BuildTimelineOptions {
  sinceMs?: number;
  untilMs?: number;
  attackOnly?: boolean;
}

/**
 * Rows → timeline entries. Exported for tests and for any future caller (an
 * evidence pack, the cloud report renderer) that wants the same record without
 * the CLI wrapper around it.
 *
 * `getEvents` already sorts by timestamp; we sort again defensively because the
 * whole value proposition of this output is that the order is the truth.
 */
export function buildTimelineEntries(
  rows: TimelineEventRow[],
  opts: BuildTimelineOptions = {},
): TimelineEntry[] {
  const ordered = [...rows].sort((a, b) => a.timestamp - b.timestamp);
  // Indexed over every row, not just the in-window ones: an artifact written
  // moments before the window opens can still explain the first tool call in it.
  const artifacts = indexArtifacts(ordered);

  const entries: TimelineEntry[] = [];
  for (const row of ordered) {
    if (opts.sinceMs !== undefined && row.timestamp < opts.sinceMs) continue;
    if (opts.untilMs !== undefined && row.timestamp > opts.untilMs) continue;

    const payload = parsePayload(row.payload);
    const techniques = techniquesForRow(row.eventType, payload);
    if (opts.attackOnly === true && techniques.length === 0) continue;

    entries.push({
      timestamp: toUtcIso(row.timestamp),
      stage: row.stage,
      eventType: row.eventType,
      ...(row.agentRole ? { agentRole: row.agentRole } : {}),
      ...(row.findingId ? { findingId: row.findingId } : {}),
      action: truncate(describeEvent(row, payload, artifacts), MAX_ACTION_LENGTH),
      techniques,
    });
  }
  return entries;
}

function techniquesForRow(eventType: string, payload: Record<string, unknown>): AttackTechnique[] {
  const tools = toolNames(payload);
  if (tools.length === 0) return techniquesForEvent(eventType);

  const seen = new Set<string>();
  const out: AttackTechnique[] = [];
  for (const tool of tools) {
    for (const technique of techniquesForEvent(eventType, tool)) {
      if (seen.has(technique.id)) continue;
      seen.add(technique.id);
      out.push(technique);
    }
  }
  return out;
}

/** `tool_artifact` names one tool; `tool_calls` lists the tools of a whole turn. */
function toolNames(payload: Record<string, unknown>): string[] {
  const single = str(payload.tool);
  if (single) return [single];
  return strArray(payload.tools);
}

// ── tool_artifact correlation ──

interface ArtifactRecord {
  timestamp: number;
  tool: string;
  payload: Record<string, unknown>;
  claimed: boolean;
}

function indexArtifacts(rows: TimelineEventRow[]): Map<string, ArtifactRecord[]> {
  const index = new Map<string, ArtifactRecord[]>();
  for (const row of rows) {
    if (row.eventType !== "tool_artifact") continue;
    const payload = parsePayload(row.payload);
    const tool = str(payload.tool);
    if (!tool) continue;
    const bucket = index.get(tool) ?? [];
    bucket.push({ timestamp: row.timestamp, tool, payload, claimed: false });
    index.set(tool, bucket);
  }
  return index;
}

/** Nearest not-yet-used artifact for `tool` within the match window, if any. */
function claimArtifact(
  index: Map<string, ArtifactRecord[]>,
  tool: string,
  timestamp: number,
): ArtifactRecord | undefined {
  const bucket = index.get(tool);
  if (!bucket) return undefined;
  let best: ArtifactRecord | undefined;
  let bestDelta = Number.POSITIVE_INFINITY;
  for (const artifact of bucket) {
    if (artifact.claimed) continue;
    const delta = Math.abs(artifact.timestamp - timestamp);
    if (delta > ARTIFACT_MATCH_WINDOW_MS) continue;
    if (delta < bestDelta) {
      best = artifact;
      bestDelta = delta;
    }
  }
  if (best) best.claimed = true;
  return best;
}

// ── Action summaries ──

function describeEvent(
  row: TimelineEventRow,
  payload: Record<string, unknown>,
  artifacts: Map<string, ArtifactRecord[]>,
): string {
  switch (row.eventType) {
    case "tool_artifact":
      return describeArtifact(payload);
    case "tool_calls":
      return describeToolCalls(row, payload, artifacts);
    case "scan_start": {
      const bits = [
        str(payload.target) ? `target ${str(payload.target)}` : undefined,
        str(payload.depth) ? `depth ${str(payload.depth)}` : undefined,
        str(payload.mode) ? `mode ${str(payload.mode)}` : undefined,
      ].filter(isPresent);
      return `Scan started${bits.length > 0 ? ` (${bits.join(", ")})` : ""}`;
    }
    case "scan_complete": {
      const total = num(payload.totalFindings);
      const duration = num(payload.durationMs);
      const bits = [
        total !== undefined ? `${total} finding(s)` : undefined,
        duration !== undefined ? `${Math.round(duration / 1000)}s` : undefined,
      ].filter(isPresent);
      return `Scan completed${bits.length > 0 ? ` — ${bits.join(", ")}` : ""}`;
    }
    case "scan_error":
    case "agent_error":
      return `Error: ${str(payload.error) ?? summarizePayload(payload)}`;
    case "scan_aborted":
      return `Scan aborted${str(payload.reason) ? `: ${str(payload.reason)}` : ""}`;
    case "scan_resumed":
      return `Scan resumed${summarySuffix(payload)}`;
    case "stage_start":
      return `Stage '${row.stage}' started${summarySuffix(payload)}`;
    case "stage_complete": {
      const findings = num(payload.findingCount);
      const detail = [
        findings !== undefined ? `${findings} finding(s)` : undefined,
        str(payload.summary),
      ].filter(isPresent);
      // Stage payloads are heterogeneous (`verified`/`falsePositive` here,
      // scanner counts there) — fall back to the generic scalar rendering so a
      // stage's own numbers are never dropped from the record.
      const rendered = detail.length > 0 ? detail.join(": ") : summarizePayload(payload);
      return `Stage '${row.stage}' completed${rendered ? ` — ${rendered}` : ""}`;
    }
    case "agent_start": {
      const maxTurns = num(payload.maxTurns);
      const toolCount = num(payload.toolCount);
      const bits = [
        maxTurns !== undefined ? `max ${maxTurns} turns` : undefined,
        toolCount !== undefined ? `${toolCount} tools` : undefined,
      ].filter(isPresent);
      return `${row.agentRole ?? "Agent"} agent started${bits.length > 0 ? ` (${bits.join(", ")})` : ""}`;
    }
    case "agent_complete": {
      const turns = num(payload.turnCount);
      const findings = num(payload.findingCount);
      const bits = [
        turns !== undefined ? `${turns} turn(s)` : undefined,
        findings !== undefined ? `${findings} finding(s)` : undefined,
        str(payload.summary),
      ].filter(isPresent);
      return `${row.agentRole ?? "Agent"} agent completed${bits.length > 0 ? ` — ${bits.join(", ")}` : ""}`;
    }
    default: {
      const summary = summarizePayload(payload);
      return summary ? `${row.eventType}: ${summary}` : row.eventType;
    }
  }
}

function describeArtifact(payload: Record<string, unknown>): string {
  const tool = str(payload.tool) ?? "tool";
  const detail = artifactDetail(payload);
  return detail ? `${tool}: ${detail}` : `${tool}${summarySuffix(payload)}`;
}

/**
 * The operative half of a `tool_artifact` payload — the request that left the
 * machine. Shapes vary per tool (`request.{url,method}`, `command`, `argv`,
 * `startUrl`, `action`), so pull whichever is present rather than switching on
 * every one of the ~18 call sites.
 */
function artifactDetail(payload: Record<string, unknown>): string | undefined {
  const request = obj(payload.request);
  const response = obj(payload.response);
  const bits: string[] = [];

  const command = str(payload.command);
  const url = str(request?.url) ?? str(payload.url) ?? str(payload.startUrl) ?? str(payload.target);
  const method = str(request?.method);
  const scanner = str(payload.scanner) ?? str(payload.binary);
  const argv = strArray(payload.argv);
  const action = str(payload.action);

  if (command) bits.push(command);
  else if (url) bits.push(`${method ? `${method} ` : ""}${url}`);
  else if (scanner) bits.push([scanner, ...argv].join(" "));
  else if (action) bits.push(action);

  const status = num(response?.status);
  if (status !== undefined) bits.push(`→ HTTP ${status}`);
  const pages = num(payload.pagesVisited);
  if (pages !== undefined) bits.push(`→ ${pages} page(s)`);
  const error = str(payload.error);
  if (error) bits.push(`→ error: ${error}`);
  if (payload.timedOut === true) bits.push("→ timed out");

  return bits.length > 0 ? bits.join(" ") : undefined;
}

function describeToolCalls(
  row: TimelineEventRow,
  payload: Record<string, unknown>,
  artifacts: Map<string, ArtifactRecord[]>,
): string {
  const tools = strArray(payload.tools);
  const turn = num(payload.turn);
  const actor = row.agentRole ?? "Agent";
  const head = `${actor} invoked ${tools.length > 0 ? tools.join(", ") : "no tools"}${
    turn !== undefined ? ` (turn ${turn})` : ""
  }`;

  // Prefer the richer artifact detail when one sits next to this turn.
  const details: string[] = [];
  for (const tool of tools) {
    const artifact = claimArtifact(artifacts, tool, row.timestamp);
    const detail = artifact ? artifactDetail(artifact.payload) : undefined;
    if (detail) details.push(`${tool}: ${detail}`);
    if (details.length >= 2) break;
  }

  const failures = (Array.isArray(payload.results) ? payload.results : [])
    .map((r) => str(obj(r)?.error))
    .filter(isPresent);

  const tail = [
    details.length > 0 ? details.join("; ") : undefined,
    failures.length > 0 ? `${failures.length} failed: ${failures[0]}` : undefined,
  ].filter(isPresent);

  return tail.length > 0 ? `${head} — ${tail.join(" — ")}` : head;
}

function summarySuffix(payload: Record<string, unknown>): string {
  const summary = summarizePayload(payload);
  return summary ? ` — ${summary}` : "";
}

/** Compact `k=v` rendering of a payload's scalar fields, for event types we have no bespoke wording for. */
function summarizePayload(payload: Record<string, unknown>): string {
  const bits: string[] = [];
  for (const [key, value] of Object.entries(payload)) {
    if (bits.length >= 6) break;
    if (value === null || value === undefined) continue;
    if (typeof value === "string") {
      if (value.trim().length === 0) continue;
      bits.push(`${key}=${truncate(value.trim(), 120)}`);
    } else if (typeof value === "number" || typeof value === "boolean") {
      bits.push(`${key}=${value}`);
    } else if (Array.isArray(value)) {
      bits.push(`${key}=[${value.length}]`);
    }
  }
  return bits.join(", ");
}

// ── Small helpers ──

/**
 * The one formatting rule the whole command exists to uphold: what the client
 * sees is a UTC ISO-8601 instant, never the epoch-ms the DB stores.
 */
function toUtcIso(epochMs: number): string {
  return new Date(epochMs).toISOString();
}

function parseInstant(value: string | undefined, flag: string): number | undefined {
  if (value === undefined) return undefined;
  const parsed = Date.parse(value.trim());
  if (!Number.isFinite(parsed)) {
    throw new Error(`Invalid ${flag} '${value}': expected an ISO-8601 timestamp, e.g. 2026-07-28T09:00:00Z.`);
  }
  return parsed;
}

function parsePayload(raw: string | undefined): Record<string, unknown> {
  if (!raw) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : { value: parsed };
  } catch {
    // A malformed payload is itself audit-relevant — keep it visible rather
    // than silently rendering the row as an empty action.
    return { unparsedPayload: truncate(raw, 200) };
  }
}

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

function isPresent<T>(value: T | undefined): value is T {
  return value !== undefined;
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function num(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function obj(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function strArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((v) => str(v)).filter(isPresent);
}
