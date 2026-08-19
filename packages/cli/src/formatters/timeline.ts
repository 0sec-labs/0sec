/**
 * Forensic timeline renderer.
 *
 * Turns the immutable `pipeline_events` audit trail of a single scan into a
 * chronological, client-deliverable record: one row per event, each carrying a
 * UTC ISO-8601 timestamp, the pipeline stage, the agent that acted, a
 * human-readable action summary, and the MITRE technique(s) the action maps
 * to. Clients cross-reference this against their own SOC detections, so the
 * contract is deliberately narrow:
 *
 *   • Timestamps are ALWAYS UTC ISO-8601. Epoch-ms never reaches the output —
 *     a raw millisecond integer is unreadable in a report appendix and
 *     ambiguous about its timezone.
 *   • Row order is the order the events happened in. Nothing is reordered,
 *     grouped, or deduplicated: the value of an audit trail is that it is
 *     complete.
 *   • ATT&CK and ATLAS are separate fields, separate CSV columns and separate
 *     markdown columns. They are two matrices with disjoint id namespaces
 *     (`T####` vs `AML.T####`); merging them into one cell would claim
 *     coverage in a matrix the client may not run. A row may carry either,
 *     both, or neither.
 *
 * Rendering only. Reading the DB, filtering the window and deriving the action
 * summaries lives in `../commands/timeline.ts`.
 */

import type { AtlasTechnique, AttackTechnique } from "@pwnkit/core";

export type TimelineFormat = "json" | "csv" | "markdown";

export const TIMELINE_FORMATS: readonly TimelineFormat[] = ["json", "csv", "markdown"];

export function isTimelineFormat(value: string): value is TimelineFormat {
  return (TIMELINE_FORMATS as readonly string[]).includes(value);
}

/** One row of the record. `timestamp` is UTC ISO-8601 — never epoch-ms. */
export interface TimelineEntry {
  timestamp: string;
  stage: string;
  eventType: string;
  agentRole?: string;
  findingId?: string;
  /** Human-readable summary of what actually happened, derived from the payload. */
  action: string;
  /** MITRE ATT&CK (Enterprise) techniques. Never merged with `atlasTechniques`. */
  techniques: AttackTechnique[];
  /** MITRE ATLAS techniques — populated only for actions against an AI system. */
  atlasTechniques: AtlasTechnique[];
}

export interface TimelineExport {
  scanId: string;
  target?: string;
  /** UTC ISO-8601 of when the export was produced. */
  generatedAt: string;
  filters: {
    since?: string;
    until?: string;
    attackOnly: boolean;
  };
  /** Events in the export after filtering. */
  eventCount: number;
  /** Events in the scan before filtering — so a filtered export says what it dropped. */
  totalEventCount: number;
  entries: TimelineEntry[];
}

export function formatTimeline(record: TimelineExport, format: TimelineFormat): string {
  switch (format) {
    case "json":
      return formatTimelineJson(record);
    case "csv":
      return formatTimelineCsv(record);
    case "markdown":
      return formatTimelineMarkdown(record);
  }
}

// ── JSON ──

function formatTimelineJson(record: TimelineExport): string {
  return JSON.stringify(record, null, 2);
}

// ── CSV ──

const CSV_COLUMNS = [
  "timestamp",
  "stage",
  "eventType",
  "agentRole",
  "findingId",
  "action",
  "attackTechniqueIds",
  "attackTactics",
  // Appended, never interleaved with the ATT&CK columns — an importer that
  // only knows the ATT&CK pair keeps working, and the two taxonomies stay
  // visibly distinct in a spreadsheet.
  "atlasTechniqueIds",
  "atlasTactics",
] as const;

function formatTimelineCsv(record: TimelineExport): string {
  const lines = [CSV_COLUMNS.join(",")];
  for (const entry of record.entries) {
    lines.push(
      [
        entry.timestamp,
        entry.stage,
        entry.eventType,
        entry.agentRole ?? "",
        entry.findingId ?? "",
        entry.action,
        entry.techniques.map((t) => t.id).join(" "),
        uniq(entry.techniques.map((t) => t.tactic)).join(" "),
        entry.atlasTechniques.map((t) => t.id).join(" "),
        uniq(entry.atlasTechniques.map((t) => t.tactic)).join(" "),
      ]
        .map(csvCell)
        .join(","),
    );
  }
  // Trailing newline: an empty scan still produces a valid, parseable
  // single-header CSV rather than a bare unterminated line.
  return lines.join("\n") + "\n";
}

/** RFC 4180 quoting — quote when the cell holds a comma, quote, CR or LF. */
function csvCell(value: string): string {
  if (!/[",\r\n]/.test(value)) return value;
  return `"${value.replace(/"/g, '""')}"`;
}

// ── Markdown ──

function formatTimelineMarkdown(record: TimelineExport): string {
  const out: string[] = [];
  out.push(`# Forensic timeline — scan \`${record.scanId}\``);
  out.push("");
  if (record.target) out.push(`- **Target:** ${record.target}`);
  out.push(`- **Generated:** ${record.generatedAt}`);
  out.push(`- **Events:** ${record.eventCount} of ${record.totalEventCount} recorded`);
  if (record.filters.since) out.push(`- **Since:** ${record.filters.since}`);
  if (record.filters.until) out.push(`- **Until:** ${record.filters.until}`);
  if (record.filters.attackOnly) {
    out.push(`- **Filter:** technique-mapped events only (pipeline lifecycle events omitted)`);
  }
  out.push("");
  out.push("All timestamps are UTC (ISO-8601).");
  out.push("");
  out.push(
    "ATT&CK (Enterprise) and ATLAS (AI systems) are separate matrices; a row may carry either, both, or neither.",
  );
  out.push("");

  if (record.entries.length === 0) {
    out.push("_No pipeline events recorded for this scan in the selected window._");
    out.push("");
    return out.join("\n");
  }

  out.push("| # | Timestamp (UTC) | Stage | Event | Agent | Finding | Action | ATT&CK | ATLAS |");
  out.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  record.entries.forEach((entry, i) => {
    out.push(
      "| " +
        [
          String(i + 1),
          entry.timestamp,
          mdCell(entry.stage),
          mdCell(entry.eventType),
          mdCell(entry.agentRole ?? "—"),
          mdCell(entry.findingId ?? "—"),
          mdCell(entry.action),
          mdTechniques(entry.techniques),
          mdTechniques(entry.atlasTechniques),
        ].join(" | ") +
        " |",
    );
  });
  out.push("");
  return out.join("\n");
}

function mdTechniques(techniques: Array<AttackTechnique | AtlasTechnique>): string {
  return techniques.length > 0 ? techniques.map(mdTechnique).join(", ") : "—";
}

function mdTechnique(technique: AttackTechnique | AtlasTechnique): string {
  const label = mdCell(`${technique.id} ${technique.name}`);
  return technique.url ? `[${label}](${technique.url})` : label;
}

/** Collapse whitespace and neutralise the two characters that break a table cell. */
function mdCell(value: string): string {
  return value.replace(/\s+/g, " ").replace(/\|/g, "\\|").trim();
}

function uniq(values: string[]): string[] {
  return [...new Set(values.filter((v) => v.length > 0))];
}
