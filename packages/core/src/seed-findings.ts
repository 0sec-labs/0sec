/**
 * Parser for external "seed" leads supplied to `0sec review --seed-findings`.
 *
 * GemmaForge is the current first-class producer (`gemmaforge scan`,
 * schema id `gemmaforge.leads/v1`). The parser is intentionally permissive
 * about on-wire field names so a v2 producer can ship without forcing a
 * 0sec release.
 *
 * Closes 0sec#368 once these are wired into the review agent's worklist.
 */
import { readFileSync } from "node:fs";
import type { SeedFinding } from "@0sec/shared";

export const GEMMAFORGE_LEADS_SCHEMA = "gemmaforge.leads/v1";

export interface ParseSeedFindingsOptions {
  /** Override the producer tag attached to each parsed seed. */
  defaultSource?: string;
}

/**
 * Parse ND-JSON text into validated {@link SeedFinding} records.
 * Lines that are blank or fail validation are skipped with a `console.warn`
 * — partial-failure is preferred to a hard abort, because a producer
 * adding a new field shouldn't bring down a scan.
 */
export function parseSeedFindings(
  ndjson: string,
  opts: ParseSeedFindingsOptions = {},
): SeedFinding[] {
  const out: SeedFinding[] = [];
  const lines = ndjson.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!.trim();
    if (!raw) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      console.warn(`[seed-findings] line ${i + 1}: invalid JSON — skipped`);
      continue;
    }
    const seed = normaliseRecord(parsed, opts.defaultSource);
    if (seed) out.push(seed);
    else console.warn(`[seed-findings] line ${i + 1}: missing required fields — skipped`);
  }
  return out;
}

/** Read a path (or `-` for stdin) and parse it. */
export function readSeedFindings(
  pathOrDash: string,
  opts: ParseSeedFindingsOptions = {},
): SeedFinding[] {
  const text =
    pathOrDash === "-"
      ? readFileSync(0, "utf-8") // stdin
      : readFileSync(pathOrDash, "utf-8");
  return parseSeedFindings(text, opts);
}

// ---------------- internals ---------------- //

function normaliseRecord(rec: unknown, defaultSource?: string): SeedFinding | null {
  if (!rec || typeof rec !== "object") return null;
  const o = rec as Record<string, unknown>;
  const schema = typeof o.schema === "string" ? o.schema : undefined;

  const file = typeof o.file === "string" ? o.file : undefined;
  const startLine = pickInt(o.start_line, o.startLine);
  const endLine = pickInt(o.end_line, o.endLine);
  const snippet = typeof o.snippet === "string" ? o.snippet : undefined;
  if (!file || !snippet || startLine === undefined || endLine === undefined) return null;

  const cwe = pickString(o.cwe, o.gemmaforge_top_cwe);

  // confidence: prefer producer-namespaced field, then generic.
  const confidence =
    pickNumber(o.gemmaforge_confidence, o.confidence) ?? undefined;

  // Source provenance. The schema id encodes the producer canonically;
  // explicit `source` wins if both present.
  const source =
    pickString(o.source)
    ?? schemaToSource(schema)
    ?? defaultSource
    ?? "external";

  // Preserve every producer-specific field that isn't already a first-class
  // SeedFinding member. Lets the renderer cite gemmaforge_layer etc. later.
  const reserved = new Set([
    "schema", "file", "start_line", "startLine", "end_line", "endLine",
    "snippet", "cwe", "confidence", "claim", "source", "metadata",
  ]);
  const extra: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) {
    if (!reserved.has(k)) extra[k] = v;
  }
  const explicitMetadata =
    o.metadata && typeof o.metadata === "object"
      ? (o.metadata as Record<string, unknown>)
      : {};
  const metadata = { ...explicitMetadata, ...extra };

  return {
    file,
    startLine,
    endLine,
    snippet,
    cwe,
    confidence,
    claim: pickString(o.claim),
    source,
    metadata: Object.keys(metadata).length > 0 ? metadata : undefined,
  };
}

function pickInt(...candidates: unknown[]): number | undefined {
  for (const c of candidates) {
    if (typeof c === "number" && Number.isInteger(c) && c >= 0) return c;
  }
  return undefined;
}

function pickNumber(...candidates: unknown[]): number | undefined {
  for (const c of candidates) {
    if (typeof c === "number" && Number.isFinite(c)) return c;
  }
  return undefined;
}

function pickString(...candidates: unknown[]): string | undefined {
  for (const c of candidates) {
    if (typeof c === "string" && c.length > 0) return c;
  }
  return undefined;
}

function schemaToSource(schema: string | undefined): string | undefined {
  if (!schema) return undefined;
  if (schema === GEMMAFORGE_LEADS_SCHEMA || schema.startsWith("gemmaforge.leads/")) {
    return "gemmaforge";
  }
  return undefined;
}
