/**
 * Optional webhook sink for streaming findings and final reports to a remote
 * HTTP endpoint in real time.
 *
 * This module is a no-op unless the user opts in via environment variables:
 *
 *   PWNKIT_CLOUD_SINK     — base URL of the remote API (e.g. https://api.example.com)
 *   PWNKIT_CLOUD_SCAN_ID  — scan correlation id (sent in X-Pwnkit-Scan-Id header
 *                           AND used in the URL path)
 *   PWNKIT_CLOUD_TOKEN    — bearer token (sent as Authorization header)
 *
 * When PWNKIT_CLOUD_SINK is unset, behavior is identical to today's local-only
 * runs. When set, every saved finding and the final scan report are POSTed to:
 *
 *   ${PWNKIT_CLOUD_SINK}/scans/${PWNKIT_CLOUD_SCAN_ID}/findings
 *
 * The integration is intentionally fire-and-forget: any error returned by the
 * remote endpoint is logged to stderr but does NOT abort the scan. Local
 * output is unchanged either way.
 *
 * The behavior can be force-disabled with PWNKIT_FEATURE_CLOUD_SINK=0 even when
 * the URL env var is set, mirroring the existing feature-flag pattern in
 * `agent/features.ts`.
 */
import { randomUUID } from "node:crypto";
import { features } from "./agent/features.js";
import type {
  CloudSinkEvidence,
  CloudSinkFinding,
  CloudSinkSeverity,
} from "./cloud-contracts.js";

export type {
  CloudSinkEvidence,
  CloudSinkFinding,
  CloudSinkFindingEnvelope,
  CloudSinkFinalReport,
  CloudSinkSeverity,
} from "./cloud-contracts.js";

/** Max bytes of any single evidence string on the wire (post-stringify). */
const EVIDENCE_MAX_BYTES = 64 * 1024;
/** Max length of short string fields (title, description, category, etc). */
const TITLE_MAX = 512;
const DESCRIPTION_MAX = 8 * 1024;

const VALID_SEVERITIES: ReadonlySet<CloudSinkSeverity> = new Set([
  "critical",
  "high",
  "medium",
  "low",
  "info",
]);

export interface CloudSinkConfig {
  /** Base URL of the remote sink, e.g. https://api.example.com */
  sinkUrl: string;
  /** Scan correlation id used in the URL path AND the X-Pwnkit-Scan-Id header */
  scanId: string;
  /** Optional bearer token sent as Authorization header */
  token?: string;
}

/**
 * Read sink configuration from the environment. Returns null when the feature
 * flag is disabled or when PWNKIT_CLOUD_SINK is unset (the no-op case).
 */
export function getCloudSinkConfig(): CloudSinkConfig | null {
  if (!features.cloudSink) return null;

  const sinkUrl = process.env.PWNKIT_CLOUD_SINK?.trim();
  if (!sinkUrl) return null;

  const scanId = process.env.PWNKIT_CLOUD_SCAN_ID?.trim();
  if (!scanId) return null;

  const token = process.env.PWNKIT_CLOUD_TOKEN?.trim() || undefined;
  return { sinkUrl, scanId, token };
}

function buildHeaders(config: CloudSinkConfig): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Pwnkit-Scan-Id": config.scanId,
  };
  if (config.token) headers["Authorization"] = `Bearer ${config.token}`;
  return headers;
}

async function postJson(
  url: string,
  body: unknown,
  config: CloudSinkConfig,
  kind: string,
): Promise<void> {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: buildHeaders(config),
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      // Drain body for diagnostics, then continue. Sink failures must never
      // abort the scan.
      const text = await res.text().catch(() => "");
      process.stderr.write(
        `[pwnkit cloud-sink] ${kind} POST ${url} returned ${res.status}: ${text.slice(0, 200)}\n`,
      );
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[pwnkit cloud-sink] ${kind} POST ${url} failed: ${msg}\n`);
  }
}

/** Narrow "looks like a plain object" guard used by the normalizer. */
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Coerce an arbitrary evidence value (string, object, array, null, number)
 * into a single string suitable for the orchestrator's
 * `evidence.request`/`evidence.response` string fields, truncating to
 * EVIDENCE_MAX_BYTES so we never blow up the ingest endpoint.
 */
function stringifyEvidenceField(v: unknown): string {
  if (v == null) return "";
  let s: string;
  if (typeof v === "string") {
    s = v;
  } else {
    try {
      s = JSON.stringify(v);
    } catch {
      s = String(v);
    }
    if (typeof s !== "string") s = String(v);
  }
  if (s.length > EVIDENCE_MAX_BYTES) {
    s = s.slice(0, EVIDENCE_MAX_BYTES) + `…[truncated ${s.length - EVIDENCE_MAX_BYTES} chars]`;
  }
  return s;
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max) + "…";
}

function pickString(raw: Record<string, unknown>, ...keys: string[]): string | undefined {
  for (const k of keys) {
    const v = raw[k];
    if (typeof v === "string" && v.length > 0) return v;
    if (typeof v === "number" || typeof v === "boolean") return String(v);
  }
  return undefined;
}

function normalizeSeverity(v: unknown): CloudSinkSeverity {
  if (typeof v === "string") {
    const lower = v.toLowerCase().trim();
    if (VALID_SEVERITIES.has(lower as CloudSinkSeverity)) {
      return lower as CloudSinkSeverity;
    }
    // Common aliases seen from LLM tool calls.
    if (lower === "informational" || lower === "information" || lower === "none") return "info";
    if (lower === "warn" || lower === "warning" || lower === "moderate") return "medium";
    if (lower === "severe") return "high";
  }
  return "info";
}

function normalizeTimestamp(v: unknown): number {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string") {
    // ISO-8601 or epoch-as-string
    const asNum = Number(v);
    if (Number.isFinite(asNum) && asNum > 0) return asNum;
    const parsed = Date.parse(v);
    if (!Number.isNaN(parsed)) return parsed;
  }
  return Date.now();
}

function normalizeEvidence(raw: Record<string, unknown>): CloudSinkEvidence {
  // Case A: nested `evidence: { request, response, analysis? }` (OSS Finding).
  const nested = raw.evidence;
  if (isRecord(nested)) {
    const analysisRaw = nested.analysis;
    const out: CloudSinkEvidence = {
      request: stringifyEvidenceField(nested.request),
      response: stringifyEvidenceField(nested.response),
    };
    if (analysisRaw != null && analysisRaw !== "") {
      const analysis = stringifyEvidenceField(analysisRaw);
      if (analysis.length > 0) out.analysis = analysis;
    }
    return out;
  }

  // Case B: flat snake_case from LLM save_finding tool call.
  const out: CloudSinkEvidence = {
    request: stringifyEvidenceField(raw.evidence_request ?? raw.request ?? ""),
    response: stringifyEvidenceField(raw.evidence_response ?? raw.response ?? ""),
  };
  const analysisRaw = raw.evidence_analysis ?? raw.analysis;
  if (analysisRaw != null && analysisRaw !== "") {
    const analysis = stringifyEvidenceField(analysisRaw);
    if (analysis.length > 0) out.analysis = analysis;
  }
  return out;
}

/**
 * Thrown when a raw finding is missing every plausible title/description and
 * cannot be coerced into a wire-valid CloudSinkFinding. Callers should log
 * and drop — a malformed finding is never worth aborting the scan over.
 */
export class CloudSinkNormalizeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CloudSinkNormalizeError";
  }
}

/**
 * Normalize an arbitrary finding-shaped value (an OSS internal `Finding`, a
 * raw LLM `save_finding` tool-call argument object, or something in between)
 * into the strict `CloudSinkFinding` shape the pwnkit-cloud orchestrator's
 * zod schema validates.
 *
 * This is the chokepoint that keeps OSS → cloud wire traffic schema-clean.
 * If you add a field to the orchestrator's `findingSchema`, add it here too.
 *
 * @throws {CloudSinkNormalizeError} when the input cannot be coerced — e.g.
 *   it is not an object, or lacks both a title and a description.
 */
export function normalizeFinding(rawFinding: unknown): CloudSinkFinding {
  if (!isRecord(rawFinding)) {
    throw new CloudSinkNormalizeError(
      `expected finding to be an object, got ${rawFinding === null ? "null" : typeof rawFinding}`,
    );
  }
  const raw = rawFinding;

  const title = pickString(raw, "title", "name", "summary");
  const description = pickString(raw, "description", "details", "body");
  if (!title && !description) {
    throw new CloudSinkNormalizeError(
      "finding is missing both `title` and `description` — nothing to report",
    );
  }

  const id =
    pickString(raw, "id", "findingId", "finding_id") ??
    // Fall back to a stable-ish UUID so the orchestrator always has a PK.
    randomUUID();

  const templateId =
    pickString(raw, "templateId", "template_id", "template") ?? "manual";

  const category = pickString(raw, "category", "attackCategory", "attack_category") ?? "unknown";

  const status = pickString(raw, "status", "workflowStatus", "workflow_status") ?? "discovered";

  const confidenceRaw = raw.confidence;
  let confidence: number | undefined;
  if (typeof confidenceRaw === "number" && Number.isFinite(confidenceRaw)) {
    confidence = Math.max(0, Math.min(1, confidenceRaw));
  }

  const normalized: CloudSinkFinding = {
    id,
    templateId: truncate(templateId, TITLE_MAX),
    title: truncate(title ?? "Untitled finding", TITLE_MAX),
    description: truncate(description ?? "", DESCRIPTION_MAX),
    severity: normalizeSeverity(raw.severity),
    category: truncate(category, TITLE_MAX),
    status: truncate(status, TITLE_MAX),
    evidence: normalizeEvidence(raw),
    timestamp: normalizeTimestamp(raw.timestamp),
  };
  if (confidence !== undefined) normalized.confidence = confidence;

  // pwnkit#170 — pass-through optional PoC step graph. We accept already-
  // structured arrays (the in-process OSS Finding case) and JSON-encoded
  // strings (the LLM tool-call case). Anything malformed is dropped — a bad
  // step graph must never block a finding from reaching cloud.
  const pocSteps = normalizePocSteps(raw.pocSteps ?? raw.poc_steps);
  if (pocSteps && pocSteps.length > 0) normalized.pocSteps = pocSteps;

  // pwnkit#193 — pass-through optional VerificationSpec. Same wire-shape
  // tolerance as pocSteps (object OR JSON string OR null). Anything
  // malformed is dropped silently; the spec is decoration on the finding,
  // never a reason to drop the finding itself.
  const verificationSpec = normalizeVerificationSpec(
    raw.verificationSpec ?? raw.verification_spec,
  );
  if (verificationSpec) normalized.verificationSpec = verificationSpec;

  return normalized;
}

/**
 * Pass-through normaliser for the optional pocSteps field. Returns the array
 * shape unchanged when the input is already array-shaped, parses a JSON-
 * encoded string into one, and yields null for any other shape. This is
 * deliberately permissive: the OSS sink is a wire-format chokepoint, not a
 * schema validator — see PocStep in @pwnkit/shared for the canonical shape.
 */
function normalizePocSteps(v: unknown): unknown[] | null {
  if (v == null || v === "") return null;
  if (Array.isArray(v)) return v;
  if (typeof v === "string") {
    try {
      const parsed = JSON.parse(v);
      if (Array.isArray(parsed)) return parsed;
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Pass-through normaliser for the optional `verificationSpec` field
 * (pwnkit#193). Returns the object shape unchanged when input is already an
 * object, parses a JSON-encoded string into one, and yields null otherwise.
 *
 * Mirrors `normalizePocSteps` in being deliberately permissive: the OSS
 * sink is a wire-format chokepoint, not a schema validator. The canonical
 * shape lives in `@pwnkit/shared/types.ts` (`VerificationSpec`).
 */
function normalizeVerificationSpec(v: unknown): Record<string, unknown> | null {
  if (v == null || v === "") return null;
  if (typeof v === "string") {
    try {
      const parsed = JSON.parse(v);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return null;
    }
    return null;
  }
  if (typeof v === "object" && !Array.isArray(v)) {
    return v as Record<string, unknown>;
  }
  return null;
}

/**
 * POST a single finding to the remote sink. No-op if env vars unset.
 *
 * The raw finding is normalized to the strict `CloudSinkFinding` shape before
 * posting so the orchestrator's zod schema accepts it. If normalization fails
 * the error is logged and the scan continues — malformed findings are never
 * worth aborting a scan over.
 */
export async function postFinding(
  finding: unknown,
  config: CloudSinkConfig | null = getCloudSinkConfig(),
): Promise<void> {
  if (!config) return;
  let normalized: CloudSinkFinding;
  try {
    normalized = normalizeFinding(finding);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[pwnkit cloud-sink] dropping malformed finding: ${msg}\n`);
    return;
  }
  const url = `${config.sinkUrl.replace(/\/+$/, "")}/scans/${encodeURIComponent(config.scanId)}/findings`;
  await postJson(url, { finding: normalized }, config, "finding");
}

/**
 * POST the final scan/audit report (with usage + cost) to the remote sink.
 * No-op if env vars unset.
 */
export async function postFinalReport(
  report: unknown,
  config: CloudSinkConfig | null = getCloudSinkConfig(),
): Promise<void> {
  if (!config) return;
  const url = `${config.sinkUrl.replace(/\/+$/, "")}/scans/${encodeURIComponent(config.scanId)}/findings`;
  await postJson(url, { report, final: true }, config, "report");
}
