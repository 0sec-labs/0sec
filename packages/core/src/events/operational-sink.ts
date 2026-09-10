/**
 * Opt-in metadata-only operational NDJSON EventSink writing to stderr.
 *
 * Enabled by setting `0SEC_LOG_FORMAT=json`. Only allowlisted lifecycle
 * and cost-counter events pass through — raw prompts, responses, reasoning,
 * tool args/results, finding evidence/descriptions, token deltas, auth
 * material, and raw error text are excluded entirely.
 *
 * Every line is a JSON object on stderr, one per bus event:
 *
 *   {"timestamp":"…","level":"info","service":"0sec","event":"step_started","step":"analyze"}
 *
 * The sink is designed for an SRE / operator who wants to observe scan
 * lifecycle and cost without seeing internal agent transcripts or finding
 * content. It reuses the existing `redactSensitiveHeaders` sweep for
 * defense-in-depth on the few string fields that pass through.
 */
import type { EventType, EventSink } from "./bus.js";
import { eventBus } from "./bus.js";
import { redactSensitiveHeaders } from "../disclose/template.js";

// ── Bounds ──────────────────────────────────────────────────────────────────

/**
 * Maximum length for a string identifier (agent_id, scan_id, tool name,
 * etc.). Values exceeding this are dropped rather than emitted.
 */
const MAX_IDENTIFIER_LENGTH = 200;

// ── Allowlist ───────────────────────────────────────────────────────────────

/**
 * Event types whose operational metadata may be serialized. All other events
 * (finding_ingested, tool_call_*, delta, reasoning_summary, subagent_message,
 * peer_message, etc.) are silently dropped without any work beyond the
 * allowlist check.
 */
const ALLOWLISTED_EVENTS: Partial<Record<EventType, true>> = {
  step_started: true,
  step_completed: true,
  cost_update: true,
  scan_completed: true,
  "analyze:stage_complete": true,
  phase_started: true,
  phase_completed: true,
  agent_turn_started: true,
  agent_turn_completed: true,
  llm_planner_invoked: true,
  skill_loaded: true,
  skill_listed: true,
  subagent_lifecycle: true,
  subagent_progress: true,
  tool_health: true,
  todos: true,
  session_objective: true,
  cross_validated_leads: true,
  untrusted_input_sanitized: true,
  oast_confirmed: true,
  pov_oracle: true,
  inline_validation: true,
};

// ── Safe-field extractors ───────────────────────────────────────────────────

function safeStr(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length === 0) return undefined;
  if (value.length > MAX_IDENTIFIER_LENGTH) return undefined;
  // Defense-in-depth: run through the existing redaction sweep so that
  // even if a safe-looking identifier somehow encodes auth material (e.g.
  // an agent name that is a JWT or AKIA key), it gets masked before
  // hitting stderr.
  return redactSensitiveHeaders(value);
}

function safeNum(value: unknown): number | undefined {
  if (typeof value !== "number") return undefined;
  if (!isFinite(value)) return undefined;
  return value;
}

function pickStr(
  target: Record<string, unknown>,
  source: Record<string, unknown>,
  key: string,
): void {
  const v = safeStr(source[key]);
  if (v !== undefined) target[key] = v;
}

function pickNum(
  target: Record<string, unknown>,
  source: Record<string, unknown>,
  key: string,
): void {
  const v = safeNum(source[key]);
  if (v !== undefined) target[key] = v;
}

function pickBool(
  target: Record<string, unknown>,
  source: Record<string, unknown>,
  key: string,
): void {
  if (typeof source[key] === "boolean") target[key] = source[key];
}

// ── Per-event safe payload builder ──────────────────────────────────────────

/**
 * Extract a safe metadata-only subset from a raw event payload.
 * Returns `null` when no safe fields survive (e.g. an otherwise-allowlisted
 * event with only sensitive fields populated), in which case no line is
 * emitted.
 */
function buildSafePayload(
  type: EventType,
  raw: Record<string, unknown>,
): Record<string, unknown> | null {
  const safe: Record<string, unknown> = {};

  switch (type) {
    case "step_started":
      pickStr(safe, raw, "step");
      pickNum(safe, raw, "n");
      break;

    case "step_completed":
      pickStr(safe, raw, "step");
      pickNum(safe, raw, "duration_ms");
      pickNum(safe, raw, "n");
      break;

    case "cost_update":
      pickNum(safe, raw, "cost_usd");
      pickNum(safe, raw, "input_tokens");
      pickNum(safe, raw, "output_tokens");
      pickNum(safe, raw, "token_input");
      pickNum(safe, raw, "token_output");
      pickNum(safe, raw, "cached_input_tokens");
      pickNum(safe, raw, "turn");
      break;

    case "scan_completed":
      pickStr(safe, raw, "exit_reason");
      pickNum(safe, raw, "findings");
      pickNum(safe, raw, "duration_ms");
      pickNum(safe, raw, "turns_used");
      pickNum(safe, raw, "tool_calls_total");
      pickNum(safe, raw, "cost_usd");
      pickNum(safe, raw, "cost_per_flag");
      // cost_breakdown — per-provider cost split (provider/model names are
      // safe identifiers; cost numbers are validated).
      if (Array.isArray(raw.cost_breakdown)) {
        const breakdown: Record<string, unknown>[] = [];
        for (const entry of raw.cost_breakdown) {
          if (entry === null || typeof entry !== "object") continue;
          const provider = safeStr(entry.provider);
          const model = safeStr(entry.model);
          if (provider === undefined || model === undefined) continue;
          const item: Record<string, unknown> = { provider, model };
          pickNum(item, entry, "cost_in");
          pickNum(item, entry, "cost_out");
          pickNum(item, entry, "cost_cache_read");
          breakdown.push(item);
        }
        if (breakdown.length > 0) safe.cost_breakdown = breakdown;
      }
      // summary is excluded because it contains finding text.
      break;

    case "analyze:stage_complete":
      pickStr(safe, raw, "staticScanner");
      pickBool(safe, raw, "staticScannerRan");
      pickNum(safe, raw, "staticScannerFindings");
      pickNum(safe, raw, "semgrepFindings");
      pickNum(safe, raw, "npmAuditFindings");
      break;

    case "phase_started":
      pickStr(safe, raw, "name");
      pickNum(safe, raw, "index");
      break;

    case "phase_completed":
      pickStr(safe, raw, "name");
      pickNum(safe, raw, "index");
      pickNum(safe, raw, "duration_ms");
      pickNum(safe, raw, "input_tokens");
      pickNum(safe, raw, "output_tokens");
      pickNum(safe, raw, "turns");
      break;

    case "agent_turn_started":
      pickNum(safe, raw, "turn");
      pickNum(safe, raw, "max_turns");
      break;

    case "agent_turn_completed":
      pickNum(safe, raw, "turn");
      pickNum(safe, raw, "duration_ms");
      pickStr(safe, raw, "reason");
      break;

    case "llm_planner_invoked":
      pickNum(safe, raw, "turn");
      pickStr(safe, raw, "model");
      pickNum(safe, raw, "tokens_est");
      break;

    case "skill_loaded":
      safe.skill_id = safeStr(raw.skill_id);
      safe.name = safeStr(raw.name);
      pickNum(safe, raw, "estimated_tokens");
      break;

    case "skill_listed":
      pickNum(safe, raw, "total");
      pickNum(safe, raw, "suggested_count");
      pickStr(safe, raw, "tag");
      break;

    case "subagent_lifecycle":
      safe.agent_id = safeStr(raw.agent_id);
      pickStr(safe, raw, "name");
      pickStr(safe, raw, "status");
      pickNum(safe, raw, "max_turns");
      pickNum(safe, raw, "turns");
      pickNum(safe, raw, "findings");
      // task, summary, error — explicitly excluded (may contain target
      // descriptions, finding summaries, or raw error text)
      break;

    case "subagent_progress":
      safe.agent_id = safeStr(raw.agent_id);
      safe.parent_scan_id = safeStr(raw.parent_scan_id);
      pickNum(safe, raw, "turn");
      pickNum(safe, raw, "max_turns");
      pickStr(safe, raw, "tool");
      // note — explicitly excluded (may contain agent-authored text)
      break;

    case "tool_health":
      safe.tool = safeStr(raw.tool);
      pickStr(safe, raw, "category");
      pickNum(safe, raw, "count");
      // message, remedy — explicitly excluded (may contain target paths,
      // command fragments, or actionable details that reference findings)
      break;

    case "todos":
      pickNum(safe, raw, "done");
      pickNum(safe, raw, "total");
      // todos array, line, revision — explicitly excluded (todos content
      // may reference findings, line may contain user-authored text)
      break;

    case "session_objective":
      pickStr(safe, raw, "scanId");
      break;

    case "cross_validated_leads":
      pickNum(safe, raw, "count");
      // leads array — explicitly excluded (contains finding ids, titles,
      // severity, confidence — finding-level details)
      break;

    case "untrusted_input_sanitized":
      safe.tool = safeStr(raw.tool);
      if (Array.isArray(raw.markers)) {
        const markers = raw.markers.map(safeStr).filter(
          (marker): marker is string => marker !== undefined,
        );
        if (markers.length > 0) safe.markers = markers;
      }
      // turn, role — excluded (not needed for operational observability)
      break;

    case "oast_confirmed":
      safe.findingId = safeStr(raw.findingId);
      pickStr(safe, raw, "category");
      pickStr(safe, raw, "oracle");
      pickStr(safe, raw, "protocol");
      // reason — explicitly excluded (may contain evidence/description text)
      break;

    case "pov_oracle":
      safe.findingId = safeStr(raw.findingId);
      pickStr(safe, raw, "category");
      pickStr(safe, raw, "oracle");
      pickBool(safe, raw, "hasPov");
      pickBool(safe, raw, "inconclusive");
      // reason — explicitly excluded
      break;

    case "inline_validation":
      safe.findingId = safeStr(raw.findingId);
      pickStr(safe, raw, "category");
      pickStr(safe, raw, "severity");
      pickBool(safe, raw, "confirmed");
      pickBool(safe, raw, "inconclusive");
      // reason, durationMs, turn — excluded (reason may contain evidence)
      break;

    default:
      return null;
  }

  // Strip any keys whose value ended up undefined (e.g. optional fields
  // that were absent or failed validation).
  for (const key of Object.keys(safe)) {
    if (safe[key] === undefined) delete safe[key];
  }

  return Object.keys(safe).length > 0 ? safe : null;
}

// ── Sink factory ────────────────────────────────────────────────────────────

let operationalSinkSubscribed = false;

/**
 * Create a new operational NDJSON EventSink that writes to stderr.
 * Use {@link maybeSubscribeOperationalEventSink} for the standard
 * env-var-gated subscription at CLI startup.
 */
export function createOperationalEventSink(): EventSink {
  return {
    emit(type, rawPayload) {
      // Early return for non-allowlisted events — zero work per event
      // for the high-volume channels (delta, subagent_message, etc.),
      // avoiding any per-token serialization overhead.
      if (!ALLOWLISTED_EVENTS[type]) return;

      const payload = buildSafePayload(type, rawPayload);
      if (payload === null) return;

      const envelope: Record<string, unknown> = {
        timestamp: new Date().toISOString(),
        level: type === "tool_health" ? "warn" : "info",
        service: "0sec",
        event: type,
      };

      // Merge only allowlisted fields, never the raw payload.
      for (const [k, v] of Object.entries(payload)) {
        envelope[k] = v;
      }

      try {
        process.stderr.write(JSON.stringify(envelope) + "\n");
      } catch {
        // stderr pipe broken — nothing actionable we can do; swallow
        // to avoid throwing into the bus error handler.
      }
    },
  };
}

/**
 * Subscribe the operational NDJSON stderr sink if `0SEC_LOG_FORMAT=json`
 * is set. Idempotent — safe to call multiple times.
 */
export function maybeSubscribeOperationalEventSink(): void {
  if (operationalSinkSubscribed) return;
  const format = process.env["0SEC_LOG_FORMAT"];
  if (format?.toLowerCase() === "json") {
    eventBus.subscribe(createOperationalEventSink());
    operationalSinkSubscribed = true;
  }
}

/** Test-only: reset the idempotency flag. */
export function _resetOperationalSinkSubscriptionForTests(): void {
  operationalSinkSubscribed = false;
}