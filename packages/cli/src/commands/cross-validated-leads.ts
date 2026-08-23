/**
 * Pure formatter for the core's `cross_validated_leads` bus event (0sec
 * FoxGuard cross-validation, Phase 4). The event is emitted once per scan when
 * the multi-modal agreement layer ran and at least one finding reached
 * `both_fire` — i.e. both the 0sec agent AND the foxguard pattern scanner
 * fired on the same file. See `CrossValidatedLeadsPayload` in
 * `@0sec/core` (`packages/core/src/events/bus.ts`).
 *
 * This module is intentionally PURE and presentation-agnostic: it validates a
 * (possibly malformed) payload, orders + caps the leads, and returns plain
 * text lines. The scan command (`run.ts`) applies chalk coloring and printing.
 * Keeping it pure lets it be unit-tested without stdout/TTY plumbing and keeps
 * the fail-soft parsing in one place (a bad payload must never crash a scan).
 */
import { severityRank } from "@0sec/shared";

/** Default number of leads to print before collapsing the tail into "+N more". */
export const CROSS_VALIDATED_LEADS_CAP = 8;

/** One rendered lead line plus the normalized severity used to color it. */
export interface CrossValidatedLeadLine {
  /** Normalized lowercase severity: critical | high | medium | low | info | unknown. */
  severity: string;
  /**
   * Fully-formatted plain-text line, e.g.
   * `[HIGH] SQL injection in login · 3 foxguard matches · 82% confidence`.
   */
  text: string;
}

/** Structured, presentation-agnostic summary of a `cross_validated_leads` event. */
export interface CrossValidatedLeadsSummary {
  /**
   * Operator-facing header, e.g.
   * `Cross-validated leads — 3 findings both scanners agree on (investigate first)`.
   */
  header: string;
  /** One entry per rendered lead, severity-ordered (critical first), capped. */
  lines: CrossValidatedLeadLine[];
  /** Number of agreeing findings beyond the cap ("+N more"); 0 when none. */
  moreCount: number;
}

/** Coerce an unknown severity into the canonical lowercase vocabulary. */
function normalizeSeverity(raw: unknown): string {
  if (typeof raw !== "string") return "unknown";
  const lower = raw.trim().toLowerCase();
  if (lower === "informational") return "info";
  return lower || "unknown";
}

/**
 * Turn a `cross_validated_leads` payload into a printable summary, or `null`
 * when there is nothing to show (no well-formed leads / not an object). Every
 * field is read defensively — a malformed payload yields the best-effort
 * summary it can, never a throw.
 */
export function formatCrossValidatedLeads(
  payload: unknown,
  cap: number = CROSS_VALIDATED_LEADS_CAP,
): CrossValidatedLeadsSummary | null {
  if (!payload || typeof payload !== "object") return null;
  const p = payload as Record<string, unknown>;

  const rawLeads = Array.isArray(p.leads) ? p.leads : [];
  const leads = rawLeads.filter(
    (l): l is Record<string, unknown> => !!l && typeof l === "object",
  );
  if (leads.length === 0) return null;

  // Severity-ordered, critical first. severityRank puts critical=4 highest, so
  // sort descending. Stable within a severity (Array.sort is stable), which
  // preserves the payload's triage order as a tiebreak.
  const ordered = [...leads].sort(
    (a, b) =>
      severityRank(normalizeSeverity(b.severity)) -
      severityRank(normalizeSeverity(a.severity)),
  );

  const effectiveCap =
    Number.isFinite(cap) && cap > 0 ? Math.floor(cap) : ordered.length;
  const shown = ordered.slice(0, effectiveCap);
  const moreCount = ordered.length - shown.length;

  // Prefer the payload's authoritative count; fall back to the leads we have.
  const count =
    typeof p.count === "number" && Number.isFinite(p.count)
      ? p.count
      : ordered.length;

  const header = `Cross-validated leads — ${count} finding${count === 1 ? "" : "s"} both scanners agree on (investigate first)`;

  const lines: CrossValidatedLeadLine[] = shown.map((lead) => {
    const severity = normalizeSeverity(lead.severity);
    const title =
      typeof lead.title === "string" && lead.title.trim()
        ? lead.title.trim()
        : "(untitled finding)";
    const parts: string[] = [`[${severity.toUpperCase()}] ${title}`];

    const matches =
      typeof lead.foxguardMatches === "number" &&
      Number.isFinite(lead.foxguardMatches)
        ? Math.max(0, Math.floor(lead.foxguardMatches))
        : undefined;
    if (matches !== undefined) {
      parts.push(`${matches} foxguard match${matches === 1 ? "" : "es"}`);
    }

    const conf =
      typeof lead.confidence === "number" && Number.isFinite(lead.confidence)
        ? Math.round(Math.min(1, Math.max(0, lead.confidence)) * 100)
        : undefined;
    if (conf !== undefined) {
      parts.push(`${conf}% confidence`);
    }

    return { severity, text: parts.join(" · ") };
  });

  return { header, lines, moreCount };
}
