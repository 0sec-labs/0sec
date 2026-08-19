/**
 * #928 — coordinated-disclosure status tracking (engine-side model + helpers).
 *
 * pwnkit already *gates* findings (`triage/verify-verdict.ts` →
 * `isDisclosureWorthy`) and *renders* artifacts (`template.ts` advisory,
 * `writeup.ts` research draft). What it lacked is a model of the disclosure
 * PROCESS — the status timeline a confirmed finding walks once an operator
 * starts coordinating with a vendor: draft → sent → acknowledged → accepted →
 * cve_assigned → published, plus the terminal off-ramps (rejected,
 * not_applicable, duplicate, withdrawn).
 *
 * This module owns that state machine and an append-only event timeline. It is
 * a PURE library: no I/O, no network, no auto-send. It never contacts a vendor
 * and never publishes anything — it only records what an operator did and
 * validates that a requested transition is legal. The operator gates every
 * real-world action (`disclosure/AGENTS.md` hard rules; embargo discipline).
 *
 * VOCABULARY PARITY: the status set and the per-status fields
 * (`disclosed_to`, `disclosed_at`, `cve_id`) are the SAME ones the dashboard
 * schema already defines — `services/dashboard/drizzle/0033_*` +
 * `0045_findings_disclosure_refs.sql` (the `findings_disclosure_status_check`
 * CHECK enum) and `0034_disclosures_and_timeline.sql`
 * (`disclosure_timeline`). The engine and dashboard are decoupled (neither
 * imports the other), so the strings are kept identical by hand and asserted in
 * `tracking.test.ts`. Do NOT introduce engine-only status strings here.
 */

/**
 * The disclosure lifecycle status. Verbatim copy of the dashboard's
 * `findings_disclosure_status_check` enum (migration 0045). The first six are
 * the forward path (#928); the last four are terminal off-ramps.
 */
export const DISCLOSURE_STATUSES = [
  "draft",
  "sent",
  "acknowledged",
  "accepted",
  "cve_assigned",
  "published",
  "rejected",
  "not_applicable",
  "duplicate",
  "withdrawn",
] as const;

export type DisclosureStatus = (typeof DISCLOSURE_STATUSES)[number];

/** Statuses from which no further transition is allowed. */
export const TERMINAL_STATUSES: ReadonlySet<DisclosureStatus> = new Set<DisclosureStatus>([
  "published",
  "rejected",
  "not_applicable",
  "duplicate",
  "withdrawn",
]);

/**
 * Statuses considered "publicly disclosed / embargo lifted" — the set the
 * research-writeup gate treats as cleared. `cve_assigned` is intentionally NOT
 * here: a CVE id can be reserved before the advisory goes public, so a writeup
 * stays embargoed until `published`. (`rejected`/`not_applicable`/`duplicate`
 * never carry a publishable narrative.)
 */
export const PUBLIC_STATUSES: ReadonlySet<DisclosureStatus> = new Set<DisclosureStatus>([
  "published",
]);

/**
 * Legal forward transitions. The forward path can also be short-circuited to a
 * terminal off-ramp from most non-terminal states (a vendor can reject or
 * dup a report at any point, an operator can withdraw). Off-ramps are added
 * uniformly below rather than enumerated per-state.
 */
const FORWARD_EDGES: Record<DisclosureStatus, DisclosureStatus[]> = {
  draft: ["sent"],
  sent: ["acknowledged", "accepted", "cve_assigned"],
  acknowledged: ["accepted", "cve_assigned"],
  accepted: ["cve_assigned", "published"],
  cve_assigned: ["published"],
  published: [],
  rejected: [],
  not_applicable: [],
  duplicate: [],
  withdrawn: [],
};

/** Off-ramps reachable from any non-terminal status. */
const OFFRAMPS: DisclosureStatus[] = [
  "rejected",
  "not_applicable",
  "duplicate",
  "withdrawn",
];

/**
 * The set of statuses reachable in one legal step from `from`. A terminal
 * status reaches nothing. Non-terminal statuses reach their forward edges plus
 * the universal off-ramps (minus duplicates / self).
 */
export function allowedNextStatuses(from: DisclosureStatus): DisclosureStatus[] {
  if (TERMINAL_STATUSES.has(from)) return [];
  const forward = FORWARD_EDGES[from] ?? [];
  const next = new Set<DisclosureStatus>(forward);
  for (const off of OFFRAMPS) next.add(off);
  next.delete(from);
  return DISCLOSURE_STATUSES.filter((s) => next.has(s));
}

/** Whether `from → to` is a legal single transition. */
export function canTransition(from: DisclosureStatus, to: DisclosureStatus): boolean {
  return allowedNextStatuses(from).includes(to);
}

/**
 * One immutable entry in a disclosure's event timeline. Mirrors the dashboard's
 * `disclosure_timeline` columns (`from_status`, `to_status`, `actor`,
 * `message`, `created_at`) so a future sync writes straight through.
 */
export interface DisclosureTimelineEvent {
  /** Status before this transition. `null` for the initial `draft` record. */
  fromStatus: DisclosureStatus | null;
  toStatus: DisclosureStatus;
  /** Who recorded the transition (operator handle / "operator"). */
  actor: string;
  /** ISO-8601 timestamp. */
  at: string;
  /** Optional free-text note for the audit trail. */
  message?: string;
}

/**
 * The engine-side disclosure record for one confirmed finding. Field names
 * mirror the dashboard `findings.*` disclosure columns
 * (`disclosure_status`, `disclosed_to`, `disclosed_at`, `cve_id`) plus the
 * append-only timeline.
 */
export interface DisclosureRecord {
  /** Finding id this disclosure tracks. */
  findingId: string;
  status: DisclosureStatus;
  /** Vendor / venue the report went to (e.g. "security@vendor.com", "GHSA"). */
  disclosedTo?: string;
  /** ISO-8601 timestamp of first contact (set on the draft→sent transition). */
  disclosedAt?: string;
  /** CVE id once assigned. */
  cveId?: string;
  /** Append-only transition history, oldest first. */
  timeline: DisclosureTimelineEvent[];
}

export class IllegalTransitionError extends Error {
  readonly from: DisclosureStatus;
  readonly to: DisclosureStatus;
  constructor(from: DisclosureStatus, to: DisclosureStatus) {
    const allowed = allowedNextStatuses(from);
    super(
      `Illegal disclosure transition ${from} → ${to}. ` +
        (allowed.length
          ? `Allowed from "${from}": ${allowed.join(", ")}.`
          : `"${from}" is terminal — no further transitions.`),
    );
    this.name = "IllegalTransitionError";
    this.from = from;
    this.to = to;
  }
}

export interface TransitionInput {
  /** Target status. */
  to: DisclosureStatus;
  /** Who recorded it. Defaults to "operator". */
  actor?: string;
  /** ISO-8601 timestamp. Defaults to now. */
  at?: string;
  message?: string;
  /** Vendor / venue — required (and only meaningful) on the draft→sent step. */
  disclosedTo?: string;
  /** CVE id — required (and only meaningful) on the *→cve_assigned step. */
  cveId?: string;
}

/**
 * Open a fresh disclosure record for a confirmed finding, in `draft`. This
 * records intent only — it sends nothing. The operator drives the subsequent
 * {@link transition} calls as the real coordination happens.
 */
export function createDisclosureRecord(
  findingId: string,
  opts: { actor?: string; at?: string; message?: string } = {},
): DisclosureRecord {
  const at = opts.at ?? new Date().toISOString();
  const actor = opts.actor ?? "operator";
  return {
    findingId,
    status: "draft",
    timeline: [
      {
        fromStatus: null,
        toStatus: "draft",
        actor,
        at,
        message: opts.message ?? "Disclosure record opened (draft).",
      },
    ],
  };
}

/**
 * Apply a legal transition, returning a NEW record (pure — the input is not
 * mutated). Throws {@link IllegalTransitionError} for an illegal edge so a
 * bad transition can never silently corrupt the audit trail.
 *
 * Side-fields are stamped only on the transition that introduces them:
 *   - `disclosedTo` / `disclosedAt` on the first move into `sent`
 *   - `cveId` on the move into `cve_assigned`
 * Stamping nothing real-world here is the point: this is a record of operator
 * actions, not an actor that performs them.
 */
export function transition(
  record: DisclosureRecord,
  input: TransitionInput,
): DisclosureRecord {
  const from = record.status;
  const to = input.to;
  if (!canTransition(from, to)) {
    throw new IllegalTransitionError(from, to);
  }
  const at = input.at ?? new Date().toISOString();
  const actor = input.actor ?? "operator";

  const next: DisclosureRecord = {
    ...record,
    status: to,
    timeline: [
      ...record.timeline,
      { fromStatus: from, toStatus: to, actor, at, message: input.message },
    ],
  };

  if (to === "sent") {
    if (input.disclosedTo) next.disclosedTo = input.disclosedTo;
    // First contact stamp — only set if not already recorded.
    next.disclosedAt = record.disclosedAt ?? at;
  }
  if (to === "cve_assigned" && input.cveId) {
    next.cveId = input.cveId;
  }

  return next;
}

/** Whether a record's current status clears the research-writeup embargo gate. */
export function isPubliclyDisclosed(record: DisclosureRecord): boolean {
  return PUBLIC_STATUSES.has(record.status);
}
