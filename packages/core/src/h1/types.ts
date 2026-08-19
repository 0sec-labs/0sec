// Minimal shapes for the HackerOne hacker API responses we consume.
//
// Deliberately partial — H1's full response payloads are huge and most
// fields are irrelevant to scope ingestion / program triage. We type only
// what `programs.ts` and `scope-export.ts` actually read. Anything else
// stays as `unknown` so a schema change at H1's end doesn't silently
// corrupt our typed views.
//
// Per AGENTS.md "no premature abstraction" — when fit-score / fit-rank /
// hacktivity land in follow-on PRs, extend these shapes there. Don't
// pre-emptively model fields nobody reads yet.
//
// Reference (May 2026):
//   GET /v1/hackers/programs            → list view, attributes: handle, name, state, …
//   GET /v1/hackers/programs/{handle}   → detail view, includes structured_scopes via relationships
//   GET /v1/hackers/programs/{handle}/structured_scopes → structured_scopes data array
//   GET /v1/hackers/payments/balance    → auth probe; identifier echoed in `data.id`

/**
 * Generic JSON:API envelope for a single resource.
 */
export interface H1Resource<TAttrs, TRels = Record<string, unknown>> {
  id: string;
  type: string;
  attributes: TAttrs;
  relationships?: TRels;
}

/**
 * Generic JSON:API envelope for a paginated collection.
 */
export interface H1Collection<TAttrs, TRels = Record<string, unknown>> {
  data: Array<H1Resource<TAttrs, TRels>>;
  links?: {
    self?: string;
    next?: string;
    prev?: string;
  };
}

/**
 * Single-resource envelope.
 */
export interface H1Single<TAttrs, TRels = Record<string, unknown>> {
  data: H1Resource<TAttrs, TRels>;
}

/** Program attributes we actually read. */
export interface H1ProgramAttributes {
  handle: string;
  name: string;
  state?: string;
  /** "internet_bug_bounty", "public_mode", "soft_launched", … */
  policy?: string;
  /** Whether the program offers monetary bounties. */
  offers_bounties?: boolean;
  currency?: string;
  /** Free-form policy/markdown text used for the automation-verdict heuristic. */
  submission_state?: string;
  triage_active?: boolean;
}

export type H1Program = H1Resource<H1ProgramAttributes>;

/** Structured-scope attributes per H1 docs (May 2026). */
export interface H1StructuredScopeAttributes {
  asset_type: string;
  asset_identifier: string;
  /** "high" | "medium" | "low" | null */
  max_severity?: string | null;
  eligible_for_bounty?: boolean;
  eligible_for_submission?: boolean;
  instruction?: string | null;
  reference?: string | null;
  availability_requirement?: string | null;
  confidentiality_requirement?: string | null;
  integrity_requirement?: string | null;
  /** True if the scope entry is for an out-of-scope asset. */
  // H1 splits in/out of scope by `eligible_for_submission`; there is no
  // single "is_out_of_scope" flag. We treat eligible_for_submission=false
  // as out-of-scope for export purposes.
}

export type H1Scope = H1Resource<H1StructuredScopeAttributes>;

/** Auth-probe response (subset). */
export interface H1BalanceAttributes {
  balance?: number | string;
  pending_balance?: number | string;
  currency?: string;
}
