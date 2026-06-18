/**
 * protocol/model.ts — core types for the protocol-conformance capability
 * (issue #972, Tier-1 foundational slice).
 *
 * The capability: read a protocol's *specification* (RFC / ABNF / ASN.1 / state
 * diagram) AND a target *implementation*, hypothesize where the implementation
 * DIVERGES from what the spec mandates, craft inputs that exercise the
 * divergence, and confirm it through an execution-grounded oracle before
 * reporting. This file holds the data model the rest of the slice operates on.
 *
 * Scope of THIS module (deliberately bounded — simplicity first; see #972):
 *   - Types only. No I/O, no LLM, no network.
 *   - HTTP/text-protocol shaped: a `ConformanceRule` carries the input that
 *     exercises it as an HTTP request shape, and a `DivergenceHypothesis`
 *     predicts an HTTP-observable. The binary/framed driver, the non-crash
 *     oracle beyond HTTP, machine-readable spec ingestion, and state-machine
 *     inference are LATER slices and are intentionally NOT modeled here.
 *
 * The promotion discipline mirrors `verify/kernel-verify.ts`: a divergence is a
 * `hypothesis` (low confidence) until the deterministic oracle confirms it
 * against a real observation. That FP-discipline — never let the LLM judge
 * itself into a confirmed report — is the whole point of the design (#972's
 * "discipline gate").
 */

// ── Spec citation + requirement strength ──

/**
 * RFC 2119 requirement levels. The oracle treats them very differently:
 *   - A `MUST` / `MUST NOT` violation is concretely observable → can be
 *     `confirmed`.
 *   - A `SHOULD` / `SHOULD NOT` violation is advisory → at most `inconclusive`,
 *     NEVER `confirmed` (conservative FP guardrail; see oracle-http.ts).
 *   - `MAY` is optional behavior — never a violation on its own.
 */
export type RequirementLevel =
  | "MUST"
  | "MUST NOT"
  | "SHOULD"
  | "SHOULD NOT"
  | "MAY";

/**
 * The HTTP surface a Tier-1 rule can constrain. Kept small on purpose — this is
 * the only protocol family the Tier-1 oracle reasons about today. Extending to
 * framed/binary protocols is a later slice (issue #972, the `driver.ts` gap).
 */
export type HttpRuleSurface = "method" | "header" | "status";

// ── ProtocolModel ──

/**
 * A named protocol the conformance engine targets, with a pointer back to the
 * authoritative spec the rules were derived from. This is intentionally thin in
 * the Tier-1 slice: we do NOT ingest a machine-readable grammar/state-machine
 * here (that is the `spec-ingest.ts` gap in #972). The `specRef` is a human/
 * audit citation, and `specExcerpt` is the raw authoritative text passed in.
 */
export interface ProtocolModel {
  /** Protocol name, e.g. "HTTP/1.1". */
  name: string;
  /** Version or spec edition, e.g. "RFC 9110". */
  version: string;
  /**
   * Source-of-spec reference — a citation a human can audit, e.g.
   * "RFC 9110 §9.3.6" or "RFC 7252". NOT a URL fetch target (no ingestion infra
   * in this slice).
   */
  specRef: string;
  /**
   * The authoritative spec text the rules were derived from (RFC/ABNF prose
   * passed in as a string). Carried for provenance + repair prompts. No parsing
   * of this into a grammar in the Tier-1 slice.
   */
  specExcerpt?: string;
}

// ── ConformanceRule ──

/**
 * The HTTP input shape that exercises a rule. Deterministic and self-contained
 * so the Tier-1 flow can craft an `http_request` from it without an LLM in the
 * loop. The fields map 1:1 onto the existing `http_request` tool
 * (`agent/tools/recon.ts`).
 */
export interface HttpExercise {
  /** HTTP method to send, e.g. "TRACE", "GET". */
  method: string;
  /** Path appended to the target base URL, e.g. "/". Defaults to "/". */
  path?: string;
  /** Request headers to set. */
  headers?: Record<string, string>;
  /** Optional request body. */
  body?: string;
}

/**
 * A single, citeable conformance requirement extracted from the spec, paired
 * with the input that exercises it and the mandated behavior.
 *
 * Example (HTTP CONNECT to an origin server): "A server MUST reject a CONNECT
 * request to a non-tunneling resource with 405" → `level: "MUST"`,
 * `exercise: { method: "CONNECT" }`, `mandate` describes the 405/4xx response.
 */
export interface ConformanceRule {
  /** Stable id, e.g. "http-trace-must-405". Used to link hypotheses back. */
  id: string;
  /** Spec citation this rule is grounded in, e.g. "RFC 9110 §9.3.8". */
  specCitation: string;
  /** RFC 2119 strength of the requirement. */
  level: RequirementLevel;
  /** Which HTTP surface this rule constrains. */
  surface: HttpRuleSurface;
  /**
   * The behavior the spec mandates, in prose, e.g. "the server MUST respond
   * with 405 (Method Not Allowed)". Human-auditable; the *machine-checkable*
   * form lives in {@link DivergenceHypothesis.predictedObservable}.
   */
  mandate: string;
  /** The concrete input that exercises this rule. */
  exercise: HttpExercise;
}

// ── DivergenceHypothesis ──

/**
 * A deterministic, oracle-checkable prediction of what a CONFORMANT
 * implementation must do, in terms an HTTP response can be matched against. The
 * oracle compares the observed response to this; a mismatch in the
 * spec-violating direction is what makes a divergence real.
 *
 * Exactly one of the matchers is set, keyed by `surface`:
 *   - method/status: `expectedStatusIn` (the set of conformant status codes) or
 *     `forbiddenStatusIn` (status codes that prove a violation).
 *   - header: `requiredHeader` / `forbiddenHeader`.
 */
export interface ConformancePrediction {
  surface: HttpRuleSurface;
  /** Status codes a conformant server MAY return (any other ⇒ candidate violation). */
  expectedStatusIn?: number[];
  /** Status codes that, if observed, CONCRETELY prove the violation (e.g. a 2xx to a MUST-reject input). */
  forbiddenStatusIn?: number[];
  /** Header name a conformant response MUST carry. */
  requiredHeader?: string;
  /** Header name a conformant response MUST NOT carry. */
  forbiddenHeader?: string;
}

/**
 * A ranked hypothesis that an implementation diverges from a specific rule. The
 * confidence here is the *prior* (LLM-assessed plausibility); the oracle, not
 * this number, decides confirmed/refuted. Mirrors the kernel-review contract
 * where a static finding is `hypothesis: true, confidence: 0.4` until the
 * verify loop runs (`review.ts:140`, `kernel-verify.ts:20-26`).
 */
export interface DivergenceHypothesis {
  /** The id of the {@link ConformanceRule} this may violate. */
  ruleId: string;
  /** Spec citation carried forward for the finding/report. */
  specCitation: string;
  /** Requirement strength carried forward (gates what the oracle may confirm). */
  level: RequirementLevel;
  /**
   * Where in the implementation the divergence is predicted (file:line, handler
   * name, or a prose locus). Free-form — we don't resolve it in Tier-1.
   */
  implLocation: string;
  /** Why the LLM thinks the impl diverges here (one sentence, audit trail). */
  rationale: string;
  /** The deterministic, oracle-checkable prediction of conformant behavior. */
  predictedObservable: ConformancePrediction;
  /** The input to send to exercise the divergence. */
  exercise: HttpExercise;
  /** LLM-assessed prior plausibility (0–1). NOT the verdict. */
  confidence: number;
}

// ── DivergenceVerdict ──

export type DivergenceStatus = "confirmed" | "refuted" | "inconclusive";

/**
 * The oracle's verdict on a single hypothesis. `confirmed` is reserved for a
 * concrete, MUST-level violation backed by a real observation; everything
 * advisory or ambiguous collapses to `inconclusive` (conservative by design).
 */
export interface DivergenceVerdict {
  ruleId: string;
  status: DivergenceStatus;
  /**
   * Confidence to stamp on the finding. Mirrors the kernel promotion contract:
   *   - confirmed  → 1.0
   *   - refuted    → 0.0 (no divergence — observation matched the spec)
   *   - inconclusive → the hypothesis prior is preserved (unchanged)
   */
  confidence: number;
  /** Human-readable evidence: observed vs expected, why it is/isn't a violation. */
  evidence: string;
}

/** A confirmed/observed response shape the Tier-1 oracle reasons over. */
export interface ObservedHttpResponse {
  /** HTTP status code observed, e.g. 200, 405. */
  status: number;
  /** Lower-cased response header names → values (best-effort). */
  headers?: Record<string, string>;
  /** Set when the request never produced a response (network error, timeout). */
  error?: string;
}
