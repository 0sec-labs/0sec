/**
 * protocol/oracle-http.ts — the Tier-1, HTTP-only, DETERMINISTIC divergence
 * oracle (issue #972).
 *
 * Given a {@link DivergenceHypothesis} and the {@link ObservedHttpResponse}
 * produced by sending its `exercise` via `http_request`, decide
 * confirmed / refuted / inconclusive by comparing the observation against the
 * hypothesis's `predictedObservable`. There is NO LLM in this file — the model
 * proposes hypotheses (`conformance-gen.ts`); a deterministic rule decides the
 * verdict. This is the FP-discipline guardrail that mirrors the crash-oracle
 * promotion contract in `verify/kernel-verify.ts:20-26`: a hypothesis is only
 * promoted to `confirmed` on concrete, real evidence.
 *
 * Conservative-by-design gating (the whole point — this is what separates us
 * from the ~18% FP static-conformance tools #972 calls out):
 *   - Only a MUST / MUST NOT-level rule can ever be `confirmed`. A SHOULD /
 *     SHOULD NOT / MAY divergence is advisory → `inconclusive`, never confirmed.
 *   - `confirmed` requires the observation to CONCRETELY violate the rule:
 *     either a status in the hypothesis's `forbiddenStatusIn` set (e.g. a 2xx
 *     to a method the spec says MUST be rejected), or a `forbiddenHeader`
 *     present / `requiredHeader` absent.
 *   - A status merely outside `expectedStatusIn` is NOT enough to confirm (the
 *     spec may permit codes we didn't enumerate) → `inconclusive`. We only
 *     `refute` when the observation positively matches conformant behavior.
 *   - A network error / no response → `inconclusive` (we observed nothing).
 *
 * Scope of THIS slice: HTTP method/header/status divergences only. Non-crash
 * oracles for framed/binary protocols are a later slice (#972).
 */
import type {
  DivergenceHypothesis,
  DivergenceVerdict,
  ObservedHttpResponse,
} from "./model.js";

/** MUST-strength levels — the only ones the oracle may ever `confirm`. */
const CONFIRMABLE_LEVELS = new Set(["MUST", "MUST NOT"]);

function inSet(value: number, set?: number[]): boolean {
  return Boolean(set && set.includes(value));
}

/** Lower-case the keys of an observed header map for case-insensitive matching. */
function lowerHeaders(headers?: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) return out;
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}

/**
 * Decide a divergence verdict for one hypothesis given the observed response.
 *
 * Returns:
 *   - `confirmed` (confidence 1.0) only on a concrete MUST-level violation;
 *   - `refuted` (confidence 0.0) when the observation positively matches the
 *     conformant prediction (no divergence);
 *   - `inconclusive` (hypothesis prior preserved) in every ambiguous /
 *     advisory / no-evidence case.
 */
export function judgeHttpDivergence(
  hypothesis: DivergenceHypothesis,
  observed: ObservedHttpResponse,
): DivergenceVerdict {
  const base = {
    ruleId: hypothesis.ruleId,
  };
  const prediction = hypothesis.predictedObservable;

  // No observation → we proved nothing. Never confirm on absence of data.
  if (observed.error !== undefined) {
    return {
      ...base,
      status: "inconclusive",
      confidence: hypothesis.confidence,
      evidence: `no response observed (transport error: ${observed.error}); cannot judge conformance`,
    };
  }

  const confirmable = CONFIRMABLE_LEVELS.has(hypothesis.level);
  const headers = lowerHeaders(observed.headers);

  // ── Status-based reasoning (surface: method | status) ──
  if (prediction.surface === "method" || prediction.surface === "status") {
    // CONCRETE violation: a status the spec forbids for this input.
    if (inSet(observed.status, prediction.forbiddenStatusIn)) {
      if (!confirmable) {
        return {
          ...base,
          status: "inconclusive",
          confidence: hypothesis.confidence,
          evidence:
            `observed status ${observed.status} is in the forbidden set ` +
            `[${prediction.forbiddenStatusIn?.join(", ")}], but the rule is ` +
            `${hypothesis.level}-level (advisory) — not a confirmable violation`,
        };
      }
      return {
        ...base,
        status: "confirmed",
        confidence: 1.0,
        evidence:
          `${hypothesis.level} violation: observed status ${observed.status}, ` +
          `which the spec forbids for this input ` +
          `(forbidden set [${prediction.forbiddenStatusIn?.join(", ")}]). ` +
          `Rule ${hypothesis.specCitation}.`,
      };
    }

    // Positively conformant: status is within the expected set → REFUTE.
    if (inSet(observed.status, prediction.expectedStatusIn)) {
      return {
        ...base,
        status: "refuted",
        confidence: 0.0,
        evidence:
          `observed status ${observed.status} matches the conformant set ` +
          `[${prediction.expectedStatusIn?.join(", ")}] — no divergence`,
      };
    }

    // Outside the expected set but NOT in a declared forbidden set: ambiguous.
    // The spec may permit codes we didn't enumerate; do not confirm on this.
    return {
      ...base,
      status: "inconclusive",
      confidence: hypothesis.confidence,
      evidence:
        `observed status ${observed.status} is neither in the conformant set ` +
        `[${prediction.expectedStatusIn?.join(", ") ?? ""}] nor a declared ` +
        `forbidden status [${prediction.forbiddenStatusIn?.join(", ") ?? ""}]; ` +
        `insufficient evidence to confirm a violation`,
    };
  }

  // ── Header-based reasoning (surface: header) ──
  if (prediction.surface === "header") {
    if (prediction.forbiddenHeader) {
      const name = prediction.forbiddenHeader.toLowerCase();
      const present = name in headers;
      if (present) {
        if (!confirmable) {
          return {
            ...base,
            status: "inconclusive",
            confidence: hypothesis.confidence,
            evidence:
              `forbidden header \`${prediction.forbiddenHeader}\` present, but ` +
              `the rule is ${hypothesis.level}-level (advisory) — not confirmable`,
          };
        }
        return {
          ...base,
          status: "confirmed",
          confidence: 1.0,
          evidence:
            `${hypothesis.level} violation: response carries header ` +
            `\`${prediction.forbiddenHeader}\`, which the spec forbids. ` +
            `Rule ${hypothesis.specCitation}.`,
        };
      }
      return {
        ...base,
        status: "refuted",
        confidence: 0.0,
        evidence: `forbidden header \`${prediction.forbiddenHeader}\` absent — no divergence`,
      };
    }

    if (prediction.requiredHeader) {
      const name = prediction.requiredHeader.toLowerCase();
      const present = name in headers;
      if (!present) {
        if (!confirmable) {
          return {
            ...base,
            status: "inconclusive",
            confidence: hypothesis.confidence,
            evidence:
              `required header \`${prediction.requiredHeader}\` missing, but ` +
              `the rule is ${hypothesis.level}-level (advisory) — not confirmable`,
          };
        }
        return {
          ...base,
          status: "confirmed",
          confidence: 1.0,
          evidence:
            `${hypothesis.level} violation: response is missing required header ` +
            `\`${prediction.requiredHeader}\`. Rule ${hypothesis.specCitation}.`,
        };
      }
      return {
        ...base,
        status: "refuted",
        confidence: 0.0,
        evidence: `required header \`${prediction.requiredHeader}\` present — no divergence`,
      };
    }
  }

  // Prediction carried no usable matcher for its surface — we can't judge.
  // (conformance-gen's Zod refine should prevent this; defense in depth.)
  return {
    ...base,
    status: "inconclusive",
    confidence: hypothesis.confidence,
    evidence: "predictedObservable carried no matcher applicable to its surface",
  };
}
