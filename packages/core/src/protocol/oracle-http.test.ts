import { describe, expect, it } from "vitest";

import { judgeHttpDivergence } from "./oracle-http.js";
import type {
  DivergenceHypothesis,
  ObservedHttpResponse,
  RequirementLevel,
  HttpRuleSurface,
} from "./model.js";

/** Build a hypothesis quickly for table-driven cases. */
function hyp(
  overrides: Partial<DivergenceHypothesis> & {
    level: RequirementLevel;
    surface: HttpRuleSurface;
  },
): DivergenceHypothesis {
  return {
    ruleId: "r1",
    specCitation: "RFC 9110 §9.3.8",
    level: overrides.level,
    implLocation: "handle()",
    rationale: "test",
    predictedObservable: {
      surface: overrides.surface,
      ...overrides.predictedObservable,
    },
    exercise: { method: "TRACE", path: "/" },
    confidence: 0.5,
    ...overrides,
  };
}

function res(
  status: number,
  headers?: Record<string, string>,
  error?: string,
): ObservedHttpResponse {
  return error !== undefined ? { status, error } : { status, headers };
}

describe("judgeHttpDivergence — status/method surface", () => {
  it("CONFIRMS a MUST violation: forbidden status observed", () => {
    const h = hyp({
      level: "MUST",
      surface: "method",
      predictedObservable: { surface: "method", expectedStatusIn: [405], forbiddenStatusIn: [200] },
    });
    const v = judgeHttpDivergence(h, res(200));
    expect(v.status).toBe("confirmed");
    expect(v.confidence).toBe(1.0);
  });

  it("CONFIRMS a MUST NOT violation the same way", () => {
    const h = hyp({
      level: "MUST NOT",
      surface: "method",
      predictedObservable: { surface: "method", forbiddenStatusIn: [200, 201] },
    });
    expect(judgeHttpDivergence(h, res(201)).status).toBe("confirmed");
  });

  it("does NOT confirm a SHOULD violation — inconclusive, prior preserved", () => {
    const h = hyp({
      level: "SHOULD",
      surface: "method",
      predictedObservable: { surface: "method", forbiddenStatusIn: [200] },
      confidence: 0.42,
    });
    const v = judgeHttpDivergence(h, res(200));
    expect(v.status).toBe("inconclusive");
    expect(v.confidence).toBe(0.42); // hypothesis prior preserved
  });

  it("REFUTES when the observed status is in the conformant set", () => {
    const h = hyp({
      level: "MUST",
      surface: "method",
      predictedObservable: { surface: "method", expectedStatusIn: [405], forbiddenStatusIn: [200] },
    });
    const v = judgeHttpDivergence(h, res(405));
    expect(v.status).toBe("refuted");
    expect(v.confidence).toBe(0.0);
  });

  it("is INCONCLUSIVE for a status neither expected nor forbidden", () => {
    const h = hyp({
      level: "MUST",
      surface: "method",
      predictedObservable: { surface: "method", expectedStatusIn: [405], forbiddenStatusIn: [200] },
      confidence: 0.6,
    });
    // 501 (Not Implemented) is arguably acceptable; spec didn't enumerate it.
    const v = judgeHttpDivergence(h, res(501));
    expect(v.status).toBe("inconclusive");
    expect(v.confidence).toBe(0.6);
  });

  it("is INCONCLUSIVE on a transport error — never confirm on no data", () => {
    const h = hyp({
      level: "MUST",
      surface: "method",
      predictedObservable: { surface: "method", forbiddenStatusIn: [200] },
      confidence: 0.5,
    });
    const v = judgeHttpDivergence(h, res(0, undefined, "ECONNREFUSED"));
    expect(v.status).toBe("inconclusive");
    expect(v.confidence).toBe(0.5);
  });
});

describe("judgeHttpDivergence — header surface", () => {
  it("CONFIRMS a MUST: required header missing", () => {
    const h = hyp({
      level: "MUST",
      surface: "header",
      predictedObservable: { surface: "header", requiredHeader: "Content-Type" },
    });
    const v = judgeHttpDivergence(h, res(200, { "x-other": "1" }));
    expect(v.status).toBe("confirmed");
  });

  it("REFUTES when the required header is present (case-insensitive)", () => {
    const h = hyp({
      level: "MUST",
      surface: "header",
      predictedObservable: { surface: "header", requiredHeader: "Content-Type" },
    });
    const v = judgeHttpDivergence(h, res(200, { "content-type": "text/html" }));
    expect(v.status).toBe("refuted");
  });

  it("CONFIRMS a MUST NOT: forbidden header present", () => {
    const h = hyp({
      level: "MUST NOT",
      surface: "header",
      predictedObservable: { surface: "header", forbiddenHeader: "Server" },
    });
    const v = judgeHttpDivergence(h, res(200, { server: "leaky/1.0" }));
    expect(v.status).toBe("confirmed");
  });

  it("REFUTES when the forbidden header is absent", () => {
    const h = hyp({
      level: "MUST NOT",
      surface: "header",
      predictedObservable: { surface: "header", forbiddenHeader: "Server" },
    });
    expect(judgeHttpDivergence(h, res(200, {})).status).toBe("refuted");
  });

  it("does NOT confirm a SHOULD missing-header — inconclusive", () => {
    const h = hyp({
      level: "SHOULD",
      surface: "header",
      predictedObservable: { surface: "header", requiredHeader: "X-Frame-Options" },
      confidence: 0.3,
    });
    const v = judgeHttpDivergence(h, res(200, {}));
    expect(v.status).toBe("inconclusive");
    expect(v.confidence).toBe(0.3);
  });
});
