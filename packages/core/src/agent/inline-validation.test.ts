import { describe, it, expect, vi } from "vitest";
import type { AttackCategory, Finding } from "@pwnkit/shared";
import type { OracleResult } from "../triage/oracles.js";
import {
  validateFindingInline,
  buildInlineValidationNote,
  shouldValidateInline,
  type InlineOracle,
} from "./inline-validation.js";
import { scoreEvidence } from "./egats.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    templateId: "manual",
    title: "Blind SQLi in /search",
    description: "single-quote induces SQL error",
    severity: "high",
    category: "sql-injection" as AttackCategory,
    status: "discovered",
    evidence: {
      request: "GET /search?q=foo HTTP/1.1\nHost: example.com\n\n",
      response: "",
      analysis: "Error on quote suggests SQLi",
    },
    timestamp: 0,
    ...overrides,
  };
}

const oracleOf =
  (r: OracleResult): InlineOracle =>
  async () =>
    r;

describe("shouldValidateInline", () => {
  it("validates high and critical, skips the rest", () => {
    expect(shouldValidateInline(makeFinding({ severity: "high" }))).toBe(true);
    expect(shouldValidateInline(makeFinding({ severity: "critical" }))).toBe(true);
    expect(shouldValidateInline(makeFinding({ severity: "medium" }))).toBe(false);
    expect(shouldValidateInline(makeFinding({ severity: "low" }))).toBe(false);
    expect(shouldValidateInline(makeFinding({ severity: "info" }))).toBe(false);
  });
});

describe("validateFindingInline", () => {
  it("confirmed when the oracle verifies", async () => {
    const out = await validateFindingInline(makeFinding(), "https://t", {
      oracle: oracleOf({
        verified: true,
        confidence: 1,
        evidence: "boolean_diff | sql_error: syntax",
        reason: "",
      }),
    });
    expect(out.confirmed).toBe(true);
    expect(out.inconclusive).toBe(false);
    expect(out.reason).toContain("sql_error");
    expect(out.confidence).toBe(1);
  });

  it("unconfirmed (clean negative) — NOT inconclusive", async () => {
    const out = await validateFindingInline(makeFinding(), "https://t", {
      oracle: oracleOf({
        verified: false,
        confidence: 0,
        evidence: "",
        reason: "no sqli signals fired",
      }),
    });
    expect(out.confirmed).toBe(false);
    expect(out.inconclusive).toBe(false);
    expect(out.reason).toContain("no sqli signals");
  });

  it("inconclusive when the oracle reports an infra error", async () => {
    const out = await validateFindingInline(makeFinding(), "https://t", {
      oracle: oracleOf({
        verified: false,
        confidence: 0,
        evidence: "",
        reason: "baseline request failed",
      }),
    });
    expect(out.confirmed).toBe(false);
    expect(out.inconclusive).toBe(true);
  });

  it("inconclusive (never false-positive) when the oracle THROWS", async () => {
    const out = await validateFindingInline(makeFinding(), "https://t", {
      oracle: async () => {
        throw new Error("collector failed to bind");
      },
    });
    expect(out.confirmed).toBe(false);
    expect(out.inconclusive).toBe(true);
    expect(out.reason).toContain("inline oracle errored");
  });
});

describe("buildInlineValidationNote", () => {
  const base = {
    findingId: "f1",
    category: "sql-injection",
    severity: "high",
    evidence: "",
    confidence: 0,
  };
  it("confirmed note tells the agent to stop re-testing", () => {
    const note = buildInlineValidationNote({
      ...base,
      confirmed: true,
      inconclusive: false,
      reason: "sql_error",
    });
    expect(note).toContain("CONFIRMED");
    expect(note).toMatch(/move on|do not keep re-testing/i);
  });
  it("unconfirmed note says do not assume success", () => {
    const note = buildInlineValidationNote({
      ...base,
      confirmed: false,
      inconclusive: false,
      reason: "no signals",
    });
    expect(note).toContain("UNCONFIRMED");
    expect(note).toMatch(/do not assume success/i);
  });
  it("inconclusive note is explicitly NOT a refutation", () => {
    const note = buildInlineValidationNote({
      ...base,
      confirmed: false,
      inconclusive: true,
      reason: "baseline request failed",
    });
    expect(note).toContain("INCONCLUSIVE");
    expect(note).toMatch(/not a refutation/i);
  });
});

describe("scoreEvidence — inline confirmation dominates regex (#554)", () => {
  it("a confirmed finding saturates the branch score to 1.0 despite negatives", () => {
    const confirmed = makeFinding({
      inlineValidation: {
        confirmed: true,
        inconclusive: false,
        reason: "boolean_diff | sql_error",
        confidence: 1,
      },
    });
    // Output is full of dead-end NEGATIVE signals.
    const noisyNegative =
      "403 Forbidden\n404 Not Found\nconnection refused\nnot vulnerable";
    const { score, evidence } = scoreEvidence(noisyNegative, [confirmed]);
    expect(score).toBe(1);
    expect(evidence.some((e) => e.source === "inline_validation")).toBe(true);
  });

  it("an UNCONFIRMED finding does not get the dominance boost", () => {
    const unconfirmed = makeFinding({
      inlineValidation: {
        confirmed: false,
        inconclusive: false,
        reason: "no signals",
      },
    });
    const confirmed = makeFinding({
      id: "f2",
      inlineValidation: {
        confirmed: true,
        inconclusive: false,
        reason: "sql_error",
        confidence: 1,
      },
    });
    const noise = "HTTP/1.1 404 Not Found";
    const un = scoreEvidence(noise, [unconfirmed]);
    const co = scoreEvidence(noise, [confirmed]);
    // The confirmed one reaches the ceiling; the unconfirmed one does not get
    // the extra +1.0 inline boost (only the base finding signal).
    expect(co.score).toBe(1);
    expect(un.evidence.some((e) => e.source === "inline_validation")).toBe(false);
  });
});
