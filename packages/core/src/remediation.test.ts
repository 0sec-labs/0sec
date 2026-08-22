/**
 * Remediation guidance — static knowledge base and the model-written path.
 *
 * `generateRemediationWithLLM` is deliberately FAIL-OPEN: any failure quietly
 * yields the static knowledge-base answer. That is right for output quality and
 * dangerous for operability — a mis-wired, unauthorised, or rate-limited
 * runtime produces output indistinguishable from a working one, and the tokens
 * it burned are invisible. These tests pin both halves: that the fallback really
 * is silent to the CALLER, and that it is never silent to the OBSERVER.
 */

import { describe, it, expect, vi } from "vitest";
import type { Finding } from "@0sec/shared";
import {
  generateRemediation,
  generateRemediationWithLLM,
  type RemediationObservation,
} from "./remediation.js";
import type { NativeRuntime } from "./runtime/types.js";

function mkFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "F-1",
    templateId: "t-1",
    title: "SQL injection in /search",
    description: "The q parameter reaches a raw query.",
    severity: "high",
    category: "sql-injection",
    status: "verified",
    evidence: { request: "GET /search?q=1'", response: "SQL syntax error", analysis: "" },
    ...overrides,
  } as Finding;
}

/** A NativeRuntime stub whose single `executeNative` reply is scripted. */
function stubRuntime(reply: unknown, usage?: Record<string, number>): NativeRuntime {
  return {
    executeNative: vi.fn(async () => ({
      content: [{ type: "text", text: typeof reply === "string" ? reply : JSON.stringify(reply) }],
      usage,
    })),
  } as unknown as NativeRuntime;
}

const VALID_REPLY = {
  summary: "Use a parameterised query for the q parameter.",
  steps: ["Replace concatenation in searchHandler", "Add a regression test"],
  codeExample: { before: "`... ${q}`", after: "db.query(sql, [q])", language: "ts" },
  references: ["https://owasp.org/sqli"],
};

describe("generateRemediation (static KB)", () => {
  it("returns guidance for a known category", () => {
    const r = generateRemediation(mkFinding());
    expect(r.summary).toBeTruthy();
    expect(r.steps.length).toBeGreaterThan(0);
    expect(Array.isArray(r.references)).toBe(true);
  });

  it("falls back rather than throwing on an unknown category", () => {
    const r = generateRemediation(mkFinding({ category: "not-a-real-category" as Finding["category"] }));
    expect(r.summary).toBeTruthy();
    expect(r.steps.length).toBeGreaterThan(0);
  });

  it("returns copies, so a caller cannot mutate the shared KB", () => {
    // Two findings in the same category must not alias one another's arrays.
    const a = generateRemediation(mkFinding());
    const b = generateRemediation(mkFinding());
    a.steps.push("mutated");
    expect(b.steps).not.toContain("mutated");
  });
});

describe("generateRemediationWithLLM — success path", () => {
  it("uses the model's finding-specific guidance", async () => {
    const r = await generateRemediationWithLLM(mkFinding(), stubRuntime(VALID_REPLY));
    expect(r.summary).toBe("Use a parameterised query for the q parameter.");
    expect(r.codeExample?.after).toBe("db.query(sql, [q])");
  });

  it("unwraps a ```json fenced reply", async () => {
    const fenced = "```json\n" + JSON.stringify(VALID_REPLY) + "\n```";
    const r = await generateRemediationWithLLM(mkFinding(), stubRuntime(fenced));
    expect(r.summary).toBe(VALID_REPLY.summary);
  });

  it("reports source 'llm' and the token usage", async () => {
    const seen: RemediationObservation[] = [];
    await generateRemediationWithLLM(
      mkFinding(),
      stubRuntime(VALID_REPLY, { inputTokens: 120, outputTokens: 45 }),
      { onObservation: (o) => seen.push(o) },
    );
    expect(seen).toHaveLength(1);
    expect(seen[0].source).toBe("llm");
    expect(seen[0].usage?.inputTokens).toBe(120);
    expect(seen[0].usage?.outputTokens).toBe(45);
  });

  it("omits codeExample when the model did not supply a usable one", async () => {
    const noExample = { ...VALID_REPLY, codeExample: { before: 1, after: 2 } };
    const r = await generateRemediationWithLLM(mkFinding(), stubRuntime(noExample));
    expect(r.codeExample).toBeUndefined();
    expect(r.summary).toBe(VALID_REPLY.summary);
  });
});

describe("generateRemediationWithLLM — fail-open, but never silent", () => {
  const baseline = generateRemediation(mkFinding());

  it("falls back to the KB when the reply is not valid JSON", async () => {
    const seen: RemediationObservation[] = [];
    const r = await generateRemediationWithLLM(mkFinding(), stubRuntime("not json at all"), {
      onObservation: (o) => seen.push(o),
    });
    expect(r.summary).toBe(baseline.summary);
    expect(seen[0].source).toBe("baseline");
    expect(seen[0].fallbackReason).toBe("error");
  });

  it("falls back when the JSON is well-formed but the wrong shape", async () => {
    const seen: RemediationObservation[] = [];
    const r = await generateRemediationWithLLM(
      mkFinding(),
      stubRuntime({ summary: "ok", steps: [], references: [] }, { inputTokens: 10, outputTokens: 2 }),
      { onObservation: (o) => seen.push(o) },
    );
    expect(r.summary).toBe(baseline.summary);
    expect(seen[0].source).toBe("baseline");
    expect(seen[0].fallbackReason).toBe("invalid_structure");
    // The call still cost tokens even though its output was unusable — that
    // spend must be reported, not swallowed with the bad answer.
    expect(seen[0].usage?.inputTokens).toBe(10);
  });

  it("falls back and reports 'no_text_block' when the runtime returns no text", async () => {
    // What a keyless / errored runtime looks like: it resolves, with nothing in it.
    const empty = {
      executeNative: vi.fn(async () => ({ content: [], usage: { inputTokens: 3, outputTokens: 0 } })),
    } as unknown as NativeRuntime;
    const seen: RemediationObservation[] = [];
    const r = await generateRemediationWithLLM(mkFinding(), empty, {
      onObservation: (o) => seen.push(o),
    });
    expect(r.summary).toBe(baseline.summary);
    expect(seen[0].fallbackReason).toBe("no_text_block");
    expect(seen[0].usage?.inputTokens).toBe(3);
  });

  it("falls back and reports 'error' when the runtime throws", async () => {
    const throwing = {
      executeNative: vi.fn(async () => {
        throw new Error("429 rate limited");
      }),
    } as unknown as NativeRuntime;
    const seen: RemediationObservation[] = [];
    const r = await generateRemediationWithLLM(mkFinding(), throwing, {
      onObservation: (o) => seen.push(o),
    });
    expect(r.summary).toBe(baseline.summary);
    expect(seen[0].source).toBe("baseline");
    expect(seen[0].fallbackReason).toBe("error");
    // No result exists to read usage from when the call threw.
    expect(seen[0].usage).toBeUndefined();
  });

  it("never throws at the caller, whatever the runtime does", async () => {
    const hostile = {
      executeNative: vi.fn(async () => {
        throw new Error("boom");
      }),
    } as unknown as NativeRuntime;
    await expect(generateRemediationWithLLM(mkFinding(), hostile)).resolves.toBeTruthy();
  });

  it("works with no observer supplied (the optional param stays optional)", async () => {
    const r = await generateRemediationWithLLM(mkFinding(), stubRuntime(VALID_REPLY));
    expect(r.summary).toBe(VALID_REPLY.summary);
  });
});
