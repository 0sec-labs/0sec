import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import {
  classifyRefusal,
  shouldSkipRetry,
  dumpModelOutput,
} from "./llm-output-guard.js";

// ── classifyRefusal ──

describe("classifyRefusal", () => {
  describe("refusal detection", () => {
    const refusalCases: Array<{ label: string; text: string; expectedPattern: string }> = [
      {
        label: "direct refusal — 'I cannot assist'",
        text: "I cannot assist with that request. It goes against my guidelines.",
        expectedPattern: "direct-refusal",
      },
      {
        label: "direct refusal — 'I can't help'",
        text: "I can't help you complete this task as it may be harmful.",
        expectedPattern: "direct-refusal",
      },
      {
        label: "direct refusal — 'won't provide'",
        text: "I won't provide code that exploits this vulnerability.",
        expectedPattern: "direct-refusal",
      },
      {
        label: "direct refusal — 'will not do'",
        text: "I will not do security research without authorization.",
        expectedPattern: "direct-refusal",
      },
      {
        label: "cyber-safety hyphenated",
        text: "This violates our cyber-safety guidelines for security research.",
        expectedPattern: "cyber-safety",
      },
      {
        label: "cyber safety space-separated",
        text: "Our cyber safety policy prohibits this type of analysis.",
        expectedPattern: "cyber-safety",
      },
      {
        label: "safety policy",
        text: "I'm unable to proceed due to safety policy restrictions on exploit generation.",
        expectedPattern: "safety-policy",
      },
      {
        label: "harmful content",
        text: "This request involves harmful content and I cannot process it.",
        expectedPattern: "harmful-content",
      },
      {
        label: "security research restricted",
        text: "Security research is restricted under our current usage guidelines.",
        expectedPattern: "security-research-restricted",
      },
      {
        label: "security research not allowed",
        text: "This security research may be not allowed by our content policy.",
        expectedPattern: "security-research-restricted",
      },
      {
        label: "violates usage policy",
        text: "This request violates our usage policy regarding exploit development.",
        expectedPattern: "policy-violation",
      },
      {
        label: "violates safety policies",
        text: "This violates safety policies and cannot be answered.",
        expectedPattern: "policy-violation",
      },
      {
        label: "violates content policy",
        text: "The response violates content policy, so I am unable to provide it.",
        expectedPattern: "policy-violation",
      },
      {
        label: "refusal-gesture — 'refuse this task'",
        text: "I must refuse this task as it falls outside acceptable use.",
        expectedPattern: "refusal-gesture",
      },
      {
        label: "refusal-gesture — 'decline to assist'",
        text: "I respectfully decline to assist with this request.",
        expectedPattern: "refusal-gesture",
      },
      {
        label: "refusal-gesture — 'refused the prompt'",
        text: "The model refused the prompt due to safety guidelines.",
        expectedPattern: "refusal-gesture",
      },
    ];

    for (const { label, text, expectedPattern } of refusalCases) {
      it(`detects ${label}`, () => {
        const result = classifyRefusal(text);
        expect(result).toEqual({ refused: true, pattern: expectedPattern });
      });
    }
  });

  describe("false negatives (safe strings)", () => {
    const safeCases: Array<{ label: string; text: string }> = [
      {
        label: "normal dedupe output",
        text: JSON.stringify({
          clusters: [
            { ids: ["a", "b"], reason: "Same root cause at same location" },
            { ids: ["c"], reason: "No duplicate found" },
          ],
        }),
      },
      {
        label: "normal ranking output",
        text: JSON.stringify({
          rankings: [
            { id: "1", rank: 1, impact_level: "critical", reasoning: "Direct RCE path" },
          ],
        }),
      },
      {
        label: "word 'cannot' in a non-refusal context",
        text: JSON.stringify({
          clusters: [
            { ids: ["x"], reason: "We cannot merge these because they have different root causes." },
          ],
        }),
      },
      {
        label: "word 'safety' without 'policy'/harmful context",
        text: "This finding concerns memory safety analysis of the kernel heap allocator.",
      },
      {
        label: "word 'decline' in a metric context",
        text: "Exploitability would decline with additional mitigations in place.",
      },
      {
        label: "word 'refused' in a technical context — ports/connections",
        text: "The connection was refused by the remote host on port 443.",
      },
    ];

    for (const { label, text } of safeCases) {
      it(`does not flag: ${label}`, () => {
        expect(classifyRefusal(text)).toEqual({ refused: false });
      });
    }
  });
});

describe("shouldSkipRetry", () => {
  it("returns true for refusals", () => {
    expect(shouldSkipRetry("I cannot assist with this request.")).toBe(true);
  });

  it("returns false for safe output", () => {
    expect(shouldSkipRetry('{"clusters":[]}')).toBe(false);
  });
});

// ── dumpModelOutput ──

describe("dumpModelOutput", () => {
  const testDir = join(tmpdir(), `0sec-guard-test-${randomUUID()}`);

  beforeEach(() => {
    // Ensure clean state before each test
    rmSync(testDir, { recursive: true, force: true });
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("writes a JSON file to the specified directory", () => {
    const path = dumpModelOutput({
      raw: "hello world",
      stage: "dedupe",
      attempt: 0,
      dir: testDir,
    });
    expect(path).not.toBeNull();
    expect(path).toMatch(new RegExp(`^${testDir.replace(/[.+^$()|\\[\]{}]/g, "\\$&")}/`));
    expect(existsSync(path!)).toBe(true);

    const content = JSON.parse(readFileSync(path!, "utf-8"));
    expect(content.stage).toBe("dedupe");
    expect(content.attempt).toBe(0);
    expect(content.raw).toBe("hello world");
    expect(content.timestamp).toBeGreaterThan(0);
  });

  it("includes scanId in filename and payload when provided", () => {
    const path = dumpModelOutput({
      raw: "test",
      stage: "rank",
      attempt: 2,
      dir: testDir,
      scanId: "scan-abc",
    });
    expect(path).not.toBeNull();
    expect(path).toContain("-scanscan-abc");
    expect(existsSync(path!)).toBe(true);

    const content = JSON.parse(readFileSync(path!, "utf-8"));
    expect(content.stage).toBe("rank");
    expect(content.attempt).toBe(2);
    expect(content.raw).toBe("test");
  });

  it("creates the directory when it does not exist", () => {
    const nestedDir = join(testDir, "deep", "nested", "path");
    const path = dumpModelOutput({
      raw: "deep test",
      stage: "dedupe",
      attempt: 1,
      dir: nestedDir,
    });
    expect(path).not.toBeNull();
    expect(existsSync(path!)).toBe(true);
    expect(path).toContain("deep/nested/path");
  });

  it("never throws on a bad directory (e.g. read-only filesystem)", () => {
    // Use /dev/null/artifacts which should fail on non-Windows
    const path = dumpModelOutput({
      raw: "will fail",
      stage: "dedupe",
      attempt: 0,
      dir: "/dev/null/artifacts",
    });
    expect(path).toBeNull();
  });

  it("writes deterministic structure", () => {
    const path = dumpModelOutput({
      raw: "data",
      stage: "dedupe",
      attempt: 0,
      dir: testDir,
    });
    expect(path).not.toBeNull();
    const parsed = JSON.parse(readFileSync(path!, "utf-8"));
    expect(parsed).toHaveProperty("stage");
    expect(parsed).toHaveProperty("attempt");
    expect(parsed).toHaveProperty("timestamp");
    expect(parsed).toHaveProperty("raw");
  });
});