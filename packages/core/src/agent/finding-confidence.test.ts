import { describe, it, expect } from "vitest";
import type { PocStep } from "@0sec/shared";
import {
  computeFindingConfidence,
  pocStatusFloor,
  POC_PRESENT_FLOOR,
  POC_VERIFIABLE_FLOOR,
} from "./finding-confidence.js";

const noteStep: PocStep = {
  id: "s1",
  kind: "exploit",
  summary: "narrate",
  action: { type: "note", text: "the agent says the bug exists" },
};

const verifiableStep: PocStep = {
  id: "s2",
  kind: "verify",
  summary: "curl returns 200",
  action: { type: "shell", cmd: "curl -s -o /dev/null -w '%{http_code}' http://t/" },
  expect: { type: "exit-zero" },
};

const httpVerifiableStep: PocStep = {
  id: "s3",
  kind: "exploit",
  summary: "trigger XSS",
  action: { type: "http", method: "GET", url: "http://t/?q=<script>" },
  expect: { type: "body-contains", text: "<script>" },
};

describe("pocStatusFloor", () => {
  it("returns 0 when no steps are attached", () => {
    expect(pocStatusFloor(undefined)).toBe(0);
    expect(pocStatusFloor([])).toBe(0);
  });

  it("returns POC_PRESENT_FLOOR when steps exist but none are verifiable", () => {
    expect(pocStatusFloor([noteStep])).toBe(POC_PRESENT_FLOOR);
  });

  it("returns POC_VERIFIABLE_FLOOR when at least one step has a verifiable expect predicate", () => {
    expect(pocStatusFloor([noteStep, verifiableStep])).toBe(POC_VERIFIABLE_FLOOR);
    expect(pocStatusFloor([httpVerifiableStep])).toBe(POC_VERIFIABLE_FLOOR);
  });
});

describe("computeFindingConfidence", () => {
  it("returns undefined when neither LLM nor PoC signal is present", () => {
    expect(computeFindingConfidence(undefined, undefined)).toBeUndefined();
    expect(computeFindingConfidence(null, undefined)).toBeUndefined();
    expect(computeFindingConfidence("0.5", undefined)).toBeUndefined();
    expect(computeFindingConfidence(NaN, undefined)).toBeUndefined();
    expect(computeFindingConfidence(Infinity, undefined)).toBeUndefined();
  });

  it("clamps LLM-reported confidence to [0,1]", () => {
    expect(computeFindingConfidence(1.5, undefined)).toBe(1);
    expect(computeFindingConfidence(-0.2, undefined)).toBe(0);
    expect(computeFindingConfidence(0.42, undefined)).toBeCloseTo(0.42);
  });

  it("returns the PoC floor when no LLM number is reported", () => {
    expect(computeFindingConfidence(undefined, [noteStep])).toBe(POC_PRESENT_FLOOR);
    expect(computeFindingConfidence(undefined, [verifiableStep])).toBe(
      POC_VERIFIABLE_FLOOR,
    );
  });

  it("takes the max of LLM number and PoC floor", () => {
    // LLM lower than floor → floor wins
    expect(computeFindingConfidence(0.3, [noteStep])).toBe(POC_PRESENT_FLOOR);
    // LLM higher than floor → LLM wins
    expect(computeFindingConfidence(0.95, [noteStep])).toBeCloseTo(0.95);
    expect(computeFindingConfidence(0.95, [verifiableStep])).toBeCloseTo(0.95);
    // LLM equal to floor
    expect(computeFindingConfidence(POC_VERIFIABLE_FLOOR, [verifiableStep])).toBe(
      POC_VERIFIABLE_FLOOR,
    );
  });

  it("output is always finite and within [0,1]", () => {
    const cases: Array<[unknown, PocStep[] | undefined]> = [
      [0, undefined],
      [1, undefined],
      [0.5, [noteStep]],
      [-1e9, [verifiableStep]],
      [1e9, [verifiableStep]],
      [0.7, [httpVerifiableStep, noteStep]],
    ];
    for (const [raw, steps] of cases) {
      const out = computeFindingConfidence(raw, steps);
      expect(out).toBeDefined();
      expect(Number.isFinite(out)).toBe(true);
      expect(out!).toBeGreaterThanOrEqual(0);
      expect(out!).toBeLessThanOrEqual(1);
    }
  });
});
