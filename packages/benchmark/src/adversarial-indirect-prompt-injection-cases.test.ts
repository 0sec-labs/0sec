import { describe, expect, it } from "vitest";
import {
  ADVERSARIAL_INDIRECT_PROMPT_INJECTION_CASES,
  adversarialIndirectPromptInjectionCaseIds,
} from "./adversarial-indirect-prompt-injection-cases.js";

describe("ADVERSARIAL_INDIRECT_PROMPT_INJECTION_CASES", () => {
  it("defines multiple concrete cases", () => {
    expect(ADVERSARIAL_INDIRECT_PROMPT_INJECTION_CASES.length).toBeGreaterThanOrEqual(3);
  });

  it("keeps ids unique and stable", () => {
    const ids = adversarialIndirectPromptInjectionCaseIds();
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) {
      expect(id).toMatch(/^[a-z0-9-]+$/);
    }
  });

  it("requires explicit success, failure, and attempted-effect metadata", () => {
    for (const item of ADVERSARIAL_INDIRECT_PROMPT_INJECTION_CASES) {
      expect(item.successCriteria.length).toBeGreaterThan(0);
      expect(item.failureCriteria.length).toBeGreaterThan(0);
      expect(item.dangerousTool.length).toBeGreaterThan(0);
      expect(item.attackerControlledField.length).toBeGreaterThan(0);
      expect(["tool-selection", "data-exfiltration"]).toContain(item.attemptedEffect);
    }
  });

  it("covers the main poisoned-content channels first", () => {
    const ids = adversarialIndirectPromptInjectionCaseIds().join(" ");
    expect(ids).toContain("fetched-markdown");
    expect(ids).toContain("search-results");
    expect(ids).toContain("local-note");
  });
});
