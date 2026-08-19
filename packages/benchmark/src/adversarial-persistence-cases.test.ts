import { describe, expect, it } from "vitest";
import {
  ADVERSARIAL_PERSISTENCE_CASES,
  adversarialPersistenceCaseIds,
} from "./adversarial-persistence-cases.js";

describe("ADVERSARIAL_PERSISTENCE_CASES", () => {
  it("defines multiple concrete cases", () => {
    expect(ADVERSARIAL_PERSISTENCE_CASES.length).toBeGreaterThanOrEqual(3);
  });

  it("keeps ids unique and stable", () => {
    const ids = adversarialPersistenceCaseIds();
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) {
      expect(id).toMatch(/^[a-z0-9-]+$/);
    }
  });

  it("records durable surface and later-effect metadata", () => {
    for (const item of ADVERSARIAL_PERSISTENCE_CASES) {
      expect(["claude-md", "notes-file", "skill-doc"]).toContain(item.durableSurface);
      expect(["instruction-hijack", "secret-exfiltration"]).toContain(item.laterEffect);
      expect(item.successCriteria.length).toBeGreaterThan(0);
      expect(item.failureCriteria.length).toBeGreaterThan(0);
    }
  });

  it("covers the main durable instruction surfaces first", () => {
    const ids = adversarialPersistenceCaseIds().join(" ");
    expect(ids).toContain("claude-md");
    expect(ids).toContain("notes-file");
    expect(ids).toContain("skill-doc");
  });
});
