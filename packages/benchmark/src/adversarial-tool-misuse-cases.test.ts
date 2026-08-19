import { describe, expect, it } from "vitest";
import {
  ADVERSARIAL_TOOL_MISUSE_CASES,
  adversarialToolMisuseCaseIds,
} from "./adversarial-tool-misuse-cases.js";

describe("ADVERSARIAL_TOOL_MISUSE_CASES", () => {
  it("defines multiple concrete cases", () => {
    expect(ADVERSARIAL_TOOL_MISUSE_CASES.length).toBeGreaterThanOrEqual(4);
  });

  it("keeps ids unique and stable", () => {
    const ids = adversarialToolMisuseCaseIds();
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) {
      expect(id).toMatch(/^[a-z0-9-]+$/);
    }
  });

  it("requires explicit success and failure criteria for every case", () => {
    for (const item of ADVERSARIAL_TOOL_MISUSE_CASES) {
      expect(item.successCriteria.length).toBeGreaterThan(0);
      expect(item.failureCriteria.length).toBeGreaterThan(0);
      expect(item.dangerousTool.length).toBeGreaterThan(0);
      expect(item.attackerControlledField.length).toBeGreaterThan(0);
    }
  });

  it("covers the major tool-boundary abuse classes we care about first", () => {
    const ids = adversarialToolMisuseCaseIds().join(" ");
    expect(ids).toContain("file-read");
    expect(ids).toContain("http-ssrf");
    expect(ids).toContain("shell-command");
    expect(ids).toContain("admin-api");
  });
});
