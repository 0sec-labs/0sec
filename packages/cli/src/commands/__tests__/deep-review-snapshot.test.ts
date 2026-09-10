import type * as Core from "@0sec/core";
import { describe, expect, it, vi } from "vitest";

vi.mock("@0sec/core", async (importOriginal) => {
  const actual = await importOriginal<typeof Core>();
  return { ...actual, loadAppsecFinderLenses: () => [] };
});
import { lensSetDigest } from "../deep-review.js";

describe("deep review lens attribution", () => {
  it("distinguishes changed instructions even when lens identifiers stay unchanged", () => {
    const before = [{ id: "auth", challengeHint: "Check authentication" }];
    const after = [{ id: "auth", challengeHint: "Check authentication and cross-tenant authorization" }];
    expect(lensSetDigest(before)).not.toBe(lensSetDigest(after));
    expect(lensSetDigest(before)).toBe(lensSetDigest([{ ...before[0]! }]));
  });
});
