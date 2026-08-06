/**
 * Runtime verifier stage — skeleton tests.
 *
 * Coverage for the no-op-without-key contract. The full E2B driver tests
 * will be added when the sandbox provisioner is implemented.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@pwnkit/shared";
import { makeRuntimeVerifier } from "./runtime-verify.js";

const E2B_KEY_BACKUP = process.env.E2B_API_KEY;

function mkFinding(id: string): Finding {
  return {
    id,
    templateId: "runtime-verify-test",
    title: `test finding ${id}`,
    description: "a test finding",
    severity: "high",
    category: "insecure-design",
    status: "discovered",
    evidence: { request: "", response: "", analysis: "curl /api/endpoint" },
    timestamp: Date.now(),
  };
}

describe("makeRuntimeVerifier", () => {
  beforeEach(() => {
    delete process.env.E2B_API_KEY;
  });

  afterEach(() => {
    if (E2B_KEY_BACKUP) process.env.E2B_API_KEY = E2B_KEY_BACKUP;
  });

  it("passes every finding through unchanged when E2B_API_KEY is unset", async () => {
    const verifier = makeRuntimeVerifier();
    const finding = mkFinding("f-1");
    const candidate = { path: "/src/test.ts" };

    const result = await verifier(finding, candidate);

    // The no-op gate never rejects — it passes findings through with a note.
    expect(result.confirmed).toBe(true);
    expect(result.reason).toMatch(/E2B_API_KEY unset/);
  });

  it("invokes the injected verify function when E2B_API_KEY is set", async () => {
    process.env.E2B_API_KEY = "test-key";
    const injected = vi.fn().mockResolvedValue({
      outcome: "pass" as const,
      confidence: 0.9,
      transcript: "curl succeeded",
      reason: "PoC triggered",
    });

    const verifier = makeRuntimeVerifier({ verify: injected });
    const finding = mkFinding("f-2");
    const candidate = { path: "/src/test.ts" };

    const result = await verifier(finding, candidate);

    expect(injected).toHaveBeenCalledOnce();
    expect(injected).toHaveBeenCalledWith(
      expect.objectContaining({
        finding,
        pocPlan: finding.evidence.analysis,
      }),
    );
    expect(result.confirmed).toBe(true);
    expect(result.reason).toMatch(/PASS/);
  });

  it("downgrades but never rejects a finding on FAIL outcome", async () => {
    process.env.E2B_API_KEY = "test-key";
    const injected = vi.fn().mockResolvedValue({
      outcome: "fail" as const,
      confidence: 0.2,
      transcript: "curl returned 404",
      reason: "endpoint not reachable",
    });

    const verifier = makeRuntimeVerifier({ verify: injected });
    const result = await verifier(mkFinding("f-3"), { path: "/src/test.ts" });

    expect(result.confirmed).toBe(true);
    expect(result.reason).toMatch(/FAIL.*endpoint not reachable/);
  });

  it("downgrades but never rejects on verifier exception", async () => {
    process.env.E2B_API_KEY = "test-key";
    const injected = vi.fn().mockRejectedValue(new Error("sandbox timeout"));

    const verifier = makeRuntimeVerifier({ verify: injected });
    const result = await verifier(mkFinding("f-4"), { path: "/src/test.ts" });

    expect(result.confirmed).toBe(true);
    expect(result.reason).toMatch(/ERROR.*sandbox timeout/);
  });
});