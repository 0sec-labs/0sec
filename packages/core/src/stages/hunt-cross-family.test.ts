/**
 * Cross-family adversarial refuter (hunt-cross-family.ts, issue #661). Coverage:
 *
 *   - `crossFamilyRefuteEnabled`: OFF by default, ON only for a truthy env.
 *   - `selectCrossFamilyRefuter`: passthrough when disabled / no finder family /
 *     no distinct candidate; forces a different-family refuter when one is
 *     available; keeps an already-cross-family refuter and records the pairing.
 *   - `makeSkepticVerifier` wiring (hunt-scan.ts): with the flag OFF (default)
 *     the model handed to the finder and the reason strings are byte-identical
 *     to today; with the flag ON and a distinct family available the refute
 *     pass runs on the different-family model and the reason is annotated.
 */

import { describe, expect, it, vi } from "vitest";
import type { Finding } from "@pwnkit/shared";
import { crossFamilyRefuteEnabled, selectCrossFamilyRefuter } from "./hunt-cross-family.js";

const agenticScanMock = vi.fn();
vi.mock("../agentic-scanner.js", () => ({
  agenticScan: (...args: unknown[]) => agenticScanMock(...args),
}));

const { makeSkepticVerifier } = await import("./hunt-scan.js");

function mkFinding(id: string, title: string): Finding {
  return {
    id,
    templateId: "xfamily-test",
    title,
    description: title,
    severity: "medium",
    category: "other",
    status: "discovered",
    evidence: { request: "", response: "", analysis: "" },
  };
}

describe("crossFamilyRefuteEnabled", () => {
  it("is OFF by default and ON only for a truthy PWNKIT_HUNT_CROSS_FAMILY", () => {
    const prev = process.env.PWNKIT_HUNT_CROSS_FAMILY;
    try {
      delete process.env.PWNKIT_HUNT_CROSS_FAMILY;
      expect(crossFamilyRefuteEnabled()).toBe(false);
      process.env.PWNKIT_HUNT_CROSS_FAMILY = "no";
      expect(crossFamilyRefuteEnabled()).toBe(false);
      process.env.PWNKIT_HUNT_CROSS_FAMILY = "1";
      expect(crossFamilyRefuteEnabled()).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_HUNT_CROSS_FAMILY;
      else process.env.PWNKIT_HUNT_CROSS_FAMILY = prev;
    }
  });
});

describe("selectCrossFamilyRefuter", () => {
  it("passthrough when disabled — returns the configured refuter unchanged", () => {
    const choice = selectCrossFamilyRefuter({
      enabled: false,
      finderModel: "claude-opus-4-7",
      refuterModel: "claude-opus-4-7",
      candidates: ["gpt-5.4"],
    });
    expect(choice).toEqual({ model: "claude-opus-4-7", crossFamily: false });
  });

  it("passthrough when the finder family is unknown (nothing to decorrelate from)", () => {
    const choice = selectCrossFamilyRefuter({
      enabled: true,
      refuterModel: "claude-opus-4-7",
      candidates: ["gpt-5.4"],
    });
    expect(choice.crossFamily).toBe(false);
    expect(choice.model).toBe("claude-opus-4-7");
  });

  it("keeps an already-cross-family refuter and records the pairing", () => {
    const choice = selectCrossFamilyRefuter({
      enabled: true,
      finderModel: "claude-opus-4-7",
      refuterModel: "gpt-5.4",
      candidates: ["gemini-2.5-pro"],
    });
    expect(choice).toEqual({
      model: "gpt-5.4",
      crossFamily: true,
      finderFamily: "anthropic",
      refuterFamily: "openai",
    });
  });

  it("forces a different-family candidate when the configured refuter shares the finder family", () => {
    const choice = selectCrossFamilyRefuter({
      enabled: true,
      finderModel: "claude-opus-4-7",
      refuterModel: "claude-haiku-4-5",
      candidates: ["claude-sonnet-4-6", "gpt-5.4"],
    });
    expect(choice).toEqual({
      model: "gpt-5.4",
      crossFamily: true,
      finderFamily: "anthropic",
      refuterFamily: "openai",
    });
  });

  it("picks a distinct-family candidate even with no pre-configured refuter", () => {
    const choice = selectCrossFamilyRefuter({
      enabled: true,
      finderModel: "gpt-5.4",
      candidates: ["gpt-4o", "gemini-2.5-pro"],
    });
    expect(choice.crossFamily).toBe(true);
    expect(choice.model).toBe("gemini-2.5-pro");
    expect(choice.refuterFamily).toBe("google");
  });

  it("passthrough when no candidate is a distinct family (assume-FP safe fallback)", () => {
    const choice = selectCrossFamilyRefuter({
      enabled: true,
      finderModel: "claude-opus-4-7",
      refuterModel: "claude-haiku-4-5",
      candidates: ["claude-sonnet-4-6"],
    });
    expect(choice).toEqual({ model: "claude-haiku-4-5", crossFamily: false });
  });
});

describe("makeSkepticVerifier — cross-family wiring", () => {
  it("gate OFF (default): the finder model and reason string are byte-identical to today", async () => {
    const prev = process.env.PWNKIT_HUNT_CROSS_FAMILY;
    delete process.env.PWNKIT_HUNT_CROSS_FAMILY;
    try {
      agenticScanMock.mockReset();
      let capturedModel: string | undefined = "sentinel";
      agenticScanMock.mockImplementation(async ({ config }: { config: { model?: string } }) => {
        capturedModel = config.model;
        return { findings: [mkFinding("survivor", "still real")] };
      });

      // finderModel + refuterCandidates are supplied but the flag is OFF → they
      // must be ignored, the configured `model` used verbatim.
      const verify = makeSkepticVerifier({
        sourceRoot: "/src",
        runtime: "api",
        model: "claude-opus-4-7",
        finderModel: "claude-opus-4-7",
        refuterCandidates: ["gpt-5.4"],
      });
      const result = await verify(mkFinding("f1", "some finding"), { path: "a.c" });

      expect(capturedModel).toBe("claude-opus-4-7");
      expect(result.reason).toBe("survived adversarial refute pass");
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_HUNT_CROSS_FAMILY;
      else process.env.PWNKIT_HUNT_CROSS_FAMILY = prev;
    }
  });

  it("gate ON: the refute pass runs on the different-family model and annotates the reason", async () => {
    agenticScanMock.mockReset();
    let capturedModel: string | undefined = "sentinel";
    agenticScanMock.mockImplementation(async ({ config }: { config: { model?: string } }) => {
      capturedModel = config.model;
      return { findings: [mkFinding("survivor", "still real")] };
    });

    // Explicit opt (not the env) so this test never leaks global state.
    const verify = makeSkepticVerifier({
      sourceRoot: "/src",
      runtime: "api",
      model: "claude-opus-4-7",
      crossFamilyRefute: true,
      finderModel: "claude-opus-4-7",
      refuterCandidates: ["gpt-5.4"],
    });
    const result = await verify(mkFinding("f1", "some finding"), { path: "a.c" });

    expect(capturedModel).toBe("gpt-5.4");
    expect(result.confirmed).toBe(true);
    expect(result.reason).toContain("survived adversarial refute pass");
    expect(result.reason).toContain("cross-family refuter: openai vs finder anthropic");
  });

  it("gate ON but no distinct family available: byte-identical to today (no annotation)", async () => {
    agenticScanMock.mockReset();
    let capturedModel: string | undefined = "sentinel";
    agenticScanMock.mockImplementation(async ({ config }: { config: { model?: string } }) => {
      capturedModel = config.model;
      return { findings: [] };
    });

    const verify = makeSkepticVerifier({
      sourceRoot: "/src",
      runtime: "api",
      model: "claude-opus-4-7",
      crossFamilyRefute: true,
      finderModel: "claude-opus-4-7",
      refuterCandidates: ["claude-sonnet-4-6"], // same family → no distinct option
    });
    const result = await verify(mkFinding("f1", "some finding"), { path: "a.c" });

    expect(capturedModel).toBe("claude-opus-4-7");
    expect(result.reason).toBe("refuted: skeptic could not reproduce the claim from source");
  });
});
