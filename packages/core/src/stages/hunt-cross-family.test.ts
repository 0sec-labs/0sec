/**
 * Cross-family adversarial refuter (hunt-cross-family.ts, issue #661). Coverage:
 *
 *   - `crossFamilyRefuteEnabled`: ON by default, OFF only for an explicit
 *     falsey env (the #661 default flip).
 *   - `refuterFamily`: classifies by MODEL family, unwrapping the `openrouter/`
 *     routing prefix so an OpenRouter-fronted Claude never counts as
 *     decorrelated from a direct Claude.
 *   - `availableRefuterCandidates`: roster derived from configured provider
 *     auth; env override; EMPTY when no provider auth is present.
 *   - `selectCrossFamilyRefuter`: passthrough (with a `status` saying why) when
 *     disabled / no finder family / no distinct candidate; forces a
 *     different-family refuter when one is available; avoids EVERY finder family
 *     in a multi-model fan-out; keeps an already-cross-family refuter.
 *   - `makeSkepticVerifier` wiring (hunt-scan.ts): the single-provider
 *     deployment degrades gracefully to the same-family refuter; two providers
 *     resolve finder and refuter to different families; a FAILING cross-family
 *     call degrades to the original model instead of throwing (which upstream
 *     would treat as fail-closed and drop the finding); every verdict carries a
 *     `decorrelation` report.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@0sec/shared";
import {
  availableRefuterCandidates,
  crossFamilyRefuteEnabled,
  describeRefuterChoice,
  refuterFamily,
  selectCrossFamilyRefuter,
} from "./hunt-cross-family.js";

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

/**
 * Provider-auth vars the roster reads. Cleared before each env-sensitive test so
 * a developer's real keys can never change which branch the test exercises —
 * these assertions are about deployment SHAPE, not about this machine.
 */
const AUTH_VARS = [
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "0SEC_CHATGPT_ACCESS_TOKEN",
  "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN",
  "Z_AI_API_KEY",
  "KIMI_API_KEY",
  "QWEN_API_KEY",
  "0SEC_HUNT_REFUTER_CANDIDATES",
  "0SEC_HUNT_CROSS_FAMILY",
] as const;

const savedEnv = new Map<string, string | undefined>();

/** Set the process env to exactly `vars` for the auth surface, restoring afterwards. */
function withProviders(vars: Record<string, string>): void {
  for (const key of AUTH_VARS) {
    if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
    delete process.env[key];
  }
  for (const [key, value] of Object.entries(vars)) {
    if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
    process.env[key] = value;
  }
}

afterEach(() => {
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  savedEnv.clear();
});

describe("crossFamilyRefuteEnabled", () => {
  it("is ON by default and OFF only for an explicit falsey 0SEC_HUNT_CROSS_FAMILY", () => {
    withProviders({});
    expect(crossFamilyRefuteEnabled()).toBe(true);
    process.env["0SEC_HUNT_CROSS_FAMILY"] = "0";
    expect(crossFamilyRefuteEnabled()).toBe(false);
    process.env["0SEC_HUNT_CROSS_FAMILY"] = "no";
    expect(crossFamilyRefuteEnabled()).toBe(false);
    process.env["0SEC_HUNT_CROSS_FAMILY"] = "";
    expect(crossFamilyRefuteEnabled()).toBe(false);
    process.env["0SEC_HUNT_CROSS_FAMILY"] = "1";
    expect(crossFamilyRefuteEnabled()).toBe(true);
  });
});

describe("refuterFamily", () => {
  it("classifies direct model ids by family", () => {
    expect(refuterFamily("claude-opus-4-7")).toBe("anthropic");
    expect(refuterFamily("gpt-5.5")).toBe("openai");
    expect(refuterFamily("glm-5.2")).toBe("z-ai");
    expect(refuterFamily(undefined)).toBe("unknown");
  });

  it("unwraps the openrouter/ routing prefix — same weights are NOT a second family", () => {
    // modelProvider() alone answers "openrouter" here, which would let the same
    // Claude weights masquerade as a decorrelated refuter.
    expect(refuterFamily("openrouter/anthropic/claude-sonnet-4.6")).toBe("anthropic");
    const choice = selectCrossFamilyRefuter({
      enabled: true,
      finderModel: "claude-opus-4-7",
      candidates: ["openrouter/anthropic/claude-sonnet-4.6"],
    });
    expect(choice.crossFamily).toBe(false);
    expect(choice.status).toBe("no-distinct-family");
  });
});

describe("availableRefuterCandidates", () => {
  it("is EMPTY when no provider auth is configured (nothing to route a refuter to)", () => {
    withProviders({});
    expect(availableRefuterCandidates()).toEqual([]);
  });

  it("lists one model per configured family, strongest-adversary first", () => {
    withProviders({ ANTHROPIC_API_KEY: "sk-ant-x", Z_AI_API_KEY: "z-x" });
    expect(availableRefuterCandidates()).toEqual(["claude-sonnet-4-6", "glm-5.3"]);
  });

  it("honours the 0SEC_HUNT_REFUTER_CANDIDATES override verbatim", () => {
    withProviders({ ANTHROPIC_API_KEY: "sk-ant-x", "0SEC_HUNT_REFUTER_CANDIDATES": "gpt-5.5, glm-5.2" });
    expect(availableRefuterCandidates()).toEqual(["gpt-5.5", "glm-5.2"]);
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
    expect(choice).toEqual({ model: "claude-opus-4-7", crossFamily: false, status: "disabled" });
  });

  it("passthrough when the finder family is unknown (nothing to decorrelate from)", () => {
    const choice = selectCrossFamilyRefuter({
      enabled: true,
      refuterModel: "claude-opus-4-7",
      candidates: ["gpt-5.4"],
    });
    expect(choice).toEqual({ model: "claude-opus-4-7", crossFamily: false, status: "unknown-finder-family" });
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
      status: "already-cross-family",
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
      status: "enforced",
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
    expect(choice.status).toBe("enforced");
  });

  it("avoids EVERY family in a multi-model finder fan-out, not just the first", () => {
    const choice = selectCrossFamilyRefuter({
      enabled: true,
      finderModels: ["claude-opus-4-7", "gpt-5.5"],
      candidates: ["gpt-5.4", "glm-5.2"],
    });
    // gpt-5.4 is a finder family here even though it is not `finderModels[0]`.
    expect(choice.model).toBe("glm-5.2");
    expect(choice.refuterFamily).toBe("z-ai");
    expect(choice.finderFamily).toContain("anthropic");
    expect(choice.finderFamily).toContain("openai");
  });

  it("passthrough when no candidate is a distinct family (assume-FP safe fallback)", () => {
    const choice = selectCrossFamilyRefuter({
      enabled: true,
      finderModel: "claude-opus-4-7",
      refuterModel: "claude-haiku-4-5",
      candidates: ["claude-sonnet-4-6"],
    });
    expect(choice).toEqual({ model: "claude-haiku-4-5", crossFamily: false, status: "no-distinct-family" });
  });

  it("describeRefuterChoice names the correlation risk when decorrelation did NOT happen", () => {
    const notApplied = describeRefuterChoice({ model: "claude-opus-4-7", crossFamily: false, status: "no-distinct-family" });
    expect(notApplied).toContain("no-distinct-family");
    expect(notApplied).toContain("correlated");
  });
});

describe("makeSkepticVerifier — cross-family wiring", () => {
  it("gate explicitly OFF: the finder model and reason string are byte-identical to the pre-#661 path", async () => {
    withProviders({ ANTHROPIC_API_KEY: "sk-ant-x", OPENAI_API_KEY: "sk-x", "0SEC_HUNT_CROSS_FAMILY": "0" });
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
    expect(result.decorrelation).toEqual({
      crossFamily: false,
      status: "disabled",
      refuterModel: "claude-opus-4-7",
    });
  });

  it("SINGLE PROVIDER (default flag ON): degrades to the same-family refuter — no error, refutation still runs", async () => {
    // The deployment shape that decides whether default-ON is safe: one key.
    withProviders({ ANTHROPIC_API_KEY: "sk-ant-x" });
    agenticScanMock.mockReset();
    let calls = 0;
    let capturedModel: string | undefined = "sentinel";
    agenticScanMock.mockImplementation(async ({ config }: { config: { model?: string } }) => {
      calls++;
      capturedModel = config.model;
      return { findings: [] };
    });

    const verify = makeSkepticVerifier({
      sourceRoot: "/src",
      runtime: "api",
      model: "claude-opus-4-7",
      finderModels: ["claude-opus-4-7"],
    });
    const result = await verify(mkFinding("f1", "some finding"), { path: "a.c" });

    // The refute pass RAN (the gate is intact), on the configured model, and the
    // reason string is byte-identical to the pre-#661 output.
    expect(calls).toBe(1);
    expect(capturedModel).toBe("claude-opus-4-7");
    expect(result.confirmed).toBe(false);
    expect(result.reason).toBe("refuted: skeptic could not reproduce the claim from source");
    // …and the verdict says out loud that it was NOT decorrelated.
    expect(result.decorrelation?.crossFamily).toBe(false);
    expect(result.decorrelation?.status).toBe("no-distinct-family");
  });

  it("TWO PROVIDERS (default flag ON): finder and refuter resolve to DIFFERENT families with no explicit roster", async () => {
    withProviders({ ANTHROPIC_API_KEY: "sk-ant-x", Z_AI_API_KEY: "z-x" });
    agenticScanMock.mockReset();
    let capturedModel: string | undefined = "sentinel";
    agenticScanMock.mockImplementation(async ({ config }: { config: { model?: string } }) => {
      capturedModel = config.model;
      return { findings: [mkFinding("survivor", "still real")] };
    });

    // No `refuterCandidates` — the roster comes from the configured auth, which
    // is the whole point: no production call site names one.
    const verify = makeSkepticVerifier({
      sourceRoot: "/src",
      runtime: "api",
      model: "claude-opus-4-7",
      finderModels: ["claude-opus-4-7"],
    });
    const result = await verify(mkFinding("f1", "some finding"), { path: "a.c" });

    expect(capturedModel).toBe("glm-5.3");
    expect(result.confirmed).toBe(true);
    expect(result.decorrelation).toEqual({
      crossFamily: true,
      status: "enforced",
      finderFamily: "anthropic",
      refuterFamily: "z-ai",
      refuterModel: "glm-5.3",
    });
    expect(refuterFamily(result.decorrelation?.refuterModel)).not.toBe(refuterFamily("claude-opus-4-7"));
  });

  it("a FAILING cross-family refuter degrades to the original model instead of throwing (a throw drops the finding upstream)", async () => {
    withProviders({ ANTHROPIC_API_KEY: "sk-ant-x", Z_AI_API_KEY: "z-x" });
    agenticScanMock.mockReset();
    const attempted: Array<string | undefined> = [];
    agenticScanMock.mockImplementation(async ({ config }: { config: { model?: string } }) => {
      attempted.push(config.model);
      // The realistic failure: the key is present but the account cannot reach
      // that model id.
      if (config.model === "glm-5.3") throw new Error("404 model not found: glm-5.3");
      return { findings: [mkFinding("survivor", "still real")] };
    });

    const lines: string[] = [];
    const verify = makeSkepticVerifier({
      sourceRoot: "/src",
      runtime: "api",
      model: "claude-opus-4-7",
      finderModels: ["claude-opus-4-7"],
      log: (m) => lines.push(m),
    });
    const result = await verify(mkFinding("f1", "some finding"), { path: "a.c" });

    expect(attempted).toEqual(["glm-5.3", "claude-opus-4-7"]);
    // The finding survives on the same-family refute rather than being dropped.
    expect(result.confirmed).toBe(true);
    expect(result.decorrelation?.crossFamily).toBe(false);
    expect(result.decorrelation?.status).toBe("degraded-refuter-error");
    expect(lines.some((l) => l.includes("degrading to same-family refute"))).toBe(true);
  });

  it("a SAME-family refuter failure still propagates — degradation must not swallow real gate errors", async () => {
    withProviders({ ANTHROPIC_API_KEY: "sk-ant-x" });
    agenticScanMock.mockReset();
    agenticScanMock.mockImplementation(async () => {
      throw new Error("provider down");
    });

    const verify = makeSkepticVerifier({
      sourceRoot: "/src",
      runtime: "api",
      model: "claude-opus-4-7",
      finderModels: ["claude-opus-4-7"],
    });
    await expect(verify(mkFinding("f1", "some finding"), { path: "a.c" })).rejects.toThrow("provider down");
  });

  it("logs one decorrelation line per constructed skeptic, including when it could NOT decorrelate", async () => {
    withProviders({ ANTHROPIC_API_KEY: "sk-ant-x" });
    const lines: string[] = [];
    makeSkepticVerifier({
      sourceRoot: "/src",
      runtime: "api",
      model: "claude-opus-4-7",
      finderModels: ["claude-opus-4-7"],
      log: (m) => lines.push(m),
    });
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("cross-family refute NOT applied (no-distinct-family)");
  });
});
