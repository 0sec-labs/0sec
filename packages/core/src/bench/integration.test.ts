import { describe, expect, it } from "vitest";

import {
  BenchIntegrationRegistry,
  createVariantExecutionFactory,
  type BenchIntegration,
} from "./integration.js";

const evaluatorAttestation = () => ({
  bundleDigest: "sha256:bundle",
  codeDigest: "sha256:code",
  configDigest: "sha256:config",
});

function fixtureIntegration(id = "fixture"): BenchIntegration {
  return {
    id,
    version: "1",
    evaluatorAttestation,
    createExecution: () => ({
      executionMetadata: { integrationId: "spoofed", harnessId: "adapter-default" },
      scan: async () => ({
        findings: [],
        benchmarkMeta: { estimatedCostUsd: 0, attackTurns: 0 },
      }),
    }),
  };
}

describe("BenchIntegrationRegistry", () => {
  it("binds authoritative integration identity to every execution", async () => {
    const registry = new BenchIntegrationRegistry([fixtureIntegration()]);
    const execution = registry.createExecution("fixture", {
      id: "candidate",
      harnessId: "external-agent",
    });
    expect(execution.executionMetadata).toEqual({
      integrationId: "fixture",
      integrationVersion: "1",
      harnessId: "external-agent",
    });
    const scan = execution.scan;
    await expect(scan({
      case: {
        id: "case",
        target: { kind: "web", image: "fixture" },
        objective: { type: "file-read", marker: "MARKER" },
        knownNegative: false,
        ci: false,
        tags: [],
      },
      attemptIndex: 0,
      target: "http://localhost",
      provisioned: { target: "http://localhost" },
      maxTurns: 1,
    })).resolves.toMatchObject({ benchmarkMeta: { attackTurns: 0 } });
  });

  it("fails closed for duplicate and unknown integration ids", () => {
    expect(() => new BenchIntegrationRegistry([
      fixtureIntegration("same"),
      fixtureIntegration("same"),
    ])).toThrow(/duplicate/);
    const registry = new BenchIntegrationRegistry([fixtureIntegration()]);
    expect(() => registry.resolve("missing")).toThrow(/unknown/);
  });

  it("creates a tournament execution factory bound to one integration", () => {
    const registry = new BenchIntegrationRegistry([fixtureIntegration()]);
    const factory = createVariantExecutionFactory(registry, "fixture");
    expect(factory({ id: "candidate" }).executionMetadata?.integrationId).toBe("fixture");
  });
});
