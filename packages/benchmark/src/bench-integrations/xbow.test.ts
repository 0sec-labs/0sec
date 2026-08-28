import { describe, expect, it } from "vitest";

import {
  createBenchIntegrationRegistry,
  createVariantExecutionFactory,
  runTournament,
  type BenchScan,
} from "@0sec/core";

import {
  createXbowBenchIntegration,
  createXbowManifest,
  type XbowLifecycle,
} from "./xbow.js";
import type { XbowChallenge } from "../xbow-runner.js";

const challenge: XbowChallenge = {
  id: "XBEN-001",
  name: "Fixture challenge",
  description: "Recover the injected flag.",
  level: 1,
  tags: ["fixture"],
  winCondition: "flag",
  path: "/fixtures/XBEN-001",
};

describe("XBOW bench integration", () => {
  it("uses a fresh injected flag and the shared objective oracle", async () => {
    const builtFlags: string[] = [];
    let stopped = 0;
    const lifecycle: XbowLifecycle = {
      build: (_challenge, flag) => {
        builtFlags.push(flag);
        return true;
      },
      start: () => 43123,
      stop: () => {
        stopped++;
      },
    };
    const createScan = (): BenchScan => async ({ case: c, target, maxTurns }) => {
      if (c.objective.type !== "flag-capture") throw new Error("expected dynamic flag objective");
      return {
        findings: [{ evidence: { response: c.objective.marker } }],
        benchmarkMeta: {
          attackTurns: maxTurns,
          estimatedCostUsd: 0.2,
          inputTokens: 12,
          outputTokens: 4,
        },
        durationMs: target === "http://localhost:43123" ? 7 : 0,
      };
    };
    const integration = createXbowBenchIntegration({
      challenges: [challenge],
      lifecycle,
      createScan,
      version: "fixture-v1",
    });
    const registry = createBenchIntegrationRegistry([integration]);
    const tournament = await runTournament(createXbowManifest([challenge]), {
      variants: [{ id: "candidate", model: "fixture-model" }],
      executionFactory: createVariantExecutionFactory(registry, "xbow"),
      maxTurns: 9,
    });

    expect(builtFlags).toHaveLength(1);
    expect(builtFlags[0]).toMatch(/^FLAG\{[0-9a-f]{24}\}$/);
    expect(stopped).toBe(1);
    const attempt = tournament.variants[0].scorecard.cases[0].attempts[0];
    expect(attempt.status).toBe("verified");
    expect(attempt.totalTokens).toBe(16);
    expect(attempt.execution).toMatchObject({
      integrationId: "xbow",
      integrationVersion: "fixture-v1",
      model: "fixture-model",
    });
  });

  it("reports lifecycle setup failures as inconclusive", async () => {
    const lifecycle: XbowLifecycle = {
      build: () => false,
      start: () => 0,
      stop: () => {},
    };
    const integration = createXbowBenchIntegration({
      challenges: [challenge],
      lifecycle,
      createScan: (): BenchScan => async () => ({ findings: [] }),
    });
    const registry = createBenchIntegrationRegistry([integration]);
    const tournament = await runTournament(createXbowManifest([challenge]), {
      variants: [{ id: "candidate" }],
      executionFactory: createVariantExecutionFactory(registry, "xbow"),
    });
    expect(tournament.variants[0].scorecard.totals.inconclusive).toBe(1);
  });
});
