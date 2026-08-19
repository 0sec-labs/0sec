import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";
import type { BenchManifest, TournamentResult } from "@0sec/core";

import { canonicalJson, writeCanonicalJsonAtomic } from "../bench-improvement.js";
import { measureOperation, selectRunManifest, validateCaptureDestination } from "../bench.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function manifest(): BenchManifest {
  return {
    id: "full-v1",
    version: 1,
    cases: ["development", "held-out", "negative"].map((id, index) => ({
      id,
      target: {
        kind: "source-audit" as const,
        package: "fixture",
        version: "1.0.0",
        ecosystem: "npm" as const,
      },
      objective: {
        type: "finding-match" as const,
        vulnClass: "path-traversal",
        sinkMarkers: ["sink"],
      },
      knownNegative: index === 2,
      ci: false,
      tags: [],
    })),
  };
}

describe("sealed bench tournament capture", () => {
  it("measures the full operation with an injectable monotonic clock", async () => {
    const ticks = [10, 25.2];
    await expect(measureOperation(async () => "done", () => ticks.shift()!)).resolves.toEqual({
      value: "done",
      elapsedMs: 16,
    });
  });

  it("selects exact ordered case ids under a new sealed manifest id", () => {
    const selected = selectRunManifest(manifest(), {
      caseId: ["held-out", "development"],
      manifestId: "smoke-held-out-v1",
    });
    expect(selected.id).toBe("smoke-held-out-v1");
    expect(selected.cases.map((entry) => entry.id)).toEqual(["held-out", "development"]);
  });

  it("rejects ambiguous or silently shrinking slice options", () => {
    expect(() => selectRunManifest(manifest(), { manifestId: "unused" })).toThrow(
      /requires at least one --case-id/,
    );
    expect(() => selectRunManifest(manifest(), { caseId: ["development"] })).toThrow(
      /--manifest-id is required/,
    );
    expect(() =>
      selectRunManifest(manifest(), {
        caseId: ["development"],
        manifestId: "slice",
        ciSubset: true,
      }),
    ).toThrow(/cannot be combined/);
    expect(() =>
      selectRunManifest(manifest(), { caseId: ["missing"], manifestId: "slice" }),
    ).toThrow(/unknown case id/);
  });

  it("creates one canonical pair artifact and refuses replacement", () => {
    const root = mkdtempSync(join(tmpdir(), "0sec-bench-capture-"));
    roots.push(root);
    const output = join(root, "nested", "tournament.json");
    const tournament = {
      manifestId: "slice",
      config: {
        passAtK: 1,
        maxTurns: 10,
        costCeilingUsd: 1,
        ciSubset: false,
        variantIds: ["champion", "challenger"],
      },
      variants: [],
      pairwise: [],
      championId: "champion",
    } as unknown as TournamentResult;
    const pair = { manifest: selectRunManifest(manifest(), { caseId: ["development"], manifestId: "slice" }), tournament };
    writeCanonicalJsonAtomic(output, pair);
    expect(readFileSync(output, "utf8")).toBe(canonicalJson(pair));
    expect(() => writeCanonicalJsonAtomic(output, pair)).toThrow(/already exists/);
    expect(() => validateCaptureDestination(output, join(root, "ledger.json"))).toThrow(
      /already exists/,
    );
    expect(() =>
      validateCaptureDestination(join(root, "same.json"), join(root, "same.json")),
    ).toThrow(/must differ from --ledger/);
  });
});
