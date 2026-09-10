/**
 * `0sec lens-synth` command tests — the CLI runs the full loop end-to-end with
 * an injected fake model + fake probe (no LLM, no finder), proving the manual
 * entry point wires miss-capture → synthesize → validate → register, defaults
 * to no write, and validates the miss-input shape.
 *
 * All fixture paths reference real temp files with proper identity metadata
 * (expectedCwe, expectedFile, expectedLine, cleanProvenance) matching the
 * validateCandidateLens contract.
 */

import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { canonicalEvolutionJson } from "@0sec/core";
import type { FinderLens, NativeRuntimeResult, LensBaselineSnapshot, LensProbe, LensProbeOutcome, LensSynthesisModel, ValidationFixture } from "@0sec/core";
import {
  parseMissInputFile,
  runLensSynthCommand,
  watchLensSynthCommand,
} from "../lens-synth.js";

const hashBytes = (bytes: Buffer): string => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const jsonCopy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const digestFn = (value: unknown): string => hashBytes(Buffer.from(canonicalEvolutionJson(jsonCopy(value))));

const CLI_BASELINE_LENSES: FinderLens[] = [{ id: "seed", challengeHint: "h" }];
const CLI_BASELINE_SNAPSHOT: LensBaselineSnapshot = { lenses: structuredClone(CLI_BASELINE_LENSES), digest: digestFn(CLI_BASELINE_LENSES) };

const GOOD_CONTENT = {
  id: "ssrf-url-fetch",
  name: "SSRF via attacker-controlled URL fetch",
  cwe: "CWE-918",
  subsystem: "HTTP client (any runtime)",
  pattern: "attacker URL reaches an HTTP client without allow-list",
  detection_signature: "Node fetch/axios; Python requests; .NET HttpClient",
  challenge_hint:
    "Hunt SSRF across languages: Node fetch/axios; Python requests/urllib; .NET HttpClient; Java HttpClient. Cite file:line and the taint path. A fixed internal URL is safe.",
  grounding: ["CWE-918"],
  confirmable: "source-static hypothesis",
};

const toolModel: LensSynthesisModel = async () =>
  ({
    content: [{ type: "tool_use", id: "t", name: "propose_appsec_lens", input: GOOD_CONTENT }],
    stopReason: "tool_use",
    durationMs: 1,
  }) as NativeRuntimeResult;

// Challenger catches the positive; baseline + all negatives stay clean.
// Returns findings matching the fixture's expected identity.
const cleanProbe: LensProbe = Object.assign(
  async (candidateLens: FinderLens | null, fixture: ValidationFixture): Promise<LensProbeOutcome> => {
    if (!candidateLens) return { surfaced: false, findings: [], costUsd: 0, durationMs: 5 };
    const isPosMatch = fixture.id === "pos" || fixture.id === "ho";
    if (isPosMatch) {
      return {
        surfaced: true,
        findings: [{
          cwe: fixture.expectedCwe ?? "CWE-918",
          file: fixture.expectedFile ?? fixture.path,
          line: fixture.expectedLine ?? 2,
          lensId: candidateLens.id,
        }],
        costUsd: 0.01,
        durationMs: 10,
      };
    }
    return { surfaced: false, findings: [], costUsd: 0, durationMs: 5 };
  },
  { baselineSnapshot: () => structuredClone(CLI_BASELINE_SNAPSHOT) },
);

let tmpDir: string;
let registryPath: string;
let missInputPath: string;
let fixtureDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "lens-cli-"));
  registryPath = join(tmpDir, "registry.json");
  missInputPath = join(tmpDir, "miss-input.json");
  fixtureDir = join(tmpDir, "fixtures");
  mkdirSync(fixtureDir, { recursive: true });
  writeFileSync(join(fixtureDir, "app.py"), "import requests\nrequests.get(user_input)\n", "utf8");
  writeFileSync(join(fixtureDir, "api.py"), "import urllib.request\nurllib.request.urlopen(user_url)\n", "utf8");
  writeFileSync(join(fixtureDir, "safe.py"), 'print("hello")\n', "utf8");

  writeFileSync(
    registryPath,
    `${JSON.stringify(
      {
        provenance: "test",
        archetypes: [
          {
            id: "seed", name: "seed", cwe: "CWE-1", domain: "appsec", subsystem: "s",
            pattern: "p", detection_signature: "d", challenge_hint: "h", grounding: ["g"],
            confirmable: "c", uid: "appsec/seed", engine_lens: null, route: "appsec-source-static",
          },
        ],
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  writeFileSync(
    missInputPath,
    JSON.stringify({
      misses: { confirmedMisses: [{ classHint: "SSRF (CWE-918)", sinkPattern: "requests.get(u)", file: "app.py", line: 7, whyMissed: "gap" }] },
      corpus: {
        positives: [{
          id: "pos",
          path: join(fixtureDir, "app.py"),
          expectedCwe: "CWE-918",
          expectedFile: join(fixtureDir, "app.py"),
          expectedLine: 2,
        }],
        negativeControls: [{
          id: "n1",
          path: join(fixtureDir, "safe.py"),
          cleanProvenance: "manual-review:clean",
        }],
        heldOut: [{
          id: "ho",
          path: join(fixtureDir, "api.py"),
          expectedCwe: "CWE-918",
          expectedFile: join(fixtureDir, "api.py"),
          expectedLine: 2,
        }],
      },
    }),
    "utf8",
  );
});

afterEach(() => rmSync(tmpDir, { recursive: true, force: true }));

function registry(): { archetypes: Array<Record<string, unknown>> } {
  const { readFileSync } = require("node:fs");
  return JSON.parse(readFileSync(registryPath, "utf8"));
}

describe("runLensSynthCommand", () => {
  it("defaults to validation-only and does not write a champion", async () => {
    const result = await runLensSynthCommand(
      { missInput: missInputPath, registry: registryPath },
      { model: toolModel, probe: cleanProbe },
    );
    expect(result.validations[0].passed).toBe(true);
    expect(result.registered).toHaveLength(0);
    expect(registry().archetypes).toHaveLength(1);
  });

  it("registers a validated champion only when explicitly promoted", async () => {
    const result = await runLensSynthCommand(
      { missInput: missInputPath, registry: registryPath, promote: true },
      { model: toolModel, probe: cleanProbe },
    );
    expect(result.registered.map((r) => r.id)).toEqual(["ssrf-url-fetch"]);
    const reg = registry();
    expect(reg.archetypes).toHaveLength(2);
    expect(reg.archetypes[1].source).toBe("synthesized");
    expect(reg.archetypes[1].miss_refs).toEqual(["app.py:7"]);
  });
});

describe("watchLensSynthCommand", () => {
  it("watches content revisions without rerunning an unchanged miss input", async () => {
    const controller = new AbortController();
    const results: unknown[] = [];
    let sleeps = 0;

    await watchLensSynthCommand(
      { missInput: missInputPath, registry: registryPath, pollIntervalMs: 100 },
      {
        model: toolModel,
        probe: cleanProbe,
        signal: controller.signal,
        onResult: (result) => { results.push(result); },
        sleep: async () => {
          sleeps++;
          if (sleeps === 1) {
            writeFileSync(
              missInputPath,
              JSON.stringify({
                misses: {
                  confirmedMisses: [{
                    classHint: "SSRF (CWE-918)",
                    sinkPattern: "requests.get(user_url)",
                    file: "app.py",
                    line: 7,
                    whyMissed: "new curated evidence revision",
                  }],
                },
                corpus: {
                  positives: [{
                    id: "pos",
                    path: join(fixtureDir, "app.py"),
                    expectedCwe: "CWE-918",
                    expectedFile: join(fixtureDir, "app.py"),
                    expectedLine: 2,
                  }],
                  negativeControls: [{
                    id: "n1",
                    path: join(fixtureDir, "safe.py"),
                    cleanProvenance: "manual-review:clean",
                  }],
                  heldOut: [{
                    id: "ho",
                    path: join(fixtureDir, "api.py"),
                    expectedCwe: "CWE-918",
                    expectedFile: join(fixtureDir, "api.py"),
                    expectedLine: 2,
                  }],
                },
              }),
              "utf8",
            );
          } else {
            controller.abort();
          }
        },
      },
    );

    expect(results).toHaveLength(2);
    expect(sleeps).toBe(2);
  });
});

describe("parseMissInputFile", () => {
  it("rejects a miss-input with no positive fixtures (fail-closed)", () => {
    expect(() => parseMissInputFile({
      misses: {},
      corpus: { positives: [], negativeControls: [{ id: "n", path: "/n" }] },
    })).toThrow(/at least one fixture/);
  });

  it("rejects a miss-input with no negative controls (fail-closed)", () => {
    expect(() => parseMissInputFile({
      misses: {},
      corpus: { positives: [{ id: "p", path: "/p" }], negativeControls: [] },
    })).toThrow(/FP regression/);
  });

});