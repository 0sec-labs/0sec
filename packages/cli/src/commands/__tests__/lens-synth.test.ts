/**
 * `0sec lens-synth` command tests — the CLI runs the full loop end-to-end with
 * an injected fake model + fake probe (no LLM, no finder), proving the manual
 * entry point wires miss-capture → synthesize → validate → register, defaults
 * to no write, and validates the miss-input shape.
 */

import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { LensProbe, LensSynthesisModel } from "@0sec/core";
import {
  parseMissInputFile,
  runLensSynthCommand,
  watchLensSynthCommand,
} from "../lens-synth.js";

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
  }) as Awaited<ReturnType<LensSynthesisModel>>;

// Challenger catches the positive; baseline + all negatives stay clean.
const cleanProbe: LensProbe = async (candidateLens, fixture) => ({
  surfaced: candidateLens !== null && fixture.id === "pos",
});

let tmpDir: string;
let registryPath: string;
let missInputPath: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "lens-cli-"));
  registryPath = join(tmpDir, "registry.json");
  missInputPath = join(tmpDir, "miss-input.json");
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
      corpus: { positives: [{ id: "pos", path: "/x/pos" }], negativeControls: [{ id: "n1", path: "/x/n1" }] },
    }),
    "utf8",
  );
});

afterEach(() => rmSync(tmpDir, { recursive: true, force: true }));

function registry(): { archetypes: Array<Record<string, unknown>> } {
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
                  positives: [{ id: "pos", path: "/x/pos" }],
                  negativeControls: [{ id: "n1", path: "/x/n1" }],
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
    expect(() => parseMissInputFile({ misses: {}, corpus: { positives: [] } })).toThrow(/at least one fixture/);
  });

  it("normalizes a valid miss-input", () => {
    const input = parseMissInputFile({
      misses: { confirmedMisses: [{ classHint: "x", sinkPattern: "y", file: "f", whyMissed: "w" }] },
      corpus: { positives: [{ id: "p", path: "/p" }], negativeControls: [{ id: "n", path: "/n" }] },
    });
    expect(input.corpus.positives).toHaveLength(1);
    expect(input.corpus.negativeControls).toHaveLength(1);
  });
});
