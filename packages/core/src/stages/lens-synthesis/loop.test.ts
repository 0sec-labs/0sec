/**
 * Self-improving lens loop — end-to-end tests.
 *
 * The full loop is exercised with a MOCKED synthesis model (returns a known-good
 * cross-language archetype via a tool-use block) and a DETERMINISTIC fake probe
 * (no LLM, no finder, no filesystem scan) writing to a TEMP registry:
 *
 *   1. seeded miss → synthesize → validate (catches-the-miss + clean controls)
 *      → REGISTERED to the temp registry with synthesis provenance.
 *   2. a candidate that regresses the negative-control corpus is REJECTED and
 *      NOT written (the fail-closed FP gate).
 *
 * Plus focused unit checks: miss-capture normalization, the recordMiss/priming
 * invariant, idempotent registration, and fail-closed synthesis on a bad hint.
 *
 * All test fixtures use real temporary files with correct identity metadata
 * (expectedCwe, expectedFile, expectedLine, cleanProvenance) to match the
 * contract in validateCandidateLens and findingMatchesFixture.
 */

import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { NativeRuntimeResult } from "../../runtime/types.js";
import { canonicalEvolutionJson } from "../../improvement/config.js";
import { HuntMemory } from "../hunt-flywheel.js";
import type { FinderLens } from "../hunt-scan.js";
import { captureLensCandidates } from "./miss-capture.js";
import { inspectLensRegistry, registerArchetype, retireArchetype } from "./register.js";
import { clusterCandidates, type LensSynthesisModel } from "./synthesize.js";
import { runLensSynthesisLoop } from "./loop.js";
import type {
  LensBaselineSnapshot,
  LensProbe,
  LensProbeOutcome,
  LensSynthesisInput,
  SynthesizedArchetype,
  ValidationFixture,
} from "./types.js";

const hashBytes = (bytes: Buffer): string => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const jsonCopy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const digestFn = (value: unknown): string => hashBytes(Buffer.from(canonicalEvolutionJson(jsonCopy(value))));

// ── Fixtures ────────────────────────────────────────────────────────────────

const GOOD_SSRF_CONTENT = {
  id: "ssrf-url-fetch",
  name: "Server-side request forgery via attacker-controlled URL fetch",
  cwe: "CWE-918",
  subsystem: "HTTP client / URL fetch (any runtime)",
  pattern: "Attacker-controlled URL reaches an HTTP client without an allow-list.",
  detection_signature:
    "Node fetch/axios(url); Python requests.get/urllib.urlopen; .NET HttpClient.GetAsync/WebClient; Java HttpClient.send. Trace taint to the URL.",
  challenge_hint:
    "Hunt SSRF only, ACROSS ALL LANGUAGES: attacker-influenced URLs reaching an HTTP client. Node fetch/axios; Python requests/urllib; .NET HttpClient/WebClient; Java HttpClient. Cite file:line and the taint path from the entry point. A fixed internal URL with no user input is safe.",
  grounding: ["CWE-918: Server-Side Request Forgery", "OWASP A10:2021"],
  confirmable: "Source-static hypothesis needing the skeptic + multi-lens verify quorum.",
};

/** A model that returns exactly one tool_use block with the given input. */
function toolModel(input: Record<string, unknown>): LensSynthesisModel {
  return async () =>
    ({
      content: [{ type: "tool_use", id: "t1", name: "propose_appsec_lens", input }],
      stopReason: "tool_use",
      durationMs: 1,
    }) as NativeRuntimeResult;
}

// Build fixtures with real temp files and proper identity metadata.
function buildFixtureArgs(): {
  tmpDir: string;
  pos: ValidationFixture;
  devPos: ValidationFixture;
  heldOutPos: ValidationFixture;
  neg1: ValidationFixture;
  neg2: ValidationFixture;
} {
  const tmpDir = mkdtempSync(join(tmpdir(), "lens-loop-test-"));
  // Dev positive: CWE-918 SSRF in dev app
  mkdirSync(join(tmpDir, "src"), { recursive: true });
  writeFileSync(join(tmpDir, "src", "fetch.py"), "import requests\nrequests.get(user_input)\n", "utf8");
  // Held-out positive: similar SSRF in different file
  writeFileSync(join(tmpDir, "src", "api.py"), "import urllib.request\nurllib.request.urlopen(user_url)\n", "utf8");
  // Negative 1: benign URL (no user input)
  writeFileSync(join(tmpDir, "src", "safe.py"), "import requests\nrequests.get('https://api.example.com/status')\n", "utf8");
  // Negative 2: another benign file
  writeFileSync(join(tmpDir, "src", "config.py"), "API_URL = 'https://api.example.com'\n", "utf8");

  return {
    tmpDir,
    pos: {
      id: "pos-ssrf",
      path: join(tmpDir, "src", "fetch.py"),
      note: "SSRF via requests.get(user_input)",
      expectedCwe: "CWE-918",
      expectedFile: join(tmpDir, "src", "fetch.py"),
      expectedLine: 2,
    },
    devPos: {
      id: "dev-ssrf",
      path: join(tmpDir, "src", "fetch.py"),
      note: "development positive (same file as pos for dev tests)",
      expectedCwe: "CWE-918",
      expectedFile: join(tmpDir, "src", "fetch.py"),
      expectedLine: 2,
    },
    heldOutPos: {
      id: "heldout-ssrf",
      path: join(tmpDir, "src", "api.py"),
      note: "heldout SSRF via urllib",
      expectedCwe: "CWE-918",
      expectedFile: join(tmpDir, "src", "api.py"),
      expectedLine: 2,
    },
    neg1: {
      id: "neg-1",
      path: join(tmpDir, "src", "safe.py"),
      cleanProvenance: "manual-review:no-user-input",
    },
    neg2: {
      id: "neg-2",
      path: join(tmpDir, "src", "config.py"),
      cleanProvenance: "manual-review:static-url",
    },
  };
}

const SEED_ENTRY_LENS: FinderLens = { id: "os-command-injection", challengeHint: "Hunt OS command injection: Node child_process; Python subprocess." };
const BASELINE_SNAPSHOT: LensBaselineSnapshot = { lenses: [SEED_ENTRY_LENS], digest: digestFn([SEED_ENTRY_LENS]) };

function snapshotBaseline(): LensBaselineSnapshot {
  return { lenses: structuredClone(BASELINE_SNAPSHOT.lenses), digest: BASELINE_SNAPSHOT.digest };
}

/**
 * A fake probe: the challenger (candidateLens != null) surfaces the positive,
 * baseline surfaces nothing. `fpFixtureIds` lets a test make the challenger ALSO
 * fire on chosen negative controls (the regression case).
 * Returns finding details matching the fixture's expected vulnerability identity.
 * Exposes a truthful deterministic baselineSnapshot required by validateCandidateLens.
 */
function fakeProbe(fpFixtureIds: string[] = []): LensProbe {
  const f = async (candidateLens: FinderLens | null, fixture: ValidationFixture): Promise<LensProbeOutcome> => {
    if (!candidateLens) return { surfaced: false, findings: [], costUsd: 0, durationMs: 5 }; // baseline finds nothing
    // Match the fixture's expected identity
    const isPositiveMatch = fixture.id === "pos-ssrf" || fixture.id === "dev-ssrf" || fixture.id === "heldout-ssrf";
    if (isPositiveMatch) {
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
    const isFp = fpFixtureIds.includes(fixture.id);
    return {
      surfaced: isFp,
      findings: isFp ? [{ cwe: "CWE-918", file: fixture.path, line: 5, lensId: candidateLens.id }] : [],
      costUsd: isFp ? 0.01 : 0,
      durationMs: 5,
    };
  };
  return Object.assign(f, { baselineSnapshot: snapshotBaseline }) as LensProbe;
}

function makeProbe(handler: (candidateLens: FinderLens | null, fixture: ValidationFixture) => Promise<LensProbeOutcome>): LensProbe {
  return Object.assign(handler, { baselineSnapshot: snapshotBaseline }) as LensProbe;
}

// ── Temp registry helpers ────────────────────────────────────────────────────

const SEED_ENTRY = {
  id: "os-command-injection",
  name: "OS command injection",
  cwe: "CWE-78",
  domain: "appsec",
  subsystem: "process / shell",
  pattern: "data reaches an exec sink",
  detection_signature: "child_process.exec / subprocess(shell=True)",
  challenge_hint: "Hunt OS command injection: Node child_process; Python subprocess.",
  grounding: ["CWE-78"],
  confirmable: "source-static hypothesis",
  uid: "appsec/os-command-injection",
  engine_lens: null,
  route: "appsec-source-static",
};

let tmpDir: string;
let registryPath: string;
let fixtures: ReturnType<typeof buildFixtureArgs>;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "lens-loop-"));
  registryPath = join(tmpDir, "appsec-archetypes.json");
  writeFileSync(
    registryPath,
    `${JSON.stringify({ provenance: "test seed", archetypes: [SEED_ENTRY] }, null, 2)}\n`,
    "utf8",
  );
  fixtures = buildFixtureArgs();
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
  rmSync(fixtures.tmpDir, { recursive: true, force: true });
});

function inputFor(extra?: Partial<ValidationFixture>): LensSynthesisInput {
  const pos: ValidationFixture = { ...fixtures.pos, ...extra };
  return {
    misses: {
      confirmedMisses: [
        {
          classHint: "SSRF (CWE-918)",
          sinkPattern: "requests.get(user_url)",
          file: "app/fetch.py",
          line: 42,
          whyMissed: "input-validation lens under-weighted URL sinks",
        },
      ],
    },
    corpus: {
      positives: [pos],
      negativeControls: [fixtures.neg1, fixtures.neg2],
      heldOut: [fixtures.heldOutPos],
    },
  };
}

function readRegistry(): { provenance: string; archetypes: Array<Record<string, unknown>> } {
  const { readFileSync } = require("node:fs");
  return JSON.parse(readFileSync(registryPath, "utf8"));
}

// ── The two required end-to-end tests ─────────────────────────────────────────

describe("runLensSynthesisLoop — full loop", () => {
  it("seeded miss → synthesized → validated (catches miss, clean controls) → REGISTERED", async () => {
    const result = await runLensSynthesisLoop(inputFor(), {
      model: toolModel(GOOD_SSRF_CONTENT),
      probe: fakeProbe(),
      registryPath,
      now: () => "2026-07-21T00:00:00.000Z",
    });

    expect(result.candidatesCaptured).toBe(1);
    expect(result.synthesized.map((s) => s.content.id)).toEqual(["ssrf-url-fetch"]);
    expect(result.validations[0].passed).toBe(true);
    expect(result.validations[0].caughtMiss).toBe(true);
    expect(result.validations[0].noFpRegression).toBe(true);
    expect(result.validations[0].isChampion).toBe(true);
    expect(result.registered.map((r) => r.id)).toEqual(["ssrf-url-fetch"]);
    expect(result.registered[0].lensVersionDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(result.rejected).toHaveLength(0);

    // The temp registry now carries the seed + the synthesized entry, with provenance.
    const reg = readRegistry();
    expect(reg.archetypes).toHaveLength(2);
    expect(reg.archetypes[0].id).toBe("os-command-injection"); // existing entry preserved
    const added = reg.archetypes[1];
    expect(added.id).toBe("ssrf-url-fetch");
    expect(added.uid).toBe("appsec/ssrf-url-fetch");
    expect(added.domain).toBe("appsec");
    expect(added.route).toBe("appsec-source-static");
    expect(added.engine_lens).toBeNull();
    expect(added.source).toBe("synthesized");
    expect(added.validated_at).toBe("2026-07-21T00:00:00.000Z");
    expect(added.miss_refs).toEqual(["app/fetch.py:42"]);
  });

  it("a candidate that regresses the negative-control corpus is REJECTED and NOT written", async () => {
    const result = await runLensSynthesisLoop(inputFor(), {
      model: toolModel(GOOD_SSRF_CONTENT),
      probe: fakeProbe([fixtures.neg1.id]), // challenger fires on a clean control → false positive
      registryPath,
      now: () => "2026-07-21T00:00:00.000Z",
    });

    expect(result.synthesized.map((s) => s.content.id)).toEqual(["ssrf-url-fetch"]);
    // It DID catch the miss, but it FP-regressed → gate 2 fails → rejected.
    expect(result.validations[0].caughtMiss).toBe(true);
    expect(result.validations[0].noFpRegression).toBe(false);
    expect(result.validations[0].passed).toBe(false);
    expect(result.registered).toHaveLength(0);
    expect(result.rejected).toHaveLength(1);
    expect(result.rejected[0].id).toBe("ssrf-url-fetch");
    expect(result.rejected[0].reason).toContain("FP regression");

    // The registry is UNTOUCHED — the seed entry is still the only one.
    const reg = readRegistry();
    expect(reg.archetypes).toHaveLength(1);
    expect(reg.archetypes[0].id).toBe("os-command-injection");
  });
});

describe("fail-closed validation gates", () => {
  it("rejects validation when corpus has no negative controls", async () => {
    const noNegatives: LensSynthesisInput = {
      misses: { confirmedMisses: [{ classHint: "SSRF", sinkPattern: "x", file: "a", whyMissed: "gap" }] },
      corpus: {
        positives: [fixtures.pos],
        negativeControls: [],
        heldOut: [fixtures.heldOutPos],
      },
    };
    const result = await runLensSynthesisLoop(noNegatives, {
      model: toolModel(GOOD_SSRF_CONTENT),
      probe: fakeProbe(),
      registryPath,
      now: () => "2026-07-21T00:00:00.000Z",
    });
    expect(result.validations[0].passed).toBe(false);
    expect(result.validations[0].reason).toContain("negative controls");
    expect(result.registered).toHaveLength(0);
  });

  it("rejects validation when a probe errors on any fixture (fail-closed)", async () => {
    const errorProbe = makeProbe(async (candidateLens, fixture) => {
      if (candidateLens && fixture.id === fixtures.neg1.id) {
        return { surfaced: false, error: "probe crashed on negative fixture", findings: [] };
      }
      return fakeProbe()(candidateLens, fixture);
    });
    const result = await runLensSynthesisLoop(inputFor(), {
      model: toolModel(GOOD_SSRF_CONTENT),
      probe: errorProbe,
      registryPath,
      now: () => "2026-07-21T00:00:00.000Z",
    });
    // The challenger caught the miss, but the errored negative fixture makes
    // both baseline and challenger inconclusive on that fixture. The overall
    // gate requires no inconclusives → rejected.
    expect(result.validations[0].passed).toBe(false);
    expect(result.validations[0].reason).toContain("inconclusive");
    expect(result.registered).toHaveLength(0);
  });

  it("rejects validation when baseline errors on a positive fixture", async () => {
    const baselineErrorProbe = makeProbe(async (candidateLens, fixture) => {
      if (!candidateLens && fixture.id === fixtures.pos.id) {
        return { surfaced: false, error: "baseline probe error on positive", findings: [] };
      }
      return fakeProbe()(candidateLens, fixture);
    });
    const result = await runLensSynthesisLoop(inputFor(), {
      model: toolModel(GOOD_SSRF_CONTENT),
      probe: baselineErrorProbe,
      registryPath,
      now: () => "2026-07-21T00:00:00.000Z",
    });
    expect(result.validations[0].passed).toBe(false);
    expect(result.validations[0].reason).toContain("inconclusive");
    expect(result.registered).toHaveLength(0);
  });

  it("rejects an unrelated-finding match (not intended vulnerability)", async () => {
    // Probe returns a finding but with the WRONG cwe vs fixture expectedCwe.
    const wrongFindingProbe = makeProbe(async (candidateLens, fixture) => {
      if (candidateLens && fixture.id === fixtures.pos.id) {
        // Return CWE-78 (command injection) for a CWE-918 fixture → not a match.
        return {
          surfaced: false,
          findings: [{ cwe: "CWE-78", file: fixture.expectedFile!, line: 42, lensId: candidateLens.id }],
          costUsd: 0.01,
          durationMs: 10,
        };
      }
      return { surfaced: false, findings: [], costUsd: 0, durationMs: 5 };
    });
    const result = await runLensSynthesisLoop(inputFor(), {
      model: toolModel(GOOD_SSRF_CONTENT),
      probe: wrongFindingProbe,
      registryPath,
      now: () => "2026-07-21T00:00:00.000Z",
    });
    expect(result.validations[0].passed).toBe(false);
    expect(result.validations[0].reason).toContain("missed");
    expect(result.registered).toHaveLength(0);
  });
});

// ── Fail-closed synthesis ─────────────────────────────────────────────────────

describe("fail-closed guardrails", () => {
  it("drops a candidate whose challenge_hint is not cross-language (nothing registered)", async () => {
    const singleLangHint = {
      ...GOOD_SSRF_CONTENT,
      challenge_hint: "Hunt SSRF: look for requests.get with a user URL.", // only one ecosystem token
    };
    const result = await runLensSynthesisLoop(inputFor(), {
      model: toolModel(singleLangHint),
      probe: fakeProbe(),
      registryPath,
      now: () => "2026-07-21T00:00:00.000Z",
    });
    expect(result.synthesized).toHaveLength(0);
    expect(result.registered).toHaveLength(0);
    expect(readRegistry().archetypes).toHaveLength(1);
  });

  it("respects the registration cap (maxRegistrations)", async () => {
    // Two distinct misses → two clusters → two archetypes, but the cap is 1.
    const twoMisses: LensSynthesisInput = {
      misses: {
        confirmedMisses: [
          { classHint: "SSRF (CWE-918)", sinkPattern: "requests.get", file: "a.py", line: 1, whyMissed: "x" },
          { classHint: "XXE (CWE-611)", sinkPattern: "parseXml", file: "b.java", line: 2, whyMissed: "y" },
        ],
      },
      corpus: {
        positives: [fixtures.devPos],
        negativeControls: [fixtures.neg1],
        heldOut: [fixtures.heldOutPos],
      },
    };
    let call = 0;
    const alternatingModel: LensSynthesisModel = async () => {
      call++;
      const input = call === 1 ? GOOD_SSRF_CONTENT : { ...GOOD_SSRF_CONTENT, id: "xxe-external-entity", cwe: "CWE-611" };
      return {
        content: [{ type: "tool_use", id: "t", name: "propose_appsec_lens", input }],
        stopReason: "tool_use",
        durationMs: 1,
      } as NativeRuntimeResult;
    };
    const result = await runLensSynthesisLoop(twoMisses, {
      model: alternatingModel,
      probe: fakeProbe(),
      registryPath,
      maxRegistrations: 1,
      now: () => "2026-07-21T00:00:00.000Z",
    });
    expect(result.synthesized.length).toBe(2);
    expect(result.registered).toHaveLength(1);
    expect(result.rejected.some((r) => r.reason.includes("registration cap"))).toBe(true);
  });
});

// ── Miss capture + registry unit checks ──────────────────────────────────────

describe("miss-capture", () => {
  it("normalizes confirmed misses and coverage gaps into candidates", () => {
    const candidates = captureLensCandidates({
      confirmedMisses: [{ classHint: "SSRF", sinkPattern: "fetch(x)", file: "a.ts", line: 9, whyMissed: "gap" }],
      incompleteCoverage: [{ file: "b.ts", lensId: "sso-trust", reason: "timeout", budgetMs: 90000 }],
    });
    expect(candidates).toHaveLength(2);
    expect(candidates[0]).toMatchObject({ source: "confirmed-miss", exampleFileLine: "a.ts:9", sinkPattern: "fetch(x)" });
    expect(candidates[1]).toMatchObject({ source: "incomplete-coverage", classHint: "sso-trust", exampleFileLine: "b.ts" });
  });

  it("clusters candidates of the same class together (shared class token)", () => {
    const candidates = captureLensCandidates({
      confirmedMisses: [
        { classHint: "deferred-free use-after-free (CWE-416)", sinkPattern: "", file: "a", whyMissed: "" },
        { classHint: "CWE-416 use after free", sinkPattern: "", file: "b", whyMissed: "" },
      ],
    });
    // Both normalize to the {cwe-416, uaf} token set, so they cluster into one.
    expect(clusterCandidates(candidates)).toHaveLength(1);
  });
});

describe("registerArchetype idempotency", () => {
  const archetype: SynthesizedArchetype = {
    content: GOOD_SSRF_CONTENT,
    missRefs: ["app/fetch.py:42"],
    clusterSize: 1,
  };
  it("is a no-op on a second registration of the same id", () => {
    const first = registerArchetype(archetype, { registryPath, validatedAt: "2026-07-21T00:00:00.000Z" });
    expect(first.written).toBe(true);
    const second = registerArchetype(archetype, { registryPath, validatedAt: "2026-07-21T00:00:00.000Z" });
    expect(second.written).toBe(false);
    expect(second.reason).toContain("idempotent");
    expect(readRegistry().archetypes).toHaveLength(2); // seed + one, not three
  });

  it("writes a ledger-bound user overlay and retires it without touching the bundled registry", () => {
    const overlayPath = join(tmpDir, "durable-overlay.json");
    const promoted = registerArchetype(archetype, {
      registryPath: overlayPath,
      validatedAt: "2026-08-30T00:00:00.000Z",
    });
    expect(promoted.written).toBe(true);
    expect(promoted.promotionDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(inspectLensRegistry(overlayPath)).toMatchObject({
      exists: true,
      valid: true,
      activeLensCount: 1,
      ledgerEntries: 1,
      unboundArchetypes: 0,
    });

    const retired = retireArchetype("ssrf-url-fetch", {
      registryPath: overlayPath,
      retiredAt: "2026-08-30T00:01:00.000Z",
    });
    expect(retired.retired).toBe(true);
    expect(retired.retirementDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(inspectLensRegistry(overlayPath)).toMatchObject({
      valid: true,
      activeLensCount: 0,
      ledgerEntries: 2,
      unboundArchetypes: 0,
    });
    const overlay = JSON.parse(require("node:fs").readFileSync(overlayPath, "utf8")) as { archetypes: unknown[]; ledger: Array<{ type: string }> };
    expect(overlay.archetypes).toEqual([]);
    expect(overlay.ledger.map((entry) => entry.type)).toEqual(["promoted", "retired"]);
  });
});

// ── The "primes, never confirms" invariant ────────────────────────────────────

describe("HuntMemory.recordMiss does not perturb the priming path", () => {
  it("recall is byte-identical before and after recording misses; drain returns them", () => {
    const memory = new HuntMemory();
    const brief = { bugClass: "nf_tables UAF (CWE-416)", pattern: "deferred-free race" };
    const before = memory.recall(brief).map((r) => ({ key: r.memory.key, score: r.score }));

    memory.recordMiss({ classHint: "SSRF", sinkPattern: "fetch(x)", exampleFileLine: "a.ts:1", whyMissed: "gap", source: "confirmed-miss" });
    expect(memory.missCandidateCount()).toBe(1);

    const after = memory.recall(brief).map((r) => ({ key: r.memory.key, score: r.score }));
    expect(after).toEqual(before); // priming recall is untouched by a recorded miss

    const drained = memory.drainMissCandidates();
    expect(drained).toHaveLength(1);
    expect(memory.missCandidateCount()).toBe(0);
  });
});