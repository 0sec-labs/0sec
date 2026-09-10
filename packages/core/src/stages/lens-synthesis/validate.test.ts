/**
 * Validator regression tests — direct calls to validateCandidateLens with real
 * temp files and truthful deterministic probes.
 *
 * Covers every fail-closed gate and receipt shape the contract specifies.
 * Each test creates its own temp fixtures, so no shared state leaks between
 * isolated edge cases.
 */

import { createHash } from "node:crypto";
import { existsSync, linkSync, mkdtempSync, writeFileSync, rmSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { canonicalEvolutionJson } from "../../improvement/config.js";
import type { FinderLens } from "../hunt-scan.js";
import { prepareValidationCorpus, validateCandidateLens } from "./validate.js";
import { registerArchetype } from "./register.js";
import type {
  LensBaselineSnapshot,
  LensProbe,
  LensProbeOutcome,
  SynthesizedArchetype,
  ValidationCorpus,
  ValidationFixture,
} from "./types.js";

// ── Helpers ──────────────────────────────────────────────────────────────

const hashBytes = (bytes: Buffer): string => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const jsonCopy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const digestFn = (value: unknown): string => hashBytes(Buffer.from(canonicalEvolutionJson(jsonCopy(value))));

const BASELINE_LENSES: FinderLens[] = [{ id: "test-finder", challengeHint: "find test vulnerabilities" }];
const BASELINE_DIGEST = digestFn(BASELINE_LENSES);

function baselineSnapshot(): LensBaselineSnapshot {
  return { lenses: structuredClone(BASELINE_LENSES), digest: BASELINE_DIGEST };
}

function makeProbe(handler: (candidateLens: FinderLens | null, fixture: ValidationFixture) => Promise<LensProbeOutcome>): LensProbe {
  return Object.assign(handler, { baselineSnapshot }) as LensProbe;
}

interface TempFixtures {
  dir: string;
  pos: ValidationFixture;
  neg: ValidationFixture;
  heldOut: ValidationFixture;
}

function createTempFixtures(): TempFixtures {
  const dir = mkdtempSync(join(tmpdir(), "val-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src", "vuln.py"), "import requests\nrequests.get(user_input)\n", "utf8");
  writeFileSync(join(dir, "src", "safe.py"), 'print("ok")\n', "utf8");
  writeFileSync(join(dir, "src", "other.py"), "import urllib.request\nurllib.request.urlopen(user_url)\n", "utf8");
  return {
    dir,
    pos: { id: "pos", path: join(dir, "src", "vuln.py"), expectedCwe: "CWE-918", expectedFile: "vuln.py", expectedLine: 2, expectedRange: [2, 2] },
    neg: { id: "neg", path: join(dir, "src", "safe.py"), cleanProvenance: "manual-review:clean" },
    heldOut: { id: "ho", path: join(dir, "src", "other.py"), expectedCwe: "CWE-918", expectedFile: "other.py", expectedLine: 2 },
  };
}

const ARCHETYPE: SynthesizedArchetype = {
  content: {
    id: "ssrf-test",
    name: "test",
    cwe: "CWE-918",
    subsystem: "http",
    pattern: "user input to HTTP client",
    detection_signature: "requests.get/urllib.request.urlopen with user taint",
    challenge_hint: "Hunt SSRF: Node fetch/axios; Python requests/urllib; .NET HttpClient; Java HttpClient",
    grounding: ["CWE-918"],
    confirmable: "source-static hypothesis",
  },
  missRefs: ["src/vuln.py:2"],
  clusterSize: 1,
};

function corpus(tf: TempFixtures, extra?: Partial<ValidationCorpus>): ValidationCorpus {
  return {
    positives: [tf.pos],
    negativeControls: [tf.neg],
    heldOut: [tf.heldOut],
    ...extra,
  };
}

// Clean probe — returns matching identity for positives, nothing for negatives.
const cleanProbe = makeProbe(async (candidateLens, fixture) => {
  if (!candidateLens) return { surfaced: false, findings: [], costUsd: 0, durationMs: 5 };
  if (fixture.id === "pos" || fixture.id === "ho") {
    return {
      surfaced: true,
      findings: [{ cwe: "CWE-918", file: fixture.expectedFile ?? fixture.path, line: fixture.expectedLine ?? 2, lensId: candidateLens.id }],
      costUsd: 0.01, durationMs: 10,
    };
  }
  return { surfaced: false, findings: [], costUsd: 0, durationMs: 5 };
});

let tf: TempFixtures;

beforeEach(() => { tf = createTempFixtures(); });
afterEach(() => { try { rmSync(tf.dir, { recursive: true, force: true }); } catch { /* ok */ } });

// ── 1. Surfaced spoof with wrong identity ───────────────────────────────

describe("identity matching", () => {
  it("rejects when probe claims surfaced=true but finding CWE does not match fixture", async () => {
    const wrongCwe = makeProbe(async (candidateLens, fixture) => {
      if (!candidateLens) return { surfaced: false, findings: [], costUsd: 0, durationMs: 5 };
      return { surfaced: true, findings: [{ cwe: "CWE-78", file: fixture.expectedFile!, line: 2, lensId: candidateLens.id }], costUsd: 0.01, durationMs: 10 };
    });
    const report = await validateCandidateLens(ARCHETYPE, corpus(tf), { probe: wrongCwe });
    expect(report.passed).toBe(false);
    expect(report.reason).toContain("missed");
    expect(report.caughtMiss).toBe(false);
  });

  it("rejects when finding file path does not match fixture expectedFile", async () => {
    const wrongFile = makeProbe(async (candidateLens, fixture) => {
      if (!candidateLens) return { surfaced: false, findings: [], costUsd: 0, durationMs: 5 };
      const findings = fixture.id === "pos" || fixture.id === "ho"
        ? [{ cwe: "CWE-918", file: "wrong/path.py", line: 42, lensId: candidateLens.id }]
        : [];
      return { surfaced: findings.length > 0, findings, costUsd: 0.01, durationMs: 10 };
    });
    const report = await validateCandidateLens(ARCHETYPE, corpus(tf), { probe: wrongFile });
    expect(report.passed).toBe(false);
    expect(report.reason).toContain("missed");
  });
});

// ── 2. Same basename, different relative path ──────────────────────────

describe("same basename different relative path", () => {
  it("rejects the wrong relative path while still evaluating the held-out corpus", async () => {
    const dir = join(tf.dir, "directory-fixture");
    mkdirSync(join(dir, "src", "a"), { recursive: true });
    mkdirSync(join(dir, "src", "b"), { recursive: true });
    writeFileSync(join(dir, "src", "a", "app.py"), "import requests\nrequests.get(user_input)\n");
    writeFileSync(join(dir, "src", "b", "app.py"), "import requests\nrequests.get(other_input)\n");
    const fixture: ValidationFixture = {
      id: "pos-a", path: dir,
      expectedCwe: "CWE-918", expectedFile: "src/a/app.py", expectedLine: 2,
    };
    const probe = makeProbe(async (candidate, entry) => candidate && entry.id === fixture.id
      ? { surfaced: true, findings: [{ cwe: "CWE-918", file: "src/b/app.py", line: 2 }], costUsd: 0.01, durationMs: 10 }
      : cleanProbe(candidate, entry));
    const report = await validateCandidateLens(ARCHETYPE, { ...corpus(tf), positives: [fixture] }, { probe });
    expect(report.passed).toBe(false);
    expect(report.caughtMiss).toBe(false);
    expect(report.heldOut.caught).toBe(true);
  });
});

// ── 3. expectedRange without expectedLine ──────────────────────────────

describe("expectedRange without expectedLine", () => {
  it("accepts the inclusive endpoint and rejects a discovery beyond it", async () => {
    const input = corpus(tf);
    input.positives = [{ ...tf.pos, expectedLine: undefined, expectedRange: [2, 3] }];
    let reportedLine = 3;
    const probe = makeProbe(async (candidate, fixture) => {
      const outcome = await cleanProbe(candidate, fixture);
      if (candidate && fixture.id === tf.pos.id) outcome.findings![0]!.line = reportedLine;
      return outcome;
    });
    expect((await validateCandidateLens(ARCHETYPE, input, { probe })).passed).toBe(true);
    reportedLine = 4;
    expect((await validateCandidateLens(ARCHETYPE, input, { probe })).passed).toBe(false);
  });
});

// ── 4. Negative findings with surfaced=false but findings present → FP ──

describe("negative fixture FP detection", () => {
  it("counts a negative fixture as FP when findings exist even if surfaced=false", async () => {
    const fpNeg = makeProbe(async (candidateLens, fixture) => {
      if (!candidateLens) return { surfaced: false, findings: [], costUsd: 0, durationMs: 5 };
      if (fixture.id === "neg") return { surfaced: false, findings: [{ cwe: "CWE-918", file: "safe.py", line: 1, lensId: candidateLens.id }], costUsd: 0.01, durationMs: 10 };
      if (fixture.id === "pos" || fixture.id === "ho") return { surfaced: true, findings: [{ cwe: "CWE-918", file: fixture.expectedFile!, line: fixture.expectedLine!, lensId: candidateLens.id }], costUsd: 0.01, durationMs: 10 };
      return { surfaced: false, findings: [], costUsd: 0, durationMs: 5 };
    });
    const report = await validateCandidateLens(ARCHETYPE, corpus(tf), { probe: fpNeg });
    expect(report.passed).toBe(false);
    // FP regression detected because findings[] on negative was non-empty
    expect(report.noFpRegression).toBe(false);
  });
});

// ── 5. Missing/unknown metrics and probe errors cannot promote ─────────

describe("missing metrics and probe errors", () => {
  it("rejects when probe returns no costUsd making outcome incomplete", async () => {
    const noCost = makeProbe(async (candidateLens, fixture) => {
      if (!candidateLens) return { surfaced: false, findings: [] }; // no cost, no duration
      if (fixture.id === "pos" || fixture.id === "ho") {
        return { surfaced: true, findings: [{ cwe: "CWE-918", file: fixture.expectedFile!, line: fixture.expectedLine!, lensId: candidateLens.id }] };
      }
      return { surfaced: false, findings: [] };
    });
    const report = await validateCandidateLens(ARCHETYPE, corpus(tf), { probe: noCost });
    expect(report.passed).toBe(false);
    expect(report.reason).toContain("inconclusive");
  });

  it("rejects when probe errors on a positive fixture", async () => {
    const errProbe = makeProbe(async (candidateLens, fixture) => {
      if (candidateLens && fixture.id === "pos") return { surfaced: false, error: "probe crashed", findings: [], costUsd: 0, durationMs: 5 };
      return cleanProbe(candidateLens, fixture);
    });
    const report = await validateCandidateLens(ARCHETYPE, corpus(tf), { probe: errProbe });
    expect(report.passed).toBe(false);
    expect(report.reason).toContain("inconclusive");
  });

  it("rejects when probe errors on a negative fixture", async () => {
    const errNegProbe = makeProbe(async (candidateLens, fixture) => {
      if (candidateLens && fixture.id === "neg") return { surfaced: false, error: "probe crashed on negative", findings: [], costUsd: 0, durationMs: 5 };
      return cleanProbe(candidateLens, fixture);
    });
    const report = await validateCandidateLens(ARCHETYPE, corpus(tf), { probe: errNegProbe });
    expect(report.passed).toBe(false);
    expect(report.reason).toContain("inconclusive");
  });
});

// ── 6. Absent held-out, missing/aliased/duplicate/changed fixture bytes ─

describe("corpus integrity checks", () => {
  it("rejects a corpus with no held-out fixtures", () => {
    expect(() => prepareValidationCorpus({
      positives: [tf.pos],
      negativeControls: [tf.neg],
      heldOut: [],
    })).toThrow(/no held-out/);
  });

  it("rejects when fixture file is missing from disk", () => {
    const missing: ValidationFixture = { id: "missing", path: join(tf.dir, "nonexistent.py"), expectedCwe: "CWE-918", expectedFile: "nonexistent.py", expectedLine: 1 };
    expect(() => prepareValidationCorpus({
      positives: [missing],
      negativeControls: [tf.neg],
      heldOut: [tf.heldOut],
    })).toThrow();
  });

  it("rejects duplicate fixture content (same digest)", () => {
    const dup = mkdtempSync(join(tmpdir(), "dup-"));
    mkdirSync(join(dup, "a"), { recursive: true });
    mkdirSync(join(dup, "b"), { recursive: true });
    writeFileSync(join(dup, "a", "x.py"), "same content", "utf8");
    writeFileSync(join(dup, "b", "y.py"), "same content", "utf8");
    expect(() => prepareValidationCorpus({
      positives: [{ id: "p1", path: join(dup, "a", "x.py"), expectedCwe: "CWE-918", expectedFile: "x.py", expectedLine: 1 }],
      negativeControls: [{ id: "n", path: tf.neg.path, cleanProvenance: "x" }],
      heldOut: [{ id: "p2", path: join(dup, "b", "y.py"), expectedCwe: "CWE-918", expectedFile: "y.py", expectedLine: 1 }],
    })).toThrow(/duplicate.*content/);
    try { rmSync(dup, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it("rejects a changed contentDigest", () => {
    const changed: ValidationFixture = { ...tf.pos, contentDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000" };
    expect(() => prepareValidationCorpus({
      positives: [changed],
      negativeControls: [tf.neg],
      heldOut: [tf.heldOut],
    })).toThrow(/content digest mismatch/);
  });

  it("rejects a symbolic-link fixture instead of following it", () => {
    const alias = join(tf.dir, "alias.py");
    symlinkSync(tf.pos.path, alias);
    expect(() => prepareValidationCorpus({
      ...corpus(tf), positives: [{ ...tf.pos, path: alias, expectedFile: "alias.py" }],
    })).toThrow();
  });

  it("rejects a hard-linked fixture instead of counting an aliased source", () => {
    const alias = join(tf.dir, "alias.py");
    linkSync(tf.pos.path, alias);
    expect(() => prepareValidationCorpus({
      ...corpus(tf), positives: [{ ...tf.pos, path: alias, expectedFile: "alias.py" }],
    })).toThrow();
  });

  it("rejects fixture bytes changed after the first probe", async () => {
    const probe = makeProbe(async (candidate, fixture) => {
      const outcome = await cleanProbe(candidate, fixture);
      writeFileSync(tf.pos.path, "changed after capture\n");
      return outcome;
    });
    const report = await validateCandidateLens(ARCHETYPE, corpus(tf), { probe });
    expect(report.passed).toBe(false);
    expect(report.receipt?.cases).toHaveLength(1);
  });
});

// ── 7. Baseline drift and supplied digest mismatch ─────────────────────

describe("baseline drift detection", () => {
  it("rejects a real baseline content change after dispatch", async () => {
    const lenses = structuredClone(BASELINE_LENSES);
    const probe = Object.assign(async (candidate: FinderLens | null, fixture: ValidationFixture) => {
      const outcome = await cleanProbe(candidate, fixture);
      lenses[0]!.challengeHint = "A different finder strategy";
      return outcome;
    }, { baselineSnapshot: () => ({ lenses: structuredClone(lenses), digest: digestFn(lenses) }) });
    const report = await validateCandidateLens(ARCHETYPE, corpus(tf), { probe });
    expect(report.passed).toBe(false);
    expect(report.receipt?.cases).toHaveLength(1);
  });

  it("rejects when corpus.baselineDigest does not match probe baseline", async () => {
    const mismatched = corpus(tf, { baselineDigest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" });
    const report = await validateCandidateLens(ARCHETYPE, mismatched, { probe: cleanProbe });
    expect(report.passed).toBe(false);
    expect(report.reason).toContain("baseline digest does not match");
  });
});

// ── 8. Repeated held-out failure veto ──────────────────────────────────

describe("held-out failure veto", () => {
  it("rejects when the first held-out trial passes but the second fails", async () => {
    let heldOutAttempts = 0;
    const probe = makeProbe(async (candidate, fixture) => {
      if (candidate && fixture.id === tf.heldOut.id && ++heldOutAttempts === 2) {
        return { surfaced: false, findings: [], costUsd: 0.01, durationMs: 10 };
      }
      return cleanProbe(candidate, fixture);
    });
    const report = await validateCandidateLens(ARCHETYPE, corpus(tf), { probe });
    expect(report.passed).toBe(false);
    expect(report.caughtMiss).toBe(true);
    expect(report.receipt?.heldOutTrials.map((trial) => trial.caughtMiss)).toEqual([true, false]);
  });
});

describe("receipt-bound promotion", () => {
  it("rejects altered evidence and another candidate before creating an overlay", async () => {
    const report = await validateCandidateLens(ARCHETYPE, corpus(tf), { probe: cleanProbe });
    expect(report.passed).toBe(true);
    const registryPath = join(tf.dir, "overlay.json");
    const options = { registryPath, validatedAt: "2026-09-09T00:00:00.000Z", validation: report };
    const other = structuredClone(ARCHETYPE);
    other.content.challenge_hint += " Also inspect redirects.";
    expect(() => registerArchetype(other, options)).toThrow();
    expect(existsSync(registryPath)).toBe(false);
    const altered = structuredClone(report);
    altered.receipt!.cases[0]!.outcome.costUsd = 999;
    expect(() => registerArchetype(ARCHETYPE, { ...options, validation: altered })).toThrow();
    expect(existsSync(registryPath)).toBe(false);
    expect(registerArchetype(ARCHETYPE, options).written).toBe(true);
  });
});