/**
 * Unit tests for the hunt-variant corpus persistence (mirrors
 * `cybergym-runner.test.ts`'s "corpus persistence" + "resolveCorpusPath"
 * describe blocks). Proves the round-trip: a `HuntFindingRecord` (as
 * `runHuntScan` now returns via `HuntScanResult.records`) projects into a
 * full JSONL row — never flattened to a title — and reads back byte-for-byte.
 */

import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Finding } from "@0sec/shared";
import type { HuntBrief, HuntFindingRecord } from "@0sec/core";
import {
  resultToHuntSample,
  sampleToJsonl,
  appendToCorpus,
  resolveHuntCorpusPath,
  HUNT_CORPUS_PATH,
} from "./hunt-corpus.js";

const tmpDirs: string[] = [];
afterEach(() => {
  for (const d of tmpDirs.splice(0)) {
    try {
      rmSync(d, { recursive: true, force: true });
    } catch {
      /* best-effort cleanup */
    }
  }
});

function mkFinding(id: string): Finding {
  return {
    id,
    templateId: "hunt-test",
    title: `finding ${id}`,
    description: "attacker-controlled length feeds an unchecked memcpy",
    severity: "high",
    category: "heap-overflow",
    status: "discovered",
    evidence: {
      request: "POST /parse",
      response: "AddressSanitizer: heap-buffer-overflow",
      analysis: "the sink at parse.c:42 trusts the TLV length field",
    },
    timestamp: 1_700_000_000_000,
  };
}

const BRIEF: HuntBrief = {
  bugClass: "missing length check before a TLV copy",
  pattern: "memcpy(dst, t->val, t->len) with no bound on t->len",
  fixReference: "nfc-digital-SENSF_RES-length-clamp",
};

describe("resultToHuntSample", () => {
  it("projects the full finding tuple, never flattened to a title", () => {
    const record: HuntFindingRecord = {
      candidatePath: "/root/linux-6.12.93/net/nfc/digital.c",
      model: "glm-5.2",
      attempt: 2,
      finding: mkFinding("f1"),
      judgeScore: 8,
      judgeReason: "matches the sink shape",
      skepticConfirmed: true,
      skepticReason: "survived adversarial refute pass",
      duplicate: false,
    };
    const sample = resultToHuntSample(record, BRIEF);
    expect(sample.id).toBe(`${record.candidatePath}:f1`);
    expect(sample.candidatePath).toBe(record.candidatePath);
    expect(sample.bugClass).toBe(BRIEF.bugClass);
    expect(sample.pattern).toBe(BRIEF.pattern);
    expect(sample.fixReference).toBe(BRIEF.fixReference);
    expect(sample.model).toBe("glm-5.2");
    expect(sample.attempt).toBe(2);
    expect(sample.judgeScore).toBe(8);
    expect(sample.judgeReason).toBe("matches the sink shape");
    expect(sample.skepticConfirmed).toBe(true);
    expect(sample.skepticReason).toBe("survived adversarial refute pass");
    expect(sample.duplicate).toBe(false);
    // The FULL finding rides along, including evidence.request/response/analysis.
    expect(sample.finding.evidence.analysis).toBe(record.finding.evidence.analysis);
    expect(sample.finding.evidence.response).toBe(record.finding.evidence.response);
  });

  it("omits optional fields cleanly when no brief / no judge / no skeptic verdict", () => {
    const record: HuntFindingRecord = {
      candidatePath: "/src/a.c",
      attempt: 0,
      finding: mkFinding("f2"),
      duplicate: false,
    };
    const sample = resultToHuntSample(record);
    expect(sample.model).toBe("default");
    expect(sample.bugClass).toBeUndefined();
    expect(sample.judgeScore).toBeUndefined();
    expect(sample.skepticConfirmed).toBeUndefined();
    expect(sample.id).toBe("/src/a.c:f2");
  });
});

describe("corpus persistence round-trip (mirror cybergym-runner's appendToCorpus)", () => {
  it("appends full finding records as JSONL and reads them back unflattened", () => {
    const dir = mkdtempSync(join(tmpdir(), "hunt-corpus-test-"));
    tmpDirs.push(dir);
    const corpus = join(dir, "results", "hunt-variant-v1.jsonl");

    const first: HuntFindingRecord = {
      candidatePath: "/src/a.c",
      model: "glm-5.2",
      attempt: 0,
      finding: mkFinding("f1"),
      judgeScore: 9,
      judgeReason: "strong match",
      skepticConfirmed: true,
      skepticReason: "survived",
      duplicate: false,
    };
    const second: HuntFindingRecord = {
      candidatePath: "/src/b.c",
      attempt: 1,
      finding: mkFinding("f2"),
      duplicate: true,
    };

    appendToCorpus([first], corpus, BRIEF);
    appendToCorpus([second], corpus);

    const lines = readFileSync(corpus, "utf8").trim().split("\n");
    expect(lines).toHaveLength(2);
    const row1 = JSON.parse(lines[0]);
    expect(row1.id).toBe("/src/a.c:f1");
    expect(row1.bugClass).toBe(BRIEF.bugClass);
    expect(row1.finding.evidence.analysis).toBe(first.finding.evidence.analysis);
    const row2 = JSON.parse(lines[1]);
    expect(row2.id).toBe("/src/b.c:f2");
    expect(row2.duplicate).toBe(true);
    expect(row2.bugClass).toBeUndefined();
  });

  it("no-ops on an empty record list (no empty file created)", () => {
    const dir = mkdtempSync(join(tmpdir(), "hunt-corpus-empty-"));
    tmpDirs.push(dir);
    const corpus = join(dir, "results", "hunt-variant-v1.jsonl");
    appendToCorpus([], corpus);
    expect(() => readFileSync(corpus, "utf8")).toThrow();
  });

  it("sampleToJsonl serializes one row per line", () => {
    const sample = resultToHuntSample({
      candidatePath: "/src/a.c",
      attempt: 0,
      finding: mkFinding("f1"),
      duplicate: false,
    });
    const line = sampleToJsonl(sample);
    expect(line.split("\n")).toHaveLength(1);
    expect(JSON.parse(line).id).toBe("/src/a.c:f1");
  });
});

describe("resolveHuntCorpusPath (HUNT_CORPUS_PATH override)", () => {
  const pkgRoot = "/some/benchmark-pkg";

  function withEnv(value: string | undefined, fn: () => void): void {
    const saved = process.env.HUNT_CORPUS_PATH;
    if (value === undefined) delete process.env.HUNT_CORPUS_PATH;
    else process.env.HUNT_CORPUS_PATH = value;
    try {
      fn();
    } finally {
      if (saved === undefined) delete process.env.HUNT_CORPUS_PATH;
      else process.env.HUNT_CORPUS_PATH = saved;
    }
  }

  it("returns the package-relative default when no override and no env are set", () => {
    withEnv(undefined, () => {
      expect(resolveHuntCorpusPath(undefined, pkgRoot)).toBe(join(pkgRoot, HUNT_CORPUS_PATH));
    });
  });

  it("resolves a relative override against the process CWD", () => {
    withEnv(undefined, () => {
      expect(resolveHuntCorpusPath("results/hunt-variant-fair-v1.jsonl", pkgRoot)).toBe(
        join(process.cwd(), "results/hunt-variant-fair-v1.jsonl"),
      );
    });
  });

  it("uses an absolute override verbatim", () => {
    expect(resolveHuntCorpusPath("/abs/corpus.jsonl", pkgRoot)).toBe("/abs/corpus.jsonl");
  });

  it("honors the HUNT_CORPUS_PATH env when no override is passed", () => {
    withEnv("env-corpus.jsonl", () => {
      expect(resolveHuntCorpusPath(undefined, pkgRoot)).toBe(join(process.cwd(), "env-corpus.jsonl"));
    });
  });
});
