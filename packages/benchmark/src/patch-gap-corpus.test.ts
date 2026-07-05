/**
 * Unit tests for the patch-gap monitor corpus persistence (mirrors
 * `hunt-corpus.test.ts`'s structure). Proves the round-trip: a ranked
 * `PatchGapCandidate[]` from a run projects into full JSONL rows — never
 * flattened to CVE-ids-only — and reads back byte-for-byte.
 */

import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { PatchGapCandidate } from "@pwnkit/core";
import {
  appendPatchGapCorpus,
  patchGapSampleToJsonl,
  resolvePatchGapCorpusPath,
  PATCH_GAP_CORPUS_PATH,
} from "./patch-gap-corpus.js";

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

function mkCandidate(cve: string): PatchGapCandidate {
  return {
    cve,
    fixSha: "deadbeefcafef00d1234567890abcdef12345678",
    title: `${cve}: fix use-after-free`,
    files: ["net/unix/af_unix.c"],
    subsystem: "net/unix",
    reachable: "reachable",
    severity: "high",
    presence: { present: false, method: "none", reason: "fix absent, live 1day candidate" },
    reason: `${cve}: fix absent, live 1day candidate (kernelCTF reachability: reachable)`,
  };
}

describe("patch-gap corpus persistence round-trip", () => {
  it("appends full candidate records as JSONL and reads them back unflattened", () => {
    const dir = mkdtempSync(join(tmpdir(), "patch-gap-corpus-test-"));
    tmpDirs.push(dir);
    const corpus = join(dir, "results", "patch-gap-v1.jsonl");

    appendPatchGapCorpus([mkCandidate("CVE-2026-00001")], "/root/linux-6.12.93", corpus, "2026-07-05T00:00:00.000Z");
    appendPatchGapCorpus([mkCandidate("CVE-2026-00002")], "/root/linux-6.12.93", corpus, "2026-07-05T01:00:00.000Z");

    const lines = readFileSync(corpus, "utf8").trim().split("\n");
    expect(lines).toHaveLength(2);
    const row1 = JSON.parse(lines[0]);
    expect(row1.candidate.cve).toBe("CVE-2026-00001");
    expect(row1.targetTreePath).toBe("/root/linux-6.12.93");
    expect(row1.candidate.presence.reason).toContain("live 1day candidate");
    const row2 = JSON.parse(lines[1]);
    expect(row2.candidate.cve).toBe("CVE-2026-00002");
  });

  it("no-ops on an empty candidate list (no empty file created)", () => {
    const dir = mkdtempSync(join(tmpdir(), "patch-gap-corpus-empty-"));
    tmpDirs.push(dir);
    const corpus = join(dir, "results", "patch-gap-v1.jsonl");
    appendPatchGapCorpus([], "/root/linux-6.12.93", corpus);
    expect(() => readFileSync(corpus, "utf8")).toThrow();
  });

  it("patchGapSampleToJsonl serializes one row per line", () => {
    const line = patchGapSampleToJsonl({
      scannedAt: "2026-07-05T00:00:00.000Z",
      targetTreePath: "/root/linux-6.12.93",
      candidate: mkCandidate("CVE-2026-00001"),
    });
    expect(line.split("\n")).toHaveLength(1);
    expect(JSON.parse(line).candidate.cve).toBe("CVE-2026-00001");
  });
});

describe("resolvePatchGapCorpusPath (PATCH_GAP_CORPUS_PATH override)", () => {
  const pkgRoot = "/some/benchmark-pkg";

  function withEnv(value: string | undefined, fn: () => void): void {
    const saved = process.env.PATCH_GAP_CORPUS_PATH;
    if (value === undefined) delete process.env.PATCH_GAP_CORPUS_PATH;
    else process.env.PATCH_GAP_CORPUS_PATH = value;
    try {
      fn();
    } finally {
      if (saved === undefined) delete process.env.PATCH_GAP_CORPUS_PATH;
      else process.env.PATCH_GAP_CORPUS_PATH = saved;
    }
  }

  it("returns the package-relative default when no override and no env are set", () => {
    withEnv(undefined, () => {
      expect(resolvePatchGapCorpusPath(undefined, pkgRoot)).toBe(join(pkgRoot, PATCH_GAP_CORPUS_PATH));
    });
  });

  it("resolves a relative override against the process CWD", () => {
    withEnv(undefined, () => {
      expect(resolvePatchGapCorpusPath("results/patch-gap-custom.jsonl", pkgRoot)).toBe(
        join(process.cwd(), "results/patch-gap-custom.jsonl"),
      );
    });
  });

  it("uses an absolute override verbatim", () => {
    expect(resolvePatchGapCorpusPath("/abs/corpus.jsonl", pkgRoot)).toBe("/abs/corpus.jsonl");
  });

  it("honors the PATCH_GAP_CORPUS_PATH env when no override is passed", () => {
    withEnv("env-corpus.jsonl", () => {
      expect(resolvePatchGapCorpusPath(undefined, pkgRoot)).toBe(join(process.cwd(), "env-corpus.jsonl"));
    });
  });
});
