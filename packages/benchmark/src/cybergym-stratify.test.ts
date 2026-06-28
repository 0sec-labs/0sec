/**
 * Unit tests for the CyberGym stratified-subset generator (issue #1029).
 *
 * The generator is a pure, deterministic, no-network tool: the same corpus +
 * seed MUST always produce the same subset (that is the pre-registration
 * contract). These tests pin the core invariants — determinism, proportional
 * allocation bounds, tolerant corpus parsing, and the bare-mask_map fallback —
 * independently of the real bench corpus (which is not in-repo).
 */

import { describe, it, expect } from "vitest";
import {
  mulberry32,
  deterministicSample,
  allocateProportional,
  stratify,
  parseCorpus,
  DEFAULT_FAIR_TARGET,
} from "./cybergym-stratify.js";

describe("mulberry32 + deterministicSample", () => {
  it("mulberry32 is deterministic for a fixed seed", () => {
    const a = mulberry32(42);
    const b = mulberry32(42);
    const seqA = Array.from({ length: 5 }, a);
    const seqB = Array.from({ length: 5 }, b);
    expect(seqA).toEqual(seqB);
  });

  it("different seeds produce different streams", () => {
    const a = Array.from({ length: 5 }, mulberry32(1));
    const b = Array.from({ length: 5 }, mulberry32(2));
    expect(a).not.toEqual(b);
  });

  it("returns all items when k >= length, in a stable (lexical) order", () => {
    const rand = mulberry32(7);
    const out = deterministicSample(["c", "a", "b"], 10, rand);
    expect(out).toEqual(["a", "b", "c"]);
  });

  it("is input-order independent (same seed → same selection)", () => {
    const k = 3;
    const set1 = new Set(deterministicSample(["a", "b", "c", "d", "e"], k, mulberry32(99)));
    const set2 = new Set(deterministicSample(["e", "d", "c", "b", "a"], k, mulberry32(99)));
    expect(set1).toEqual(set2);
  });

  it("picks exactly k distinct items", () => {
    const items = Array.from({ length: 20 }, (_, i) => `t${i}`);
    const out = deterministicSample(items, 7, mulberry32(5));
    expect(out).toHaveLength(7);
    expect(new Set(out).size).toBe(7);
    expect(out.every((x) => items.includes(x))).toBe(true);
  });
});

describe("allocateProportional (largest-remainder)", () => {
  it("takes all when total <= target", () => {
    expect(allocateProportional([3, 3, 3], 20)).toEqual([3, 3, 3]);
    expect(allocateProportional([3, 3, 3], 9)).toEqual([3, 3, 3]);
  });

  it("sums to target and never exceeds a bucket's size", () => {
    const sizes = [100, 50, 25, 13];
    const alloc = allocateProportional(sizes, 75);
    expect(alloc.reduce((s, n) => s + n, 0)).toBe(75);
    alloc.forEach((n, i) => expect(n).toBeLessThanOrEqual(sizes[i]));
  });

  it("is proportional: the biggest bucket gets the biggest allocation", () => {
    const alloc = allocateProportional([200, 100, 50], 70);
    expect(alloc[0]).toBeGreaterThan(alloc[1]);
    expect(alloc[1]).toBeGreaterThan(alloc[2]);
  });

  it("returns all-zero when target is 0", () => {
    expect(allocateProportional([5, 5], 0)).toEqual([0, 0]);
  });
});

describe("stratify (pure, deterministic)", () => {
  const tasks = [
    ...Array.from({ length: 10 }, (_, i) => ({
      taskId: `arvo:${1000 + i}`,
      fields: { project: "freetype", crashType: "heap-buffer-overflow" },
    })),
    ...Array.from({ length: 6 }, (_, i) => ({
      taskId: `arvo:${2000 + i}`,
      fields: { project: "glibc", crashType: "use-after-free" },
    })),
    ...Array.from({ length: 4 }, (_, i) => ({
      taskId: `arvo:${3000 + i}`,
      fields: { project: "yara", crashType: "stack-overflow" },
    })),
  ]; // 20 tasks, 3 strata

  it("is deterministic — same seed gives the same subset", () => {
    const opts = { target: 10, seed: 123, stratifyBy: ["project", "crashType"] };
    const a = stratify(tasks, opts);
    const b = stratify(tasks, opts);
    expect(a.subset).toEqual(b.subset);
  });

  it("different seeds can give different subsets (membership)", () => {
    const a = stratify(tasks, { target: 8, seed: 1, stratifyBy: ["project"] });
    const b = stratify(tasks, { target: 8, seed: 2, stratifyBy: ["project"] });
    expect(a.subset).not.toEqual(b.subset);
  });

  it("caps the subset at the universe size when target > total", () => {
    const r = stratify(tasks, {
      target: 999,
      seed: 1,
      stratifyBy: ["project"],
    });
    expect(r.subset).toHaveLength(20);
    expect(r.total).toBe(20);
  });

  it("subset size never exceeds the target (when target < total)", () => {
    const r = stratify(tasks, {
      target: 10,
      seed: 1,
      stratifyBy: ["project"],
    });
    expect(r.subset.length).toBeLessThanOrEqual(10);
  });

  it("allocates proportionally across strata (largest bucket gets the most)", () => {
    const r = stratify(tasks, {
      target: 10,
      seed: 1,
      stratifyBy: ["project"],
    });
    const byProj = (p: string) =>
      r.buckets.find((b) => b.key === p)?.sampled ?? 0;
    // freetype (10) > glibc (6) > yara (4)
    expect(byProj("freetype")).toBeGreaterThan(byProj("glibc"));
    expect(byProj("glibc")).toBeGreaterThan(byProj("yara"));
  });

  it("no stratum is sampled beyond its allocation (bounded by size)", () => {
    const r = stratify(tasks, {
      target: 10,
      seed: 1,
      stratifyBy: ["project", "crashType"],
    });
    for (const b of r.buckets) {
      expect(b.sampled).toBeLessThanOrEqual(b.size);
      expect(b.sampled).toBeLessThanOrEqual(b.allocated);
    }
  });

  it("reports missingFields + stratifiedFully=false when a stratum field is absent", () => {
    const bareTasks = [
      { taskId: "arvo:1", fields: { project: "x" } },
      { taskId: "arvo:2", fields: { project: "y" } },
    ];
    const r = stratify(bareTasks, {
      target: 1,
      seed: 1,
      stratifyBy: ["project", "crashType"],
    });
    expect(r.missingFields).toEqual(["crashType"]);
    expect(r.stratifiedFully).toBe(false);
  });
});

describe("parseCorpus (tolerant of shape)", () => {
  it("parses a mask_map.json object into a bare id universe", () => {
    const mask = JSON.stringify({
      "arvo:10400": "7fa395d7dac0",
      "arvo:1065": "abc123",
      "arvo:47101": "deadbeef",
    });
    const tasks = parseCorpus(mask);
    expect(tasks.map((t) => t.taskId).sort()).toEqual([
      "arvo:10400",
      "arvo:1065",
      "arvo:47101",
    ]);
    // mask_map carries no project/crashType metadata.
    expect(tasks.every((t) => Object.keys(t.fields).length === 0)).toBe(true);
  });

  it("parses a JSONL corpus, skipping the summary row", () => {
    const jsonl = [
      '{"kind":"summary","tasks":3,"passed":2}',
      '{"kind":"task","taskId":"arvo:10400","project":"graphicsmagick","crashType":"heap-buffer-overflow"}',
      '{"kind":"task","taskId":"arvo:1065","project":"glibc","crashType":"use-after-free"}',
      '{"kind":"task","taskId":"arvo:3938","project":"yara"}',
    ].join("\n");
    const tasks = parseCorpus(jsonl);
    expect(tasks).toHaveLength(3);
    expect(tasks[0].taskId).toBe("arvo:10400");
    expect(tasks[0].fields.project).toBe("graphicsmagick");
    expect(tasks[0].fields.crashType).toBe("heap-buffer-overflow");
    expect(tasks[2].fields.project).toBe("yara");
    expect(tasks[2].fields.crashType).toBeUndefined();
  });

  it("parses a JSON array of records (with field aliases)", () => {
    const arr = JSON.stringify([
      { task_id: "arvo:1", project: "p1", bug_type: "uaf" },
      { id: "arvo:2", repo: "p2", sanitizer: "asan" },
    ]);
    const tasks = parseCorpus(arr);
    expect(tasks).toHaveLength(2);
    expect(tasks[0].taskId).toBe("arvo:1");
    expect(tasks[0].fields.crashType).toBe("uaf");
    expect(tasks[1].taskId).toBe("arvo:2");
    expect(tasks[1].fields.project).toBe("p2");
    expect(tasks[1].fields.crashType).toBe("asan");
  });

  it("throws on a totally unrecognized shape", () => {
    expect(() => parseCorpus("just some plain text\nnot json at all")).toThrow(
      /Unrecognized corpus shape/,
    );
  });

  it("returns [] for empty input", () => {
    expect(parseCorpus("")).toEqual([]);
  });
});

describe("end-to-end: mask_map fallback path (no metadata)", () => {
  it("still produces a deterministic, sized subset from a bare mask_map", () => {
    const mask: Record<string, string> = {};
    for (let i = 0; i < 200; i++) {
      mask[`arvo:${10000 + i}`] = `mask${i}`;
    }
    const tasks = parseCorpus(JSON.stringify(mask));
    const a = stratify(tasks, {
      target: DEFAULT_FAIR_TARGET,
      seed: 0xc6f1a5ed,
      stratifyBy: ["project", "crashType"],
    });
    const b = stratify(tasks, {
      target: DEFAULT_FAIR_TARGET,
      seed: 0xc6f1a5ed,
      stratifyBy: ["project", "crashType"],
    });
    expect(a.subset).toEqual(b.subset); // deterministic
    expect(a.subset.length).toBeLessThanOrEqual(DEFAULT_FAIR_TARGET);
    expect(a.subset.length).toBe(DEFAULT_FAIR_TARGET); // 200 > 175 → samples exactly 175
    expect(a.stratifiedFully).toBe(false); // no metadata present
    expect(a.missingFields.sort()).toEqual(["crashType", "project"]);
    // every stratum collapsed to "unknown"
    expect(a.buckets.every((bk) => bk.key.includes("unknown"))).toBe(true);
  });
});
