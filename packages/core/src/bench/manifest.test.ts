import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  parseManifest,
  loadManifest,
  selectCiCases,
  subsetManifest,
  partitionCases,
  type BenchManifest,
} from "./manifest.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

function baseCase(overrides: Record<string, unknown> = {}) {
  return {
    id: "c1",
    target: { kind: "web", image: "img:1", port: 8080 },
    objective: { type: "file-read", marker: "MARKER_1234" },
    ...overrides,
  };
}

describe("parseManifest", () => {
  it("accepts a minimal valid manifest and applies defaults", () => {
    const m = parseManifest({ id: "m1", cases: [baseCase()] });
    expect(m.version).toBe(1);
    expect(m.cases[0].knownNegative).toBe(false);
    expect(m.cases[0].ci).toBe(false);
    expect(m.cases[0].tags).toEqual([]);
  });

  it("rejects duplicate case ids", () => {
    expect(() =>
      parseManifest({ id: "m1", cases: [baseCase(), baseCase()] }),
    ).toThrow(/duplicate case id "c1"/);
  });

  it("rejects an empty manifest", () => {
    expect(() => parseManifest({ id: "m1", cases: [] })).toThrow();
  });

  it("rejects a kasan-hit objective on a web target", () => {
    expect(() =>
      parseManifest({
        id: "m1",
        cases: [
          baseCase({ objective: { type: "kasan-hit", signature: "use-after-free" } }),
        ],
      }),
    ).toThrow(/kasan-hit objective requires a kernel target/);
  });

  it("rejects a non-kasan objective on a kernel target", () => {
    expect(() =>
      parseManifest({
        id: "m1",
        cases: [
          baseCase({
            target: { kind: "kernel", reproducerRef: "corpus://k/1" },
            objective: { type: "file-read", marker: "MARKER_1234" },
          }),
        ],
      }),
    ).toThrow(/kasan-hit objective requires a kernel target/);
  });

  it("accepts a well-formed kernel case", () => {
    const m = parseManifest({
      id: "m1",
      cases: [
        baseCase({
          id: "k1",
          target: { kind: "kernel", reproducerRef: "corpus://k/1", ecosystem: "kernel-tree" },
          objective: { type: "kasan-hit" },
        }),
      ],
    });
    expect(m.cases[0].target.kind).toBe("kernel");
  });

  it("rejects a too-short marker", () => {
    expect(() =>
      parseManifest({
        id: "m1",
        cases: [baseCase({ objective: { type: "file-read", marker: "x" } })],
      }),
    ).toThrow();
  });
});

describe("loadManifest (example-manifest.json)", () => {
  let manifest: BenchManifest;

  it("loads + validates the committed example manifest", async () => {
    manifest = await loadManifest(join(__dirname, "example-manifest.json"));
    expect(manifest.id).toMatch(/references-only/);
  });

  it("has >=5 web targets, >=3 kernel cases, and >=3 known-negatives", async () => {
    manifest = await loadManifest(join(__dirname, "example-manifest.json"));
    const web = manifest.cases.filter((c) => c.target.kind === "web");
    const kernel = manifest.cases.filter((c) => c.target.kind === "kernel");
    const { knownNegatives } = partitionCases(manifest.cases);
    expect(web.length).toBeGreaterThanOrEqual(5);
    expect(kernel.length).toBeGreaterThanOrEqual(3);
    expect(knownNegatives.length).toBeGreaterThanOrEqual(3);
  });

  it("the example carries no inline exploit/corpus content (references only)", async () => {
    const { readFile } = await import("node:fs/promises");
    const raw = await readFile(join(__dirname, "example-manifest.json"), "utf8");
    // References are image refs / corpus:// locators / compose dirs only.
    expect(raw).toMatch(/REFERENCES ONLY/);
    // No raw exploit primitives should be sitting in the manifest.
    expect(raw).not.toMatch(/<script>/i);
    expect(raw).not.toMatch(/\bUNION SELECT\b/i);
  });
});

describe("parseManifest — source-audit + finding-match", () => {
  const sourceAuditCase = (overrides: Record<string, unknown> = {}) => ({
    id: "sa1",
    target: { kind: "source-audit", package: "sequelize", version: "6.37.8" },
    objective: {
      type: "finding-match",
      vulnClass: "sql-injection",
      sinkMarkers: ["Sequelize.prototype.set"],
    },
    ...overrides,
  });

  it("accepts a well-formed source-audit case and defaults ecosystem to npm", () => {
    const m = parseManifest({ id: "m1", cases: [sourceAuditCase()] });
    expect(m.cases[0].target.kind).toBe("source-audit");
    expect((m.cases[0].target as { ecosystem: string }).ecosystem).toBe("npm");
  });

  it("rejects a finding-match objective on a web target", () => {
    expect(() =>
      parseManifest({
        id: "m1",
        cases: [sourceAuditCase({ target: { kind: "web", image: "img:1", port: 80 } })],
      }),
    ).toThrow(/finding-match objective requires a source-audit target/);
  });

  it("rejects a non-finding-match objective on a source-audit target", () => {
    expect(() =>
      parseManifest({
        id: "m1",
        cases: [sourceAuditCase({ objective: { type: "file-read", marker: "MARKER_1234" } })],
      }),
    ).toThrow(/file-read objective requires a web target/);
  });

  it("rejects a finding-match objective with no sink markers", () => {
    expect(() =>
      parseManifest({
        id: "m1",
        cases: [
          sourceAuditCase({
            objective: { type: "finding-match", vulnClass: "sql-injection", sinkMarkers: [] },
          }),
        ],
      }),
    ).toThrow();
  });

  it("still rejects the legacy kasan/kernel mismatch with its original message", () => {
    expect(() =>
      parseManifest({
        id: "m1",
        cases: [baseCase({ objective: { type: "kasan-hit", signature: "uaf" } })],
      }),
    ).toThrow(/kasan-hit objective requires a kernel target/);
  });
});

describe("loadManifest (corpus-v1.json — the real labeled corpus)", () => {
  it("loads + validates the committed corpus", async () => {
    const m = await loadManifest(join(__dirname, "corpus-v1.json"));
    expect(m.id).toBe("0sec-bench-corpus-v1");
    expect(m.cases.length).toBeGreaterThanOrEqual(30);
    expect(m.cases.length).toBeLessThanOrEqual(60);
  });

  it("has ~1/3 known-negatives for a real FP-rate measurement", async () => {
    const m = await loadManifest(join(__dirname, "corpus-v1.json"));
    const { positives, knownNegatives } = partitionCases(m.cases);
    expect(knownNegatives.length).toBeGreaterThanOrEqual(positives.length / 3 - 2);
    const negFraction = knownNegatives.length / m.cases.length;
    expect(negFraction).toBeGreaterThanOrEqual(0.25);
    expect(negFraction).toBeLessThanOrEqual(0.45);
  });

  it("spans the ICP: source-audit (npm), kernel, and a CI subset", async () => {
    const m = await loadManifest(join(__dirname, "corpus-v1.json"));
    const sourceAudit = m.cases.filter((c) => c.target.kind === "source-audit");
    const kernel = m.cases.filter((c) => c.target.kind === "kernel");
    expect(sourceAudit.length).toBeGreaterThanOrEqual(20);
    expect(kernel.length).toBeGreaterThanOrEqual(3);
    expect(selectCiCases(m).length).toBeGreaterThanOrEqual(3);
  });

  it("carries no inline exploit/corpus content (references + sink labels only)", async () => {
    const { readFile } = await import("node:fs/promises");
    const raw = await readFile(join(__dirname, "corpus-v1.json"), "utf8");
    expect(raw).toMatch(/REFERENCES ONLY/);
    expect(raw).not.toMatch(/<script>/i);
    expect(raw).not.toMatch(/\bUNION\s+SELECT\b/i);
  });
});

describe("selectCiCases", () => {
  it("returns only ci-flagged cases", () => {
    const m = parseManifest({
      id: "m1",
      cases: [
        baseCase({ id: "a", ci: true }),
        baseCase({ id: "b", ci: false }),
        baseCase({ id: "c", ci: true }),
      ],
    });
    expect(selectCiCases(m).map((c) => c.id)).toEqual(["a", "c"]);
  });
});

describe("subsetManifest", () => {
  const manifest = parseManifest({
    id: "full",
    cases: [
      baseCase({ id: "dev" }),
      baseCase({ id: "held" }),
      baseCase({ id: "negative", knownNegative: true }),
    ],
  });

  it("preserves requested order and gives the sealed slice its own id", () => {
    const subset = subsetManifest(manifest, ["held", "dev"], "full:development");
    expect(subset.id).toBe("full:development");
    expect(subset.cases.map((c) => c.id)).toEqual(["held", "dev"]);
  });

  it("fails closed for missing or duplicate case ids", () => {
    expect(() => subsetManifest(manifest, ["missing"], "bad")).toThrow(/unknown case id/);
    expect(() => subsetManifest(manifest, ["dev", "dev"], "bad")).toThrow(/duplicate/);
  });
});
