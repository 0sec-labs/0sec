import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  parseManifest,
  loadManifest,
  selectCiCases,
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
