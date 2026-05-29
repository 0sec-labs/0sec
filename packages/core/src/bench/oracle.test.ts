import { describe, it, expect } from "vitest";
import { ObjectiveOracle, type BenchScanResult } from "./oracle.js";
import type { BenchCase } from "./manifest.js";

function webCase(overrides: Partial<BenchCase> = {}): BenchCase {
  return {
    id: "w1",
    target: { kind: "web", image: "img:1", port: 80 },
    objective: { type: "file-read", marker: "BENCH_MARKER_AAAA" },
    knownNegative: false,
    ci: false,
    tags: [],
    ...overrides,
  } as BenchCase;
}

function kernelCase(overrides: Partial<BenchCase> = {}): BenchCase {
  return {
    id: "k1",
    target: { kind: "kernel", reproducerRef: "corpus://k/1", ecosystem: "kernel-tree" },
    objective: { type: "kasan-hit" },
    knownNegative: false,
    ci: false,
    tags: [],
    ...overrides,
  } as BenchCase;
}

const oracle = new ObjectiveOracle();

describe("ObjectiveOracle — positive web cases", () => {
  it("verifies when the injected marker appears in finding evidence", () => {
    const report: BenchScanResult = {
      findings: [
        {
          category: "path-traversal",
          evidence: { response: "...leaked file contents BENCH_MARKER_AAAA here..." },
        },
      ],
    };
    const out = oracle.evaluate({ case: webCase(), report, attemptIndex: 0 });
    expect(out.status).toBe("verified");
    expect(out.confidence).toBe(0.95);
  });

  it("finds the marker in the conversation trace too", () => {
    const report: BenchScanResult = {
      findings: [],
      trace: [{ role: "tool", content: "cat /etc/secret -> BENCH_MARKER_AAAA" }],
    };
    expect(oracle.evaluate({ case: webCase(), report, attemptIndex: 0 }).status).toBe(
      "verified",
    );
  });

  it("refutes when there is no marker, even if a finding was reported", () => {
    const report: BenchScanResult = {
      findings: [{ category: "path-traversal", confidence: 0.95, status: "verified" }],
    };
    // A positive case requires concrete proof; an over-claim is NOT enough.
    const out = oracle.evaluate({ case: webCase(), report, attemptIndex: 0 });
    expect(out.status).toBe("refuted");
    expect(out.confidence).toBe(0.0);
  });

  it("marker match is case-insensitive", () => {
    const report: BenchScanResult = {
      findings: [{ evidence: { response: "bench_marker_aaaa" } }],
    };
    expect(oracle.evaluate({ case: webCase(), report, attemptIndex: 0 }).status).toBe(
      "verified",
    );
  });

  it("returns inconclusive when the scan errored", () => {
    const report: BenchScanResult = { error: "docker start failed" };
    const out = oracle.evaluate({ case: webCase(), report, attemptIndex: 0 });
    expect(out.status).toBe("inconclusive");
    expect(out.confidence).toBeNull();
  });
});

describe("ObjectiveOracle — ssrf token", () => {
  it("verifies on the OAST callback token", () => {
    const c = webCase({
      id: "s1",
      objective: { type: "ssrf-callback", token: "OAST_TOKEN_ZZZZ" },
    });
    const report: BenchScanResult = {
      findings: [{ category: "ssrf", evidence: { response: "callback hit: OAST_TOKEN_ZZZZ" } }],
    };
    expect(oracle.evaluate({ case: c, report, attemptIndex: 0 }).status).toBe("verified");
  });
});

describe("ObjectiveOracle — known-negative FP detection", () => {
  it("flags a false positive when a known-negative over-claims an in-family exploit", () => {
    const c = webCase({ id: "neg-sqli", knownNegative: true, objective: { type: "db-access", marker: "NEVER_PRESENT_XX" } });
    const report: BenchScanResult = {
      // No marker (impossible on a non-vulnerable target) but the scanner
      // asserted a high-confidence SQLi → over-claim → false positive.
      findings: [{ category: "sql-injection", confidence: 0.97, status: "verified" }],
    };
    const out = oracle.evaluate({ case: c, report, attemptIndex: 0 });
    expect(out.status).toBe("verified");
    expect(out.notes).toMatch(/FALSE POSITIVE/);
  });

  it("refutes a clean known-negative (no marker, no over-claim)", () => {
    const c = webCase({ id: "neg-clean", knownNegative: true, objective: { type: "db-access", marker: "NEVER_PRESENT_XX" } });
    const report: BenchScanResult = {
      findings: [{ category: "information-disclosure", confidence: 0.4 }],
    };
    expect(oracle.evaluate({ case: c, report, attemptIndex: 0 }).status).toBe("refuted");
  });

  it("a hallucinated marker on a known-negative is also a false positive", () => {
    const c = webCase({ id: "neg-hall", knownNegative: true, objective: { type: "file-read", marker: "BENCH_MARKER_AAAA" } });
    const report: BenchScanResult = {
      findings: [{ evidence: { analysis: "I believe the file said BENCH_MARKER_AAAA" } }],
    };
    expect(oracle.evaluate({ case: c, report, attemptIndex: 0 }).status).toBe("verified");
  });
});

describe("ObjectiveOracle — kernel kasan cases", () => {
  it("verifies on a KASAN slab-use-after-free signature", () => {
    const c = kernelCase({ objective: { type: "kasan-hit", signature: "slab-use-after-free" } });
    const report: BenchScanResult = {
      findings: [
        {
          category: "use-after-free",
          evidence: { analysis: "BUG: KASAN: slab-use-after-free in nfs_do_thing+0x10" },
        },
      ],
    };
    expect(oracle.evaluate({ case: c, report, attemptIndex: 0 }).status).toBe("verified");
  });

  it("verifies on any crash signature when no specific signature is required", () => {
    const c = kernelCase({ objective: { type: "kasan-hit" } });
    const report: BenchScanResult = {
      findings: [{ evidence: { analysis: "general protection fault: 0000 [#1] SMP" } }],
    };
    expect(oracle.evaluate({ case: c, report, attemptIndex: 0 }).status).toBe("verified");
  });

  it("refutes a clean kernel run (no crash)", () => {
    const c = kernelCase({ objective: { type: "kasan-hit" } });
    const report: BenchScanResult = { findings: [{ evidence: { analysis: "reproducer exited 0" } }] };
    expect(oracle.evaluate({ case: c, report, attemptIndex: 0 }).status).toBe("refuted");
  });
});
