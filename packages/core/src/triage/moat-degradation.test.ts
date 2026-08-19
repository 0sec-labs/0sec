/**
 * Degradation tests for the opt-in FP-moat layers.
 *
 * These pin the safety property that the default-ON/KEEP-OFF assessment rests
 * on: when a moat layer's external dependency is missing — no foxguard binary,
 * no source tree, an unreadable path — the layer must return a NEUTRAL result
 * and never a suppression. A moat layer that rejects findings because a tool
 * was not installed would silently destroy recall on exactly the hosts least
 * likely to notice.
 *
 * They are also the precondition for enabling anything by default. A layer
 * cannot be a safe default until its absent-dependency path is proven inert,
 * so these tests are the evidence any future flip must cite.
 *
 * Note the asymmetry these encode: degrading safely is necessary but NOT
 * sufficient for a default flip. Both layers below also carry a per-finding
 * cost (a full repo walk / a full repo scan, neither cached across findings),
 * which is why they remain opt-in despite passing here.
 */

import { describe, it, expect } from "vitest";
import type { Finding } from "@pwnkit/shared";
import { checkMultiModalAgreement, fuseTriageSignals } from "./multi-modal.js";
import { checkReachability } from "./reachability.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f-1",
    templateId: "t",
    title: "SQL injection in src/db/query.ts",
    description: "user input reaches a raw query in src/db/query.ts",
    severity: "high",
    category: "sql-injection",
    status: "discovered",
    evidence: { request: "", response: "", analysis: "" },
    confidence: 0.7,
    timestamp: Date.now(),
    ...overrides,
  } as Finding;
}

const MISSING_DIR = "/nonexistent-path-for-pwnkit-degradation-test";

describe("multi-modal agreement degrades safely without its dependencies", () => {
  it("returns a neutral verdict when the source tree does not exist", async () => {
    const result = await checkMultiModalAgreement(makeFinding(), MISSING_DIR, {
      foxguardPath: "/bin/true",
    });

    expect(result.agreement).toBe("only_pwnkit");
    expect(result.confidence).toBe(0.5);
    expect(result.foxguardFindings).toHaveLength(0);
  });

  it("returns a neutral verdict when the foxguard binary fails to run", async () => {
    const result = await checkMultiModalAgreement(makeFinding(), process.cwd(), {
      foxguardPath: "/bin/true",
      runner: () => Promise.reject(new Error("ENOENT: foxguard not installed")),
    });

    expect(result.agreement).toBe("only_pwnkit");
    expect(result.confidence).toBe(0.5);
    expect(result.reasoning).toContain("foxguard");
  });

  it("produces no auto_reject from a neutral (dependency-absent) verdict", async () => {
    const multiModal = await checkMultiModalAgreement(makeFinding(), MISSING_DIR, {
      foxguardPath: "/bin/true",
    });

    // A high-severity finding with complete evidence must survive a scan on a
    // host where foxguard was never installed.
    const fused = fuseTriageSignals({
      multiModal,
      holdingItWrong: false,
      evidenceCompleteness: 0.9,
    });

    expect(fused.decision).not.toBe("auto_reject");
  });
});

describe("reachability gate degrades safely without a readable source tree", () => {
  /**
   * The gate only acts on `!reachable && confidence >= 0.7`. Both no-source
   * paths must therefore land on the reachable side, or below that threshold,
   * or both — otherwise a missing repo would look like dead code.
   */
  it("fails open when the source directory cannot be read", async () => {
    const result = await checkReachability(makeFinding(), MISSING_DIR);

    expect(result.reachable).toBe(true);
    expect(result.confidence).toBeLessThan(0.7);
  });

  it("fails open when the directory exists but holds no source files", async () => {
    const { mkdtempSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const empty = mkdtempSync(join(tmpdir(), "pwnkit-reach-empty-"));

    const result = await checkReachability(makeFinding(), empty);

    expect(result.reachable).toBe(true);
    expect(result.confidence).toBeLessThan(0.7);
  });
});
