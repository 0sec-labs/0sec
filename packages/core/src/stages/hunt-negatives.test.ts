/**
 * Learned negatives (hunt-negatives.ts). Coverage:
 *
 *   - `huntNegativesEnabled`: OFF by default, ON only for a truthy env.
 *   - `matchNegative`: a finding matching a known-refuted shape is matched
 *     (score >= NEGATIVE_MIN); a novel finding is not (returns `null`).
 *   - `negativeContext`: a label + explicit override instruction, not a
 *     command to drop the finding.
 *   - `makeSkepticVerifier` wiring (hunt-scan.ts): attaches the negative
 *     context to the skeptic prompt for a matching finding when
 *     PWNKIT_HUNT_NEGATIVES=1; a novel finding's prompt is unaffected; the
 *     verifier NEVER auto-rejects on its own — it still calls the (mocked)
 *     finder and returns whatever that finder's outcome implies.
 */

import { describe, expect, it, vi } from "vitest";
import type { Finding } from "@pwnkit/shared";
import { huntNegativesEnabled, matchNegative, negativeContext, type KnownNegative } from "./hunt-negatives.js";

const agenticScanMock = vi.fn();
vi.mock("../agentic-scanner.js", () => ({
  agenticScan: (...args: unknown[]) => agenticScanMock(...args),
}));

const { makeSkepticVerifier } = await import("./hunt-scan.js");

function mkFinding(id: string, title: string, analysis: string): Finding {
  return {
    id,
    templateId: "negatives-test",
    title,
    description: title,
    severity: "medium",
    category: "other",
    status: "discovered",
    evidence: { request: "", response: "", analysis },
  };
}

function mkNegative(): KnownNegative {
  return {
    key: "drivers/net/wireless/marvell/mwifiex/txrx.c:mwifiex debug-gated OOB",
    classTokens: new Set(["cwe-125", "oob"]),
    sinkTokens: new Set(["mwifiex_process_rx_packet"]),
    reason: "mwifiex is not built on the kernelCTF COS target — dead code, not reachable",
    candidatePath: "drivers/net/wireless/marvell/mwifiex/txrx.c",
    provenance: "record:drivers/net/wireless/marvell/mwifiex/txrx.c model=default",
  };
}

describe("huntNegativesEnabled", () => {
  it("is OFF by default and ON only for a truthy PWNKIT_HUNT_NEGATIVES", () => {
    const prev = process.env.PWNKIT_HUNT_NEGATIVES;
    try {
      delete process.env.PWNKIT_HUNT_NEGATIVES;
      expect(huntNegativesEnabled()).toBe(false);
      process.env.PWNKIT_HUNT_NEGATIVES = "no";
      expect(huntNegativesEnabled()).toBe(false);
      process.env.PWNKIT_HUNT_NEGATIVES = "1";
      expect(huntNegativesEnabled()).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_HUNT_NEGATIVES;
      else process.env.PWNKIT_HUNT_NEGATIVES = prev;
    }
  });
});

describe("matchNegative", () => {
  it("matches a finding with the same refuted shape (class + sink overlap)", () => {
    const negative = mkNegative();
    const matching = mkFinding(
      "f1",
      "mwifiex OOB read",
      "mwifiex_process_rx_packet reads out-of-bounds, CWE-125 out-of-bounds",
    );
    const match = matchNegative(matching, [negative]);
    expect(match).not.toBeNull();
    expect(match?.negative.key).toBe(negative.key);
    expect(match?.score).toBeGreaterThan(0);
  });

  it("does not match a novel finding with no shared class/sink tokens", () => {
    const negative = mkNegative();
    const novel = mkFinding("f2", "an unrelated nf_tables UAF", "nft_set_elem_deactivate use-after-free, CWE-416");
    expect(matchNegative(novel, [negative])).toBeNull();
  });

  it("never mutates the finding and never signals a verdict — it only returns a label or null", () => {
    const negative = mkNegative();
    const matching = mkFinding("f1", "mwifiex OOB read", "mwifiex_process_rx_packet out-of-bounds, CWE-125");
    const before = JSON.stringify(matching);
    const match = matchNegative(matching, [negative]);
    expect(JSON.stringify(matching)).toBe(before);
    expect(match).not.toBeNull();
    // The return shape carries a label + score only — no "confirmed"/"reject" field.
    expect(Object.keys(match ?? {}).sort()).toEqual(["negative", "score"]);
  });
});

describe("negativeContext", () => {
  it("is a label + explicit override instruction, not a drop command", () => {
    const negative = mkNegative();
    const text = negativeContext({ negative, score: 0.5 });
    expect(text).toContain("KNOWN PRIOR REFUTE");
    expect(text).toContain(negative.reason);
    expect(text.toLowerCase()).toContain("not an auto-dismissal");
  });
});

describe("makeSkepticVerifier — learned-negatives wiring", () => {
  it("attaches negative context to the prompt for a matching finding when PWNKIT_HUNT_NEGATIVES=1, but still calls the finder and honors its outcome", async () => {
    const prev = process.env.PWNKIT_HUNT_NEGATIVES;
    process.env.PWNKIT_HUNT_NEGATIVES = "1";
    try {
      agenticScanMock.mockReset();
      let capturedHint = "";
      agenticScanMock.mockImplementation(async ({ challengeHint }: { challengeHint: string }) => {
        capturedHint = challengeHint;
        // The finder still runs and can still "confirm" (survive) despite the
        // negative context — nothing here auto-rejects.
        return { findings: [mkFinding("survivor", "still real", "")] };
      });

      const negative = mkNegative();
      const verify = makeSkepticVerifier({ sourceRoot: "/src", runtime: "api", negatives: [negative] });
      const matching = mkFinding(
        "f1",
        "mwifiex OOB read",
        "mwifiex_process_rx_packet reads out-of-bounds, CWE-125 out-of-bounds",
      );
      const result = await verify(matching, { path: negative.candidatePath });

      expect(capturedHint).toContain("KNOWN PRIOR REFUTE");
      expect(capturedHint).toContain(negative.reason);
      // The skeptic call still ran and still decided — here it "confirmed"
      // (survived), proving the negative note did not auto-reject anything.
      expect(result.confirmed).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_HUNT_NEGATIVES;
      else process.env.PWNKIT_HUNT_NEGATIVES = prev;
    }
  });

  it("does not attach negative context for a novel finding with no matching shape", async () => {
    const prev = process.env.PWNKIT_HUNT_NEGATIVES;
    process.env.PWNKIT_HUNT_NEGATIVES = "1";
    try {
      agenticScanMock.mockReset();
      let capturedHint = "";
      agenticScanMock.mockImplementation(async ({ challengeHint }: { challengeHint: string }) => {
        capturedHint = challengeHint;
        return { findings: [] };
      });

      const negative = mkNegative();
      const verify = makeSkepticVerifier({ sourceRoot: "/src", runtime: "api", negatives: [negative] });
      const novel = mkFinding("f2", "an unrelated nf_tables UAF", "nft_set_elem_deactivate use-after-free, CWE-416");
      await verify(novel, { path: "net/netfilter/nf_tables_api.c" });

      expect(capturedHint).not.toContain("KNOWN PRIOR REFUTE");
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_HUNT_NEGATIVES;
      else process.env.PWNKIT_HUNT_NEGATIVES = prev;
    }
  });

  it("gate OFF (default): no negative context attached even for a matching finding", async () => {
    const prev = process.env.PWNKIT_HUNT_NEGATIVES;
    delete process.env.PWNKIT_HUNT_NEGATIVES;
    try {
      agenticScanMock.mockReset();
      let capturedHint = "";
      agenticScanMock.mockImplementation(async ({ challengeHint }: { challengeHint: string }) => {
        capturedHint = challengeHint;
        return { findings: [] };
      });

      const negative = mkNegative();
      const verify = makeSkepticVerifier({ sourceRoot: "/src", runtime: "api", negatives: [negative] });
      const matching = mkFinding(
        "f1",
        "mwifiex OOB read",
        "mwifiex_process_rx_packet reads out-of-bounds, CWE-125 out-of-bounds",
      );
      await verify(matching, { path: negative.candidatePath });

      expect(capturedHint).not.toContain("KNOWN PRIOR REFUTE");
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_HUNT_NEGATIVES;
      else process.env.PWNKIT_HUNT_NEGATIVES = prev;
    }
  });
});
