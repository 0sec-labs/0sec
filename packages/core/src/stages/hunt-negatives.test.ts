/**
 * Learned negatives (hunt-negatives.ts). Coverage:
 *
 *   - `huntNegativesEnabled`: ON by default, OFF only for an explicit falsey env.
 *   - `loadKnownNegatives` / `loadKnownNegativesFromEnv`: the derived set is
 *     BOUNDED (MAX_KNOWN_NEGATIVES, freshest kept) and the feature is inert
 *     when no corpus is configured — the reason default-ON is safe.
 *   - `matchNegative`: a finding matching a known-refuted shape is matched
 *     (score >= NEGATIVE_MIN); a novel finding is not (returns `null`).
 *   - `negativeContext`: a label + explicit override instruction, not a
 *     command to drop the finding, with the quoted prior reason truncated.
 *   - `makeSkepticVerifier` wiring (hunt-scan.ts): attaches the negative
 *     context to the skeptic prompt for a matching finding (default ON, and
 *     with PWNKIT_HUNT_NEGATIVES=1); at most ONE negative is ever attached; a
 *     novel finding's prompt is unaffected; PWNKIT_HUNT_NEGATIVES=0 restores
 *     the old prompt exactly; the verifier NEVER auto-rejects on its own — it
 *     still calls the (mocked) finder and returns whatever that finder's
 *     outcome implies.
 */

import { rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { Finding } from "@pwnkit/shared";
import {
  huntNegativesEnabled,
  loadKnownNegatives,
  loadKnownNegativesFromEnv,
  matchNegative,
  negativeContext,
  MAX_KNOWN_NEGATIVES,
  MAX_NEGATIVE_REASON_CHARS,
  type KnownNegative,
} from "./hunt-negatives.js";

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
  it("is ON by default and OFF only for an explicit falsey PWNKIT_HUNT_NEGATIVES", () => {
    const prev = process.env.PWNKIT_HUNT_NEGATIVES;
    try {
      delete process.env.PWNKIT_HUNT_NEGATIVES;
      expect(huntNegativesEnabled()).toBe(true);
      process.env.PWNKIT_HUNT_NEGATIVES = "no";
      expect(huntNegativesEnabled()).toBe(false);
      process.env.PWNKIT_HUNT_NEGATIVES = "0";
      expect(huntNegativesEnabled()).toBe(false);
      process.env.PWNKIT_HUNT_NEGATIVES = "";
      expect(huntNegativesEnabled()).toBe(false);
      process.env.PWNKIT_HUNT_NEGATIVES = "1";
      expect(huntNegativesEnabled()).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_HUNT_NEGATIVES;
      else process.env.PWNKIT_HUNT_NEGATIVES = prev;
    }
  });
});

describe("loadKnownNegatives / loadKnownNegativesFromEnv — bounded and inert by default", () => {
  /** A corpus of `n` refuted rows, in the JSONL shape `loadHuntCorpusRows` reads. */
  function writeCorpus(n: number, opts: { reasonChars?: number } = {}): string {
    const path = join(tmpdir(), `pwnkit-negatives-test-${process.pid}-${Math.random().toString(36).slice(2)}.jsonl`);
    const lines: string[] = [];
    for (let i = 0; i < n; i++) {
      lines.push(
        JSON.stringify({
          candidatePath: `drivers/net/dev${i}.c`,
          bugClass: "oob",
          model: "default",
          attempt: 0,
          duplicate: false,
          skepticConfirmed: false,
          skepticReason: opts.reasonChars ? "x".repeat(opts.reasonChars) : `refuted ${i}`,
          finding: mkFinding(`f${i}`, `oob in dev${i}`, `dev${i}_rx reads out-of-bounds, CWE-125`),
        }),
      );
    }
    writeFileSync(path, lines.join("\n"), "utf8");
    return path;
  }

  it("caps the derived set at MAX_KNOWN_NEGATIVES, keeping the freshest (tail) rows", () => {
    const path = writeCorpus(MAX_KNOWN_NEGATIVES + 25);
    try {
      const negatives = loadKnownNegatives(path);
      expect(negatives).toHaveLength(MAX_KNOWN_NEGATIVES);
      // Tail-kept: the last corpus row must be present, the first must not.
      expect(negatives.at(-1)?.candidatePath).toBe(`drivers/net/dev${MAX_KNOWN_NEGATIVES + 24}.c`);
      expect(negatives.some((n) => n.candidatePath === "drivers/net/dev0.c")).toBe(false);
    } finally {
      rmSync(path, { force: true });
    }
  });

  it("is inert when HUNT_CORPUS_PATH is unset — default-ON with no corpus changes nothing", () => {
    const prev = process.env.HUNT_CORPUS_PATH;
    try {
      delete process.env.HUNT_CORPUS_PATH;
      expect(loadKnownNegativesFromEnv()).toEqual([]);
    } finally {
      if (prev === undefined) delete process.env.HUNT_CORPUS_PATH;
      else process.env.HUNT_CORPUS_PATH = prev;
    }
  });

  it("loads from HUNT_CORPUS_PATH when set, and tolerates a missing file", () => {
    const prev = process.env.HUNT_CORPUS_PATH;
    const path = writeCorpus(3);
    try {
      process.env.HUNT_CORPUS_PATH = path;
      expect(loadKnownNegativesFromEnv()).toHaveLength(3);
      process.env.HUNT_CORPUS_PATH = join(tmpdir(), "pwnkit-does-not-exist.jsonl");
      expect(loadKnownNegativesFromEnv()).toEqual([]);
    } finally {
      rmSync(path, { force: true });
      if (prev === undefined) delete process.env.HUNT_CORPUS_PATH;
      else process.env.HUNT_CORPUS_PATH = prev;
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

  it("truncates an unbounded prior reason so corpus text can never dominate the prompt", () => {
    const negative = { ...mkNegative(), reason: "y".repeat(MAX_NEGATIVE_REASON_CHARS * 4) };
    const text = negativeContext({ negative, score: 0.5 });
    expect(text).toContain("y".repeat(MAX_NEGATIVE_REASON_CHARS));
    expect(text).not.toContain("y".repeat(MAX_NEGATIVE_REASON_CHARS + 1));
    // Still a bounded label, not a wall of prior text.
    expect(text.length).toBeLessThan(MAX_NEGATIVE_REASON_CHARS + 700);
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

  it("gate ON BY DEFAULT (env unset): a matching finding still gets its prior refute as context", async () => {
    const prev = process.env.PWNKIT_HUNT_NEGATIVES;
    delete process.env.PWNKIT_HUNT_NEGATIVES;
    try {
      agenticScanMock.mockReset();
      let capturedHint = "";
      agenticScanMock.mockImplementation(async ({ challengeHint }: { challengeHint: string }) => {
        capturedHint = challengeHint;
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
      // Injected, bounded to ONE match, and still non-binding: the skeptic ran
      // and confirmed anyway.
      expect(capturedHint.match(/KNOWN PRIOR REFUTE/g)).toHaveLength(1);
      expect(result.confirmed).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_HUNT_NEGATIVES;
      else process.env.PWNKIT_HUNT_NEGATIVES = prev;
    }
  });

  it("attaches at most ONE negative — the best match — even when many shapes match", async () => {
    const prev = process.env.PWNKIT_HUNT_NEGATIVES;
    delete process.env.PWNKIT_HUNT_NEGATIVES;
    try {
      agenticScanMock.mockReset();
      let capturedHint = "";
      agenticScanMock.mockImplementation(async ({ challengeHint }: { challengeHint: string }) => {
        capturedHint = challengeHint;
        return { findings: [] };
      });

      const many: KnownNegative[] = Array.from({ length: 50 }, (_, i) => ({
        ...mkNegative(),
        key: `k${i}`,
        reason: `refuted variant ${i}`,
        provenance: `record:variant-${i}`,
      }));
      const verify = makeSkepticVerifier({ sourceRoot: "/src", runtime: "api", negatives: many });
      await verify(
        mkFinding("f1", "mwifiex OOB read", "mwifiex_process_rx_packet reads out-of-bounds, CWE-125 out-of-bounds"),
        { path: "drivers/net/wireless/marvell/mwifiex/txrx.c" },
      );

      expect(capturedHint.match(/KNOWN PRIOR REFUTE/g)).toHaveLength(1);
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_HUNT_NEGATIVES;
      else process.env.PWNKIT_HUNT_NEGATIVES = prev;
    }
  });

  it("gate explicitly OFF: no negative context attached even for a matching finding", async () => {
    const prev = process.env.PWNKIT_HUNT_NEGATIVES;
    process.env.PWNKIT_HUNT_NEGATIVES = "0";
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
