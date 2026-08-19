/**
 * Surface-desirability scoring for the generic fresh-surface hunt. Tests the
 * PURE policy (prefix classification, score math, ranking order, default-off
 * passthrough) — the I/O signals (grep/git) are exercised via injected
 * SurfaceSignals so no kernel tree is required.
 */
import { describe, expect, it } from "vitest";
import {
  applySurfaceRanking,
  computeSurfaceScore,
  isHardToFuzzSurface,
  W_HARD_TO_FUZZ,
  W_PARSER_DENSE,
  W_PARSER_SOME,
  W_STALE_OLD,
  W_STALE_MID,
  SWEEP_PENALTY_FLOOR,
  type SurfaceSignals,
} from "./surface-desirability.js";

const NONE: SurfaceSignals = { hardToFuzz: false, parserIdiomLines: 0, lastTouchDays: null, recentSecurityCommits: 0 };

describe("isHardToFuzzSurface", () => {
  it("flags stateful/protocol parser subsystems", () => {
    expect(isHardToFuzzSurface("net/nfc/nci/ntf.c")).toBe(true);
    expect(isHardToFuzzSurface("net/mac802154/llsec.c")).toBe(true);
    expect(isHardToFuzzSurface("net/netfilter/nf_conntrack_h323_asn1.c")).toBe(true);
    expect(isHardToFuzzSurface("drivers/net/wireless/marvell/mwifiex/scan.c")).toBe(true);
    expect(isHardToFuzzSurface("fs/smb/server/smbacl.c")).toBe(true);
  });
  it("does not flag generic core paths (no bonus, not a penalty)", () => {
    expect(isHardToFuzzSurface("mm/memory.c")).toBe(false);
    expect(isHardToFuzzSurface("kernel/sched/core.c")).toBe(false);
    expect(isHardToFuzzSurface("fs/ext4/inode.c")).toBe(false);
  });
  it("handles absolute paths and requires a path-segment boundary", () => {
    expect(isHardToFuzzSurface("/root/linux-next/net/nfc/llcp_core.c")).toBe(true);
    expect(isHardToFuzzSurface("notnet/nfc/x.c")).toBe(false); // substring, not a segment
  });
});

describe("computeSurfaceScore", () => {
  it("is zero for a path with no signals", () => {
    expect(computeSurfaceScore(NONE)).toBe(0);
  });
  it("adds the hard-to-fuzz bonus", () => {
    expect(computeSurfaceScore({ ...NONE, hardToFuzz: true })).toBe(W_HARD_TO_FUZZ);
  });
  it("buckets parser-idiom density (dense > some > none), not linearly", () => {
    expect(computeSurfaceScore({ ...NONE, parserIdiomLines: 40 })).toBe(W_PARSER_DENSE);
    expect(computeSurfaceScore({ ...NONE, parserIdiomLines: 8 })).toBe(W_PARSER_SOME);
    expect(computeSurfaceScore({ ...NONE, parserIdiomLines: 2 })).toBe(0);
  });
  it("rewards staleness in two tiers", () => {
    expect(computeSurfaceScore({ ...NONE, lastTouchDays: 500 })).toBe(W_STALE_OLD);
    expect(computeSurfaceScore({ ...NONE, lastTouchDays: 200 })).toBe(W_STALE_MID);
    expect(computeSurfaceScore({ ...NONE, lastTouchDays: 30 })).toBe(0);
  });
  it("penalizes recent security sweeps, floored so one hot file can't dominate", () => {
    expect(computeSurfaceScore({ ...NONE, recentSecurityCommits: 1 })).toBe(-2);
    expect(computeSurfaceScore({ ...NONE, recentSecurityCommits: 2 })).toBe(-4);
    expect(computeSurfaceScore({ ...NONE, recentSecurityCommits: 99 })).toBe(SWEEP_PENALTY_FLOOR);
  });
  it("combines signals additively — the target profile scores high", () => {
    // hard-to-fuzz + dense parser idioms + very stale + never swept.
    const ideal: SurfaceSignals = { hardToFuzz: true, parserIdiomLines: 50, lastTouchDays: 900, recentSecurityCommits: 0 };
    expect(computeSurfaceScore(ideal)).toBe(W_HARD_TO_FUZZ + W_PARSER_DENSE + W_STALE_OLD);
    // a freshly-swept generic file nets negative — deprioritized below the ideal.
    const swept: SurfaceSignals = { hardToFuzz: false, parserIdiomLines: 0, lastTouchDays: 5, recentSecurityCommits: 3 };
    expect(computeSurfaceScore(swept)).toBe(-6);
    expect(computeSurfaceScore(ideal)).toBeGreaterThan(computeSurfaceScore(swept));
  });
});

describe("applySurfaceRanking", () => {
  const paths = ["mm/memory.c", "net/nfc/nci/ntf.c", "kernel/sched/core.c"];

  it("is a no-op passthrough when not enabled (default-off backward compat)", () => {
    const r = applySurfaceRanking(paths, {});
    expect(r.paths).toEqual(paths);
    expect(r.scores).toEqual([]);
  });
  it("is a no-op when explicitly disabled", () => {
    expect(applySurfaceRanking(paths, { enabled: false }).paths).toEqual(paths);
  });
  it("path-only mode floats hard-to-fuzz surfaces to the top", () => {
    // pathOnly => no grep/git; only the hard-to-fuzz prefix contributes.
    const r = applySurfaceRanking(paths, { enabled: true, pathOnly: true });
    expect(r.paths[0]).toBe("net/nfc/nci/ntf.c");
    expect(r.scores[0].score).toBe(W_HARD_TO_FUZZ);
  });
  it("is a stable sort — equal-score candidates keep incoming (size) order", () => {
    // two non-hard-to-fuzz files score equal (0); their relative order is preserved.
    const r = applySurfaceRanking(["mm/a.c", "mm/b.c", "net/nfc/x.c"], { enabled: true, pathOnly: true });
    expect(r.paths).toEqual(["net/nfc/x.c", "mm/a.c", "mm/b.c"]);
  });
});
