import { describe, expect, it } from "vitest";

import { scanForPatchGapCandidates } from "./patch-gap.js";
import type { GitExec } from "./patch-gap-check.js";
import type { UpstreamFixEntry } from "./patch-gap-feed.js";

/** A fake exec whose "target" behavior is entirely table-driven: SHAs in
 * `fixedShas` are ancestors (present); `upstreamRefs` mainline SHAs are found
 * via the cherry-pick-reference trailer; everything else is absent. */
function makeFakeExec(fixedShas: Set<string>, upstreamRefs: Set<string>): GitExec {
  return (_tree, args) => {
    if (args[0] === "rev-parse") return "true";
    if (args[0] === "merge-base") {
      const sha = args[args.length - 2];
      if (fixedShas.has(sha)) return "";
      throw new Error("not an ancestor");
    }
    if (args[0] === "log") {
      const grepArg = args.find((a) => a.startsWith("--grep="))!;
      const sha = grepArg.match(/commit ([0-9a-f]+) upstream\./)?.[1];
      if (sha && upstreamRefs.has(sha)) return "somesha\n";
      return "";
    }
    throw new Error(`unexpected git call: ${args.join(" ")}`);
  };
}

const ALREADY_FIXED_ENTRY: UpstreamFixEntry = {
  cve: "CVE-2026-00001",
  title: "net/unix: fix use-after-free",
  files: ["net/unix/af_unix.c"],
  candidateShas: ["1111111111111111111111111111111111111a"],
};

const REACHABLE_LIVE_ENTRY: UpstreamFixEntry = {
  cve: "CVE-2026-00002",
  title: "crypto: fix double-free in af_alg",
  files: ["crypto/algif_skcipher.c"],
  candidateShas: ["2222222222222222222222222222222222222b"],
};

const UNREACHABLE_LIVE_ENTRY: UpstreamFixEntry = {
  cve: "CVE-2026-00003",
  title: "bluetooth: fix overflow",
  files: ["net/bluetooth/hci_core.c"],
  candidateShas: ["3333333333333333333333333333333333333c"],
};

describe("kernel/patch-gap: scanForPatchGapCandidates", () => {
  it("skips an entry whose fix is already an ancestor of the target (already backported)", () => {
    const exec = makeFakeExec(new Set(["1111111111111111111111111111111111111a"]), new Set());
    const res = scanForPatchGapCandidates({
      targetTreePath: "/fake/target",
      entries: [ALREADY_FIXED_ENTRY],
      gitExec: exec,
    });
    expect(res.candidates).toHaveLength(0);
    expect(res.skippedAlreadyFixed).toBe(1);
    expect(res.total).toBe(1);
  });

  it("surfaces an absent + kernelCTF-reachable fix as a ranked candidate", () => {
    const exec = makeFakeExec(new Set(), new Set());
    const res = scanForPatchGapCandidates({
      targetTreePath: "/fake/target",
      entries: [REACHABLE_LIVE_ENTRY],
      gitExec: exec,
    });
    expect(res.candidates).toHaveLength(1);
    const c = res.candidates[0]!;
    expect(c.cve).toBe("CVE-2026-00002");
    expect(c.reachable).toBe("reachable"); // crypto/ is REACHABLE_PATH_PREFIXES
    expect(c.fixSha).toBe("2222222222222222222222222222222222222b");
    expect(c.severity).toBe("high"); // "double-free" keyword
    expect(c.presence.present).toBe(false);
  });

  it("drops an absent-but-unreachable-on-kernelCTF fix by default (reachableOnly)", () => {
    const exec = makeFakeExec(new Set(), new Set());
    const res = scanForPatchGapCandidates({
      targetTreePath: "/fake/target",
      entries: [UNREACHABLE_LIVE_ENTRY],
      gitExec: exec,
    });
    expect(res.candidates).toHaveLength(0);
    expect(res.skippedUnreachable).toBe(1);
  });

  it("keeps the unreachable entry (annotated) when reachableOnly is false", () => {
    const exec = makeFakeExec(new Set(), new Set());
    const res = scanForPatchGapCandidates({
      targetTreePath: "/fake/target",
      entries: [UNREACHABLE_LIVE_ENTRY],
      gitExec: exec,
      reachableOnly: false,
    });
    expect(res.candidates).toHaveLength(1);
    expect(res.candidates[0]!.reachable).toBe("unreachable");
    expect(res.skippedUnreachable).toBe(0);
  });

  it("matches the cherry-pick-reference path (new SHA in target, same mainline fix)", () => {
    const entry: UpstreamFixEntry = {
      ...REACHABLE_LIVE_ENTRY,
      mainlineSha: "4444444444444444444444444444444444444d",
    };
    const exec = makeFakeExec(new Set(), new Set(["4444444444444444444444444444444444444d"]));
    const res = scanForPatchGapCandidates({
      targetTreePath: "/fake/target",
      entries: [entry],
      gitExec: exec,
    });
    expect(res.candidates).toHaveLength(0);
    expect(res.skippedAlreadyFixed).toBe(1);
  });

  it("ranks reachable-and-high-severity above unknown/low-signal, mixed batch", () => {
    const lowSignalReachable: UpstreamFixEntry = {
      cve: "CVE-2026-00004",
      title: "net/unix: minor cleanup", // no high-signal keyword
      files: ["net/unix/af_unix.c"],
      candidateShas: ["5555555555555555555555555555555555555e"],
    };
    const exec = makeFakeExec(new Set(), new Set());
    const res = scanForPatchGapCandidates({
      targetTreePath: "/fake/target",
      entries: [lowSignalReachable, REACHABLE_LIVE_ENTRY],
      gitExec: exec,
    });
    expect(res.candidates).toHaveLength(2);
    // REACHABLE_LIVE_ENTRY (severity "high") ranks before the low-signal one.
    expect(res.candidates[0]!.cve).toBe("CVE-2026-00002");
    expect(res.candidates[1]!.cve).toBe("CVE-2026-00004");
  });
});
