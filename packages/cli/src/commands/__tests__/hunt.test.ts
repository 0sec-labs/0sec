import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@pwnkit/shared";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const {
  generateVariantCandidatesMock,
  runHuntScanMock,
  makeSkepticVerifierMock,
  buildInvariantHuntContextMock,
  localMirrorsMock,
  syncLoreMirrorMock,
  makeLloreJudgeMock,
  prepareMock,
  getCloudSinkConfigMock,
  postFindingMock,
  noveltyJudge,
} = vi.hoisted(() => {
  const skepticVerifier = vi.fn();
  const noveltyJudge = vi.fn();
  return {
    generateVariantCandidatesMock: vi.fn(),
    runHuntScanMock: vi.fn(),
    makeSkepticVerifierMock: vi.fn(() => skepticVerifier),
    buildInvariantHuntContextMock: vi.fn(),
    localMirrorsMock: vi.fn(),
    syncLoreMirrorMock: vi.fn(),
    makeLloreJudgeMock: vi.fn(() => noveltyJudge),
    prepareMock: vi.fn(),
    getCloudSinkConfigMock: vi.fn(),
    postFindingMock: vi.fn(),
    skepticVerifier,
    noveltyJudge,
  };
});

vi.mock("@pwnkit/core", () => ({
  generateVariantCandidates: generateVariantCandidatesMock,
  runHuntScan: runHuntScanMock,
  makeSkepticVerifier: makeSkepticVerifierMock,
  buildInvariantHuntContext: buildInvariantHuntContextMock,
  localMirrors: localMirrorsMock,
  syncLoreMirror: syncLoreMirrorMock,
  makeLloreJudge: makeLloreJudgeMock,
  prepare: prepareMock,
  getCloudSinkConfig: getCloudSinkConfigMock,
  postFinding: postFindingMock,
}));

const { leadToCandidateFinding, runHunt } = await import("../hunt.js");

function makeLead(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "lead-1",
    templateId: "variant-hunt",
    title: "Possible UAF in foo_release()",
    description: "The release path frees obj without clearing the dangling ref.",
    severity: "high",
    category: "memory-safety" as Finding["category"],
    status: "confirmed", // finder/skeptic-confirmed — must be downgraded
    evidence: {
      request: "n/a",
      response: "drivers/foo/foo.c:120",
      analysis: "skeptic survived the refute pass",
    },
    ...overrides,
  } as Finding;
}

describe("leadToCandidateFinding (#1051)", () => {
  it("forces status to 'discovered' — never confirmed/sendable", () => {
    const out = leadToCandidateFinding(makeLead(), "use-after-free", "abc123 fix");
    expect(out.status).toBe("discovered");
  });

  it("preserves the finder's honest severity (no inflation/deflation)", () => {
    expect(leadToCandidateFinding(makeLead({ severity: "high" }), "uaf", "ref").severity).toBe("high");
    expect(leadToCandidateFinding(makeLead({ severity: "medium" }), "uaf", "ref").severity).toBe("medium");
  });

  it("stamps lead provenance (bug class + seed) into evidence.analysis", () => {
    const out = leadToCandidateFinding(makeLead(), "use-after-free", "abc123 fix the UAF");
    const evidence = out.evidence as { analysis: string };
    expect(evidence.analysis).toContain("use-after-free");
    expect(evidence.analysis).toContain("abc123 fix the UAF");
    expect(evidence.analysis).toMatch(/LEAD|HYPOTHESIS/);
    expect(evidence.analysis).toContain("skeptic survived the refute pass");
  });

  it("marks the candidate with the recency-hunt template id and keeps title/description", () => {
    const out = leadToCandidateFinding(makeLead(), "uaf", "ref");
    expect(out.templateId).toBe("recency-hunt-lead");
    expect(out.title).toBe("Possible UAF in foo_release()");
    expect(out.description).toContain("dangling ref");
  });

  it("never carries a 'confirmed' status through even when the lead has no analysis", () => {
    const lead = makeLead({ evidence: { request: "", response: "" } });
    const out = leadToCandidateFinding(lead, "uaf", "ref");
    expect(out.status).toBe("discovered");
    const evidence = out.evidence as { analysis: string };
    expect(evidence.analysis).toMatch(/LEAD|HYPOTHESIS/);
  });
});

describe("runHunt — novelty gate wiring", () => {
  let tmpRoot: string;
  let seedPath: string;

  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), "pwnkit-hunt-test-"));
    seedPath = join(tmpRoot, "seed.patch");
    writeFileSync(seedPath, "diff --git a/foo.c b/foo.c\n", "utf8");

    generateVariantCandidatesMock.mockReset().mockResolvedValue({
      brief: {
        bugClass: "missing bounds check",
        pattern: "index before array access",
      },
      grepPatterns: ["foo"],
      candidates: [{ path: "drivers/media/foo.c" }],
      warnings: [],
    });
    runHuntScanMock.mockReset().mockResolvedValue({
      findings: [],
      confirmed: [],
      duplicates: [],
      scanned: 1,
      warnings: [],
    });
    makeSkepticVerifierMock.mockClear();
    prepareMock.mockReset().mockImplementation(async (target: string) => ({
      targetType: "source-code",
      resolvedTarget: target,
      repoPath: target,
      cleanup: vi.fn(),
    }));
    localMirrorsMock.mockReset().mockReturnValue([
      { list: "linux-media", epoch: 1, dir: "/root/lore-mirror/linux-media__1" },
    ]);
    syncLoreMirrorMock.mockReset().mockResolvedValue([
      { list: "linux-media", epoch: 2, dir: "/root/lore-mirror/linux-media__2" },
    ]);
    makeLloreJudgeMock.mockClear();
    buildInvariantHuntContextMock.mockReset().mockResolvedValue(null);
    getCloudSinkConfigMock.mockReset().mockReturnValue(null);
    postFindingMock.mockReset().mockResolvedValue(undefined);
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it("passes local lore mirrors into runHuntScan when novelty is enabled", async () => {
    const outcome = await runHunt({
      sourceRoot: tmpRoot,
      seedPath,
      novelty: {
        rootDir: "/root/lore-mirror",
        lists: ["linux-media"],
      },
    });

    expect(outcome.exitCode).toBe(1);
    expect(localMirrorsMock).toHaveBeenCalledWith("/root/lore-mirror", ["linux-media"]);
    expect(syncLoreMirrorMock).not.toHaveBeenCalled();
    expect(runHuntScanMock).toHaveBeenCalledOnce();
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.novelty).toMatchObject({
      mirrors: [{ list: "linux-media", epoch: 1, dir: "/root/lore-mirror/linux-media__1" }],
    });
    expect(outcome.result).toMatchObject({
      novelty: {
        enabled: true,
        mirrors: [{ list: "linux-media", epoch: 1, dir: "/root/lore-mirror/linux-media__1" }],
      },
    });
  });

  it("syncs lore mirrors first when novelty.sync is enabled", async () => {
    await runHunt({
      sourceRoot: tmpRoot,
      seedPath,
      novelty: {
        rootDir: "/root/lore-mirror",
        lists: ["linux-media", "netdev"],
        recentEpochs: 2,
        sync: true,
        model: "gpt-5.5-codex",
      },
    });

    expect(syncLoreMirrorMock).toHaveBeenCalledWith({
      rootDir: "/root/lore-mirror",
      lists: ["linux-media", "netdev"],
      recentEpochs: 2,
      log: expect.any(Function),
    });
    expect(localMirrorsMock).not.toHaveBeenCalled();
    expect(makeLloreJudgeMock).toHaveBeenCalledWith({ model: "gpt-5.5-codex" });
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.novelty).toMatchObject({
      mirrors: [{ list: "linux-media", epoch: 2, dir: "/root/lore-mirror/linux-media__2" }],
      judge: noveltyJudge,
    });
  });

  it("continues fail-open when novelty is requested but no mirrors exist", async () => {
    localMirrorsMock.mockReturnValue([]);

    await runHunt({
      sourceRoot: tmpRoot,
      seedPath,
      novelty: {
        rootDir: "/missing",
        lists: ["linux-media"],
      },
    });

    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.novelty).toBeUndefined();
  });

  it("fails closed before discovery when novelty evidence is required but unavailable", async () => {
    localMirrorsMock.mockReturnValue([]);

    const outcome = await runHunt({
      sourceRoot: tmpRoot,
      seedPath,
      novelty: { rootDir: "/missing/lore", lists: ["linux-kernel"], required: true },
    });

    expect(outcome.exitCode).toBe(3);
    expect(generateVariantCandidatesMock).not.toHaveBeenCalled();
    expect(runHuntScanMock).not.toHaveBeenCalled();
    expect(outcome.result).toMatchObject({
      novelty: { enabled: true, required: true, mirrors: [] },
      note: expect.stringContaining("did not run"),
    });
  });

  it("applies the kernel-LPE methodology preset to candidate selection and finder review", async () => {
    await runHunt({ sourceRoot: tmpRoot, seedPath, methodology: true });

    expect(generateVariantCandidatesMock).toHaveBeenCalledWith(expect.objectContaining({ reachablePrefer: true }));
    expect(runHuntScanMock).toHaveBeenCalledWith(expect.objectContaining({
      attemptsPerCandidate: 4,
      judgeTopK: 2,
      brief: expect.objectContaining({
        pattern: expect.stringMatching(/object lifecycle.*buffer\/page provenance/is),
      }),
    }));
  });

  it("continues fail-open when novelty sync fails", async () => {
    syncLoreMirrorMock.mockRejectedValueOnce(new Error("network down"));

    const outcome = await runHunt({
      sourceRoot: tmpRoot,
      seedPath,
      novelty: {
        rootDir: "/root/lore-mirror",
        lists: ["linux-media"],
        sync: true,
      },
    });

    expect(outcome.exitCode).toBe(1);
    expect(runHuntScanMock).toHaveBeenCalledOnce();
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.novelty).toBeUndefined();
    expect(outcome.result).toMatchObject({
      warnings: [expect.stringContaining("novelty sync failed")],
    });
  });

  it("passes the staged seed file contents through as fix.diff", async () => {
    await runHunt({
      sourceRoot: tmpRoot,
      seedPath,
      verify: false,
    });

    expect(generateVariantCandidatesMock).toHaveBeenCalledWith(expect.objectContaining({
      sourceRoot: tmpRoot,
      fix: { diff: "diff --git a/foo.c b/foo.c\n", reference: seedPath },
    }));
  });

  it("skips the requested number of ranked candidate sites before scanning", async () => {
    generateVariantCandidatesMock.mockResolvedValueOnce({
      brief: {
        bugClass: "missing bounds check",
        pattern: "index before array access",
      },
      grepPatterns: ["foo"],
      candidates: [
        { path: "drivers/media/first.c" },
        { path: "drivers/media/second.c" },
        { path: "drivers/media/third.c" },
      ],
      warnings: [],
    });

    const outcome = await runHunt({
      sourceRoot: tmpRoot,
      seedPath,
      maxCandidates: 2,
      skipCandidates: 1,
      verify: false,
    });

    expect(generateVariantCandidatesMock).toHaveBeenCalledWith(expect.objectContaining({
      maxCandidates: 3,
    }));
    expect(runHuntScanMock).toHaveBeenCalledWith(expect.objectContaining({
      candidates: [
        expect.objectContaining({ path: `${tmpRoot}/drivers/media/second.c` }),
        expect.objectContaining({ path: `${tmpRoot}/drivers/media/third.c` }),
      ],
    }));
    expect(outcome.result).toMatchObject({
      candidate_sites: ["drivers/media/second.c", "drivers/media/third.c"],
      skipped_candidates: 1,
    });
  });

  it("resolves git/local sources through prepare and cleans them up", async () => {
    const cleanup = vi.fn();
    prepareMock.mockResolvedValueOnce({
      targetType: "source-code",
      resolvedTarget: "/tmp/pwnkit-review/repo",
      repoPath: "/tmp/pwnkit-review/repo",
      cleanup,
    });

    await runHunt({
      sourceRoot: "https://github.com/torvalds/linux.git",
      seedPath,
      verify: false,
    });

    expect(prepareMock).toHaveBeenCalledWith(
      "https://github.com/torvalds/linux.git",
      "source-code",
      {},
      expect.any(Function),
    );
    expect(generateVariantCandidatesMock).toHaveBeenCalledWith(expect.objectContaining({
      sourceRoot: "/tmp/pwnkit-review/repo",
    }));
    expect(cleanup).toHaveBeenCalledOnce();
  });

  it("injects the invariant prompt block into the finder brief when --invariant is set", async () => {
    buildInvariantHuntContextMock.mockResolvedValueOnce({
      subsystem: "net/unix",
      subsystemFiles: ["net/unix/af_unix.c"],
      modelPath: `${tmpRoot}/.pwnkit/invariant-models/net__unix.json`,
      modelLoaded: true,
      model: { objects: [{ object: "struct unix_sock" }] },
      violations: [{ kind: "unlocked-field-access" }],
      promptBlock: "INVARIANT MODEL of net/unix (1 key object(s))",
    });

    const outcome = await runHunt({ sourceRoot: tmpRoot, seedPath, invariant: true, verify: false });

    expect(buildInvariantHuntContextMock).toHaveBeenCalledWith(expect.objectContaining({
      sourceRoot: tmpRoot,
      seedDiff: "diff --git a/foo.c b/foo.c\n",
    }));
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.brief.pattern).toContain("index before array access");
    expect(opts.brief.pattern).toContain("INVARIANT MODEL of net/unix");
    expect(outcome.result).toMatchObject({
      invariant: { enabled: true, subsystem: "net/unix", model_loaded: true, objects: 1, violations: 1 },
    });
  });

  it("leaves the brief untouched when --invariant yields no context (fail-open)", async () => {
    buildInvariantHuntContextMock.mockResolvedValueOnce(null);

    const outcome = await runHunt({ sourceRoot: tmpRoot, seedPath, invariant: true, verify: false });

    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.brief.pattern).toBe("index before array access");
    expect(outcome.result).toMatchObject({
      invariant: { enabled: false },
      warnings: [expect.stringContaining("no subsystem scope")],
    });
  });

  it("continues the plain hunt when the invariant stage throws (fail-open)", async () => {
    buildInvariantHuntContextMock.mockRejectedValueOnce(new Error("model build exploded"));

    const outcome = await runHunt({ sourceRoot: tmpRoot, seedPath, invariant: true, verify: false });

    expect(outcome.exitCode).toBe(1);
    expect(runHuntScanMock).toHaveBeenCalledOnce();
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.brief.pattern).toBe("index before array access");
    expect(outcome.result).toMatchObject({
      invariant: { enabled: false },
      warnings: [expect.stringContaining("model build exploded")],
    });
  });
});
