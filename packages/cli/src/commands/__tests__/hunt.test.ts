import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const {
  generateVariantCandidatesMock,
  runHuntScanMock,
  makeSkepticVerifierMock,
  localMirrorsMock,
  syncLoreMirrorMock,
  makeLloreJudgeMock,
  detectTargetTypeMock,
  prepareMock,
  noveltyJudge,
} = vi.hoisted(() => {
  const skepticVerifier = vi.fn();
  const noveltyJudge = vi.fn();
  return {
    generateVariantCandidatesMock: vi.fn(),
    runHuntScanMock: vi.fn(),
    makeSkepticVerifierMock: vi.fn(() => skepticVerifier),
    localMirrorsMock: vi.fn(),
    syncLoreMirrorMock: vi.fn(),
    makeLloreJudgeMock: vi.fn(() => noveltyJudge),
    detectTargetTypeMock: vi.fn(),
    prepareMock: vi.fn(),
    skepticVerifier,
    noveltyJudge,
  };
});

vi.mock("@pwnkit/core", () => ({
  generateVariantCandidates: generateVariantCandidatesMock,
  runHuntScan: runHuntScanMock,
  makeSkepticVerifier: makeSkepticVerifierMock,
  localMirrors: localMirrorsMock,
  syncLoreMirror: syncLoreMirrorMock,
  makeLloreJudge: makeLloreJudgeMock,
  detectTargetType: detectTargetTypeMock,
  prepare: prepareMock,
}));

const { runHunt } = await import("../hunt.js");

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
    detectTargetTypeMock.mockReset().mockReturnValue("source-code");
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

  it("treats a non-file seed as a commit ref", async () => {
    await runHunt({
      sourceRoot: tmpRoot,
      seedPath: "abc1234def",
      verify: false,
    });

    expect(generateVariantCandidatesMock).toHaveBeenCalledWith(expect.objectContaining({
      sourceRoot: tmpRoot,
      fix: { commit: "abc1234def", reference: "abc1234def" },
    }));
  });

  it("passes an inline diff seed through as fix.diff", async () => {
    const diff = "diff --git a/foo.c b/foo.c\n@@\n-  bad();\n+  good();\n";

    await runHunt({
      sourceRoot: tmpRoot,
      seedPath: diff,
      verify: false,
    });

    expect(generateVariantCandidatesMock).toHaveBeenCalledWith(expect.objectContaining({
      sourceRoot: tmpRoot,
      fix: { diff, reference: "inline-diff" },
    }));
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
});
