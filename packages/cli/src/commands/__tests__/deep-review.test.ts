import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@pwnkit/shared";
import type { FinderLens, VerifyLens } from "@pwnkit/core";

// ── Pure helpers (no @pwnkit/core load needed) ───────────────────────────────
import {
  selectProfileLenses,
  enumerateDeepReviewCandidates,
  isNonProtocolEvmPath,
  defaultFinderLenses,
  defaultVerifyLenses,
  type ProfileLensSets,
  type DeepReviewEnumHelpers,
} from "../deep-review.js";

function tagged(id: string): FinderLens[] {
  return [{ id, challengeHint: `hint-${id}` }];
}
const SETS: ProfileLensSets = {
  evmFinderLenses: tagged("evm-f"),
  evmVerifyLenses: tagged("evm-v") as VerifyLens[],
  solanaFinderLenses: tagged("sol-f"),
  solanaVerifyLenses: tagged("sol-v") as VerifyLens[],
  cardanoFinderLenses: tagged("car-f"),
  cardanoVerifyLenses: tagged("car-v") as VerifyLens[],
  cairoFinderLenses: tagged("cairo-f"),
  cairoVerifyLenses: tagged("cairo-v") as VerifyLens[],
  moveFinderLenses: tagged("move-f"),
  moveVerifyLenses: tagged("move-v") as VerifyLens[],
};

describe("selectProfileLenses", () => {
  it("picks the EVM lens set for evm-onchain", () => {
    const r = selectProfileLenses("evm-onchain", SETS);
    expect(r.matchedProfile).toBe("evm-onchain");
    expect(r.finderLenses).toBe(SETS.evmFinderLenses);
    expect(r.verifyLenses).toBe(SETS.evmVerifyLenses);
  });

  it("picks the Solana lens set for solana-onchain", () => {
    const r = selectProfileLenses("solana-onchain", SETS);
    expect(r.matchedProfile).toBe("solana-onchain");
    expect(r.finderLenses).toBe(SETS.solanaFinderLenses);
    expect(r.verifyLenses).toBe(SETS.solanaVerifyLenses);
  });

  it("picks the Cardano lens set for cardano-onchain", () => {
    const r = selectProfileLenses("cardano-onchain", SETS);
    expect(r.matchedProfile).toBe("cardano-onchain");
    expect(r.finderLenses).toBe(SETS.cardanoFinderLenses);
  });

  it("picks the Cairo lens set for cairo-onchain", () => {
    const r = selectProfileLenses("cairo-onchain", SETS);
    expect(r.matchedProfile).toBe("cairo-onchain");
    expect(r.finderLenses).toBe(SETS.cairoFinderLenses);
    expect(r.verifyLenses).toBe(SETS.cairoVerifyLenses);
  });

  it("picks the Move lens set for move-onchain", () => {
    const r = selectProfileLenses("move-onchain", SETS);
    expect(r.matchedProfile).toBe("move-onchain");
    expect(r.finderLenses).toBe(SETS.moveFinderLenses);
    expect(r.verifyLenses).toBe(SETS.moveVerifyLenses);
  });

  it("is case/whitespace-insensitive", () => {
    expect(selectProfileLenses("  EVM-Onchain ", SETS).matchedProfile).toBe("evm-onchain");
  });

  it.each(["default", "linux-kernel", "c-library", "cardano-haskell", "totally-unknown", undefined])(
    "falls back to the generic default lens set for %s",
    (profile) => {
      const r = selectProfileLenses(profile as string | undefined, SETS);
      expect(r.matchedProfile).toBe("default");
      expect(r.finderLenses).toBe(defaultFinderLenses);
      expect(r.verifyLenses).toBe(defaultVerifyLenses);
    },
  );

  it("ships a non-empty default verify set (makeMultiLensVerifier requires ≥1)", () => {
    expect(defaultVerifyLenses.length).toBeGreaterThan(0);
    expect(defaultFinderLenses.length).toBeGreaterThan(0);
  });

  it("default finder set unions the 4 generic lenses with the 5 data-driven appsec lenses", () => {
    const ids = defaultFinderLenses.map((l) => l.id);
    // The generic buckets are preserved …
    expect(ids).toEqual(expect.arrayContaining(["memory-safety", "input-validation", "auth-logic", "secrets-crypto"]));
    // … and every appsec lens is added on top (the Swiss-miss coverage classes).
    for (const id of APPSEC_LENS_IDS) expect(ids).toContain(id);
    expect(defaultFinderLenses).toHaveLength(4 + APPSEC_LENS_IDS.length);
    // No id collisions — each lens is its own best-of-N group.
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("REGRESSION: no on-chain profile's finder set carries an appsec lens", () => {
    for (const set of [
      SETS.evmFinderLenses,
      SETS.solanaFinderLenses,
      SETS.cardanoFinderLenses,
      SETS.cairoFinderLenses,
      SETS.moveFinderLenses,
    ]) {
      const ids = set.map((l) => l.id);
      for (const appsecId of APPSEC_LENS_IDS) expect(ids).not.toContain(appsecId);
    }
    // And the on-chain branches return their bespoke set by reference, untouched.
    expect(selectProfileLenses("evm-onchain", SETS).finderLenses).toBe(SETS.evmFinderLenses);
    expect(selectProfileLenses("solana-onchain", SETS).finderLenses).toBe(SETS.solanaFinderLenses);
  });
});

describe("enumerateDeepReviewCandidates", () => {
  const sizes: Record<string, number> = {
    "/repo/big.ts": 9000,
    "/repo/mid.ts": 5000,
    "/repo/small.ts": 100,
    "/repo/tiny.ts": 10,
  };
  const helpers: DeepReviewEnumHelpers = {
    collectScopeFiles: () => Object.keys(sizes),
    countScopeFilesUpTo: () => Object.keys(sizes).length,
    fileSize: (p) => sizes[p] ?? 0,
  };

  it("ranks candidates largest-first and caps to maxCandidates", () => {
    const r = enumerateDeepReviewCandidates("/repo", helpers, { maxCandidates: 2 });
    expect(r.candidates).toEqual(["/repo/big.ts", "/repo/mid.ts"]);
    expect(r.overCap).toBe(false);
    expect(r.totalFiles).toBe(4);
  });

  it("returns all files (sorted) when maxCandidates exceeds the count", () => {
    const r = enumerateDeepReviewCandidates("/repo", helpers, { maxCandidates: 99 });
    expect(r.candidates).toEqual(["/repo/big.ts", "/repo/mid.ts", "/repo/small.ts", "/repo/tiny.ts"]);
  });

  it("flags overCap when the scope exceeds the file cap", () => {
    const over: DeepReviewEnumHelpers = {
      collectScopeFiles: () => ["/repo/a.ts"],
      countScopeFilesUpTo: (_d, limit) => limit + 1,
      fileSize: () => 1,
    };
    const r = enumerateDeepReviewCandidates("/repo", over, { maxCandidates: 40, fileCap: 5000 });
    expect(r.overCap).toBe(true);
    expect(r.totalFiles).toBe(5001);
  });

  it("breaks size ties deterministically by path", () => {
    const flat: DeepReviewEnumHelpers = {
      collectScopeFiles: () => ["/repo/z.ts", "/repo/a.ts", "/repo/m.ts"],
      countScopeFilesUpTo: () => 3,
      fileSize: () => 100,
    };
    const r = enumerateDeepReviewCandidates("/repo", flat, { maxCandidates: 3 });
    expect(r.candidates).toEqual(["/repo/a.ts", "/repo/m.ts", "/repo/z.ts"]);
  });

  it("applies an `exclude` predicate BEFORE the largest-first cap", () => {
    // The two largest files are vendored/test; without the filter they'd win the
    // cap and starve the real src file. With it, the src file is selected.
    const sizes: Record<string, number> = {
      "/repo/lib/forge-std/src/Vm.sol": 90000,
      "/repo/test/Vault.t.sol": 80000,
      "/repo/src/Vault.sol": 1000,
    };
    const h: DeepReviewEnumHelpers = {
      collectScopeFiles: () => Object.keys(sizes),
      countScopeFilesUpTo: () => Object.keys(sizes).length,
      fileSize: (p) => sizes[p] ?? 0,
    };
    const r = enumerateDeepReviewCandidates("/repo", h, {
      maxCandidates: 1,
      exclude: (p) => isNonProtocolEvmPath(p, "/repo"),
    });
    expect(r.candidates).toEqual(["/repo/src/Vault.sol"]);
  });
});

describe("isNonProtocolEvmPath — evm candidate scoping (test/vendored exclusion)", () => {
  const root = "/repo";
  it.each([
    "/repo/lib/forge-std/src/Vm.sol",
    "/repo/lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol",
    "/repo/lib/openzeppelin-contracts-upgradeable/lib/forge-std/src/console2.sol", // nested vendored lib
    "/repo/test/unit/CapyfiAggregatorV3Test.t.sol",
    "/repo/src/Vault.t.sol",              // Foundry test filename anywhere
    "/repo/test/contracts/WalletsManager.t.sol",
    "/repo/script/Deploy.s.sol",
    "/repo/scripts/deploy.ts",
    "/repo/src/mocks/MockOracle.sol",
    "/repo/node_modules/@oz/ERC20.sol",
    "/repo/src/Vault.test.ts",
    "/repo/src/Vault.spec.js",
  ])("excludes non-protocol path %s", (p) => {
    expect(isNonProtocolEvmPath(p, root)).toBe(true);
  });

  it.each([
    "/repo/src/contracts/Comptroller.sol",
    "/repo/src/Vault.sol",
    "/repo/contracts/Token.sol",
    "/repo/Vault.sol",                    // root-level protocol source
    "/repo/src/libraries/SafeMath.sol",   // own `libraries` dir is NOT vendored `lib`
    "/repo/src/interfaces/IVault.sol",
  ])("keeps protocol source %s", (p) => {
    expect(isNonProtocolEvmPath(p, root)).toBe(false);
  });

  it("does not exclude a path that escapes the scope root", () => {
    expect(isNonProtocolEvmPath("/other/lib/x.sol", "/repo")).toBe(false);
  });
});

// ── runDeepReview wiring (with @pwnkit/core mocked, mirrors hunt.test.ts) ─────

const {
  runHuntScanMock,
  makeMultiLensVerifierMock,
  prepareMock,
  collectScopeFilesMock,
  countScopeFilesUpToMock,
  getCloudSinkConfigMock,
  postFindingMock,
  verifierFn,
} = vi.hoisted(() => {
  const verifierFn = vi.fn();
  return {
    runHuntScanMock: vi.fn(),
    makeMultiLensVerifierMock: vi.fn(() => verifierFn),
    prepareMock: vi.fn(),
    collectScopeFilesMock: vi.fn(),
    countScopeFilesUpToMock: vi.fn(),
    getCloudSinkConfigMock: vi.fn(),
    postFindingMock: vi.fn(),
    verifierFn,
  };
});

vi.mock("@pwnkit/core", () => ({
  runHuntScan: runHuntScanMock,
  makeMultiLensVerifier: makeMultiLensVerifierMock,
  prepare: prepareMock,
  collectScopeFiles: collectScopeFilesMock,
  countScopeFilesUpTo: countScopeFilesUpToMock,
  getCloudSinkConfig: getCloudSinkConfigMock,
  postFinding: postFindingMock,
  evmFinderLenses: [{ id: "evm-f", challengeHint: "x" }],
  evmVerifyLenses: [{ id: "evm-v", challengeHint: "y" }],
  solanaFinderLenses: [{ id: "sol-f", challengeHint: "x" }],
  solanaVerifyLenses: [{ id: "sol-v", challengeHint: "y" }],
  cardanoFinderLenses: [{ id: "car-f", challengeHint: "x" }],
  cardanoVerifyLenses: [{ id: "car-v", challengeHint: "y" }],
  cairoFinderLenses: [{ id: "cairo-f", challengeHint: "x" }],
  cairoVerifyLenses: [{ id: "cairo-v", challengeHint: "y" }],
  moveFinderLenses: [{ id: "move-f", challengeHint: "x" }],
  moveVerifyLenses: [{ id: "move-v", challengeHint: "y" }],
  // Mirrors the real appsec registry's 5 lens ids (validated against the JSON in
  // packages/core's appsec-catalog.test.ts) so defaultFinderLenses — which
  // spreads this at module-eval — carries them here. The barrel is mocked in
  // this file, so this stands in for the data-driven loader.
  loadAppsecFinderLenses: () => [
    { id: "os-command-injection", challengeHint: "appsec-cmd" },
    { id: "method-authz-differential", challengeHint: "appsec-authz" },
    { id: "template-xss-ssti", challengeHint: "appsec-xss" },
    { id: "sso-trust", challengeHint: "appsec-sso" },
    { id: "resource-exhaustion-dos", challengeHint: "appsec-dos" },
  ],
}));

/** The 5 data-driven appsec lens ids the default fallback set must carry (kept in
 *  sync with appsec-archetypes.json; the JSON itself is asserted in core's
 *  appsec-catalog.test.ts). */
const APPSEC_LENS_IDS = [
  "os-command-injection",
  "method-authz-differential",
  "template-xss-ssti",
  "sso-trust",
  "resource-exhaustion-dos",
];

const { runDeepReview } = await import("../deep-review.js");

function makeLead(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "lead-1",
    templateId: "deep-review",
    title: "Reentrancy in withdraw()",
    description: "ETH sent before balance zeroed.",
    severity: "high",
    category: "reentrancy" as Finding["category"],
    status: "confirmed",
    evidence: { request: "n/a", response: "src/Vault.sol:88", analysis: "quorum survived" },
    ...overrides,
  } as Finding;
}

describe("runDeepReview — seedless lens-driven review", () => {
  beforeEach(() => {
    prepareMock.mockReset().mockImplementation(async (target: string) => ({
      targetType: "source-code",
      resolvedTarget: target,
      repoPath: target,
      cleanup: vi.fn(),
    }));
    collectScopeFilesMock.mockReset().mockReturnValue(["/repo/src/Vault.sol", "/repo/src/Token.sol"]);
    countScopeFilesUpToMock.mockReset().mockReturnValue(2);
    makeMultiLensVerifierMock.mockClear();
    runHuntScanMock.mockReset().mockResolvedValue({
      findings: [makeLead()],
      confirmed: [makeLead()],
      duplicates: [],
      scanned: 8,
      finderCompleted: 8,
      finderTimedOut: 0,
      finderErrored: 0,
      warnings: [],
    });
    getCloudSinkConfigMock.mockReset().mockReturnValue(null);
    postFindingMock.mockReset().mockResolvedValue(undefined);
  });

  it("selects the profile lens set and wires it into runHuntScan + multi-lens verify", async () => {
    const outcome = await runDeepReview({ target: "/repo", profile: "evm-onchain" });

    expect(outcome.exitCode).toBe(0);
    // verify quorum built from the EVM verify lenses
    expect(makeMultiLensVerifierMock).toHaveBeenCalledOnce();
    expect((makeMultiLensVerifierMock.mock.calls[0] as unknown[])[0]).toEqual([{ id: "evm-v", challengeHint: "y" }]);
    // finder lenses + the built verifier threaded into runHuntScan
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.lenses).toEqual([{ id: "evm-f", challengeHint: "x" }]);
    expect(opts.verify).toBe(verifierFn);
    // Both mock files stat to size 0, so the deterministic alphabetical
    // tie-break orders them Token < Vault.
    expect(opts.candidates).toEqual([
      { path: "/repo/src/Token.sol" },
      { path: "/repo/src/Vault.sol" },
    ]);
    expect(outcome.result).toMatchObject({ mode: "deep_review", profile: "evm-onchain", confirmed: 1 });
  });

  it("evm-onchain: excludes test/vendored/script files from the finder candidate set", async () => {
    collectScopeFilesMock.mockReturnValue([
      "/repo/lib/forge-std/src/Vm.sol",         // vendored — dropped
      "/repo/test/contracts/Vault.t.sol",       // test — dropped
      "/repo/script/Deploy.s.sol",              // deploy script — dropped
      "/repo/src/Comptroller.sol",              // protocol source — kept
      "/repo/src/contracts/Vault.sol",          // protocol source — kept
    ]);
    countScopeFilesUpToMock.mockReturnValue(5);
    await runDeepReview({ target: "/repo", profile: "evm-onchain" });
    const opts = runHuntScanMock.mock.calls[0]![0];
    // All mock files stat to size 0 → alphabetical tie-break among the KEPT src files.
    expect(opts.candidates).toEqual([
      { path: "/repo/src/Comptroller.sol" },
      { path: "/repo/src/contracts/Vault.sol" },
    ]);
  });

  it("non-evm profile: does NOT apply the evm test/vendored exclusion", async () => {
    collectScopeFilesMock.mockReturnValue([
      "/repo/lib/forge-std/src/Vm.sol",
      "/repo/src/Comptroller.sol",
    ]);
    countScopeFilesUpToMock.mockReturnValue(2);
    await runDeepReview({ target: "/repo", profile: "linux-kernel" });
    const opts = runHuntScanMock.mock.calls[0]![0];
    // Kernel/default candidate selection is unchanged — the lib file is kept.
    expect(opts.candidates).toEqual([
      { path: "/repo/lib/forge-std/src/Vm.sol" },
      { path: "/repo/src/Comptroller.sol" },
    ]);
  });

  it("falls back to the default lens set for a non-onchain profile", async () => {
    await runDeepReview({ target: "/repo", profile: "linux-kernel" });
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.lenses).toBe(defaultFinderLenses);
    expect((makeMultiLensVerifierMock.mock.calls[0] as unknown[])[0]).toBe(defaultVerifyLenses);
  });

  it("posts gated leads to the cloud sink as 'discovered' candidates when in cloud mode", async () => {
    getCloudSinkConfigMock.mockReturnValue({ scanId: "s1", endpoint: "http://x", token: "t" });
    const outcome = await runDeepReview({ target: "/repo", profile: "evm-onchain" });
    expect(postFindingMock).toHaveBeenCalledOnce();
    expect(postFindingMock.mock.calls[0]![0]).toMatchObject({ status: "discovered" });
    expect(outcome.result).toMatchObject({ ingested: 1 });
  });

  it("persists each lead INCREMENTALLY via runHuntScan's onConfirmed hook (not only at the end)", async () => {
    getCloudSinkConfigMock.mockReturnValue({ scanId: "s1", endpoint: "http://x", token: "t" });
    const leadA = makeLead({ id: "lead-A", title: "A" });
    const leadB = makeLead({ id: "lead-B", title: "B" });
    // Simulate the real verify pool: fire onConfirmed as each lead lands, THEN
    // resolve. Assert BOTH were already POSTed before the sweep returned — so a
    // mid-sweep kill would still leave them persisted.
    runHuntScanMock.mockImplementation(
      async (opts: { onConfirmed?: (f: Finding) => void | Promise<void> }) => {
        expect(typeof opts.onConfirmed).toBe("function");
        await opts.onConfirmed!(leadA);
        await opts.onConfirmed!(leadB);
        expect(postFindingMock).toHaveBeenCalledTimes(2); // persisted mid-sweep
        return { findings: [leadA, leadB], confirmed: [leadA, leadB], duplicates: [], scanned: 8, warnings: [] };
      },
    );

    const outcome = await runDeepReview({ target: "/repo", profile: "evm-onchain" });

    // Streamed 2; the end-of-run safety net did NOT double-post (deduped by id).
    expect(postFindingMock).toHaveBeenCalledTimes(2);
    expect(postFindingMock.mock.calls.every((c) => (c[0] as { status: string }).status === "discovered")).toBe(true);
    expect(outcome.result).toMatchObject({ ingested: 2, confirmed: 2 });
  });

  it("does not wire onConfirmed nor post anything when NOT in cloud mode", async () => {
    // getCloudSinkConfig returns null by default (set in beforeEach).
    let wiredHook: unknown;
    runHuntScanMock.mockImplementation(async (opts: { onConfirmed?: unknown }) => {
      wiredHook = opts.onConfirmed;
      return { findings: [makeLead()], confirmed: [makeLead()], duplicates: [], scanned: 8, warnings: [] };
    });
    const outcome = await runDeepReview({ target: "/repo", profile: "evm-onchain" });
    expect(wiredHook).toBeUndefined();
    expect(postFindingMock).not.toHaveBeenCalled();
    expect(outcome.result).toMatchObject({ ingested: null });
  });

  it("bounds the fan-out: caps candidates to the fast default (8), largest-first, at the wider default concurrency (8)", async () => {
    const many = Array.from({ length: 30 }, (_, i) => `/repo/src/f${String(i).padStart(2, "0")}.sol`);
    collectScopeFilesMock.mockReturnValue(many);
    countScopeFilesUpToMock.mockReturnValue(30);
    await runDeepReview({ target: "/repo", profile: "evm-onchain" });
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.candidates).toHaveLength(8);
    expect(opts.concurrency).toBe(8);
  });

  it("defaults to a single model (no models passed) × 1 attempt — the fast fan-out", async () => {
    await runDeepReview({ target: "/repo", profile: "evm-onchain" });
    const opts = runHuntScanMock.mock.calls[0]![0];
    // single provider-default model: `models` is left unset so runHuntScan uses its own default
    expect(opts.models).toBeUndefined();
    expect(opts.attemptsPerCandidate).toBe(1);
  });

  it("passes an explicit attemptsPerCandidate for a deliberate best-of-N run", async () => {
    await runDeepReview({ target: "/repo", profile: "evm-onchain", attemptsPerCandidate: 3 });
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.attemptsPerCandidate).toBe(3);
  });

  it("honors PWNKIT_DEEP_REVIEW_ATTEMPTS as the default attempt count", async () => {
    const prev = process.env.PWNKIT_DEEP_REVIEW_ATTEMPTS;
    process.env.PWNKIT_DEEP_REVIEW_ATTEMPTS = "2";
    try {
      await runDeepReview({ target: "/repo", profile: "evm-onchain" });
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_DEEP_REVIEW_ATTEMPTS;
      else process.env.PWNKIT_DEEP_REVIEW_ATTEMPTS = prev;
    }
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.attemptsPerCandidate).toBe(2);
  });

  it("honors PWNKIT_DEEP_REVIEW_MODELS as the default finder model set", async () => {
    const prev = process.env.PWNKIT_DEEP_REVIEW_MODELS;
    process.env.PWNKIT_DEEP_REVIEW_MODELS = "model-a, model-b";
    try {
      await runDeepReview({ target: "/repo", profile: "evm-onchain" });
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_DEEP_REVIEW_MODELS;
      else process.env.PWNKIT_DEEP_REVIEW_MODELS = prev;
    }
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.models).toEqual(["model-a", "model-b"]);
    // first model also threads into the verifier
    expect((makeMultiLensVerifierMock.mock.calls[0] as unknown[])[1]).toMatchObject({ model: "model-a" });
  });

  it("an explicit --models opt overrides the env default", async () => {
    const prev = process.env.PWNKIT_DEEP_REVIEW_MODELS;
    process.env.PWNKIT_DEEP_REVIEW_MODELS = "env-model";
    try {
      await runDeepReview({ target: "/repo", profile: "evm-onchain", models: ["flag-model"] });
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_DEEP_REVIEW_MODELS;
      else process.env.PWNKIT_DEEP_REVIEW_MODELS = prev;
    }
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.models).toEqual(["flag-model"]);
  });

  it("honors PWNKIT_DEEP_REVIEW_MAX_CANDIDATES as the default candidate cap", async () => {
    const many = Array.from({ length: 30 }, (_, i) => `/repo/src/f${String(i).padStart(2, "0")}.sol`);
    collectScopeFilesMock.mockReturnValue(many);
    countScopeFilesUpToMock.mockReturnValue(30);
    const prev = process.env.PWNKIT_DEEP_REVIEW_MAX_CANDIDATES;
    process.env.PWNKIT_DEEP_REVIEW_MAX_CANDIDATES = "5";
    try {
      await runDeepReview({ target: "/repo", profile: "evm-onchain" });
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_DEEP_REVIEW_MAX_CANDIDATES;
      else process.env.PWNKIT_DEEP_REVIEW_MAX_CANDIDATES = prev;
    }
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.candidates).toHaveLength(5);
  });

  it("exits 2 (skip) without running the hunt when the scope exceeds the review cap", async () => {
    countScopeFilesUpToMock.mockReturnValue(5001);
    const outcome = await runDeepReview({ target: "/repo" });
    expect(outcome.exitCode).toBe(2);
    expect(runHuntScanMock).not.toHaveBeenCalled();
    expect(outcome.result).toMatchObject({ mode: "deep_review" });
    expect((outcome.result as { note: string }).note).toMatch(/--subsystem/);
  });

  it("exits 0 (complete, not failed) when the sweep RAN but surfaced no surviving leads", async () => {
    // A clean 0-lead hunt is a valid SUCCESS: the sweep completed, finders did
    // real work (finderCompleted > 0), nothing survived the quorum. Must NOT be
    // exit-non-zero, or the cloud worker marks the scan failed (CapyFi/Onyx).
    runHuntScanMock.mockResolvedValue({
      findings: [], confirmed: [], duplicates: [],
      scanned: 8, finderCompleted: 8, finderTimedOut: 0, finderErrored: 0,
      warnings: [],
    });
    const outcome = await runDeepReview({ target: "/repo", profile: "evm-onchain" });
    expect(outcome.exitCode).toBe(0);
    expect(outcome.result).toMatchObject({ mode: "deep_review", confirmed: 0 });
  });

  it("exits 0 when a PARTIAL subset of finders timed out but some completed (real coverage)", async () => {
    // 20/32 timing out (Onyx) still leaves real coverage — a success, not failure.
    runHuntScanMock.mockResolvedValue({
      findings: [], confirmed: [], duplicates: [],
      scanned: 32, finderCompleted: 12, finderTimedOut: 20, finderErrored: 0,
      warnings: ["finder timed out on X — abandoned"],
    });
    const outcome = await runDeepReview({ target: "/repo", profile: "evm-onchain" });
    expect(outcome.exitCode).toBe(0);
  });

  it("exits 3 (genuine failure) when the sweep did NO work — every finder failed", async () => {
    // 0 of N completed = an LLM/backend failure (auth, total stall), NOT a clean
    // 0-finding result. This must still fail so real outages aren't masked.
    runHuntScanMock.mockResolvedValue({
      findings: [], confirmed: [], duplicates: [],
      scanned: 8, finderCompleted: 0, finderTimedOut: 3, finderErrored: 5,
      warnings: ["fetch failed", "LLM auth error"],
    });
    const outcome = await runDeepReview({ target: "/repo", profile: "evm-onchain" });
    expect(outcome.exitCode).toBe(3);
    expect(outcome.result).toMatchObject({ mode: "deep_review", finder_completed: 0 });
    expect((outcome.result as { error: string }).error).toMatch(/every finder run failed/);
  });

  it("rejects a subsystem that escapes the source tree", async () => {
    await expect(runDeepReview({ target: "/repo", subsystem: "../../etc" })).rejects.toThrow(/escapes/);
  });
});
