import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@0sec/shared";
import type { FinderLens, VerifyLens } from "@0sec/core";

// ── Pure helpers (no @0sec/core load needed) ───────────────────────────────
import {
  selectProfileLenses,
  enumerateDeepReviewCandidates,
  isNonProtocolEvmPath,
  detectStack,
  selectDefaultFinderLensesForStack,
  selectCandidatesModuleSpread,
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

  it("uses the invocation snapshot for a default-profile review", () => {
    const snapshot = tagged("newly-promoted");
    const result = selectProfileLenses(undefined, SETS, snapshot);
    expect(result.finderLenses).toBe(snapshot);
    expect(result.finderLenses.map((lens) => lens.id)).toEqual(["newly-promoted"]);
  });

  it("ships a non-empty default verify set (makeMultiLensVerifier requires ≥1)", () => {
    expect(defaultVerifyLenses.length).toBeGreaterThan(0);
    expect(defaultFinderLenses.length).toBeGreaterThan(0);
  });

  it("default finder set unions the 5 generic lenses with the 5 data-driven appsec lenses", () => {
    const ids = defaultFinderLenses.map((l) => l.id);
    // The generic buckets are preserved …
    expect(ids).toEqual(expect.arrayContaining(["memory-safety", "input-validation", "auth-logic", "secrets-crypto", "cross-component"]));
    // … and every appsec lens is added on top (the Swiss-miss coverage classes).
    for (const id of APPSEC_LENS_IDS) expect(ids).toContain(id);
    expect(defaultFinderLenses).toHaveLength(5 + APPSEC_LENS_IDS.length);
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

// ── B3: stack-aware default-profile lens selection ───────────────────────────

describe("detectStack — infer target stack from candidate extensions", () => {
  it("detects a managed/web stack (C#/Angular) — the memory-safety-is-noise case", () => {
    const files = [
      "/app/src/Controllers/HrdController.cs",
      "/app/src/waf/Config.cs",
      "/app/web/src/app/app.component.ts",
      "/app/web/src/index.html",
    ];
    expect(detectStack(files)).toBe("managed-web");
  });

  it("detects a native stack (C/C++) — memory-safety primary", () => {
    expect(detectStack(["/proj/src/parser.c", "/proj/include/parser.h", "/proj/src/vm.cpp"])).toBe("native");
  });

  it("treats Rust as native (its unsafe surface keeps memory-safety relevant)", () => {
    expect(detectStack(["/proj/src/lib.rs", "/proj/src/main.rs"])).toBe("native");
  });

  it("detects Go / Python / Java / PHP / Ruby as managed", () => {
    expect(detectStack(["/svc/main.go", "/svc/handler.go"])).toBe("managed-web");
    expect(detectStack(["/svc/app.py"])).toBe("managed-web");
    expect(detectStack(["/svc/Main.java", "/svc/pom-generated/X.java"])).toBe("managed-web");
    expect(detectStack(["/svc/index.php"])).toBe("managed-web");
    expect(detectStack(["/svc/app.rb"])).toBe("managed-web");
  });

  it("returns mixed when both native and managed sources are present (safe default)", () => {
    expect(detectStack(["/proj/native/ext.c", "/proj/web/app.ts"])).toBe("mixed");
  });

  it("returns unknown when nothing is recognized (e.g. only .sol / no source)", () => {
    expect(detectStack(["/repo/src/Vault.sol", "/repo/src/Token.sol"])).toBe("unknown");
    expect(detectStack([])).toBe("unknown");
    expect(detectStack(["/repo/Makefile", "/repo/README"])).toBe("unknown");
  });
});

describe("selectDefaultFinderLensesForStack — drop memory-safety on managed code", () => {
  it("managed-web: drops memory-safety, keeps input-validation + auth-logic + secrets-crypto + all appsec", () => {
    const files = ["/app/HrdController.cs", "/app/app.component.ts"];
    const lenses = selectDefaultFinderLensesForStack(files, defaultFinderLenses);
    const ids = lenses.map((l) => l.id);
    expect(ids).not.toContain("memory-safety");
    expect(ids).toEqual(expect.arrayContaining(["input-validation", "auth-logic", "secrets-crypto"]));
    for (const id of APPSEC_LENS_IDS) expect(ids).toContain(id);
    // Exactly the full set minus the one memory-safety lens.
    expect(lenses).toHaveLength(defaultFinderLenses.length - 1);
  });

  it("native: returns the full default set UNCHANGED (same reference — memory-safety primary)", () => {
    const lenses = selectDefaultFinderLensesForStack(["/proj/parser.c"], defaultFinderLenses);
    expect(lenses).toBe(defaultFinderLenses);
    expect(lenses.map((l) => l.id)).toContain("memory-safety");
  });

  it("mixed / unknown: returns the full default set UNCHANGED (safe default, same reference)", () => {
    expect(selectDefaultFinderLensesForStack(["/p/ext.c", "/p/app.ts"], defaultFinderLenses)).toBe(defaultFinderLenses);
    expect(selectDefaultFinderLensesForStack(["/repo/Vault.sol"], defaultFinderLenses)).toBe(defaultFinderLenses);
    expect(selectDefaultFinderLensesForStack([], defaultFinderLenses)).toBe(defaultFinderLenses);
  });
});

// ── B1: module-spread candidate selection ────────────────────────────────────

describe("selectCandidatesModuleSpread — spread the budget across subsystems", () => {
  it("round-robins across top-level modules instead of clustering on the biggest one", () => {
    // The `waf` module has the 3 largest files; largest-first would take all 3
    // slots there and never reach `hrd`/`auth`. Module-spread must include all.
    const entries = [
      { p: "/app/waf/a.cs", size: 9000 },
      { p: "/app/waf/b.cs", size: 8000 },
      { p: "/app/waf/c.cs", size: 7000 },
      { p: "/app/hrd/HrdController.cs", size: 500 },
      { p: "/app/auth/Login.cs", size: 400 },
    ];
    const picked = selectCandidatesModuleSpread(entries, "/app", 3);
    const modules = new Set(picked.map((p) => p.split("/")[2]));
    // Breadth: 3 slots span 3 distinct modules, not 3 files from `waf`.
    expect(modules).toEqual(new Set(["waf", "hrd", "auth"]));
    // Within a module, the largest file wins → waf's `a.cs` is the waf pick.
    expect(picked).toContain("/app/waf/a.cs");
    expect(picked).not.toContain("/app/waf/b.cs");
  });

  it("visits modules by their largest file, then takes each module's next-largest in later rounds", () => {
    const entries = [
      { p: "/app/waf/a.cs", size: 9000 },
      { p: "/app/waf/b.cs", size: 8000 },
      { p: "/app/hrd/x.cs", size: 6000 },
      { p: "/app/hrd/y.cs", size: 5000 },
    ];
    // 4-slot budget over 2 modules → round 1: waf/a, hrd/x; round 2: waf/b, hrd/y.
    expect(selectCandidatesModuleSpread(entries, "/app", 4)).toEqual([
      "/app/waf/a.cs",
      "/app/hrd/x.cs",
      "/app/waf/b.cs",
      "/app/hrd/y.cs",
    ]);
  });

  it("degrades to plain largest-first for a single-module tree (old behavior preserved)", () => {
    const entries = [
      { p: "/app/src/big.ts", size: 9000 },
      { p: "/app/src/mid.ts", size: 5000 },
      { p: "/app/src/small.ts", size: 100 },
    ];
    expect(selectCandidatesModuleSpread(entries, "/app", 2)).toEqual(["/app/src/big.ts", "/app/src/mid.ts"]);
  });

  it("enumerateDeepReviewCandidates spreads across modules given a clustered tree", () => {
    const sizes: Record<string, number> = {
      "/app/waf/a.cs": 9000,
      "/app/waf/b.cs": 8000,
      "/app/waf/c.cs": 7000,
      "/app/hrd/HrdController.cs": 500,
      "/app/auth/Login.cs": 400,
    };
    const h: DeepReviewEnumHelpers = {
      collectScopeFiles: () => Object.keys(sizes),
      countScopeFilesUpTo: () => Object.keys(sizes).length,
      fileSize: (p) => sizes[p] ?? 0,
    };
    const r = enumerateDeepReviewCandidates("/app", h, { maxCandidates: 3 });
    expect(new Set(r.candidates.map((p) => p.split("/")[2]))).toEqual(new Set(["waf", "hrd", "auth"]));
  });
});

// ── runDeepReview wiring (with @0sec/core mocked, mirrors hunt.test.ts) ─────

const {
  runHuntScanMock,
  makeMultiLensVerifierMock,
  prepareMock,
  collectScopeFilesMock,
  countScopeFilesUpToMock,
  getCloudSinkConfigMock,
  postFindingMock,
  eventBusEmitMock,
  verifierFn,
  runThreatModelPlannerMock,
  createRuntimeMock,
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
    eventBusEmitMock: vi.fn(),
    verifierFn,
    // Threat-model planner mocks: fail-closed by default (returns null → fallback to module-spread).
    runThreatModelPlannerMock: vi.fn().mockResolvedValue(null),
    // Return a minimal Runtime stub so the planner code path doesn't crash.
    createRuntimeMock: vi.fn(() => ({ execute: vi.fn(), type: "api", isAvailable: vi.fn() })),
  };
});

vi.mock("@0sec/core", () => ({
  runHuntScan: runHuntScanMock,
  makeMultiLensVerifier: makeMultiLensVerifierMock,
  prepare: prepareMock,
  collectScopeFiles: collectScopeFilesMock,
  countScopeFilesUpTo: countScopeFilesUpToMock,
  getCloudSinkConfig: getCloudSinkConfigMock,
  postFinding: postFindingMock,
  eventBus: { emit: eventBusEmitMock },
  ScanCostLedger: class {
    costBreakdown() { return null; }
  },
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
  // Threat-model planner (B6): fail-closed mock — returns null so the fallback
  // to module-spread selection is exercised, and createRuntime returns a stub.
  createRuntime: createRuntimeMock,
  runThreatModelPlanner: runThreatModelPlannerMock,
  allocateCandidatesAcrossLanes: vi.fn(),
  parseThreatLaneJson: vi.fn().mockReturnValue(null),
  matchesLane: vi.fn().mockReturnValue(false),
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
      dropped: [],
      scanned: 8,
      finderCompleted: 8,
      finderTimedOut: 0,
      finderErrored: 0,
      warnings: [],
    });
    getCloudSinkConfigMock.mockReset().mockReturnValue(null);
    postFindingMock.mockReset().mockResolvedValue(undefined);
    eventBusEmitMock.mockReset();
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
    expect(outcome.report).toMatchObject({
      target: "/repo",
      summary: { totalAttacks: 8, totalFindings: 1 },
      findings: [{ status: "discovered" }],
    });
  });

  it("emits one parent terminal event and threads one ledger through the whole review", async () => {
    await runDeepReview({ target: "/repo", profile: "evm-onchain", costCeilingUsd: 1 });

    const huntOptions = runHuntScanMock.mock.calls[0]?.[0] as Record<string, unknown>;
    const verifierOptions = (makeMultiLensVerifierMock.mock.calls[0] as unknown[] | undefined)?.[1] as Record<string, unknown>;
    expect(huntOptions.costLedger).toBe(verifierOptions.costLedger);
    expect(huntOptions.costCeilingUsd).toBe(1);
    expect(eventBusEmitMock).toHaveBeenCalledWith(
      "scan_completed",
      expect.objectContaining({ exit_reason: "completed", findings_count: 1 }),
    );
  });

  it("emits a failed parent terminal event when the review throws", async () => {
    runHuntScanMock.mockRejectedValueOnce(new Error("provider unavailable"));

    await expect(runDeepReview({ target: "/repo", profile: "evm-onchain" })).rejects.toThrow("provider unavailable");
    expect(eventBusEmitMock).toHaveBeenCalledWith(
      "scan_completed",
      expect.objectContaining({ exit_reason: "failed" }),
    );
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

  it("falls back to a fresh default lens snapshot for a non-onchain profile", async () => {
    await runDeepReview({ target: "/repo", profile: "linux-kernel" });
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.lenses).toEqual(defaultFinderLenses);
    expect(opts.lenses).not.toBe(defaultFinderLenses);
    expect((makeMultiLensVerifierMock.mock.calls[0] as unknown[])[0]).toBe(defaultVerifyLenses);
  });

  it("B3: default profile on a MANAGED (C#/Angular) target drops memory-safety from the finder set", async () => {
    // The exact Swiss-miss shape: a C#/Angular app. Default profile → stack-aware
    // selection must run appsec/authz/injection, NOT memory-safety.
    collectScopeFilesMock.mockReturnValue([
      "/app/src/Controllers/HrdController.cs",
      "/app/web/src/app/app.component.ts",
    ]);
    countScopeFilesUpToMock.mockReturnValue(2);
    await runDeepReview({ target: "/app" }); // no profile → default fall-through
    const opts = runHuntScanMock.mock.calls[0]![0];
    const ids = (opts.lenses as { id: string }[]).map((l) => l.id);
    expect(ids).not.toContain("memory-safety");
    expect(ids).toEqual(expect.arrayContaining(["input-validation", "auth-logic", "secrets-crypto"]));
    for (const id of APPSEC_LENS_IDS) expect(ids).toContain(id);
    // Verify quorum is unchanged (B3 only reshapes the finder set).
    expect((makeMultiLensVerifierMock.mock.calls[0] as unknown[])[0]).toBe(defaultVerifyLenses);
  });

  it("B3: default profile on a NATIVE (C) target keeps the full invocation snapshot (memory-safety primary)", async () => {
    collectScopeFilesMock.mockReturnValue(["/proj/src/parser.c", "/proj/include/parser.h"]);
    countScopeFilesUpToMock.mockReturnValue(2);
    await runDeepReview({ target: "/proj" }); // default fall-through, native tree
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.lenses).toEqual(defaultFinderLenses);
    expect(opts.lenses).not.toBe(defaultFinderLenses);
    expect((opts.lenses as { id: string }[]).map((lens) => lens.id)).toContain("memory-safety");
  });

  it("B3 REGRESSION: on-chain profiles are NOT stack-adjusted even on managed-looking files", async () => {
    // A `.ts`-heavy Solana repo must still get the bespoke Solana finder set,
    // never the managed-web-adjusted default set.
    collectScopeFilesMock.mockReturnValue(["/repo/programs/x.ts", "/repo/app/y.ts"]);
    countScopeFilesUpToMock.mockReturnValue(2);
    await runDeepReview({ target: "/repo", profile: "solana-onchain" });
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.lenses).toEqual([{ id: "sol-f", challengeHint: "x" }]);
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
        return { findings: [leadA, leadB], confirmed: [leadA, leadB], duplicates: [], dropped: [], scanned: 8, warnings: [] };
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
      return { findings: [makeLead()], confirmed: [makeLead()], duplicates: [], dropped: [], scanned: 8, warnings: [] };
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

  it("honors 0SEC_DEEP_REVIEW_ATTEMPTS as the default attempt count", async () => {
    const prev = process.env["0SEC_DEEP_REVIEW_ATTEMPTS"];
    process.env["0SEC_DEEP_REVIEW_ATTEMPTS"] = "2";
    try {
      await runDeepReview({ target: "/repo", profile: "evm-onchain" });
    } finally {
      if (prev === undefined) delete process.env["0SEC_DEEP_REVIEW_ATTEMPTS"];
      else process.env["0SEC_DEEP_REVIEW_ATTEMPTS"] = prev;
    }
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.attemptsPerCandidate).toBe(2);
  });

  it("honors 0SEC_DEEP_REVIEW_MODELS as the default finder model set", async () => {
    const prev = process.env["0SEC_DEEP_REVIEW_MODELS"];
    process.env["0SEC_DEEP_REVIEW_MODELS"] = "model-a, model-b";
    try {
      await runDeepReview({ target: "/repo", profile: "evm-onchain" });
    } finally {
      if (prev === undefined) delete process.env["0SEC_DEEP_REVIEW_MODELS"];
      else process.env["0SEC_DEEP_REVIEW_MODELS"] = prev;
    }
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.models).toEqual(["model-a", "model-b"]);
    // first model also threads into the verifier
    expect((makeMultiLensVerifierMock.mock.calls[0] as unknown[])[1]).toMatchObject({ model: "model-a" });
  });

  it("an explicit --models opt overrides the env default", async () => {
    const prev = process.env["0SEC_DEEP_REVIEW_MODELS"];
    process.env["0SEC_DEEP_REVIEW_MODELS"] = "env-model";
    try {
      await runDeepReview({ target: "/repo", profile: "evm-onchain", models: ["flag-model"] });
    } finally {
      if (prev === undefined) delete process.env["0SEC_DEEP_REVIEW_MODELS"];
      else process.env["0SEC_DEEP_REVIEW_MODELS"] = prev;
    }
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.models).toEqual(["flag-model"]);
  });

  it("honors 0SEC_DEEP_REVIEW_MAX_CANDIDATES as the default candidate cap", async () => {
    const many = Array.from({ length: 30 }, (_, i) => `/repo/src/f${String(i).padStart(2, "0")}.sol`);
    collectScopeFilesMock.mockReturnValue(many);
    countScopeFilesUpToMock.mockReturnValue(30);
    const prev = process.env["0SEC_DEEP_REVIEW_MAX_CANDIDATES"];
    process.env["0SEC_DEEP_REVIEW_MAX_CANDIDATES"] = "5";
    try {
      await runDeepReview({ target: "/repo", profile: "evm-onchain" });
    } finally {
      if (prev === undefined) delete process.env["0SEC_DEEP_REVIEW_MAX_CANDIDATES"];
      else process.env["0SEC_DEEP_REVIEW_MAX_CANDIDATES"] = prev;
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
      findings: [], confirmed: [], duplicates: [], dropped: [],
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
      findings: [], confirmed: [], duplicates: [], dropped: [],
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
      findings: [], confirmed: [], duplicates: [], dropped: [],
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

  it("B6: useThreatModel calls the planner and falls back when it returns nothing", async () => {
    // The mock planner returns null by default (fail-closed). The review should
    // proceed with the normal module-spread candidate selection.
    runThreatModelPlannerMock.mockClear();
    await runDeepReview({ target: "/repo", profile: "evm-onchain", useThreatModel: true });
    expect(runThreatModelPlannerMock).toHaveBeenCalledOnce();
    expect(createRuntimeMock).toHaveBeenCalledOnce();
    // Candidate selection still ran (module-spread fallback).
    const opts = runHuntScanMock.mock.calls[0]![0];
    expect(opts.candidates).toBeDefined();
    expect(opts.candidates.length).toBe(2);
  });

  it("B6: useThreatModel is OFF by default — planner is NOT called", async () => {
    runThreatModelPlannerMock.mockClear();
    await runDeepReview({ target: "/repo" });
    expect(runThreatModelPlannerMock).not.toHaveBeenCalled();
  });
});

// ── B6: Threat-model planner — pure function tests ───────────────────────────
// These bypass the @0sec/core mock by importing directly from the source file.

import type * as osecCore from "@0sec/core";

// Bypass the @0sec/core mock above via importActual (a direct relative
// source import would escape the cli tsconfig rootDir and fail the build).
const {
  parseThreatLaneJson,
  matchesLane: tlMatchesLane,
  allocateCandidatesAcrossLanes: tlAllocateCandidatesAcrossLanes,
} = await vi.importActual<typeof osecCore>("@0sec/core");

describe("parseThreatLaneJson — threat-model JSON parser", () => {
  it("parses a valid JSON array of lanes", () => {
    const lanes = parseThreatLaneJson(
      '[{"name":"kv-r2","rationale":"KV consistency across R2 boundaries","subsystems":["kv","r2"]}]',
    );
    expect(lanes).toHaveLength(1);
    expect(lanes![0]).toEqual({
      name: "kv-r2",
      rationale: "KV consistency across R2 boundaries",
      subsystems: ["kv", "r2"],
    });
  });

  it("strips markdown fences around the JSON", () => {
    const lanes = parseThreatLaneJson(
      "```json\n[{\"name\":\"a\",\"rationale\":\"b\",\"subsystems\":[\"c\"]}]\n```",
    );
    expect(lanes).toHaveLength(1);
    expect(lanes![0].name).toBe("a");
  });

  it("returns null for invalid JSON", () => {
    expect(parseThreatLaneJson("not json")).toBeNull();
  });

  it("returns null for non-array JSON", () => {
    expect(parseThreatLaneJson('{"name":"x"}')).toBeNull();
  });

  it("skips incomplete lane entries (missing rationale or subsystems)", () => {
    const lanes = parseThreatLaneJson(
      '[{"name":"a","rationale":"","subsystems":["x"]},{"name":"b","rationale":"ok","subsystems":["y"]}]',
    );
    expect(lanes).toHaveLength(1);
    expect(lanes![0].name).toBe("b");
  });

  it("returns null when no valid lanes survive the filter", () => {
    expect(parseThreatLaneJson('[{"name":"a","rationale":"","subsystems":[]}]')).toBeNull();
  });
});

describe("matchesLane — file-to-lane assignment", () => {
  it("matches a file whose path prefix matches a subsystem", () => {
    expect(tlMatchesLane("/repo/kv/store.ts", "/repo", ["kv", "r2"])).toBe(true);
  });

  it("does not match a file in an unrelated subsystem", () => {
    expect(tlMatchesLane("/repo/auth/login.ts", "/repo", ["kv", "r2"])).toBe(false);
  });

  it("matches a deeply nested file under a subsystem prefix", () => {
    expect(tlMatchesLane("/repo/sharing/scheduler/job.ts", "/repo", ["sharing", "scheduler"])).toBe(true);
  });

  it("returns false for a path that escapes the scope root", () => {
    expect(tlMatchesLane("/other/repo/x.ts", "/repo", ["x"])).toBe(false);
  });
});

describe("allocateCandidatesAcrossLanes — lane-aware budget spread", () => {
  it("spreads candidates across lanes round-robin", () => {
    const entries = [
      { p: "/repo/kv/big.ts", size: 9000 },
      { p: "/repo/kv/small.ts", size: 100 },
      { p: "/repo/r2/big.ts", size: 7000 },
      { p: "/repo/r2/small.ts", size: 50 },
      { p: "/repo/auth/login.ts", size: 500 },
    ];
    const lanes = [{ name: "kv-r2", rationale: "x", subsystems: ["kv", "r2"] }];
    const picked = tlAllocateCandidatesAcrossLanes(entries, lanes, "/repo", 2);
    expect(picked).toHaveLength(2);
    expect(picked).toContain("/repo/kv/big.ts");
    expect(picked).toContain("/repo/auth/login.ts");
  });

  it("allocates across multiple lanes in priority order", () => {
    const entries = [
      { p: "/repo/kv/big.ts", size: 9000 },
      { p: "/repo/r2/mid.ts", size: 5000 },
      { p: "/repo/auth/login.ts", size: 400 },
    ];
    const lanes = [
      { name: "data", rationale: "x", subsystems: ["kv", "r2"] },
      { name: "identity", rationale: "y", subsystems: ["auth"] },
    ];
    const picked = tlAllocateCandidatesAcrossLanes(entries, lanes, "/repo", 2);
    expect(picked).toEqual(["/repo/kv/big.ts", "/repo/auth/login.ts"]);
  });

  it("drops empty lanes (warning) when fewer files than lanes", () => {
    const entries = [{ p: "/repo/kv/store.ts", size: 1000 }];
    const lanes = [
      { name: "kv-r2", rationale: "x", subsystems: ["kv"] },
      { name: "identity", rationale: "y", subsystems: ["auth"] },
    ];
    const picked = tlAllocateCandidatesAcrossLanes(entries, lanes, "/repo", 3);
    expect(picked).toEqual(["/repo/kv/store.ts"]);
  });

  it("handles budget smaller than lane count (round-robin selects subset)", () => {
    const entries = [
      { p: "/repo/kv/a.ts", size: 1000 },
      { p: "/repo/r2/b.ts", size: 800 },
      { p: "/repo/auth/c.ts", size: 600 },
    ];
    const lanes = [
      { name: "data", rationale: "x", subsystems: ["kv"] },
      { name: "edge", rationale: "y", subsystems: ["r2"] },
      { name: "identity", rationale: "z", subsystems: ["auth"] },
    ];
    const picked = tlAllocateCandidatesAcrossLanes(entries, lanes, "/repo", 2);
    expect(picked).toHaveLength(2);
    expect(picked).toContain("/repo/kv/a.ts");
    expect(picked).toContain("/repo/r2/b.ts");
  });

  it("preserves deterministic ordering within each lane (largest-first, path tie-break)", () => {
    const entries = [
      { p: "/repo/kv/z.ts", size: 100 },
      { p: "/repo/kv/a.ts", size: 100 },
    ];
    const lanes = [{ name: "kv-r2", rationale: "x", subsystems: ["kv"] }];
    const picked = tlAllocateCandidatesAcrossLanes(entries, lanes, "/repo", 2);
    expect(picked).toEqual(["/repo/kv/a.ts", "/repo/kv/z.ts"]);
  });
});
