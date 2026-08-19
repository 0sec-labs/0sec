/**
 * EVM verify harness tests. `parseForgeOutput` / `adjudicateForgeOutcomes` /
 * `evmVerifyCacheKey` / `planEvmVerify` are PURE — no forge, no anvil, no RPC.
 * The sample `forge test --json` blobs below are hand-written to the real forge
 * output shape (top-level suite key → `test_results` → per-fn result with
 * `status` / `kind` / `reason` / `counterexample` / `decoded_logs`).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  adjudicateForgeOutcomes,
  evmForkRpc,
  evmVerifyCacheKey,
  evmVerifyEnabled,
  forgeAvailable,
  parseForgeOutput,
  planEvmVerify,
  runEvmVerify,
  type EvmVerifyRequest,
} from "./evm-verify.js";

// A passing exploit test (impact assertion held → proof).
const FORGE_JSON_EXPLOIT_PASS = JSON.stringify({
  "test/PwnkitExploit.t.sol:PwnkitExploit": {
    test_results: {
      "testExploitDrainsVault()": {
        status: "Success",
        reason: null,
        counterexample: null,
        decoded_logs: ["attacker profit: 1000000000000000000"],
        kind: { Standard: 84213 },
      },
      "testSetup()": {
        status: "Success",
        reason: null,
        counterexample: null,
        decoded_logs: [],
        kind: { Standard: 21000 },
      },
    },
  },
});

// A reverted exploit test (exploit did NOT reproduce → not_proven).
const FORGE_JSON_EXPLOIT_FAIL = JSON.stringify({
  "test/PwnkitExploit.t.sol:PwnkitExploit": {
    test_results: {
      "testExploitDrainsVault()": {
        status: "Failure",
        reason: "revert: ReentrancyGuard: reentrant call",
        counterexample: null,
        decoded_logs: [],
        kind: { Standard: 45000 },
      },
    },
  },
});

// A broken invariant with a counterexample (property broke → proof).
const FORGE_JSON_INVARIANT_BROKEN = JSON.stringify({
  "test/Solvency.t.sol:SolvencyInvariants": {
    test_results: {
      "invariant_vaultSolvent()": {
        status: "Failure",
        reason: "vault drained below deposits",
        counterexample: { Sequence: [{ sender: "0xattacker", func: "withdraw" }] },
        kind: { Invariant: { runs: 256, calls: 3840, reverts: 12 } },
      },
    },
  },
});

// A skipped test.
const FORGE_JSON_SKIPPED = JSON.stringify({
  "test/PwnkitExploit.t.sol:PwnkitExploit": {
    test_results: {
      "testExploit()": { status: "Skipped", reason: "vm.skip", counterexample: null, kind: "Standard" },
    },
  },
});

// forge sometimes prints compiler preamble before the JSON object.
const FORGE_JSON_WITH_PREAMBLE = `Compiling 3 files with 0.8.24
Solc 0.8.24 finished in 1.23s
${FORGE_JSON_EXPLOIT_PASS}`;

describe("parseForgeOutput", () => {
  it("parses a passing exploit test with decoded logs and gas", () => {
    const parsed = parseForgeOutput(FORGE_JSON_EXPLOIT_PASS);
    expect(parsed.ok).toBe(true);
    expect(parsed.passed).toBe(2);
    expect(parsed.failed).toBe(0);
    expect(parsed.skipped).toBe(0);
    const exploit = parsed.outcomes.find((o) => o.name === "testExploitDrainsVault");
    expect(exploit).toBeDefined();
    expect(exploit!.status).toBe("pass");
    expect(exploit!.kind).toBe("standard");
    expect(exploit!.gas).toBe(84213);
    expect(exploit!.decodedLogs).toEqual(["attacker profit: 1000000000000000000"]);
    // parens stripped from the fn name
    expect(exploit!.name).not.toContain("(");
  });

  it("parses a failing test and extracts the revert reason", () => {
    const parsed = parseForgeOutput(FORGE_JSON_EXPLOIT_FAIL);
    expect(parsed.ok).toBe(true);
    expect(parsed.failed).toBe(1);
    const o = parsed.outcomes[0]!;
    expect(o.status).toBe("fail");
    expect(o.reason).toBe("revert: ReentrancyGuard: reentrant call");
    expect(o.counterexample).toBeUndefined();
  });

  it("parses a broken invariant with a counterexample and invariant kind", () => {
    const parsed = parseForgeOutput(FORGE_JSON_INVARIANT_BROKEN);
    expect(parsed.ok).toBe(true);
    const o = parsed.outcomes[0]!;
    expect(o.status).toBe("fail");
    expect(o.kind).toBe("invariant");
    expect(o.counterexample).toBeDefined();
    expect(o.counterexample).toContain("withdraw");
  });

  it("normalizes a Skipped status", () => {
    const parsed = parseForgeOutput(FORGE_JSON_SKIPPED);
    expect(parsed.ok).toBe(true);
    expect(parsed.skipped).toBe(1);
    expect(parsed.outcomes[0]!.status).toBe("skip");
    // bare-string kind still normalizes
    expect(parsed.outcomes[0]!.kind).toBe("standard");
  });

  it("tolerates a compiler preamble before the JSON object", () => {
    const parsed = parseForgeOutput(FORGE_JSON_WITH_PREAMBLE);
    expect(parsed.ok).toBe(true);
    expect(parsed.passed).toBe(2);
  });

  it("returns a parseError (never throws) on empty input", () => {
    const parsed = parseForgeOutput("");
    expect(parsed.ok).toBe(false);
    expect(parsed.parseError).toMatch(/empty/i);
    expect(parsed.outcomes).toHaveLength(0);
  });

  it("returns a parseError on non-JSON garbage", () => {
    const parsed = parseForgeOutput("error: forge not found\ncommand exited 127");
    expect(parsed.ok).toBe(false);
    expect(parsed.parseError).toBeDefined();
  });

  it("returns a parseError on malformed JSON", () => {
    const parsed = parseForgeOutput('{ "suite": { "test_results": }} ');
    expect(parsed.ok).toBe(false);
    expect(parsed.parseError).toMatch(/parse failed/i);
  });
});

describe("adjudicateForgeOutcomes", () => {
  it("marks proven when an exploit-shaped test passes", () => {
    const verdict = adjudicateForgeOutcomes(parseForgeOutput(FORGE_JSON_EXPLOIT_PASS));
    expect(verdict.status).toBe("proven");
    expect(verdict.provingTest?.name).toBe("testExploitDrainsVault");
  });

  it("marks proven when an invariant breaks with a counterexample", () => {
    const verdict = adjudicateForgeOutcomes(parseForgeOutput(FORGE_JSON_INVARIANT_BROKEN));
    expect(verdict.status).toBe("proven");
    expect(verdict.provingTest?.name).toBe("invariant_vaultSolvent");
  });

  it("marks not_proven and surfaces the failing assertion when the exploit reverts", () => {
    const verdict = adjudicateForgeOutcomes(parseForgeOutput(FORGE_JSON_EXPLOIT_FAIL));
    expect(verdict.status).toBe("not_proven");
    expect(verdict.failingAssertion).toContain("reentrant call");
  });

  it("does not treat a vacuous green suite as proof", () => {
    const vacuous = JSON.stringify({
      "test/X.t.sol:X": {
        test_results: { "testNothing()": { status: "Success", reason: null, kind: { Standard: 1 } } },
      },
    });
    const verdict = adjudicateForgeOutcomes(parseForgeOutput(vacuous));
    expect(verdict.status).toBe("not_proven");
  });

  it("propagates a parse error as not_proven", () => {
    const verdict = adjudicateForgeOutcomes(parseForgeOutput(""));
    expect(verdict.status).toBe("not_proven");
  });
});

describe("evmVerifyCacheKey", () => {
  const base: EvmVerifyRequest = {
    targetRepo: "/tmp/target",
    testSource: "contract T {}",
    forkBlock: 20_000_000,
    chainId: 1,
    targetCommit: "abc123",
  };

  it("is deterministic for identical inputs", () => {
    expect(evmVerifyCacheKey(base)).toBe(evmVerifyCacheKey({ ...base }));
  });

  it("changes when the fork block changes (proof is block-bound)", () => {
    expect(evmVerifyCacheKey(base)).not.toBe(evmVerifyCacheKey({ ...base, forkBlock: 20_000_001 }));
  });

  it("changes when the chain id changes", () => {
    expect(evmVerifyCacheKey(base)).not.toBe(evmVerifyCacheKey({ ...base, chainId: 10 }));
  });

  it("changes when the test source changes", () => {
    expect(evmVerifyCacheKey(base)).not.toBe(evmVerifyCacheKey({ ...base, testSource: "contract U {}" }));
  });
});

describe("env gate", () => {
  const saved = { verify: process.env.PWNKIT_EVM_VERIFY, rpc: process.env.PWNKIT_EVM_FORK_RPC };
  beforeEach(() => {
    delete process.env.PWNKIT_EVM_VERIFY;
    delete process.env.PWNKIT_EVM_FORK_RPC;
  });
  afterEach(() => {
    if (saved.verify === undefined) delete process.env.PWNKIT_EVM_VERIFY;
    else process.env.PWNKIT_EVM_VERIFY = saved.verify;
    if (saved.rpc === undefined) delete process.env.PWNKIT_EVM_FORK_RPC;
    else process.env.PWNKIT_EVM_FORK_RPC = saved.rpc;
  });

  it("is OFF by default", () => {
    expect(evmVerifyEnabled()).toBe(false);
    expect(forgeAvailable()).toBe(false);
  });

  it("respects PWNKIT_EVM_VERIFY truthiness (mirrors archetypeSweepEnabled)", () => {
    for (const off of ["", "0", "false", "no"]) {
      process.env.PWNKIT_EVM_VERIFY = off;
      expect(evmVerifyEnabled()).toBe(false);
    }
    for (const on of ["1", "true", "yes"]) {
      process.env.PWNKIT_EVM_VERIFY = on;
      expect(evmVerifyEnabled()).toBe(true);
    }
  });

  it("forgeAvailable requires both the gate ON and a fork RPC", () => {
    process.env.PWNKIT_EVM_VERIFY = "1";
    expect(forgeAvailable()).toBe(false); // no RPC yet
    process.env.PWNKIT_EVM_FORK_RPC = "https://rpc.example/archive";
    expect(forgeAvailable()).toBe(true);
    expect(evmForkRpc()).toBe("https://rpc.example/archive");
  });
});

describe("planEvmVerify", () => {
  const req: EvmVerifyRequest = {
    targetRepo: "/tmp/target",
    testSource: "contract T {}",
    forkUrl: "https://rpc.example/archive",
    forkBlock: 20_000_000,
    testContract: "PwnkitExploit",
  };

  it("assembles a normalized forge invocation but does NOT need the gate on (force)", () => {
    const { plan, warnings } = planEvmVerify({ ...req, force: true });
    expect(plan).toBeDefined();
    expect(plan!.command).toContain("forge test");
    expect(plan!.argv).toContain("--json");
    expect(plan!.argv).toContain("--fork-url");
    expect(plan!.argv).toContain("--fork-block-number");
    expect(plan!.argv).toContain("20000000");
    expect(plan!.argv).toContain("--match-contract");
    expect(plan!.argv).toContain("PwnkitExploit");
    expect(plan!.cacheKey).toMatch(/^evm-/);
    expect(warnings).toHaveLength(0);
  });

  it("warns (but still plans) when the gate is off — like planArchetypeSweep", () => {
    delete process.env.PWNKIT_EVM_VERIFY;
    const { plan, warnings } = planEvmVerify(req);
    expect(plan).toBeDefined();
    expect(warnings.some((w) => /PWNKIT_EVM_VERIFY/.test(w))).toBe(true);
  });

  it("omits the plan and warns when no fork RPC is resolvable", () => {
    const { plan, warnings } = planEvmVerify({
      targetRepo: "/tmp/t",
      testSource: "x",
      force: true,
    });
    expect(plan).toBeUndefined();
    expect(warnings.some((w) => /fork RPC/i.test(w))).toBe(true);
  });

  it("warns about an unpinned fork block (non-reproducible proof)", () => {
    const { plan, warnings } = planEvmVerify({
      targetRepo: "/tmp/t",
      testSource: "x",
      forkUrl: "https://rpc.example/archive",
      force: true,
    });
    expect(plan).toBeDefined();
    expect(plan!.argv).not.toContain("--fork-block-number");
    expect(warnings.some((w) => /forkBlock|reproducible/i.test(w))).toBe(true);
  });

  it("routes the forge command at a local node when useAnvil is set", () => {
    const { plan } = planEvmVerify({ ...req, useAnvil: true, force: true });
    expect(plan!.useAnvil).toBe(true);
    expect(plan!.forkUrl).toContain("127.0.0.1");
  });
});

describe("runEvmVerify (default-safe gate)", () => {
  const saved = process.env.PWNKIT_EVM_VERIFY;
  afterEach(() => {
    if (saved === undefined) delete process.env.PWNKIT_EVM_VERIFY;
    else process.env.PWNKIT_EVM_VERIFY = saved;
  });

  it("is a no-op that never runs when the gate is off", async () => {
    delete process.env.PWNKIT_EVM_VERIFY;
    const result = await runEvmVerify({
      targetRepo: "/tmp/t",
      testSource: "contract T {}",
      forkUrl: "https://rpc.example/archive",
      forkBlock: 1,
    });
    expect(result.status).toBe("skipped");
    expect(result.ran).toBe(false);
  });

  it("returns an honest harness_failed (not a fake proven) when gated on but exec is stubbed", async () => {
    const result = await runEvmVerify({
      targetRepo: "/tmp/t",
      testSource: "contract T {}",
      forkUrl: "https://rpc.example/archive",
      forkBlock: 1,
      force: true,
    });
    expect(result.status).toBe("harness_failed");
    expect(result.ran).toBe(false);
    expect(result.reason).toMatch(/not implemented/i);
    expect(result.cacheKey).toMatch(/^evm-/);
  });
});
