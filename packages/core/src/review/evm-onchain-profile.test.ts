import { describe, it, expect } from "vitest";
import {
  evmOnchainReviewAgentPrompt,
  evmFinderLenses,
  evmVerifyLenses,
} from "./evm-onchain-profile.js";

describe("evmOnchainReviewAgentPrompt", () => {
  it("instructs the agent to confirm the tree is an EVM/Solidity tree before doing anything (Step 0)", () => {
    const prompt = evmOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/Step 0/);
    expect(prompt).toMatch(/foundry\.toml/);
    expect(prompt).toMatch(/hardhat\.config/);
    expect(prompt).toMatch(/pragma solidity/);
    expect(prompt).toMatch(/OpenZeppelin/);
    // Must explicitly tell the agent to refuse if it's not an EVM tree.
    expect(prompt).toMatch(/refuse/i);
    // And name the repo path.
    expect(prompt).toMatch(/\/tmp\/repo/);
  });

  it("maps the external-call, privileged, price, upgrade and cross-chain surfaces (Step 1)", () => {
    const prompt = evmOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/\.call\{value:\}|call\{value:/);
    expect(prompt).toMatch(/delegatecall/);
    expect(prompt).toMatch(/onlyOwner/);
    expect(prompt).toMatch(/getReserves/);
    expect(prompt).toMatch(/lzReceive/);
    expect(prompt).toMatch(/initialize/);
  });

  it("lists the EVM DeFi/bridge hypothesis classes (Step 2 taxonomy)", () => {
    const prompt = evmOnchainReviewAgentPrompt("/tmp/repo", []);
    // Reentrancy — all four flavors.
    expect(prompt).toMatch(/Reentrancy/i);
    expect(prompt).toMatch(/cross-function/i);
    expect(prompt).toMatch(/read-only/i);
    expect(prompt).toMatch(/cross-contract/i);
    // Access control / init front-run.
    expect(prompt).toMatch(/Access control|missing-auth/i);
    expect(prompt).toMatch(/front-run/i);
    // Oracle / price manipulation.
    expect(prompt).toMatch(/[Oo]racle/);
    expect(prompt).toMatch(/TWAP/);
    // Rounding / first-depositor inflation.
    expect(prompt).toMatch(/first-depositor|share inflation/i);
    expect(prompt).toMatch(/ERC4626/);
    // Signature / permit / EIP-712 replay.
    expect(prompt).toMatch(/EIP-712/);
    expect(prompt).toMatch(/permit/);
    // Cross-chain — first-class high-value class.
    expect(prompt).toMatch(/[Cc]ross-chain/);
    expect(prompt).toMatch(/source.?chain.?id/i);
    expect(prompt).toMatch(/nonce/);
    // Delegatecall / proxy storage collision.
    expect(prompt).toMatch(/storage.?collision|storage-layout|storage layout/i);
    // Unchecked external-call return.
    expect(prompt).toMatch(/[Uu]nchecked/);
    // MEV / sandwich.
    expect(prompt).toMatch(/MEV|sandwich/i);
    // Unbounded-loop DoS.
    expect(prompt).toMatch(/[Uu]nbounded/);
    expect(prompt).toMatch(/DoS/);
  });

  it("emits a Foundry test as the PoC form", () => {
    const prompt = evmOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/Foundry/);
    expect(prompt).toMatch(/forge test|forge-std/);
  });

  it("carries a false-positive gate that kills the common EVM myths", () => {
    const prompt = evmOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/FALSE-POSITIVE GATE/);
    // CEI / nonReentrant already-guarded.
    expect(prompt).toMatch(/nonReentrant|Checks-Effects-Interactions/);
    // 0.8 checked math.
    expect(prompt).toMatch(/0\.8/);
    // Modifier-gated.
    expect(prompt).toMatch(/modifier/);
    // Robust TWAP already.
    expect(prompt).toMatch(/TWAP/);
    // SafeERC20 already.
    expect(prompt).toMatch(/SafeERC20/);
  });

  it("has a mandatory self-check and the save_finding / category / poc_steps contract", () => {
    const prompt = evmOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/MANDATORY SELF-CHECK/);
    expect(prompt).toMatch(/save_finding/);
    // The category enum must enumerate the taxonomy.
    expect(prompt).toMatch(/reentrancy\|access-control\|oracle-manipulation/);
    expect(prompt).toMatch(/cross-chain-replay/);
    expect(prompt).toMatch(/delegatecall-proxy/);
    // poc_steps contract is mandatory.
    expect(prompt).toMatch(/poc_steps/);
    expect(prompt).toMatch(/MANDATORY JSON-encoded PocStep/);
  });

  it("gates unguarded initializer/reinitializer findings on upgrade atomicity (atomic-upgrade FP gate)", () => {
    const prompt = evmOnchainReviewAgentPrompt("/tmp/repo", []);
    // The atomic-upgrade FP gate must be present in the false-positive section.
    expect(prompt).toMatch(/ATOMIC upgrade/);
    // Names the three closing mechanisms.
    expect(prompt).toMatch(/upgradeAndCall|upgradeToAndCall/);
    expect(prompt).toMatch(/reinitializer\(N\)/);
    expect(prompt).toMatch(/VAA|multicall/);
    expect(prompt).toMatch(/TemporalGovernor/);
    // Only high/critical when impl-swap and init are SEPARATE txs (a real window).
    expect(prompt).toMatch(/SEPARATE/);
    // Encodes the real motivating false positives.
    expect(prompt).toMatch(/Moonwell/);
  });

  it("carries the atomic-upgrade check in the access-control finder lens and novelty verify lens", () => {
    const finder = evmFinderLenses.find((l) => l.id === "access-control-reentrancy");
    expect(finder?.challengeHint).toMatch(/atomic|upgradeAndCall/i);
    const verify = evmVerifyLenses.find((l) => l.id === "novelty-known-issue");
    expect(verify?.challengeHint).toMatch(/ATOMIC upgrade|upgradeAndCall/);
  });

  it("makes the novelty verify lens challenge the oracle-staleness SECURITY PREMISE (push feed vs computed-live rate), not just the code claim", () => {
    const verify = evmVerifyLenses.find((l) => l.id === "novelty-known-issue");
    expect(verify).toBeDefined();
    const hint = verify!.challengeHint;
    // Names the premise-refutation obligation and the source-type distinction.
    expect(hint).toMatch(/PREMISE REFUTATION/);
    expect(hint).toMatch(/push[- ]?feed|push feed/i);
    expect(hint).toMatch(/computed-live|fresh-by-construction/i);
    // Confirming the code claim is explicitly not enough.
    expect(hint).toMatch(/NOT sufficient/);
    // Anti-over-suppression: do not refute merely on uncertainty about the source.
    expect(hint).toMatch(/unsure of the source type/i);
  });

  it("makes the scope verify lens check DEPLOYMENT LIVENESS (test-only/unwired => not HIGH) without over-suppressing", () => {
    const verify = evmVerifyLenses.find((l) => l.id === "scope");
    expect(verify).toBeDefined();
    const hint = verify!.challengeHint;
    expect(hint).toMatch(/DEPLOYMENT LIVENESS/);
    // Names the deploy/wiring surface it must search.
    expect(hint).toMatch(/deploy/i);
    expect(hint).toMatch(/\*\.s\.sol|broadcast|hardhat-deploy/);
    // Test-only / mock => downgrade from HIGH.
    expect(hint).toMatch(/TEST-ONLY|MOCK/);
    // Anti-over-suppression: uncertainty about deployment is NOT grounds to refute.
    expect(hint).toMatch(/uncertain/i);
    expect(hint).toMatch(/over-suppress/i);
  });

  it("makes the scope lens GATE SEVERITY on value-flow reachability: a no-consumer / no-custody HIGH must be refuted (the two Cap FPs)", () => {
    const verify = evmVerifyLenses.find((l) => l.id === "scope");
    expect(verify).toBeDefined();
    const hint = verify!.challengeHint;
    // The gate exists and is framed as a SEVERITY gate, not a mere annotation.
    expect(hint).toMatch(/VALUE-FLOW REACHABILITY GATE/);
    expect(hint).toMatch(/GATES SEVERITY/);
    // The two positive conditions that keep a HIGH: at least one on-chain
    // consumer OR real value custody/routing.
    expect(hint).toMatch(/ON-CHAIN CONSUMER/);
    expect(hint).toMatch(/CUSTODIES OR ROUTES PROTOCOL VALUE/i);
    // The exemplar negatives to refute at HIGH (both Cap FP shapes) are encoded.
    expect(hint).toMatch(/zero-balance pass-through|sweep router/i);
    expect(hint).toMatch(/adapter\/library\/helper with no live consumer|no live consumer/i);
    // The bounty out-of-scope framing for accidental dust.
    expect(hint).toMatch(/dust/i);
    expect(hint).toMatch(/OUT-OF-SCOPE/i);
    // It must REFUTE / force-downgrade such a finding, not just hedge it.
    expect(hint).toMatch(/refute it|force-downgrade/i);
    expect(hint).toMatch(/CANNOT STAND AT HIGH/i);
  });

  it("keeps the value-flow gate fail-closed-safe: refute only on an affirmative negative, never on uncertainty, and a wired component keeps severity", () => {
    const verify = evmVerifyLenses.find((l) => l.id === "scope");
    const hint = verify!.challengeHint;
    // Anti-over-suppression: only an affirmatively-established negative refutes.
    expect(hint).toMatch(/AFFIRMATIVELY-ESTABLISHED negative/i);
    expect(hint).toMatch(/NEVER on mere uncertainty/i);
    // A genuinely-wired HIGH survives — a component with a live consumer or real
    // value flow keeps its severity (protects real bugs from the fail-closed gate).
    expect(hint).toMatch(/KEEPS its severity/i);
    // Must cite concrete evidence of the negative, mirroring 0sec#3's pattern.
    expect(hint).toMatch(/grep .*consumers|came back empty/i);
  });

  it("threads the operator hypothesis into a primary-direction block when provided", () => {
    const prompt = evmOnchainReviewAgentPrompt("/tmp/repo", [], "look at the bridge withdraw handler");
    expect(prompt).toMatch(/OPERATOR HYPOTHESIS/);
    expect(prompt).toMatch(/look at the bridge withdraw handler/);
  });

  it("renders static scanner leads when provided", () => {
    const prompt = evmOnchainReviewAgentPrompt("/tmp/repo", [
      {
        ruleId: "evm-seed.external-call.call-value",
        message: "low-level ETH call",
        severity: "high",
        path: "src/Vault.sol",
        startLine: 42,
        endLine: 42,
        snippet: "(bool ok,) = msg.sender.call{value: amount}(\"\");",
      },
    ]);
    expect(prompt).toMatch(/evm-seed\.external-call\.call-value/);
    expect(prompt).toMatch(/src\/Vault\.sol:42/);
  });
});
