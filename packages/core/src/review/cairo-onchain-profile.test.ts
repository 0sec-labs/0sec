import { describe, it, expect } from "vitest";
import {
  cairoOnchainReviewAgentPrompt,
  cairoFinderLenses,
  cairoVerifyLenses,
} from "./cairo-onchain-profile.js";

describe("cairoOnchainReviewAgentPrompt", () => {
  it("instructs the agent to confirm the tree is a Cairo/Starknet tree before doing anything (Step 0)", () => {
    const prompt = cairoOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/Step 0/);
    expect(prompt).toMatch(/Scarb\.toml/);
    expect(prompt).toMatch(/#\[starknet::contract\]/);
    expect(prompt).toMatch(/#\[storage\]/);
    expect(prompt).toMatch(/#\[external\(v0\)\]/);
    expect(prompt).toMatch(/ContractAddress/);
    expect(prompt).toMatch(/felt252/);
    // Must explicitly tell the agent to refuse if it's not a Cairo tree.
    expect(prompt).toMatch(/refuse/i);
    // And name the repo path.
    expect(prompt).toMatch(/\/tmp\/repo/);
  });

  it("maps the storage, caller, external-call, L1↔L2 and price surfaces (Step 1)", () => {
    const prompt = cairoOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/get_caller_address/);
    expect(prompt).toMatch(/call_contract_syscall|call_contract/);
    expect(prompt).toMatch(/l1_handler/);
    expect(prompt).toMatch(/from_address/);
    expect(prompt).toMatch(/Map|LegacyMap/);
    expect(prompt).toMatch(/assert_only_owner/);
  });

  it("lists the Cairo/Starknet hypothesis classes (Step 2 taxonomy)", () => {
    const prompt = cairoOnchainReviewAgentPrompt("/tmp/repo", []);
    // Caller / ownership auth gap.
    expect(prompt).toMatch(/[Cc]aller \/ ownership authorization gap|caller assertion/);
    expect(prompt).toMatch(/get_caller_address\(\) == self\.owner/);
    // Fixed-point / share-conversion rounding — the zkLend / Vesu class.
    expect(prompt).toMatch(/zkLend|Vesu/);
    expect(prompt).toMatch(/to_shares|to_assets|convert_to_shares/);
    // Reentrancy via call_contract.
    expect(prompt).toMatch(/[Rr]eentrancy/);
    // Storage-slot / mapping default-value trust.
    expect(prompt).toMatch(/default-value trust|default/i);
    // Unchecked external-call result.
    expect(prompt).toMatch(/[Uu]nchecked external-call/);
    // L1↔L2 message / l1_handler.
    expect(prompt).toMatch(/L1↔L2|l1_handler/);
    // Oracle staleness.
    expect(prompt).toMatch(/[Oo]racle stale|last_updated_timestamp/);
  });

  it("emits a starknet-foundry (snforge) test as the PoC form", () => {
    const prompt = cairoOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/starknet-foundry/);
    expect(prompt).toMatch(/snforge/);
    // Cairo unit test fallback is named.
    expect(prompt).toMatch(/#\[cfg\(test\)\]/);
  });

  it("carries a false-positive gate that kills the common Cairo myths", () => {
    const prompt = cairoOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/FALSE-POSITIVE GATE/);
    // Auth already asserted / OZ component.
    expect(prompt).toMatch(/assert_only_owner|Ownable/);
    // assert/panic reverts => unchecked-return idioms don't apply (reject-vs-clamp).
    expect(prompt).toMatch(/reject-vs-clamp|REJECT-on-failure/i);
    expect(prompt).toMatch(/panic/);
    // u256/u128 overflow already traps; felt252 wraps mod p.
    expect(prompt).toMatch(/u256|u128/);
    expect(prompt).toMatch(/felt252/);
    // Oracle fresh-by-construction.
    expect(prompt).toMatch(/fresh-by-construction/);
    // Storage default initialized/guarded.
    expect(prompt).toMatch(/is_initialized|initialized/);
  });

  it("has a mandatory self-check and the save_finding / category / poc_steps contract", () => {
    const prompt = cairoOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/MANDATORY SELF-CHECK/);
    expect(prompt).toMatch(/save_finding/);
    // The category enum must enumerate the taxonomy.
    expect(prompt).toMatch(/caller-auth\|share-rounding\|reentrancy/);
    expect(prompt).toMatch(/l1-l2-message/);
    expect(prompt).toMatch(/oracle-staleness/);
    // poc_steps contract is mandatory.
    expect(prompt).toMatch(/poc_steps/);
    expect(prompt).toMatch(/MANDATORY JSON-encoded PocStep/);
  });

  it("makes the novelty verify lens challenge the reject-vs-clamp and oracle premises, not just the code claim", () => {
    const verify = cairoVerifyLenses.find((l) => l.id === "novelty-known-issue");
    expect(verify).toBeDefined();
    const hint = verify!.challengeHint;
    expect(hint).toMatch(/PREMISE REFUTATION/);
    // Starknet reject-on-failure: an input that merely panics is a self-revert.
    expect(hint).toMatch(/REJECT-on-failure|self-inflicted revert|self-revert/i);
    expect(hint).toMatch(/AFFIRMATIVELY swallows/);
    // Oracle source-type resolution.
    expect(hint).toMatch(/computed-live|fresh-by-construction/i);
    expect(hint).toMatch(/PUSH feed/i);
    // Anti-over-suppression: don't refute merely on uncertainty.
    expect(hint).toMatch(/unsure/i);
  });

  it("carries the caller-auth + share-rounding + l1-l2 finder lenses", () => {
    expect(cairoFinderLenses.find((l) => l.id === "caller-auth-reentrancy")).toBeDefined();
    const share = cairoFinderLenses.find((l) => l.id === "share-rounding-arithmetic");
    expect(share?.challengeHint).toMatch(/zkLend|Vesu|to_shares/);
    const l1 = cairoFinderLenses.find((l) => l.id === "l1-l2-message");
    expect(l1?.challengeHint).toMatch(/from_address/);
  });

  it("threads the operator hypothesis into a primary-direction block when provided", () => {
    const prompt = cairoOnchainReviewAgentPrompt("/tmp/repo", [], "look at the l1_handler mint path");
    expect(prompt).toMatch(/OPERATOR HYPOTHESIS/);
    expect(prompt).toMatch(/look at the l1_handler mint path/);
  });

  it("renders static scanner leads when provided", () => {
    const prompt = cairoOnchainReviewAgentPrompt("/tmp/repo", [
      {
        ruleId: "cairo-seed.caller.no-owner-assert",
        message: "state-changing entrypoint without get_caller_address assertion",
        severity: "high",
        path: "src/vault.cairo",
        startLine: 88,
        endLine: 88,
        snippet: "fn withdraw(ref self: ContractState, amount: u256) {",
      },
    ]);
    expect(prompt).toMatch(/cairo-seed\.caller\.no-owner-assert/);
    expect(prompt).toMatch(/src\/vault\.cairo:88/);
  });
});
