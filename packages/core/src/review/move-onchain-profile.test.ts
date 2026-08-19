import { describe, it, expect } from "vitest";
import {
  moveOnchainReviewAgentPrompt,
  moveFinderLenses,
  moveVerifyLenses,
} from "./move-onchain-profile.js";

describe("moveOnchainReviewAgentPrompt", () => {
  it("instructs the agent to confirm the tree is a Move tree before doing anything (Step 0)", () => {
    const prompt = moveOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/Step 0/);
    expect(prompt).toMatch(/Move\.toml/);
    expect(prompt).toMatch(/public entry fun/);
    expect(prompt).toMatch(/has key|has store/);
    expect(prompt).toMatch(/TxContext/);
    expect(prompt).toMatch(/object::/);
    expect(prompt).toMatch(/transfer::/);
    // Must explicitly tell the agent to refuse if it's not a Move tree.
    expect(prompt).toMatch(/refuse/i);
    // And name the repo path.
    expect(prompt).toMatch(/\/tmp\/repo/);
  });

  it("maps resources/objects, capabilities, shared objects, coins and arithmetic (Step 1)", () => {
    const prompt = moveOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/AdminCap|OwnerCap|TreasuryCap/);
    expect(prompt).toMatch(/share_object/);
    expect(prompt).toMatch(/Balance<T>|Coin<T>/);
    expect(prompt).toMatch(/object::id\(pool\)|pool_id/);
    expect(prompt).toMatch(/integer_mate|full_math|checked_/);
  });

  it("lists the Move resource/object hypothesis classes (Step 2 taxonomy)", () => {
    const prompt = moveOnchainReviewAgentPrompt("/tmp/repo", []);
    // Object / capability ownership & binding gap — the Cetus / Scallop class.
    expect(prompt).toMatch(/Cetus/);
    expect(prompt).toMatch(/Scallop/);
    expect(prompt).toMatch(/object \/ capability ownership|binding gap/i);
    // Arithmetic overflow / truncation in shared math libs — checked_shlw.
    expect(prompt).toMatch(/checked_shlw/);
    expect(prompt).toMatch(/\$223M/);
    // Uninitialized / reward-index accounting — last_index.
    expect(prompt).toMatch(/last_index/);
    expect(prompt).toMatch(/reward.?index/i);
    // Public-transfer / capability leakage.
    expect(prompt).toMatch(/capability leak/i);
    expect(prompt).toMatch(/public_transfer/);
    // Shared-object consensus race.
    expect(prompt).toMatch(/[Ss]hared-object|consensus race/);
    // init / one-time-witness misuse.
    expect(prompt).toMatch(/one-time-witness|witness/i);
    // Coin / balance conservation.
    expect(prompt).toMatch(/[Cc]oin \/ balance conservation|conservation/);
  });

  it("emits a Move unit test (sui move test / aptos move test) as the PoC form", () => {
    const prompt = moveOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/sui move test/);
    expect(prompt).toMatch(/aptos move test/);
    expect(prompt).toMatch(/test_scenario|#\[test\]/);
  });

  it("carries a false-positive gate that kills the common Move myths", () => {
    const prompt = moveOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/FALSE-POSITIVE GATE/);
    // Capability-gated is NOT a vuln.
    expect(prompt).toMatch(/Capability-gated is NOT a vuln|capability by value or reference/i);
    // The Move VM enforces resource linearity & ownership.
    expect(prompt).toMatch(/resource linearity/i);
    // abort reverts => unchecked-return idioms don't apply.
    expect(prompt).toMatch(/ABORT-on-failure|abort.{0,30}revert/i);
    // Native + - * abort on overflow; the real class is shifts/casts/unsound checked_*.
    expect(prompt).toMatch(/abort on overflow/i);
    expect(prompt).toMatch(/checked_shlw/);
    // Reward-index initialized correctly.
    expect(prompt).toMatch(/last_index/);
  });

  it("has a mandatory self-check and the save_finding / category / poc_steps contract", () => {
    const prompt = moveOnchainReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/MANDATORY SELF-CHECK/);
    expect(prompt).toMatch(/save_finding/);
    // The category enum must enumerate the taxonomy.
    expect(prompt).toMatch(/object-capability-binding\|math-overflow-truncation\|reward-index-accounting/);
    expect(prompt).toMatch(/capability-leak/);
    expect(prompt).toMatch(/coin-conservation/);
    // poc_steps contract is mandatory.
    expect(prompt).toMatch(/poc_steps/);
    expect(prompt).toMatch(/MANDATORY JSON-encoded PocStep/);
  });

  it("makes the novelty verify lens challenge the capability, overflow and abort premises, not just the code claim", () => {
    const verify = moveVerifyLenses.find((l) => l.id === "novelty-known-issue");
    expect(verify).toBeDefined();
    const hint = verify!.challengeHint;
    expect(hint).toMatch(/PREMISE REFUTATION/);
    // Capability argument already proves auth — refute unless leaked/unbound/forgeable.
    expect(hint).toMatch(/&AdminCap/);
    expect(hint).toMatch(/LEAKED/);
    // Native arithmetic aborts on overflow — refute unless shift/cast/unsound checked_*.
    expect(hint).toMatch(/ABORTS? on overflow/i);
    expect(hint).toMatch(/checked_shlw/);
    // abort => a bad input that aborts is a self-revert, not profit.
    expect(hint).toMatch(/self-revert/i);
    // Anti-over-suppression: don't refute merely on uncertainty.
    expect(hint).toMatch(/unsure/i);
  });

  it("carries the object-binding + math-overflow + reward-index finder lenses", () => {
    const bind = moveFinderLenses.find((l) => l.id === "object-capability-binding");
    expect(bind?.challengeHint).toMatch(/Cetus|Scallop|object::id\(pool\)|pool_id/);
    const math = moveFinderLenses.find((l) => l.id === "math-overflow-truncation");
    expect(math?.challengeHint).toMatch(/checked_shlw|\$223M/);
    const reward = moveFinderLenses.find((l) => l.id === "reward-index-accounting");
    expect(reward?.challengeHint).toMatch(/last_index/);
  });

  it("threads the operator hypothesis into a primary-direction block when provided", () => {
    const prompt = moveOnchainReviewAgentPrompt("/tmp/repo", [], "look at the close_position pool binding");
    expect(prompt).toMatch(/OPERATOR HYPOTHESIS/);
    expect(prompt).toMatch(/look at the close_position pool binding/);
  });

  it("renders static scanner leads when provided", () => {
    const prompt = moveOnchainReviewAgentPrompt("/tmp/repo", [
      {
        ruleId: "move-seed.binding.position-pool-unbound",
        message: "Position object not bound to Pool ID before redemption",
        severity: "high",
        path: "sources/pool.move",
        startLine: 120,
        endLine: 120,
        snippet: "public entry fun close_position(pool: &mut Pool, position: Position, ctx: &mut TxContext) {",
      },
    ]);
    expect(prompt).toMatch(/move-seed\.binding\.position-pool-unbound/);
    expect(prompt).toMatch(/sources\/pool\.move:120/);
  });
});
