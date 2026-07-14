/**
 * checker-synthesis: the self-validating loop.
 *
 * Every I/O boundary is injected (fake git returning known pre/post images,
 * fake LLM runtime, fake grep, real temp file for the sweep), so the loop runs
 * fully offline. Asserts the three load-bearing properties:
 *   (a) a checker is synthesized from a fix,
 *   (b) self-validation REJECTS a checker that doesn't flag its seed and ACCEPTS
 *       one that flags the pre-image + is silent on the post-fix image,
 *   (c) the sweep→verify composition is invoked (composeGate short-circuits).
 */
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import {
  evaluateChecker,
  selfValidateChecker,
  synthesizeChecker,
  synthesizeValidatedChecker,
  sweepCheckerForSiblings,
  runCheckerVariantHunt,
  type CheckerGit,
  type CheckerRuntime,
  type CheckerSeed,
  type SynthesizedChecker,
} from "./checker-synthesis.js";
import type { HuntScanOptions, HuntScanResult, HuntVerifier } from "../stages/hunt-scan.js";

// ── Fixtures: a length-controlled copy fixed by adding a bound ────────────────

const SEED: CheckerSeed = { fixSha: "deadbeefcafe", subject: "foo: bound skb->len before copy" };
const FIXED_FILE = "net/foo/bar.c";

const PRE_IMAGE = `int foo_read(struct sk_buff *skb, u8 *dst) {
\tmemcpy(dst, skb->data, skb->len);
\treturn 0;
}
`;
const POST_IMAGE = `int foo_read(struct sk_buff *skb, u8 *dst) {
\tif (skb->len > FOO_MAX)
\t\treturn -EINVAL;
\tmemcpy(dst, skb->data, skb->len);
\treturn 0;
}
`;

const GOOD_CHECKER_INPUT = {
  bugClass: "missing length bound before a length-controlled copy",
  invariant: "a skb->len upper bound must precede the memcpy that uses it",
  sinkPattern: "memcpy\\([^,]+,[^,]+,[^)]*->len\\)",
  guardPattern: "if \\([^)]*->len",
  guardWindow: 8,
};
const BAD_CHECKER_INPUT = {
  ...GOOD_CHECKER_INPUT,
  // Sink that never matches the seed → cannot flag the pre-image → must reject.
  sinkPattern: "never_matches_xyzzy_sink",
};

/** Fake git: `<sha>^` → pre-image, `<sha>` → post-image, for the one fixed file. */
function fakeGit(): CheckerGit {
  return {
    show(_tree, ref, path) {
      if (path !== FIXED_FILE) return undefined;
      if (ref === `${SEED.fixSha}^`) return PRE_IMAGE;
      if (ref === SEED.fixSha) return POST_IMAGE;
      return undefined;
    },
    diff: () => "--- a/net/foo/bar.c\n+++ b/net/foo/bar.c\n@@ guard added @@\n",
    files: () => [FIXED_FILE],
  };
}

function runtimeEmitting(...inputs: object[]): CheckerRuntime {
  const emit = vi.fn();
  for (const input of inputs) {
    emit.mockResolvedValueOnce({
      content: [{ type: "tool_use", name: "emit_checker", input }],
    });
  }
  return { executeNative: (...a: unknown[]) => emit(...a) };
}

// ── (a) synthesis ─────────────────────────────────────────────────────────────

describe("synthesizeChecker", () => {
  it("emits a checker from a fix diff + pre-image (one executeNative call)", async () => {
    const checker = await synthesizeChecker({
      seed: SEED,
      diff: "diff",
      preImages: [{ path: FIXED_FILE, content: PRE_IMAGE }],
      runtime: runtimeEmitting(GOOD_CHECKER_INPUT),
    });
    expect(checker).not.toBeNull();
    expect(checker!.sinkPattern).toBe(GOOD_CHECKER_INPUT.sinkPattern);
    expect(checker!.guardPattern).toBe(GOOD_CHECKER_INPUT.guardPattern);
    expect(checker!.id).toMatch(/^chk-[0-9a-f]{16}$/);
    expect(checker!.validation.accepted).toBe(false); // not validated yet
  });

  it("returns null when the model emits no usable checker", async () => {
    const rt: CheckerRuntime = { executeNative: async () => ({ content: [{ type: "text", text: "no" }] }) };
    const checker = await synthesizeChecker({ seed: SEED, diff: "d", preImages: [], runtime: rt });
    expect(checker).toBeNull();
  });
});

// ── evaluateChecker: the pure invariant matcher ───────────────────────────────

describe("evaluateChecker", () => {
  it("flags a sink with no guard in window; is silent when the guard is present", () => {
    const checker = { ...GOOD_CHECKER_INPUT };
    expect(evaluateChecker(checker, FIXED_FILE, PRE_IMAGE)).toHaveLength(1);
    expect(evaluateChecker(checker, FIXED_FILE, POST_IMAGE)).toHaveLength(0);
  });

  it("an out-of-window guard does NOT suppress the flag", () => {
    const narrow = { ...GOOD_CHECKER_INPUT, guardWindow: 1 };
    // Guard is 2 lines above the sink in POST_IMAGE; window 1 can't see it.
    expect(evaluateChecker(narrow, FIXED_FILE, POST_IMAGE)).toHaveLength(1);
  });
});

// ── (b) self-validation accept/reject ─────────────────────────────────────────

describe("selfValidateChecker", () => {
  const mkChecker = (input: typeof GOOD_CHECKER_INPUT): SynthesizedChecker => ({
    id: "chk-test",
    ...input,
    seed: SEED,
    validation: { accepted: false, preImageFlags: 0, postImageFlags: 0, seedFiles: [], reason: "" },
  });

  it("ACCEPTS a checker that flags the pre-image and is silent post-fix", () => {
    const v = selfValidateChecker(mkChecker(GOOD_CHECKER_INPUT), "/t", [FIXED_FILE], fakeGit());
    expect(v.accepted).toBe(true);
    expect(v.preImageFlags).toBe(1);
    expect(v.postImageFlags).toBe(0);
    expect(v.seedFiles).toEqual([FIXED_FILE]);
  });

  it("REJECTS a checker that fails to flag its own seed (preImageFlags === 0)", () => {
    const v = selfValidateChecker(mkChecker(BAD_CHECKER_INPUT), "/t", [FIXED_FILE], fakeGit());
    expect(v.accepted).toBe(false);
    expect(v.preImageFlags).toBe(0);
    expect(v.reason).toMatch(/does not flag its own seed/);
  });

  it("REJECTS an over-broad checker that still fires on the post-fix image", () => {
    // A guard pattern that never matches → post-image sink stays 'unguarded'.
    const v = selfValidateChecker(
      mkChecker({ ...GOOD_CHECKER_INPUT, guardPattern: "no_such_guard_zzz" }),
      "/t",
      [FIXED_FILE],
      fakeGit(),
    );
    expect(v.accepted).toBe(false);
    expect(v.postImageFlags).toBeGreaterThan(0);
    expect(v.reason).toMatch(/still fires/);
  });
});

describe("synthesizeValidatedChecker — retry loop", () => {
  it("rejects the first (bad) checker and accepts the regenerated good one", async () => {
    const deps = { git: fakeGit(), runtime: runtimeEmitting(BAD_CHECKER_INPUT, GOOD_CHECKER_INPUT) };
    const res = await synthesizeValidatedChecker(SEED, "/t", { deps });
    expect(res.checker).not.toBeNull();
    expect(res.checker!.validation.accepted).toBe(true);
    expect(res.attempts).toBe(2);
    expect(res.rejections).toHaveLength(1); // the first attempt's rejection reason
    expect(res.rejections[0]).toMatch(/does not flag its own seed/);
  });

  it("returns null when no attempt validates within the budget", async () => {
    const deps = { git: fakeGit(), runtime: runtimeEmitting(BAD_CHECKER_INPUT, BAD_CHECKER_INPUT) };
    const res = await synthesizeValidatedChecker(SEED, "/t", { maxAttempts: 2, deps });
    expect(res.checker).toBeNull();
    expect(res.attempts).toBe(2);
    expect(res.rejections).toHaveLength(2);
  });
});

// ── (c) sweep → verify composition ────────────────────────────────────────────

describe("sweep + runCheckerVariantHunt (composeGate)", () => {
  let tree: string;
  const SIBLING = "net/foo/baz.c";

  const validatedChecker: SynthesizedChecker = {
    id: "chk-sweep",
    ...GOOD_CHECKER_INPUT,
    seed: SEED,
    validation: { accepted: true, preImageFlags: 1, postImageFlags: 0, seedFiles: [FIXED_FILE], reason: "ok" },
  };

  beforeAll(() => {
    tree = mkdtempSync(join(tmpdir(), "chk-sweep-"));
    mkdirSync(join(tree, "net/foo"), { recursive: true });
    // A sibling with the SAME unguarded sink the fix never touched.
    writeFileSync(join(tree, SIBLING), PRE_IMAGE, "utf8");
  });
  afterAll(() => rmSync(tree, { recursive: true, force: true }));

  const sweepDeps = () => ({
    // Seed fixed file is excluded; grep prefilter returns the sibling.
    git: { ...fakeGit(), files: () => [FIXED_FILE] } as CheckerGit,
    grepFiles: () => [FIXED_FILE, SIBLING], // FIXED_FILE must be excluded by the sweep
    weggliAvailable: () => false,
  });

  it("surfaces the sibling and excludes the seed's fixed file", () => {
    const hits = sweepCheckerForSiblings(validatedChecker, tree, { deps: sweepDeps() });
    expect(hits.map((h) => h.file)).toEqual([SIBLING]);
    expect(hits[0].line).toBe(2);
  });

  it("composes the gate via composeGate and invokes runHunt with the sweep candidates", async () => {
    const stageA = vi.fn<HuntVerifier>().mockResolvedValue({ confirmed: true, reason: "A ok" });
    const stageB = vi.fn<HuntVerifier>().mockResolvedValue({ confirmed: true, reason: "B ok" });

    let captured: HuntScanOptions | undefined;
    const runHunt = vi.fn(async (opts: HuntScanOptions): Promise<HuntScanResult> => {
      captured = opts;
      return { candidates: [], confirmed: [], scanned: 0 } as unknown as HuntScanResult;
    });

    const result = await runCheckerVariantHunt({
      tree,
      checker: validatedChecker,
      runtime: "api",
      gate: [stageA, stageB],
      sweep: { deps: sweepDeps() },
      runHunt,
    });

    expect(result).not.toBeNull();
    expect(runHunt).toHaveBeenCalledOnce();
    expect(captured!.candidates.map((c) => c.path)).toEqual([SIBLING]);
    expect(captured!.brief?.bugClass).toBe(GOOD_CHECKER_INPUT.bugClass);
    expect(captured!.verify).toBeDefined();

    // Drive the composed verifier: composeGate runs A then B (both confirm).
    const pass = await captured!.verify!({} as never, { path: SIBLING });
    expect(pass.confirmed).toBe(true);
    expect(stageA).toHaveBeenCalledOnce();
    expect(stageB).toHaveBeenCalledOnce();

    // composeGate short-circuits: when A rejects, B is never consulted.
    stageA.mockResolvedValueOnce({ confirmed: false, reason: "A refute" });
    const fail = await captured!.verify!({} as never, { path: SIBLING });
    expect(fail.confirmed).toBe(false);
    expect(stageB).toHaveBeenCalledOnce(); // still 1 — not called again
  });

  it("returns null when the sweep finds no siblings", async () => {
    const runHunt = vi.fn();
    const result = await runCheckerVariantHunt({
      tree,
      checker: validatedChecker,
      runtime: "api",
      sweep: { deps: { ...sweepDeps(), grepFiles: () => [] } },
      runHunt: runHunt as never,
    });
    expect(result).toBeNull();
    expect(runHunt).not.toHaveBeenCalled();
  });
});
