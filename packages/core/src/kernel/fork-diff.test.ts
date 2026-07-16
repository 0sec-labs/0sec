/**
 * fork-diff (Engine F): vendor/downstream fork bug-diff.
 *
 * Every I/O boundary is injected — a fake ForkTreeIo (known file lists +
 * contents), the fake checker-synthesis git + LLM runtime, and an injected
 * runHunt — so the whole stage runs offline. Asserts the load-bearing
 * properties of both halves:
 *   HALF 1 (missing-backport): a mainline-validated checker that STILL FIRES on
 *     the vendor copy of the fixed file is a backport gap; it's silent when the
 *     vendor took the guard, and absent when the vendor doesn't ship the file.
 *   HALF 2 (vendor-only-code): the set/text diff surfaces vendor-only files +
 *     vendor-added functions as candidates, and the hunt composes them through
 *     composeGate (short-circuiting) and runs against the VENDOR tree.
 */
import { describe, expect, it, vi } from "vitest";

import {
  checkVendorForMissingBackport,
  huntMissingBackports,
  missingBackportHitToFinding,
  extractFunctionDefs,
  enumerateVendorOnlyFiles,
  enumerateVendorAddedFunctions,
  computeVendorForkDiff,
  runVendorForkDiffHunt,
  type ForkTreeIo,
  type MissingBackportHit,
} from "./fork-diff.js";
import type { CheckerGit, CheckerRuntime, CheckerSeed, SynthesizedChecker } from "./checker-synthesis.js";
import type { HuntScanOptions, HuntScanResult, HuntVerifier } from "../stages/hunt-scan.js";

// ── Shared fixtures: a length-controlled copy fixed by adding a bound ─────────

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
const BAD_CHECKER_INPUT = { ...GOOD_CHECKER_INPUT, sinkPattern: "never_matches_xyzzy_sink" };

const validatedChecker: SynthesizedChecker = {
  id: "chk-forkdiff",
  ...GOOD_CHECKER_INPUT,
  seed: SEED,
  validation: { accepted: true, preImageFlags: 1, postImageFlags: 0, seedFiles: [FIXED_FILE], reason: "ok" },
};

/** Fake checker git: `<sha>^` → pre-image, `<sha>` → post-image, one fixed file. */
function fakeCheckerGit(): CheckerGit {
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
    emit.mockResolvedValueOnce({ content: [{ type: "tool_use", name: "emit_checker", input }] });
  }
  return { executeNative: (...a: unknown[]) => emit(...a) };
}

/** ForkTreeIo backed by an in-memory {tree: {path: content}} map. */
function forkIo(trees: Record<string, Record<string, string>>): ForkTreeIo {
  return {
    listFiles: (tree) => Object.keys(trees[tree] ?? {}),
    readFile: (tree, p) => trees[tree]?.[p],
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// HALF 1 — missing-backport
// ═══════════════════════════════════════════════════════════════════════════

describe("checkVendorForMissingBackport", () => {
  it("flags the vendor file when it lacks the fix's guard (vendor == pre-image)", () => {
    const io = forkIo({ V: { [FIXED_FILE]: PRE_IMAGE } });
    const hits = checkVendorForMissingBackport(validatedChecker, "V", [FIXED_FILE], io);
    expect(hits).toHaveLength(1);
    expect(hits[0].file).toBe(FIXED_FILE);
    expect(hits[0].line).toBe(2);
    expect(hits[0].seedFixSha).toBe(SEED.fixSha);
    expect(hits[0].checkerId).toBe(validatedChecker.id);
  });

  it("is silent when the vendor already has the guard (vendor == post-image)", () => {
    const io = forkIo({ V: { [FIXED_FILE]: POST_IMAGE } });
    expect(checkVendorForMissingBackport(validatedChecker, "V", [FIXED_FILE], io)).toHaveLength(0);
  });

  it("returns nothing when the vendor doesn't ship the fixed file", () => {
    const io = forkIo({ V: {} });
    expect(checkVendorForMissingBackport(validatedChecker, "V", [FIXED_FILE], io)).toHaveLength(0);
  });
});

describe("huntMissingBackports", () => {
  it("synthesizes+validates a mainline checker and finds a vendor backport gap", async () => {
    const io = forkIo({ V: { [FIXED_FILE]: PRE_IMAGE } });
    const res = await huntMissingBackports({
      mainlineTree: "ML",
      vendorTree: "V",
      seeds: [SEED],
      checkerDeps: { git: fakeCheckerGit(), runtime: runtimeEmitting(GOOD_CHECKER_INPUT) },
      io,
    });
    expect(res.checkersValidated).toBe(1);
    expect(res.gapsFound).toBe(1);
    expect(res.entries[0].checker?.validation.accepted).toBe(true);
    expect(res.entries[0].hits[0].file).toBe(FIXED_FILE);
  });

  it("records a rejection and no gap when no checker validates", async () => {
    const io = forkIo({ V: { [FIXED_FILE]: PRE_IMAGE } });
    const res = await huntMissingBackports({
      mainlineTree: "ML",
      vendorTree: "V",
      seeds: [SEED],
      maxAttempts: 2,
      checkerDeps: { git: fakeCheckerGit(), runtime: runtimeEmitting(BAD_CHECKER_INPUT, BAD_CHECKER_INPUT) },
      io,
    });
    expect(res.checkersValidated).toBe(0);
    expect(res.gapsFound).toBe(0);
    expect(res.entries[0].checker).toBeUndefined();
    expect(res.entries[0].rejections.length).toBeGreaterThan(0);
  });
});

describe("missingBackportHitToFinding", () => {
  it("renders a hypothesis-grade review finding", () => {
    const hit: MissingBackportHit = {
      file: FIXED_FILE,
      line: 2,
      snippet: "memcpy(dst, skb->data, skb->len);",
      checkerId: validatedChecker.id,
      bugClass: validatedChecker.bugClass,
      invariant: validatedChecker.invariant,
      seedFixSha: SEED.fixSha,
      seedReference: "CVE-2026-0000",
    };
    const f = missingBackportHitToFinding(hit);
    expect(f.title).toContain("vendor missing backport");
    expect(f.fingerprint).toBe(`backport:${validatedChecker.id}:${FIXED_FILE}:2`);
    expect(f.evidence.analysis).toContain("Source: fork-diff (missing-backport)");
    expect(f.confidence).toBe(0.5);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// HALF 2 — vendor-only-code
// ═══════════════════════════════════════════════════════════════════════════

describe("extractFunctionDefs", () => {
  it("extracts column-0 definitions and skips prototypes, calls, and control statements", () => {
    const src = `int shared_a(void)
{
\tif (x) {
\t\tshared_a();
\t}
\treturn 0;
}
static void vendor_added_fn(struct x *p);
static void vendor_added_fn(struct x *p)
{
}
`;
    const names = extractFunctionDefs(src).map((d) => d.name);
    expect(names).toContain("shared_a");
    expect(names).toContain("vendor_added_fn");
    expect(names).not.toContain("if");
  });
});

describe("enumerateVendorOnlyFiles", () => {
  it("returns files present in vendor but absent from mainline", () => {
    expect(enumerateVendorOnlyFiles(["a.c", "b.c"], ["a.c", "b.c", "vendor.c"])).toEqual(["vendor.c"]);
  });
});

describe("enumerateVendorAddedFunctions", () => {
  it("returns functions defined in the vendor copy but not in mainline", () => {
    const mainline = `int shared_a(void)\n{\n\treturn 0;\n}\n`;
    const vendor = `int shared_a(void)\n{\n\treturn 0;\n}\nint vendor_extra(void)\n{\n\treturn 1;\n}\n`;
    const added = enumerateVendorAddedFunctions("drivers/x/shared.c", mainline, vendor);
    expect(added).toHaveLength(1);
    expect(added[0].name).toBe("vendor_extra");
    expect(added[0].file).toBe("drivers/x/shared.c");
  });
});

describe("computeVendorForkDiff", () => {
  const SHARED = "drivers/x/shared.c";
  const VENDOR_ONLY = "drivers/vendor/only.c";
  const mainlineShared = `int shared_a(void)\n{\n\treturn 0;\n}\n`;
  const vendorShared = `int shared_a(void)\n{\n\treturn 0;\n}\nint vendor_extra(void)\n{\n\treturn 1;\n}\n`;
  const vendorOnly = `int vendor_only_fn(void)\n{\n\treturn 0;\n}\n`;

  const io = forkIo({
    ML: { [SHARED]: mainlineShared },
    V: { [SHARED]: vendorShared, [VENDOR_ONLY]: vendorOnly },
  });

  it("surfaces vendor-only files + vendor-added functions as candidates", () => {
    const diff = computeVendorForkDiff({ mainlineTree: "ML", vendorTree: "V", io });
    expect(diff.vendorOnlyFiles).toEqual([VENDOR_ONLY]);
    expect(diff.vendorAddedFunctions.map((f) => f.name)).toEqual(["vendor_extra"]);
    expect(diff.candidates).toHaveLength(2);
    expect(diff.candidates[0].path).toBe(VENDOR_ONLY);
    expect(diff.candidates[0].hint).toContain("VENDOR-ONLY FILE");
    expect(diff.candidates[1].path).toBe(SHARED);
    expect(diff.candidates[1].hint).toContain("VENDOR-ADDED FUNCTION");
    expect(diff.brief.bugClass).toContain("vendor-introduced");
  });

  it("respects includeAddedFunctions=false (vendor-only files only)", () => {
    const diff = computeVendorForkDiff({
      mainlineTree: "ML",
      vendorTree: "V",
      io,
      includeAddedFunctions: false,
    });
    expect(diff.vendorAddedFunctions).toHaveLength(0);
    expect(diff.candidates.map((c) => c.path)).toEqual([VENDOR_ONLY]);
  });
});

describe("runVendorForkDiffHunt (composeGate)", () => {
  const io = forkIo({
    ML: { "shared.c": "int a(void)\n{\n\treturn 0;\n}\n" },
    V: { "shared.c": "int a(void)\n{\n\treturn 0;\n}\n", "vendor.c": "int v(void)\n{\n\treturn 0;\n}\n" },
  });

  it("computes the diff and hunts vendor candidates through the composed gate on the VENDOR tree", async () => {
    const stageA = vi.fn<HuntVerifier>().mockResolvedValue({ confirmed: true, reason: "A ok" });
    const stageB = vi.fn<HuntVerifier>().mockResolvedValue({ confirmed: true, reason: "B ok" });

    let captured: HuntScanOptions | undefined;
    const runHunt = vi.fn(async (opts: HuntScanOptions): Promise<HuntScanResult> => {
      captured = opts;
      return { confirmed: [], findings: [] } as unknown as HuntScanResult;
    });

    const result = await runVendorForkDiffHunt({
      mainlineTree: "ML",
      vendorTree: "V",
      runtime: "api",
      gate: [stageA, stageB],
      io,
      runHunt,
    });

    expect(result).not.toBeNull();
    expect(runHunt).toHaveBeenCalledOnce();
    expect(captured!.sourceRoot).toBe("V"); // hunt runs against the vendor tree
    expect(captured!.candidates.map((c) => c.path)).toContain("vendor.c");
    expect(captured!.brief?.bugClass).toContain("vendor-introduced");
    expect(captured!.verify).toBeDefined();

    // composeGate: A then B (both confirm).
    const pass = await captured!.verify!({} as never, { path: "vendor.c" });
    expect(pass.confirmed).toBe(true);
    expect(stageA).toHaveBeenCalledOnce();
    expect(stageB).toHaveBeenCalledOnce();

    // Short-circuit: A rejects → B not consulted again.
    stageA.mockResolvedValueOnce({ confirmed: false, reason: "A refute" });
    const fail = await captured!.verify!({} as never, { path: "vendor.c" });
    expect(fail.confirmed).toBe(false);
    expect(stageB).toHaveBeenCalledOnce();
  });

  it("returns null when the vendor tree adds no code (no candidates)", async () => {
    const sameIo = forkIo({
      ML: { "shared.c": "int a(void)\n{\n\treturn 0;\n}\n" },
      V: { "shared.c": "int a(void)\n{\n\treturn 0;\n}\n" },
    });
    const runHunt = vi.fn();
    const result = await runVendorForkDiffHunt({
      mainlineTree: "ML",
      vendorTree: "V",
      runtime: "api",
      io: sameIo,
      runHunt: runHunt as never,
    });
    expect(result).toBeNull();
    expect(runHunt).not.toHaveBeenCalled();
  });
});
