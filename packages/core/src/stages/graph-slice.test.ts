/**
 * graph-slice — the deterministic interprocedural slicer + its seed-diff adapter
 * (`pwnkit hunt --graph-slice`). Proven here against a SYNTHETIC graphson CPG
 * fixture shaped like the bench af_unix `scm_fp_list` proof
 * (bench:/root/graph-lpe/): a use/dispatch site in one file whose object is
 * ALLOCATED and FREED in cross-function, cross-FILE helpers.
 *
 *   (a) Cpg.fromGraphson loads the graphson vertices/edges and builds the
 *       interprocedural call graph (CONTAINS + CALL) and DDG indexes.
 *   (b) findTargets resolves a bare name AND a file:line spec to method ids.
 *   (c) buildSlice from the use site reaches the cross-function alloc + free
 *       sinks (external lifetime primitives are kept); renderSlice emits ONE
 *       compact block naming both cross-file helpers and both source files —
 *       the multi-step chain the flat per-file read structurally cannot see.
 *   (d) injectOps synthesizes an ops-struct indirect-call edge that pulls an
 *       otherwise-unreachable handler into the slice.
 *   (e) buildGraphSliceHuntContext runs end-to-end over a real temp tree
 *       (pre-exported CPG JSON on disk) and fail-opens (null) with no CPG.
 */

import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  Cpg,
  buildSlice,
  findTargets,
  injectOps,
  renderSlice,
  sliceAroundTargets,
} from "./graph-slice.js";
import {
  buildGraphSliceHuntContext,
  extractTouchedFunctions,
  formatGraphSlicePromptBlock,
} from "./graph-slice-hunt-context.js";

// ── Graphson fixture builder ───────────────────────────────────────────────────

/** Wrap a scalar as a Joern vertex-property value (numbers exercise the typed-dict branch). */
function vProp(value: string | number | boolean): unknown {
  const el = typeof value === "number" ? { "@type": "g:Int32", "@value": value } : value;
  return { "@type": "g:VertexProperty", "@value": { "@type": "g:List", "@value": [el] } };
}

function method(
  id: number,
  name: string,
  file: string,
  a: number,
  b: number,
  external = false,
): unknown {
  const props: Record<string, unknown> = {
    NAME: vProp(name),
    FULL_NAME: vProp(name),
    FILENAME: vProp(file),
    LINE_NUMBER: vProp(a),
    LINE_NUMBER_END: vProp(b),
  };
  if (external) props.IS_EXTERNAL = vProp(true);
  return { "@type": "g:Vertex", id: { "@value": id }, label: "METHOD", properties: props };
}

function callNode(id: number, code: string, line: number): unknown {
  return {
    "@type": "g:Vertex",
    id: { "@value": id },
    label: "CALL",
    properties: { CODE: vProp(code), LINE_NUMBER: vProp(line) },
  };
}

function edge(label: string, out: number, inn: number): unknown {
  return { "@type": "g:Edge", label, outV: { "@value": out }, inV: { "@value": inn } };
}

/**
 * The af_unix scm_fp_list lifetime, minimized:
 *   unix_attach_fds (af_unix.c)  --use/dispatch site (slice root)
 *     ├─ calls unix_prepare_fpl (garbage.c)   ──▶ kvmalloc_array   [ALLOC, cross-file]
 *     └─ calls unix_destroy_fpl (garbage.c)   ──▶ kvfree           [FREE,  cross-file]
 *   unix_close (garbage.c)  --reachable ONLY via a synthesized ops edge
 */
function buildFixtureGraphson(): unknown {
  const vertices = [
    method(1, "unix_attach_fds", "net/unix/af_unix.c", 1500, 1560),
    method(2, "unix_prepare_fpl", "net/unix/garbage.c", 272, 298),
    method(3, "unix_destroy_fpl", "net/unix/garbage.c", 300, 307),
    method(4, "kvmalloc_array", "", 0, 0, true),
    method(5, "kvfree", "", 0, 0, true),
    method(6, "unix_close", "net/unix/garbage.c", 400, 420),
    callNode(101, "unix_prepare_fpl(scm, ...)", 1520),
    callNode(102, "kvmalloc_array(count, size, GFP_KERNEL)", 281),
    callNode(103, "unix_destroy_fpl(fpl)", 1540),
    callNode(104, "kvfree(fpl->vertices)", 305),
    callNode(105, "sk->sk_prot->close(sk, 0)", 1550), // DYNAMIC_DISPATCH → ops-resolved
  ];
  const edges = [
    // enclosing method for each call node
    edge("CONTAINS", 1, 101),
    edge("CONTAINS", 2, 102),
    edge("CONTAINS", 1, 103),
    edge("CONTAINS", 3, 104),
    edge("CONTAINS", 1, 105),
    // resolved calls
    edge("CALL", 101, 2),
    edge("CALL", 102, 4),
    edge("CALL", 103, 3),
    edge("CALL", 104, 5),
  ];
  return { "@type": "g:Graph", "@value": { vertices, edges } };
}

function fixtureCpg(): Cpg {
  return Cpg.fromGraphson(buildFixtureGraphson());
}

// ── (a) loader + call graph ─────────────────────────────────────────────────────

describe("Cpg.fromGraphson", () => {
  it("builds the interprocedural call graph from CONTAINS + CALL edges", () => {
    const cpg = fixtureCpg();
    expect(cpg.methods.size).toBe(6);
    expect(cpg.mname(1)).toBe("unix_attach_fds");
    expect(cpg.mfile(2)).toBe("net/unix/garbage.c");
    expect(cpg.isExternal(4)).toBe(true);
    // unix_attach_fds calls unix_prepare_fpl and unix_destroy_fpl
    const callees = cpg.allCallees(1).map(([m]) => cpg.mname(m)).sort();
    expect(callees).toEqual(["unix_destroy_fpl", "unix_prepare_fpl"]);
    // unix_prepare_fpl calls the alloc sink
    expect(cpg.allCallees(2).map(([m]) => cpg.mname(m))).toContain("kvmalloc_array");
  });
});

// ── (b) target resolution ───────────────────────────────────────────────────────

describe("findTargets", () => {
  it("resolves a bare function name to its internal method id", () => {
    const cpg = fixtureCpg();
    expect(findTargets(cpg, "unix_attach_fds")).toEqual([1]);
  });
  it("resolves a file:line spec to the enclosing method", () => {
    const cpg = fixtureCpg();
    // line 285 is inside unix_prepare_fpl (272-298)
    expect(findTargets(cpg, "garbage.c:285")).toEqual([2]);
    // a line outside any method resolves to nothing
    expect(findTargets(cpg, "garbage.c:999")).toEqual([]);
  });
});

// ── (c) the core proof: the slice surfaces the cross-file alloc + free ───────────

describe("buildSlice + renderSlice", () => {
  it("reaches the cross-function alloc and free sinks from the use site", () => {
    const cpg = fixtureCpg();
    const { dist } = buildSlice(cpg, findTargets(cpg, "unix_attach_fds"), 3);
    const reached = new Set([...dist.keys()].map((m) => cpg.mname(m)));
    // both cross-file helpers AND their external lifetime sinks are in the slice
    expect(reached).toContain("unix_prepare_fpl");
    expect(reached).toContain("unix_destroy_fpl");
    expect(reached).toContain("kvmalloc_array");
    expect(reached).toContain("kvfree");
  });

  it("renders one compact block naming both cross-file helpers and both files", () => {
    const cpg = fixtureCpg();
    const slice = buildSlice(cpg, findTargets(cpg, "unix_attach_fds"), 3);
    const { text, stats } = renderSlice(cpg, slice);
    // the alloc + free chain the flat single-file read (af_unix.c only) misses
    expect(text).toContain("kvmalloc_array");
    expect(text).toContain("kvfree");
    // crosses a FILE boundary: both source files appear
    expect(stats.files).toContain("net/unix/af_unix.c");
    expect(stats.files).toContain("net/unix/garbage.c");
    expect(stats.functions).toBeGreaterThanOrEqual(3);
  });
});

// ── (d) Phase-1 ops-struct edge synthesis ───────────────────────────────────────

describe("injectOps", () => {
  it("synthesizes an indirect-call edge that pulls an unreachable handler into the slice", () => {
    const cpg = fixtureCpg();
    // without the ops edge, unix_close is unreachable from unix_attach_fds
    const before = new Set([...buildSlice(cpg, findTargets(cpg, "unix_attach_fds"), 3).dist.keys()]);
    expect([...before].map((m) => cpg.mname(m))).not.toContain("unix_close");

    const added = injectOps(cpg, {
      synth_edges: [{ caller_mid: 1, callee: "unix_close", callnode: 105, field: "close" }],
    });
    expect(added).toBe(1);

    const after = sliceAroundTargets(cpg, ["unix_attach_fds"], { hops: 3 });
    expect(after).not.toBeNull();
    expect(after!.text).toContain("unix_close");
  });
});

// ── (e) the seed-diff adapter, end-to-end + fail-open ────────────────────────────

describe("extractTouchedFunctions", () => {
  it("recovers the function name from a git diff hunk header", () => {
    const diff = [
      "diff --git a/net/unix/af_unix.c b/net/unix/af_unix.c",
      "--- a/net/unix/af_unix.c",
      "+++ b/net/unix/af_unix.c",
      "@@ -1500,7 +1500,8 @@ static int unix_attach_fds(struct scm_cookie *scm, struct sk_buff *skb)",
      "-\told = fpl;",
      "+\tnew = fpl;",
    ].join("\n");
    expect(extractTouchedFunctions(diff)).toEqual(["unix_attach_fds"]);
  });
});

describe("formatGraphSlicePromptBlock", () => {
  it("wraps the slice in a bounded, labeled context block", () => {
    const block = formatGraphSlicePromptBlock(
      "net/unix",
      ["unix_attach_fds"],
      "SLICE_BODY",
      { functions: 3, files: ["a.c", "b.c"], callEdges: 4, chars: 10 },
      2,
    );
    expect(block).toContain("GRAPH REACHABILITY SLICE of net/unix");
    expect(block).toContain("unix_attach_fds");
    expect(block).toContain("2 ops-struct indirect-call edge(s) synthesized");
    expect(block).toContain("SLICE_BODY");
  });
});

describe("buildGraphSliceHuntContext", () => {
  const dirs: string[] = [];
  afterEach(() => {
    // temp dirs are OS-cleaned; nothing durable to remove between tests
    dirs.length = 0;
  });

  function makeTree(): { sourceRoot: string; seedDiff: string } {
    const sourceRoot = mkdtempSync(join(tmpdir(), "graph-slice-"));
    dirs.push(sourceRoot);
    // pre-exported CPG at the conventional path
    const cpgDir = join(sourceRoot, ".pwnkit", "cpg");
    mkdirSync(cpgDir, { recursive: true });
    writeFileSync(join(cpgDir, "net__unix.json"), JSON.stringify(buildFixtureGraphson()));
    // real source files so the renderer can surface path lines
    const unixDir = join(sourceRoot, "net", "unix");
    mkdirSync(unixDir, { recursive: true });
    writeFileSync(join(unixDir, "af_unix.c"), Array(1600).fill("/* line */").join("\n"));
    writeFileSync(join(unixDir, "garbage.c"), Array(320).fill("/* line */").join("\n"));
    const seedDiff = [
      "diff --git a/net/unix/garbage.c b/net/unix/garbage.c",
      "+++ b/net/unix/garbage.c",
      "@@ -1500,6 +1500,7 @@ static int unix_attach_fds(struct scm_cookie *scm, struct sk_buff *skb)",
      "+\t/* fix */",
    ].join("\n");
    return { sourceRoot, seedDiff };
  }

  it("builds the slice context from a pre-exported CPG and injects the cross-file chain", () => {
    const { sourceRoot, seedDiff } = makeTree();
    const ctx = buildGraphSliceHuntContext({ sourceRoot, seedDiff });
    expect(ctx).not.toBeNull();
    expect(ctx!.subsystem).toBe("net/unix");
    expect(ctx!.targetFunctions).toContain("unix_attach_fds");
    expect(ctx!.resolvedTargets).toBe(1);
    expect(ctx!.promptBlock).toContain("kvmalloc_array");
    expect(ctx!.promptBlock).toContain("kvfree");
    expect(ctx!.stats.files).toContain("net/unix/garbage.c");
  });

  it("fail-opens (null) when no CPG export exists for the subsystem", () => {
    const sourceRoot = mkdtempSync(join(tmpdir(), "graph-slice-nocpg-"));
    const seedDiff = [
      "diff --git a/net/unix/garbage.c b/net/unix/garbage.c",
      "@@ -10,6 +10,7 @@ static int unix_attach_fds(struct scm_cookie *scm)",
      "+\t/* fix */",
    ].join("\n");
    expect(existsSync(join(sourceRoot, ".pwnkit"))).toBe(false);
    expect(buildGraphSliceHuntContext({ sourceRoot, seedDiff })).toBeNull();
  });
});
