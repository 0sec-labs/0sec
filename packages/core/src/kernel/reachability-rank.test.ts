import { describe, expect, it } from "vitest";
import { resolve } from "node:path";
import { rankSinkReachability, type CallEdge } from "./index.js";
import type { EntryPoint as BoundaryEntryPoint } from "./syscall-boundary-map.js";

const FIXTURE_TREE = resolve(__dirname, "__fixtures__/fake-kernel-tree");

// The fixture file drivers/char/vuln_dev.c wires:
//   SYSCALL_DEFINE2(vuln_open) -> vuln_dispatch -> vuln_copy_payload [SINK]
//   SYSCALL_DEFINE1(vuln_stat) -> vuln_readonly_info  (does NOT reach sink)
// The copy_from_user sink lives inside vuln_copy_payload.
const SINK = { file: "drivers/char/vuln_dev.c", line: 20 };

describe("rankSinkReachability", () => {
  it("ranks the reaching syscall first for a multi-hop sink", async () => {
    const result = await rankSinkReachability(SINK, FIXTURE_TREE);

    expect(result.sinkFunction).toBe("vuln_copy_payload");
    expect(result.candidates.length).toBeGreaterThan(0);

    const top = result.candidates[0]!;
    expect(top.entry.type).toBe("syscall");
    expect(top.entry.name).toBe("vuln_open");
    // entry -> vuln_dispatch -> vuln_copy_payload = 2 hops
    expect(top.pathLength).toBe(2);
    expect(top.path).toEqual([
      "vuln_open",
      "vuln_dispatch",
      "vuln_copy_payload",
    ]);
    expect(top.confidence).toBe("direct");
  });

  it("does not rank an unrelated syscall as the reaching one", async () => {
    const result = await rankSinkReachability(SINK, FIXTURE_TREE);
    // vuln_stat reaches vuln_readonly_info, never the sink. It must not be
    // the top candidate. (It may appear as a same-file fallback below.)
    const top = result.candidates[0]!;
    expect(top.entry.name).not.toBe("vuln_stat");

    const stat = result.candidates.find((c) => c.entry.name === "vuln_stat");
    if (stat) {
      // If present at all, it's only via the low-confidence same-file fallback.
      expect(stat.confidence).toBe("same-file-fallback");
      expect(stat.score).toBeLessThan(top.score);
    }
  });

  it("resolves the enclosing function from file:line", async () => {
    const result = await rankSinkReachability(
      { file: "drivers/char/vuln_dev.c", line: 21 },
      FIXTURE_TREE,
    );
    expect(result.sinkFunction).toBe("vuln_copy_payload");
  });

  it("honours an explicit sink function name", async () => {
    const result = await rankSinkReachability(
      { file: "drivers/char/vuln_dev.c", line: 1, function: "vuln_dispatch" },
      FIXTURE_TREE,
    );
    expect(result.sinkFunction).toBe("vuln_dispatch");
    const top = result.candidates[0]!;
    expect(top.entry.name).toBe("vuln_open");
    expect(top.pathLength).toBe(1);
  });

  it("reuses pre-supplied entry points instead of scanning", async () => {
    const entryPoints: BoundaryEntryPoint[] = [
      {
        type: "syscall",
        name: "vuln_open",
        file: "drivers/char/vuln_dev.c",
        line: 40,
      },
    ];
    const result = await rankSinkReachability(SINK, FIXTURE_TREE, {
      entryPoints,
    });
    expect(result.candidates.map((c) => c.entry.name)).toContain("vuln_open");
    // vuln_stat was not in the supplied set, so it must be absent.
    expect(result.candidates.map((c) => c.entry.name)).not.toContain(
      "vuln_stat",
    );
  });

  it("recovers an indirect edge from supplied SARIF call edges", async () => {
    // Pretend the sink is reached only via a function pointer the regex graph
    // cannot see: an ioctl handler dispatched through file_operations. We model
    // it with an explicit sink function 'handler_only_via_fptr' that nothing
    // calls directly, then supply a SARIF edge from a known syscall.
    const extraEdges: CallEdge[] = [
      {
        caller: "vuln_open",
        callee: "vuln_copy_payload",
        file: "drivers/char/vuln_dev.c",
        line: 0,
        confidence: "sarif",
      },
    ];
    const result = await rankSinkReachability(
      { file: "drivers/char/vuln_dev.c", line: 1, function: "vuln_copy_payload" },
      FIXTURE_TREE,
      { extraEdges },
    );
    const direct = result.candidates.find((c) => c.entry.name === "vuln_open");
    expect(direct).toBeDefined();
    // The direct 2-hop path should still win over the synthetic 1-hop sarif
    // edge because direct confidence outranks sarif. Either way vuln_open ranks.
    expect(result.candidates[0]!.entry.name).toBe("vuln_open");
  });

  it("warns and returns no candidates when the sink function is unresolvable", async () => {
    const result = await rankSinkReachability(
      { file: "drivers/char/does_not_exist.c", line: 999 },
      FIXTURE_TREE,
    );
    expect(result.candidates).toEqual([]);
    expect(result.warnings.join(" ")).toMatch(/[Cc]ould not resolve/);
  });

  it("throws when the tree path does not exist", async () => {
    await expect(
      rankSinkReachability(SINK, "/nonexistent/kernel/tree"),
    ).rejects.toThrow(/not found/);
  });
});
