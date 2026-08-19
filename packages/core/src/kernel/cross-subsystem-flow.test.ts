import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  describeAssumptionMismatch,
  detectBoundaryCrossing,
  formatCrossSubsystemFlowsForPrompt,
  getFlowsForSubsystem,
  identifySubsystem,
  KERNEL_SUBSYSTEMS,
  KNOWN_CROSS_SUBSYSTEM_FLOWS,
  scanCrossSubsystemFlows,
} from "./cross-subsystem-flow.js";

let tmpRoot: string;

beforeEach(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), "0sec-cross-subsystem-test-"));
});

afterEach(() => {
  rmSync(tmpRoot, { recursive: true, force: true });
});

// ── KERNEL_SUBSYSTEMS database ────────────────────────────────────────────

describe("KERNEL_SUBSYSTEMS", () => {
  it("contains at least 10 subsystems", () => {
    expect(KERNEL_SUBSYSTEMS.length).toBeGreaterThanOrEqual(10);
  });

  it("every subsystem has required fields", () => {
    for (const sub of KERNEL_SUBSYSTEMS) {
      expect(sub.id).toBeTruthy();
      expect(sub.name).toBeTruthy();
      expect(sub.paths.length).toBeGreaterThan(0);
      expect(sub.dataStructures.length).toBeGreaterThan(0);
      expect(sub.boundaryFunctions.length).toBeGreaterThan(0);
    }
  });

  it("includes key subsystems for Copy Fail tracing", () => {
    const ids = KERNEL_SUBSYSTEMS.map((s) => s.id);
    expect(ids).toContain("crypto");
    expect(ids).toContain("splice");
    expect(ids).toContain("mm");
    expect(ids).toContain("net/core");
  });

  it("has unique IDs", () => {
    const ids = KERNEL_SUBSYSTEMS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

// ── KNOWN_CROSS_SUBSYSTEM_FLOWS ───────────────────────────────────────────

describe("KNOWN_CROSS_SUBSYSTEM_FLOWS", () => {
  it("contains at least 5 known flow patterns", () => {
    expect(KNOWN_CROSS_SUBSYSTEM_FLOWS.length).toBeGreaterThanOrEqual(5);
  });

  it("every flow has required fields", () => {
    for (const flow of KNOWN_CROSS_SUBSYSTEM_FLOWS) {
      expect(flow.id).toBeTruthy();
      expect(flow.description).toBeTruthy();
      expect(flow.chain.length).toBeGreaterThanOrEqual(2);
      expect(flow.dataObject).toBeTruthy();
      expect(Object.keys(flow.assumptions).length).toBeGreaterThan(0);
      expect(flow.vulnerabilityClass).toBeTruthy();
      expect(flow.detectionHints.length).toBeGreaterThan(0);
      expect(["critical", "high", "medium", "low"]).toContain(flow.risk);
    }
  });

  it("includes the Copy Fail (CVE-2026-31431) pattern", () => {
    const copyFail = KNOWN_CROSS_SUBSYSTEM_FLOWS.find((f) =>
      f.knownCves.includes("CVE-2026-31431"),
    );
    expect(copyFail).toBeDefined();
    expect(copyFail!.chain).toEqual(["crypto", "splice", "mm", "crypto"]);
    expect(copyFail!.dataObject).toContain("struct page");
    expect(copyFail!.risk).toBe("critical");
  });

  it("includes Dirty Pipe (CVE-2022-0847) pattern", () => {
    const dirtyPipe = KNOWN_CROSS_SUBSYSTEM_FLOWS.find((f) =>
      f.knownCves.includes("CVE-2022-0847"),
    );
    expect(dirtyPipe).toBeDefined();
    expect(dirtyPipe!.chain).toContain("splice");
    expect(dirtyPipe!.chain).toContain("mm");
  });

  it("includes Dirty COW (CVE-2016-5195) pattern", () => {
    const dirtyCow = KNOWN_CROSS_SUBSYSTEM_FLOWS.find((f) =>
      f.knownCves.includes("CVE-2016-5195"),
    );
    expect(dirtyCow).toBeDefined();
    expect(dirtyCow!.chain).toContain("mm");
  });

  it("has unique IDs", () => {
    const ids = KNOWN_CROSS_SUBSYSTEM_FLOWS.map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("all chain entries reference known subsystem IDs", () => {
    const knownIds = new Set(KERNEL_SUBSYSTEMS.map((s) => s.id));
    for (const flow of KNOWN_CROSS_SUBSYSTEM_FLOWS) {
      for (const subsystemId of flow.chain) {
        expect(knownIds.has(subsystemId)).toBe(true);
      }
    }
  });
});

// ── identifySubsystem ─────────────────────────────────────────────────────

describe("identifySubsystem", () => {
  it("identifies crypto/ files as crypto subsystem", () => {
    expect(identifySubsystem("crypto/algif_aead.c")).toBe("crypto");
    expect(identifySubsystem("crypto/af_alg.c")).toBe("crypto");
  });

  it("identifies mm/ files as mm subsystem", () => {
    expect(identifySubsystem("mm/filemap.c")).toBe("mm");
    expect(identifySubsystem("mm/page_alloc.c")).toBe("mm");
  });

  it("identifies splice files as splice subsystem", () => {
    expect(identifySubsystem("fs/splice.c")).toBe("splice");
    expect(identifySubsystem("fs/pipe.c")).toBe("splice");
  });

  it("identifies net/core files", () => {
    expect(identifySubsystem("net/core/skbuff.c")).toBe("net/core");
  });

  it("identifies net/ipv4 files", () => {
    expect(identifySubsystem("net/ipv4/esp4.c")).toBe("net/ipv4");
    expect(identifySubsystem("net/ipv4/tcp.c")).toBe("net/ipv4");
  });

  it("identifies io_uring files", () => {
    expect(identifySubsystem("io_uring/splice.c")).toBe("io_uring");
  });

  it("identifies net/netfilter files", () => {
    expect(identifySubsystem("net/netfilter/nf_tables_api.c")).toBe(
      "net/netfilter",
    );
  });

  it("returns 'unknown' for unrecognized paths", () => {
    expect(identifySubsystem("arch/x86/kernel/entry.S")).toBe("unknown");
    expect(identifySubsystem("lib/string.c")).toBe("unknown");
  });

  it("handles paths with leading slashes", () => {
    expect(identifySubsystem("/crypto/algif_aead.c")).toBe("crypto");
  });

  it("prefers more specific subsystems", () => {
    // net/ipv4/ should match net/ipv4, not net/core
    expect(identifySubsystem("net/ipv4/tcp.c")).toBe("net/ipv4");
    // net/netfilter/ should match net/netfilter, not net/core
    expect(identifySubsystem("net/netfilter/nf_tables.c")).toBe("net/netfilter");
  });
});

// ── detectBoundaryCrossing ────────────────────────────────────────────────

describe("detectBoundaryCrossing", () => {
  it("detects crypto function calls from splice subsystem", () => {
    const result = detectBoundaryCrossing(
      "  crypto_aead_decrypt(req);",
      "splice",
    );
    expect(result).not.toBeNull();
    expect(result!.targetSubsystem).toBe("crypto");
    expect(result!.matchedFunction).toBe("crypto_aead_decrypt");
  });

  it("detects page cache functions called from crypto subsystem", () => {
    const result = detectBoundaryCrossing(
      "  page = find_get_page(mapping, index);",
      "crypto",
    );
    expect(result).not.toBeNull();
    expect(result!.targetSubsystem).toBe("mm");
    expect(result!.matchedFunction).toBe("find_get_page");
  });

  it("detects splice functions called from io_uring", () => {
    const result = detectBoundaryCrossing(
      "  ret = do_splice(in, &off_in, out, &off_out, len, flags);",
      "io_uring",
    );
    expect(result).not.toBeNull();
    expect(result!.targetSubsystem).toBe("splice");
    expect(result!.matchedFunction).toBe("do_splice");
  });

  it("does not flag calls within the same subsystem", () => {
    const result = detectBoundaryCrossing(
      "  crypto_aead_decrypt(req);",
      "crypto",
    );
    expect(result).toBeNull();
  });

  it("returns null for lines without boundary function calls", () => {
    const result = detectBoundaryCrossing(
      "  int x = some_local_helper();",
      "crypto",
    );
    expect(result).toBeNull();
  });

  it("detects skb_cow_data from crypto (net/core boundary)", () => {
    const result = detectBoundaryCrossing(
      "  err = skb_cow_data(skb, 0, &trailer);",
      "crypto",
    );
    expect(result).not.toBeNull();
    expect(result!.targetSubsystem).toBe("net/core");
    expect(result!.matchedFunction).toBe("skb_cow_data");
  });

  it("detects sg_set_page from splice (crypto boundary)", () => {
    const result = detectBoundaryCrossing(
      "  sg_set_page(&sg[i], page, len, offset);",
      "splice",
    );
    expect(result).not.toBeNull();
    expect(result!.targetSubsystem).toBe("crypto");
    expect(result!.matchedFunction).toBe("sg_set_page");
  });
});

// ── scanCrossSubsystemFlows ───────────────────────────────────────────────

describe("scanCrossSubsystemFlows", () => {
  it("detects cross-subsystem calls in a crypto file calling mm functions", () => {
    const tree = join(tmpRoot, "linux");
    const cryptoDir = join(tree, "crypto");
    mkdirSync(cryptoDir, { recursive: true });
    writeFileSync(
      join(cryptoDir, "algif_aead.c"),
      `#include <linux/mm.h>
#include <crypto/aead.h>

static int aead_sendpage(struct socket *sock, struct page *page,
                         int offset, size_t size, int flags)
{
    struct page *cached = find_get_page(mapping, index);
    void *addr = kmap_local_page(cached);
    sg_set_page(&sg[0], cached, size, offset);
    return 0;
}
`,
    );

    const result = scanCrossSubsystemFlows({ tree });

    expect(result.crossings.length).toBeGreaterThanOrEqual(2);

    // Should detect crypto -> mm crossing (find_get_page, kmap_local_page)
    const mmCrossings = result.crossings.filter(
      (c) => c.sourceSubsystem === "crypto" && c.targetSubsystem === "mm",
    );
    expect(mmCrossings.length).toBeGreaterThanOrEqual(2);
    expect(
      mmCrossings.some((c) => c.matchedPattern === "find_get_page"),
    ).toBe(true);
    expect(
      mmCrossings.some((c) => c.matchedPattern === "kmap_local_page"),
    ).toBe(true);
  });

  it("builds flow summaries from crossings", () => {
    const tree = join(tmpRoot, "linux");
    const cryptoDir = join(tree, "crypto");
    mkdirSync(cryptoDir, { recursive: true });
    writeFileSync(
      join(cryptoDir, "algif_aead.c"),
      `static void foo(void) {
    find_get_page(mapping, idx);
    kmap_local_page(page);
    skb_cow_data(skb, 0, &trailer);
}
`,
    );

    const result = scanCrossSubsystemFlows({ tree });

    expect(result.flowSummaries.length).toBeGreaterThanOrEqual(1);

    const mmFlow = result.flowSummaries.find(
      (s) => s.from === "crypto" && s.to === "mm",
    );
    expect(mmFlow).toBeDefined();
    expect(mmFlow!.crossingCount).toBeGreaterThanOrEqual(2);
    expect(mmFlow!.files.length).toBeGreaterThanOrEqual(1);
  });

  it("tags crossings that match known vulnerable flows", () => {
    const tree = join(tmpRoot, "linux");
    const cryptoDir = join(tree, "crypto");
    mkdirSync(cryptoDir, { recursive: true });
    writeFileSync(
      join(cryptoDir, "algif_aead.c"),
      `static void foo(void) {
    do_splice(in, &off_in, out, &off_out, len, flags);
}
`,
    );

    const result = scanCrossSubsystemFlows({ tree });
    const spliceCrossings = result.crossings.filter(
      (c) => c.targetSubsystem === "splice",
    );

    // crypto -> splice is part of the Copy Fail pattern
    expect(spliceCrossings.length).toBeGreaterThanOrEqual(1);
    expect(spliceCrossings[0]!.knownFlowId).toBe(
      "copy-fail-afalg-splice-pagecache-aead",
    );
  });

  it("filters by subsystem when provided", () => {
    const tree = join(tmpRoot, "linux");
    const cryptoDir = join(tree, "crypto");
    const mmDir = join(tree, "mm");
    mkdirSync(cryptoDir, { recursive: true });
    mkdirSync(mmDir, { recursive: true });
    writeFileSync(
      join(cryptoDir, "algif_aead.c"),
      `static void foo(void) { find_get_page(mapping, idx); }`,
    );
    writeFileSync(
      join(mmDir, "filemap.c"),
      `static void bar(void) { crypto_aead_decrypt(req); }`,
    );

    // Only scan crypto
    const result = scanCrossSubsystemFlows({
      tree,
      subsystem: "crypto",
    });

    // Should only have crossings from crypto files
    for (const crossing of result.crossings) {
      expect(crossing.sourceSubsystem).toBe("crypto");
    }
  });

  it("returns empty crossings for tree with no cross-subsystem calls", () => {
    const tree = join(tmpRoot, "linux");
    const cryptoDir = join(tree, "crypto");
    mkdirSync(cryptoDir, { recursive: true });
    writeFileSync(
      join(cryptoDir, "internal.c"),
      `static int helper(void) { return local_func(); }`,
    );

    const result = scanCrossSubsystemFlows({ tree });
    expect(result.crossings).toHaveLength(0);
    expect(result.flowSummaries).toHaveLength(0);
  });

  it("handles nonexistent tree paths gracefully", () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree, { recursive: true });

    const result = scanCrossSubsystemFlows({ tree });
    expect(result.crossings).toHaveLength(0);
    expect(result.warnings).toHaveLength(0);
  });

  it("respects maxFilesPerDir limit", () => {
    const tree = join(tmpRoot, "linux");
    const cryptoDir = join(tree, "crypto");
    mkdirSync(cryptoDir, { recursive: true });

    // Create many files
    for (let i = 0; i < 10; i++) {
      writeFileSync(
        join(cryptoDir, `file${i}.c`),
        `static void f(void) { find_get_page(m, i); }`,
      );
    }

    const result = scanCrossSubsystemFlows({
      tree,
      maxFilesPerDir: 3,
    });

    // Should still work but scan fewer files
    expect(result.crossings.length).toBeLessThanOrEqual(3);
  });

  it("skips comment lines", () => {
    const tree = join(tmpRoot, "linux");
    const cryptoDir = join(tree, "crypto");
    mkdirSync(cryptoDir, { recursive: true });
    writeFileSync(
      join(cryptoDir, "algif_aead.c"),
      `// find_get_page(mapping, index);
/* skb_cow_data(skb, 0, &trailer); */
* kmap_local_page(page);
  do_splice(in, &off, out, &off2, len, flags);
`,
    );

    const result = scanCrossSubsystemFlows({ tree });

    // Only the non-commented do_splice should be detected
    expect(result.crossings).toHaveLength(1);
    expect(result.crossings[0]!.matchedPattern).toBe("do_splice");
  });
});

// ── getFlowsForSubsystem ─────────────────────────────────────────────────

describe("getFlowsForSubsystem", () => {
  it("returns flows involving the crypto subsystem", () => {
    const flows = getFlowsForSubsystem("crypto");
    expect(flows.length).toBeGreaterThanOrEqual(1);
    for (const flow of flows) {
      expect(flow.chain).toContain("crypto");
    }
  });

  it("returns flows involving the splice subsystem", () => {
    const flows = getFlowsForSubsystem("splice");
    expect(flows.length).toBeGreaterThanOrEqual(2);
    for (const flow of flows) {
      expect(flow.chain).toContain("splice");
    }
  });

  it("returns flows involving mm", () => {
    const flows = getFlowsForSubsystem("mm");
    expect(flows.length).toBeGreaterThanOrEqual(3);
  });

  it("returns empty array for subsystem with no known flows", () => {
    const flows = getFlowsForSubsystem("drivers/usb");
    expect(flows).toHaveLength(0);
  });
});

// ── describeAssumptionMismatch ────────────────────────────────────────────

describe("describeAssumptionMismatch", () => {
  it("describes the crypto <-> splice mismatch", () => {
    const desc = describeAssumptionMismatch("crypto", "splice");
    expect(desc).not.toBeNull();
    expect(desc).toContain("copy-fail");
    expect(desc).toContain("struct page");
    expect(desc).toContain("crypto");
    expect(desc).toContain("splice");
  });

  it("describes the splice <-> mm mismatch", () => {
    const desc = describeAssumptionMismatch("splice", "mm");
    expect(desc).not.toBeNull();
    expect(desc).toContain("struct page");
  });

  it("returns null for subsystems with no known mismatch", () => {
    const desc = describeAssumptionMismatch("drivers/usb", "bpf");
    expect(desc).toBeNull();
  });

  it("works in reverse direction", () => {
    const desc = describeAssumptionMismatch("splice", "crypto");
    expect(desc).not.toBeNull();
    expect(desc).toContain("copy-fail");
  });

  it("includes CVE references when available", () => {
    const desc = describeAssumptionMismatch("crypto", "splice");
    expect(desc).toContain("CVE-2026-31431");
  });
});

// ── formatCrossSubsystemFlowsForPrompt ────────────────────────────────────

describe("formatCrossSubsystemFlowsForPrompt", () => {
  it("renders tracing instructions without scan results", () => {
    const prompt = formatCrossSubsystemFlowsForPrompt();
    expect(prompt).toContain("Cross-Subsystem Data Flow Tracing Instructions");
    expect(prompt).toContain("Tracing protocol");
    expect(prompt).toContain("Trace UP");
    expect(prompt).toContain("Trace DOWN");
    expect(prompt).toContain("Document assumptions");
    expect(prompt).toContain("Find the mismatch");
    expect(prompt).toContain("struct page");
    expect(prompt).toContain("struct sk_buff");
  });

  it("includes all known flow patterns", () => {
    const prompt = formatCrossSubsystemFlowsForPrompt();
    for (const flow of KNOWN_CROSS_SUBSYSTEM_FLOWS) {
      expect(prompt).toContain(flow.id);
    }
  });

  it("includes CVE references in prompt", () => {
    const prompt = formatCrossSubsystemFlowsForPrompt();
    expect(prompt).toContain("CVE-2026-31431");
    expect(prompt).toContain("CVE-2022-0847");
    expect(prompt).toContain("CVE-2016-5195");
  });

  it("includes scan results when provided", () => {
    const tree = join(tmpRoot, "linux");
    const cryptoDir = join(tree, "crypto");
    mkdirSync(cryptoDir, { recursive: true });
    writeFileSync(
      join(cryptoDir, "algif_aead.c"),
      `static void foo(void) { find_get_page(mapping, idx); }`,
    );

    const result = scanCrossSubsystemFlows({ tree });
    const prompt = formatCrossSubsystemFlowsForPrompt(result);

    expect(prompt).toContain("Detected boundary crossings");
    expect(prompt).toContain("crypto");
    expect(prompt).toContain("mm");
  });

  it("shows risk levels for known flow patterns in results", () => {
    const tree = join(tmpRoot, "linux");
    const cryptoDir = join(tree, "crypto");
    mkdirSync(cryptoDir, { recursive: true });
    writeFileSync(
      join(cryptoDir, "algif_aead.c"),
      `static void foo(void) { do_splice(in, &off, out, &off2, len, 0); }`,
    );

    const result = scanCrossSubsystemFlows({ tree });
    const prompt = formatCrossSubsystemFlowsForPrompt(result);

    expect(prompt).toContain("CRITICAL");
  });

  it("includes detection hints for each flow", () => {
    const prompt = formatCrossSubsystemFlowsForPrompt();
    expect(prompt).toContain("Detection hints");
    expect(prompt).toContain("af_alg_sendpage");
    expect(prompt).toContain("PIPE_BUF_FLAG_CAN_MERGE");
  });
});
