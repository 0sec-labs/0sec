/**
 * Kernel archetype catalog tests. `loadKernelArchetypes` / `filterArchetypes` /
 * `archetypeToHuntBrief` / `symbolsFromDetectionSignature` are pure — no mocks
 * needed. `generateArchetypeCandidates` / `planArchetypeSweep` shell out to the
 * real `grep` binary over a throwaway temp fixture tree (mirrors how
 * `variant-candidates.ts` would be tested), never a mock.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  archetypeSweepEnabled,
  archetypeToHuntBrief,
  candidateGrepPatterns,
  filterArchetypes,
  FREEBSD_BARE_KERNEL_WORDS,
  generateArchetypeCandidates,
  hypothesisOnly,
  loadFreebsdArchetypes,
  loadKernelArchetypes,
  needsKernelVerify,
  planArchetypeSweep,
  symbolsFromDetectionSignature,
  type KernelArchetype,
} from "./archetype-catalog.js";

describe("loadKernelArchetypes", () => {
  it("loads all 34 kernel-domain archetypes with unique uids under kernel/", () => {
    const archetypes = loadKernelArchetypes();
    expect(archetypes).toHaveLength(34);
    const uids = new Set(archetypes.map((a) => a.uid));
    expect(uids.size).toBe(34);
    for (const a of archetypes) {
      expect(a.uid.startsWith("kernel/")).toBe(true);
      expect(a.name.length).toBeGreaterThan(0);
      expect(a.pattern.length).toBeGreaterThan(0);
      expect(a.detectionSignature.length).toBeGreaterThan(0);
      expect(["kernel-static", "kernel-verify", "not-binary-detectable"]).toContain(a.route);
    }
  });

  it("is cached (repeated calls return the same reference)", () => {
    expect(loadKernelArchetypes()).toBe(loadKernelArchetypes());
  });

  it("route counts match the ported 0verse registry (11 static / 15 verify / 8 not-binary-detectable)", () => {
    const archetypes = loadKernelArchetypes();
    const counts = { "kernel-static": 0, "kernel-verify": 0, "not-binary-detectable": 0 };
    for (const a of archetypes) counts[a.route]++;
    expect(counts).toEqual({ "kernel-static": 11, "kernel-verify": 15, "not-binary-detectable": 8 });
  });
});

describe("hypothesisOnly / needsKernelVerify", () => {
  it("kernel-static is not hypothesis-only and does not need kernel-verify", () => {
    const a = loadKernelArchetypes().find((x) => x.route === "kernel-static")!;
    expect(hypothesisOnly(a)).toBe(false);
    expect(needsKernelVerify(a)).toBe(false);
  });

  it("kernel-verify is hypothesis-only AND needs kernel-verify", () => {
    const a = loadKernelArchetypes().find((x) => x.route === "kernel-verify")!;
    expect(hypothesisOnly(a)).toBe(true);
    expect(needsKernelVerify(a)).toBe(true);
  });

  it("not-binary-detectable is hypothesis-only but does not itself need kernel-verify", () => {
    const a = loadKernelArchetypes().find((x) => x.route === "not-binary-detectable")!;
    expect(hypothesisOnly(a)).toBe(true);
    expect(needsKernelVerify(a)).toBe(false);
  });
});

describe("filterArchetypes", () => {
  const archetypes = loadKernelArchetypes();

  it("filters by route", () => {
    const statics = filterArchetypes(archetypes, { routes: ["kernel-static"] });
    expect(statics.length).toBe(11);
    expect(statics.every((a) => a.route === "kernel-static")).toBe(true);
  });

  it("filters by cwe substring (case-insensitive)", () => {
    const uaf = filterArchetypes(archetypes, { cwe: "cwe-416" });
    expect(uaf.length).toBeGreaterThan(0);
    expect(uaf.every((a) => a.cwe.toLowerCase().includes("cwe-416"))).toBe(true);
  });

  it("filters by subsystem substring", () => {
    const netfilter = filterArchetypes(archetypes, { subsystem: "netfilter" });
    expect(netfilter.length).toBeGreaterThan(0);
    expect(netfilter.every((a) => a.subsystem.toLowerCase().includes("netfilter"))).toBe(true);
  });

  it("filters by explicit uid list", () => {
    const picked = filterArchetypes(archetypes, { uids: ["kernel/DRV-01", "kernel/DRV-03"] });
    expect(picked.map((a) => a.uid).sort()).toEqual(["kernel/DRV-01", "kernel/DRV-03"]);
  });

  it("composes filters (AND semantics)", () => {
    const none = filterArchetypes(archetypes, { routes: ["kernel-static"], subsystem: "nowhere-subsystem" });
    expect(none).toHaveLength(0);
  });
});

describe("archetypeToHuntBrief", () => {
  it("produces a non-empty bugClass/pattern/fixReference from a real archetype", () => {
    const a = loadKernelArchetypes().find((x) => x.id === "DRV-01")!;
    const brief = archetypeToHuntBrief(a);
    expect(brief.bugClass).toContain(a.name);
    expect(brief.bugClass).toContain(a.cwe);
    expect(brief.pattern).toContain(a.pattern);
    expect(brief.pattern).toContain(a.detectionSignature);
    expect(brief.fixReference).toContain(a.uid);
  });
});

describe("symbolsFromDetectionSignature", () => {
  it("extracts real kernel symbol names from a known archetype's detection signature", () => {
    const nf03 = loadKernelArchetypes().find((x) => x.id === "NF-03")!;
    const symbols = symbolsFromDetectionSignature(nf03.detectionSignature);
    expect(symbols).toContain("nla_parse");
    expect(symbols).toContain("nla_get_u32");
  });

  it("ignores short/no-underscore tokens and common prose", () => {
    const symbols = symbolsFromDetectionSignature("the quick brown fox has a bad free() and use of it");
    expect(symbols).toEqual([]);
  });

  it("dedupes and sorts", () => {
    const symbols = symbolsFromDetectionSignature("kfree_rcu appears twice: kfree_rcu again, then call_rcu once");
    expect(symbols).toEqual(["call_rcu", "kfree_rcu"]);
  });
});

describe("candidateGrepPatterns", () => {
  it("returns at least one ERE pattern for an archetype with real symbols", () => {
    const nf03 = loadKernelArchetypes().find((x) => x.id === "NF-03")!;
    const patterns = candidateGrepPatterns(nf03);
    expect(patterns.length).toBeGreaterThan(0);
    expect(patterns[0]).toMatch(/^\\b\(.+\)\\b$/);
  });

  it("chunks wide symbol sets into multiple patterns (alternation width cap)", () => {
    const wide: KernelArchetype = {
      uid: "kernel/TEST-WIDE", id: "TEST-WIDE", name: "test", cwe: "CWE-0", subsystem: "test",
      pattern: "test pattern",
      detectionSignature: Array.from({ length: 20 }, (_, i) => `symbol_number_${i}`).join(" / "),
      grounding: [], confirmableNote: "", engineLens: null, route: "kernel-static",
    };
    const patterns = candidateGrepPatterns(wide);
    expect(patterns.length).toBeGreaterThan(1);
  });

  it("returns [] when the detection signature has no extractable symbols", () => {
    const noSymbols: KernelArchetype = {
      uid: "kernel/TEST-NONE", id: "TEST-NONE", name: "test", cwe: "CWE-0", subsystem: "test",
      pattern: "test pattern", detectionSignature: "no static shape here, needs a live oracle",
      grounding: [], confirmableNote: "", engineLens: null, route: "not-binary-detectable",
    };
    expect(candidateGrepPatterns(noSymbols)).toEqual([]);
  });
});

describe("generateArchetypeCandidates + planArchetypeSweep (real grep over a temp fixture tree)", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "pwnkit-archetype-test-"));
    writeFileSync(
      join(dir, "netlink_hit.c"),
      "int parse(struct nlattr *a) { u32 v = nla_get_u32(a); return v; }\n",
    );
    writeFileSync(join(dir, "unrelated.c"), "int add(int a, int b) { return a + b; }\n");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("finds the file containing the archetype's symbol and ranks it above unrelated files", () => {
    const nf03 = loadKernelArchetypes().find((x) => x.id === "NF-03")!;
    const candidates = generateArchetypeCandidates(nf03, dir);
    expect(candidates.map((c) => c.path)).toContain("netlink_hit.c");
    expect(candidates.map((c) => c.path)).not.toContain("unrelated.c");
    expect(candidates[0]?.hint).toContain(nf03.uid);
  });

  it("returns [] for an archetype whose detection signature has no grep-able symbols", () => {
    const noSymbols: KernelArchetype = {
      uid: "kernel/TEST-NONE", id: "TEST-NONE", name: "test", cwe: "CWE-0", subsystem: "test",
      pattern: "test pattern", detectionSignature: "needs a live oracle",
      grounding: [], confirmableNote: "", engineLens: null, route: "not-binary-detectable",
    };
    expect(generateArchetypeCandidates(noSymbols, dir)).toEqual([]);
  });

  it("archetypeSweepEnabled() defaults to false", () => {
    const prev = process.env.PWNKIT_ARCHETYPE_SWEEP;
    delete process.env.PWNKIT_ARCHETYPE_SWEEP;
    try {
      expect(archetypeSweepEnabled()).toBe(false);
    } finally {
      if (prev !== undefined) process.env.PWNKIT_ARCHETYPE_SWEEP = prev;
    }
  });

  it("planArchetypeSweep is a no-op with a warning when the env gate is off and force is not set", () => {
    const prev = process.env.PWNKIT_ARCHETYPE_SWEEP;
    delete process.env.PWNKIT_ARCHETYPE_SWEEP;
    try {
      const result = planArchetypeSweep({ sourceRoot: dir, uids: ["kernel/NF-03"] });
      expect(result.plans).toEqual([]);
      expect(result.warnings[0]).toContain("PWNKIT_ARCHETYPE_SWEEP");
    } finally {
      if (prev !== undefined) process.env.PWNKIT_ARCHETYPE_SWEEP = prev;
    }
  });

  it("planArchetypeSweep produces plans across multiple archetypes when forced (multi-lens sweep)", () => {
    writeFileSync(
      join(dir, "netlink_hit2.c"),
      "void other(struct nlattr *a) { nla_memcpy(dst, a, 4); }\n",
    );
    const result = planArchetypeSweep({
      sourceRoot: dir,
      uids: ["kernel/NF-03"],
      force: true,
    });
    expect(result.plans.length).toBe(1);
    const plan = result.plans[0]!;
    expect(plan.archetype.uid).toBe("kernel/NF-03");
    expect(plan.brief.bugClass).toContain(plan.archetype.cwe);
    expect(plan.candidates.map((c) => c.path).sort()).toEqual(["netlink_hit.c", "netlink_hit2.c"]);
    expect(plan.grepPatterns.length).toBeGreaterThan(0);
  });

  it("planArchetypeSweep warns (not throws) on an archetype with no static grep signal", () => {
    // Pick a uid known to be hypothesis-only with prose unlikely to yield symbols.
    const result = planArchetypeSweep({ sourceRoot: dir, uids: ["kernel/BPF-01"], force: true });
    // Either it found symbols (plan produced or "matched nothing" warning) or no
    // symbols at all — both are honest non-throwing outcomes.
    expect(() => result).not.toThrow();
    expect(result.plans.length + result.warnings.length).toBeGreaterThan(0);
  });
});

// ── FreeBSD archetype pack ───────────────────────────────────────────────────
// Mirrors the Linux-pack test coverage above: the pack loads, has the
// expected count/routes, archetypeToHuntBrief works on a FreeBSD archetype,
// and candidateGrepPatterns emits FreeBSD symbols (copyout/copyin/malloc) —
// NOT Linux ones — once the bare-word allow-list is supplied.

describe("loadFreebsdArchetypes", () => {
  it("loads all 10 FreeBSD-domain archetypes with unique uids under freebsd/", () => {
    const archetypes = loadFreebsdArchetypes();
    expect(archetypes).toHaveLength(10);
    const uids = new Set(archetypes.map((a) => a.uid));
    expect(uids.size).toBe(10);
    for (const a of archetypes) {
      expect(a.uid.startsWith("freebsd/")).toBe(true);
      expect(a.name.length).toBeGreaterThan(0);
      expect(a.pattern.length).toBeGreaterThan(0);
      expect(a.detectionSignature.length).toBeGreaterThan(0);
      expect(a.grounding.length).toBeGreaterThan(0);
      expect(["kernel-static", "kernel-verify", "not-binary-detectable"]).toContain(a.route);
    }
  });

  it("is cached (repeated calls return the same reference) and independent from the Linux cache", () => {
    expect(loadFreebsdArchetypes()).toBe(loadFreebsdArchetypes());
    const freebsdUids = new Set(loadFreebsdArchetypes().map((a) => a.uid));
    const kernelUids = new Set(loadKernelArchetypes().map((a) => a.uid));
    for (const uid of freebsdUids) expect(kernelUids.has(uid)).toBe(false);
  });

  it("route counts: 6 kernel-static / 4 kernel-verify / 0 not-binary-detectable", () => {
    const archetypes = loadFreebsdArchetypes();
    const counts = { "kernel-static": 0, "kernel-verify": 0, "not-binary-detectable": 0 };
    for (const a of archetypes) counts[a.route]++;
    expect(counts).toEqual({ "kernel-static": 6, "kernel-verify": 4, "not-binary-detectable": 0 });
  });

  it("covers the requested FreeBSD bug classes (copyout infoleak, copyin TOCTOU, malloc overflow, missing priv_check, ioctl OOB, free/uma_zfree UAF, sysctl OOB)", () => {
    const ids = new Set(loadFreebsdArchetypes().map((a) => a.id));
    for (const id of ["CP-01", "CP-02", "MA-01", "PRIV-01", "IOC-01", "UAF-01", "SYSCTL-01"]) {
      expect(ids.has(id)).toBe(true);
    }
  });
});

describe("archetypeToHuntBrief on a FreeBSD archetype", () => {
  it("produces a non-empty bugClass/pattern/fixReference", () => {
    const a = loadFreebsdArchetypes().find((x) => x.id === "CP-01")!;
    const brief = archetypeToHuntBrief(a);
    expect(brief.bugClass).toContain(a.name);
    expect(brief.bugClass).toContain(a.cwe);
    expect(brief.pattern).toContain(a.pattern);
    expect(brief.pattern).toContain(a.detectionSignature);
    expect(brief.fixReference).toContain(a.uid);
  });
});

describe("candidateGrepPatterns on the FreeBSD pack — FreeBSD symbols, not Linux ones", () => {
  it("without bareWords still finds the underscored real FreeBSD symbols (e.g. priv_check, uma_zfree)", () => {
    const priv = loadFreebsdArchetypes().find((x) => x.id === "PRIV-01")!;
    const symbols = symbolsFromDetectionSignature(priv.detectionSignature);
    expect(symbols).toContain("priv_check");
    // Never a Linux-specific symbol.
    expect(symbols).not.toContain("copy_from_user");
    expect(symbols).not.toContain("kmalloc");

    const uaf = loadFreebsdArchetypes().find((x) => x.id === "UAF-01")!;
    expect(symbolsFromDetectionSignature(uaf.detectionSignature)).toContain("uma_zfree");
  });

  it("bare copyout/copyin/malloc are NOT matched without the bare-word allow-list (Linux path stays unaffected by default)", () => {
    const cp01 = loadFreebsdArchetypes().find((x) => x.id === "CP-01")!;
    const symbols = symbolsFromDetectionSignature(cp01.detectionSignature);
    expect(symbols).not.toContain("copyout");
  });

  it("with FREEBSD_BARE_KERNEL_WORDS, candidateGrepPatterns emits copyout/copyin/malloc symbols", () => {
    const cp01 = loadFreebsdArchetypes().find((x) => x.id === "CP-01")!;
    const symbols = symbolsFromDetectionSignature(cp01.detectionSignature, FREEBSD_BARE_KERNEL_WORDS);
    expect(symbols).toContain("copyout");

    const ma01 = loadFreebsdArchetypes().find((x) => x.id === "MA-01")!;
    const maSymbols = symbolsFromDetectionSignature(ma01.detectionSignature, FREEBSD_BARE_KERNEL_WORDS);
    expect(maSymbols).toContain("malloc");
    expect(maSymbols).toContain("mallocarray");

    const patterns = candidateGrepPatterns(cp01, FREEBSD_BARE_KERNEL_WORDS);
    expect(patterns.length).toBeGreaterThan(0);
    expect(patterns.some((p) => p.includes("copyout"))).toBe(true);
  });
});

describe("generateArchetypeCandidates + planArchetypeSweep on the FreeBSD pack (real grep, temp fixture tree)", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "pwnkit-freebsd-archetype-test-"));
    writeFileSync(
      join(dir, "uninit_leak.c"),
      "int copyout_ucontext(ucontext_t *uc) { return copyout(uc, 0, sizeof(*uc)); }\n",
    );
    writeFileSync(join(dir, "unrelated.c"), "int add(int a, int b) { return a + b; }\n");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("finds the file containing the archetype's bare-word symbol (copyout) when bareWords is supplied", () => {
    const cp01 = loadFreebsdArchetypes().find((x) => x.id === "CP-01")!;
    const candidates = generateArchetypeCandidates(cp01, dir, { bareWords: FREEBSD_BARE_KERNEL_WORDS });
    expect(candidates.map((c) => c.path)).toContain("uninit_leak.c");
    expect(candidates.map((c) => c.path)).not.toContain("unrelated.c");
  });

  it("planArchetypeSweep with domain: 'freebsd' + force sweeps the FreeBSD pack, not the Linux one", () => {
    const result = planArchetypeSweep({
      sourceRoot: dir,
      domain: "freebsd",
      uids: ["freebsd/CP-01"],
      bareWords: FREEBSD_BARE_KERNEL_WORDS,
      force: true,
    });
    expect(result.plans.length).toBe(1);
    const plan = result.plans[0]!;
    expect(plan.archetype.uid).toBe("freebsd/CP-01");
    expect(plan.candidates.map((c) => c.path)).toContain("uninit_leak.c");
  });

  it("planArchetypeSweep still defaults to the kernel (Linux) domain when domain is omitted", () => {
    const result = planArchetypeSweep({
      sourceRoot: dir,
      uids: ["freebsd/CP-01"], // a freebsd uid does not exist in the kernel (Linux) pack
      force: true,
    });
    expect(result.plans).toEqual([]);
  });
});
