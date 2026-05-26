import { describe, expect, it } from "vitest";
import {
  DIRTY_FRAG_PATTERNS,
  DIRTY_FRAG_PATTERN_LIST,
  matchPatternByRuleId,
  matchPatternsBySourceHints,
  filterPatternsForConfig,
  SKB_INPLACE_AEAD_NO_COW,
  SPLICE_INPLACE_CRYPTO_NO_COW,
  SPLICE_IOURING_FIXED_BUFFER_ALIAS,
  VMSPLICE_KERNEL_CONSUMER_ALIAS,
  AF_ALG_ANY_ALGORITHM_SPLICE,
  GENERIC_PAGE_WRITE_NO_OWNERSHIP,
  type DirtyFragPattern,
} from "./dirty-frag-patterns.js";

// ── Pattern library structure ───────────────────────────────────────────────

describe("DIRTY_FRAG_PATTERN_LIST", () => {
  it("contains exactly 6 patterns", () => {
    expect(DIRTY_FRAG_PATTERN_LIST).toHaveLength(6);
  });

  it("all patterns have unique ids", () => {
    const ids = DIRTY_FRAG_PATTERN_LIST.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("all patterns have non-empty required fields", () => {
    for (const pattern of DIRTY_FRAG_PATTERN_LIST) {
      expect(pattern.id).toBeTruthy();
      expect(pattern.name).toBeTruthy();
      expect(pattern.description.length).toBeGreaterThan(20);
      expect(pattern.triggerConditions.length).toBeGreaterThan(0);
      expect(pattern.mitigations.length).toBeGreaterThan(0);
      expect(pattern.subsystems.length).toBeGreaterThan(0);
      expect(pattern.ruleIdPrefix).toBe("kernel/dirty-frag-class");
      expect(pattern.sourceHints.length).toBeGreaterThan(0);
    }
  });

  it("all patterns are accessible via the Map", () => {
    for (const pattern of DIRTY_FRAG_PATTERN_LIST) {
      expect(DIRTY_FRAG_PATTERNS.get(pattern.id)).toBe(pattern);
    }
  });
});

// ── Individual pattern shapes ───────────────────────────────────────────────

describe("SKB_INPLACE_AEAD_NO_COW (pattern 0 — original)", () => {
  it("targets ESP/AEAD in net/ipv4, net/ipv6, net/xfrm", () => {
    expect(SKB_INPLACE_AEAD_NO_COW.subsystems).toContain("net/ipv4");
    expect(SKB_INPLACE_AEAD_NO_COW.subsystems).toContain("net/ipv6");
    expect(SKB_INPLACE_AEAD_NO_COW.subsystems).toContain("net/xfrm");
  });

  it("requires ESP and AEAD config", () => {
    expect(SKB_INPLACE_AEAD_NO_COW.kernelConfigDeps).toContain("CONFIG_INET_ESP");
    expect(SKB_INPLACE_AEAD_NO_COW.kernelConfigDeps).toContain("CONFIG_CRYPTO_AEAD");
  });

  it("lists skb_cow_data as a mitigation", () => {
    expect(SKB_INPLACE_AEAD_NO_COW.mitigations).toContain("skb_cow_data()");
  });
});

describe("SPLICE_INPLACE_CRYPTO_NO_COW (pattern a — Copy Fail)", () => {
  it("references CVE-2026-31431", () => {
    expect(SPLICE_INPLACE_CRYPTO_NO_COW.knownCves).toContain("CVE-2026-31431");
  });

  it("targets crypto and fs/splice subsystems", () => {
    expect(SPLICE_INPLACE_CRYPTO_NO_COW.subsystems).toContain("crypto");
    expect(SPLICE_INPLACE_CRYPTO_NO_COW.subsystems).toContain("fs/splice");
  });

  it("requires CRYPTO_USER_API config", () => {
    expect(SPLICE_INPLACE_CRYPTO_NO_COW.kernelConfigDeps).toContain("CONFIG_CRYPTO_USER_API");
  });

  it("source hints match af_alg splice functions", () => {
    expect(SPLICE_INPLACE_CRYPTO_NO_COW.sourceHints.some((re) => re.test("af_alg_make_sg"))).toBe(true);
    expect(SPLICE_INPLACE_CRYPTO_NO_COW.sourceHints.some((re) => re.test("algif_aead_recvmsg"))).toBe(true);
  });
});

describe("SPLICE_IOURING_FIXED_BUFFER_ALIAS (pattern b)", () => {
  it("targets io_uring subsystem", () => {
    expect(SPLICE_IOURING_FIXED_BUFFER_ALIAS.subsystems).toContain("io_uring");
  });

  it("requires CONFIG_IO_URING", () => {
    expect(SPLICE_IOURING_FIXED_BUFFER_ALIAS.kernelConfigDeps).toContain("CONFIG_IO_URING");
  });

  it("source hints match io_uring registration functions", () => {
    expect(
      SPLICE_IOURING_FIXED_BUFFER_ALIAS.sourceHints.some((re) =>
        re.test("io_sqe_buffers_register"),
      ),
    ).toBe(true);
  });
});

describe("VMSPLICE_KERNEL_CONSUMER_ALIAS (pattern c)", () => {
  it("references CVE-2022-0847 (Dirty Pipe)", () => {
    expect(VMSPLICE_KERNEL_CONSUMER_ALIAS.knownCves).toContain("CVE-2022-0847");
  });

  it("has no kernel config deps (always reachable)", () => {
    expect(VMSPLICE_KERNEL_CONSUMER_ALIAS.kernelConfigDeps).toHaveLength(0);
  });

  it("source hints match vmsplice and pipe functions", () => {
    expect(
      VMSPLICE_KERNEL_CONSUMER_ALIAS.sourceHints.some((re) =>
        re.test("vmsplice_to_pipe"),
      ),
    ).toBe(true);
    expect(
      VMSPLICE_KERNEL_CONSUMER_ALIAS.sourceHints.some((re) =>
        re.test("generic_pipe_buf_ops"),
      ),
    ).toBe(true);
  });
});

describe("AF_ALG_ANY_ALGORITHM_SPLICE (pattern d)", () => {
  it("covers all 5 AF_ALG algorithm types in config deps", () => {
    const deps = AF_ALG_ANY_ALGORITHM_SPLICE.kernelConfigDeps;
    expect(deps).toContain("CONFIG_CRYPTO_USER_API_SKCIPHER");
    expect(deps).toContain("CONFIG_CRYPTO_USER_API_HASH");
    expect(deps).toContain("CONFIG_CRYPTO_USER_API_RNG");
    expect(deps).toContain("CONFIG_CRYPTO_USER_API_AEAD");
    expect(deps).toContain("CONFIG_CRYPTO_USER_API_AKCIPHER");
  });

  it("source hints cover all algif_*_recvmsg implementations", () => {
    const hints = AF_ALG_ANY_ALGORITHM_SPLICE.sourceHints;
    for (const fn of [
      "algif_skcipher_recvmsg",
      "algif_hash_recvmsg",
      "algif_rng_recvmsg",
      "algif_aead_recvmsg",
      "algif_akcipher_recvmsg",
    ]) {
      expect(hints.some((re) => re.test(fn))).toBe(true);
    }
  });
});

describe("GENERIC_PAGE_WRITE_NO_OWNERSHIP (pattern e — abstract)", () => {
  it("covers multiple subsystems (abstract pattern)", () => {
    expect(GENERIC_PAGE_WRITE_NO_OWNERSHIP.subsystems.length).toBeGreaterThan(3);
  });

  it("references all three foundational CVEs", () => {
    expect(GENERIC_PAGE_WRITE_NO_OWNERSHIP.knownCves).toContain("CVE-2022-0847");
    expect(GENERIC_PAGE_WRITE_NO_OWNERSHIP.knownCves).toContain("CVE-2022-25636");
    expect(GENERIC_PAGE_WRITE_NO_OWNERSHIP.knownCves).toContain("CVE-2026-31431");
  });

  it("source hints match kmap and page ownership checks", () => {
    const hints = GENERIC_PAGE_WRITE_NO_OWNERSHIP.sourceHints;
    expect(hints.some((re) => re.test("kmap"))).toBe(true);
    expect(hints.some((re) => re.test("kmap_atomic"))).toBe(true);
    expect(hints.some((re) => re.test("page_address"))).toBe(true);
    expect(hints.some((re) => re.test("page_count"))).toBe(true);
    expect(hints.some((re) => re.test("copy_highpage"))).toBe(true);
  });
});

// ── matchPatternByRuleId ────────────────────────────────────────────────────

describe("matchPatternByRuleId", () => {
  it("matches exact rule-id for original skb pattern", () => {
    const p = matchPatternByRuleId("kernel/dirty-frag-class/skb-inplace-aead-no-cow");
    expect(p).toBe(SKB_INPLACE_AEAD_NO_COW);
  });

  it("matches exact rule-id for splice crypto pattern", () => {
    const p = matchPatternByRuleId("kernel/dirty-frag-class/splice-inplace-crypto-no-cow");
    expect(p).toBe(SPLICE_INPLACE_CRYPTO_NO_COW);
  });

  it("matches exact rule-id for io_uring pattern", () => {
    const p = matchPatternByRuleId("kernel/dirty-frag-class/splice-iouring-fixed-buffer-alias");
    expect(p).toBe(SPLICE_IOURING_FIXED_BUFFER_ALIAS);
  });

  it("matches exact rule-id for vmsplice pattern", () => {
    const p = matchPatternByRuleId("kernel/dirty-frag-class/vmsplice-kernel-consumer-alias");
    expect(p).toBe(VMSPLICE_KERNEL_CONSUMER_ALIAS);
  });

  it("matches exact rule-id for AF_ALG any-algorithm pattern", () => {
    const p = matchPatternByRuleId("kernel/dirty-frag-class/af-alg-any-algorithm-splice");
    expect(p).toBe(AF_ALG_ANY_ALGORITHM_SPLICE);
  });

  it("matches exact rule-id for generic page-write pattern", () => {
    const p = matchPatternByRuleId("kernel/dirty-frag-class/generic-page-write-no-ownership-check");
    expect(p).toBe(GENERIC_PAGE_WRITE_NO_OWNERSHIP);
  });

  it("matches rule-id with sub-rule suffix", () => {
    const p = matchPatternByRuleId("kernel/dirty-frag-class/skb-inplace-aead-no-cow/esp4");
    expect(p).toBe(SKB_INPLACE_AEAD_NO_COW);
  });

  it("returns undefined for unknown rule-id", () => {
    expect(matchPatternByRuleId("kernel/some-other-rule")).toBeUndefined();
  });

  it("returns undefined for empty rule-id", () => {
    expect(matchPatternByRuleId("")).toBeUndefined();
  });
});

// ── matchPatternsBySourceHints ──────────────────────────────────────────────

describe("matchPatternsBySourceHints", () => {
  it("matches ESP input path to skb pattern", () => {
    const matches = matchPatternsBySourceHints("net/ipv4/esp4.c", "esp4_input_done");
    expect(matches.some((p) => p.id === "skb-inplace-aead-no-cow")).toBe(true);
  });

  it("matches af_alg_make_sg to splice crypto pattern", () => {
    const matches = matchPatternsBySourceHints("crypto/algif_aead.c", "af_alg_make_sg called here");
    expect(matches.some((p) => p.id === "splice-inplace-crypto-no-cow")).toBe(true);
  });

  it("matches io_sqe_buffers_register to io_uring pattern", () => {
    const matches = matchPatternsBySourceHints("io_uring/rsrc.c", "io_sqe_buffers_register");
    expect(matches.some((p) => p.id === "splice-iouring-fixed-buffer-alias")).toBe(true);
  });

  it("matches vmsplice_to_pipe to vmsplice pattern", () => {
    const matches = matchPatternsBySourceHints("fs/splice.c", "vmsplice_to_pipe");
    expect(matches.some((p) => p.id === "vmsplice-kernel-consumer-alias")).toBe(true);
  });

  it("matches algif_hash_recvmsg to AF_ALG any-algorithm pattern", () => {
    const matches = matchPatternsBySourceHints("crypto/algif_hash.c", "algif_hash_recvmsg");
    expect(matches.some((p) => p.id === "af-alg-any-algorithm-splice")).toBe(true);
  });

  it("matches kmap_atomic to generic page-write pattern", () => {
    const matches = matchPatternsBySourceHints("mm/page_alloc.c", "kmap_atomic");
    expect(matches.some((p) => p.id === "generic-page-write-no-ownership-check")).toBe(true);
  });

  it("returns empty array for unrelated file", () => {
    const matches = matchPatternsBySourceHints("drivers/gpu/drm/i915/gem.c", "some unrelated function");
    expect(matches).toHaveLength(0);
  });

  it("can match multiple patterns for overlapping hints", () => {
    // algif_aead_recvmsg appears in both splice-crypto and af-alg patterns
    const matches = matchPatternsBySourceHints("crypto/algif_aead.c", "algif_aead_recvmsg");
    expect(matches.length).toBeGreaterThanOrEqual(2);
    const ids = matches.map((p) => p.id);
    expect(ids).toContain("splice-inplace-crypto-no-cow");
    expect(ids).toContain("af-alg-any-algorithm-splice");
  });
});

// ── filterPatternsForConfig ─────────────────────────────────────────────────

describe("filterPatternsForConfig", () => {
  it("returns all patterns when all configs are enabled", () => {
    const allConfigs = new Set<string>();
    for (const p of DIRTY_FRAG_PATTERN_LIST) {
      for (const dep of p.kernelConfigDeps) {
        allConfigs.add(dep);
      }
    }
    const result = filterPatternsForConfig(allConfigs);
    expect(result).toHaveLength(DIRTY_FRAG_PATTERN_LIST.length);
  });

  it("always includes patterns with no config deps", () => {
    const empty = new Set<string>();
    const result = filterPatternsForConfig(empty);
    // vmsplice and generic have no config deps
    const ids = result.map((p) => p.id);
    expect(ids).toContain("vmsplice-kernel-consumer-alias");
    expect(ids).toContain("generic-page-write-no-ownership-check");
  });

  it("excludes patterns whose config deps are not met", () => {
    const empty = new Set<string>();
    const result = filterPatternsForConfig(empty);
    const ids = result.map((p) => p.id);
    // io_uring pattern requires CONFIG_IO_URING
    expect(ids).not.toContain("splice-iouring-fixed-buffer-alias");
  });

  it("includes io_uring pattern when CONFIG_IO_URING is set", () => {
    const configs = new Set(["CONFIG_IO_URING"]);
    const result = filterPatternsForConfig(configs);
    const ids = result.map((p) => p.id);
    expect(ids).toContain("splice-iouring-fixed-buffer-alias");
  });

  it("includes splice-crypto pattern when any of its deps is set", () => {
    const configs = new Set(["CONFIG_CRYPTO_USER_API_AEAD"]);
    const result = filterPatternsForConfig(configs);
    const ids = result.map((p) => p.id);
    expect(ids).toContain("splice-inplace-crypto-no-cow");
  });
});
