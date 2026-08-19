/**
 * Dirty-frag pattern library — shared-memory aliasing vulnerability class.
 *
 * The "Dirty Frag" class (CVE-2026-31431 / Copy Fail) is an *instance* of a
 * broader vulnerability pattern: any in-place operation on shared/aliased memory
 * without ownership verification.  Eric Biggers (kernel crypto maintainer) noted
 * that ALL AF_ALG exploits follow this general shape — the crypto subsystem
 * operates in-place on buffers whose provenance it doesn't verify.
 *
 * This module defines the pattern library so foxguard (or any SARIF-producing
 * scanner) can classify findings, and so the variant-hunt pipeline can attach
 * richer metadata to each candidate.
 *
 * See: https://github.com/0sec-labs/0sec/issues/470
 */

// ── Types ───────────────────────────────────────────────────────────────────

export interface DirtyFragPattern {
  /** Stable identifier used as the foxguard rule-id suffix. */
  id: string;
  /** Human-readable name. */
  name: string;
  /** One-paragraph description of the pattern. */
  description: string;
  /** Syscall / API sequence that triggers the vulnerability. */
  triggerConditions: string[];
  /**
   * Key kernel checks that, if present, mitigate the issue.
   * Absence of these checks is what makes a call site vulnerable.
   */
  mitigations: string[];
  /** Kernel Kconfig symbols that must be enabled for the pattern to be reachable. */
  kernelConfigDeps: string[];
  /** Kernel subsystems where this pattern is expected to appear. */
  subsystems: string[];
  /** CVEs known to be instances of this pattern. */
  knownCves: string[];
  /** Foxguard rule-id prefix: `kernel/dirty-frag-class/<id>`. */
  ruleIdPrefix: string;
  /**
   * Regex patterns that match against source code (file paths + function names)
   * to flag potential instances.  Used for lightweight pre-screening before
   * heavier interprocedural analysis.
   */
  sourceHints: RegExp[];
}

// ── Pattern definitions ─────────────────────────────────────────────────────

/**
 * Pattern 0 (original): in-place AEAD on shared skb frag without COW.
 *
 * The original dirty-frag pattern: ESP/AEAD decrypts in-place on a shared
 * skb fragment without calling skb_cow_data / skb_unshare first.
 */
export const SKB_INPLACE_AEAD_NO_COW: DirtyFragPattern = {
  id: "skb-inplace-aead-no-cow",
  name: "In-place AEAD on shared skb frag without COW",
  description:
    "ESP or another AEAD consumer decrypts in-place on a shared skb fragment " +
    "without calling skb_cow_data() or skb_unshare() first. If the fragment " +
    "is shared (e.g. cloned via skb_clone, or backed by a page-cache page), " +
    "the in-place write corrupts the original data.",
  triggerConditions: [
    "skb with shared frags enters ESP/AEAD decrypt path",
    "crypto_aead_decrypt() called on skb->data or frag pages without prior skb_cow_data()",
  ],
  mitigations: [
    "skb_cow_data()",
    "skb_unshare()",
    "pskb_expand_head()",
    "skb_copy()",
  ],
  kernelConfigDeps: [
    "CONFIG_INET_ESP",
    "CONFIG_INET6_ESP",
    "CONFIG_CRYPTO_AEAD",
  ],
  subsystems: ["net/ipv4", "net/ipv6", "net/xfrm"],
  knownCves: ["CVE-2022-25636"],
  ruleIdPrefix: "kernel/dirty-frag-class",
  sourceHints: [
    /esp[46]_input(?:_done)?/,
    /crypto_aead_decrypt/,
    /skb_cow_data/,
    /xfrm_input/,
  ],
};

/**
 * Pattern (a): splice + in-place crypto on non-COW pages.
 *
 * The Copy Fail pattern: splice() moves page-cache pages into a crypto
 * scatterlist, crypto operates in-place, corrupting the page cache.
 */
export const SPLICE_INPLACE_CRYPTO_NO_COW: DirtyFragPattern = {
  id: "splice-inplace-crypto-no-cow",
  name: "splice + in-place crypto on non-COW page-cache pages",
  description:
    "splice() moves page-cache pages into a crypto scatterlist (e.g. via " +
    "AF_ALG accept FD). The crypto subsystem then operates in-place on those " +
    "pages without verifying ownership (get_page/page_ref_inc) or checking " +
    "page_mapcount(). This corrupts the page cache, allowing an unprivileged " +
    "user to modify file contents visible to other processes.",
  triggerConditions: [
    "splice() source FD -> AF_ALG accept FD",
    "read()/aio_read() on the crypto FD triggers in-place encrypt/decrypt",
    "page-cache pages passed without copy-on-write",
  ],
  mitigations: [
    "get_page() / page_ref_inc() before in-place operation",
    "page_mapcount() check to detect shared pages",
    "copy_highpage() to private buffer before modification",
    "af_alg_make_sg() with GFP allocation for private copies",
  ],
  kernelConfigDeps: [
    "CONFIG_CRYPTO_USER_API",
    "CONFIG_CRYPTO_USER_API_AEAD",
    "CONFIG_CRYPTO_USER_API_SKCIPHER",
  ],
  subsystems: ["crypto", "fs/splice"],
  knownCves: ["CVE-2026-31431"],
  ruleIdPrefix: "kernel/dirty-frag-class",
  sourceHints: [
    /af_alg_(?:make_sg|pull_tsgl|async_cb)/,
    /algif_aead_recvmsg/,
    /algif_skcipher_recvmsg/,
    /splice_to_pipe/,
    /direct_splice_actor/,
    /generic_file_splice_read/,
  ],
};

/**
 * Pattern (b): sendfile/splice into io_uring fixed buffers.
 *
 * io_uring registered buffers (IORING_REGISTER_BUFFERS) pin user pages.
 * If splice/sendfile moves page-cache pages into these buffers and io_uring
 * operates on them in-place, the same aliasing corruption occurs.
 */
export const SPLICE_IOURING_FIXED_BUFFER_ALIAS: DirtyFragPattern = {
  id: "splice-iouring-fixed-buffer-alias",
  name: "splice/sendfile into io_uring fixed buffers aliasing page cache",
  description:
    "io_uring registered buffers (IORING_REGISTER_BUFFERS) pin user pages. " +
    "If splice or sendfile moves page-cache pages into these pinned buffers, " +
    "and io_uring subsequently operates on them in-place via " +
    "IORING_OP_READ_FIXED / IORING_OP_WRITE_FIXED, the page cache is " +
    "corrupted through the aliased mapping.",
  triggerConditions: [
    "IORING_REGISTER_BUFFERS pins user pages",
    "splice()/sendfile() moves page-cache pages into registered buffer range",
    "IORING_OP_READ_FIXED or IORING_OP_WRITE_FIXED on the aliased pages",
  ],
  mitigations: [
    "io_uring buffer registration should copy pages, not pin shared ones",
    "page_count() == 1 check before pinning",
    "FOLL_PIN with unpin_user_page() to detect aliasing",
  ],
  kernelConfigDeps: [
    "CONFIG_IO_URING",
  ],
  subsystems: ["io_uring", "fs/splice", "mm"],
  knownCves: [],
  ruleIdPrefix: "kernel/dirty-frag-class",
  sourceHints: [
    /io_sqe_buffers_register/,
    /io_uring_register/,
    /IORING_REGISTER_BUFFERS/,
    /io_read_fixed/,
    /io_write_fixed/,
    /splice_to_pipe/,
  ],
};

/**
 * Pattern (c): vmsplice aliasing with any in-kernel consumer.
 *
 * vmsplice() can push user pages into a pipe without copying.  If a kernel
 * consumer reads from the pipe and operates in-place (or holds a reference
 * beyond the expected lifetime), the user can modify data the kernel thinks
 * is stable.
 */
export const VMSPLICE_KERNEL_CONSUMER_ALIAS: DirtyFragPattern = {
  id: "vmsplice-kernel-consumer-alias",
  name: "vmsplice user-page aliasing with in-kernel pipe consumer",
  description:
    "vmsplice() pushes user-space pages into a pipe without copying (when " +
    "SPLICE_F_GIFT is not set, pages may be aliased). If a kernel consumer " +
    "reads from the pipe and either operates in-place on the page data or " +
    "holds a reference beyond the expected lifetime, the user can mutate " +
    "data the kernel considers immutable. This is a generalization of the " +
    "Dirty Pipe (CVE-2022-0847) class.",
  triggerConditions: [
    "vmsplice() pushes user pages into pipe without SPLICE_F_GIFT",
    "kernel consumer reads from pipe and operates in-place",
    "consumer does not copy page data to private buffer before use",
  ],
  mitigations: [
    "Pipe consumer must copy data (iov_iter_copy_from_user_atomic or equivalent)",
    "SPLICE_F_GIFT must trigger page stealing, not aliasing",
    "Pipe buffer ops->release must drop page references correctly",
  ],
  kernelConfigDeps: [],
  subsystems: ["fs/splice", "fs/pipe", "net/core", "crypto"],
  knownCves: ["CVE-2022-0847"],
  ruleIdPrefix: "kernel/dirty-frag-class",
  sourceHints: [
    /vmsplice_to_pipe/,
    /splice_pipe_to/,
    /pipe_buf_release/,
    /pipe_buf_operations/,
    /generic_pipe_buf_ops/,
    /page_cache_pipe_buf_ops/,
  ],
};

/**
 * Pattern (d): page-cache writes from any AF_ALG algorithm.
 *
 * Copy Fail used AEAD (GCM), but AF_ALG exposes: skcipher, hash, rng, aead,
 * akcipher.  Each algorithm type's `*_recvmsg` implementation needs to be
 * checked for in-place operations on spliced pages.
 */
export const AF_ALG_ANY_ALGORITHM_SPLICE: DirtyFragPattern = {
  id: "af-alg-any-algorithm-splice",
  name: "AF_ALG any algorithm type in-place operation on spliced pages",
  description:
    "AF_ALG exposes multiple crypto algorithm types to userspace: skcipher, " +
    "hash, rng, aead, and akcipher.  Each type's recvmsg() implementation " +
    "may operate in-place on spliced page-cache pages. The Copy Fail CVE " +
    "demonstrated this for AEAD/GCM, but the pattern applies to every " +
    "algorithm type whose recvmsg path writes to input scatterlist pages " +
    "without verifying ownership.",
  triggerConditions: [
    "AF_ALG socket created with any algorithm type (skcipher, hash, rng, aead, akcipher)",
    "splice() provides page-cache pages as input",
    "algif_*_recvmsg() writes to scatterlist pages in-place",
  ],
  mitigations: [
    "Each algif_*_recvmsg must copy spliced pages before in-place operation",
    "af_alg_get_rsgl() should allocate private pages for output",
    "SGL_FLG_PAGES_ALLOCED flag to distinguish owned vs. borrowed pages",
  ],
  kernelConfigDeps: [
    "CONFIG_CRYPTO_USER_API",
    "CONFIG_CRYPTO_USER_API_SKCIPHER",
    "CONFIG_CRYPTO_USER_API_HASH",
    "CONFIG_CRYPTO_USER_API_RNG",
    "CONFIG_CRYPTO_USER_API_AEAD",
    "CONFIG_CRYPTO_USER_API_AKCIPHER",
  ],
  subsystems: ["crypto"],
  knownCves: ["CVE-2026-31431"],
  ruleIdPrefix: "kernel/dirty-frag-class",
  sourceHints: [
    /algif_skcipher_recvmsg/,
    /algif_hash_recvmsg/,
    /algif_rng_recvmsg/,
    /algif_aead_recvmsg/,
    /algif_akcipher_recvmsg/,
    /af_alg_get_rsgl/,
    /af_alg_pull_tsgl/,
    /af_alg_alloc_areq/,
  ],
};

/**
 * Pattern (e): generic in-place operation on struct page * without ownership check.
 *
 * The abstract pattern: function receives a struct page *, writes to it or
 * modifies its contents, without verifying page_count() == 1, PagePrivate,
 * or calling copy_highpage().
 */
export const GENERIC_PAGE_WRITE_NO_OWNERSHIP: DirtyFragPattern = {
  id: "generic-page-write-no-ownership-check",
  name: "In-place write to struct page without ownership verification",
  description:
    "The abstract dirty-frag pattern: a kernel function receives a " +
    "struct page * (or a scatterlist / bio_vec referencing pages), writes " +
    "to its contents via kmap/kmap_atomic/page_address, without first " +
    "verifying page_count() == 1, checking PagePrivate, or calling " +
    "copy_highpage() to create a private copy.  This is the root cause " +
    "of all shared-memory aliasing vulnerabilities in the kernel.",
  triggerConditions: [
    "Function receives struct page * from an untrusted or shared source",
    "Function writes to the page via kmap(), kmap_atomic(), or page_address()",
    "No ownership check: page_count() == 1, PagePrivate, or page_mapcount() == 0",
    "No private copy: copy_highpage() or alloc_page() + copy not called",
  ],
  mitigations: [
    "page_count() == 1 check before write",
    "PagePrivate flag verification",
    "copy_highpage() to private page before modification",
    "page_mapcount() == 0 check (no other mappings)",
    "GUP (get_user_pages) with FOLL_PIN and proper unpin",
  ],
  kernelConfigDeps: [],
  subsystems: ["mm", "crypto", "fs/splice", "io_uring", "net/core", "block"],
  knownCves: [
    "CVE-2022-0847",
    "CVE-2022-25636",
    "CVE-2026-31431",
  ],
  ruleIdPrefix: "kernel/dirty-frag-class",
  sourceHints: [
    /kmap(?:_atomic|_local_page)?/,
    /page_address/,
    /sg_set_page/,
    /sg_assign_page/,
    /bio_add_page/,
    /copy_highpage/,
    /page_count/,
    /page_mapcount/,
    /PagePrivate/,
  ],
};

/**
 * Pattern (f): page-cache provenance via zero-copy ingress.
 *
 * The Copy Fail recipe as a first-class pattern: an attacker uses a zero-copy
 * ingress API (splice / MSG_SPLICE_PAGES / vmsplice / sendfile / AF_ALG) to
 * deliver page-cache pages of a file it can read into a kernel scatterlist or
 * skb frag, then the kernel performs an in-place STORE on that page without a
 * copy-on-write — because the page's *provenance* (it came from the page cache
 * of a file the caller cannot write) is never checked. The differentiator from
 * the generic struct-page pattern is the SOURCE: the page is a borrowed
 * page-cache page reached through zero-copy ingress, which is what turns an
 * in-place op into an arbitrary-file write primitive.
 */
export const PAGECACHE_PROVENANCE_ZEROCOPY_INGRESS: DirtyFragPattern = {
  id: "pagecache-provenance-zerocopy-ingress",
  name: "Page-cache provenance not verified on zero-copy ingress before in-place store",
  description:
    "A zero-copy ingress API (splice, MSG_SPLICE_PAGES, vmsplice, sendfile, " +
    "or AF_ALG algif_* recvmsg/sendmsg) delivers page-cache pages of a " +
    "file the attacker can read into a kernel scatterlist or skb frag. The " +
    "kernel then performs an in-place STORE (crypto decrypt with src == dst, " +
    "header rewrite, memcpy through kmap) without proving the page is owned " +
    "or copying it first. Because the page is a borrowed page-cache page, the " +
    "in-place write corrupts file contents the caller could not otherwise " +
    "modify — a page-cache write primitive (Copy Fail). Audit the " +
    "SKBFL_SHARED_FRAG set-vs-checked asymmetry, skb_cow_data/skb_unshare " +
    "COW-skip fast paths, and req->src == req->dst in-place crypto.",
  triggerConditions: [
    "Zero-copy ingress (splice / MSG_SPLICE_PAGES / vmsplice / sendfile / AF_ALG) supplies page-cache pages",
    "Pages reach a scatterlist or skb frag and are stored in-place (req->src == req->dst, or set SKBFL_SHARED_FRAG)",
    "No skb_has_shared_frag / skb->data_len check before the in-place op",
    "No page provenance / ownership proof: page_mapcount, folio mapping, or copy-on-write",
  ],
  mitigations: [
    "skb_cow_data() / skb_unshare() before the in-place op (no shared-frag COW-skip fast path)",
    "skb_has_shared_frag(skb) / skb->data_len gate before in-place store",
    "Distinct destination scatterlist (req->dst != req->src) for page-cache-backed sources",
    "page_mapcount() / folio->mapping check to reject page-cache pages",
    "copy_highpage() / copy_user_highpage() to a private page before modification",
  ],
  kernelConfigDeps: [
    "CONFIG_CRYPTO_USER_API",
    "CONFIG_CRYPTO_USER_API_AEAD",
    "CONFIG_CRYPTO_USER_API_SKCIPHER",
  ],
  subsystems: ["crypto", "fs/splice", "net/core", "net/ipv4", "net/ipv6", "mm"],
  knownCves: ["CVE-2026-43284", "CVE-2026-46300", "CVE-2026-31431"],
  ruleIdPrefix: "kernel/dirty-frag-class",
  sourceHints: [
    /MSG_SPLICE_PAGES/,
    /SKBFL_SHARED_FRAG/,
    /skb_has_shared_frag/,
    /skb_cow_data/,
    /skb_unshare/,
    /sendpage|splice_to_pipe|generic_file_splice_read/,
    /req->src|->src\s*==\s*->dst|sg_init_one/,
  ],
};

/**
 * Pattern (g): release-path uncancelled work → use-after-free / controlled
 * indirect call.
 *
 * The meson-vdec / seq_midi shape (and the mtk-jpeg / media release-work
 * family): an object owns a work_struct / delayed_work / timer / tasklet or an
 * ops function pointer, and the release/remove/disconnect/close teardown frees
 * the object WITHOUT first cancelling the pending work with the matching
 * cancel_*_sync / del_timer_sync / tasklet_kill. A work item that fires after
 * the free dereferences — and indirect-calls through — freed memory, giving a
 * controlled indirect call. Copy-paste sibling drivers rarely all receive the
 * cancel fix, so this pairs with the incomplete-fix variant hunt.
 */
export const RELEASE_PATH_UNCANCELLED_WORK_UAF: DirtyFragPattern = {
  id: "release-path-uncancelled-work-uaf",
  name: "Object freed in release path without cancelling its pending work (UAF / controlled indirect call)",
  description:
    "An object that owns a work_struct, delayed_work, timer_list, tasklet, or " +
    "an ops/callback function pointer is freed in a ->release / ->remove / " +
    "->disconnect / ->close path or an error label WITHOUT a preceding " +
    "cancel_work_sync / cancel_delayed_work_sync / del_timer_sync / " +
    "tasklet_kill / flush_workqueue. The still-queued work fires after the " +
    "free and dereferences (and indirect-calls through) freed memory — a " +
    "use-after-free that yields a controlled indirect call. Richest in " +
    "drivers/media, sound/, and drivers/usb where sibling drivers copy the " +
    "release path. Note the cancel_*_work_sync -> disable_*_work_sync " +
    "migration: a re-queue after a plain cancel is the same UAF.",
  triggerConditions: [
    "Object owns a work_struct / delayed_work / timer_list / tasklet / ops fn-ptr",
    "Object is freed (kfree/kvfree/put_device/*_free) in ->release/->remove/->disconnect/->close or an error label",
    "No cancel_work_sync / cancel_delayed_work_sync / del_timer_sync / tasklet_kill before the free",
    "Userspace can trigger the teardown (close(2), unbind, device removal) while work is queued",
  ],
  mitigations: [
    "cancel_work_sync() / cancel_delayed_work_sync() before freeing the owner",
    "del_timer_sync() / timer_shutdown_sync() before free",
    "tasklet_kill() before free",
    "flush_workqueue() / destroy_workqueue() on the owning workqueue before free",
    "disable_work_sync() / disable_delayed_work_sync() to also prevent re-queue",
  ],
  kernelConfigDeps: [],
  subsystems: ["drivers/media", "sound", "drivers/usb", "drivers/gpu", "net/core"],
  knownCves: [],
  ruleIdPrefix: "kernel/dirty-frag-class",
  sourceHints: [
    /work_struct|delayed_work|timer_list|tasklet_struct/,
    /cancel_work_sync|cancel_delayed_work_sync/,
    /del_timer_sync|timer_shutdown_sync|tasklet_kill/,
    /disable_work_sync|disable_delayed_work_sync/,
    /\.release\s*=|\.remove\s*=|\.disconnect\s*=/,
    /flush_workqueue|destroy_workqueue/,
  ],
};

// ── Pattern library ─────────────────────────────────────────────────────────

/** All dirty-frag patterns, indexed by stable id. */
export const DIRTY_FRAG_PATTERNS: ReadonlyMap<string, DirtyFragPattern> = new Map([
  [SKB_INPLACE_AEAD_NO_COW.id, SKB_INPLACE_AEAD_NO_COW],
  [SPLICE_INPLACE_CRYPTO_NO_COW.id, SPLICE_INPLACE_CRYPTO_NO_COW],
  [SPLICE_IOURING_FIXED_BUFFER_ALIAS.id, SPLICE_IOURING_FIXED_BUFFER_ALIAS],
  [VMSPLICE_KERNEL_CONSUMER_ALIAS.id, VMSPLICE_KERNEL_CONSUMER_ALIAS],
  [AF_ALG_ANY_ALGORITHM_SPLICE.id, AF_ALG_ANY_ALGORITHM_SPLICE],
  [GENERIC_PAGE_WRITE_NO_OWNERSHIP.id, GENERIC_PAGE_WRITE_NO_OWNERSHIP],
  [PAGECACHE_PROVENANCE_ZEROCOPY_INGRESS.id, PAGECACHE_PROVENANCE_ZEROCOPY_INGRESS],
  [RELEASE_PATH_UNCANCELLED_WORK_UAF.id, RELEASE_PATH_UNCANCELLED_WORK_UAF],
]);

/** All dirty-frag patterns as an array. */
export const DIRTY_FRAG_PATTERN_LIST: readonly DirtyFragPattern[] = [
  SKB_INPLACE_AEAD_NO_COW,
  SPLICE_INPLACE_CRYPTO_NO_COW,
  SPLICE_IOURING_FIXED_BUFFER_ALIAS,
  VMSPLICE_KERNEL_CONSUMER_ALIAS,
  AF_ALG_ANY_ALGORITHM_SPLICE,
  GENERIC_PAGE_WRITE_NO_OWNERSHIP,
  PAGECACHE_PROVENANCE_ZEROCOPY_INGRESS,
  RELEASE_PATH_UNCANCELLED_WORK_UAF,
];

// ── Matching helpers ────────────────────────────────────────────────────────

/**
 * Given a foxguard rule-id (e.g. "kernel/dirty-frag-class/splice-inplace-crypto-no-cow"),
 * return the matching pattern, or undefined if no match.
 */
export function matchPatternByRuleId(ruleId: string): DirtyFragPattern | undefined {
  for (const pattern of DIRTY_FRAG_PATTERN_LIST) {
    const fullPrefix = `${pattern.ruleIdPrefix}/${pattern.id}`;
    if (ruleId === fullPrefix || ruleId.startsWith(`${fullPrefix}/`)) {
      return pattern;
    }
  }
  return undefined;
}

/**
 * Given a file path and optional message text, return all patterns whose
 * sourceHints match.  Useful for pre-screening source files before heavier
 * interprocedural analysis.
 */
export function matchPatternsBySourceHints(
  filePath: string,
  message?: string,
): DirtyFragPattern[] {
  const text = message ? `${filePath} ${message}` : filePath;
  return DIRTY_FRAG_PATTERN_LIST.filter((pattern) =>
    pattern.sourceHints.some((re) => re.test(text)),
  );
}

/**
 * Given a set of enabled kernel config symbols (e.g. from a .config file),
 * return the patterns that are reachable — i.e. whose kernelConfigDeps are
 * all satisfied.  Patterns with no config deps are always included.
 */
export function filterPatternsForConfig(
  enabledConfigs: ReadonlySet<string>,
): DirtyFragPattern[] {
  return DIRTY_FRAG_PATTERN_LIST.filter((pattern) => {
    if (pattern.kernelConfigDeps.length === 0) return true;
    return pattern.kernelConfigDeps.some((dep) => enabledConfigs.has(dep));
  });
}
