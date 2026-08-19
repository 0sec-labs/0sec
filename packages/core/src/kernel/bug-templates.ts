/**
 * kernel/bug-templates.ts
 *
 * ACTOR-style bug-template DSL (USENIX Sec'23, Fleischer et al.,
 * "ACTOR: Action-Guided Kernel Fuzzing").
 *
 * ACTOR's insight: instead of optimizing code coverage, encode a known bug
 * CLASS as a temporal pattern of *actions* over a shared data structure
 * ("alloc object O, transform O in-place, free O while another thread reads
 * it"), then synthesize fuzzer programs that realize that pattern. A bug we
 * already found becomes a hunter for its own variants.
 *
 * This module is the declarative half of that loop. It lets us write a bug
 * class once, as a {@link BugTemplate}, and get two grounded artifacts out:
 *
 *   1. A STATIC matcher hint ({@link matchTemplate}) — does a slice of kernel
 *      source look like an instance of this class? This feeds the variant-hunt
 *      pipeline (`variant-hunt.ts` / `dirty-frag-patterns.ts`) as a
 *      pre-screening lens, complementing the foxguard/SARIF path.
 *
 *   2. A structured FUZZING OBJECTIVE ({@link templateToFuzzObjective}) — the
 *      ordered syscall action-sequence a fuzzer / spec-gen should aim to
 *      realize, plus the signal that flags a variant. This is the bridge to
 *      `spec-gen.ts` (syzlang generation) and, later, the fuzzer box.
 *
 * Scope of THIS module (simplicity first, deliberately bounded):
 *   - We ENCODE classes and PRODUCE objectives. We do NOT run a fuzzer, emit
 *     syzlang, or compile anything. Those are downstream consumers.
 *   - Templates are grounded in classes we have actually documented:
 *     the CopyFail page-cache-write class (CVE-2026-31431), the in-place
 *     skb-splice class (rxrpc / AEAD-on-shared-frag), and the UAF / refcount
 *     families that dominate net/ and driver bugs.
 */

// ── DSL types ────────────────────────────────────────────────────────────────

/**
 * The role an action plays in the bug pattern. These mirror ACTOR's notion of
 * actions that operate on a shared data structure at different points in time.
 */
export type ActionKind =
  /** Bring the target object into existence (open/socket/mmap/register...). */
  | "alloc"
  /** Make the object's backing memory shared / aliased / pinned. */
  | "alias"
  /** Mutate the object's contents in place (the dangerous step). */
  | "transform"
  /** Read the object's contents — the observer that races or sees corruption. */
  | "read"
  /** Release the object while another action may still reference it. */
  | "free";

/**
 * A single step in a bug-class pattern: a kind of operation, the syscall /
 * kernel entry point that realizes it, and what it does to the target object.
 */
export interface TemplateAction {
  /** Stable id, unique within a template (referenced by signal/notes). */
  id: string;
  kind: ActionKind;
  /** The userspace syscall(s) / kernel entry that realizes this action. */
  syscall: string;
  /**
   * Whether an attacker controls the LENGTH of this action (the classic
   * "write-beyond-output" / attacker-length lever). Only meaningful for
   * `transform`/`read`/`alloc`.
   */
  attackerControlledLength?: boolean;
  /** Free-text note: what this step contributes to the class. */
  note: string;
}

/**
 * The observable signal that distinguishes a true variant from noise — the
 * condition the fuzzer's oracle (or a human triager) checks for.
 */
export interface VariantSignal {
  /** What kind of corruption / safety violation the class produces. */
  kind:
    | "page-cache-corruption"
    | "shared-buffer-corruption"
    | "use-after-free"
    | "refcount-underflow"
    | "oob-write";
  /** Human description of the signal. */
  description: string;
  /**
   * The ordered action ids whose temporal interleaving produces the signal,
   * e.g. ["transform", "read"] means "the in-place transform corrupts what a
   * concurrent reader sees". This is the temporal relationship ACTOR encodes.
   */
  betweenActions: string[];
}

/**
 * A bug CLASS encoded as a pattern of actions over a shared data structure,
 * plus the signal that marks a variant. Grounded in a class we have actually
 * found / documented.
 */
export interface BugTemplate {
  /** Stable identifier (kebab-case). */
  id: string;
  /** Human-readable name. */
  name: string;
  /** The shared data structure / object the actions operate on. */
  targetObject: string;
  /** One-paragraph description of the class. */
  description: string;
  /** Ordered action pattern. The temporal order is load-bearing. */
  actions: TemplateAction[];
  /** What indicates a variant of this class. */
  signal: VariantSignal;
  /**
   * Kernel checks whose ABSENCE is what makes a call site an instance of the
   * class (e.g. skb_cow_data, page_count == 1). Mirrors the dirty-frag
   * `mitigations` field so the two libraries stay consistent.
   */
  missingGuards: string[];
  /** Kconfig symbols that must be enabled for the class to be reachable. */
  kernelConfigDeps: string[];
  /** Subsystems where this class is expected to appear. */
  subsystems: string[];
  /** CVEs known to be instances of this class. */
  knownCves: string[];
  /**
   * Regex hints over source (file paths + function names) that flag a likely
   * instance. Re-uses the same lightweight pre-screen idea as
   * dirty-frag-patterns `sourceHints`.
   */
  sourceHints: RegExp[];
}

// ── Starter catalog ──────────────────────────────────────────────────────────
//
// Each template is grounded in a class we have actually documented:
//   - copyfail-inplace-pagecache  → CVE-2026-31431 (CopyFail / Dirty Frag)
//   - skb-inplace-splice          → in-place AEAD/splice on shared skb frags
//   - uaf-cross-thread            → the net/ + driver cross-thread UAF family
//   - refcount-underflow          → put-without-get / double-put escalation

/**
 * CopyFail page-cache-write class. AF_ALG + splice pins page-cache pages into a
 * crypto scatterlist; the crypto path transforms them IN PLACE with an
 * attacker-controlled length and writes beyond the output, corrupting the page
 * cache that other processes read back. The class is "in-place transform on
 * pinnable pages + write-beyond-output without an ownership/COW guard".
 */
export const COPYFAIL_INPLACE_PAGECACHE: BugTemplate = {
  id: "copyfail-inplace-pagecache",
  name: "CopyFail in-place transform on page-cache pages (write-beyond-output)",
  targetObject: "page-cache page (struct page/folio) pinned into a scatterlist",
  description:
    "An unprivileged user splices page-cache pages into a kernel crypto " +
    "scatterlist (e.g. via an AF_ALG accept FD). The crypto path transforms " +
    "those pages in place with an attacker-controlled length, writing beyond " +
    "the intended output, without first taking ownership (get_page / " +
    "page_count == 1) or copying to a private page. The in-place write " +
    "corrupts the shared page cache, letting the attacker modify file " +
    "contents visible to other processes (CVE-2026-31431, CopyFail / Dirty " +
    "Frag).",
  actions: [
    {
      id: "alloc",
      kind: "alloc",
      syscall: "socket(AF_ALG) + bind + accept",
      note: "Create the crypto transform FD that will consume input pages.",
    },
    {
      id: "alias",
      kind: "alias",
      syscall: "splice(file_fd -> alg_fd) / sendfile",
      note: "Move page-cache pages of a victim file into the crypto input scatterlist without a copy.",
    },
    {
      id: "transform",
      kind: "transform",
      syscall: "read(alg_fd) / recvmsg(alg_fd)",
      attackerControlledLength: true,
      note: "In-place encrypt/decrypt over the aliased pages; attacker length drives write-beyond-output.",
    },
    {
      id: "read",
      kind: "read",
      syscall: "read(file_fd) from another process / page-cache lookup",
      note: "Another reader observes the corrupted page-cache contents.",
    },
  ],
  signal: {
    kind: "page-cache-corruption",
    description:
      "Bytes of a page-cache page change after the in-place transform even " +
      "though no legitimate writer wrote them — a reader of the same file " +
      "sees attacker-modified contents.",
    betweenActions: ["transform", "read"],
  },
  missingGuards: [
    "get_page() / page_ref_inc() before in-place operation",
    "page_count() == 1 check",
    "page_mapcount() == 0 check",
    "copy_highpage() to a private page before modification",
  ],
  kernelConfigDeps: [
    "CONFIG_CRYPTO_USER_API",
    "CONFIG_CRYPTO_USER_API_AEAD",
    "CONFIG_CRYPTO_USER_API_SKCIPHER",
  ],
  subsystems: ["crypto", "fs/splice", "mm"],
  knownCves: ["CVE-2026-31431"],
  sourceHints: [
    /af_alg_(?:make_sg|pull_tsgl|get_rsgl)/,
    /algif_(?:aead|skcipher|hash|rng|akcipher)_recvmsg/,
    /sg_set_page/,
    /(?:generic_file_)?splice_read/,
    /copy_highpage/,
    /page_count|page_mapcount/,
  ],
};

/**
 * In-place skb-splice class. A crypto/network consumer (ESP/AEAD, rxrpc)
 * transforms a SHARED skb fragment in place without skb_cow_data() /
 * skb_unshare(), so the in-place write corrupts the original cloned/aliased
 * buffer that another path still reads.
 */
export const SKB_INPLACE_SPLICE: BugTemplate = {
  id: "skb-inplace-splice",
  name: "In-place transform on shared skb fragment without COW",
  targetObject: "shared/cloned skb fragment (struct sk_buff frags / page)",
  description:
    "A network or crypto consumer (ESP/AEAD decrypt, rxrpc splice) operates " +
    "in place on an skb fragment that is shared — cloned via skb_clone or " +
    "backed by a page-cache page — without first calling skb_cow_data() or " +
    "skb_unshare(). The in-place transform corrupts the original buffer that " +
    "another receiver still reads, an instance of the same shared-memory " +
    "aliasing class as CopyFail but on the skb path.",
  actions: [
    {
      id: "alloc",
      kind: "alloc",
      syscall: "socket(AF_RXRPC|AF_INET ESP) + sendmsg",
      note: "Create the socket/flow whose skb will be transformed.",
    },
    {
      id: "alias",
      kind: "alias",
      syscall: "skb_clone / shared frag via splice",
      note: "Make the skb fragment shared so the in-place write aliases another reader's view.",
    },
    {
      id: "transform",
      kind: "transform",
      syscall: "crypto_aead_decrypt / rxrpc in-place splice",
      attackerControlledLength: true,
      note: "In-place transform on the shared frag without skb_cow_data().",
    },
    {
      id: "read",
      kind: "read",
      syscall: "recvmsg on the other clone / forwarded skb",
      note: "The aliased reader observes corrupted fragment bytes.",
    },
  ],
  signal: {
    kind: "shared-buffer-corruption",
    description:
      "A cloned/shared skb fragment's bytes differ between two readers after " +
      "an in-place transform, indicating a missing COW before mutation.",
    betweenActions: ["transform", "read"],
  },
  missingGuards: [
    "skb_cow_data()",
    "skb_unshare()",
    "pskb_expand_head()",
    "skb_copy()",
  ],
  kernelConfigDeps: ["CONFIG_INET_ESP", "CONFIG_AF_RXRPC", "CONFIG_CRYPTO_AEAD"],
  subsystems: ["net/core", "net/ipv4", "net/rxrpc", "net/xfrm"],
  knownCves: ["CVE-2022-25636", "CVE-2026-43500"],
  sourceHints: [
    /esp[46]_input(?:_done)?/,
    /crypto_aead_decrypt/,
    /skb_cow_data|skb_unshare/,
    /rxrpc_/,
    /skb_clone/,
  ],
};

/**
 * Cross-thread UAF class. One thread frees the target object while another
 * thread still holds and dereferences a pointer to it, because the lifetime is
 * not protected by a refcount/lock spanning both uses. Dominant in net/ and
 * driver ioctl surfaces.
 */
export const UAF_CROSS_THREAD: BugTemplate = {
  id: "uaf-cross-thread",
  name: "Cross-thread use-after-free on a shared object",
  targetObject: "heap object shared between two threads (sock, file, driver ctx)",
  description:
    "Two threads share a pointer to a heap object whose lifetime is not " +
    "guarded by a refcount or lock spanning both uses. One thread frees the " +
    "object (close, teardown, error path) while the other still dereferences " +
    "it, yielding a use-after-free. This is the dominant kernel LPE class on " +
    "net/ and driver ioctl surfaces.",
  actions: [
    {
      id: "alloc",
      kind: "alloc",
      syscall: "open / socket / ioctl(CREATE)",
      note: "Allocate the shared object and obtain a handle in two threads.",
    },
    {
      id: "read",
      kind: "read",
      syscall: "ioctl / read / sendmsg (thread B)",
      note: "Thread B begins an operation that dereferences the object.",
    },
    {
      id: "free",
      kind: "free",
      syscall: "close / ioctl(DESTROY) (thread A)",
      note: "Thread A frees the object concurrently, racing thread B's dereference.",
    },
  ],
  signal: {
    kind: "use-after-free",
    description:
      "Thread B dereferences the object after thread A's free completes " +
      "(KASAN use-after-free), reachable because no shared refcount/lock " +
      "covers both the read and the free.",
    betweenActions: ["read", "free"],
  },
  missingGuards: [
    "refcount_inc_not_zero() before use",
    "lock held across both the use and the free",
    "RCU grace period (synchronize_rcu / call_rcu) before free",
  ],
  kernelConfigDeps: [],
  subsystems: ["net/core", "drivers", "fs"],
  knownCves: [],
  sourceHints: [
    /kfree|kvfree|kmem_cache_free/,
    /refcount_dec|put_device|sock_put|fput/,
    /->\s*\w+\s*\(/,
  ],
};

/**
 * Refcount-underflow class. A put without a matching get (or a double-put on an
 * error path) drives a refcount below its real value, triggering a premature
 * free and an exploitable UAF.
 */
export const REFCOUNT_UNDERFLOW: BugTemplate = {
  id: "refcount-underflow",
  name: "Refcount underflow via unbalanced put / double-put",
  targetObject: "refcounted object (kref / refcount_t / atomic_t users)",
  description:
    "An error or teardown path drops a reference it never took (put without " +
    "get), or drops the same reference twice (double-put), driving the " +
    "refcount below its true value. The object is then freed while still in " +
    "use, producing an exploitable use-after-free. The variant hunt looks for " +
    "put sites on paths that lack a balancing get.",
  actions: [
    {
      id: "alloc",
      kind: "alloc",
      syscall: "open / socket / ioctl(CREATE)",
      note: "Allocate the refcounted object (refcount starts at 1).",
    },
    {
      id: "transform",
      kind: "transform",
      syscall: "ioctl / setsockopt error path",
      note: "Drive the unbalanced-put or double-put path (often an error branch).",
    },
    {
      id: "free",
      kind: "free",
      syscall: "implicit free when refcount hits zero early",
      note: "Premature free as the underflowed refcount reaches zero.",
    },
    {
      id: "read",
      kind: "read",
      syscall: "subsequent use of the still-referenced object",
      note: "A legitimate remaining holder dereferences the freed object.",
    },
  ],
  signal: {
    kind: "refcount-underflow",
    description:
      "A refcount_t warns on underflow / saturate, or an object is freed " +
      "while a legitimate reference is still outstanding, traced to a put " +
      "with no balancing get on the taken path.",
    betweenActions: ["free", "read"],
  },
  missingGuards: [
    "matching get for every put on the path",
    "refcount_t (not raw atomic_t) to catch underflow",
    "single-owner cleanup (no double release on error paths)",
  ],
  kernelConfigDeps: [],
  subsystems: ["net/core", "drivers", "kernel"],
  knownCves: [],
  sourceHints: [
    /refcount_dec(?:_and_test)?|kref_put|put_device|sock_put|fput|dput/,
    /refcount_inc|kref_get|get_device|sock_hold/,
    /err|fail|out_/,
  ],
};

// ── Catalog ──────────────────────────────────────────────────────────────────

/** All bug templates as an array, in catalog order. */
export const BUG_TEMPLATE_LIST: readonly BugTemplate[] = [
  COPYFAIL_INPLACE_PAGECACHE,
  SKB_INPLACE_SPLICE,
  UAF_CROSS_THREAD,
  REFCOUNT_UNDERFLOW,
];

/** All bug templates indexed by stable id. */
export const BUG_TEMPLATES: ReadonlyMap<string, BugTemplate> = new Map(
  BUG_TEMPLATE_LIST.map((t) => [t.id, t]),
);

/** Look up a template by id. */
export function getBugTemplate(id: string): BugTemplate | undefined {
  return BUG_TEMPLATES.get(id);
}

// ── Static matching ──────────────────────────────────────────────────────────

/** Result of matching a template against a slice of subsystem source. */
export interface TemplateMatch {
  templateId: string;
  /** Source hint regexes that fired. */
  matchedHints: string[];
  /**
   * Whether the source shows an in-place TRANSFORM together with at least one
   * other action of the pattern — the minimal shape of an instance. This is a
   * heuristic pre-screen, not a proof.
   */
  hasInPlaceTransform: boolean;
  /** missingGuards whose presence was NOT observed in the source slice. */
  absentGuards: string[];
  /** 0..1 confidence — fraction of hints that fired, boosted by absent guards. */
  score: number;
  /** Whether the match clears the screening bar (score > 0 and a transform). */
  isCandidate: boolean;
}

/**
 * Match a bug template against a slice of subsystem source (file path + body).
 * Returns a static-matcher hint for the variant-hunt pipeline: which hints
 * fired, which mitigating guards are absent, and a screening score.
 *
 * Heuristic and intentionally cheap — a pre-screen before heavier
 * interprocedural analysis (foxguard / CodeQL), not a soundness claim.
 */
export function matchTemplate(
  template: BugTemplate,
  subsystemSource: string,
): TemplateMatch {
  const text = subsystemSource;
  const lower = text.toLowerCase();

  const matchedHints = template.sourceHints
    .filter((re) => re.test(text))
    .map((re) => re.source);

  // An in-place transform shows up as a write to shared memory: the template's
  // transform syscall token, or generic in-place write primitives.
  const transformAction = template.actions.find((a) => a.kind === "transform");
  const transformToken = transformAction
    ? transformAction.syscall.split(/[^a-z0-9_]+/i)[0].toLowerCase()
    : "";
  const hasInPlaceTransform =
    (transformToken.length > 2 && lower.includes(transformToken)) ||
    /in[-_ ]?place|crypto_\w+_(?:en|de)crypt|kmap|page_address|memcpy|memmove/.test(
      lower,
    );

  // A guard is "absent" if none of its identifier tokens appear in the source.
  const absentGuards = template.missingGuards.filter((guard) => {
    const tokens = guard.match(/[a-z_]+\(/gi) ?? [];
    if (tokens.length === 0) return false; // prose-only guard, skip
    return !tokens.some((tok) =>
      lower.includes(tok.replace(/\($/, "").toLowerCase()),
    );
  });

  const hintFraction =
    template.sourceHints.length > 0
      ? matchedHints.length / template.sourceHints.length
      : 0;
  const guardBoost =
    template.missingGuards.length > 0
      ? 0.3 * (absentGuards.length / template.missingGuards.length)
      : 0;
  const transformBoost = hasInPlaceTransform ? 0.2 : 0;
  const score = Math.min(hintFraction + guardBoost + transformBoost, 1);

  return {
    templateId: template.id,
    matchedHints,
    hasInPlaceTransform,
    absentGuards,
    score: Math.round(score * 100) / 100,
    isCandidate: matchedHints.length > 0 && hasInPlaceTransform,
  };
}

/** Match every catalog template against a source slice; return candidates only. */
export function matchAllTemplates(subsystemSource: string): TemplateMatch[] {
  return BUG_TEMPLATE_LIST.map((t) => matchTemplate(t, subsystemSource)).filter(
    (m) => m.isCandidate,
  );
}

// ── Fuzzing objective generation ─────────────────────────────────────────────

/** One step of a fuzzing objective: an action mapped to a syscall to realize. */
export interface FuzzObjectiveStep {
  order: number;
  actionId: string;
  kind: ActionKind;
  /** The syscall / entry point the fuzzer should emit for this step. */
  syscall: string;
  /** Whether the fuzzer should mutate this step's length aggressively. */
  fuzzLength: boolean;
  rationale: string;
}

/**
 * A structured, fuzzer-facing objective derived from a bug template: the
 * target object, the ordered action→syscall sequence to synthesize, the
 * temporal relationship to enforce, and the oracle signal to watch for. This
 * is the artifact spec-gen / the fuzzer consume — analysis output only; this
 * module does not run anything.
 */
export interface FuzzObjective {
  templateId: string;
  name: string;
  targetObject: string;
  /** Ordered action→syscall steps to realize. */
  steps: FuzzObjectiveStep[];
  /**
   * The temporal constraint the synthesized program must satisfy, as action
   * ids, e.g. ["transform", "read"] => "transform must happen before/concurrent
   * with read on the same object".
   */
  temporalRelation: string[];
  /** The oracle signal that flags a variant. */
  signal: VariantSignal;
  /** Kconfig prerequisites for the objective to be reachable. */
  kernelConfigDeps: string[];
  /** Subsystems to target. */
  subsystems: string[];
  /** Known CVEs the class derives from (provenance). */
  knownCves: string[];
}

/**
 * Turn a bug template into a structured fuzzing objective: the ordered syscall
 * action-sequence a fuzzer / spec-gen can target, with attacker-controlled
 * lengths flagged for aggressive mutation and the temporal relation + oracle
 * signal carried through. Pure transform; nothing is executed.
 */
export function templateToFuzzObjective(template: BugTemplate): FuzzObjective {
  const steps: FuzzObjectiveStep[] = template.actions.map((action, i) => ({
    order: i + 1,
    actionId: action.id,
    kind: action.kind,
    syscall: action.syscall,
    fuzzLength: action.attackerControlledLength === true,
    rationale: action.note,
  }));

  return {
    templateId: template.id,
    name: template.name,
    targetObject: template.targetObject,
    steps,
    temporalRelation: template.signal.betweenActions,
    signal: template.signal,
    kernelConfigDeps: template.kernelConfigDeps,
    subsystems: template.subsystems,
    knownCves: template.knownCves,
  };
}

/** Fuzzing objectives for the whole catalog. */
export function allFuzzObjectives(): FuzzObjective[] {
  return BUG_TEMPLATE_LIST.map(templateToFuzzObjective);
}
