/**
 * Concurrency-aware analysis — a cross-function shared-field LOCKSET-INCONSISTENCY
 * race-CANDIDATE generator. 0sec's first increment of concurrency awareness.
 *
 * NOISE CONTROL (why the output is prover-feedable, not a dump): the raw
 * lockset-inconsistency signal is dominated by benign FP classes, so bounded
 * refinements run before a candidate is emitted (measured on the fs/locks + net/unix
 * + ipc/mqueue + posix-timers + fs/notify + ipc/shm sweep):
 *   REFINEMENT 0 (INTERPROCEDURAL LOCK PROPAGATION) — the #1 FP class: a helper
 *     that never takes a lock ITSELF but is only ever CALLED while a caller holds one
 *     (mqueue `__do_notify`/`remove_notification` under `info->lock`, the net/unix GC
 *     leaf helpers under `unix_gc_lock`, `exit_itimers`) looks "unlocked" and gets
 *     flagged. A lightweight subsystem call graph folds the locks a function ALWAYS
 *     runs under (held by ALL its call-sites, MUST-intersection, iterated to a bounded
 *     fixpoint) into that function's field accesses, so the touch is no longer
 *     unlocked and the candidate is suppressed. Callers that DISAGREE propagate
 *     nothing — the candidate is kept (real signal). See {@link computePropagatedLocks}.
 *   FILTER 1 — suppress init/teardown/getter functions on the UNLOCKED side. A field
 *     touched only-unlocked inside a constructor/copy/dumper (`flock_make_lock`,
 *     `lease_init`, `*_alloc`, `lock_get_status`, `*_show`, `shmem_fill_super`, …) is
 *     single-threaded pre-publication or a read-only dump, not a race. See
 *     {@link isSuppressedInconsistentFn}.
 *   FILTER 2 — require a WRITE somewhere in the racing pair. An all-reads-vs-reads
 *     "race" on a lifetime field cannot corrupt memory. To keep this from killing the
 *     REAL list-linkage races (`flc_blocked_requests`/`flc_blocked_member`), a
 *     `&x->field` passed to a list/hlist MUTATOR ({@link LIST_MUTATORS}) counts as a
 *     write to that field.
 * Both are name/AST heuristics with documented misses (see each site). On mm/shmem.c
 * discovery this cut candidates 33→17 (6 init/getter + 7 reads-only removed); the
 * high-value `flc_blocker`/`flc_blocked_requests` cancel-vs-wake candidates survive.
 *
 * WHY this exists (the gap it closes): the seedless invariant checker
 * ({@link ./c-dataflow.ts}, {@link ./subsystem-invariant-model.ts}) is
 * INTRA-procedural and SINGLE-threaded by construction — it reasons about one
 * function, one path, one thread of control. It literally cannot see the bug class
 * that dominates what survives on the hardened, eligible kernel surface: a field
 * mutated by one thread while another thread reads/frees it, because the two
 * accesses live in DIFFERENT functions reachable from independent entry points
 * (two syscalls, a syscall vs. a work/timer/softirq). The intra-proc engine, asked
 * "is this one access correctly locked?", answers "yes" for BOTH sites and never
 * relates them. This module relates them.
 *
 *   subsystem source ──▶ per-function structured MUST lock-set over every access to
 *                        a shared field ──▶ CROSS-FUNCTION Eraser-style consistency
 *                        check ──▶ RaceCandidate[]  (field guarded by L in fn A but
 *                        touched with no lock / a different lock in independently
 *                        reachable fn B) ──▶ HuntCandidate[] for runHuntScan
 *
 * WHAT it computes (the lock-set idea from c-dataflow, lifted cross-function):
 *   1. For each shared field of a modeled object (its lifetime / refcount / state
 *      fields), find EVERY access across ALL functions in the subsystem, and the
 *      set of locks held AT that access (a structured must-analysis over the
 *      function AST — reuses the acquire/release vocabulary and the receiver+field
 *      lock canonicalization from c-dataflow, and additionally sees accessor-macro
 *      accesses `READ_ONCE`/`WRITE_ONCE`/`smp_load_acquire`/`smp_store_release`,
 *      which the intra-proc UAF event stream intentionally skips).
 *   2. Apply the Eraser lockset-refinement idea ACROSS functions: a field that is
 *      accessed while holding lock L in some function(s) but with NO lock (or a
 *      DISJOINT lock) in another, independently reachable function is flagged as a
 *      "possible concurrent access with inconsistent locking" candidate.
 *   3. Prioritize fields whose torn state is a lifetime/refcount pointer (a race on
 *      `->blocker`/`->transport`/`->notify_sock`/a refcount = potential UAF);
 *      de-prioritize pure stat counters.
 *
 * HONEST SCOPE — read before trusting a candidate. This is a race SMELL detector,
 * NOT a proven data race:
 *   - It finds LOCKSET INCONSISTENCY, which is *necessary* but not *sufficient* for
 *     a race. There is NO happens-before analysis and NO interleaving proof. A field
 *     deliberately accessed locklessly with acquire/release memory ordering (exactly
 *     how `fs/locks.c` handles `flc_blocker`) is CORRECT but WILL be flagged. That is
 *     a false positive by construction, and the honest output is "candidate", not
 *     "bug".
 *   - "Independently reachable" is approximated as "different function". REFINEMENT 0
 *     (interprocedural lock propagation) now suppresses the common case where the two
 *     functions share a caller that holds the lock across the call; what remains is a
 *     bounded, documented residue — a callee reached only through a function pointer
 *     (invisible edge), or an EXPORTED function with unknown external callers, is
 *     conservatively treated as a real entry point and still flagged.
 *   - Fields are keyed by NAME (no points-to / no type resolution): a `->state` on
 *     two unrelated structs is unified. Locks are compared by lock-FIELD identity
 *     (receiver-stripped) to blunt the reciprocal aliasing problem, but it remains a
 *     heuristic.
 *   - The two noise filters (above) are name/AST heuristics, so they under- AND
 *     over-fire: a constructor NOT matching the name patterns (e.g. `__shmem_get_inode`,
 *     which allocates but is named `_get_`) leaks a pre-publication write FP through
 *     FILTER 1; conversely a genuinely-concurrent function named like a getter would be
 *     wrongly suppressed. FILTER 2's write requirement drops an all-reads race, which is
 *     benign for UAF but could hide a torn-read-only correctness bug.
 * Race analysis is famously imprecise; treat every candidate as a lead for the
 * downstream skeptic+prover gate (and a real racing repro), never as a finding.
 */

import type Parser from "tree-sitter";
import type { HuntBrief, HuntCandidate } from "./hunt-scan.js";
import type { InvariantModel, InvariantObjectModel } from "./subsystem-invariant-model.js";
import {
  canon,
  collectFunctions,
  DEFAULT_ACQUIRE_FNS,
  DEFAULT_RELEASE_FNS,
  normalizeLockToken,
  parseC,
  releaseFnsFor,
} from "./c-dataflow.js";

type TsNode = Parser.SyntaxNode;

// ── Read-side accessor macros that also count as "lock held" (read-side critical) ─
// RCU read-side is a valid guard for a lockless-looking read; without this the
// checker would flag rcu-guarded reads as unlocked and drown in FPs.
const RCU_ACQUIRE = ["rcu_read_lock", "rcu_read_lock_bh", "rcu_read_lock_sched", "srcu_read_lock"] as const;
const RCU_RELEASE = ["rcu_read_unlock", "rcu_read_unlock_bh", "rcu_read_unlock_sched", "srcu_read_unlock"] as const;

// Accessor macros that wrap a WRITE to the field in their first argument. A field
// touched only through these (never a plain `x->f = ...`) is still a write.
const WRITE_ACCESSORS = new Set(["WRITE_ONCE", "smp_store_release", "smp_store_mb", "rcu_assign_pointer"]);

// List/hlist MUTATORS: a `&x->field` passed to one of these mutates that field's
// list linkage — i.e. it is a WRITE to the field. Without this, list-head fields
// (flc_blocked_requests / flc_blocked_member / flc_list) look read-only (every
// touch is `&x->f` inside a call), so the "require a write" filter would wrongly
// drop the real cancel-vs-wake list races. READ-ONLY list ops (list_empty,
// list_first_entry, list_for_each*, list_entry, list_is_head) are deliberately
// EXCLUDED so a `list_empty(&head)` guard does not count as a write.
const LIST_MUTATORS = new Set([
  "list_add", "list_add_tail", "list_add_rcu", "list_add_tail_rcu",
  "list_del", "list_del_init", "list_del_rcu",
  "list_move", "list_move_tail",
  "list_replace", "list_replace_init", "list_replace_rcu",
  "list_splice", "list_splice_init", "list_splice_tail", "list_splice_tail_init",
  "list_bulk_move_tail", "list_cut_position", "list_rotate_left",
  "hlist_add_head", "hlist_add_head_rcu", "hlist_add_before", "hlist_add_behind",
  "hlist_del", "hlist_del_init", "hlist_del_rcu",
  "INIT_LIST_HEAD", "INIT_HLIST_NODE",
]);

// ── Public types ────────────────────────────────────────────────────────────────

/** One access to a tracked shared field, with the lock-set held AT that access. */
export interface FieldAccessSite {
  /** Repo-relative file. */
  file: string;
  /** The enclosing function. */
  functionName: string;
  /** 1-based line of the access. */
  line: number;
  /** The tracked field name (as written after `->`/`.`). */
  field: string;
  /** Whether this access writes the field (best-effort: assignment LHS or a write-accessor macro). */
  isWrite: boolean;
  /** Canonical lock keys held at this point (e.g. `blocked_lock_lock`, `ctx->flc_lock`). */
  locks: string[];
  /** Receiver-stripped lock IDENTITIES (e.g. `blocked_lock_lock`, `flc_lock`) used for consistency. */
  lockIdentities: string[];
  /**
   * Lock identities added by INTERPROCEDURAL propagation — locks NOT acquired in
   * this function but held by ALL of its (in-subsystem) call-sites, so the callee
   * runs under them (e.g. `__do_notify` under mqueue's `info->lock`). Empty for a
   * directly-locked or genuinely-lockless access. Folded into {@link lockIdentities}
   * for the consistency check; kept separate for provenance in the report/tests.
   */
  propagatedLocks: string[];
}

/**
 * One in-subsystem call-site of a (subsystem-defined) function, with the MUST
 * lock-set held by the CALLER at the call. Feeds the interprocedural lock
 * propagation: a callee whose every call-site holds lock L runs under L.
 */
export interface CallSiteRecord {
  /** The function making the call. */
  caller: string;
  /** The called function's name (plain-identifier callees only). */
  callee: string;
  /** Receiver-stripped lock identities held by the caller AT this call. */
  lockIdentities: string[];
}

export type RaceCandidateKind =
  /** The field is guarded by a consistent lock in some functions but touched with NO lock in another. */
  | "unlocked-vs-locked"
  /** The locked accesses themselves disagree — some hold lock A, some lock B (no common guard). */
  | "inconsistent-locks";

/** Confidence in the field being genuinely shared-mutable (NOT in it being a real race). */
export type RaceSeverity = "high" | "medium" | "low";

/** One cross-function lockset-inconsistency race candidate for a single field. */
export interface RaceCandidate {
  kind: RaceCandidateKind;
  /** The modeled object the field belongs to (or `"(discovered)"` in discovery mode). */
  object: string;
  /** The shared field the inconsistency is on. */
  field: string;
  /**
   * UAF-relevance of the field, used to rank: `high` = a lifetime/refcount/pointer
   * field (a race here is potential UAF), `low` = a stat counter (a race here is at
   * worst a torn statistic), `medium` = everything else.
   */
  severity: RaceSeverity;
  /** The lock identity/identities the majority of locked accesses agree on (the presumed guard). */
  guardConsensus: string[];
  /** Whether at least one racing access was detected as a WRITE (a read/read-only set cannot race). */
  hasWrite: boolean;
  /** Accesses that hold a consensus guard lock. */
  consensusAccesses: FieldAccessSite[];
  /** Accesses that hold NO consensus lock (unlocked or disjoint-locked) — the inconsistent side. */
  inconsistentAccesses: FieldAccessSite[];
  /** Human-readable, honest summary of the smell. */
  detail: string;
}

export interface FindRaceCandidatesOptions {
  /** Cap emitted candidates (default 40). */
  maxCandidates?: number;
  /**
   * ALSO discover shared fields not named in the model: any field accessed in ≥2
   * distinct functions AND under a lock in ≥1 of them. Lets the checker run against
   * a thin/empty model. Default false (model-seeded only, as specified).
   */
  discoverSharedFields?: boolean;
  /** Cap auto-discovered fields per subsystem (default 40) to keep the scan bounded. */
  maxDiscoveredFields?: number;
  /**
   * Enable the interprocedural (call-graph) lock-propagation refinement that
   * suppresses the callee-under-caller's-lock FP class (a helper flagged as
   * "unlocked" only because the lock is held by its callers). Default `true`.
   * Set `false` to reproduce the pre-propagation (intra-procedural-lock) behavior.
   */
  interprocLockPropagation?: boolean;
  /**
   * Max propagation fixpoint rounds (default 8). Round 1 is the pure ONE-LEVEL
   * rule (a callee inherits the intersection of its direct callers' held locks);
   * each further round lets a lock held N frames up reach a callee through a chain
   * of always-under-that-lock call-sites (e.g. the unix GC leaf helpers, which sit
   * two frames below `unix_gc_lock`). Bounded to keep recursion/deep graphs finite.
   */
  maxPropagationRounds?: number;
  log?: (msg: string) => void;
}

// ── Field classification (UAF-relevance for ranking) ────────────────────────────

// Pointer / lifetime / refcount-ish field names: a race on one of these can be a
// use-after-free or refcount underflow. Deliberately broad — ranking, not gating.
const UAF_RELEVANT_RE =
  /(blocker|blocked|transport|notify_sock|sock$|_sk$|owner|next$|prev$|list$|head$|node$|link$|member|waiter|task|file$|cred|parent|child|ref$|refcnt|refcount|users$|usage|count$|ptr$|obj$|dev$|queue$)/i;

// Pure statistic / counter fields: a race here is at worst a torn number.
const STAT_RE = /(stat|packets|bytes|drops|errors|jiffies|_time$|nr_|num_|_bps$|throughput|latency)/i;

function classifyField(field: string, obj: InvariantObjectModel | null): RaceSeverity {
  const hasLifetime = !!obj && (obj.lifecycleRules.length > 0 || obj.refcountRules.length > 0);
  if (STAT_RE.test(field) && !UAF_RELEVANT_RE.test(field)) return "low";
  if (UAF_RELEVANT_RE.test(field) || hasLifetime) return "high";
  return "medium";
}

// ── FP FILTER 1: init / teardown / getter-function suppression ───────────────────
//
// The dominant FP class this checker emits is SINGLE-THREADED pre-publication or
// read-only access: a field written while a freshly-allocated object is still
// private to its constructor, or read by a /proc dumper / lookup. Those functions
// run before the object is shared (constructors/init/copy) or only observe it
// (getters/dumps), so an "unlocked" access there is NOT a real concurrent race.
// We suppress such functions from the INCONSISTENT (unlocked/disjoint-lock) side
// of a candidate only — the locked/consensus side is never suppressed.
//
// HONEST LIMITS: this is a NAME + read-only heuristic, no call-graph reachability.
//   - A constructor whose name doesn't match the patterns (e.g. `__shmem_get_inode`,
//     which allocates but is named `_get_`) is only caught by the pure-reader arm
//     when it reads, NOT when it writes — so a constructor-write FP can survive.
//   - A genuinely concurrent function that happens to be named `*_show`/`*_free`
//     would be wrongly suppressed. In this subsystem none are; documented residual.

// Strong constructor / teardown / dumper / mount-parse names: suppressed regardless
// of read-vs-write, because init WRITES are pre-publication and dumps are read-only.
const INIT_TEARDOWN_FN_RE = new RegExp(
  [
    "(^|_)init($|_)", // *_init, init_*, locks_init_lock_heads
    "(^|_)alloc($|_)", // locks_alloc_lock, shmem_alloc_inode, alloc_posix_timer (leading alloc)
    "_create($|_)",
    "_make_", // flock_make_lock
    "_copy($|_)", // locks_copy_conflock / locks_copy_lock
    "_dup($|_)",
    "_clone($|_)",
    "_to_[a-z0-9_]+_lock$", // flock64_to_posix_lock (userspace→lock converter)
    "_setup$", // lease_setup
    "_ctor$",
    "(^|_)new_", // new_inode-style
    "_show$", // locks_show, show_fd_locks (via ^show_ below)
    "^show_",
    "_show_options$", // shmem_show_options
    "_get_status$", // lock_get_status
    "_dump(_|$)", // locks_dump_ctx_list
    "_seq_show$",
    "_free($|_)", // locks_free_lock, shmem_free_inode, shmem_free_fc
    "_destroy($|_)",
    "_release($|_)", // locks_release_private
    "_evict($|_)", // shmem_evict_inode
    "_put_super$", // shmem_put_super
    "_fini$",
    "_fill_super$", // shmem_fill_super
    "_parse($|_)", // shmem_parse_one
    "_reconfigure$", // shmem_reconfigure
    "_get_tree$",
  ].join("|"),
  "i",
);

// Weaker getter/lookup hints: suppressed ONLY when the function is a PURE READER of
// the field (never writes it there) — a getter-ish name AND read-only usage together
// mark a read-side consumer (lookup / match / encode / stat), not a racing writer.
const GETTER_HINT_RE = /(_get_|_lookup|_find(_|$)|_match$|_encode_|_stat($|_)|_seq_|_show)/i;

/** Should this inconsistent-side access be suppressed as init/teardown/getter noise? */
function isSuppressedInconsistentFn(fnName: string, fnWritesField: boolean): boolean {
  if (INIT_TEARDOWN_FN_RE.test(fnName)) return true;
  if (!fnWritesField && GETTER_HINT_RE.test(fnName)) return true;
  return false;
}

// ── Lock vocabulary + identity ──────────────────────────────────────────────────

interface LockVocab {
  acquire: Set<string>;
  release: Set<string>;
}

/** Build the acquire/release token vocabulary: defaults + RCU read-side + model custom. */
function buildLockVocab(model: InvariantModel): LockVocab {
  const acquire = new Set<string>([...DEFAULT_ACQUIRE_FNS, ...RCU_ACQUIRE]);
  const release = new Set<string>([...DEFAULT_RELEASE_FNS, ...RCU_RELEASE]);
  for (const obj of model.objects) {
    for (const rule of obj.lockRules) {
      if (rule.acquireFns) {
        for (const a of rule.acquireFns) acquire.add(a);
        for (const r of releaseFnsFor(rule.acquireFns)) release.add(r);
      }
    }
  }
  return { acquire, release };
}

/** Receiver-stripped lock identity: the lock FIELD (or the global name). */
function lockIdentity(lockKey: string): string {
  const n = normalizeLockToken(lockKey);
  return n.global ? n.key : n.lockField;
}

// ── Structured MUST lock-set over one function's AST ─────────────────────────────

interface WalkResult {
  /** True if this subtree unconditionally leaves the enclosing block (return/goto/break/continue). */
  diverged: boolean;
}

const intersect = (a: Set<string>, b: Set<string>): Set<string> => {
  const out = new Set<string>();
  for (const k of a) if (b.has(k)) out.add(k);
  return out;
};
const replaceInPlace = (target: Set<string>, next: Set<string>): void => {
  target.clear();
  for (const k of next) target.add(k);
};

/**
 * Record every access to a tracked field in a function, with a structured MUST
 * lock-set held at each access. `tracked === null` means record ALL fields (used by
 * discovery). This is a source-ordered, brace-scope-aware must-analysis: at a branch
 * it clones the held-set per branch and merges by INTERSECTION on fall-through, and
 * it discards a branch's lock mutations when the branch diverges (return/goto) — so
 * the common `lock(); if (err) { unlock(); return; } ...access...; unlock();` pattern
 * correctly reports the lock still held at the post-`if` access. It is NOT a full
 * CFG (no goto-join lattice), which is the documented residual imprecision.
 */
function analyzeFunction(
  fnBody: TsNode,
  src: string,
  file: string,
  fnName: string,
  tracked: Set<string> | null,
  vocab: LockVocab,
  sink: FieldAccessSite[],
  callSink?: CallSiteRecord[],
): void {
  const held = new Set<string>();
  // >0 while walking the arguments of a list/hlist MUTATOR call: every `&x->field`
  // inside them is a write to that field's linkage. Balanced increment/decrement.
  let mutatorArgDepth = 0;

  const recordAccess = (node: TsNode, field: string, isWrite: boolean): void => {
    const snapshot = [...held].sort();
    sink.push({
      file,
      functionName: fnName,
      line: node.startPosition.row + 1,
      field,
      isWrite,
      locks: snapshot,
      lockIdentities: [...new Set(snapshot.map(lockIdentity))].sort(),
      propagatedLocks: [],
    });
  };

  const recordCallSite = (callee: string): void => {
    if (!callSink || !callee) return;
    // Lock identities held by THIS function at the call point (before the call's
    // own acquire/release effect) — the caller-side lock-set the callee inherits.
    callSink.push({
      caller: fnName,
      callee,
      lockIdentities: [...new Set([...held].map(lockIdentity))].sort(),
    });
  };

  const callArg0Key = (args: TsNode | null): string | null => {
    const a0 = args?.namedChildren[0];
    return a0 ? canon(a0, src) : null;
  };

  // walk returns whether the subtree diverges. `held` is mutated in place for
  // straight-line threading; branch nodes clone/merge explicitly.
  const walk = (node: TsNode, assignTarget: boolean): WalkResult => {
    switch (node.type) {
      case "call_expression": {
        const callee = node.childForFieldName("function");
        const name = callee && callee.type === "identifier" ? src.slice(callee.startIndex, callee.endIndex) : "";
        const args = node.childForFieldName("arguments");
        const isWriteAccessor = WRITE_ACCESSORS.has(name);
        const isListMutator = LIST_MUTATORS.has(name);
        // Recurse into args in source order to catch tracked field accesses in them
        // (incl. arg0: this is how READ_ONCE/smp_load_acquire wrap a shared access).
        if (args) {
          const kids = args.namedChildren;
          // A `&x->field` arg of a list mutator is a WRITE to that field's linkage.
          if (isListMutator) mutatorArgDepth++;
          for (let i = 0; i < kids.length; i++) {
            // arg0 of a write-accessor is a WRITE to that field.
            walk(kids[i], i === 0 && isWriteAccessor);
          }
          if (isListMutator) mutatorArgDepth--;
        }
        // Record the call-site with the caller's CURRENT lock-set (before this
        // call's own acquire/release effect) for interprocedural propagation.
        if (name && !vocab.acquire.has(name) && !vocab.release.has(name)) recordCallSite(name);
        // Apply the lock effect AFTER evaluating args.
        if (vocab.acquire.has(name)) {
          const key = callArg0Key(args);
          if (key) held.add(key);
        } else if (vocab.release.has(name)) {
          const key = callArg0Key(args);
          if (key) held.delete(key);
        }
        return { diverged: false };
      }
      case "field_expression": {
        const fieldNode = node.childForFieldName("field");
        const field = fieldNode ? src.slice(fieldNode.startIndex, fieldNode.endIndex) : "";
        if (field && (tracked === null || tracked.has(field)))
          recordAccess(node, field, assignTarget || mutatorArgDepth > 0);
        // Recurse into the receiver so `a->b->c` records inner accesses too. The
        // receiver fields are the ACCESS PATH, not the mutated linkage / assigned
        // lvalue, so clear both write-contexts for them: in `&x->c.flc_list` only
        // `flc_list` is the written linkage, `c` is just the path (a read).
        const arg = node.childForFieldName("argument");
        if (arg) {
          const savedDepth = mutatorArgDepth;
          mutatorArgDepth = 0;
          walk(arg, false);
          mutatorArgDepth = savedDepth;
        }
        return { diverged: false };
      }
      case "assignment_expression": {
        // Covers `=` and augmented forms (`+=`, `|=`, …): the LHS is a write.
        const left = node.childForFieldName("left");
        const right = node.childForFieldName("right");
        if (right) walk(right, false);
        if (left) walk(left, true);
        return { diverged: false };
      }
      case "update_expression": {
        // `x->f++` / `--x->f`: the operand is read AND written — treat as a write.
        const arg = node.childForFieldName("argument");
        if (arg) walk(arg, true);
        return { diverged: false };
      }
      case "if_statement": {
        const cond = node.childForFieldName("condition");
        if (cond) walk(cond, false);
        const consequence = node.childForFieldName("consequence");
        const alternative = node.childForFieldName("alternative");

        // Walk each branch against its OWN clone of the entry held-set; walkAgainst
        // leaves `held` unchanged and writes the branch's exit lock-set into the clone.
        const thenHeld = new Set(held);
        const thenDiverged = consequence ? walkAgainst(consequence, thenHeld, false) : false;

        // elseHeld === a copy of the entry held-set when there is no `else` (the
        // cond-false path simply falls through with the entry locks still held).
        const elseHeld = new Set(held);
        let elseDiverged = false;
        if (alternative) {
          const altStmt =
            alternative.type === "else_clause" ? alternative.namedChildren[0] ?? alternative : alternative;
          elseDiverged = walkAgainst(altStmt, elseHeld, false);
        }

        // Merge fall-through paths by MUST intersection; a diverging branch (one that
        // returns/gotos) contributes no fall-through lock-set.
        if (thenDiverged && elseDiverged) return { diverged: true }; // post-if unreachable
        let merged: Set<string>;
        if (thenDiverged) merged = elseHeld; // only the else/fall-through path continues
        else if (elseDiverged) merged = thenHeld;
        else merged = intersect(thenHeld, elseHeld);
        replaceInPlace(held, merged);
        return { diverged: false };
      }
      case "while_statement":
      case "for_statement": {
        const init = node.childForFieldName("initializer");
        if (init) walk(init, false);
        const cond = node.childForFieldName("condition");
        if (cond) walk(cond, false);
        const body = node.childForFieldName("body");
        const update = node.childForFieldName("update");
        const before = new Set(held);
        if (body) {
          // Walk the body against a CLONE (never `held` itself — walkAgainst would
          // empty it). Body may run 0 times → MUST held after = intersect(entry, exit).
          const bodyHeld = new Set(held);
          walkAgainst(body, bodyHeld, false);
          if (update) walkAgainst(update, bodyHeld, false);
          replaceInPlace(held, intersect(before, bodyHeld));
        }
        return { diverged: false };
      }
      case "do_statement": {
        // Body runs ≥1 time → its effects persist.
        const body = node.childForFieldName("body");
        if (body) walk(body, false);
        const cond = node.childForFieldName("condition");
        if (cond) walk(cond, false);
        return { diverged: false };
      }
      case "switch_statement": {
        const cond = node.childForFieldName("condition");
        if (cond) walk(cond, false);
        const body = node.childForFieldName("body");
        // Walk each case against a clone (record accesses); conservatively leave the
        // post-switch held-set unchanged (switch rarely establishes a durable lock).
        if (body) {
          for (const caseNode of body.namedChildren) {
            const clone = new Set(held);
            walkAgainst(caseNode, clone, false);
          }
        }
        return { diverged: false };
      }
      case "return_statement": {
        for (const k of node.namedChildren) walk(k, false);
        return { diverged: true };
      }
      case "goto_statement":
      case "break_statement":
      case "continue_statement": {
        return { diverged: true };
      }
      case "labeled_statement": {
        // A goto target is a join point; we don't model incoming goto lock-sets, so
        // we keep the fall-through held-set (kernel error labels are typically
        // reached with the lock still held). Documented imprecision.
        let diverged = false;
        for (const k of node.namedChildren) {
          if (k.type === "statement_identifier") continue;
          diverged = walk(k, false).diverged || diverged;
        }
        return { diverged };
      }
      case "compound_statement": {
        let diverged = false;
        for (const child of node.namedChildren) {
          const r = walk(child, false);
          if (r.diverged) {
            diverged = true;
            break; // rest of the block is dead code
          }
        }
        return { diverged };
      }
      default: {
        let diverged = false;
        for (const child of node.namedChildren) {
          if (walk(child, assignTarget).diverged) diverged = true;
        }
        return { diverged };
      }
    }
  };

  // Walk `node` with `target` as the live held-set (temporarily swaps `held`).
  const walkAgainst = (node: TsNode, target: Set<string>, assignTarget: boolean): boolean => {
    const saved = new Set(held);
    replaceInPlace(held, target);
    const r = walk(node, assignTarget);
    replaceInPlace(target, held);
    replaceInPlace(held, saved);
    return r.diverged;
  };

  walk(fnBody, false);
}

// ── Collect accesses across the whole subsystem ─────────────────────────────────

function collectAccesses(
  sources: Array<{ file: string; text: string }>,
  tracked: Set<string> | null,
  vocab: LockVocab,
  log: (m: string) => void,
  callSink?: CallSiteRecord[],
  definedFns?: Set<string>,
): FieldAccessSite[] {
  const sink: FieldAccessSite[] = [];
  for (const { file, text } of sources) {
    const root = parseC(text);
    if (!root) {
      log(`[concurrency] parse failed for ${file}`);
      continue;
    }
    for (const fn of collectFunctions(root, text)) {
      if (definedFns) definedFns.add(fn.name);
      analyzeFunction(fn.body, text, file, fn.name, tracked, vocab, sink, callSink);
    }
  }
  return sink;
}

// ── Interprocedural (call-graph) lock propagation ───────────────────────────────
//
// THE REFINEMENT. The dominant FP the intra-procedural lock-set emits is the
// callee-under-caller's-lock case: a helper (`__do_notify`, `remove_notification`,
// the net/unix GC leaf helpers, `exit_itimers`) that never acquires a lock ITSELF
// but is only ever reached while a caller holds one, so its field touches look
// "unlocked" and get flagged against the properly-locked accesses elsewhere.
//
// FIX: over the subsystem call graph, compute for each DEFINED function the set of
// lock identities held at EVERY one of its in-subsystem call-sites (a MUST /
// intersection analysis). If that set is non-empty, the function always runs under
// those locks, so they are folded into the lock-set of its field accesses — the
// touch is no longer "unlocked" and the benign candidate is suppressed. If callers
// DISAGREE (one holds L, another doesn't) the intersection is empty and nothing is
// propagated, so the candidate is KEPT (that inconsistency is real signal — this is
// exactly what preserves fs/locks' `flc_blocker`, whose lockless fast-path caller
// `locks_delete_block` holds no lock at the call).
//
// The base rule is ONE-LEVEL (a callee inherits its direct callers' held locks). It
// is iterated to a bounded fixpoint so a lock held several frames up (the unix GC
// tree holds `unix_gc_lock` two frames above the leaf helpers) reaches a leaf when
// every intermediate call-site is itself under the (already-propagated) lock.
//
// HONEST LIMITS:
//   • NAME-BASED graph, no points-to: two static same-named functions collapse;
//     indirect / function-pointer / macro-expanded calls are invisible edges, so a
//     callee reached ONLY through a function pointer looks call-site-less (an entry
//     point) and is never suppressed (conservative — keeps the candidate).
//   • ONLY IN-SUBSYSTEM call-sites are seen. An EXPORTED function (EXPORT_SYMBOL)
//     has external callers we cannot inspect, which may hold no lock, so exported
//     functions are treated as un-propagatable (kept lockless) to avoid FALSELY
//     suppressing a genuine candidate reached lock-free from outside the subsystem.
//   • Context-INSENSITIVE MUST analysis: one lock-free call-site anywhere defeats
//     propagation for that callee (sound for avoiding false suppression, but it can
//     UNDER-suppress — a helper lock-free on a dead/unrelated path stays flagged).
//   • A function with zero in-subsystem call-sites is an independent entry point and
//     gets no propagation by construction.

/** Names of functions exported out of the subsystem (external, possibly lock-free, callers). */
function collectExportedSymbols(sources: Array<{ file: string; text: string }>): Set<string> {
  const out = new Set<string>();
  const re = /EXPORT_SYMBOL(?:_GPL|_NS|_NS_GPL)?\s*\(\s*([A-Za-z_]\w*)/g;
  for (const { text } of sources) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) out.add(m[1]);
  }
  return out;
}

/**
 * Compute, per defined function, the lock identities it ALWAYS runs under (folded
 * into its field accesses). See the block comment above for the rule + limits.
 */
function computePropagatedLocks(
  callSites: CallSiteRecord[],
  definedFns: Set<string>,
  exported: Set<string>,
  maxRounds: number,
): Map<string, string[]> {
  // callee → its in-subsystem call-sites (only calls to functions we actually
  // analyze can be annotated; library calls like spin_lock are irrelevant here).
  const byCallee = new Map<string, CallSiteRecord[]>();
  for (const cs of callSites) {
    if (!definedFns.has(cs.callee)) continue;
    const arr = byCallee.get(cs.callee);
    if (arr) arr.push(cs);
    else byCallee.set(cs.callee, [cs]);
  }

  // Fixpoint over MUST-intersection. `prop` grows monotonically (each round can only
  // add locks a caller now carries), so it converges; `maxRounds` bounds recursion
  // and deep chains. An exported callee is pinned empty (external lock-free callers).
  const prop = new Map<string, Set<string>>();
  for (let round = 0; round < Math.max(1, maxRounds); round++) {
    let changed = false;
    for (const [callee, sites] of byCallee) {
      if (exported.has(callee)) continue; // un-propagatable: keep lockless
      // Intersection over call-sites of (locks held at the site) ∪ (locks the
      // CALLER itself always runs under — the one-hop lift that makes it iterate).
      let acc: Set<string> | null = null;
      for (const cs of sites) {
        const callerProp = prop.get(cs.caller) ?? new Set<string>();
        const atSite = new Set<string>([...cs.lockIdentities, ...callerProp]);
        if (acc === null) acc = atSite;
        else acc = intersect(acc, atSite);
        if (acc.size === 0) break;
      }
      const next = acc ?? new Set<string>();
      const prev = prop.get(callee) ?? new Set<string>();
      if (next.size !== prev.size || [...next].some((k) => !prev.has(k))) {
        prop.set(callee, next);
        changed = true;
      }
    }
    if (!changed) break;
  }

  const out = new Map<string, string[]>();
  for (const [fn, set] of prop) if (set.size > 0) out.set(fn, [...set].sort());
  return out;
}

// ── Eraser-style cross-function consistency check ───────────────────────────────

/** Mode (most frequent) identity across a list of identity-sets. */
function modeIdentity(sets: string[][]): string | null {
  const counts = new Map<string, number>();
  for (const s of sets) for (const id of s) counts.set(id, (counts.get(id) ?? 0) + 1);
  let best: string | null = null;
  let bestN = 0;
  for (const [id, n] of counts) if (n > bestN) ((bestN = n), (best = id));
  return best;
}

/** Intersection of a list of identity-sets (Eraser refinement). Empty if they disagree. */
function intersectAll(sets: string[][]): Set<string> {
  if (sets.length === 0) return new Set();
  let acc = new Set(sets[0]);
  for (let i = 1; i < sets.length; i++) acc = intersect(acc, new Set(sets[i]));
  return acc;
}

/**
 * The cross-function lockset-inconsistency race-candidate generator.
 *
 * Given the invariant model (for the shared-field seed + UAF-relevance ranking) and
 * the subsystem sources, computes each shared field's per-access lock-set across ALL
 * functions and flags the fields whose locking is INCONSISTENT across independently
 * reachable functions. Deterministic; NO LLM.
 */
export function findRaceCandidates(
  model: InvariantModel,
  sources: Array<{ file: string; text: string }>,
  opts: FindRaceCandidatesOptions = {},
): RaceCandidate[] {
  const log = opts.log ?? (() => {});
  const maxCandidates = opts.maxCandidates ?? 40;
  const vocab = buildLockVocab(model);

  // 1. Seed the tracked shared fields from the model (its objects' guarded fields).
  const fieldToObject = new Map<string, InvariantObjectModel>();
  const tracked = new Set<string>();
  for (const obj of model.objects) {
    for (const rule of obj.lockRules) {
      for (const f of rule.guardedFields) {
        tracked.add(f);
        if (!fieldToObject.has(f)) fieldToObject.set(f, obj);
      }
    }
  }

  // 1b. Optionally discover additional shared fields (accessed in ≥2 fns, ≥1 locked).
  if (opts.discoverSharedFields) {
    const all = collectAccesses(sources, null, vocab, log);
    const byField = new Map<string, { fns: Set<string>; locked: boolean }>();
    for (const a of all) {
      const e = byField.get(a.field) ?? { fns: new Set<string>(), locked: false };
      e.fns.add(a.functionName);
      if (a.lockIdentities.length > 0) e.locked = true;
      byField.set(a.field, e);
    }
    const discovered = [...byField.entries()]
      .filter(([f, e]) => e.locked && e.fns.size >= 2 && !tracked.has(f))
      .map(([f]) => f)
      .slice(0, opts.maxDiscoveredFields ?? 40);
    for (const f of discovered) tracked.add(f);
    if (discovered.length > 0) log(`[concurrency] discovered ${discovered.length} extra shared field(s): ${discovered.join(", ")}`);
  }

  if (tracked.size === 0) {
    log("[concurrency] no shared fields to track (empty model, discovery off)");
    return [];
  }

  // 2. One pass to collect every access to a tracked field + its lock-set, and (for
  //    the interprocedural refinement) every in-subsystem call-site with the caller's
  //    held lock-set + the set of defined function names.
  const callSites: CallSiteRecord[] = [];
  const definedFns = new Set<string>();
  const propagate = opts.interprocLockPropagation ?? true;
  const accesses = collectAccesses(
    sources,
    tracked,
    vocab,
    log,
    propagate ? callSites : undefined,
    propagate ? definedFns : undefined,
  );

  // 2b. Interprocedural lock propagation: fold the locks a function ALWAYS runs
  //     under (held by all its call-sites) into its field accesses, suppressing the
  //     callee-under-caller's-lock FP class. See computePropagatedLocks for the rule.
  if (propagate) {
    const exported = collectExportedSymbols(sources);
    const propByFn = computePropagatedLocks(callSites, definedFns, exported, opts.maxPropagationRounds ?? 8);
    let augmented = 0;
    for (const a of accesses) {
      const extra = propByFn.get(a.functionName);
      if (!extra || extra.length === 0) continue;
      const added = extra.filter((id) => !a.lockIdentities.includes(id));
      if (added.length === 0) continue;
      a.propagatedLocks = added;
      a.lockIdentities = [...new Set([...a.lockIdentities, ...added])].sort();
      augmented++;
    }
    if (augmented > 0) log(`[concurrency] interproc lock-propagation folded caller locks into ${augmented} access(es)`);
  }

  const byField = new Map<string, FieldAccessSite[]>();
  for (const a of accesses) {
    const arr = byField.get(a.field);
    if (arr) arr.push(a);
    else byField.set(a.field, [a]);
  }

  // 3. Per field, apply the Eraser cross-function consistency check.
  const candidates: RaceCandidate[] = [];
  let droppedInitGetter = 0; // FP FILTER 1: inconsistent side was all init/teardown/getter
  let droppedReadsOnly = 0; // FP FILTER 2: no write anywhere in the racing pair
  for (const [field, sites] of byField) {
    const locked = sites.filter((s) => s.lockIdentities.length > 0);
    if (locked.length === 0) continue; // never locked anywhere → no discipline to violate

    // Consensus guard: Eraser intersection of the locked accesses' identities; if
    // they disagree (empty), fall back to the single most-frequent lock.
    const inter = intersectAll(locked.map((s) => s.lockIdentities));
    let consensus: Set<string>;
    let kind: RaceCandidateKind;
    if (inter.size > 0) {
      consensus = inter;
      kind = "unlocked-vs-locked";
    } else {
      const mode = modeIdentity(locked.map((s) => s.lockIdentities));
      consensus = mode ? new Set([mode]) : new Set();
      kind = "inconsistent-locks";
    }
    if (consensus.size === 0) continue;

    const holdsConsensus = (s: FieldAccessSite) => s.lockIdentities.some((id) => consensus.has(id));
    const consensusAccesses = sites.filter(holdsConsensus);
    const inconsistentRaw = sites.filter((s) => !holdsConsensus(s));
    if (consensusAccesses.length === 0 || inconsistentRaw.length === 0) continue;

    // FP FILTER 1 — suppress init/teardown/getter functions on the inconsistent
    // (unlocked/disjoint-lock) side. A function is "pure reader of the field" if it
    // never writes THIS field anywhere; getter-hint names are only suppressed then.
    const fnWritesField = new Set(
      sites.filter((s) => s.isWrite).map((s) => s.functionName),
    );
    const inconsistentAccesses = inconsistentRaw.filter(
      (s) => !isSuppressedInconsistentFn(s.functionName, fnWritesField.has(s.functionName)),
    );
    // If every inconsistent access was init/getter noise, the smell was benign
    // single-threaded/read-only access — drop the candidate entirely.
    if (inconsistentAccesses.length === 0) {
      droppedInitGetter++;
      continue;
    }

    // Require the two sides to live in DIFFERENT functions (independently reachable
    // ≈ distinct entry points). Same-function lock-then-unlock is normal.
    const consensusFns = new Set(consensusAccesses.map((s) => s.functionName));
    const crossFn = inconsistentAccesses.some((s) => !consensusFns.has(s.functionName));
    if (!crossFn) continue;

    const obj = fieldToObject.get(field) ?? null;
    const severity = classifyField(field, obj);
    // FP FILTER 2 — require a WRITE somewhere in the racing pair (over the surviving
    // accesses). An all-reads-vs-reads "race" on a lifetime field cannot corrupt
    // memory (nobody mutates it), so it is benign for UAF purposes: drop it.
    const hasWrite = [...consensusAccesses, ...inconsistentAccesses].some((s) => s.isWrite);
    if (!hasWrite) {
      droppedReadsOnly++;
      continue;
    }

    const guard = [...consensus].sort();
    const badFns = [...new Set(inconsistentAccesses.filter((s) => !consensusFns.has(s.functionName)).map((s) => s.functionName))];
    const detail =
      `Field '${field}'${obj ? ` of ${obj.object}` : ""} is accessed while holding ${guard.join("/")} in ` +
      `${[...consensusFns].join(", ")}, but with ${kind === "unlocked-vs-locked" ? "NO consensus lock" : "a DISJOINT lock-set"} in ` +
      `${badFns.join(", ")} — independently reachable. ${hasWrite ? "At least one racing access is a WRITE." : "No write detected among racing accesses (read/read — lower confidence)."} ` +
      `SMELL ONLY: no happens-before proof; a field intentionally accessed with acquire/release memory ordering is a false positive here.`;

    candidates.push({
      kind,
      object: obj?.object ?? "(discovered)",
      field,
      severity,
      guardConsensus: guard,
      hasWrite,
      consensusAccesses,
      inconsistentAccesses,
      detail,
    });
  }

  // 4. Rank: high severity first, writes before read/read, more inconsistent sites first.
  const sevRank: Record<RaceSeverity, number> = { high: 0, medium: 1, low: 2 };
  candidates.sort(
    (a, b) =>
      sevRank[a.severity] - sevRank[b.severity] ||
      Number(b.hasWrite) - Number(a.hasWrite) ||
      b.inconsistentAccesses.length - a.inconsistentAccesses.length ||
      a.field.localeCompare(b.field),
  );
  const capped = candidates.slice(0, maxCandidates);
  log(
    `[concurrency] ${candidates.length} race candidate(s)` +
      `${capped.length < candidates.length ? ` (capped to ${capped.length})` : ""}` +
      ` — filtered out ${droppedInitGetter} init/teardown/getter + ${droppedReadsOnly} reads-only FP field(s)`,
  );
  return capped;
}

// ── Map to runHuntScan candidates (parallel to violationsToHuntPlan) ────────────

export interface RaceHuntPlan {
  /** The race candidates found. */
  candidates: RaceCandidate[];
  /** One `runHuntScan` brief describing the concurrency bug class. */
  brief: HuntBrief;
  /** `runHuntScan` candidate sites (one per file, merged per-site hints). */
  huntCandidates: HuntCandidate[];
}

/**
 * Turn race candidates into a {@link HuntBrief} + {@link HuntCandidate}[] that plug
 * straight into `runHuntScan`, grouped per file (one candidate per file, merged
 * hints), so the downstream finder + skeptic + prover gate confirms or kills each
 * lockset-inconsistency smell against the real code and a racing repro.
 */
export function raceCandidatesToHuntPlan(model: InvariantModel, candidates: RaceCandidate[]): RaceHuntPlan {
  const bySite = new Map<string, HuntCandidate>();
  for (const c of candidates) {
    // Anchor the hint at the inconsistent (unlocked/differently-locked) side.
    const anchor = c.inconsistentAccesses[0];
    const file = anchor?.file ?? c.consensusAccesses[0]?.file ?? model.subsystemFiles[0] ?? "unknown";
    const badSites = c.inconsistentAccesses.map((s) => `${s.functionName}():${s.line}`).join(", ");
    const goodSites = c.consensusAccesses.map((s) => `${s.functionName}():${s.line}`).join(", ");
    const hint =
      `RACE CANDIDATE (${c.severity}, ${c.kind}) — lockset inconsistency on field '${c.field}' of ${c.object}. ` +
      `Guarded by ${c.guardConsensus.join("/")} at ${goodSites}; touched WITHOUT it at ${badSites}. ${c.detail}`;
    const existing = bySite.get(file);
    if (existing) existing.hint = `${existing.hint}\n---\n${hint}`;
    else bySite.set(file, { path: file, hint });
  }
  const brief: HuntBrief = {
    bugClass: "concurrency: cross-function lockset-inconsistency race candidate (possible UAF/data race)",
    pattern:
      "A shared struct field is accessed while holding a lock in one function but with no lock (or a disjoint lock) in " +
      "another, independently reachable function (a distinct syscall / work / timer / softirq entry). Confirm the two " +
      "accesses can genuinely run concurrently (no caller-held lock, no acquire/release ordering that makes the lockless " +
      "access safe) and that at least one is a write, then look for the torn-state primitive (UAF on a lifetime pointer, " +
      "refcount underflow, or a data race). This is a SMELL, not a proven race — no happens-before analysis was done.",
    fixReference: undefined,
  };
  return { candidates, brief, huntCandidates: [...bySite.values()] };
}
