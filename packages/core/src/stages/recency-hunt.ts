/**
 * recency-hunt — the RECENCY FLYWHEEL orchestration stage.
 *
 * The hard-won thesis this encodes: the frozen kernelCTF-LTS snapshot is TAPPED
 * because it is a *hardened* snapshot — syzkaller + the top exploit groups have
 * already swept it. Bugs live in the RECENCY WINDOW: just-committed code, in the
 * days before that same machinery hardens it. The only structure that beats the
 * audit-density wall is one that continuously hunts the freshness window.
 *
 * Pipeline (each arrow narrows the funnel — most commits SHOULD filter out):
 *
 *   git diff <range> on the kernel tree
 *        │  changed files + hunks
 *        ▼
 *   REACHABILITY filter  ({@link isReachablePath})  ── drop HW drivers, arch/,
 *        │                 tools/, docs, CAP-gated-only paths. Keep unpriv-
 *        │                 reachable, kernelCTF-eligible-ish subsystems.
 *        ▼
 *   SEMANTIC-vs-COSMETIC classifier  ({@link classifySemanticVsCosmetic})
 *        │  The KEY filter. A diff that renames / reformats / reshapes control
 *        │  flow AROUND UNCHANGED get/put/lock/free/alloc logic is COSMETIC → skip.
 *        │  A diff that ADDS / REMOVES / REORDERS a get/put/lock/free/alloc, or
 *        │  changes a refcount/lifetime field's handling, is SEMANTIC → hunt.
 *        │  (Deterministic {@link lifetimeTokenSignal} pre-computes the signal;
 *        │   the LLM is the authority and gets that signal as a hint.)
 *        ▼
 *   REFINED ENGINE on the semantic-changed files — ALL THREE detectors share ONE
 *        │  invariant model (built once per file) and feed the SAME adversarial gate:
 *        │   • dataflow — {@link runSubsystemInvariantHunt}: buildInvariantModel →
 *        │     findViolationsDataflow (intra-proc lock-set + reaching-free) → gate.
 *        │   • refcount — {@link findInterprocRefcountCouplings}: call-graph-aware
 *        │     get/put coupling; keeps `leak-suspect` (non-balanced) couplings. A
 *        │     fresh commit can add a CROSS-FILE refcount leak the intra-proc path
 *        │     structurally cannot see.
 *        │   • race — {@link findRaceCandidates}: cross-function lockset-inconsistency
 *        │     with interproc lock propagation; keeps high-severity write-bearing
 *        │     candidates. A fresh commit can add a CROSS-THREAD race, not just an
 *        │     intra-proc lifetime bug.
 *        │  Each candidate is tagged with its detector; all flow through the same
 *        │  runHuntScan skeptic gate. Detector selection is configurable (default all).
 *        ▼
 *   ADVERSARIAL VERIFY (the skeptic gate, assume-FP) → confirmed, ranked
 *        │
 *        ▼
 *   RANKED REPORT (JSON + markdown): funnel counts, per-file verdicts,
 *   high-confidence survivors flagged + shaped as an autoclimb bug-spec.
 *
 * WHY the vsock MSG_ZEROCOPY lead was FALSE (encoded here): that "rewrite" only
 * reshaped branch layout ON TOP OF an already-landed refcount fix — no
 * reintroduction. So the filter signal is a SEMANTIC lifetime-logic change, NOT
 * "the file was rewritten." {@link lifetimeTokenSignal} is exactly that
 * discriminator: identical get/put/lock multiset across +/- lines ⇒ cosmetic.
 *
 * HONEST SCOPE: a survivor is a LEAD worth weaponizing, not a proven 0-day. The
 * skeptic gate refutes over-approximation FPs but does not PROVE; novelty (is it
 * already patched later in the same window?) and real reachability are the
 * downstream gates the operator runs before any disclosure. NOTHING here sends.
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding, RuntimeMode } from "@0sec/shared";
import { LlmApiRuntime } from "../runtime/llm-api.js";
import {
  resolveContainedSourcePath,
  runSubsystemInvariantHunt,
  type InvariantModel,
  type SubsystemInvariantHuntInput,
  type SubsystemInvariantHuntResult,
} from "./subsystem-invariant-model.js";
import {
  couplingsToHuntPlan,
  findInterprocRefcountCouplings,
  type RefcountCoupling,
} from "./interproc-refcount.js";
import {
  findRaceCandidates,
  raceCandidatesToHuntPlan,
  type RaceCandidate,
} from "./concurrency-race.js";
import {
  makeSkepticVerifier,
  runHuntScan,
  type HuntBrief,
  type HuntCandidate,
  type HuntScanResult,
  type HuntVerifier,
} from "./hunt-scan.js";
import { runAssumptionHunt } from "./assumption-mining.js";
import type { DynamicWitnessDeps, WitnessResult, WitnessMode } from "./dynamic-witness.js";

// ── Reachability allowlist (the clear config) ──────────────────────────────────

/** One allowlist rule: a path prefix that is unprivileged-reachable + a label. */
export interface ReachRule {
  /** Repo-relative path prefix (matched with `startsWith`). */
  prefix: string;
  /** Human subsystem label for the report. */
  label: string;
}

/**
 * Unprivileged-reachable, kernelCTF-eligible-ish subsystems a recency hunt keeps.
 * Ordered longest-first is NOT required — {@link isReachablePath} picks the most
 * specific (longest) matching prefix. Edit this list to widen / narrow scope.
 */
export const RECENCY_REACHABLE_ALLOWLIST: readonly ReachRule[] = [
  // Socket families — the richest unprivileged attack surface.
  { prefix: "net/", label: "net (socket families)" },
  { prefix: "io_uring/", label: "io_uring" },
  // SysV / POSIX IPC.
  { prefix: "ipc/", label: "ipc" },
  // Core fs objects reachable from an unprivileged fd — enumerated on purpose
  // (the rest of fs/ is filesystem-driver code we do NOT want to hunt blindly).
  { prefix: "fs/aio.c", label: "fs/aio" },
  { prefix: "fs/eventfd.c", label: "fs/eventfd" },
  { prefix: "fs/eventpoll.c", label: "fs/eventpoll (epoll)" },
  { prefix: "fs/signalfd.c", label: "fs/signalfd" },
  { prefix: "fs/timerfd.c", label: "fs/timerfd" },
  { prefix: "fs/select.c", label: "fs/select (poll/select)" },
  { prefix: "fs/pipe.c", label: "fs/pipe" },
  { prefix: "fs/splice.c", label: "fs/splice" },
  { prefix: "fs/locks.c", label: "fs/locks (file locking)" },
  { prefix: "fs/fcntl.c", label: "fs/fcntl" },
  { prefix: "fs/dnotify.c", label: "fs/dnotify" },
  { prefix: "fs/userfaultfd.c", label: "fs/userfaultfd" },
  { prefix: "fs/notify/", label: "fs/notify (inotify/fanotify)" },
  // Timers / posix-timers reachable via syscall.
  { prefix: "kernel/time/", label: "kernel/time" },
  { prefix: "kernel/futex/", label: "kernel/futex" },
  { prefix: "kernel/signal.c", label: "kernel/signal" },
  // AF_ALG / keyrings — unprivileged crypto + key material lifetime.
  { prefix: "crypto/", label: "crypto (AF_ALG)" },
  { prefix: "security/keys/", label: "security/keys" },
  // mm reachable via mmap/brk/madvise (broad — still worth the window).
  { prefix: "mm/", label: "mm" },
];

/**
 * Always-drop prefixes (evaluated BEFORE the allowlist). Hardware drivers,
 * arch-specific code, tooling, docs, samples, and the build system are not the
 * unprivileged-reachable freshness surface we hunt.
 */
export const RECENCY_DENYLIST: readonly string[] = [
  "drivers/",
  "arch/",
  "tools/",
  "Documentation/",
  "samples/",
  "scripts/",
  "virt/",
  "certs/",
  "usr/",
  "firmware/",
  "sound/", // ALSA HW; the reachable seq/timer bits are the exception, not the rule
  "include/", // headers change constantly and are not a hunt target on their own
  "LICENSES/",
];

/** The verdict of the reachability filter for one file. */
export interface ReachVerdict {
  reachable: boolean;
  reason: string;
  /** Subsystem label when reachable. */
  subsystem?: string;
}

/**
 * Decide whether a repo-relative path is in the unprivileged-reachable hunt
 * scope. Denylist wins; then the most-specific (longest) allowlist prefix. Only
 * C sources / headers are ever in scope.
 */
export function isReachablePath(path: string): ReachVerdict {
  const p = path.replace(/^\.\//, "");
  if (!/\.(c|h)$/.test(p)) {
    return { reachable: false, reason: `not a C source/header (${p})` };
  }
  for (const deny of RECENCY_DENYLIST) {
    if (p.startsWith(deny)) {
      return { reachable: false, reason: `denylisted prefix ${deny} (HW/arch/tooling/docs — not unpriv-reachable)` };
    }
  }
  let best: ReachRule | undefined;
  for (const rule of RECENCY_REACHABLE_ALLOWLIST) {
    if (p.startsWith(rule.prefix)) {
      if (!best || rule.prefix.length > best.prefix.length) best = rule;
    }
  }
  if (best) return { reachable: true, reason: `matched allowlist ${best.prefix}`, subsystem: best.label };
  return { reachable: false, reason: "no allowlist match (not a known unpriv-reachable subsystem)" };
}

// ── Deterministic lifetime-token signal (the cosmetic-vs-semantic discriminator) ─

/**
 * The lifetime / refcount / lock / alloc operations whose ADDITION, REMOVAL, or
 * REORDERING is the semantic signal. A diff that changes NONE of these (identical
 * multiset across +/- lines) is a cosmetic reshuffle around unchanged lifetime
 * logic — the vsock MSG_ZEROCOPY false-lead shape.
 */
const LIFETIME_TOKEN_RX = new RegExp(
  [
    // explicit lock/unlock families
    "(?:raw_)?spin_(?:un)?lock(?:_irq(?:save|restore)?|_bh)?",
    "(?:read|write)_(?:un)?lock(?:_bh|_irq)?",
    "mutex_(?:lock|unlock|trylock)",
    "rcu_read_(?:un)?lock(?:_bh)?",
    "down_(?:read|write|read_trylock)",
    "up_(?:read|write)",
    "lock_sock|release_sock|bh_lock_sock|bh_unlock_sock",
    "local_bh_(?:disable|enable)",
    // refcount / kref / atomic lifetime
    "refcount_(?:inc|dec|add|sub|set|dec_and_test|inc_not_zero)",
    "kref_(?:get|put|init)",
    "atomic_(?:inc|dec|add|sub|dec_and_test)(?:_return)?",
    // well-known get/put/hold pairs
    "sock_(?:hold|put)|dev_(?:hold|put)|__?module_get|module_put",
    "get_task_struct|put_task_struct|get_file|fput|fget|fdput",
    "kobject_(?:get|put)|dput|dget|mntget|mntput|iget|iput",
    // generic get/put/hold/free suffix pairs (e.g. foo_get / foo_put)
    "[a-z_][a-z0-9_]*_(?:get|put|hold|free|destroy|release)\\b",
    // alloc / free
    "k[zvm]?alloc(?:_node|_array)?|kmem_cache_(?:alloc|free)|kfree(?:_rcu|_skb)?|kvfree|vfree|vmalloc",
    "alloc_skb|consume_skb|skb_(?:get|unref)|free_percpu|alloc_percpu",
    // rcu deferral / publication
    "call_rcu|synchronize_rcu|rcu_assign_pointer|rcu_dereference",
  ].join("|"),
  "g",
);

/** The deterministic lifetime-token delta of a unified diff. */
export interface LifetimeSignal {
  /** Lifetime tokens on ADDED (`+`) lines, as a sorted multiset (token×count). */
  added: string[];
  /** Lifetime tokens on REMOVED (`-`) lines. */
  removed: string[];
  /**
   * True when the added/removed multisets DIFFER — a lifetime op was added,
   * removed, or its count changed. This is the deterministic "semantic" hint.
   * False ⇒ the same lifetime ops on both sides ⇒ likely a cosmetic reshuffle.
   */
  hasSemanticSignal: boolean;
}

function tokensOf(line: string): string[] {
  const out: string[] = [];
  LIFETIME_TOKEN_RX.lastIndex = 0;
  for (let m = LIFETIME_TOKEN_RX.exec(line); m; m = LIFETIME_TOKEN_RX.exec(line)) out.push(m[0]);
  return out;
}

function multisetKey(tokens: string[]): string {
  const counts = new Map<string, number>();
  for (const t of tokens) counts.set(t, (counts.get(t) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([t, c]) => `${t}:${c}`).join(",");
}

/**
 * Compute the deterministic lifetime-token signal of a unified diff hunk body.
 * Only real `+`/`-` content lines are considered (diff headers `+++`/`---` and
 * `@@` hunks are ignored). This is the cheap pre-classifier the LLM confirms.
 */
export function lifetimeTokenSignal(diffText: string): LifetimeSignal {
  const added: string[] = [];
  const removed: string[] = [];
  for (const raw of diffText.split("\n")) {
    if (raw.startsWith("+++") || raw.startsWith("---")) continue;
    if (raw.startsWith("+")) added.push(...tokensOf(raw.slice(1)));
    else if (raw.startsWith("-")) removed.push(...tokensOf(raw.slice(1)));
  }
  const addedSorted = [...added].sort();
  const removedSorted = [...removed].sort();
  return {
    added: addedSorted,
    removed: removedSorted,
    hasSemanticSignal: multisetKey(addedSorted) !== multisetKey(removedSorted),
  };
}

// ── Semantic-vs-cosmetic classifier (LLM authority, deterministic hint) ─────────

/** The precise rubric the classifier LLM is held to. Exported for auditability. */
export const SEMANTIC_COSMETIC_RUBRIC = `You classify a single kernel-source DIFF as SEMANTIC or COSMETIC for the purpose
of a lifetime/refcount/lock bug hunt. Be strict: the whole value of this filter is
that MOST diffs are COSMETIC and correctly skipped.

Classify SEMANTIC when the diff does ANY of:
  - ADDS, REMOVES, or REORDERS a get/put/hold/release, lock/unlock, alloc/free,
    or rcu-publish/deref call.
  - Changes which lock guards a field, or the order two locks are taken.
  - Changes how a refcount / lifetime field is incremented, decremented, tested,
    or the condition under which an object is freed.
  - Moves a free/put earlier or later relative to a use of the same object.
  - Changes an error/cleanup path so an object is (or is not) released on a branch
    it previously was (or was not).

Classify COSMETIC when the diff ONLY does things like:
  - Rename a variable / function / struct field with no change to lifetime calls.
  - Reformat, rewrap, reindent, or re-comment.
  - Reshape control flow (early-return, goto→if, split a helper) AROUND UNCHANGED
    get/put/lock/free logic — the SAME lifetime operations run in the SAME order
    on the SAME objects. THIS IS THE KEY TRAP: a "rewrite" that only reshuffles
    branch layout on top of already-correct lifetime code is COSMETIC. Do not be
    fooled by diff size.
  - Pure additions of unrelated features that touch no shared object's lifetime.

If the lifetime operations present are IDENTICAL before and after (same multiset,
same objects), it is COSMETIC even if the code looks heavily rewritten.

Return your verdict via the emit_classification tool. When unsure, prefer COSMETIC
unless there is a concrete added/removed/reordered lifetime operation you can name.`;

const CLASSIFY_TOOL = {
  name: "emit_classification",
  description: "Emit the semantic-vs-cosmetic verdict for the diff.",
  input_schema: {
    type: "object",
    properties: {
      verdict: { type: "string", enum: ["semantic", "cosmetic"] },
      confidence: { type: "number", description: "0.0–1.0" },
      reason: { type: "string", description: "One or two sentences citing the concrete lifetime change (or its absence)." },
    },
    required: ["verdict", "reason"],
  },
} as const;

/** Input to the semantic-vs-cosmetic classifier. */
export interface ClassifyInput {
  file: string;
  subsystem?: string;
  /** The unified diff for this file over the hunt range. */
  diffText: string;
  /** The deterministic pre-computed signal (fed to the LLM as a hint). */
  signal: LifetimeSignal;
  /** Classifier model override (default: gpt-5.5 via the codex/api runtime). */
  model?: string;
}

/** The classifier verdict. */
export interface CosmeticVerdict {
  verdict: "semantic" | "cosmetic";
  confidence?: number;
  reason: string;
  /** True when the deterministic signal and the LLM verdict disagreed. */
  signalDisagreed?: boolean;
}

const CLASSIFIER_SYSTEM = SEMANTIC_COSMETIC_RUBRIC;

/**
 * Classify one file's diff as SEMANTIC (hunt it) or COSMETIC (skip) via the LLM,
 * with the deterministic {@link lifetimeTokenSignal} supplied as a hint. The LLM
 * is the authority; we record when it disagrees with the deterministic signal so
 * classifier precision can be audited.
 */
export async function classifySemanticVsCosmetic(input: ClassifyInput): Promise<CosmeticVerdict> {
  const model = input.model ?? "gpt-5.5";
  const hint =
    `Deterministic lifetime-token signal (a hint, not the answer):\n` +
    `  added lifetime tokens:   ${input.signal.added.length ? input.signal.added.join(", ") : "(none)"}\n` +
    `  removed lifetime tokens: ${input.signal.removed.length ? input.signal.removed.join(", ") : "(none)"}\n` +
    `  multisets differ (added/removed a lifetime op): ${input.signal.hasSemanticSignal ? "YES" : "no"}\n`;
  const userText =
    `## File\n${input.file}${input.subsystem ? ` (${input.subsystem})` : ""}\n\n` +
    `## ${hint}\n## Diff\n\`\`\`diff\n${clip(input.diffText, 24_000)}\n\`\`\`\n\n` +
    `Classify this diff per the rubric. Emit via emit_classification.`;
  const messages = [{ role: "user", content: [{ type: "text", text: userText }] }];

  const rt = new LlmApiRuntime({ type: "api", model, timeout: 180_000 });
  let out: { verdict?: string; confidence?: number; reason?: string } | null = null;
  try {
    const res = (await rt.executeNative(CLASSIFIER_SYSTEM, messages as never, [CLASSIFY_TOOL] as never, {
      onThinking() {}, onDelta() {}, onText() {}, onUsage() {},
    } as never)) as { content?: Array<Record<string, unknown>> };
    const call = (res.content ?? []).find(
      (b) => (b as { type?: string; name?: string }).type === "tool_use" && (b as { name?: string }).name === "emit_classification",
    ) as { input?: { verdict?: string; confidence?: number; reason?: string } } | undefined;
    if (call?.input) out = call.input;
  } catch (e) {
    // Fail OPEN toward the deterministic signal: an LLM error must not silently
    // drop a real semantic change, nor invent one. Defer to the token signal.
    const verdict = input.signal.hasSemanticSignal ? "semantic" : "cosmetic";
    return { verdict, reason: `classifier LLM error (${String(e).slice(0, 120)}); fell back to deterministic signal`, signalDisagreed: false };
  }

  const verdict = out?.verdict === "semantic" ? "semantic" : "cosmetic";
  const reason = out?.reason?.trim() || "(no reason emitted)";
  return {
    verdict,
    ...(typeof out?.confidence === "number" ? { confidence: out.confidence } : {}),
    reason,
    signalDisagreed: (verdict === "semantic") !== input.signal.hasSemanticSignal,
  };
}

// ── git plumbing (injectable for tests) ─────────────────────────────────────────

/** A git runner: given argv + cwd, returns stdout. Injectable so tests need no repo. */
export type GitRunner = (args: string[], cwd: string) => string;

const realGit: GitRunner = (args, cwd) =>
  execFileSync("git", args, { cwd, encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });

/** One changed file in the hunt range. */
export interface ChangedFile {
  /** Repo-relative path (the post-image path for renames). */
  path: string;
  /** git status letter: A(dded) M(odified) R(enamed) etc. */
  status: string;
}

/**
 * Resolve a git range for the hunt. Explicit `range` wins; otherwise the last
 * `hours` are turned into `<oldest-in-window>^..HEAD`. Returns null when no
 * commit falls in the window (an empty, honest funnel).
 */
export function resolveRange(tree: string, opts: { range?: string; hours?: number }, git: GitRunner = realGit): string | null {
  if (opts.range && opts.range.trim()) return opts.range.trim();
  const hours = opts.hours ?? 24;
  const since = `${hours} hours ago`;
  const revs = git(["log", `--since=${since}`, "--pretty=%H"], tree).trim().split("\n").filter(Boolean);
  if (revs.length === 0) return null;
  const oldest = revs[revs.length - 1];
  // <oldest>^..HEAD — everything from just before the oldest in-window commit.
  return `${oldest}^..HEAD`;
}

/** Count commits in a range (for the funnel's first number). */
export function countCommits(tree: string, range: string, git: GitRunner = realGit): number {
  const out = git(["rev-list", "--count", range], tree).trim();
  const n = parseInt(out, 10);
  return Number.isFinite(n) ? n : 0;
}

/**
 * The changed C files in a range (Added/Modified/Renamed). Deletes are dropped
 * (no code to hunt). Parses `git diff --name-status`.
 */
export function changedFilesInRange(tree: string, range: string, git: GitRunner = realGit): ChangedFile[] {
  const out = git(["diff", "--name-status", "-M", range], tree);
  return parseNameStatus(out);
}

/** Pure parser for `git diff --name-status` output. Exposed for testing. */
export function parseNameStatus(nameStatus: string): ChangedFile[] {
  const files: ChangedFile[] = [];
  for (const line of nameStatus.split("\n")) {
    if (!line.trim()) continue;
    const parts = line.split("\t");
    const status = parts[0] ?? "";
    if (status.startsWith("D")) continue; // deletion — nothing to hunt
    // For renames (Rxxx) the post-image path is the LAST field.
    const path = parts[parts.length - 1];
    if (!path) continue;
    files.push({ path, status: status[0] ?? "?" });
  }
  return files;
}

/** The unified diff for one file over the range. */
export function fileDiff(tree: string, range: string, path: string, git: GitRunner = realGit): string {
  return git(["diff", "-M", range, "--", path], tree);
}

// ── Detectors ───────────────────────────────────────────────────────────────────

/**
 * The refined-engine detectors a semantic-changed file is hunted with.
 *   • `dataflow` — intra-proc lock-set + reaching-free ({@link findViolationsDataflow}).
 *   • `refcount` — inter-procedural call-graph get/put coupling ({@link findInterprocRefcountCouplings}).
 *   • `race`     — cross-function lockset-inconsistency ({@link findRaceCandidates}).
 * The first three share ONE invariant model (built once per file) and feed the SAME
 * static adversarial (skeptic) gate; a survivor records which detector surfaced it.
 *   • `dual-view` — assumption-mining cross-api/cross-phase enumerator
 *     ({@link runAssumptionHunt} → {@link scanDualViewContexts}). Materially different:
 *     it MINES the file's relied-on preconditions (one LLM turn), enumerates dual-view
 *     seams the static skeptic structurally cannot judge, and routes them to the
 *     DYNAMIC KASAN oracle instead of the skeptic. A dual-view SURVIVOR is only ever a
 *     candidate the oracle DYNAMICALLY WITNESSED (an object-bound KASAN splat).
 */
export type RecencyDetector = "dataflow" | "refcount" | "race" | "dual-view";

/**
 * The default detector set — the three static detectors that share the invariant
 * model + skeptic gate. Unchanged cost: adding `dual-view` costs an extra per-file
 * LLM mine (and, under `--dynamic-witness`, VM boots), so it is opt-in (selected
 * explicitly, or implied when a `dynamicWitness` budget is configured).
 */
export const RECENCY_DETECTORS_ALL: readonly RecencyDetector[] = ["dataflow", "refcount", "race"];

/** The FULL "crazy-bug machine" — the three static detectors PLUS assumption-mining dual-view. */
export const RECENCY_DETECTORS_FULL: readonly RecencyDetector[] = ["dataflow", "refcount", "race", "dual-view"];

/** Per-detector candidate/survivor counts (the honest per-detector funnel). */
export interface DetectorCounts {
  dataflow: number;
  refcount: number;
  race: number;
  /** Assumption-mining dual-view: candidates = enumerated seams; survivors = DYNAMICALLY WITNESSED only. */
  dualView: number;
}

// ── The report shape ────────────────────────────────────────────────────────────

/**
 * Dynamic-witness evidence carried by a `dual-view` survivor — this is what makes a
 * dual-view flywheel entry a REAL WITNESSED FINDING (an object-bound KASAN splat +
 * the repro that produced it) rather than a static candidate. Present ONLY on
 * `detector: "dual-view"` survivors that the KASAN oracle confirmed.
 */
export interface WitnessEvidence {
  /** The promote-class KASAN signature (kasan-uaf / kasan-oob / kasan-double-free / …). */
  signature?: string;
  /** The candidate object/function token the splat bound to (the anti-incidental proof). */
  boundTo?: string;
  /** The extracted, object-bound KASAN splat region (the witness). */
  splat?: string;
  /** The unprivileged C PoC that produced the splat (the repro — re-runnable in the KASAN VM). */
  repro?: string;
  /** The dual-view object TYPE both phases operate on (`fuse_req`, `dma_buf`). */
  object: string;
  /** entry A — the phase that ESTABLISHES the guarantee. */
  entryA: string;
  /** entry B — the phase that reached the same object WITHOUT it (the violator). */
  entryB: string;
  /** How many synthesize→boot→witness rounds it took. */
  rounds: number;
}

/** A high-confidence survivor, shaped as an autoclimb-ready bug-spec + seed. */
export interface RecencySurvivor {
  /** Which detector surfaced this lead (dataflow / refcount / race / dual-view). */
  detector: RecencyDetector;
  file: string;
  functionName: string;
  line: number;
  bugClass: string;
  title: string;
  verifyVerdict: string;
  subsystem?: string;
  /** The finding id from the hunt (for cross-reference). */
  findingId: string;
  severity: string;
  /**
   * DYNAMIC-WITNESS evidence — present ONLY on `dual-view` survivors. A dual-view
   * survivor is, by construction, one the KASAN oracle witnessed; this carries the
   * splat + repro as the auditable proof (distinct from a static skeptic verdict).
   */
  witness?: WitnessEvidence;
  /**
   * A bug-spec + trigger-seed shaped for `0sec exploit --autoclimb` and the
   * disclosure stager. Staged only — nothing is auto-sent (operator-gated).
   */
  bugSpec: {
    subsystem?: string;
    file: string;
    functionName: string;
    line: number;
    bugClass: string;
    description: string;
    /** The hunt's own evidence/analysis prose — the trigger hypothesis seed. */
    analysis: string;
    /** Ready-to-run next steps for the operator. */
    nextSteps: string[];
  };
}

/** Per-file record through the whole funnel. */
export interface RecencyFileRecord {
  file: string;
  status: string;
  reachable: boolean;
  reachReason: string;
  subsystem?: string;
  /** Set once reachable: the classifier stage outcome. */
  classification?: "semantic" | "cosmetic" | "classifier-capped";
  classifyReason?: string;
  lifetimeSignal?: LifetimeSignal;
  /** Set once semantic + hunted: total candidate + survivor counts (all detectors). */
  candidates?: number;
  survivorCount?: number;
  /** Per-detector candidate leads fed to the gate (dataflow / refcount / race / dual-view). */
  candidatesByDetector?: DetectorCounts;
  /** Per-detector survivors after the gate (dual-view survivors are dynamically-witnessed). */
  survivorsByDetector?: DetectorCounts;
  /** Dual-view candidates actually run through the (expensive) KASAN oracle on this file. */
  dualViewWitnessAttempted?: number;
  /** Non-fatal error hunting this file (recorded, not thrown). */
  error?: string;
}

/** The full ranked recency-hunt report (JSON-serializable). */
export interface RecencyHuntReport {
  tree: string;
  range: string;
  generatedAt: string;
  funnel: {
    commits: number;
    changedFiles: number;
    inScope: number;
    semantic: number;
    candidates: number;
    survivors: number;
    /** Candidate leads per detector across all hunted files (dataflow / refcount / race / dual-view). */
    candidatesByDetector: DetectorCounts;
    /** Survivors per detector after the gate (dual-view = dynamically witnessed). */
    survivorsByDetector: DetectorCounts;
    /**
     * The dual-view honest funnel's middle number: dual-view candidates actually run
     * through the KASAN oracle across the whole run (bounded by the dynamic-witness
     * budget). candidatesByDetector.dualView ≥ this ≥ survivorsByDetector.dualView.
     */
    dualViewWitnessAttempted: number;
  };
  /** Which detectors this run executed on each semantic-changed file. */
  detectors: RecencyDetector[];
  files: RecencyFileRecord[];
  /** Flattened, ranked survivors across all files (the leads). */
  survivors: RecencySurvivor[];
  notes: string[];
}

// ── Orchestrator ────────────────────────────────────────────────────────────────

/**
 * The refcount + race detectors' shared input: they reuse the SAME invariant model
 * the dataflow hunt built for this file (no second LLM model-build), read the file's
 * current source, run their deterministic candidate generator, and feed the leads
 * through the SAME `runHuntScan` skeptic gate.
 */
export interface RecencyExtraDetectInput {
  /** Which of the extra detectors to run (subset of `["refcount","race"]`). */
  detectors: RecencyDetector[];
  /** The invariant model built once for this file (reused by every detector). */
  model: InvariantModel;
  /** Absolute kernel tree root. */
  sourceRoot: string;
  /** The repo-relative changed file being hunted. */
  file: string;
  /** Subsystem label for the report/bug-spec. */
  subsystem?: string;
  runtime: RuntimeMode;
  /** Finder model override (mirrors the dataflow finder model). */
  finderModel?: string;
  /** Skeptic+prover gate override (defaults to {@link makeSkepticVerifier}). */
  verify?: HuntVerifier;
  log?: (msg: string) => void;
}

/** Per-detector result of {@link RecencyHuntDeps.detect}. */
export interface DetectorOutcome {
  /** Raw detector leads fed to the gate (before verify). */
  candidateCount: number;
  /** Survivors after the adversarial gate, already shaped + tagged. */
  survivors: RecencySurvivor[];
}

/** The extra-detector (refcount + race) run result, keyed by detector. */
export interface RecencyExtraDetectResult {
  refcount?: DetectorOutcome;
  race?: DetectorOutcome;
}

// ── dual-view detector (assumption-mining → dynamic KASAN oracle) ─────────────────

/**
 * The dynamic-witness budget for the flywheel's `dual-view` detector. VM boots are
 * EXPENSIVE, so the oracle is bounded at the RUN level (a run may hunt dozens of
 * files): the orchestrator hands each file a slice of the remaining run budget and
 * decrements it by what the file consumes. Tuned by the bench sibling's measured
 * seconds/candidate + compile% + boot-time numbers.
 */
export interface RecencyDynamicWitnessConfig {
  /**
   * Total dual-view candidates run through the KASAN oracle across the WHOLE run.
   * Default 10 (bumped from 8: ranking + rotation + the pre-filter mean the budget now
   * lands on a cleaner, higher-value, non-repeating pool, so a modestly larger cap buys
   * real coverage). This is the hard cost ceiling — at most this many synthesize→boot
   * loops per flywheel run regardless of how many files surface candidates.
   */
  maxCandidatesPerRun?: number;
  /** Per-file cap on witnessed candidates (also clamped to the remaining run budget). Default 6. */
  maxCandidatesPerFile?: number;
  /** Bounded PoC-repair rounds per candidate — each round is one VM boot. Default 2. */
  maxRoundsPerCandidate?: number;
  /**
   * PoC-shape mode for the oracle: `single` (sequential), `race` (concurrent
   * multi-thread), or `auto` (pick `race` per race-shaped seam). Default `auto` — a
   * non-race seam resolves to `single`, so the default preserves existing behaviour.
   * This is the `--witness-mode` flag's home.
   */
  witnessMode?: WitnessMode;
  /** Race worker-thread count for race-mode PoCs (default 4). `--witness-race-threads`. */
  raceThreads?: number;
  /** Race per-thread iteration budget for race-mode PoCs (default 200000). `--witness-race-iters`. */
  raceIters?: number;
  /**
   * Injectable synth/boot boundaries (+ runtime/model) for the oracle. Tests inject
   * a mock `synthesizePoc`/`bootPoc` here; the bench sibling can pin a coder model.
   * When omitted, the real LLM synthesizer + KASAN-VM harness run.
   */
  deps?: DynamicWitnessDeps;
}

/**
 * Input to the flywheel's `dual-view` detector for ONE semantic-changed file. Unlike
 * the refcount/race detectors it does NOT reuse the dataflow invariant model — it
 * mines its OWN assumption model (one LLM turn), so it takes the raw file + tree.
 */
export interface RecencyDualViewInput {
  sourceRoot: string;
  file: string;
  subsystem?: string;
  runtime: RuntimeMode;
  /** Per-file assumption-model JSON path (mine-once; reused if present unless `remine`). */
  assumptionModelPath: string;
  /** Force a fresh assumption mine (default: reuse a stored model if present — the "reuse if built" note). */
  remine?: boolean;
  /** Mining LLM override (mirrors the flywheel's finder model). */
  model?: string;
  /**
   * The dynamic-witness budget for THIS file, already clamped to the remaining run
   * budget by the orchestrator. ABSENT ⇒ candidate-generation only: dual-view seams
   * are enumerated + counted, but nothing is booted, so the file yields 0 survivors
   * (the honest static-only mode — the static skeptic refutes this class, so we do
   * not waste it on them).
   */
  witnessBudget?: { maxCandidates: number; maxRounds: number; rotationStatePath?: string; deps?: DynamicWitnessDeps };
  log?: (msg: string) => void;
}

/** The dual-view detector's run result (the honest dual-view funnel for one file). */
export interface RecencyDualViewResult {
  /** Dual-view seams enumerated (the funnel's dual-view candidate count). */
  candidateCount: number;
  /** Candidates actually run through the KASAN oracle on this file (≤ witnessBudget.maxCandidates). */
  witnessAttempted: number;
  /** Dynamically-witnessed (object-bound KASAN) survivors, tagged `dual-view`, carrying splat+repro. */
  survivors: RecencySurvivor[];
  /** Honest funnel tail. */
  refuted: number;
  inconclusive: number;
}

/** Injectable dependencies (all default to the real implementations). */
export interface RecencyHuntDeps {
  git?: GitRunner;
  classify?: (input: ClassifyInput) => Promise<CosmeticVerdict>;
  hunt?: (input: SubsystemInvariantHuntInput) => Promise<SubsystemInvariantHuntResult>;
  /**
   * The refcount + race detectors on one file, sharing the dataflow hunt's model.
   * Injectable so the orchestrator test stays git/classify/hunt/LLM-free.
   */
  detect?: (input: RecencyExtraDetectInput) => Promise<RecencyExtraDetectResult>;
  /**
   * The `dual-view` detector on one file: mine assumptions → dual-view enumerator →
   * (budgeted) dynamic KASAN oracle. Injectable so the orchestrator test stays
   * LLM/VM-free. Defaults to {@link runRecencyDualViewDetector}.
   */
  dualView?: (input: RecencyDualViewInput) => Promise<RecencyDualViewResult>;
}

/** Input to a recency hunt. */
export interface RecencyHuntInput {
  /** Absolute path to the kernel tree (e.g. /root/linux-next). */
  tree: string;
  /** Explicit git range; else `hours` drives a since-window. */
  range?: string;
  hours?: number;
  runtime: RuntimeMode;
  /** Directory the per-file invariant models are stored under. */
  modelDir: string;
  /** Model-build / finder model override. */
  model?: string;
  /** Classifier model override (default gpt-5.5). */
  classifierModel?: string;
  /**
   * Which detectors to run on each semantic-changed file. Default: all three
   * ({@link RECENCY_DETECTORS_ALL}). A fresh commit can introduce a cross-file
   * refcount leak (`refcount`) or a cross-thread race (`race`), not just an
   * intra-proc lifetime bug (`dataflow`) — so the flywheel runs all three by
   * default. Narrow this to cut cost or isolate a detector. Add `"dual-view"` (or
   * configure {@link dynamicWitness}, which implies it) to run the full crazy-bug
   * machine: assumption-mining → dual-view enumerator → dynamic KASAN oracle.
   */
  detectors?: RecencyDetector[];
  /**
   * DYNAMIC-WITNESS config for the `dual-view` detector. When set, the flywheel runs
   * the dual-view enumerator on each semantic file and routes its candidates to the
   * KASAN synthesize→boot→witness oracle (bounded by this budget), promoting ONLY
   * dynamically-witnessed candidates to survivors. Setting this IMPLIES the
   * `dual-view` detector (it is auto-added to the effective detector set). Omit it to
   * skip the oracle: `dual-view` (if explicitly selected) then only enumerates +
   * counts candidates. This is the `--dynamic-witness` flag's home.
   */
  dynamicWitness?: RecencyDynamicWitnessConfig;
  /**
   * Force a fresh assumption mine for the `dual-view` detector each run (default
   * false = reuse a stored per-file assumption model if one exists — the cheap
   * "reuse if built" path). Set true when reusing a `modelDir` across days so a
   * fresh recency window never re-checks a stale assumption model.
   */
  remineAssumptions?: boolean;
  /** Cap on files actually hunted (protects against a huge merge window). */
  maxHuntFiles?: number;
  /**
   * Cap on in-scope files sent to the (LLM) semantic classifier. The linux-next
   * SNAPSHOT repo rebases the whole merge window daily, so a naive wall-clock
   * window can surface hundreds of in-scope files — this bounds the classifier
   * cost. Files beyond the cap are recorded as `classifier-capped`, not hunted.
   * A production flywheel should instead diff against yesterday's snapshot tag
   * (see README) so the window is genuinely one day of new work.
   */
  maxClassifyFiles?: number;
  log?: (msg: string) => void;
  deps?: RecencyHuntDeps;
}

/** The per-finding site the survivor is anchored at (best-effort, detector-specific). */
interface SurvivorSite {
  functionName: string;
  line: number;
  bugClass: string;
}

/**
 * Shape ONE confirmed finding into an autoclimb-ready {@link RecencySurvivor},
 * tagged with the detector that surfaced it. Shared by all three detectors so the
 * bug-spec + next-steps shaping is identical regardless of origin.
 */
function shapeSurvivor(
  detector: RecencyDetector,
  rec: RecencyFileRecord,
  finding: Finding,
  site: SurvivorSite,
  verifyVerdict: string,
): RecencySurvivor {
  const analysis = (finding.evidence as { analysis?: string } | undefined)?.analysis ?? finding.description ?? "";
  const { functionName, line, bugClass } = site;
  return {
    detector,
    file: rec.file,
    functionName,
    line,
    bugClass,
    title: finding.title,
    verifyVerdict,
    ...(rec.subsystem ? { subsystem: rec.subsystem } : {}),
    findingId: finding.id,
    severity: finding.severity,
    bugSpec: {
      ...(rec.subsystem ? { subsystem: rec.subsystem } : {}),
      file: rec.file,
      functionName,
      line,
      bugClass,
      description: finding.title,
      analysis,
      nextSteps: [
        `0sec exploit --autoclimb --source <tree> --target ${rec.file} (weaponize this ${detector} lead)`,
        `Verify unpriv reachability of ${rec.file}:${line} in ${functionName}() before any disclosure`,
        `Confirm the bug is NOT already patched later in the same recency window (novelty gate)`,
        `If weaponized: stage via the disclosure stager — operator-gated, do NOT auto-send`,
      ],
    },
  };
}

/** Best-effort site from a confirmed finding's own annotation (populated by some finders). */
function siteFromFinding(finding: Finding, fallback: SurvivorSite): SurvivorSite {
  const ann = finding.reviewAnnotation;
  return ann?.startLine ? { ...fallback, line: ann.startLine } : fallback;
}

/** The `dataflow` detector's survivors — anchored at the deterministic violation site. */
function survivorsFromHunt(rec: RecencyFileRecord, result: SubsystemInvariantHuntResult): RecencySurvivor[] {
  const confirmed = result.hunt?.confirmed ?? [];
  const records = result.hunt?.records ?? [];
  // Best-effort site — the deterministic violation the finding tracks back to.
  const viol = result.violations.find((v) => v.file === rec.file);
  const fallback: SurvivorSite = {
    functionName: viol?.functionName ?? "(unknown)",
    line: viol?.line ?? 0,
    bugClass: viol?.kind ?? "invariant-violation",
  };
  return confirmed.map((f: Finding) => {
    const match = records.find((r) => r.finding.id === f.id);
    return shapeSurvivor("dataflow", rec, f, siteFromFinding(f, fallback), match?.skepticReason ?? "confirmed by skeptic gate");
  });
}

// ── The refcount + race detectors (share the dataflow hunt's model + the gate) ────

/** Read one file's current source text (path-contained under the tree). */
function readFileText(sourceRoot: string, file: string): string | null {
  const path = resolveContainedSourcePath(sourceRoot, file);
  if (!path) return null;
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

/**
 * Default {@link RecencyHuntDeps.detect}: run the refcount + race detectors on one
 * semantic-changed file, reusing the invariant model the dataflow hunt already built
 * (no second LLM call) and feeding their leads through the SAME `runHuntScan` skeptic
 * gate. Deterministic candidate generation; only the verify step touches the LLM, and
 * only when a detector actually generates ≥1 lead.
 */
export async function runRecencyExtraDetectors(input: RecencyExtraDetectInput): Promise<RecencyExtraDetectResult> {
  const log = input.log ?? (() => {});
  const out: RecencyExtraDetectResult = {};
  const text = readFileText(input.sourceRoot, input.file);
  if (text == null) {
    log(`[recency] could not read ${input.file} for refcount/race detectors — skipped`);
    return out;
  }
  const sources = [{ file: input.file, text }];
  const rec: RecencyFileRecord = {
    file: input.file,
    status: "?",
    reachable: true,
    reachReason: "in scope",
    ...(input.subsystem ? { subsystem: input.subsystem } : {}),
  };
  const verify = input.verify ?? makeSkepticVerifier({ sourceRoot: input.sourceRoot, runtime: input.runtime });

  const runGate = async (candidates: HuntCandidate[], brief: HuntBrief): Promise<HuntScanResult> =>
    runHuntScan({
      sourceRoot: input.sourceRoot,
      candidates,
      brief,
      runtime: input.runtime,
      ...(input.finderModel ? { models: [input.finderModel] } : {}),
      verify,
      log,
    });

  // ── refcount: call-graph get/put coupling; keep leak-suspect (non-balanced). ──
  if (input.detectors.includes("refcount")) {
    const couplings = findInterprocRefcountCouplings(input.model, sources, { log });
    // couplingsToHuntPlan defaults to non-balanced-only (leak-suspect) selection.
    const plan = couplingsToHuntPlan(input.model, couplings);
    const leadCouplings = couplings.filter((c) => c.verdict !== "balanced");
    let survivors: RecencySurvivor[] = [];
    if (plan.candidates.length > 0) {
      const hunt = await runGate(plan.candidates, plan.brief);
      survivors = survivorsFromExtraHunt("refcount", rec, hunt, refcountSite(leadCouplings));
    }
    out.refcount = { candidateCount: leadCouplings.length, survivors };
  }

  // ── race: cross-function lockset inconsistency; keep high-sev write-bearing. ──
  if (input.detectors.includes("race")) {
    const races = findRaceCandidates(input.model, sources, { log });
    const leads = races.filter((c) => c.severity === "high" && c.hasWrite);
    const plan = raceCandidatesToHuntPlan(input.model, leads);
    let survivors: RecencySurvivor[] = [];
    if (plan.huntCandidates.length > 0) {
      const hunt = await runGate(plan.huntCandidates, plan.brief);
      survivors = survivorsFromExtraHunt("race", rec, hunt, raceSite(leads));
    }
    out.race = { candidateCount: leads.length, survivors };
  }

  return out;
}

/** Representative site for a refcount survivor — the top-ranked leak-suspect coupling's get. */
function refcountSite(leads: RefcountCoupling[]): SurvivorSite {
  const c = leads[0];
  return c
    ? { functionName: c.getSite.fn, line: c.getSite.line, bugClass: `inter-procedural refcount ${c.verdict}` }
    : { functionName: "(unknown)", line: 0, bugClass: "inter-procedural refcount imbalance" };
}

/** Representative site for a race survivor — the top-ranked candidate's inconsistent access. */
function raceSite(leads: RaceCandidate[]): SurvivorSite {
  const c = leads[0];
  const a = c?.inconsistentAccesses[0] ?? c?.consensusAccesses[0];
  return c && a
    ? { functionName: a.functionName, line: a.line, bugClass: `concurrency race (${c.kind})` }
    : { functionName: "(unknown)", line: 0, bugClass: "concurrency race candidate" };
}

/** Shape the confirmed findings of a refcount/race gate run into tagged survivors. */
function survivorsFromExtraHunt(
  detector: RecencyDetector,
  rec: RecencyFileRecord,
  hunt: HuntScanResult,
  fallback: SurvivorSite,
): RecencySurvivor[] {
  return hunt.confirmed.map((f) => {
    const match = hunt.records.find((r) => r.finding.id === f.id);
    return shapeSurvivor(detector, rec, f, siteFromFinding(f, fallback), match?.skepticReason ?? "confirmed by skeptic gate");
  });
}

// ── The dual-view detector (assumption-mining → dynamic KASAN oracle) ─────────────

/**
 * Shape ONE dynamically-witnessed dual-view {@link WitnessResult} into a flywheel
 * {@link RecencySurvivor}, tagged `dual-view` and carrying the KASAN splat + repro as
 * {@link WitnessEvidence}. This is materially different from {@link shapeSurvivor}: it
 * has no `Finding` and no static skeptic verdict — its proof is the object-bound
 * kernel splat the oracle captured, which is what makes it a real WITNESSED finding.
 */
function shapeWitnessSurvivor(rec: RecencyFileRecord, w: WitnessResult): RecencySurvivor {
  const c = w.candidate;
  const sig = w.witnessedAttempt?.check?.signature ?? "kasan";
  const bugClass = `dual-view ${c.kind} (${sig})`;
  return {
    detector: "dual-view",
    file: rec.file,
    functionName: c.entryB,
    line: 0, // dual-view is a two-phase seam, not a single site; the splat carries the faulting frame
    bugClass,
    title: `dynamically-witnessed dual-view violation on struct ${c.object} (${c.entryA} ⇄ ${c.entryB})`,
    verifyVerdict: w.summary,
    ...(rec.subsystem ? { subsystem: rec.subsystem } : {}),
    findingId: c.assumptionId,
    severity: "high",
    witness: {
      ...(w.witnessedAttempt?.check?.signature ? { signature: w.witnessedAttempt.check.signature } : {}),
      ...(w.witnessedAttempt?.check?.boundTo ? { boundTo: w.witnessedAttempt.check.boundTo } : {}),
      ...(w.splat ? { splat: w.splat } : {}),
      ...(w.finalCSource ? { repro: w.finalCSource } : {}),
      object: c.object,
      entryA: c.entryA,
      entryB: c.entryB,
      rounds: w.attempts.length,
    },
    bugSpec: {
      ...(rec.subsystem ? { subsystem: rec.subsystem } : {}),
      file: rec.file,
      functionName: c.entryB,
      line: 0,
      bugClass,
      description: `Dual-view / cross-phase assumption violation DYNAMICALLY WITNESSED by an object-bound ${sig} splat: ${c.entryA}() establishes ${c.establisherToken} on struct ${c.object}; ${c.entryB}() reaches the same object without it.`,
      analysis: `${c.detail}\n\nWITNESS: ${w.summary}`,
      nextSteps: [
        `Reproduce: the witnessing PoC is attached (survivor.witness.repro) — re-run in the KASAN VM to confirm the ${sig} on struct ${c.object}`,
        `Confirm novelty: is this cross-phase bug already patched later in the same recency window? (novelty gate)`,
        `Weaponize from the witnessing PoC: 0sec exploit --autoclimb --source <tree> --target ${rec.file}`,
        `If weaponized: stage via the disclosure stager — operator-gated, do NOT auto-send`,
      ],
    },
  };
}

/**
 * Default {@link RecencyHuntDeps.dualView}: the flywheel's 4th detector on one file.
 * Reuses the assumption-mining pipeline wholesale — {@link runAssumptionHunt} with
 * `skipHunt: true` (the dual-view class goes to the DYNAMIC oracle, NOT the static
 * skeptic, which v2 proved refutes them all) and `dualView: true`. When a
 * `witnessBudget` is supplied it also threads the bounded `dynamicWitness` config so
 * the (expensive) KASAN synthesize→boot→witness loop runs; without it, the seams are
 * enumerated + counted only. The single-view caller-scan contexts `runAssumptionHunt`
 * also computes are intentionally ignored here — this detector is the dual-view class.
 */
export async function runRecencyDualViewDetector(input: RecencyDualViewInput): Promise<RecencyDualViewResult> {
  const log = input.log ?? (() => {});
  const rec: RecencyFileRecord = {
    file: input.file,
    status: "?",
    reachable: true,
    reachReason: "in scope",
    ...(input.subsystem ? { subsystem: input.subsystem } : {}),
  };
  const wb = input.witnessBudget;
  const res = await runAssumptionHunt({
    sourceRoot: input.sourceRoot,
    subsystem: input.subsystem ?? input.file,
    subsystemFiles: [input.file],
    runtime: input.runtime,
    modelPath: input.assumptionModelPath,
    ...(input.remine ? { remine: true } : {}),
    ...(input.model ? { model: input.model } : {}),
    dualView: true,
    skipHunt: true, // dual-view → dynamic oracle, never the static skeptic
    ...(wb
      ? {
          dynamicWitness: {
            maxCandidates: wb.maxCandidates,
            maxRounds: wb.maxRounds,
            runtime: input.runtime,
            ...(wb.rotationStatePath ? { rotationStatePath: wb.rotationStatePath } : {}),
            ...(wb.deps ?? {}),
          },
        }
      : {}),
    log,
  });

  const candidateCount = res.dualViewContexts.length;
  const witness = res.witness;
  if (!witness) {
    return { candidateCount, witnessAttempted: 0, survivors: [], refuted: 0, inconclusive: 0 };
  }
  return {
    candidateCount,
    witnessAttempted: witness.results.length,
    survivors: witness.confirmed.map((w) => shapeWitnessSurvivor(rec, w)),
    refuted: witness.refuted.length,
    inconclusive: witness.inconclusive.length,
  };
}

/**
 * Run the recency flywheel over a kernel tree + range. Honest by construction:
 * every stage records why a file was dropped, and the funnel counts are the raw
 * numbers. Most files SHOULD filter out — that is the correct, expected shape.
 */
export async function runRecencyHunt(input: RecencyHuntInput): Promise<RecencyHuntReport> {
  const log = input.log ?? (() => {});
  const git = input.deps?.git ?? realGit;
  const classify = input.deps?.classify ?? classifySemanticVsCosmetic;
  const hunt = input.deps?.hunt ?? runSubsystemInvariantHunt;
  const detect = input.deps?.detect ?? runRecencyExtraDetectors;
  const dualViewDetect = input.deps?.dualView ?? runRecencyDualViewDetector;
  const notes: string[] = [];

  // Detector selection (default: the three static detectors). The dataflow path
  // builds the shared invariant model; refcount + race reuse it. If dataflow is
  // deselected but an extra detector is on, the model is still built (via skipHunt)
  // so they have one. A `dynamicWitness` budget IMPLIES the dual-view detector — the
  // oracle's whole job is the dual-view class — so it is auto-added when configured.
  let detectors = (input.detectors && input.detectors.length > 0 ? input.detectors : RECENCY_DETECTORS_ALL).filter(
    (d): d is RecencyDetector => RECENCY_DETECTORS_FULL.includes(d),
  );
  if (input.dynamicWitness && !detectors.includes("dual-view")) detectors = [...detectors, "dual-view"];
  const runDataflow = detectors.includes("dataflow");
  const extraDetectors = detectors.filter((d) => d === "refcount" || d === "race");
  const runDualView = detectors.includes("dual-view");
  const zero = (): DetectorCounts => ({ dataflow: 0, refcount: 0, race: 0, dualView: 0 });

  // Dynamic-witness RUN budget: VM boots are expensive, so the oracle is bounded
  // across the WHOLE run (a run may hunt dozens of files). Each file gets a slice of
  // what remains; the budget decrements by candidates actually witnessed. Absent a
  // `dynamicWitness` config the budget is 0 — dual-view then only enumerates seams.
  const dwConfig = input.dynamicWitness;
  let witnessBudgetRemaining = dwConfig ? dwConfig.maxCandidatesPerRun ?? 10 : 0;
  const dwPerFile = dwConfig?.maxCandidatesPerFile ?? 6;
  const dwRounds = dwConfig?.maxRoundsPerCandidate ?? 2;
  // Merge the witness-shape knobs (mode + race threads/iters) into the oracle deps so
  // they thread down to witnessAssumptionViolation. Omitting them leaves the default
  // (`auto` mode) intact. `raceConfig` is only set when a knob was actually supplied.
  const dwRaceConfig =
    dwConfig?.raceThreads !== undefined || dwConfig?.raceIters !== undefined
      ? {
          raceConfig: {
            ...(dwConfig?.raceThreads !== undefined ? { threads: dwConfig.raceThreads } : {}),
            ...(dwConfig?.raceIters !== undefined ? { iters: dwConfig.raceIters } : {}),
          },
        }
      : {};
  const dwWitnessDeps: DynamicWitnessDeps | undefined =
    dwConfig && (dwConfig.deps || dwConfig.witnessMode !== undefined || dwConfig.raceThreads !== undefined || dwConfig.raceIters !== undefined)
      ? { ...(dwConfig.deps ?? {}), ...(dwConfig.witnessMode !== undefined ? { witnessMode: dwConfig.witnessMode } : {}), ...dwRaceConfig }
      : undefined;
  // CROSS-RUN ROTATION state — one durable file per modelDir so consecutive daily runs
  // over the same tree/window test FRESH dual-view candidates instead of the same
  // ranked top-N. Reusing a modelDir across days is exactly when this earns its keep.
  const rotationStatePath = join(input.modelDir, ".witnessed-candidates.json");

  const range = resolveRange(input.tree, { range: input.range, hours: input.hours }, git);
  const generatedAt = new Date().toISOString();
  if (!range) {
    notes.push(`No commits in the last ${input.hours ?? 24}h window — empty funnel (this is a valid, honest result).`);
    return {
      tree: input.tree, range: "(empty window)", generatedAt,
      funnel: {
        commits: 0, changedFiles: 0, inScope: 0, semantic: 0, candidates: 0, survivors: 0,
        candidatesByDetector: zero(), survivorsByDetector: zero(), dualViewWitnessAttempted: 0,
      },
      detectors, files: [], survivors: [], notes,
    };
  }
  log(`[recency] detectors: ${detectors.join(", ")}`);
  log(`[recency] range ${range}`);

  const commits = countCommits(input.tree, range, git);
  const changed = changedFilesInRange(input.tree, range, git);
  log(`[recency] ${commits} commit(s), ${changed.length} changed file(s)`);

  const files: RecencyFileRecord[] = [];
  const inScope: RecencyFileRecord[] = [];

  // Stage 1 — reachability filter.
  for (const cf of changed) {
    const reach = isReachablePath(cf.path);
    const rec: RecencyFileRecord = {
      file: cf.path, status: cf.status,
      reachable: reach.reachable, reachReason: reach.reason,
      ...(reach.subsystem ? { subsystem: reach.subsystem } : {}),
    };
    files.push(rec);
    if (reach.reachable) inScope.push(rec);
  }
  log(`[recency] ${inScope.length} file(s) in unpriv-reachable scope`);

  // Stage 2 — semantic-vs-cosmetic classifier. Bound the classifier cost: the
  // snapshot repo can surface hundreds of in-scope files, so classify at most
  // `maxClassifyFiles` and record the remainder as capped (not silently dropped).
  const maxClassify = input.maxClassifyFiles ?? 80;
  const toClassify = inScope.slice(0, maxClassify);
  for (const rec of inScope.slice(maxClassify)) {
    rec.classification = "classifier-capped";
    rec.classifyReason = `beyond --max-classify-files=${maxClassify} (snapshot merge-window churn; see README on tag-diffing)`;
  }
  if (inScope.length > maxClassify) {
    notes.push(`Classifier capped at ${maxClassify} of ${inScope.length} in-scope files (snapshot rebases the whole merge window daily — diff against yesterday's snapshot tag for a true 1-day window).`);
  }
  const semantic: RecencyFileRecord[] = [];
  for (const rec of toClassify) {
    let diffText = "";
    try {
      diffText = fileDiff(input.tree, range, rec.file, git);
    } catch (e) {
      rec.error = `diff failed: ${String(e).slice(0, 120)}`;
      continue;
    }
    const signal = lifetimeTokenSignal(diffText);
    rec.lifetimeSignal = signal;
    let verdict: CosmeticVerdict;
    try {
      verdict = await classify({ file: rec.file, subsystem: rec.subsystem, diffText, signal, model: input.classifierModel });
    } catch (e) {
      rec.error = `classify failed: ${String(e).slice(0, 120)}`;
      continue;
    }
    rec.classification = verdict.verdict;
    rec.classifyReason = verdict.reason;
    if (verdict.verdict === "semantic") semantic.push(rec);
    else log(`[recency] SKIP (cosmetic) ${rec.file}: ${verdict.reason}`);
  }
  log(`[recency] ${semantic.length} file(s) passed the semantic filter`);

  // Stage 3+4 — refined engine + adversarial verify, per semantic file.
  const maxHunt = input.maxHuntFiles ?? 25;
  const toHunt = semantic.slice(0, maxHunt);
  if (semantic.length > maxHunt) {
    notes.push(`Capped hunt at ${maxHunt} of ${semantic.length} semantic files (raise --max-hunt-files to widen).`);
  }

  const candidatesByDetector = zero();
  const survivorsByDetector = zero();
  let dualViewWitnessAttempted = 0;
  const survivors: RecencySurvivor[] = [];
  for (const rec of toHunt) {
    log(`[recency] hunting ${rec.file} (${rec.subsystem}) with [${detectors.join(", ")}]`);
    const recCands = zero();
    const recSurvs = zero();
    try {
      // Detectors 1-3 — the STATIC engine (dataflow + refcount + race), sharing ONE
      // invariant model + the skeptic gate. Built only when a static detector is
      // selected; a dual-view-only run skips the invariant model entirely.
      if (runDataflow || extraDetectors.length > 0) {
        const modelPath = join(input.modelDir, `${rec.file.replace(/[/.]/g, "_")}.model.json`);
        // ONE model per file, shared by every static detector. When dataflow is
        // deselected we still build it (skipHunt) so refcount/race have a model to reuse.
        const result = await hunt({
          sourceRoot: input.tree,
          subsystem: rec.subsystem ?? rec.file,
          subsystemFiles: [rec.file],
          runtime: input.runtime,
          modelPath,
          rebuildModel: true, // fresh window — never reuse a stale model
          ...(runDataflow ? {} : { skipHunt: true }),
          ...(input.model ? { model: input.model } : {}),
          log,
        });

        // Detector 1 — dataflow (intra-proc lock-set + reaching-free).
        if (runDataflow) {
          recCands.dataflow = result.violations.length;
          const survs = survivorsFromHunt(rec, result);
          recSurvs.dataflow = survs.length;
          survivors.push(...survs);
        }

        // Detectors 2+3 — refcount + race, reusing the SAME model just built.
        if (extraDetectors.length > 0) {
          const extra = await detect({
            detectors: extraDetectors,
            model: result.model,
            sourceRoot: input.tree,
            file: rec.file,
            ...(rec.subsystem ? { subsystem: rec.subsystem } : {}),
            runtime: input.runtime,
            ...(input.model ? { finderModel: input.model } : {}),
            log,
          });
          if (extra.refcount) {
            recCands.refcount = extra.refcount.candidateCount;
            recSurvs.refcount = extra.refcount.survivors.length;
            survivors.push(...extra.refcount.survivors);
          }
          if (extra.race) {
            recCands.race = extra.race.candidateCount;
            recSurvs.race = extra.race.survivors.length;
            survivors.push(...extra.race.survivors);
          }
        }
      }

      // Detector 4 — dual-view (assumption-mining → dynamic KASAN oracle). Mines its
      // OWN assumption model (not the invariant model), enumerates cross-phase seams,
      // and — when RUN budget remains — routes them to the KASAN synthesize→boot→
      // witness oracle. ONLY dynamically-witnessed candidates become survivors. The
      // per-file witness slice is clamped to what remains of the run budget so VM
      // boots stay bounded across the whole run.
      if (runDualView) {
        const perFileCap = Math.min(dwPerFile, witnessBudgetRemaining);
        const witnessBudget =
          dwConfig && perFileCap > 0
            ? { maxCandidates: perFileCap, maxRounds: dwRounds, rotationStatePath, ...(dwWitnessDeps ? { deps: dwWitnessDeps } : {}) }
            : undefined;
        const dv = await dualViewDetect({
          sourceRoot: input.tree,
          file: rec.file,
          ...(rec.subsystem ? { subsystem: rec.subsystem } : {}),
          runtime: input.runtime,
          assumptionModelPath: join(input.modelDir, `${rec.file.replace(/[/.]/g, "_")}.assumptions.json`),
          ...(input.remineAssumptions ? { remine: true } : {}),
          ...(input.model ? { model: input.model } : {}),
          ...(witnessBudget ? { witnessBudget } : {}),
          log,
        });
        recCands.dualView = dv.candidateCount;
        recSurvs.dualView = dv.survivors.length;
        rec.dualViewWitnessAttempted = dv.witnessAttempted;
        dualViewWitnessAttempted += dv.witnessAttempted;
        witnessBudgetRemaining = Math.max(0, witnessBudgetRemaining - dv.witnessAttempted);
        survivors.push(...dv.survivors);
      }

      rec.candidatesByDetector = recCands;
      rec.survivorsByDetector = recSurvs;
      rec.candidates = recCands.dataflow + recCands.refcount + recCands.race + recCands.dualView;
      rec.survivorCount = recSurvs.dataflow + recSurvs.refcount + recSurvs.race + recSurvs.dualView;
      candidatesByDetector.dataflow += recCands.dataflow;
      candidatesByDetector.refcount += recCands.refcount;
      candidatesByDetector.race += recCands.race;
      candidatesByDetector.dualView += recCands.dualView;
      survivorsByDetector.dataflow += recSurvs.dataflow;
      survivorsByDetector.refcount += recSurvs.refcount;
      survivorsByDetector.race += recSurvs.race;
      survivorsByDetector.dualView += recSurvs.dualView;
    } catch (e) {
      rec.error = `hunt failed: ${String(e).slice(0, 160)}`;
      log(`[recency] hunt error on ${rec.file}: ${rec.error}`);
    }
  }

  const totalCandidates =
    candidatesByDetector.dataflow + candidatesByDetector.refcount + candidatesByDetector.race + candidatesByDetector.dualView;

  // Rank survivors: higher severity first, then those with a concrete line.
  const sevRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  survivors.sort((a, b) => (sevRank[b.severity] ?? 0) - (sevRank[a.severity] ?? 0) || b.line - a.line);

  if (survivors.length === 0) {
    notes.push("0 survivors this window — the honest expected result for a short window. The value is the working continuous system, not a guaranteed hit.");
  } else {
    notes.push(`${survivors.length} survivor lead(s) — HYPOTHESES, not proven bugs. Weaponize via autoclimb + verify novelty/reachability before any operator-gated disclosure.`);
  }
  notes.push(
    `Per-detector candidates {dataflow: ${candidatesByDetector.dataflow}, refcount: ${candidatesByDetector.refcount}, race: ${candidatesByDetector.race}, dual-view: ${candidatesByDetector.dualView}} → ` +
      `survivors {dataflow: ${survivorsByDetector.dataflow}, refcount: ${survivorsByDetector.refcount}, race: ${survivorsByDetector.race}, dual-view: ${survivorsByDetector.dualView}}.`,
  );
  if (runDualView) {
    // The honest dual-view funnel: seams enumerated → witness-attempted (bounded by
    // the run budget) → dynamically WITNESSED (the only ones promoted to survivors).
    notes.push(
      `Dual-view funnel: ${candidatesByDetector.dualView} seam candidate(s) → ${dualViewWitnessAttempted} witness-attempted (KASAN oracle) → ${survivorsByDetector.dualView} WITNESSED. ` +
        (dwConfig
          ? `Dynamic-witness budget: ${dwConfig.maxCandidatesPerRun ?? 10} candidate(s)/run × ${dwRounds} round(s) each (VM boots — the hard cost ceiling).`
          : `No --dynamic-witness budget configured — dual-view enumerated seams only (0 witnessed; the static skeptic refutes this class, so it is not run on them).`),
    );
  }

  return {
    tree: input.tree, range, generatedAt,
    funnel: {
      commits,
      changedFiles: changed.length,
      inScope: inScope.length,
      semantic: semantic.length,
      candidates: totalCandidates,
      survivors: survivors.length,
      candidatesByDetector,
      survivorsByDetector,
      dualViewWitnessAttempted,
    },
    detectors, files, survivors, notes,
  };
}

// ── Rendering ────────────────────────────────────────────────────────────────────

/** Render a recency report as operator-readable markdown. */
export function renderRecencyReportMarkdown(r: RecencyHuntReport): string {
  const L: string[] = [];
  L.push(`# Recency flywheel report`);
  L.push("");
  L.push(`- **tree**: \`${r.tree}\``);
  L.push(`- **range**: \`${r.range}\``);
  L.push(`- **generated**: ${r.generatedAt}`);
  L.push("");
  L.push(`## Funnel`);
  L.push("");
  L.push(`| stage | count |`);
  L.push(`|---|---|`);
  L.push(`| commits in window | ${r.funnel.commits} |`);
  L.push(`| changed files | ${r.funnel.changedFiles} |`);
  L.push(`| in unpriv-reachable scope | ${r.funnel.inScope} |`);
  L.push(`| passed semantic filter | ${r.funnel.semantic} |`);
  L.push(`| engine candidates (all detectors) | ${r.funnel.candidates} |`);
  L.push(`| **survivors (leads)** | **${r.funnel.survivors}** |`);
  L.push("");
  L.push(`**Detectors run:** ${r.detectors.join(", ")}`);
  L.push("");
  L.push(`| detector | candidates | survivors |`);
  L.push(`|---|---|---|`);
  const cbd = r.funnel.candidatesByDetector;
  const sbd = r.funnel.survivorsByDetector;
  L.push(`| dataflow | ${cbd.dataflow} | ${sbd.dataflow} |`);
  L.push(`| refcount | ${cbd.refcount} | ${sbd.refcount} |`);
  L.push(`| race | ${cbd.race} | ${sbd.race} |`);
  if (r.detectors.includes("dual-view")) {
    L.push(`| dual-view (dynamic) | ${cbd.dualView} | ${sbd.dualView} |`);
    L.push("");
    L.push(`> dual-view funnel: ${cbd.dualView} seam candidate(s) → ${r.funnel.dualViewWitnessAttempted} witness-attempted → **${sbd.dualView} dynamically WITNESSED** (object-bound KASAN). Only witnessed candidates are survivors.`);
  }
  L.push("");
  if (r.survivors.length > 0) {
    L.push(`## Survivors (ranked leads — verify before any disclosure)`);
    L.push("");
    for (const s of r.survivors) {
      L.push(`### ${s.file}:${s.line} — ${s.bugClass} (${s.severity}) [${s.detector}]`);
      L.push("");
      L.push(`- **detector**: ${s.detector}`);
      L.push(`- **function**: \`${s.functionName}()\``);
      if (s.subsystem) L.push(`- **subsystem**: ${s.subsystem}`);
      L.push(`- **title**: ${s.title}`);
      L.push(`- **verify verdict**: ${s.verifyVerdict}`);
      if (s.witness) {
        // A dual-view survivor is a DYNAMICALLY WITNESSED finding — surface the
        // KASAN splat + repro as the load-bearing evidence (not a static verdict).
        const w = s.witness;
        L.push(`- **DYNAMIC WITNESS**: object-bound \`${w.signature ?? "kasan"}\` on \`struct ${w.object}\`${w.boundTo ? ` (bound to \`${w.boundTo}\`)` : ""}, ${w.entryA}() ⇄ ${w.entryB}(), witnessed in ${w.rounds} round(s)`);
        if (w.splat) {
          L.push("");
          L.push("  KASAN splat:");
          L.push("");
          L.push("  ```");
          for (const line of w.splat.split("\n")) L.push(`  ${line}`);
          L.push("  ```");
        }
        if (w.repro) L.push(`- **repro**: a witnessing unprivileged C PoC is attached in \`survivor.witness.repro\` (${w.repro.length} bytes) — re-runnable in the KASAN VM`);
      }
      L.push(`- **next steps**:`);
      for (const step of s.bugSpec.nextSteps) L.push(`  - ${step}`);
      L.push("");
    }
  }
  L.push(`## Per-file trace`);
  L.push("");
  for (const f of r.files) {
    if (!f.reachable) {
      L.push(`- \`${f.file}\` (${f.status}) — DROPPED: ${f.reachReason}`);
    } else if (f.classification === "cosmetic") {
      L.push(`- \`${f.file}\` (${f.subsystem}) — SKIP (cosmetic): ${f.classifyReason}`);
    } else if (f.classification === "classifier-capped") {
      L.push(`- \`${f.file}\` (${f.subsystem}) — CAPPED (not classified): ${f.classifyReason}`);
    } else if (f.error) {
      L.push(`- \`${f.file}\` (${f.subsystem}) — ERROR: ${f.error}`);
    } else if (f.classification === "semantic") {
      const c = f.candidatesByDetector;
      const perDet = c ? ` [dataflow: ${c.dataflow}, refcount: ${c.refcount}, race: ${c.race}, dual-view: ${c.dualView}]` : "";
      L.push(`- \`${f.file}\` (${f.subsystem}) — SEMANTIC → hunted: ${f.candidates ?? 0} candidate(s)${perDet}, ${f.survivorCount ?? 0} survivor(s). ${f.classifyReason}`);
    } else {
      L.push(`- \`${f.file}\` (${f.subsystem}) — in scope, not classified`);
    }
  }
  L.push("");
  if (r.notes.length > 0) {
    L.push(`## Notes`);
    L.push("");
    for (const n of r.notes) L.push(`- ${n}`);
    L.push("");
  }
  return L.join("\n");
}

// ── small util ───────────────────────────────────────────────────────────────────

function clip(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max)}\n/* …clipped ${s.length - max} chars… */`;
}
