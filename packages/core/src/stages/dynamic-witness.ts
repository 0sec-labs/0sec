/**
 * DYNAMIC WITNESS — v3 of the assumption-mining hunter, and the piece the whole
 * field structurally lacks: the DYNAMIC ORACLE for dual-view / cross-phase
 * assumption candidates.
 *
 * WHY THIS EXISTS. v0-v2 mine relied-on assumptions, enumerate dual-view /
 * cross-phase seams (one long-lived object reached by two distinct entries/phases
 * where the second does not re-establish the first's guarantee), and hand every
 * survivor to the STATIC skeptic gate. v2's bench run proved the honest ceiling:
 * the static skeptic REFUTES all dual-view candidates. That is EXPECTED — a
 * dual-view/cross-phase bug is an INSTANCE problem (do the two phases touch the
 * SAME object concurrently / after the guarantee is dropped?), and no static,
 * name-based analysis can judge instance aliasing across two call-trees. The
 * candidate is neither confirmable nor refutable on paper.
 *
 * So the arbiter has to be DYNAMIC. This module takes a dual-view candidate and:
 *   1. SYNTHESIZES an unprivileged C PoC (LLM) that drives the two-view violation
 *      sequence — entry A establishes the assumed state, entry B violates it,
 *      then the dereference/use that would fault is triggered.
 *   2. BOOTS it in a KASAN VM (reusing the existing kernel-VM harness —
 *      {@link runReproducerInKernelVm} / the busybox-initramfs lane), capturing
 *      serial + dmesg.
 *   3. WITNESSES honestly: promote to CONFIRMED **only** when a real KASAN splat
 *      fires AND is BOUND to the candidate's object/site (the faulting function or
 *      the alloc/free stack references the candidate's object or one of its
 *      entries) — not an incidental splat, and never a splat the PoC itself
 *      printed (the anti-fabrication guard). No splat → refuted. Never compiled →
 *      inconclusive.
 *   4. ITERATES: feed the boot output back to the LLM to fix the PoC across a
 *      bounded budget — a PoC is usually wrong before it is right (AEG is hard).
 *
 * HONEST SCOPE. This is assume-FP by construction: the default verdict is
 * refuted/inconclusive; CONFIRMED requires an object-bound kernel splat from a run
 * the PoC did not fabricate. PoC synthesis is AEG-hard — compile rate < 1, and a
 * compiling PoC that actually drives the race/UAF is rarer still — so the realistic
 * hit-rate on HEAVILY-audited surfaces (net/unix SCM_RIGHTS, where DirtyCred lives)
 * is ~0 new bugs. The payoff is (a) MECHANISM: a synthesize→boot→witness loop that
 * runs end-to-end and cannot fabricate a crash, and (b) LEVERAGE: pointed at
 * FRESH / under-audited cross-phase objects, the same oracle turns an unjudgeable
 * static candidate into a real dynamic verdict.
 */

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { ReproducerResult, CrashReport } from "../triage/kernel-oracle.js";
import { runReproducerInKernelVm } from "../triage/kernel-vm-runner.js";
import { LlmApiRuntime } from "../runtime/index.js";
import type { RuntimeMode } from "@pwnkit/shared";
import {
  isMechanizableEstablisher,
  subjectSelfEnforces,
  type Assumption,
  type AssumptionKind,
  type SecurityRelevance,
  type ViolatingContext,
} from "./assumption-mining.js";

// ── The dual-view candidate (input to the oracle) ────────────────────────────────

/** One source excerpt handed to the synthesizer (a function body + its label). */
export interface CandidateSource {
  /** Human label: `entryA (establishing)`, `entryB (skipping)`, `relied-on subject`. */
  label: string;
  /** The function name the excerpt is for (for provenance). */
  fn: string;
  /** The C body text. */
  code: string;
}

/**
 * A dual-view / cross-phase candidate — the assumption + object + the establishing
 * entry (A) / skipping entry (B) pair + the mined predicate + the relevant source
 * excerpts. This is what the static enumerator ({@link scanDualViewContexts})
 * produces and what the static skeptic cannot judge; the dynamic oracle is the
 * arbiter.
 */
export interface DualViewCandidate {
  assumptionId: string;
  subsystem: string;
  /** The object TYPE token both views operate on (`unix_sock`, `scm_fp_list`, `fuse_req`). */
  object: string;
  /** The function that RELIES on the guarantee. */
  subject: string;
  /** entry A — the view that ESTABLISHES the guarantee on the object. */
  entryA: string;
  /** entry B — the view that reaches the SAME object type WITHOUT the guarantee. */
  entryB: string;
  /** The token entry A establishes and entry B skips (a lock / validator / get). */
  establisherToken: string;
  kind: AssumptionKind;
  securityRelevance: SecurityRelevance;
  /** The mined precondition entry B may violate. */
  predicate: string;
  /** True when entry B is an unprivileged syscall/socket-op reachable entry. */
  unprivEntry: boolean;
  /** Source excerpts for the synthesizer (entryA, entryB, subject bodies). */
  sources: CandidateSource[];
  /** The enumerator's free-form detail (what to confirm). */
  detail: string;
}

/**
 * Build a {@link DualViewCandidate} from a dual-view {@link ViolatingContext}, its
 * {@link Assumption}, and the subsystem body index. Non-dual-view contexts (the
 * caller-scan class) return null — the dynamic oracle is only for the dual-view
 * class the static skeptic cannot judge.
 */
export function dualViewCandidateFromContext(
  ctx: ViolatingContext,
  assumption: Assumption,
  bodies: Map<string, string>,
  subsystem: string,
): DualViewCandidate | null {
  if (!ctx.dualView || !ctx.object || !ctx.pairedEntry) return null;
  const entryA = ctx.pairedEntry;
  const entryB = ctx.caller;
  const sources: CandidateSource[] = [];
  const push = (label: string, fn: string) => {
    const code = bodies.get(fn);
    if (code) sources.push({ label, fn, code });
  };
  push("entryA (establishing view)", entryA);
  push("entryB (skipping view)", entryB);
  if (assumption.subject !== entryA && assumption.subject !== entryB) {
    push("relied-on subject", assumption.subject);
  }
  return {
    assumptionId: ctx.assumptionId,
    subsystem,
    object: ctx.object,
    subject: ctx.subject,
    entryA,
    entryB,
    establisherToken: ctx.establisherToken,
    kind: assumption.kind,
    securityRelevance: assumption.securityRelevance,
    predicate: assumption.predicate,
    unprivEntry: ctx.unprivEntry,
    sources,
    detail: ctx.detail,
  };
}

// ── Witness MODE + race-shape detection ──────────────────────────────────────────
//
// The single-threaded synth boots one sequential PoC per round. That is STRUCTURALLY
// unable to construct a multi-thread race/teardown interleave — so for a RACE-CLASS
// seam (DirtyCred/DirtyPipe class: a put racing a use, a concurrent swap of the same
// object, a double-fetch during use), a `refuted` from the single-thread synth only
// means "my sequential PoC didn't trigger it", NOT "safe". The race mode adds a synth
// path that emits a genuinely CONCURRENT PoC (N pthreads hammering entryA vs entryB on
// the SAME object under a start barrier, CPU-pinned, 100k+ iterations) to WIDEN the
// window. The KASAN boot + object-bound-splat witness check are IDENTICAL — only the
// PoC SHAPE and the "give the race many attempts" differ.

/** Which PoC shape the oracle synthesizes for a seam. */
export type WitnessMode =
  | "single" // the original single-threaded sequential PoC (unchanged)
  | "race" // a concurrent multi-thread PoC (pthreads + barrier + affinity + hammer loop)
  | "auto"; // pick `race` for a race-shaped seam, `single` otherwise (see resolveWitnessMode)

/** Race-PoC knobs — worker-thread count and per-thread iteration budget. */
export interface RaceConfig {
  /** Concurrent worker threads driving entryA vs entryB. */
  threads: number;
  /** Iterations each worker loops to widen the race window. */
  iters: number;
}

export const DEFAULT_RACE_THREADS = 4;
export const DEFAULT_RACE_ITERS = 200_000;
export const DEFAULT_RACE_CONFIG: RaceConfig = { threads: DEFAULT_RACE_THREADS, iters: DEFAULT_RACE_ITERS };

/**
 * The assumption kinds whose VIOLATION is inherently a concurrent/teardown INTERLEAVE
 * (timing-dependent), not a sequential ordering bug. These are the DirtyCred/DirtyPipe
 * family the single-threaded synth cannot express: a held-lock guarantee a concurrent
 * unlocked path violates, a same-type object swapped underneath a consumer, a
 * put racing a use, a double-init under concurrent re-entry, a value changing between
 * check and use.
 */
const RACE_SHAPED_KINDS = new Set<AssumptionKind>([
  "lock-held",
  "ownership-exclusive",
  "refcount-positive",
  "called-once",
  "revalidated",
]);

/**
 * A seam is RACE-SHAPED when either signal holds:
 *   1. its assumption kind is a concurrency/teardown kind (the primary signal), OR
 *   2. entry B is unprivileged-reachable AND the relevance is memory-safety
 *      (lifetime/type) — i.e. both phases are concurrently reachable from unprivileged
 *      syscalls and the credible violation is a concurrent teardown/use of the object.
 * Conservative: a non-race kind with no unpriv/memory-safety signal stays single.
 */
export function isRaceShapedCandidate(c: DualViewCandidate): boolean {
  if (RACE_SHAPED_KINDS.has(c.kind)) return true;
  if (c.unprivEntry && (c.securityRelevance === "lifetime" || c.securityRelevance === "type")) return true;
  return false;
}

/**
 * Resolve a {@link WitnessMode} against one candidate to the concrete PoC shape:
 * `single`/`race` pass through; `auto` picks `race` for a race-shaped seam and
 * `single` otherwise. `single` is guaranteed byte-for-byte the original path.
 */
export function resolveWitnessMode(mode: WitnessMode, c: DualViewCandidate): "single" | "race" {
  if (mode === "single") return "single";
  if (mode === "race") return "race";
  return isRaceShapedCandidate(c) ? "race" : "single";
}

// ── PoC synthesis (LLM boundary — injectable for tests) ──────────────────────────

export interface PocSynthesisInput {
  candidate: DualViewCandidate;
  /** 1-based synthesis round. */
  round: number;
  /**
   * The PoC SHAPE to synthesize. `"single"` (default/undefined) is the original
   * single-threaded sequential PoC — its prompt is byte-for-byte unchanged. `"race"`
   * asks for a genuinely CONCURRENT multi-thread PoC (pthreads + start barrier + CPU
   * pinning + a high-iteration hammer loop) so a cross-phase RACE/teardown interleave
   * the single-threaded synth cannot express gets many attempts to fire.
   */
  mode?: "single" | "race";
  /** Race knobs (threads/iterations). Present when `mode === "race"`. */
  race?: RaceConfig;
  /** The PoC from the previous round (present on rounds > 1). */
  priorCSource?: string;
  /**
   * The previous boot's feedback (compile error, or the serial/dmesg tail with no
   * matching splat) — the model uses it to FIX the PoC. Present on rounds > 1.
   */
  priorFeedback?: string;
}

export interface PocSynthesisResult {
  /** The synthesized self-contained C program. */
  cSource: string;
  /** Optional model rationale (recorded, not load-bearing). */
  rationale?: string;
}

/** The LLM boundary — synthesize (or repair) a PoC. Injectable so tests mock it. */
export type SynthesizePocFn = (input: PocSynthesisInput) => Promise<PocSynthesisResult | null>;

/** The VM boundary — compile + boot a PoC in a KASAN VM. Injectable so tests mock it. */
export type BootPocFn = (cSource: string, candidate: DualViewCandidate) => Promise<ReproducerResult>;

const SYNTH_SYSTEM =
  "You are a world-class Linux kernel exploit engineer writing a PROOF-OF-CONCEPT trigger, not a description. " +
  "You are given a DUAL-VIEW / CROSS-PHASE assumption candidate: a long-lived kernel object reached by TWO " +
  "distinct entries/phases, where entry A establishes a guarantee (a held lock / a validated ref / an " +
  "exclusive owner / a once-only init) and entry B reaches the SAME object WITHOUT re-establishing it. Your " +
  "job: produce a SELF-CONTAINED, UNPRIVILEGED C program that (a) sets up the object via entry A's path to " +
  "establish the assumed state, (b) drives entry B's path in the way that VIOLATES entry A's assumption on the " +
  "SAME object instance, and (c) triggers the dereference/use that would fault — aiming for a KASAN " +
  "use-after-free / out-of-bounds / double-free on the candidate's object.\n\n" +
  "HARD RULES:\n" +
  "  1. Output ONE complete C file in a single ```c fenced block. It must compile with " +
  "`gcc -O0 -static -o poc poc.c -lpthread` on a modern glibc. No external headers beyond libc/uapi; if a " +
  "syscall wrapper is missing, use syscall(2) with the __NR_ number directly.\n" +
  "  2. Drop privileges early: call setuid(65534)/setgid(65534) after any setup that is itself unprivileged, " +
  "so the trigger runs as an UNPRIVILEGED user (the whole point — the object must be reachable without root). " +
  "If the whole flow is unprivileged (SCM_RIGHTS, AF_UNIX, io_uring, fuse mounts in a userns), drop immediately.\n" +
  "  3. To hit a cross-phase RACE, spawn threads that hammer entry A and entry B concurrently on the SAME object " +
  "(the same fd / same socket / same registered buffer), pinned to CPUs if it helps, looping thousands of times.\n" +
  "  4. Do NOT print fabricated kernel logs. NEVER printf a 'BUG: KASAN' / 'use-after-free' / 'general " +
  "protection' string — the witness is the KERNEL's splat on the serial console, and a PoC that prints one is " +
  "rejected as fabrication. Print only your own progress markers.\n" +
  "  5. Make it deterministic-ish and bounded: exit within ~20s even if it does not trigger (the harness caps " +
  "the run). Emit via the fenced C block only; a one-paragraph plan before it is fine.";

const RACE_SYNTH_SYSTEM =
  "You are a world-class Linux kernel exploit engineer writing a genuinely CONCURRENT, MULTI-THREAD " +
  "PROOF-OF-CONCEPT race trigger, not a description and not a single-threaded stub. You are given a " +
  "DUAL-VIEW / CROSS-PHASE assumption candidate whose violation is a RACE: a long-lived kernel object reached " +
  "by TWO distinct entries/phases, where entry A holds a guarantee (a held lock / a validated ref / an " +
  "exclusive owner / a live refcount) and entry B, run CONCURRENTLY on the SAME object instance, tears it " +
  "down or mutates it out from under A — the DirtyCred/DirtyPipe class (a put racing a use, a same-type " +
  "object swapped mid-use, a double-fetch, a concurrent teardown). Your job: produce a SELF-CONTAINED, " +
  "UNPRIVILEGED C program that races entry A against entry B on the SAME object to trip a KASAN " +
  "use-after-free / out-of-bounds / double-free.\n\n" +
  "HARD RULES:\n" +
  "  1. Output ONE complete C file in a single ```c fenced block. It MUST compile with " +
  "`gcc -O0 -static -o poc poc.c -lpthread` on a modern glibc. Include <pthread.h>, <sched.h>, <unistd.h>. " +
  "No external headers beyond libc/uapi; if a syscall wrapper is missing, use syscall(2) with __NR_ directly.\n" +
  "  2. GENUINELY CONCURRENT STRUCTURE — all of these, not a sketch:\n" +
  "     • A `pthread_barrier_t` start barrier so every worker begins the contended window at the SAME instant " +
  "(initialize it for exactly the number of threads that wait on it, and have each worker `pthread_barrier_wait` " +
  "before its hammer loop).\n" +
  "     • N worker threads via `pthread_create` — roughly half driving entry A's path, half driving entry B's " +
  "path, all on the SAME shared object (same fd / same socket / same registered buffer/id).\n" +
  "     • CPU PINNING: each worker calls `sched_setaffinity` onto a DISTINCT core (cpu = worker_index % " +
  "get_nprocs()) so A and B run on different physical CPUs and actually overlap.\n" +
  "     • A tight HAMMER LOOP of a HIGH iteration count (100000+ per thread) around the contended syscall pair, " +
  "and an OUTER loop that RE-ARMS the object (re-create/re-register) each attempt so the window is retried many " +
  "times — a race almost never fires on the first pass.\n" +
  "  3. Drop privileges early (setuid/setgid to 65534) once setup is unprivileged, OR run fully unprivileged " +
  "from the start (SCM_RIGHTS, AF_UNIX, io_uring, userns) — the object must be reachable without root.\n" +
  "  4. Do NOT print fabricated kernel logs. NEVER printf a 'BUG: KASAN' / 'use-after-free' / 'general " +
  "protection' string — the witness is the KERNEL's splat on serial; a PoC that prints one is rejected as " +
  "fabrication. Print only your own progress markers (e.g. iteration counts).\n" +
  "  5. Bounded: cap total wall time (~20s) with an overall attempt ceiling and join all threads before exit, " +
  "so it terminates even when the race does not fire (the harness also caps the run). Emit the fenced C block; " +
  "a one-paragraph plan before it is fine.";

/** The race-scaffold spec appended to the user prompt so the model emits the required concurrent structure. */
function raceScaffoldSpec(c: DualViewCandidate, race: RaceConfig): string {
  return (
    `## RACE SYNTHESIS — emit a CONCURRENT multi-thread PoC\n` +
    `This seam is race-shaped: the violation of '${c.predicate}' on struct ${c.object} is a concurrent ` +
    `interleave, NOT a sequential A-then-B ordering. A single-threaded PoC CANNOT witness it. Race ` +
    `entry A (${c.entryA}, which establishes ${c.establisherToken}) against entry B (${c.entryB}, which skips ` +
    `it) on the SAME struct ${c.object} instance.\n\n` +
    `REQUIRED structure (all must appear in the emitted C):\n` +
    `- pthread_barrier_t start barrier; every worker pthread_barrier_wait()s before the hammer loop.\n` +
    `- ${race.threads} worker threads via pthread_create: ~half drive ${c.entryA}'s syscall path, ~half drive ` +
    `${c.entryB}'s, all on ONE shared object.\n` +
    `- sched_setaffinity pinning each worker to a distinct CPU (cpu = idx % get_nprocs()).\n` +
    `- a per-thread hammer loop of ${race.iters}+ iterations around the contended syscalls, inside an outer ` +
    `loop that RE-ARMS the object each attempt.\n` +
    `- join all threads; bounded ~20s wall clock; no fabricated splat strings.\n`
  );
}

/** Compose the per-round race synthesis prompt (candidate + race scaffold + excerpts + prior feedback). */
export function buildRaceSynthesisPrompt(input: PocSynthesisInput): string {
  const c = input.candidate;
  const race = input.race ?? DEFAULT_RACE_CONFIG;
  const excerpts = c.sources
    .map((s) => `### ${s.label} — ${s.fn}()\n\`\`\`c\n${clip(s.code, 8000)}\n\`\`\``)
    .join("\n\n");
  const header =
    `## Dual-view RACE candidate (subsystem: ${c.subsystem})\n` +
    `- object (type reached + contended by both views): struct ${c.object}\n` +
    `- entry A (ESTABLISHES ${c.establisherToken}): ${c.entryA}()\n` +
    `- entry B (SKIPS ${c.establisherToken}, race it): ${c.entryB}()\n` +
    `- relied-on subject: ${c.subject}()\n` +
    `- assumption kind: ${c.kind} (${c.securityRelevance})\n` +
    `- relied-on precondition (entry B races to violate): ${c.predicate}\n` +
    `- unprivileged-reachable entry B: ${c.unprivEntry ? "yes" : "unknown"}\n\n` +
    `${c.detail}\n`;
  if (input.round > 1) {
    return (
      `${header}\n${raceScaffoldSpec(c, race)}\n## Prior race PoC (round ${input.round - 1}) did NOT witness the bug — FIX it.\n` +
      `\`\`\`c\n${clip(input.priorCSource ?? "", 9000)}\n\`\`\`\n\n` +
      `## Boot feedback (compile error, or serial/dmesg with NO object-bound KASAN splat)\n` +
      `\`\`\`\n${clip(input.priorFeedback ?? "(none captured)", 6000)}\n\`\`\`\n\n` +
      `Diagnose why the race did not fire (window too narrow? threads not on the same instance? barrier/affinity ` +
      `missing? too few iterations? compile error?) and emit a corrected complete concurrent C file that keeps ` +
      `the required race structure.\n\n## Source excerpts\n\n${excerpts}`
    );
  }
  return `${header}\n${raceScaffoldSpec(c, race)}\n## Source excerpts\n\n${excerpts}\n\nSynthesize the concurrent race PoC now.`;
}

/** Compose the per-round synthesis prompt (the candidate + excerpts + prior feedback). */
export function buildSynthesisPrompt(input: PocSynthesisInput): string {
  if (input.mode === "race") return buildRaceSynthesisPrompt(input);
  const c = input.candidate;
  const excerpts = c.sources
    .map((s) => `### ${s.label} — ${s.fn}()\n\`\`\`c\n${clip(s.code, 8000)}\n\`\`\``)
    .join("\n\n");
  const header =
    `## Dual-view assumption candidate (subsystem: ${c.subsystem})\n` +
    `- object (type reached by both views): struct ${c.object}\n` +
    `- entry A (ESTABLISHES ${c.establisherToken}): ${c.entryA}()\n` +
    `- entry B (SKIPS ${c.establisherToken}): ${c.entryB}()\n` +
    `- relied-on subject: ${c.subject}()\n` +
    `- assumption kind: ${c.kind} (${c.securityRelevance})\n` +
    `- relied-on precondition (entry B may violate): ${c.predicate}\n` +
    `- unprivileged-reachable entry B: ${c.unprivEntry ? "yes" : "unknown"}\n\n` +
    `${c.detail}\n`;
  if (input.round > 1) {
    return (
      `${header}\n## Prior PoC (round ${input.round - 1}) did NOT witness the bug — FIX it.\n` +
      `\`\`\`c\n${clip(input.priorCSource ?? "", 9000)}\n\`\`\`\n\n` +
      `## Boot feedback (compile error, or serial/dmesg with NO object-bound KASAN splat)\n` +
      `\`\`\`\n${clip(input.priorFeedback ?? "(none captured)", 6000)}\n\`\`\`\n\n` +
      `Diagnose why it did not trigger (wrong syscall sequence? never reached entry B on the same instance? ` +
      `window too narrow? compile error?) and emit a corrected complete C file.\n\n## Source excerpts\n\n${excerpts}`
    );
  }
  return `${header}\n## Source excerpts\n\n${excerpts}\n\nSynthesize the PoC now.`;
}

function clip(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + `\n/* ...[truncated ${s.length - n} chars] */` : s;
}

/**
 * Extract the C source from an LLM response: the first ```c (or bare ```) fenced
 * block, else — when the model returned raw C with no fence — the whole text if it
 * looks like a C program. Returns null when nothing usable is present.
 */
export function extractCFromLlmOutput(text: string): string | null {
  if (!text) return null;
  const fenced = text.match(/```(?:c|cpp|c\+\+)?\s*\n([\s\S]*?)```/i);
  if (fenced && fenced[1].trim()) return fenced[1].replace(/\s+$/, "") + "\n";
  // No fence — accept a bare program only if it plausibly is one.
  if (/#include\b|\bint\s+main\s*\(/.test(text)) return text.replace(/\s+$/, "") + "\n";
  return null;
}

/**
 * Default PoC synthesizer: route the prompt through the IN-PROCESS
 * {@link LlmApiRuntime} via `executeNative` (which sends `stream: true` and parses
 * the SSE response) and extract the fenced C. `model` picks the provider/model
 * (e.g. `gpt-5.5` → chatgpt-codex via `~/.codex/auth.json`). Tests inject their
 * own {@link SynthesizePocFn} and never reach this.
 *
 * WHY `executeNative` AND NOT `execute`. The chatgpt-codex backend
 * (`/backend-api/codex/responses`) REQUIRES a streaming request: the legacy
 * buffered `execute()` posts a non-streaming body and gets HTTP 400
 * `"Stream must be set to true"`, which `execute()` swallows into an empty
 * `output` → `extractCFromLlmOutput` returns null → EVERY synthesis fails → the
 * whole `--dynamic-witness` loop reports 100% `inconclusive` (the oracle looks
 * dead while actually never getting a PoC). `executeNative` is the streaming path
 * (verified live on bench against gpt-5.5), so synthesis MUST use it.
 *
 * The `runtime` arg is accepted for signature compatibility but synthesis always
 * runs in-process (`type: "api"`) — the ProcessRuntime CLI only implements
 * `executeNative` for claude, not codex, so the CLI lane cannot synthesise here.
 */
export function makeDefaultSynthesizePoc(_runtime: RuntimeMode, model?: string, timeoutMs = 300_000): SynthesizePocFn {
  return async (input) => {
    const rt = new LlmApiRuntime({ type: "api", timeout: timeoutMs, ...(model ? { model } : {}) });
    const system = input.mode === "race" ? RACE_SYNTH_SYSTEM : SYNTH_SYSTEM;
    const res = await rt.executeNative(
      system,
      [{ role: "user", content: [{ type: "text", text: buildSynthesisPrompt(input) }] }],
      [],
    );
    const text = (res.content ?? [])
      .filter((b) => b.type === "text")
      .map((b) => (b as { text: string }).text)
      .join("\n");
    const cSource = extractCFromLlmOutput(text);
    if (!cSource) return null;
    return { cSource };
  };
}

/** Default VM boundary: wrap the PoC in a CrashReport and boot it via the KASAN harness. */
export const defaultBootPoc: BootPocFn = (cSource) => {
  const report: CrashReport = {
    raw: "",
    crashType: "unknown",
    faultingFunction: "unknown",
    stackFrames: [],
    reproducer: cSource,
    reproducerLanguage: "c",
  };
  return runReproducerInKernelVm(report);
};

// ── Witness check (deterministic, assume-FP) ─────────────────────────────────────

/**
 * The memory-safety splat classes the oracle PROMOTES on. A UBSAN/null-deref/GPF is
 * a crash but not the object-bound KASAN witness this stage requires; those keep the
 * verdict below `confirmed` (a real UAF/OOB/double-free is the dual-view payoff).
 */
const WITNESS_SIGNATURES: { pattern: RegExp; signature: string }[] = [
  { pattern: /KASAN:\s+slab-use-after-free|KASAN:.*use-after-free|use-after-free in/i, signature: "kasan-uaf" },
  { pattern: /KASAN:\s+slab-out-of-bounds|KASAN:.*out-of-bounds|out-of-bounds in/i, signature: "kasan-oob" },
  { pattern: /KASAN:.*double-free|double-free or invalid-free/i, signature: "kasan-double-free" },
  { pattern: /KASAN:.*invalid-free/i, signature: "kasan-invalid-free" },
  { pattern: /KASAN:.*stack-out-of-bounds/i, signature: "kasan-stack-oob" },
];

/**
 * Any recognizable kernel crash (broader than the promote set) — for reporting.
 *
 * The KASAN alternative is ANCHORED to real splat forms (`BUG: KASAN …` or
 * `KASAN: slab-/global-/stack-/vmalloc-/use-after-free/out-of-bounds/…`). A bare
 * `KASAN:` alternative used to match the boot banner
 * `kasan: KernelAddressSanitizer initialized` (case-insensitive), so EVERY clean
 * boot on a KASAN kernel was mislabelled "a kernel crash fired" — both in the
 * refute reason AND in the boot-feedback fed to the next synthesis round, which
 * misled the LLM into "fixing" a crash that never happened. WITNESS_SIGNATURES
 * (the promote set) is unaffected — assume-FP stays intact.
 */
const ANY_CRASH = /BUG:\s*KASAN|KASAN:\s*(?:slab-|global-|stack-|vmalloc-|use-after-free|out-of-bounds|invalid-free|double-free)|UBSAN|general protection fault|NULL pointer dereference|kernel NULL pointer|BUG:\s*KCSAN/i;

export interface WitnessCheck {
  /** True only for a real, object-bound, non-fabricated memory-safety splat. */
  witnessed: boolean;
  /** The promote-class signature (kasan-uaf/…), when one fired. */
  signature?: string;
  /** True when the splat referenced the candidate's object/site. */
  objectBound: boolean;
  /** The candidate reference token the splat bound to (function or object type). */
  boundTo?: string;
  /** The extracted KASAN report region (the splat), when present. */
  splat?: string;
  /** Why witnessed is false (or the confirming reason when true). */
  reason: string;
}

/** The candidate identifiers a genuine, object-bound splat should reference. */
export function candidateReferenceTokens(c: DualViewCandidate): string[] {
  const toks = new Set<string>();
  for (const t of [c.object, c.subject, c.entryA, c.entryB, ...c.sources.map((s) => s.fn)]) {
    const s = (t ?? "").trim();
    if (s && s.length >= 4) toks.add(s);
  }
  return [...toks];
}

/**
 * Extract the KASAN/oops report region from a dmesg/serial dump: from the first
 * crash-signature line to a bounded window after (or the closing `====` rule KASAN
 * prints). Coarse but enough to scope the object-binding check to the splat itself
 * (not incidental mentions elsewhere in the boot log).
 */
export function extractSplatRegion(dmesg: string): string | null {
  if (!dmesg) return null;
  const lines = dmesg.split(/\r?\n/);
  let start = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/BUG:\s*KASAN|KASAN:\s*(slab|global|stack|use-after|out-of|double-free|invalid-free)|general protection fault|NULL pointer dereference/i.test(lines[i])) {
      start = i;
      break;
    }
  }
  if (start < 0) return null;
  // Pull in the opening '=' rule when it sits just above the BUG line (KASAN
  // brackets the report), so the region is the full splat.
  if (start > 0 && /^={5,}\s*$/.test(lines[start - 1].replace(/^\[\s*\d+\.\d+\]\s*/, "").trim())) start -= 1;
  // End at the CLOSING '=' rule after the BUG line, else an 80-line window. The
  // rule is timestamp-prefixed on a live serial console, so strip that first.
  let end = Math.min(lines.length, start + 80);
  for (let i = start + 1; i < Math.min(lines.length, start + 120); i++) {
    if (/^={5,}\s*$/.test(lines[i].replace(/^\[\s*\d+\.\d+\]\s*/, "").trim())) { end = i + 1; break; }
  }
  return lines.slice(start, end).join("\n");
}

/**
 * Anti-fabrication guard (the oracle's anti-cheat idea): a PoC must not manufacture
 * its own splat. If ANY crash-signature line present in the dmesg is ALSO a
 * substring of the PoC source, the "splat" may be a `printf` the exploit emitted —
 * refuse to credit it. Kernel-emitted splats carry addresses/line-numbers the
 * source cannot contain, so a genuine splat never matches this.
 */
export function pocFabricatesSplat(cSource: string, dmesg: string): boolean {
  if (!cSource || !dmesg) return false;
  const src = cSource;
  for (const line of dmesg.split(/\r?\n/)) {
    const t = line.trim();
    if (t.length < 12) continue;
    if (!ANY_CRASH.test(t)) continue;
    // Strip a leading "[   12.345678] " timestamp the kernel adds but source can't.
    const bare = t.replace(/^\[\s*\d+\.\d+\]\s*/, "");
    if (bare.length >= 12 && src.includes(bare)) return true;
  }
  return false;
}

/**
 * WITNESS CHECK (assume-FP). Promote to witnessed ONLY when:
 *   • the run executed (the PoC actually ran — not a compile-only artifact),
 *   • a promote-class KASAN splat is present in the dmesg,
 *   • the splat is BOUND to the candidate (its region references the object type
 *     or one of the candidate's functions), and
 *   • the PoC did not fabricate the splat.
 * Any miss returns witnessed=false with the specific reason.
 */
export function checkWitness(candidate: DualViewCandidate, cSource: string, result: ReproducerResult): WitnessCheck {
  const dmesg = `${result.dmesg ?? ""}\n${result.output ?? ""}`;
  const splat = extractSplatRegion(dmesg);
  if (!result.executed) {
    return { witnessed: false, objectBound: false, reason: result.compiled ? "PoC compiled but did not execute in the VM" : "PoC did not compile", ...(splat ? { splat } : {}) };
  }
  const sigHit = WITNESS_SIGNATURES.find((s) => s.pattern.test(dmesg));
  if (!sigHit) {
    return { witnessed: false, objectBound: false, reason: ANY_CRASH.test(dmesg) ? "a kernel crash fired but not a promote-class KASAN UAF/OOB/double-free splat" : "no KASAN splat in the boot output", ...(splat ? { splat } : {}) };
  }
  if (pocFabricatesSplat(cSource, dmesg)) {
    return { witnessed: false, objectBound: false, signature: sigHit.signature, reason: "REJECTED: a splat line is a verbatim substring of the PoC source — fabricated, not a kernel-emitted splat", ...(splat ? { splat } : {}) };
  }
  const region = splat ?? dmesg;
  const tokens = candidateReferenceTokens(candidate);
  const boundTo = tokens.find((t) => new RegExp(`\\b${escapeRe(t)}\\b`).test(region));
  if (!boundTo) {
    return { witnessed: false, objectBound: false, signature: sigHit.signature, reason: `KASAN ${sigHit.signature} splat fired but is NOT bound to the candidate — no candidate object/function [${tokens.join(", ")}] appears in the splat (incidental splat)`, ...(splat ? { splat } : {}) };
  }
  return {
    witnessed: true,
    objectBound: true,
    signature: sigHit.signature,
    boundTo,
    ...(splat ? { splat } : {}),
    reason: `object-bound ${sigHit.signature}: the splat references '${boundTo}' (the candidate's ${boundTo === candidate.object ? "object type" : "entry/subject"}) — a real dynamic witness of the assumption violation`,
  };
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// ── The dynamic-witness loop ─────────────────────────────────────────────────────

export type WitnessVerdict =
  | "confirmed" // object-bound KASAN splat from a non-fabricated run
  | "refuted" // PoC compiled + ran across the budget, no object-bound splat
  | "inconclusive"; // PoC never compiled/executed, or synthesis produced nothing

export interface WitnessAttempt {
  round: number;
  /** The LLM produced a PoC this round. */
  synthesized: boolean;
  compiled: boolean;
  executed: boolean;
  timedOut: boolean;
  /** The witness check verdict for this round's boot. */
  check?: WitnessCheck;
  /** Tail of the boot output / compile error fed back to the next round. */
  feedbackTail: string;
}

export interface WitnessResult {
  candidate: DualViewCandidate;
  verdict: WitnessVerdict;
  attempts: WitnessAttempt[];
  /** The confirming attempt, when verdict === "confirmed". */
  witnessedAttempt?: WitnessAttempt;
  /** The PoC of the confirming (or last) round. */
  finalCSource?: string;
  /** The exact object-bound splat, when confirmed. */
  splat?: string;
  /** One-line human summary. */
  summary: string;
}

export interface DynamicWitnessDeps {
  /** LLM PoC synthesizer. Defaults to {@link makeDefaultSynthesizePoc}(runtime,model). */
  synthesizePoc?: SynthesizePocFn;
  /** VM boot boundary. Defaults to {@link defaultBootPoc} (the real KASAN harness). */
  bootPoc?: BootPocFn;
  /** Runtime for the default synthesizer (ignored when synthesizePoc is injected). */
  runtime?: RuntimeMode;
  /** Model for the default synthesizer. */
  model?: string;
  /** Bounded PoC-repair budget (synthesis→boot→witness rounds). Default 3. */
  maxRounds?: number;
  /**
   * PoC-shape mode. `single` (unchanged) synthesizes a sequential PoC; `race` a
   * concurrent multi-thread PoC; `auto` picks `race` for a race-shaped seam and
   * `single` otherwise. Default `auto` — a NON-race seam resolves to `single`, so the
   * default preserves the original single-thread behaviour unless race actually applies.
   */
  witnessMode?: WitnessMode;
  /** Race knobs (threads/iters) used when the resolved mode is `race`. Defaults applied per field. */
  raceConfig?: Partial<RaceConfig>;
  log?: (msg: string) => void;
}

/**
 * Run the dynamic oracle on one dual-view candidate: synthesize → boot in KASAN →
 * witness, iterating the PoC across a bounded budget until it witnesses or the
 * budget is spent. Assume-FP: returns `confirmed` ONLY on a real, object-bound,
 * non-fabricated KASAN splat.
 */
export async function witnessAssumptionViolation(
  candidate: DualViewCandidate,
  deps: DynamicWitnessDeps = {},
): Promise<WitnessResult> {
  const log = deps.log ?? (() => {});
  const maxRounds = Math.max(1, deps.maxRounds ?? 3);
  const synthesize = deps.synthesizePoc ?? makeDefaultSynthesizePoc(deps.runtime ?? "api", deps.model);
  const boot = deps.bootPoc ?? defaultBootPoc;
  // Resolve the PoC shape ONCE per candidate. `auto` (default) picks `race` only for a
  // race-shaped seam; a non-race seam resolves to `single` and the synthesis input +
  // prompt are byte-for-byte the original path.
  const resolvedMode = resolveWitnessMode(deps.witnessMode ?? "auto", candidate);
  const raceConfig: RaceConfig = {
    threads: deps.raceConfig?.threads ?? DEFAULT_RACE_THREADS,
    iters: deps.raceConfig?.iters ?? DEFAULT_RACE_ITERS,
  };
  if (resolvedMode === "race") {
    log(`[witness]   race-shaped seam → CONCURRENT PoC synthesis (${raceConfig.threads} threads × ${raceConfig.iters} iters)`);
  }

  const attempts: WitnessAttempt[] = [];
  let priorCSource: string | undefined;
  let priorFeedback: string | undefined;
  let lastCSource: string | undefined;

  for (let round = 1; round <= maxRounds; round++) {
    log(`[witness] ${candidate.assumptionId} ${candidate.entryA}⇄${candidate.entryB} on struct ${candidate.object} — round ${round}/${maxRounds}: synthesizing PoC`);
    let synth: PocSynthesisResult | null = null;
    try {
      synth = await synthesize({
        candidate,
        round,
        // Only the race path adds mode/race to the input — a single-resolved seam keeps
        // the original input shape (mode undefined), so its prompt is byte-for-byte unchanged.
        ...(resolvedMode === "race" ? { mode: "race" as const, race: raceConfig } : {}),
        ...(priorCSource ? { priorCSource } : {}),
        ...(priorFeedback ? { priorFeedback } : {}),
      });
    } catch (err) {
      log(`[witness]   synthesis error: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (!synth || !synth.cSource.trim()) {
      attempts.push({ round, synthesized: false, compiled: false, executed: false, timedOut: false, feedbackTail: "synthesizer produced no PoC" });
      priorFeedback = "the previous round produced no usable C — emit a complete compilable file in a ```c block";
      continue;
    }
    lastCSource = synth.cSource;

    log(`[witness]   booting PoC (${synth.cSource.length} bytes) in KASAN VM`);
    let result: ReproducerResult;
    try {
      result = await boot(synth.cSource, candidate);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      attempts.push({ round, synthesized: true, compiled: false, executed: false, timedOut: false, feedbackTail: `boot error: ${msg}`.slice(0, 4000) });
      priorCSource = synth.cSource;
      priorFeedback = `the KASAN boot errored: ${msg}`.slice(0, 4000);
      continue;
    }

    const check = checkWitness(candidate, synth.cSource, result);
    const feedbackTail = (result.compiled ? (result.dmesg || result.output) : result.output).slice(-4000);
    const attempt: WitnessAttempt = {
      round,
      synthesized: true,
      compiled: result.compiled,
      executed: result.executed,
      timedOut: result.timedOut,
      check,
      feedbackTail,
    };
    attempts.push(attempt);
    log(`[witness]   round ${round}: compiled=${result.compiled} executed=${result.executed} ⇒ ${check.witnessed ? "WITNESSED" : "no witness"} (${check.reason})`);

    if (check.witnessed) {
      return {
        candidate,
        verdict: "confirmed",
        attempts,
        witnessedAttempt: attempt,
        finalCSource: synth.cSource,
        ...(check.splat ? { splat: check.splat } : {}),
        summary: `CONFIRMED: object-bound ${check.signature} witnessed on struct ${candidate.object} at round ${round} — ${check.reason}`,
      };
    }
    priorCSource = synth.cSource;
    priorFeedback = `${check.reason}\n--- boot output tail ---\n${feedbackTail}`;
  }

  // No witness within budget. Distinguish refuted (we DID compile+run a PoC that
  // simply never faulted) from inconclusive (we never got a running PoC — an AEG /
  // synthesis limit, NOT evidence the assumption holds).
  const everRan = attempts.some((a) => a.executed);
  const verdict: WitnessVerdict = everRan ? "refuted" : "inconclusive";
  return {
    candidate,
    verdict,
    attempts,
    ...(lastCSource ? { finalCSource: lastCSource } : {}),
    summary:
      verdict === "refuted"
        ? `refuted: ${attempts.length} PoC round(s) compiled + ran but produced no object-bound KASAN splat on struct ${candidate.object} (assume-FP holds)`
        : `inconclusive: no PoC compiled+executed within ${maxRounds} round(s) (AEG/synthesis limit — NOT evidence the assumption holds)`,
  };
}

// ── CHEAP PRE-FILTER (drop the obviously-benign before the expensive witness) ─────
//
// The dual-view enumerator can surface 100+ candidates on a hot file; most are
// pervasive-but-benign cross-phase pairs. Booting each through the ~minutes-long KASAN
// oracle is the budget bottleneck, so a cheap DETERMINISTIC pre-filter removes the
// candidates the oracle STRUCTURALLY cannot promote or that are illusory skips, leaving
// the budget for a cleaner pool. CONSERVATIVE by design — every rule has a principled
// reason a genuine bug cannot match it, and drops are logged.

/**
 * The securityRelevance classes the KASAN oracle can WITNESS: a real dynamic verdict
 * requires a memory-safety splat (UAF / OOB / double-free). lifetime → UAF, type →
 * type-confusion UAF, bounds → OOB. An `authz` (skipped capability check) or `other`
 * assumption produces NO memory-safety splat, so the oracle can never confirm it —
 * witnessing it only burns budget. (Those still flow through the static caller-scan
 * path elsewhere; they are just not a fit for the dynamic dual-view oracle.)
 */
const WITNESSABLE_RELEVANCE = new Set<SecurityRelevance>(["lifetime", "type", "bounds"]);

export interface DualViewPreFilterResult {
  kept: ViolatingContext[];
  dropped: Array<{ ctx: ViolatingContext; reason: string }>;
}

/**
 * Drop obviously-benign dual-view contexts before the expensive oracle. Rules (each
 * conservative, each logged):
 *   1. securityRelevance not memory-safety → the KASAN oracle cannot witness it.
 *   2. entryB SELF-ENFORCES the establisher (the same tested {@link subjectSelfEnforces}
 *      1b uses) — the "skip" is really guarded, so it is not a latent bug.
 *   3. entryB directly CALLS the establisher token/alias — both phases take the guard,
 *      the dual-view "skip" is illusory (both-paths-clearly-same-lock).
 * A context whose assumption is not in `byId` is KEPT (cannot judge → do not drop).
 * Non-dual-view contexts are passed through untouched (not this oracle's class).
 */
export function preFilterDualViewContexts(
  contexts: ViolatingContext[],
  byId: Map<string, Assumption>,
  bodies: Map<string, string>,
): DualViewPreFilterResult {
  const kept: ViolatingContext[] = [];
  const dropped: Array<{ ctx: ViolatingContext; reason: string }> = [];
  for (const ctx of contexts) {
    if (!ctx.dualView) {
      kept.push(ctx);
      continue;
    }
    const a = byId.get(ctx.assumptionId);
    if (!a) {
      kept.push(ctx);
      continue;
    }
    // Rule 1: only a memory-safety relevance can produce a witnessable KASAN splat.
    if (!WITNESSABLE_RELEVANCE.has(a.securityRelevance)) {
      dropped.push({
        ctx,
        reason: `securityRelevance '${a.securityRelevance}' is not memory-safety — the KASAN oracle can only witness lifetime/type/bounds (UAF/OOB/double-free), so this can never be confirmed dynamically`,
      });
      continue;
    }
    const entryBBody = bodies.get(ctx.caller);
    if (entryBBody) {
      // Rule 2: entryB self-enforces the establisher (illusory skip) — reuse 1b's check.
      const selfReason = subjectSelfEnforces(entryBBody, a);
      if (selfReason) {
        dropped.push({ ctx, reason: `entryB ${ctx.caller}() ${selfReason}` });
        continue;
      }
      // Rule 3: entryB directly calls the establisher token/alias (both-paths-same-guard).
      const toks = [a.oracle.establisherToken, ...(a.oracle.establisherAliases ?? [])].filter(isMechanizableEstablisher);
      const present = toks.find((t) => new RegExp(`\\b${escapeRe(t)}\\s*\\(`).test(entryBBody));
      if (present) {
        dropped.push({
          ctx,
          reason: `entryB ${ctx.caller}() directly calls establisher '${present}' — both phases take the guard (illusory dual-view skip)`,
        });
        continue;
      }
    }
    kept.push(ctx);
  }
  return { kept, dropped };
}

// ── CROSS-RUN ROTATION (coverage accumulates instead of re-testing the same top-N) ─
//
// Without persistence, consecutive daily flywheel runs witness the SAME top-N
// candidates every day (whatever ranks highest), so a 100+ candidate backlog is never
// covered — the budget is spent re-confirming yesterday's refutations. A small durable
// state records which candidates were already witnessed (+ verdict + when); each run
// PREFERS un-witnessed candidates and skips ones witnessed within a TTL, re-including
// them after the TTL (the code may have changed). Bounded + self-pruning.

/** Rotation-state schema version — bump if the shape changes. */
export const ROTATION_STATE_VERSION = 1 as const;
/** Re-witness a candidate only after this long (the code may have changed since). */
export const ROTATION_TTL_MS = 14 * 24 * 60 * 60 * 1000; // 14 days
/** Drop rotation entries older than this on save (self-pruning window). */
const ROTATION_RETENTION_MS = 2 * ROTATION_TTL_MS; // 28 days
/** Hard cap on stored entries (drop oldest beyond this) so the file stays bounded. */
const ROTATION_MAX_ENTRIES = 5000;

export interface RotationEntry {
  verdict: WitnessVerdict;
  /** ISO timestamp of the run that witnessed this candidate. */
  witnessedAt: string;
  object: string;
  entryA: string;
  entryB: string;
}

export interface RotationState {
  version: number;
  /** Stable candidate id → its last witness record. */
  candidates: Record<string, RotationEntry>;
}

/** Stable candidate id = short sha256 of object + entryA + entryB + file + assumption(+predicate). */
export function candidateStableId(parts: {
  object: string;
  entryA: string;
  entryB: string;
  entryBFile?: string;
  assumptionId: string;
  predicate?: string;
}): string {
  const key = [parts.object, parts.entryA, parts.entryB, parts.entryBFile ?? "", parts.assumptionId, parts.predicate ?? ""].join(" ");
  return createHash("sha256").update(key).digest("hex").slice(0, 16);
}

/** Stable id for a dual-view {@link ViolatingContext} (+ the mined predicate for cross-remine stability). */
export function candidateStableIdFromContext(ctx: ViolatingContext, predicate: string): string {
  return candidateStableId({
    object: ctx.object ?? "",
    entryA: ctx.pairedEntry ?? "",
    entryB: ctx.caller,
    entryBFile: ctx.callerFile,
    assumptionId: ctx.assumptionId,
    predicate,
  });
}

/** Load rotation state (a fresh empty state on any read/parse/version error). */
export function loadRotationState(path: string): RotationState {
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as RotationState;
    if (raw && raw.version === ROTATION_STATE_VERSION && raw.candidates && typeof raw.candidates === "object") {
      return raw;
    }
  } catch {
    /* fresh */
  }
  return { version: ROTATION_STATE_VERSION, candidates: {} };
}

/** Prune expired entries + bound the entry count (keep the most recent). Pure. */
export function pruneRotationState(state: RotationState, now = Date.now()): RotationState {
  const entries = Object.entries(state.candidates)
    .filter(([, e]) => {
      const t = Date.parse(e.witnessedAt);
      return Number.isFinite(t) && now - t < ROTATION_RETENTION_MS;
    })
    .sort((a, b) => Date.parse(b[1].witnessedAt) - Date.parse(a[1].witnessedAt))
    .slice(0, ROTATION_MAX_ENTRIES);
  return { version: ROTATION_STATE_VERSION, candidates: Object.fromEntries(entries) };
}

/** Write the (pruned) rotation state, creating parent dirs. */
export function saveRotationState(path: string, state: RotationState, now = Date.now()): void {
  const pruned = pruneRotationState(state, now);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(pruned, null, 2) + "\n", "utf8");
}

/** True when `id` was witnessed within the TTL (so this run should SKIP it). */
export function isWitnessedWithinTtl(state: RotationState, id: string, now = Date.now(), ttlMs = ROTATION_TTL_MS): boolean {
  const e = state.candidates[id];
  if (!e) return false;
  const t = Date.parse(e.witnessedAt);
  return Number.isFinite(t) && now - t < ttlMs;
}

// ── Orchestration: run the oracle over the dual-view contexts of a hunt ──────────

export interface WitnessDualViewInput {
  /** Dual-view violating contexts (from {@link scanDualViewContexts}). */
  contexts: ViolatingContext[];
  /** The kept assumptions (to join predicate/kind by id). */
  kept: Assumption[];
  /** Subsystem body index (for the source excerpts). */
  bodies: Map<string, string>;
  subsystem: string;
  /** Cap the candidates run through the (expensive) dynamic oracle. Default 10. */
  maxCandidates?: number;
  /**
   * CROSS-RUN ROTATION state file (e.g. `<model-dir>/.witnessed-candidates.json`). When
   * set, candidates witnessed within {@link ROTATION_TTL_MS} are SKIPPED so consecutive
   * runs cover FRESH candidates; verdicts are recorded back after the run. Omit to
   * disable rotation (every run selects the ranked top-N with no memory).
   */
  rotationStatePath?: string;
  /** Clock injection for deterministic rotation tests (default Date.now()). */
  now?: number;
  deps?: DynamicWitnessDeps;
  log?: (msg: string) => void;
}

export interface WitnessDualViewResult {
  results: WitnessResult[];
  confirmed: WitnessResult[];
  refuted: WitnessResult[];
  inconclusive: WitnessResult[];
}

/**
 * Run the dynamic oracle over the DUAL-VIEW contexts of an assumption hunt —
 * BYPASSING the static skeptic (the whole point: static cannot judge this class).
 * Builds a {@link DualViewCandidate} per context and witnesses it. Non-dual-view
 * contexts are ignored here (they keep the static caller-scan path).
 */
export async function witnessDualViewContexts(input: WitnessDualViewInput): Promise<WitnessDualViewResult> {
  const log = input.log ?? input.deps?.log ?? (() => {});
  const byId = new Map(input.kept.map((a) => [a.id, a]));
  const cap = input.maxCandidates ?? 10;
  const now = input.now ?? Date.now();

  // The contexts arrive WEAPONIZABILITY-RANKED from scanDualViewContexts (highest-value
  // first). Keep only the dual-view class (the static caller-scan class is not this
  // oracle's job) and preserve that order through pre-filter + rotation + the cap.
  const dualCtxs = input.contexts.filter((c) => c.dualView);

  // CHANGE 3 — cheap pre-filter: drop the obviously-benign before the expensive oracle.
  const pf = preFilterDualViewContexts(dualCtxs, byId, input.bodies);
  for (const d of pf.dropped) {
    log(`[witness] pre-filter dropped ${d.ctx.caller}⇄${d.ctx.pairedEntry ?? "?"} on struct ${d.ctx.object ?? "?"}: ${d.reason}`);
  }
  if (pf.dropped.length) {
    log(`[witness] pre-filter kept ${pf.kept.length}/${dualCtxs.length} dual-view candidate(s) (${pf.dropped.length} benign dropped)`);
  }

  // CHANGE 2 — cross-run rotation: prefer un-witnessed candidates so coverage
  // accumulates across daily runs instead of re-testing the same ranked top-N.
  const rotationState = input.rotationStatePath ? loadRotationState(input.rotationStatePath) : null;
  const idOf = (ctx: ViolatingContext): string =>
    candidateStableIdFromContext(ctx, byId.get(ctx.assumptionId)?.predicate ?? "");

  const selected: ViolatingContext[] = [];
  let skippedByRotation = 0;
  for (const ctx of pf.kept) {
    if (rotationState && isWitnessedWithinTtl(rotationState, idOf(ctx), now)) {
      skippedByRotation++;
      continue;
    }
    selected.push(ctx);
    if (selected.length >= cap) break;
  }
  if (skippedByRotation) {
    log(`[witness] rotation skipped ${skippedByRotation} candidate(s) already witnessed within the ${ROTATION_TTL_MS / 86_400_000}d TTL — testing fresh ones`);
  }

  const candidates: DualViewCandidate[] = [];
  const idByCandidate = new Map<DualViewCandidate, string>();
  for (const ctx of selected) {
    const a = byId.get(ctx.assumptionId);
    if (!a) continue;
    const cand = dualViewCandidateFromContext(ctx, a, input.bodies, input.subsystem);
    if (cand) {
      candidates.push(cand);
      idByCandidate.set(cand, idOf(ctx));
    }
  }
  log(`[witness] running the dynamic oracle on ${candidates.length} dual-view candidate(s) (bypassing the static skeptic)`);

  const results: WitnessResult[] = [];
  for (const cand of candidates) {
    results.push(await witnessAssumptionViolation(cand, { ...input.deps, log }));
  }

  // CHANGE 2 — record verdicts so the NEXT run rotates to fresh candidates.
  if (rotationState && input.rotationStatePath) {
    const at = new Date(now).toISOString();
    for (const r of results) {
      const id = idByCandidate.get(r.candidate);
      if (!id) continue;
      rotationState.candidates[id] = {
        verdict: r.verdict,
        witnessedAt: at,
        object: r.candidate.object,
        entryA: r.candidate.entryA,
        entryB: r.candidate.entryB,
      };
    }
    saveRotationState(input.rotationStatePath, rotationState, now);
  }

  return {
    results,
    confirmed: results.filter((r) => r.verdict === "confirmed"),
    refuted: results.filter((r) => r.verdict === "refuted"),
    inconclusive: results.filter((r) => r.verdict === "inconclusive"),
  };
}
