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

import type { ReproducerResult, CrashReport } from "../triage/kernel-oracle.js";
import { runReproducerInKernelVm } from "../triage/kernel-vm-runner.js";
import { LlmApiRuntime } from "../runtime/index.js";
import type { RuntimeMode } from "@pwnkit/shared";
import type {
  Assumption,
  AssumptionKind,
  SecurityRelevance,
  ViolatingContext,
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

// ── PoC synthesis (LLM boundary — injectable for tests) ──────────────────────────

export interface PocSynthesisInput {
  candidate: DualViewCandidate;
  /** 1-based synthesis round. */
  round: number;
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

/** Compose the per-round synthesis prompt (the candidate + excerpts + prior feedback). */
export function buildSynthesisPrompt(input: PocSynthesisInput): string {
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
    const res = await rt.executeNative(
      SYNTH_SYSTEM,
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

  const attempts: WitnessAttempt[] = [];
  let priorCSource: string | undefined;
  let priorFeedback: string | undefined;
  let lastCSource: string | undefined;

  for (let round = 1; round <= maxRounds; round++) {
    log(`[witness] ${candidate.assumptionId} ${candidate.entryA}⇄${candidate.entryB} on struct ${candidate.object} — round ${round}/${maxRounds}: synthesizing PoC`);
    let synth: PocSynthesisResult | null = null;
    try {
      synth = await synthesize({ candidate, round, ...(priorCSource ? { priorCSource } : {}), ...(priorFeedback ? { priorFeedback } : {}) });
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

// ── Orchestration: run the oracle over the dual-view contexts of a hunt ──────────

export interface WitnessDualViewInput {
  /** Dual-view violating contexts (from {@link scanDualViewContexts}). */
  contexts: ViolatingContext[];
  /** The kept assumptions (to join predicate/kind by id). */
  kept: Assumption[];
  /** Subsystem body index (for the source excerpts). */
  bodies: Map<string, string>;
  subsystem: string;
  /** Cap the candidates run through the (expensive) dynamic oracle. Default 8. */
  maxCandidates?: number;
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
  const cap = input.maxCandidates ?? 8;
  const candidates: DualViewCandidate[] = [];
  for (const ctx of input.contexts) {
    if (!ctx.dualView) continue;
    const a = byId.get(ctx.assumptionId);
    if (!a) continue;
    const cand = dualViewCandidateFromContext(ctx, a, input.bodies, input.subsystem);
    if (cand) candidates.push(cand);
    if (candidates.length >= cap) break;
  }
  log(`[witness] running the dynamic oracle on ${candidates.length} dual-view candidate(s) (bypassing the static skeptic)`);

  const results: WitnessResult[] = [];
  for (const cand of candidates) {
    results.push(await witnessAssumptionViolation(cand, { ...input.deps, log }));
  }
  return {
    results,
    confirmed: results.filter((r) => r.verdict === "confirmed"),
    refuted: results.filter((r) => r.verdict === "refuted"),
    inconclusive: results.filter((r) => r.verdict === "inconclusive"),
  };
}
