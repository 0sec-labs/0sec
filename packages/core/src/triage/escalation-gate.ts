/**
 * SyzScope-style impact-escalation triage gate.
 *
 * Inspired by SyzScope (USENIX Security '22): a fuzzer-exposed bug that KASAN
 * labels as "low-risk" (e.g. a slab out-of-bounds READ, or a UAF read) often
 * sits adjacent to a *high-risk* primitive — an attacker who grooms the heap so
 * the over-/under-read lands on a different object can frequently turn the same
 * faulting site into a controllable write, a function-pointer leak, or a
 * UAF-control primitive. SyzScope proves this with S2E + symbolic execution.
 * We can't run S2E in the triage path, so this is the lighter weight version:
 * a heuristic pass over the KASAN signature shape plus an OPTIONAL single LLM
 * reasoning pass over the splat. The point is the same — DON'T discard an
 * exploitable bug just because the splat KASAN happened to catch was the benign
 * read instead of the write hiding one groom away.
 *
 * This module sits as a GATE between KASAN-confirm and weaponize:
 *
 *   verify (kernel-oracle / kernel-vm-runner: KASAN reproduced)
 *        │
 *        ▼
 *   assessEscalation(report)  ← THIS GATE: what is the impact CEILING?
 *        │
 *        ▼
 *   shouldWeaponize(verdict)  ← opt-in: is it worth the weaponize budget?
 *        │
 *        ▼
 *   weaponize (kernel/exploit/*)
 *
 * It is deliberately decoupled from the pipeline: it is a pure function plus a
 * thin gate predicate. The consumer (the verify→weaponize handoff) opts in by
 * calling {@link assessEscalation} on a confirmed crash and gating on
 * {@link shouldWeaponize}; nothing here rewires the existing flow.
 *
 * Relationship to {@link classifyKernelPrimitive} (kernel-primitive.ts): that
 * module answers "what primitive did *this splat* prove?" — a faithful label of
 * the observed crash. This module answers the SyzScope question on top of it:
 * "what is the highest-risk primitive this bug could *escalate* to?" It REUSES
 * `classifyKernelPrimitive` for the base label and only ever raises the ceiling
 * above it; it never lowers a primitive the splat already proved.
 */

import type { CrashReport } from "@0sec/shared";
import type {
  NativeRuntime,
  NativeMessage,
  NativeContentBlock,
} from "../runtime/types.js";
import {
  classifyKernelPrimitive,
  type KernelPrimitive,
  type KernelPrimitiveKind,
} from "./kernel-primitive.js";

// ── Public types ──────────────────────────────────────────────────────────

/**
 * The impact ceiling — the highest-risk primitive class this bug is assessed to
 * reach, ordered weakest → strongest. This is an UPPER bound on impact, not a
 * proof: it is what the bug could escalate to, which the weaponize stage then
 * tries to actually demonstrate.
 *
 *   `dos-only`     — denial-of-service only (null-deref, pure panic). No memory
 *                    primitive an attacker can steer.
 *   `info-leak`    — controllable read of adjacent / freed memory (KASLR / heap
 *                    pointer disclosure). OOB-read, UAF-read.
 *   `oob-write`    — controllable corruption of an adjacent allocation (a
 *                    write-what-where candidate). The classic escalation target
 *                    for an OOB-read sitting next to a write path.
 *   `uaf-control`  — a dangling reference that, once reclaimed, hands the
 *                    attacker control over an object's contents — the strongest
 *                    fuzzer-crash primitive (function-pointer / cred hijack).
 */
export type ImpactCeiling = "dos-only" | "info-leak" | "oob-write" | "uaf-control";

/** Ascending impact rank — higher means a more dangerous ceiling. */
const CEILING_RANK: Record<ImpactCeiling, number> = {
  "dos-only": 0,
  "info-leak": 1,
  "oob-write": 2,
  "uaf-control": 3,
};

/** Return the higher (more dangerous) of two ceilings. */
export function maxCeiling(a: ImpactCeiling, b: ImpactCeiling): ImpactCeiling {
  return CEILING_RANK[a] >= CEILING_RANK[b] ? a : b;
}

/**
 * Whether the escalation raised the ceiling ABOVE what the raw KASAN splat
 * directly proved (the SyzScope payoff), and on what basis.
 */
export type EscalationBasis =
  | "splat-only" // ceiling == what the splat proved; no escalation
  | "heuristic" // heuristic adjacency cues raised the ceiling
  | "llm"; // the optional LLM pass raised (or confirmed-higher) the ceiling

export interface EscalationVerdict {
  /** Assessed impact ceiling for this bug. */
  ceiling: ImpactCeiling;
  /** Confidence in the ceiling assessment, [0,1]. */
  confidence: number;
  /**
   * The primitive the raw splat directly proved (from
   * {@link classifyKernelPrimitive}) — the floor we escalate above.
   */
  splatCeiling: ImpactCeiling;
  /** True when `ceiling` is strictly above `splatCeiling`. */
  escalated: boolean;
  /** What raised the ceiling (or `splat-only` when nothing did). */
  basis: EscalationBasis;
  /** Whether the optional LLM reasoning pass actually ran. */
  llmUsed: boolean;
  /** Short, human-readable reasoning lines for the audit trail. */
  rationale: string[];
}

export interface AssessEscalationOptions {
  /**
   * Optional LLM runtime. When provided, a single reasoning pass over the splat
   * is run to flag escalation an attacker could reach that the heuristics miss
   * (e.g. "this OOB-read victim object embeds a function pointer that a
   * neighbouring write path can clobber"). Omit it for a cheap heuristic-only
   * assessment — the gate works without an LLM.
   */
  runtime?: NativeRuntime;
  /** Override the system prompt for the LLM pass (tests / tuning). */
  llmSystemPrompt?: string;
}

// ── Heuristic layer ─────────────────────────────────────────────────────────

/**
 * Map a proven primitive to the impact ceiling it directly establishes. This is
 * the FLOOR — escalation only ever raises above it.
 */
function ceilingForPrimitive(kind: KernelPrimitiveKind): ImpactCeiling {
  switch (kind) {
    case "use-after-free":
      // A UAF is a dangling ref; even a read-UAF is a reclaim away from control.
      return "uaf-control";
    case "out-of-bounds-write":
      return "oob-write";
    case "double-free":
    case "invalid-free":
      // Freelist confusion → overlapping allocations → attacker-controlled
      // object contents. Treated as a UAF-class control primitive.
      return "uaf-control";
    case "out-of-bounds-read":
      return "info-leak";
    case "null-deref":
    case "uninitialized-access":
    case "unknown":
      return "dos-only";
  }
}

/**
 * Adjacency cues in the raw splat that suggest a low-risk read is one heap-groom
 * away from a high-risk write / control primitive — the core SyzScope intuition,
 * grounded in the shapes a real KASAN splat actually prints.
 */
interface AdjacencyCues {
  /** A write path appears in the call stack alongside the faulting read. */
  writePathNearby: boolean;
  /** The victim object/cache plausibly holds a function pointer or list head. */
  controlObjectNearby: boolean;
  /** Both KASAN alloc and free sites are known (object lifecycle pinned). */
  lifecyclePinned: boolean;
}

/**
 * Frame / cache name fragments that indicate the faulting region is shared with
 * a write path or holds steerable control data. These are conservative,
 * real-kernel substrings — function-pointer-bearing structs (ops tables, timers,
 * work items) and the write-side mirrors of common read paths.
 */
const WRITE_PATH_FRAMES =
  /(_write|_store|_send|_xmit|memcpy|copy_from_user|_set|_put|_enqueue|_insert)/i;

const CONTROL_OBJECT_HINTS =
  /(_ops\b|->ops|file_operations|timer_list|work_struct|callback|->func|fn\)|kfunc|cred\b|->next\b|list_head)/i;

function detectAdjacencyCues(report: CrashReport): AdjacencyCues {
  const haystack = [
    report.rawText ?? "",
    report.faultingFunction ?? "",
    ...(report.callStack ?? []),
  ].join("\n");

  return {
    writePathNearby: WRITE_PATH_FRAMES.test(haystack),
    controlObjectNearby: CONTROL_OBJECT_HINTS.test(haystack),
    lifecyclePinned: Boolean(report.allocSite && report.freeSite),
  };
}

/**
 * Heuristic escalation: given the base primitive and adjacency cues, decide
 * whether a low-risk read ceiling can be raised. Mirrors SyzScope's finding
 * that OOB/UAF *reads* are the bugs most often hiding a write/control impact.
 */
function heuristicEscalate(
  base: ImpactCeiling,
  cues: AdjacencyCues,
  rationale: string[],
): ImpactCeiling {
  let ceiling = base;

  // An info-leak (OOB-read / UAF-read) sitting next to a write path is the
  // canonical escalation: groom a writeable / controllable object into the
  // faulting slot and the same site becomes a corruption primitive.
  if (base === "info-leak") {
    if (cues.controlObjectNearby) {
      ceiling = maxCeiling(ceiling, "uaf-control");
      rationale.push(
        "OOB/UAF read victim region plausibly holds a function pointer or list" +
          " head (control-object cue) — a reclaim/groom could turn the leak into" +
          " a control-flow primitive.",
      );
    } else if (cues.writePathNearby) {
      ceiling = maxCeiling(ceiling, "oob-write");
      rationale.push(
        "OOB/UAF read sits adjacent to a write path in the same flow — heap" +
          " grooming could place a corruptible object at the faulting offset," +
          " escalating the read to an out-of-bounds write candidate.",
      );
    }
  }

  // An OOB-write next to control objects rises to UAF-class control.
  if (base === "oob-write" && cues.controlObjectNearby) {
    ceiling = maxCeiling(ceiling, "uaf-control");
    rationale.push(
      "OOB write neighbours a control-bearing object — corrupting a function" +
        " pointer / list head is a control-flow hijack candidate, not just" +
        " adjacent-data corruption.",
    );
  }

  // A pinned lifecycle (alloc+free known) makes reclaim-based escalation far
  // more credible — it is the precondition for landing a controlled object.
  if (ceiling !== base && cues.lifecyclePinned) {
    rationale.push(
      "Object lifecycle is pinned (both KASAN alloc and free sites known), so a" +
        " reclaim window can be targeted deterministically — escalation is" +
        " concretely groomable, not merely theoretical.",
    );
  }

  return ceiling;
}

/** Confidence for the heuristic verdict, before any LLM adjustment. */
function heuristicConfidence(
  base: ImpactCeiling,
  ceiling: ImpactCeiling,
  primitive: KernelPrimitive,
  cues: AdjacencyCues,
): number {
  // Start from the classifier's confidence in the base primitive.
  let conf = primitive.confidence;
  if (ceiling === base) {
    // No escalation: confidence in "the splat ceiling is the ceiling".
    return Number(Math.min(1, conf).toFixed(2));
  }
  // Escalation is inherently a hypothesis — discount, then add back for each
  // corroborating cue so a well-grounded escalation isn't over-penalised.
  conf *= 0.6;
  if (cues.lifecyclePinned) conf += 0.12;
  if (cues.controlObjectNearby) conf += 0.1;
  if (cues.writePathNearby) conf += 0.08;
  return Number(Math.max(0.2, Math.min(0.9, conf)).toFixed(2));
}

// ── LLM layer (optional) ─────────────────────────────────────────────────────

const DEFAULT_LLM_SYSTEM_PROMPT = `You are a Linux kernel exploitation analyst doing SyzScope-style impact triage.

You are given a KASAN crash report that a fuzzer found and that has ALREADY been confirmed to reproduce. KASAN reports the FIRST illegal access it sees, which is frequently the benign one (an out-of-bounds READ or a use-after-free READ). Your job is to assess the IMPACT CEILING: the highest-risk primitive a competent attacker could escalate this same bug to via heap grooming / reclaim, NOT just what the splat literally shows.

Reason specifically about:
- Whether the over-/under-read could be turned into an out-of-bounds WRITE by grooming a different, writeable object into the faulting offset.
- Whether the victim/freed object plausibly holds a function pointer, ops table, list head, or credentials that a neighbouring write path could clobber (control primitive).
- Whether the faulting flow has a nearby write/copy/store path.

Be skeptical and concrete; do not invent escalation that the report gives no basis for. A pure NULL dereference with no attacker-controlled allocation is dos-only.

Reply with ONLY a JSON object:
{"ceiling": "dos-only" | "info-leak" | "oob-write" | "uaf-control", "confidence": <0..1>, "reason": "<one or two sentences>"}`;

interface ParsedLlmEscalation {
  ceiling: ImpactCeiling | null;
  confidence: number;
  reason: string;
}

const VALID_CEILINGS: ImpactCeiling[] = [
  "dos-only",
  "info-leak",
  "oob-write",
  "uaf-control",
];

function extractText(blocks: NativeContentBlock[]): string {
  for (const b of blocks) {
    if (b.type === "text") return b.text;
  }
  return "";
}

/** Parse the LLM JSON reply; tolerant of markdown fences and prose. */
export function parseLlmEscalation(raw: string): ParsedLlmEscalation {
  const match = raw.match(/\{[\s\S]*?"ceiling"[\s\S]*?\}/);
  if (match) {
    try {
      const parsed = JSON.parse(match[0]) as Record<string, unknown>;
      const ceiling = String(parsed.ceiling ?? "");
      return {
        ceiling: VALID_CEILINGS.includes(ceiling as ImpactCeiling)
          ? (ceiling as ImpactCeiling)
          : null,
        confidence:
          typeof parsed.confidence === "number"
            ? Math.max(0, Math.min(1, parsed.confidence))
            : 0.5,
        reason:
          typeof parsed.reason === "string" ? parsed.reason : "no reason provided",
      };
    } catch {
      // fall through to null
    }
  }
  return { ceiling: null, confidence: 0, reason: "could not parse LLM response" };
}

function buildLlmUserMessage(report: CrashReport): string {
  const parts: string[] = [];
  parts.push(`Crash type: ${report.crashType}`);
  if (report.accessType) parts.push(`Access: ${report.accessType}`);
  if (report.accessSize) parts.push(`Access size: ${report.accessSize} bytes`);
  if (report.faultingFunction) parts.push(`Faulting function: ${report.faultingFunction}`);
  if (report.allocSite) parts.push(`Alloc site: ${report.allocSite}`);
  if (report.freeSite) parts.push(`Free site: ${report.freeSite}`);
  if (report.slabCache) parts.push(`Slab cache: ${report.slabCache}`);
  if (report.callStack?.length) {
    parts.push(`Call stack:\n${report.callStack.slice(0, 20).join("\n")}`);
  }
  // The raw splat is the richest signal; cap it so a giant log doesn't blow the
  // context window.
  if (report.rawText) {
    parts.push(`KASAN report:\n${report.rawText.slice(0, 4000)}`);
  }
  return parts.join("\n");
}

// ── Public entry point ──────────────────────────────────────────────────────

/**
 * Assess the impact ceiling of a CONFIRMED KASAN finding — the SyzScope-style
 * gate that turns a "low-risk" splat into evidence of a high-risk primitive so
 * the bug is not discarded before weaponize.
 *
 * Heuristic-only when `opts.runtime` is omitted; with a runtime, a single LLM
 * reasoning pass can raise the ceiling further. The LLM can only ever RAISE the
 * ceiling (never lower it below the splat-proven floor) — assume-false
 * discipline: we never let an LLM talk us out of a primitive the splat proved.
 */
export async function assessEscalation(
  report: CrashReport,
  opts: AssessEscalationOptions = {},
): Promise<EscalationVerdict> {
  const rationale: string[] = [];

  const primitive = classifyKernelPrimitive(report);
  const splatCeiling = ceilingForPrimitive(primitive.kind);
  rationale.push(
    `Splat proves a ${primitive.kind} primitive (control=${primitive.control})` +
      ` → base ceiling ${splatCeiling}.`,
  );

  const cues = detectAdjacencyCues(report);
  let ceiling = heuristicEscalate(splatCeiling, cues, rationale);
  let basis: EscalationBasis = ceiling === splatCeiling ? "splat-only" : "heuristic";
  let confidence = heuristicConfidence(splatCeiling, ceiling, primitive, cues);

  // Optional LLM pass — only consulted to RAISE the ceiling.
  let llmUsed = false;
  if (opts.runtime) {
    try {
      const system = opts.llmSystemPrompt ?? DEFAULT_LLM_SYSTEM_PROMPT;
      const messages: NativeMessage[] = [
        { role: "user", content: [{ type: "text", text: buildLlmUserMessage(report) }] },
      ];
      const result = await opts.runtime.executeNative(system, messages, []);
      if (!result.error) {
        llmUsed = true;
        const parsed = parseLlmEscalation(extractText(result.content));
        if (parsed.ceiling && CEILING_RANK[parsed.ceiling] > CEILING_RANK[ceiling]) {
          ceiling = parsed.ceiling;
          basis = "llm";
          // Blend: the LLM raised it, so its confidence drives, lightly damped.
          confidence = Number(Math.min(0.95, parsed.confidence * 0.9).toFixed(2));
          rationale.push(`LLM escalation: ${parsed.reason}`);
        } else if (parsed.ceiling) {
          rationale.push(
            `LLM concurred at or below the current ceiling (${parsed.ceiling}); no raise.`,
          );
        }
      } else {
        rationale.push(`LLM pass errored (${result.error}); heuristic verdict stands.`);
      }
    } catch (err) {
      // Never let an LLM failure sink the gate — heuristics already decided.
      rationale.push(
        `LLM pass threw (${err instanceof Error ? err.message : String(err)}); heuristic verdict stands.`,
      );
    }
  }

  return {
    ceiling,
    confidence,
    splatCeiling,
    escalated: CEILING_RANK[ceiling] > CEILING_RANK[splatCeiling],
    basis,
    llmUsed,
    rationale,
  };
}

// ── Gate predicate (verify → weaponize seam) ─────────────────────────────────

/**
 * Whether the assessed ceiling clears the bar to spend weaponize budget.
 *
 * This is the gate the verify→weaponize handoff calls AFTER KASAN-confirm. The
 * default bar is `info-leak` — a `dos-only` bug is not worth a weaponize run,
 * but anything that could leak or corrupt memory is. The bar is configurable so
 * a budget-constrained caller can require `oob-write` (skip pure leaks).
 *
 * Returns `false` for `dos-only` by default — the one thing the gate is meant to
 * filter out — and `true` for every escalatable ceiling.
 */
export function shouldWeaponize(
  verdict: EscalationVerdict,
  minCeiling: ImpactCeiling = "info-leak",
): boolean {
  return CEILING_RANK[verdict.ceiling] >= CEILING_RANK[minCeiling];
}

/** Render an escalation verdict into compact lines for `evidence.analysis`. */
export function describeEscalation(verdict: EscalationVerdict): string[] {
  const lines = [
    `Impact ceiling: ${verdict.ceiling} (confidence ${verdict.confidence.toFixed(2)}, basis=${verdict.basis})`,
    `Splat-proven floor: ${verdict.splatCeiling}${verdict.escalated ? " — ESCALATED above floor" : ""}`,
  ];
  for (const r of verdict.rationale) lines.push(`- ${r}`);
  return lines;
}
