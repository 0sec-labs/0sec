/**
 * Race-widening smell-hunter candidate generation — 0sec's kernelCTF Pipeline #3.
 *
 * A sibling of `generateVariantCandidates` (variant-candidates.ts) and
 * `generateInvariantCandidates` (invariant-candidates.ts). This hunts the ONE
 * static smell behind the LPE-grade races that are currently winning real
 * kernelCTF money (ExpRace, Calif's "race within a race", CVE-2025-38617 which
 * beat SLAB_VIRTUAL + RANDOM_KMALLOC_CACHES): a "nanosecond" window that a
 * winner WIDENS into controllable seconds.
 *
 * The smell, stated as code shape:
 *
 *     unlock(A) ─▶ [ sleep / mutex_lock / GFP_KERNEL alloc / copy_from_user ] ─▶ lock(B)
 *                                    ▲
 *                     attacker-influenced state read/written across the gap
 *
 * The key insight the winners exploit: between dropping lock A and taking the
 * next (SLEEPABLE) lock B — or doing any sleeping op (a mutex, a GFP_KERNEL
 * allocation that can block on reclaim, a copy_from_user that can fault) — the
 * scheduler can preempt, so the window is not really "nanoseconds". If attacker
 * state is consulted across that gap, the attacker races a second thread in and
 * WIDENS the window (mdelay/kprobe on the sleep point, userfaultfd/FUSE stalls
 * on the copy) from ns to 10-118s of controllable time (ExpRace made 10/10
 * races reliable). "Conditional logic near locks is a smell."
 *
 *   subsystem source ──LLM──▶ RaceSmellCandidate[] {lock_a, sleep_point, lock_b,
 *                                   │                 attacker_state, widen_hint,
 *                                   │                 hypothesized_primitive}
 *                                   ▼ map to sites + prover knobs
 *                       runHuntScan(brief, candidates)   ── and ──▶ kernel-vm-runner
 *                                                             race-widening kprobe
 *
 * Same shape/interface as its siblings (returns a `brief` + `HuntCandidate[]`)
 * so it drops straight into `runHuntScan`; it additionally returns the rich
 * smell candidates, and — the new part — a `widenEnv` per candidate that maps
 * the `widen_hint` onto the existing `0SEC_KERNEL_QEMU_WIDEN_*` prover knobs
 * (kernel-vm-runner.ts), i.e. WHERE to inject the `mdelay()` kprobe to widen
 * THIS specific window.
 *
 * The LLM does the one thing a grep can't: read a lock/sleep/lock sequence and
 * reason about whether attacker state is consulted across the sleeping gap. It
 * is a HYPOTHESIS generator — every candidate still goes through the
 * skeptic+prover gate in `runHuntScan` (and a real widened race repro) before it
 * is believed. No self-grading here.
 */

import { readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import type { RuntimeMode } from "@0sec/shared";
import { LlmApiRuntime } from "../runtime/llm-api.js";
import type { HuntBrief, HuntCandidate } from "./hunt-scan.js";

/**
 * The kernelCTF Tier-1 subsystem grid — the surfaces where sleepable-lock races
 * have repeatedly paid out. Callers with no list of their own can seed the hunt
 * from this (each entry is a repo-relative dir/file under the source tree).
 */
export const KERNELCTF_TIER1_RACE_GRID: readonly string[] = [
  "net/unix/af_unix.c",
  "net/unix/garbage.c",
  "ipc/msg.c",
  "ipc/sem.c",
  "ipc/shm.c",
  "fs/pipe.c",
  "fs/splice.c",
  "security/keys/keyring.c",
  "security/keys/process_keys.c",
  "crypto/af_alg.c",
  "crypto/algif_hash.c",
  "net/core/sock.c",
  "net/core/scm.c",
];

export interface RaceSmellHuntInput {
  /** Local source tree the subsystem files live under. */
  sourceRoot: string;
  /**
   * The subsystem source files to smell-hunt (repo-relative or absolute), e.g.
   * `["net/unix/af_unix.c", "ipc/msg.c"]`. Defaults to
   * {@link KERNELCTF_TIER1_RACE_GRID} when omitted/empty.
   */
  subsystemFiles?: string[];
  runtime: RuntimeMode;
  model?: string;
  /** Cap the emitted candidate sites (default 20). */
  maxCandidates?: number;
  /** Chars of source sent to the model per file (default 24000; clipped with a marker). */
  maxCharsPerFile?: number;
  /**
   * Default `mdelay()` widen delay (ms) written into a candidate's `widenEnv`
   * when the model does not suggest one. 500ms turns a ns window into a wide,
   * schedulable one without hanging the guest. Default 500.
   */
  defaultWidenDelayMs?: number;
  log?: (msg: string) => void;
}

/**
 * A hint for WHERE to widen this specific window. `injectSymbol` is the kernel
 * symbol (function) the race-widening kprobe should probe; `suggestedDelayMs`
 * is how long to stall there; `rationale` says why that point widens the gap.
 * Mapped onto the `0SEC_KERNEL_QEMU_WIDEN_*` runner knobs by {@link widenEnvFor}.
 */
export interface RaceWidenHint {
  /** Kernel function to probe with the mdelay() kprobe (usually the enclosing fn of `sleep_point`). */
  injectSymbol: string;
  /** Suggested stall in ms to widen the window (default filled from input.defaultWidenDelayMs). */
  suggestedDelayMs?: number;
  /** Why probing there widens THIS window (e.g. "stall inside the mutex_lock so B wins the reordered state"). */
  rationale: string;
}

/** One hypothesized widenable race: a sleepable gap with attacker state across it. */
export interface RaceSmellCandidate {
  /** The lock dropped before the sleeping gap (e.g. "u->lock", "spin_unlock(&pipe->rd_wait.lock)"). */
  lockA: string;
  /** The sleeping op across the gap: a mutex_lock, sleep, GFP_KERNEL alloc, or copy_from_user/to_user. */
  sleepPoint: string;
  /** The lock/mechanism (re)acquired after the gap — the SECOND lock (e.g. a mutex, or re-taking A). */
  lockB: string;
  /** The attacker-influenced state read or written ACROSS the gap (the thing a 2nd thread can tear). */
  attackerState: string;
  /** WHERE to inject the widening delay to make this ns-window controllable. */
  widenHint: RaceWidenHint;
  /** The primitive the torn state yields (e.g. "UAF on the re-fetched object", "double-free", "OOB"). */
  hypothesizedPrimitive: string;
  /** Where the smell lives — repo-relative `file` or `file:line` (used as the hunt site). */
  site?: string;
}

/**
 * The concrete `0SEC_KERNEL_QEMU_WIDEN_*` env the kernel-vm-runner reads to
 * insmod the race-widening kprobe for this candidate. `OFFSET` is intentionally
 * absent — the exact `symbol+offset` is resolved at repro time against the
 * booted vmlinux; the symbol + delay is what the static smell can pin.
 */
export interface RaceWidenEnv {
  "0SEC_KERNEL_QEMU_WIDEN_SYMBOL": string;
  "0SEC_KERNEL_QEMU_WIDEN_DELAY_MS": string;
}

export interface RaceSmellHuntPlan {
  /** Plugs straight into `runHuntScan` — the bug-class/pattern brief. */
  brief: HuntBrief;
  /** The `runHuntScan` candidate sites (file + per-site hint) — deduped onto files. */
  candidates: HuntCandidate[];
  /** The rich structured smell candidates (what the race repro / widening consumes). */
  smellCandidates: RaceSmellCandidate[];
  /** Per-candidate prover-knob env, index-aligned with `smellCandidates`. */
  widenEnvs: RaceWidenEnv[];
  warnings: string[];
}

interface AnalysisFromModel {
  candidates: RaceSmellCandidate[];
}

const clip = (s: string, n: number) =>
  s.length > n ? s.slice(0, n) + `\n...[truncated ${s.length - n} chars]` : s;

/** Read a subsystem file (repo-relative under sourceRoot, or absolute). Returns null on failure. */
function readSource(sourceRoot: string, file: string): string | null {
  const path = isAbsolute(file) ? file : join(sourceRoot, file);
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

/** Normalize `file:line` / `file` to the repo-relative file part for site matching. */
function siteFile(site: string | undefined): string | undefined {
  if (!site) return undefined;
  const trimmed = site.trim().replace(/^\.\//, "");
  const noLine = trimmed.replace(/:\d+(?::\d+)?$/, "");
  return noLine || undefined;
}

/**
 * Map a candidate's `widenHint` onto the runner's `0SEC_KERNEL_QEMU_WIDEN_*`
 * knobs (kernel-vm-runner.ts). This is the bridge that tells the prover WHERE to
 * inject the mdelay() kprobe to widen THIS window from ns to seconds.
 */
export function widenEnvFor(candidate: RaceSmellCandidate, defaultDelayMs: number): RaceWidenEnv {
  const delay =
    typeof candidate.widenHint?.suggestedDelayMs === "number" && candidate.widenHint.suggestedDelayMs > 0
      ? Math.floor(candidate.widenHint.suggestedDelayMs)
      : defaultDelayMs;
  return {
    "0SEC_KERNEL_QEMU_WIDEN_SYMBOL": candidate.widenHint.injectSymbol,
    "0SEC_KERNEL_QEMU_WIDEN_DELAY_MS": String(delay),
  };
}

const ANALYSIS_TOOL = {
  name: "emit_race_smell_analysis",
  description:
    "Emit the race-widening smell candidates: sleepable-lock gaps with attacker state read/written across them.",
  input_schema: {
    type: "object",
    properties: {
      candidates: {
        type: "array",
        description:
          "Race-widening smells: unlock(A) -> [sleep/mutex/GFP_KERNEL alloc/copy_from_user] -> lock(B) sequences where attacker-influenced state is used across the sleeping gap.",
        items: {
          type: "object",
          properties: {
            lockA: { type: "string", description: "The lock dropped BEFORE the sleeping gap (name the exact lock)." },
            sleepPoint: {
              type: "string",
              description:
                "The sleeping op across the gap: a mutex_lock (NOT a spinlock), an explicit sleep/schedule, a GFP_KERNEL/GFP_NOFS allocation that can block on reclaim, or a copy_from_user/copy_to_user that can fault.",
            },
            lockB: { type: "string", description: "The SECOND lock/mechanism acquired AFTER the gap (or A re-taken)." },
            attackerState: {
              type: "string",
              description:
                "The attacker-influenced state (field/object/index/length/pointer) READ or WRITTEN across the gap that a concurrent thread can tear.",
            },
            widenHint: {
              type: "object",
              description: "Where to inject a widening delay to make this ns-window controllable.",
              properties: {
                injectSymbol: {
                  type: "string",
                  description: "Kernel function symbol to probe with an mdelay() kprobe (usually the fn enclosing sleepPoint).",
                },
                suggestedDelayMs: { type: "number", description: "Suggested stall in ms (optional; omit to use the default)." },
                rationale: { type: "string", description: "Why stalling there widens THIS window." },
              },
              required: ["injectSymbol", "rationale"],
            },
            hypothesizedPrimitive: {
              type: "string",
              description: "The primitive the torn state yields (UAF / double-free / OOB / type confusion / refcount underflow).",
            },
            site: { type: "string", description: "Where the smell lives: repo-relative file or file:line." },
          },
          required: ["lockA", "sleepPoint", "lockB", "attackerState", "widenHint", "hypothesizedPrimitive"],
        },
      },
    },
    required: ["candidates"],
  },
};

const SYSTEM =
  "You are a kernel RACE-CONDITION analyst hunting the ONE static smell behind LPE-grade races that win kernelCTF: a " +
  "lock/sleep/lock sequence with attacker state across the gap. The winning technique (ExpRace, Calif's 'race within a " +
  "race') takes a window that LOOKS like unexploitable nanoseconds and WIDENS it to controllable seconds by stalling on " +
  "the sleeping op — so the exploitable smell is precisely a SLEEPABLE gap between two lock operations.\n\n" +
  "Hunt this shape in the provided source:\n" +
  "  1. a lock A is RELEASED (spin_unlock / mutex_unlock / rcu_read_unlock / read_unlock), then\n" +
  "  2. a SLEEPING operation runs before the next acquire: a mutex_lock (sleepable, NOT a spinlock), an explicit " +
  "sleep/schedule/wait, a GFP_KERNEL or GFP_NOFS allocation (can block on reclaim), or a copy_from_user/copy_to_user " +
  "(can fault and sleep — attacker-stallable via userfaultfd/FUSE), then\n" +
  "  3. a second lock B is acquired (or A re-taken), and\n" +
  "  4. attacker-influenced state (a field, object, index, length, or pointer the attacker set via a syscall) is READ " +
  "or WRITTEN across that gap — often re-fetched/re-validated AFTER the sleep, so a concurrent thread that mutates it " +
  "during the widened window tears the invariant.\n\n" +
  "'Conditional logic near a dropped lock is a smell' — flag TOCTOU where state is checked before the gap and used after. " +
  "For each smell name: the released lock A, the exact sleepPoint, the re-acquired lock B, the attacker state torn across " +
  "the gap, the PRIMITIVE it yields (UAF/double-free/OOB/type-confusion/underflow), and a widenHint — the kernel function " +
  "to probe with an mdelay() kprobe to stretch THIS window and why. Give the SITE (file or file:line).\n\n" +
  "Be concrete and grounded — every candidate must point at real code in the provided source. A pure spinlock-to-spinlock " +
  "sequence with NO sleeping op in between is NOT a candidate (no schedulable window to widen). Rank the clearest sleepable " +
  "gap with the most attacker-controlled state first. Emit 3-8 candidates via emit_race_smell_analysis.";

export async function generateRaceSmellCandidates(input: RaceSmellHuntInput): Promise<RaceSmellHuntPlan> {
  const log = input.log ?? (() => {});
  const warnings: string[] = [];
  const maxCandidates = input.maxCandidates ?? 20;
  const maxCharsPerFile = input.maxCharsPerFile ?? 24_000;
  const defaultWidenDelayMs = input.defaultWidenDelayMs ?? 500;

  const files = input.subsystemFiles && input.subsystemFiles.length > 0 ? input.subsystemFiles : [...KERNELCTF_TIER1_RACE_GRID];

  // 1. Read the subsystem source.
  const sources: Array<{ file: string; text: string }> = [];
  for (const file of files) {
    const text = readSource(input.sourceRoot, file);
    if (text == null) {
      warnings.push(`could not read subsystem file: ${file}`);
      continue;
    }
    sources.push({ file, text });
  }
  if (sources.length === 0) {
    throw new Error("race-smell hunt could not read any subsystem file under sourceRoot");
  }

  // 2. LLM: hunt the lock/sleep/lock smell. The model is a HYPOTHESIS generator —
  //    the verify gate + widened race repro downstream, not this, decides truth.
  const sourceBlocks = sources
    .map((s) => `### FILE: ${s.file}\n\`\`\`c\n${clip(s.text, maxCharsPerFile)}\n\`\`\``)
    .join("\n\n");
  const messages = [{ role: "user", content: [{ type: "text", text: `## Subsystem source\n\n${sourceBlocks}` }] }];

  const rt = new LlmApiRuntime({ type: "api", ...(input.model ? { model: input.model } : {}), timeout: 300_000 });
  let analysis: AnalysisFromModel | null = null;
  try {
    const res = (await rt.executeNative(SYSTEM, messages as never, [ANALYSIS_TOOL] as never, {
      onThinking() {}, onDelta() {}, onText() {}, onUsage() {},
    } as never)) as { content?: Array<Record<string, unknown>> };
    const call = (res.content ?? []).find(
      (b) => (b as { type?: string; name?: string }).type === "tool_use" && (b as { name?: string }).name === "emit_race_smell_analysis",
    ) as { input?: AnalysisFromModel } | undefined;
    if (call?.input) analysis = call.input;
  } catch (e) {
    throw new Error(`race-smell LLM call failed: ${String(e).slice(0, 200)}`);
  }

  const rawCandidates = Array.isArray(analysis?.candidates) ? analysis!.candidates : [];
  if (rawCandidates.length === 0) throw new Error("model did not emit any race-smell candidates");

  // 3. Keep only well-formed candidates (the full lock/sleep/lock tuple + a widen symbol).
  const valid = rawCandidates.filter(
    (c) =>
      c &&
      typeof c.lockA === "string" && c.lockA.trim() &&
      typeof c.sleepPoint === "string" && c.sleepPoint.trim() &&
      typeof c.lockB === "string" && c.lockB.trim() &&
      typeof c.attackerState === "string" && c.attackerState.trim() &&
      typeof c.hypothesizedPrimitive === "string" && c.hypothesizedPrimitive.trim() &&
      c.widenHint && typeof c.widenHint.injectSymbol === "string" && c.widenHint.injectSymbol.trim(),
  );
  if (valid.length < rawCandidates.length) {
    warnings.push(`dropped ${rawCandidates.length - valid.length} malformed candidate(s) (missing lock/sleep/lock tuple or widen symbol)`);
  }
  if (valid.length === 0) throw new Error("model emitted candidates but none had a usable lock/sleep/lock tuple");

  const smellCandidates = valid.slice(0, maxCandidates);
  if (valid.length > maxCandidates) {
    warnings.push(`capped candidates ${valid.length} -> ${maxCandidates} (raise maxCandidates to widen)`);
  }

  log(`[race-smell] ${smellCandidates.length} widenable smell(s) across ${sources.length} file(s)`);

  // 4. Map the widen hint onto the prover knobs, index-aligned.
  const widenEnvs = smellCandidates.map((c) => widenEnvFor(c, defaultWidenDelayMs));

  // 5. Map each smell to a runHuntScan site. Prefer the model's `site` when it
  //    names a provided file; else fall back to the first readable file.
  const knownFiles = new Set(sources.map((s) => s.file));
  const fallbackFile = sources[0].file;
  const bySite = new Map<string, HuntCandidate>(); // dedupe multiple smells onto the same site
  smellCandidates.forEach((c, i) => {
    const sf = siteFile(c.site);
    const path = sf && knownFiles.has(sf) ? sf : fallbackFile;
    const env = widenEnvs[i];
    const hint =
      `RACE-WIDENING smell. Sequence: unlock(${c.lockA}) -> ${c.sleepPoint} -> lock(${c.lockB}). ` +
      `Attacker state '${c.attackerState}' is used across the sleeping gap — hypothesized ${c.hypothesizedPrimitive}. ` +
      `Confirm the gap is SLEEPABLE (mutex/alloc/copy/sleep, not spinlock-only) and that a 2nd thread can tear the state ` +
      `during the widened window. Widen via kprobe on ${env["0SEC_KERNEL_QEMU_WIDEN_SYMBOL"]} (mdelay ${env["0SEC_KERNEL_QEMU_WIDEN_DELAY_MS"]}ms): ${c.widenHint.rationale}`;
    const existing = bySite.get(path);
    if (existing) existing.hint = `${existing.hint}\n---\n${hint}`;
    else bySite.set(path, { path, hint });
  });
  const candidates = [...bySite.values()];

  const brief: HuntBrief = {
    bugClass: "race-widening: sleepable-lock gap with attacker state across it (ExpRace/Calif class)",
    pattern:
      "unlock(A) -> [sleep / mutex_lock / GFP_KERNEL alloc / copy_from_user] -> lock(B), where attacker-influenced " +
      "state is read/written across the sleeping gap. A LOOKS-nanosecond window that a 2nd thread widens (mdelay kprobe " +
      "on the sleep point) into controllable seconds to tear the state and land a UAF/double-free/OOB.",
    fixReference: undefined,
  };

  return { brief, candidates, smellCandidates, widenEnvs, warnings };
}
