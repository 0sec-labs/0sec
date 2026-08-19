/**
 * Engine C — auto-harness-synthesis (pwnkit#1228, the field's choke point).
 *
 * The single unblocker for binary/Windows and deep kernel paths
 * (docs/operations/llm-lpe-innovation-plan.md, U3): "the choke point is
 * auto-synthesizing the init handshake / device state so a closed-source driver
 * loads and reaches its vulnerable IOCTL." A mechanized-artifact oracle
 * (mechanized-artifact.ts) can only CONFIRM a bug it can reproduce — and it
 * cannot reproduce a bug it cannot REACH. This module closes that loop: given a
 * target sink (a kernel ioctl/syscall path, or a decompiled Windows driver
 * IOCTL), it drives an LLM to synthesise the harness that OPENS the device, runs
 * the init handshake, builds the arg struct, and issues the call that lands on
 * the sink — validated by a real reachability signal (a KCOV edge hit at the
 * sink, or a crash), not the model's say-so.
 *
 * It reuses two shipped ideas verbatim:
 *   - the two-phase reach→refine trigger (kernel-verify.ts): first prove the
 *     deep path is REACHABLE under a cheap probe build, THEN escalate to the
 *     sanitizer build to nail the crash. Cheap first, expensive only on reach.
 *   - the coverage-feedback re-prompt (kernel-verify.ts): when a run collects
 *     KCOV, feed the model how many NEW edges it reached toward the sink so the
 *     next attempt is guided by real execution coverage, not blind retry.
 *
 * The output is a validated harness (a C/syz reproducer for kernel; a C harness
 * that CreateFile+DeviceIoControls the driver for Windows) that the
 * mechanized-artifact gate's `reproduce` seam then runs through the N×
 * reproduction gate to produce the sanitizer {@link CrashArtifact}.
 *
 * DOMAIN-NEUTRAL by design: the execution + reachability oracle is an INJECTED
 * seam ({@link HarnessRunner}) returning one shape for both worlds — kernel prod
 * wraps kernel-vm-runner with KCOV; Windows prod wraps the Hyper-V host with a
 * WinDbg breakpoint at the dispatch routine. The synth LOGIC is identical, so it
 * is fully unit-testable with a fake runner (no VM, no keys).
 */

import type { NativeToolDef } from "../runtime/types.js";

// ────────────────────────────────────────────────────────────────────
// Target contract — what we are trying to reach
// ────────────────────────────────────────────────────────────────────

export type HarnessDomain = "kernel-syscall" | "kernel-ioctl" | "windows-ioctl";

/**
 * The sink to reach, plus everything known about how to reach it. For kernel
 * this comes from the finding metadata + the subsystem source slice; for
 * Windows it comes from the decompiler (Ghidra/BinaryNinja headless) — the
 * device name, the dispatch routine, the IOCTL code, and the inferred input
 * struct layout, all extracted from pseudo-C.
 */
export interface HarnessTarget {
  domain: HarnessDomain;
  /** The faulting/sink symbol or address the harness must reach. */
  sink: string;
  /** Source / decompiled context the model reads to build the harness. */
  context: string;

  // ── kernel-ioctl / windows-ioctl ──────────────────────────────────
  /** Device to open — "/dev/foo" (kernel) or "\\\\.\\FooDevice" (Windows). */
  devicePath?: string;
  /** The IOCTL / request code that dispatches to the sink (decimal or 0x-hex string). */
  ioctlCode?: string;
  /**
   * The inferred input-buffer / arg-struct layout the sink reads — field names,
   * sizes, offsets. For Windows this is the decompiler's reconstruction; the
   * harness must fill it so the vulnerable path (not an early -EINVAL) is taken.
   */
  argStructLayout?: string;
  /**
   * The init HANDSHAKE required before the sink is reachable — a prior IOCTL
   * that allocates the object, a bind/connect, a mode-set that enables the
   * private ioctl. The most commonly-missing piece; naming it here lets the
   * model target it explicitly.
   */
  initHandshake?: string;

  // ── kernel-syscall ────────────────────────────────────────────────
  /** Ranked entry syscalls that reach the sink (from the reachability hint). */
  entrySyscalls?: string[];
}

// ────────────────────────────────────────────────────────────────────
// Execution + reachability oracle — the injected seam
// ────────────────────────────────────────────────────────────────────

export type HarnessLang = "c" | "syz";

/** A harness the model emitted for one attempt. */
export interface HarnessProgram {
  lang: HarnessLang;
  source: string;
}

/** Which build the runner should use for this attempt (two-phase reach→refine). */
export type HarnessPhase = "reach" | "refine";

export interface HarnessRunInput {
  program: HarnessProgram;
  phase: HarnessPhase;
  target: HarnessTarget;
}

/**
 * The result of running one harness attempt. Deliberately ONE shape for kernel
 * and Windows: `reached` is the reachability verdict (a KCOV edge at the sink, a
 * WinDbg breakpoint hit at the dispatch routine, or a crash that proves the path
 * ran); `crashed`/`dmesg` carry the sanitizer signal from a `refine`-phase run.
 */
export interface HarnessRunResult {
  /** Did the harness build/compile? A build failure is a non-observation, retryable. */
  built: boolean;
  /** Did execution reach the sink (coverage hit / breakpoint / crash on the path)? */
  reached: boolean;
  /** Did a sanitizer / crash oracle fire (refine phase)? */
  crashed?: boolean;
  /** Raw crash / debugger / dmesg text (refine phase). */
  crashOutput?: string;
  /**
   * Directed-search feedback for the next attempt: which NEW edges toward the
   * sink this attempt reached, or which gate it stalled at (e.g. "returned
   * -EINVAL at foo_ioctl+0x20 — arg validation, handshake likely missing").
   * Fed back verbatim into the re-prompt. Injected so the runner owns how it is
   * computed (KCOV diff for kernel, module-coverage for Windows).
   */
  coverageFeedback?: string;
  /** Free-form error when the run could not be attempted. */
  error?: string;
}

/**
 * The injected execution + reachability oracle. Kernel prod: build the program,
 * boot QEMU with KCOV (`reach` phase = cheap oops/WARN build, `refine` = KASAN),
 * set `reached` from a KCOV PC landing in the sink neighbourhood. Windows prod:
 * compile the harness, run it on the Hyper-V host against the loaded driver, set
 * `reached` from a WinDbg bp at the dispatch routine. Tests inject a fake.
 */
export type HarnessRunner = (input: HarnessRunInput) => Promise<HarnessRunResult>;

// ────────────────────────────────────────────────────────────────────
// The synthesis LLM — injected, structured-output
// ────────────────────────────────────────────────────────────────────

/**
 * The `emit_harness` tool the synth model must call. Structured-output
 * discipline (kernel-run.ts): the harness is emitted through a schema, not
 * free-form prose, so the runner gets a program it can build directly.
 */
export const emitHarnessTool: NativeToolDef = {
  name: "emit_harness",
  description:
    "Emit a self-contained harness that opens the device, performs the init handshake, builds the " +
    "arg struct, and issues the call that REACHES the target sink. For a kernel target emit a C " +
    "reproducer with main() (or a syz program); for a Windows driver emit a C harness that " +
    "CreateFile()s the device and DeviceIoControl()s the IOCTL. Reach the sink — do not stop at an " +
    "early validation return.",
  input_schema: {
    type: "object",
    properties: {
      lang: { type: "string", enum: ["c", "syz"], description: "Harness language." },
      source: { type: "string", description: "The full harness source." },
      rationale: {
        type: "string",
        description: "One line: how this harness reaches the sink (which handshake, which arg gate it clears).",
      },
    },
    required: ["lang", "source"],
  },
};

/**
 * One synth turn, injected. Given the running conversation (as a single rendered
 * prompt for simplicity in this skeleton) returns the model's emitted harness or
 * null when it declined. Prod routes this through the engine runtime + the
 * emit_harness tool; tests return canned programs.
 */
export type HarnessSynthModel = (prompt: string) => Promise<HarnessProgram | null>;

// ────────────────────────────────────────────────────────────────────
// The synth loop
// ────────────────────────────────────────────────────────────────────

export interface HarnessSynthOptions {
  /** Max synth→run attempts. Default 6. Each attempt is one model turn + one run. */
  maxAttempts?: number;
  /**
   * Two-phase reach→refine. On by default: run early attempts under the cheap
   * `reach` build to LAND the path, then escalate to `refine` (sanitizer) once
   * reached. Set false to run every attempt under `refine` (slower, no cheap
   * reach probe).
   */
  twoPhase?: boolean;
  log?: (msg: string) => void;
}

export type HarnessSynthStatus =
  | "reached-and-crashed" // landed the sink AND a sanitizer crash fired — the win
  | "reached" // landed the sink but no crash (still useful — hand to N× repro / bounded check)
  | "not-reached" // never landed the sink within budget
  | "no-harness"; // the model never emitted a usable harness

export interface HarnessAttemptRecord {
  index: number;
  phase: HarnessPhase;
  program?: HarnessProgram;
  built: boolean;
  reached: boolean;
  crashed: boolean;
  note: string;
}

export interface HarnessSynthResult {
  status: HarnessSynthStatus;
  /** The harness that reached the sink (present for `reached*`). */
  harness?: HarnessProgram;
  /** Raw crash output when `status === "reached-and-crashed"`. */
  crashOutput?: string;
  attempts: HarnessAttemptRecord[];
  reason: string;
}

function renderPrompt(
  target: HarnessTarget,
  history: HarnessAttemptRecord[],
  phase: HarnessPhase,
  lastFeedback: string | undefined,
): string {
  const parts: string[] = [
    `You are the AUTO-HARNESS synthesiser. Reach this sink so it can be dynamically triggered.`,
    ``,
    `## Target`,
    `domain: ${target.domain}`,
    `sink: ${target.sink}`,
    target.devicePath ? `device: ${target.devicePath}` : "",
    target.ioctlCode ? `ioctl code: ${target.ioctlCode}` : "",
    target.initHandshake ? `init handshake required: ${target.initHandshake}` : "",
    target.argStructLayout ? `arg struct layout:\n${target.argStructLayout}` : "",
    target.entrySyscalls?.length ? `candidate entry syscalls: ${target.entrySyscalls.join(", ")}` : "",
    ``,
    `## Context (source / decompiled)`,
    target.context,
    ``,
    `## Phase`,
    phase === "reach"
      ? "REACH: just LAND the path to the sink under a cheap build. Any signal that the sink ran is success; the exact crash comes later."
      : "REFINE: the path is reachable — now trigger the bug so the sanitizer fires at the sink.",
  ];
  if (history.length > 0) {
    parts.push("", "## Prior attempts");
    for (const a of history.slice(-3)) {
      parts.push(
        `- attempt ${a.index} (${a.phase}): built=${a.built} reached=${a.reached} crashed=${a.crashed} — ${a.note}`,
      );
    }
  }
  if (lastFeedback) {
    parts.push("", "## Coverage feedback (target your next attempt at this)", lastFeedback);
  }
  parts.push("", "Emit the harness via emit_harness. Reach the sink — do not stop at an early validation return.");
  return parts.filter(Boolean).join("\n");
}

const DEFAULT_MAX_ATTEMPTS = 6;

/**
 * Drive the synth→run loop until the harness reaches the sink (and, on the
 * refine build, crashes) or the attempt budget is spent.
 *
 * Flow per attempt:
 *   1. Prompt the model (with prior-attempt history + last coverage feedback).
 *   2. Build+run the emitted harness under the current phase's build.
 *   3. REACH phase: any `reached` signal escalates the phase to REFINE (we do
 *      NOT trust the cheap build for the exact crash). Not reached → feed the
 *      coverage gap back and retry.
 *   4. REFINE phase: `reached && crashed` is the win; `reached && !crashed` is
 *      banked as a reached-but-benign harness (hand to the N× repro / bounded
 *      check); not reached → feedback + retry.
 */
export async function synthesizeHarness(
  target: HarnessTarget,
  model: HarnessSynthModel,
  runner: HarnessRunner,
  opts: HarnessSynthOptions = {},
): Promise<HarnessSynthResult> {
  const log = opts.log ?? (() => {});
  const maxAttempts = Math.max(1, opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS);
  const twoPhase = opts.twoPhase ?? true;

  const attempts: HarnessAttemptRecord[] = [];
  let phase: HarnessPhase = twoPhase ? "reach" : "refine";
  let lastFeedback: string | undefined;
  let reachedHarness: HarnessProgram | undefined;

  for (let i = 0; i < maxAttempts; i++) {
    const prompt = renderPrompt(target, attempts, phase, lastFeedback);

    let program: HarnessProgram | null;
    try {
      program = await model(prompt);
    } catch (e) {
      attempts.push({ index: i, phase, built: false, reached: false, crashed: false, note: `model error: ${String(e).slice(0, 100)}` });
      continue;
    }
    if (!program) {
      attempts.push({ index: i, phase, built: false, reached: false, crashed: false, note: "model emitted no harness" });
      continue;
    }

    let result: HarnessRunResult;
    try {
      result = await runner({ program, phase, target });
    } catch (e) {
      attempts.push({ index: i, phase, program, built: false, reached: false, crashed: false, note: `runner error: ${String(e).slice(0, 100)}` });
      continue;
    }

    lastFeedback = result.coverageFeedback;
    const crashed = Boolean(result.crashed);
    attempts.push({
      index: i,
      phase,
      program,
      built: result.built,
      reached: result.reached,
      crashed,
      note: result.error ?? (result.reached ? "reached sink" : "did not reach sink"),
    });
    log(`[harness-synth] attempt ${i} (${phase}): built=${result.built} reached=${result.reached} crashed=${crashed}`);

    if (!result.reached) continue;

    // Reached the sink.
    reachedHarness = program;

    if (phase === "reach") {
      // Cheap build landed the path — escalate to the sanitizer build. Do NOT
      // trust the reach build for the exact crash signature.
      phase = "refine";
      log(`[harness-synth] path reached under cheap build — escalating to refine`);
      continue;
    }

    // Refine phase.
    if (crashed) {
      return {
        status: "reached-and-crashed",
        harness: program,
        ...(result.crashOutput ? { crashOutput: result.crashOutput } : {}),
        attempts,
        reason: `sink reached and sanitizer fired on attempt ${i}`,
      };
    }
    // Reached but no crash — bank the harness; the sink is dynamically
    // triggerable, so the N× repro / bounded-check path can take over.
    // Keep iterating in case a later attempt also crashes.
  }

  if (reachedHarness) {
    return {
      status: "reached",
      harness: reachedHarness,
      attempts,
      reason: "sink reached but no sanitizer crash within budget — harness is triggerable; hand to N× repro / bounded check",
    };
  }
  return {
    status: attempts.some((a) => a.program) ? "not-reached" : "no-harness",
    attempts,
    reason: attempts.some((a) => a.program)
      ? `sink not reached in ${attempts.length} attempt(s)`
      : "model never emitted a usable harness",
  };
}
