/**
 * KCSAN data-race triage (kernelCTF Pipeline #1, issue #1112).
 *
 * Wires a parsed {@link KcsanRace} through pwnkit's hunt-engine gate:
 *
 *   KcsanRace ──> HuntBrief + synthetic Finding
 *                     │
 *                     ▼  composeGate(skeptic, race-widen prover)
 *   SKEPTIC (makeSkepticVerifier): re-reads the racing source and asks "is this a
 *     race on ATTACKER-CONTROLLABLE state that could yield a UAF/OOB primitive?"
 *     — it filters KCSAN's benign-race noise (most data-races are harmless stat
 *     counters / diagnostic reads) BEFORE we spend a VM boot on them.
 *                     │  survives
 *                     ▼
 *   PROVER (race-widening kernel-vm-runner): boots the reproducer on the PREEMPT
 *     + KASAN `-async` build with an `mdelay()` kprobe injected at the racing PC
 *     (the KCSAN faulting function) to widen the window. CONFIRMED when the
 *     flagged race turns into a KASAN splat (a benign race never will).
 *
 * Reuses `composeGate` + `makeSkepticVerifier` from the hunt stage and
 * `runReproducerInKernelVm` from the kernel VM runner verbatim — the only new
 * parts are the KcsanRace→brief/finding mapping and the race-widen prover
 * wrapper. Kept as a small focused module (no changes to the hunt-scan /
 * kernel-vm-runner god-modules).
 *
 * WHAT IS STUBBED (see the PR body): the prover needs a C reproducer that drives
 * the two racing syscalls. Automatic reproducer SYNTHESIS from a KCSAN report is
 * not built here — the caller supplies `prover.reproducer` (e.g. the syzkaller
 * C repro KCSAN emits). With no reproducer the prover returns a clean
 * "inconclusive" verdict rather than a false confirm.
 */

import type { Finding, RuntimeMode } from "@pwnkit/shared";
import {
  composeGate,
  makeSkepticVerifier,
  type HuntBrief,
  type HuntCandidate,
  type HuntVerifier,
} from "../stages/hunt-scan.js";
import type { CrashReport, ReproducerResult } from "./kernel-oracle.js";
import { runReproducerInKernelVm } from "./kernel-vm-runner.js";
import type { KcsanRace } from "./kcsan-race.js";

/** Default mdelay() injected at the racing PC to widen the window (ms). */
export const DEFAULT_RACE_WIDEN_DELAY_MS = 50;

/**
 * Map a {@link KcsanRace} to a {@link HuntBrief}. The brief frames the hunt as a
 * VARIANT-style search for the one specific race, so the skeptic re-reads only
 * for THIS bug class instead of doing a fresh broad hunt.
 */
export function kcsanRaceToBrief(race: KcsanRace): HuntBrief {
  const objectDesc = race.object ? ` on object ${race.object}` : "";
  const aDir = race.a.access ?? "access";
  const bDir = race.b.access ?? "access";
  return {
    bugClass:
      "unsynchronized concurrent access (data race) on shared kernel state that may yield a UAF / OOB / torn-pointer primitive",
    pattern:
      `concurrent ${aDir} in ${race.a.fn} racing a ${bDir} in ${race.b.fn}${objectDesc} ` +
      "without a common lock — look for a pointer/length/refcount that one side frees or shrinks " +
      "while the other side reads or writes it.",
    fixReference: `KCSAN: data-race in ${race.a.fn} / ${race.b.fn}`,
  };
}

/**
 * Build the synthetic {@link Finding} the skeptic judges. The skeptic only reads
 * `title` + `description`, but a full Finding is constructed so the gate contract
 * is honoured and the finding can be persisted like any other.
 */
export function kcsanRaceToFinding(race: KcsanRace, brief: HuntBrief): Finding {
  const site = race.a.file ? `${race.a.file}:${race.a.line}` : race.a.fn;
  return {
    id: `kcsan-${race.a.fn}-${race.b.fn}`.replace(/[^A-Za-z0-9_-]+/g, "-"),
    templateId: "kcsan-data-race",
    title: `KCSAN data-race in ${race.a.fn} / ${race.b.fn}`,
    description:
      `${brief.bugClass}.\n\n${brief.pattern}\n\n` +
      `Racing sites:\n` +
      `  A: ${race.a.access ?? "access"} (${race.a.size ?? "?"}B) at ${site}\n` +
      `     stack: ${race.a.stack.slice(0, 4).join(" <- ")}\n` +
      `  B: ${race.b.access ?? "access"} (${race.b.size ?? "?"}B) at ${race.b.file ? `${race.b.file}:${race.b.line}` : race.b.fn}\n` +
      `     stack: ${race.b.stack.slice(0, 4).join(" <- ")}\n` +
      (race.valueChanged ? `  value changed: ${race.valueChanged.from} -> ${race.valueChanged.to}\n` : ""),
    severity: "high",
    category: "race-condition",
    status: "discovered",
    timestamp: Date.now(),
    evidence: {
      request: brief.pattern,
      response: race.raw,
      analysis: "Surfaced by KCSAN on the concurrency-sanitizer kernel; not yet proven exploitable.",
    },
  };
}

/**
 * The `PWNKIT_KERNEL_QEMU_WIDEN_*` env the kernel VM runner reads to inject the
 * `mdelay()` kprobe at the racing PC. Exposed (and unit-tested) as a pure
 * mapping; the prover applies it around the runner call since
 * `runReproducerInKernelVm` sources its config from `loadKernelVmConfigFromEnv`.
 */
export function raceWidenEnv(race: KcsanRace, delayMs: number, offset: number): Record<string, string> {
  return {
    PWNKIT_KERNEL_QEMU_WIDEN_SYMBOL: race.a.fn,
    PWNKIT_KERNEL_QEMU_WIDEN_OFFSET: `0x${offset.toString(16)}`,
    PWNKIT_KERNEL_QEMU_WIDEN_DELAY_MS: String(delayMs),
  };
}

/** Does a run's output/dmesg carry a KASAN splat? Returns the signature snippet. */
export function detectKasanSplat(text: string): string | undefined {
  const m = /KASAN:\s*([a-z0-9-]+)/i.exec(text) ?? /(BUG:\s*KASAN[^\n]*)/i.exec(text);
  return m ? m[1] ?? m[0] : undefined;
}

export interface KcsanProverConfig {
  /**
   * C reproducer source that drives the two racing syscalls. Supplied by the
   * caller (e.g. the syzkaller C repro). Absent ⇒ the prover returns
   * "inconclusive" instead of confirming — reproducer synthesis is out of scope.
   */
  reproducer?: string;
  /** mdelay() injected at the racing PC. Default {@link DEFAULT_RACE_WIDEN_DELAY_MS}. */
  widenDelayMs?: number;
  /** Byte offset into the racing function for the kprobe. Default 0 (function entry). */
  widenOffset?: number;
  /**
   * Injection point for tests / alternate executors. Defaults to the real QEMU
   * runner `runReproducerInKernelVm`. In tests, pass a fake returning a canned
   * {@link ReproducerResult} so no VM is needed.
   */
  vmRunner?: (report: CrashReport) => Promise<ReproducerResult>;
}

/**
 * The PROVER half of the gate: boot the reproducer on the `-async` PREEMPT+KASAN
 * build with the race window widened at the KCSAN faulting PC, and confirm iff
 * the race becomes a KASAN splat. Never self-graded — a benign data race widens
 * to nothing.
 */
export function makeRaceWidenProver(race: KcsanRace, cfg: KcsanProverConfig = {}): HuntVerifier {
  const vmRunner = cfg.vmRunner ?? runReproducerInKernelVm;
  const delayMs = cfg.widenDelayMs ?? DEFAULT_RACE_WIDEN_DELAY_MS;
  const offset = cfg.widenOffset ?? 0;
  return async () => {
    if (!cfg.reproducer) {
      return {
        confirmed: false,
        reason:
          "prover inconclusive: no race-driving C reproducer supplied (reproducer synthesis from a KCSAN report is not wired — pass prover.reproducer)",
      };
    }
    const report: CrashReport = {
      raw: race.raw,
      crashType: "kcsan-data-race",
      faultingFunction: race.a.fn,
      stackFrames: race.a.stack,
      reproducer: cfg.reproducer,
      reproducerLanguage: "c",
      ...(race.a.access ? { accessType: race.a.access } : {}),
      ...(race.a.size ? { accessSize: race.a.size } : {}),
    };
    // Apply the widen env around the runner call (it reads config from env), then
    // restore so we don't leak widen params to other work in the same process.
    const env = raceWidenEnv(race, delayMs, offset);
    const saved = new Map<string, string | undefined>();
    for (const [k, v] of Object.entries(env)) {
      saved.set(k, process.env[k]);
      process.env[k] = v;
    }
    try {
      const result = await vmRunner(report);
      const splat = detectKasanSplat(`${result.dmesg}\n${result.output}`);
      if (splat) {
        return {
          confirmed: true,
          reason: `race widened at ${race.a.fn} (+0x${offset.toString(16)}, mdelay ${delayMs}ms) became a KASAN splat: ${splat}`,
        };
      }
      if (!result.compiled) {
        return { confirmed: false, reason: `prover inconclusive: reproducer failed to compile — ${result.output.slice(0, 200)}` };
      }
      return {
        confirmed: false,
        reason: "race-widened run produced no KASAN splat — benign race or the window was not hit",
      };
    } finally {
      for (const [k, v] of saved) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  };
}

export interface TriageKcsanOptions {
  race: KcsanRace;
  /** Source tree the skeptic re-reads (the racing subsystem). */
  sourceRoot: string;
  runtime: RuntimeMode;
  /** File the skeptic points at. Defaults to the racing site's file (or fn). */
  candidatePath?: string;
  /** Skeptic model override. */
  skepticModel?: string;
  /** Prover config (reproducer + widen knobs + injectable vmRunner). */
  prover?: KcsanProverConfig;
  /**
   * Override the skeptic verifier. Defaults to {@link makeSkepticVerifier}
   * (which calls an LLM). Injected in tests so triage runs fully offline.
   */
  skeptic?: HuntVerifier;
  log?: (msg: string) => void;
}

export interface TriageKcsanResult {
  brief: HuntBrief;
  finding: Finding;
  /** Passed the skeptic AND the race-widen prover. */
  confirmed: boolean;
  /** The verdict reason from the gate stage that decided the outcome. */
  reason: string;
}

/**
 * Triage a single KCSAN data-race: derive the brief + finding, then run it
 * through `composeGate(skeptic, race-widen prover)`. The skeptic filters benign
 * races; the prover proves the survivors by turning the widened race into a
 * KASAN splat.
 */
export async function triageKcsanRace(opts: TriageKcsanOptions): Promise<TriageKcsanResult> {
  const log = opts.log ?? (() => {});
  const brief = kcsanRaceToBrief(opts.race);
  const finding = kcsanRaceToFinding(opts.race, brief);
  const candidate: HuntCandidate = {
    path: opts.candidatePath ?? opts.race.a.file ?? opts.race.a.fn,
    hint: brief.pattern,
  };

  const skeptic =
    opts.skeptic ??
    makeSkepticVerifier({
      sourceRoot: opts.sourceRoot,
      runtime: opts.runtime,
      ...(opts.skepticModel ? { model: opts.skepticModel } : {}),
    });
  const prover = makeRaceWidenProver(opts.race, opts.prover ?? {});
  const gate = composeGate(skeptic, prover);

  log(`[kcsan] triaging data-race in ${opts.race.a.fn} / ${opts.race.b.fn}`);
  const verdict = await gate(finding, candidate);
  log(`[kcsan] ${verdict.confirmed ? "CONFIRMED" : "rejected"}: ${verdict.reason}`);

  return { brief, finding, confirmed: verdict.confirmed, reason: verdict.reason };
}
