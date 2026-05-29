/**
 * Reproducer minimization (pwnkit#569).
 *
 * A confirmed kernel reproducer is rarely minimal — syzkaller programs carry
 * dozens of incidental syscalls, and agent-authored C reproducers carry setup
 * noise. A minimized repro is both a stronger disclosure artifact ("these 3
 * syscalls are sufficient") and sharper evidence of the real trigger.
 *
 * This module runs a **delta-debugging** pass (Zeller & Hildebrandt's ddmin)
 * over the reproducer's *units* — one syscall per line for `.syz` programs,
 * one source line for C — against an injected crash oracle. The result is a
 * "1-minimal" repro: removing any single retained unit stops the crash.
 *
 * The oracle is injected so the core algorithm is unit-testable without
 * booting QEMU. `makeKernelMinimizeOracle` wraps the real Tier-1
 * `KernelVerifyRunner` for production use.
 */

import type { KernelVerifyRunner, KernelVerifyRunnerInput } from "./kernel-verify-types.js";
import type { Finding } from "@pwnkit/shared";

// ── Types ─────────────────────────────────────────────────────────────────

export type ReproducerLang = "syz" | "c";

/**
 * Verdict for a single candidate reproducer. The minimizer only needs to know
 * "does this still crash the way we want?" — `signature` is carried through for
 * diagnostics.
 */
export interface MinimizeOracleResult {
  stillCrashes: boolean;
  signature?: string;
}

export type MinimizeOracle = (
  program: string,
  lang: ReproducerLang,
) => Promise<MinimizeOracleResult>;

export interface MinimizeOptions {
  /** Reproducer language — controls how the program is split into units. */
  lang: ReproducerLang;
  /** The crash oracle. Injected so the algorithm is testable without QEMU. */
  oracle: MinimizeOracle;
  /**
   * Max oracle invocations before bailing with the best repro found so far.
   * Each oracle call boots QEMU, so this is the real cost knob. Default 200.
   */
  maxOracleCalls?: number;
  /**
   * If set, the minimizer keeps a candidate only when the oracle reports this
   * exact signature (substring match, case-insensitive). When omitted, any
   * crash counts — matching the loose "still crashes" contract.
   */
  expectedSignature?: string;
  /** Optional progress logger. */
  logger?: (line: string) => void;
}

export interface MinimizeResult {
  /** The minimized reproducer source. */
  program: string;
  lang: ReproducerLang;
  originalUnitCount: number;
  minimizedUnitCount: number;
  /** Units removed (their original text), for the disclosure diff. */
  removedUnits: string[];
  oracleCalls: number;
  /** False when the original program did not crash under the oracle. */
  reproduced: boolean;
  /** Signature observed on the final minimized program (if any). */
  signature?: string;
  /** True when ddmin reached a 1-minimal fixpoint before the budget ran out. */
  oneMinimal: boolean;
}

// ── Unit splitting ──────────────────────────────────────────────────────────

/**
 * Split a reproducer into the units ddmin will try to remove.
 *
 * For `.syz` programs each non-blank, non-comment line is one syscall. For C we
 * split on lines but treat preprocessor/`#include` and the bare `main`
 * scaffolding lines as *structural* — never candidates for removal, so we never
 * produce uncompilable C. Structural lines are tracked separately and stitched
 * back in on every candidate render.
 */
export interface SplitProgram {
  /** Removable units, in order. */
  units: string[];
  /**
   * Render function: given the subset of unit indices to KEEP (sorted), return
   * a full program string with structural lines preserved in position.
   */
  render: (keepIdx: number[]) => string;
}

const C_STRUCTURAL = /^\s*(#|int\s+main|void\s+main|\}|\{|return\b|\/\/|\/\*|\*)/;

export function splitProgram(program: string, lang: ReproducerLang): SplitProgram {
  const rawLines = program.split("\n");

  if (lang === "syz") {
    // One syscall per line. Blank lines and comments are structural noise that
    // we drop entirely on render (they carry no trigger semantics).
    const unitIdx: number[] = [];
    rawLines.forEach((line, i) => {
      const t = line.trim();
      if (t.length > 0 && !t.startsWith("#")) unitIdx.push(i);
    });
    const units = unitIdx.map((i) => rawLines[i]!);
    const render = (keepIdx: number[]): string => {
      const keep = new Set(keepIdx);
      return units.filter((_, i) => keep.has(i)).join("\n");
    };
    return { units, render };
  }

  // C: line-oriented, structural lines pinned.
  const unitOrigIdx: number[] = [];
  rawLines.forEach((line, i) => {
    const t = line.trim();
    if (t.length === 0) return; // blank — pinned (kept verbatim)
    if (C_STRUCTURAL.test(line)) return; // structural — pinned
    unitOrigIdx.push(i);
  });
  const units = unitOrigIdx.map((i) => rawLines[i]!);

  const render = (keepIdx: number[]): string => {
    const keep = new Set(keepIdx);
    // Map each removable unit's original line index → whether it is kept.
    const removableKept = new Map<number, boolean>();
    unitOrigIdx.forEach((origI, unitI) => removableKept.set(origI, keep.has(unitI)));
    const out: string[] = [];
    rawLines.forEach((line, i) => {
      if (removableKept.has(i)) {
        if (removableKept.get(i)) out.push(line);
      } else {
        out.push(line); // structural / blank — always kept
      }
    });
    return out.join("\n");
  };
  return { units, render };
}

// ── ddmin ─────────────────────────────────────────────────────────────────

/**
 * Delta-debugging minimization (ddmin) over a list of unit indices.
 *
 * Standard algorithm: at granularity `n`, partition the kept set into `n`
 * chunks. If removing any single chunk still satisfies the test, drop it and
 * restart at the reduced granularity. If removing any *complement* (all but one
 * chunk) still passes, recurse into that complement. Otherwise increase
 * granularity (up to |kept|). Terminates at a 1-minimal set.
 *
 * `test(keepIdx)` returns true when the subset still reproduces.
 */
export async function ddmin(
  unitCount: number,
  test: (keepIdx: number[]) => Promise<boolean>,
): Promise<number[]> {
  let kept = Array.from({ length: unitCount }, (_, i) => i);
  let granularity = 2;

  while (kept.length >= 2) {
    const chunks = partition(kept, Math.min(granularity, kept.length));
    let reduced = false;

    // Try removing each complement (keep just one chunk).
    if (chunks.length > 2) {
      for (const chunk of chunks) {
        if (await test(chunk)) {
          kept = chunk;
          granularity = 2;
          reduced = true;
          break;
        }
      }
    }

    if (!reduced) {
      // Try removing each single chunk (keep the rest).
      for (let i = 0; i < chunks.length; i++) {
        const candidate = chunks.filter((_, ci) => ci !== i).flat();
        if (candidate.length > 0 && (await test(candidate))) {
          kept = candidate;
          granularity = Math.max(granularity - 1, 2);
          reduced = true;
          break;
        }
      }
    }

    if (!reduced) {
      if (granularity >= kept.length) break; // 1-minimal
      granularity = Math.min(kept.length, granularity * 2);
    }
  }

  return kept;
}

function partition(arr: number[], n: number): number[][] {
  const chunks: number[][] = [];
  const size = Math.ceil(arr.length / n);
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}

// ── Public entry point ──────────────────────────────────────────────────────

/**
 * Minimize a reproducer against a crash oracle. Returns the smallest still-
 * crashing program ddmin could find within the oracle-call budget.
 *
 * Contract:
 *   - First verifies the *original* program crashes; if it doesn't, returns it
 *     unchanged with `reproduced:false` (nothing to minimize).
 *   - Caches oracle verdicts by program text so repeated candidates are free.
 *   - Honours `maxOracleCalls`; on exhaustion returns the best repro so far
 *     with `oneMinimal:false`.
 */
export async function minimizeReproducer(
  program: string,
  opts: MinimizeOptions,
): Promise<MinimizeResult> {
  const log = opts.logger ?? (() => {});
  const budget = opts.maxOracleCalls ?? 200;
  const { units, render } = splitProgram(program, opts.lang);

  const cache = new Map<string, MinimizeOracleResult>();
  let oracleCalls = 0;

  const signatureMatches = (res: MinimizeOracleResult): boolean => {
    if (!res.stillCrashes) return false;
    if (!opts.expectedSignature) return true;
    return (res.signature ?? "").toLowerCase().includes(opts.expectedSignature.toLowerCase());
  };

  // Verify the full program first.
  const baseResult = await runOracle(program);
  if (!signatureMatches(baseResult)) {
    log("[minimize] original program did not reproduce — skipping minimization");
    return {
      program,
      lang: opts.lang,
      originalUnitCount: units.length,
      minimizedUnitCount: units.length,
      removedUnits: [],
      oracleCalls,
      reproduced: false,
      signature: baseResult.signature,
      oneMinimal: false,
    };
  }

  if (units.length <= 1) {
    return {
      program,
      lang: opts.lang,
      originalUnitCount: units.length,
      minimizedUnitCount: units.length,
      removedUnits: [],
      oracleCalls,
      reproduced: true,
      signature: baseResult.signature,
      oneMinimal: true,
    };
  }

  let budgetHit = false;

  const test = async (keepIdx: number[]): Promise<boolean> => {
    if (budgetHit) return false;
    const candidate = render([...keepIdx].sort((a, b) => a - b));
    const res = await runOracle(candidate);
    return signatureMatches(res);
  };

  const keptIdx = await ddmin(units.length, test);
  const keptSorted = [...keptIdx].sort((a, b) => a - b);
  const minimized = render(keptSorted);

  // Final confirmation pass on the minimized program for its signature.
  const finalResult = await runOracle(minimized);
  const keptSet = new Set(keptSorted);
  const removedUnits = units.filter((_, i) => !keptSet.has(i));

  log(
    `[minimize] ${units.length} → ${keptSorted.length} units` +
      ` (${oracleCalls} oracle calls${budgetHit ? ", budget exhausted" : ""})`,
  );

  return {
    program: minimized,
    lang: opts.lang,
    originalUnitCount: units.length,
    minimizedUnitCount: keptSorted.length,
    removedUnits,
    oracleCalls,
    reproduced: true,
    signature: finalResult.signature ?? baseResult.signature,
    oneMinimal: !budgetHit,
  };

  async function runOracle(candidate: string): Promise<MinimizeOracleResult> {
    const cached = cache.get(candidate);
    if (cached) return cached;
    if (oracleCalls >= budget) {
      budgetHit = true;
      return { stillCrashes: false };
    }
    oracleCalls++;
    const res = await opts.oracle(candidate, opts.lang);
    cache.set(candidate, res);
    return res;
  }
}

// ── Default kernel oracle ───────────────────────────────────────────────────

export interface KernelMinimizeOracleDeps {
  runner: KernelVerifyRunner;
  finding: Finding;
  kernelTree: string;
  kernelConfig?: string;
  forceBuild?: boolean;
  /** Required when `MinimizeOptions.expectedSignature` is set on the runner side. */
  expectedSignature?: string;
}

/**
 * Build a `MinimizeOracle` backed by the real Tier-1 kernel runner. Each call
 * hands the candidate program to `verifyKernelFinding` (via the injected
 * `KernelVerifyRunner`) and maps the oracle verdict to `stillCrashes`.
 */
export function makeKernelMinimizeOracle(deps: KernelMinimizeOracleDeps): MinimizeOracle {
  return async (program, lang) => {
    const input: KernelVerifyRunnerInput = {
      finding: deps.finding,
      program,
      programLang: lang,
      expectedSignature: deps.expectedSignature,
      kernelTree: deps.kernelTree,
      kernelConfig: deps.kernelConfig,
      forceBuild: deps.forceBuild,
    };
    const oracle = await deps.runner(input);
    return {
      stillCrashes: oracle.crashed,
      signature: oracle.detectedCrashType,
    };
  };
}
