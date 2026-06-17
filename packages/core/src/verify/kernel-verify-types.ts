/**
 * Shared types for the Tier 2 kernel-finding verification path.
 *
 * Lives in its own module so both the `kernel_run` tool implementation (in
 * `agent/tools/kernel-run.ts`) and the verification loop (in
 * `verify/kernel-verify.ts`) can import it without setting up a circular
 * dependency.
 */

import type { Finding } from "@pwnkit/shared";

/**
 * Two-phase trigger phase (AIxCC / Shellphish T3 — sanitizer "loosening").
 *
 *   - `reach`  — Phase 1. Prove the deep code path is REACHABLE under a cheap,
 *                crude build (an oops/WARN/printk probe, no KASAN). Any kernel
 *                crash signal counts; we are answering "can the reproducer even
 *                get there?" before paying for the expensive sanitizer build.
 *   - `refine` — Phase 2. Refine to the EXACT KASAN signature under the
 *                sanitizer build, now that reachability is established.
 *
 * The loop starts in `reach` and escalates to `refine` once a phase-1 attempt
 * lands the path. A single-phase caller (no two-phase opts) runs everything in
 * `refine`, which is byte-for-byte the pre-T3 behaviour.
 */
export type KernelVerifyPhase = "reach" | "refine";

/**
 * Outcome of a single reproducer attempt against the Tier 1 oracle. This is
 * the structured signal the agent sees inside its `tool_result` so it can
 * decide whether to refine the next attempt.
 */
export interface KernelVerifyOracleResult {
  /** Did the reproducer build & boot in the guest? */
  ran: boolean;
  /** Did KASAN/UBSAN/oops fire at all? */
  crashed: boolean;
  /** Did the crash signature match `expected_signature` (when supplied)? */
  signatureMatched: boolean;
  /** Canonical crash type extracted from dmesg, e.g. "kasan-uaf". */
  detectedCrashType?: string;
  /** Full or truncated dmesg for the agent to read. */
  dmesgExcerpt: string;
  /** Short human-readable reason. */
  reason: string;
  /** Numeric oracle confidence in [0,1] for downstream promotion logic. */
  oracleConfidence: number;
  /** Did the Tier 1 build use a cached kernel image? */
  buildStatus?: "env" | "hit" | "miss" | "unknown";
  /**
   * Which two-phase trigger phase produced this result (AIxCC T3). Set by the
   * verify loop on each attempt — `reach` for a phase-1 reachability probe,
   * `refine` for a phase-2 KASAN-signature attempt. Undefined on legacy
   * single-phase paths and on raw runner results before the loop stamps it.
   */
  phase?: KernelVerifyPhase;
}

/**
 * Input shape consumed by the Tier 1 runner. Kept narrow so the loop can be
 * unit-tested against an injected mock without booting QEMU.
 */
export interface KernelVerifyRunnerInput {
  finding: Finding;
  program: string;
  programLang: "syz" | "c";
  expectedSignature?: string;
  kernelTree: string;
  /** Build profile name (e.g. "kasan", "defconfig+kasan"). */
  kernelConfig?: string;
  forceBuild?: boolean;
}

/**
 * The Tier 1 runner is a single async function so callers can swap it for a
 * mock in tests. Default implementation lives in `kernel-verify.ts` and
 * delegates to `prepareKernelVmArtifacts` + `runReproducerInKernelVm`.
 */
export type KernelVerifyRunner = (
  input: KernelVerifyRunnerInput,
) => Promise<KernelVerifyOracleResult>;
