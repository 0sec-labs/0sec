/**
 * Patch generate → validate (AIxCC / Shellphish T7 — root-cause correctness).
 *
 * A `reproduced` verdict proves a reproducer trips KASAN against the unpatched
 * tree. That is necessary but NOT sufficient to claim we understand the
 * ROOT CAUSE: a reproducer can fire for an adjacent reason, or the bug might be
 * misattributed. AIxCC's patch-as-oracle technique closes that gap — generate a
 * candidate fix, apply it, rebuild, and re-run the SAME reproducer:
 *
 *   - KASAN no longer fires under the patched build  ⇒ the patch removed the
 *     defect the reproducer exercised: ROOT CAUSE CONFIRMED (`patchValidated`).
 *   - KASAN still fires                              ⇒ the patch did not address
 *     the real defect (wrong root cause, or an incomplete fix).
 *
 * The patched rebuild is cache-keyed by the PATCHED tree fingerprint via
 * {@link prepareKernelVmArtifacts} (a `git apply` leaves the tree dirty, so
 * `git describe --dirty` yields a distinct cache key) — the unpatched and
 * patched kernels never collide in the build cache.
 *
 * Dependency-injectable end to end (LLM patch-gen, the patch applier, the build
 * runner, and the Tier-1 VM runner) so the whole flow unit-tests without an LLM
 * or a QEMU boot. Reuses {@link isKernelGitTree} from `kernel/fix-commit-intel.ts`
 * as the apply guard and {@link checkAlreadyFixed} to give the patch generator
 * upstream-fix context when available.
 */

import { execFileSync } from "node:child_process";
import type { Finding } from "@0sec/shared";
import {
  prepareKernelVmArtifacts,
  verifyKernelFinding,
  type KernelConfigProfile,
} from "../triage/kernel-vm-runner.js";
import {
  checkAlreadyFixed,
  isKernelGitTree,
} from "../kernel/fix-commit-intel.js";

/** A candidate kernel fix the LLM proposed for a reproduced finding. */
export interface CandidatePatch {
  /** Unified diff (`git apply`-able) against the kernel tree. */
  diff: string;
  /** One-line human rationale for the fix, for the audit trail. */
  rationale?: string;
}

/**
 * Generate a candidate patch for a reproduced finding. The default
 * implementation is LLM-backed by the caller; tests inject a deterministic
 * generator. Returns `null` when no candidate could be produced (e.g. the LLM
 * declined) — the validator reports `patch_generation_failed` rather than
 * throwing.
 */
export type PatchGenerator = (ctx: {
  finding: Finding;
  /** The reproducer that triggered KASAN (the thing the patch must defuse). */
  reproducer: string;
  reproducerLang: "syz" | "c";
  /** The KASAN dmesg the reproducer produced, for root-cause context. */
  crashDmesg: string;
  /** Recent upstream-fix context for the cited function, when a git tree exists. */
  upstreamFixHint?: string;
}) => Promise<CandidatePatch | null>;

/** Apply a unified diff to the kernel tree. Throws on a failed apply. */
export type PatchApplier = (input: { tree: string; diff: string }) => void;

/** Revert a previously-applied diff. Best-effort; must not throw. */
export type PatchReverter = (input: { tree: string; diff: string }) => void;

export type PatchValidateStatus =
  | "root_cause_confirmed"
  | "not_root_cause"
  | "patch_generation_failed"
  | "patch_apply_failed"
  | "rebuild_failed"
  | "error";

export interface PatchValidateResult {
  status: PatchValidateStatus;
  /**
   * True ONLY when the patched rebuild made KASAN stop firing for the same
   * reproducer — the single bit downstream disclosure consumes (AIxCC T7).
   */
  patchValidated: boolean;
  /** The candidate patch that was tried (when one was generated). */
  patch?: CandidatePatch;
  /** Build cache key of the PATCHED kernel (proves a distinct, patched build). */
  patchedCacheKey?: string;
  /** The Tier-1 status from re-running the reproducer on the patched build. */
  rerunStatus?: string;
  /** Human-readable reason for the audit trail. */
  reason: string;
}

export interface PatchValidateOptions {
  finding: Finding;
  /** Linux source tree the patched kernel is built from. */
  kernelTree: string;
  /** The reproducer that produced the `reproduced` verdict. */
  reproducer: string;
  reproducerLang: "syz" | "c";
  /** The KASAN dmesg that fired on the unpatched build. */
  crashDmesg: string;
  /** Path to the reproducer file (re-run against the patched build). */
  reproducerPath: string;
  /**
   * Expected crash signature — when set, the re-run only counts as "still
   * firing" if THIS signature reappears. Defaults to the engine's any-KASAN
   * detection.
   */
  expectedSignature?: string;
  /** Build profile for the patched rebuild. Defaults to "kasan". */
  kernelConfig?: KernelConfigProfile;
  cacheDir?: string;
  /** LLM patch generator. */
  patchGenerator: PatchGenerator;
  /** Patch applier. Defaults to `git apply`. */
  patchApplier?: PatchApplier;
  /** Patch reverter. Defaults to `git apply -R`. */
  patchReverter?: PatchReverter;
  /** Injection point for tests / alternate build executors. */
  buildRunner?: Parameters<typeof prepareKernelVmArtifacts>[0]["buildRunner"];
  /** Injection point for tests; defaults to the real Tier-1 VM runner. */
  vmRunner?: Parameters<typeof verifyKernelFinding>[0]["vmRunner"];
  /** Custom logger; defaults to `console.log`. */
  logger?: (line: string) => void;
}

/** Default applier: `git apply` the diff via stdin against the tree. */
function gitApply(input: { tree: string; diff: string }): void {
  execFileSync("git", ["apply", "--whitespace=nowarn", "-"], {
    cwd: input.tree,
    input: input.diff,
    stdio: ["pipe", "ignore", "pipe"],
  });
}

/** Default reverter: `git apply -R`; swallow errors (best-effort cleanup). */
function gitApplyRevert(input: { tree: string; diff: string }): void {
  try {
    execFileSync("git", ["apply", "-R", "--whitespace=nowarn", "-"], {
      cwd: input.tree,
      input: input.diff,
      stdio: ["pipe", "ignore", "ignore"],
    });
  } catch {
    // best-effort revert
  }
}

function failed(
  status: PatchValidateStatus,
  reason: string,
  extra: Partial<PatchValidateResult> = {},
): PatchValidateResult {
  return { status, patchValidated: false, reason, ...extra };
}

/**
 * Generate a candidate fix for a reproduced kernel finding, apply it, rebuild
 * (cache-keyed by the patched fingerprint), and re-run the reproducer. Returns
 * `root_cause_confirmed` (with `patchValidated: true`) only when KASAN stops
 * firing under the patched build.
 *
 * Always reverts the applied patch before returning (the tree is left clean),
 * even on the confirmed path — validation must not mutate the caller's checkout.
 */
export async function validatePatchRemovesCrash(
  opts: PatchValidateOptions,
): Promise<PatchValidateResult> {
  const log = opts.logger ?? ((line: string) => console.log(line));
  const apply = opts.patchApplier ?? gitApply;
  const revert = opts.patchReverter ?? gitApplyRevert;

  // 1. Gather upstream-fix context (best-effort) so the patch generator can
  // mirror how the bug was really fixed upstream when it has been.
  let upstreamFixHint: string | undefined;
  if (isKernelGitTree(opts.kernelTree)) {
    const filePath = opts.finding.evidence?.request
      ?.match(/^([\w./\-+]+\.[ch])(?::\d+)?\s*$/m)?.[1];
    if (filePath) {
      const fixed = checkAlreadyFixed({ tree: opts.kernelTree, filePath });
      if (fixed.commits.length > 0) upstreamFixHint = fixed.reason;
    }
  }

  // 2. Generate the candidate patch.
  let patch: CandidatePatch | null;
  try {
    patch = await opts.patchGenerator({
      finding: opts.finding,
      reproducer: opts.reproducer,
      reproducerLang: opts.reproducerLang,
      crashDmesg: opts.crashDmesg,
      ...(upstreamFixHint ? { upstreamFixHint } : {}),
    });
  } catch (err) {
    return failed(
      "patch_generation_failed",
      `patch generator threw: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!patch || !patch.diff.trim()) {
    return failed("patch_generation_failed", "patch generator produced no diff");
  }

  // 3. Apply the patch to the tree.
  try {
    apply({ tree: opts.kernelTree, diff: patch.diff });
  } catch (err) {
    return failed(
      "patch_apply_failed",
      `git apply failed: ${err instanceof Error ? err.message : String(err)}`,
      { patch },
    );
  }

  try {
    // 4. Rebuild the patched kernel. The dirty tree yields a distinct cache key
    // (`git describe --dirty`), so the patched build never collides with the
    // unpatched one in the cache.
    let patchedCacheKey: string;
    try {
      const artifacts = prepareKernelVmArtifacts({
        kernelTree: opts.kernelTree,
        configProfile: opts.kernelConfig ?? "kasan",
        ...(opts.cacheDir ? { cacheDir: opts.cacheDir } : {}),
        // Force a fresh build: the cache key changes with the dirty tree, but we
        // never want to risk reusing an unpatched artifact for the patched run.
        force: true,
        logger: log,
        ...(opts.buildRunner ? { buildRunner: opts.buildRunner } : {}),
      });
      patchedCacheKey = artifacts.cacheKey;
    } catch (err) {
      return failed(
        "rebuild_failed",
        `patched kernel rebuild failed: ${err instanceof Error ? err.message : String(err)}`,
        { patch },
      );
    }

    // 5. Re-run the SAME reproducer against the patched build.
    const verdict = await verifyKernelFinding({
      reproducerPath: opts.reproducerLang === "c" ? opts.reproducerPath : undefined,
      syzProgramPath: opts.reproducerLang === "syz" ? opts.reproducerPath : undefined,
      kernelTree: opts.kernelTree,
      kernelConfig: opts.kernelConfig ?? "kasan",
      ...(opts.cacheDir ? { cacheDir: opts.cacheDir } : {}),
      ...(opts.expectedSignature ? { expectedSignature: opts.expectedSignature } : {}),
      logger: log,
      ...(opts.buildRunner ? { buildRunner: opts.buildRunner } : {}),
      ...(opts.vmRunner ? { vmRunner: opts.vmRunner } : {}),
    });

    // KASAN no longer fires (the reproducer ran but did not reproduce) ⇒ the
    // patch removed the defect: root cause confirmed. A `reproduced` re-run
    // means the patch did NOT address the real bug. `build_failed`/`run_failed`
    // is inconclusive — we cannot claim the patch fixed anything.
    if (verdict.status === "reproduced") {
      return {
        status: "not_root_cause",
        patchValidated: false,
        patch,
        patchedCacheKey,
        rerunStatus: verdict.status,
        reason:
          "KASAN still fires under the patched build — the candidate patch did " +
          "not address the root cause (wrong fix or incomplete fix)",
      };
    }
    if (verdict.status === "no_signal") {
      return {
        status: "root_cause_confirmed",
        patchValidated: true,
        patch,
        patchedCacheKey,
        rerunStatus: verdict.status,
        reason:
          "the same reproducer no longer trips KASAN under the patched build — " +
          "root cause confirmed (patch-as-oracle)",
      };
    }
    // build_failed / run_failed — inconclusive, never a confirmation.
    return failed(
      "rebuild_failed",
      `patched re-run was inconclusive (tier1 status=${verdict.status}); ` +
        "cannot confirm root cause",
      { patch, patchedCacheKey, rerunStatus: verdict.status },
    );
  } finally {
    // Always restore the tree — validation never leaves a dirty checkout.
    revert({ tree: opts.kernelTree, diff: patch.diff });
  }
}
