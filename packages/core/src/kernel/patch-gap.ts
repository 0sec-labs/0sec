/**
 * kernel/patch-gap.ts
 *
 * The kernelCTF **patch-gap 1day monitor**: combines the upstream CVE feed
 * (`patch-gap-feed.ts`), the target-tree presence check
 * (`patch-gap-check.ts`), and the kernelCTF COS-6.12 reachability gate
 * (`../stages/hunt-reachability.ts`, already grounded in
 * `services/orchestrator/src/kernelctf-config.ts`'s CONFIG_* facts) into one
 * ranked feed of `PatchGapCandidate`s ready to hand to the weaponize
 * pipeline (`runKernelExploitChain` / `USE_KERNEL_WEAPONIZE`).
 *
 * This is the winning kernelCTF shape: a security fix lands in mainline /
 * stable, the COS-6.12 target tree hasn't backported it yet — that gap
 * window is a LIVE 1day. Generic source-hunting (the engine's other kernel
 * stages) doesn't reason about "is this specific known fix present or
 * absent in the specific target tree", it looks for NEW bugs; this module
 * is the complementary, much cheaper technique of tracking KNOWN bugs
 * through the backport pipeline.
 *
 * Pure orchestration — no network. The feed is pre-loaded by the caller
 * (`loadVulnsFeedFromDir` for the real bench clone, or an in-memory array in
 * tests); the target-tree check takes an injectable `GitExec`.
 */

import { classifyPathReachability, type PathReachability } from "../stages/hunt-reachability.js";
import { checkFixPresentInTarget, defaultGitExec, type GitExec, type FixPresenceResult } from "./patch-gap-check.js";
import type { UpstreamFixEntry } from "./patch-gap-feed.js";

/** Cheap severity signal from the fix title/description — no CVSS in this feed, so this is a coarse tie-breaker, not a real severity score. */
const HIGH_SIGNAL_KEYWORDS = [
  "use-after-free",
  "use after free",
  "uaf",
  "out-of-bounds",
  "out of bounds",
  "double-free",
  "double free",
  "overflow",
  "underflow",
  "race",
  "null deref",
  "null-ptr-deref",
] as const;

function severityHint(title: string): "high" | "unknown" {
  const lower = title.toLowerCase();
  return HIGH_SIGNAL_KEYWORDS.some((kw) => lower.includes(kw)) ? "high" : "unknown";
}

/** Best-effort subsystem label from the first touched file — same "path prefix" vocabulary `classifyPathReachability` uses. */
function subsystemOf(files: readonly string[]): string {
  const first = files[0];
  if (!first) return "unknown";
  const segments = first.split("/");
  return segments.slice(0, 2).join("/");
}

/** One ranked patch-gap candidate — a known, upstream-fixed bug absent from the target tree and reachable on kernelCTF. */
export interface PatchGapCandidate {
  cve: string;
  /** The SHA surfaced as "the" fix for this candidate — the mainline commit when known, else the first per-branch backport SHA. */
  fixSha: string;
  title: string;
  files: string[];
  subsystem: string;
  reachable: PathReachability;
  severity: "high" | "unknown";
  /** Full presence-check detail (method, matched SHA if any, reason) for triage/audit. */
  presence: FixPresenceResult;
  /** Human-readable one-liner combining presence + reachability, ready for a log line or PR/report. */
  reason: string;
}

export interface PatchGapScanOptions {
  /** Path to the target tree to diff against, e.g. bench's `/root/linux-6.12.93`. */
  targetTreePath: string;
  /** Pre-loaded upstream fix entries (from `loadVulnsFeedFromDir` or an in-memory list in tests). */
  entries: readonly UpstreamFixEntry[];
  /** Injectable git exec (tests / non-default transport). Default: real local `git`. */
  gitExec?: GitExec;
  /**
   * Drop candidates whose subsystem isn't confirmed `"reachable"` on kernelCTF
   * COS (step 3 of the monitor: gate by reachability). Default `true` — an
   * unreachable-on-COS bug is real but not kernelCTF-eligible, and would
   * waste weaponize-pipeline compute. Set `false` to keep everything
   * (e.g. for a distro-only audit) with `reachable` still annotated per-entry.
   */
  reachableOnly?: boolean;
}

export interface PatchGapScanResult {
  /** Ranked candidates: `reachable` first, then `severity: "high"`, then newest CVE id. */
  candidates: PatchGapCandidate[];
  /** Entries whose fix was CONFIRMED present in the target tree (already backported — not a 1day). */
  skippedAlreadyFixed: number;
  /** Entries dropped by the reachability gate (only when `reachableOnly` is true). */
  skippedUnreachable: number;
  /** Total entries scanned. */
  total: number;
}

const REACHABILITY_RANK: Record<PathReachability, number> = { reachable: 0, unknown: 1, unreachable: 2 };
const SEVERITY_RANK: Record<"high" | "unknown", number> = { high: 0, unknown: 1 };

/**
 * Run the patch-gap monitor: for each upstream fix entry, check target-tree
 * presence, gate by kernelCTF reachability, and rank the survivors.
 */
export function scanForPatchGapCandidates(opts: PatchGapScanOptions): PatchGapScanResult {
  const exec = opts.gitExec ?? defaultGitExec;
  const reachableOnly = opts.reachableOnly ?? true;

  let skippedAlreadyFixed = 0;
  let skippedUnreachable = 0;
  const candidates: PatchGapCandidate[] = [];

  for (const entry of opts.entries) {
    const presence = checkFixPresentInTarget(entry, opts.targetTreePath, exec);
    if (presence.present) {
      skippedAlreadyFixed++;
      continue;
    }

    const reachable = classifyPathReachability(entry.files[0] ?? "");
    if (reachableOnly && reachable !== "reachable") {
      skippedUnreachable++;
      continue;
    }

    const severity = severityHint(entry.title);
    const fixSha = entry.mainlineSha ?? entry.candidateShas[0] ?? "unknown";
    candidates.push({
      cve: entry.cve,
      fixSha,
      title: entry.title,
      files: entry.files,
      subsystem: subsystemOf(entry.files),
      reachable,
      severity,
      presence,
      reason: `${entry.cve}: ${presence.reason} (kernelCTF reachability: ${reachable})`,
    });
  }

  candidates.sort((a, b) => {
    const byReach = REACHABILITY_RANK[a.reachable] - REACHABILITY_RANK[b.reachable];
    if (byReach !== 0) return byReach;
    const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (bySeverity !== 0) return bySeverity;
    return b.cve.localeCompare(a.cve);
  });

  return {
    candidates,
    skippedAlreadyFixed,
    skippedUnreachable,
    total: opts.entries.length,
  };
}
