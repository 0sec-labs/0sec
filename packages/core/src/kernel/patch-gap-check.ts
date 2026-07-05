/**
 * kernel/patch-gap-check.ts
 *
 * Answers ONE question per upstream fix: is this fix already present in the
 * target tree (e.g. kernelCTF's COS-6.12 checkout)? Absent => the target is
 * still vulnerable in the gap window — a live 1day.
 *
 * Two independent checks, either of which confirms "present":
 *
 *   1. ANCESTOR — `git merge-base --is-ancestor <sha> HEAD`. Works when the
 *      target tree's history literally contains the fix commit OBJECT (true
 *      for a straight stable-branch merge, and covers the case where the
 *      target directly merged the mainline commit rather than a cherry-pick).
 *
 *   2. CHERRY-PICK REFERENCE — stable-branch cherry-picks get a NEW commit
 *      SHA (different object) but conventionally carry a trailer line
 *      `commit <mainline-sha> upstream.` pointing back at the ORIGINAL
 *      mainline commit. If the target independently backported the same fix
 *      (its own cherry-pick, its own new SHA), the ancestor check above
 *      can't see it — but its commit message still carries that trailer with
 *      the SAME mainline SHA the CVE feed's "(cherry picked from commit X)"
 *      description note gives us. Searching the target's log for that
 *      trailer string catches this case.
 *
 * Mirrors the safety contract in
 * `services/worker-controller/src/runners/verify-target-fix-check.ts`: this
 * is a pure OPTIMIZATION signal, not a source of a false negative. `present`
 * is `true` ONLY on a confirmed match (clean git exit). A malformed SHA, a
 * missing/non-git tree, or a git error all resolve to `present: false` —
 * i.e. we NEVER silently drop a real 1day candidate because a git call
 * hiccupped; worst case a genuinely-already-fixed entry slips through as a
 * candidate and gets caught later by the (much more expensive) weaponize/
 * verify stage instead.
 */

import { execFileSync } from "node:child_process";
import type { UpstreamFixEntry } from "./patch-gap-feed.js";

const SHA_RE = /^[0-9a-f]{7,40}$/i;

/** Injected git exec — sync, throws on non-zero exit. Same shape as `execFileSync`'s contract, so the default is a one-line wrapper and tests can substitute a pure fake. */
export type GitExec = (treePath: string, args: string[]) => string;

/** Default `GitExec`: shell real `git` against a local tree (bench runs the target trees locally — no ssh hop needed inside this module). */
export const defaultGitExec: GitExec = (treePath, args) =>
  execFileSync("git", args, {
    cwd: treePath,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    maxBuffer: 16 * 1024 * 1024,
  });

/** Which check (if any) confirmed the fix is present. */
export type FixPresenceMethod = "ancestor-sha" | "cherry-pick-reference" | "none";

export interface FixPresenceResult {
  /** true ONLY on a confirmed ancestor or cherry-pick-reference match. */
  present: boolean;
  method: FixPresenceMethod;
  /** the SHA that produced the match, when `present` is true. */
  matchedSha?: string;
  /** human-readable, always set — surfaced in candidate `reason` / triage notes. */
  reason: string;
}

/**
 * True iff `treePath` is a real git work tree, per the SAME injected `exec`
 * the rest of this module uses (deliberately re-probed here rather than
 * reusing `fix-commit-intel.ts`'s `isKernelGitTree`, which always shells a
 * real `git` process — that would make the exec injection seam a lie: a
 * test could swap in a fake `exec` for the ancestor/log calls yet still hit
 * a real git process for this one guard).
 */
function isGitTree(exec: GitExec, treePath: string): boolean {
  try {
    return exec(treePath, ["rev-parse", "--is-inside-work-tree"]).trim() === "true";
  } catch {
    return false;
  }
}

/** True iff `sha` is an ancestor of HEAD in `treePath` (a CONFIRMED, exit-0 result — anything else, including an error, is `false`). */
function isAncestor(exec: GitExec, treePath: string, sha: string): boolean {
  try {
    exec(treePath, ["merge-base", "--is-ancestor", sha, "HEAD"]);
    return true;
  } catch {
    return false;
  }
}

/** True iff the target's log contains a commit whose message carries the `commit <mainlineSha> upstream.` trailer (the stable-cherry-pick provenance line). */
function hasCherryPickReference(exec: GitExec, treePath: string, mainlineSha: string): boolean {
  try {
    const out = exec(treePath, [
      "log",
      "--all",
      "--fixed-strings",
      `--grep=commit ${mainlineSha} upstream.`,
      "--pretty=format:%H",
    ]);
    return out.trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * Check whether `entry`'s fix is already present in `treePath`. See the
 * module doc for the two-check strategy and the fail-soft contract.
 */
export function checkFixPresentInTarget(
  entry: UpstreamFixEntry,
  treePath: string,
  exec: GitExec = defaultGitExec,
): FixPresenceResult {
  if (!isGitTree(exec, treePath)) {
    return {
      present: false,
      method: "none",
      reason: `${treePath} is not a git work tree — presence check skipped, treating as absent (candidate)`,
    };
  }

  // 1. Ancestor check: mainline SHA first (the fix commit itself, if the
  //    target ever merges upstream directly), then every per-branch backport
  //    SHA the feed lists.
  const ancestorCandidates = [entry.mainlineSha, ...entry.candidateShas].filter(
    (s): s is string => typeof s === "string" && SHA_RE.test(s),
  );
  for (const sha of ancestorCandidates) {
    if (isAncestor(exec, treePath, sha)) {
      return {
        present: true,
        method: "ancestor-sha",
        matchedSha: sha,
        reason: `fix commit ${sha} is an ancestor of HEAD in ${treePath} — already backported, not a 1day`,
      };
    }
  }

  // 2. Cherry-pick reference: the target may carry its OWN backport commit
  //    (a different SHA) that still cites the mainline commit in its
  //    "commit X upstream." trailer.
  if (entry.mainlineSha && SHA_RE.test(entry.mainlineSha)) {
    if (hasCherryPickReference(exec, treePath, entry.mainlineSha)) {
      return {
        present: true,
        method: "cherry-pick-reference",
        matchedSha: entry.mainlineSha,
        reason:
          `${treePath} has a commit referencing "commit ${entry.mainlineSha} upstream." — ` +
          `independently backported (new SHA, same mainline fix) — already backported, not a 1day`,
      };
    }
  }

  return {
    present: false,
    method: "none",
    reason:
      ancestorCandidates.length > 0 || entry.mainlineSha
        ? `no ancestor match and no cherry-pick-reference match in ${treePath} — fix absent, live 1day candidate`
        : `entry carries no checkable SHA — treated as absent (candidate) rather than silently dropped`,
  };
}
