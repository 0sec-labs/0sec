import { execFileSync } from "node:child_process";

export const DEFAULT_GIT_CLONE_TIMEOUT_MS = 120_000;
export const MAX_GIT_CLONE_TIMEOUT_MS = 600_000;

/**
 * Resolve the optional cloud-provided clone deadline. The worker only sets it
 * for linux-kernel reviews; every other source clone retains the historical
 * two-minute ceiling.
 */
export function resolveGitCloneTimeoutMs(
  raw = process.env["0SEC_GIT_CLONE_TIMEOUT_MS"],
): number {
  if (raw == null || raw.trim() === "") return DEFAULT_GIT_CLONE_TIMEOUT_MS;

  const timeoutMs = Number(raw);
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < DEFAULT_GIT_CLONE_TIMEOUT_MS ||
    timeoutMs > MAX_GIT_CLONE_TIMEOUT_MS
  ) {
    throw new Error(
      `0SEC_GIT_CLONE_TIMEOUT_MS must be an integer between ${DEFAULT_GIT_CLONE_TIMEOUT_MS} and ${MAX_GIT_CLONE_TIMEOUT_MS}`,
    );
  }
  return timeoutMs;
}

/**
 * Source/kernel git targets can pin a version with the `<url>.git@<ref>`
 * convention (e.g. `https://github.com/torvalds/linux.git@v5.10`). Both clone
 * sites previously passed the whole string to `git clone`, which fails with
 * "Repository not found" because `linux.git@v5.10` is not a real URL.
 *
 * Parse the suffix off. The match requires `@` AFTER `.git`, so an SSH-style
 * `git@host:owner/repo.git` (where `@` precedes `.git`) never misfires.
 */
export function parseRepoRef(target: string): { url: string; ref?: string } {
  const m = /^(.+\.git)@(.+)$/.exec(target);
  if (m) return { url: m[1]!, ref: m[2]! };
  return { url: target };
}

/**
 * Clone a git target at depth 1, honoring an optional `@<ref>` version suffix
 * by passing `--branch <ref>` (works for tags and branches) instead of cloning
 * the default branch and never checking the pinned version out.
 */
export function cloneGitRepo(
  target: string,
  destDir: string,
  timeoutMs = resolveGitCloneTimeoutMs(),
): void {
  const { url, ref } = parseRepoRef(target);
  const args = ["clone", "--depth", "1"];
  if (ref) args.push("--branch", ref);
  args.push(url, destDir);
  execFileSync("git", args, { timeout: timeoutMs, stdio: "pipe" });
}
