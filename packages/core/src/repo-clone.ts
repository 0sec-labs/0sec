import { execFileSync } from "node:child_process";

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
  timeoutMs = 120_000,
): void {
  const { url, ref } = parseRepoRef(target);
  const args = ["clone", "--depth", "1"];
  if (ref) args.push("--branch", ref);
  args.push(url, destDir);
  execFileSync("git", args, { timeout: timeoutMs, stdio: "pipe" });
}
