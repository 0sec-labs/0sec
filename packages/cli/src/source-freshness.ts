import { execFileSync } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

declare const __PWNKIT_BUILD_COMMIT__: string;

const BYPASS_ENV = "PWNKIT_ALLOW_STALE_SOURCE_DIST";

type GitExec = (cwd: string, args: string[]) => string;

export interface SourceDistFreshnessOptions {
  entryUrl?: string;
  entryPath?: string;
  buildCommit?: string;
  env?: NodeJS.ProcessEnv;
  execGit?: GitExec;
}

export interface SourceDistFreshnessResult {
  stale: boolean;
  checked: boolean;
  reason?: string;
  repoRoot?: string;
  bundlePath?: string;
  buildCommit?: string;
  headCommit?: string;
  message?: string;
}

function currentBuildCommit(): string | undefined {
  if (typeof __PWNKIT_BUILD_COMMIT__ !== "undefined") {
    return __PWNKIT_BUILD_COMMIT__;
  }
  return undefined;
}

function normalizeCommit(value: string | undefined): string | undefined {
  const trimmed = value?.trim().toLowerCase();
  return trimmed && /^[0-9a-f]{40}$/.test(trimmed) ? trimmed : undefined;
}

function defaultExecGit(cwd: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
}

function sameRealPath(a: string, b: string): boolean {
  try {
    return realpathSync(a) === realpathSync(b);
  } catch {
    return false;
  }
}

export function checkSourceDistFreshness(
  opts: SourceDistFreshnessOptions = {},
): SourceDistFreshnessResult {
  const env = opts.env ?? process.env;
  if (env[BYPASS_ENV] === "1") {
    return { checked: false, stale: false, reason: "bypassed" };
  }

  const buildCommit = normalizeCommit(opts.buildCommit ?? currentBuildCommit());
  if (!buildCommit) {
    return { checked: false, stale: false, reason: "missing-build-commit" };
  }

  const bundlePath =
    opts.entryPath ??
    (opts.entryUrl ? fileURLToPath(opts.entryUrl) : fileURLToPath(import.meta.url));
  const realBundlePath = realpathSync(bundlePath);
  if (basename(realBundlePath) !== "pwnkit.js" || basename(dirname(realBundlePath)) !== "dist") {
    return { checked: false, stale: false, reason: "not-root-dist-bundle", bundlePath: realBundlePath };
  }

  const repoRoot = dirname(dirname(realBundlePath));
  if (!existsSync(join(repoRoot, ".git"))) {
    return { checked: false, stale: false, reason: "not-git-checkout", bundlePath: realBundlePath };
  }

  const execGit = opts.execGit ?? defaultExecGit;
  let gitRoot: string;
  let headCommit: string | undefined;
  try {
    gitRoot = execGit(repoRoot, ["rev-parse", "--show-toplevel"]);
    headCommit = normalizeCommit(execGit(repoRoot, ["rev-parse", "HEAD"]));
  } catch {
    return { checked: false, stale: false, reason: "git-unavailable", bundlePath: realBundlePath, repoRoot };
  }

  if (!sameRealPath(repoRoot, gitRoot) || !headCommit) {
    return { checked: false, stale: false, reason: "git-root-mismatch", bundlePath: realBundlePath, repoRoot };
  }

  if (buildCommit === headCommit) {
    return {
      checked: true,
      stale: false,
      bundlePath: realBundlePath,
      repoRoot,
      buildCommit,
      headCommit,
    };
  }

  const message = [
    "pwnkit source checkout bundle is stale.",
    `dist/pwnkit.js was built from ${buildCommit.slice(0, 12)}, but checkout HEAD is ${headCommit.slice(0, 12)}.`,
    `Run \`pnpm run build\` from ${repoRoot} before invoking dist/pwnkit.js.`,
    `Set ${BYPASS_ENV}=1 only if you intentionally want to run the stale bundle.`,
  ].join(" ");

  return {
    checked: true,
    stale: true,
    bundlePath: realBundlePath,
    repoRoot,
    buildCommit,
    headCommit,
    message,
  };
}

export function enforceSourceDistFreshness(opts: SourceDistFreshnessOptions = {}): void {
  const result = checkSourceDistFreshness(opts);
  if (!result.stale) return;
  console.error(result.message);
  process.exit(2);
}

