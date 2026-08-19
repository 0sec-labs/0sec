/**
 * kernel/fix-commit-intel.ts
 *
 * Kernel git-fix-commit intelligence — the shared primitive behind two
 * techniques the engine was missing on the `linux-kernel` path, and which
 * (empirically, 2026-06) accounted for both our best lead and our worst
 * wasted effort:
 *
 *   1. INCOMPLETE-FIX VARIANT HUNTING (find side). Mine recent `Fixes:`-tagged
 *      / security-keyworded commits, learn the function FAMILY each one touched,
 *      then surface sibling functions that look unguarded — the
 *      "encrypt path got the fix, decrypt sibling didn't" shape that surfaced a
 *      real netns-UAF in net/tipc/crypto.c. Breadth-first subsystem rotation
 *      never finds these; they only fall out of fix-diff analysis.
 *
 *   2. ALREADY-FIXED FALSE-POSITIVE GATE (verify side). Before spending a
 *      QEMU/KASAN boot on a kernel finding, check whether the cited function was
 *      fixed at/near HEAD by a recent commit. This auto-kills the "real bug, but
 *      patched N days ago" FP class that burned multiple verification cycles
 *      (e.g. a ksmbd UAF fixed 8 days before we re-found it; the skb
 *      shared-frag / "Fragnesia" cluster).
 *
 * Design: pure-ish and dependency-free — only shells read-only `git` against an
 * already-present local kernel tree, mirroring triage/kernel-vm-runner.ts. No
 * network, no new packages. Every function fails SOFT (empty / `unknown`) on a
 * non-git tree or a git error, so wiring it in can never harden a real finding
 * out of existence by accident — consistent with the repo's assume-FP triage
 * contract.
 */
import { execFileSync } from "node:child_process";

/** A commit that touched the queried scope and looks security-relevant. */
export interface FixCommit {
  sha: string;
  subject: string;
  /** committer date, ISO-8601. */
  dateIso: string;
  /** referenced commit hash from a `Fixes:` trailer, if the commit carried one. */
  fixesTag?: string;
  /** the security keyword (UAF / OOB / refcount / …) that matched, if any. */
  securityKeyword?: string;
}

/**
 * Keywords that mark a commit as plausibly closing a memory-safety / lifetime
 * defect. Lowercased substring match against subject + body.
 */
const SECURITY_KEYWORDS = [
  "use-after-free",
  "use after free",
  "uaf",
  "out-of-bounds",
  "out of bounds",
  "oob read",
  "oob write",
  "double-free",
  "double free",
  "refcount",
  "reference count",
  "data race",
  "race condition",
  "overflow",
  "underflow",
  "null deref",
  "null-ptr-deref",
  "null pointer",
  "uninitialized",
  "memory leak",
  "slab-out-of-bounds",
] as const;

const UNIT_SEP = "\x1f";
const RECORD_SEP = "\x1e";

function git(tree: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: tree,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    // Kernel history is large; a 3-month net/ window can be a few MB.
    maxBuffer: 128 * 1024 * 1024,
  });
}

/** True iff `tree` is the work tree of a real git repo (and git is usable). */
export function isKernelGitTree(tree: string): boolean {
  try {
    return git(tree, ["rev-parse", "--is-inside-work-tree"]).trim() === "true";
  } catch {
    return false;
  }
}

function matchSecurityKeyword(haystack: string): string | undefined {
  const lower = haystack.toLowerCase();
  for (const kw of SECURITY_KEYWORDS) {
    if (lower.includes(kw)) return kw;
  }
  return undefined;
}

/** Extract the referenced sha from a `Fixes: <sha> ("subject")` trailer. */
function extractFixesTag(body: string): string | undefined {
  const m = body.match(/^\s*Fixes:\s*([0-9a-f]{8,40})\b/im);
  return m ? m[1] : undefined;
}

function parseLogRecords(raw: string): FixCommit[] {
  const out: FixCommit[] = [];
  for (const record of raw.split(RECORD_SEP)) {
    const rec = record.trim();
    if (!rec) continue;
    const [sha = "", dateIso = "", subject = "", body = ""] = rec.split(UNIT_SEP);
    if (!sha) continue;
    const securityKeyword = matchSecurityKeyword(`${subject}\n${body}`);
    const fixesTag = extractFixesTag(body);
    out.push({
      sha: sha.trim(),
      dateIso: dateIso.trim(),
      subject: subject.trim(),
      ...(fixesTag ? { fixesTag } : {}),
      ...(securityKeyword ? { securityKeyword } : {}),
    });
  }
  return out;
}

export interface MineFixCommitsOptions {
  tree: string;
  /** git `--since` spec; default "3 months ago". */
  since?: string;
  /** path prefixes to scope the log to, e.g. ["net/tipc", "crypto"]. */
  paths?: string[];
  /** cap on commits scanned; default 400. */
  limit?: number;
  /** when true, keep only commits that look security-relevant (kw or Fixes:). */
  securityOnly?: boolean;
}

/**
 * Mine recent commits in a kernel tree (optionally scoped to `paths`). Returns
 * the security-relevant ones by default — the corpus an incomplete-fix hunt
 * walks to look for unguarded siblings. Fails soft (returns []) on any error.
 */
export function mineFixCommits(opts: MineFixCommitsOptions): FixCommit[] {
  const { tree } = opts;
  if (!isKernelGitTree(tree)) return [];
  const since = opts.since ?? "3 months ago";
  const limit = opts.limit ?? 400;
  const securityOnly = opts.securityOnly ?? true;

  const format = ["%H", "%cI", "%s", "%b"].join(UNIT_SEP) + RECORD_SEP;
  const args = [
    "log",
    `--since=${since}`,
    `--max-count=${limit}`,
    "--no-merges",
    `--pretty=format:${format}`,
  ];
  if (opts.paths && opts.paths.length > 0) {
    args.push("--", ...opts.paths);
  }

  let raw: string;
  try {
    raw = git(tree, args);
  } catch {
    return [];
  }

  const commits = parseLogRecords(raw);
  return securityOnly
    ? commits.filter((c) => c.securityKeyword || c.fixesTag)
    : commits;
}

export interface AlreadyFixedResult {
  /** true => the cited function/file was very likely fixed recently. */
  likelyFixed: boolean;
  /**
   * true => a recent security/`Fixes:` commit changed a line mentioning the
   * EXACT faulting function (pickaxe hit). This is the strong signal a consumer
   * should act on (skip the QEMU boot); a `likelyFixed` that is NOT
   * `functionLevelMatch` is only a file-level hint worth annotating.
   */
  functionLevelMatch: boolean;
  /** the commits that drove the verdict (most recent first). */
  commits: FixCommit[];
  /** human-readable one-liner for triage notes. */
  reason: string;
}

export interface CheckAlreadyFixedOptions {
  tree: string;
  /** the file the finding cites, repo-relative (e.g. "fs/smb/server/smb2pdu.c"). */
  filePath: string;
  /** the faulting function, if known (e.g. "smb2_remove_blocked_lock"). */
  faultingFunction?: string;
  /** git `--since` spec; default "3 months ago". */
  since?: string;
}

/**
 * Decide whether a kernel finding is likely already-fixed upstream — the
 * deterministic FP gate that runs BEFORE an expensive QEMU/KASAN boot.
 *
 * Strategy (read-only git against the local tree):
 *   - `git log --since -- <file>`: recent commits touching the file; flag the
 *     security-keyworded / `Fixes:`-tagged ones.
 *   - `git log -S<function> -- <file>`: commits that added/removed lines
 *     mentioning the function (the pickaxe) — catches a guard added right at the
 *     faulting site even when the subject is terse.
 *
 * `likelyFixed` is true when at least one recent commit both (a) touches the
 * cited file (and function, when given) and (b) reads as a security/lifetime
 * fix. Fails SOFT: a non-git tree or git error returns `likelyFixed: false`, so
 * this never suppresses a finding on infrastructure trouble.
 */
export function checkAlreadyFixed(
  opts: CheckAlreadyFixedOptions,
): AlreadyFixedResult {
  const { tree, filePath, faultingFunction } = opts;
  const since = opts.since ?? "3 months ago";

  if (!isKernelGitTree(tree) || !filePath) {
    return {
      likelyFixed: false,
      functionLevelMatch: false,
      commits: [],
      reason: "no git tree / file",
    };
  }

  const format = ["%H", "%cI", "%s", "%b"].join(UNIT_SEP) + RECORD_SEP;
  const byPath = (extraArgs: string[]): FixCommit[] => {
    try {
      return parseLogRecords(
        git(tree, [
          "log",
          `--since=${since}`,
          "--no-merges",
          `--pretty=format:${format}`,
          ...extraArgs,
          "--",
          filePath,
        ]),
      );
    } catch {
      return [];
    }
  };

  // (a) recent commits touching the file.
  const touchingFile = byPath([]);
  // (b) pickaxe on the function name. `-G` (not `-S`) matches commits whose
  // diff contains an added/removed line mentioning the function — the right
  // semantic for "a commit changed code at this function", independent of
  // whether the occurrence count changed.
  const touchingFn = faultingFunction
    ? byPath([`-G${faultingFunction}`])
    : [];

  // Dedup by sha, keep the security-relevant ones.
  const bySha = new Map<string, FixCommit>();
  for (const c of [...touchingFn, ...touchingFile]) {
    if (c.securityKeyword || c.fixesTag) bySha.set(c.sha, c);
  }
  const commits = [...bySha.values()].sort((a, b) =>
    b.dateIso.localeCompare(a.dateIso),
  );

  // A pickaxe hit on the exact function is the strongest signal; a generic
  // security commit on the file is weaker but still worth flagging for triage.
  const fnSecurityHit = touchingFn.find((c) => c.securityKeyword || c.fixesTag);
  const functionLevelMatch = Boolean(fnSecurityHit);
  const likelyFixed = functionLevelMatch || commits.length > 0;

  let reason: string;
  if (fnSecurityHit) {
    reason = `recent fix touches ${faultingFunction} in ${filePath}: ${fnSecurityHit.sha.slice(0, 12)} "${fnSecurityHit.subject}" (${fnSecurityHit.dateIso.slice(0, 10)})`;
  } else if (commits.length > 0) {
    reason = `recent security commit(s) on ${filePath}: ${commits[0].sha.slice(0, 12)} "${commits[0].subject}" (${commits[0].dateIso.slice(0, 10)})`;
  } else {
    reason = `no recent fix found for ${filePath} since ${since}`;
  }

  return { likelyFixed, functionLevelMatch, commits, reason };
}
