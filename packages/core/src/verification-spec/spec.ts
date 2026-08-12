// pwnkit#193 / pwnkit-cloud#111 — deterministic finding re-verification.
//
// `evaluateVerificationSpec` runs a finding's `VerificationSpec.code[]`
// predicates against a target repo on disk and reports whether the finding
// is still real. It is intentionally *cheap*: no LLM calls, no target
// provisioning, no network. Cloud's canary watcher calls this on every
// upstream HEAD refresh; the OSS engine emits the spec when it produces a
// finding so that re-evaluation later is deterministic.
//
// Behavioural predicates (`VerificationSpec.behavior`) require a provisioned
// target and are out of scope here — the helper short-circuits with a stable
// `behavior eval not yet supported` reason.

import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, isAbsolute, normalize, sep } from "node:path";
import { promisify } from "node:util";
import type {
  VerificationCodePredicate,
  VerificationSpec,
} from "@pwnkit/shared";

const execFileAsync = promisify(execFile);
const MAX_GIT_DIFF_BYTES = 1_000_000;
const GIT_CHECK_TIMEOUT_MS = 5_000;
const FULL_GIT_OBJECT_ID_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;

/**
 * Result of a single predicate evaluation. `passed === true` means the
 * predicate held; `false` means it was definitely violated; `null` means
 * it could not be evaluated (file missing, regex invalid, etc.) and the
 * caller should treat it conservatively.
 */
export interface PredicateResult {
  predicate: VerificationCodePredicate;
  passed: boolean;
  /** Short, stable, human-readable explanation. */
  reason: string;
}

/**
 * Aggregate verification result. `passed === true` only when every code-level
 * predicate held. `failedPredicates` lists the ones that did not (including
 * predicates that could not be evaluated).
 */
export interface VerificationResult {
  passed: boolean;
  failedPredicates: PredicateResult[];
  /**
   * Optional top-level reason. Populated for short-circuit cases:
   *  - empty `code[]` and no `behavior` → "no predicates"
   *  - `behavior` present → "behavior eval not yet supported"
   * For normal evaluations, this is undefined and the per-predicate reasons
   * carry the detail.
   */
  reason?: string;
}

/**
 * Maximum length of a regex pattern the verifier will compile. Verification
 * specs are produced by an LLM and consumed by a long-running canary watcher
 * — a single pathological pattern (e.g. `(a+)+$`) on a large file is enough
 * to stall the worker for minutes via catastrophic backtracking. The bound
 * here is a defence-in-depth complement to the file-size cap below: it
 * rejects most ReDoS-prone inputs before they ever reach the regex engine.
 */
const MAX_PATTERN_LENGTH = 512;

/**
 * Maximum file size (bytes) the verifier will read into memory for pattern
 * matching. Files above this cap short-circuit with a stable reason. 1 MB
 * is generous for the kinds of source files specs target (TS/JS/Py/Go) and
 * keeps regex matching cost predictable. Combined with `MAX_PATTERN_LENGTH`,
 * this caps the worst-case runtime of a single predicate.
 */
const MAX_FILE_BYTES = 1_000_000;

/**
 * Resolve a repo-relative path against `repoRoot`. Refuses to escape the
 * root via `..` segments or absolute paths — same defence-in-depth pattern
 * the agent's `read_file` uses, so that a malicious finding can't be made
 * to read `/etc/passwd` on a verifier host. Returns null on rejection.
 *
 * NOTE: the lexical check here is necessary but not sufficient — symlinks
 * inside the repo can still resolve outside it. Use {@link checkRepoBoundary}
 * before any actual filesystem read to enforce the boundary on the resolved
 * target.
 */
function resolveRepoPath(repoRoot: string, file: string): string | null {
  if (typeof file !== "string" || file.length === 0) return null;
  // Reject absolute paths outright. The spec is a contract about a target
  // repo's tree; absolute paths belong to nobody.
  if (isAbsolute(file)) return null;
  const root = resolve(repoRoot);
  const candidate = resolve(root, file);
  const normalized = normalize(candidate);
  // Ensure the candidate is *under* root (or equal to it). Use `sep` so the
  // boundary check works on both posix and win32.
  if (normalized !== root && !normalized.startsWith(root + sep)) {
    return null;
  }
  return normalized;
}

/**
 * Outcome of the realpath-based boundary check. We distinguish three cases
 * so the caller can produce a stable, accurate reason string:
 *   - `inside`: target resolves under the repo root → safe to read.
 *   - `missing`: path entry does not exist (no symlink, no file).
 *     Callers surface this as "file not found", same as the pre-symlink-
 *     hardening behaviour.
 *   - `outside`: path entry exists but resolves outside the repo root
 *     (escaping symlink, broken symlink, dangling chain). Callers refuse
 *     the read with "path resolves outside repo root".
 */
type RepoBoundaryOutcome = "inside" | "missing" | "outside";

/**
 * Defence-in-depth boundary check that resolves symlinks before comparing
 * paths. `resolveRepoPath` already rejects lexical escapes (`..`, absolute
 * paths); this helper covers the case where a symlink *inside* the repo
 * points *outside* it.
 *
 * Distinguishes a genuinely missing path (no entry at all) from one that
 * exists but resolves outside the repo, so callers can keep the legacy
 * "file not found" reason for missing files while flipping escapes to
 * "path resolves outside repo root".
 */
async function checkRepoBoundary(
  repoRoot: string,
  absPath: string,
): Promise<RepoBoundaryOutcome> {
  // `lstat` succeeds on broken symlinks (it doesn't follow them), so a
  // failure here means the path entry itself doesn't exist.
  try {
    await fs.lstat(absPath);
  } catch {
    return "missing";
  }
  try {
    const [realRoot, realTarget] = await Promise.all([
      fs.realpath(repoRoot),
      fs.realpath(absPath),
    ]);
    if (realTarget === realRoot || realTarget.startsWith(realRoot + sep)) {
      return "inside";
    }
    return "outside";
  } catch {
    // The path entry exists (lstat succeeded) but realpath couldn't
    // resolve it — broken symlink, dangling chain, or EACCES on a parent.
    // Conservatively treat as outside so we never read it.
    return "outside";
  }
}

/**
 * Build a RegExp from a pattern + optional flags string. Returns null on
 * invalid regex OR when the pattern exceeds {@link MAX_PATTERN_LENGTH}.
 * The verifier never throws on malformed predicates — a bad or oversized
 * regex flips the predicate to `passed: false` with a clear reason.
 */
function safeRegex(pattern: string, flags?: string): RegExp | null {
  if (typeof pattern !== "string") return null;
  if (pattern.length > MAX_PATTERN_LENGTH) return null;
  try {
    return new RegExp(pattern, flags);
  } catch {
    return null;
  }
}

/**
 * Read a file into memory, capped at {@link MAX_FILE_BYTES}. Returns null
 * for missing/unreadable/oversized files so the caller surfaces a stable
 * "file not found or unreadable" reason rather than running a regex over
 * a multi-megabyte blob.
 */
async function readFileSafe(absPath: string): Promise<string | null> {
  try {
    const stat = await fs.stat(absPath);
    if (!stat.isFile()) return null;
    if (stat.size > MAX_FILE_BYTES) return null;
    return await fs.readFile(absPath, "utf8");
  } catch {
    return null;
  }
}

async function fileExists(absPath: string): Promise<boolean> {
  try {
    await fs.access(absPath);
    return true;
  } catch {
    return false;
  }
}

async function evaluateGitDiffApplies(
  predicate: Extract<VerificationCodePredicate, { kind: "git-diff-applies" }>,
  repoRoot: string,
): Promise<PredicateResult> {
  if (predicate.diff.trim().length === 0) {
    return { predicate, passed: false, reason: "git diff is empty" };
  }
  if (Buffer.byteLength(predicate.diff, "utf8") > MAX_GIT_DIFF_BYTES) {
    return {
      predicate,
      passed: false,
      reason: `git diff exceeds ${MAX_GIT_DIFF_BYTES} bytes`,
    };
  }
  if (!FULL_GIT_OBJECT_ID_RE.test(predicate.baseCommit)) {
    return { predicate, passed: false, reason: "invalid git base commit" };
  }

  let head: string;
  try {
    const result = await execFileAsync("git", ["rev-parse", "--verify", "HEAD"], {
      cwd: repoRoot,
      timeout: GIT_CHECK_TIMEOUT_MS,
      maxBuffer: 4096,
    });
    head = result.stdout.trim();
  } catch {
    return {
      predicate,
      passed: false,
      reason: "git repository HEAD unavailable",
    };
  }

  if (head.toLowerCase() !== predicate.baseCommit.toLowerCase()) {
    return {
      predicate,
      passed: false,
      reason: "git HEAD does not match diff base commit",
    };
  }

  let tempDir: string | undefined;
  try {
    tempDir = await fs.mkdtemp(join(tmpdir(), "pwnkit-verify-diff-"));
    const patchPath = join(tempDir, "evidence.patch");
    await fs.writeFile(patchPath, predicate.diff, { encoding: "utf8", mode: 0o600 });
    await execFileAsync(
      "git",
      ["apply", "--check", "--whitespace=nowarn", "--", patchPath],
      {
        cwd: repoRoot,
        timeout: GIT_CHECK_TIMEOUT_MS,
        maxBuffer: 65_536,
      },
    );
    return {
      predicate,
      passed: true,
      reason: "git diff applies cleanly",
    };
  } catch {
    // Do not surface `git apply` stderr: both the diff and target filenames may
    // be attacker-influenced. The stable reason is enough for callers.
    return {
      predicate,
      passed: false,
      reason: "git diff does not apply cleanly",
    };
  } finally {
    if (tempDir) {
      try {
        await fs.rm(tempDir, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup; a stale private tmp directory is harmless.
      }
    }
  }
}

async function evaluateOne(
  predicate: VerificationCodePredicate,
  repoRoot: string,
): Promise<PredicateResult> {
  switch (predicate.kind) {
    case "file-exists": {
      const abs = resolveRepoPath(repoRoot, predicate.file);
      if (!abs) {
        return {
          predicate,
          passed: false,
          reason: `path escapes repo root or is invalid: ${predicate.file}`,
        };
      }
      const outcome = await checkRepoBoundary(repoRoot, abs);
      if (outcome === "outside") {
        // Symlink-traversal guard: a symlink inside the repo whose real
        // target lives outside it must not be reported as "exists".
        return {
          predicate,
          passed: false,
          reason: `path resolves outside repo root: ${predicate.file}`,
        };
      }
      const ok = outcome === "inside";
      return {
        predicate,
        passed: ok,
        reason: ok ? "file exists" : `file not found: ${predicate.file}`,
      };
    }

    case "file-contains": {
      const abs = resolveRepoPath(repoRoot, predicate.file);
      if (!abs) {
        return {
          predicate,
          passed: false,
          reason: `path escapes repo root or is invalid: ${predicate.file}`,
        };
      }
      const outcome = await checkRepoBoundary(repoRoot, abs);
      if (outcome === "outside") {
        // Symlink-traversal guard before any read. Predicate fails closed
        // when the resolved target lives outside the repo root.
        return {
          predicate,
          passed: false,
          reason: `path resolves outside repo root: ${predicate.file}`,
        };
      }
      if (outcome === "missing") {
        return {
          predicate,
          passed: false,
          reason: `file not found or unreadable: ${predicate.file}`,
        };
      }
      const content = await readFileSafe(abs);
      if (content === null) {
        return {
          predicate,
          passed: false,
          reason: `file not found or unreadable: ${predicate.file}`,
        };
      }
      const re = safeRegex(predicate.pattern, predicate.flags);
      if (!re) {
        return {
          predicate,
          passed: false,
          reason: `invalid regex: /${predicate.pattern}/${predicate.flags ?? ""}`,
        };
      }
      const matched = re.test(content);
      return {
        predicate,
        passed: matched,
        reason: matched
          ? `pattern matched in ${predicate.file}`
          : `pattern not found in ${predicate.file}`,
      };
    }

    case "file-missing-pattern": {
      const abs = resolveRepoPath(repoRoot, predicate.file);
      if (!abs) {
        return {
          predicate,
          passed: false,
          reason: `path escapes repo root or is invalid: ${predicate.file}`,
        };
      }
      const outcome = await checkRepoBoundary(repoRoot, abs);
      if (outcome === "outside") {
        // Symlink-traversal guard before any read. Otherwise the predicate
        // becomes a confirmed-presence oracle for arbitrary files outside
        // the repo (passed=true means "pattern absent in /etc/passwd").
        return {
          predicate,
          passed: false,
          reason: `path resolves outside repo root: ${predicate.file}`,
        };
      }
      if (outcome === "missing") {
        // Conservative: missing file means we can't assert the pattern is
        // absent in any meaningful sense. Treat as failed so the finding
        // surfaces as `partial-fix` rather than silently passing.
        return {
          predicate,
          passed: false,
          reason: `file not found or unreadable: ${predicate.file}`,
        };
      }
      const content = await readFileSafe(abs);
      if (content === null) {
        // Conservative: missing file means we can't assert the pattern is
        // absent in any meaningful sense. Treat as failed so the finding
        // surfaces as `partial-fix` rather than silently passing.
        return {
          predicate,
          passed: false,
          reason: `file not found or unreadable: ${predicate.file}`,
        };
      }
      const re = safeRegex(predicate.pattern, predicate.flags);
      if (!re) {
        return {
          predicate,
          passed: false,
          reason: `invalid regex: /${predicate.pattern}/${predicate.flags ?? ""}`,
        };
      }
      const matched = re.test(content);
      return {
        predicate,
        passed: !matched,
        reason: matched
          ? `pattern unexpectedly present in ${predicate.file}`
          : `pattern absent in ${predicate.file}`,
      };
    }


    case "git-diff-applies":
      return evaluateGitDiffApplies(predicate, repoRoot);
    case "ast-shape": {
      // Tree-sitter not yet wired in as a runtime dep. The conservative
      // contract is: an unimplemented predicate cannot prove the finding
      // is fixed, so we mark it as failed with a stable reason. Cloud's
      // watcher can downgrade this case to `unknown` rather than treating
      // it as a hard partial-fix; the OSS verifier just reports facts.
      return {
        predicate,
        passed: false,
        reason: "ast-shape predicates are not yet implemented in the OSS verifier",
      };
    }
    default: {
      // Exhaustiveness guard. If a new predicate kind is added to the
      // discriminated union without a case here, this branch becomes a
      // type error at compile time.
      const _exhaustive: never = predicate;
      void _exhaustive;
      return {
        predicate: predicate as VerificationCodePredicate,
        passed: false,
        reason: "unknown predicate kind",
      };
    }
  }
}

/**
 * Evaluate a {@link VerificationSpec} against `repoRoot` on disk.
 *
 * - Every `code[]` predicate is evaluated. The aggregate `passed` is true
 *   iff every predicate held and at least one predicate actually describes
 *   the vulnerable state. `git-diff-applies` validates artifact compatibility
 *   only, so it cannot establish a positive verdict on its own.
 * - `failedPredicates` is the list of predicates whose `passed` was false
 *   (for caller-side rendering: "these predicates flipped → finding is
 *   partial-fix").
 * - When `spec.behavior` is present, this helper does NOT attempt to run
 *   it; it returns the code-level result with `reason` set to a stable
 *   "behavior eval not yet supported" string. Callers that need
 *   behavioural verification should dispatch separately.
 *
 * No exceptions are thrown for normal failure modes (missing files, bad
 * regex, path escapes). Every failure is a structured PredicateResult.
 */
export async function evaluateVerificationSpec(
  spec: VerificationSpec,
  repoRoot: string,
): Promise<VerificationResult> {
  const results: PredicateResult[] = [];
  for (const predicate of spec.code) {
    results.push(await evaluateOne(predicate, repoRoot));
  }

  const failedPredicates = results.filter((r) => !r.passed);

  const hasVulnerabilityPredicate = spec.code.some(
    (predicate) => predicate.kind !== "git-diff-applies",
  );

  // An artifact receipt alone says nothing about whether the target remains
  // vulnerable. Preserve the receipt result, but prevent callers from reading
  // source compatibility as proof of exploitation.
  if (!hasVulnerabilityPredicate && !spec.behavior) {
    return {
      passed: false,
      failedPredicates,
      reason: spec.code.length === 0 ? "no predicates" : "no vulnerability predicates",
    };
  }

  const codePassed = failedPredicates.length === 0 && hasVulnerabilityPredicate;

  if (spec.behavior) {
    // Code-level passed and a behavioural step exists: we can't actually
    // run it here. Surface the limitation rather than silently claiming
    // "still vulnerable". Callers should treat this as inconclusive
    // pending a behavioural runner.
    return {
      passed: codePassed,
      failedPredicates,
      reason: "behavior eval not yet supported",
    };
  }

  return {
    passed: codePassed,
    failedPredicates,
  };
}
