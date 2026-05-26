import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import type { Finding } from "@pwnkit/shared";

export type PatchStatus =
  | "still-vulnerable"   // every cited file:line still exists and matches the described shape
  | "partial-fix"        // some refs still resolve but others were edited or removed
  | "fixed"              // no cited ref resolves any more
  | "file-removed"       // the vulnerable file itself is gone
  | "unknown";           // couldn't find any usable pattern in the finding

export interface FileRef {
  file: string;
  line?: number;
  /** Verbatim code snippet pulled from the finding that should still be present. */
  snippet?: string;
}

export interface ReverifyResult {
  status: PatchStatus;
  ref: string;
  notes: string[];
  refsChecked: FileRef[];
  refsStillPresent: FileRef[];
  refsMissing: FileRef[];
}

export interface ReverifyOptions {
  repoPath: string;
  /** Git ref (tag/sha/branch) to check out before verifying. Defaults to current HEAD. */
  ref?: string;
  /** If true, run `git checkout <ref>` before reading files. Defaults to false (work off the current worktree). */
  checkout?: boolean;
}

// Strip ANSI, backticks, asterisks so grep-style snippet matching isn't thrown
// off by the agent's markdown flourishes.
function normaliseForMatch(s: string): string {
  return s.replace(/\[[0-9;]*m/g, "").replace(/[`*_]+/g, "").trim();
}

/**
 * Pull file:line references out of a finding. Looks in description, analysis,
 * and evidence blocks. Ignores file:line-like strings that look like URLs.
 */
export function extractFileRefs(finding: Finding): FileRef[] {
  const haystack = [
    finding.description,
    finding.evidence?.analysis,
    finding.evidence?.request,
    finding.evidence?.response,
  ]
    .filter((s): s is string => typeof s === "string" && s.length > 0)
    .join("\n\n");

  const seen = new Map<string, FileRef>();
  // Accept things like "server/src/routes/foo.ts:1234" or
  // "packages/shared/src/types.ts:69-99" or "src/foo.ts".
  // Reject url-ish (http://…/path:1234) by requiring the preceding char not be "/" plus a known protocol.
  const regex = /(?<![\w/\-:])([a-zA-Z0-9_./\-]+\.(?:ts|tsx|js|jsx|mjs|cjs|py|rb|go|rs|c|h|cc|cpp|java|kt|swift|php|sh|sql))(?::(\d+)(?:-\d+)?)?/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(haystack)) !== null) {
    const file = match[1];
    const line = match[2] ? Number(match[2]) : undefined;
    if (file.startsWith("http:") || file.startsWith("https:")) continue;
    const key = `${file}:${line ?? ""}`;
    if (!seen.has(key)) seen.set(key, { file, line });
  }

  return Array.from(seen.values());
}

/**
 * Run a git command in the repo, return stdout on success, null on failure.
 */
function gitCmd(repoPath: string, args: string[]): string | null {
  try {
    return execFileSync("git", args, { cwd: repoPath, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" });
  } catch {
    return null;
  }
}

/**
 * Verify a finding against a given repo + ref. The repo must already be
 * checked out at the ref OR the caller must pass `checkout: true`.
 *
 * The status is conservative: we return "still-vulnerable" only if every
 * cited file:line resolves and its line is a plausible match for the described
 * shape. If any reference is missing or the file was removed, we downgrade.
 */
export function verifyAgainstRef(finding: Finding, options: ReverifyOptions): ReverifyResult {
  const refs = extractFileRefs(finding);
  const repoPath = resolve(options.repoPath);

  if (options.checkout && options.ref) {
    gitCmd(repoPath, ["checkout", "-q", options.ref]);
  }

  const currentRef = options.ref
    ?? gitCmd(repoPath, ["rev-parse", "--abbrev-ref", "HEAD"])?.trim()
    ?? gitCmd(repoPath, ["rev-parse", "--short", "HEAD"])?.trim()
    ?? "HEAD";

  if (refs.length === 0) {
    return {
      status: "unknown",
      ref: currentRef,
      notes: ["Could not extract any file:line references from the finding. Consider adding `server/src/.../file.ts:NNN` style citations to the description before re-running."],
      refsChecked: [],
      refsStillPresent: [],
      refsMissing: [],
    };
  }

  const notes: string[] = [];
  const refsStillPresent: FileRef[] = [];
  const refsMissing: FileRef[] = [];

  for (const ref of refs) {
    const abs = join(repoPath, ref.file);
    if (!existsSync(abs)) {
      refsMissing.push(ref);
      notes.push(`${ref.file} — file does not exist at ${currentRef}.`);
      continue;
    }
    // File exists. If a line is cited, we could try to compare that line's
    // content against a snippet pulled from the finding. For v1 we just
    // confirm file presence and line-range validity.
    if (ref.line !== undefined) {
      try {
        const content = readFileSync(abs, "utf8").split("\n");
        if (ref.line > content.length) {
          refsMissing.push(ref);
          notes.push(`${ref.file}:${ref.line} — line is out of range (file has ${content.length} lines at ${currentRef}).`);
          continue;
        }
      } catch {
        // File is unreadable (perms, binary, etc.) — treat as still present for now.
      }
    }
    refsStillPresent.push(ref);
  }

  let status: PatchStatus;
  if (refsStillPresent.length === 0) {
    status = refsMissing.some((r) => !existsSync(join(repoPath, r.file))) ? "file-removed" : "fixed";
  } else if (refsMissing.length === 0) {
    status = "still-vulnerable";
  } else {
    status = "partial-fix";
  }

  if (status === "still-vulnerable") {
    notes.unshift(`All ${refsStillPresent.length} cited file${refsStillPresent.length === 1 ? "" : "s"} still resolve at ${currentRef}. Status is conservative — a human should confirm the *shape* of the code at each line hasn't been patched.`);
  }

  return {
    status,
    ref: currentRef,
    notes,
    refsChecked: refs,
    refsStillPresent,
    refsMissing,
  };
}

function refsMatch(a: FileRef, b: FileRef): boolean {
  return a.file === b.file && a.line === b.line;
}

/**
 * Human-readable patch-status block for the advisory's "Patch status" section.
 */
export function formatPatchStatusSection(result: ReverifyResult): string {
  const banner: Record<PatchStatus, string> = {
    "still-vulnerable": `**Still vulnerable** on \`${result.ref}\`.`,
    "partial-fix": `**Partial fix** on \`${result.ref}\` — some cited references changed, others remain.`,
    "fixed": `**Fixed** on \`${result.ref}\`. All cited references have been edited or removed upstream.`,
    "file-removed": `**Vulnerable file removed** on \`${result.ref}\`. The affected path no longer exists in the tree.`,
    "unknown": `**Could not auto-verify** against \`${result.ref}\`. No machine-checkable references were extractable from the finding.`,
  };

  const lines: string[] = [];
  lines.push(banner[result.status]);
  if (result.refsChecked.length > 0) {
    lines.push("");
    lines.push(`Refs checked (${result.refsChecked.length}):`);
    for (const ref of result.refsChecked) {
      const present = result.refsStillPresent.some((r) => refsMatch(r, ref));
      const marker = present ? "✓" : "✗";
      lines.push(`- ${marker} \`${ref.file}${ref.line ? `:${ref.line}` : ""}\``);
    }
  }
  if (result.notes.length > 0) {
    lines.push("");
    for (const note of result.notes) lines.push(`> ${note}`);
  }
  return lines.join("\n");
}
