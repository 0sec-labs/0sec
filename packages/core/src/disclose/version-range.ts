import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import type { Finding } from "@0sec/shared";
import { extractFileRefs, type FileRef } from "./canary.js";

export interface VersionRangeResult {
  /** Tags (newest first) where every cited file:line still resolves — i.e. the finding is present. */
  affectedTags: string[];
  /** Earliest tag where the finding is still present (= "introduced in" lower bound). */
  introducedIn?: string;
  /** First tag (newest-first walk) where at least one cited file is gone. null if never. */
  fixedIn?: string;
  /** true when the pattern resolves at the repo's current HEAD. */
  presentOnHead: boolean;
  status: "present-on-head" | "removed-upstream" | "indeterminate" | "no-tags";
  notes: string[];
}

export interface VersionRangeOptions {
  repoPath: string;
  /** Max number of tags to walk from newest to oldest. Default 30. */
  tagLimit?: number;
  /** Optional filter: only consider tags that match this glob. */
  tagGlob?: string;
}

function gitCmd(repoPath: string, args: string[]): string | null {
  try {
    return execFileSync("git", args, {
      cwd: repoPath,
      stdio: ["ignore", "pipe", "pipe"],
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
    }).trim();
  } catch {
    return null;
  }
}

/**
 * List tags sorted newest-first. Prefer semver-ish version ordering (`-v:refname`)
 * so rapidly-created tags that share a creator-date second still sort stably.
 * Falls back to creator-date if version ordering yields nothing (non-semver tags).
 */
function listTags(repoPath: string, limit: number, glob?: string): string[] {
  const baseArgs = ["tag"];
  if (glob) baseArgs.push("-l", glob);
  const byVersion = gitCmd(repoPath, [...baseArgs, "--sort=-v:refname"]);
  if (byVersion && byVersion.length > 0) {
    return byVersion.split("\n").filter(Boolean).slice(0, limit);
  }
  const byDate = gitCmd(repoPath, [...baseArgs, "--sort=-creatordate"]);
  if (!byDate) return [];
  return byDate.split("\n").filter(Boolean).slice(0, limit);
}

/**
 * Does a file with non-empty content exist at this ref?
 */
function fileExistsAtRef(repoPath: string, ref: string, filePath: string): boolean {
  const out = gitCmd(repoPath, ["cat-file", "-e", `${ref}:${filePath}`]);
  // `cat-file -e` exits 0 on hit, non-zero on miss. `gitCmd` returns "" on hit
  // (empty stdout), null on miss.
  return out !== null;
}

/**
 * If a line number is cited, check the line exists (i.e. file is long enough)
 * at the given ref. Line content matching is out of scope for v1 — file +
 * line-range existence is the conservative, fast check.
 */
function lineExistsAtRef(repoPath: string, ref: string, filePath: string, line: number): boolean {
  const content = gitCmd(repoPath, ["show", `${ref}:${filePath}`]);
  if (content === null) return false;
  const lineCount = content.split("\n").length;
  return line <= lineCount;
}

/**
 * Every cited ref resolves at this git ref iff the finding is still present.
 */
function findingPresentAtRef(repoPath: string, ref: string, refs: FileRef[]): boolean {
  if (refs.length === 0) return false;
  for (const r of refs) {
    if (!fileExistsAtRef(repoPath, ref, r.file)) return false;
    if (r.line !== undefined && !lineExistsAtRef(repoPath, ref, r.file, r.line)) return false;
  }
  return true;
}

/**
 * Walk the repo's tags newest-first, classifying each as "finding present" or
 * "finding absent." Returns the set of affected tags and heuristics for the
 * "introduced in" / "fixed in" bounds.
 *
 * The walk is newest-first so that once we find the first absent tag we can
 * mark everything from that point backwards as absent candidates and — by
 * stopping at the first gap — avoid scanning the entire tag history.
 */
export function detectVersionRange(finding: Finding, options: VersionRangeOptions): VersionRangeResult {
  const repoPath = resolve(options.repoPath);
  const tagLimit = options.tagLimit ?? 30;
  const refs = extractFileRefs(finding);
  const notes: string[] = [];

  if (refs.length === 0) {
    return {
      affectedTags: [],
      presentOnHead: false,
      status: "indeterminate",
      notes: ["Could not extract file:line references from the finding. Add explicit `path/to/file.ts:NNN` citations to the description and re-run."],
    };
  }

  const tags = listTags(repoPath, tagLimit, options.tagGlob);
  const presentOnHead = findingPresentAtRef(repoPath, "HEAD", refs);

  if (tags.length === 0) {
    notes.push(`No tags found in ${repoPath}${options.tagGlob ? ` matching '${options.tagGlob}'` : ""}.`);
    return {
      affectedTags: [],
      presentOnHead,
      status: "no-tags",
      notes,
    };
  }

  // Walk every tag (newest-first) and classify. Don't short-circuit — the
  // shape can be introduced in tag N, still present in N+1, and removed at
  // N+2; stopping at the first absent tag misses the affected range.
  const classified: Array<{ tag: string; present: boolean }> = tags.map((tag) => ({
    tag,
    present: findingPresentAtRef(repoPath, tag, refs),
  }));

  const affectedTags = classified.filter((c) => c.present).map((c) => c.tag);
  const introducedIn = affectedTags[affectedTags.length - 1];

  // `fixedIn` = the most-recent absent tag that sits newer than the newest
  // affected tag. In the newest-first array, that's the absent tag immediately
  // *before* (higher up in the array) the first present tag.
  let fixedIn: string | undefined;
  const firstPresentIdx = classified.findIndex((c) => c.present);
  if (firstPresentIdx > 0) {
    // There's at least one absent tag between HEAD and the newest affected tag.
    // Walk backwards to the one that sits immediately newer than the present
    // region — that's the "fixed-in" tag.
    fixedIn = classified[firstPresentIdx - 1]?.tag;
  }

  let status: VersionRangeResult["status"];
  if (presentOnHead) status = "present-on-head";
  else if (affectedTags.length > 0) status = "removed-upstream";
  else status = "indeterminate";

  if (affectedTags.length === tagLimit) {
    notes.push(`Hit the ${tagLimit}-tag walk limit — the introducing tag may be older than reported. Pass --tag-limit to extend.`);
  }

  return {
    affectedTags,
    introducedIn,
    fixedIn,
    presentOnHead,
    status,
    notes,
  };
}

/**
 * Turn the version-range result into a markdown string suited to the advisory
 * template's "Affected versions" section.
 */
export function formatVersionRangeLine(result: VersionRangeResult): string {
  switch (result.status) {
    case "present-on-head":
      if (result.introducedIn) {
        return `\`>= ${result.introducedIn}\`, including the repo's current \`HEAD\`. Confirmed on: ${result.affectedTags.map((t) => "`" + t + "`").join(", ")}.`;
      }
      return "Present on the repo's current `HEAD` (no tagged introduction point detected).";
    case "removed-upstream":
      if (result.introducedIn && result.fixedIn) {
        return `\`>= ${result.introducedIn}\`, \`< ${result.fixedIn}\`. Confirmed affected: ${result.affectedTags.map((t) => "`" + t + "`").join(", ")}. Fixed from \`${result.fixedIn}\` onward.`;
      }
      if (result.introducedIn) {
        return `\`>= ${result.introducedIn}\`. Confirmed affected: ${result.affectedTags.map((t) => "`" + t + "`").join(", ")}. Fixed upstream at HEAD.`;
      }
      return "Removed upstream since the last release.";
    case "no-tags":
      return "_No release tags available in the target repo to infer a range._";
    case "indeterminate":
    default:
      return "_Could not auto-detect a version range — add file:line citations to the finding and re-run._";
  }
}
