/**
 * Workspace change-attestation.
 *
 * A security agent mutates its engagement workspace — writes PoCs, patches,
 * artifacts, sometimes into a target checkout. Two things matter: (1) being able
 * to prove EXACTLY which files the agent touched (an attestation for the evidence
 * pack, and a guard against a "finding" that is really the agent's own artifact),
 * and (2) catching an accidental clobber. This module is the attestation half:
 * hash the workspace at a baseline, hash it again later, diff the manifests.
 *
 * Content-hash based ON PURPOSE — not a shadow git repo. It never runs git,
 * never touches the target's real `.git`, index, or branches, and cannot corrupt
 * a checkout: it only reads files and hashes them. Deterministic and testable
 * against a temp dir. (A shadow-git `restore`/undo layer, from the OpenCode
 * model, is a separate, heavier follow-up; attestation is the high-value slice.)
 */

import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

/** One file's fingerprint in a snapshot. */
export interface FileFingerprint {
  readonly hash: string;
  readonly size: number;
}

/** A workspace snapshot: relative POSIX path -> fingerprint. */
export type SnapshotManifest = Readonly<Record<string, FileFingerprint>>;

export interface SnapshotOptions {
  /** Skip files larger than this (PoC binaries / core dumps / pcaps). Default 4 MiB. */
  readonly maxFileBytes?: number;
  /** Directory names to skip entirely, anywhere in the tree. */
  readonly skipDirs?: readonly string[];
  /** Hard cap on files walked, so a pathological tree can't hang a scan. */
  readonly maxFiles?: number;
}

const DEFAULT_SKIP_DIRS = new Set([".git", "node_modules", ".venv", "__pycache__", ".cache", "dist", ".next"]);
const DEFAULT_MAX_FILE_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_FILES = 20_000;

/** Normalize a relative path to POSIX separators so manifests are platform-stable. */
function toPosix(p: string): string {
  return sep === "/" ? p : p.split(sep).join("/");
}

/**
 * Snapshot `root`: walk it, hashing each regular file (sha256) into a manifest.
 * Symlinks are skipped (never followed — a symlink out of the workspace must not
 * pull external content into the attestation). Total, fail-soft: an unreadable
 * file is recorded with an empty hash rather than throwing, so one permission
 * error can't abort the whole snapshot.
 */
export function snapshotWorkspace(root: string, opts: SnapshotOptions = {}): SnapshotManifest {
  const maxFileBytes = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const maxFiles = opts.maxFiles ?? DEFAULT_MAX_FILES;
  const skipDirs = new Set([...DEFAULT_SKIP_DIRS, ...(opts.skipDirs ?? [])]);
  const out: Record<string, FileFingerprint> = {};
  let count = 0;

  const walk = (dir: string): void => {
    if (count >= maxFiles) return;
    let entries: import("node:fs").Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // unreadable dir — skip
    }
    for (const entry of entries) {
      if (count >= maxFiles) return;
      if (entry.isSymbolicLink()) continue;
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue;
        walk(abs);
        continue;
      }
      if (!entry.isFile()) continue;
      let size: number;
      try {
        size = statSync(abs).size;
      } catch {
        continue;
      }
      if (size > maxFileBytes) {
        // Recorded as present-but-unhashed (size only) so a big file's
        // appearance/deletion is still attested, without reading megabytes.
        out[toPosix(relative(root, abs))] = { hash: `size:${size}`, size };
        count += 1;
        continue;
      }
      let hash = "";
      try {
        hash = createHash("sha256").update(readFileSync(abs)).digest("hex");
      } catch {
        hash = "";
      }
      out[toPosix(relative(root, abs))] = { hash, size };
      count += 1;
    }
  };

  walk(root);
  return out;
}

export interface SnapshotDiff {
  readonly added: string[];
  readonly modified: string[];
  readonly deleted: string[];
}

/** True if a diff records no changes. */
export function isEmptyDiff(d: SnapshotDiff): boolean {
  return d.added.length === 0 && d.modified.length === 0 && d.deleted.length === 0;
}

/**
 * Diff two manifests: what changed going from `base` to `current`. `added` =
 * present now, absent then; `deleted` = the reverse; `modified` = present in both
 * with a different hash. All lists sorted for a stable, reviewable attestation.
 */
export function diffSnapshots(base: SnapshotManifest, current: SnapshotManifest): SnapshotDiff {
  const added: string[] = [];
  const modified: string[] = [];
  const deleted: string[] = [];
  for (const path of Object.keys(current)) {
    const b = base[path];
    if (!b) added.push(path);
    else if (b.hash !== current[path]!.hash) modified.push(path);
  }
  for (const path of Object.keys(base)) {
    if (!(path in current)) deleted.push(path);
  }
  added.sort();
  modified.sort();
  deleted.sort();
  return { added, modified, deleted };
}

/** A one-line human summary of a diff, for logs / the evidence pack. */
export function summarizeDiff(d: SnapshotDiff): string {
  if (isEmptyDiff(d)) return "no workspace changes";
  return `workspace changes: +${d.added.length} added, ~${d.modified.length} modified, -${d.deleted.length} deleted`;
}
