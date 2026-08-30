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
 * against a temp dir.
 *
 * This file has two halves. The attestation half (`snapshotWorkspace` /
 * `diffSnapshots`) records WHAT changed. The restore half further down
 * (`captureCheckpoint` / `restoreCheckpoint` — the OpenCode "snapshot undo"
 * model) can put it BACK, still without ever running git: a checkpoint is a
 * bounded content archive, and restore rewrites/recreates/prunes files under
 * `root` to return the tree to that state.
 */

import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";

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

/**
 * ---------------------------------------------------------------------------
 * Restore layer (the OpenCode "snapshot undo" model — content archive, not a
 * shadow git repo).
 *
 * The attestation half above proves WHAT changed. This half can put it BACK: a
 * checkpoint captures each in-scope file's actual bytes + mode, and
 * `restoreCheckpoint` returns the tree to that state — rewriting modified files,
 * re-creating deleted ones, and (optionally) pruning files created since.
 *
 * Deliberately NOT a shadow git repo: it never runs git, never touches any real
 * `.git`/index/branch, and can only read+write regular files under `root`, so it
 * cannot corrupt a checkout. That costs the dedup/compression a shadow repo
 * would give, so it is bounded (same `maxFileBytes`/`skipDirs`/`maxFiles` walk
 * as the snapshot) and aimed at an engagement workspace (PoCs, patches, small
 * artifacts), not a giant source tree. Over-cap files are neither captured nor
 * pruned — restore simply never touches them, which is the safe default.
 * ---------------------------------------------------------------------------
 */

/** One captured file: its bytes (base64) and POSIX mode bits. */
export interface CapturedFile {
  /** File contents, base64-encoded (safe for binary PoCs). */
  readonly content: string;
  /** Low mode bits (e.g. 0o644 / 0o755) so an executable PoC stays executable. */
  readonly mode: number;
}

/** A restorable checkpoint: relative POSIX path -> captured bytes + mode. */
export type WorkspaceCheckpoint = Readonly<Record<string, CapturedFile>>;

export interface RestoreOptions extends SnapshotOptions {
  /**
   * Delete files that exist now but were absent at checkpoint time — i.e. a true
   * "undo to checkpoint". Default true. Only walk-eligible files under `root`
   * are ever candidates (never a skipDir entry, never an over-cap file, never a
   * symlink), so this cannot reach outside the captured surface.
   */
  readonly pruneCreated?: boolean;
  /** Compute the report without touching the filesystem. Default false. */
  readonly dryRun?: boolean;
}

export interface RestoreReport {
  /** Existed but differed — rewritten to the checkpoint content. */
  readonly restored: string[];
  /** Had been deleted since checkpoint — re-created. */
  readonly created: string[];
  /** Created after checkpoint — deleted (only when `pruneCreated`). */
  readonly pruned: string[];
  /** Already byte-identical to the checkpoint — left alone. */
  readonly unchanged: string[];
  /** Per-file failures (fail-soft: one error never aborts the restore). */
  readonly errors: ReadonlyArray<{ readonly path: string; readonly error: string }>;
}

const LOW_MODE_MASK = 0o777;

/**
 * Capture a restorable checkpoint of `root`. Same walk/limits as
 * {@link snapshotWorkspace}, but stores each in-scope file's bytes + mode.
 * Over-cap files and symlinks are skipped (not captured → restore never touches
 * them). Fail-soft: an unreadable file is skipped rather than throwing.
 */
export function captureCheckpoint(root: string, opts: SnapshotOptions = {}): WorkspaceCheckpoint {
  const maxFileBytes = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const maxFiles = opts.maxFiles ?? DEFAULT_MAX_FILES;
  const skipDirs = new Set([...DEFAULT_SKIP_DIRS, ...(opts.skipDirs ?? [])]);
  const out: Record<string, CapturedFile> = {};
  let count = 0;

  const walk = (dir: string): void => {
    if (count >= maxFiles) return;
    let entries: import("node:fs").Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
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
      let st: import("node:fs").Stats;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.size > maxFileBytes) continue; // never captured → never restored/pruned
      try {
        const buf = readFileSync(abs);
        out[toPosix(relative(root, abs))] = {
          content: buf.toString("base64"),
          mode: st.mode & LOW_MODE_MASK,
        };
        count += 1;
      } catch {
        // unreadable file — skip
      }
    }
  };

  walk(root);
  return out;
}

/** Resolve a checkpoint's relative POSIX path under root, or null if it escapes. */
function safeResolveUnder(root: string, relPosix: string): string | null {
  const absRoot = resolve(root);
  const abs = resolve(absRoot, relPosix);
  if (abs !== absRoot && !abs.startsWith(absRoot + sep)) return null; // traversal guard
  return abs;
}

/**
 * Restore `root` to `checkpoint`. Rewrites modified files, re-creates deleted
 * ones (mode preserved), and — unless `pruneCreated` is false — deletes files
 * created since. Fail-soft and path-guarded: a checkpoint key that resolves
 * outside `root` is recorded as an error and never written. Returns a full
 * report; with `dryRun` the report is computed without any filesystem change.
 */
export function restoreCheckpoint(
  root: string,
  checkpoint: WorkspaceCheckpoint,
  opts: RestoreOptions = {},
): RestoreReport {
  const pruneCreated = opts.pruneCreated ?? true;
  const dryRun = opts.dryRun ?? false;
  const restored: string[] = [];
  const created: string[] = [];
  const pruned: string[] = [];
  const unchanged: string[] = [];
  const errors: Array<{ path: string; error: string }> = [];

  for (const [relPosix, cap] of Object.entries(checkpoint)) {
    const abs = safeResolveUnder(root, relPosix);
    if (!abs) {
      errors.push({ path: relPosix, error: "path escapes workspace root" });
      continue;
    }
    let want: Buffer;
    try {
      want = Buffer.from(cap.content, "base64");
    } catch {
      errors.push({ path: relPosix, error: "corrupt checkpoint content" });
      continue;
    }
    let exists = true;
    let same = false;
    try {
      const cur = readFileSync(abs);
      same = cur.equals(want);
    } catch {
      exists = false;
    }
    if (exists && same) {
      unchanged.push(relPosix);
      continue;
    }
    if (!dryRun) {
      try {
        mkdirSync(dirname(abs), { recursive: true });
        writeFileSync(abs, want);
        try {
          chmodSync(abs, cap.mode & LOW_MODE_MASK);
        } catch {
          // mode restore is best-effort (e.g. non-POSIX fs)
        }
      } catch (err) {
        errors.push({ path: relPosix, error: err instanceof Error ? err.message : String(err) });
        continue;
      }
    }
    (exists ? restored : created).push(relPosix);
  }

  if (pruneCreated) {
    // Walk the CURRENT tree with the SAME filters used to capture, so only files
    // that WOULD have been captured are prune candidates. Anything absent from
    // the checkpoint but present now was created since → delete it.
    const nowManifest = snapshotWorkspace(root, opts);
    for (const relPosix of Object.keys(nowManifest)) {
      if (relPosix in checkpoint) continue;
      // Never prune an over-cap file (recorded as `size:` in the manifest): it
      // was never captured, so we cannot know it is agent-created.
      if (nowManifest[relPosix]!.hash.startsWith("size:")) continue;
      const abs = safeResolveUnder(root, relPosix);
      if (!abs) {
        errors.push({ path: relPosix, error: "path escapes workspace root" });
        continue;
      }
      if (!dryRun) {
        try {
          rmSync(abs, { force: true });
        } catch (err) {
          errors.push({ path: relPosix, error: err instanceof Error ? err.message : String(err) });
          continue;
        }
      }
      pruned.push(relPosix);
    }
  }

  restored.sort();
  created.sort();
  pruned.sort();
  unchanged.sort();
  return { restored, created, pruned, unchanged, errors };
}

/** One-line human summary of a restore, for logs / the operator. */
export function summarizeRestore(r: RestoreReport): string {
  const parts = [
    `~${r.restored.length} restored`,
    `+${r.created.length} recreated`,
    `-${r.pruned.length} pruned`,
    `=${r.unchanged.length} unchanged`,
  ];
  if (r.errors.length > 0) parts.push(`!${r.errors.length} errors`);
  return `workspace restore: ${parts.join(", ")}`;
}
