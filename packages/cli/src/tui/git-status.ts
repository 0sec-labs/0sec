/**
 * Git context for the TUI status bar.
 *
 * The status bar mirrors the compact prompt other tools show — branch name
 * plus a count of modified and untracked files, e.g.
 *
 *     ~/coding/0sec-labs/0sec   publish/main-integration *54 ?29
 *
 * Two constraints shape this module. First, the numbers must come from git
 * itself, not a hand-rolled directory walk, because git already knows the
 * ignore rules, the index state, and submodule boundaries — reimplementing
 * that would drift from what the user sees in `git status`. Second, the read
 * happens on the render path of a live terminal UI, so it must be both fast
 * and unable to fail: a status bar that throws, hangs, or prints to the
 * terminal it does not own is worse than one that simply shows nothing.
 *
 * The porcelain v2 format (`git status --porcelain=v2 --branch`) is the
 * stable, machine-readable contract for exactly this — it is documented to
 * remain compatible across git versions, unlike the human-facing output.
 * Parsing lives in `parseGitStatus`, kept pure so the tests can exercise
 * every branch/upstream/change permutation from string fixtures without a
 * real repository. `readGitStatus` is the thin, failure-swallowing shell
 * that actually invokes git.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/** Milliseconds before a git invocation is abandoned. */
const DEFAULT_TIMEOUT_MS = 250;

/** Length of the abbreviated commit sha git itself shows by default. */
const SHORT_SHA_LENGTH = 7;

export interface GitStatus {
  /** True when the cwd is inside a git work tree. */
  isRepo: boolean;
  /** Branch name, or null when detached / unknown. */
  branch: string | null;
  /** Short commit sha when detached, else null. */
  detachedSha: string | null;
  /** Count of tracked files with modifications (staged or unstaged). */
  modified: number;
  /** Count of untracked files. */
  untracked: number;
  /** Commits ahead of upstream, or null when there is no upstream. */
  ahead: number | null;
  /** Commits behind upstream, or null when there is no upstream. */
  behind: number | null;
}

/**
 * The value git prints for `# branch.head` when HEAD does not point at a
 * named branch. It is a literal token, not a valid ref name, so treating it
 * as the branch would be wrong — a detached HEAD has no branch.
 */
const DETACHED_HEAD_TOKEN = "(detached)";

/** A well-formed result for "there is nothing to show". */
function emptyStatus(isRepo: boolean): GitStatus {
  return {
    isRepo,
    branch: null,
    detachedSha: null,
    modified: 0,
    untracked: 0,
    ahead: null,
    behind: null,
  };
}

/**
 * Parse the output of `git status --porcelain=v2 --branch`.
 *
 * Pure by design: every failure mode of the real command is represented by
 * the input string, so the caller decides what "no repo" means and this
 * function only ever reports what the given text describes. Any output at
 * all is taken as evidence we are inside a work tree — git emits the header
 * lines even for a pristine repo — so `isRepo` is true whenever there is a
 * recognizable line and false only for empty/garbage input.
 */
export function parseGitStatus(porcelainV2Output: string): GitStatus {
  const result = emptyStatus(false);

  for (const rawLine of porcelainV2Output.split("\n")) {
    // porcelain v2 records are newline-terminated; a trailing "\r" from a
    // CRLF pipe would otherwise cling to the last token on each line.
    const line = rawLine.replace(/\r$/, "");
    if (line.length === 0) continue;

    // Header lines carry branch/upstream state. Everything else is a change
    // record whose single-character prefix classifies it.
    if (line.startsWith("# ")) {
      result.isRepo = true;
      parseHeaderLine(line.slice(2), result);
      continue;
    }

    // The prefix is the record type followed by a space. Matching the space
    // too avoids miscounting any future line type whose name happens to
    // begin with one of these characters.
    if (line.startsWith("1 ") || line.startsWith("2 ") || line.startsWith("u ")) {
      // "1 " ordinary change, "2 " rename/copy, "u " unmerged — all are
      // tracked files with pending modifications, so all count as modified.
      result.isRepo = true;
      result.modified += 1;
      continue;
    }

    if (line.startsWith("? ")) {
      result.isRepo = true;
      result.untracked += 1;
      continue;
    }

    // Ignored entries ("! ") and any unrecognized line are deliberately
    // skipped: an unknown record must never throw or perturb the counts.
  }

  return result;
}

/** Apply a single `# branch.*` header (leading "# " already stripped). */
function parseHeaderLine(header: string, result: GitStatus): void {
  if (header.startsWith("branch.head ")) {
    const value = header.slice("branch.head ".length).trim();
    // Detached HEAD leaves the branch null; the sha (from branch.oid) is the
    // useful identifier in that state and is populated below.
    result.branch = value === DETACHED_HEAD_TOKEN ? null : value;
    return;
  }

  if (header.startsWith("branch.oid ")) {
    const value = header.slice("branch.oid ".length).trim();
    // Stash the abbreviated sha on the result; whether it survives depends on
    // detached state, which branch.head may report either before or after
    // this line, so the final reconciliation happens in readGitStatus's
    // caller-facing shape. We keep it here and clear it when on a branch.
    result.detachedSha = value.slice(0, SHORT_SHA_LENGTH) || null;
    return;
  }

  if (header.startsWith("branch.ab ")) {
    // Format: "+<ahead> -<behind>". Presence of the line means an upstream is
    // configured; its absence is what leaves ahead/behind null.
    const rest = header.slice("branch.ab ".length).trim();
    const match = /^\+(\d+)\s+-(\d+)$/.exec(rest);
    if (match) {
      result.ahead = Number.parseInt(match[1], 10);
      result.behind = Number.parseInt(match[2], 10);
    }
  }
}

/**
 * Read git status for `cwd`, never throwing.
 *
 * Every failure — not a repo, git not installed, the timeout firing, a
 * non-zero exit — collapses to a well-formed `GitStatus` with `isRepo:
 * false`. The status bar renders that as "no git context" rather than
 * crashing a frame. The timeout is the load-bearing guard: on a huge or
 * network-backed work tree `git status` can take seconds, and blocking the
 * render loop for that long would freeze the whole UI, so we cap it and give
 * up quietly.
 */
export async function readGitStatus(
  cwd: string,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<GitStatus> {
  try {
    const { stdout } = await execFileAsync(
      "git",
      ["status", "--porcelain=v2", "--branch"],
      {
        cwd,
        timeout: timeoutMs,
        // A pathological repo could emit an enormous status; cap the buffer
        // so a rogue read cannot balloon memory. Overflow rejects, which we
        // swallow like any other failure.
        maxBuffer: 4 * 1024 * 1024,
        windowsHide: true,
      },
    );

    const status = parseGitStatus(stdout);
    // parseGitStatus keeps the abbreviated oid for every repo so it is
    // available when detached; on a named branch it is not part of the API's
    // contract, so drop it here to match the documented shape.
    if (status.branch !== null) {
      status.detachedSha = null;
    }
    return status;
  } catch {
    // execFile rejects on spawn failure (git missing), non-zero exit (not a
    // repo), and timeout alike. None of these are actionable at a render
    // boundary, and writing an error anywhere would corrupt the TUI, so the
    // rejection is intentionally silent.
    return emptyStatus(false);
  }
}
