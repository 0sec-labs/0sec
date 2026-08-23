/**
 * Console session transcripts, persisted to `~/.0sec/console-sessions/<id>.json`.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT THIS WRITES TO DISK, AND WHY IT IS SENSITIVE
 * ─────────────────────────────────────────────────────────────────────────────
 * This store persists the *entire* native message array of a console session:
 * every operator prompt, every model reply, and every tool call together with
 * its full result. On a security tool that is engagement content, not chat
 * history. In practice a single file here can contain:
 *
 *   - target hostnames, IPs, internal URLs and the scope an operator approved;
 *   - discovered findings before they are triaged, redacted or disclosed;
 *   - raw HTTP requests and responses captured as exploit evidence, including
 *     session cookies, bearer tokens and CSRF tokens seen on the wire;
 *   - file contents and command output from the operator's own machine;
 *   - credentials the operator pasted into the console, or that a tool echoed.
 *
 * It is written because operators want to close the console and pick the
 * engagement back up — `ConsoleSession` already accepts `initialMessages`, so
 * restoring a session is exactly "hand back the array we stored". The cost of
 * that convenience is a durable, plaintext copy of the above sitting in the
 * operator's home directory, which is a fact both they and any future
 * maintainer of this file need to hold in mind.
 *
 * The transcript is stored FAITHFULLY. This module deliberately does not
 * attempt to scrub secrets out of it, and that is a decision, not an omission.
 * A scrubber over free-form tool output cannot be complete — it would catch
 * `Authorization: Bearer …` and miss the same token inside a JSON body, a
 * base64 blob, a JWT in a URL, or a password in a stack trace — and a partial
 * scrub is worse than none: it advertises a guarantee it cannot keep, so the
 * file gets treated as safe to copy into a ticket, a bug report or a shared
 * host. It would also corrupt the very evidence a resumed session needs. So
 * the contract is the honest one: everything is kept, nothing is sanitised,
 * and the protection is filesystem permissions plus the operator's ability to
 * delete.
 *
 * Consequences, enforced here rather than left to callers:
 *
 *   1. Files are 0600 and the directory is 0700, re-applied on every save so
 *      an entry left loose by an older build, a restored backup or a hand-edit
 *      is tightened rather than trusted.
 *   2. Nothing is transmitted anywhere. This is local disk only — no upload,
 *      no telemetry, no cloud sync path.
 *   3. Deletion is first-class: `deleteSession` removes one transcript and
 *      `pruneSessions` caps how much history accumulates, so the store does
 *      not silently retain an operator's engagements forever.
 *   4. Nothing here prints, on any path. This runs inside a TUI that owns the
 *      terminal, and the payloads involved are exactly the ones that must not
 *      reach a scrollback buffer or a CI log.
 *
 * Like the settings and credential stores next door, every function is TOTAL:
 * a missing directory, an unreadable file, malformed JSON or a read-only home
 * is reported as an empty/false/null result, never as an exception. A bad
 * history file may not take down a live console.
 */

import { chmodSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { homeStateDir } from "@0sec/shared";

/** Listing entry: everything needed to describe a session without loading it. */
export interface StoredSessionMeta {
  /** Stable session id — the `ConsoleSession.scanId`, and the filename stem. */
  id: string;
  /**
   * Epoch milliseconds, INJECTED by the caller. Nothing in this module reads
   * the clock: a store whose ordering depends on an ambient `Date.now()` can
   * only be tested by mocking global time, and the codebase forbids
   * nondeterministic clocks in logic that has tests.
   */
  savedAt: number;
  /** Engagement target at save time, when the session had one. */
  target?: string;
  /** Model id the session was running on, for the listing. */
  model?: string;
  /** Autonomy mode at save time, for the listing. */
  mode?: string;
  /** Working directory the console ran in; the default listing filter. */
  cwd: string;
  /** Number of native messages in the transcript. */
  messageCount: number;
  /** First operator message, trimmed, for a human-readable listing. */
  preview: string;
}

/** A full transcript: the listing metadata plus the messages to replay. */
export interface StoredSession extends StoredSessionMeta {
  /**
   * The session's native message array, stored opaquely. Typed `unknown[]` on
   * purpose: this module is a byte pipe for `NativeMessage[]` and must not
   * acquire a compile-time dependency on a shape the engine is free to evolve.
   * The caller casts on the way back into `initialMessages`.
   */
  messages: unknown[];
}

/** Subdirectory of the 0sec state dir holding one JSON file per session. */
const SESSIONS_DIRNAME = "console-sessions";

/** Owner-only: nobody else on the machine has business reading a transcript. */
const FILE_MODE = 0o600;
/**
 * Owner-only on the directory too. A 0600 file inside a 0755 directory still
 * leaks the session ids, the count and the sizes of an operator's engagements
 * to every local account, and a group- or world-*writable* directory would let
 * another account replace a transcript wholesale — which, since transcripts get
 * replayed straight back into a live model context, is a content-injection
 * primitive rather than a mere disclosure.
 */
const DIR_MODE = 0o700;

/** How many sessions `pruneSessions` keeps when the caller names no limit. */
export const DEFAULT_PRUNE_KEEP = 20;

/** Longest preview retained; a listing row is one terminal line, not a page. */
const PREVIEW_MAX_LENGTH = 120;

/**
 * Ids are used as filenames, so this pattern is a security boundary, not a
 * tidiness rule: it must reject anything that could escape `sessionsDir`.
 * Requiring an alphanumeric first character kills `..` and dotfiles outright,
 * and the allow-list body admits no `/`, no `\`, no NUL and nothing
 * shell-interesting. Console ids are `console-<uuid>`, which fits comfortably.
 */
const SESSION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** File suffix; also what `listSessions` uses to recognise its own files. */
const FILE_SUFFIX = ".json";

/**
 * Transcripts live beside the rest of the per-user engine state (scan DB,
 * journals, credentials, TUI settings) rather than in a bespoke directory, so
 * `homeStateDir` from `@0sec/shared` — not a local `".0sec"` literal — decides
 * where that is. One definition of the state root means a future relocation or
 * an `$XDG_STATE_HOME` migration happens in one place, and — for a directory
 * full of engagement data — that such a relocation cannot leave a stale copy
 * behind in a path only this file knew about.
 */
export function sessionsDir(homeDir?: string): string {
  return join(homeStateDir(homeDir), SESSIONS_DIRNAME);
}

/** Whether `id` is safe to use as a filename inside `sessionsDir`. */
export function isValidSessionId(id: unknown): id is string {
  return typeof id === "string" && SESSION_ID_PATTERN.test(id);
}

/** Absolute path of one session file, or null when the id is not usable. */
function sessionFilePath(id: unknown, homeDir?: string): string | null {
  if (!isValidSessionId(id)) return null;
  return join(sessionsDir(homeDir), `${id}${FILE_SUFFIX}`);
}

/** Reads `key` off a raw object, tolerating any value shape. */
function rawValue(raw: unknown, key: string): unknown {
  // Arrays and `null` are typeof "object" too; neither can carry our keys, and
  // treating them as an empty bag gives the wanted "fall back" behaviour rather
  // than a special case that throws.
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return undefined;
  return (raw as Record<string, unknown>)[key];
}

/** A non-blank string value, or undefined — optional fields stay absent. */
function optionalString(raw: unknown, key: string): string | undefined {
  const value = rawValue(raw, key);
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/** Control characters (C0 + DEL + C1), the ANSI-escape building blocks. */
const CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]+/g;

/**
 * Preview text is rendered into a terminal listing, and it arrives from a file
 * on disk that a hostile local process — or a restored backup, or a hand-edit —
 * could have rewritten. Control characters are stripped rather than escaped so
 * a crafted transcript cannot smuggle ANSI sequences into the operator's
 * terminal (cursor moves, colour resets, or a clear-screen that hides which
 * session they are about to resume). Whitespace collapses for the same reason:
 * one entry is one line.
 */
function sanitizePreview(value: unknown): string {
  if (typeof value !== "string") return "";
  const flattened = value.replace(CONTROL_CHARS, " ").replace(/\s+/g, " ").trim();
  return flattened.length > PREVIEW_MAX_LENGTH
    ? `${flattened.slice(0, PREVIEW_MAX_LENGTH - 1)}…`
    : flattened;
}

/**
 * Total coercion of a parsed file into listing metadata.
 *
 * `id` comes from the FILENAME, never from the body: the filename is the key
 * every other function addresses a session by, so a body whose `id` had drifted
 * (a copied file, a hand-edit) would otherwise produce a listing row that
 * `loadSession` cannot open. A non-finite `savedAt` sorts last rather than
 * rejecting the file — an unorderable transcript is still a recoverable one.
 */
function toMeta(id: string, raw: unknown, messageCount: number): StoredSessionMeta {
  const savedAt = rawValue(raw, "savedAt");
  const cwd = rawValue(raw, "cwd");
  const target = optionalString(raw, "target");
  const model = optionalString(raw, "model");
  const mode = optionalString(raw, "mode");
  return {
    id,
    savedAt: typeof savedAt === "number" && Number.isFinite(savedAt) ? savedAt : 0,
    ...(target !== undefined ? { target } : {}),
    ...(model !== undefined ? { model } : {}),
    ...(mode !== undefined ? { mode } : {}),
    cwd: typeof cwd === "string" ? cwd : "",
    messageCount,
    preview: sanitizePreview(rawValue(raw, "preview")),
  };
}

/**
 * Parses one file into a full session, or null.
 *
 * The one HARD requirement is `messages`: it is the only field whose consumer
 * cannot degrade, since it is replayed straight into a model context. A file
 * whose `messages` is missing, a string, an object or anything else is rejected
 * outright rather than repaired into an empty array — resuming into a silently
 * truncated engagement is far worse for an operator than being told the session
 * is gone, because the model would confidently continue without the context
 * that justified its earlier conclusions.
 */
function parseSession(id: string, text: string): StoredSession | null {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  const messages = rawValue(raw, "messages");
  if (!Array.isArray(messages)) return null;
  return { ...toMeta(id, raw, messages.length), messages };
}

/**
 * Persists one transcript with owner-only permissions, reporting success as a
 * return value rather than an exception — a read-only or full home directory is
 * a "could not save" notice in the transcript, not a lost console.
 *
 * Permissions are applied twice on purpose. The `mode` option on `writeFileSync`
 * and `mkdirSync` only takes effect when the entry is *created*, and even then
 * it is masked by the process umask; an existing world-readable file would keep
 * its loose mode silently. The explicit `chmodSync` calls therefore run
 * unconditionally, so every save is also a repair. `mode` on the create path
 * still matters: it closes the window between "file exists with the default
 * mode" and "chmod lands", during which the transcript would be readable.
 *
 * `messageCount` and `preview` are recomputed from the payload rather than
 * trusted from the caller, so a listing can never claim a size the stored
 * transcript does not have.
 */
export function saveSession(session: StoredSession, homeDir?: string): boolean {
  try {
    if (!Array.isArray(session?.messages)) return false;
    const path = sessionFilePath(session.id, homeDir);
    if (path === null) return false;

    const dir = sessionsDir(homeDir);
    mkdirSync(dir, { recursive: true, mode: DIR_MODE });
    chmodSync(dir, DIR_MODE);

    const payload: StoredSession = {
      ...toMeta(session.id, session, session.messages.length),
      messages: session.messages,
    };
    // Not pretty-printed, unlike the settings file next door: this one is not
    // meant to be read by hand, and a transcript's indentation is pure bulk.
    writeFileSync(path, `${JSON.stringify(payload)}\n`, { encoding: "utf8", mode: FILE_MODE });
    chmodSync(path, FILE_MODE);
    return true;
  } catch {
    return false;
  }
}

/**
 * Lists stored sessions newest-first, skipping anything it cannot read.
 *
 * A single corrupt or truncated file — a save interrupted by a killed terminal
 * is the realistic case — must cost the operator that one session and no more,
 * which is why the store is one file per session and why every read here is
 * individually guarded.
 *
 * `cwd` filtering is the default expectation of a resume UI rather than an
 * afterthought: an operator resuming in project A being offered project B's
 * engagement is both noise and a small disclosure, since the preview line
 * carries the other engagement's subject.
 */
export function listSessions(
  homeDir?: string,
  opts?: { cwd?: string; limit?: number },
): StoredSessionMeta[] {
  const dir = sessionsDir(homeDir);
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    // A missing directory is the common case: nothing has ever been saved.
    return [];
  }

  const out: StoredSessionMeta[] = [];
  for (const entry of entries) {
    if (!entry.endsWith(FILE_SUFFIX)) continue;
    const id = entry.slice(0, -FILE_SUFFIX.length);
    // A file whose stem is not a valid id cannot have been written by us and
    // cannot be addressed by `loadSession`, so listing it would only offer the
    // operator a row that fails to open.
    if (!isValidSessionId(id)) continue;

    let text: string;
    try {
      text = readFileSync(join(dir, entry), "utf8");
    } catch {
      continue;
    }
    const parsed = parseSession(id, text);
    if (parsed === null) continue;
    if (opts?.cwd !== undefined && parsed.cwd !== opts.cwd) continue;

    const { messages: _messages, ...meta } = parsed;
    out.push(meta);
  }

  // Ties break on id so the order is total and therefore testable: two sessions
  // saved in the same millisecond must not depend on readdir order.
  out.sort((a, b) => b.savedAt - a.savedAt || a.id.localeCompare(b.id));

  const limit = opts?.limit;
  if (typeof limit === "number" && Number.isFinite(limit)) {
    return out.slice(0, Math.max(0, Math.floor(limit)));
  }
  return out;
}

/** Boundaries for {@link relativeAge}, kept named so the thresholds are legible. */
const SECONDS_PER_MINUTE = 60;
const MINUTES_PER_HOUR = 60;
const HOURS_PER_DAY = 24;
const DAYS_PER_WEEK = 7;

/**
 * A compact "last used" age — `12s`, `5m`, `3h`, `2d`, `6w` — for the resume
 * picker to render beside a row. Pure by contract: `now` is a parameter, never
 * an ambient `Date.now()`, so a listing renders identically under test and the
 * whole store stays deterministic.
 *
 * The thresholds and the clock-skew clamp mirror the transcript's own
 * `relativeAge` (chat/TranscriptEntry.tsx) so the two age strings on screen read
 * the same, and this one simply carries the ladder further: seconds → minutes →
 * hours → days → weeks, since a resumable engagement can be far older than a
 * message inside the current turn. Weeks is the top rung on purpose — a resume
 * list that has drifted into months is a pruning problem, not a formatting one.
 *
 * A non-positive `savedAt` returns "" rather than a fabricated age: it is the
 * store's "unorderable / no timestamp" sentinel (see `toMeta`), and the caller
 * omits the separator entirely rather than printing a dangling "· ". A future
 * `savedAt` (clock skew, a restored backup) clamps to `0s`, never a negative.
 */
export function relativeAge(savedAt: number, now: number): string {
  if (!Number.isFinite(savedAt) || savedAt <= 0) return "";
  const seconds = Math.max(0, Math.floor((now - savedAt) / 1000));
  if (seconds < SECONDS_PER_MINUTE) return `${seconds}s`;
  const minutes = Math.floor(seconds / SECONDS_PER_MINUTE);
  if (minutes < MINUTES_PER_HOUR) return `${minutes}m`;
  const hours = Math.floor(minutes / MINUTES_PER_HOUR);
  if (hours < HOURS_PER_DAY) return `${hours}h`;
  const days = Math.floor(hours / HOURS_PER_DAY);
  if (days < DAYS_PER_WEEK) return `${days}d`;
  return `${Math.floor(days / DAYS_PER_WEEK)}w`;
}

/**
 * Loads one transcript, or null. Never throws: a nonexistent id, a rejected id,
 * an unreadable file and a malformed one are all the same answer to the caller
 * — "there is nothing here to resume" — which the resume UI renders as a notice
 * rather than dying on.
 */
export function loadSession(id: string, homeDir?: string): StoredSession | null {
  const path = sessionFilePath(id, homeDir);
  if (path === null) return null;
  try {
    return parseSession(id, readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

/**
 * Removes one transcript. Returns whether a file was actually deleted, so the
 * UI can distinguish "gone now" from "was never there" without a stat race.
 *
 * This is the operator's direct answer to "get this engagement off my disk", so
 * it must work on a file this module would refuse to *load*: a corrupt
 * transcript is still sensitive, and deletion deliberately does not parse.
 */
export function deleteSession(id: string, homeDir?: string): boolean {
  const path = sessionFilePath(id, homeDir);
  if (path === null) return false;
  try {
    // `force: false` is what makes the return value meaningful: a missing file
    // raises, and we report that as "nothing was deleted".
    rmSync(path, { force: false });
    return true;
  } catch {
    return false;
  }
}

/**
 * Caps retained history at the newest `keep` sessions ({@link DEFAULT_PRUNE_KEEP}
 * by default) and returns how many were removed.
 *
 * Retention is a security property here, not housekeeping: without a bound, a
 * store of plaintext engagement data grows for the life of the install, and the
 * oldest entries are exactly the ones whose exposure the operator has long
 * stopped thinking about. `keep` counts across ALL working directories on
 * purpose — a per-project cap would let an operator with fifty projects
 * accumulate fifty times the intended footprint.
 *
 * A file too corrupt to list is not pruned: it is invisible to the ordering, so
 * removing it would mean deleting something we could never show the operator
 * first. `deleteSession` remains the way to get rid of those.
 */
export function pruneSessions(homeDir?: string, opts?: { keep?: number }): number {
  const requested = opts?.keep;
  const keep =
    typeof requested === "number" && Number.isFinite(requested)
      ? Math.max(0, Math.floor(requested))
      : DEFAULT_PRUNE_KEEP;

  let removed = 0;
  for (const meta of listSessions(homeDir).slice(keep)) {
    if (deleteSession(meta.id, homeDir)) removed += 1;
  }
  return removed;
}
