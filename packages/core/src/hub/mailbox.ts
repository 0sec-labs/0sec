/**
 * Hub mailbox — the durable, single-machine message transport (increment 3).
 *
 * This is the transport DESIGN.md recommends (option A): a brokerless
 * filesystem spool under the per-user state dir, one file per message, created
 * atomically so concurrent senders can never collide and a reader can never
 * observe a half-written message. There is no daemon, no election, and — by
 * construction — **no network listener of any kind**.
 *
 * ## On-disk layout
 *
 * ```
 * <homeStateDir()>/hub/<sha256(realpath(project))>/   0700
 *   mbox/<peerId>/new/<ts>-<rand>.msg                 0600  pending direct mail
 *   mbox/<peerId>/cur/<ts>-<rand>.msg                 0600  claimed by an in-flight drain
 *   bcast/<ts>-<rand>.msg                             0600  to:"all", shared by every reader
 *   cursor/<peerId>.json                              0600  which broadcasts this peer consumed
 * ```
 *
 * The rendezvous is keyed by the **realpath** of the project directory, so a
 * symlink cannot alias two different projects (or two different users' trees)
 * into one channel. It lives in the per-user state dir, never in the project
 * tree — a repo may be a shared clone, a container bind mount, or plain
 * world-readable, and a message spool must be none of those.
 *
 * ## Atomicity and crash-safety
 *
 * Sending is a three-step dance that is safe against both concurrent senders
 * and a crash at any instant:
 *
 *   1. Reserve a scratch name with `O_CREAT|O_EXCL` — the kernel guarantees
 *      exactly one sender wins that name, so two senders can never interleave
 *      into the same file.
 *   2. Write the whole payload, `fsync`, `fchmod 0600`, close. The scratch name
 *      is dot-prefixed and ends in `.part`; readers only ever list `*.msg`, so a
 *      partially-written payload is invisible to them by construction.
 *   3. Publish by `link()`ing the scratch name to the final `*.msg` name and
 *      unlinking the scratch. `link` is atomic and fails with `EEXIST` rather
 *      than clobbering, so it can never destroy another sender's message; where
 *      hardlinks are unsupported we fall back to `rename` (also atomic on the
 *      same filesystem) guarded by an existence check.
 *
 * A crash before step 3 leaves only an inert `.part` file that no reader looks
 * at. A crash after step 3 leaves a delivered message plus a stray `.part`.
 * There is no window in which a reader sees a truncated message.
 *
 * Draining is a two-phase claim, which is what keeps a crashed reader from
 * losing mail: {@link drainInbox} first `rename`s each pending file from `new/`
 * into `cur/` (atomic; losing the race just means another reader got it, which
 * we tolerate), and only then reads-and-unlinks each claimed file one at a time.
 * A drain that dies mid-flight leaves every not-yet-returned message sitting in
 * `cur/`, and the next drain sweeps `cur/` back in before touching `new/`.
 * Nothing a reader had not yet returned is ever lost; the cost is the standard
 * at-least-once trade (a message read but not yet unlinked when the process dies
 * is redelivered), so consumers must be idempotent.
 *
 * ## Messages carry data, never authority
 *
 * A {@link HubMessage} is inert prose. This module has no operation that mutates
 * another peer's scope, auth config, tool-approval state, or roster entry, and
 * the message shape has nowhere to put such a thing: `body` is a string that is
 * stripped of ANSI and control characters on decode, and `from`/`to` are roster
 * ids validated against the registry's own id rules. A peer asking another peer
 * to "add evil.com to scope" changes nothing until a human re-approves scope in
 * the receiving session. Consumers should still route `body` through the
 * codebase's untrusted-input sanitizer before it reaches a model's context —
 * this module guarantees the bytes are safe to *display*, not that the prose is
 * trustworthy.
 *
 * ## Time
 *
 * Every timestamp is INJECTED on the message (`ts`). Nothing here reads a clock;
 * `encodeMessage` / `decodeMessage` / `hubDirName` / `stripUnsafeText` are pure
 * and total.
 */

import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { homeStateDir } from "@0sec/shared";
import { sanitizeId } from "./registry.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Reserved `to` value meaning "every peer except me". It is deliberately a
 * value a sanitized roster id could also take, so it is RESERVED: the roster
 * wiring (increment 2) must never hand this id to a real peer, and
 * {@link drainInbox} / {@link peekInbox} refuse to treat it as one.
 */
export const BROADCAST_ID = "all";

/** Ids that may never name a real peer. See {@link BROADCAST_ID}. */
export const RESERVED_PEER_IDS: readonly string[] = [BROADCAST_ID];

/** Directory name for the hub spool under the per-user state dir. */
export const HUB_ROOT_NAME = "hub";

/**
 * Max characters retained in a message body. The hub is for short prose;
 * DESIGN.md is explicit that bulk payloads (evidence blobs, HAR files, repro
 * scripts) are passed BY PATH/URI REFERENCE and never inlined, so the spool
 * stays small and no peer can wedge another's disk with a single send. Bodies
 * longer than this are truncated with a visible marker rather than rejected —
 * losing the tail of a chatty message is better than losing the message.
 */
export const MAX_BODY_CHARS = 8_192;

/** Marker appended to a body that hit {@link MAX_BODY_CHARS}. */
export const TRUNCATION_MARKER = "[0sec-hub: body truncated]";

/**
 * Max messages retained per inbox (and in the shared broadcast spool). A peer
 * that is not draining — crashed, wedged, or simply busy — must not let a
 * chatty sender grow the spool without bound. On overflow the OLDEST messages
 * are dropped first (filenames sort by creation timestamp), and the count is
 * reported back to the sender in {@link SendResult.dropped} so the loss is
 * observable rather than silent.
 */
export const MAX_INBOX_MESSAGES = 256;

/** Max characters kept for the display-only `id` / `replyTo` fields. */
const MAX_TOKEN_CHARS = 128;

/** Attempts to find a free message filename before giving up. */
const MAX_NAME_ATTEMPTS = 8;

const DIR_MODE = 0o700;
const FILE_MODE = 0o600;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** One hub message. Inert data: prose plus addressing. */
export interface HubMessage {
  /** Unique, sortable-by-creation id. Display/dedup only — never a path. */
  id: string;
  /** Sender's roster id. */
  from: string;
  /** Recipient's roster id, or {@link BROADCAST_ID}. */
  to: string;
  /** Plain prose. Stripped of ANSI/control characters on decode. */
  body: string;
  /** Epoch ms, INJECTED by the caller. Never read from a clock in here. */
  ts: number;
  /** Optional id of the message being replied to. */
  replyTo?: string;
}

/**
 * Outcome of {@link sendMessage}.
 *
 * This deviates from a bare `boolean` on purpose: the retention cap is allowed
 * to drop old mail, and the brief requires that loss be OBSERVABLE. This module
 * may not print (a library has no business writing to an operator's stdout on
 * the hot path), and the sender is the only party still in scope when the drop
 * happens, so the count rides back on the return value. `ok` carries the boolean
 * a caller wants; check `result.ok`, never the truthiness of `result`.
 */
export interface SendResult {
  /** Did the message land in a mailbox? */
  ok: boolean;
  /** Messages evicted by the retention cap during this send. */
  dropped: number;
  /** Machine-readable failure reason when `ok` is false. */
  reason?: SendFailure;
  /** Was the body truncated to {@link MAX_BODY_CHARS}? */
  truncated?: boolean;
}

/** Why a send was refused. */
export type SendFailure =
  | "invalid-from"
  | "invalid-to"
  | "invalid-ts"
  | "invalid-body"
  | "io-error";

// ---------------------------------------------------------------------------
// Pure helpers — no clock, no filesystem
// ---------------------------------------------------------------------------

/* eslint-disable no-control-regex */
/** OSC string: ESC ] ... terminated by BEL, ST, or end of input. */
const RE_OSC = /\x1B\][\s\S]*?(?:\x07|\x1B\\|$)/g;
/** CSI sequence: ESC [ params intermediates final (final optional = truncated). */
const RE_CSI = /\x1B\[[0-?]*[ -/]*[@-~]?/g;
/** Any other escape sequence, including a lone trailing ESC. */
const RE_ESC = /\x1B[@-Z\\-_]?/g;
/** C0 controls except TAB and LF, plus DEL. */
const RE_C0 = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
/** C1 controls — the 8-bit CSI/OSC introducers. */
const RE_C1 = /[\x80-\x9F]/g;
/** Zero-width and bidi formatting characters ("trojan source" spoofing). */
const RE_INVISIBLE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g;
/* eslint-enable no-control-regex */

/**
 * Strip everything that could move a cursor, repaint a screen, or reorder text
 * on an operator's terminal, keeping only printable prose plus `\n` and `\t`.
 *
 * The hub delivers text written by ANOTHER session straight into a human's
 * view. Without this, a peer could emit `ESC [ 2 J` to wipe the screen, an
 * OSC 8 hyperlink or OSC 52 clipboard write, or a bidi override (the "trojan
 * source" trick) to make a message render as something other than what it says.
 * We strip, in order: OSC strings (which have their own terminators), CSI
 * sequences, any remaining escapes, C0 controls other than tab/newline, DEL,
 * C1 controls, and bidi/zero-width formatting characters. Pure and total.
 */
export function stripUnsafeText(raw: string): string {
  return raw
    // CRLF / lone CR -> LF first, so the C0 strip below cannot eat a line break.
    .replace(/\r\n?/g, "\n")
    .replace(RE_OSC, "")
    .replace(RE_CSI, "")
    .replace(RE_ESC, "")
    .replace(RE_C0, "")
    .replace(RE_C1, "")
    .replace(RE_INVISIBLE, "");
}

/**
 * Is `value` a usable roster id for addressing? True only when it is exactly
 * what the registry's {@link sanitizeId} would produce — we REJECT rather than
 * coerce, because coercing `"../../etc/passwd"` into `"etcpasswd"` would
 * silently deliver mail to a different (possibly real) peer instead of
 * surfacing the attempt. Path separators, `..`, whitespace, control characters,
 * and over-long ids all fail here, so a crafted id can never escape the spool.
 */
export function isValidPeerId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && sanitizeId(value) === value;
}

/** Reduce a display-only token (`id`, `replyTo`) to safe, bounded characters. */
function sanitizeToken(raw: string): string {
  return raw.replace(/[^A-Za-z0-9._:-]/g, "").slice(0, MAX_TOKEN_CHARS);
}

function clampBody(raw: string): { body: string; truncated: boolean } {
  if (raw.length <= MAX_BODY_CHARS) return { body: raw, truncated: false };
  return { body: raw.slice(0, MAX_BODY_CHARS) + TRUNCATION_MARKER, truncated: true };
}

/**
 * Serialize a message to the exact bytes that go on disk. Pure. The body is
 * sanitized and clamped HERE as well as on decode: the spool should never hold
 * an escape sequence in the first place, and a reader must still not trust it.
 */
export function encodeMessage(msg: HubMessage): string {
  const { body } = clampBody(stripUnsafeText(msg.body));
  const out: Record<string, unknown> = {
    v: 1,
    id: sanitizeToken(msg.id),
    from: msg.from,
    to: msg.to,
    ts: msg.ts,
    body,
  };
  if (msg.replyTo !== undefined) out.replyTo = sanitizeToken(msg.replyTo);
  return JSON.stringify(out);
}

/**
 * Parse bytes read from the spool back into a message.
 *
 * PURE AND TOTAL: malformed JSON, a truncated file, a JSON value that is not an
 * object, missing fields, wrong types, a non-finite `ts`, an id that fails
 * {@link isValidPeerId} — every one of these yields `null`. It never throws and
 * never partially trusts a record. The body is re-sanitized on the way out, so
 * even a hand-edited spool file cannot inject terminal escapes into an
 * operator's screen.
 */
export function decodeMessage(raw: string): HubMessage | null {
  if (typeof raw !== "string" || raw.length === 0) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const rec = parsed as Record<string, unknown>;

  const { from, to, ts, body, id } = rec;
  if (!isValidPeerId(from)) return null;
  if (!isValidPeerId(to)) return null;
  if (typeof ts !== "number" || !Number.isFinite(ts)) return null;
  if (typeof body !== "string") return null;
  if (typeof id !== "string") return null;

  const safeId = sanitizeToken(id);
  if (safeId.length === 0) return null;

  const msg: HubMessage = {
    id: safeId,
    from,
    to,
    ts,
    body: clampBody(stripUnsafeText(body)).body,
  };
  if (typeof rec.replyTo === "string") {
    const replyTo = sanitizeToken(rec.replyTo);
    // A malformed replyTo is dropped, not fatal: it is a display-only backlink
    // and losing it is strictly better than losing the message.
    if (replyTo.length > 0) msg.replyTo = replyTo;
  }
  return msg;
}

/**
 * Deterministic directory name for a project's rendezvous: the SHA-256 of its
 * realpath, hex. Pure — the realpath resolution happens in {@link hubDir}.
 *
 * Hashing (rather than embedding the path) keeps the spool name from leaking a
 * client/engagement name into a directory listing, and gives a fixed-length,
 * always-safe filename for any project path.
 */
export function hubDirName(realProjectPath: string): string {
  return createHash("sha256").update(realProjectPath, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/**
 * Absolute path of the hub spool for `projectPath`.
 *
 * The project path is resolved through `realpath` FIRST so that a symlink
 * cannot alias two distinct projects into one channel (or point one user's
 * session at a directory it does not really own). If the path does not exist
 * yet we fall back to a lexical `resolve`, which is still stable and still
 * outside the project tree.
 */
export function hubDir(projectPath: string, homeDir?: string): string {
  let real: string;
  try {
    real = realpathSync(projectPath);
  } catch {
    real = resolve(projectPath);
  }
  return join(homeStateDir(homeDir), HUB_ROOT_NAME, hubDirName(real));
}

function mailboxDir(root: string, peerId: string): string {
  return join(root, "mbox", peerId);
}

function broadcastDir(root: string): string {
  return join(root, "bcast");
}

function cursorPath(root: string, peerId: string): string {
  return join(root, "cursor", `${peerId}.json`);
}

// ---------------------------------------------------------------------------
// Filesystem primitives
// ---------------------------------------------------------------------------

function errCode(err: unknown): string {
  return typeof err === "object" && err !== null && "code" in err
    ? String((err as { code?: unknown }).code)
    : "";
}

/**
 * Create `dir` (and parents) `0700`, then TIGHTEN it even if it already
 * existed. We never trust a pre-existing spool directory's mode: it may have
 * been created by an older build, restored from a backup, or widened by another
 * tool. `chmod` is best-effort (a no-op on Windows) and its failure must not
 * break messaging.
 */
function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: DIR_MODE });
  try {
    chmodSync(dir, DIR_MODE);
  } catch {
    /* best effort: not every platform/filesystem honours chmod */
  }
}

/** Create the whole spool skeleton for one peer, tightening modes on the way. */
function ensurePeerDirs(root: string, peerId: string): { newDir: string; curDir: string } {
  ensureDir(root);
  ensureDir(join(root, "mbox"));
  const base = mailboxDir(root, peerId);
  ensureDir(base);
  const newDir = join(base, "new");
  const curDir = join(base, "cur");
  ensureDir(newDir);
  ensureDir(curDir);
  return { newDir, curDir };
}

function ensureBroadcastDirs(root: string): string {
  ensureDir(root);
  const dir = broadcastDir(root);
  ensureDir(dir);
  ensureDir(join(root, "cursor"));
  return dir;
}

/** Message filenames sort lexicographically in creation order. */
function messageFileName(ts: number): string {
  return `${String(Math.floor(ts)).padStart(15, "0")}-${randomBytes(8).toString("hex")}.msg`;
}

/** List `*.msg` entries, oldest first. A missing directory lists as empty. */
function listMessages(dir: string): string[] {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  return names.filter((n) => n.endsWith(".msg")).sort();
}

function safeUnlink(path: string): void {
  try {
    unlinkSync(path);
  } catch {
    /* already gone — the whole transport treats ENOENT as "someone beat me" */
  }
}

/**
 * Publish `payload` into `dir` as one atomic `*.msg` file.
 *
 * See the module header for the reserve/write/link dance and why each step is
 * needed. Returns false only if every naming attempt collided or the write
 * failed outright.
 */
function writeMessageFile(dir: string, ts: number, payload: string): boolean {
  for (let attempt = 0; attempt < MAX_NAME_ATTEMPTS; attempt++) {
    const name = messageFileName(ts);
    const finalPath = join(dir, name);
    const partPath = join(dir, `.${name}.part`);

    // 1. Reserve the scratch name. O_EXCL means exactly one writer wins it, so
    //    two concurrent senders can never share one file. The name is
    //    dot-prefixed and does not end in `.msg`, so no reader will list it.
    let fd: number;
    try {
      fd = openSync(
        partPath,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
        FILE_MODE,
      );
    } catch {
      continue; // name taken (or transient) — pick a new one
    }

    // 2. Write the payload in full before it can be seen.
    try {
      writeSync(fd, payload, 0, "utf8");
      try {
        fsyncSync(fd);
      } catch {
        /* fsync is unsupported on some filesystems; process-crash safety
           already comes from the atomic publish in step 3. */
      }
      try {
        fchmodSync(fd, FILE_MODE);
      } catch {
        /* best effort; the O_EXCL open above already asked for 0600 */
      }
      closeSync(fd);
    } catch {
      try {
        closeSync(fd);
      } catch {
        /* already closed */
      }
      safeUnlink(partPath);
      return false;
    }

    // 3. Publish atomically. `link` refuses to clobber (EEXIST), so it can never
    //    destroy another sender's message.
    try {
      linkSync(partPath, finalPath);
      safeUnlink(partPath);
      try {
        chmodSync(finalPath, FILE_MODE);
      } catch {
        /* best effort */
      }
      return true;
    } catch (err) {
      if (errCode(err) === "EEXIST") {
        safeUnlink(partPath);
        continue; // astronomically unlikely; just pick another name
      }
      // Hardlinks unsupported (Windows/exFAT/some FUSE): fall back to rename,
      // which is also atomic on the same filesystem. Guard against clobbering.
      if (existsSync(finalPath)) {
        safeUnlink(partPath);
        continue;
      }
      try {
        renameSync(partPath, finalPath);
        try {
          chmodSync(finalPath, FILE_MODE);
        } catch {
          /* best effort */
        }
        return true;
      } catch {
        safeUnlink(partPath);
        return false;
      }
    }
  }
  return false;
}

/** Read a spool file, tolerating it vanishing between listing and reading. */
function readIfPresent(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

/**
 * Enforce the retention cap on a message directory, dropping OLDEST first.
 * Returns how many files were evicted so the caller can report the loss.
 */
function enforceRetention(dir: string, cap: number): number {
  const names = listMessages(dir);
  if (names.length <= cap) return 0;
  const doomed = names.slice(0, names.length - cap);
  let dropped = 0;
  for (const name of doomed) {
    try {
      unlinkSync(join(dir, name));
      dropped++;
    } catch {
      /* a reader drained it first — not a drop we caused */
    }
  }
  return dropped;
}

// ---------------------------------------------------------------------------
// Broadcast cursors
// ---------------------------------------------------------------------------

/**
 * Which broadcast files a peer has already consumed.
 *
 * Broadcast is a SHARED LOG, not a send-time fan-out: `to: "all"` writes exactly
 * ONE file into `bcast/`, and each peer records the filenames it has taken in
 * its OWN cursor file. Consequences, all deliberate:
 *
 *   - One peer draining a broadcast cannot deny it to the others, because
 *     draining a broadcast deletes nothing — it only appends to that peer's
 *     private cursor. No reader can starve another.
 *   - Each cursor file has exactly ONE writer (the peer it belongs to), so the
 *     concurrent-writer problem disappears; it is still written temp-then-rename
 *     so a crash mid-write cannot leave a torn cursor.
 *   - A peer that joins later still sees every broadcast still in the spool,
 *     which a send-time fan-out to the then-current roster could not offer.
 *   - The broadcast spool is reclaimed by the retention cap
 *     ({@link MAX_INBOX_MESSAGES}, oldest-first) rather than by readers, so its
 *     size is bounded without any peer needing to be alive to collect it.
 *
 * The cursor is pruned on every write down to the filenames still present in
 * the spool, so it inherits the spool's bound and cannot grow forever.
 */
interface BroadcastCursor {
  seen: string[];
}

function readCursor(root: string, peerId: string): Set<string> {
  const raw = readIfPresent(cursorPath(root, peerId));
  if (raw === null) return new Set();
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== "object" || parsed === null) return new Set();
    const seen = (parsed as BroadcastCursor).seen;
    if (!Array.isArray(seen)) return new Set();
    return new Set(seen.filter((n): n is string => typeof n === "string"));
  } catch {
    // A torn or hand-mangled cursor degrades to "seen nothing": the peer
    // re-reads broadcasts still in the spool (at-least-once, consistent with
    // the rest of the transport) rather than silently skipping them.
    return new Set();
  }
}

function writeCursor(root: string, peerId: string, seen: Set<string>, present: string[]): void {
  const presentSet = new Set(present);
  const pruned = [...seen].filter((n) => presentSet.has(n)).sort();
  const target = cursorPath(root, peerId);
  const tmp = `${target}.${randomBytes(6).toString("hex")}.part`;
  const payload = JSON.stringify({ seen: pruned } satisfies BroadcastCursor);
  let fd: number;
  try {
    fd = openSync(tmp, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, FILE_MODE);
  } catch {
    return; // the cursor is an optimization; failing to persist only redelivers
  }
  try {
    writeSync(fd, payload, 0, "utf8");
    try {
      fchmodSync(fd, FILE_MODE);
    } catch {
      /* best effort */
    }
    closeSync(fd);
    // rename is atomic on the same filesystem, and this file has exactly one
    // writer, so replacing our own previous cursor is precisely what we want.
    renameSync(tmp, target);
    try {
      chmodSync(target, FILE_MODE);
    } catch {
      /* best effort */
    }
  } catch {
    try {
      closeSync(fd);
    } catch {
      /* already closed */
    }
    safeUnlink(tmp);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Deliver `msg` into the recipient's mailbox (or the broadcast spool when
 * `to === "all"`). Fire-and-forget: it does not wait for, or even know about,
 * the recipient — which need not exist yet.
 *
 * Addressing is validated by SHAPE, not against the live roster: the roster is
 * increment 2's concern and is racy by nature (a peer can exit between check
 * and write). What is guaranteed here is that `from`/`to` are exactly what
 * {@link sanitizeId} would produce, so a crafted address can never become a
 * path component that escapes the spool.
 */
export function sendMessage(projectPath: string, msg: HubMessage, homeDir?: string): SendResult {
  if (!isValidPeerId(msg?.from)) return { ok: false, dropped: 0, reason: "invalid-from" };
  if (!isValidPeerId(msg?.to)) return { ok: false, dropped: 0, reason: "invalid-to" };
  if (typeof msg.ts !== "number" || !Number.isFinite(msg.ts) || msg.ts < 0) {
    return { ok: false, dropped: 0, reason: "invalid-ts" };
  }
  if (typeof msg.body !== "string") return { ok: false, dropped: 0, reason: "invalid-body" };

  const root = hubDir(projectPath, homeDir);
  const isBroadcast = msg.to === BROADCAST_ID;

  let dir: string;
  try {
    dir = isBroadcast ? ensureBroadcastDirs(root) : ensurePeerDirs(root, msg.to).newDir;
  } catch {
    return { ok: false, dropped: 0, reason: "io-error" };
  }

  const clamped = clampBody(stripUnsafeText(msg.body));
  const payload = encodeMessage(msg);

  let ok: boolean;
  try {
    ok = writeMessageFile(dir, msg.ts, payload);
  } catch {
    ok = false;
  }
  if (!ok) return { ok: false, dropped: 0, reason: "io-error", truncated: clamped.truncated };

  // Enforce the cap AFTER publishing so the newest message is never the one
  // dropped — a full inbox sheds history, not the thing you just said.
  let dropped = 0;
  try {
    dropped = enforceRetention(dir, MAX_INBOX_MESSAGES);
  } catch {
    /* retention is best-effort; the message itself is already delivered */
  }
  return { ok: true, dropped, truncated: clamped.truncated };
}

/**
 * Read and CONSUME everything addressed to `peerId`: direct mail plus any
 * broadcast this peer has not taken yet. Returns messages oldest-first.
 *
 * Direct mail is claimed with `rename` into `cur/` before it is read, and
 * unlinked one at a time after it is decoded — see the module header for why
 * that makes a mid-drain crash lossless. Broadcasts are never deleted here;
 * they are only recorded in this peer's cursor, so draining one does not deny
 * it to any other peer.
 *
 * A file that vanishes between listing and reading (another reader got it, or
 * retention evicted it) is skipped silently — that is normal in a spool with
 * concurrent participants, not an error. A file that fails to decode is dropped
 * from the spool rather than re-claimed forever.
 */
export function drainInbox(projectPath: string, peerId: string, homeDir?: string): HubMessage[] {
  if (!isValidPeerId(peerId) || peerId === BROADCAST_ID) return [];
  const root = hubDir(projectPath, homeDir);

  let dirs: { newDir: string; curDir: string };
  try {
    dirs = ensurePeerDirs(root, peerId);
  } catch {
    return [];
  }
  const { newDir, curDir } = dirs;

  // Phase 0 — recover anything a previous drain claimed but never returned.
  const claimed = new Set(listMessages(curDir));

  // Phase 1 — claim pending mail. Losing the rename race (ENOENT) means another
  // reader took it; that is fine and must not throw.
  for (const name of listMessages(newDir)) {
    try {
      renameSync(join(newDir, name), join(curDir, name));
      claimed.add(name);
    } catch {
      /* vanished, or claimed by someone else */
    }
  }

  // Phase 2 — read then unlink, one at a time.
  const out: HubMessage[] = [];
  for (const name of [...claimed].sort()) {
    const path = join(curDir, name);
    const raw = readIfPresent(path);
    if (raw !== null) {
      const msg = decodeMessage(raw);
      if (msg !== null) out.push(msg);
    }
    safeUnlink(path);
  }

  out.push(...collectBroadcasts(root, peerId, true));
  return sortMessages(out);
}

/**
 * Read everything currently addressed to `peerId` WITHOUT consuming it: no file
 * is unlinked, no message is claimed, and the broadcast cursor is not advanced.
 * Calling `peek` then `drain` returns the same messages twice, by design.
 *
 * Like {@link drainInbox} it tolerates a message file disappearing between
 * listing and reading — a concurrent drain is expected, not exceptional.
 */
export function peekInbox(projectPath: string, peerId: string, homeDir?: string): HubMessage[] {
  if (!isValidPeerId(peerId) || peerId === BROADCAST_ID) return [];
  const root = hubDir(projectPath, homeDir);

  let dirs: { newDir: string; curDir: string };
  try {
    dirs = ensurePeerDirs(root, peerId);
  } catch {
    return [];
  }

  const out: HubMessage[] = [];
  // `cur/` first: anything sitting there was claimed by an earlier drain.
  for (const dir of [dirs.curDir, dirs.newDir]) {
    for (const name of listMessages(dir)) {
      const raw = readIfPresent(join(dir, name));
      if (raw === null) continue;
      const msg = decodeMessage(raw);
      if (msg !== null) out.push(msg);
    }
  }
  out.push(...collectBroadcasts(root, peerId, false));
  return sortMessages(out);
}

/**
 * Collect the broadcasts `peerId` has not seen. A peer never receives its own
 * broadcast. When `advance` is true the peer's cursor is updated to cover every
 * broadcast currently in the spool — including its own and any undecodable ones,
 * so neither is re-examined on the next drain.
 */
function collectBroadcasts(root: string, peerId: string, advance: boolean): HubMessage[] {
  const dir = broadcastDir(root);
  const present = listMessages(dir);
  if (present.length === 0) return [];

  const seen = readCursor(root, peerId);
  const out: HubMessage[] = [];
  for (const name of present) {
    if (seen.has(name)) continue;
    const raw = readIfPresent(join(dir, name));
    if (raw !== null) {
      const msg = decodeMessage(raw);
      // A peer does not hear its own broadcast.
      if (msg !== null && msg.from !== peerId) out.push(msg);
    }
    if (advance) seen.add(name);
  }
  if (advance) {
    ensureDir(join(root, "cursor"));
    writeCursor(root, peerId, seen, present);
  }
  return out;
}

/** Stable oldest-first ordering: by timestamp, then by id as a tiebreak. */
function sortMessages(msgs: HubMessage[]): HubMessage[] {
  return msgs.sort((a, b) => (a.ts !== b.ts ? a.ts - b.ts : a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/**
 * Build a unique, creation-sortable message id from an INJECTED timestamp.
 * Convenience for callers; the randomness is not a clock, so this stays clear of
 * the ambient-time ban. Pass `entropy` to make it fully deterministic in tests.
 */
export function newMessageId(ts: number, entropy?: string): string {
  const suffix = entropy ?? randomBytes(6).toString("hex");
  return `${String(Math.floor(ts)).padStart(15, "0")}-${sanitizeToken(suffix)}`;
}
