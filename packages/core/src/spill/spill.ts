/**
 * Oversized tool-result spilling (the "spill" policy).
 *
 * ## Why this exists
 *
 * A security scan's tool output is routinely enormous: a full HTTP response
 * body, a 5 MB file read, a directory listing with thousands of entries, a
 * fuzzer log. Today every byte of that lands in the model conversation, and
 * because every tool iteration RESENDS the whole conversation, one large
 * result is billed again on every subsequent round. A real session burned
 * 779,532 input tokens in a single turn that way (see the turn-token budget
 * note in console/turn-engine.ts). The large result also crowds out earlier
 * evidence, which is the more expensive failure: the model forgets the finding
 * it was chasing because a directory listing pushed it out of the window.
 *
 * The fix, borrowed from the DeepSeek harness, is a SPILL: a result over a
 * threshold is written to a session-scoped file on disk, and what enters the
 * conversation is a bounded head preview plus an explicit locator telling the
 * model (a) that it did NOT receive everything, (b) exactly how big the real
 * output was, and (c) the exact call to make to read any part of the rest.
 *
 * The doctrine on that inline text is the same one `read-file-window.ts`
 * settled on for truncated reads: a bare `truncated: true` flag is technically
 * present but is not read as an instruction, and a model that half-reads a
 * file then cites it as complete produces exactly the hallucinated-evidence
 * class that AGENTS.md treats as a bright line. So the truncation is stated IN
 * the text, in the imperative, with the follow-up call spelled out.
 *
 * ## Units
 *
 * Every size in this module — `thresholdChars`, `previewChars`,
 * `originalChars`, and the `offset`/`limit` of {@link readSpill} — is counted
 * in JavaScript string length (UTF-16 code units), NOT bytes and not Unicode
 * scalar values. One unit is used everywhere so the number the model is shown
 * is the same number its `offset` is measured in.
 *
 * ## Wiring (not done here — this module is deliberately standalone)
 *
 * The producer side calls {@link spillIfLarge} where a tool result is turned
 * into conversation content (`stringifyToolResult` in console/turn-engine.ts)
 * and puts `result.inline` in the `tool_result` block. The retrieval side must
 * expose {@link readSpill} to the model as a tool whose name matches
 * `SpillConfig.retrievalTool` (default {@link DEFAULT_SPILL_RETRIEVAL_TOOL}) —
 * the inline text names that tool, so if it is not registered the locator is a
 * lie. Note that the existing `read_file` tool CANNOT stand in: it enforces
 * scope containment against the scanned source root, and spills live under the
 * per-user state dir, so it would refuse every spill path.
 *
 * ## Retention
 *
 * A spill file is ENGAGEMENT EVIDENCE — it is verbatim target output (response
 * bodies, tokens the target handed back, memory dumps). It is written 0600
 * inside a 0700 per-scan directory under the per-user state dir, and it is NOT
 * time-expired by anything in this module: nothing here deletes a file the
 * caller did not ask to delete, because a spill may be the only surviving copy
 * of the evidence behind a finding. Retention is therefore explicit and owned
 * by the scan lifecycle: call {@link pruneSpills} when the scan terminates (or
 * after its evidence pack has been exported) to drop the whole per-scan
 * directory. Until that call, spills persist across process restarts, which is
 * also what makes a resumed scan able to re-read them.
 */
import {
  chmodSync,
  closeSync,
  fchmodSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { join, resolve, sep } from "node:path";
import { homeStateDir } from "@0sec/shared";

// ---------------------------------------------------------------------------
// Bounds and names
// ---------------------------------------------------------------------------

/**
 * Results at or below this many characters go into the conversation verbatim.
 * ~20k chars is roughly 5k tokens: big enough that ordinary tool output (a
 * command's stdout, a JSON finding, a short response body) is never disturbed,
 * small enough that the resend-per-iteration multiplier stays bounded.
 */
export const DEFAULT_SPILL_THRESHOLD_CHARS = 20_000;

/**
 * How much of the head stays inline when a result spills. Enough to identify
 * WHAT the output is (status line, headers, first records, the banner) so the
 * model can decide whether paging further is worth a turn.
 */
export const DEFAULT_SPILL_PREVIEW_CHARS = 2_000;

/** Default characters returned by {@link readSpill} when no `limit` is given. */
export const DEFAULT_READ_SPILL_CHARS = 8_000;

/** Hard ceiling on a single {@link readSpill} slice — a page, never the file. */
export const MAX_READ_SPILL_CHARS = 64_000;

/**
 * Refuse to load a spill larger than this into process memory. A single tool
 * result this big is a bug in the producing tool, not a read to service; the
 * file stays on disk at its recorded path for offline inspection.
 */
export const MAX_READ_SPILL_FILE_BYTES = 128 * 1024 * 1024;

/** Nesting depth beyond which a serialized structure is elided. */
const MAX_SERIALIZE_DEPTH = 64;

/** Directory under the per-user state dir that holds every scan's spills. */
export const SPILLS_DIR_NAME = "spills";

/**
 * Marker prefix for the 0sec-authored status text wrapped around a preview.
 * Namespaced so a reader (human or model) can tell it from tool output. It is
 * not a cryptographic delimiter — target output can contain this literal
 * string — but tool results are already classified UNTRUSTED downstream, so
 * spoofing it buys an attacker nothing they cannot do by writing "ignore
 * previous instructions" into the same response body.
 */
export const SPILL_NOTE_PREFIX = "[0sec:spill]";

/**
 * Tool name the inline locator tells the model to call. The harness must
 * register a tool under this name backed by {@link readSpill}; override via
 * `SpillConfig.retrievalTool` when it is registered under another name.
 */
export const DEFAULT_SPILL_RETRIEVAL_TOOL = "read_spill";

/**
 * Accepted `scanId` shape. `scanId` becomes a path segment, so it is VALIDATED
 * and rejected, never sanitized: a sanitizer that rewrites `../../etc` into
 * something writable silently invents a directory, whereas a rejection makes
 * the caller's bug visible. Must start alphanumeric (so `.`, `..` and dotfiles
 * are out) and contain nothing but `[A-Za-z0-9._-]` (so no `/`, no `\`, no NUL).
 */
const SCAN_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface SpillConfig {
  /** Results larger than this (in characters) spill. */
  thresholdChars?: number;
  /** How much of the head to keep inline. */
  previewChars?: number;
  /** Session id — scopes the spill directory. */
  scanId: string;
  /** Injected for testability; defaults to the per-user state dir. */
  homeDir?: string;
  /**
   * Name of the registered tool that reads a spill back, as written into the
   * inline locator. Defaults to {@link DEFAULT_SPILL_RETRIEVAL_TOOL}.
   */
  retrievalTool?: string;
}

export interface SpillResult {
  /** True when the payload was written out. */
  spilled: boolean;
  /** What should be placed in the conversation. */
  inline: string;
  /** Absolute path, when spilled. */
  path?: string;
  /** Original size in characters. */
  originalChars: number;
}

/** Options for {@link readSpill}. Offsets and limits are in characters. */
export interface ReadSpillOptions {
  /** 0-based character offset into the spilled payload. Default 0. */
  offset?: number;
  /**
   * Maximum characters to return. Default {@link DEFAULT_READ_SPILL_CHARS},
   * clamped to {@link MAX_READ_SPILL_CHARS} — paging a spill back in one call
   * would undo the whole point of spilling it.
   */
  limit?: number;
  /** Injected for testability; defaults to the per-user state dir. */
  homeDir?: string;
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/** Root holding every scan's spill directory: `<state dir>/spills`. */
function spillsRoot(homeDir?: string): string {
  return join(homeStateDir(homeDir), SPILLS_DIR_NAME);
}

function assertScanId(scanId: string): void {
  // Belt and braces: the charset already forbids a leading dot, so `..` and
  // `../x` cannot match, but an explicit traversal check keeps the intent
  // legible to the next reader (and to an audit).
  if (typeof scanId !== "string" || !SCAN_ID_PATTERN.test(scanId) || scanId.includes("..")) {
    throw new Error(
      `Invalid 0sec spill scan id ${JSON.stringify(scanId)}: expected [A-Za-z0-9][A-Za-z0-9._-]{0,127} with no path separators or traversal.`,
    );
  }
}

/**
 * Absolute spill directory for one scan: `<state dir>/spills/<scanId>`.
 *
 * THROWS on an invalid `scanId` (see {@link SCAN_ID_PATTERN}) — this is the one
 * function in the module that throws, and deliberately so: an id that cannot
 * be turned into a safe path is a programming error at the call site, not a
 * runtime condition to degrade around. Every other entry point catches it.
 */
export function spillDir(scanId: string, homeDir?: string): string {
  assertScanId(scanId);
  return join(spillsRoot(homeDir), scanId);
}

// ---------------------------------------------------------------------------
// Untrusted-content hygiene
// ---------------------------------------------------------------------------

const ANSI_OSC = /\u001B\][\s\S]*?(?:\u0007|\u001B\\|$)/g;
const ANSI_CSI = /\u001B\[[0-?]*[ -/]*[@-~]/g;
const ANSI_OTHER = /\u001B[@-Z\\-_]/g;
// C0 minus \t and \n, plus DEL and the C1 block (which some terminals still
// decode as escape introducers).
const CONTROL_CHARS = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g;

/**
 * Strip ANSI escape sequences and control characters from target-produced
 * text.
 *
 * This makes the text safe to DISPLAY, not safe to TRUST. A spill holds
 * verbatim output from the target — response bodies, logs, file contents — and
 * that content remains adversarial after this call: it can still argue, still
 * impersonate a 0sec status line, still carry a prompt injection. All this
 * removes is the terminal's own control channel, so rendering a spill cannot
 * move the cursor, repaint or erase the lines around it, retitle the operator's
 * window, or emit a bracketed-paste/response sequence. Trust decisions belong
 * to the untrusted-content framing downstream, not here.
 *
 * `\n` and `\t` survive because they are the content's own structure.
 */
function stripForDisplay(text: string): string {
  return text
    .replace(ANSI_OSC, "")
    .replace(ANSI_CSI, "")
    .replace(ANSI_OTHER, "")
    .replace(CONTROL_CHARS, "");
}

// ---------------------------------------------------------------------------
// Deterministic serialization
// ---------------------------------------------------------------------------

/**
 * Serialize an arbitrary tool payload to a stable string.
 *
 * Deterministic: object keys are emitted in sorted order, so the same logical
 * payload produces the same bytes regardless of insertion order — a spill can
 * therefore be content-addressed or diffed across runs. Total: cycles become
 * `"[Circular]"` (detected against the ANCESTOR chain, so a DAG that repeats a
 * shared reference still serializes in full rather than being falsely flagged),
 * depth is capped, and anything that still explodes falls back to `String()`.
 * A `string` payload passes through untouched — quoting a body the model is
 * about to read would only add noise.
 */
function stableSerialize(payload: unknown): string {
  if (typeof payload === "string") return payload;
  try {
    return serializeValue(payload, [], 0);
  } catch {
    try {
      return String(payload);
    } catch {
      return "[unserializable payload]";
    }
  }
}

function serializeValue(value: unknown, ancestors: object[], depth: number): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "number":
      return Number.isFinite(value) ? String(value) : JSON.stringify(String(value));
    case "boolean":
      return value ? "true" : "false";
    case "bigint":
      return JSON.stringify(`${value.toString()}n`);
    case "undefined":
      return "null";
    case "function":
      return JSON.stringify(`[Function ${value.name || "anonymous"}]`);
    case "symbol":
      return JSON.stringify(String(value));
  }

  const obj = value as object;
  if (ancestors.includes(obj)) return '"[Circular]"';
  if (depth >= MAX_SERIALIZE_DEPTH) return '"[MaxDepth]"';

  const nextAncestors = [...ancestors, obj];
  const nextDepth = depth + 1;

  if (Array.isArray(obj)) {
    return `[${obj.map((item) => serializeValue(item, nextAncestors, nextDepth)).join(",")}]`;
  }
  if (obj instanceof Date) {
    return JSON.stringify(Number.isNaN(obj.getTime()) ? "Invalid Date" : obj.toISOString());
  }
  if (obj instanceof Error) {
    return serializePlain(
      { name: obj.name, message: obj.message, stack: obj.stack },
      nextAncestors,
      nextDepth,
    );
  }
  if (obj instanceof Map) {
    const entries = [...obj.entries()]
      .map(
        ([k, v]) =>
          `[${serializeValue(k, nextAncestors, nextDepth)},${serializeValue(v, nextAncestors, nextDepth)}]`,
      )
      .sort();
    return `[${entries.join(",")}]`;
  }
  if (obj instanceof Set) {
    const items = [...obj.values()]
      .map((item) => serializeValue(item, nextAncestors, nextDepth))
      .sort();
    return `[${items.join(",")}]`;
  }

  return serializePlain(obj as Record<string, unknown>, nextAncestors, nextDepth);
}

function serializePlain(
  obj: Record<string, unknown>,
  ancestors: object[],
  depth: number,
): string {
  const parts: string[] = [];
  for (const key of Object.keys(obj).sort()) {
    const raw = obj[key];
    if (raw === undefined) continue; // match JSON.stringify: omit undefined members
    parts.push(`${JSON.stringify(key)}:${serializeValue(raw, ancestors, depth)}`);
  }
  return `{${parts.join(",")}}`;
}

// ---------------------------------------------------------------------------
// Inline replacement text
// ---------------------------------------------------------------------------

/**
 * Cut a head preview without splitting a surrogate pair (a lone half renders
 * as U+FFFD and would corrupt the last visible character of the preview).
 */
function headPreview(text: string, limit: number): string {
  if (text.length <= limit) return text;
  let end = limit;
  const last = text.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end -= 1;
  return text.slice(0, end);
}

/**
 * The text that replaces the payload in the conversation.
 *
 * Every line here is load-bearing:
 *  - it states TRUNCATED up front, in the imperative, before any content, so a
 *    model that skims the first line still learns the result is partial;
 *  - it gives the true original size and the exact withheld remainder, so the
 *    model can tell "a bit more" from "10,000x more";
 *  - it names the retrieval tool, the exact path, and the offset to resume at,
 *    so acting on it costs one call and no guessing;
 *  - it closes the preview with an explicit end marker, so the preview's last
 *    line is not mistaken for the end of the output.
 *
 * The preview is passed through {@link stripForDisplay} first: the preview is
 * embedded INSIDE 0sec-authored framing, and raw ANSI in it could repaint or
 * erase the locator lines around it when the transcript is rendered — that is,
 * the payload could forge or hide 0sec's own status text. The verbatim bytes
 * remain on disk; only this framed copy is cleaned.
 */
function buildSpillNotice(args: {
  serialized: string;
  previewChars: number;
  path: string;
  retrievalTool: string;
}): string {
  const { serialized, previewChars, path, retrievalTool } = args;
  const preview = stripForDisplay(headPreview(serialized, previewChars));
  const total = serialized.length;
  const shown = Math.min(previewChars, total);
  const withheld = total - shown;

  return [
    `${SPILL_NOTE_PREFIX} THIS TOOL RESULT IS TRUNCATED. The tool produced ${total} characters; ` +
      `only the first ${shown} are below. The remaining ${withheld} characters are NOT in this ` +
      `conversation and you have NOT seen them.`,
    `The complete, unmodified output was written to disk at:`,
    `  ${path}`,
    `To read any part of it, call the \`${retrievalTool}\` tool with that exact path plus ` +
      `\`offset\` (0-based character offset into the full output) and \`limit\` (characters to ` +
      `return, default ${DEFAULT_READ_SPILL_CHARS}, maximum ${MAX_READ_SPILL_CHARS}). ` +
      `Continue this output at offset ${shown}. Page with successive offsets, or search it with ` +
      `a command over the same path.`,
    `Do not describe, summarize, or cite this output as complete unless you have read it to the end.`,
    `--- preview: characters 0-${shown} of ${total} ---`,
    preview,
    `--- end of preview (${withheld} characters withheld) ---`,
  ].join("\n");
}

/**
 * The text used when the payload was too large but could NOT be persisted
 * (unwritable state dir, full disk, invalid scan id). Degrading to a silent
 * full inline would reintroduce the token blowup this module exists to stop,
 * and dropping the payload would lose evidence, so the middle path is: keep as
 * much as the caller already declared acceptable inline (`thresholdChars`) and
 * say plainly that the rest is gone and is not retrievable.
 */
function buildDegradedNotice(args: {
  serialized: string;
  thresholdChars: number;
  reason: string;
}): string {
  const { serialized, thresholdChars, reason } = args;
  const kept = stripForDisplay(headPreview(serialized, thresholdChars));
  const total = serialized.length;
  const shown = Math.min(thresholdChars, total);
  const withheld = total - shown;

  return [
    `${SPILL_NOTE_PREFIX} THIS TOOL RESULT IS TRUNCATED AND THE REMAINDER WAS LOST. The tool ` +
      `produced ${total} characters; only the first ${shown} are below. 0sec could not write the ` +
      `full output to disk (${reason}), so the remaining ${withheld} characters are NOT retrievable. ` +
      `Re-run the tool with a narrower request (a filter, a byte range, fewer paths) instead of ` +
      `assuming what the rest contained.`,
    `--- partial output: characters 0-${shown} of ${total} ---`,
    kept,
    `--- end of partial output (${withheld} characters lost) ---`,
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Spilling
// ---------------------------------------------------------------------------

function positiveInt(value: number | undefined, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? Math.floor(value)
    : fallback;
}

/**
 * Create (or tighten) the per-scan spill directory and return it.
 *
 * The mode passed to `mkdirSync` is masked by the process umask and is IGNORED
 * outright when the directory already exists, so both the root and the per-scan
 * directory are `chmod`ed afterwards. Tighten, do not trust: a directory left
 * behind by an earlier run with a laxer umask (or by a hostile pre-create) is
 * corrected before anything is written into it.
 */
function ensureSpillDir(scanId: string, homeDir?: string): string {
  const root = spillsRoot(homeDir);
  const dir = spillDir(scanId, homeDir);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  chmodSync(dir, 0o700);
  return dir;
}

/**
 * Write `content` to a fresh randomly named file in `dir`, returning its path.
 *
 * `'wx'` is `O_CREAT|O_EXCL|O_WRONLY`: it fails rather than truncating an
 * existing file, and O_EXCL refuses to follow a symlink at the final path
 * component — so a pre-planted `spill-<name>.txt -> ~/.ssh/authorized_keys`
 * cannot turn a spill into an arbitrary-file overwrite. The name carries 128
 * bits of randomness, so predicting one to plant is not on the table either;
 * one retry covers the astronomically unlikely collision.
 */
function writeSpillFile(dir: string, content: string): string {
  let lastError: unknown;
  for (let attempt = 0; attempt < 2; attempt++) {
    const path = join(dir, `spill-${randomBytes(16).toString("hex")}.txt`);
    let fd: number | undefined;
    try {
      fd = openSync(path, "wx", 0o600);
      // Re-assert the mode on the open descriptor: the create mode is masked by
      // the umask (which can only tighten) but this also covers a filesystem
      // that ignores the create mode entirely.
      fchmodSync(fd, 0o600);
      writeSync(fd, content, 0, "utf8");
      return path;
    } catch (error) {
      lastError = error;
    } finally {
      if (fd !== undefined) {
        try {
          closeSync(fd);
        } catch {
          /* nothing useful to do with a close failure here */
        }
      }
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

function describeError(error: unknown): string {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  if (code) return code;
  const message = error instanceof Error ? error.message : String(error);
  return message.slice(0, 120) || "unknown error";
}

/**
 * Spill `payload` if its serialized form exceeds the threshold.
 *
 * NEVER THROWS. Every failure mode — invalid scan id, unwritable state dir,
 * full disk, unserializable payload — degrades to `spilled: false` with the
 * payload (bounded) still inline. Losing a tool result or killing a scan
 * partway through an engagement is strictly worse than paying for some tokens.
 */
export function spillIfLarge(payload: unknown, config: SpillConfig): SpillResult {
  const serialized = stableSerialize(payload);
  const originalChars = serialized.length;
  const thresholdChars = positiveInt(config?.thresholdChars, DEFAULT_SPILL_THRESHOLD_CHARS);
  // A preview larger than the threshold would inline more than the policy
  // allows; clamp rather than reject, since it is a harmless config mistake.
  const previewChars = Math.min(
    positiveInt(config?.previewChars, DEFAULT_SPILL_PREVIEW_CHARS),
    thresholdChars,
  );
  const retrievalTool = config?.retrievalTool || DEFAULT_SPILL_RETRIEVAL_TOOL;

  if (originalChars <= thresholdChars) {
    return { spilled: false, inline: serialized, originalChars };
  }

  try {
    const dir = ensureSpillDir(config.scanId, config.homeDir);
    const path = writeSpillFile(dir, serialized);
    return {
      spilled: true,
      inline: buildSpillNotice({ serialized, previewChars, path, retrievalTool }),
      path,
      originalChars,
    };
  } catch (error) {
    return {
      spilled: false,
      inline: buildDegradedNotice({
        serialized,
        thresholdChars,
        reason: describeError(error),
      }),
      originalChars,
    };
  }
}

// ---------------------------------------------------------------------------
// Reading back
// ---------------------------------------------------------------------------

/**
 * Whether `child` lies within the `parent` subtree (or IS it). Both must be
 * canonicalized real paths. The `parent + sep` guard defeats the sibling-prefix
 * trap: `/a/bc` is NOT within `/a/b`, which a bare `startsWith` would accept.
 */
function isWithinDir(child: string, parent: string): boolean {
  return child === parent || child.startsWith(parent + sep);
}

/**
 * Read a window of a spilled payload, or `null` when the path is not a
 * readable spill.
 *
 * Containment is enforced on REAL paths: both the requested file and the spill
 * root are resolved through `realpathSync` (which resolves every symlink and
 * `..`) before comparison, so neither `.../spills/x/../../.ssh/id_ed25519` nor
 * a symlink planted inside the spill directory can escape, and the comparison
 * itself is subtree-aware rather than a string prefix. The target must also be
 * a regular file — a directory or a FIFO is refused instead of hanging a scan.
 *
 * Returned content is passed through {@link stripForDisplay}, which makes it
 * safe to DISPLAY, not safe to TRUST: it is verbatim target output and stays
 * adversarial. Slicing happens on the file's own characters BEFORE stripping,
 * so `offset` means the same thing here as in the inline locator; the returned
 * slice may therefore be shorter than `limit` once escapes are removed.
 *
 * NEVER THROWS — a missing file, a racing prune, or a permission error is
 * `null`.
 */
export function readSpill(path: string, opts?: ReadSpillOptions): string | null {
  try {
    if (typeof path !== "string" || path.length === 0) return null;

    const root = realpathSync(spillsRoot(opts?.homeDir));
    const real = realpathSync(resolve(path));
    if (!isWithinDir(real, root)) return null;

    const stat = statSync(real);
    if (!stat.isFile()) return null;
    if (stat.size > MAX_READ_SPILL_FILE_BYTES) return null;

    const offset = Math.max(0, positiveInt(opts?.offset, 0));
    const limit = Math.min(
      Math.max(1, positiveInt(opts?.limit, DEFAULT_READ_SPILL_CHARS)),
      MAX_READ_SPILL_CHARS,
    );

    const content = readFileSync(real, "utf8");
    if (offset >= content.length) return "";
    return stripForDisplay(content.slice(offset, offset + limit));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------

/**
 * Delete every spill file for `scanId` and the scan's spill directory, and
 * return how many files were removed.
 *
 * This is the retention control described in the module header: spills hold
 * engagement evidence and are never expired on a timer, so the scan lifecycle
 * must call this at scan end (or after the evidence pack has been exported) to
 * stop the evidence being retained indefinitely under the operator's home
 * directory.
 *
 * Only the directory's own entries are removed and `unlink` never follows a
 * symlink, so a planted link is dropped as a link rather than deleting its
 * target. NEVER THROWS; an unremovable entry is skipped and simply not counted.
 */
export function pruneSpills(scanId: string, homeDir?: string): number {
  let removed = 0;
  try {
    const dir = spillDir(scanId, homeDir);
    for (const entry of readdirSync(dir)) {
      const path = join(dir, entry);
      try {
        if (lstatSync(path).isDirectory()) continue; // nothing here creates these
        unlinkSync(path);
        removed++;
      } catch {
        /* skip what we cannot remove; the count stays honest */
      }
    }
    try {
      rmdirSync(dir);
    } catch {
      /* non-empty (skipped entries) or already gone — the files are what matter */
    }
  } catch {
    /* invalid scan id or no such directory: nothing was retained to prune */
  }
  return removed;
}
