/**
 * Clipboard helper for the TUI console.
 *
 * Two independent copy paths, both safe to use while OpenTUI owns the
 * terminal framebuffer:
 *
 *   1. OSC 52 — an escape sequence the terminal emulator itself intercepts
 *      and turns into a clipboard write. It works locally AND across SSH
 *      (the sequence rides the same PTY the shell does), which makes it the
 *      primary path for a tool that is frequently driven over a remote
 *      session. The catch: the renderer repaints differentially and tracks
 *      every cell it believes is on screen, so a raw `process.stdout.write`
 *      of an escape sequence would desync that model and corrupt the frame.
 *      Therefore this module NEVER touches `process.stdout` for OSC 52. The
 *      caller injects an `emit(data)` writer — in the console that will be
 *      OpenTUI's own safe stdout handle, so the sequence goes out through
 *      the renderer's channel instead of racing it.
 *
 *   2. Subprocess — `pbcopy` / `xclip` / `xsel` / `wl-copy` / `clip.exe`.
 *      Spawning a child process does not write to our stdout, so it cannot
 *      corrupt the framebuffer. Used as a fallback when OSC 52 is not
 *      wanted (no `emit`) or not possible (payload over the OSC 52 size
 *      limit). The spawner is injectable so unit tests never shell out.
 *
 * Nothing here throws. A failed spawn, a missing tool, or an oversize
 * payload resolves to `{ ok: false }` — copying to the clipboard is a
 * convenience, never a reason to crash the console.
 *
 * This module is intentionally free of any UI/OpenTUI import: it is a pure,
 * dependency-injected helper. The interactive wiring (copy-on-highlight,
 * the "copied" toast) lands later in the chat-screen pass and lives there.
 */

import { execFileSync, spawn as nodeSpawn } from "node:child_process";

const ESC = "\x1b";
const BEL = "\x07";
const ST = `${ESC}\\`;

/**
 * Practical OSC 52 payload ceiling.
 *
 * The spec imposes no limit, but real terminals do — most cap the escape
 * sequence they will buffer somewhere in the tens-to-low-hundreds of KB
 * (and older/default builds far lower). Base64 inflates the input by ~4/3,
 * so we bound the *raw UTF-8 input* at 100 KB; anything larger is refused
 * (or truncated, per option) rather than emitting a sequence the terminal
 * will silently drop. Subprocess tools have no such limit, so oversize
 * payloads fall through to the subprocess path when one is available.
 */
export const OSC52_MAX_BYTES = 100_000;

export interface BuildOsc52Options {
  /**
   * Wrap the sequence for a tmux passthrough (DCS `tmux;` … ST) so it
   * reaches the outer terminal when running inside tmux. Every ESC inside
   * the payload is doubled, as tmux requires. Off by default: when tmux is
   * configured with `set -g allow-passthrough on` (or the user is not in
   * tmux at all) the raw sequence is correct; the wrapper is opt-in.
   */
  passthrough?: boolean;
  /** Override the input-byte ceiling. Defaults to {@link OSC52_MAX_BYTES}. */
  maxBytes?: number;
  /**
   * What to do when the input exceeds the ceiling:
   *   - "refuse"   (default) — produce no sequence, flag `capped: true`.
   *   - "truncate" — copy the first `maxBytes` bytes, flag `truncated: true`.
   */
  onOversize?: "refuse" | "truncate";
}

export interface BuildOsc52Result {
  /** Whether a usable sequence was produced. */
  ok: boolean;
  /** The escape sequence, or "" when refused. */
  sequence: string;
  /** UTF-8 byte length of the text actually encoded. */
  bytes: number;
  /** True when the input was over the ceiling and dropped ("refuse"). */
  capped: boolean;
  /** True when the input was over the ceiling and clipped ("truncate"). */
  truncated: boolean;
}

/**
 * Truncate a UTF-8 buffer to at most `maxBytes` without splitting a
 * multi-byte codepoint (which would leave an invalid tail).
 */
function clampUtf8(text: string, maxBytes: number): Buffer {
  const buf = Buffer.from(text, "utf8");
  if (buf.length <= maxBytes) return buf;
  let end = maxBytes;
  // Walk back off any UTF-8 continuation byte (0b10xxxxxx).
  while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
  return buf.subarray(0, end);
}

function wrapPassthrough(sequence: string): string {
  // tmux DCS passthrough: ESC P tmux; <esc-doubled payload> ESC \
  return `${ESC}Ptmux;${sequence.replace(/\x1b/g, ESC + ESC)}${ST}`;
}

/**
 * Build an OSC 52 clipboard sequence with the full result flags.
 *
 * Format: `ESC ] 52 ; c ; <base64(utf8(text))> BEL`
 * (the `c` selector targets the system clipboard).
 */
export function buildOsc52Result(
  text: string,
  opts: BuildOsc52Options = {},
): BuildOsc52Result {
  const maxBytes = opts.maxBytes ?? OSC52_MAX_BYTES;
  const rawLen = Buffer.byteLength(text, "utf8");

  if (rawLen > maxBytes) {
    if (opts.onOversize !== "truncate") {
      return { ok: false, sequence: "", bytes: rawLen, capped: true, truncated: false };
    }
    const clamped = clampUtf8(text, maxBytes);
    const b64 = clamped.toString("base64");
    let sequence = `${ESC}]52;c;${b64}${BEL}`;
    if (opts.passthrough) sequence = wrapPassthrough(sequence);
    return { ok: true, sequence, bytes: clamped.length, capped: false, truncated: true };
  }

  const b64 = Buffer.from(text, "utf8").toString("base64");
  let sequence = `${ESC}]52;c;${b64}${BEL}`;
  if (opts.passthrough) sequence = wrapPassthrough(sequence);
  return { ok: true, sequence, bytes: rawLen, capped: false, truncated: false };
}

/**
 * Build an OSC 52 clipboard sequence.
 *
 * Returns the escape sequence, or "" when the payload exceeds the size
 * ceiling in the default "refuse" mode. Use {@link buildOsc52Result} when
 * you need the flags (capped / truncated / bytes).
 */
export function buildOsc52(text: string, opts: BuildOsc52Options = {}): string {
  return buildOsc52Result(text, opts).sequence;
}

export type ClipboardMethod =
  | "osc52"
  | "pbcopy"
  | "xclip"
  | "xsel"
  | "wl-copy"
  | "clip.exe"
  | "none";

export interface ClipboardResult {
  /** Whether the text was handed to a clipboard mechanism. */
  ok: boolean;
  /** Which mechanism succeeded, or "none" when all paths failed. */
  method: ClipboardMethod;
  /** UTF-8 byte length of the input text. */
  bytes: number;
}

export interface SpawnResult {
  ok: boolean;
  code?: number | null;
}

/**
 * Inject a clipboard-subprocess runner. Receives the tool, its argv, and
 * the text to feed on stdin; resolves to `{ ok }`. May be sync or async.
 * Must not throw for a failed copy — return `{ ok: false }` instead.
 */
export type ClipboardSpawn = (
  cmd: string,
  args: string[],
  input: string,
) => Promise<SpawnResult> | SpawnResult;

/** `which`-style probe: true when the named executable is on PATH. */
export type ClipboardWhich = (cmd: string) => boolean;

export interface CopyOptions {
  /**
   * Safe terminal writer for the OSC 52 sequence (e.g. OpenTUI's stdout
   * handle). When provided and the payload fits, this is the primary path.
   * MUST NOT be `process.stdout.write` unbound — see the module header.
   */
  emit?: (data: string) => void;
  /** Subprocess runner for the fallback path. Injected for testability. */
  spawn?: ClipboardSpawn;
  /** Executable probe for tool detection. Injected for testability. */
  which?: ClipboardWhich;
  /** Platform id (Node `process.platform` shape). Defaults to the host. */
  platform?: NodeJS.Platform | string;
  /** Forward OSC 52 build options (passthrough / size handling). */
  osc52?: BuildOsc52Options;
}

interface ToolSpec {
  method: Exclude<ClipboardMethod, "osc52" | "none">;
  cmd: string;
  args: string[];
}

/**
 * Ordered subprocess candidates per platform. First available wins.
 *
 * Linux lists Wayland first (wl-copy) then X11 (xclip, xsel), with
 * `clip.exe` last so a WSL session — which Node reports as "linux" — can
 * still reach the Windows clipboard when no native tool is installed.
 */
const TOOL_MATRIX: Record<string, ToolSpec[]> = {
  darwin: [{ method: "pbcopy", cmd: "pbcopy", args: [] }],
  linux: [
    { method: "wl-copy", cmd: "wl-copy", args: [] },
    { method: "xclip", cmd: "xclip", args: ["-selection", "clipboard"] },
    { method: "xsel", cmd: "xsel", args: ["--clipboard", "--input"] },
    { method: "clip.exe", cmd: "clip.exe", args: [] },
  ],
  win32: [{ method: "clip.exe", cmd: "clip.exe", args: [] }],
};

/**
 * Pick the subprocess clipboard tool for a platform. Pure: depends only on
 * the injected platform and `which` probe. Returns null when none of the
 * platform's candidates are on PATH (or the platform is unknown).
 */
export function detectClipboardTool(
  platform: NodeJS.Platform | string,
  which: ClipboardWhich,
): ToolSpec | null {
  const candidates = TOOL_MATRIX[platform] ?? [];
  for (const spec of candidates) {
    if (which(spec.cmd)) return spec;
  }
  return null;
}

/**
 * Copy `text` to the clipboard. Prefers OSC 52 via the injected `emit`
 * writer (works locally and over SSH); falls back to a platform
 * subprocess via `spawn` when `emit` is absent or the payload is too large
 * for OSC 52. Never throws, never writes raw stdout itself.
 */
export async function copyToClipboard(
  text: string,
  opts: CopyOptions = {},
): Promise<ClipboardResult> {
  const bytes = Buffer.byteLength(text, "utf8");

  // Path 1: OSC 52 through the injected safe writer.
  if (opts.emit) {
    const built = buildOsc52Result(text, opts.osc52);
    if (built.ok) {
      try {
        opts.emit(built.sequence);
        return { ok: true, method: "osc52", bytes };
      } catch {
        // Fall through to the subprocess path below.
      }
    }
    // built.ok === false means the payload was over the OSC 52 ceiling in
    // "refuse" mode — subprocess tools have no such limit, so fall through.
  }

  // Path 2: platform subprocess.
  if (opts.spawn) {
    const platform = opts.platform ?? process.platform;
    const which = opts.which ?? defaultWhich;
    const tool = detectClipboardTool(platform, which);
    if (tool) {
      try {
        const res = await opts.spawn(tool.cmd, tool.args, text);
        if (res && res.ok) return { ok: true, method: tool.method, bytes };
      } catch {
        // Swallow — a failed copy is not a crash.
      }
    }
  }

  return { ok: false, method: "none", bytes };
}

// --- Production defaults (never exercised by unit tests, which inject) ---

/**
 * Default `which` probe using the platform lookup command. Returns false
 * on any error so detection degrades to "tool unavailable".
 */
export const defaultWhich: ClipboardWhich = (cmd: string): boolean => {
  try {
    const finder = process.platform === "win32" ? "where" : "which";
    execFileSync(finder, [cmd], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
};

/**
 * Default subprocess runner. Spawns the tool, writes `input` to its stdin,
 * and resolves `{ ok }` on a zero exit code. Never rejects.
 */
export const defaultSpawn: ClipboardSpawn = (cmd, args, input) =>
  new Promise<SpawnResult>((resolve) => {
    try {
      const child = nodeSpawn(cmd, args, { stdio: ["pipe", "ignore", "ignore"] });
      child.on("error", () => resolve({ ok: false }));
      child.on("close", (code: number | null) =>
        resolve({ ok: code === 0, code }),
      );
      child.stdin?.on("error", () => {
        /* EPIPE if the tool exits early — handled by close/error */
      });
      child.stdin?.end(input);
    } catch {
      resolve({ ok: false });
    }
  });
