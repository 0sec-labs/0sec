/**
 * One truncation policy for every model-visible tool output.
 *
 * We used to head-slice at three different caps (bash 10,000 chars, craft-loop
 * 7,000 chars, read_file 500 lines) and throw the tail away. For a scanner the
 * TAIL is the verdict: the exit status, the sanitizer summary line, the last
 * error. A head-only slice reliably keeps the banner and discards the answer.
 *
 * This module implements the Codex policy (`utils/string/src/truncate.rs`):
 * keep the head AND the tail, split the budget 50/50, mark the gap, and prepend
 * a header stating the original size. The budget is expressed in tokens and
 * converted with a flat 4-bytes-per-token estimate — no tokenizer, matching
 * Codex. The estimate only decides how much text survives, so being off by a
 * few percent costs nothing.
 *
 * Slicing is code-point aware: a cut never lands inside a surrogate pair, so a
 * multi-byte character at the split boundary is dropped whole rather than
 * turned into a lone surrogate.
 */

/** Flat bytes-per-token estimate. Matches Codex; no tokenizer involved. */
export const BYTES_PER_TOKEN = 4;

/**
 * Default model-visible budget for one tool output, in tokens.
 *
 * 10,000 tokens is the Codex `MODEL_FORMAT_MAX_TOKENS`. Our previous bash cap
 * was 10,000 *chars* — roughly a quarter of this.
 */
export const DEFAULT_TOOL_OUTPUT_TOKENS = 10_000;

export type TruncateMode = "tokens" | "bytes";

export interface TruncateOptions {
  /** Budget for the kept text, in `mode` units. Default {@link DEFAULT_TOOL_OUTPUT_TOKENS}. */
  limit?: number;
  /** Whether `limit` counts tokens (default) or raw UTF-8 bytes. */
  mode?: TruncateMode;
}

export interface TruncateResult {
  /** Head + marker + tail, or the input unchanged when it fits the budget. */
  text: string;
  truncated: boolean;
  /** Estimated token count of the ORIGINAL text. */
  originalTokens: number;
  /** Line count of the ORIGINAL text. */
  originalLines: number;
  /** Estimated tokens removed from the middle. 0 when nothing was cut. */
  truncatedTokens: number;
}

/** UTF-8 byte length of a single code point. */
function utf8Size(codePoint: number): number {
  if (codePoint < 0x80) return 1;
  if (codePoint < 0x800) return 2;
  if (codePoint < 0x10000) return 3;
  return 4;
}

/** Longest code-point-aligned prefix of `text` that fits `byteBudget`. */
function headSlice(text: string, byteBudget: number): string {
  let bytes = 0;
  let i = 0;
  while (i < text.length) {
    const cp = text.codePointAt(i)!;
    const size = utf8Size(cp);
    if (bytes + size > byteBudget) break;
    bytes += size;
    i += cp > 0xffff ? 2 : 1;
  }
  return text.slice(0, i);
}

/** Longest code-point-aligned suffix of `text` that fits `byteBudget`. */
function tailSlice(text: string, byteBudget: number): string {
  let bytes = 0;
  let end = text.length;
  while (end > 0) {
    // Step back one code POINT, not one code unit: a low surrogate preceded by
    // a high surrogate is half of a character and must move two units.
    let start = end - 1;
    const unit = text.charCodeAt(start);
    if (unit >= 0xdc00 && unit <= 0xdfff && start > 0) {
      const prev = text.charCodeAt(start - 1);
      if (prev >= 0xd800 && prev <= 0xdbff) start -= 1;
    }
    const size = utf8Size(text.codePointAt(start)!);
    if (bytes + size > byteBudget) break;
    bytes += size;
    end = start;
  }
  return text.slice(end);
}

/** Estimated token count of `text` under the flat bytes-per-token model. */
export function estimateTokens(text: string): number {
  return Math.ceil(Buffer.byteLength(text, "utf8") / BYTES_PER_TOKEN);
}

/**
 * Keep the head and the tail of `text`, drop the middle, and mark the gap.
 *
 * Returns the input untouched (and `truncated: false`) whenever it already fits
 * the budget, so callers can cheaply detect the no-op case.
 */
export function truncateMiddle(text: string, options: TruncateOptions = {}): TruncateResult {
  const limit = options.limit ?? DEFAULT_TOOL_OUTPUT_TOKENS;
  const mode = options.mode ?? "tokens";
  const byteBudget = Math.max(0, mode === "tokens" ? limit * BYTES_PER_TOKEN : limit);

  const totalBytes = Buffer.byteLength(text, "utf8");
  const originalTokens = Math.ceil(totalBytes / BYTES_PER_TOKEN);
  // `"".split("\n")` is `[""]`, i.e. 1 line — report empty input as 0 lines.
  const originalLines = text.length === 0 ? 0 : text.split("\n").length;

  if (totalBytes <= byteBudget) {
    return { text, truncated: false, originalTokens, originalLines, truncatedTokens: 0 };
  }

  const headBudget = Math.floor(byteBudget / 2);
  const head = headSlice(text, headBudget);
  const tail = tailSlice(text, byteBudget - headBudget);
  const keptBytes = Buffer.byteLength(head, "utf8") + Buffer.byteLength(tail, "utf8");
  const truncatedTokens = Math.ceil((totalBytes - keptBytes) / BYTES_PER_TOKEN);

  return {
    text: `${head}\n…${truncatedTokens} tokens truncated…\n${tail}`,
    truncated: true,
    originalTokens,
    originalLines,
    truncatedTokens,
  };
}

/**
 * The model-visible rendering: {@link truncateMiddle} plus the Codex header
 * that tells the model how much it is NOT seeing. Untruncated text is returned
 * verbatim with no header.
 */
export function formatTruncated(text: string, policy: TruncateOptions = {}): string {
  const result = truncateMiddle(text, policy);
  if (!result.truncated) return result.text;
  return [
    `Warning: truncated output (original token count: ${result.originalTokens})`,
    `Total output lines: ${result.originalLines}`,
    "",
    result.text,
  ].join("\n");
}
