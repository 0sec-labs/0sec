/**
 * Windowed reads for the `read_file` agent tool.
 *
 * ## Why this exists
 *
 * Before this module `read_file` could only ever return the FIRST `max_lines`
 * lines of a file (default 500). There was no way to ask for the middle. For
 * the source-review and kernel-audit workloads that is the dominant read shape:
 * the agent greps, gets back `fs/xfs/xfs_ioctl.c:3421`, and then needs the 80
 * lines around 3421 — in a file that is 5000 lines long. The only escape hatch
 * was to shell out (`run_command: sed -n '3380,3460p' file`), which costs an
 * extra turn, produces output the loop does not track as a source-file read
 * (see `_sourceFilesRead` in agent/tools.ts — only `read_file` feeds the
 * coverage gate), and is a strictly worse interface than the tool that already
 * exists.
 *
 * The second, quieter failure was silent truncation. The old handler returned
 * `{ content, totalLines, truncated }`. `truncated: true` is technically in the
 * JSON the model sees, but it is a bare boolean with no instruction attached —
 * in practice models read the 500 lines, see no more, and reason as if the file
 * ended there. A finding built on a file the agent only half-read is exactly
 * the "hallucinated file/line reference" class that AGENTS.md flags as a
 * HackerOne bright-line violation. So truncation is now stated IN the returned
 * text, in the imperative, with the exact follow-up call to make.
 *
 * ## Why the logic lives here and not in the ToolExecutor
 *
 * Same reason as `apply-patch.ts` and `scope-path.ts`: the windowing is pure
 * (string in, window out) and deserves direct unit tests that do not have to
 * stand up a `ToolExecutor`, a `ToolContext`, a scope root and a temp dir just
 * to assert an off-by-one. The handler in agent/tools.ts keeps the I/O and the
 * scope enforcement; this file keeps the arithmetic.
 *
 * ## Line numbering convention
 *
 * `offset` is 1-BASED and matches `grep -n` / `rg -n` / `sed -n 'Np'` / the
 * `file.c:247` citation format used in `evidence_request`. This is deliberate:
 * the overwhelmingly common call sequence is grep → read around the hit, and a
 * 0-based offset would make the agent silently read one line off from every
 * line number the rest of its toolchain reports. A 0-based `offset` is
 * therefore REJECTED rather than clamped — clamping 0 to 1 would hand back a
 * window that is right by accident and teach the model nothing, while an error
 * that names the convention is recovered from in one turn.
 */

/** Default window size, unchanged from the pre-offset handler. */
export const READ_FILE_DEFAULT_MAX_LINES = 500;

/**
 * Marker prefix for the synthetic status line appended to windowed content.
 *
 * Namespaced so a reader (human or model) can tell it apart from file content.
 * It is not a cryptographic delimiter — a file could contain this literal
 * string — but `read_file` output is already classified UNTRUSTED and passes
 * through `sanitizeUntrustedToolResult` before it re-enters model context, so
 * spoofing this line buys an attacker nothing they cannot already do by
 * writing "ignore previous instructions" into the same file.
 */
export const READ_FILE_NOTE_PREFIX = "[0sec:read_file]";

/** A resolved window over a file's lines, or a rejected request. */
export type ReadFileWindow =
  | {
      ok: true;
      /** The selected lines, joined by "\n", plus a trailing status note when relevant. */
      content: string;
      /** Total lines in the whole file (not just the window). */
      totalLines: number;
      /** 1-based line number of the first line in `content`. */
      startLine: number;
      /**
       * 1-based line number of the last line in `content`. For a window that
       * starts past EOF this is `startLine - 1`, i.e. an empty window.
       */
      endLine: number;
      /** True when lines AFTER `endLine` were omitted. */
      truncated: boolean;
      /** When `truncated`, the `offset` to pass to read the next window. */
      nextOffset?: number;
    }
  | { ok: false; error: string };

/**
 * Coerce a model-supplied numeric argument.
 *
 * Tool arguments arrive as `unknown` because different providers serialize
 * numbers differently — several pass `"500"` as a string even when the schema
 * says `type: "number"`. The pre-offset handler tolerated this only by
 * accident (`Array.prototype.slice` coerces its arguments), so accepting
 * numeric strings here is preserving existing behaviour, not adding leniency.
 * Anything that is not an integer at or above `min` is rejected with a message
 * that states the constraint, because a silently coerced bad offset produces
 * confidently wrong line citations.
 */
function parsePositiveIntArg(
  value: unknown,
  name: string,
  min: number,
): { ok: true; value: number | undefined } | { ok: false; error: string } {
  if (value === undefined || value === null) return { ok: true, value: undefined };

  const n = typeof value === "number" ? value : typeof value === "string" ? Number(value.trim()) : NaN;

  if (!Number.isFinite(n) || !Number.isInteger(n)) {
    return {
      ok: false,
      error: `read_file: \`${name}\` must be an integer, got ${JSON.stringify(value)}`,
    };
  }
  if (n < min) {
    return {
      ok: false,
      error:
        name === "offset"
          ? `read_file: \`offset\` is 1-based (line 1 is the first line of the file), got ${n}. ` +
            `Pass offset=1 to read from the start.`
          : `read_file: \`${name}\` must be >= ${min}, got ${n}`,
    };
  }
  return { ok: true, value: n };
}

/**
 * Select a line window out of already-read file content.
 *
 * `totalLines` is `content.split("\n").length`, which counts a trailing empty
 * element for files that end in a newline (so it reads one higher than
 * `wc -l`). That is the pre-existing contract of this tool's `totalLines`
 * field and is left alone on purpose: `split("\n")` indices ARE the 1-based
 * line numbers every other tool in the chain reports, and changing the count
 * now would silently move the meaning of a field callers already log.
 *
 * An `offset` past EOF is NOT an error. It returns an empty window with a note
 * saying so — the agent asked a well-formed question about a file that is
 * shorter than it assumed, and the useful answer is "the file has N lines",
 * not a thrown exception that costs a turn.
 */
export function windowFileContent(
  fileContent: string,
  args: { offset?: unknown; maxLines?: unknown },
): ReadFileWindow {
  const offsetArg = parsePositiveIntArg(args.offset, "offset", 1);
  if (!offsetArg.ok) return { ok: false, error: offsetArg.error };

  const maxLinesArg = parsePositiveIntArg(args.maxLines, "max_lines", 1);
  if (!maxLinesArg.ok) return { ok: false, error: maxLinesArg.error };

  const offset = offsetArg.value ?? 1;
  const maxLines = maxLinesArg.value ?? READ_FILE_DEFAULT_MAX_LINES;

  const lines = fileContent.split("\n");
  const totalLines = lines.length;

  // Past EOF: empty window, explicit note, still a success.
  if (offset > totalLines) {
    return {
      ok: true,
      content:
        `${READ_FILE_NOTE_PREFIX} offset ${offset} is past the end of this file ` +
        `(${totalLines} lines total). Nothing to read.`,
      totalLines,
      startLine: offset,
      endLine: offset - 1,
      truncated: false,
    };
  }

  const startIdx = offset - 1;
  const endIdx = Math.min(startIdx + maxLines, totalLines); // exclusive
  const selected = lines.slice(startIdx, endIdx);
  const startLine = offset;
  const endLine = endIdx;
  const truncated = endIdx < totalLines;

  // State where we are whenever the window is not the whole file. A window
  // that starts mid-file is just as misleading as one that ends early if the
  // model forgets it asked for an offset, so the note covers both cases.
  const notes: string[] = [];
  if (truncated) {
    notes.push(
      `${READ_FILE_NOTE_PREFIX} TRUNCATED — showed lines ${startLine}-${endLine} of ${totalLines}. ` +
        `${totalLines - endLine} more line(s) follow. ` +
        `Call read_file again with offset=${endLine + 1} to continue.`,
    );
  } else if (startLine > 1) {
    notes.push(
      `${READ_FILE_NOTE_PREFIX} showed lines ${startLine}-${endLine} of ${totalLines} (end of file). ` +
        `Lines 1-${startLine - 1} were not read.`,
    );
  }

  const content = notes.length > 0 ? [...selected, ...notes].join("\n") : selected.join("\n");

  return {
    ok: true,
    content,
    totalLines,
    startLine,
    endLine,
    truncated,
    ...(truncated ? { nextOffset: endLine + 1 } : {}),
  };
}
