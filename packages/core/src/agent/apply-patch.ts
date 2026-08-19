// ── apply_patch — structured DSL for reliable file edits (pwnkit#230) ──
//
// Mirrors OpenAI Codex CLI's `apply_patch` envelope. The tool accepts a
// single string in the "*** Begin Patch … *** End Patch" DSL and applies
// a sequence of Add/Update/Delete operations atomically-per-op against
// files inside the agent's scoped directory.
//
// Design choices vs a free-form bash heredoc:
//   1. Context-line anchoring is REQUIRED for updates. The `@@ <anchor>`
//      header must locate exactly one line in the target file. If the
//      anchor matches zero or multiple lines, the operation fails LOUDLY
//      with a useful error instead of silently corrupting the file.
//   2. Add operations refuse to clobber an existing file. To overwrite,
//      use the explicit `*** Replace File:` directive (still single-step,
//      no in-place editing — just write-with-overwrite).
//   3. Delete operations refuse to unlink a missing file (would otherwise
//      mask a typo).
//   4. All paths are resolved through the same `resolveScopedPath` chokepoint
//      that `read_file` and `run_command` use; out-of-scope writes throw.
//
// Reference: BoxPwnr's `ApplyPatchTool` in `src/boxpwnr/tools/tools.py`
// (lines 718–907 in 0ca/BoxPwnr).

import {
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

// ── DSL primitives ──

export type PatchOp =
  | { kind: "add"; path: string; contents: string; overwrite: boolean }
  | { kind: "update"; path: string; hunks: PatchHunk[] }
  | { kind: "delete"; path: string };

export interface PatchHunk {
  /**
   * The text after `@@` on the hunk header. MUST locate exactly one
   * matching line in the target. Empty (`@@`) is allowed only for files
   * with a single hunk anchored at the file start.
   */
  anchor: string;
  /**
   * The body lines following the header, in order. Each line is one of:
   *   - " <line>"   — context line (must match)
   *   - "-<line>"   — line removed
   *   - "+<line>"   — line added
   * The leading marker character is preserved on the parsed body.
   */
  body: PatchBodyLine[];
}

export type PatchBodyLine =
  | { kind: "context"; text: string }
  | { kind: "del"; text: string }
  | { kind: "add"; text: string };

// ── Parser ──

const BEGIN = "*** Begin Patch";
const END = "*** End Patch";

/**
 * Parse a patch envelope into a sequence of operations.
 *
 * Throws on malformed envelopes (missing Begin/End, unknown directives,
 * etc.). Does NOT touch the filesystem — pure transformation.
 */
export function parsePatch(input: string): PatchOp[] {
  // Normalise EOLs. The DSL is line-oriented; CRLF input from copy-pasted
  // patches must round-trip the same way unix LF input does.
  const text = input.replace(/\r\n/g, "\n");
  const lines = text.split("\n");

  // Strip trailing empty line introduced by a final newline.
  if (lines.length > 0 && lines[lines.length - 1] === "") {
    lines.pop();
  }

  if (lines.length === 0 || lines[0].trim() !== BEGIN) {
    throw new Error(
      `apply_patch: envelope must start with "${BEGIN}" (got: ${lines[0] ?? "<empty>"})`,
    );
  }
  if (lines[lines.length - 1].trim() !== END) {
    throw new Error(`apply_patch: envelope must end with "${END}"`);
  }

  // Drop the envelope markers; we work the body.
  const body = lines.slice(1, -1);
  const ops: PatchOp[] = [];

  let i = 0;
  while (i < body.length) {
    const line = body[i];
    const trimmed = line.trim();

    if (trimmed === "") {
      // Permit blank separators between operations.
      i += 1;
      continue;
    }

    const addMatch = /^\*\*\* Add File: (.+)$/.exec(trimmed);
    const replaceMatch = /^\*\*\* Replace File: (.+)$/.exec(trimmed);
    const updateMatch = /^\*\*\* Update File: (.+)$/.exec(trimmed);
    const deleteMatch = /^\*\*\* Delete File: (.+)$/.exec(trimmed);

    if (addMatch || replaceMatch) {
      const path = (addMatch?.[1] ?? replaceMatch![1]).trim();
      const overwrite = replaceMatch !== null;
      i += 1;
      const contentLines: string[] = [];
      while (i < body.length && !isOpHeader(body[i])) {
        const ln = body[i];
        // Add/Replace bodies require every payload line to begin with `+`.
        // The leading `+` is the DSL marker; it is stripped from the
        // material that gets written to disk.
        if (ln.length === 0) {
          // Blank lines are allowed (and represent a literal blank line in
          // the new file). Codex emits "+" for these, but we accept either.
          contentLines.push("");
        } else if (ln[0] === "+") {
          contentLines.push(ln.slice(1));
        } else {
          throw new Error(
            `apply_patch: Add/Replace body lines must start with "+" (got: ${JSON.stringify(ln)})`,
          );
        }
        i += 1;
      }
      ops.push({
        kind: "add",
        path,
        contents: contentLines.join("\n"),
        overwrite,
      });
      continue;
    }

    if (deleteMatch) {
      ops.push({ kind: "delete", path: deleteMatch[1].trim() });
      i += 1;
      continue;
    }

    if (updateMatch) {
      const path = updateMatch[1].trim();
      i += 1;
      const hunks: PatchHunk[] = [];
      while (i < body.length && !isOpHeader(body[i])) {
        const hunkLine = body[i];
        if (!hunkLine.startsWith("@@")) {
          throw new Error(
            `apply_patch: Update File body must begin with "@@ <anchor>" hunk header (got: ${JSON.stringify(
              hunkLine,
            )})`,
          );
        }
        const anchor = hunkLine.slice(2).trim();
        i += 1;
        const hunkBody: PatchBodyLine[] = [];
        while (
          i < body.length &&
          !isOpHeader(body[i]) &&
          !body[i].startsWith("@@")
        ) {
          const ln = body[i];
          if (ln === "") {
            // Blank line in the hunk body is treated as a context blank.
            hunkBody.push({ kind: "context", text: "" });
          } else if (ln[0] === " ") {
            hunkBody.push({ kind: "context", text: ln.slice(1) });
          } else if (ln[0] === "+") {
            hunkBody.push({ kind: "add", text: ln.slice(1) });
          } else if (ln[0] === "-") {
            hunkBody.push({ kind: "del", text: ln.slice(1) });
          } else {
            throw new Error(
              `apply_patch: Update hunk body lines must start with " ", "+", or "-" (got: ${JSON.stringify(
                ln,
              )})`,
            );
          }
          i += 1;
        }
        hunks.push({ anchor, body: hunkBody });
      }
      if (hunks.length === 0) {
        throw new Error(
          `apply_patch: "Update File: ${path}" requires at least one "@@" hunk`,
        );
      }
      ops.push({ kind: "update", path, hunks });
      continue;
    }

    throw new Error(
      `apply_patch: unknown directive (got: ${JSON.stringify(trimmed)})`,
    );
  }

  if (ops.length === 0) {
    throw new Error("apply_patch: envelope contains no operations");
  }

  return ops;
}

function isOpHeader(line: string): boolean {
  return (
    line.startsWith("*** Add File:") ||
    line.startsWith("*** Replace File:") ||
    line.startsWith("*** Update File:") ||
    line.startsWith("*** Delete File:")
  );
}

// ── Application ──

export interface ApplyPatchResult {
  applied: Array<{ kind: PatchOp["kind"]; path: string }>;
}

/**
 * Apply parsed patch operations against the filesystem. `pathResolver`
 * is the chokepoint that maps logical patch paths (relative to the agent's
 * scope) to absolute filesystem paths and refuses any path that escapes
 * the scope. The same function powers `read_file`/`run_command` so the
 * write surface inherits identical scope-confinement guarantees.
 */
export function applyPatchOps(
  ops: PatchOp[],
  pathResolver: (logical: string) => string,
): ApplyPatchResult {
  const applied: ApplyPatchResult["applied"] = [];

  for (const op of ops) {
    const abs = pathResolver(op.path);

    if (op.kind === "add") {
      if (!op.overwrite && existsSync(abs)) {
        throw new Error(
          `apply_patch: Add File "${op.path}" failed — file already exists. Use "*** Replace File: ${op.path}" to overwrite.`,
        );
      }
      // Auto-create the parent directory so a single patch can stage a
      // brand-new file under a brand-new subtree.
      mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, op.contents, "utf-8");
      applied.push({ kind: "add", path: op.path });
      continue;
    }

    if (op.kind === "delete") {
      if (!existsSync(abs)) {
        throw new Error(
          `apply_patch: Delete File "${op.path}" failed — file does not exist`,
        );
      }
      unlinkSync(abs);
      applied.push({ kind: "delete", path: op.path });
      continue;
    }

    // Update.
    if (!existsSync(abs)) {
      throw new Error(
        `apply_patch: Update File "${op.path}" failed — file does not exist`,
      );
    }
    const original = readFileSync(abs, "utf-8");
    const updated = applyUpdateHunks(original, op.path, op.hunks);
    writeFileSync(abs, updated, "utf-8");
    applied.push({ kind: "update", path: op.path });
  }

  return { applied };
}

/**
 * Apply a sequence of `@@`-anchored hunks against the in-memory file
 * contents. The result is a single `string` ready to write back. Throws
 * on ambiguous or missing anchors, missing context lines, and del-line
 * mismatches.
 *
 * Algorithm per hunk:
 *   1. Locate the anchor uniquely. Empty anchor pins to line 0.
 *   2. From that index, walk the hunk body: context/del lines must match
 *      the corresponding source line; add lines are buffered for output.
 *   3. Splice the touched range out and replace it with the rebuilt block.
 */
export function applyUpdateHunks(
  source: string,
  logicalPath: string,
  hunks: PatchHunk[],
): string {
  // Preserve a trailing newline if it was there originally; we re-emit it.
  const hadTrailingNewline = source.endsWith("\n");
  const sourceBody = hadTrailingNewline ? source.slice(0, -1) : source;
  let lines = sourceBody.split("\n");

  for (const hunk of hunks) {
    const anchorIdx = locateAnchor(lines, hunk.anchor, logicalPath);
    const { newLines, consumed } = applyOneHunk(
      lines,
      anchorIdx,
      hunk,
      logicalPath,
    );
    lines = [
      ...lines.slice(0, anchorIdx),
      ...newLines,
      ...lines.slice(anchorIdx + consumed),
    ];
  }

  return lines.join("\n") + (hadTrailingNewline ? "\n" : "");
}

function locateAnchor(
  lines: string[],
  anchor: string,
  logicalPath: string,
): number {
  if (anchor === "") {
    // Empty anchor pins to the file start. Useful for patches that
    // change the very first lines.
    return 0;
  }
  // Substring match (anchor is typically a function signature or unique
  // identifier line). We deliberately do NOT support regex — the DSL is
  // for humans and should be predictable.
  const matches: number[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(anchor)) {
      matches.push(i);
    }
  }
  if (matches.length === 0) {
    throw new Error(
      `apply_patch: anchor "${anchor}" not found in ${logicalPath}; refine the @@ anchor to a line that exists in the file`,
    );
  }
  if (matches.length > 1) {
    throw new Error(
      `apply_patch: context "${anchor}" matches ${matches.length} locations in ${logicalPath}; refine the @@ anchor to be unique`,
    );
  }
  return matches[0];
}

function applyOneHunk(
  lines: string[],
  anchorIdx: number,
  hunk: PatchHunk,
  logicalPath: string,
): { newLines: string[]; consumed: number } {
  const newLines: string[] = [];
  let cursor = anchorIdx;

  for (const entry of hunk.body) {
    if (entry.kind === "context") {
      const observed = lines[cursor];
      if (observed === undefined || observed !== entry.text) {
        throw new Error(
          `apply_patch: context mismatch in ${logicalPath} at line ${cursor + 1}: expected ${JSON.stringify(
            entry.text,
          )}, got ${JSON.stringify(observed ?? "<eof>")}`,
        );
      }
      newLines.push(entry.text);
      cursor += 1;
      continue;
    }
    if (entry.kind === "del") {
      const observed = lines[cursor];
      if (observed === undefined || observed !== entry.text) {
        throw new Error(
          `apply_patch: removed line mismatch in ${logicalPath} at line ${cursor + 1}: expected ${JSON.stringify(
            entry.text,
          )}, got ${JSON.stringify(observed ?? "<eof>")}`,
        );
      }
      // skip the source line (don't push it to newLines).
      cursor += 1;
      continue;
    }
    // add
    newLines.push(entry.text);
    // do NOT advance cursor — adds inject without consuming source.
  }

  return { newLines, consumed: cursor - anchorIdx };
}
