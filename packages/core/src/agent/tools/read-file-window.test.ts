import { describe, it, expect } from "vitest";
import {
  windowFileContent,
  READ_FILE_DEFAULT_MAX_LINES,
  READ_FILE_NOTE_PREFIX,
} from "./read-file-window.js";

/** A file whose Nth line literally reads "line N", so windows are self-checking. */
function numberedFile(lineCount: number): string {
  return Array.from({ length: lineCount }, (_, i) => `line ${i + 1}`).join("\n");
}

/** The content minus any appended `[pwnkit:read_file]` status lines. */
function bodyLines(content: string): string[] {
  return content.split("\n").filter((l) => !l.startsWith(READ_FILE_NOTE_PREFIX));
}

describe("windowFileContent — backwards compatibility", () => {
  it("with no args returns the first 500 lines, as the pre-offset handler did", () => {
    const result = windowFileContent(numberedFile(1200), {});
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const body = bodyLines(result.content);
    expect(body).toHaveLength(READ_FILE_DEFAULT_MAX_LINES);
    expect(body[0]).toBe("line 1");
    expect(body[499]).toBe("line 500");
    expect(result.totalLines).toBe(1200);
    expect(result.truncated).toBe(true);
    expect(result.startLine).toBe(1);
    expect(result.endLine).toBe(500);
  });

  it("does not mark a fully-read file as truncated and appends no note", () => {
    const result = windowFileContent(numberedFile(10), {});
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.truncated).toBe(false);
    expect(result.nextOffset).toBeUndefined();
    expect(result.content).toBe(numberedFile(10));
    expect(result.content).not.toContain(READ_FILE_NOTE_PREFIX);
  });

  it("keeps totalLines counting the trailing element of a newline-terminated file", () => {
    // Pre-existing contract: split("\n") on "a\nb\n" yields ["a","b",""].
    // Pinned so a future refactor cannot silently redefine totalLines.
    const result = windowFileContent("a\nb\n", {});
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.totalLines).toBe(3);
  });

  it("honours max_lines exactly as before when no offset is given", () => {
    const result = windowFileContent(numberedFile(100), { maxLines: 7 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(bodyLines(result.content)).toEqual([
      "line 1", "line 2", "line 3", "line 4", "line 5", "line 6", "line 7",
    ]);
    expect(result.truncated).toBe(true);
  });
});

describe("windowFileContent — offset windows", () => {
  it("returns the exact requested window, 1-based", () => {
    const result = windowFileContent(numberedFile(5000), { offset: 3380, maxLines: 5 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(bodyLines(result.content)).toEqual([
      "line 3380", "line 3381", "line 3382", "line 3383", "line 3384",
    ]);
    expect(result.startLine).toBe(3380);
    expect(result.endLine).toBe(3384);
    expect(result.totalLines).toBe(5000);
  });

  it("offset=1 is identical to omitting offset", () => {
    const withOffset = windowFileContent(numberedFile(50), { offset: 1, maxLines: 10 });
    const without = windowFileContent(numberedFile(50), { maxLines: 10 });
    expect(withOffset).toEqual(without);
  });

  it("reads the final line when offset lands on it", () => {
    const result = windowFileContent(numberedFile(42), { offset: 42, maxLines: 10 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(bodyLines(result.content)).toEqual(["line 42"]);
    expect(result.startLine).toBe(42);
    expect(result.endLine).toBe(42);
    expect(result.truncated).toBe(false);
  });

  it("paging with nextOffset walks the whole file with no gaps or repeats", () => {
    const file = numberedFile(23);
    const seen: string[] = [];
    let offset: number | undefined = 1;

    while (offset !== undefined) {
      const result = windowFileContent(file, { offset, maxLines: 5 });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      seen.push(...bodyLines(result.content));
      offset = result.nextOffset;
    }

    expect(seen).toEqual(file.split("\n"));
  });
});

describe("windowFileContent — truncation is signalled in the text", () => {
  it("states the window, the remaining count and the next call to make", () => {
    const result = windowFileContent(numberedFile(1000), { offset: 100, maxLines: 50 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.truncated).toBe(true);
    expect(result.nextOffset).toBe(150);
    expect(result.content).toContain(`${READ_FILE_NOTE_PREFIX} TRUNCATED`);
    expect(result.content).toContain("showed lines 100-149 of 1000");
    expect(result.content).toContain("851 more line(s) follow");
    expect(result.content).toContain("offset=150");
  });

  it("puts the note last so it cannot be mistaken for a leading line of the file", () => {
    const result = windowFileContent(numberedFile(1000), { offset: 10, maxLines: 3 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const lines = result.content.split("\n");
    expect(lines.slice(0, 3)).toEqual(["line 10", "line 11", "line 12"]);
    expect(lines[lines.length - 1]).toContain(READ_FILE_NOTE_PREFIX);
  });

  it("notes the skipped prefix when a mid-file window reaches EOF", () => {
    // Not "truncated" (nothing follows), but the agent still only saw part of
    // the file — silence here is how a half-read file gets cited as whole.
    const result = windowFileContent(numberedFile(20), { offset: 15, maxLines: 100 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.truncated).toBe(false);
    expect(result.nextOffset).toBeUndefined();
    expect(result.content).toContain("showed lines 15-20 of 20 (end of file)");
    expect(result.content).toContain("Lines 1-14 were not read");
  });
});

describe("windowFileContent — out-of-range and invalid arguments", () => {
  it("treats an offset past EOF as an empty window, not an error", () => {
    const result = windowFileContent(numberedFile(10), { offset: 9999 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.totalLines).toBe(10);
    expect(result.startLine).toBe(9999);
    expect(result.endLine).toBe(9998); // empty window
    expect(result.truncated).toBe(false);
    expect(result.content).toContain("past the end of this file");
    expect(result.content).toContain("(10 lines total)");
    expect(bodyLines(result.content)).toEqual([]);
  });

  it("rejects a 0-based offset and names the convention instead of clamping", () => {
    const result = windowFileContent(numberedFile(10), { offset: 0 });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain("1-based");
    expect(result.error).toContain("offset=1");
  });

  it("rejects a negative offset", () => {
    const result = windowFileContent(numberedFile(10), { offset: -5 });
    expect(result.ok).toBe(false);
  });

  it("rejects a non-integer offset", () => {
    const result = windowFileContent(numberedFile(10), { offset: 3.5 });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain("must be an integer");
  });

  it("rejects a non-numeric offset", () => {
    const result = windowFileContent(numberedFile(10), { offset: "start" });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain("must be an integer");
  });

  it("accepts a numeric string, because providers do serialize numbers that way", () => {
    const result = windowFileContent(numberedFile(100), { offset: "20", maxLines: "3" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(bodyLines(result.content)).toEqual(["line 20", "line 21", "line 22"]);
  });

  it("rejects max_lines below 1 rather than returning a silently empty read", () => {
    const result = windowFileContent(numberedFile(10), { maxLines: 0 });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain("max_lines");
  });

  it("handles an empty file", () => {
    const result = windowFileContent("", {});
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.totalLines).toBe(1);
    expect(result.content).toBe("");
    expect(result.truncated).toBe(false);
  });
});
