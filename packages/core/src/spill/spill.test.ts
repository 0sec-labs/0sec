import { describe, expect, it, beforeEach, afterEach } from "vitest";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { homeStateDir } from "@0sec/shared";
import {
  DEFAULT_SPILL_RETRIEVAL_TOOL,
  MAX_READ_SPILL_CHARS,
  SPILLS_DIR_NAME,
  SPILL_NOTE_PREFIX,
  pruneSpills,
  readSpill,
  spillDir,
  spillIfLarge,
} from "./spill.js";

const SCAN_ID = "scan-abc123";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "0sec-spill-"));
});

afterEach(() => {
  try {
    chmodSync(join(homeStateDir(home), SPILLS_DIR_NAME), 0o700);
  } catch {
    /* not every test creates it */
  }
  rmSync(home, { recursive: true, force: true });
});

function bigPayload(chars: number, fill = "A"): string {
  return fill.repeat(chars);
}

describe("spillDir", () => {
  it("scopes the directory under the shared state dir, never a hardcoded .0sec literal", () => {
    expect(spillDir(SCAN_ID, home)).toBe(join(homeStateDir(home), SPILLS_DIR_NAME, SCAN_ID));
  });

  it("rejects traversal and separators in scanId instead of sanitizing them", () => {
    for (const bad of ["..", "../evil", "a/b", "a\\b", ".hidden", "", "a b", "a\tb", "a\u0000b"]) {
      expect(() => spillDir(bad, home)).toThrow(/Invalid 0sec spill scan id/);
    }
  });
});

describe("spillIfLarge — threshold", () => {
  it("leaves a result at or below the threshold completely untouched", () => {
    const payload = bigPayload(100);
    const result = spillIfLarge(payload, { scanId: SCAN_ID, homeDir: home, thresholdChars: 100 });

    expect(result.spilled).toBe(false);
    expect(result.inline).toBe(payload);
    expect(result.path).toBeUndefined();
    expect(result.originalChars).toBe(100);
    expect(existsSync(spillDir(SCAN_ID, home))).toBe(false);
  });

  it("spills a result over the threshold and writes the payload verbatim", () => {
    const payload = bigPayload(5_000, "B");
    const result = spillIfLarge(payload, {
      scanId: SCAN_ID,
      homeDir: home,
      thresholdChars: 1_000,
      previewChars: 200,
    });

    expect(result.spilled).toBe(true);
    expect(result.originalChars).toBe(5_000);
    expect(result.path).toBeDefined();
    expect(readFileSync(result.path as string, "utf8")).toBe(payload);
  });
});

describe("spillIfLarge — the inline replacement text", () => {
  const payload = `HEAD-MARKER\n${bigPayload(9_000, "x")}`;

  function spill() {
    return spillIfLarge(payload, {
      scanId: SCAN_ID,
      homeDir: home,
      thresholdChars: 1_000,
      previewChars: 300,
    });
  }

  it("states the true original size, the withheld remainder and the resume offset", () => {
    const { inline } = spill();
    expect(inline).toContain(SPILL_NOTE_PREFIX);
    expect(inline).toContain("TRUNCATED");
    expect(inline).toContain(`${payload.length} characters`);
    expect(inline).toContain(`the first 300`);
    expect(inline).toContain(`${payload.length - 300} characters are NOT in this conversation`);
    expect(inline).toContain("Continue this output at offset 300");
  });

  it("names the retrieval tool, its arguments and the exact path", () => {
    const result = spill();
    expect(result.inline).toContain(`\`${DEFAULT_SPILL_RETRIEVAL_TOOL}\``);
    expect(result.inline).toContain(result.path as string);
    expect(result.inline).toContain("`offset`");
    expect(result.inline).toContain("`limit`");
    expect(result.inline).toContain(String(MAX_READ_SPILL_CHARS));
  });

  it("honours a caller-supplied retrieval tool name", () => {
    const { inline } = spillIfLarge(payload, {
      scanId: SCAN_ID,
      homeDir: home,
      thresholdChars: 1_000,
      retrievalTool: "fetch_spill",
    });
    expect(inline).toContain("`fetch_spill`");
    expect(inline).not.toContain(`\`${DEFAULT_SPILL_RETRIEVAL_TOOL}\``);
  });

  it("keeps only a bounded head preview and marks where it ends", () => {
    const { inline } = spill();
    expect(inline).toContain("HEAD-MARKER");
    expect(inline).toContain("--- end of preview");
    // The preview itself is bounded; the whole notice stays far under the payload.
    expect(inline.length).toBeLessThan(1_500);
  });

  it("clamps a preview larger than the threshold", () => {
    const { inline } = spillIfLarge(payload, {
      scanId: SCAN_ID,
      homeDir: home,
      thresholdChars: 500,
      previewChars: 5_000,
    });
    expect(inline).toContain("the first 500 are below");
  });
});

describe("spillIfLarge — permissions", () => {
  it("creates the spill root and per-scan dir 0700 and the file 0600", () => {
    const result = spillIfLarge(bigPayload(4_000), {
      scanId: SCAN_ID,
      homeDir: home,
      thresholdChars: 100,
    });

    const root = join(homeStateDir(home), SPILLS_DIR_NAME);
    expect(statSync(root).mode & 0o777).toBe(0o700);
    expect(statSync(spillDir(SCAN_ID, home)).mode & 0o777).toBe(0o700);
    expect(statSync(result.path as string).mode & 0o777).toBe(0o600);
  });

  it("tightens an already-existing world-readable directory instead of trusting it", () => {
    const root = join(homeStateDir(home), SPILLS_DIR_NAME);
    const dir = join(root, SCAN_ID);
    mkdirSync(dir, { recursive: true, mode: 0o777 });
    chmodSync(root, 0o777);
    chmodSync(dir, 0o777);

    spillIfLarge(bigPayload(4_000), { scanId: SCAN_ID, homeDir: home, thresholdChars: 100 });

    expect(statSync(root).mode & 0o777).toBe(0o700);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
  });

  it("gives every spill a distinct random name (no clobbering)", () => {
    const cfg = { scanId: SCAN_ID, homeDir: home, thresholdChars: 10 };
    const a = spillIfLarge(bigPayload(50, "a"), cfg);
    const b = spillIfLarge(bigPayload(50, "b"), cfg);

    expect(a.path).not.toBe(b.path);
    expect(readFileSync(a.path as string, "utf8")).toBe(bigPayload(50, "a"));
    expect(readFileSync(b.path as string, "utf8")).toBe(bigPayload(50, "b"));
  });
});

describe("spillIfLarge — degrading instead of throwing", () => {
  it("returns the payload inline (bounded) when the spill dir cannot be created", () => {
    // A regular FILE where the spills root belongs: mkdir fails with ENOTDIR for
    // every uid, including root, so this holds in a containerized CI too.
    mkdirSync(homeStateDir(home), { recursive: true });
    writeFileSync(join(homeStateDir(home), SPILLS_DIR_NAME), "not a directory");

    const payload = bigPayload(3_000, "z");
    const result = spillIfLarge(payload, {
      scanId: SCAN_ID,
      homeDir: home,
      thresholdChars: 500,
    });

    expect(result.spilled).toBe(false);
    expect(result.path).toBeUndefined();
    expect(result.originalChars).toBe(3_000);
    expect(result.inline).toContain("THE REMAINDER WAS LOST");
    expect(result.inline).toContain("2500 characters are NOT retrievable");
    expect(result.inline).toContain("z".repeat(100));
    // Bounded by the threshold rather than dumping all 3,000 characters.
    expect(result.inline.length).toBeLessThan(payload.length);
  });

  it("degrades rather than throwing on an invalid scanId", () => {
    const result = spillIfLarge(bigPayload(3_000), {
      scanId: "../escape",
      homeDir: home,
      thresholdChars: 100,
    });
    expect(result.spilled).toBe(false);
    expect(result.inline).toContain("THE REMAINDER WAS LOST");
  });
});

describe("spillIfLarge — serialization", () => {
  it("serializes non-string payloads deterministically regardless of key order", () => {
    const a = { zeta: 1, alpha: { b: [1, 2], a: "x" }, mid: true };
    const b = { mid: true, alpha: { a: "x", b: [1, 2] }, zeta: 1 };

    const one = spillIfLarge(a, { scanId: SCAN_ID, homeDir: home });
    const two = spillIfLarge(b, { scanId: SCAN_ID, homeDir: home });

    expect(one.inline).toBe(two.inline);
    expect(one.inline).toBe('{"alpha":{"a":"x","b":[1,2]},"mid":true,"zeta":1}');
  });

  it("does not throw on a cyclic structure", () => {
    const cyclic: Record<string, unknown> = { name: "loop" };
    cyclic.self = cyclic;

    const result = spillIfLarge(cyclic, { scanId: SCAN_ID, homeDir: home });
    expect(result.spilled).toBe(false);
    expect(result.inline).toBe('{"name":"loop","self":"[Circular]"}');
  });

  it("serializes a shared (non-cyclic) reference in full rather than calling it circular", () => {
    const shared = { k: 1 };
    const result = spillIfLarge({ a: shared, b: shared }, { scanId: SCAN_ID, homeDir: home });
    expect(result.inline).toBe('{"a":{"k":1},"b":{"k":1}}');
  });

  it("handles values JSON.stringify refuses or drops", () => {
    const result = spillIfLarge(
      { big: 10n, nan: Number.NaN, fn: function named() {}, gone: undefined, set: new Set([2, 1]) },
      { scanId: SCAN_ID, homeDir: home },
    );
    expect(result.inline).toContain('"big":"10n"');
    expect(result.inline).toContain('"nan":"NaN"');
    expect(result.inline).toContain('"fn":"[Function named]"');
    expect(result.inline).not.toContain("gone");
    expect(result.inline).toContain('"set":[1,2]');
  });

  it("counts originalChars on the serialized form", () => {
    const result = spillIfLarge({ a: 1 }, { scanId: SCAN_ID, homeDir: home });
    expect(result.originalChars).toBe('{"a":1}'.length);
  });
});

describe("readSpill", () => {
  function spilled(payload: string) {
    const result = spillIfLarge(payload, {
      scanId: SCAN_ID,
      homeDir: home,
      thresholdChars: 10,
      previewChars: 10,
    });
    return result.path as string;
  }

  it("round-trips a payload and pages it with offset/limit", () => {
    const payload = "0123456789ABCDEFGHIJ".repeat(50); // 1,000 chars
    const path = spilled(payload);

    expect(readSpill(path, { limit: 1_000, homeDir: home })).toBe(payload);
    expect(readSpill(path, { offset: 20, limit: 10, homeDir: home })).toBe("0123456789");
    expect(readSpill(path, { offset: 990, limit: 100, homeDir: home })).toBe(payload.slice(990));
    expect(readSpill(path, { offset: 5_000, homeDir: home })).toBe("");
  });

  it("bounds the returned slice even when a huge limit is requested", () => {
    const payload = bigPayload(MAX_READ_SPILL_CHARS + 5_000, "q");
    const path = spilled(payload);

    const slice = readSpill(path, { limit: 10_000_000, homeDir: home });
    expect(slice?.length).toBe(MAX_READ_SPILL_CHARS);
  });

  it("defaults to a bounded page when no limit is given", () => {
    const path = spilled(bigPayload(50_000, "p"));
    expect(readSpill(path, { homeDir: home })?.length).toBe(8_000);
  });

  it("strips ANSI escapes and control characters so the content cannot drive a terminal", () => {
    const hostile =
      "\u001B[31mRED\u001B[0m\u001B[2J\u001B]0;pwned\u0007ok\rrewrite\bmore\tkeep\nlines";
    const path = spilled(hostile);

    const out = readSpill(path, { limit: 1_000, homeDir: home });
    expect(out).toBe("REDokrewritemore\tkeep\nlines");
    expect(out).not.toMatch(/[\u001B\u0007\u009B\r\b]/);
    // The file on disk still holds the verbatim evidence.
    expect(readFileSync(path, "utf8")).toBe(hostile);
  });

  it("refuses a path outside the spill root", () => {
    const outside = join(home, "outside.txt");
    writeFileSync(outside, "secret");
    expect(readSpill(outside, { homeDir: home })).toBeNull();
    expect(readSpill("/etc/passwd", { homeDir: home })).toBeNull();
  });

  it("refuses a sibling directory whose path merely shares the root's prefix (/a/bc vs /a/b)", () => {
    spilled("a seed payload over the threshold");
    const sibling = `${join(homeStateDir(home), SPILLS_DIR_NAME)}-evil`;
    mkdirSync(sibling, { recursive: true });
    const planted = join(sibling, "loot.txt");
    writeFileSync(planted, "not a spill");

    expect(planted.startsWith(join(homeStateDir(home), SPILLS_DIR_NAME))).toBe(true);
    expect(readSpill(planted, { homeDir: home })).toBeNull();
  });

  it("refuses traversal out of the spill directory", () => {
    const path = spilled("payload that is comfortably over the threshold");
    const escape = join(spillDir(SCAN_ID, home), "..", "..", "..", "outside.txt");
    writeFileSync(join(home, "outside.txt"), "secret");
    expect(readSpill(escape, { homeDir: home })).toBeNull();
  });

  it("refuses a symlink planted inside the spill directory that points outside", () => {
    spilled("payload that is comfortably over the threshold");
    const secret = join(home, "id_ed25519");
    writeFileSync(secret, "PRIVATE KEY");
    const link = join(spillDir(SCAN_ID, home), "spill-link.txt");
    symlinkSync(secret, link);

    expect(readSpill(link, { homeDir: home })).toBeNull();
  });

  it("refuses a directory and a missing file without throwing", () => {
    spilled("payload that is comfortably over the threshold");
    expect(readSpill(spillDir(SCAN_ID, home), { homeDir: home })).toBeNull();
    expect(readSpill(join(spillDir(SCAN_ID, home), "nope.txt"), { homeDir: home })).toBeNull();
    expect(readSpill("", { homeDir: home })).toBeNull();
  });
});

describe("pruneSpills", () => {
  it("removes every spill for the scan and reports the count", () => {
    const cfg = { scanId: SCAN_ID, homeDir: home, thresholdChars: 10 };
    const paths = [1, 2, 3].map((n) => spillIfLarge(bigPayload(50, String(n)), cfg).path as string);

    expect(pruneSpills(SCAN_ID, home)).toBe(3);
    for (const path of paths) expect(existsSync(path)).toBe(false);
    expect(existsSync(spillDir(SCAN_ID, home))).toBe(false);
  });

  it("is idempotent and never throws on a missing or invalid scan", () => {
    expect(pruneSpills(SCAN_ID, home)).toBe(0);
    expect(pruneSpills("../escape", home)).toBe(0);
  });

  it("leaves another scan's spills alone", () => {
    const keep = spillIfLarge(bigPayload(50), {
      scanId: "other-scan",
      homeDir: home,
      thresholdChars: 10,
    }).path as string;
    spillIfLarge(bigPayload(50), { scanId: SCAN_ID, homeDir: home, thresholdChars: 10 });

    expect(pruneSpills(SCAN_ID, home)).toBe(1);
    expect(existsSync(keep)).toBe(true);
  });
});
