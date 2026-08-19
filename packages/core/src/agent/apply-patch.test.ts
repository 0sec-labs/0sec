import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, isAbsolute, resolve } from "node:path";
import {
  parsePatch,
  applyPatchOps,
  applyUpdateHunks,
} from "./apply-patch.js";

// ── Parser ──

describe("parsePatch", () => {
  it("parses a single Update File envelope", () => {
    const ops = parsePatch(
      [
        "*** Begin Patch",
        "*** Update File: src/foo.ts",
        "@@ function greet",
        " function greet(name) {",
        "-  return `Hello ${name}`;",
        "+  return `Hi ${name}!`;",
        " }",
        "*** End Patch",
      ].join("\n"),
    );
    expect(ops).toHaveLength(1);
    expect(ops[0].kind).toBe("update");
    if (ops[0].kind !== "update") throw new Error("type narrowing");
    expect(ops[0].path).toBe("src/foo.ts");
    expect(ops[0].hunks).toHaveLength(1);
    expect(ops[0].hunks[0].anchor).toBe("function greet");
    expect(ops[0].hunks[0].body).toEqual([
      { kind: "context", text: "function greet(name) {" },
      { kind: "del", text: "  return `Hello ${name}`;" },
      { kind: "add", text: "  return `Hi ${name}!`;" },
      { kind: "context", text: "}" },
    ]);
  });

  it("parses an Add File envelope", () => {
    const ops = parsePatch(
      [
        "*** Begin Patch",
        "*** Add File: src/new.ts",
        "+export const x = 1;",
        "+export const y = 2;",
        "*** End Patch",
      ].join("\n"),
    );
    expect(ops).toHaveLength(1);
    expect(ops[0]).toEqual({
      kind: "add",
      path: "src/new.ts",
      contents: "export const x = 1;\nexport const y = 2;",
      overwrite: false,
    });
  });

  it("parses Replace File as overwriting Add", () => {
    const ops = parsePatch(
      [
        "*** Begin Patch",
        "*** Replace File: src/cfg.ts",
        "+export const cfg = { v: 2 };",
        "*** End Patch",
      ].join("\n"),
    );
    expect(ops[0]).toEqual({
      kind: "add",
      path: "src/cfg.ts",
      contents: "export const cfg = { v: 2 };",
      overwrite: true,
    });
  });

  it("parses a Delete File envelope", () => {
    const ops = parsePatch(
      [
        "*** Begin Patch",
        "*** Delete File: src/dead.ts",
        "*** End Patch",
      ].join("\n"),
    );
    expect(ops).toEqual([{ kind: "delete", path: "src/dead.ts" }]);
  });

  it("supports multiple ops in one envelope", () => {
    const ops = parsePatch(
      [
        "*** Begin Patch",
        "*** Add File: a.txt",
        "+a",
        "*** Delete File: b.txt",
        "*** End Patch",
      ].join("\n"),
    );
    expect(ops).toHaveLength(2);
    expect(ops[0].kind).toBe("add");
    expect(ops[1].kind).toBe("delete");
  });

  it("rejects envelopes missing Begin Patch", () => {
    expect(() =>
      parsePatch(["*** Update File: x.ts", "@@ foo", "*** End Patch"].join("\n")),
    ).toThrow(/must start with/);
  });

  it("rejects envelopes missing End Patch", () => {
    expect(() =>
      parsePatch(["*** Begin Patch", "*** Add File: a", "+x"].join("\n")),
    ).toThrow(/must end with/);
  });

  it("rejects unknown directive", () => {
    expect(() =>
      parsePatch(
        ["*** Begin Patch", "*** Refactor File: x", "*** End Patch"].join("\n"),
      ),
    ).toThrow(/unknown directive/);
  });

  it("rejects Update with no @@ hunk", () => {
    expect(() =>
      parsePatch(
        ["*** Begin Patch", "*** Update File: x", "*** End Patch"].join("\n"),
      ),
    ).toThrow(/at least one "@@" hunk/);
  });

  it("rejects Add body line without leading +", () => {
    expect(() =>
      parsePatch(
        [
          "*** Begin Patch",
          "*** Add File: a",
          "no leading plus",
          "*** End Patch",
        ].join("\n"),
      ),
    ).toThrow(/must start with "\+"/);
  });

  it("rejects malformed hunk body marker", () => {
    expect(() =>
      parsePatch(
        [
          "*** Begin Patch",
          "*** Update File: x",
          "@@ anchor",
          "?bad-marker",
          "*** End Patch",
        ].join("\n"),
      ),
    ).toThrow(/must start with " ", "\+", or "-"/);
  });

  it("normalises CRLF input", () => {
    const ops = parsePatch(
      "*** Begin Patch\r\n*** Delete File: a.txt\r\n*** End Patch\r\n",
    );
    expect(ops).toEqual([{ kind: "delete", path: "a.txt" }]);
  });
});

// ── In-memory hunk application ──

describe("applyUpdateHunks", () => {
  it("applies a clean delete+add hunk", () => {
    const src = ["alpha", "beta", "gamma", ""].join("\n");
    const result = applyUpdateHunks(src, "x.ts", [
      {
        anchor: "beta",
        body: [
          { kind: "del", text: "beta" },
          { kind: "add", text: "BETA" },
        ],
      },
    ]);
    expect(result).toBe(["alpha", "BETA", "gamma", ""].join("\n"));
  });

  it("preserves missing trailing newline", () => {
    const src = ["alpha", "beta"].join("\n"); // no trailing newline
    const result = applyUpdateHunks(src, "x.ts", [
      {
        anchor: "beta",
        body: [
          { kind: "del", text: "beta" },
          { kind: "add", text: "B" },
        ],
      },
    ]);
    expect(result).toBe("alpha\nB");
  });

  it("throws loudly when anchor matches multiple lines", () => {
    const src = ["x", "x", "x"].join("\n");
    expect(() =>
      applyUpdateHunks(src, "dup.ts", [
        {
          anchor: "x",
          body: [
            { kind: "del", text: "x" },
            { kind: "add", text: "y" },
          ],
        },
      ]),
    ).toThrow(/matches 3 locations in dup\.ts; refine the @@ anchor/);
  });

  it("throws loudly when anchor not found", () => {
    expect(() =>
      applyUpdateHunks("hello\nworld\n", "x.ts", [
        {
          anchor: "ghost",
          body: [{ kind: "context", text: "hello" }],
        },
      ]),
    ).toThrow(/anchor "ghost" not found in x\.ts/);
  });

  it("throws loudly on context line mismatch", () => {
    expect(() =>
      applyUpdateHunks("alpha\nbeta\ngamma\n", "x.ts", [
        {
          anchor: "alpha",
          body: [
            { kind: "context", text: "alpha" },
            { kind: "context", text: "BETA" }, // wrong
          ],
        },
      ]),
    ).toThrow(/context mismatch in x\.ts at line 2/);
  });

  it("throws loudly on del line mismatch", () => {
    expect(() =>
      applyUpdateHunks("alpha\nbeta\n", "x.ts", [
        {
          anchor: "alpha",
          body: [
            { kind: "context", text: "alpha" },
            { kind: "del", text: "WRONG" },
          ],
        },
      ]),
    ).toThrow(/removed line mismatch in x\.ts at line 2/);
  });

  it("supports pure addition (no del lines)", () => {
    const result = applyUpdateHunks(
      "line1\nline3\n",
      "x.ts",
      [
        {
          anchor: "line1",
          body: [
            { kind: "context", text: "line1" },
            { kind: "add", text: "line2" },
            { kind: "context", text: "line3" },
          ],
        },
      ],
    );
    expect(result).toBe("line1\nline2\nline3\n");
  });

  it("applies multiple hunks in one update", () => {
    const src = ["one", "two", "three", "four"].join("\n");
    const result = applyUpdateHunks(src, "x.ts", [
      {
        anchor: "one",
        body: [
          { kind: "del", text: "one" },
          { kind: "add", text: "ONE" },
        ],
      },
      {
        anchor: "four",
        body: [
          { kind: "del", text: "four" },
          { kind: "add", text: "FOUR" },
        ],
      },
    ]);
    expect(result).toBe(["ONE", "two", "three", "FOUR"].join("\n"));
  });
});

// ── End-to-end with real filesystem ──

describe("applyPatchOps (filesystem)", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "0sec-apply-patch-"));
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  // Mirror tools.ts's resolveScopedPath chokepoint.
  function resolver(logical: string): string {
    const root = resolve(tmp);
    const candidate = isAbsolute(logical)
      ? resolve(logical)
      : resolve(root, logical);
    if (candidate !== root && !candidate.startsWith(root + "/")) {
      throw new Error(`Path escapes the allowed scope: ${logical}`);
    }
    return candidate;
  }

  it("round-trip: update writes the new content back", () => {
    const target = join(tmp, "greet.ts");
    writeFileSync(
      target,
      [
        "function greet(name) {",
        "  return `Hello ${name}`;",
        "}",
        "",
      ].join("\n"),
    );
    const patch = [
      "*** Begin Patch",
      "*** Update File: greet.ts",
      "@@ function greet",
      " function greet(name) {",
      "-  return `Hello ${name}`;",
      "+  return `Hi ${name}!`;",
      " }",
      "*** End Patch",
    ].join("\n");

    const ops = parsePatch(patch);
    const result = applyPatchOps(ops, resolver);
    expect(result.applied).toEqual([{ kind: "update", path: "greet.ts" }]);

    const after = readFileSync(target, "utf-8");
    expect(after).toBe(
      [
        "function greet(name) {",
        "  return `Hi ${name}!`;",
        "}",
        "",
      ].join("\n"),
    );
  });

  it("Add File creates a new file with the expected contents", () => {
    const patch = [
      "*** Begin Patch",
      "*** Add File: nested/sub/new.ts",
      "+export const X = 1;",
      "+export const Y = 2;",
      "*** End Patch",
    ].join("\n");
    const ops = parsePatch(patch);
    applyPatchOps(ops, resolver);

    const created = join(tmp, "nested/sub/new.ts");
    expect(existsSync(created)).toBe(true);
    expect(readFileSync(created, "utf-8")).toBe(
      "export const X = 1;\nexport const Y = 2;",
    );
  });

  it("Add File refuses to overwrite an existing file", () => {
    const target = join(tmp, "exists.ts");
    writeFileSync(target, "// pre-existing\n");

    const ops = parsePatch(
      [
        "*** Begin Patch",
        "*** Add File: exists.ts",
        "+// new",
        "*** End Patch",
      ].join("\n"),
    );

    expect(() => applyPatchOps(ops, resolver)).toThrow(
      /Add File "exists\.ts" failed — file already exists.*Replace File/,
    );
    // File untouched.
    expect(readFileSync(target, "utf-8")).toBe("// pre-existing\n");
  });

  it("Replace File overwrites an existing file", () => {
    const target = join(tmp, "exists.ts");
    writeFileSync(target, "// old\n");
    const ops = parsePatch(
      [
        "*** Begin Patch",
        "*** Replace File: exists.ts",
        "+// new",
        "*** End Patch",
      ].join("\n"),
    );
    applyPatchOps(ops, resolver);
    expect(readFileSync(target, "utf-8")).toBe("// new");
  });

  it("Delete File unlinks the file", () => {
    const target = join(tmp, "victim.ts");
    writeFileSync(target, "// soon to be gone\n");
    expect(existsSync(target)).toBe(true);

    const ops = parsePatch(
      [
        "*** Begin Patch",
        "*** Delete File: victim.ts",
        "*** End Patch",
      ].join("\n"),
    );
    applyPatchOps(ops, resolver);
    expect(existsSync(target)).toBe(false);
  });

  it("Delete File fails loudly on missing target", () => {
    const ops = parsePatch(
      [
        "*** Begin Patch",
        "*** Delete File: ghost.ts",
        "*** End Patch",
      ].join("\n"),
    );
    expect(() => applyPatchOps(ops, resolver)).toThrow(
      /Delete File "ghost\.ts" failed — file does not exist/,
    );
  });

  it("Update fails loudly on ambiguous context (3 matches)", () => {
    const target = join(tmp, "dup.ts");
    writeFileSync(target, ["x", "x", "x", ""].join("\n"));
    const ops = parsePatch(
      [
        "*** Begin Patch",
        "*** Update File: dup.ts",
        "@@ x",
        "-x",
        "+y",
        "*** End Patch",
      ].join("\n"),
    );
    expect(() => applyPatchOps(ops, resolver)).toThrow(
      /context "x" matches 3 locations in dup\.ts; refine the @@ anchor to be unique/,
    );
    // File untouched.
    expect(readFileSync(target, "utf-8")).toBe(["x", "x", "x", ""].join("\n"));
  });

  it("Update fails loudly when anchor not found", () => {
    const target = join(tmp, "f.ts");
    writeFileSync(target, "alpha\nbeta\n");
    const ops = parsePatch(
      [
        "*** Begin Patch",
        "*** Update File: f.ts",
        "@@ ghost-signature",
        " alpha",
        "*** End Patch",
      ].join("\n"),
    );
    expect(() => applyPatchOps(ops, resolver)).toThrow(
      /anchor "ghost-signature" not found in f\.ts/,
    );
  });

  it("refuses paths that escape scope", () => {
    const ops = parsePatch(
      [
        "*** Begin Patch",
        "*** Add File: ../escape.ts",
        "+nope",
        "*** End Patch",
      ].join("\n"),
    );
    expect(() => applyPatchOps(ops, resolver)).toThrow(/escapes the allowed scope/);
  });
});
