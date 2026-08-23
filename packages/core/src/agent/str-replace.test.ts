import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { ToolExecutor, getToolsForRole } from "./tools.js";
import type { ToolContext, ToolResultMeta } from "./types.js";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// str_replace — exact-string file edit (Claude text_editor contract). These
// executor-level tests pin the match/uniqueness semantics, the scope gate, and
// the display-only edit-card meta.

const baseCtx: ToolContext = {
  target: "https://example.com",
  scanId: "str-replace-test",
  findings: [],
  attackResults: [],
  targetInfo: {},
};

describe("str_replace (executor-level integration)", () => {
  let tmp: string;
  let scopedExecutor: ToolExecutor;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "0sec-str-replace-"));
    scopedExecutor = new ToolExecutor({ ...baseCtx, scopePath: tmp }, null);
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("replaces a unique exact match and reports the change", async () => {
    const target = join(tmp, "greet.ts");
    writeFileSync(target, ["function greet(name) {", "  return `Hello ${name}`;", "}", ""].join("\n"));

    const result = await scopedExecutor.execute({
      name: "str_replace",
      arguments: {
        path: "greet.ts",
        old_string: "  return `Hello ${name}`;",
        new_string: "  return `Hi ${name}!`;",
      },
    });

    expect(result.success).toBe(true);
    expect(result.output).toEqual({ path: "greet.ts", replacements: 1 });
    expect(readFileSync(target, "utf-8")).toBe(
      ["function greet(name) {", "  return `Hi ${name}!`;", "}", ""].join("\n"),
    );
  });

  it("attaches a display-only edit-card meta with added/removed and a diff", async () => {
    const target = join(tmp, "meta.ts");
    writeFileSync(target, ["const a = 1;", "const b = 2;", ""].join("\n"));

    const result = await scopedExecutor.execute({
      name: "str_replace",
      arguments: { path: "meta.ts", old_string: "const b = 2;", new_string: "const b = 3;\nconst c = 4;" },
    });

    expect(result.success).toBe(true);
    const meta = result.meta as ToolResultMeta;
    expect(meta.kind).toBe("edit");
    expect(meta.path).toBe("meta.ts");
    expect(meta.removed).toBe(1);
    expect(meta.added).toBe(2);
    expect(meta.diff).toBe(["-const b = 2;", "+const b = 3;", "+const c = 4;"].join("\n"));
    // Model-facing shape carries no diff — meta is display-only.
    expect(result.output).not.toHaveProperty("diff");
  });

  it("errors when old_string is not found", async () => {
    const target = join(tmp, "nf.ts");
    writeFileSync(target, "const x = 1;\n");

    const result = await scopedExecutor.execute({
      name: "str_replace",
      arguments: { path: "nf.ts", old_string: "const y = 2;", new_string: "const z = 3;" },
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/not found in nf\.ts/);
    // File untouched.
    expect(readFileSync(target, "utf-8")).toBe("const x = 1;\n");
  });

  it("refuses a non-unique match unless replace_all is set", async () => {
    const target = join(tmp, "dup.ts");
    writeFileSync(target, ["x", "x", "x", ""].join("\n"));

    const result = await scopedExecutor.execute({
      name: "str_replace",
      arguments: { path: "dup.ts", old_string: "x", new_string: "y" },
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/matches 3 locations in dup\.ts; not unique/);
    expect(result.error).toMatch(/replace_all/);
    // File untouched.
    expect(readFileSync(target, "utf-8")).toBe(["x", "x", "x", ""].join("\n"));
  });

  it("replaces every occurrence with replace_all", async () => {
    const target = join(tmp, "all.ts");
    writeFileSync(target, ["x", "x", "x", ""].join("\n"));

    const result = await scopedExecutor.execute({
      name: "str_replace",
      arguments: { path: "all.ts", old_string: "x", new_string: "y", replace_all: true },
    });

    expect(result.success).toBe(true);
    expect(result.output).toEqual({ path: "all.ts", replacements: 3 });
    expect(readFileSync(target, "utf-8")).toBe(["y", "y", "y", ""].join("\n"));
    expect((result.meta as ToolResultMeta).removed).toBe(3);
    expect((result.meta as ToolResultMeta).added).toBe(3);
  });

  it("is whitespace/indentation-sensitive — a TAB indent is not matched by spaces", async () => {
    const target = join(tmp, "ws.ts");
    // Body indented with a TAB; the model supplies spaces.
    writeFileSync(target, ["function f() {", "\treturn 1;", "}", ""].join("\n"));

    const result = await scopedExecutor.execute({
      name: "str_replace",
      arguments: { path: "ws.ts", old_string: "  return 1;", new_string: "  return 2;" },
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/not found/);
    expect(readFileSync(target, "utf-8")).toBe(["function f() {", "\treturn 1;", "}", ""].join("\n"));

    // The exact tab-indented old_string succeeds.
    const ok = await scopedExecutor.execute({
      name: "str_replace",
      arguments: { path: "ws.ts", old_string: "\treturn 1;", new_string: "\treturn 2;" },
    });
    expect(ok.success).toBe(true);
    expect(readFileSync(target, "utf-8")).toBe(["function f() {", "\treturn 2;", "}", ""].join("\n"));
  });

  it("treats `$` in new_string literally (no regex/replacement-pattern expansion)", async () => {
    const target = join(tmp, "dollar.ts");
    writeFileSync(target, "const a = 1;\n");

    const result = await scopedExecutor.execute({
      name: "str_replace",
      arguments: { path: "dollar.ts", old_string: "const a = 1;", new_string: "const a = `$&$1`;" },
    });

    expect(result.success).toBe(true);
    expect(readFileSync(target, "utf-8")).toBe("const a = `$&$1`;\n");
  });

  it("refuses a path that escapes the scope", async () => {
    const outside = mkdtempSync(join(tmpdir(), "0sec-str-replace-out-"));
    const secret = join(outside, "secret.txt");
    writeFileSync(secret, "top secret\n");
    try {
      const result = await scopedExecutor.execute({
        name: "str_replace",
        arguments: { path: "../".repeat(8) + join(outside, "secret.txt").replace(/^\/+/, ""), old_string: "top secret", new_string: "pwned" },
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/escapes the allowed scope/);
      // Absolute-path escape is refused too.
      const abs = await scopedExecutor.execute({
        name: "str_replace",
        arguments: { path: secret, old_string: "top secret", new_string: "pwned" },
      });
      expect(abs.success).toBe(false);
      expect(abs.error).toMatch(/escapes the allowed scope/);
      // Secret untouched.
      expect(readFileSync(secret, "utf-8")).toBe("top secret\n");
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("does not follow a symlink pointing outside the scope", async () => {
    const outside = mkdtempSync(join(tmpdir(), "0sec-str-replace-symout-"));
    const secret = join(outside, "creds.txt");
    writeFileSync(secret, "aws_key\n");
    try {
      symlinkSync(secret, join(tmp, "link.txt"));
      const result = await scopedExecutor.execute({
        name: "str_replace",
        arguments: { path: "link.txt", old_string: "aws_key", new_string: "pwned" },
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/escapes the allowed scope/);
      expect(readFileSync(secret, "utf-8")).toBe("aws_key\n");
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("errors when the file does not exist", async () => {
    const result = await scopedExecutor.execute({
      name: "str_replace",
      arguments: { path: "nope.ts", old_string: "a", new_string: "b" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/file does not exist/);
  });

  it("rejects an empty old_string", async () => {
    writeFileSync(join(tmp, "e.ts"), "x\n");
    const result = await scopedExecutor.execute({
      name: "str_replace",
      arguments: { path: "e.ts", old_string: "", new_string: "y" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/must not be empty/);
  });

  it("rejects an identical old_string / new_string no-op", async () => {
    writeFileSync(join(tmp, "same.ts"), "same\n");
    const result = await scopedExecutor.execute({
      name: "str_replace",
      arguments: { path: "same.ts", old_string: "same", new_string: "same" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/identical/);
  });

  it("edits a file in a nested subdirectory of the scope", async () => {
    mkdirSync(join(tmp, "src", "lib"), { recursive: true });
    const nested = join(tmp, "src", "lib", "n.ts");
    writeFileSync(nested, "const v = 1;\n");
    const result = await scopedExecutor.execute({
      name: "str_replace",
      arguments: { path: "src/lib/n.ts", old_string: "const v = 1;", new_string: "const v = 2;" },
    });
    expect(result.success).toBe(true);
    expect(readFileSync(nested, "utf-8")).toBe("const v = 2;\n");
  });
});

describe("str_replace scope + role gating (mirrors apply_patch)", () => {
  it("refuses to run without a scoped local directory", async () => {
    const executor = new ToolExecutor({ ...baseCtx }, null);
    const result = await executor.execute({
      name: "str_replace",
      arguments: { path: "x.ts", old_string: "a", new_string: "b" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/requires a scoped local directory/);
  });

  it("is offered to the verify role only alongside apply_patch when scoped", () => {
    const scoped = getToolsForRole("verify", { hasScope: true }).map((t) => t.name);
    expect(scoped).toContain("str_replace");
    expect(scoped).toContain("apply_patch");

    const unscoped = getToolsForRole("verify").map((t) => t.name);
    expect(unscoped).not.toContain("str_replace");
    expect(unscoped).not.toContain("apply_patch");
  });
});
