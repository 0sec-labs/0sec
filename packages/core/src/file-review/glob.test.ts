import { describe, expect, it } from "vitest";
import { globToRegex, matchGlob, matchAnyGlob, normalizeRelPath } from "./glob.js";

describe("globToRegex", () => {
  it("matches ** across directories", () => {
    expect(matchGlob("src/a/b/file.ts", "**/*.ts")).toBe(true);
    expect(matchGlob("file.ts", "**/*.ts")).toBe(true);
    expect(matchGlob("src/a/file.js", "**/*.ts")).toBe(false);
  });

  it("single * stays within one directory", () => {
    expect(matchGlob("src/file.ts", "src/*.ts")).toBe(true);
    expect(matchGlob("src/sub/file.ts", "src/*.ts")).toBe(false);
  });

  it("supports brace alternation and ?", () => {
    expect(matchGlob("a/file.tsx", "**/*.{ts,tsx}")).toBe(true);
    expect(matchGlob("a/file.ts", "**/*.{ts,tsx}")).toBe(true);
    expect(matchGlob("a/file.py", "**/*.{ts,tsx}")).toBe(false);
    expect(matchGlob("src/x1.ts", "src/x?.ts")).toBe(true);
    expect(matchGlob("src/x12.ts", "src/x?.ts")).toBe(false);
  });

  it("escapes regex specials in literals", () => {
    const re = globToRegex("a.b/c+d.ts");
    expect(re.test("a.b/c+d.ts")).toBe(true);
    expect(re.test("axb/c+d.ts")).toBe(false);
  });
});

describe("matchAnyGlob + normalizeRelPath", () => {
  it("matches any pattern", () => {
    expect(matchAnyGlob("node_modules/x/y.js", ["**/node_modules/**"])).toBe(true);
    expect(matchAnyGlob("src/x.ts", ["**/node_modules/**"])).toBe(false);
  });

  it("normalizes separators and ./ prefix", () => {
    expect(normalizeRelPath(".\\src\\a.ts")).toBe("src/a.ts");
    expect(normalizeRelPath("./src/a.ts")).toBe("src/a.ts");
  });
});
