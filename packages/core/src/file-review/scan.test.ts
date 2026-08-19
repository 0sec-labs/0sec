import { describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ReviewStore } from "./store.js";
import { compileMatchers, collectScannableFiles, matchFileContent, runReviewScan } from "./scan.js";
import { DEFAULT_REVIEW_MATCHERS } from "./matchers-default.js";
import type { ReviewMatcherSpec } from "./types.js";

function fixtureRepo(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "0sec-fr-scan-"));
  fs.mkdirSync(path.join(root, "src/api"), { recursive: true });
  fs.mkdirSync(path.join(root, "node_modules/dep"), { recursive: true });
  fs.writeFileSync(
    path.join(root, "src/api/users.ts"),
    [
      'const q = `SELECT * FROM users WHERE id = ${req.params.id}`;',
      "fetch(req.body.url);",
      "const apiKey = 'sk-abc123def456ghi789jkl012mno345';",
    ].join("\n"),
  );
  fs.writeFileSync(path.join(root, "src/api/health.ts"), "export const ok = true;\n");
  fs.writeFileSync(path.join(root, "node_modules/dep/index.js"), "eval('malicious');\n");
  return root;
}

describe("collectScannableFiles", () => {
  it("skips node_modules and non-source files", () => {
    const root = fixtureRepo();
    const files = collectScannableFiles(root);
    expect(files).toContain("src/api/users.ts");
    expect(files).toContain("src/api/health.ts");
    expect(files.some((f) => f.startsWith("node_modules"))).toBe(false);
  });

  it("honors caller ignore patterns", () => {
    const root = fixtureRepo();
    const files = collectScannableFiles(root, ["**/health.ts"]);
    expect(files).not.toContain("src/api/health.ts");
  });
});

describe("compileMatchers", () => {
  it("compiles valid specs", () => {
    const specs = DEFAULT_REVIEW_MATCHERS;
    const compiled = compileMatchers(specs);
    expect(compiled.length).toBe(specs.length);
  });

  it("rejects duplicate and malformed slugs", () => {
    const bad: ReviewMatcherSpec[] = [
      {
        version: 1,
        slug: "Bad_Slug",
        description: "x",
        noiseTier: "normal",
        filePatterns: ["**/*.ts"],
        patterns: [{ source: "x", label: "x" }],
      },
    ];
    expect(() => compileMatchers(bad)).toThrow(/kebab-case/);
    expect(() => compileMatchers(DEFAULT_REVIEW_MATCHERS, { existingSlugs: ["rce"] })).toThrow(/already in use/);
  });

  it("rejects specs whose examples don't match", () => {
    const bad: ReviewMatcherSpec[] = [
      {
        version: 1,
        slug: "no-match",
        description: "x",
        noiseTier: "normal",
        filePatterns: ["**/*.ts"],
        patterns: [{ source: "zzz-never", label: "x" }],
        examples: ["this does not contain the pattern"],
      },
    ];
    expect(() => compileMatchers(bad)).toThrow(/example does not match/);
  });
});

describe("matchFileContent", () => {
  it("fires only on matching file globs", () => {
    const compiled = compileMatchers([
      {
        version: 1,
        slug: "ts-only",
        description: "x",
        noiseTier: "normal",
        filePatterns: ["**/*.ts"],
        patterns: [{ source: "eval\\s*\\(", label: "eval" }],
      },
    ]);
    const hits = matchFileContent(compiled[0], "a.ts", "eval(x);");
    expect(hits).toHaveLength(1);
    expect(hits[0].lineNumbers).toEqual([1]);
    expect(matchFileContent(compiled[0], "a.py", "eval(x);")).toEqual([]);
  });
});

describe("runReviewScan", () => {
  it("writes candidates and pending status into records", () => {
    const root = fixtureRepo();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "0sec-fr-data-"));
    const store = new ReviewStore({ dataDir: dir });
    const matchers = compileMatchers(DEFAULT_REVIEW_MATCHERS);

    const result = runReviewScan(store, { projectId: "p", rootPath: root, matchers });
    expect(result.filesScanned).toBe(2); // node_modules excluded
    expect(result.candidatesFound).toBeGreaterThan(0);
    expect(result.matcherHits["sql-injection"]).toContain("src/api/users.ts");

    const record = store.readRecord("p", "src/api/users.ts");
    expect(record?.status).toBe("pending");
    expect(record?.candidates.length).toBeGreaterThan(0);
    expect(record?.fileHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("re-scan is additive and does not duplicate candidates", () => {
    const root = fixtureRepo();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "0sec-fr-data-"));
    const store = new ReviewStore({ dataDir: dir });
    const matchers = compileMatchers(DEFAULT_REVIEW_MATCHERS);

    runReviewScan(store, { projectId: "p", rootPath: root, matchers });
    const first = store.readRecord("p", "src/api/users.ts")!.candidates.length;
    runReviewScan(store, { projectId: "p", rootPath: root, matchers });
    const second = store.readRecord("p", "src/api/users.ts")!.candidates.length;
    expect(second).toBe(first);
  });

  it("analyzed files with unchanged hash stay out of the pending pool", () => {
    const root = fixtureRepo();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "0sec-fr-data-"));
    const store = new ReviewStore({ dataDir: dir });
    const matchers = compileMatchers(DEFAULT_REVIEW_MATCHERS);

    runReviewScan(store, { projectId: "p", rootPath: root, matchers });
    const rec = store.readRecord("p", "src/api/users.ts")!;
    rec.status = "analyzed";
    rec.analyzedHash = rec.fileHash;
    store.writeRecord(rec);

    runReviewScan(store, { projectId: "p", rootPath: root, matchers });
    expect(store.readRecord("p", "src/api/users.ts")?.status).toBe("analyzed");
  });

  it("changed content re-enters the pending pool", () => {
    const root = fixtureRepo();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "0sec-fr-data-"));
    const store = new ReviewStore({ dataDir: dir });
    const matchers = compileMatchers(DEFAULT_REVIEW_MATCHERS);

    runReviewScan(store, { projectId: "p", rootPath: root, matchers });
    const rec = store.readRecord("p", "src/api/users.ts")!;
    rec.status = "analyzed";
    rec.analyzedHash = rec.fileHash;
    store.writeRecord(rec);

    fs.appendFileSync(path.join(root, "src/api/users.ts"), "\neval(userInput);\n");
    runReviewScan(store, { projectId: "p", rootPath: root, matchers });
    expect(store.readRecord("p", "src/api/users.ts")?.status).toBe("pending");
  });
});
