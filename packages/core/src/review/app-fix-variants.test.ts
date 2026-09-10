/**
 * packages/core/src/review/app-fix-variants.test.ts
 *
 * Tests for the application security-fix variant hunt. Uses real mini git repos
 * constructed in temp directories to validate the full end-to-end path:
 * git resolution → diff analysis → sibling detection → guard check.
 */

import { execFileSync, execSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { huntAppFixVariants, appFixVariantsToSeedFindings } from "./app-fix-variants.js";
import type { AppFixVariantHuntResult } from "./app-fix-variants.js";

// ── Test repo builder ─────────────────────────────────────────────────────────

function git(dir: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: dir,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
  });
}

interface TestRepo {
  path: string;
  /** SHA of each commit, keyed by commit message prefix. */
  commits: Record<string, string>;
  /** HEAD commit SHA. */
  head: string;
  cleanup(): void;
}

/**
 * Build a mini git repo with application code for variant hunting tests.
 * Returns paths and commit SHAs so tests can reference specific commits.
 */
function buildTestRepo(name: string, files: Record<string, string>): TestRepo {
  const dir = mkdtempSync(join(tmpdir(), `app-fix-variants-${name}-`));
  const commits: Record<string, string> = {};

  try {
    git(dir, ["init", "-b", "main"]);
    git(dir, ["config", "user.email", "test@0sec.dev"]);
    git(dir, ["config", "user.name", "0sec Test"]);

    for (const [filePath, content] of Object.entries(files)) {
      const fullPath = join(dir, filePath);
      writeFileSync(fullPath, content, "utf8");
    }

    // First commit — the vulnerable baseline
    git(dir, ["add", "-A"]);
    git(dir, ["commit", "-m", "initial: vulnerable baseline"]);
    const initialSha = git(dir, ["rev-parse", "HEAD"]).trim();
    commits["initial"] = initialSha;

    // Subsequent commits can be added by the test
    return {
      path: dir,
      commits,
      get head() {
        return git(dir, ["rev-parse", "HEAD"]).trim();
      },
      cleanup() {
        rmSync(dir, { recursive: true, force: true });
      },
    };
  } catch (err) {
    rmSync(dir, { recursive: true, force: true });
    throw err;
  }
}

function makeCommit(repo: TestRepo, message: string, files: Record<string, string>): string {
  for (const [filePath, content] of Object.entries(files)) {
    const fullPath = join(repo.path, filePath);
    writeFileSync(fullPath, content, "utf8");
  }
  git(repo.path, ["add", "-A"]);
  git(repo.path, ["commit", "-m", message]);
  const sha = git(repo.path, ["rev-parse", "HEAD"]).trim();
  repo.commits[message] = sha;
  return sha;
}

// ── JS/TS authorization fix fixture ──────────────────────────────────────────

const JS_AUTH_BASELINE = `// handlers.js
const express = require("express");
const router = express.Router();

// GET /api/admin — admin-only endpoint
function getAdminConfig(req, res) {
  // NO auth check — vulnerable
  const config = { secretKey: "top-secret", featureFlags: ["dark-mode"] };
  res.json(config);
}

// GET /api/users — list users
function getUsers(req, res) {
  const users = [{ id: 1, name: "Alice" }, { id: 2, name: "Bob" }];
  res.json(users);
}

// POST /api/admin/update — update admin config
function updateAdminConfig(req, res) {
  // NO auth check — vulnerable
  const { key, value } = req.body;
  console.log("Updating admin config");
  res.json({ ok: true });
}

// DELETE /api/admin/config — delete config (safe sibling already guarded)
function deleteAdminConfig(req, res) {
  if (!req.headers.authorization || req.headers.authorization !== "Bearer admin-token") {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const { key } = req.body;
  console.log("Deleting config key:", key);
  res.json({ ok: true });
}
`;

const JS_AUTH_FIX = `// handlers.js
const express = require("express");
const router = express.Router();

function requireAdmin(req, res, next) {
  if (!req.headers.authorization || req.headers.authorization !== "Bearer admin-token") {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// GET /api/admin — admin-only endpoint
function getAdminConfig(req, res) {
  if (!req.headers.authorization || req.headers.authorization !== "Bearer admin-token") {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const config = { secretKey: "top-secret", featureFlags: ["dark-mode"] };
  res.json(config);
}

// GET /api/users — list users
function getUsers(req, res) {
  const users = [{ id: 1, name: "Alice" }, { id: 2, name: "Bob" }];
  res.json(users);
}

// POST /api/admin/update — update admin config
function updateAdminConfig(req, res) {
  // NO auth check — still vulnerable
  const { key, value } = req.body;
  console.log("Updating admin config");
  res.json({ ok: true });
}

// DELETE /api/admin/config — delete config (still guarded)
function deleteAdminConfig(req, res) {
  if (!req.headers.authorization || req.headers.authorization !== "Bearer admin-token") {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const { key } = req.body;
  console.log("Deleting config key:", key);
  res.json({ ok: true });
}
`;

// ── Python validation fix fixture ────────────────────────────────────────────

const PY_VALIDATION_BASELINE = `# main.py
from flask import request, jsonify

def process_report(report_id, data):
    # No input validation — vulnerable
    query = f"SELECT * FROM reports WHERE id = {report_id}"
    execute_query(query)
    return jsonify({"processed": True})

def handle_upload(file_data):
    # No validation — vulnerable
    save_file(file_data)
    return jsonify({"uploaded": True, "size": len(file_data)})

def safe_process(report_id, data):
    if not isinstance(report_id, int) or report_id <= 0:
        return jsonify({"error": "Invalid report ID"}), 400
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid data"}), 400
    query = f"SELECT * FROM reports WHERE id = {report_id}"
    execute_query(query)
    return jsonify({"processed": True})
`;

const PY_VALIDATION_FIX = `# main.py
from flask import request, jsonify

def process_report(report_id, data):
    if not isinstance(report_id, int) or report_id <= 0:
        return jsonify({"error": "Invalid report ID"}), 400
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid data"}), 400
    query = f"SELECT * FROM reports WHERE id = {report_id}"
    execute_query(query)
    return jsonify({"processed": True})

def handle_upload(file_data):
    # No validation — still vulnerable
    save_file(file_data)
    return jsonify({"uploaded": True, "size": len(file_data)})

def safe_process(report_id, data):
    if not isinstance(report_id, int) or report_id <= 0:
        return jsonify({"error": "Invalid report ID"}), 400
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid data"}), 400
    query = f"SELECT * FROM reports WHERE id = {report_id}"
    execute_query(query)
    return jsonify({"processed": True})
`;

// ── Refactor-only commit fixture (logging change, no security fix) ──────────

const JS_REFACTOR_BASELINE = `// logger.js
function logInfo(message) {
  console.log("[INFO]", message);
}

function logError(message) {
  console.log("[ERROR]", message);
}

function processData(data) {
  logInfo("Processing data");
  return data.filter(Boolean);
}
`;

const JS_REFACTOR_CHANGE = `// logger.js
function logInfo(message, context) {
  console.log("[INFO]", message, context || "");
}

function logError(message, error) {
  console.log("[ERROR]", message, error?.stack || error);
}

function processData(data) {
  logInfo("Processing data", { size: data.length });
  return data.filter(Boolean);
}
`;

// ── TS auth fix fixture ──────────────────────────────────────────────────────

const TS_AUTH_BASELINE = `// admin.service.ts
import { Injectable } from "@nestjs/common";

@Injectable()
export class AdminService {
  getDashboard(): DashboardData {
    // No auth check — vulnerable
    return { users: 100, revenue: 50000, secret: "redacted" };
  }

  getSystemConfig(): SystemConfig {
    if (this.authService.isAdmin()) {
      return this.configRepository.getSystemConfig();
    }
    throw new ForbiddenException();
  }
}
`;

const TS_AUTH_FIX = `// admin.service.ts
import { Injectable } from "@nestjs/common";

@Injectable()
export class AdminService {
  getDashboard(): DashboardData {
    if (!this.authService.isAdmin()) {
      throw new ForbiddenException();
    }
    return { users: 100, revenue: 50000, secret: "redacted" };
  }

  getSystemConfig(): SystemConfig {
    if (this.authService.isAdmin()) {
      return this.configRepository.getSystemConfig();
    }
    throw new ForbiddenException();
  }
}
`;

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("huntAppFixVariants", () => {
  describe("JS/TS authorization fix in handlers", () => {
    let repo: TestRepo;
    let fixSha: string;

    beforeEach(() => {
      repo = buildTestRepo("js-auth", { "handlers.js": JS_AUTH_BASELINE });
      fixSha = makeCommit(repo, "fix: add auth check to getAdminConfig", {
        "handlers.js": JS_AUTH_FIX,
      });
    });

    afterEach(() => {
      repo.cleanup();
    });

    it("finds unpatched admin handler (updateAdminConfig)", () => {
      const result = huntAppFixVariants({
        repoPath: repo.path,
        fixCommit: fixSha,
      });

      expect(result.fixCommit).toBe(fixSha);
      expect(result.fixSubject).toContain("add auth check to getAdminConfig");
      expect(result.errors).toHaveLength(0);

      // Should find updateAdminConfig as unguarded candidate
      const candidates = result.candidates.filter((c) => !c.guardPresent);
      const updateFn = candidates.find((c) => c.functionName === "updateAdminConfig");
      expect(updateFn).toBeDefined();
      expect(updateFn!.checkType).toBe("authorization");
      expect(updateFn!.language).toBe("javascript");
    });

    it("does NOT flag already-guarded deleteAdminConfig", () => {
      const result = huntAppFixVariants({
        repoPath: repo.path,
        fixCommit: fixSha,
      });

      expect(result.candidates.some((candidate) => candidate.functionName === "deleteAdminConfig")).toBe(false);
    });

    it("excludes the fixed function itself", () => {
      const result = huntAppFixVariants({
        repoPath: repo.path,
        fixCommit: fixSha,
      });

      const fixedFn = result.candidates.find((c) => c.functionName === "getAdminConfig");
      expect(fixedFn).toBeUndefined();
    });

    it("records the fixed function and check type in metadata", () => {
      const result = huntAppFixVariants({
        repoPath: repo.path,
        fixCommit: fixSha,
      });

      expect(Object.keys(result.fixedFunctions).length).toBeGreaterThan(0);
      const handlersFns = result.fixedFunctions["handlers.js"];
      expect(handlersFns).toBeDefined();
      expect(handlersFns).toContain("getAdminConfig");
      expect(result.checkType).toBe("authorization");
    });

    it("converts to SeedFindings with correct shape", () => {
      const result = huntAppFixVariants({
        repoPath: repo.path,
        fixCommit: fixSha,
      });

      const seeds = appFixVariantsToSeedFindings(result);
      expect(seeds.length).toBeGreaterThan(0);

      for (const seed of seeds) {
        expect(seed.source).toBe("app-fix-variant-hunt");
        expect(seed.confidence).toBe(0.3);
        expect(seed.file).toBeTruthy();
        expect(seed.metadata?.fixCommit).toBe(fixSha);
        expect(seed.metadata?.checkType).toBe("authorization");
      }
    });
  });

  describe("Python validation fix", () => {
    let repo: TestRepo;
    let fixSha: string;

    beforeEach(() => {
      repo = buildTestRepo("py-validation", { "main.py": PY_VALIDATION_BASELINE });
      fixSha = makeCommit(repo, "fix: add input validation to process_report", {
        "main.py": PY_VALIDATION_FIX,
      });
    });

    afterEach(() => {
      repo.cleanup();
    });

    it("finds unpatched sibling (handle_upload)", () => {
      const result = huntAppFixVariants({
        repoPath: repo.path,
        fixCommit: fixSha,
      });

      const candidates = result.candidates.filter((c) => !c.guardPresent);
      const uploadFn = candidates.find((c) => c.functionName === "handle_upload");
      expect(uploadFn).toBeDefined();
      expect(uploadFn!.checkType).toBe("validation");
      expect(uploadFn!.language).toBe("python");
    });

    it("does not flag already-guarded safe_process", () => {
      const result = huntAppFixVariants({
        repoPath: repo.path,
        fixCommit: fixSha,
      });

      expect(result.candidates.some((candidate) => candidate.functionName === "safe_process")).toBe(false);
    });

  });

  describe("TypeScript auth fix", () => {
    let repo: TestRepo;
    let fixSha: string;

    beforeEach(() => {
      repo = buildTestRepo("ts-auth", { "admin.service.ts": TS_AUTH_BASELINE });
      fixSha = makeCommit(repo, "fix: add auth guard to getDashboard", {
        "admin.service.ts": TS_AUTH_FIX,
      });
    });

    afterEach(() => {
      repo.cleanup();
    });

    it("finds unguarded variant comment in TS", () => {
      const result = huntAppFixVariants({
        repoPath: repo.path,
        fixCommit: fixSha,
      });

      const candidates = result.candidates.filter((c) => !c.guardPresent);
      expect(candidates.length).toBeGreaterThanOrEqual(1);

      // Verify TS language coverage
      expect(result.languageCoverage.typescript).toBe("supported");
    });
  });

  describe("Invalid inputs and edge cases", () => {
    it("throws on non-existent ref", () => {
      // Use a real git repo but a fake ref
      const repo = buildTestRepo("bad-ref", { "a.js": "const x = 1;" });
      try {
        expect(() => {
          huntAppFixVariants({
            repoPath: repo.path,
            fixCommit: "deadbeef1234567890123456789012345678901",
          });
        }).toThrow(/not.*resolv|invalid.*ref|not.*valid/i);
      } finally {
        repo.cleanup();
      }
    });

    it("throws on non-git directory", () => {
      const dir = mkdtempSync(join(tmpdir(), "app-fix-variants-non-git-"));
      try {
        expect(() => {
          huntAppFixVariants({
            repoPath: dir,
            fixCommit: "abc123",
          });
        }).toThrow(/not.*valid git|not.*git/i);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("reports coverage for skipped languages in result", () => {
      // A repo with only C files should find nothing but still report coverage
      const repo = buildTestRepo("c-only", { "main.c": "int main() { return 0; }" });
      // Also needs an empty JS file that's not a fix
      makeCommit(repo, "fix: non-security change", { "main.c": "int main() { return 1; }" });

      try {
        // The fix commit only touches .c (skipped) — needs a JS/TS/Python commit
        // Instead, test a repo with mixed langs where fix touches C
        const result = huntAppFixVariants({
          repoPath: repo.path,
          fixCommit: repo.commits["fix: non-security change"],
        });

        expect(result.languageCoverage.c).toBe("skipped");
        expect(result.languageCoverage.javascript).toBe("supported");
        expect(result.languageCoverage.python).toBe("supported");
      } finally {
        repo.cleanup();
      }
    });
  });

  describe("Refactor-only commits yield no security candidates", () => {
    let repo: TestRepo;

    beforeEach(() => {
      repo = buildTestRepo("refactor", { "logger.js": JS_REFACTOR_BASELINE });
      makeCommit(repo, "refactor: add context parameter to log functions", {
        "logger.js": JS_REFACTOR_CHANGE,
      });
    });

    afterEach(() => {
      repo.cleanup();
    });

    it("refactor commit yields no security-relevant candidates", () => {
      const result = huntAppFixVariants({
        repoPath: repo.path,
        fixCommit: repo.commits["refactor: add context parameter to log functions"],
      });

      expect(result.candidates).toEqual([]);
    });
  });

  describe("Empty and edge case repos", () => {
    it("works with no modified JS/TS/Python files", () => {
      const repo = buildTestRepo("only-c-fix", { "main.c": "int main() { return 0; }" });
      makeCommit(repo, "fix: change return", { "main.c": "int main() { return 42; }" });

      try {
        const result = huntAppFixVariants({
          repoPath: repo.path,
          fixCommit: repo.commits["fix: change return"],
        });

        // Should have no candidates (only C files processed)
        expect(result.candidates).toHaveLength(0);
        expect(result.fixSubject).toBe("fix: change return");
      } finally {
        repo.cleanup();
      }
    });
  });
});

describe("appFixVariantsToSeedFindings", () => {

  it("returns empty array for result with no candidates", () => {
    const seeds = appFixVariantsToSeedFindings({
      candidates: [],
      errors: [],
      fixCommit: "0000000000000000000000000000000000000000",
      fixSubject: "no changes",
      fixedFiles: [],
      fixedFunctions: {},
      addedCheck: "(none)",
      checkType: "other",
      languageCoverage: {},
    });

    expect(seeds).toHaveLength(0);
  });
});