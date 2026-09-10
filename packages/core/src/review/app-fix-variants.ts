/**
 * packages/core/src/review/app-fix-variants.ts
 *
 * Application security-fix-driven variant hunting — the "foxguard for app code"
 * complement. Given a repo checkout and a security-fix commit SHA, it:
 *
 *   1. Resolves the commit to its full SHA and first-parent preimage.
 *   2. Diffs the fix against its parent to extract added authorization /
 *      validation guard patterns from JS/TS/Python functions the fix touched.
 *   3. Scans the checked-out source for structurally similar function paths
 *      that lack the guard — candidate unpatched variant sites.
 *   4. Excludes the fixed site itself and any sibling that already carries an
 *      equivalent guard.
 *
 * The work is pure read-only git + heuristic regex function extraction — no
 * parser, no AST, no model calls. Candidate coverage is a hypothesis, never a
 * confirmed vulnerability. Language support is explicit: JS/TS/Python are
 * supported; other languages report "skipped".
 *
 * Design constraints:
 *   - Fails HARD (throws) on invalid refs, non-git trees, commits with no
 *     parent (root commits), and options that can't be satisfied. The caller
 *     must catch and surface the error — no silent empty success.
 *   - All changed JS/TS/Python functions in the fix commit are analyzed, not
 *     just the first one.
 *   - Guard checking is heuristic and conservative: a sibling is skipped
 *     (excluded from candidates) only if the extracted guard pattern appears
 *     within its body. There is no caller escape hatch for safe siblings.
 *   - Results are deterministically ordered (stable sort by file then line).
 */

import { execFileSync } from "node:child_process";
import { readFileSync, lstatSync, realpathSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";
import type { SeedFinding } from "@0sec/shared";

// ── Types ────────────────────────────────────────────────────────────────────

export type FixCheckType = "authorization" | "validation" | "other";

export interface AppFixVariantCandidate {
  /** Repo-relative POSIX path to the file containing the variant. */
  file: string;
  /** 1-indexed line of the variant function definition. */
  line: number;
  /** Name of the unpatched variant function. */
  functionName: string;
  /** Name of the function the fix commit actually modified. */
  fixedFunction: string;
  /** Full (40-char) SHA of the fix commit. */
  fixCommit: string;
  /** Excerpt of the guard/check the fix added. */
  addedCheck: string;
  /** Classification of the added check. */
  checkType: FixCheckType;
  /** Language of the file. "skipped" for unsupported languages. */
  language: "javascript" | "typescript" | "python" | "skipped";
  /** First ~2 lines of the variant function for context. */
  snippet: string;
  /** True if the sibling already has a similar guard (excluded from candidates). */
  guardPresent: boolean;
}

export interface AppFixVariantHuntResult {
  /** Unpatched candidates (guardPresent === false). */
  candidates: AppFixVariantCandidate[];
  /** Non-fatal errors encountered during processing. */
  errors: string[];
  /** Resolved full SHA of the fix commit. */
  fixCommit: string;
  /** Subject line of the fix commit. */
  fixSubject: string;
  /** Repo-relative files touched by the fix (not just JS/TS/Python). */
  fixedFiles: string[];
  /** Functions modified by the fix, per file. */
  fixedFunctions: Record<string, string[]>;
  /** Guard/check text extracted from the fix diff. */
  addedCheck: string;
  /** Classification of the extracted check. */
  checkType: FixCheckType;
  /** Language coverage: which language families were analyzed vs skipped. */
  languageCoverage: Record<string, "supported" | "skipped">;
}

export interface AppFixVariantHuntOptions {
  /** Absolute path to the checked-out repository. */
  repoPath: string;
  /** The fix commit ref (tag, SHA, relative ref). Resolved to full SHA. */
  fixCommit: string;
  /** Maximum candidates to return. Default 50. */
  maxCandidates?: number;
  /** Maximum source files to scan. Default 200. */
  maxFiles?: number;
}

// ── Language coverage table ───────────────────────────────────────────────────

const LANGUAGE_COVERAGE: Record<string, "supported" | "skipped"> = {
  javascript: "supported",
  typescript: "supported",
  python: "supported",
  c: "skipped",
  cpp: "skipped",
  rust: "skipped",
  go: "skipped",
  java: "skipped",
  ruby: "skipped",
  php: "skipped",
  solidity: "skipped",
  move: "skipped",
  cairo: "skipped",
  haskell: "skipped",
  other: "skipped",
};

// ── Source file extension → language mapping ─────────────────────────────────

const EXT_TO_LANG: Record<string, "javascript" | "typescript" | "python" | "skipped"> = {
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".jsx": "javascript",
  ".ts": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".tsx": "typescript",
  ".py": "python",
  ".pyx": "python",
  ".pyi": "python",
};

// ── Git helpers ───────────────────────────────────────────────────────────────

function git(repoPath: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repoPath,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 128 * 1024 * 1024,
  });
}

/** Resolve a ref to its full 40-character SHA. */
function resolveSha(repoPath: string, ref: string): string {
  try {
    return git(repoPath, ["rev-parse", "--verify", "--end-of-options", `${ref}^{commit}`]).trim();
  } catch {
    throw new Error(
      `Fix commit '${ref}' could not be resolved to a valid commit in ${repoPath}. ` +
        "Ensure the ref exists and is a commit (tag, SHA, or branch name).",
    );
  }
}

/** Get the first-parent SHA of `sha`. Throws if it has no parent (root commit). */
function firstParentSha(repoPath: string, sha: string): string {
  try {
    const parents = git(repoPath, ["rev-list", "--parents", "-n", "1", sha]).trim().split(/\s+/);
    // rev-list output: <sha> <parent1> [<parent2> ...]
    if (parents.length < 2) {
      throw new Error(
        `Fix commit ${sha} has no parent (it is a root commit). Cannot compute a fix diff.`,
      );
    }
    return parents[1]; // first parent
  } catch (err) {
    if (err instanceof Error && err.message.includes("root commit")) throw err;
    throw new Error(
      `Failed to resolve first parent of fix commit ${sha}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/** Verify the repo is a valid git working tree. */
function ensureGitTree(repoPath: string): void {
  try {
    const result = git(repoPath, ["rev-parse", "--is-inside-work-tree"]).trim();
    if (result !== "true") throw new Error("Not a git working tree");
  } catch (err) {
    if (err instanceof Error && err.message === "Not a git working tree") throw err;
    throw new Error(
      `Path '${repoPath}' is not a valid git repository. Cannot perform variant hunt.`,
    );
  }
}

// ── Diff analysis ─────────────────────────────────────────────────────────────

interface DiffHunk {
  /** The enclosing function name, extracted from hunk context. */
  functionName: string;
  /** Line number in the post-image where the hunk begins. */
  startLine: number;
  /** Source lines that were ADDED (prefixed with +, excluding context/metadata). */
  addedLines: string[];
  /** Full raw hunk text. */
  raw: string;
}

const HUNK_HEADER = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@\s*(.*)$/;

/**
 * Heuristically parse a unified diff into hunks with their enclosing function
 * names. Uses git's hunk-header function context (the text after @@), plus a
 * fallback that looks back through the diff for function-like declarations.
 * This is heuristic — it doesn't parse an AST.
 */
function parseDiffHunks(diff: string): DiffHunk[] {
  const hunks: DiffHunk[] = [];
  let currentHunk: DiffHunk | null = null;

  for (const line of diff.split("\n")) {
    const headerMatch = line.match(HUNK_HEADER);
    if (headerMatch) {
      if (currentHunk && currentHunk.addedLines.length > 0) {
        hunks.push(currentHunk);
      }
      const startLine = parseInt(headerMatch[1], 10);
      const context = headerMatch[2] || "";
      // Extract function name from context: `function foo(`, `def foo(`, ` foo(`
      const ctxFn = extractFunctionFromContext(context);
      currentHunk = {
        functionName: ctxFn || "unknown",
        startLine,
        addedLines: [],
        raw: "",
      };
    }

    if (!currentHunk) continue;

    // Capture added lines (those starting with +, but not +++ (file header))
    if (line.startsWith("+") && !line.startsWith("+++")) {
      currentHunk.addedLines.push(line.slice(1));
    }
  }

  if (currentHunk && currentHunk.addedLines.length > 0) {
    hunks.push(currentHunk);
  }

  return hunks;
}

/** Extract a function-like identifier from hunk context text. */
function extractFunctionFromContext(context: string): string | null {
  // Patterns: `func_name(param` or `func_name (param`
  const m = context.match(/\b([a-zA-Z_$][\w$]*)\s*\(/);
  if (m) return m[1];
  return null;
}

/** Check if a line looks like it adds an authorization or validation guard. */
function classifyCheckLine(line: string): FixCheckType | null {
  const trimmed = line.trim();
  if (/^(?:\/\/|#|\/\*|\*)/.test(trimmed)) return null;

  // Authorization patterns (checked first — auth is more specific)
  const authPatterns = [
    /\b(?:owner_?id|tenant_?id|user_?id|req\.user)\b.*(?:!==|!=|===|==)/i,
    /\b(?:isAdmin|isOwner|isAuthenticated|hasRole|hasPermission|authorize|requireAuth)\s*\(/,
    /\b(?:checkAuth|verifyAuth|ensureAuth|assertAuth)\s*\(/,
    /\b(?:userId|user\.id|session\.user|req\.user)\s*(?:!==|!=|===|==)\s*(?:null|undefined)\s*\)?$/,
    /\b(?:\.isAdmin|\.isOwner|\.hasRole)\s*\(/,
    /\b(?:role|permission|scope)\s*(?:!==|!=|===|==)\s*['"`]/,
    // req.headers / req.cookies based auth (Express middleware style)
    /\breq\.headers\..*authorization\s*(?:!==|!=|===|==)/i,
    /\breq\.cookies\..*token\s*(?:!==|!=|===|==)/i,
    // Generic header-based auth check
    /\b(?:headers|cookies)\..*token.*\b(?:===|!==|==|!=)\s*['"`]/i,
    /\badmin_required\b|\blogin_required\b|\bauth_required\b/,
    // Python decorator-like auth patterns
    /^\s*@.*(?:login_required|admin_required|permission_required|auth_required)\b/,
    /^\s*@.*\.(?:require_auth|require_admin|require_permission)\b/,
    /raise\s+(?:NotAuthenticated|PermissionDenied|PermissionError|AuthenticationError|Forbidden)\s*\(/,
    /^\s*if\s+(?:not\s+)?(?:is_authenticated|is_admin|has_permission|user_is_owner)\s*\(/,
  ];

  for (const p of authPatterns) {
    if (p.test(trimmed)) return "authorization";
  }

  // Validation patterns
  const validationPatterns = [
    /\b(?:validate|sanitize|assert|check|ensure)\s*\(/,
    /\b(?:if\s*!\s*\w+|if\s+\w+\s*===\s*(?:null|undefined))\s*(?:\{|then|return)/,
    /\b(?:throw|raise)\s+(?:new\s+)?(?:Error|TypeError|RangeError|ValidationError|ValueError)\s*\(/,
    /^\s*if\s+typeof\s+\w+\s*(?:!==|===)\s*['"`]/,
    /^\s*if\s+\w+\s+is\s+(?:None|null|undefined)\s*:/,
    /^\s*if\s+(?:not\s+)?\w+\s*(?:==|!=|is|in)\s*(?:None|null|undefined|\[\]|\(\)|['"`]["'`])\s*:?/,
    /\b(?:\.strip\(\)|\.trim\(\))\s*(?:!==|!==|==)\s*['"`]['"`]/,
    /^\s*if\s+(?:not\s+)?\w+\.(?:valid|validate|check)\s*\(/,
    // Input shape checks
    /\b(?:isNaN|Number\.isNaN|is_numeric|is_string|isinstance)\s*\(/,
    // Range/size checks
    /\b(?:len|length|size)\s*[<(].*[>)].*[<>]=?\s*\d+/,
  ];

  for (const p of validationPatterns) {
    if (p.test(trimmed)) return "validation";
  }

  return null;
}

// ── Function extraction from source (heuristic regex) ─────────────────────────

interface ExtractedFunction {
  name: string;
  startLine: number;
  endLine: number;
  body: string;
  /** Lines of the function body (indented content). */
  bodyLines: string[];
}

/**
 * Heuristically extract function definitions from source code. Uses regex
 * patterns matched to JS/TS and Python function syntax — these are heuristics,
 * not AST parsing, and may miss edge cases (arrow functions assigned to
 * variables, decorated functions spanning multiple lines, etc.).
 */
function extractFunctions(source: string, language: string): ExtractedFunction[] {
  const functions: ExtractedFunction[] = [];
  const lines = source.split("\n");

  if (language === "python") {
    // Python: `def name(params):`
    const DEF_RE = /^(\s*)(?:async\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/;
    // Decorator lines preceding a def
    const DECORATOR_RE = /^\s*@/;

    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(DEF_RE);
      if (!m) continue;

      const name = m[2];
      const startLine = i + 1; // 1-indexed
      // Find the end of the function body by tracking indentation
      const baseIndent = m[1].length;
      let endLine = i + 1;
      for (let j = i + 1; j < lines.length; j++) {
        const line = lines[j];
        if (line.trim() === "") continue;
        const indent = line.match(/^\s*/)?.[0].length ?? 0;
        // A line at or below base indent (not decorator) ends the function
        if (indent <= baseIndent && !DECORATOR_RE.test(line) && !line.trim().startsWith("#")) {
          endLine = j; // function body ends at previous line
          break;
        }
        endLine = j + 1;
      }

      const bodyLines = lines.slice(i + 1, endLine);
      functions.push({
        name,
        startLine,
        endLine,
        body: bodyLines.join("\n"),
        bodyLines,
      });
    }
  } else {
    // JS/TS: `function name(`, `async function name(`, `name = function(`, method shorthand
    const FUNC_RE = /^(?:(\s*)(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+([a-zA-Z_$][\w$]*)\s*\(|(\s*)(?:const\s+|let\s+|var\s+)?([a-zA-Z_$][\w$]*)\s*=\s*(?:async\s+)?function\s*\()/;
    // Method shorthand: `name(params) {` or `name(params): ReturnType {` as class/obj method
    const METHOD_RE = /^(\s*)([a-zA-Z_$][\w$]*)\s*\([^)]*\)\s*(:\s*[^{]+)?\s*\{/;
    // Arrow function assigned to variable: `const name = (params) => {` or `const name = params => {`
    const ARROW_RE = /^(\s*)(?:export\s+)?(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[a-zA-Z_$][\w$]*)\s*=>\s*\{/;

    let inFunction: { name: string; startLine: number; braceStart: number } | null = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Try to detect function starts
      if (inFunction === null) {
        const funcMatch = line.match(FUNC_RE);
        const methodMatch = line.match(METHOD_RE);
        const arrowMatch = line.match(ARROW_RE);

        let name: string | null = null;
        if (funcMatch) {
          name = funcMatch[2] || funcMatch[4];
        } else if (methodMatch) {
          // Only match if the line looks like a class/object method, not a bare block
          name = methodMatch[2];
        } else if (arrowMatch) {
          name = arrowMatch[2];
        }

        if (name) {
          // Count opening braces in the definition line itself
          const openBraces = (line.match(/\{/g) || []).length;
          const closeBraces = (line.match(/\}/g) || []).length;
          if (openBraces > closeBraces) {
            inFunction = { name, startLine: i + 1, braceStart: openBraces - closeBraces };
          }
        }
      } else {
        // Track brace depth
        const openBraces = (line.match(/\{/g) || []).length;
        const closeBraces = (line.match(/\}/g) || []).length;
        inFunction.braceStart += openBraces - closeBraces;

        if (inFunction.braceStart <= 0) {
          // Function ended
          const bodyLines = lines.slice(inFunction.startLine, i + 1);
          functions.push({
            name: inFunction.name,
            startLine: inFunction.startLine,
            endLine: i + 1,
            body: bodyLines.join("\n"),
            bodyLines,
          });
          inFunction = null;
        }
      }
    }
  }

  return functions;
}

/**
 * Extract a short snippet (first ~2 non-empty lines) from a function body.
 */
function functionSnippet(bodyLines: string[], language: string): string {
  const lines: string[] = [];
  for (const line of bodyLines) {
    const trimmed = line.trim();
    if (trimmed && trimmed !== "{") {
      lines.push(line);
      if (lines.length >= 2) break;
    }
  }
  return lines.join("\n").slice(0, 200);
}

/**
 * Check if a function body already contains the extracted guard pattern.
 * The guard text may be `; `-joined (multiple extracted guard lines from the diff)
 * or newline-separated. We check each guard line individually against the body.
 */
function bodyHasGuard(bodyLines: string[], addedCheck: string): boolean {
  const guardRaw = addedCheck.trim();
  if (guardRaw.length < 5) return false;

  const bodyText = bodyLines.join("\n").toLowerCase();

  // Split by both `; ` (from the join) and `\n` (natural line breaks)
  const guardLines = guardRaw
    .split(/;\s*/)
    .flatMap((part) => part.split("\n"))
    .map((l) => l.trim().toLowerCase())
    .filter((l) => l.length >= 10);

  for (const gl of guardLines) {
    if (bodyText.includes(gl)) return true;
  }

  return false;
}

// ── Structure similarity scoring ──────────────────────────────────────────────

/**
 * Compute a structural similarity score (0–1) between two function bodies.
 * Compares line count similarity and then checks the proportion of keyword-level
 * structure tokens that overlap. This is a heuristic — it doesn't parse AST.
 */
function structuralSimilarity(fixedBody: string[], variantBody: string[]): number {
  if (fixedBody.length === 0 && variantBody.length === 0) return 1;
  if (fixedBody.length === 0 || variantBody.length === 0) return 0;

  // 1. Size similarity — functions of vastly different sizes are unlikely variants
  const maxLen = Math.max(fixedBody.length, variantBody.length);
  const minLen = Math.min(fixedBody.length, variantBody.length);
  const sizeScore = maxLen > 0 ? minLen / maxLen : 1;

  // 2. Structural keyword overlap

  // Extract structural tokens: control flow, operators, calls
  function extractTokens(lines: string[]): Set<string> {
    const tokens = new Set<string>();
    for (const line of lines) {
      const trimmed = line.trim();
      // Control flow keywords
      const controlKeywords = trimmed.match(
        /\b(if|else|for|while|switch|case|break|continue|return|try|catch|finally|throw|raise|with|async|await|yield|def|function|const|let|var|import|export|from|class|new|this|super)\b/g,
      );
      if (controlKeywords) {
        for (const kw of controlKeywords) tokens.add(kw);
      }
      // Method calls (identifier followed by parenthesis)
      const calls = trimmed.match(/\b([a-zA-Z_]\w*)\s*\(/g);
      if (calls) {
        for (const c of calls) {
          const name = c.replace(/\s*\($/, "");
          // Skip generic/common functions
          if (!["if", "for", "while", "switch", "catch"].includes(name) && name.length > 1) {
            tokens.add(`call:${name}`);
          }
        }
      }
    }
    return tokens;
  }

  const fixedTokens = extractTokens(fixedBody);
  const variantTokens = extractTokens(variantBody);

  if (fixedTokens.size === 0 && variantTokens.size === 0) return sizeScore;
  if (fixedTokens.size === 0 || variantTokens.size === 0) return sizeScore * 0.5;

  // Jaccard similarity on structural tokens
  const intersection = new Set([...fixedTokens].filter((t) => variantTokens.has(t)));
  const union = new Set([...fixedTokens, ...variantTokens]);

  const tokenScore = union.size > 0 ? intersection.size / union.size : 0;

  // Weighted: size 40%, structural tokens 60%
  return sizeScore * 0.4 + tokenScore * 0.6;
}

// ── Main algorithm ────────────────────────────────────────────────────────────

/**
 * Hunt for unpatched application security-fix variants. Pure read-only git +
 * heuristic source analysis — no network calls, no model inference. Fails hard
 * on invalid inputs.
 */
export function huntAppFixVariants(opts: AppFixVariantHuntOptions): AppFixVariantHuntResult {
  const repoPath = realpathSync(opts.repoPath);
  const maxCandidates = opts.maxCandidates ?? 50;
  const maxFiles = opts.maxFiles ?? 200;
  if (!Number.isInteger(maxCandidates) || maxCandidates < 1 || !Number.isInteger(maxFiles) || maxFiles < 1) {
    throw new Error("maxCandidates and maxFiles must be positive integers");
  }
  ensureGitTree(repoPath);
  const sha = resolveSha(repoPath, opts.fixCommit);
  const parent = firstParentSha(repoPath, sha);
  const changedFiles = git(repoPath, ["diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", parent, sha, "--"]).split("\0").filter(Boolean);
  const result: AppFixVariantHuntResult = {
    candidates: [], errors: [], fixCommit: sha,
    fixSubject: git(repoPath, ["log", "--format=%s", "-n", "1", sha]).trim(),
    fixedFiles: changedFiles, fixedFunctions: {}, addedCheck: "", checkType: "other",
    languageCoverage: { ...LANGUAGE_COVERAGE },
  };
  interface FixedSite { file: string; fn: ExtractedFunction; check: string; type: FixCheckType; language: string }
  const sites: FixedSite[] = [];
  const languageFor = (file: string) => EXT_TO_LANG[file.slice(file.lastIndexOf(".")).toLowerCase()] ?? "skipped";
  for (const file of changedFiles) {
    const language = languageFor(file);
    if (language === "skipped") continue;
    try {
      // Compare the actual fix to its parent, NOT HEAD (which may be months newer).
      const post = git(repoPath, ["show", `${sha}:${file}`]);
      let pre = "";
      try { pre = git(repoPath, ["show", `${parent}:${file}`]); } catch { /* Newly added file. */ }
      const previous = extractFunctions(pre, language);
      const diff = git(repoPath, ["diff", "--no-ext-diff", "--no-textconv", parent, sha, "--", file]);
      const additions = parseDiffHunks(diff).flatMap((hunk) => hunk.addedLines).map((line) => line.trim());
      const addedGuards = additions.filter((line) => classifyCheckLine(line) !== null);
      for (const fn of extractFunctions(post, language)) {
        const old = previous.find((candidate) => candidate.name === fn.name);
        if (old?.body === fn.body) continue;
        const guards = addedGuards.filter((line) => fn.bodyLines.some((body) => body.trim() === line));
        if (!guards.length) continue;
        const type = guards.some((line) => classifyCheckLine(line) === "authorization") ? "authorization" : "validation";
        sites.push({ file, fn, check: [...new Set(guards)].join("; "), type, language });
        (result.fixedFunctions[file] ??= []).push(fn.name);
      }
    } catch (error) {
      result.errors.push(`${file}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  result.addedCheck = [...new Set(sites.map((site) => site.check))].join("\n");
  result.checkType = sites.some((site) => site.type === "authorization") ? "authorization" : sites.length ? "validation" : "other";
  if (!sites.length) return result;
  const directories = new Set(sites.map((site) => dirname(site.file)));
  const files = git(repoPath, ["ls-files", "-z"]).split("\0").filter((file) =>
    file && languageFor(file) !== "skipped" && directories.has(dirname(file)));
  files.sort((a, b) => Number(!changedFiles.includes(a)) - Number(!changedFiles.includes(b)) || a.localeCompare(b));
  if (files.length > maxFiles) result.errors.push(`Source coverage limited to ${maxFiles} of ${files.length} related tracked files`);
  for (const file of files.slice(0, maxFiles)) {
    const language = languageFor(file);
    try {
      const path = resolve(repoPath, file);
      const canonical = realpathSync(path);
      if (!canonical.startsWith(repoPath + sep) || canonical !== path || lstatSync(path).isSymbolicLink()) {
        result.errors.push(`${file}: skipped symlink or path outside repository`);
        continue;
      }
      if (lstatSync(path).size > 1024 * 1024) { result.errors.push(`${file}: exceeds 1 MiB source limit`); continue; }
      // Candidates use current working-tree bytes, matching the review pipeline.
      const functions = extractFunctions(readFileSync(path, "utf8"), language);
      for (const fn of functions) {
        if (result.fixedFunctions[file]?.includes(fn.name)) continue;
        let best: FixedSite | undefined;
        let score = 0.3;
        for (const site of sites) {
          if (site.language !== language) continue;
          const similarity = structuralSimilarity(site.fn.bodyLines, fn.bodyLines);
          if (similarity >= score) { best = site; score = similarity; }
        }
        if (!best || bodyHasGuard(fn.bodyLines, best.check)) continue;
        result.candidates.push({
          file, line: fn.startLine, functionName: fn.name, fixedFunction: best.fn.name, fixCommit: sha,
          addedCheck: best.check, checkType: best.type, language, snippet: functionSnippet(fn.bodyLines, language), guardPresent: false,
        });
      }
    } catch (error) {
      result.errors.push(`${file}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  result.candidates.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
  result.candidates = result.candidates.slice(0, maxCandidates);
  return result;
}


// ── SeedFinding conversion ─────────────────────────────────────────────────────

/**
 * Convert variant hunt candidates to SeedFindings for the review pipeline.
 * Only unguarded candidates are included (guardPresent === false).
 * Each SeedFinding cites the variant function location and includes the fix
 * provenance as metadata.
 */
export function appFixVariantsToSeedFindings(
  result: AppFixVariantHuntResult,
): SeedFinding[] {
  const seeds: SeedFinding[] = [];

  for (const candidate of result.candidates) {
    if (candidate.guardPresent) continue; // Only seed unguarded variants

    seeds.push({
      file: candidate.file,
      startLine: candidate.line,
      endLine: candidate.line + 1, // best-effort single-line span
      snippet: candidate.snippet.slice(0, 500),
      source: "app-fix-variant-hunt",
      confidence: 0.3, // Low confidence — heuristic only, needs model review
      claim: `${candidate.functionName}: potential ${candidate.checkType} gap — sibling of fixed ${candidate.fixedFunction}`,
      metadata: {
        fixCommit: candidate.fixCommit,
        fixedFunction: candidate.fixedFunction,
        addedCheck: candidate.addedCheck,
        checkType: candidate.checkType,
        language: candidate.language,
      },
    });
  }

  return seeds;
}