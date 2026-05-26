/**
 * Reachability Gate ("Endor Labs moat")
 *
 * For every finding, check whether the vulnerable sink is actually reachable
 * from an application entry point (HTTP handler, CLI main, user-facing API).
 * Dead code and test-only paths are not exploitable, so findings that only
 * land in those files should be suppressed before we spend LLM tokens on them.
 *
 * This module implements a zero-dependency, grep/pattern-based first pass
 * (Approach 2 in the design doc). It is deliberately conservative: when it
 * cannot make a confident call it returns `reachable: true` with low
 * confidence so the rest of the pipeline still has a chance to verify.
 *
 * TODO: upgrade to tree-sitter-based call graph walking (Approach 1) for
 * precise interprocedural reachability.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, extname, join, relative, sep } from "node:path";

import type { Finding } from "@pwnkit/shared";

// ────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────

export interface ReachabilityResult {
  /** `true` if the sink is (or may be) reachable from an entry point. */
  reachable: boolean;
  /** 0–1 confidence in the verdict. Values < 0.7 should not be acted on. */
  confidence: number;
  /** Entry-point files that can reach the sink file. */
  entryPoints: string[];
  /** One example path, entry → … → sink file. */
  callPath: string[];
  /** Human-readable explanation. */
  reason: string;
}

// ────────────────────────────────────────────────────────────────────
// Config
// ────────────────────────────────────────────────────────────────────

const SOURCE_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".py", ".rb", ".go", ".java", ".kt", ".php",
]);

const IGNORE_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "out", "coverage",
  ".next", ".nuxt", ".turbo", ".cache", "vendor", "target",
  "__pycache__", ".venv", "venv", "env",
]);

// Directory name patterns that clearly indicate an HTTP/CLI entry point.
const ENTRY_DIR_PATTERNS: RegExp[] = [
  /(?:^|[\\/])routes?(?:[\\/]|$)/i,
  /(?:^|[\\/])handlers?(?:[\\/]|$)/i,
  /(?:^|[\\/])controllers?(?:[\\/]|$)/i,
  /(?:^|[\\/])pages[\\/]api(?:[\\/]|$)/,
  /(?:^|[\\/])app[\\/]api(?:[\\/]|$)/,
  /(?:^|[\\/])api[\\/]/i,
  /(?:^|[\\/])endpoints?(?:[\\/]|$)/i,
  /(?:^|[\\/])views?(?:[\\/]|$)/i,
  /(?:^|[\\/])resolvers?(?:[\\/]|$)/i,
  /(?:^|[\\/])middlewares?(?:[\\/]|$)/i,
];

// Filenames that are typical program entry points.
const ENTRY_FILE_NAMES = new Set([
  "index.js", "index.ts", "index.mjs", "index.cjs",
  "main.js", "main.ts", "main.py", "main.go", "Main.java",
  "server.js", "server.ts", "server.py",
  "app.js", "app.ts", "app.py",
  "cli.js", "cli.ts", "cli.py",
  "manage.py", "wsgi.py", "asgi.py",
]);

// Content-level tells that a file registers HTTP routes.
const ENTRY_CONTENT_PATTERNS: RegExp[] = [
  /\bapp\.(get|post|put|patch|delete|use|all|options|head)\s*\(/,
  /\brouter\.(get|post|put|patch|delete|use|all|options|head)\s*\(/,
  /\bexpress\s*\(\s*\)/,
  /\bfastify\s*\(/,
  /\bnew\s+Koa\s*\(/,
  /\bexport\s+default\s+(?:async\s+)?function\s+handler\b/,
  /\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b/,
  /@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b/,
  /@app\.(?:route|get|post|put|patch|delete)\s*\(/, // Flask
  /\bFastAPI\s*\(/,
  /\bDjango\b.*\burls\b/,
  /\bgin\.(?:Default|New)\s*\(/, // Go Gin
  /\bhttp\.HandleFunc\s*\(/, // Go net/http
];

// Test / dead-code markers.
const TEST_FILE_PATTERNS: RegExp[] = [
  /(?:^|[\\/])(?:__tests__|tests?|spec|specs|fixtures?|mocks?|examples?|benchmarks?)(?:[\\/]|$)/i,
  /\.(?:test|spec)\.(?:js|jsx|ts|tsx|mjs|cjs|py)$/i,
  /_test\.(?:go|py)$/i,
];

const INTERNAL_MARKERS: RegExp[] = [
  /(?:^|[\\/])__internal__(?:[\\/]|$)/,
  /(?:^|[\\/])internal(?:[\\/]|$)/,
  /(?:^|[\\/])scripts?(?:[\\/]|$)/,
  /(?:^|[\\/])tools?(?:[\\/]|$)/,
];

const MAX_FILES = 5000;
const MAX_FILE_BYTES = 512 * 1024;
const MAX_DEPTH = 6;

// ────────────────────────────────────────────────────────────────────
// File walker
// ────────────────────────────────────────────────────────────────────

interface SourceFile {
  absPath: string;
  relPath: string;
  baseName: string;
  content: string;
}

function walkSources(root: string): SourceFile[] {
  const out: SourceFile[] = [];
  function walk(dir: string, depth: number): void {
    if (depth > MAX_DEPTH) return;
    if (out.length >= MAX_FILES) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry)) continue;
      const abs = join(dir, entry);
      let st;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        walk(abs, depth + 1);
      } else if (st.isFile()) {
        if (!SOURCE_EXTENSIONS.has(extname(entry))) continue;
        if (st.size > MAX_FILE_BYTES) continue;
        let content: string;
        try {
          content = readFileSync(abs, "utf8");
        } catch {
          continue;
        }
        out.push({
          absPath: abs,
          relPath: relative(root, abs),
          baseName: entry,
          content,
        });
        if (out.length >= MAX_FILES) return;
      }
    }
  }
  walk(root, 0);
  return out;
}

// ────────────────────────────────────────────────────────────────────
// Finding → (sinkFile, sinkSymbol) extraction
// ────────────────────────────────────────────────────────────────────

export interface SinkLocation {
  file: string | null;
  symbol: string | null;
}

const FILE_HINT_REGEX =
  /([\w./@-]+[\\/][\w./@-]+\.(?:js|jsx|ts|tsx|mjs|cjs|py|rb|go|java|kt|php))(?::(\d+))?/;
const SYMBOL_HINT_REGEXES: RegExp[] = [
  /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/,
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?/,
  /\b([A-Za-z_$][\w$]*)\s*\(/,
];

export function extractSinkLocation(finding: Finding): SinkLocation {
  const hayStack = [
    finding.title ?? "",
    finding.description ?? "",
    finding.evidence?.analysis ?? "",
    finding.evidence?.request ?? "",
    finding.evidence?.response ?? "",
  ].join("\n");

  let file: string | null = null;
  const fileMatch = hayStack.match(FILE_HINT_REGEX);
  if (fileMatch) file = fileMatch[1] ?? null;

  let symbol: string | null = null;
  for (const rx of SYMBOL_HINT_REGEXES) {
    const m = hayStack.match(rx);
    if (m && m[1] && m[1].length > 2 && !COMMON_WORDS.has(m[1])) {
      symbol = m[1];
      break;
    }
  }

  return { file, symbol };
}

const COMMON_WORDS = new Set([
  "the", "and", "for", "with", "from", "this", "that", "return", "const",
  "function", "async", "await", "import", "export", "require", "module",
  "true", "false", "null", "undefined", "void", "let", "var",
]);

// ────────────────────────────────────────────────────────────────────
// Entry-point detection
// ────────────────────────────────────────────────────────────────────

function isTestFile(relPath: string): boolean {
  return TEST_FILE_PATTERNS.some((rx) => rx.test(relPath));
}

function isInternalFile(relPath: string): boolean {
  return INTERNAL_MARKERS.some((rx) => rx.test(relPath));
}

function isEntryPoint(file: SourceFile): boolean {
  if (isTestFile(file.relPath)) return false;
  if (ENTRY_DIR_PATTERNS.some((rx) => rx.test(file.relPath))) return true;
  if (ENTRY_FILE_NAMES.has(file.baseName)) return true;
  // Content-based detection (short-circuit on first hit).
  for (const rx of ENTRY_CONTENT_PATTERNS) {
    if (rx.test(file.content)) return true;
  }
  return false;
}

// ────────────────────────────────────────────────────────────────────
// Import graph (file → imported files)
// ────────────────────────────────────────────────────────────────────

const IMPORT_REGEXES: RegExp[] = [
  /\bimport\s+(?:[\s\S]*?)\s+from\s+['"]([^'"]+)['"]/g,
  /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /\bfrom\s+([\w.]+)\s+import\b/g, // python
  /^\s*import\s+([\w./]+)\s*$/gm, // python/go style
];

function extractImports(content: string): string[] {
  const out: string[] = [];
  for (const rx of IMPORT_REGEXES) {
    rx.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rx.exec(content)) !== null) {
      if (m[1]) out.push(m[1]);
    }
  }
  return out;
}

/**
 * Resolve an import specifier (relative-only for now) against the file that
 * contains it, returning the matching entry in `byRel` if any.
 */
function resolveImport(
  fromRel: string,
  spec: string,
  byRel: Map<string, SourceFile>,
): SourceFile | null {
  if (!spec.startsWith(".") && !spec.startsWith("/")) return null;
  const fromDirParts = fromRel.split(sep).slice(0, -1);
  const specParts = spec.split(/[\\/]/);
  const stack = [...fromDirParts];
  for (const part of specParts) {
    if (part === "" || part === ".") continue;
    if (part === "..") stack.pop();
    else stack.push(part);
  }
  const base = stack.join(sep);
  const candidates = [
    base,
    ...[...SOURCE_EXTENSIONS].map((ext) => base + ext),
    ...[...SOURCE_EXTENSIONS].map((ext) => join(base, "index" + ext)),
  ];
  for (const c of candidates) {
    const hit = byRel.get(c);
    if (hit) return hit;
  }
  return null;
}

// ────────────────────────────────────────────────────────────────────
// The gate
// ────────────────────────────────────────────────────────────────────

function notReachable(reason: string, confidence: number): ReachabilityResult {
  return { reachable: false, confidence, entryPoints: [], callPath: [], reason };
}

function reachable(
  reason: string,
  confidence: number,
  entryPoints: string[] = [],
  callPath: string[] = [],
): ReachabilityResult {
  return { reachable: true, confidence, entryPoints, callPath, reason };
}

/**
 * Check whether a finding's vulnerable sink is reachable from an entry point.
 *
 * Returns `reachable: true` with low confidence when the check cannot make a
 * decision (missing file info, unparseable source tree, etc.) — the calling
 * pipeline should only suppress findings when
 * `reachable: false && confidence >= 0.7`.
 */
export async function checkReachability(
  finding: Finding,
  sourceDir: string,
): Promise<ReachabilityResult> {
  // 0. Pull what we know from the finding.
  const sink = extractSinkLocation(finding);

  // 1. Walk the source tree.
  let files: SourceFile[];
  try {
    files = walkSources(sourceDir);
  } catch (err) {
    return reachable(
      `reachability check skipped: could not read ${sourceDir} (${(err as Error).message})`,
      0.1,
    );
  }
  if (files.length === 0) {
    return reachable("reachability check skipped: no source files found", 0.1);
  }

  const byRel = new Map<string, SourceFile>();
  for (const f of files) byRel.set(f.relPath, f);

  // 2. Resolve sink file.
  let sinkFile: SourceFile | null = null;
  if (sink.file) {
    const normalized = sink.file.replace(/^\.?[\\/]/, "");
    sinkFile = byRel.get(normalized) ?? null;
    if (!sinkFile) {
      // Fall back to basename match.
      const base = basename(normalized);
      sinkFile = files.find((f) => f.baseName === base) ?? null;
    }
  }
  if (!sinkFile && sink.symbol) {
    // Try to locate the symbol definition across all files.
    const defRegex = new RegExp(
      `\\b(?:function|class|def)\\s+${escapeRegExp(sink.symbol)}\\b|\\b(?:const|let|var)\\s+${escapeRegExp(sink.symbol)}\\s*=`,
    );
    sinkFile = files.find((f) => defRegex.test(f.content)) ?? null;
  }

  if (!sinkFile) {
    return reachable(
      "reachability check skipped: could not locate sink file from finding metadata",
      0.2,
    );
  }

  // 3. Fast suppression rules on the sink file itself.
  if (isTestFile(sinkFile.relPath)) {
    return notReachable(
      `sink lives in a test file (${sinkFile.relPath}); not exposed to real traffic`,
      0.9,
    );
  }
  if (isInternalFile(sinkFile.relPath)) {
    return notReachable(
      `sink lives in an __internal__/scripts/tools path (${sinkFile.relPath}); not an application entry surface`,
      0.75,
    );
  }

  // 4. Build reverse-import graph: file → files that import it.
  const importers = new Map<string, Set<string>>();
  for (const f of files) {
    const specs = extractImports(f.content);
    for (const spec of specs) {
      const target = resolveImport(f.relPath, spec, byRel);
      if (!target) continue;
      if (!importers.has(target.relPath)) importers.set(target.relPath, new Set());
      importers.get(target.relPath)!.add(f.relPath);
    }
  }

  // 5. Precompute entry-point set.
  const entryFiles = new Set<string>();
  for (const f of files) if (isEntryPoint(f)) entryFiles.add(f.relPath);

  if (entryFiles.size === 0) {
    return reachable(
      "no entry points detected in source tree; cannot prove unreachability",
      0.2,
    );
  }

  // 6. If the sink file is itself an entry point, we're done.
  if (entryFiles.has(sinkFile.relPath)) {
    return reachable(
      `sink file is itself an entry point (${sinkFile.relPath})`,
      0.9,
      [sinkFile.relPath],
      [sinkFile.relPath],
    );
  }

  // 7. BFS backwards from sinkFile through the importer graph looking for any
  //    entry-point file. Skip test-only importers — those should not count as
  //    reachability.
  const queue: Array<{ file: string; path: string[] }> = [
    { file: sinkFile.relPath, path: [sinkFile.relPath] },
  ];
  const seen = new Set<string>([sinkFile.relPath]);
  const reachingEntries: string[] = [];
  let bestPath: string[] = [];
  const nonTestImporterFiles = new Set<string>();
  let anyImporter = false;

  while (queue.length) {
    const { file, path } = queue.shift()!;
    const parents = importers.get(file);
    if (!parents || parents.size === 0) continue;
    for (const parent of parents) {
      anyImporter = true;
      if (isTestFile(parent)) continue;
      nonTestImporterFiles.add(parent);
      if (seen.has(parent)) continue;
      seen.add(parent);
      const nextPath = [parent, ...path];
      if (entryFiles.has(parent)) {
        reachingEntries.push(parent);
        if (bestPath.length === 0) bestPath = nextPath;
        if (reachingEntries.length >= 5) {
          return reachable(
            `sink reachable from ${reachingEntries.length}+ entry point(s)`,
            0.9,
            reachingEntries,
            bestPath,
          );
        }
      }
      queue.push({ file: parent, path: nextPath });
    }
  }

  if (reachingEntries.length > 0) {
    return reachable(
      `sink reachable from ${reachingEntries.length} entry point(s)`,
      0.85,
      reachingEntries,
      bestPath,
    );
  }

  if (!anyImporter) {
    return notReachable(
      `sink file (${sinkFile.relPath}) has no importers anywhere in the repo — dead code`,
      0.85,
    );
  }

  if (nonTestImporterFiles.size === 0) {
    return notReachable(
      `sink file (${sinkFile.relPath}) is only imported from test files — not reachable in production`,
      0.9,
    );
  }

  // Imported from non-entry, non-test files — could still be unreachable but
  // we don't have enough signal. Stay conservative.
  return reachable(
    `sink file has ${nonTestImporterFiles.size} non-entry importer(s); cannot prove unreachability`,
    0.3,
  );
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
