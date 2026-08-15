// Scan stage of the file-review pipeline (deepsec `scan`): glob the review
// root, run declarative regex matchers over every source file, and write
// `candidates` into each FileRecord. Free — no AI. Additive merge: a re-scan
// merges new candidates into existing records; unchanged files (same
// content hash) keep their records untouched.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {
  DEFAULT_IGNORE_DIR_GLOBS,
  DEFAULT_IGNORE_FILE_GLOBS,
  matchAnyGlob,
  normalizeRelPath,
} from "./glob.js";
import { mergeCandidates, ReviewStore } from "./store.js";
import type { ReviewCandidateMatch, ReviewFileRecord, ReviewMatcherSpec } from "./types.js";

// ── Source universe ────────────────────────────────────────────────────────

const SCAN_EXTS = new Set([
  ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx",
  ".py", ".rb", ".php", ".go", ".rs", ".java", ".kt", ".swift",
  ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".cs", ".lua", ".sol",
  ".yml", ".yaml", ".tf", ".toml", ".sql", ".sh",
]);

/** Max bytes per file read into the content cache (skip giant artifacts). */
const MAX_SCAN_FILE_BYTES = 2_000_000;

/**
 * Collect the scannable file universe under `root`, as POSIX paths relative
 * to `root`. Honors DEFAULT_IGNORE_* globs plus caller ignore patterns.
 */
export function collectScannableFiles(
  root: string,
  ignorePatterns: readonly string[] = [],
): string[] {
  const files: string[] = [];
  const walk = (dir: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      const rel = normalizeRelPath(path.relative(root, full));
      if (entry.isDirectory()) {
        if (matchAnyGlob(`${rel}/`, [...DEFAULT_IGNORE_DIR_GLOBS, ...ignorePatterns])) continue;
        walk(full);
      } else if (entry.isFile()) {
        const ext = entry.name.slice(entry.name.lastIndexOf("."));
        if (!SCAN_EXTS.has(ext)) continue;
        if (matchAnyGlob(rel, [...DEFAULT_IGNORE_FILE_GLOBS, ...ignorePatterns])) continue;
        files.push(rel);
      }
    }
  };
  walk(root);
  return files.sort();
}

// ── Matcher compilation ────────────────────────────────────────────────────

export interface CompiledMatcher {
  spec: ReviewMatcherSpec;
  patterns: Array<{ regex: RegExp; label: string }>;
}

const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const VALID_FLAGS = /^[dgimsuvy]*$/;
/** Reject bounded repetitions demanding ≥1000 matches (deepsec guard). */
const EXPLOSION_RE = /\{(\d{4,}|\d{3,},)/;

/**
 * Compile data-only matcher specs, validating slugs, flags, regex syntax,
 * example self-tests, and slug collisions. Throws with every issue joined —
 * the caller (setup gate) surfaces them for one repair attempt.
 */
export function compileMatchers(
  specs: readonly ReviewMatcherSpec[],
  opts: { existingSlugs?: readonly string[] } = {},
): CompiledMatcher[] {
  const issues: string[] = [];
  const slugs = new Set(opts.existingSlugs ?? []);
  const out: CompiledMatcher[] = [];

  for (const spec of specs) {
    const where = `matcher '${spec.slug || "(unnamed)"}'`;
    if (!SLUG_RE.test(spec.slug)) {
      issues.push(`${where}: slug must be kebab-case`);
      continue;
    }
    if (slugs.has(spec.slug)) {
      issues.push(`${where}: slug already in use`);
      continue;
    }
    if (spec.filePatterns.length === 0 || spec.patterns.length === 0) {
      issues.push(`${where}: needs at least one filePattern and one pattern`);
      continue;
    }
    const patterns: CompiledMatcher["patterns"] = [];
    let ok = true;
    for (const p of spec.patterns) {
      if (p.flags !== undefined && !VALID_FLAGS.test(p.flags)) {
        issues.push(`${where}: invalid regex flags '${p.flags}'`);
        ok = false;
        break;
      }
      if (EXPLOSION_RE.test(p.source)) {
        issues.push(`${where}: pattern '${p.source}' risks match explosion`);
        ok = false;
        break;
      }
      try {
        patterns.push({ regex: new RegExp(p.source, p.flags ?? ""), label: p.label });
      } catch (err) {
        issues.push(`${where}: invalid regex: ${(err as Error).message}`);
        ok = false;
        break;
      }
    }
    if (!ok) continue;
    // Example self-test: every declared example must match some pattern.
    for (const example of spec.examples ?? []) {
      if (!patterns.some(({ regex }) => regex.test(example))) {
        issues.push(`${where}: example does not match any pattern: ${JSON.stringify(example.slice(0, 80))}`);
        ok = false;
      }
    }
    if (!ok) continue;
    slugs.add(spec.slug);
    out.push({ spec, patterns });
  }

  if (issues.length > 0) throw new Error(`matcher compilation failed: ${issues.join("; ")}`);
  return out;
}

/** Run one compiled matcher over file content → candidate matches. */
export function matchFileContent(
  matcher: CompiledMatcher,
  filePath: string,
  content: string,
): ReviewCandidateMatch[] {
  if (matcher.spec.filePatterns.length > 0 && !matchAnyGlob(filePath, matcher.spec.filePatterns)) {
    return [];
  }
  if (matcher.spec.excludeFilePatterns?.length && matchAnyGlob(filePath, matcher.spec.excludeFilePatterns)) {
    return [];
  }
  const matches: ReviewCandidateMatch[] = [];
  const lines = content.split(/\r?\n/);
  for (const { regex, label } of matcher.patterns) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      regex.lastIndex = 0;
      const m = regex.exec(line);
      if (m) {
        matches.push({
          vulnSlug: matcher.spec.slug,
          lineNumbers: [i + 1],
          snippet: line.trim().slice(0, 200),
          matchedPattern: label,
        });
      }
    }
  }
  return matches;
}

// ── Scan stage ─────────────────────────────────────────────────────────────

export interface ReviewScanParams {
  projectId: string;
  rootPath: string;
  matchers: readonly CompiledMatcher[];
  ignorePatterns?: readonly string[];
  runId?: string;
  log?: (msg: string) => void;
}

export interface ReviewScanResult {
  runId: string;
  filesScanned: number;
  filesWithCandidates: number;
  candidatesFound: number;
  /** Per-matcher hit counts, keyed by slug (feeds the coverage gate). */
  matcherHits: Record<string, string[]>;
  languageStats: Array<{ language: string; scannedFiles: number; candidates: number }>;
  durationMs: number;
}

/**
 * Free regex scan: build the file universe, run every matcher over each
 * file, merge candidates additively into FileRecords, and stamp status
 * `pending` on files that have candidates and were not analyzed against the
 * current content hash.
 */
export function runReviewScan(store: ReviewStore, params: ReviewScanParams): ReviewScanResult {
  const started = Date.now();
  const run = store.createRunMeta({
    projectId: params.projectId,
    rootPath: params.rootPath,
    type: "scan",
    runId: params.runId,
  });
  const files = collectScannableFiles(params.rootPath, params.ignorePatterns);

  // Content cache: each file is read once across all matchers (deepsec
  // driver design — matchers share one pre-read, CRLF-normalized copy).
  const matcherHits: Record<string, string[]> = {};
  const langStats = new Map<string, { scannedFiles: number; candidates: number }>();
  let candidatesFound = 0;
  let filesWithCandidates = 0;

  for (const rel of files) {
    const abs = path.join(params.rootPath, rel);
    let content: string;
    try {
      const st = fs.statSync(abs);
      if (st.size > MAX_SCAN_FILE_BYTES) continue;
      content = fs.readFileSync(abs, "utf8").replace(/\r\n/g, "\n");
    } catch {
      continue;
    }
    const hash = crypto.createHash("sha256").update(content).digest("hex");

    const incoming: ReviewCandidateMatch[] = [];
    for (const matcher of params.matchers) {
      const hits = matchFileContent(matcher, rel, content);
      if (hits.length === 0) continue;
      incoming.push(...hits);
      (matcherHits[matcher.spec.slug] ??= []).push(rel);
    }

    const lang = extLanguage(rel);
    const stat = langStats.get(lang) ?? { scannedFiles: 0, candidates: 0 };
    stat.scannedFiles += 1;
    stat.candidates += incoming.length;
    langStats.set(lang, stat);

    let record = store.readRecord(params.projectId, rel);
    if (!record) {
      record = {
        filePath: rel,
        projectId: params.projectId,
        candidates: [],
        findings: [],
        analysisHistory: [],
        status: "pending",
      };
    }
    mergeCandidates(record, incoming);
    candidatesFound += incoming.length;
    if (incoming.length > 0) filesWithCandidates += 1;

    record.fileHash = hash;
    record.lastScannedAt = new Date().toISOString();
    record.lastScannedRunId = run.runId;
    // Files with candidates re-enter the pending pool unless already
    // analyzed against THIS exact content hash (the resume skip key).
    if (record.candidates.length > 0 && record.analyzedHash !== hash) {
      record.status = "pending";
    }
    store.writeRecord(record);
  }

  run.completedAt = new Date().toISOString();
  run.phase = "done";
  run.stats = { filesScanned: files.length, candidatesFound };
  store.saveRunMeta(run);

  const languageStats = [...langStats.entries()]
    .map(([language, s]) => ({ language, ...s }))
    .sort((a, b) => b.scannedFiles - a.scannedFiles);

  params.log?.(
    `scan: ${files.length} files, ${candidatesFound} candidates in ${filesWithCandidates} files (${run.runId})`,
  );

  return {
    runId: run.runId,
    filesScanned: files.length,
    filesWithCandidates,
    candidatesFound,
    matcherHits,
    languageStats,
    durationMs: Date.now() - started,
  };
}

const EXT_LANG: Record<string, string> = {
  ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript",
  ".mjs": "javascript", ".cjs": "javascript", ".py": "python", ".rb": "ruby",
  ".php": "php", ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin",
  ".swift": "swift", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
  ".cs": "csharp", ".lua": "lua", ".sol": "solidity", ".tf": "terraform",
  ".yml": "yaml", ".yaml": "yaml", ".sql": "sql", ".sh": "shell",
};

function extLanguage(rel: string): string {
  const ext = rel.slice(rel.lastIndexOf("."));
  return EXT_LANG[ext] ?? "other";
}
