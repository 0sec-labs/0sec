/**
 * Source-file collection utilities shared by audit + research per-file loops.
 *
 * Extracted from `audit.ts:collectSourceFiles` so the per-file research /
 * audit orchestration loops (#285) can share one implementation. Keeping
 * this minimal — it's a deterministic file walker, not a tool-driven scan.
 */

import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const DEFAULT_SOURCE_EXTS = new Set([
  ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts",
  ".jsx", ".tsx", ".json", ".yml", ".yaml",
  ".py", ".pyx", ".pyi",
  ".rs",
  ".go",
  ".rb",
  ".php",
  ".java", ".kt",
  ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp",
]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "target",
  "__pycache__", ".venv", "venv", ".tox",
  "vendor", "third_party", "deps",
  ".cache", ".next", ".nuxt", "coverage",
]);

const DEFAULT_MAX_FILES = 50;
const DEFAULT_MAX_FILE_SIZE = 200_000;

/**
 * Recursively collect source file paths from a directory. Returns absolute
 * paths in deterministic readdirSync order.
 *
 * Skips:
 *  - vendored / build-output directories (`node_modules`, `dist`, `target`, …)
 *  - files larger than `maxFileSize` bytes
 *  - non-source extensions
 *
 * The default max of 50 keeps single-shot prompts tractable; per-file
 * orchestration loops can pass a larger limit if their per-file budget can
 * absorb it.
 */
export function collectScopeFiles(
  dir: string,
  opts: { maxFiles?: number; maxFileSize?: number; extensions?: Set<string> } = {},
): string[] {
  const maxFiles = opts.maxFiles ?? DEFAULT_MAX_FILES;
  const maxFileSize = opts.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const exts = opts.extensions ?? DEFAULT_SOURCE_EXTS;
  const files: string[] = [];

  function walk(d: string): void {
    if (files.length >= maxFiles) return;
    let entries: string[];
    try {
      entries = readdirSync(d);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (files.length >= maxFiles) return;
      if (SKIP_DIRS.has(entry)) continue;
      const full = join(d, entry);
      try {
        const st = statSync(full);
        if (st.isDirectory()) {
          walk(full);
        } else if (st.isFile() && st.size < maxFileSize) {
          const ext = full.slice(full.lastIndexOf("."));
          if (exts.has(ext)) {
            files.push(full);
          }
        }
      } catch {
        // skip unreadable
      }
    }
  }

  walk(dir);
  return files;
}
