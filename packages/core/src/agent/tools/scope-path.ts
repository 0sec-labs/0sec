/**
 * Scoped-path resolution shared by the extracted tool handlers (pwnkit#1284).
 *
 * Pulled out of agent/tools.ts verbatim so per-domain handler modules (starting
 * with intel.ts) can enforce the same scope-escape guard as the still-in-class
 * handlers without importing back into the executor (which would be circular).
 * Behavior is identical to the original private `resolveScopedPath` helper.
 */
import { lstatSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, resolve, sep } from "node:path";

function pathEntryExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function canonicalizePath(path: string): string {
  const missingSegments: string[] = [];
  let existingPath = path;

  while (!pathEntryExists(existingPath)) {
    const parent = dirname(existingPath);
    if (parent === existingPath) {
      throw new Error(`Path does not have an existing parent: ${path}`);
    }
    missingSegments.unshift(basename(existingPath));
    existingPath = parent;
  }

  // realpath resolves every symlink in the existing prefix. A dangling symlink
  // fails here instead of becoming a write-through escape for apply_patch.
  return resolve(realpathSync(existingPath), ...missingSegments);
}

function isScopedPath(scopePath: string, inputPath: string): boolean {
  const root = realpathSync(scopePath);
  const logicalCandidate = isAbsolute(inputPath)
    ? resolve(inputPath)
    : resolve(root, inputPath);
  const candidate = canonicalizePath(logicalCandidate);

  return candidate === root || candidate.startsWith(root + sep);
}

export function resolveScopedPath(scopePath: string, inputPath: string): string {
  if (!isScopedPath(scopePath, inputPath)) {
    throw new Error(`Path escapes the allowed scope: ${inputPath}`);
  }

  const root = realpathSync(scopePath);
  const logicalCandidate = isAbsolute(inputPath)
    ? resolve(inputPath)
    : resolve(root, inputPath);
  return canonicalizePath(logicalCandidate);
}
