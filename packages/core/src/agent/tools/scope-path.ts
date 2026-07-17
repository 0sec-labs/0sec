/**
 * Scoped-path resolution shared by the extracted tool handlers (pwnkit#1284).
 *
 * Pulled out of agent/tools.ts verbatim so per-domain handler modules (starting
 * with intel.ts) can enforce the same scope-escape guard as the still-in-class
 * handlers without importing back into the executor (which would be circular).
 * Behavior is identical to the original private `resolveScopedPath` helper.
 */
import { isAbsolute, resolve } from "node:path";

export function resolveScopedPath(scopePath: string, inputPath: string): string {
  const root = resolve(scopePath);
  const candidate = isAbsolute(inputPath)
    ? resolve(inputPath)
    : resolve(root, inputPath);

  if (candidate !== root && !candidate.startsWith(root + "/")) {
    throw new Error(`Path escapes the allowed scope: ${inputPath}`);
  }

  return candidate;
}
