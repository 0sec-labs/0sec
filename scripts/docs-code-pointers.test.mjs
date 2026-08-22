/**
 * Docs must not point at code that does not exist.
 *
 * Motivation: an audit found `packages/core/src/triage/adversarial.ts` and
 * `packages/core/src/agent/loop-dispatch.ts` referenced across seven doc pages —
 * one of them marking the feature "Shipped" in a competitive comparison — when
 * neither file, nor its documented feature flag, existed anywhere in the tree.
 * For a project whose pitch is evidence-first honesty, docs claiming
 * capabilities we do not have is the worst possible bug class.
 *
 * This test parses every backticked `packages/...` and `0verse/...` source path
 * out of the docs and asserts it resolves on disk. Documenting something
 * unbuilt is still fine — describe it in prose, or mark it planned, but do not
 * hand the reader a file path that goes nowhere.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Paths that are deliberately non-resolving: filename templates for
 * not-yet-created artifacts, and forward-looking proposals that explicitly say
 * "create this file". Keep this list SHORT and justified — every entry is a
 * place the docs are allowed to name something that isn't there.
 */
const ALLOWED_MISSING = new Set([
  // Filename pattern for a results file produced per-run, not committed.
  "packages/benchmark/results/foxguard-ablation-YYYY-MM-DD.json",
  // agent-techniques.md is an explicit proposal doc: "Create ...", "New file
  // ...", "Not impl". The path is the proposed destination, not a claim.
  "packages/core/src/agent/patterns-db.ts",
]);

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry.startsWith(".")) continue;
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (entry.endsWith(".md")) out.push(p);
  }
  return out;
}

test("every code path referenced in the docs exists on disk", () => {
  const docFiles = [
    ...walk(join(ROOT, "docs", "src", "content", "docs")),
    join(ROOT, "README.md"),
  ].filter((f) => existsSync(f));

  const pattern = /`((?:packages|0verse)\/[A-Za-z0-9_./-]+\.(?:ts|tsx|py|json|mjs))`/g;
  const broken = [];

  for (const file of docFiles) {
    const text = readFileSync(file, "utf-8");
    for (const match of text.matchAll(pattern)) {
      const rel = match[1];
      if (ALLOWED_MISSING.has(rel)) continue;
      if (!existsSync(join(ROOT, rel))) {
        broken.push(`${rel}  <-  ${file.slice(ROOT.length + 1)}`);
      }
    }
  }

  assert.deepEqual(
    broken,
    [],
    `Docs reference source files that do not exist:\n  ${broken.join("\n  ")}\n\n` +
      `Either fix the path, describe the feature without a file pointer, or add a ` +
      `justified entry to ALLOWED_MISSING in this test.`,
  );
});
