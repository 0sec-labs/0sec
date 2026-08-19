#!/usr/bin/env node
/**
 * check_skill.mjs — validate a single candidate skill YAML using the EXACT
 * runtime validator, without duplicating it.
 *
 * The skill-refine loop (`skill_refine_loop.py --promote`) shells out to this
 * before it is ever allowed to write a YAML into the skills tree. We reuse
 * `loadSkillRegistry()` from @0sec/core (skills/index.ts) — the same code the
 * agent uses to hot-load skills from disk — by pointing it at a temp directory
 * containing only the candidate file. If the candidate is malformed (missing
 * fields, non-integer version, bad regex trigger, duplicate id, ...) the loader
 * throws and we exit non-zero, so a broken skill can never reach the tree.
 *
 * Usage:
 *   node check_skill.mjs <path/to/candidate.yaml> [--core-dist <dir>]
 *
 * Exit codes:
 *   0  candidate parses + validates cleanly
 *   1  validation failed (message on stderr)
 *   2  bad invocation / could not locate the core build
 */

import { fileURLToPath } from "node:url";
import { dirname, join, resolve, basename } from "node:path";
import { mkdtempSync, copyFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));

function fail(code, msg) {
  process.stderr.write(msg + "\n");
  process.exit(code);
}

const args = process.argv.slice(2);
let yamlPath = null;
let coreDist = null;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--core-dist") {
    coreDist = args[++i];
  } else if (!yamlPath) {
    yamlPath = args[i];
  }
}

if (!yamlPath) {
  fail(2, "usage: node check_skill.mjs <candidate.yaml> [--core-dist <dir>]");
}
yamlPath = resolve(yamlPath);
if (!existsSync(yamlPath)) {
  fail(2, `candidate YAML not found: ${yamlPath}`);
}

// Default to the sibling core package's build output.
// scripts/train -> scripts -> benchmark -> packages -> core/dist
const distDir = coreDist
  ? resolve(coreDist)
  : resolve(HERE, "../../../core/dist");
const indexPath = join(distDir, "agent", "skills", "index.js");
if (!existsSync(indexPath)) {
  fail(
    2,
    `core build not found at ${indexPath}\n` +
      `Run: pnpm --filter @0sec/core build  (or pass --core-dist <dir>)`,
  );
}

const mod = await import(indexPath);
if (typeof mod.loadSkillRegistry !== "function") {
  fail(2, "loadSkillRegistry not exported from core build — build stale?");
}

// Isolate the candidate in a temp dir so the loader validates ONLY it and we
// don't collide with real skill IDs (duplicate-id check would false-fail).
const staging = mkdtempSync(join(tmpdir(), "0sec-skill-check-"));
try {
  copyFileSync(yamlPath, join(staging, basename(yamlPath)));
  mod.clearSkillRegistry?.();
  const registry = mod.loadSkillRegistry(staging);
  mod.clearSkillRegistry?.();
  const ids = [...registry.keys()];
  if (ids.length !== 1) {
    fail(1, `expected exactly one skill in candidate, got ${ids.length}`);
  }
  process.stdout.write(`OK ${ids[0]}\n`);
  process.exit(0);
} catch (err) {
  fail(1, `INVALID ${basename(yamlPath)}: ${err?.message ?? err}`);
} finally {
  rmSync(staging, { recursive: true, force: true });
}
