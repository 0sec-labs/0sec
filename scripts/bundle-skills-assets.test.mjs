/**
 * bundle-skills-assets.test.mjs — guards that the JIT methodology skill YAML
 * actually ships in the packaged CLI bundle.
 *
 * The skill loader (packages/core/src/agent/skills/index.ts) walks its own
 * module directory for *.yaml and validates each file as a skill. esbuild lands
 * that loader in dist/chunks/, so scripts/bundle-cli.mjs copies the skill tree
 * to dist/chunks/agent/skills/. Without that copy the shipped binary loads ZERO
 * skills — list_skills is empty even with 0SEC_FEATURE_JIT_SKILLS on. This test
 * fails loudly if a build regresses that copy.
 *
 * Skips when no bundle is present (bundle build hasn't run), like install.test.
 *
 * Run with: pnpm test:bundle-skills  (root package.json)
 */

import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC_SKILLS = join(ROOT, "packages/core/src/agent/skills");
const BUNDLE_SKILLS = join(ROOT, "dist/chunks/agent/skills");
const BUNDLE_CHUNKS = join(ROOT, "dist/chunks");

function walkYaml(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkYaml(p));
    else if (entry.name.endsWith(".yaml") || entry.name.endsWith(".yml")) out.push(p);
  }
  return out;
}

const bundleBuilt = existsSync(BUNDLE_CHUNKS);

test("every source skill YAML ships in the bundle", { skip: !bundleBuilt }, () => {
  const srcCount = walkYaml(SRC_SKILLS).length;
  const bundleCount = walkYaml(BUNDLE_SKILLS).length;
  assert.ok(srcCount > 0, "expected skill YAML in source tree");
  assert.equal(
    bundleCount,
    srcCount,
    `bundle ships ${bundleCount} skill YAML but source has ${srcCount} — ` +
      `scripts/bundle-cli.mjs skill copy regressed`,
  );
});

test("the framework packs are present in the bundle", { skip: !bundleBuilt }, () => {
  for (const name of ["nextjs.yaml", "supabase.yaml", "python-web.yaml"]) {
    const p = join(BUNDLE_SKILLS, "frameworks", name);
    assert.ok(existsSync(p) && statSync(p).size > 0, `${name} should ship in the bundle`);
  }
});

test("no non-skill YAML leaks under dist/chunks (would fail skill validation)", { skip: !bundleBuilt }, () => {
  // The loader validates EVERY yaml under its dir as a skill, so a stray yaml
  // outside agent/skills/ would hard-fail loading in the packaged binary.
  const stray = walkYaml(BUNDLE_CHUNKS).filter(
    (p) => !p.includes(join("agent", "skills")),
  );
  assert.deepEqual(stray, [], `unexpected non-skill YAML under dist/chunks:\n  ${stray.join("\n  ")}`);
});
