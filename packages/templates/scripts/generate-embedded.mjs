#!/usr/bin/env node
// Scans packages/templates/attacks/**/*.yaml at build time and emits
// packages/templates/src/embedded.ts with all templates inlined as a
// const array.
//
// Why this exists:
//   - `bun build --compile` can't read YAMLs from the filesystem at
//     runtime — its virtual /$bunfs doesn't include them.
//   - esbuild can copy them into dist/ (see scripts/bundle-cli.mjs)
//     but binary distribution has no such copy step.
//   - An inlined TS const works for both bundlers and for dev.
//
// The loader prefers EMBEDDED_TEMPLATES when it's non-empty; falls back
// to fs scanning for dev workflows that edit YAMLs without rebuilding.

import { readFileSync, writeFileSync, readdirSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgRoot = join(__dirname, "..");
const attacksDir = join(pkgRoot, "attacks");
const outFile = join(pkgRoot, "src", "embedded.ts");

const templates = [];

for (const category of readdirSync(attacksDir, { withFileTypes: true })) {
  if (!category.isDirectory()) continue;
  const categoryDir = join(attacksDir, category.name);

  for (const file of readdirSync(categoryDir).sort()) {
    if (!file.endsWith(".yaml") && !file.endsWith(".yml")) continue;
    const raw = readFileSync(join(categoryDir, file), "utf-8");
    const parsed = parseYaml(raw);
    templates.push(parsed);
  }
}

templates.sort((a, b) => (a.id ?? "").localeCompare(b.id ?? ""));

const banner = `// GENERATED FILE — do not edit.
// Regenerate with: pnpm --filter @pwnkit/templates gen
//
// Inlines every YAML under packages/templates/attacks/ as a typed
// const so the loader works without filesystem access. Needed for
// binary distribution (bun build --compile's /$bunfs has no YAMLs).
import type { AttackTemplate } from "@pwnkit/shared";

export const EMBEDDED_TEMPLATES: AttackTemplate[] = ${JSON.stringify(templates, null, 2)};
`;

mkdirSync(dirname(outFile), { recursive: true });
writeFileSync(outFile, banner, "utf-8");
console.log(`Generated ${outFile} with ${templates.length} templates`);
