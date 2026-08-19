import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import type { AttackTemplate, ScanDepth } from "@pwnkit/shared";
import { EMBEDDED_TEMPLATES } from "./embedded.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const TEMPLATES_DIR_CANDIDATES = [
  join(__dirname, "..", "attacks"),
  join(__dirname, "attacks"),
];

let _cache: AttackTemplate[] | null = null;

export function clearTemplateCache(): void {
  _cache = null;
}

function resolveTemplatesDir(): string {
  for (const candidate of TEMPLATES_DIR_CANDIDATES) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }

  return TEMPLATES_DIR_CANDIDATES[0];
}

function loadFromFilesystem(): AttackTemplate[] {
  const templates: AttackTemplate[] = [];
  const dir = resolveTemplatesDir();

  for (const category of readdirSync(dir, { withFileTypes: true })) {
    if (!category.isDirectory()) continue;
    const categoryDir = join(dir, category.name);

    for (const file of readdirSync(categoryDir)) {
      if (extname(file) !== ".yaml" && extname(file) !== ".yml") continue;
      const raw = readFileSync(join(categoryDir, file), "utf-8");
      const parsed = parseYaml(raw) as AttackTemplate;
      templates.push(parsed);
    }
  }

  return templates;
}

export function loadTemplates(depth?: ScanDepth): AttackTemplate[] {
  if (_cache) {
    return depth ? _cache.filter((t) => t.depth.includes(depth)) : _cache;
  }

  // Prefer the codegenned inlined templates — they're required for binary
  // distribution (bun build --compile can't read the YAMLs at runtime) and
  // also avoid fs calls in the hot path of normal runs. Fall back to
  // filesystem scanning when the embedded list is empty (dev checkouts
  // that haven't regenerated after touching a YAML).
  const templates = EMBEDDED_TEMPLATES.length > 0
    ? EMBEDDED_TEMPLATES
    : loadFromFilesystem();

  _cache = templates;
  return depth ? _cache.filter((t) => t.depth.includes(depth)) : _cache;
}

export function loadTemplateById(id: string): AttackTemplate | undefined {
  const all = loadTemplates();
  return all.find((t) => t.id === id);
}
