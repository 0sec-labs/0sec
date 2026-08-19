/**
 * Skill registry — loads YAML skill definitions, provides lookup and
 * trigger-matching for JIT methodology injection (#410, #456).
 */

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import type { SkillDefinition, SkillSummary } from "./types.js";
import type { VulnClass } from "../prompts.js";

export type { SkillDefinition, SkillSummary } from "./types.js";

/**
 * Maps an EGATS vuln class (#557) to the methodology skill that should be
 * auto-loaded for a specialist branch. Only classes with a matching skill in
 * the registry are listed — classes without a dedicated skill (xss, idor)
 * still route to a specialist prompt + tool subset, they just don't preload a
 * skill. Skill IDs must match the `id:` of a YAML file under this directory
 * tree (validated by the skill-integration test).
 */
export const VULN_CLASS_SKILL: Partial<Record<VulnClass, string>> = {
  sqli: "sqli-advanced",
  ssti: "ssti-exploitation",
  ssrf: "ssrf-bypass",
  "auth-bypass": "jwt-attacks",
};

/** Return the skill ID to auto-load for a vuln class, or undefined if none. */
export function skillIdForVulnClass(vulnClass: VulnClass): string | undefined {
  return VULN_CLASS_SKILL[vulnClass];
}

const __dirname = fileURLToPath(new URL(".", import.meta.url));

const REQUIRED_FIELDS: Array<keyof SkillDefinition> = [
  "id",
  "name",
  "description",
  "version",
  "applicable_roles",
  "tags",
  "triggers",
  "estimated_tokens",
  "content",
];

const VALID_ROLES = new Set(["attack", "audit", "review"]);

// ── Internal helpers ────────────────────────────────────────────────

function validateSkill(raw: unknown, filePath: string): SkillDefinition {
  if (typeof raw !== "object" || raw === null) {
    throw new Error(`Skill file ${filePath}: expected an object at top level`);
  }
  const obj = raw as Record<string, unknown>;

  for (const field of REQUIRED_FIELDS) {
    if (!(field in obj)) {
      throw new Error(`Skill file ${filePath}: missing required field "${field}"`);
    }
  }

  if (typeof obj.id !== "string" || obj.id.length === 0) {
    throw new Error(`Skill file ${filePath}: "id" must be a non-empty string`);
  }
  if (typeof obj.name !== "string") {
    throw new Error(`Skill file ${filePath}: "name" must be a string`);
  }
  if (typeof obj.description !== "string") {
    throw new Error(`Skill file ${filePath}: "description" must be a string`);
  }
  if (typeof obj.version !== "number" || !Number.isInteger(obj.version)) {
    throw new Error(`Skill file ${filePath}: "version" must be an integer`);
  }
  if (!Array.isArray(obj.applicable_roles) || obj.applicable_roles.length === 0) {
    throw new Error(`Skill file ${filePath}: "applicable_roles" must be a non-empty array`);
  }
  for (const role of obj.applicable_roles) {
    if (!VALID_ROLES.has(role as string)) {
      throw new Error(
        `Skill file ${filePath}: invalid role "${role}" — must be one of: attack, audit, review`,
      );
    }
  }
  if (!Array.isArray(obj.tags)) {
    throw new Error(`Skill file ${filePath}: "tags" must be an array`);
  }
  if (!Array.isArray(obj.triggers)) {
    throw new Error(`Skill file ${filePath}: "triggers" must be an array`);
  }
  // Validate that trigger patterns are valid regexes
  for (const pattern of obj.triggers) {
    if (typeof pattern !== "string") {
      throw new Error(`Skill file ${filePath}: trigger patterns must be strings`);
    }
    try {
      new RegExp(pattern, "i");
    } catch {
      throw new Error(`Skill file ${filePath}: invalid regex trigger "${pattern}"`);
    }
  }
  if (typeof obj.estimated_tokens !== "number" || obj.estimated_tokens <= 0) {
    throw new Error(`Skill file ${filePath}: "estimated_tokens" must be a positive number`);
  }
  if (typeof obj.content !== "string" || obj.content.length === 0) {
    throw new Error(`Skill file ${filePath}: "content" must be a non-empty string`);
  }

  return obj as unknown as SkillDefinition;
}

function walkYamlFiles(dir: string): string[] {
  const files: string[] = [];
  if (!existsSync(dir)) return files;

  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkYamlFiles(fullPath));
    } else if (extname(entry.name) === ".yaml" || extname(entry.name) === ".yml") {
      files.push(fullPath);
    }
  }
  return files;
}

// ── Registry cache ──────────────────────────────────────────────────

let _registry: Map<string, SkillDefinition> | null = null;
let _registryDir: string | null = null;

/** Clear the cached registry (useful in tests). */
export function clearSkillRegistry(): void {
  _registry = null;
  _registryDir = null;
}

// ── Public API ──────────────────────────────────────────────────────

/**
 * Load all YAML skill files from the skills directory tree.
 * Returns a Map keyed by skill ID. Results are cached after first call.
 */
export function loadSkillRegistry(
  skillsDir?: string,
): Map<string, SkillDefinition> {
  const dir = skillsDir ?? __dirname;
  if (_registry && _registryDir === dir) return _registry;
  const yamlFiles = walkYamlFiles(dir);
  const registry = new Map<string, SkillDefinition>();

  for (const filePath of yamlFiles) {
    const raw = readFileSync(filePath, "utf-8");
    const parsed = parseYaml(raw);
    const skill = validateSkill(parsed, filePath);

    if (registry.has(skill.id)) {
      throw new Error(
        `Duplicate skill ID "${skill.id}" — found in multiple YAML files`,
      );
    }
    registry.set(skill.id, skill);
  }

  _registry = registry;
  _registryDir = dir;
  return registry;
}

/**
 * Look up a single skill by ID. Returns undefined if not found.
 */
export function getSkillById(
  id: string,
  registry?: Map<string, SkillDefinition>,
): SkillDefinition | undefined {
  const reg = registry ?? loadSkillRegistry();
  return reg.get(id);
}

/**
 * Return lightweight summaries for all skills, optionally filtered by tag
 * and/or role. The `suggested` field is always false in static listings;
 * it is set to true by `matchTriggers` for contextually relevant skills.
 */
export function listSkillSummaries(
  opts?: { tag?: string; role?: string },
  registry?: Map<string, SkillDefinition>,
): SkillSummary[] {
  const reg = registry ?? loadSkillRegistry();
  const summaries: SkillSummary[] = [];

  for (const skill of reg.values()) {
    if (opts?.tag && !skill.tags.includes(opts.tag)) continue;
    if (
      opts?.role &&
      !skill.applicable_roles.includes(opts.role as "attack" | "audit" | "review")
    ) {
      continue;
    }

    summaries.push({
      id: skill.id,
      name: skill.name,
      description: skill.description,
      tags: skill.tags,
      estimated_tokens: skill.estimated_tokens,
      suggested: false,
    });
  }

  return summaries;
}

export function formatJitSkillsInstruction(): string {
  const skillIds = listSkillSummaries().map((skill) => skill.id).join(", ");
  return `When you need focused methodology mid-run, call list_skills to inspect available just-in-time skills, then call load_skill with one of: ${skillIds}. Do not load every skill upfront; load only the skill that matches your current hypothesis.`;
}

/**
 * Run trigger regex patterns against recent tool output texts.
 * Returns a Set of skill IDs whose triggers matched at least one text.
 *
 * Each skill requires at least 2 distinct trigger matches to fire
 * (same threshold as playbook detection — avoids single-keyword noise).
 */
export function matchTriggers(
  texts: string[],
  skills: SkillDefinition[],
): Set<string> {
  const combined = texts.join("\n");
  const matched = new Set<string>();

  for (const skill of skills) {
    let hitCount = 0;
    for (const pattern of skill.triggers) {
      try {
        const re = new RegExp(pattern, "i");
        if (re.test(combined)) {
          hitCount++;
        }
      } catch {
        // Skip invalid regex patterns gracefully at runtime
        continue;
      }
    }
    if (hitCount >= 2) {
      matched.add(skill.id);
    }
  }

  return matched;
}
