import { describe, expect, it, beforeEach } from "vitest";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import { EMBEDDED_SKILL_YAML } from "./skills.generated.js";
import { clearSkillRegistry, loadSkillRegistry } from "./index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SKILLS_DIR = __dirname;
const CORE_ROOT = join(__dirname, "..", "..", "..");

function walkYaml(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkYaml(p));
    else if (entry.name.endsWith(".yaml") || entry.name.endsWith(".yml")) out.push(p);
  }
  return out;
}

/**
 * The embedded skill manifest (skills.generated.ts) is what makes JIT skills
 * survive `bun --compile` — the loader falls back to it when no YAML is on disk
 * (the packaged binary case). These tests pin that it stays faithful to the
 * source YAML and that the fallback path actually registers every skill.
 */
describe("embedded skill manifest", () => {
  it("covers every source skill YAML, byte-for-byte (regen if this fails)", () => {
    const onDisk = walkYaml(SKILLS_DIR);
    const relKeys = onDisk
      .map((p) => relative(SKILLS_DIR, p).split("\\").join("/"))
      .sort();

    // Same set of files.
    expect(Object.keys(EMBEDDED_SKILL_YAML).sort()).toEqual(relKeys);

    // Same content — catches an edited YAML with a stale manifest.
    for (const abs of onDisk) {
      const rel = relative(SKILLS_DIR, abs).split("\\").join("/");
      expect(
        EMBEDDED_SKILL_YAML[rel],
        `${rel} drifted — run: pnpm --filter @0sec/core generate-skills`,
      ).toBe(readFileSync(abs, "utf8"));
    }
  });

  it("regenerating the manifest is a no-op (deterministic + committed)", () => {
    const path = join(SKILLS_DIR, "skills.generated.ts");
    const before = readFileSync(path, "utf8");
    execFileSync("node", [join(CORE_ROOT, "scripts", "generate-skills-manifest.mjs")]);
    const after = readFileSync(path, "utf8");
    expect(after, "generator output drifted from the committed file").toBe(before);
  });

  it("every embedded entry parses and validates as a loadable skill", () => {
    for (const [rel, raw] of Object.entries(EMBEDDED_SKILL_YAML)) {
      const parsed = parseYaml(raw) as { id?: unknown; content?: unknown };
      expect(typeof parsed.id, `${rel} needs an id`).toBe("string");
      expect(typeof parsed.content, `${rel} needs content`).toBe("string");
    }
  });

  it("the loader registers all skills from the manifest when no YAML is on disk", () => {
    // Point the loader at an empty dir → forces the embedded-manifest fallback,
    // exactly as the compiled binary hits it.
    clearSkillRegistry();
    const emptyDir = fileURLToPath(new URL(".", import.meta.url)) + "__does_not_exist__";
    const reg = loadSkillRegistry(emptyDir);
    expect(reg.size).toBe(Object.keys(EMBEDDED_SKILL_YAML).length);
    for (const id of ["nextjs-appsec", "supabase-appsec", "python-web-appsec"]) {
      expect(reg.has(id), `embedded fallback should register ${id}`).toBe(true);
    }
    clearSkillRegistry();
  });
});
