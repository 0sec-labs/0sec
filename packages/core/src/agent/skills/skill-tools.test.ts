import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import { fileURLToPath } from "node:url";
import { ToolExecutor, TOOL_DEFINITIONS, getToolsForRole } from "../tools.js";
import { clearSkillRegistry, loadSkillRegistry } from "./index.js";
import type { ToolContext } from "../types.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));

/**
 * Build a minimal ToolContext for skill-tool tests. Skills only need
 * `role`, `recentToolResultTexts`, and `loadedSkills` — the rest are
 * stubs so the ToolExecutor constructor doesn't complain.
 */
function makeCtx(overrides?: Partial<ToolContext>): ToolContext {
  return {
    target: "http://localhost:1234",
    scanId: "test-scan",
    findings: [],
    attackResults: [],
    targetInfo: {},
    role: "attack",
    ...overrides,
  };
}

describe("Skill Tools (#457)", () => {
  let savedJitSkills: string | undefined;

  beforeEach(() => {
    savedJitSkills = process.env.PWNKIT_FEATURE_JIT_SKILLS;
    process.env.PWNKIT_FEATURE_JIT_SKILLS = "1";
    clearSkillRegistry();
    loadSkillRegistry(__dirname);
  });

  afterEach(() => {
    if (savedJitSkills === undefined) delete process.env.PWNKIT_FEATURE_JIT_SKILLS;
    else process.env.PWNKIT_FEATURE_JIT_SKILLS = savedJitSkills;
    clearSkillRegistry();
  });

  // ── list_skills ─────────────────────────────────────────────────

  describe("list_skills", () => {
    it("returns summaries for all skills", async () => {
      const executor = new ToolExecutor(makeCtx());
      const result = await executor.execute({
        name: "list_skills",
        arguments: {},
      });

      expect(result.success).toBe(true);
      const output = result.output as {
        skills: Array<{ id: string; name: string; suggested: boolean }>;
        total: number;
      };
      expect(output.total).toBe(16);
      expect(output.skills.length).toBe(16);

      // Every skill should have the expected shape
      for (const s of output.skills) {
        expect(typeof s.id).toBe("string");
        expect(typeof s.name).toBe("string");
        expect(typeof s.suggested).toBe("boolean");
      }
    });

    it("filters by tag", async () => {
      const executor = new ToolExecutor(makeCtx());
      const result = await executor.execute({
        name: "list_skills",
        arguments: { tag: "sqli" },
      });

      expect(result.success).toBe(true);
      const output = result.output as {
        skills: Array<{ id: string; tags: string[] }>;
        total: number;
      };
      expect(output.total).toBeGreaterThanOrEqual(1);
      for (const s of output.skills) {
        expect(s.tags).toContain("sqli");
      }
    });

    it("returns empty list for nonexistent tag", async () => {
      const executor = new ToolExecutor(makeCtx());
      const result = await executor.execute({
        name: "list_skills",
        arguments: { tag: "does-not-exist-xyz" },
      });

      expect(result.success).toBe(true);
      const output = result.output as { total: number };
      expect(output.total).toBe(0);
    });

    it("marks suggested skills based on trigger matching", async () => {
      const executor = new ToolExecutor(
        makeCtx({
          recentToolResultTexts: [
            "ERROR: You have an error in your SQL syntax near 'test'",
            "UNION SELECT 1,2,3 from information_schema.tables",
          ],
        }),
      );

      const result = await executor.execute({
        name: "list_skills",
        arguments: {},
      });

      expect(result.success).toBe(true);
      const output = result.output as {
        skills: Array<{ id: string; suggested: boolean }>;
        suggested_count: number;
      };

      const sqli = output.skills.find((s) => s.id === "sqli-advanced");
      expect(sqli).toBeDefined();
      expect(sqli!.suggested).toBe(true);
      expect(output.suggested_count).toBeGreaterThanOrEqual(1);
    });

    it("marks no skills suggested when there are no recent texts", async () => {
      const executor = new ToolExecutor(makeCtx());
      const result = await executor.execute({
        name: "list_skills",
        arguments: {},
      });

      expect(result.success).toBe(true);
      const output = result.output as {
        skills: Array<{ suggested: boolean }>;
        suggested_count: number;
      };
      expect(output.suggested_count).toBe(0);
      expect(output.skills.every((s) => !s.suggested)).toBe(true);
    });
  });

  // ── load_skill ──────────────────────────────────────────────────

  describe("load_skill", () => {
    it("returns skill content for a valid skill ID", async () => {
      const executor = new ToolExecutor(
        makeCtx({ loadedSkills: new Set() }),
      );
      const result = await executor.execute({
        name: "load_skill",
        arguments: { skill_id: "sqli-advanced" },
      });

      expect(result.success).toBe(true);
      const output = result.output as {
        kind: string;
        skill_id: string;
        name: string;
        content: string;
        estimated_tokens: number;
      };
      expect(output.kind).toBe("skill_loaded");
      expect(output.skill_id).toBe("sqli-advanced");
      expect(output.name).toBe("Advanced SQL Injection");
      expect(typeof output.content).toBe("string");
      expect(output.content.length).toBeGreaterThan(0);
      expect(output.estimated_tokens).toBeGreaterThan(0);
    });

    it("refuses double-load for already loaded skills", async () => {
      const loaded = new Set(["sqli-advanced"]);
      const executor = new ToolExecutor(makeCtx({ loadedSkills: loaded }));
      const result = await executor.execute({
        name: "load_skill",
        arguments: { skill_id: "sqli-advanced" },
      });

      expect(result.success).toBe(true);
      const output = result.output as { kind: string; message: string };
      expect(output.kind).toBe("already_loaded");
      expect(output.message).toBe("Skill already loaded");
    });

    it("tracks loaded skills across consecutive calls", async () => {
      const ctx = makeCtx({ loadedSkills: new Set() });
      const executor = new ToolExecutor(ctx);

      // First load — should succeed
      const first = await executor.execute({
        name: "load_skill",
        arguments: { skill_id: "jwt-attacks" },
      });
      expect(first.success).toBe(true);
      expect((first.output as { kind: string }).kind).toBe("skill_loaded");

      // Second load of same skill — should return already_loaded
      const second = await executor.execute({
        name: "load_skill",
        arguments: { skill_id: "jwt-attacks" },
      });
      expect(second.success).toBe(true);
      expect((second.output as { kind: string }).kind).toBe("already_loaded");
    });

    it("initializes loadedSkills set when ctx has none", async () => {
      // ctx.loadedSkills is undefined (not pre-initialized)
      const ctx = makeCtx();
      expect(ctx.loadedSkills).toBeUndefined();

      const executor = new ToolExecutor(ctx);
      const result = await executor.execute({
        name: "load_skill",
        arguments: { skill_id: "prototype-pollution" },
      });

      expect(result.success).toBe(true);
      expect(ctx.loadedSkills).toBeDefined();
      expect(ctx.loadedSkills!.has("prototype-pollution")).toBe(true);
    });

    it("returns error for unknown skill ID", async () => {
      const executor = new ToolExecutor(
        makeCtx({ loadedSkills: new Set() }),
      );
      const result = await executor.execute({
        name: "load_skill",
        arguments: { skill_id: "nonexistent-skill-xyz" },
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("Unknown skill ID");
      expect(result.error).toContain("nonexistent-skill-xyz");
    });

    it("returns error when skill_id is missing", async () => {
      const executor = new ToolExecutor(makeCtx());
      const result = await executor.execute({
        name: "load_skill",
        arguments: {},
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("skill_id is required");
    });
  });

  // ── Feature flag gating ─────────────────────────────────────────

  describe("feature flag gating", () => {
    const originalEnv = process.env.PWNKIT_FEATURE_JIT_SKILLS;

    afterEach(() => {
      if (originalEnv === undefined) {
        delete process.env.PWNKIT_FEATURE_JIT_SKILLS;
      } else {
        process.env.PWNKIT_FEATURE_JIT_SKILLS = originalEnv;
      }
    });

    it("both tools are absent from all roles when feature flag is off", () => {
      process.env.PWNKIT_FEATURE_JIT_SKILLS = "0";

      for (const role of ["discovery", "attack", "verify", "report", "audit", "review"]) {
        const tools = getToolsForRole(role);
        const names = tools.map((t) => t.name);
        expect(names).not.toContain("list_skills");
        expect(names).not.toContain("load_skill");
      }
    });

    it("both tools are present for attack role when feature flag is on", () => {
      process.env.PWNKIT_FEATURE_JIT_SKILLS = "1";

      const tools = getToolsForRole("attack");
      const names = tools.map((t) => t.name);
      expect(names).toContain("list_skills");
      expect(names).toContain("load_skill");
    });

    it("both tools are present for audit role when feature flag is on", () => {
      process.env.PWNKIT_FEATURE_JIT_SKILLS = "1";

      const tools = getToolsForRole("audit");
      const names = tools.map((t) => t.name);
      expect(names).toContain("list_skills");
      expect(names).toContain("load_skill");
    });

    it("both tools are present for review role when feature flag is on", () => {
      process.env.PWNKIT_FEATURE_JIT_SKILLS = "1";

      const tools = getToolsForRole("review");
      const names = tools.map((t) => t.name);
      expect(names).toContain("list_skills");
      expect(names).toContain("load_skill");
    });
  });

  // ── Tool definitions exist in TOOL_DEFINITIONS ──────────────────

  describe("tool definitions", () => {
    it("list_skills is defined in TOOL_DEFINITIONS", () => {
      expect(TOOL_DEFINITIONS.list_skills).toBeDefined();
      expect(TOOL_DEFINITIONS.list_skills.name).toBe("list_skills");
      expect(TOOL_DEFINITIONS.list_skills.parameters.tag).toBeDefined();
    });

    it("load_skill is defined in TOOL_DEFINITIONS", () => {
      expect(TOOL_DEFINITIONS.load_skill).toBeDefined();
      expect(TOOL_DEFINITIONS.load_skill.name).toBe("load_skill");
      expect(TOOL_DEFINITIONS.load_skill.parameters.skill_id).toBeDefined();
      expect(TOOL_DEFINITIONS.load_skill.required).toEqual(["skill_id"]);
    });
  });
});
