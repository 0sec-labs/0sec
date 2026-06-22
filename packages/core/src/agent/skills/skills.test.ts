import { describe, expect, it, beforeEach } from "vitest";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadSkillRegistry,
  getSkillById,
  listSkillSummaries,
  matchTriggers,
  clearSkillRegistry,
  formatJitSkillsInstruction,
} from "./index.js";
import type { SkillDefinition, SkillSummary } from "./types.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));

const EXPECTED_SKILL_IDS = [
  "graphql-introspection",
  "wordpress-deep",
  "sqli-advanced",
  "ssti-exploitation",
  "prototype-pollution",
  "blind-exploitation",
  "jwt-attacks",
  "crypto-misuse",
  "race-condition",
  "deserialization-chains",
  "request-smuggling",
  "structural-sqli",
  "command-injection",
  "ssrf-bypass",
  "path-traversal",
  "native-memory-safety",
  "llm-prompt-injection",
  "llm-insecure-output-handling",
  "llm-excessive-agency",
  "llm-rag-poisoning",
  "llm-prompt-layer-write",
  "cardano-eutxo-validators",
];

const VALID_ROLES = new Set(["attack", "audit", "review"]);

describe("Skill Registry", () => {
  beforeEach(() => {
    clearSkillRegistry();
  });

  // ── Schema validation ──────────────────────────────────────────

  describe("schema validation for all skills", () => {
    it("loadSkillRegistry() loads all starter skills", () => {
      const registry = loadSkillRegistry(__dirname);
      expect(registry.size).toBe(EXPECTED_SKILL_IDS.length);
      for (const id of EXPECTED_SKILL_IDS) {
        expect(registry.has(id)).toBe(true);
      }
    });

    it.each(EXPECTED_SKILL_IDS)("skill '%s' has all required fields", (id) => {
      const registry = loadSkillRegistry(__dirname);
      const skill = registry.get(id)!;
      expect(skill).toBeDefined();

      // Required string fields
      expect(typeof skill.id).toBe("string");
      expect(skill.id.length).toBeGreaterThan(0);
      expect(typeof skill.name).toBe("string");
      expect(skill.name.length).toBeGreaterThan(0);
      expect(typeof skill.description).toBe("string");
      expect(skill.description.length).toBeGreaterThan(0);
      expect(typeof skill.content).toBe("string");
      expect(skill.content.length).toBeGreaterThan(0);

      // Version
      expect(typeof skill.version).toBe("number");
      expect(Number.isInteger(skill.version)).toBe(true);
      expect(skill.version).toBeGreaterThanOrEqual(1);

      // Arrays
      expect(Array.isArray(skill.applicable_roles)).toBe(true);
      expect(skill.applicable_roles.length).toBeGreaterThan(0);
      for (const role of skill.applicable_roles) {
        expect(VALID_ROLES.has(role)).toBe(true);
      }

      expect(Array.isArray(skill.tags)).toBe(true);
      expect(skill.tags.length).toBeGreaterThan(0);

      expect(Array.isArray(skill.triggers)).toBe(true);
      expect(skill.triggers.length).toBeGreaterThan(0);

      // Token estimate
      expect(typeof skill.estimated_tokens).toBe("number");
      expect(skill.estimated_tokens).toBeGreaterThan(0);
    });

    it.each(EXPECTED_SKILL_IDS)(
      "skill '%s' has valid regex trigger patterns",
      (id) => {
        const registry = loadSkillRegistry(__dirname);
        const skill = registry.get(id)!;
        for (const pattern of skill.triggers) {
          expect(() => new RegExp(pattern, "i")).not.toThrow();
        }
      },
    );

    it.each(EXPECTED_SKILL_IDS)(
      "skill '%s' uses kebab-case ID",
      (id) => {
        expect(id).toMatch(/^[a-z][a-z0-9]*(-[a-z0-9]+)*$/);
      },
    );
  });

  // ── getSkillById ───────────────────────────────────────────────

  describe("getSkillById()", () => {
    it("returns the correct skill for known IDs", () => {
      const registry = loadSkillRegistry(__dirname);
      for (const id of EXPECTED_SKILL_IDS) {
        const skill = getSkillById(id, registry);
        expect(skill).toBeDefined();
        expect(skill!.id).toBe(id);
      }
    });

    it("returns undefined for unknown IDs", () => {
      const registry = loadSkillRegistry(__dirname);
      expect(getSkillById("nonexistent-skill", registry)).toBeUndefined();
      expect(getSkillById("", registry)).toBeUndefined();
      expect(getSkillById("sqli", registry)).toBeUndefined(); // close but not exact
    });
  });

  // ── listSkillSummaries ─────────────────────────────────────────

  describe("listSkillSummaries()", () => {
    it("returns all skills when no filter is applied", () => {
      const registry = loadSkillRegistry(__dirname);
      const summaries = listSkillSummaries(undefined, registry);
      expect(summaries.length).toBe(EXPECTED_SKILL_IDS.length);
    });

    it("returns SkillSummary objects with correct shape", () => {
      const registry = loadSkillRegistry(__dirname);
      const summaries = listSkillSummaries(undefined, registry);
      for (const s of summaries) {
        expect(typeof s.id).toBe("string");
        expect(typeof s.name).toBe("string");
        expect(typeof s.description).toBe("string");
        expect(Array.isArray(s.tags)).toBe(true);
        expect(typeof s.estimated_tokens).toBe("number");
        expect(typeof s.suggested).toBe("boolean");
        expect(s.suggested).toBe(false); // static listing
      }
    });

    it("filters by tag correctly", () => {
      const registry = loadSkillRegistry(__dirname);

      const sqliResults = listSkillSummaries({ tag: "sqli" }, registry);
      expect(sqliResults.length).toBeGreaterThanOrEqual(1);
      expect(sqliResults.every((s) => s.tags.includes("sqli"))).toBe(true);

      const jwtResults = listSkillSummaries({ tag: "jwt" }, registry);
      expect(jwtResults.length).toBeGreaterThanOrEqual(1);
      expect(jwtResults.every((s) => s.tags.includes("jwt"))).toBe(true);

      const noResults = listSkillSummaries(
        { tag: "nonexistent-tag" },
        registry,
      );
      expect(noResults.length).toBe(0);
    });

    it("filters by role correctly", () => {
      const registry = loadSkillRegistry(__dirname);

      const attackSkills = listSkillSummaries({ role: "attack" }, registry);
      expect(attackSkills.length).toBe(EXPECTED_SKILL_IDS.length);

      const reviewSkills = listSkillSummaries({ role: "review" }, registry);
      expect(reviewSkills.length).toBe(5);
      const reviewIds = reviewSkills.map((s) => s.id).sort();
      expect(reviewIds).toEqual([
        "blind-exploitation",
        "cardano-eutxo-validators",
        "crypto-misuse",
        "graphql-introspection",
        "jwt-attacks",
      ]);
    });

    it("combines tag and role filters", () => {
      const registry = loadSkillRegistry(__dirname);

      const results = listSkillSummaries(
        { tag: "blind", role: "review" },
        registry,
      );
      expect(results.length).toBe(1);
      expect(results[0].id).toBe("blind-exploitation");
    });
  });

  describe("formatJitSkillsInstruction()", () => {
    it("points agents to list_skills/load_skill without embedding skill bodies", () => {
      const instruction = formatJitSkillsInstruction();

      expect(instruction).toContain("list_skills");
      expect(instruction).toContain("load_skill");
      expect(instruction).toContain("sqli-advanced");
      expect(instruction).toContain("Do not load every skill upfront");
      expect(instruction).not.toContain("##");
    });
  });

  // ── matchTriggers ──────────────────────────────────────────────

  describe("matchTriggers()", () => {
    it("matches sqli-advanced from SQL error output", () => {
      const registry = loadSkillRegistry(__dirname);
      const skills = [...registry.values()];

      const texts = [
        "ERROR: You have an error in your SQL syntax near 'test'",
        "UNION SELECT 1,2,3 from information_schema.tables",
      ];
      const matched = matchTriggers(texts, skills);
      expect(matched.has("sqli-advanced")).toBe(true);
    });

    it("matches ssti-exploitation from template output", () => {
      const registry = loadSkillRegistry(__dirname);
      const skills = [...registry.values()];

      const texts = [
        "Response contains: {{config}} and the template engine is Jinja2",
        "Output: 49",
      ];
      const matched = matchTriggers(texts, skills);
      expect(matched.has("ssti-exploitation")).toBe(true);
    });

    it("matches prototype-pollution from Node.js indicators", () => {
      const registry = loadSkillRegistry(__dirname);
      const skills = [...registry.values()];

      const texts = [
        'POST /api/settings with body {"__proto__": {"admin": true}}',
        "The application uses lodash.merge for deep object merging",
      ];
      const matched = matchTriggers(texts, skills);
      expect(matched.has("prototype-pollution")).toBe(true);
    });

    it("matches blind-exploitation from blind injection indicators", () => {
      const registry = loadSkillRegistry(__dirname);
      const skills = [...registry.values()];

      const texts = [
        "The injection appears to be blind — no output is visible",
        "Trying time-based detection with SLEEP(5)",
      ];
      const matched = matchTriggers(texts, skills);
      expect(matched.has("blind-exploitation")).toBe(true);
    });

    it("matches jwt-attacks from JWT token output", () => {
      const registry = loadSkillRegistry(__dirname);
      const skills = [...registry.values()];

      const texts = [
        "Authorization: Bearer ***REMOVED***",
        'JWT header: {"alg": "HS256", "typ": "JWT"}',
      ];
      const matched = matchTriggers(texts, skills);
      expect(matched.has("jwt-attacks")).toBe(true);
    });

    it("returns empty set when no triggers match", () => {
      const registry = loadSkillRegistry(__dirname);
      const skills = [...registry.values()];

      const texts = ["This is completely benign text with no security indicators."];
      const matched = matchTriggers(texts, skills);
      expect(matched.size).toBe(0);
    });

    it("requires at least 2 trigger matches per skill (threshold)", () => {
      const registry = loadSkillRegistry(__dirname);
      const skills = [...registry.values()];

      // Only one trigger match — should not fire (threshold is 2)
      const texts = ["The token has expired"];
      const matched = matchTriggers(texts, skills);
      expect(matched.has("jwt-attacks")).toBe(false);
    });

    it("does not throw on malformed input", () => {
      const registry = loadSkillRegistry(__dirname);
      const skills = [...registry.values()];

      expect(() => matchTriggers([], skills)).not.toThrow();
      expect(() => matchTriggers([""], skills)).not.toThrow();
      expect(() =>
        matchTriggers(
          ["\x00\xff null bytes and weird chars"],
          skills,
        ),
      ).not.toThrow();
      expect(() =>
        matchTriggers(
          ["a".repeat(100000)],
          skills,
        ),
      ).not.toThrow();
    });

    it("trigger regexes do not throw on adversarial strings", () => {
      const registry = loadSkillRegistry(__dirname);
      const skills = [...registry.values()];

      const adversarial = [
        "((((((((((",
        "\\\\\\\\\\\\",
        "${`{{<%=",
        "a]b[c{d}e(f)g",
        "SELECT * FROM; DROP TABLE --",
        "\n\r\t\0",
      ];
      expect(() => matchTriggers(adversarial, skills)).not.toThrow();
    });
  });

  // ── Content quality checks ─────────────────────────────────────

  describe("content quality", () => {
    it.each(EXPECTED_SKILL_IDS)(
      "skill '%s' content has actionable methodology (>20 lines)",
      (id) => {
        const registry = loadSkillRegistry(__dirname);
        const skill = registry.get(id)!;
        const lineCount = skill.content.split("\n").length;
        expect(lineCount).toBeGreaterThanOrEqual(20);
      },
    );

    it.each(EXPECTED_SKILL_IDS)(
      "skill '%s' content contains phase/step headers",
      (id) => {
        const registry = loadSkillRegistry(__dirname);
        const skill = registry.get(id)!;
        // Should have at least 3 markdown headers (phases/steps)
        const headers = skill.content.match(/^###?\s/gm) ?? [];
        expect(headers.length).toBeGreaterThanOrEqual(3);
      },
    );

    it("estimated_tokens are in expected range (400-1000)", () => {
      const registry = loadSkillRegistry(__dirname);
      for (const skill of registry.values()) {
        expect(skill.estimated_tokens).toBeGreaterThanOrEqual(400);
        expect(skill.estimated_tokens).toBeLessThanOrEqual(1000);
      }
    });
  });
});
