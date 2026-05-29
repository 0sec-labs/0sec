/**
 * JIT skills tool definitions (pwnkit#611 — split out of the monolithic
 * agent/tools.ts registry).
 *
 * Just-in-time methodology skill discovery/loading (feature-gated behind
 * --features jit_skills).
 *
 * Pure `ToolDefinition` metadata (name / description / parameter schema). The
 * ./tools/index.ts barrel merges every per-domain map into the canonical
 * `TOOL_DEFINITIONS` registry; the matching runtime handlers live on the
 * `ToolExecutor` class in agent/tools.ts.
 */
import type { ToolDefinition } from "../types.js";

export const skillsToolDefinitions: Record<string, ToolDefinition> = {
  list_skills: {
    name: "list_skills",
    description:
      "List available methodology skills that can be loaded into your context. Skills marked 'suggested' match patterns in your recent findings. Use when you need deeper guidance on a specific attack vector.",
    parameters: {
      tag: { type: "string", description: "Optional tag filter" },
    },
  },

  load_skill: {
    name: "load_skill",
    description:
      "Load a skill's methodology guide into your working context. Use list_skills first to see what's available.",
    parameters: {
      skill_id: { type: "string", description: "Skill ID from list_skills" },
    },
    required: ["skill_id"],
  },
};
