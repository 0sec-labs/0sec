/**
 * Skill definitions for JIT methodology loading (#410).
 *
 * Skills are YAML files providing focused, actionable methodology guides
 * that the agent can load mid-scan via `load_skill`. They replace the
 * monolithic playbook injection with targeted, on-demand knowledge.
 */

export interface SkillDefinition {
  id: string;
  name: string;
  description: string;
  version: number;
  applicable_roles: Array<"attack" | "audit" | "review">;
  tags: string[];
  triggers: string[]; // regex patterns
  estimated_tokens: number;
  content: string; // markdown methodology
}

export interface SkillSummary {
  id: string;
  name: string;
  description: string;
  tags: string[];
  estimated_tokens: number;
  suggested: boolean;
}
