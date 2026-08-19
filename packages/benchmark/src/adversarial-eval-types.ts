import type { AttackCategory } from "@pwnkit/shared";

export type AdversarialTargetClass =
  | "mcp-server"
  | "tool-using-agent"
  | "agent-http-api";

export type AdversarialAttackClass =
  | "indirect-prompt-injection"
  | "tool-misuse"
  | "data-exfiltration"
  | "persistence";

export interface AdversarialEvalCase {
  id: string;
  title: string;
  targetClass: AdversarialTargetClass;
  attackClass: AdversarialAttackClass;
  scenario: string;
  attackPrompt: string;
  dangerousTool: string;
  attackerControlledField: string;
  successCriteria: string[];
  failureCriteria: string[];
  expectedFindingCategories: AttackCategory[];
}
