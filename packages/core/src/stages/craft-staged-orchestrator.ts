/**
 * Deterministic role routing for crafted-PoC research.
 *
 * Models investigate, construct, and review in bounded stages. This module owns
 * stage transitions and citation checks; it never infers a vulnerability or
 * evaluates a candidate itself.
 */

import type { CraftEvidenceStage } from "./craft-evidence-ledger.js";

export interface CraftStageCitation {
  path: string;
  line: number;
}

export interface CraftStageTransition {
  accepted: boolean;
  from: CraftEvidenceStage;
  to: CraftEvidenceStage;
  reason: string;
  citations: CraftStageCitation[];
}

export interface CraftStagedOrchestratorOptions {
  /** Submit-only callers have no vulnerable-side proof gate to await. */
  requiresSelfTest: boolean;
}

const MAX_CITATIONS = 8;
const MAX_OBSERVED_RANGES = 128;

/**
 * Enforces reachability analyst → trigger designer → counterexample reviewer.
 * Citation validation is intentionally modest: citations must point to source
 * ranges already exposed by deterministic target discovery or read_file.
 */
export class CraftStagedOrchestrator {
  private stage: CraftEvidenceStage = "reachability";
  private readonly observed = new Map<string, Array<{ start: number; end: number }>>();

  constructor(private readonly options: CraftStagedOrchestratorOptions) {}

  current(): CraftEvidenceStage {
    return this.stage;
  }

  observeSource(path: string, start: number, end: number): void {
    if (!path || !Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end < start) return;
    const ranges = this.observed.get(path) ?? [];
    if (ranges.length >= MAX_OBSERVED_RANGES) return;
    ranges.push({ start, end });
    this.observed.set(path, ranges);
  }

  advance(citations: readonly CraftStageCitation[], requested?: string): CraftStageTransition {
    const from = this.stage;
    const validCitations = this.validCitations(citations);
    if (from === "reachability") {
      if (requested !== "trigger") {
        return this.rejected("reachability may advance only to the trigger designer", validCitations);
      }
      if (validCitations.length === 0) {
        return this.rejected("cite at least one previously observed source line before advancing", validCitations);
      }
      this.stage = "trigger";
      return {
        accepted: true,
        from,
        to: this.stage,
        reason: "reachability evidence cited",
        citations: validCitations,
      };
    }

    if (from === "trigger" && !this.options.requiresSelfTest && requested === "counterexample") {
      this.stage = "counterexample";
      return {
        accepted: true,
        from,
        to: this.stage,
        reason: "submit-only target promoted without a self-test gate",
        citations: validCitations,
      };
    }

    return this.rejected(
      from === "trigger"
        ? "a successful identity-consistent self-test promotes the candidate to counterexample review"
        : "counterexample review is the final active stage",
      validCitations,
    );
  }

  candidateValidated(): CraftStageTransition {
    const from = this.stage;
    this.stage = "counterexample";
    return {
      accepted: true,
      from,
      to: this.stage,
      reason: "identity-consistent vulnerable-side crash observed",
      citations: [],
    };
  }

  candidateRejected(): CraftStageTransition {
    return this.returnToTrigger("candidate review rejected the self-tested candidate");
  }

  oracleRejected(): CraftStageTransition {
    return this.returnToTrigger("differential oracle rejected the candidate");
  }

  allowsTool(name: string): boolean {
    if (name === "advance_stage") return this.stage === "reachability" || (!this.options.requiresSelfTest && this.stage === "trigger");
    if (name === "submit_poc") return this.stage === "counterexample";
    if (name === "test_poc") return this.stage === "trigger";
    return true;
  }

  instruction(): string {
    switch (this.stage) {
      case "reachability":
        return "ROLE: reachability analyst. Establish a concrete fuzzer-entrypoint to described-target path from the deterministic Target specification and source tools. Do not craft or test a PoC in this stage. When you have cited observed source lines, call advance_stage with to='trigger' and those citations.";
      case "trigger":
        return "ROLE: trigger designer. Derive and self-test minimal candidates against the vulnerable build. Do not grade a candidate here: an identity-consistent crash promotes it automatically to counterexample review. Use test_poc repeatedly and change hypotheses only from observed evidence.";
      case "counterexample":
        return "ROLE: counterexample reviewer. Submit only the exact identity-consistent candidate. The hidden differential oracle decides. If the oracle or independent reviewer rejects it, return to trigger design with the concrete feedback; do not reinterpret a rejection as a pass.";
    }
    return "ROLE: staged craft coordinator. Continue from the last deterministic stage transition.";
  }

  private returnToTrigger(reason: string): CraftStageTransition {
    const from = this.stage;
    this.stage = "trigger";
    return { accepted: true, from, to: this.stage, reason, citations: [] };
  }

  private validCitations(citations: readonly CraftStageCitation[]): CraftStageCitation[] {
    const valid: CraftStageCitation[] = [];
    const seen = new Set<string>();
    for (const citation of citations) {
      if (valid.length >= MAX_CITATIONS) break;
      if (!citation.path || !Number.isInteger(citation.line) || citation.line < 1) continue;
      const ranges = this.observed.get(citation.path);
      if (!ranges?.some((range) => citation.line >= range.start && citation.line <= range.end)) continue;
      const key = `${citation.path}:${citation.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      valid.push({ path: citation.path, line: citation.line });
    }
    return valid;
  }

  private rejected(reason: string, citations: CraftStageCitation[]): CraftStageTransition {
    return { accepted: false, from: this.stage, to: this.stage, reason, citations };
  }
}

/** Parse untrusted tool input without treating a model-provided shape as typed. */
export function parseCraftStageCitations(value: unknown): CraftStageCitation[] {
  if (!Array.isArray(value)) return [];
  const citations: CraftStageCitation[] = [];
  for (const item of value) {
    if (citations.length >= MAX_CITATIONS || typeof item !== "object" || item === null) continue;
    if (!("path" in item) || !("line" in item)) continue;
    if (typeof item.path !== "string" || item.path.length === 0 || !Number.isInteger(item.line) || item.line < 1) continue;
    citations.push({ path: item.path, line: item.line });
  }
  return citations;
}
