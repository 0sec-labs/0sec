import {
  appendProposalAttempt,
  readProposalReplay,
  validateProposalAttempt,
  type ProposalAttempt,
} from "./proposal-replay.js";
import {
  rankResearchProposals,
  trainProposalRanker,
  type ProposalRankerModel,
} from "./proposal-ranker.js";
import { validateResearchProposal, type ResearchProposal } from "./proposal.js";

export interface ProposalLearningContext {
  model: ProposalRankerModel;
  attemptNumber: number;
  signal?: AbortSignal;
}

export interface RunProposalLearningLoopOptions {
  proposals: readonly unknown[];
  replayPath: string;
  /** Hard experiment ceiling for this invocation. */
  maxAttempts: number;
  heldoutTargetFamilies?: string[];
  explorationFraction?: number;
  signal?: AbortSignal;
  failFast?: boolean;
  execute(
    proposal: ResearchProposal,
    context: ProposalLearningContext,
  ): Promise<unknown>;
}

export interface ProposalLearningLoopResult {
  attempted: ProposalAttempt[];
  deferredProposalIds: string[];
  skippedTerminalProposalIds: string[];
  warnings: string[];
  modelBefore: ProposalRankerModel;
  modelAfter: ProposalRankerModel;
}

const TERMINAL_OUTCOMES = new Set<ProposalAttempt["outcome"]>([
  "confirmed",
  "refuted",
  "duplicate",
]);

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value as number;
}

/**
 * Bounded automatic proposal learning. The controller never invents labels:
 * `execute` must return a fully evidence-gated attempt, which is revalidated
 * and bound to the selected proposal before it enters the durable replay.
 */
export async function runProposalLearningLoop(
  options: RunProposalLearningLoopOptions,
): Promise<ProposalLearningLoopResult> {
  const maxAttempts = positiveInteger(options.maxAttempts, "maxAttempts");
  const proposals = options.proposals.map(validateResearchProposal);
  if (new Set(proposals.map((proposal) => proposal.id)).size !== proposals.length) {
    throw new Error("proposal learning input contains duplicate proposals");
  }

  let replay = readProposalReplay(options.replayPath);
  const terminalProposalIds = new Set(
    replay
      .filter((attempt) => TERMINAL_OUTCOMES.has(attempt.outcome))
      .map((attempt) => attempt.proposal.id),
  );
  const skippedTerminalProposalIds = proposals
    .filter((proposal) => terminalProposalIds.has(proposal.id))
    .map((proposal) => proposal.id);
  let remaining = proposals.filter((proposal) => !terminalProposalIds.has(proposal.id));
  const modelBefore = trainProposalRanker(replay, {
    heldoutTargetFamilies: options.heldoutTargetFamilies,
  });
  const attempted: ProposalAttempt[] = [];
  const unresolved: ResearchProposal[] = [];
  const warnings: string[] = [];
  let executionCount = 0;

  while (remaining.length > 0 && executionCount < maxAttempts) {
    if (options.signal?.aborted) {
      warnings.push("proposal learning stopped because the abort signal fired");
      break;
    }
    const model = trainProposalRanker(replay, {
      heldoutTargetFamilies: options.heldoutTargetFamilies,
    });
    const ranked = rankResearchProposals(model, remaining, {
      explorationFraction: options.explorationFraction,
    });
    const selected = ranked[0]!.proposal;
    remaining = remaining.filter((proposal) => proposal.id !== selected.id);
    executionCount += 1;

    try {
      const rawAttempt = await options.execute(selected, {
        model,
        attemptNumber: executionCount,
        ...(options.signal ? { signal: options.signal } : {}),
      });
      const attempt = validateProposalAttempt(rawAttempt);
      if (attempt.proposal.id !== selected.id) {
        throw new Error(
          `executor returned attempt for ${attempt.proposal.id}, expected ${selected.id}`,
        );
      }
      appendProposalAttempt(options.replayPath, attempt);
      replay = [...replay, attempt];
      attempted.push(attempt);
    } catch (error) {
      unresolved.push(selected);
      const warning = `proposal ${selected.id} produced no learnable attempt: ${
        error instanceof Error ? error.message : String(error)
      }`;
      warnings.push(warning);
      if (options.failFast) throw new Error(warning, { cause: error });
    }
  }

  return {
    attempted,
    deferredProposalIds: [...unresolved, ...remaining].map((proposal) => proposal.id),
    skippedTerminalProposalIds,
    warnings,
    modelBefore,
    modelAfter: trainProposalRanker(replay, {
      heldoutTargetFamilies: options.heldoutTargetFamilies,
    }),
  };
}
