import {
  PROPOSAL_FEATURE_NAMES,
  PROPOSAL_FEATURE_SCHEMA_VERSION,
  proposalDigest,
  validateResearchProposal,
  type ProposalFeatures,
  type ResearchProposal,
} from "./proposal.js";
import {
  proposalReplayDigest,
  proposalTrainingExamples,
  validateProposalReplay,
} from "./proposal-replay.js";

export const PROPOSAL_RANKER_SCHEMA_VERSION = 1 as const;

export interface ProposalRankerModel {
  schemaVersion: typeof PROPOSAL_RANKER_SCHEMA_VERSION;
  id: string;
  status: "untrained" | "trained";
  featureSchemaVersion: typeof PROPOSAL_FEATURE_SCHEMA_VERSION;
  replayDigest: string;
  trainingSetDigest: string;
  positiveCount: number;
  negativeCount: number;
  heldoutCount: number;
  heldoutTargetFamilies: string[];
  seenKinds: ResearchProposal["kind"][];
  seenOrigins: ResearchProposal["origin"][];
  seenCitationPaths: string[];
  weights: Record<keyof ProposalFeatures, number>;
}

export interface TrainProposalRankerOptions {
  /** Entire families are excluded to prevent sibling-target leakage. */
  heldoutTargetFamilies?: string[];
}

export interface RankedProposal {
  proposal: ResearchProposal;
  score: number;
  selection: "exploit" | "explore";
}

export interface RankProposalOptions {
  /** Fraction of output positions reserved for coverage/diversity. */
  explorationFraction?: number;
}

function featureValue(features: ProposalFeatures, name: keyof ProposalFeatures): number {
  const value = features[name];
  return name === "citedSpanCount" || name === "distinctFileCount" ? Math.log1p(value) : value;
}

function zeroWeights(): ProposalRankerModel["weights"] {
  return Object.fromEntries(PROPOSAL_FEATURE_NAMES.map((name) => [name, 0])) as ProposalRankerModel["weights"];
}

function uniqueSorted<T extends string>(values: readonly T[]): T[] {
  return [...new Set(values)].sort() as T[];
}

export function trainProposalRanker(
  replay: readonly unknown[],
  options: TrainProposalRankerOptions = {},
): ProposalRankerModel {
  const attempts = validateProposalReplay(replay);
  const heldoutTargetFamilies = uniqueSorted(options.heldoutTargetFamilies ?? []);
  const heldout = new Set(heldoutTargetFamilies);
  const allExamples = proposalTrainingExamples(attempts);
  const examples = allExamples.filter((example) => !heldout.has(example.targetFamily));
  const positives = examples.filter((example) => example.label === 1);
  const negatives = examples.filter((example) => example.label === 0);
  const status: ProposalRankerModel["status"] =
    positives.length > 0 && negatives.length > 0 ? "trained" : "untrained";
  const weights = zeroWeights();
  if (status === "trained") {
    for (const name of PROPOSAL_FEATURE_NAMES) {
      const positiveMean = positives.reduce((sum, item) => sum + featureValue(item.features, name), 0) / positives.length;
      const negativeMean = negatives.reduce((sum, item) => sum + featureValue(item.features, name), 0) / negatives.length;
      weights[name] = positiveMean - negativeMean;
    }
  }
  const body = {
    schemaVersion: PROPOSAL_RANKER_SCHEMA_VERSION,
    status,
    featureSchemaVersion: PROPOSAL_FEATURE_SCHEMA_VERSION,
    replayDigest: proposalReplayDigest(attempts),
    trainingSetDigest: proposalDigest(examples.map((example) => example.attemptId)),
    positiveCount: positives.length,
    negativeCount: negatives.length,
    heldoutCount: allExamples.length - examples.length,
    heldoutTargetFamilies,
    seenKinds: uniqueSorted(examples.map((example) => example.kind)),
    seenOrigins: uniqueSorted(examples.map((example) => example.origin)),
    seenCitationPaths: uniqueSorted(examples.flatMap((example) => example.citationPaths)),
    weights,
  };
  return { ...body, id: `ranker:${proposalDigest(body).slice("sha256:".length)}` };
}

export function scoreResearchProposal(model: ProposalRankerModel, value: unknown): number {
  const proposal = validateResearchProposal(value);
  if (model.status !== "trained") return 0;
  return PROPOSAL_FEATURE_NAMES.reduce(
    (sum, name) => sum + model.weights[name] * featureValue(proposal.features, name),
    0,
  );
}

function noveltyScore(
  proposal: ResearchProposal,
  model: ProposalRankerModel,
  chosen: readonly ResearchProposal[],
): number {
  const chosenKinds = new Set(chosen.map((item) => item.kind));
  const chosenOrigins = new Set(chosen.map((item) => item.origin));
  const chosenPaths = new Set(chosen.flatMap((item) => item.citations.map((citation) => citation.path)));
  const paths = [...new Set(proposal.citations.map((citation) => citation.path))];
  return (
    (model.seenKinds.includes(proposal.kind) ? 0 : 8) +
    (chosenKinds.has(proposal.kind) ? 0 : 4) +
    (model.seenOrigins.includes(proposal.origin) ? 0 : 2) +
    (chosenOrigins.has(proposal.origin) ? 0 : 1) +
    paths.filter((path) => !model.seenCitationPaths.includes(path)).length * 2 +
    paths.filter((path) => !chosenPaths.has(path)).length
  );
}

function diversityOrder(
  proposals: readonly ResearchProposal[],
  model: ProposalRankerModel,
): ResearchProposal[] {
  const remaining = [...proposals];
  const result: ResearchProposal[] = [];
  while (remaining.length > 0) {
    remaining.sort((a, b) => {
      const difference = noveltyScore(b, model, result) - noveltyScore(a, model, result);
      return difference || a.id.localeCompare(b.id);
    });
    result.push(remaining.shift()!);
  }
  return result;
}

/**
 * Ranking is ordering-only: every input proposal appears exactly once. Even a
 * trained model reserves explicit exploration positions for unseen structure.
 */
export function rankResearchProposals(
  model: ProposalRankerModel,
  values: readonly unknown[],
  options: RankProposalOptions = {},
): RankedProposal[] {
  const proposals = values.map(validateResearchProposal);
  if (new Set(proposals.map((proposal) => proposal.id)).size !== proposals.length) {
    throw new Error("proposal ranking input contains duplicate proposals");
  }
  if (proposals.length === 0) return [];
  if (model.status === "untrained") {
    return diversityOrder(proposals, model).map((proposal) => ({ proposal, score: 0, selection: "explore" }));
  }
  const fraction = options.explorationFraction ?? 0.2;
  if (!Number.isFinite(fraction) || fraction < 0 || fraction > 1) {
    throw new Error("explorationFraction must be between 0 and 1");
  }
  const explorationCount = Math.min(proposals.length, Math.ceil(proposals.length * fraction));
  const explorers = diversityOrder(proposals, model).slice(0, explorationCount);
  const explorerIds = new Set(explorers.map((proposal) => proposal.id));
  const exploiters = proposals
    .filter((proposal) => !explorerIds.has(proposal.id))
    .sort((a, b) => scoreResearchProposal(model, b) - scoreResearchProposal(model, a) || a.id.localeCompare(b.id));
  const ranked: RankedProposal[] = exploiters.map((proposal) => ({
    proposal,
    score: scoreResearchProposal(model, proposal),
    selection: "exploit",
  }));
  for (let index = 0; index < explorers.length; index += 1) {
    const proposal = explorers[index]!;
    const position = Math.min(ranked.length, Math.floor(((index + 1) * (ranked.length + 1)) / (explorers.length + 1)));
    ranked.splice(position, 0, {
      proposal,
      score: scoreResearchProposal(model, proposal),
      selection: "explore",
    });
  }
  return ranked;
}
