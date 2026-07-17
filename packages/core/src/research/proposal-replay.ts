import {
  closeSync,
  constants,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

import {
  canonicalProposalJson,
  proposalDigest,
  validateResearchProposal,
  type ResearchProposal,
} from "./proposal.js";

export const PROPOSAL_ATTEMPT_SCHEMA_VERSION = 1 as const;

export type ProposalOutcome =
  | "untried"
  | "inconclusive"
  | "refuted"
  | "confirmed"
  | "duplicate";

export type EvidenceKind =
  | "deterministic_oracle"
  | "sanitizer"
  | "reproducer"
  | "coverage"
  | "journal"
  | "model_report";

export interface ProposalEvidenceReceipt {
  kind: EvidenceKind;
  digest: string;
  producer: { id: string; digest: string };
}

export interface ProposalAttempt {
  schemaVersion: typeof PROPOSAL_ATTEMPT_SCHEMA_VERSION;
  id: string;
  proposal: ResearchProposal;
  experiment: { id: string; digest: string };
  outcome: ProposalOutcome;
  evidence: ProposalEvidenceReceipt[];
  coverage?: { adequate: boolean; digest: string };
  duplicateOfProposalId?: string;
}

export interface CreateProposalAttemptInput {
  proposal: ResearchProposal;
  experiment: { id: string; digest: string };
  outcome: ProposalOutcome;
  evidence?: ProposalEvidenceReceipt[];
  coverage?: { adequate: boolean; digest: string };
  duplicateOfProposalId?: string;
}

export interface ProposalTrainingExample {
  attemptId: string;
  proposalId: string;
  targetFamily: string;
  kind: ResearchProposal["kind"];
  origin: ResearchProposal["origin"];
  citationPaths: string[];
  label: 0 | 1;
  features: ResearchProposal["features"];
}

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const SAFE_ID = /^[a-z0-9][a-z0-9._:-]{0,159}$/;
const OUTCOMES = new Set<ProposalOutcome>([
  "untried",
  "inconclusive",
  "refuted",
  "confirmed",
  "duplicate",
]);
const EVIDENCE_KINDS = new Set<EvidenceKind>([
  "deterministic_oracle",
  "sanitizer",
  "reproducer",
  "coverage",
  "journal",
  "model_report",
]);
const TRUTH_EVIDENCE = new Set<EvidenceKind>([
  "deterministic_oracle",
  "sanitizer",
  "reproducer",
]);

function safeId(value: unknown, label: string): string {
  if (typeof value !== "string" || !SAFE_ID.test(value)) {
    throw new Error(`${label} must be a safe lowercase identifier`);
  }
  return value;
}

function digest(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a lowercase sha256 digest`);
  }
  return value;
}

function validateEvidence(value: unknown): ProposalEvidenceReceipt[] {
  if (!Array.isArray(value)) throw new Error("attempt.evidence must be an array");
  const receipts = value.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error(`attempt.evidence[${index}] must be an object`);
    }
    const raw = item as Record<string, unknown>;
    if (!EVIDENCE_KINDS.has(raw.kind as EvidenceKind)) {
      throw new Error(`attempt.evidence[${index}].kind is unsupported`);
    }
    return {
      kind: raw.kind as EvidenceKind,
      digest: digest(raw.digest, `attempt.evidence[${index}].digest`),
      producer: (() => {
        if (!raw.producer || typeof raw.producer !== "object" || Array.isArray(raw.producer)) {
          throw new Error(`attempt.evidence[${index}].producer must be an object`);
        }
        const producer = raw.producer as Record<string, unknown>;
        return {
          id: safeId(producer.id, `attempt.evidence[${index}].producer.id`),
          digest: digest(producer.digest, `attempt.evidence[${index}].producer.digest`),
        };
      })(),
    };
  });
  const identities = receipts.map((receipt) => `${receipt.kind}:${receipt.digest}`);
  if (new Set(identities).size !== identities.length) {
    throw new Error("attempt.evidence contains duplicate receipts");
  }
  return receipts;
}

function validateOutcomeRules(attempt: Omit<ProposalAttempt, "id">): void {
  const hasTruthEvidence = attempt.evidence.some((receipt) => TRUTH_EVIDENCE.has(receipt.kind));
  const independentTruthEvidence = attempt.evidence.some(
    (receipt) =>
      TRUTH_EVIDENCE.has(receipt.kind) &&
      receipt.producer.id !== attempt.proposal.generator.id &&
      receipt.producer.digest !== attempt.proposal.generator.digest,
  );
  if ((attempt.outcome === "confirmed" || attempt.outcome === "duplicate") && !hasTruthEvidence) {
    throw new Error(`${attempt.outcome} requires deterministic truth evidence`);
  }
  if ((attempt.outcome === "confirmed" || attempt.outcome === "duplicate") && !independentTruthEvidence) {
    throw new Error(`${attempt.outcome} requires truth evidence from an independent producer`);
  }
  if (attempt.outcome === "refuted") {
    if (!hasTruthEvidence) throw new Error("refuted requires deterministic truth evidence");
    if (!independentTruthEvidence) {
      throw new Error("refuted requires truth evidence from an independent producer");
    }
    if (!attempt.coverage?.adequate) {
      throw new Error("refuted requires an explicit adequate coverage receipt");
    }
  }
  if (attempt.outcome === "duplicate" && !attempt.duplicateOfProposalId) {
    throw new Error("duplicate requires duplicateOfProposalId");
  }
  if (attempt.outcome !== "duplicate" && attempt.duplicateOfProposalId) {
    throw new Error("duplicateOfProposalId is only valid for duplicate outcomes");
  }
  if (attempt.outcome !== "refuted" && attempt.coverage?.adequate) {
    throw new Error("adequate negative coverage is only valid for refuted outcomes");
  }
}

export function createProposalAttempt(input: CreateProposalAttemptInput): ProposalAttempt {
  const proposal = validateResearchProposal(input.proposal);
  if (!OUTCOMES.has(input.outcome)) throw new Error("attempt.outcome is unsupported");
  const body: Omit<ProposalAttempt, "id"> = {
    schemaVersion: PROPOSAL_ATTEMPT_SCHEMA_VERSION,
    proposal,
    experiment: {
      id: safeId(input.experiment.id, "attempt.experiment.id"),
      digest: digest(input.experiment.digest, "attempt.experiment.digest"),
    },
    outcome: input.outcome,
    evidence: validateEvidence(input.evidence ?? []),
    ...(input.coverage
      ? {
          coverage: {
            adequate: input.coverage.adequate === true,
            digest: digest(input.coverage.digest, "attempt.coverage.digest"),
          },
        }
      : {}),
    ...(input.duplicateOfProposalId
      ? { duplicateOfProposalId: safeId(input.duplicateOfProposalId, "attempt.duplicateOfProposalId") }
      : {}),
  };
  validateOutcomeRules(body);
  return { ...body, id: `attempt:${proposalDigest(body).slice("sha256:".length)}` };
}

export function validateProposalAttempt(value: unknown): ProposalAttempt {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("attempt must be an object");
  }
  const raw = value as Record<string, unknown>;
  if (raw.schemaVersion !== PROPOSAL_ATTEMPT_SCHEMA_VERSION) {
    throw new Error(`attempt.schemaVersion must be ${PROPOSAL_ATTEMPT_SCHEMA_VERSION}`);
  }
  if (!raw.experiment || typeof raw.experiment !== "object" || Array.isArray(raw.experiment)) {
    throw new Error("attempt.experiment must be an object");
  }
  if (!OUTCOMES.has(raw.outcome as ProposalOutcome)) throw new Error("attempt.outcome is unsupported");
  const experiment = raw.experiment as Record<string, unknown>;
  const attempt = createProposalAttempt({
    proposal: validateResearchProposal(raw.proposal),
    experiment: {
      id: safeId(experiment.id, "attempt.experiment.id"),
      digest: digest(experiment.digest, "attempt.experiment.digest"),
    },
    outcome: raw.outcome as ProposalOutcome,
    evidence: validateEvidence(raw.evidence),
    ...(raw.coverage && typeof raw.coverage === "object" && !Array.isArray(raw.coverage)
      ? {
          coverage: {
            adequate: (raw.coverage as Record<string, unknown>).adequate === true,
            digest: digest(
              (raw.coverage as Record<string, unknown>).digest,
              "attempt.coverage.digest",
            ),
          },
        }
      : {}),
    ...(raw.duplicateOfProposalId !== undefined
      ? {
          duplicateOfProposalId: safeId(
            raw.duplicateOfProposalId,
            "attempt.duplicateOfProposalId",
          ),
        }
      : {}),
  });
  if (safeId(raw.id, "attempt.id") !== attempt.id) {
    throw new Error("attempt.id does not match its canonical content digest");
  }
  return attempt;
}

/**
 * Validates an append-only replay and rejects contradictory terminal truth
 * labels for the same immutable proposal.
 */
export function validateProposalReplay(values: readonly unknown[]): ProposalAttempt[] {
  const attempts = values.map(validateProposalAttempt);
  const ids = new Set<string>();
  const labels = new Map<string, 0 | 1>();
  for (const attempt of attempts) {
    if (ids.has(attempt.id)) throw new Error(`proposal replay contains duplicate attempt: ${attempt.id}`);
    ids.add(attempt.id);
    const label = attempt.outcome === "confirmed" ? 1 : attempt.outcome === "refuted" ? 0 : undefined;
    if (label === undefined) continue;
    const previous = labels.get(attempt.proposal.id);
    if (previous !== undefined && previous !== label) {
      throw new Error(`proposal replay has conflicting truth labels for ${attempt.proposal.id}`);
    }
    labels.set(attempt.proposal.id, label);
  }
  return attempts;
}

export function proposalReplayDigest(values: readonly unknown[]): string {
  const attempts = validateProposalReplay(values);
  return proposalDigest(attempts.map((attempt) => attempt.id));
}

/** Censored, inconclusive, and duplicate outcomes are deliberately excluded. */
export function proposalTrainingExamples(values: readonly unknown[]): ProposalTrainingExample[] {
  return validateProposalReplay(values).flatMap((attempt) => {
    const label = attempt.outcome === "confirmed" ? 1 : attempt.outcome === "refuted" ? 0 : undefined;
    return label === undefined
      ? []
      : [{
          attemptId: attempt.id,
          proposalId: attempt.proposal.id,
          targetFamily: attempt.proposal.target.family,
          kind: attempt.proposal.kind,
          origin: attempt.proposal.origin,
          citationPaths: [...new Set(attempt.proposal.citations.map((citation) => citation.path))].sort(),
          label,
          features: attempt.proposal.features,
        }];
  });
}

export function serializeProposalReplay(values: readonly unknown[]): string {
  return canonicalProposalJson(validateProposalReplay(values));
}

/** Reads and validates the append-only JSONL replay artifact. */
export function readProposalReplay(path: string): ProposalAttempt[] {
  try {
    if (lstatSync(path).isSymbolicLink()) {
      throw new Error("proposal replay path must not be a symbolic link");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  const lines = readFileSync(path, "utf8").split("\n").filter((line) => line.trim() !== "");
  return validateProposalReplay(
    lines.map((line, index) => {
      try {
        return JSON.parse(line) as unknown;
      } catch {
        throw new Error(`proposal replay line ${index + 1} is not valid JSON`);
      }
    }),
  );
}

/**
 * Appends one validated attempt with O_APPEND/O_NOFOLLOW and re-validates the
 * existing replay first. Each attempt is written in one syscall as one JSONL
 * record so concurrent writers cannot byte-interleave records.
 */
export function appendProposalAttempt(path: string, value: unknown): ProposalAttempt {
  const attempt = validateProposalAttempt(value);
  const existing = readProposalReplay(path);
  validateProposalReplay([...existing, attempt]);
  mkdirSync(dirname(path), { recursive: true });
  const line = `${JSON.stringify(JSON.parse(canonicalProposalJson(attempt)))}\n`;
  const fd = openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    writeFileSync(fd, line, "utf8");
  } finally {
    closeSync(fd);
  }
  return attempt;
}
