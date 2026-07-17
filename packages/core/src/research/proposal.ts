import { createHash } from "node:crypto";

export const RESEARCH_PROPOSAL_SCHEMA_VERSION = 1 as const;
export const PROPOSAL_FEATURE_SCHEMA_VERSION = 1 as const;

export type ProposalOrigin =
  | "target_observation"
  | "spec_invariant"
  | "memory_prior";

export type ProposalKind =
  | "lifecycle"
  | "resource_balance"
  | "input_boundary"
  | "state_transition"
  | "spec_contradiction"
  | "behavior_differential";

/**
 * Pre-verification features only. A verifier outcome must never be folded back
 * into this vector: the immutable proposal digest binds these values before an
 * experiment starts.
 */
export interface ProposalFeatures {
  citedSpanCount: number;
  distinctFileCount: number;
  crossesTrustBoundary: 0 | 1;
  hasStateTransition: 0 | 1;
  hasBehavioralDifferential: 0 | 1;
  externallyReachable: 0 | 1;
}

export const PROPOSAL_FEATURE_NAMES = [
  "citedSpanCount",
  "distinctFileCount",
  "crossesTrustBoundary",
  "hasStateTransition",
  "hasBehavioralDifferential",
  "externallyReachable",
] as const satisfies readonly (keyof ProposalFeatures)[];

export interface TargetSourceFile {
  /** Safe, repository-relative POSIX path. */
  path: string;
  content: string;
}

export interface TargetSourceSnapshot {
  targetId: string;
  /** Leakage boundary used for target-disjoint train/eval splits. */
  targetFamily: string;
  files: TargetSourceFile[];
}

export interface ProposalCitationInput {
  path: string;
  startLine: number;
  endLine: number;
  symbol?: string;
}

export interface ProposalCitation extends ProposalCitationInput {
  excerptSha256: string;
}

export interface ResearchProposal {
  schemaVersion: typeof RESEARCH_PROPOSAL_SCHEMA_VERSION;
  id: string;
  target: {
    id: string;
    family: string;
    digest: string;
  };
  generator: {
    id: string;
    digest: string;
  };
  origin: ProposalOrigin;
  kind: ProposalKind;
  observedFact: string;
  falsifiableQuestion: string;
  citations: ProposalCitation[];
  parentProposalIds: string[];
  featureSchemaVersion: typeof PROPOSAL_FEATURE_SCHEMA_VERSION;
  features: ProposalFeatures;
}

export interface CreateResearchProposalInput {
  target: TargetSourceSnapshot;
  generator: { id: string; digest: string };
  origin: ProposalOrigin;
  kind: ProposalKind;
  observedFact: string;
  falsifiableQuestion: string;
  citations: ProposalCitationInput[];
  parentProposalIds?: string[];
  features: Omit<ProposalFeatures, "citedSpanCount" | "distinctFileCount">;
}

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const SAFE_ID = /^[a-z0-9][a-z0-9._:-]{0,159}$/;
const SAFE_PATH_SEGMENT = /^(?!\.\.?$)[^/\0]+$/;
const ORIGINS = new Set<ProposalOrigin>([
  "target_observation",
  "spec_invariant",
  "memory_prior",
]);
const KINDS = new Set<ProposalKind>([
  "lifecycle",
  "resource_balance",
  "input_boundary",
  "state_transition",
  "spec_contradiction",
  "behavior_differential",
]);

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, nested]) => [key, canonicalize(nested)]),
    );
  }
  return value;
}

export function canonicalProposalJson(value: unknown): string {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}

export function proposalDigest(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalProposalJson(value)).digest("hex")}`;
}

function text(value: unknown, label: string, max = 8_000): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${label} must be a non-empty string`);
  }
  if (value.length > max) throw new Error(`${label} exceeds ${max} characters`);
  return value.trim();
}

function safeId(value: unknown, label: string): string {
  const parsed = text(value, label, 160);
  if (!SAFE_ID.test(parsed)) throw new Error(`${label} must be a safe lowercase identifier`);
  return parsed;
}

export function normalizeProposalPath(value: unknown, label = "citation.path"): string {
  const parsed = text(value, label, 1_024).replaceAll("\\", "/");
  if (parsed.startsWith("/") || parsed.split("/").some((part) => !SAFE_PATH_SEGMENT.test(part))) {
    throw new Error(`${label} must be a safe repository-relative path`);
  }
  return parsed;
}

function digest(value: unknown, label: string): string {
  const parsed = text(value, label, 71);
  if (!SHA256.test(parsed)) throw new Error(`${label} must be a lowercase sha256 digest`);
  return parsed;
}

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value as number;
}

function binary(value: unknown, label: string): 0 | 1 {
  if (value !== 0 && value !== 1) throw new Error(`${label} must be 0 or 1`);
  return value;
}

function validateFeatures(value: unknown): ProposalFeatures {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("proposal.features must be an object");
  }
  const raw = value as Record<string, unknown>;
  const extra = Object.keys(raw).filter(
    (key) => !(PROPOSAL_FEATURE_NAMES as readonly string[]).includes(key),
  );
  if (extra.length > 0) throw new Error(`proposal.features contains unknown fields: ${extra.join(", ")}`);
  return {
    citedSpanCount: positiveInteger(raw.citedSpanCount, "proposal.features.citedSpanCount"),
    distinctFileCount: positiveInteger(raw.distinctFileCount, "proposal.features.distinctFileCount"),
    crossesTrustBoundary: binary(raw.crossesTrustBoundary, "proposal.features.crossesTrustBoundary"),
    hasStateTransition: binary(raw.hasStateTransition, "proposal.features.hasStateTransition"),
    hasBehavioralDifferential: binary(
      raw.hasBehavioralDifferential,
      "proposal.features.hasBehavioralDifferential",
    ),
    externallyReachable: binary(raw.externallyReachable, "proposal.features.externallyReachable"),
  };
}

function uniqueStrings(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  const parsed = value.map((item, index) => safeId(item, `${label}[${index}]`));
  if (new Set(parsed).size !== parsed.length) throw new Error(`${label} contains duplicates`);
  return parsed;
}

function fileMap(snapshot: TargetSourceSnapshot): Map<string, string> {
  safeId(snapshot.targetId, "target.targetId");
  safeId(snapshot.targetFamily, "target.targetFamily");
  if (!Array.isArray(snapshot.files) || snapshot.files.length === 0) {
    throw new Error("target.files must be a non-empty array");
  }
  const files = new Map<string, string>();
  for (let index = 0; index < snapshot.files.length; index += 1) {
    const file = snapshot.files[index];
    const path = normalizeProposalPath(file?.path, `target.files[${index}].path`);
    if (files.has(path)) throw new Error(`target.files contains duplicate path: ${path}`);
    if (!file || typeof file.content !== "string") {
      throw new Error(`target.files[${index}].content must be a string`);
    }
    files.set(path, file.content.replaceAll("\r\n", "\n"));
  }
  return files;
}

export function digestTargetSnapshot(snapshot: TargetSourceSnapshot): string {
  const files = fileMap(snapshot);
  return proposalDigest({
    targetId: snapshot.targetId,
    targetFamily: snapshot.targetFamily,
    files: [...files.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([path, content]) => ({ path, sha256: proposalDigest(content) })),
  });
}

function materializeCitation(
  input: ProposalCitationInput,
  files: Map<string, string>,
  index: number,
): ProposalCitation {
  const path = normalizeProposalPath(input.path, `citations[${index}].path`);
  const content = files.get(path);
  if (content === undefined) throw new Error(`citation path is not in the target snapshot: ${path}`);
  const startLine = positiveInteger(input.startLine, `citations[${index}].startLine`);
  const endLine = positiveInteger(input.endLine, `citations[${index}].endLine`);
  if (startLine > endLine) throw new Error(`citations[${index}] line range is reversed`);
  const lines = content.split("\n");
  if (endLine > lines.length) {
    throw new Error(`citations[${index}] line range exceeds ${path} (${lines.length} lines)`);
  }
  const excerpt = lines.slice(startLine - 1, endLine).join("\n");
  return {
    path,
    startLine,
    endLine,
    ...(input.symbol ? { symbol: text(input.symbol, `citations[${index}].symbol`, 256) } : {}),
    excerptSha256: proposalDigest(excerpt),
  };
}

export function createResearchProposal(input: CreateResearchProposalInput): ResearchProposal {
  const files = fileMap(input.target);
  if (!ORIGINS.has(input.origin)) throw new Error(`unsupported proposal origin: ${String(input.origin)}`);
  if (!KINDS.has(input.kind)) throw new Error(`unsupported proposal kind: ${String(input.kind)}`);
  if (!Array.isArray(input.citations) || input.citations.length === 0) {
    throw new Error("a target-derived proposal needs at least one citation");
  }
  const citations = input.citations.map((citation, index) =>
    materializeCitation(citation, files, index),
  );
  const parentProposalIds = uniqueStrings(input.parentProposalIds ?? [], "parentProposalIds");
  const body = {
    schemaVersion: RESEARCH_PROPOSAL_SCHEMA_VERSION,
    target: {
      id: safeId(input.target.targetId, "target.targetId"),
      family: safeId(input.target.targetFamily, "target.targetFamily"),
      digest: digestTargetSnapshot(input.target),
    },
    generator: {
      id: safeId(input.generator.id, "generator.id"),
      digest: digest(input.generator.digest, "generator.digest"),
    },
    origin: input.origin,
    kind: input.kind,
    observedFact: text(input.observedFact, "observedFact"),
    falsifiableQuestion: text(input.falsifiableQuestion, "falsifiableQuestion"),
    citations,
    parentProposalIds,
    featureSchemaVersion: PROPOSAL_FEATURE_SCHEMA_VERSION,
    features: {
      citedSpanCount: citations.length,
      distinctFileCount: new Set(citations.map((citation) => citation.path)).size,
      crossesTrustBoundary: binary(input.features.crossesTrustBoundary, "features.crossesTrustBoundary"),
      hasStateTransition: binary(input.features.hasStateTransition, "features.hasStateTransition"),
      hasBehavioralDifferential: binary(
        input.features.hasBehavioralDifferential,
        "features.hasBehavioralDifferential",
      ),
      externallyReachable: binary(input.features.externallyReachable, "features.externallyReachable"),
    },
  };
  return { ...body, id: `proposal:${proposalDigest(body).slice("sha256:".length)}` };
}

export function validateResearchProposal(value: unknown): ResearchProposal {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("proposal must be an object");
  }
  const raw = value as Record<string, unknown>;
  if (raw.schemaVersion !== RESEARCH_PROPOSAL_SCHEMA_VERSION) {
    throw new Error(`proposal.schemaVersion must be ${RESEARCH_PROPOSAL_SCHEMA_VERSION}`);
  }
  const target = raw.target as Record<string, unknown>;
  const generator = raw.generator as Record<string, unknown>;
  if (!target || typeof target !== "object") throw new Error("proposal.target must be an object");
  if (!generator || typeof generator !== "object") throw new Error("proposal.generator must be an object");
  if (!ORIGINS.has(raw.origin as ProposalOrigin)) throw new Error("proposal.origin is unsupported");
  if (!KINDS.has(raw.kind as ProposalKind)) throw new Error("proposal.kind is unsupported");
  if (!Array.isArray(raw.citations) || raw.citations.length === 0) {
    throw new Error("proposal.citations must be a non-empty array");
  }
  const citations: ProposalCitation[] = raw.citations.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error(`proposal.citations[${index}] must be an object`);
    }
    const citation = item as Record<string, unknown>;
    const startLine = positiveInteger(citation.startLine, `proposal.citations[${index}].startLine`);
    const endLine = positiveInteger(citation.endLine, `proposal.citations[${index}].endLine`);
    if (startLine > endLine) throw new Error(`proposal.citations[${index}] line range is reversed`);
    return {
      path: normalizeProposalPath(citation.path, `proposal.citations[${index}].path`),
      startLine,
      endLine,
      ...(citation.symbol !== undefined
        ? { symbol: text(citation.symbol, `proposal.citations[${index}].symbol`, 256) }
        : {}),
      excerptSha256: digest(
        citation.excerptSha256,
        `proposal.citations[${index}].excerptSha256`,
      ),
    };
  });
  const proposal: ResearchProposal = {
    schemaVersion: RESEARCH_PROPOSAL_SCHEMA_VERSION,
    id: safeId(raw.id, "proposal.id"),
    target: {
      id: safeId(target.id, "proposal.target.id"),
      family: safeId(target.family, "proposal.target.family"),
      digest: digest(target.digest, "proposal.target.digest"),
    },
    generator: {
      id: safeId(generator.id, "proposal.generator.id"),
      digest: digest(generator.digest, "proposal.generator.digest"),
    },
    origin: raw.origin as ProposalOrigin,
    kind: raw.kind as ProposalKind,
    observedFact: text(raw.observedFact, "proposal.observedFact"),
    falsifiableQuestion: text(raw.falsifiableQuestion, "proposal.falsifiableQuestion"),
    citations,
    parentProposalIds: uniqueStrings(raw.parentProposalIds ?? [], "proposal.parentProposalIds"),
    featureSchemaVersion: (() => {
      if (raw.featureSchemaVersion !== PROPOSAL_FEATURE_SCHEMA_VERSION) {
        throw new Error(`proposal.featureSchemaVersion must be ${PROPOSAL_FEATURE_SCHEMA_VERSION}`);
      }
      return PROPOSAL_FEATURE_SCHEMA_VERSION;
    })(),
    features: validateFeatures(raw.features),
  };
  const { id, ...body } = proposal;
  const expected = `proposal:${proposalDigest(body).slice("sha256:".length)}`;
  if (id !== expected) throw new Error("proposal.id does not match its canonical content digest");
  if (proposal.features.citedSpanCount !== proposal.citations.length) {
    throw new Error("proposal citedSpanCount does not match citations");
  }
  if (proposal.features.distinctFileCount !== new Set(proposal.citations.map((c) => c.path)).size) {
    throw new Error("proposal distinctFileCount does not match citations");
  }
  return proposal;
}
