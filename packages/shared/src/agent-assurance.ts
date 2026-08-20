import { z } from "zod";
import { EvidenceArtifactSchema } from "./verification.js";

/** Versioned, machine-readable evidence contract for a tool-using agent test. */
export const AGENT_ACTION_ASSURANCE_SCHEMA_VERSION = "0sec.agent-action-assurance/v1" as const;

/** Untrusted surface through which a test payload reaches the agent. */
export const AgentInjectionVectorSchema = z.enum([
  "readme",
  "code-comment",
  "issue-or-pr",
  "web-content",
  "tool-output",
  "support-doc",
  "email",
  "forum-post",
  "rules-file",
]);
export type AgentInjectionVector = z.infer<typeof AgentInjectionVectorSchema>;

/** Input case supplied by a customer-owned test harness. Payload bytes never enter the evidence manifest. */
export const AgentActionScenarioSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(1),
  injection_vector: AgentInjectionVectorSchema,
  benign_task: z.string().min(1),
  payload: z.string().min(1),
  prohibited_action: z.string().min(1),
}).strict();
export type AgentActionScenario = z.infer<typeof AgentActionScenarioSchema>;

const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/, "sha256 must be 64 lowercase hex characters");
const IsoTimestampSchema = z.string().datetime({ offset: true });

/** The action oracle is authoritative; an LLM response alone cannot mark a case safe or broken. */
export const AgentActionOutcomeSchema = z.enum([
  "observed",
  "not_observed",
  "inconclusive",
  "error",
]);
export type AgentActionOutcome = z.infer<typeof AgentActionOutcomeSchema>;

export const AgentActionTargetMetadataSchema = z.object({
  scope_sha256: Sha256Schema,
  environment: z.enum(["local", "test", "staging"]),
  agent_endpoint: z.string().url(),
  mcp_endpoint: z.string().url(),
  oracle_endpoint: z.string().url(),
  target_version: z.string().min(1),
  policy_version: z.string().min(1),
  model_version: z.string().min(1),
  tool_versions: z.record(z.string().min(1)),
  configuration_sha256: Sha256Schema,
}).strict();
export type AgentActionTargetMetadata = z.infer<typeof AgentActionTargetMetadataSchema>;

const AgentActionToolCallSchema = z.object({
  name: z.string().min(1),
  args_sha256: Sha256Schema,
}).strict();

const AgentActionRedactionSchema = z.object({
  strategy: z.literal("sensitive-text-v1"),
  redacted_fields: z.array(z.string().min(1)),
  /** Customer-facing bundles never include unredacted execution bytes. */
  raw_artifacts: z.literal(false),
}).strict();

const AgentActionRetestSchema = z.object({
  previous_run_id: z.string().uuid(),
  previous_manifest_sha256: Sha256Schema,
  configuration_changed: z.boolean(),
}).strict();

/**
 * Portable agent-action evidence. It records the tested configuration and hashes
 * every supplied artifact, while keeping unbounded request, response, and secret
 * bytes outside the manifest.
 */
export const AgentActionEvidenceManifestSchema = z.object({
  schema_version: z.literal(AGENT_ACTION_ASSURANCE_SCHEMA_VERSION),
  run_id: z.string().uuid(),
  created_at: IsoTimestampSchema,
  target: AgentActionTargetMetadataSchema,
  scenario: z.object({
    id: z.string().min(1),
    title: z.string().min(1),
    injection_vector: AgentInjectionVectorSchema,
    payload_sha256: Sha256Schema,
    prohibited_action: z.string().min(1),
  }).strict(),
  execution: z.object({
    request_sha256: Sha256Schema,
    response_sha256: Sha256Schema,
    transcript_sha256: Sha256Schema,
    mcp_tools_sha256: Sha256Schema,
    tool_calls: z.array(AgentActionToolCallSchema),
  }).strict(),
  oracle: z.object({
    name: z.string().min(1),
    outcome: AgentActionOutcomeSchema,
    complete: z.boolean(),
    observation_sha256: Sha256Schema,
    observed_at: IsoTimestampSchema.optional(),
    summary: z.string().optional(),
  }).strict(),
  redaction: AgentActionRedactionSchema,
  retest: AgentActionRetestSchema.optional(),
  artifacts: z.array(EvidenceArtifactSchema),
}).strict().superRefine((manifest, ctx) => {
  const requiresCompleteOracle = manifest.oracle.outcome === "observed"
    || manifest.oracle.outcome === "not_observed";
  if (requiresCompleteOracle && !manifest.oracle.complete) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["oracle", "complete"],
      message: "observed and not_observed outcomes require a complete action-oracle observation",
    });
  }

  if (manifest.oracle.outcome === "inconclusive" && manifest.oracle.complete) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["oracle", "complete"],
      message: "an inconclusive outcome cannot claim a complete action-oracle observation",
    });
  }

  for (const [field, endpoint] of Object.entries({
    agent_endpoint: manifest.target.agent_endpoint,
    mcp_endpoint: manifest.target.mcp_endpoint,
    oracle_endpoint: manifest.target.oracle_endpoint,
  })) {
    const parsed = new URL(endpoint);
    if (parsed.username || parsed.password) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["target", field],
        message: "endpoint URLs must not embed credentials",
      });
    }
  }

  for (const [index, artifact] of manifest.artifacts.entries()) {
    if (/^(?:\/|[A-Za-z]:[\\/])/.test(artifact.path) || /(?:^|[\\/])\.\.(?:[\\/]|$)/.test(artifact.path)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["artifacts", index, "path"],
        message: "artifact paths must be relative and must not escape the evidence bundle",
      });
    }
  }
});
export type AgentActionEvidenceManifest = z.infer<typeof AgentActionEvidenceManifestSchema>;

/** Fail closed at the wire boundary before a manifest reaches a report, archive, or retest. */
export function parseAgentActionEvidenceManifest(value: unknown): AgentActionEvidenceManifest {
  return AgentActionEvidenceManifestSchema.parse(value);
}
