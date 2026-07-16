/**
 * Shared wire contracts between the pwnkit `cloud-sink` and the
 * pwnkit-cloud orchestrator.
 *
 * These types MUST stay in sync with the zod schema in
 * `pwnkit-cloud/services/orchestrator/src/routes/scans.ts`. The orchestrator
 * validates every `/scans/:id/findings` POST with strict zod, so any drift
 * silently 400s the whole scan. Keep both sides of the contract aligned.
 *
 * Field reference (as of 2026-04 handshake):
 *
 *   findingSchema = z.object({
 *     id: z.string(),
 *     templateId: z.string(),
 *     title: z.string(),
 *     description: z.string(),
 *     severity: z.enum(["critical","high","medium","low","info"]),
 *     category: z.string(),
 *     status: z.string(),
 *     evidence: z.object({
 *       request: z.string(),
 *       response: z.string(),
 *       analysis: z.string().optional(),
 *     }),
 *     confidence: z.number().min(0).max(1).optional(),
 *     timestamp: z.number(),
 *   });
 *
 *   ingestSchema = z.object({
 *     finding: findingSchema,
 *     feature_vector: z.array(z.number()).length(45).nullable().optional(),
 *   });
 */

/** Severity levels accepted by the orchestrator (strict enum). */
export type CloudSinkSeverity = "critical" | "high" | "medium" | "low" | "info";

/** Evidence payload. request/response are always strings on the wire. */
export interface CloudSinkEvidence {
  request: string;
  response: string;
  analysis?: string;
}

/**
 * Optional structured proof-of-concept step graph (pwnkit#170). Emitted only
 * when the OSS agent has structured execution data; otherwise undefined and
 * the cloud falls back to the prose `evidence.*` strings as before.
 *
 * The cloud orchestrator currently does NOT yet validate this field — by
 * default zod strips unknown keys, so sending it is safe even before cloud
 * adds its own schema. When cloud lands the matching zod entry, it should
 * mirror the `PocStep` shape in `@pwnkit/shared/types.ts` (kept loose here
 * as `unknown[]` so OSS additions can roll out before cloud's schema does).
 */
export type CloudSinkPocSteps = unknown[];

/**
 * Optional machine-executable verification contract (pwnkit#193 /
 * pwnkit-cloud#111). Pass-through field; the OSS sink does not enrich or
 * validate beyond a shape check. Cloud's canary watcher imports
 * `evaluateVerificationSpec` from `@pwnkit/core` to evaluate it; the
 * orchestrator schema strips unknown keys today and will land its own zod
 * entry mirroring `VerificationSpec` in `@pwnkit/shared/types.ts`.
 */
export type CloudSinkVerificationSpec = Record<string, unknown>;

/**
 * Strict finding shape the pwnkit-cloud orchestrator accepts at
 * POST /scans/:id/findings.
 */
export interface CloudSinkFinding {
  id: string;
  templateId: string;
  title: string;
  description: string;
  severity: CloudSinkSeverity;
  category: string;
  /**
   * Free-form workflow status. The OSS emits values like "discovered",
   * "confirmed", "false-positive". The orchestrator accepts any string but
   * downstream dashboards prefer the vetted set; callers should keep to the
   * OSS `FindingStatus` vocabulary.
   */
  status: string;
  evidence: CloudSinkEvidence;
  /** 0..1 agent-assessed confidence, if available. */
  confidence?: number;
  reviewAnnotation?: {
    path: string;
    startLine: number;
    endLine?: number;
    suggestion?: string;
  };
  /** Unix epoch milliseconds. */
  timestamp: number;
  /**
   * Optional ordered PoC step graph (pwnkit#170). Pass-through field — the
   * OSS sink does not enrich or validate it beyond a shape check, and the
   * cloud orchestrator will silently strip it until its schema is updated.
   */
  pocSteps?: CloudSinkPocSteps;
  /**
   * Optional machine-executable verification spec (pwnkit#193). Pass-through;
   * the cloud orchestrator strips it today and will accept it once its
   * schema mirrors `VerificationSpec` in `@pwnkit/shared/types.ts`.
   */
  verificationSpec?: CloudSinkVerificationSpec;
  /** Optional target-neutral research evidence envelopes. */
  researchEvidence?: unknown[];
}

/**
 * Envelope posted to POST /scans/:id/findings for a single finding.
 * Matches `ingestSchema` in the orchestrator.
 */
export interface CloudSinkFindingEnvelope {
  finding: CloudSinkFinding;
  /** Optional 45-dim feature vector for the triage model. */
  feature_vector?: number[] | null;
}

/**
 * Final scan report envelope. The orchestrator does not (yet) strict-validate
 * this shape; it is posted to the same /findings endpoint with `final: true`
 * as a scan-completion marker. Keep the surface small and stringly-typed so a
 * future zod schema can layer on without breaking existing writers.
 */
export interface CloudSinkFinalReport {
  report: unknown;
  final: true;
}
