/**
 * Cloud-surface tool definitions (pwnkit#925, part of #923 CodeWall parity).
 *
 * Live AWS cloud testing — the BCG-post angle pwnkit was blind to. Three tools,
 * all READ/VERIFY-ONLY:
 *   - cloud_s3_probe          — public-bucket / ACL testing + orphaned-bucket
 *                               takeover detection (NoSuchBucket → re-creatable).
 *   - cloud_validate_credentials — safe validation of a harvested AWS key via
 *                               sts:GetCallerIdentity + read-only over-privilege
 *                               probes (no mutation, ever).
 *
 * Pure `ToolDefinition` metadata; the runtime handlers live on the
 * `ToolExecutor` class in agent/tools.ts and are routed by `cloudDispatch`.
 * Feature-gated behind PWNKIT_FEATURE_CLOUD_SURFACE (default OFF) AND
 * engagement-scope gated, deny-by-default (#924 parity): cloud probing is recon
 * against the target org, so it only runs for an authorized engagement scope.
 *
 * AWS/S3 is the MVP. Azure (Blob SAS / orphaned CNAME) and GCP (GCS ACL) are
 * deferred follow-ups — see agent/cloud-surface.ts header.
 */
import type { ToolDefinition } from "../types.js";

export const cloudToolDefinitions: Record<string, ToolDefinition> = {
  cloud_s3_probe: {
    name: "cloud_s3_probe",
    description:
      "Test S3 buckets for PUBLIC access and ORPHANED-BUCKET TAKEOVER, anonymously and read-only. " +
      "For each bucket name (pass names you derived from the target/org, or that you harvested from app config, HTML, redirects, or integration manifests), sends an unauthenticated GET / and GET /?acl. " +
      "Reports per bucket: `public` (anonymous listing works — leak), `private` (exists but gated), or `not-found` (NoSuchBucket — re-creatable, the orphaned-integration TAKEOVER class the BCG report flagged: an attacker re-creates the dangling bucket and intercepts whatever the integration writes). " +
      "Strictly read-only: it NEVER writes objects, deletes, or creates the takeover-able bucket — it only flags it. SCOPE-GATED, deny-by-default: each bucket must be authorized by the engagement scope (its S3 endpoint in the scope's in_scope); buckets out of scope, or any bucket when no scope is configured, are skipped (no-op). Use when the target references S3 buckets or you can guess org bucket names. Returns per-bucket verdicts + pre-drafted findings for public buckets and takeover-able references.",
    parameters: {
      buckets: {
        type: "object",
        description:
          "Array of S3 bucket NAMES to probe (e.g. [\"acme-backups\", \"acme-exports\"]). Names only, not URLs.",
      },
      region: {
        type: "string",
        description:
          "Optional AWS region for the regional endpoint (e.g. eu-central-1). Defaults to the global us-east-1 endpoint.",
      },
      max_keys: {
        type: "number",
        description: "Max object keys to sample from a public listing as evidence (default 10, capped at 100).",
      },
    },
    required: ["buckets"],
  },
  cloud_validate_credentials: {
    name: "cloud_validate_credentials",
    description:
      "Validate a HARVESTED AWS credential safely and enumerate how over-privileged it is — READ-ONLY. " +
      "Calls sts:GetCallerIdentity (the zero-impact AWS whoami) to confirm the key is live and resolve its account/ARN, then probes a few read-only List* actions (s3:ListAllMyBuckets, iam:ListAttachedUserPolicies) to gauge effective permissions. " +
      "HIGH severity when a long-lived IAM-user key has broad read access (over-privileged). The action allowlist is enforced in code — it CANNOT call any mutating API, so there is no data exfiltration beyond the minimal identity proof. " +
      "SCOPE-GATED, deny-by-default: requires an authorized engagement scope (validating a target org's credential is recon against its cloud account); refuses when no scope is configured. Use after you harvest an AWS access key (e.g. an AKIA… id + secret from source, env, or a leaked config). Returns validity, the resolved identity, the read-only permissions that succeeded, and a pre-drafted finding when the key is live/over-privileged.",
    parameters: {
      access_key_id: { type: "string", description: "The AWS access key id (e.g. AKIA…)." },
      secret_access_key: { type: "string", description: "The AWS secret access key paired with the id." },
      session_token: {
        type: "string",
        description: "Optional session token for temporary (assumed-role) credentials.",
      },
      region: {
        type: "string",
        description: "Optional AWS region for SigV4 signing (default us-east-1).",
      },
    },
    required: ["access_key_id", "secret_access_key"],
  },
};

/** Tool-name → ToolExecutor handler-method name (pwnkit#614). */
export const cloudDispatch: Record<string, string> = {
  cloud_s3_probe: "cloudS3Probe",
  cloud_validate_credentials: "cloudValidateCredentials",
};

/**
 * Cloud-surface tool names — gated behind the cloud-surface feature flag, like
 * SCANNER_TOOL_NAMES. Both the role tool sets and the audit/review
 * "everything" set filter on this single source.
 */
export const CLOUD_TOOL_NAMES: ReadonlyArray<string> = ["cloud_s3_probe", "cloud_validate_credentials"];
