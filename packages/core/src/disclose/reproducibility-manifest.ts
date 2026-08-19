/**
 * #151 — Reproducibility manifest for verified findings.
 *
 * A deterministic, redacted, locally-assembled snapshot of the full
 * reproducibility context: scope, target, tool revision, model/provider
 * configuration, environment fingerprint, evidence hashes, verification
 * status, and generation time. Reuses `redactSensitiveHeaders` and
 * `redactPii` from the existing disclosure pipeline so the same secret
 * and PII sweep covers the manifest.
 *
 * Designed to be surfaced for HUMAN INSPECTION via `0sec disclose review`
 * BEFORE any disclosure artifact is drafted. The manifest itself never sends
 * or publishes anything.
 *
 * INVARIANTS:
 *   - Deterministic for a supplied timestamp + input.
 *   - Refuses incomplete or non-verified-PoV evidence.
 *   - Redacts credentials, cookies, auth headers, tokens, email/PII, and
 *     raw sensitive request/response content by default.
 *   - Evidence is hashed AFTER redaction so the hash is safe to publish.
 */

import { createHash } from "node:crypto";
import { redactSensitiveHeaders } from "./template.js";
import { redactPii } from "./writeup.js";
import type { Finding, VerificationResult } from "@0sec/shared";

// ── Types ──────────────────────────────────────────────────────────────────

/**
 * The deterministic, redacted reproducibility manifest for one verified
 * finding. Every string field is already redacted before it reaches this
 * type — the assembler guarantees that.
 */
export interface ReproducibilityManifest {
  /** Manifest schema version (bump on breaking shape changes). */
  manifestVersion: 1;

  /** ISO-8601 generation timestamp (deterministic via options). */
  generatedAt: string;

  /** The finding identifier this manifest was assembled from. */
  findingId: string;
  /** Finding title (redacted). */
  findingTitle: string;
  /** Finding severity. */
  findingSeverity: string;
  /** Finding category. */
  findingCategory: string;

  /** Status of the finding at manifest generation time. */
  findingStatus: string;

  /** Target identifier: URL, package, or repo (PII-redacted). */
  targetIdentifier: string;

  /**
   * Tool / 0sec version manifest was assembled under.
   * Falls back to `"unknown"` when the version is not embedded at build time.
   */
  toolVersion: string;

  /**
   * Deterministic hash of the finding's structured PoC step graph, if
   * present. SHA-256 of the JSON-stringified `pocSteps` array (after
   * redaction of each step's command/body content).
   */
  harnessRevision: string | null;

  /**
   * Provider and model name, if available at assembly time.
   * Redacted if it contains user-identifying information.
   */
  modelConfig: string | null;

  /**
   * Environment fingerprint: operating system, architecture, and
   * Node.js runtime version.
   */
  environmentFingerprint: {
    /** `process.platform` value, e.g. `"darwin"`, `"linux"`, `"win32"`. */
    platform: string;
    /** `process.arch` value, e.g. `"arm64"`, `"x64"`. */
    arch: string;
    /** Node.js version string, e.g. `"v22.0.0"`. */
    nodeVersion: string;
  };

  /**
   * SHA-256 hashes of the finding's evidence request and response
   * content, computed AFTER `redactSensitiveHeaders` has been applied.
   * This ensures the hashes are safe to include in any downstream
   * artifact without leaking secrets.
   */
  evidenceHashes: {
    requestHash: string | null;
    responseHash: string | null;
  };

  /**
   * Aggregate verification status drawn from the finding's PoC execution
   * report and layer verdicts.
   */
  verification: {
    /** The overall PoC verdict, if a behavioural re-verify ran. */
    pocVerdict: string | null;
    /** Number of triage layer verdicts present. */
    layerVerdictCount: number;
    /**
     * Number of passing layer verdicts. A verified finding should have
     * at least one pass to be considered complete.
     */
    passedLayerCount: number;
    /** The last deterministic-replay verification result, if any. */
    replayVerdict: string | null;
    /** ISO-8601 timestamp of the PoC execution, if available. */
    verifiedAt: string | null;
  };

  /** Which redaction sweeps were applied during assembly. */
  redactionsApplied: string[];
}

export interface ManifestOptions {
  /**
   * Override the generation timestamp (ISO-8601 string). Used by tests
   * to assert deterministic output. Defaults to `new Date().toISOString()`.
   */
  timestamp?: string;
  /**
   * Override the tool version string. Used by tests and build-embedded
   * version stamps. Defaults to trying `process.env["0SEC_VERSION"]` or
   * read from the package.json at build time, falling back to `"unknown"`.
   */
  toolVersion?: string;
  /**
   * Model/provider config string. e.g. `"anthropic/claude-sonnet-4"`,
   * `"openai/gpt-4o"`. Redacted if it contains PII.
   */
  modelConfig?: string;
  /**
   * Override the target identifier. When omitted, extracted from the
   * finding's evidence request URL if available.
   */
  targetIdentifier?: string;
}

// ── Errors ──────────────────────────────────────────────────────────────────

export class UnverifiedFindingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnverifiedFindingError";
  }
}

export class IncompleteEvidenceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IncompleteEvidenceError";
  }
}

// ── Constants ───────────────────────────────────────────────────────────────

/** The current manifest schema version. Bump on breaking shape changes. */
export const MANIFEST_VERSION = 1 as const;

/**
 * Hash algorithm used for evidence digests. Chosen for availability,
 * speed, and collision resistance adequate for reproducibility assertions.
 */
const HASH_ALGORITHM = "sha256";

/** Finding statuses that clear the verified gate. */
const VERIFIED_STATUSES: Record<string, true> = {
  verified: true,
  confirmed: true,
};


/**
 * Strip RFC 3986 userinfo (user:password@host) from URLs before the value
 * enters a manifest or digest. Replaces the entire userinfo with [REDACTED]
 * while preserving the scheme and host.
 */
const SENSITIVE_USERINFO = /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^@\n]+@/gi;

/**
 * Sensitive URL parameter values and credentials that header-only redaction
 * does not reach. Matches common OAuth, API, and authentication parameter
 * names.
 */
const SENSITIVE_QUERY_VALUE = /([?&](?:access_token|api[_-]?key|authorization|auth|cookie|session|token|bearer|jwt|refresh_token|client_secret|client_id|password|passwd|secret)=)[^&#\s]*/gi;

/**
 * Standalone credential key=value pattern for free-form text fields that
 * are not URL query strings (e.g. severity, category, generatedAt, tool
 * version). Catches cases where an externally controlled string contains
 * something like "critical-client_secret=sk-leaked" without a preceding
 * ? or &. Uses word-boundary lookahead to avoid false matches on
 * unrelated hyphenated words.
 */
const STANDALONE_CREDENTIAL = /(^|[\s,;:.-])((?:access_token|api[_-]?key|authorization|auth|cookie|session|token|bearer|jwt|refresh_token|client_secret|client_id|password|passwd|secret)=)[^\s,;:)\]"'`]*(?![\w-])/gi;


/** Apply every redaction needed before a value enters a manifest or digest. */
function redactManifestValue(value: string): string {
  return redactPii(
    redactSensitiveHeaders(value)
      .replace(SENSITIVE_USERINFO, "$1[REDACTED-USER]@")
      .replace(SENSITIVE_QUERY_VALUE, "$1[REDACTED]")
      .replace(STANDALONE_CREDENTIAL, "$1$2[REDACTED]"),
  );
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Safely redact and hash a string value. Returns null when the input is
 * null, undefined, or empty.
 */
function redactAndHash(value: string | null | undefined): string | null {
  if (!value) return null;
  return createHash(HASH_ALGORITHM)
    .update(redactManifestValue(value), "utf8")
    .digest("hex");
}

/**
 * Produce a stable recursive JSON representation. A top-level replacer array
 * would silently omit nested fields, which would make materially different PoC
 * graphs share a harness revision.
 */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .filter((key) => record[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}


/**
 * Collect the non-sensitive environment fingerprint that is safe to
 * include in a reproducibility manifest.
 */
function collectEnvironmentFingerprint(): ReproducibilityManifest["environmentFingerprint"] {
  return {
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.version,
  };
}

/**
 * Extract a target identifier from a finding, falling back to "unknown".
 * The result is PII-redacted.
 */
function extractTarget(finding: Finding): string {
  const url = finding.evidence?.request?.match(/^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/)?.[1]
    ?? finding.evidence?.request?.match(/^\S+/)?.[0];
  if (url) return redactManifestValue(url);
  if (finding.title) return redactManifestValue(finding.title);
  return "unknown";
}

/**
 * Compute the PoC step graph revision hash. Redacts each step's
 * command/body content before hashing so the harness fingerprint is
 * itself safe to share.
 */
function computeHarnessRevision(finding: Finding): string | null {
  if (!finding.pocSteps || finding.pocSteps.length === 0) return null;

  const redactedSteps = finding.pocSteps.map((step) => {
    const action = step.action ? { ...step.action } : step.action;
    if (action && "cmd" in action && typeof action.cmd === "string") {
      (action as Record<string, unknown>).cmd = redactManifestValue(action.cmd);
    }
    if (action && "body" in action && typeof action.body === "string") {
      (action as Record<string, unknown>).body = redactManifestValue(action.body);
    }
    return { ...step, action };
  });

  return createHash(HASH_ALGORITHM)
    .update(canonicalJson(redactedSteps), "utf8")
    .digest("hex");
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Assemble a deterministic, redacted reproducibility manifest from a
 * verified finding.
 *
 * Gates:
 *   - `UnverifiedFindingError` when the finding's status is not
 *     `verified` or `confirmed`.
 *   - `IncompleteEvidenceError` when the finding has no PoC execution
 *     report AND no layer verdicts — i.e. the evidence is incomplete.
 *
 * @param finding — The verified finding to manifest.
 * @param opts — Optional configuration overrides for deterministic output.
 * @returns A redacted ReproducibilityManifest.
 */
export function assembleReproducibilityManifest(
  finding: Finding,
  opts: ManifestOptions = {},
): ReproducibilityManifest {
  const redactionsApplied: string[] = [];

  // ── Gate: verified status ────────────────────────────────────────────
  if (!VERIFIED_STATUSES[finding.status]) {
    throw new UnverifiedFindingError(
      `Cannot assemble reproducibility manifest for finding ${finding.id}: status is "${finding.status}", expected "verified" or "confirmed".`,
    );
  }
  redactionsApplied.push("verified-status-gate");

  // ── Gate: successful verified PoV/impact ────────────────────────────
  // A layer verdict is triage evidence, not a successful PoV. This manifest
  // needs either behavioural proof or a canonical deterministic replay receipt.
  const pocExec = finding.pocExecution as
    | { overallVerdict?: string; startedAt?: string }
    | undefined;
  const layerVerdicts = finding.layerVerdicts ?? [];
  const replayResult = finding.verification_result as VerificationResult | undefined;
  const pocSuccessful = pocExec?.overallVerdict === "exploit_still_works";
  const replaySuccessful =
    replayResult?.status === "reproduced" || replayResult?.oast_confirmed === true;

  if (!pocSuccessful && !replaySuccessful) {
    throw new IncompleteEvidenceError(
      `Cannot assemble reproducibility manifest for finding ${finding.id}: no successful verified PoV. ` +
        `PoC verdict was ${pocExec?.overallVerdict ?? "absent"} and replay status was ` +
        `${replayResult?.status ?? "absent"}. A reproduced PoC or verified replay is required.`,
    );
  }

  const pocVerdict = pocExec?.overallVerdict ?? null;
  const passedLayerCount = layerVerdicts.filter(
    (verdict) => verdict.verdict === "pass",
  ).length;
  const verifiedAt = pocExec?.startedAt ?? replayResult?.completed_at ?? null;
  const replayVerdict = replayResult?.status ?? null;

  if (pocSuccessful) redactionsApplied.push("poc-verified-impact");
  if (replaySuccessful) redactionsApplied.push("replay-verified-impact");
  const target = opts.targetIdentifier
    ? redactManifestValue(opts.targetIdentifier)
    : extractTarget(finding);
  const modelConfig = opts.modelConfig
    ? redactManifestValue(opts.modelConfig)
    : null;
  const toolVersion = opts.toolVersion ?? process.env["0SEC_VERSION"] ?? "unknown";
  const timestamp = opts.timestamp ?? new Date().toISOString();

  // Redact the finding title through the full sanitization pipeline.
  const sanitizedTitle = redactManifestValue(finding.title);

  // Compute evidence hashes after redaction.
  const evidenceReq = finding.evidence?.request ?? null;
  const evidenceRes = finding.evidence?.response ?? null;
  const evidenceHashes = {
    requestHash: redactAndHash(evidenceReq),
    responseHash: redactAndHash(evidenceRes),
  };

  // Compute harness revision from redacted PoC steps.
  const harnessRevision = computeHarnessRevision(finding);


  // Redact EVERY externally-controlled string before it enters the manifest.
  // This covers finding metadata, option-derived values, verification
  // timestamps and verdicts — not just the target identifier and title.
  const sanitizedGeneratedAt = redactManifestValue(timestamp);
  const sanitizedFindingId = redactManifestValue(finding.id);
  const sanitizedSeverity = redactManifestValue(finding.severity);
  const sanitizedCategory = redactManifestValue(finding.category);
  const sanitizedStatus = redactManifestValue(finding.status);
  const sanitizedToolVersion = redactManifestValue(toolVersion);
  const sanitizedPocVerdict = pocVerdict ? redactManifestValue(pocVerdict) : null;
  const sanitizedReplayVerdict = replayVerdict ? redactManifestValue(replayVerdict) : null;
  const sanitizedVerifiedAt = verifiedAt ? redactManifestValue(verifiedAt) : null;

  // Collect which sweeps ran.
  redactionsApplied.push("redact-sensitive-headers");
  redactionsApplied.push("redact-pii");
  redactionsApplied.push("redact-all-text-fields");
  redactionsApplied.push("strip-url-userinfo");

  return {
    manifestVersion: MANIFEST_VERSION,
    generatedAt: sanitizedGeneratedAt,
    findingId: sanitizedFindingId,
    findingTitle: sanitizedTitle,
    findingSeverity: sanitizedSeverity,
    findingCategory: sanitizedCategory,
    findingStatus: sanitizedStatus,
    targetIdentifier: target,
    toolVersion: sanitizedToolVersion,
    harnessRevision,
    modelConfig,
    environmentFingerprint: collectEnvironmentFingerprint(),
    evidenceHashes,
    verification: {
      pocVerdict: sanitizedPocVerdict,
      layerVerdictCount: layerVerdicts.length,
      passedLayerCount,
      replayVerdict: sanitizedReplayVerdict,
      verifiedAt: sanitizedVerifiedAt,
    },
    redactionsApplied,
  };
}

/**
 * Render a ReproducibilityManifest as a human-readable text block for
 * CLI display or local review. Returns a string — writes nothing.
 *
 * The output is already redacted by the assembler; this function only
 * formats it for terminal consumption.
 */
export function renderReproducibilityManifest(manifest: ReproducibilityManifest): string {
  const lines: string[] = [];
  const add = (key: string, val: unknown) => {
    lines.push(`  ${key.padEnd(28)} ${val ?? "—"}`);
  };

  lines.push("─".repeat(72));
  lines.push("  REPRODUCIBILITY MANIFEST  (v" + manifest.manifestVersion + ")");
  lines.push("─".repeat(72));
  lines.push("");
  add("Generated", manifest.generatedAt);
  add("Finding ID", manifest.findingId);
  add("Title", manifest.findingTitle);
  add("Severity", manifest.findingSeverity);
  add("Category", manifest.findingCategory);
  add("Status", manifest.findingStatus);
  lines.push("");

  lines.push("  Target");
  lines.push("  " + "─".repeat(66));
  add("Identifier", manifest.targetIdentifier);
  lines.push("");

  lines.push("  Environment");
  lines.push("  " + "─".repeat(66));
  add("Tool version", manifest.toolVersion);
  add("Platform", manifest.environmentFingerprint.platform);
  add("Architecture", manifest.environmentFingerprint.arch);
  add("Node.js", manifest.environmentFingerprint.nodeVersion);
  add("Model config", manifest.modelConfig ?? "—");
  lines.push("");

  lines.push("  Evidence");
  lines.push("  " + "─".repeat(66));
  add("Request (SHA-256)", manifest.evidenceHashes.requestHash ?? "—");
  add("Response (SHA-256)", manifest.evidenceHashes.responseHash ?? "—");
  add("Harness revision", manifest.harnessRevision ?? "—");
  lines.push("");

  lines.push("  Verification");
  lines.push("  " + "─".repeat(66));
  add("PoC verdict", manifest.verification.pocVerdict ?? "—");
  add("Layer verdicts", `${manifest.verification.passedLayerCount}/${manifest.verification.layerVerdictCount} pass`);
  add("Replay verdict", manifest.verification.replayVerdict ?? "—");
  add("Verified at", manifest.verification.verifiedAt ?? "—");
  lines.push("");

  lines.push("  Redactions applied");
  lines.push("  " + "─".repeat(66));
  for (const r of manifest.redactionsApplied) {
    lines.push(`    • ${r}`);
  }
  lines.push("");
  lines.push("─".repeat(72));
  lines.push("  MANIFEST — FOR HUMAN REVIEW ONLY. NOT A DISCLOSURE ARTIFACT.");
  lines.push("─".repeat(72));

  return lines.join("\n");
}