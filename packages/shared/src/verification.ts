/**
 * 0sec#193 — VerificationResult schema (zod).
 *
 * Canonical, machine-checkable shape of the JSON payload the deterministic
 * replay verifier emits after running a finding's PoC. Cloud, the CLI, the
 * journal, and any third-party consumer parse this through `VerificationResultSchema`
 * so a drifting field surfaces as a Zod error rather than a silent miss.
 *
 * The shape is intentionally richer than the in-issue example: it carries
 * per-command argv/stdout/stderr excerpts (capped so JSON stays log-sized),
 * a typed list of assertions, hashed evidence-artifact descriptors so big
 * payloads (screenshots, full captures, dmesg dumps) can be stored as
 * sidecar files and referenced by sha256, and an engine_metadata block so
 * the result is self-describing across local/docker/qemu runners.
 *
 * This module is the SHAPE contract; the runner skeleton that produces it
 * lives in `@0sec/core/verify/replay-runner`. The two are deliberately
 * decoupled — cloud's ingest can consume the schema without pulling in any
 * runner dependency.
 */

import { z } from "zod";

// ── Status / mode enums ─────────────────────────────────────────────────────
//
// The four terminal statuses cover the full verification phase space:
//   • reproduced     — PoC ran and the exploit fired (all assertions passed)
//   • not_reproduced — PoC ran but at least one assertion failed (vulnerability appears patched)
//   • error          — verifier-infrastructure failure (bad finding, runner crash, etc.)
//   • skipped        — verifier declined to run (no poc_steps, unsupported runner, scope gate)
//
// `error` and `skipped` differ in *who's fault* the non-result is:
// `error` means we tried and broke; `skipped` means we chose not to try.

export const VerificationStatusSchema = z.enum([
  "reproduced",
  "not_reproduced",
  "error",
  "skipped",
]);

export type VerificationStatus = z.infer<typeof VerificationStatusSchema>;

/**
 * Verification mode. `deterministic_replay` is the cheap, no-LLM path: the
 * verifier consumes `finding.pocSteps` and the declared assertions and runs
 * them through a sandbox runner. `agent_assisted` is reserved for a future
 * fallback where an LLM-driven loop re-attempts a finding the deterministic
 * replay couldn't reproduce (out of scope for #193 itself, but the shape
 * needs to discriminate the two so downstream gating logic stays honest).
 */
export const VerificationModeSchema = z.enum([
  "deterministic_replay",
  "agent_assisted",
]);

export type VerificationMode = z.infer<typeof VerificationModeSchema>;

// ── Runner identification ───────────────────────────────────────────────────
//
// Which executor produced this result. `local` means the runner shelled out
// on the host (this is the only impl shipped with #193's first slice).
// `docker` / `qemu` are reserved for the sandbox-isolation work that the
// issue body calls out as a follow-up. They appear in the schema today so
// cloud-side ingest can already discriminate without a schema migration
// later.

export const RunnerKindSchema = z.enum(["local", "docker", "qemu"]);
export type RunnerKind = z.infer<typeof RunnerKindSchema>;

// ── Engine metadata ─────────────────────────────────────────────────────────
//
// Captures the host fingerprint a downstream consumer needs to reproduce
// the same run. `os` and `arch` mirror Node's `process.platform` /
// `process.arch` values verbatim — we store the raw string so a future
// platform doesn't need a schema migration.

export const EngineMetadataSchema = z.object({
  os: z.string(),
  arch: z.string(),
  runner: RunnerKindSchema,
});

export type EngineMetadata = z.infer<typeof EngineMetadataSchema>;

// ── Per-command capture ─────────────────────────────────────────────────────
//
// One entry per executed step. argv is the literal argv array the runner
// spawned (for shell steps, this is `["/bin/sh", "-c", "<cmd>"]`; for http
// steps, it's `[<method>, <url>]` so cloud has a uniform "what did we
// invoke" line per step). stdout/stderr excerpts are capped at 8 KiB each
// by the runner — the full output, when retained, lives in
// `evidence_artifacts` keyed by sha256.

export const VerificationCommandSchema = z.object({
  argv: z.array(z.string()).min(1),
  exit_code: z.number().int().nullable(),
  stdout_excerpt: z.string().optional(),
  stderr_excerpt: z.string().optional(),
  duration_ms: z.number().nonnegative(),
});

export type VerificationCommand = z.infer<typeof VerificationCommandSchema>;

// ── Assertions ──────────────────────────────────────────────────────────────
//
// Four assertion kinds cover the bulk of deterministic-replay needs:
//
//   • file_exists       — the named path exists on disk after the step ran
//   • http_status       — the most recent HTTP response status matches `expected`
//   • string_in_output  — `expected` substring is present in stdout (or response body)
//   • exit_code         — the most recent step exited with `expected` numeric code
//
// `target` identifies what was checked (the path / URL / step id). `expected`
// is the declared expectation from the finding; `actual` is what the runner
// observed. `passed === actual === expected` by definition for the simple
// kinds; we still store both so a future debugger can re-derive the verdict
// without re-running.
//
// The discriminator is `kind`; we intentionally keep `expected`/`actual` as
// permissive shapes so callers can add new kinds without a schema migration.

export const AssertionKindSchema = z.enum([
  "file_exists",
  "http_status",
  "string_in_output",
  "exit_code",
]);

export type AssertionKind = z.infer<typeof AssertionKindSchema>;

export const VerificationAssertionSchema = z.object({
  kind: AssertionKindSchema,
  target: z.string(),
  expected: z.union([z.string(), z.number(), z.boolean()]),
  actual: z.union([z.string(), z.number(), z.boolean(), z.null()]),
  passed: z.boolean(),
});

export type VerificationAssertion = z.infer<typeof VerificationAssertionSchema>;

// ── Evidence artifacts ──────────────────────────────────────────────────────
//
// Sidecar files the runner emits alongside the JSON result: request/response
// captures, screenshots, dmesg snapshots, raw stdout/stderr dumps. We store
// the on-disk path (relative to the run dir) and a sha256 so cloud-side
// ingest can deduplicate and verify integrity without re-fetching the bytes.
//
// `kind` is intentionally a free-form string (not an enum) so new artifact
// kinds (e.g. "tcpdump_pcap", "rr_trace") don't require a schema bump.

export const EvidenceArtifactSchema = z.object({
  kind: z.string().min(1),
  path: z.string().min(1),
  sha256: z
    .string()
    .regex(/^[0-9a-f]{64}$/i, "sha256 must be 64 lowercase hex chars"),
  bytes: z.number().int().nonnegative().optional(),
});

export type EvidenceArtifact = z.infer<typeof EvidenceArtifactSchema>;

// ── Top-level result ────────────────────────────────────────────────────────
//
// All fields above the dashed line are REQUIRED. The shape is intentionally
// flat (no nested optional sub-objects beyond the typed sub-records) so
// cloud's SQL schema can mirror it 1:1 with minimal denormalisation.

export const VerificationResultSchema = z.object({
  status: VerificationStatusSchema,
  mode: VerificationModeSchema,
  finding_id: z.string().min(1),
  engine_version: z.string().min(1),
  started_at: z.string().min(1),
  completed_at: z.string().min(1),
  duration_ms: z.number().nonnegative(),
  commands: z.array(VerificationCommandSchema),
  assertions: z.array(VerificationAssertionSchema),
  evidence_artifacts: z.array(EvidenceArtifactSchema),
  engine_metadata: EngineMetadataSchema,
  // Optional, additive fields. Existing producers can leave these undefined.
  error_reason: z.string().nullable().optional(),
  summary: z.string().optional(),
  // #659 / #1278 — evidence provenance surfaced to the cloud verify writeback.
  //
  // `evidence_kind` mirrors the cloud contract's VerifyEvidenceKind (0cloud
  // `@0cloud/cloud-contracts`): a reproduced kind promotes the finding to
  // in_scope, `source-only` never does. Producers that actually reproduced a
  // PoC set it; leave it undefined to let the consumer keep its own default
  // (the cloud maps a `reproduced` replay to `reproduced-poc` on its own, so
  // an undefined kind never downgrades a genuine replay). We only ever emit a
  // REPRODUCED kind here — never `source-only` — for exactly that reason.
  //
  // `oast_confirmed` is the out-of-band signal: true when a token-matched OAST
  // (interactsh-style DNS/HTTP) callback proved a blind class (SSRF / OOB-RCE /
  // OOB-SQLi / blind XSS). Its proof lives OUTSIDE the request/response the
  // deterministic replay can see, so the cloud promotes it even when the
  // in-band replay predicates left the status at `not_reproduced` / `skipped`.
  evidence_kind: z
    .enum(["reproduced-poc", "source-only", "reproduced-memcorruption-poc"])
    .optional(),
  oast_confirmed: z.boolean().optional(),
});

export type VerificationResult = z.infer<typeof VerificationResultSchema>;
