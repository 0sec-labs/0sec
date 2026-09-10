/**
 * Lens-synthesis FEEDBACK — durable local learning queue.
 *
 * Persists coverage observations from opted-in deep reviews and provides
 * operator capture/curation/approve API. Approved records carry vetted
 * positive/held-out/negative fixtures matching the LensGate contract, source
 * access consent, and trusted evidence reference digests.
 *
 * Status lifecycle:
 *
 *   pending ──▶ approved ──▶ processed
 *      │                      │
 *      └──▶ rejected   ◀──────┘
 *
 * "pending":  raw observation, not yet reviewed by operator
 * "approved": operator-curated, carries fixtures, ready for synthesis
 * "processed": watcher consumed this into the lens loop (outcome retained)
 * "rejected": operator declined, with reason
 *
 * Content-addressed identities: id is sha256 of (content fields + provenance
 * + revision digest), so different revisions of the same miss produce
 * distinct ids and never deduplicate against each other.
 *
 * Consent/privacy: an observation MUST have `consent: true` to be approved
 * with fixture paths; without consent, approval is refused. Source file text
 * is never stored — only paths and line numbers.
 *
 * Crash recovery: claimForProcessing generates an exclusive claim token
 * stored on the observation. markProcessed requires the same token. A
 * failed/cancelled synthesis releases the claim by calling releaseClaim(id).
 * No observation is ever marked "processed" without a retained outcome.
 *
 * Cross-process safety: a file-level advisory lock serializes
 * read-modify-write cycles. Corruption is always fail-closed: schema
 * validation rejects malformed entries; only ENOENT produces an empty store.
 */

import { randomUUID, createHash } from "node:crypto";
import {
  constants, mkdirSync, openSync, readFileSync, renameSync, rmdirSync,
  unlinkSync, fstatSync, writeFileSync, fsyncSync, closeSync,
} from "node:fs";
import { resolve, dirname } from "node:path";
import { homeStateDir } from "@0sec/shared";
import type { LensValidationReport, RegisteredLens, ValidationFixture, ValidationCorpus } from "./types.js";
import { ensureEvolutionDirectory, readEvolutionArtifact } from "../../improvement/artifacts.js";
import { prepareValidationCorpus } from "./validate.js";

// ── Types ─────────────────────────────────────────────────────────────────

export type ObservationStatus = "pending" | "approved" | "processed" | "rejected";
export type ObservationSource = "confirmed-miss" | "incomplete-coverage";

/** Evidence reference — file content trusted by digest verification. */
export interface EvidenceRef {
  file: string;
  digest: string;
}

/**
 * One entry in the durable learning queue.
 * Content-addressed: id is sha256 of classHint/sinkPattern/exampleFileLine/
 * whyMissed/sourceRevisionDigest/scanId/source + serialized evidenceRefs.
 */
export interface LearningObservation {
  /** Content-addressed id (see {@link observationDigest}). */
  id: string;
  classHint: string;
  sinkPattern: string;
  exampleFileLine: string;
  whyMissed: string;
  source: ObservationSource;
  scanId: string;
  /** Source revision digest — different revisions never collate. */
  sourceRevisionDigest: string;
  evidenceRefs: EvidenceRef[];
  /** Explicit operator consent for source access. Without it, approval is refused. */
  consent: boolean;
  status: ObservationStatus;
  approvedShape?: ApprovedObservationShape;
  rejectedReason?: string;
  /** Finder lens that surfaced this miss (set by automatic capture). */
  detectorLensId?: string;
  /** Version digest of the detector lens at capture time. */
  detectorLensVersionDigest?: string;
  /** Exclusive claim token set by claimForProcessing; cleared on releaseClaim or markProcessed. */
  claimToken?: string;
  /**
   * Retained evaluation outcome, including rejected and non-promoting runs.
   * Registration IDs are empty when no lens was installed.
   */
  processedOutcome?: {
    registeredLensIds: string[];
    /** Full registered lens objects including lensVersionDigest, present when available. */
    registeredLenses?: RegisteredLens[];
    validatedAt: string;
    validationReports?: LensValidationReport[];
    /** Warnings captured during processing. */
    warnings?: string[];
    /** Candidates that did not register, with reasons. */
    rejected?: Array<{ id: string; reason: string }>;
  };
  createdAt: string;
  updatedAt: string;
}

export interface ObservationFilter {
  status?: ObservationStatus | ObservationStatus[];
  source?: ObservationSource;
  scanId?: string;
  limit?: number;
  offset?: number;
}

export interface CaptureObservationInput {
  classHint: string;
  sinkPattern: string;
  exampleFileLine: string;
  whyMissed: string;
  source: ObservationSource;
  scanId: string;
  sourceRevisionDigest: string;
  evidenceRefs?: EvidenceRef[];
  /** Explicit user opt-in. False = approval is never possible. Set true on capture. */
  consent?: boolean;
  /** Finder lens that surfaced this miss (set by automatic capture). */
  detectorLensId?: string;
  /** Version digest of the detector lens at the time of capture. */
  detectorLensVersionDigest?: string;
}

export interface ApprovedObservationShape {
  positives: ValidationFixture[];
  heldOut: ValidationFixture[];
  negativeControls: ValidationFixture[];
}

export interface ObservationQueueSummary {
  total: number;
  pending: number;
  approved: number;
  processed: number;
  rejected: number;
}

export interface ObservationQueueOptions {
  storePath?: string;
}

/** Approve options — controls consent gate and model source access. */
export interface ApproveObservationOptions {
  /** Explicit operator consent for model source access. True overrides observation.consent. */
  allowModelSourceAccess?: boolean;
  /** Override store path for testing. */
  storePath?: string;
}

export interface ClaimedApprovedObservation {
  id: string;
  claimToken: string;
  classHint: string;
  sinkPattern: string;
  exampleFileLine: string;
  whyMissed: string;
  source: ObservationSource;
  scanId: string;
  sourceRevisionDigest: string;
  evidenceRefs: EvidenceRef[];
  consent: boolean;
  detectorLensId?: string;
  detectorLensVersionDigest?: string;
  approvedShape: ApprovedObservationShape;
}

// ── Zod schemas for CLI reuse ─────────────────────────────────────────────

const VALIDATION_FIXTURE_KEYS: ReadonlySet<string> = new Set([
  "id", "path", "note", "expectedCwe", "expectedFile",
  "expectedLine", "expectedRange", "contentDigest", "cleanProvenance",
]);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isValidValidationFixture(v: unknown): v is ValidationFixture {
  if (!isRecord(v)) return false;
  if (typeof v.id !== "string" || v.id === "") return false;
  if (typeof v.path !== "string" || v.path === "") return false;
  const extra = Object.keys(v).filter(
    (k) => !VALIDATION_FIXTURE_KEYS.has(k),
  );
  if (extra.length > 0) return false;
  if (v.note !== undefined && typeof v.note !== "string") return false;
  if (v.expectedCwe !== undefined && typeof v.expectedCwe !== "string") return false;
  if (v.expectedFile !== undefined && typeof v.expectedFile !== "string") return false;
  if (v.expectedLine !== undefined && (typeof v.expectedLine !== "number" || !Number.isFinite(v.expectedLine))) return false;
  if (v.expectedRange !== undefined) {
    if (!Array.isArray(v.expectedRange)) return false;
    if (v.expectedRange.length !== 2) return false;
    if (typeof v.expectedRange[0] !== "number" || typeof v.expectedRange[1] !== "number") return false;
  }
  if (v.contentDigest !== undefined && typeof v.contentDigest !== "string") return false;
  if (v.cleanProvenance !== undefined && typeof v.cleanProvenance !== "string") return false;
  return true;
}

export function parseApprovedObservationShape(raw: unknown): ApprovedObservationShape {
  if (!isRecord(raw)) throw new Error("approved observation shape must be a JSON object");
  const positives = raw.positives;
  const heldOut = raw.heldOut;
  const negativeControls = raw.negativeControls;
  if (!Array.isArray(positives)) throw new Error("approved shape.positives must be an array");
  if (!Array.isArray(heldOut)) throw new Error("approved shape.heldOut must be an array");
  if (!Array.isArray(negativeControls)) throw new Error("approved shape.negativeControls must be an array");
  if (positives.length === 0) throw new Error("approved shape requires at least one positive fixture");
  if (heldOut.length === 0) throw new Error("approved shape requires at least one held-out fixture");
  if (negativeControls.length === 0) throw new Error("approved shape requires at least one negative-control fixture");
  for (let i = 0; i < positives.length; i++) {
    if (!isValidValidationFixture(positives[i])) throw new Error(`approved shape.positives[${i}] is not a valid ValidationFixture`);
  }
  for (let i = 0; i < heldOut.length; i++) {
    if (!isValidValidationFixture(heldOut[i])) throw new Error(`approved shape.heldOut[${i}] is not a valid ValidationFixture`);
  }
  for (let i = 0; i < negativeControls.length; i++) {
    if (!isValidValidationFixture(negativeControls[i])) throw new Error(`approved shape.negativeControls[${i}] is not a valid ValidationFixture`);
  }
  return { positives, heldOut, negativeControls };
}

export function parseObservationInput(raw: unknown): CaptureObservationInput {
  if (!isRecord(raw)) throw new Error("observation input must be a JSON object");
  for (const key of ["classHint", "exampleFileLine", "whyMissed", "source", "scanId", "sourceRevisionDigest"]) {
    if (typeof raw[key] !== "string" || !raw[key].trim()) throw new Error(`observation input.${key} is required as a nonempty string`);
  }
  if (raw.sinkPattern !== undefined && typeof raw.sinkPattern !== "string") throw new Error("observation sinkPattern must be a string");
  if (raw.consent !== undefined && typeof raw.consent !== "boolean") throw new Error("observation consent must be boolean");
  if (raw.evidenceRefs !== undefined && !Array.isArray(raw.evidenceRefs)) throw new Error("observation evidenceRefs must be an array");
  const classHint = String(raw.classHint ?? "");
  const sinkPattern = String(raw.sinkPattern ?? "");
  const exampleFileLine = String(raw.exampleFileLine ?? "");
  const whyMissed = String(raw.whyMissed ?? "");
  const source = String(raw.source ?? "");
  const scanId = String(raw.scanId ?? "");
  const sourceRevisionDigest = String(raw.sourceRevisionDigest ?? "");
  if (!classHint) throw new Error("observation input.classHint is required");
  if (!exampleFileLine) throw new Error("observation input.exampleFileLine is required");
  if (!whyMissed) throw new Error("observation input.whyMissed is required");
  if (source !== "confirmed-miss" && source !== "incomplete-coverage") {
    throw new Error(`observation input.source must be "confirmed-miss" or "incomplete-coverage", got "${source}"`);
  }
  if (!scanId) throw new Error("observation input.scanId is required");
  if (!sourceRevisionDigest) throw new Error("observation input.sourceRevisionDigest is required");

  let evidenceRefs: EvidenceRef[] = [];
  if (Array.isArray(raw.evidenceRefs)) {
    for (let i = 0; i < raw.evidenceRefs.length; i++) {
      const ref = raw.evidenceRefs[i];
      if (!isRecord(ref) || typeof ref.file !== "string" || typeof ref.digest !== "string") {
        throw new Error(`observation input.evidenceRefs[${i}] must be { file: string, digest: string }`);
      }
      if (!ref.file || !ref.digest) throw new Error(`observation input.evidenceRefs[${i}] has empty file or digest`);
      evidenceRefs.push({ file: ref.file, digest: ref.digest });
    }
  }

  const consent = typeof raw.consent === "boolean" ? raw.consent : false;

  const detectorLensId = typeof raw.detectorLensId === "string" && raw.detectorLensId.trim() ? raw.detectorLensId : undefined;
  const detectorLensVersionDigest = typeof raw.detectorLensVersionDigest === "string" && raw.detectorLensVersionDigest.trim() ? raw.detectorLensVersionDigest : undefined;

  return { classHint, sinkPattern, exampleFileLine, whyMissed, source, scanId, sourceRevisionDigest, evidenceRefs, consent, detectorLensId, detectorLensVersionDigest };
}

// ── Content addressing ────────────────────────────────────────────────────

/**
 * Compute the content-addressed id for an observation.
 * Includes provenance fields so different revisions, scans, or evidence sets
 * produce distinct ids and never deduplicate against each other.
 */
export function observationDigest(
  classHint: string,
  sinkPattern: string,
  exampleFileLine: string,
  whyMissed: string,
  sourceRevisionDigest: string,
  scanId: string,
  source: ObservationSource,
  evidenceRefs: EvidenceRef[],
  detectorLensId?: string,
  detectorLensVersionDigest?: string,
): string {
  const h = createHash("sha256");
  h.update(classHint).update("\0");
  h.update(sinkPattern).update("\0");
  h.update(exampleFileLine).update("\0");
  h.update(whyMissed).update("\0");
  h.update(sourceRevisionDigest).update("\0");
  h.update(scanId).update("\0");
  h.update(source).update("\0");
  for (const ref of evidenceRefs) {
    h.update(ref.file).update("\0").update(ref.digest).update("\0");
  }
  if (detectorLensId) h.update(detectorLensId).update("\0");
  if (detectorLensVersionDigest) h.update(detectorLensVersionDigest).update("\0");
  return h.digest("hex");
}

// ── Store persistence with process-safe locking ───────────────────────────

const DEFAULT_OBSERVATIONS_DIR = "lens-synthesis";
const DEFAULT_OBSERVATIONS_FILE = "observations.json";

const STORE_MODE = 0o600;
const DIR_MODE = 0o700;

function storePath(opts?: ObservationQueueOptions): string {
  return resolve(opts?.storePath ?? resolve(homeStateDir(), DEFAULT_OBSERVATIONS_DIR, DEFAULT_OBSERVATIONS_FILE));
}

/** Advisory lock for cross-process serialization via exclusive mkdir. */
function acquireLock(store: string): number {
  ensureStoreDir(store);
  // Fail promptly on contention or a stale lock. Never spin/block the event
  // loop or reclaim a lock while another process may still own it.
  mkdirSync(`${store}.lockdir`, { mode: DIR_MODE });
  return 0;
}

function releaseLock(store: string, _token: number): void {
  rmdirSync(`${store}.lockdir`);
}

function ensureStoreDir(path: string): void {
  ensureEvolutionDirectory(dirname(path));
}

/**
 * Schema-validate a loaded observation entry. Corrupt data fails closed.
 */
function validateObservation(v: unknown): v is LearningObservation {
  if (!isRecord(v)) return false;
  if (typeof v.id !== "string") return false;
  if (typeof v.classHint !== "string") return false;
  if (typeof v.sinkPattern !== "string") return false;
  if (typeof v.exampleFileLine !== "string") return false;
  if (typeof v.whyMissed !== "string") return false;
  if (v.source !== "confirmed-miss" && v.source !== "incomplete-coverage") return false;
  if (typeof v.scanId !== "string") return false;
  if (typeof v.sourceRevisionDigest !== "string") return false;
  if (v.detectorLensId !== undefined && typeof v.detectorLensId !== "string") return false;
  if (v.detectorLensVersionDigest !== undefined && typeof v.detectorLensVersionDigest !== "string") return false;
  if (!Array.isArray(v.evidenceRefs)) return false;
  for (const ref of v.evidenceRefs) {
    if (!isRecord(ref) || typeof ref.file !== "string" || typeof ref.digest !== "string") return false;
  }
  if (typeof v.consent !== "boolean") return false;
  if (v.status !== "pending" && v.status !== "approved" && v.status !== "processed" && v.status !== "rejected") return false;
  if (typeof v.createdAt !== "string") return false;
  if (typeof v.updatedAt !== "string") return false;
  if (v.approvedShape !== undefined) {
    if (!isRecord(v.approvedShape)) return false;
    const shape = v.approvedShape;
    if (!Array.isArray(shape.positives) || !Array.isArray(shape.heldOut) || !Array.isArray(shape.negativeControls)) return false;
    for (const arr of [shape.positives, shape.heldOut, shape.negativeControls]) {
      if (!arr.every(isValidValidationFixture)) return false;
    }
  }
  if (v.rejectedReason !== undefined && typeof v.rejectedReason !== "string") return false;
  if (v.claimToken !== undefined && typeof v.claimToken !== "string") return false;
  if (v.processedOutcome !== undefined) {
    if (!isRecord(v.processedOutcome)) return false;
    const outcome = v.processedOutcome;
    if (!Array.isArray(outcome.registeredLensIds) || !outcome.registeredLensIds.every((id) => typeof id === "string")) return false;
    if (typeof outcome.validatedAt !== "string") return false;
    if (outcome.registeredLenses !== undefined) {
      if (!Array.isArray(outcome.registeredLenses)) return false;
      for (const lens of outcome.registeredLenses) {
        if (!isRecord(lens) || typeof lens.id !== "string" || typeof lens.uid !== "string"
          || typeof lens.validatedAt !== "string" || typeof lens.lensVersionDigest !== "string"
          || !Array.isArray(lens.missRefs) || !lens.missRefs.every((ref) => typeof ref === "string")) return false;
      }
    }
    if (outcome.validationReports !== undefined && !Array.isArray(outcome.validationReports)) return false;
    if (outcome.warnings !== undefined && (!Array.isArray(outcome.warnings) || !outcome.warnings.every((warning) => typeof warning === "string"))) return false;
    if (outcome.rejected !== undefined) {
      if (!Array.isArray(outcome.rejected)) return false;
      for (const rejected of outcome.rejected) {
        if (!isRecord(rejected) || typeof rejected.id !== "string" || typeof rejected.reason !== "string") return false;
      }
    }
  }
  return true;
}

/** Load all observations from the store. Fails closed on corruption: only ENOENT returns []. */
function loadAll(store: string): LearningObservation[] {
  let parsed: unknown;
  try {
    parsed = readEvolutionArtifact(store);
  } catch (err: unknown) {
    const nodeErr = err as NodeJS.ErrnoException;
    if (nodeErr.code === "ENOENT") return [];
    throw new Error(`failed to read observation store ${store}: ${nodeErr.message}`);
  }


  if (!Array.isArray(parsed)) {
    throw new Error(`observation store ${store} root is not an array`);
  }

  const valid: LearningObservation[] = [];
  for (let i = 0; i < parsed.length; i++) {
    const validated: unknown = parsed[i];
    if (!validateObservation(validated)) {
      throw new Error(`observation store ${store} entry [${i}] failed schema validation`);
    }
    valid.push(validated);
  }
  return valid;
}

/** Write observations with cross-process lock, correct perms, and fsync. */
function writeAll(store: string, observations: LearningObservation[]): void {
  ensureStoreDir(store);
  const dir = dirname(store);
  const tmp = resolve(dir, `.obs-${randomUUID()}.tmp`);
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, STORE_MODE);
  try {
    try {
      writeFileSync(fd, JSON.stringify(observations, null, 2), "utf8");
      fsyncSync(fd);
    } finally { closeSync(fd); }
    renameSync(tmp, store);
    const directoryFd = openSync(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
  } finally {
    try { unlinkSync(tmp); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }
}

// ── Helper: verify evidence ref digests ───────────────────────────────────

/**
 * Verify that every evidence ref's file exists and matches its digest.
 * Throws on the first mismatch. Pure validation — no I/O besides stat+read.
 */
function verifyEvidenceRefs(refs: EvidenceRef[]): void {
  for (const ref of refs) {
    try {
      const fd = openSync(ref.file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      let content: Buffer;
      try {
        const stat = fstatSync(fd);
        if (!stat.isFile() || stat.nlink !== 1 || stat.size > 64 * 1024 * 1024) throw new Error("unsafe or oversized evidence file");
        content = readFileSync(fd);
      } finally { closeSync(fd); }
      const actual = createHash("sha256").update(content).digest("hex");
      if (actual !== ref.digest) {
        throw new Error(
          `evidence ref ${ref.file} digest mismatch: expected ${ref.digest}, computed ${actual}`,
        );
      }
    } catch (err: unknown) {
      const nodeErr = err as NodeJS.ErrnoException;
      if (nodeErr.code === "ENOENT") {
        throw new Error(`evidence ref ${ref.file} not found`);
      }
      throw err;
    }
  }
}

// ── Queue API ─────────────────────────────────────────────────────────────

/**
 * Capture one observation into the durable queue.
 * Deduplicates by content-addressed id (same content + provenance → no-op).
 * Cross-process safe: acquires a lock around read-modify-write.
 */
export function captureObservation(
  input: CaptureObservationInput,
  opts?: ObservationQueueOptions,
): LearningObservation {
  input = parseObservationInput(input);
  const store = storePath(opts);
  const lockToken = acquireLock(store);
  try {
    const observations = loadAll(store);
    const now = new Date().toISOString();
    const evidenceRefs = input.evidenceRefs ?? [];
    const consent = input.consent ?? false;
    const id = observationDigest(
      input.classHint, input.sinkPattern, input.exampleFileLine, input.whyMissed,
      input.sourceRevisionDigest, input.scanId, input.source, evidenceRefs,
      input.detectorLensId, input.detectorLensVersionDigest,
    );

    if (observations.some((o) => o.id === id)) {
      return observations.find((o) => o.id === id)!;
    }

    const entry: LearningObservation = {
      id,
      classHint: input.classHint,
      sinkPattern: input.sinkPattern,
      exampleFileLine: input.exampleFileLine,
      whyMissed: input.whyMissed,
      source: input.source,
      scanId: input.scanId,
      sourceRevisionDigest: input.sourceRevisionDigest,
      evidenceRefs,
      consent,
      detectorLensId: input.detectorLensId,
      detectorLensVersionDigest: input.detectorLensVersionDigest,
      status: "pending",
      createdAt: now,
      updatedAt: now,
    };

    observations.push(entry);
    writeAll(store, observations);
    return entry;
  } finally {
    releaseLock(store, lockToken);
  }
}

/**
 * List observations matching filter criteria.
 * Ordered newest-first by createdAt.
 */
export function listObservations(
  filter?: ObservationFilter,
  opts?: ObservationQueueOptions,
): LearningObservation[] {
  const store = storePath(opts);
  const lockToken = acquireLock(store);
  try {
    let observations = loadAll(store);

    if (filter?.status) {
      const statuses = Array.isArray(filter.status) ? filter.status : [filter.status];
      const statusSet = new Set(statuses);
      observations = observations.filter((o) => statusSet.has(o.status));
    }
    if (filter?.source) {
      observations = observations.filter((o) => o.source === filter.source);
    }
    if (filter?.scanId) {
      observations = observations.filter((o) => o.scanId === filter.scanId);
    }

    observations.sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    const offset = filter?.offset ?? 0;
    const limit = filter?.limit ?? observations.length;
    return observations.slice(offset, offset + limit);
  } finally {
    releaseLock(store, lockToken);
  }
}

/**
 * Approve a pending observation with operator-curated fixtures.
 *
 * Guards:
 * - observation MUST be "pending" status
 * - observation MUST have `consent: true` OR `allowModelSourceAccess` MUST be true
 * - shape MUST pass {@link prepareValidationCorpus} — the authoritative check
 *   that validates fixture file existence, rejects symlinks/hardlinks/overlap/
 *   duplicate content/aliases, requires CWE/file/line identity for positives,
 *   requires cleanProvenance for negatives, and stamps contentDigest
 * - all evidenceRefs on the observation MUST verify (exist + digest match)
 *
 * Sets status to "approved" and attaches the stamped fixtures.
 */
export function approveObservation(
  id: string,
  shape: ApprovedObservationShape,
  opts?: ApproveObservationOptions,
): LearningObservation {
  const store = storePath(opts);
  const lockToken = acquireLock(store);
  try {
    const observations = loadAll(store);
    const idx = observations.findIndex((o) => o.id === id);
    if (idx === -1) throw new Error(`observation ${id} not found`);

    const entry = observations[idx]!;
    if (entry.status !== "pending") {
      throw new Error(`cannot approve observation ${id}: status is "${entry.status}", expected "pending"`);
    }

    // Consent gate: observation must have consent=true OR explicit allowModelSourceAccess.
    // When allowModelSourceAccess grants the consent, persist it on the entry so
    // downstream consumers (claimForProcessing, markProcessed) see the granted flag.
    const grantSourceAccess = opts?.allowModelSourceAccess === true;
    if (!entry.consent && !grantSourceAccess) {
      throw new Error(
        `cannot approve observation ${id}: consent is false and allowModelSourceAccess is not set. ` +
        "Operator must explicitly grant source access via --allow-source-access or capture with consent=true.",
      );
    }
    if (grantSourceAccess && !entry.consent) {
      entry.consent = true;
    }

    // Authoritative corpus validation via prepareValidationCorpus — checks
    // fixture file existence on disk, rejects symlinks/hardlinks/overlap/
    // duplicate content/aliases, validates CWE/file/line for positives,
    // requires cleanProvenance for negatives, and stamps contentDigest.
    const corpus = prepareValidationCorpus({
      positives: shape.positives,
      heldOut: shape.heldOut,
      negativeControls: shape.negativeControls,
    });

    // Verify evidence content refs
    if (entry.evidenceRefs.length > 0) {
      verifyEvidenceRefs(entry.evidenceRefs);
    }

    entry.status = "approved";
    entry.approvedShape = {
      positives: corpus.positives,
      heldOut: corpus.heldOut,
      negativeControls: corpus.negativeControls,
    };
    entry.updatedAt = new Date().toISOString();
    observations[idx] = entry;
    writeAll(store, observations);
    return entry;
  } finally {
    releaseLock(store, lockToken);
  }
}

/**
 * Reject a pending observation with a reason.
 */
export function rejectObservation(
  id: string,
  reason: string,
  opts?: ObservationQueueOptions,
): LearningObservation {
  const store = storePath(opts);
  const lockToken = acquireLock(store);
  try {
    const observations = loadAll(store);
    const idx = observations.findIndex((o) => o.id === id);
    if (idx === -1) throw new Error(`observation ${id} not found`);
    const entry = observations[idx]!;
    if (entry.status !== "pending") throw new Error(`cannot reject observation ${id}: status is "${entry.status}"`);
    if (!reason) throw new Error("rejection reason is required");

    entry.status = "rejected";
    entry.rejectedReason = reason;
    entry.updatedAt = new Date().toISOString();
    observations[idx] = entry;
    writeAll(store, observations);
    return entry;
  } finally {
    releaseLock(store, lockToken);
  }
}

/**
 * Get the queue summary.
 */
export function observationQueueSummary(
  opts?: ObservationQueueOptions,
): ObservationQueueSummary {
  const store = storePath(opts);
  const lockToken = acquireLock(store);
  try {
    const observations = loadAll(store);
    let pending = 0;
    let approved = 0;
    let processed = 0;
    let rejected = 0;
    for (const o of observations) {
      switch (o.status) {
        case "pending": pending++; break;
        case "approved": approved++; break;
        case "processed": processed++; break;
        case "rejected": rejected++; break;
      }
    }
    return { total: observations.length, pending, approved, processed, rejected };
  } finally {
    releaseLock(store, lockToken);
  }
}

/**
 * Claim approved observations for processing.
 *
 * Generates an exclusive claim token per observation, stored persistently.
 * The caller MUST hold the returned token and pass it to:
 *   - {@link markProcessed} on success (requires token + outcome)
 *   - {@link releaseClaim} on failure/cancellation (reverts to approved)
 *
 * Crash recovery: on reload, approved entries with a claimToken are
 * "claimed but not completed" — the caller (watcher) should re-claim them
 * by calling releaseClaim for stale tokens and then re-attempting.
 * Claimed entries are excluded from subsequent claimForProcessing calls
 * so two watchers never process the same observation.
 */
export function claimForProcessing(
  opts?: ObservationQueueOptions,
): ClaimedApprovedObservation[] {
  const store = storePath(opts);
  const lockToken = acquireLock(store);
  try {
    const observations = loadAll(store);
    const claimed: ClaimedApprovedObservation[] = [];

    for (let i = 0; i < observations.length; i++) {
      const o = observations[i]!;
      // Skip: not approved, already claimed, or already processed.
      if (o.status !== "approved") continue;
      if (o.claimToken) continue;
      if (!o.approvedShape) continue;

      const claimToken = randomUUID();
      o.claimToken = claimToken;
      o.updatedAt = new Date().toISOString();
      observations[i] = o;

      claimed.push({
        id: o.id,
        claimToken,
        classHint: o.classHint,
        sinkPattern: o.sinkPattern,
        exampleFileLine: o.exampleFileLine,
        whyMissed: o.whyMissed,
        source: o.source,
        scanId: o.scanId,
        sourceRevisionDigest: o.sourceRevisionDigest,
        evidenceRefs: o.evidenceRefs,
        consent: o.consent,
        ...(o.detectorLensId ? { detectorLensId: o.detectorLensId } : {}),
        ...(o.detectorLensVersionDigest ? { detectorLensVersionDigest: o.detectorLensVersionDigest } : {}),
        approvedShape: o.approvedShape,
      });
    }

    if (claimed.length > 0) {
      writeAll(store, observations);
    }

    return claimed;
  } finally {
    releaseLock(store, lockToken);
  }
}

/**
 * Mark a claimed observation as processed.
 *
 * Requires the exact claim token from {@link claimForProcessing}. The outcome
 * records which lens(es) were actually registered as a result of processing
 * this observation — never marks processed without a retained outcome.
 *
 * Returns true on success, false if the observation is not in a claimable state.
 */
export function markProcessed(
  id: string,
  outcome: {
    registeredLensIds: string[];
    /** Full registered lens objects including lensVersionDigest, present when available. */
    registeredLenses?: RegisteredLens[];
    validatedAt: string;
    validationReports?: LensValidationReport[];
    /** Warnings captured during processing. */
    warnings?: string[];
    /** Candidates that did not register, with reasons. */
    rejected?: Array<{ id: string; reason: string }>;
  },
  claimToken: string,
  opts?: ObservationQueueOptions,
): boolean {
  const store = storePath(opts);
  const lockToken = acquireLock(store);
  try {
    const observations = loadAll(store);
    const idx = observations.findIndex((o) => o.id === id);
    if (idx === -1) return false;
    const entry = observations[idx]!;
    if (entry.claimToken !== claimToken) return false;
    if (entry.status !== "approved") return false;

    entry.status = "processed";
    entry.processedOutcome = {
      registeredLensIds: outcome.registeredLensIds,
      validatedAt: outcome.validatedAt,
      ...(outcome.registeredLenses ? { registeredLenses: outcome.registeredLenses } : {}),
      ...(outcome.validationReports ? { validationReports: outcome.validationReports } : {}),
      ...(outcome.warnings ? { warnings: outcome.warnings } : {}),
      ...(outcome.rejected ? { rejected: outcome.rejected } : {}),
    };
    entry.claimToken = undefined;
    entry.updatedAt = new Date().toISOString();
    observations[idx] = entry;
    writeAll(store, observations);
    return true;
  } finally {
    releaseLock(store, lockToken);
  }
}

/**
 * Release a previously claimed observation back to "approved" status.
 * Used when processing fails or is cancelled — the observation can be
 * re-claimed on the next try.
 */
export function releaseClaim(
  id: string,
  claimToken: string,
  opts?: ObservationQueueOptions,
): boolean {
  const store = storePath(opts);
  const lockToken = acquireLock(store);
  try {
    const observations = loadAll(store);
    const idx = observations.findIndex((o) => o.id === id);
    if (idx === -1) return false;
    const entry = observations[idx]!;
    if (entry.claimToken !== claimToken) return false;
    if (entry.status !== "approved") return false;

    entry.claimToken = undefined;
    entry.updatedAt = new Date().toISOString();
    observations[idx] = entry;
    writeAll(store, observations);
    return true;
  } finally {
    releaseLock(store, lockToken);
  }
}

/**
 * Get a single observation by id.
 */
export function getObservation(
  id: string,
  opts?: ObservationQueueOptions,
): LearningObservation | undefined {
  const store = storePath(opts);
  const lockToken = acquireLock(store);
  try {
    return loadAll(store).find((o) => o.id === id);
  } finally {
    releaseLock(store, lockToken);
  }
}