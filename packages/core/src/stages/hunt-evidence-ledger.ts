/**
 * Hunt evidence ledger — the shared, append-only claim store for a hunt
 * campaign.
 *
 * ## The gap this closes (measured, not speculative)
 *
 * `runHuntScan` fans finders and skeptics out across a `pool` (hunt-scan.ts
 * :366) and each `agenticScan` gets its OWN throwaway SQLite file
 * (`freshHuntDb`, hunt-scan.ts:63) precisely so concurrent workers never
 * contend on a write lock. That decision is correct and this module does not
 * touch it. But it means workers share NOTHING at runtime: they hand findings
 * back to the parent and that is the entire channel.
 *
 * The learned-negatives loop (hunt-negatives.ts) is the closest thing to shared
 * memory, and it is strictly END-OF-RUN: `@0sec/benchmark`'s `appendToCorpus`
 * writes `HuntFindingRecord[]` after `runHuntScan` has already returned, and
 * `loadKnownNegativesFromEnv()` reads that corpus ONCE, when the skeptic
 * verifier is constructed. So when worker A refutes a shape at minute 2 of a
 * 40-minute sweep, workers B..N re-derive that refutation from scratch for the
 * remaining 38 minutes, and a second hunt PROCESS running the same campaign
 * never sees it at all. That is the concrete waste this module removes.
 *
 * ## Shape, and why each field exists
 *
 * A claim carries its supporting evidence, its dependencies, and a status of
 * `unresolved | validated | disproven`. Two properties are load-bearing:
 *
 *  1. **Observations are distinguishable from assumptions.** Every evidence
 *     entry declares a {@link EvidenceStance}. This is not a decorative label:
 *     an `observation` MUST carry a `locator` (a `file:line`, a tool name, a
 *     command) so it can be re-checked by another worker, and a claim may NOT
 *     reach a terminal status (`validated` / `disproven`) on assumptions alone
 *     — see {@link validateClaimBody}. Without that rule, "distinguishable"
 *     degrades to a field nobody fills in honestly, and a swarm cheerfully
 *     buries a dead end under three layers of confident inference.
 *
 *  2. **Negative results stay available.** A `disproven` claim is a first-class
 *     record, not an absence. {@link disprovenHuntClaims} is what a later
 *     worker reads so it does not re-walk the dead end;
 *     `loadKnownNegativesFromLedger` (hunt-negatives.ts) adapts those records
 *     into the EXISTING `KnownNegative` shape so the skeptic prompt path is
 *     unchanged — this integrates with the learned-negatives gate rather than
 *     forking a second one.
 *
 * ## Why append-only JSONL and not SQLite (and not `proposal-replay.ts`)
 *
 * SQLite is off the table by the same reasoning that produced `freshHuntDb`:
 * one shared DB across a fan-out is exactly the write-lock contention that
 * crashed verify steps mid-sweep. A single-writer parent-owned store would
 * work for the in-process `pool`, but not for the case that actually costs us
 * — two hunt PROCESSES on one campaign — and it would put the parent on the
 * critical path of every worker's write.
 *
 * So: append-only JSONL, one record per line, written with a single
 * `O_APPEND|O_CREAT|O_NOFOLLOW` write. That is the mechanism
 * `research/proposal-replay.ts:328` already uses and it is reused here
 * deliberately — as is its canonical-JSON + content-addressed-id discipline
 * (`canonicalProposalJson` / `proposalDigest`, imported below rather than
 * reimplemented). O_APPEND makes each worker's write land at the current end
 * of file without a seek race, and one write syscall per small record means
 * concurrent writers cannot byte-interleave a record.
 *
 * What is deliberately NOT reused is `proposal-replay.ts`'s SCHEMA and its
 * write path, for three reasons that are specific and checkable:
 *
 *  - `createProposalAttempt` demands a `ResearchProposal`, which demands
 *    citations with `excerptSha256` digests computed against a
 *    `TargetSourceSnapshot` of full file contents (research/proposal.ts). A
 *    hunt claim has a finder's prose and a `file:line` that may not even
 *    resolve. Building a verified snapshot per claim mid-sweep is not
 *    affordable and often not possible.
 *  - Its outcome rules (proposal-replay.ts:156-164) require `refuted` to carry
 *    deterministic truth evidence (`deterministic_oracle|sanitizer|reproducer`)
 *    from an INDEPENDENT producer plus an adequate coverage receipt. The hunt
 *    skeptic's refutation is a `model_report`. The single most valuable thing
 *    to persist here is therefore the one thing that store refuses to record —
 *    and relaxing the rule is not an option, because those labels feed
 *    `proposalTrainingExamples` → `proposal-ranker.ts:70`. Loosening the bar to
 *    fit hunt evidence would poison an ML label set.
 *  - `appendProposalAttempt` re-reads and re-validates the ENTIRE replay before
 *    every append (proposal-replay.ts:330). That is fine for a single-writer
 *    research loop and wrong here twice over: it is O(n^2) across a campaign,
 *    and across processes the read-then-append window is racy anyway, so it
 *    buys no real exclusion.
 *
 * The consequence of dropping that read-before-write is that duplicate
 * suppression moves to READ time. Records are content-addressed
 * ({@link HuntClaimRecord.id}), so re-running identical work produces a
 * byte-identical record and {@link readHuntLedger} collapses it. That is the
 * deliberate trade: idempotence as a read-time property, because a write-time
 * check cannot be made race-free across processes without a lock, and a lock is
 * precisely what the per-worker-SQLite decision exists to avoid.
 */

import { closeSync, constants, lstatSync, mkdirSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import { canonicalProposalJson, proposalDigest } from "../research/proposal.js";

export const HUNT_CLAIM_SCHEMA_VERSION = 1 as const;

/**
 * Whether a piece of evidence is something a worker SAW or something it
 * BELIEVED. The distinction the Sangfor design calls out and that most
 * implementations skip.
 *
 *  - `observation` — a fact re-checkable by another worker running the same
 *    read: a line of source at a path, a sanitizer report, a command's output.
 *    Requires a `locator`; that requirement is what keeps the label honest.
 *  - `assumption` — an inference, a prior, a "this is probably how the caller
 *    works". Legitimate and worth recording (it is what a later worker must
 *    attack first), but never sufficient on its own to settle a claim.
 */
export type EvidenceStance = "observation" | "assumption";

/**
 * `unresolved` is the honest default. `validated` / `disproven` are TERMINAL
 * and both require at least one observation — see {@link validateClaimBody}.
 * There is no `inconclusive`: an investigation that ran and settled nothing
 * leaves the claim `unresolved` with its assumptions recorded, which is the
 * same information without a third state to reason about.
 */
export type ClaimStatus = "unresolved" | "validated" | "disproven";

export interface HuntEvidence {
  stance: EvidenceStance;
  /** What was observed or assumed, in plain text. */
  statement: string;
  /** Producer id — the worker, model, or tool. Evidence is never anonymous. */
  source: string;
  /**
   * Where the evidence can be re-checked (`drivers/net/foo.c:412`, a command,
   * a sanitizer log path). REQUIRED for `observation`, optional for
   * `assumption` — an assumption by definition has no re-runnable source.
   */
  locator?: string;
}

/**
 * What a claim is ABOUT. This is the coarse join key: two workers investigating
 * the same site for the same bug class collide here by construction, even when
 * they phrase their statements differently, which is what makes the
 * known-negative bridge able to match across workers at all.
 */
export interface HuntClaimShape {
  /** Candidate path the claim concerns — the same `candidatePath` the hunt records use. */
  path: string;
  /** Bug class / archetype, e.g. "CWE-416 use-after-free" or "missing length check". */
  bugClass: string;
}

export interface RecordHuntClaimInput {
  shape: HuntClaimShape;
  /** The falsifiable claim itself, e.g. "`foo_free()` frees `sk` while the timer can still fire". */
  statement: string;
  status: ClaimStatus;
  evidence: readonly HuntEvidence[];
  /** `claimKey`s this claim was formed on top of — see {@link staleHuntClaims}. */
  dependsOn?: readonly string[];
  /** Worker identity (`finder-3`, `skeptic.gpt-5.5`). Distinguishes independent corroboration from a re-run. */
  worker: string;
}

export interface HuntClaimRecord {
  schemaVersion: typeof HUNT_CLAIM_SCHEMA_VERSION;
  /**
   * Content address of this RECORD — digest of (shape, statement, status,
   * evidence, dependsOn, worker). Identical work re-done yields an identical
   * id, which is how {@link readHuntLedger} makes a re-run idempotent. There is
   * deliberately no timestamp in the digested body: a clock would make every
   * re-run a new record and destroy that property. File order carries sequence.
   */
  id: string;
  /**
   * Content address of the CLAIM — digest of (shape, statement) only. Stable
   * across status transitions and across workers, so `unresolved` then
   * `disproven` are two records of one claim rather than two claims.
   */
  claimKey: string;
  shape: HuntClaimShape;
  statement: string;
  status: ClaimStatus;
  evidence: HuntEvidence[];
  dependsOn: string[];
  worker: string;
}

/** A `claimKey`'s full history collapsed to its current standing. */
export interface ResolvedHuntClaim {
  claimKey: string;
  shape: HuntClaimShape;
  statement: string;
  /** The most recent TERMINAL status in file order, or `unresolved` when none. */
  status: ClaimStatus;
  /**
   * True when this claim has been both `validated` and `disproven` in the
   * ledger. Kept as DATA rather than raised as an error — see
   * {@link resolveHuntLedger} for why a swarm must not let one worker's bad
   * record brick the campaign for everyone else.
   */
  conflicted: boolean;
  /** Every record for this claim, in file order. The audit trail. */
  records: HuntClaimRecord[];
  /** Union of `observation` evidence across every record, deduped. */
  observations: HuntEvidence[];
  /** Union of `assumption` evidence across every record, deduped. */
  assumptions: HuntEvidence[];
  /** Union of declared dependencies across every record. */
  dependsOn: string[];
}

// ── Bounds ───────────────────────────────────────────────────────────────────
//
// Every one of these caps a value written by a model into a file that other
// workers must parse on a hot path. Unbounded text here costs read time for
// every worker in the campaign, and a multi-megabyte line is also the case most
// likely to tear under a concurrent write.

export const MAX_CLAIM_STATEMENT_CHARS = 2_000;
export const MAX_EVIDENCE_STATEMENT_CHARS = 2_000;
export const MAX_LOCATOR_CHARS = 300;
export const MAX_EVIDENCE_PER_CLAIM = 32;
export const MAX_DEPENDENCIES_PER_CLAIM = 16;

const SHA256 = /^sha256:[0-9a-f]{64}$/;
/** Producer/worker ids: same conservative alphabet `proposal.ts` uses for `safeId`. */
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/;
const STANCES = new Set<EvidenceStance>(["observation", "assumption"]);
const STATUSES = new Set<ClaimStatus>(["unresolved", "validated", "disproven"]);
const TERMINAL: ReadonlySet<ClaimStatus> = new Set<ClaimStatus>(["validated", "disproven"]);

function text(value: unknown, label: string, max: number): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${label} must be a non-empty string`);
  }
  const trimmed = value.trim();
  if (trimmed.length > max) throw new Error(`${label} exceeds ${max} characters`);
  return trimmed;
}

function safeId(value: unknown, label: string): string {
  if (typeof value !== "string" || !SAFE_ID.test(value)) {
    throw new Error(`${label} must be a safe identifier`);
  }
  return value;
}

function digestValue(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a lowercase sha256 digest`);
  }
  return value;
}

/** Stable identity of one evidence entry, used to dedupe within and across records. */
function evidenceIdentity(evidence: HuntEvidence): string {
  return `${evidence.stance} ${evidence.source} ${evidence.locator ?? ""} ${evidence.statement}`;
}

function validateEvidence(value: unknown): HuntEvidence[] {
  if (!Array.isArray(value)) throw new Error("claim.evidence must be an array");
  if (value.length === 0) throw new Error("claim.evidence must not be empty");
  if (value.length > MAX_EVIDENCE_PER_CLAIM) {
    throw new Error(`claim.evidence exceeds ${MAX_EVIDENCE_PER_CLAIM} entries`);
  }
  const entries = value.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error(`claim.evidence[${index}] must be an object`);
    }
    const raw = item as Record<string, unknown>;
    if (!STANCES.has(raw.stance as EvidenceStance)) {
      throw new Error(`claim.evidence[${index}].stance must be "observation" or "assumption"`);
    }
    const stance = raw.stance as EvidenceStance;
    // The rule that keeps the stance label honest: an observation is a thing
    // another worker can go and re-check, so it must say WHERE. Without this an
    // "observation" is just an assumption with a confident tone.
    if (stance === "observation" && (raw.locator === undefined || raw.locator === null)) {
      throw new Error(`claim.evidence[${index}] is an observation and must carry a locator`);
    }
    return {
      stance,
      statement: text(raw.statement, `claim.evidence[${index}].statement`, MAX_EVIDENCE_STATEMENT_CHARS),
      source: safeId(raw.source, `claim.evidence[${index}].source`),
      ...(raw.locator === undefined || raw.locator === null
        ? {}
        : { locator: text(raw.locator, `claim.evidence[${index}].locator`, MAX_LOCATOR_CHARS) }),
    } satisfies HuntEvidence;
  });
  const seen = new Set<string>();
  return entries.filter((entry) => {
    const identity = evidenceIdentity(entry);
    if (seen.has(identity)) return false;
    seen.add(identity);
    return true;
  });
}

/**
 * The terminal-status rule, stated once: a claim may not be settled on
 * assumptions alone.
 *
 * This is the hunt-scale analogue of `proposal-replay.ts`'s independent-truth
 * -evidence requirement, calibrated to the evidence a hunt actually produces. A
 * skeptic that re-read the file and can cite the guard it found has made an
 * OBSERVATION and may refute. A skeptic that reasoned its way to "this is
 * probably unreachable" has made an ASSUMPTION and leaves the claim
 * `unresolved` — which is the correct outcome, because an assumption-only
 * refutation is exactly the record that would suppress a later worker's real
 * finding via the known-negative bridge.
 */
function validateClaimBody(status: ClaimStatus, evidence: readonly HuntEvidence[]): void {
  if (!TERMINAL.has(status)) return;
  if (!evidence.some((entry) => entry.stance === "observation")) {
    throw new Error(`${status} requires at least one observation (assumptions alone cannot settle a claim)`);
  }
}

/** Validate an input and stamp its content-addressed ids. Pure; performs no I/O. */
export function createHuntClaim(input: RecordHuntClaimInput): HuntClaimRecord {
  if (!STATUSES.has(input.status)) throw new Error("claim.status is unsupported");
  if (!input.shape || typeof input.shape !== "object") throw new Error("claim.shape must be an object");
  const shape: HuntClaimShape = {
    path: text(input.shape.path, "claim.shape.path", MAX_LOCATOR_CHARS),
    bugClass: text(input.shape.bugClass, "claim.shape.bugClass", MAX_LOCATOR_CHARS),
  };
  const statement = text(input.statement, "claim.statement", MAX_CLAIM_STATEMENT_CHARS);
  const evidence = validateEvidence(input.evidence);
  validateClaimBody(input.status, evidence);
  const dependsOn = [...new Set((input.dependsOn ?? []).map((d, i) => digestValue(d, `claim.dependsOn[${i}]`)))].sort();
  if (dependsOn.length > MAX_DEPENDENCIES_PER_CLAIM) {
    throw new Error(`claim.dependsOn exceeds ${MAX_DEPENDENCIES_PER_CLAIM} entries`);
  }
  const worker = safeId(input.worker, "claim.worker");
  // claimKey binds (shape, statement) only — the claim's identity has to
  // survive its own status changing, or a refutation would file itself under a
  // different key than the claim it refutes.
  const claimKey = proposalDigest({ shape, statement });
  const body = {
    schemaVersion: HUNT_CLAIM_SCHEMA_VERSION,
    claimKey,
    shape,
    statement,
    status: input.status,
    evidence,
    dependsOn,
    worker,
  } satisfies Omit<HuntClaimRecord, "id">;
  return { ...body, id: proposalDigest(body) };
}

/** Parse one on-disk record and verify its id still matches its content. */
export function validateHuntClaimRecord(value: unknown): HuntClaimRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("claim must be an object");
  }
  const raw = value as Record<string, unknown>;
  if (raw.schemaVersion !== HUNT_CLAIM_SCHEMA_VERSION) {
    throw new Error(`claim.schemaVersion must be ${HUNT_CLAIM_SCHEMA_VERSION}`);
  }
  if (!raw.shape || typeof raw.shape !== "object" || Array.isArray(raw.shape)) {
    throw new Error("claim.shape must be an object");
  }
  const shape = raw.shape as Record<string, unknown>;
  const record = createHuntClaim({
    shape: {
      path: text(shape.path, "claim.shape.path", MAX_LOCATOR_CHARS),
      bugClass: text(shape.bugClass, "claim.shape.bugClass", MAX_LOCATOR_CHARS),
    },
    statement: text(raw.statement, "claim.statement", MAX_CLAIM_STATEMENT_CHARS),
    status: raw.status as ClaimStatus,
    evidence: validateEvidence(raw.evidence),
    ...(Array.isArray(raw.dependsOn) ? { dependsOn: raw.dependsOn as string[] } : {}),
    worker: safeId(raw.worker, "claim.worker"),
  });
  if (digestValue(raw.id, "claim.id") !== record.id) {
    throw new Error("claim.id does not match its canonical content digest");
  }
  if (digestValue(raw.claimKey, "claim.claimKey") !== record.claimKey) {
    throw new Error("claim.claimKey does not match its canonical shape+statement digest");
  }
  return record;
}

/**
 * Append one claim record.
 *
 * Single `O_APPEND|O_CREAT|O_NOFOLLOW` open, one `writeFileSync` of one JSONL
 * line, then close. O_APPEND makes the kernel place the write at the current
 * end of file atomically with respect to other appenders, so two workers never
 * clobber each other's offset; one write syscall per small record keeps records
 * from byte-interleaving. `O_NOFOLLOW` refuses a symlinked ledger path — same
 * guard `proposal-replay.ts` uses, for the same reason (a ledger path is often
 * operator-supplied).
 *
 * Deliberately does NOT read the file first. See this module's header: the
 * read-validate-append pattern is quadratic across a campaign and racy across
 * processes, so duplicate suppression lives in {@link readHuntLedger} instead.
 */
export function appendHuntClaim(path: string, input: RecordHuntClaimInput | HuntClaimRecord): HuntClaimRecord {
  const record = "id" in input ? validateHuntClaimRecord(input) : createHuntClaim(input);
  try {
    if (lstatSync(path).isSymbolicLink()) {
      throw new Error("hunt evidence ledger path must not be a symbolic link");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  mkdirSync(dirname(path), { recursive: true });
  // canonicalProposalJson is pretty-printed; re-serialize compactly so one
  // record is exactly one line (JSONL) while keeping the canonical key order
  // that makes the digest reproducible.
  const line = `${JSON.stringify(JSON.parse(canonicalProposalJson(record)))}\n`;
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
  return record;
}

export interface ReadHuntLedgerOptions {
  /**
   * Called once per line that could not be parsed or validated. Optional
   * because the default behaviour is to SKIP such a line, not throw.
   */
  onMalformed?: (line: string, reason: string) => void;
}

/**
 * Read the ledger: tolerant, deduped, in file order.
 *
 * Two behaviours are deliberate and both are about not letting one worker
 * damage the campaign:
 *
 *  - A malformed line is SKIPPED, not thrown (the discipline
 *    `loadHuntCorpusRows` in hunt-flywheel.ts already established). A worker
 *    killed mid-write can leave a torn final line; one torn line must not
 *    blind every other worker to every prior record.
 *  - Records are deduped by their content-addressed `id`, first occurrence
 *    wins. This is what makes a re-run idempotent at the semantic level even
 *    though the file physically grew — see the header for why dedupe is a
 *    read-time property here.
 *
 * A missing file is an empty ledger, not an error: workers routinely start
 * before anything has been written.
 */
export function readHuntLedger(path: string, opts: ReadHuntLedgerOptions = {}): HuntClaimRecord[] {
  try {
    if (lstatSync(path).isSymbolicLink()) {
      throw new Error("hunt evidence ledger path must not be a symbolic link");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  const seen = new Set<string>();
  const records: HuntClaimRecord[] = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (trimmed === "") continue;
    let record: HuntClaimRecord;
    try {
      record = validateHuntClaimRecord(JSON.parse(trimmed) as unknown);
    } catch (error) {
      opts.onMalformed?.(trimmed, String((error as Error).message ?? error));
      continue;
    }
    if (seen.has(record.id)) continue;
    seen.add(record.id);
    records.push(record);
  }
  return records;
}

/**
 * Collapse records into one entry per `claimKey`.
 *
 * Conflict handling is the interesting part. `proposal-replay.ts:264` THROWS
 * when one proposal carries contradictory terminal labels, which is right for a
 * curated research replay written by one loop. Here it would be a footgun: a
 * ledger is written concurrently by many workers, so a single bad terminal
 * record would make every subsequent `readHuntLedger` throw and take the whole
 * campaign's shared memory down with it. Instead the contradiction is recorded
 * as {@link ResolvedHuntClaim.conflicted} and BOTH records are retained.
 *
 * The operational rule that follows: a conflicted claim is never treated as a
 * known negative ({@link disprovenHuntClaims} excludes it). Two workers
 * disagreeing is a reason to look harder, not a reason to suppress the next
 * worker who looks.
 */
export function resolveHuntLedger(records: readonly HuntClaimRecord[]): Map<string, ResolvedHuntClaim> {
  const resolved = new Map<string, ResolvedHuntClaim>();
  const terminalSeen = new Map<string, Set<ClaimStatus>>();
  for (const record of records) {
    let entry = resolved.get(record.claimKey);
    if (!entry) {
      entry = {
        claimKey: record.claimKey,
        shape: record.shape,
        statement: record.statement,
        status: "unresolved",
        conflicted: false,
        records: [],
        observations: [],
        assumptions: [],
        dependsOn: [],
      };
      resolved.set(record.claimKey, entry);
      terminalSeen.set(record.claimKey, new Set());
    }
    entry.records.push(record);
    for (const evidence of record.evidence) {
      const bucket = evidence.stance === "observation" ? entry.observations : entry.assumptions;
      if (!bucket.some((existing) => evidenceIdentity(existing) === evidenceIdentity(evidence))) {
        bucket.push(evidence);
      }
    }
    for (const dep of record.dependsOn) if (!entry.dependsOn.includes(dep)) entry.dependsOn.push(dep);
    if (TERMINAL.has(record.status)) {
      // Latest terminal status in file order wins: a claim that was disproven
      // and then validated on new evidence is validated.
      entry.status = record.status;
      const seen = terminalSeen.get(record.claimKey)!;
      seen.add(record.status);
      if (seen.size > 1) entry.conflicted = true;
    }
  }
  return resolved;
}

/** Convenience: read + resolve in one call. */
export function loadHuntLedger(path: string, opts: ReadHuntLedgerOptions = {}): Map<string, ResolvedHuntClaim> {
  return resolveHuntLedger(readHuntLedger(path, opts));
}

/**
 * The dead ends — `disproven` and not contradicted. This is the set a worker
 * consults before spending a finder or a skeptic call on a shape someone
 * already killed.
 */
export function disprovenHuntClaims(resolved: ReadonlyMap<string, ResolvedHuntClaim>): ResolvedHuntClaim[] {
  return [...resolved.values()].filter((claim) => claim.status === "disproven" && !claim.conflicted);
}

/** Claims still open — nothing terminal, or terminal-but-contradicted. */
export function unresolvedHuntClaims(resolved: ReadonlyMap<string, ResolvedHuntClaim>): ResolvedHuntClaim[] {
  return [...resolved.values()].filter((claim) => claim.status === "unresolved" || claim.conflicted);
}

/**
 * Claims that rest, transitively, on a claim that has since been disproven.
 *
 * This is why `dependsOn` is stored rather than merely being prose in the
 * statement: in a swarm the expensive failure is not one wrong claim, it is the
 * three claims built on top of it that nobody revisited. A stale claim is not
 * automatically wrong — its own evidence may still stand — but it is the queue
 * a campaign should re-examine first when a foundation collapses.
 *
 * Cycle-safe: `dependsOn` is operator/model-supplied and can contain a loop, so
 * the walk tracks visited keys rather than trusting the graph to be acyclic.
 */
export function staleHuntClaims(resolved: ReadonlyMap<string, ResolvedHuntClaim>): ResolvedHuntClaim[] {
  const disproven = new Set(disprovenHuntClaims(resolved).map((claim) => claim.claimKey));
  if (disproven.size === 0) return [];
  const stale: ResolvedHuntClaim[] = [];
  for (const claim of resolved.values()) {
    if (disproven.has(claim.claimKey)) continue;
    const visited = new Set<string>([claim.claimKey]);
    const queue = [...claim.dependsOn];
    let hit = false;
    while (queue.length > 0 && !hit) {
      const key = queue.shift()!;
      if (visited.has(key)) continue;
      visited.add(key);
      if (disproven.has(key)) {
        hit = true;
        break;
      }
      const dep = resolved.get(key);
      if (dep) queue.push(...dep.dependsOn);
    }
    if (hit) stale.push(claim);
  }
  return stale;
}
