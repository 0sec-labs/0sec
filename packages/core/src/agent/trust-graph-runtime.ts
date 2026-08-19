/**
 * Trust-graph loop wiring (0sec#771, connects #786 + #780).
 *
 * This is the OPT-IN bridge that connects the durable
 * {@link PersistentCredentialStore} (credential-store.ts, #786) and the
 * `credential_shared` journal kind (journal/credential-shared.ts, #780) into the
 * single-scan native agent loop (native-loop.ts).
 *
 * Design contract — the whole point of this module:
 *
 *   The native loop's default, single-scan behaviour MUST be byte-identical to
 *   before. Every durable-store interaction is gated on an OPTIONAL
 *   `trustGraph` config block. When that block is absent the loop never
 *   constructs a {@link TrustGraphSession}, so there is zero new I/O and zero
 *   behaviour change. This is asserted by a test that runs the loop with no
 *   `trustGraph` config and proves the store receives zero calls.
 *
 * When the block IS present, a {@link TrustGraphSession} owns three additive
 * behaviours, each a thin call into the already-tested #786/#780 surface:
 *
 *   1. {@link TrustGraphSession.renderPriorFootholds} — at loop start, render
 *      prior-scan footholds for this target (hash + redacted preview only) to
 *      inject alongside the normal in-scan loot render.
 *   2. {@link TrustGraphSession.persist} — when loot is harvested / on loop
 *      completion, persist newly-found credentials (hash + preview only; the
 *      plaintext never leaves the in-memory ledger).
 *   3. {@link TrustGraphSession.noteHarvest} — when a harvested value's hash
 *      matches a credential a PRIOR scan recovered from a DIFFERENT source
 *      target, that's a cross-target reuse: emit a `credential_shared` journal
 *      entry (source target, dest target, kind, originating finding).
 *
 * The store is referenced through the structural {@link CredentialStoreLike}
 * interface (a subset of {@link PersistentCredentialStore}) so tests can inject
 * a spy double and assert exact call counts without a real DB.
 */

import type { LootLedger, LootItem } from "./loot.js";
import { hashCredentialValue } from "./credential-store.js";
import {
  appendCredentialShared,
  type CredentialSharedSink,
} from "./journal/credential-shared.js";

/** Row shape returned by the store's `list`. Subset of `PersistentCredentialRow`. */
export interface PriorCredentialRow {
  credentialKind: string;
  valueHash: string;
  /** Source target the credential was originally recovered from. */
  target: string | null;
  /** Finding that first surfaced the credential. */
  firstFindingId: string | null;
}

/**
 * Structural subset of {@link PersistentCredentialStore} that the loop wiring
 * needs. Declared here (not imported as the class) so a test can pass a spy
 * double and assert call counts; the real store satisfies it by shape.
 */
export interface CredentialStoreLike {
  list(opts?: { target?: string; limit?: number }): PriorCredentialRow[];
  renderPriorFootholds(opts?: { target?: string; limit?: number }): string;
  saveLedger(
    ledger: LootLedger,
    attribution?: { target?: string | null; scanId?: string | null; findingId?: string | null },
  ): number;
}

/**
 * Optional `trustGraph` config block on {@link NativeAgentConfig}. ABSENT by
 * default → the loop behaves exactly as today (no store, no new I/O).
 */
export interface TrustGraphConfig {
  /** Durable cross-scan credential store (#786). */
  store: CredentialStoreLike;
  /**
   * Stable identifier for THIS scan's target in trust-graph terms — the
   * `sourceTarget`/`destTarget` boundary used to decide whether a matched prior
   * credential is a cross-target reuse. Defaults to `config.target` when unset.
   */
  sourceTargetId?: string;
  /**
   * Sink for `credential_shared` journal entries (#780). Defaults to the loop's
   * shadow journal when omitted. Tests inject a capturing double.
   */
  journalSink?: CredentialSharedSink;
}

/**
 * Per-run trust-graph session. Constructed ONLY when `config.trustGraph` is set
 * (see {@link maybeCreateTrustGraphSession}). Owns the prior-credential index
 * loaded once at loop start and the dedup set for `credential_shared` emits.
 */
export class TrustGraphSession {
  private readonly store: CredentialStoreLike;
  private readonly sourceTargetId: string;
  private readonly journalSink: CredentialSharedSink;
  /** valueHash → prior row, for cross-target reuse detection. */
  private readonly priorByHash = new Map<string, PriorCredentialRow>();
  /** valueHashes already emitted as credential_shared, to emit at most once. */
  private readonly emitted = new Set<string>();

  constructor(opts: {
    store: CredentialStoreLike;
    sourceTargetId: string;
    journalSink: CredentialSharedSink;
    priorRows: PriorCredentialRow[];
  }) {
    this.store = opts.store;
    this.sourceTargetId = opts.sourceTargetId;
    this.journalSink = opts.journalSink;
    for (const row of opts.priorRows) {
      // First write wins — a value seen on multiple prior targets keeps the
      // earliest attribution, which is what the credential_shared edge wants.
      if (!this.priorByHash.has(row.valueHash)) this.priorByHash.set(row.valueHash, row);
    }
  }

  /** Number of prior-scan credentials loaded (for telemetry/tests). */
  get priorCount(): number {
    return this.priorByHash.size;
  }

  /**
   * Secret-free "footholds from prior scans" block to inject at loop start
   * alongside the normal loot render. "" when there's nothing to show.
   */
  renderPriorFootholds(target: string): string {
    return this.store.renderPriorFootholds({ target });
  }

  /**
   * Inspect newly-harvested loot items. For each whose hash matches a prior
   * scan's credential recovered from a DIFFERENT source target, emit a
   * `credential_shared` journal entry (at most once per value). Returns the
   * number of entries emitted (0 in the common case). Pure aside from the
   * journal append; never throws into the loop (caller wraps in try/catch).
   */
  noteHarvest(newItems: readonly LootItem[], turn?: number): number {
    let emittedCount = 0;
    for (const item of newItems) {
      const hash = hashCredentialValue(item.value);
      if (this.emitted.has(hash)) continue;
      const prior = this.priorByHash.get(hash);
      if (!prior) continue;
      const priorTarget = (prior.target ?? "").trim();
      // Reuse only counts across a target boundary. Same-target re-discovery is
      // just the same scan-lineage seeing its own credential again.
      if (!priorTarget || priorTarget === this.sourceTargetId) continue;
      this.emitted.add(hash);
      appendCredentialShared(this.journalSink, {
        sourceTarget: priorTarget,
        destTarget: this.sourceTargetId,
        credentialKind: prior.credentialKind || item.kind,
        originatingFindingId: prior.firstFindingId || "unknown",
        rationale: `Credential ${item.kind} recovered on ${priorTarget} reused against ${this.sourceTargetId}`,
        ...(turn !== undefined ? { turn } : {}),
      });
      emittedCount += 1;
    }
    return emittedCount;
  }

  /**
   * Persist the in-memory ledger to the durable store (hash + preview only).
   * Returns the number of items persisted. Used on loop completion (and may be
   * called incrementally; the store upsert is idempotent).
   */
  persist(ledger: LootLedger, attribution: { target: string; scanId: string }): number {
    return this.store.saveLedger(ledger, attribution);
  }
}

/**
 * Construct a {@link TrustGraphSession} iff `trustGraph` config is present.
 * Returns `undefined` when absent — the loop then takes its exact pre-existing
 * path (no store, no I/O, byte-identical behaviour).
 *
 * `defaultJournalSink` is the loop's shadow journal, used when the config
 * doesn't override the sink.
 */
export function maybeCreateTrustGraphSession(
  trustGraph: TrustGraphConfig | undefined,
  opts: { target: string; defaultJournalSink: CredentialSharedSink },
): TrustGraphSession | undefined {
  if (!trustGraph) return undefined;
  const sourceTargetId = trustGraph.sourceTargetId ?? opts.target;
  const journalSink = trustGraph.journalSink ?? opts.defaultJournalSink;
  // Load prior footholds ONCE at construction so the per-turn hot path only
  // touches the in-memory index, not the DB.
  const priorRows = trustGraph.store.list({ target: opts.target });
  return new TrustGraphSession({
    store: trustGraph.store,
    sourceTargetId,
    journalSink,
    priorRows,
  });
}
