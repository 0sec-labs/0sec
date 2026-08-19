/**
 * PersistentCredentialStore (pwnkit#771, extends #687).
 *
 * The in-memory {@link LootLedger} (loot.ts) is single-scan: every foothold it
 * harvests evaporates when the scan ends. This store is the durable companion —
 * a thin, security-conscious bridge between a `LootLedger` and the `@pwnkit/db`
 * `persistent_credentials` / `trust_graph_edges` tables. It lets footholds
 * harvested in one scan persist and be re-surfaced to a later scan against the
 * same target.
 *
 * Security invariant (issue acceptance criterion): the plaintext secret NEVER
 * leaves this process boundary into durable storage or logs. We persist only a
 * SHA-256 `valueHash` (the dedup/lookup key) and a short, redacted
 * `valuePreview` for human/agent recognition. The full value stays in the
 * in-memory ledger for the lifetime of the scan and is discarded with it.
 *
 * This is a FIRST SLICE (pwnkit#771): the load/save APIs and the durable schema
 * exist and are unit-tested, but the native agent loop is only stubbed to call
 * them (see native-loop.ts TODO). The loop wiring is deliberately not rewritten
 * here.
 */

import { createHash } from "node:crypto";
import type {
  pwnkitDB,
  PersistentCredentialRow,
  CredentialKindDB,
} from "@pwnkit/db";
import type { LootKind, LootItem } from "./loot.js";
import { LootLedger } from "./loot.js";

/** How many leading chars of a value survive into the (redacted) preview. */
const PREVIEW_PREFIX_LEN = 6;
/** Hard cap on rows synced from the DB back into a ledger in one load. */
const DEFAULT_LOAD_LIMIT = 200;

/**
 * SHA-256 of a loot value, normalized the same way LootLedger dedups
 * (trimmed + lowercased) so the same secret hashes identically regardless of
 * which scan captured it.
 */
export function hashCredentialValue(value: string): string {
  return createHash("sha256").update(value.trim().toLowerCase(), "utf8").digest("hex");
}

/**
 * Redacted, non-secret preview of a value. Shows a short prefix and the length
 * so an operator/agent can recognise a known foothold without the plaintext
 * ever being persisted or logged. e.g. `admin:…(12)`.
 */
export function previewCredentialValue(value: string): string {
  const v = value.trim();
  if (v.length <= PREVIEW_PREFIX_LEN) {
    // Very short values: still don't echo the whole thing verbatim in a way
    // that reads as "the secret"; mark the length instead.
    return `${v.slice(0, Math.min(2, v.length))}…(${v.length})`;
  }
  return `${v.slice(0, PREVIEW_PREFIX_LEN)}…(${v.length})`;
}

/** Attribution context passed when syncing a ledger into the store. */
export interface CredentialAttribution {
  target?: string | null;
  scanId?: string | null;
  findingId?: string | null;
}

/**
 * Durable credential store backed by `@pwnkit/db`. Constructed with a live
 * `pwnkitDB`; all hashing/redaction happens here so the db layer never sees a
 * plaintext secret.
 */
export class PersistentCredentialStore {
  constructor(private readonly db: pwnkitDB) {}

  /**
   * Persist a single loot item. Returns the stored (secret-free) row. The
   * plaintext `item.value` is hashed + previewed here and discarded; only the
   * derived representations are handed to the db.
   */
  save(item: LootItem, attribution: CredentialAttribution = {}): PersistentCredentialRow {
    return this.db.upsertPersistentCredential({
      credentialKind: item.kind,
      valueHash: hashCredentialValue(item.value),
      valuePreview: previewCredentialValue(item.value),
      context: item.context ?? null,
      target: attribution.target ?? null,
      scanId: attribution.scanId ?? null,
      findingId: attribution.findingId ?? null,
      source: item.source ?? null,
      turn: item.turn ?? null,
    });
  }

  /**
   * Sync an entire LootLedger into durable storage. Idempotent: re-saving a
   * value already present bumps its `timesSeen` instead of duplicating. Returns
   * the number of items persisted (attempted).
   */
  saveLedger(ledger: LootLedger, attribution: CredentialAttribution = {}): number {
    let count = 0;
    for (const item of ledger.all()) {
      this.save(item, attribution);
      count += 1;
    }
    return count;
  }

  /**
   * Read back persisted credential rows (secret-free) — for a later scan to
   * see what earlier scans discovered. Optionally filter by target/kind.
   */
  list(opts: { target?: string; kind?: CredentialKindDB; limit?: number } = {}): PersistentCredentialRow[] {
    return this.db.listPersistentCredentials({
      target: opts.target,
      credentialKind: opts.kind,
      limit: opts.limit ?? DEFAULT_LOAD_LIMIT,
    });
  }

  /**
   * Render a compact, secret-free "known footholds from prior scans" block for
   * injection into a later scan's context. Mirrors LootLedger.render() shape
   * but uses only previews (the plaintext is not available cross-scan — the
   * agent must re-harvest or re-derive the actual value).
   *
   * Returns "" when there's nothing to show.
   */
  renderPriorFootholds(opts: { target?: string; limit?: number } = {}): string {
    const rows = this.list({ target: opts.target, limit: opts.limit ?? 12 });
    if (rows.length === 0) return "";
    const lines = rows.map((r) => {
      const ctx = r.context ? ` — ${r.context}` : "";
      const where = r.target ? ` (target ${r.target})` : "";
      return `- ${r.credentialKind}: ${r.valuePreview}${ctx}${where} [seen ${r.timesSeen}×]`;
    });
    return [
      "## Footholds from prior scans (persistent credential store)",
      "These hashes/previews were captured against this target in earlier scans.",
      "The plaintext is not carried across scans — re-harvest or re-derive the",
      "value if you need to reuse it.",
      ...lines,
    ].join("\n");
  }

  /**
   * Record a directed trust edge (e.g. a credential authenticates_to a host).
   * Convenience pass-through to the db layer so callers can keep both halves of
   * the #771 surface (`persistent_credentials` + `trust_graph_edges`) in one
   * place. `srcId` for a credential edge is conventionally its `valueHash`.
   */
  addTrustEdge(edge: {
    srcKind: string;
    srcId: string;
    dstKind: string;
    dstId: string;
    relation: string;
    scanId?: string | null;
    findingId?: string | null;
    confidence?: number | null;
    note?: string | null;
  }) {
    return this.db.upsertTrustGraphEdge(edge);
  }
}

/** Loot kinds that are credential-like. Currently all LootKind values map 1:1. */
export const CREDENTIAL_LOOT_KINDS: readonly LootKind[] = [
  "credential",
  "token",
  "path",
  "endpoint",
  "hash",
  "cookie",
];
