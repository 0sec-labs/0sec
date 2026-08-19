/**
 * Helper for the `credential_shared` journal kind (#773).
 *
 * Records a trust edge: a foothold recovered on one target reused across a
 * target boundary against another. Kept in its own small module so the
 * cross-target emit call-site has a single typed entry point and so the kind's
 * required fields are validated in one place rather than re-spelled at every
 * append site.
 */

import type { JournalEntry, JournalEntryInput } from "./types.js";

/** Anything with an `append` that takes a `JournalEntryInput` — the real
 *  `JournalWriter`, the shadow journal, or a test double. */
export interface CredentialSharedSink {
  append(entry: JournalEntryInput): JournalEntry | void;
}

export interface CredentialSharedRecord {
  /** Target the credential was originally recovered from. */
  sourceTarget: string;
  /** Target the credential was reused against. */
  destTarget: string;
  /** Kind of foothold reused (e.g. "password", "ssh_key", "api_token"). */
  credentialKind: string;
  /** Id of the finding that first surfaced the credential. */
  originatingFindingId: string;
  /** Optional human-readable explanation of the trust edge. */
  rationale?: string;
  /** Originating loop turn, when known. */
  turn?: number;
}

/**
 * Build a `credential_shared` journal entry input. Pure: no I/O. Validates
 * that the four chain-attribution fields are non-empty so a malformed trust
 * edge never reaches the journal.
 */
export function buildCredentialSharedEntry(record: CredentialSharedRecord): JournalEntryInput {
  const sourceTarget = record.sourceTarget.trim();
  const destTarget = record.destTarget.trim();
  const credentialKind = record.credentialKind.trim();
  const originatingFindingId = record.originatingFindingId.trim();

  if (!sourceTarget) throw new Error("credential_shared: sourceTarget is required");
  if (!destTarget) throw new Error("credential_shared: destTarget is required");
  if (!credentialKind) throw new Error("credential_shared: credentialKind is required");
  if (!originatingFindingId) throw new Error("credential_shared: originatingFindingId is required");

  return {
    kind: "credential_shared",
    sourceTarget,
    destTarget,
    credentialKind,
    originatingFindingId,
    ...(record.rationale ? { rationale: record.rationale } : {}),
    ...(record.turn !== undefined ? { turn: record.turn } : {}),
  };
}

/**
 * Append a `credential_shared` entry to a journal/shadow sink. Thin wrapper
 * around {@link buildCredentialSharedEntry} so the eventual cross-target emit
 * loop calls one helper instead of re-constructing the entry shape inline.
 */
export function appendCredentialShared(
  sink: CredentialSharedSink,
  record: CredentialSharedRecord,
): void {
  sink.append(buildCredentialSharedEntry(record));
}
