import { JOURNAL_SCHEMA_VERSION, type JournalEntry } from "./types.js";

export function migrateJournalEntry(raw: unknown): JournalEntry {
  if (!raw || typeof raw !== "object") {
    throw new Error("Invalid journal entry: expected object");
  }

  const entry = raw as { schemaVersion?: unknown; kind?: unknown };
  if (entry.schemaVersion === JOURNAL_SCHEMA_VERSION) {
    return raw as JournalEntry;
  }

  throw new Error(`Unsupported journal entry schema version: ${String(entry.schemaVersion)}`);
}
