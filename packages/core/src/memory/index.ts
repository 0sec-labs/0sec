/**
 * memory/ — persistent, cross-session hunt memory.
 *
 * A pattern DB so learnings from one target inform the next. See
 * {@link HuntMemoryStore} for the API. This barrel is intentionally scoped to
 * the memory submodule; the top-level package barrel is wired separately.
 */
export {
  HuntMemoryStore,
  huntMemoryPath,
  redactSecrets,
  HUNT_MEMORY_SCHEMA_VERSION,
  HUNT_REDACTED,
} from "./hunt-memory.js";
export type {
  HuntRecord,
  HuntRecordInput,
  HuntRecordKind,
  HuntSeverity,
  HuntQuery,
  HuntStats,
  HuntMemoryOptions,
} from "./hunt-memory.js";
