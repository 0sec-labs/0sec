/**
 * MongoDB ObjectID forge.
 *
 * A MongoDB ObjectId is 12 bytes (24 hex chars):
 *   • 4 bytes — timestamp in seconds since the Unix epoch (big-endian)
 *   • 5 bytes — random "machine ID" (per-process value, stable across the
 *               objects produced by a single MongoDB driver instance)
 *   • 3 bytes — counter (big-endian, monotonically incrementing per process)
 *
 * This module exposes pure helpers to compute (forge), parse, and enumerate
 * ObjectIds without pulling in the MongoDB driver. The primary use case is
 * IDOR challenges (e.g. XBEN-099) where the agent observes one ObjectId in
 * traffic, copies the 5-byte machine ID, and then forges the "first user"
 * ObjectId by setting the timestamp to `appStartTimestamp` and the counter
 * to 0 (or 1, 2, ...).
 */

const HEX_RE = /^[0-9a-fA-F]+$/;
const MAX_TIMESTAMP = 0xffffffff; // 4 bytes
const MAX_COUNTER = 0xffffff; // 3 bytes

export interface ForgeObjectIdOptions {
  /** Unix timestamp in seconds (4-byte big-endian prefix). */
  timestamp: number;
  /** 5-byte machine ID as a 10-char hex string. */
  machineId: string;
  /** 3-byte counter (0..16777215, big-endian). */
  counter: number;
}

export interface ParsedObjectId {
  timestamp: number;
  machineId: string;
  counter: number;
}

export interface ForgeObjectIdSequenceOptions {
  timestamp: number;
  machineId: string;
  counterStart: number;
  count: number;
}

/**
 * Compute a MongoDB ObjectID from its three components.
 *
 * @returns 24-char lowercase hex string (canonical ObjectId representation).
 */
export function forgeObjectId(opts: ForgeObjectIdOptions): string {
  const { timestamp, machineId, counter } = opts;

  if (!Number.isInteger(timestamp)) {
    throw new Error(`forgeObjectId: timestamp must be an integer, got ${timestamp}`);
  }
  if (timestamp < 0 || timestamp > MAX_TIMESTAMP) {
    throw new Error(
      `forgeObjectId: timestamp ${timestamp} out of 4-byte range [0, ${MAX_TIMESTAMP}]`,
    );
  }
  if (typeof machineId !== "string" || machineId.length !== 10 || !HEX_RE.test(machineId)) {
    throw new Error(
      `forgeObjectId: machineId must be a 10-char hex string, got ${JSON.stringify(machineId)}`,
    );
  }
  if (!Number.isInteger(counter)) {
    throw new Error(`forgeObjectId: counter must be an integer, got ${counter}`);
  }
  if (counter < 0 || counter > MAX_COUNTER) {
    throw new Error(
      `forgeObjectId: counter ${counter} out of 3-byte range [0, ${MAX_COUNTER}]`,
    );
  }

  const tsHex = timestamp.toString(16).padStart(8, "0");
  const counterHex = counter.toString(16).padStart(6, "0");
  return (tsHex + machineId.toLowerCase() + counterHex).toLowerCase();
}

/**
 * Parse a 24-char hex ObjectId into its (timestamp, machineId, counter) parts.
 * Useful for extracting the machine ID from an observed ObjectId so you can
 * forge sibling IDs at arbitrary timestamps/counters.
 */
export function parseObjectId(hex: string): ParsedObjectId {
  if (typeof hex !== "string") {
    throw new Error(`parseObjectId: input must be a string, got ${typeof hex}`);
  }
  if (hex.length !== 24) {
    throw new Error(
      `parseObjectId: ObjectId must be 24 hex chars, got length ${hex.length}`,
    );
  }
  if (!HEX_RE.test(hex)) {
    throw new Error(`parseObjectId: ObjectId must be hex, got ${JSON.stringify(hex)}`);
  }

  const lower = hex.toLowerCase();
  const timestamp = parseInt(lower.slice(0, 8), 16);
  const machineId = lower.slice(8, 18);
  const counter = parseInt(lower.slice(18, 24), 16);

  return { timestamp, machineId, counter };
}

/**
 * Generate a sequence of N forged ObjectIds with monotonically increasing
 * counters starting at `counterStart`. Returns an array of 24-char hex
 * strings. Used to enumerate "the first N possible users."
 */
export function forgeObjectIdSequence(opts: ForgeObjectIdSequenceOptions): string[] {
  const { timestamp, machineId, counterStart, count } = opts;

  if (!Number.isInteger(count) || count < 0) {
    throw new Error(`forgeObjectIdSequence: count must be a non-negative integer, got ${count}`);
  }
  if (count > MAX_COUNTER + 1) {
    throw new Error(
      `forgeObjectIdSequence: count ${count} exceeds 3-byte counter space (${MAX_COUNTER + 1})`,
    );
  }
  if (!Number.isInteger(counterStart) || counterStart < 0) {
    throw new Error(
      `forgeObjectIdSequence: counterStart must be a non-negative integer, got ${counterStart}`,
    );
  }
  if (counterStart + count - 1 > MAX_COUNTER) {
    throw new Error(
      `forgeObjectIdSequence: counter overflow — counterStart=${counterStart} + count=${count} would exceed ${MAX_COUNTER}`,
    );
  }

  const out: string[] = new Array(count);
  for (let i = 0; i < count; i++) {
    out[i] = forgeObjectId({ timestamp, machineId, counter: counterStart + i });
  }
  return out;
}
