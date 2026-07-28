/**
 * Strict reader for a {@link ConstructRequest.params} bag.
 *
 * The strictness is the feature. These params arrive from an LLM's tool call,
 * i.e. from a producer that will occasionally emit `with` for `width`,
 * `bit_depth` for `bitDepth`, or a string `"8"` where a number belongs. A
 * lenient reader turns each of those into a *silently defaulted* field, and the
 * agent then submits a file it believes it parameterised and did not. In a
 * stage whose graded budget is measured in single digits, an input that looks
 * built-to-spec and isn't is the most expensive failure available.
 *
 * So: unknown keys are an error, wrong types are an error, out-of-range values
 * are an error, and every message names the offending key and the accepted
 * shape so the agent can fix it in one turn rather than three.
 */

import { fromHex } from "./binary.js";

/** Thrown internally by the readers; plugins convert it to a `ConstructErr`. */
export class ParamError extends Error {}

export class ParamReader {
  private readonly bag: Record<string, unknown>;
  private readonly seen = new Set<string>();

  constructor(params: Record<string, unknown> | undefined) {
    this.bag = params ?? {};
  }

  /** Present (and not `undefined`/`null`) in the bag. */
  has(key: string): boolean {
    const v = this.bag[key];
    this.seen.add(key);
    return v !== undefined && v !== null;
  }

  /** Integer in `[min, max]`, or `fallback` when absent. */
  int(key: string, fallback: number, min: number, max: number): number {
    this.seen.add(key);
    const v = this.bag[key];
    if (v === undefined || v === null) return fallback;
    if (typeof v !== "number" || !Number.isInteger(v)) {
      throw new ParamError(`\`${key}\` must be an integer (got ${JSON.stringify(v)})`);
    }
    if (v < min || v > max) {
      throw new ParamError(`\`${key}\` must be in [${min}, ${max}] (got ${v})`);
    }
    return v;
  }

  /** Boolean, or `fallback` when absent. */
  bool(key: string, fallback: boolean): boolean {
    this.seen.add(key);
    const v = this.bag[key];
    if (v === undefined || v === null) return fallback;
    if (typeof v !== "boolean") throw new ParamError(`\`${key}\` must be true or false (got ${JSON.stringify(v)})`);
    return v;
  }

  /** String, or `fallback` when absent. */
  str(key: string, fallback: string): string {
    this.seen.add(key);
    const v = this.bag[key];
    if (v === undefined || v === null) return fallback;
    if (typeof v !== "string") throw new ParamError(`\`${key}\` must be a string (got ${JSON.stringify(v)})`);
    return v;
  }

  /**
   * Bytes from a hex string. Hex rather than base64 because hex is what the
   * agent is already reading in sanitizer traces and `xxd` output, and a
   * transcription error in hex is visible where one in base64 is not.
   */
  hex(key: string, fallback: Uint8Array): Uint8Array {
    this.seen.add(key);
    const v = this.bag[key];
    if (v === undefined || v === null) return fallback;
    if (typeof v !== "string") throw new ParamError(`\`${key}\` must be a hex string (got ${JSON.stringify(v)})`);
    const bytes = fromHex(v);
    if (!bytes) throw new ParamError(`\`${key}\` is not valid hex: ${JSON.stringify(v.slice(0, 48))}`);
    return bytes;
  }

  /** Array of plain objects, or `[]` when absent. */
  objects(key: string): Record<string, unknown>[] {
    this.seen.add(key);
    const v = this.bag[key];
    if (v === undefined || v === null) return [];
    if (!Array.isArray(v)) throw new ParamError(`\`${key}\` must be an array of objects`);
    return v.map((item, i) => {
      if (typeof item !== "object" || item === null || Array.isArray(item)) {
        throw new ParamError(`\`${key}[${i}]\` must be an object`);
      }
      return item as Record<string, unknown>;
    });
  }

  /**
   * Fail if the caller passed a key no reader touched. Call this LAST, after
   * every field has been read, so `seen` is complete.
   */
  rejectUnknown(help: string): void {
    const unknown = Object.keys(this.bag).filter((k) => !this.seen.has(k));
    if (unknown.length > 0) {
      throw new ParamError(
        `unknown param${unknown.length > 1 ? "s" : ""} ${unknown.map((k) => `\`${k}\``).join(", ")}. ${help}`,
      );
    }
  }
}

/** Run `fn`, converting a {@link ParamError} into the plugin's error string. */
export function withParams<T>(fn: () => T): { ok: true; value: T } | { ok: false; error: string } {
  try {
    return { ok: true, value: fn() };
  } catch (e) {
    if (e instanceof ParamError) return { ok: false, error: e.message };
    throw e;
  }
}
