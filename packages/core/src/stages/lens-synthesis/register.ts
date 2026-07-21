/**
 * Lens-synthesis stage 4 — REGISTER.
 *
 * Append ONE validated champion to the appsec registry JSON via a safe writer
 * that (1) preserves the top-level `provenance` and every existing archetype,
 * (2) is IDEMPOTENT on `id` (a re-run with the same id is a no-op, never a
 * duplicate), (3) re-validates the archetype schema before writing (fail-closed
 * — a malformed candidate is refused), and (4) writes atomically (temp file +
 * rename) so a crash mid-write never leaves a truncated registry.
 *
 * This is the only stage that mutates the engine's own detector registry, so it
 * refuses to write anything that isn't a schema-valid, cross-language,
 * appsec-source-static archetype carrying synthesis provenance.
 */

import { readFileSync, renameSync, writeFileSync, unlinkSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import {
  appsecArchetypesPath,
  type RawAppsecArchetype,
} from "../appsec-catalog.js";
import { isCrossLanguageHint } from "./synthesize.js";
import type { RegisteredLens, SynthesizedArchetype } from "./types.js";

interface RegistryFile {
  provenance: string;
  archetypes: RawAppsecArchetype[];
}

const KEBAB_ID = /^[a-z0-9][a-z0-9-]{1,63}$/;
const CWE_CODE = /CWE-\d+/;

function readRegistry(path: string): RegistryFile {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  if (
    !parsed || typeof parsed !== "object" ||
    typeof (parsed as RegistryFile).provenance !== "string" ||
    !Array.isArray((parsed as RegistryFile).archetypes)
  ) {
    throw new Error(`registry ${path} is not a { provenance, archetypes[] } file`);
  }
  return parsed as RegistryFile;
}

/**
 * Build the on-disk archetype from validated synthesis content + provenance.
 * The loop (not the model) owns domain/route/engine_lens/uid + provenance, and
 * the key order mirrors the authored seed entries for a clean diff. Throws when
 * the content fails the fail-closed schema/quality checks.
 */
export function buildRegistryEntry(
  archetype: SynthesizedArchetype,
  validatedAt: string,
): RawAppsecArchetype {
  const c = archetype.content;
  if (!KEBAB_ID.test(c.id)) throw new Error(`archetype id '${c.id}' is not kebab-case`);
  if (!CWE_CODE.test(c.cwe)) throw new Error(`archetype '${c.id}' cwe '${c.cwe}' has no CWE code`);
  for (const [field, value] of [
    ["name", c.name], ["subsystem", c.subsystem], ["pattern", c.pattern],
    ["detection_signature", c.detection_signature], ["challenge_hint", c.challenge_hint],
    ["confirmable", c.confirmable],
  ] as const) {
    if (typeof value !== "string" || value.trim().length === 0) {
      throw new Error(`archetype '${c.id}' field '${field}' must be a non-empty string`);
    }
  }
  if (!Array.isArray(c.grounding) || c.grounding.length === 0) {
    throw new Error(`archetype '${c.id}' grounding must be a non-empty array`);
  }
  if (!isCrossLanguageHint(c.challenge_hint)) {
    throw new Error(`archetype '${c.id}' challenge_hint is not cross-language (fail-closed)`);
  }
  return {
    id: c.id,
    name: c.name,
    cwe: c.cwe,
    domain: "appsec",
    subsystem: c.subsystem,
    pattern: c.pattern,
    detection_signature: c.detection_signature,
    challenge_hint: c.challenge_hint,
    grounding: [...c.grounding],
    confirmable: c.confirmable,
    uid: `appsec/${c.id}`,
    engine_lens: null,
    route: "appsec-source-static",
    source: "synthesized",
    validated_at: validatedAt,
    miss_refs: [...archetype.missRefs],
  };
}

/** Serialize the registry the way the seed file is formatted (2-space, trailing newline). */
function serialize(registry: RegistryFile): string {
  return `${JSON.stringify(registry, null, 2)}\n`;
}

/** Atomically replace `path` with `contents` (same-dir temp + rename). */
function writeAtomic(path: string, contents: string): void {
  const tmp = join(dirname(path), `.${randomUUID()}.appsec-archetypes.tmp`);
  try {
    writeFileSync(tmp, contents, { encoding: "utf8", mode: 0o644 });
    renameSync(tmp, path);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      /* best-effort cleanup */
    }
    throw err;
  }
}

export interface RegisterOutcome {
  /** True only when a NEW entry was appended. */
  written: boolean;
  registered?: RegisteredLens;
  /** Why nothing was written (idempotent skip, or unreachable — errors throw). */
  reason?: string;
}

/**
 * Register ONE validated archetype. Idempotent on id: if the id is already in
 * the registry, no-op with `written:false`. Otherwise append + atomic write.
 * Throws only on a structural/registry-IO fault (the loop catches it as a
 * rejection). `registryPath` defaults to the bundled seed registry.
 */
export function registerArchetype(
  archetype: SynthesizedArchetype,
  opts: { registryPath?: string; validatedAt: string },
): RegisterOutcome {
  const path = opts.registryPath ?? appsecArchetypesPath();
  const registry = readRegistry(path);
  const id = archetype.content.id;
  if (registry.archetypes.some((a) => a.id === id || a.uid === `appsec/${id}`)) {
    return { written: false, reason: `id '${id}' already present — idempotent skip` };
  }
  const entry = buildRegistryEntry(archetype, opts.validatedAt);
  const next: RegistryFile = {
    provenance: registry.provenance,
    archetypes: [...registry.archetypes, entry],
  };
  writeAtomic(path, serialize(next));
  return {
    written: true,
    registered: {
      id: entry.id,
      uid: entry.uid,
      validatedAt: opts.validatedAt,
      missRefs: [...(entry.miss_refs ?? [])],
    },
  };
}
