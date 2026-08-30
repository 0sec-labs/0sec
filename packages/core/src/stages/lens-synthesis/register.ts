/**
 * Lens-synthesis stage 4 — REGISTER.
 *
 * Append ONE validated champion to the operator-owned appsec overlay. The
 * bundled registry remains immutable: a promotion creates or updates
 * `~/.0sec/lenses/appsec-archetypes.json` by default.
 *
 * Each transition is written atomically with a hash-linked ledger. The runtime
 * loader admits only ledger-bound synthesized entries, so a partial write,
 * malformed overlay, or an unbound hand-edited entry cannot affect a review.
 */

import { randomUUID } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import {
  activeAppsecLensRegistryPath,
  appsecArchetypeDigest,
  appsecLensLedgerEntryDigest,
  type AppsecLensLedgerEntry,
  type AppsecLensRegistry,
  type RawAppsecArchetype,
} from "../appsec-catalog.js";
import { isCrossLanguageHint } from "./synthesize.js";
import type { RegisteredLens, SynthesizedArchetype } from "./types.js";

interface RegistryFile extends AppsecLensRegistry {
  archetypes: RawAppsecArchetype[];
  ledger: AppsecLensLedgerEntry[];
}

const KEBAB_ID = /^[a-z0-9][a-z0-9-]{1,63}$/;
const CWE_CODE = /CWE-\d+/;

function activeLedgerEntries(ledger: readonly AppsecLensLedgerEntry[]): Map<string, string> {
  const active = new Map<string, string>();
  let previousDigest: string | null = null;
  for (const [index, entry] of ledger.entries()) {
    if (
      entry.schemaVersion !== 1 ||
      entry.sequence !== index + 1 ||
      !Number.isFinite(Date.parse(entry.occurredAt)) ||
      (entry.type !== "promoted" && entry.type !== "retired") ||
      !KEBAB_ID.test(entry.lensId) ||
      entry.previousDigest !== previousDigest
    ) {
      throw new Error(`registry ledger entry ${index} is malformed`);
    }
    const expectedDigest = appsecLensLedgerEntryDigest({
      schemaVersion: entry.schemaVersion,
      sequence: entry.sequence,
      occurredAt: entry.occurredAt,
      type: entry.type,
      lensId: entry.lensId,
      archetypeDigest: entry.archetypeDigest,
      previousDigest: entry.previousDigest,
    });
    if (entry.entryDigest !== expectedDigest) {
      throw new Error(`registry ledger entry ${index} has an invalid digest`);
    }
    if (entry.type === "promoted") {
      if (active.has(entry.lensId)) {
        throw new Error(`registry ledger promotes active lens '${entry.lensId}' twice`);
      }
      active.set(entry.lensId, entry.archetypeDigest);
    } else {
      if (active.get(entry.lensId) !== entry.archetypeDigest) {
        throw new Error(`registry ledger retires unknown or mismatched lens '${entry.lensId}'`);
      }
      active.delete(entry.lensId);
    }
    previousDigest = entry.entryDigest;
  }
  return active;
}

function readRegistry(path: string): RegistryFile {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`registry ${path} is not a JSON object`);
  }
  const value = parsed as Partial<RegistryFile>;
  if (
    (value.schemaVersion !== undefined && value.schemaVersion !== 1) ||
    typeof value.provenance !== "string" ||
    value.provenance.trim().length === 0 ||
    !Array.isArray(value.archetypes)
  ) {
    throw new Error(`registry ${path} is not a supported appsec registry`);
  }
  const ledger = value.ledger === undefined ? [] : value.ledger;
  if (!Array.isArray(ledger)) throw new Error(`registry ${path} ledger must be an array`);
  activeLedgerEntries(ledger);
  return {
    schemaVersion: 1,
    provenance: value.provenance,
    archetypes: value.archetypes,
    ledger,
  };
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

/** Serialize the registry deterministically enough for operator review. */
function serialize(registry: RegistryFile): string {
  return `${JSON.stringify(registry, null, 2)}\n`;
}

/** Atomically replace `path` with `contents` (same-dir temp + rename). */
function writeAtomic(path: string, contents: string): void {
  const tmp = join(dirname(path), `.${randomUUID()}.appsec-archetypes.tmp`);
  try {
    writeFileSync(tmp, contents, { encoding: "utf8", mode: 0o600 });
    renameSync(tmp, path);
  } catch (error) {
    try {
      unlinkSync(tmp);
    } catch {
      /* best-effort cleanup */
    }
    throw error;
  }
}

function ensureRegistry(path: string): void {
  if (existsSync(path)) return;
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const initial: RegistryFile = {
    schemaVersion: 1,
    provenance: "0sec validated self-evolving appsec lens overlay",
    archetypes: [],
    ledger: [],
  };
  try {
    writeFileSync(path, serialize(initial), { encoding: "utf8", mode: 0o600, flag: "wx" });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
}

function appendLedgerEntry(
  registry: RegistryFile,
  type: AppsecLensLedgerEntry["type"],
  lensId: string,
  archetypeDigest: string,
  occurredAt: string,
): AppsecLensLedgerEntry {
  const previousDigest = registry.ledger[registry.ledger.length - 1]?.entryDigest ?? null;
  const unsigned = {
    schemaVersion: 1 as const,
    sequence: registry.ledger.length + 1,
    occurredAt,
    type,
    lensId,
    archetypeDigest,
    previousDigest,
  };
  return {
    ...unsigned,
    entryDigest: appsecLensLedgerEntryDigest(unsigned),
  };
}

export interface RegisterOutcome {
  /** True only when a NEW entry was appended. */
  written: boolean;
  registered?: RegisteredLens;
  /** Hash-chain receipt for the accepted promotion. */
  promotionDigest?: string;
  /** Why nothing was written (idempotent skip, or unreachable — errors throw). */
  reason?: string;
}

export interface RetireOutcome {
  retired: boolean;
  id: string;
  registryPath: string;
  retirementDigest?: string;
  reason?: string;
}

export interface LensRegistryStatus {
  path: string;
  exists: boolean;
  valid: boolean;
  activeLensCount: number;
  ledgerEntries: number;
  unboundArchetypes: number;
  error?: string;
}

/** Inspect the selected overlay without mutating it. */
export function inspectLensRegistry(registryPath?: string): LensRegistryStatus {
  const path = registryPath ?? activeAppsecLensRegistryPath();
  if (!existsSync(path)) {
    return {
      path,
      exists: false,
      valid: true,
      activeLensCount: 0,
      ledgerEntries: 0,
      unboundArchetypes: 0,
    };
  }
  try {
    const metadata = lstatSync(path);
    if (!metadata.isFile()) throw new Error("registry must be a regular file");
    if ((metadata.mode & 0o022) !== 0) {
      throw new Error("registry must not be group- or world-writable");
    }
    const registry = readRegistry(path);
    const active = activeLedgerEntries(registry.ledger);
    const unboundArchetypes = registry.archetypes.filter(
      (archetype) => active.get(archetype.id) !== appsecArchetypeDigest(archetype),
    ).length;
    return {
      path,
      exists: true,
      valid: unboundArchetypes === 0 && active.size === registry.archetypes.length,
      activeLensCount: active.size,
      ledgerEntries: registry.ledger.length,
      unboundArchetypes,
    };
  } catch (error) {
    return {
      path,
      exists: true,
      valid: false,
      activeLensCount: 0,
      ledgerEntries: 0,
      unboundArchetypes: 0,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Register ONE validated archetype. The default target is the user-owned
 * overlay; an explicit `registryPath` remains available for isolated tests and
 * controlled worker environments.
 */
export function registerArchetype(
  archetype: SynthesizedArchetype,
  opts: { registryPath?: string; validatedAt: string },
): RegisterOutcome {
  const entry = buildRegistryEntry(archetype, opts.validatedAt);
  const path = opts.registryPath ?? activeAppsecLensRegistryPath();
  ensureRegistry(path);
  const registry = readRegistry(path);
  if (registry.archetypes.some((existing) => existing.id === entry.id || existing.uid === entry.uid)) {
    return { written: false, reason: `id '${entry.id}' already present — idempotent skip` };
  }
  const promoted = appendLedgerEntry(
    registry,
    "promoted",
    entry.id,
    appsecArchetypeDigest(entry),
    opts.validatedAt,
  );
  const next: RegistryFile = {
    schemaVersion: 1,
    provenance: registry.provenance,
    archetypes: [...registry.archetypes, entry],
    ledger: [...registry.ledger, promoted],
  };
  writeAtomic(path, serialize(next));
  return {
    written: true,
    promotionDigest: promoted.entryDigest,
    registered: {
      id: entry.id,
      uid: entry.uid,
      validatedAt: opts.validatedAt,
      missRefs: [...(entry.miss_refs ?? [])],
    },
  };
}

/**
 * Retire a promoted overlay lens. This affects future snapshots only: reviews
 * that already captured their finder lens array remain unchanged.
 */
export function retireArchetype(
  id: string,
  opts: { registryPath?: string; retiredAt?: string } = {},
): RetireOutcome {
  const path = opts.registryPath ?? activeAppsecLensRegistryPath();
  if (!KEBAB_ID.test(id)) {
    return { retired: false, id, registryPath: path, reason: "lens id must be kebab-case" };
  }
  if (!existsSync(path)) {
    return { retired: false, id, registryPath: path, reason: "registry does not exist" };
  }
  const registry = readRegistry(path);
  const index = registry.archetypes.findIndex((archetype) => archetype.id === id);
  if (index < 0) {
    return { retired: false, id, registryPath: path, reason: "lens is not active in this registry" };
  }
  const archetype = registry.archetypes[index]!;
  if (archetype.source !== "synthesized") {
    return { retired: false, id, registryPath: path, reason: "only synthesized overlay lenses can be retired" };
  }
  const archetypeDigest = appsecArchetypeDigest(archetype);
  if (activeLedgerEntries(registry.ledger).get(id) !== archetypeDigest) {
    return { retired: false, id, registryPath: path, reason: "lens is not bound by the promotion ledger" };
  }
  const retired = appendLedgerEntry(
    registry,
    "retired",
    id,
    archetypeDigest,
    opts.retiredAt ?? new Date().toISOString(),
  );
  const next: RegistryFile = {
    schemaVersion: 1,
    provenance: registry.provenance,
    archetypes: registry.archetypes.filter((entry) => entry.id !== id),
    ledger: [...registry.ledger, retired],
  };
  writeAtomic(path, serialize(next));
  return {
    retired: true,
    id,
    registryPath: path,
    retirementDigest: retired.entryDigest,
  };
}
