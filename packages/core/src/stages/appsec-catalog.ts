/**
 * Appsec bug-archetype catalog — the data-driven, cross-language application-
 * security lens registry for the seedless finder surfaces (`deep-review` /
 * `hunt`) and the `review` prose hunt list.
 *
 * This is the appsec sibling of `archetype-catalog.ts` (the kernel/FreeBSD/
 * Chromium packs). It deliberately MIRRORS that module's shape — an inert JSON
 * data file (`data/appsec-archetypes.json`) plus a pure, cached loader — but is
 * a SEPARATE registry with its own types, because appsec archetypes carry a
 * different load-bearing field and a different confirmability model:
 *
 *   - The kernel packs feed `runHuntScan` a `HuntBrief` derived from a
 *     `detectionSignature` (grep-able kernel symbols), and several classes need
 *     the build+boot+KASAN `kernel-verify` lane to go from candidate to proven.
 *   - The appsec pack feeds the FINDER-LENS surface: each archetype's
 *     `challengeHint` IS a ready-to-use {@link FinderLens} `challengeHint` (a
 *     cross-language, sink-shape-citing hunt angle), and there is NO
 *     build/execution/sanitizer lane for these at all — every entry is
 *     `route: "appsec-source-static"`, i.e. a read/grep hit is a hypothesis for
 *     the skeptic + multi-lens verify quorum, never an auto-confirmed finding.
 *
 * Keeping this as its own module (rather than adding an `"appsec"` domain to
 * `ArchetypeDomain` and an `"appsec-source-static"` value to `ArchetypeRoute`)
 * means the kernel/FreeBSD/Chromium sweep code — `symbolsFromDetectionSignature`
 * and its snake_case grep heuristic, `planArchetypeSweep`, the on-chain profile
 * paths — is left byte-for-byte untouched. This registry generates FINDER
 * LENSES, not grep candidates; it never shells out and never confirms anything.
 *
 * This is the substrate for the self-evolving lens loop: a validated
 * candidate is written to an operator-owned overlay, not this bundled source
 * file. The overlay is read when a new finder snapshot is requested, so a
 * long-lived CLI process picks up a completed promotion for its next review
 * without ever changing an active engagement's lens set.
 *
 * The legacy `0SEC_RUNTIME_LENSES` blob remains a deliberately opt-in,
 * ephemeral overlay. Durable promotions use the user registry plus its
 * hash-linked ledger; malformed, unsafe, or unbound registries fail closed.
 * Every overlay is additive: baked lenses always win an id collision.
 */

import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import embeddedAppsecArchetypes from "./data/appsec-archetypes.json" with { type: "json" };
import type { FinderLens } from "./hunt-scan.js";

// ── Data shape ───────────────────────────────────────────────────────────────

/**
 * Confirmability route for appsec archetypes. Unlike the kernel packs (which
 * split a grep-able static shape from one that needs a build+boot+KASAN
 * prover), this repo has NO application build/execution/sanitizer lane for
 * these classes, so there is a single value: a hit is always a source-static
 * hypothesis for the skeptic + verify quorum.
 */
export type AppsecRoute = "appsec-source-static";

/** One cross-language application-security bug-class archetype. */
export interface AppsecArchetype {
  /** e.g. "appsec/APPSEC-01" — stable across edits. */
  uid: string;
  /** Original catalog id, e.g. "APPSEC-01". */
  id: string;
  name: string;
  /** CWE code(s), e.g. "CWE-78" or "CWE-862 / CWE-639". */
  cwe: string;
  /** Always "appsec" (kept explicit for schema-parity with the kernel packs). */
  domain: string;
  subsystem: string;
  /** The generalized pattern / anti-pattern description (no exploit code). */
  pattern: string;
  /** Human/skeptic-facing grep-and-read evidence (concrete sink shapes per language). */
  detectionSignature: string;
  /**
   * The load-bearing field: a cross-language, sink-shape-citing hunt angle that
   * maps DIRECTLY onto {@link FinderLens.challengeHint}. This is what the
   * finder actually reads.
   */
  challengeHint: string;
  /** Public CWE/OWASP witnesses (and concrete misses) this archetype is grounded in. */
  grounding: string[];
  /** Free-text confirmability caveat (kept verbatim — the honest limit). */
  confirmableNote: string;
  /** The engine lens/seed id that implements this archetype, or null (this registry IS the implementation). */
  engineLens: string | null;
  route: AppsecRoute;
  /**
   * Provenance: how this archetype entered the registry. "authored" (the human
   * seed pack) is the implicit default when the field is absent; "synthesized"
   * marks an entry the self-improving lens loop generated + validated. Optional
   * + additive so the seed entries (which omit it) parse unchanged.
   */
  source?: "authored" | "synthesized";
  /** ISO-8601 stamp of when the lens loop validated a synthesized entry. */
  validatedAt?: string;
  /** The miss refs (file:line) the synthesized entry was built to close. */
  missRefs?: string[];
}

/** The on-disk (snake_case) shape. Exported so the safe writer emits byte-identical entries. */
export interface RawAppsecArchetype {
  uid: string;
  id: string;
  domain: string;
  name: string;
  cwe: string;
  subsystem: string;
  pattern: string;
  detection_signature: string;
  challenge_hint: string;
  grounding: string[];
  confirmable: string;
  engine_lens: string | null;
  route: string;
  /** Provenance (optional/additive — absent on the authored seed entries). */
  source?: "authored" | "synthesized";
  validated_at?: string;
  miss_refs?: string[];
}

/** A ledger event binding a durable self-evolving registry transition. */
export interface AppsecLensLedgerEntry {
  schemaVersion: 1;
  sequence: number;
  occurredAt: string;
  type: "promoted" | "retired";
  lensId: string;
  archetypeDigest: string;
  previousDigest: string | null;
  entryDigest: string;
}

/** On-disk shape for the mutable, user-owned additive lens overlay. */
export interface AppsecLensRegistry {
  schemaVersion: 1;
  provenance: string;
  archetypes: RawAppsecArchetype[];
  ledger: AppsecLensLedgerEntry[];
}

function mapRawAppsecArchetypes(raw: RawAppsecArchetype[]): AppsecArchetype[] {
  return raw.map((a) => ({
    uid: a.uid,
    id: a.id,
    name: a.name,
    cwe: a.cwe,
    domain: a.domain,
    subsystem: a.subsystem,
    pattern: a.pattern,
    detectionSignature: a.detection_signature,
    challengeHint: a.challenge_hint,
    grounding: [...a.grounding],
    confirmableNote: a.confirmable,
    engineLens: a.engine_lens,
    route: a.route as AppsecRoute,
    ...(a.source ? { source: a.source } : {}),
    ...(a.validated_at ? { validatedAt: a.validated_at } : {}),
    ...(a.miss_refs ? { missRefs: [...a.miss_refs] } : {}),
  }));
}

let _cache: AppsecArchetype[] | null = null;

/** Absolute path to the bundled appsec-archetype data file (src and dist both carry it). */
export function appsecArchetypesPath(): string {
  return fileURLToPath(new URL("./data/appsec-archetypes.json", import.meta.url));
}

/**
 * Default user-owned overlay. It is intentionally outside the installed
 * package, so a successful promotion never edits checked-in or bundled source.
 */
export function appsecUserArchetypesPath(homeDir: string = homedir()): string {
  return join(homeDir, ".0sec", "lenses", "appsec-archetypes.json");
}

/** A deliberate process override for isolated workers and tests. */
export function activeAppsecLensRegistryPath(): string {
  const configured = process.env["0SEC_APPSEC_LENS_REGISTRY"]?.trim();
  return configured ? resolve(configured) : appsecUserArchetypesPath();
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

function digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

/** Stable content binding used by durable-registry promotion and retirement events. */
export function appsecArchetypeDigest(archetype: RawAppsecArchetype): string {
  return digest(archetype);
}

/** Stable content binding for a ledger row before its self digest is attached. */
export function appsecLensLedgerEntryDigest(
  entry: Omit<AppsecLensLedgerEntry, "entryDigest">,
): string {
  return digest(entry);
}

function readAppsecArchetypes(): { archetypes: RawAppsecArchetype[] } {
  try {
    return JSON.parse(readFileSync(appsecArchetypesPath(), "utf8")) as { archetypes: RawAppsecArchetype[] };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    return embeddedAppsecArchetypes as { archetypes: RawAppsecArchetype[] };
  }
}

/** Load the appsec-domain archetypes (cached; pure data — never executes anything). */
export function loadAppsecArchetypes(): AppsecArchetype[] {
  if (_cache) return _cache;
  const raw = readAppsecArchetypes();
  _cache = mapRawAppsecArchetypes(raw.archetypes);
  return _cache;
}

// ── FinderLens mapping ───────────────────────────────────────────────────────

/**
 * Deterministic archetype -> {@link FinderLens} mapping (no LLM call; pure data
 * transform). The archetype's `id` becomes the lens id (part of the best-of-N
 * group key, so lenses UNION rather than compete) and its `challengeHint` is
 * the focused hunt angle appended to the finder brief.
 */
export function appsecArchetypeToFinderLens(a: AppsecArchetype): FinderLens {
  return { id: a.id, challengeHint: a.challengeHint };
}

// ── Durable + ephemeral overlays (fail-closed) ──────────────────────────────

/** Env flag gating legacy ephemeral runtime injection. */
const RUNTIME_LENSES_FLAG = "0SEC_RUNTIME_LENSES_ENABLED";
/** Env var carrying the legacy ephemeral runtime JSON blob. */
const RUNTIME_LENSES_ENV = "0SEC_RUNTIME_LENSES";
const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const LENS_ID = /^[a-z0-9][a-z0-9-]{1,63}$/;

/** True only when the operator has explicitly enabled legacy runtime injection. */
function runtimeLensesEnabled(): boolean {
  return !["", "0", "false", "no"].includes((process.env[RUNTIME_LENSES_FLAG] ?? "").toLowerCase());
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

/**
 * Structural guard shared by the baked-compatible ephemeral and durable
 * overlays. Durable data receives stricter provenance and ledger checks below.
 */
function isRawAppsecArchetype(value: unknown): value is RawAppsecArchetype {
  if (typeof value !== "object" || value === null) return false;
  const archetype = value as Record<string, unknown>;
  const isNonEmptyString = (field: unknown): field is string =>
    typeof field === "string" && field.trim().length > 0;
  return (
    isNonEmptyString(archetype.id) &&
    isNonEmptyString(archetype.challenge_hint) &&
    typeof archetype.uid === "string" &&
    typeof archetype.domain === "string" &&
    typeof archetype.name === "string" &&
    typeof archetype.cwe === "string" &&
    typeof archetype.subsystem === "string" &&
    typeof archetype.pattern === "string" &&
    typeof archetype.detection_signature === "string" &&
    typeof archetype.confirmable === "string" &&
    typeof archetype.route === "string" &&
    (archetype.engine_lens === null || typeof archetype.engine_lens === "string") &&
    isStringArray(archetype.grounding)
  );
}

function isDurablyValidatedArchetype(value: unknown): value is RawAppsecArchetype {
  if (!isRawAppsecArchetype(value)) return false;
  return (
    LENS_ID.test(value.id) &&
    value.uid === `appsec/${value.id}` &&
    value.domain === "appsec" &&
    value.engine_lens === null &&
    value.route === "appsec-source-static" &&
    value.source === "synthesized" &&
    typeof value.validated_at === "string" &&
    Number.isFinite(Date.parse(value.validated_at)) &&
    value.grounding.length > 0 &&
    value.grounding.every((entry) => entry.trim().length > 0) &&
    Array.isArray(value.miss_refs) &&
    value.miss_refs.length > 0 &&
    value.miss_refs.every((entry) => typeof entry === "string" && entry.trim().length > 0)
  );
}

function isAppsecLensLedgerEntry(value: unknown): value is AppsecLensLedgerEntry {
  if (typeof value !== "object" || value === null) return false;
  const entry = value as Record<string, unknown>;
  return (
    entry.schemaVersion === 1 &&
    Number.isInteger(entry.sequence) &&
    (entry.sequence as number) > 0 &&
    typeof entry.occurredAt === "string" &&
    Number.isFinite(Date.parse(entry.occurredAt)) &&
    (entry.type === "promoted" || entry.type === "retired") &&
    typeof entry.lensId === "string" &&
    LENS_ID.test(entry.lensId) &&
    typeof entry.archetypeDigest === "string" &&
    SHA256_DIGEST.test(entry.archetypeDigest) &&
    (entry.previousDigest === null || (typeof entry.previousDigest === "string" && SHA256_DIGEST.test(entry.previousDigest))) &&
    typeof entry.entryDigest === "string" &&
    SHA256_DIGEST.test(entry.entryDigest)
  );
}

/**
 * Read the operator-owned overlay afresh. A scan calls this only while
 * constructing its lens snapshot; an in-flight scan therefore stays pinned.
 */
function loadDurableAppsecArchetypes(): RawAppsecArchetype[] {
  const registryPath = activeAppsecLensRegistryPath();
  if (!existsSync(registryPath)) return [];

  try {
    const metadata = lstatSync(registryPath);
    if (!metadata.isFile()) throw new Error("registry must be a regular file");
    if ((metadata.mode & 0o022) !== 0) {
      throw new Error("registry must not be group- or world-writable");
    }

    const parsed = JSON.parse(readFileSync(registryPath, "utf8")) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("registry must be a JSON object");
    }
    const registry = parsed as Partial<AppsecLensRegistry>;
    if (
      registry.schemaVersion !== 1 ||
      typeof registry.provenance !== "string" ||
      registry.provenance.trim().length === 0 ||
      !Array.isArray(registry.archetypes) ||
      !Array.isArray(registry.ledger)
    ) {
      throw new Error("registry must carry schemaVersion 1, provenance, archetypes, and ledger");
    }

    const active = new Map<string, string>();
    let previousDigest: string | null = null;
    for (const [index, rawEntry] of registry.ledger.entries()) {
      if (!isAppsecLensLedgerEntry(rawEntry)) throw new Error(`ledger entry ${index} is malformed`);
      const entry = rawEntry;
      if (entry.sequence !== index + 1 || entry.previousDigest !== previousDigest) {
        throw new Error(`ledger entry ${index} breaks sequence or hash linkage`);
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
      if (entry.entryDigest !== expectedDigest) throw new Error(`ledger entry ${index} digest does not match`);
      if (entry.type === "promoted") {
        if (active.has(entry.lensId)) throw new Error(`ledger promotes active lens '${entry.lensId}' twice`);
        active.set(entry.lensId, entry.archetypeDigest);
      } else {
        if (active.get(entry.lensId) !== entry.archetypeDigest) {
          throw new Error(`ledger retires unknown or mismatched lens '${entry.lensId}'`);
        }
        active.delete(entry.lensId);
      }
      previousDigest = entry.entryDigest;
    }

    const archetypes: RawAppsecArchetype[] = [];
    for (const rawArchetype of registry.archetypes) {
      if (!isDurablyValidatedArchetype(rawArchetype)) {
        throw new Error("registry contains an unvalidated synthesized lens");
      }
      if (active.get(rawArchetype.id) !== appsecArchetypeDigest(rawArchetype)) {
        throw new Error(`registry lens '${rawArchetype.id}' is not bound by its ledger`);
      }
      archetypes.push(rawArchetype);
    }
    if (active.size !== archetypes.length) {
      throw new Error("registry ledger and active archetype set disagree");
    }
    return archetypes;
  } catch (error) {
    console.warn(
      `[appsec-lens-registry] ignoring ${registryPath}: ${error instanceof Error ? error.message : String(error)}`,
    );
    return [];
  }
}

/**
 * Read the flag-gated `0SEC_RUNTIME_LENSES` blob. This is intentionally kept
 * separate from the durable registry: it is an explicit, process-local
 * experiment surface and never survives a restart.
 */
function loadRuntimeAppsecLenses(): FinderLens[] {
  if (!runtimeLensesEnabled()) return [];
  const blob = process.env[RUNTIME_LENSES_ENV];
  if (!blob || blob.trim().length === 0) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(blob);
  } catch {
    console.warn(`[appsec-runtime-lenses] ${RUNTIME_LENSES_ENV} is not valid JSON — falling back to durable lenses`);
    return [];
  }
  if (!Array.isArray(parsed)) {
    console.warn(`[appsec-runtime-lenses] ${RUNTIME_LENSES_ENV} must be a JSON array — falling back to durable lenses`);
    return [];
  }

  const valid: RawAppsecArchetype[] = [];
  for (const entry of parsed) {
    if (isRawAppsecArchetype(entry)) valid.push(entry);
    else console.warn("[appsec-runtime-lenses] skipping malformed runtime lens entry");
  }
  return mapRawAppsecArchetypes(valid).map(appsecArchetypeToFinderLens);
}

/**
 * Return an immutable-at-call-time finder snapshot. Baked lenses load first,
 * followed by the durable user registry and the opt-in ephemeral blob. Later
 * overlays can add ids but never override an earlier lens.
 */
export function loadAppsecFinderLenses(): FinderLens[] {
  const baked = loadAppsecArchetypes().map(appsecArchetypeToFinderLens);
  const durable = mapRawAppsecArchetypes(loadDurableAppsecArchetypes()).map(appsecArchetypeToFinderLens);
  const runtime = loadRuntimeAppsecLenses();
  const seen = new Set(baked.map((lens) => lens.id));
  const merged = [...baked];

  for (const lens of [...durable, ...runtime]) {
    if (seen.has(lens.id)) continue;
    seen.add(lens.id);
    merged.push(lens);
  }
  return merged;
}
