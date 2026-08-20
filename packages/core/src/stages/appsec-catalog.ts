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
 * This is the substrate for autonomous lens synthesis: adding coverage is a
 * data-file edit (append an archetype), not a code change, and the same JSON
 * shape a future generator would emit is the one this loader consumes today.
 *
 * RUNTIME injection: {@link loadAppsecFinderLenses} can additionally union in
 * lenses supplied at scan time via the `0SEC_RUNTIME_LENSES` env var (a JSON
 * array of the SAME snake_case archetype objects the baked file holds). This
 * lets the cloud's self-improving lens loop apply freshly synthesized lenses
 * WITHOUT an engine rebuild. It is gated behind `0SEC_RUNTIME_LENSES_ENABLED`
 * (default OFF — unset behaves byte-identically to today) and is fail-closed:
 * malformed JSON or a bad entry is warned-and-skipped, never thrown. Baked
 * (authored/validated) lenses always win an id collision — a runtime blob can
 * only ADD coverage, never shadow or override an authored lens.
 */

import { readFileSync } from "node:fs";
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

// ── Runtime lens injection (flag-gated, fail-closed) ─────────────────────────

/** Env flag gating runtime lens injection. Unset / empty / 0 / false / no → OFF. */
const RUNTIME_LENSES_FLAG = "0SEC_RUNTIME_LENSES_ENABLED";
/** Env var carrying the runtime lens JSON blob (array of RawAppsecArchetype). */
const RUNTIME_LENSES_ENV = "0SEC_RUNTIME_LENSES";

/** True only when the operator has explicitly enabled runtime lens injection. */
function runtimeLensesEnabled(): boolean {
  return !["", "0", "false", "no"].includes((process.env[RUNTIME_LENSES_FLAG] ?? "").toLowerCase());
}

function isStringArray(x: unknown): x is string[] {
  return Array.isArray(x) && x.every((v) => typeof v === "string");
}

/**
 * Structural guard: is `x` a well-formed on-disk {@link RawAppsecArchetype}?
 * This IS the runtime validation — it mirrors the shape the baked loader casts,
 * so only entries that would map cleanly through {@link mapRawAppsecArchetypes}
 * pass. `id` and `challenge_hint` (the two load-bearing FinderLens fields) must
 * be non-empty; the optional provenance fields are not required.
 */
function isRawAppsecArchetype(x: unknown): x is RawAppsecArchetype {
  if (typeof x !== "object" || x === null) return false;
  const a = x as Record<string, unknown>;
  const nonEmptyStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;
  return (
    nonEmptyStr(a.id) &&
    nonEmptyStr(a.challenge_hint) &&
    typeof a.uid === "string" &&
    typeof a.domain === "string" &&
    typeof a.name === "string" &&
    typeof a.cwe === "string" &&
    typeof a.subsystem === "string" &&
    typeof a.pattern === "string" &&
    typeof a.detection_signature === "string" &&
    typeof a.confirmable === "string" &&
    typeof a.route === "string" &&
    (a.engine_lens === null || typeof a.engine_lens === "string") &&
    isStringArray(a.grounding)
  );
}

/**
 * Read the flag-gated `0SEC_RUNTIME_LENSES` blob and map it to
 * {@link FinderLens}[] using the SAME validation + mapping the baked loader
 * uses. Fail-closed at every step: flag OFF, missing env, non-array JSON, or a
 * parse error each yield `[]`; a single malformed entry is warned-and-skipped
 * rather than aborting the batch. Never throws — the scan proceeds baked-only.
 */
function loadRuntimeAppsecLenses(): FinderLens[] {
  if (!runtimeLensesEnabled()) return [];
  const blob = process.env[RUNTIME_LENSES_ENV];
  if (!blob || blob.trim().length === 0) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(blob);
  } catch {
    console.warn(`[appsec-runtime-lenses] ${RUNTIME_LENSES_ENV} is not valid JSON — falling back to baked lenses`);
    return [];
  }
  if (!Array.isArray(parsed)) {
    console.warn(`[appsec-runtime-lenses] ${RUNTIME_LENSES_ENV} must be a JSON array — falling back to baked lenses`);
    return [];
  }

  const valid: RawAppsecArchetype[] = [];
  for (const entry of parsed) {
    if (isRawAppsecArchetype(entry)) valid.push(entry);
    else console.warn(`[appsec-runtime-lenses] skipping malformed runtime lens entry`);
  }
  return mapRawAppsecArchetypes(valid).map(appsecArchetypeToFinderLens);
}

/**
 * Load the appsec archetype registry as a ready-to-use {@link FinderLens}[] —
 * the entry point the finder surfaces (`defaultFinderLenses`) consume to add
 * cross-language appsec coverage alongside the generic lenses.
 *
 * Baked lenses ({@link loadAppsecArchetypes}, pure + cached) load first, then —
 * only when `0SEC_RUNTIME_LENSES_ENABLED` is on — runtime lenses union in,
 * deduped by lens id with BAKED WINNING every collision (a runtime blob can add
 * new ids but never shadow an authored/validated lens). With the flag off this
 * is byte-identical to `loadAppsecArchetypes().map(appsecArchetypeToFinderLens)`.
 */
export function loadAppsecFinderLenses(): FinderLens[] {
  const baked = loadAppsecArchetypes().map(appsecArchetypeToFinderLens);
  const runtime = loadRuntimeAppsecLenses();
  if (runtime.length === 0) return baked;

  const seen = new Set(baked.map((l) => l.id));
  const merged = [...baked];
  for (const lens of runtime) {
    if (seen.has(lens.id)) continue; // baked (or an earlier runtime entry) wins
    seen.add(lens.id);
    merged.push(lens);
  }
  return merged;
}
