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
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
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
}

interface RawAppsecArchetype {
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
  }));
}

let _cache: AppsecArchetype[] | null = null;

/** Absolute path to the bundled appsec-archetype data file (src and dist both carry it). */
export function appsecArchetypesPath(): string {
  return fileURLToPath(new URL("./data/appsec-archetypes.json", import.meta.url));
}

/** Load the appsec-domain archetypes (cached; pure data — never executes anything). */
export function loadAppsecArchetypes(): AppsecArchetype[] {
  if (_cache) return _cache;
  const raw = JSON.parse(readFileSync(appsecArchetypesPath(), "utf8")) as { archetypes: RawAppsecArchetype[] };
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

/**
 * Load the appsec archetype registry as a ready-to-use {@link FinderLens}[] —
 * the entry point the finder surfaces (`defaultFinderLenses`) consume to add
 * cross-language appsec coverage alongside the generic lenses. Pure + cached
 * (delegates to {@link loadAppsecArchetypes}).
 */
export function loadAppsecFinderLenses(): FinderLens[] {
  return loadAppsecArchetypes().map(appsecArchetypeToFinderLens);
}
