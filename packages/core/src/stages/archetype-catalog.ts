/**
 * Kernel bug-archetype catalog — multi-archetype seeding for `runHuntScan`.
 *
 * Today's hunt (`variant-candidates.ts` -> `runHuntScan`) sweeps ONE bug class
 * per invocation: a human/LLM reads ONE recent fix diff, names ONE bug class,
 * and greps for variant sites of THAT class. It is the only method that has
 * actually produced a 0-day for us (the TIPC incomplete-fix hunt), but it is
 * seeded by hand, one fix at a time.
 *
 * This module ports the kernel-relevant slice of 0verse's 90-archetype,
 * CVE-grounded bug-pattern registry (`bench:/root/0verse/src/zeroverse/
 * seedcatalog.py` + `data/archetypes.json`) into pwnkit as a standing LIBRARY
 * of kernel bug-class archetypes (`data/kernel-archetypes.json`, 34 entries).
 * Instead of one hand-picked seed, a hunt can now draw a `HuntBrief` from ANY
 * archetype in the library — or sweep several at once — so one invocation
 * covers many bug classes over the same reachable surface.
 *
 * Two responsibilities, split like 0verse's `seedcatalog.py` (inert data) vs.
 * `bugclasses.py` (the executing lenses):
 *
 *   - `loadKernelArchetypes` / `filterArchetypes` / `archetypeToHuntBrief` are
 *     PURE and always available (no env gate) — inert data + a deterministic
 *     mapping, exactly like `seedcatalog.load_archetypes()`.
 *   - `planArchetypeSweep` actually touches the filesystem (greps the source
 *     tree) and is gated by `archetypeSweepEnabled()` /
 *     `PWNKIT_ARCHETYPE_SWEEP=1` (default OFF), mirroring 0verse's
 *     `ZEROVERSE_FLYWHEEL` opt-in discipline for anything that runs.
 *
 * IMPORTANT DIFFERENCE FROM 0VERSE: 0verse's `route` field
 * (`kernel-static` / `kernel-verify` / `not-binary-detectable`) classifies
 * detectability on a STRIPPED BINARY with no source. pwnkit's kernel hunt runs
 * against the actual kernel SOURCE TREE (a git checkout), so the grep-ability
 * of an archetype here is NOT gated by its 0verse `route` — a `kernel-verify`
 * archetype (e.g. a UAF/race) can still have a perfectly grep-able source
 * shape (the symbols named in its `detectionSignature`), even though 0verse
 * could only treat it as a hypothesis on a binary. What the `route` DOES still
 * tell us: whether a confirmed source-level hit needs the kernel-verify lane
 * (build+boot+KASAN) to go from "candidate" to "proven", or whether the
 * skeptic-only gate is plausible. See `hypothesisOnly` / `needsKernelVerify`.
 *
 * This module generates CANDIDATES ONLY. It never confirms anything: the
 * skeptic + prover gate in `hunt-scan.ts` (`makeSkepticVerifier` /
 * `composeGate`) remains the sole adjudicator, untouched by this file.
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { HuntBrief, HuntCandidate } from "./hunt-scan.js";

// ── Data shape ───────────────────────────────────────────────────────────────

/**
 * 0verse's kernel-domain route vocabulary (binary-detectability
 * classification; see file header), extended with `"source-static"` for the
 * Chromium pack: unlike the kernel/FreeBSD packs (which distinguish a
 * grep-able static shape from one that needs a build+boot+KASAN prover),
 * pwnkit has NO Chromium build/execution lane at all today — every Chromium
 * archetype is source-static-only by construction, so this single value
 * covers the whole pack rather than splitting it into static/verify like the
 * kernel packs do.
 */
export type ArchetypeRoute = "kernel-static" | "kernel-verify" | "not-binary-detectable" | "source-static";

/** One CVE-grounded kernel bug-class archetype, ported from 0verse's registry. */
export interface KernelArchetype {
  /** e.g. "kernel/NF-01" — stable across ports. */
  uid: string;
  /** Original catalog id, e.g. "NF-01". */
  id: string;
  name: string;
  /** CWE code(s), e.g. "CWE-416" or "CWE-416 / CWE-415". */
  cwe: string;
  subsystem: string;
  /** The generalized pattern / anti-pattern description (no exploit code). */
  pattern: string;
  /** How this class is spotted (symbol names, decompiled shape, lens mapping). */
  detectionSignature: string;
  /** Public CVE/advisory witnesses this archetype is grounded in. */
  grounding: string[];
  /** 0verse's free-text confirmability caveat (kept verbatim — it is the honest limit). */
  confirmableNote: string;
  /** The 0verse engine lens/seed id that implements this archetype, or null (unmapped). */
  engineLens: string | null;
  route: ArchetypeRoute;
}

interface RawArchetype {
  uid: string;
  id: string;
  domain: string;
  name: string;
  cwe: string;
  subsystem: string;
  pattern: string;
  detection_signature: string;
  grounding: string[];
  confirmable: string;
  engine_lens: string | null;
  route: string;
}

function mapRawArchetypes(raw: RawArchetype[]): KernelArchetype[] {
  return raw.map((a) => ({
    uid: a.uid,
    id: a.id,
    name: a.name,
    cwe: a.cwe,
    subsystem: a.subsystem,
    pattern: a.pattern,
    detectionSignature: a.detection_signature,
    grounding: [...a.grounding],
    confirmableNote: a.confirmable,
    engineLens: a.engine_lens,
    route: a.route as ArchetypeRoute,
  }));
}

let _cache: KernelArchetype[] | null = null;

/** Absolute path to the bundled kernel-archetype data file (src and dist both carry it). */
export function kernelArchetypesPath(): string {
  return fileURLToPath(new URL("./data/kernel-archetypes.json", import.meta.url));
}

/** Load the 34 kernel-domain archetypes (cached; pure data — never executes anything). */
export function loadKernelArchetypes(): KernelArchetype[] {
  if (_cache) return _cache;
  const raw = JSON.parse(readFileSync(kernelArchetypesPath(), "utf8")) as { archetypes: RawArchetype[] };
  _cache = mapRawArchetypes(raw.archetypes);
  return _cache;
}

let _freebsdCache: KernelArchetype[] | null = null;

/** Absolute path to the bundled FreeBSD-archetype data file (src and dist both carry it). */
export function freebsdArchetypesPath(): string {
  return fileURLToPath(new URL("./data/freebsd-archetypes.json", import.meta.url));
}

/**
 * Load the FreeBSD-domain archetype pack (cached; pure data — never executes
 * anything). Same schema/shape as `loadKernelArchetypes`, but grounded in
 * FreeBSD idioms (copyout/copyin, malloc(9)/mallocarray, priv_check, sysctl,
 * d_ioctl_t, uma_zfree) instead of Linux ones — see the data file's
 * `provenance` field for the honest caveat that no FreeBSD kernel-verify
 * (build+boot+KASAN) lane exists yet in this repo.
 */
export function loadFreebsdArchetypes(): KernelArchetype[] {
  if (_freebsdCache) return _freebsdCache;
  const raw = JSON.parse(readFileSync(freebsdArchetypesPath(), "utf8")) as { archetypes: RawArchetype[] };
  _freebsdCache = mapRawArchetypes(raw.archetypes);
  return _freebsdCache;
}

let _chromiumCache: KernelArchetype[] | null = null;

/** Absolute path to the bundled Chromium-archetype data file (src and dist both carry it). */
export function chromiumArchetypesPath(): string {
  return fileURLToPath(new URL("./data/chromium-archetypes.json", import.meta.url));
}

/**
 * Load the Chromium-domain archetype pack (cached; pure data — never
 * executes anything). Same schema/shape as `loadKernelArchetypes`, but
 * grounded in V8/Blink/Mojo/base:: bug classes (TurboFan/Maglev type
 * confusion, Oilpan UAF, Mojo IPC validation gaps, unwrapped raw_ptr UAF)
 * instead of kernel ones — see the data file's `provenance` field for the
 * honest caveat that no Chromium build/execution lane (compile, ASan/libFuzzer
 * harness, v8CTF submit path) exists yet in this repo, so every entry is
 * `route: "source-static"` (see `ArchetypeRoute`'s header).
 */
export function loadChromiumArchetypes(): KernelArchetype[] {
  if (_chromiumCache) return _chromiumCache;
  const raw = JSON.parse(readFileSync(chromiumArchetypesPath(), "utf8")) as { archetypes: RawArchetype[] };
  _chromiumCache = mapRawArchetypes(raw.archetypes);
  return _chromiumCache;
}

/** Which archetype library `planArchetypeSweep` draws from. Defaults to "kernel" (Linux) — unchanged behavior. */
export type ArchetypeDomain = "kernel" | "freebsd" | "chromium";

/**
 * Curated allow-list of bare (no-underscore) FreeBSD kernel primitives worth
 * grepping verbatim — see `symbolsFromDetectionSignature`'s header for why
 * the default underscore-shape heuristic misses these. Pass to
 * `candidateGrepPatterns` / `generateArchetypeCandidates` / `planArchetypeSweep`
 * when sweeping the FreeBSD pack; Linux callers that omit this stay unaffected.
 */
export const FREEBSD_BARE_KERNEL_WORDS = ["copyout", "copyin", "copyinstr", "malloc", "mallocarray"] as const;

/**
 * Curated allow-list of bare (no-underscore) Chromium/V8/Blink/Mojo symbols
 * worth grepping verbatim — see `symbolsFromDetectionSignature`'s header for
 * why the default underscore-shape heuristic misses these. Chromium C++ uses
 * PascalCase/camelCase almost exclusively (unlike Linux/FreeBSD kernel C's
 * snake_case), so WITHOUT this allow-list nearly every Chromium archetype's
 * `detectionSignature` would yield zero extractable symbols — the one
 * exception is `raw_ptr`, which genuinely is snake_case and already matches
 * the default heuristic unassisted. Pass to `candidateGrepPatterns` /
 * `generateArchetypeCandidates` / `planArchetypeSweep` when sweeping the
 * Chromium pack; kernel/FreeBSD callers that omit this stay unaffected.
 */
export const CHROMIUM_BARE_WORDS = [
  "TurboFan", "Maglev", "CheckMap", "TransitionElementsKind", "InferMaps", "JSCallReducer", "KeyedStoreIC",
  "BuildClassLiteral", "ClassBoilerplate", "FastNewObject",
  "JSTypedArray", "BackingStore", "ArrayBufferView", "Detach",
  "Local", "HandleScope", "EscapableHandleScope", "Persistent",
  "GarbageCollected", "MakeGarbageCollected", "Member", "WeakMember",
  "GetExecutionContext", "ScriptState",
  "GarbageCollectedMixin",
  "Deserialize", "StructTraits", "ArrayDataView", "DataView",
  "PendingRemote", "PendingReceiver", "Remote", "Receiver",
  "WeakPtr", "CheckedNumeric",
] as const;

/** True when the class needs the kernel-verify lane (build+boot+KASAN) to go from candidate to proven. */
export function needsKernelVerify(a: KernelArchetype): boolean {
  return a.route === "kernel-verify";
}

/**
 * True when 0verse could only ever surface this as a hypothesis on a bare
 * binary (`kernel-verify` or `not-binary-detectable`) — mirrors
 * `seedcatalog.Archetype.hypothesis_only`. Does NOT mean "don't bother" on
 * source: see the file header. It means a source-level hit here still needs a
 * dynamic prover, not just the skeptic re-read, before it counts as confirmed.
 */
export function hypothesisOnly(a: KernelArchetype): boolean {
  return a.route === "kernel-verify" || a.route === "not-binary-detectable";
}

// ── Filtering ────────────────────────────────────────────────────────────────

export interface ArchetypeFilter {
  /** Keep only these routes. */
  routes?: ArchetypeRoute[];
  /** Keep only archetypes whose `cwe` field contains this substring (case-insensitive). */
  cwe?: string;
  /** Keep only archetypes whose `subsystem` field contains this substring (case-insensitive). */
  subsystem?: string;
  /** Keep only these uids. */
  uids?: string[];
}

/** Filter the archetype library by route / CWE / subsystem / explicit uid list. */
export function filterArchetypes(archetypes: readonly KernelArchetype[], filter: ArchetypeFilter = {}): KernelArchetype[] {
  const cwe = filter.cwe?.toLowerCase();
  const subsystem = filter.subsystem?.toLowerCase();
  const uidSet = filter.uids ? new Set(filter.uids) : null;
  return archetypes.filter((a) => {
    if (filter.routes && !filter.routes.includes(a.route)) return false;
    if (cwe && !a.cwe.toLowerCase().includes(cwe)) return false;
    if (subsystem && !a.subsystem.toLowerCase().includes(subsystem)) return false;
    if (uidSet && !uidSet.has(a.uid)) return false;
    return true;
  });
}

// ── Brief mapping ────────────────────────────────────────────────────────────

/** Deterministic archetype -> HuntBrief mapping (no LLM call; pure data transform). */
export function archetypeToHuntBrief(a: KernelArchetype): HuntBrief {
  return {
    bugClass: `${a.name} (${a.cwe})`,
    pattern: `${a.pattern} DETECTION SIGNATURE: ${a.detectionSignature}`,
    fixReference: a.grounding.length > 0 ? `${a.uid}: ${a.grounding.join(", ")}` : a.uid,
  };
}

// ── Deterministic candidate-site generation (no LLM call) ───────────────────

// Common English words that happen to look like snake_case identifiers in
// prose ("look_for", "same_as") — kept short and deliberately conservative:
// a false inclusion only costs one wasted grep pattern, never a wrong finding.
const _STOPWORDS = new Set([
  "look_for", "look_at", "same_as", "either_or", "and_or", "over_time",
]);

/**
 * Extract plausible kernel symbol names (function/macro identifiers a
 * `detectionSignature` names as the grep-able evidence, e.g. `nla_parse`,
 * `kfree_rcu`, `ns_capable`) from an archetype's prose. Deterministic,
 * no LLM: requires lowercase snake_case with at least one underscore and
 * length >= 6 — the shape almost every real kernel symbol has and almost no
 * incidental English phrase does. This is intentionally conservative (favors
 * precision over recall): a symbol missed here just means that archetype
 * yields fewer/no grep candidates, never a wrong one.
 *
 * `bareWords` (optional, default none — existing/Linux callers are
 * byte-for-byte unaffected) is a curated allow-list of exact, unambiguous
 * kernel API names to match verbatim even though they DON'T have the
 * underscore shape above. FreeBSD's core copy-to/from-user and allocation
 * primitives are bare single words (`copyout`, `copyin`, `malloc`) unlike
 * Linux's `copy_to_user` / `kmalloc`, so the heuristic above would silently
 * yield zero candidates for them without this escape hatch. Each allow-listed
 * word is curated by hand precisely because it is NOT ordinary English (see
 * why bare `free` is deliberately left off `FREEBSD_BARE_KERNEL_WORDS` — too
 * common in prose/comments to be a safe bare-word match).
 */
export function symbolsFromDetectionSignature(text: string, bareWords: readonly string[] = []): string[] {
  const found = text.match(/\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/g) ?? [];
  const out = new Set<string>();
  for (const raw of found) {
    if (raw.length < 6) continue;
    if (_STOPWORDS.has(raw)) continue;
    out.add(raw);
  }
  for (const bare of bareWords) {
    if (new RegExp(`\\b${bare}\\b`).test(text)) out.add(bare);
  }
  return [...out].sort();
}

/**
 * Build the ERE grep pattern(s) for an archetype's candidate sites: an
 * alternation of its detection-signature symbols, each required to appear in
 * a call/reference position (`sym(` or `sym` as its own token). Returns an
 * empty array when no reliable symbol was extracted (an honest "no static
 * grep signal" — the archetype still exists as a brief for a human/LLM-driven
 * hunt, it just cannot self-seed candidates this way).
 *
 * `bareWords` forwards to `symbolsFromDetectionSignature` (see its header) —
 * pass `FREEBSD_BARE_KERNEL_WORDS` when sweeping the FreeBSD pack.
 */
export function candidateGrepPatterns(a: KernelArchetype, bareWords: readonly string[] = []): string[] {
  const symbols = symbolsFromDetectionSignature(a.detectionSignature, bareWords);
  if (symbols.length === 0) return [];
  // Cap alternation width so a single pattern stays a readable, auditable
  // grep invocation; split into multiple patterns rather than one giant one.
  const chunkSize = 8;
  const patterns: string[] = [];
  for (let i = 0; i < symbols.length; i += chunkSize) {
    const chunk = symbols.slice(i, i + chunkSize);
    patterns.push(`\\b(${chunk.join("|")})\\b`);
  }
  return patterns;
}

function grepFiles(pattern: string, sourceRoot: string, includeGlobs: string[]): string[] {
  const args = ["-rlE", ...includeGlobs.map((g) => `--include=${g}`), "--", pattern, "."];
  try {
    const out = execFileSync("grep", args, {
      cwd: sourceRoot,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      timeout: 60_000,
    }) as string;
    return out.split("\n").map((s) => s.replace(/^\.\//, "").trim()).filter(Boolean);
  } catch {
    return []; // grep exits 1 on no match
  }
}

export interface ArchetypeCandidateOptions {
  /** File globs to search (default C/C++/headers — kernel source). */
  includeGlobs?: string[];
  /** Cap the candidate file list per archetype (default 20). */
  maxCandidates?: number;
  /** Bare-word allow-list forwarded to `candidateGrepPatterns` (default none — see its header). */
  bareWords?: readonly string[];
}

/**
 * Grep `sourceRoot` for one archetype's candidate sites (no LLM call). Ranks
 * files by how many independent symbol-chunks matched (stronger signal),
 * mirroring `generateVariantCandidates`'s ranking. Returns `[]` (with no
 * error) when the archetype has no extractable symbols or nothing matched —
 * an honest empty result, not a crash.
 */
export function generateArchetypeCandidates(
  a: KernelArchetype,
  sourceRoot: string,
  opts: ArchetypeCandidateOptions = {},
): HuntCandidate[] {
  const includeGlobs = opts.includeGlobs ?? ["*.c", "*.h"];
  const maxCandidates = opts.maxCandidates ?? 20;
  const patterns = candidateGrepPatterns(a, opts.bareWords ?? []);
  if (patterns.length === 0) return [];

  const hits = new Map<string, number>();
  for (const pat of patterns) {
    for (const f of grepFiles(pat, sourceRoot, includeGlobs)) {
      hits.set(f, (hits.get(f) ?? 0) + 1);
    }
  }
  const ranked = [...hits.entries()].sort((x, y) => y[1] - x[1]).map(([path]) => path);
  return ranked.slice(0, maxCandidates).map((path) => ({
    path,
    hint: `Archetype ${a.uid} (${a.name}): check whether ${a.pattern}`,
  }));
}

// ── The sweep planner (the only part that touches the filesystem) ──────────

/** Opt-in gate. Default OFF — mirrors 0verse's `ZEROVERSE_FLYWHEEL=1` discipline. */
export function archetypeSweepEnabled(): boolean {
  return !["", "0", "false", "no"].includes((process.env.PWNKIT_ARCHETYPE_SWEEP ?? "").toLowerCase());
}

export interface ArchetypeSweepPlan {
  archetype: KernelArchetype;
  brief: HuntBrief;
  candidates: HuntCandidate[];
  grepPatterns: string[];
}

export interface ArchetypeSweepOptions extends ArchetypeFilter, ArchetypeCandidateOptions {
  sourceRoot: string;
  /** Skip the env gate (tests only — production callers must respect `archetypeSweepEnabled()`). */
  force?: boolean;
  /** Which archetype library to sweep. Defaults to "kernel" (Linux, unchanged behavior). */
  domain?: ArchetypeDomain;
}

export interface ArchetypeSweepResult {
  plans: ArchetypeSweepPlan[];
  warnings: string[];
}

/**
 * Sweep a filtered subset of the kernel archetype library over `sourceRoot`,
 * producing one `{brief, candidates}` pair per archetype — the multi-lens
 * seeding: many bug classes, one invocation, over the same reachable surface.
 * Each plan is meant to feed a separate `runHuntScan({brief, candidates})`
 * call; this function only plans, it never runs a finder or a verifier.
 *
 * Gated by `archetypeSweepEnabled()` (default OFF): when disabled and
 * `opts.force` is not set, returns no plans and a warning explaining why,
 * rather than silently doing nothing.
 *
 * `opts.domain` picks the library: "kernel" (default, Linux, unchanged),
 * "freebsd" (`loadFreebsdArchetypes()`), or "chromium"
 * (`loadChromiumArchetypes()`). Callers sweeping the FreeBSD pack should also
 * pass `bareWords: FREEBSD_BARE_KERNEL_WORDS`, and callers sweeping the
 * Chromium pack should pass `bareWords: CHROMIUM_BARE_WORDS` (see
 * `symbolsFromDetectionSignature`'s header) to actually surface their
 * bare-symbol-shaped candidates (copyout/copyin/malloc for FreeBSD;
 * TurboFan/Member/Deserialize/etc. for Chromium).
 */
export function planArchetypeSweep(opts: ArchetypeSweepOptions): ArchetypeSweepResult {
  if (!opts.force && !archetypeSweepEnabled()) {
    return {
      plans: [],
      warnings: ["archetype sweep disabled (set PWNKIT_ARCHETYPE_SWEEP=1 to enable, or pass force:true)"],
    };
  }
  const warnings: string[] = [];
  const library =
    opts.domain === "freebsd" ? loadFreebsdArchetypes() : opts.domain === "chromium" ? loadChromiumArchetypes() : loadKernelArchetypes();
  const selected = filterArchetypes(library, opts);
  const plans: ArchetypeSweepPlan[] = [];
  for (const archetype of selected) {
    const grepPatterns = candidateGrepPatterns(archetype, opts.bareWords ?? []);
    if (grepPatterns.length === 0) {
      warnings.push(`${archetype.uid}: no extractable symbols in detectionSignature — no self-seeded candidates`);
      continue;
    }
    const candidates = generateArchetypeCandidates(archetype, opts.sourceRoot, opts);
    if (candidates.length === 0) {
      warnings.push(`${archetype.uid}: grep matched nothing under ${opts.sourceRoot}`);
      continue;
    }
    plans.push({ archetype, brief: archetypeToHuntBrief(archetype), candidates, grepPatterns });
  }
  return { plans, warnings };
}
