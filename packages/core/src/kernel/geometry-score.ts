/**
 * kernel/geometry-score.ts
 *
 * EXPLOITABLE-GEOMETRY SCORING — pick bugs by the property that turns a crash
 * into a root, not by "is this code path buggy". This is the LPE-hunt upgrade
 * plan's #0 lever (docs/operations/lpe-hunt-upgrade-plan-2026-07-07.md): the
 * kernelCTF winners select a bug for its OBJECT GEOMETRY. Two properties matter:
 *
 *   1. SIBLING-TYPE TYPE-CONFUSION. A UAF on one member of a class graph whose
 *      siblings are similar-size structs carrying a `_ops` function-pointer table
 *      (net/sched qdisc: HFSC/QFQ/DRR/SFQ/CHOKe; tls; xfrm) gives a clean
 *      type-confusion into a DIFFERENTLY-SEEDED cache — exactly what defeats
 *      RANDOM_KMALLOC_CACHES (CVE-2024-53164, -2025-21700).
 *   2. ELASTIC-RECLAIM PATH. A heap-corruption primitive (UAF / OOB-write) in a
 *      generic kmalloc bucket that a known elastic reclaim object can land in
 *      (msg_msg / pipe_buffer / user_key_payload / xattr / AF_PACKET TX_RING /
 *      BPF map values) — the >20-of-32 data-only weaponization recipe.
 *
 * A pure READ-OOB / DoS with no write and no reclaim path is DEPRIORITIZED even
 * when real: Will Liu found 8 CVEs but only 3 were exploitable — a bug-presence
 * scan wastes effort on the DoS-only 5.
 *
 * Deterministic + rule-based over a Finding's prose (title / description /
 * evidence). No I/O, no LLM, no VM — fully unit-testable. Reuses the reclaim-
 * object vocabulary from the weaponization recipe library (single source of
 * truth for the sprays we know how to land) rather than re-listing it.
 */
import type { Finding } from "@0sec/shared";

import { RECIPE_LIBRARY } from "./exploit/recipes.js";

export interface GeometryScore {
  /** Higher = better exploitable geometry. Signed: pure DoS/read-OOB goes negative. */
  geometryScore: number;
  /** Human-readable justification lines (each signal that fired). */
  rationale: string[];
  /** A sibling-type type-confusion path (the RANDOM_KMALLOC_CACHES defeater). */
  hasTypeConfusion: boolean;
  /** A plausible elastic-reclaim path for a heap-corruption primitive. */
  hasReclaimPath: boolean;
}

// Weights. Type-confusion and a landed reclaim path are the two properties the
// winners actually select on, so they dominate; a heap-corruption primitive with
// no established reclaim still beats a pure DoS; a read-OOB/DoS is pushed below
// zero so it sorts under any weaponizable candidate.
const W_TYPE_CONFUSION = 40;
const W_RECLAIM_PATH = 35;
const W_ELASTIC_OBJECT_NAMED = 15; // extra confidence when a concrete spray object is cited
const W_WRITE_PRIMITIVE = 10; // heap corruption present but no reclaim path established yet
const W_DOS_PENALTY = -40;

// ── Signal vocabularies ──────────────────────────────────────────────────────

/**
 * Reclaim (elastic) object vocabulary. The kmalloc-backed sprays come straight
 * from the weaponization recipe library so the two stay in sync; the extras are
 * the elastic primitives the LPE-hunt plan calls out that the recipe catalog
 * does not yet enumerate as first-class spray objects.
 */
const RECIPE_SPRAY_TOKENS = new Set<string>(RECIPE_LIBRARY.flatMap((r) => r.sprayObjects));
const RECLAIM_FROM_RECIPES = ["msg_msg", "pipe_buffer", "sk_buff", "setxattr"].filter((o) =>
  RECIPE_SPRAY_TOKENS.has(o),
);
const EXTRA_ELASTIC_OBJECTS = [
  "msg_msgseg",
  "msgsnd",
  "user_key_payload",
  "add_key",
  "simple_xattr",
  "xattr",
  "tx_ring",
  "af_packet",
  "bpf map",
  "bpf_map",
];
const ELASTIC_RECLAIM_TERMS = [...new Set([...RECLAIM_FROM_RECIPES, ...EXTRA_ELASTIC_OBJECTS])];

/**
 * net/sched qdisc class-graph siblings + the other sibling-type-rich subsystems
 * the plan flags. Presence of one of these near a UAF is a strong type-confusion
 * geometry signal (a UAF there confuses into a differently-seeded cache).
 */
const SIBLING_CLASS_TERMS = [
  "qdisc",
  "hfsc",
  "qfq",
  "drr",
  "sfq",
  "choke",
  "tc-graft",
  "tc_graft",
  "netem",
];

// A `foo_ops` struct-of-function-pointers next to the bug: the classic
// type-confusion target (overwrite the ops pointer / confuse into an ops-bearing
// sibling → controlled call).
const OPS_STRUCT_RE = /\b[a-z][a-z0-9_]*_ops\b/;

const TYPE_CONFUSION_PHRASES = [
  "type confusion",
  "type-confusion",
  "function pointer",
  "function-pointer",
  "fnptr",
  "vtable",
  "virtual table",
  "ops table",
  "sibling type",
  "sibling struct",
  "same class",
  "class graph",
  "class hierarchy",
];

const WRITE_PRIMITIVE_PHRASES = [
  "use-after-free",
  "use after free",
  "uaf",
  "out-of-bounds write",
  "out of bounds write",
  "oob write",
  "oob-write",
  "slab-out-of-bounds write",
  "double free",
  "double-free",
  "heap overflow",
  "buffer overflow",
  "write-what-where",
  "arbitrary write",
  "heap corruption",
];

const SLAB_CONTEXT_RE = /\bkmalloc(?:-cg)?-\d+\b|\bkmalloc\b|\bkmem_cache\b|\bslab\b/;

// Pure read / DoS shapes: real, but with no write and no reclaim they don't reach root.
const DOS_PHRASES = [
  "out-of-bounds read",
  "out of bounds read",
  "oob read",
  "oob-read",
  "slab-out-of-bounds read",
  "info leak",
  "information leak",
  "memory disclosure",
  "null deref",
  "null-ptr-deref",
  "null pointer deref",
  "null pointer dereference",
  "warn_on",
  "warning:",
  "denial of service",
  "denial-of-service",
  "soft lockup",
  "deadlock",
  "hang",
];

function hasAny(haystack: string, terms: readonly string[]): string | undefined {
  for (const t of terms) if (haystack.includes(t)) return t;
  return undefined;
}

/** Build the searchable prose from a finding (title + description + evidence + category). */
function findingHaystack(finding: Finding): string {
  const ev = finding.evidence ?? ({} as Finding["evidence"]);
  return [
    finding.title,
    finding.description,
    ev?.analysis,
    ev?.request,
    ev?.response,
    finding.category,
  ]
    .filter(Boolean)
    .join("\n")
    .toLowerCase();
}

/**
 * Score a candidate finding by EXPLOITABLE GEOMETRY. Deterministic, rule-based.
 *
 * The ranking intent: a sibling-type type-confusion + elastic-reclaimable
 * heap-corruption candidate scores high; a pure read-OOB / DoS scores below
 * zero, so a caller that sorts by `geometryScore` descending pushes the
 * weaponizable bugs to the front of the (expensive) verify/weaponize queue.
 */
export function scoreGeometry(finding: Finding): GeometryScore {
  const hay = findingHaystack(finding);
  const rationale: string[] = [];
  let score = 0;

  // ── Type-confusion geometry ────────────────────────────────────────────────
  const opsHit = OPS_STRUCT_RE.exec(hay)?.[0];
  const phraseHit = hasAny(hay, TYPE_CONFUSION_PHRASES);
  const classHit = hasAny(hay, SIBLING_CLASS_TERMS);
  const hasTypeConfusion = Boolean(opsHit || phraseHit || classHit);
  if (hasTypeConfusion) {
    score += W_TYPE_CONFUSION;
    const why = [
      opsHit ? `\`${opsHit}\` fn-ptr struct` : "",
      phraseHit ? `"${phraseHit}"` : "",
      classHit ? `sibling class '${classHit}'` : "",
    ]
      .filter(Boolean)
      .join(", ");
    rationale.push(
      `+${W_TYPE_CONFUSION} sibling-type type-confusion geometry (${why}) — defeats RANDOM_KMALLOC_CACHES via a differently-seeded cache`,
    );
  }

  // ── Elastic-reclaim path ───────────────────────────────────────────────────
  const writeHit = hasAny(hay, WRITE_PRIMITIVE_PHRASES);
  const elasticHit = hasAny(hay, ELASTIC_RECLAIM_TERMS);
  const slabContext = SLAB_CONTEXT_RE.test(hay);
  // A heap-corruption write primitive is reclaimable when it lands in a slab
  // bucket (explicit kmalloc/slab context) OR a concrete elastic object is
  // already named. A page-only or stack-only write without slab context does not
  // qualify for the generic slab reclaim (it needs a cross-cache bridge first).
  const hasReclaimPath = Boolean(writeHit) && (slabContext || Boolean(elasticHit));
  if (hasReclaimPath) {
    score += W_RECLAIM_PATH;
    rationale.push(
      `+${W_RECLAIM_PATH} elastic-reclaim path: '${writeHit}' in a ${
        slabContext ? "generic kmalloc/slab bucket" : "reclaimable object"
      } — the data-only weaponization recipe applies`,
    );
    if (elasticHit) {
      score += W_ELASTIC_OBJECT_NAMED;
      rationale.push(
        `+${W_ELASTIC_OBJECT_NAMED} concrete reclaim object cited ('${elasticHit}') — known landable spray`,
      );
    }
  } else if (writeHit) {
    score += W_WRITE_PRIMITIVE;
    rationale.push(
      `+${W_WRITE_PRIMITIVE} heap-corruption primitive ('${writeHit}') but no slab/elastic reclaim path established — needs a cross-cache bridge`,
    );
  }

  // ── Pure read-OOB / DoS penalty ────────────────────────────────────────────
  const dosHit = hasAny(hay, DOS_PHRASES);
  if (dosHit && !writeHit) {
    score += W_DOS_PENALTY;
    rationale.push(
      `${W_DOS_PENALTY} pure read-OOB / DoS ('${dosHit}') with no write primitive — deprioritized (real but not weaponizable to root)`,
    );
  }

  if (rationale.length === 0) {
    rationale.push("no exploitable-geometry signal detected (neutral)");
  }

  return { geometryScore: score, rationale, hasTypeConfusion, hasReclaimPath };
}

/**
 * Stable-sort a list of items by their finding's geometry score, best first.
 * Equal scores preserve input order (stable), so this only ever RE-RANKS — it
 * never drops a candidate. Used by hunt-scan to up-rank weaponizable findings
 * ahead of the expensive verify gate.
 */
export function rankByGeometry<T>(items: readonly T[], findingOf: (item: T) => Finding): T[] {
  return items
    .map((item, i) => ({ item, i, score: scoreGeometry(findingOf(item)).geometryScore }))
    .sort((a, b) => b.score - a.score || a.i - b.i)
    .map((x) => x.item);
}
