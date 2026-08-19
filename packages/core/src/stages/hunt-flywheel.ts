/**
 * Hunt memory flywheel — a preseeded 5-layer cognitive memory that PRIMES
 * 0sec's kernel hunt (`runHuntScan`). Ports 0verse's PoV-dataset flywheel
 * (bench:`/root/0verse/src/zeroverse/flywheel.py`, "#43 (M7 Bet B)") into
 * 0sec, reusing what's already here instead of re-inventing it:
 *
 *   - PRINCIPLE / SEMANTIC / PROCEDURAL are preseeded from the 34-entry kernel
 *     archetype registry (`archetype-catalog.ts`'s `loadKernelArchetypes()`) —
 *     the concepts, sink associations, and confirmation procedures.
 *   - EPISODIC / ANALOGICAL are preseeded from the hunt-variant corpus
 *     (`@0sec/benchmark`'s `hunt-variant-v1.jsonl`, read by PATH here — core
 *     must not depend on `@0sec/benchmark`, the wrong dependency direction)
 *     — past finder findings + their skeptic verdicts, and cross-site links
 *     when the same bug class recurred across candidates.
 *
 * Like 0verse's registry, the store ships FULL at construction, never empty:
 * an earlier "consolidate an empty store at run time" design extracts nothing
 * (0verse's own lesson, kept verbatim in the module header there).
 *
 * Three operations, all opt-in (`0SEC_HUNT_FLYWHEEL=1`, default OFF):
 *
 *   1. `recall(brief)` — the most-similar past concepts/procedures/findings,
 *      by a bug-class/CWE + sink-symbol token join key (`classTokens`),
 *      Jaccard-scored.
 *   2. `prime(brief, recalled)` — turns a recall into a funnel injection: a
 *      framing string, a bounded rank-bonus function, and a cost-router hint.
 *   3. `remember(record, brief)` — folds a hunt run's finding back into the
 *      EPISODIC layer so the next run's preseed can recall it.
 *
 * ============================================================================
 * THE INVARIANT: the flywheel PRIMES; it never CONFIRMS.
 * ============================================================================
 * No method here returns a confirmed verdict. `HuntPriming.rankBonus` only
 * ever feeds the best-of-N judge ORDERING and the attempt-budget cost-router
 * in `hunt-scan.ts`'s `runHuntScan` — never `opts.verify` (the skeptic+prover
 * gate), which stays the sole adjudicator, called with exactly
 * `(finding, candidate)`, byte-identical whether the flywheel is on or off.
 * See `runHuntScan`'s best-of-N ranking block in `hunt-scan.ts` for the exact
 * enforcement point, and `provePriming()` below for a controlled proof: a
 * similar target's judge-rank is lifted, an un-similar control's is not (delta
 * 0 — no spurious lift), and confirmation never enters the ordering key.
 */

import { readFileSync } from "node:fs";
import type { Finding } from "@0sec/shared";
import { loadKernelArchetypes, symbolsFromDetectionSignature } from "./archetype-catalog.js";
import type { HuntBrief, HuntFindingRecord } from "./hunt-scan.js";
import type { LensCandidate } from "./lens-synthesis/types.js";

// ── Opt-in gate ──────────────────────────────────────────────────────────────

/** Default OFF — mirrors 0verse's `ZEROVERSE_FLYWHEEL=1` / `archetypeSweepEnabled()`'s discipline. */
export function huntFlywheelEnabled(): boolean {
  return !["", "0", "false", "no"].includes((process.env["0SEC_HUNT_FLYWHEEL"] ?? "").toLowerCase());
}

// ── Layers ───────────────────────────────────────────────────────────────────

export type HuntMemoryLayer = "principle" | "semantic" | "procedural" | "episodic" | "analogical";
export const HUNT_MEMORY_LAYERS: readonly HuntMemoryLayer[] = [
  "principle",
  "semantic",
  "procedural",
  "episodic",
  "analogical",
];

/** A recall must clear this combined-similarity floor to prime the funnel. Below it, the cost-router suggests the cheap lane. */
export const PRIME_MIN = 0.18;

// ── The cross-corpus join key (bug-class + sink-symbol token set) ──────────
// Mirrors flywheel.py's `class_tokens`: normalize a CWE code / bug-class
// phrase / archetype name to a comparable token set so a corpus row spelling
// a class "CWE-416" and an archetype spelling it "deferred-free UAF" still
// join on a shared "uaf" token.

const CWE_RX = /cwe-\d+/gi;
const _LENS_CLASS_IDS = [
  "uaf",
  "overflow",
  "oob",
  "intoverflow",
  "race",
  "refcount",
  "typeconfusion",
  "nullderef",
  "infoleak",
  "fmtstring",
  "cmdi",
  "toctou",
] as const;
const _PHRASE_TO_CLASS: Record<string, string> = {
  "use-after-free": "uaf",
  "use after free": "uaf",
  "deferred-free": "uaf",
  "deferred free": "uaf",
  "double-free": "uaf",
  "double free": "uaf",
  refcount: "refcount",
  "reference count": "refcount",
  "out-of-bounds": "oob",
  "out of bounds": "oob",
  "oob write": "oob",
  "oob read": "oob",
  "buffer overflow": "overflow",
  "stack overflow": "overflow",
  "heap overflow": "overflow",
  "integer overflow": "intoverflow",
  "type confusion": "typeconfusion",
  "race condition": "race",
  toctou: "toctou",
  "null pointer": "nullderef",
  "null-pointer": "nullderef",
  "information leak": "infoleak",
  "info leak": "infoleak",
  "format string": "fmtstring",
  "command injection": "cmdi",
};

/**
 * Normalize one or more class spellings (CWE codes, archetype names,
 * free-text bug descriptions) to a comparable token set: every `cwe-\d+` code
 * plus any recognized lens-id / phrase. The join key that lets a corpus row's
 * `CWE-416` meet an archetype's "deferred-free UAF" name.
 */
export function classTokens(...parts: Array<string | undefined>): ReadonlySet<string> {
  const blob = parts
    .filter((p): p is string => Boolean(p))
    .join(" ")
    .toLowerCase();
  const toks = new Set<string>();
  for (const m of blob.matchAll(CWE_RX)) toks.add(m[0]);
  for (const cid of _LENS_CLASS_IDS) if (new RegExp(`\\b${cid}\\b`).test(blob)) toks.add(cid);
  for (const [phrase, cid] of Object.entries(_PHRASE_TO_CLASS)) if (blob.includes(phrase)) toks.add(cid);
  return toks;
}

/** Jaccard similarity of two token sets; 0 when either is empty. */
export function jaccard(a: ReadonlySet<string>, b: ReadonlySet<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  const union = a.size + b.size - inter;
  return union ? inter / union : 0;
}

/** class-token + sink-symbol-token pair for an arbitrary text blob (reuses `symbolsFromDetectionSignature`'s conservative snake_case-symbol extraction as the sink-token vocabulary). */
export function memoryTokens(
  bugClass: string | undefined,
  pattern: string | undefined,
  text: string,
): { classToks: ReadonlySet<string>; sinkToks: ReadonlySet<string> } {
  return {
    classToks: classTokens(bugClass, pattern, text),
    sinkToks: new Set(symbolsFromDetectionSignature(`${pattern ?? ""} ${text}`)),
  };
}

/** class/sink tokens for a live `Finding` — the query side of a recall over a raw finder result. */
export function findingTokens(f: Finding): { classToks: ReadonlySet<string>; sinkToks: ReadonlySet<string> } {
  const text = `${f.title} ${f.description} ${f.evidence?.analysis ?? ""}`;
  return memoryTokens(undefined, undefined, text);
}

// ── Memory record + recall result ───────────────────────────────────────────

export interface HuntMemoryRecord {
  layer: HuntMemoryLayer;
  key: string;
  classTokens: ReadonlySet<string>;
  sinkTokens: ReadonlySet<string>;
  /** Variant-analysis framing to prime the funnel; "" when this layer has none. */
  framing: string;
  text: string;
  provenance: string;
  confirmed: boolean;
  /** A small prior (a proven-fruitful episodic memory outweighs a raw principle). */
  weight: number;
}

export interface HuntRecall {
  memory: HuntMemoryRecord;
  score: number;
  reasons: string[];
}

function scoreMemory(
  queryClass: ReadonlySet<string>,
  querySink: ReadonlySet<string>,
  m: HuntMemoryRecord,
): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  const cls = jaccard(queryClass, m.classTokens);
  if (cls) reasons.push(`class:${cls.toFixed(2)}`);
  const snk = jaccard(querySink, m.sinkTokens);
  if (snk) reasons.push(`sink:${snk.toFixed(2)}`);
  // Class match dominates (it's the more reliable signal across corpora); sink
  // overlap corroborates. Mirrors flywheel.py's class-dominant weighted blend.
  const base = 0.65 * cls + 0.35 * snk;
  const score = Math.min(1, Math.round(base * m.weight * 10_000) / 10_000);
  return { score, reasons };
}

// ── Priming (the funnel injection) ──────────────────────────────────────────

export interface HuntPriming {
  active: boolean;
  recalls: HuntRecall[];
  framing: string;
  context: string;
  topScore: number;
  costRoute: "full" | "cheap";
  costReason: string;
  /**
   * A bounded [0, 0.70] ordering bonus for a finding that matches recalled
   * memory (0.50 for a primed sink-symbol hit, 0.20 for a primed class-token
   * hit). Gated by `active`: an un-similar target always gets 0. This affects
   * ONLY queue ordering — it is never passed to `opts.verify`.
   */
  rankBonus(finding: Finding): number;
}

function noSignalPriming(): HuntPriming {
  return {
    active: false,
    recalls: [],
    framing: "",
    context: "",
    topScore: 0,
    costRoute: "cheap",
    costReason: "no similar memory above PRIME_MIN — cost-router suggests the cheap lane",
    rankBonus: () => 0,
  };
}

function contextBlock(recalls: HuntRecall[]): string {
  const lines = [
    "PRIMING — most similar prior knowledge (memory PRIMES; the skeptic+prover gate still confirms):",
  ];
  for (const r of recalls) lines.push(`  [${r.memory.layer} ${r.score.toFixed(2)} ${r.reasons.join(",")}] ${r.memory.text}`);
  return lines.join("\n");
}

/**
 * The exact ordering key `runHuntScan`'s best-of-N judge uses when priming is
 * active: the judge score normalized to 0..1 plus the bounded rank-bonus.
 * Exported so `provePriming` (and any test) exercises the SAME function wired
 * into production, not a re-implementation that could drift out of sync.
 * When `priming` is `null` the caller should use the raw `judgeScore`
 * directly — see `runHuntScan`'s ranking block.
 */
export function primedOrderKey(judgeScore: number, priming: HuntPriming, finding: Finding): number {
  return judgeScore / 10 + priming.rankBonus(finding);
}

// ── Corpus row shape (hunt-variant-v1.jsonl) ────────────────────────────────
// Read by path, not import: `@0sec/core` must not depend on
// `@0sec/benchmark` (hunt-corpus.ts there depends on `@0sec/core`, not the
// other way around). This is a minimal structural subset of `HuntSample`.

export interface HuntCorpusRow {
  candidatePath?: string;
  bugClass?: string;
  pattern?: string;
  fixReference?: string;
  model?: string;
  judgeScore?: number;
  skepticConfirmed?: boolean;
  skepticReason?: string;
  duplicate?: boolean;
  finding?: { title?: string; description?: string; evidence?: { analysis?: string } };
}

/**
 * Best-effort NDJSON read of a hunt-variant corpus file. A missing, empty, or
 * unparseable-line file is a no-op (one bad line is skipped, never thrown) —
 * the archetype preseed already stands on its own without it.
 */
export function loadHuntCorpusRows(path: string): HuntCorpusRow[] {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  const rows: HuntCorpusRow[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      rows.push(JSON.parse(trimmed) as HuntCorpusRow);
    } catch {
      // one malformed line must not sink the whole preseed
    }
  }
  return rows;
}

// ── Preseed builders ─────────────────────────────────────────────────────────

const _ROUTE_PROCEDURE: Record<string, string> = {
  "kernel-static": "grep-visible on source; a confirmed hit is plausible via the skeptic-only gate",
  "kernel-verify": "hypothesis only — build+boot+KASAN kernel-verify lane required before it counts as proven",
  "not-binary-detectable": "no static/binary signal — needs source-level review or an honest hand-off",
};

function procedureForRoute(route: string): string {
  return _ROUTE_PROCEDURE[route] ?? "route-specific confirmation procedure";
}

// ── HuntMemory: the preseeded 5-layer store + recall / prime / remember ────

export interface HuntMemoryOptions {
  /**
   * Path to a hunt-variant NDJSON corpus (episodic/analogical preseed).
   * Optional — a missing path is a no-op; PRINCIPLE/SEMANTIC/PROCEDURAL
   * (the archetype preseed) always stand on their own.
   */
  corpusPath?: string;
}

export class HuntMemory {
  private readonly memories: HuntMemoryRecord[] = [];

  /**
   * The self-improving lens loop's miss store — a store DISJOINT from the
   * 5-layer priming `memories` above. It holds CANDIDATE lenses (proposals to
   * hunt a class the finder missed), which stage 2 of the lens loop clusters
   * and synthesizes. It is intentionally NOT a `HuntMemoryLayer` and never
   * enters `recall`/`prime`/`scoreMemory`, so the "primes, never confirms"
   * invariant on the priming path is byte-unaffected: recording a miss cannot
   * change any recall score, any rank-bonus, or any cost-route. See
   * lens-synthesis/miss-capture.ts.
   */
  private readonly missCandidates: LensCandidate[] = [];

  constructor(opts: HuntMemoryOptions = {}) {
    this.preseedArchetypes();
    if (opts.corpusPath) this.loadCorpus(opts.corpusPath);
  }

  private add(m: HuntMemoryRecord): void {
    this.memories.push(m);
  }

  private preseedArchetypes(): void {
    for (const a of loadKernelArchetypes()) {
      const sinkToks = new Set(symbolsFromDetectionSignature(a.detectionSignature));
      const clsToks = classTokens(a.cwe, a.name, a.pattern);
      const framing = `VARIANT ANALYSIS (${a.cwe}): hunt siblings of the '${a.name}' pattern — ${a.detectionSignature.slice(0, 160)}`;
      // PRINCIPLE: the pattern + the honest confirmability limit.
      this.add({
        layer: "principle",
        key: `principle:${a.uid}`,
        classTokens: clsToks,
        sinkTokens: sinkToks,
        framing,
        text: `[${a.uid}] ${a.name}: ${a.pattern}  LIMIT: ${a.confirmableNote}`,
        provenance: `archetype:${a.uid}`,
        confirmed: false,
        weight: 1.0,
      });
      // SEMANTIC: bug-class -> sink-symbol association (only when the
      // detection signature actually named extractable symbols).
      if (sinkToks.size > 0) {
        this.add({
          layer: "semantic",
          key: `semantic:${a.uid}`,
          classTokens: clsToks,
          sinkTokens: sinkToks,
          framing,
          text: `${a.cwe} (${a.subsystem}) sinks=${[...sinkToks].sort().join(",")}`,
          provenance: `archetype:${a.uid}`,
          confirmed: false,
          weight: 1.0,
        });
      }
      // PROCEDURAL: how this class is confirmed (the route-specific gate shape).
      this.add({
        layer: "procedural",
        key: `procedural:${a.uid}`,
        classTokens: clsToks,
        sinkTokens: sinkToks,
        framing: "",
        text: `route=${a.route}: ${procedureForRoute(a.route)}`,
        provenance: `archetype:${a.uid}`,
        confirmed: false,
        weight: 0.9,
      });
    }
  }

  /** Fold a hunt-variant NDJSON corpus into EPISODIC (+ ANALOGICAL for bug classes seen at >1 site). Returns the number of episodic rows added. */
  loadCorpus(path: string): number {
    const rows = loadHuntCorpusRows(path);
    const analog = new Map<string, { members: Set<string>; classToks: Set<string> }>();
    let added = 0;
    for (const row of rows) {
      const text = `${row.finding?.title ?? ""} ${row.finding?.description ?? ""} ${row.finding?.evidence?.analysis ?? ""}`;
      const { classToks, sinkToks } = memoryTokens(row.bugClass, row.pattern, text);
      const confirmed = row.skepticConfirmed === true;
      this.add({
        layer: "episodic",
        key: `episodic:${row.candidatePath ?? ""}:${row.finding?.title ?? added}`,
        classTokens: classToks,
        sinkTokens: sinkToks,
        framing: confirmed
          ? `a confirmed ${row.bugClass ?? "bug"} was found on a similar site (${row.candidatePath ?? ""}) — hunt its sibling here`
          : "",
        text: `${row.candidatePath ?? ""}: ${row.bugClass ?? ""} [skeptic=${row.skepticConfirmed ?? "unrun"}]`,
        provenance: `record:${row.candidatePath ?? ""} model=${row.model ?? "default"}`,
        confirmed,
        weight: confirmed ? 1.15 : 0.85,
      });
      added++;
      if (row.bugClass) {
        const acc = analog.get(row.bugClass) ?? { members: new Set<string>(), classToks: new Set<string>() };
        if (row.candidatePath) acc.members.add(row.candidatePath);
        for (const t of classToks) acc.classToks.add(t);
        analog.set(row.bugClass, acc);
      }
    }
    for (const [bugClass, acc] of analog) {
      if (acc.members.size < 2) continue; // an analogical link needs >1 distinct site
      this.add({
        layer: "analogical",
        key: `analogical:${bugClass}`,
        classTokens: acc.classToks,
        sinkTokens: new Set(),
        framing: `the '${bugClass}' pattern recurs across ${acc.members.size} site(s) — treat this as another sibling`,
        text: `cross-site link: ${bugClass} seen on ${[...acc.members].sort().join(", ")}`,
        provenance: `corpus:${bugClass} members=${acc.members.size}`,
        confirmed: false,
        weight: Math.min(1.3, 1.0 + 0.05 * acc.members.size),
      });
    }
    return added;
  }

  counts(): Record<string, number> {
    const c: Record<string, number> = {};
    for (const layer of HUNT_MEMORY_LAYERS) c[layer] = 0;
    for (const m of this.memories) c[m.layer] = (c[m.layer] ?? 0) + 1;
    c.total = this.memories.length;
    return c;
  }

  /** Retrieve the top-`topK` memories most similar to `brief`, ranked by combined similarity. The 'Recall' step. */
  recall(brief: HuntBrief, opts: { topK?: number; minScore?: number } = {}): HuntRecall[] {
    const topK = opts.topK ?? 5;
    const minScore = opts.minScore ?? PRIME_MIN;
    const queryClass = classTokens(brief.bugClass, brief.pattern, brief.fixReference);
    const querySink = new Set(symbolsFromDetectionSignature(brief.pattern));
    const scored: HuntRecall[] = [];
    for (const m of this.memories) {
      const { score, reasons } = scoreMemory(queryClass, querySink, m);
      if (score >= minScore) scored.push({ memory: m, score, reasons });
    }
    scored.sort((a, b) => b.score - a.score || a.memory.layer.localeCompare(b.memory.layer) || a.memory.key.localeCompare(b.memory.key));
    return scored.slice(0, topK);
  }

  /**
   * Turn a recall into a funnel injection: a framing string, a RAG context
   * block, a rank-bonus over the recalled sinks/classes, and a cost-router
   * hint. Returns the inert no-signal priming when `recalled` (or a fresh
   * `recall(brief)`) is empty. PRIMES only — never a verdict.
   */
  prime(brief: HuntBrief, recalled?: HuntRecall[]): HuntPriming {
    const recalls = recalled ?? this.recall(brief);
    if (recalls.length === 0) return noSignalPriming();
    const top = recalls[0];
    const primedClassTokens = new Set<string>();
    const primedSinkTokens = new Set<string>();
    for (const r of recalls) {
      for (const t of r.memory.classTokens) primedClassTokens.add(t);
      for (const t of r.memory.sinkTokens) primedSinkTokens.add(t);
    }
    const framing = recalls.find((r) => r.memory.framing)?.memory.framing ?? "";
    const context = contextBlock(recalls);
    return {
      active: true,
      recalls,
      framing,
      context,
      topScore: top.score,
      costRoute: "full",
      costReason: `recalled ${recalls.length} similar memory/-ies (top=${top.score.toFixed(2)}) — escalate to the full lane`,
      rankBonus: (finding: Finding) => {
        const { classToks, sinkToks } = findingTokens(finding);
        let bonus = 0;
        for (const t of sinkToks) {
          if (primedSinkTokens.has(t)) {
            bonus += 0.5;
            break;
          }
        }
        for (const t of classToks) {
          if (primedClassTokens.has(t)) {
            bonus += 0.2;
            break;
          }
        }
        return Math.min(0.7, bonus);
      },
    };
  }

  /**
   * Capture: fold one hunt-run finding record back into EPISODIC. Reuses
   * `HuntFindingRecord` — the same shape `@0sec/benchmark`'s
   * `hunt-corpus.ts` persists — so this stores labels + pointers only (never
   * raw bytes beyond what the `Finding` itself already carries). Next
   * construction's `loadCorpus` reads it back: the loop closes across runs.
   */
  remember(record: HuntFindingRecord, brief?: HuntBrief): void {
    const text = `${record.finding.title} ${record.finding.description} ${record.finding.evidence?.analysis ?? ""}`;
    const bugClass = brief?.bugClass;
    const { classToks, sinkToks } = memoryTokens(bugClass, brief?.pattern, text);
    const confirmed = record.skepticConfirmed === true;
    this.add({
      layer: "episodic",
      key: `episodic:${record.candidatePath}:${record.finding.id}`,
      classTokens: classToks,
      sinkTokens: sinkToks,
      framing: confirmed
        ? `a confirmed ${bugClass ?? "bug"} was found on a similar site (${record.candidatePath}) — hunt its sibling here`
        : "",
      text: `${record.candidatePath}: ${bugClass ?? record.finding.title} [skeptic=${record.skepticConfirmed ?? "unrun"}]`,
      provenance: `record:${record.candidatePath} model=${record.model ?? "default"}`,
      confirmed,
      weight: confirmed ? 1.15 : 0.85,
    });
  }

  // ── Lens-loop miss store (disjoint from the priming layers) ──────────────
  //
  // These three methods are the ONLY surface that touches `missCandidates`.
  // None of them reads or writes the 5-layer `memories`, and none is called by
  // `recall`/`prime`, so they cannot perturb priming. This stores lens
  // PROPOSALS; it never confirms a finding — the invariant holds.

  /** Persist ONE coverage-miss candidate for the lens-synthesis loop to consume. */
  recordMiss(candidate: LensCandidate): void {
    this.missCandidates.push(candidate);
  }

  /** How many miss candidates are queued. */
  missCandidateCount(): number {
    return this.missCandidates.length;
  }

  /**
   * Return every queued miss candidate and CLEAR the store (drain semantics),
   * so a subsequent loop run starts from an empty queue and cannot
   * double-synthesize the same miss. Returns a copy — the caller owns it.
   */
  drainMissCandidates(): LensCandidate[] {
    return this.missCandidates.splice(0, this.missCandidates.length);
  }
}

// ============================================================================
// PROOF — primed vs cold, with an un-similar control (real, computed numbers)
// ============================================================================

export interface HuntProofReport {
  similarRecallTop: number;
  controlRecallTop: number;
  similarColdRank: number;
  similarPrimedRank: number;
  controlColdRank: number;
  controlPrimedRank: number;
  similarCostRoute: "full" | "cheap";
  controlCostRoute: "full" | "cheap";
}

function mkProofFinding(id: string, title: string, analysis: string): Finding {
  return {
    id,
    templateId: "hunt-flywheel-proof",
    title,
    description: title,
    severity: "medium",
    category: "other",
    status: "discovered",
    evidence: { request: "", response: "", analysis },
  } as Finding;
}

/** 1-indexed rank of `targetId` under the SAME ordering key `runHuntScan` uses (`primedOrderKey` when `priming` is set, the raw judge score when it is `null`). */
function rankToLocate(findings: Finding[], scores: Map<string, number>, priming: HuntPriming | null, targetId: string): number {
  const ordered = [...findings].sort((a, b) => {
    const ka = priming ? primedOrderKey(scores.get(a.id) ?? 0, priming, a) : (scores.get(a.id) ?? 0);
    const kb = priming ? primedOrderKey(scores.get(b.id) ?? 0, priming, b) : (scores.get(b.id) ?? 0);
    return kb - ka;
  });
  return ordered.findIndex((f) => f.id === targetId) + 1;
}

/**
 * Controlled primed-vs-cold proof — the TS mirror of 0verse's
 * `prove_priming()` (bench:`/root/0verse/src/zeroverse/flywheel.py`). Seeds
 * memory with ONE confirmed nf_tables deferred-free UAF record (the
 * `kernel/NF-01` archetype's exact shape), then measures how many judge-rank
 * positions are needed to reach a MATCHING finding on a SIMILAR site (buried
 * under generic noise) — cold (judge score only) vs primed (judge score +
 * flywheel rank-bonus) — and repeats on an UN-SIMILAR control (a format-string
 * finding; no kernel archetype or seeded memory shares its tokens). Never
 * calls `opts.verify` — only the ordering key `runHuntScan` itself uses — so
 * this is a pure re-ordering proof, not a confirmation.
 */
export function provePriming(): HuntProofReport {
  const memory = new HuntMemory();
  const brief: HuntBrief = {
    bugClass: "nf_tables set-element deferred-free UAF (CWE-416)",
    pattern:
      "nft_set_elem_deactivate then a GC/async destroy races the commit path and frees the element while still referenced",
  };
  memory.remember(
    {
      candidatePath: "net/netfilter/nf_tables_api.c",
      model: "proof-seed",
      attempt: 0,
      finding: mkProofFinding(
        "seed",
        "nf_tables deferred-free UAF",
        "nft_set_elem_deactivate races nft_set_gc_intr, use-after-free",
      ),
      skepticConfirmed: true,
      skepticReason: "reproduced under KASAN",
      duplicate: false,
    },
    brief,
  );

  // SIMILAR target: the same class/site shape, generically UNDER-scored (a
  // real finder often ranks a vendor/kernel-specific sink low by keyword
  // overlap alone) and buried under higher-scoring generic noise.
  const similarTarget = mkProofFinding(
    "similar-target",
    "nf_tables element UAF",
    "nft_set_elem_deactivate use-after-free race with gc",
  );
  const similarFindings = [
    mkProofFinding("similar-n1", "unrelated parse bug", "generic parsing issue"),
    mkProofFinding("similar-n2", "unrelated overflow", "generic overflow issue"),
    similarTarget,
  ];
  const similarScores = new Map<string, number>([
    ["similar-target", 2],
    ["similar-n1", 6],
    ["similar-n2", 5],
  ]);

  // CONTROL: an un-similar finding (format-string, not a kernel-archetype
  // class at all) — memory must NOT lift it; the cost-router should route it
  // to the cheap lane.
  const controlTarget = mkProofFinding("control-target", "format string bug", "sprintf with unchecked user format string");
  const controlFindings = [
    mkProofFinding("control-n1", "unrelated overflow", "generic overflow issue"),
    mkProofFinding("control-n2", "unrelated parse bug", "generic parsing issue"),
    controlTarget,
  ];
  const controlScores = new Map<string, number>([
    ["control-target", 2],
    ["control-n1", 6],
    ["control-n2", 5],
  ]);
  const controlBrief: HuntBrief = { bugClass: "format string bug", pattern: "sprintf unchecked user format string" };

  const similarRecall = memory.recall(brief);
  const controlRecall = memory.recall(controlBrief);
  const similarPriming = memory.prime(brief, similarRecall);
  const controlPriming = memory.prime(controlBrief, controlRecall);

  return {
    similarRecallTop: similarRecall[0]?.score ?? 0,
    controlRecallTop: controlRecall[0]?.score ?? 0,
    similarColdRank: rankToLocate(similarFindings, similarScores, null, "similar-target"),
    similarPrimedRank: rankToLocate(similarFindings, similarScores, similarPriming, "similar-target"),
    controlColdRank: rankToLocate(controlFindings, controlScores, null, "control-target"),
    controlPrimedRank: rankToLocate(controlFindings, controlScores, controlPriming, "control-target"),
    similarCostRoute: similarPriming.costRoute,
    controlCostRoute: controlPriming.costRoute,
  };
}
