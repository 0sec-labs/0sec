/**
 * Craft memory — a 5-tier cross-task learning store for the craft agent.
 *
 * This is our implementation of the mechanism the SOTA CyberGym solver
 * (Crystalline) credits for its entire edge over the base model: a tiered memory
 * that LEARNS across tasks. The base model alone scores ~66%; the tiered memory
 * is what lifts it to ~90% — recipes and bug patterns compound from task to task
 * (their procedural knowledge grew 520 → 4,866 entries over 1,507 tasks).
 *
 * The five levels (lowest → highest abstraction):
 *   episodic   — a specific task experience ("arvo:10400: MNG LOOP OOB via len<5")
 *   semantic   — a domain concept ("ASAN flags heap-buffer-overflow on OOB read")
 *   procedural — a reusable construction recipe ("minimal MNG = sig+MHDR+LOOP")
 *   analogical — a cross-domain mapping ("CFF blend stack ≈ realloc-invalidated ptr")
 *   principle  — an abstract invariant ("length checks must precede field reads")
 *
 * remember() appends; recall() ranks by keyword overlap + recency and returns the
 * top-k for a query; consolidate() periodically asks an LLM to promote recent
 * episodes into the higher tiers (Hebbian: patterns that recur get promoted).
 *
 * Storage is append-only JSONL (concurrency-safe across the parallel workers —
 * appends don't clobber, recall is read-only). No native dependency.
 */

import { appendFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";

export type MemoryLevel =
  | "episodic"
  | "semantic"
  | "procedural"
  | "analogical"
  | "principle";

export const MEMORY_LEVELS: MemoryLevel[] = [
  "episodic",
  "semantic",
  "procedural",
  "analogical",
  "principle",
];

export interface Memory {
  id: string;
  level: MemoryLevel;
  /** The knowledge itself (one crisp fact / recipe / principle). */
  content: string;
  /** Where it came from (task id, "preseed", "consolidation"). */
  source: string;
  /** Optional retrieval tags / extra context to match against. */
  context?: string;
  createdAt: number;
}

const STOPWORDS = new Set(
  "the a an of to in on for with and or is are be by at as it its from into via that this you your we our minimal valid use using bytes byte file input".split(" "),
);

function tokenize(s: string): string[] {
  return (s.toLowerCase().match(/[a-z0-9_]{3,}/g) ?? []).filter((t) => !STOPWORDS.has(t));
}

export class CraftMemoryStore {
  private path: string;
  private mems: Memory[] = [];
  private loaded = false;
  /** Count of episodes at the last consolidation, to gate the next one. */
  private lastConsolidatedEpisodeCount = 0;

  constructor(path: string) {
    this.path = path;
  }

  private ensureLoaded(): void {
    if (this.loaded) return;
    this.loaded = true;
    if (!existsSync(this.path)) {
      mkdirSync(dirname(this.path), { recursive: true });
      return;
    }
    for (const line of readFileSync(this.path, "utf8").split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        const m = JSON.parse(t) as Memory;
        if (m && m.id && m.level && m.content) this.mems.push(m);
      } catch {
        /* skip malformed */
      }
    }
    this.lastConsolidatedEpisodeCount = this.mems.filter((m) => m.level === "episodic").length;
  }

  /** Number of memories, optionally by level. */
  count(level?: MemoryLevel): number {
    this.ensureLoaded();
    return level ? this.mems.filter((m) => m.level === level).length : this.mems.length;
  }

  /** Per-level histogram (for stats / logging). */
  stats(): Record<MemoryLevel, number> {
    this.ensureLoaded();
    const out = Object.fromEntries(MEMORY_LEVELS.map((l) => [l, 0])) as Record<MemoryLevel, number>;
    for (const m of this.mems) out[m.level]++;
    return out;
  }

  /** Append a memory (deduped against an identical existing content). */
  remember(input: { level: MemoryLevel; content: string; source: string; context?: string }): Memory | null {
    this.ensureLoaded();
    const content = input.content.trim();
    if (content.length < 8) return null;
    if (this.mems.some((m) => m.level === input.level && m.content === content)) return null;
    const m: Memory = {
      id: randomUUID(),
      level: input.level,
      content,
      source: input.source,
      ...(input.context ? { context: input.context } : {}),
      createdAt: this.mems.length, // monotonic ordinal (no wall clock in the engine)
    };
    this.mems.push(m);
    appendFileSync(this.path, JSON.stringify(m) + "\n", "utf8");
    return m;
  }

  /**
   * Recall the top-k memories for a query: keyword overlap (Jaccard-ish, IDF-light)
   * + a small recency boost, optionally filtered to one level. Higher tiers get a
   * mild prior (a principle/recipe generalizes better than one episode).
   */
  recall(query: string, opts: { topK?: number; level?: MemoryLevel } = {}): Memory[] {
    this.ensureLoaded();
    const topK = opts.topK ?? 6;
    const qTokens = new Set(tokenize(query));
    if (qTokens.size === 0) return [];
    const levelPrior: Record<MemoryLevel, number> = {
      episodic: 0.0,
      semantic: 0.15,
      procedural: 0.25,
      analogical: 0.2,
      principle: 0.3,
    };
    const n = this.mems.length || 1;
    const scored = this.mems
      .filter((m) => (opts.level ? m.level === opts.level : true))
      .map((m) => {
        const mTokens = tokenize(`${m.content} ${m.context ?? ""}`);
        const mset = new Set(mTokens);
        let overlap = 0;
        for (const t of qTokens) if (mset.has(t)) overlap++;
        if (overlap === 0) return { m, score: -1 };
        const score =
          overlap / Math.sqrt(mTokens.length + 1) +
          levelPrior[m.level] +
          0.1 * (m.createdAt / n); // mild recency
        return { m, score };
      })
      .filter((x) => x.score >= 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, topK);
    return scored.map((x) => x.m);
  }

  /**
   * Render recalled memories as a compact bullet list for prompt injection.
   */
  recallText(query: string, opts: { topK?: number } = {}): string {
    const hits = this.recall(query, opts);
    if (hits.length === 0) return "(no relevant memories yet)";
    return hits.map((m) => `- [${m.level}] ${m.content}`).join("\n");
  }

  /** Whether a consolidation is due (≥ everyN new episodes since the last one). */
  consolidationDue(everyN = 20): boolean {
    this.ensureLoaded();
    return this.count("episodic") - this.lastConsolidatedEpisodeCount >= everyN;
  }

  /** The most recent episodic memories (for the consolidation LLM to promote). */
  recentEpisodes(limit = 30): Memory[] {
    this.ensureLoaded();
    return this.mems.filter((m) => m.level === "episodic").slice(-limit);
  }

  /** Mark consolidation done at the current episode count. */
  markConsolidated(): void {
    this.lastConsolidatedEpisodeCount = this.count("episodic");
  }
}
