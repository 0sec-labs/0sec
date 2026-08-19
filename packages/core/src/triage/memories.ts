/**
 * Semgrep-style "Assistant Memories" — per-target persistent FP context that
 * learns from human triage decisions. When a user marks a finding as a false
 * positive (and says why), the reason is stored as a `TriageMemory`. On future
 * scans the memories are injected as few-shot examples into the verify prompt,
 * and a sufficiently strong match auto-rejects the finding without spending a
 * verification call.
 *
 * Scope hierarchy:
 *   - global   — applies to every scan
 *   - package  — applies to findings whose target starts with a given package
 *                identifier (e.g. an npm package name or repo path prefix)
 *   - target   — applies only to an exact target (URL, repo path, etc.)
 *
 * Relevance is currently computed with a lightweight token-overlap heuristic
 * so the module has zero external dependencies. An embedding-backed ranker can
 * replace `scoreMemory` without touching the public API.
 */

import { randomUUID } from "node:crypto";
import type { Finding } from "@pwnkit/shared";

// ── Public Types ──

export type MemoryScope = "global" | "target" | "package";

export interface TriageMemory {
  id: string;
  scope: MemoryScope;
  /** For scope=target: the target URL. For scope=package: package/repo id. */
  scopeValue?: string;
  /** Vulnerability category this memory relates to (matches Finding.category). */
  category: string;
  /** Short, human-readable description of the FP pattern. */
  pattern: string;
  /** The learned reason this pattern is a false positive. */
  reasoning: string;
  createdAt: number;
  /** How many times this memory has been surfaced to the verify pipeline. */
  appliedCount: number;
}

/**
 * Minimal subset of the @pwnkit/db interface used by MemoryStore. Declared
 * structurally so tests can inject an in-memory fake without pulling in the
 * real better-sqlite3 binding.
 */
export interface MemoryDbHandle {
  insertTriageMemory(row: {
    id: string;
    scope: MemoryScope;
    scopeValue?: string | null;
    category: string;
    pattern: string;
    reasoning: string;
    createdAt: number;
    appliedCount?: number;
  }): void;
  listTriageMemories(opts?: {
    scope?: MemoryScope;
    scopeValue?: string;
    category?: string;
    limit?: number;
  }): Array<{
    id: string;
    scope: MemoryScope;
    scopeValue: string | null;
    category: string;
    pattern: string;
    reasoning: string;
    createdAt: number;
    appliedCount: number;
  }>;
  deleteTriageMemory(id: string): boolean;
  incrementMemoryAppliedCount(id: string): void;
  close?(): void;
}

export interface MemoryStoreOptions {
  /** Optional max number of memories returned by getRelevantMemories. */
  maxRelevant?: number;
  /**
   * Threshold above which a memory is considered a strong match. Callers can
   * use this to auto-reject a finding without invoking the LLM.
   */
  strongMatchThreshold?: number;
}

// ── Helpers ──

const DEFAULT_MAX_RELEVANT = 5;
const DEFAULT_STRONG_MATCH = 0.75;

function normalise(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9\s]/g, " ").replace(/\s+/g, " ").trim();
}

function tokenise(text: string): Set<string> {
  return new Set(
    normalise(text)
      .split(" ")
      .filter((t) => t.length >= 3),
  );
}

/**
 * Token-overlap (Jaccard) similarity between a memory's pattern+reasoning and
 * a finding's title+description+evidence. Cheap, deterministic, and good
 * enough to surface obviously-relevant memories; replace with embeddings for
 * better recall.
 */
export function scoreMemory(memory: TriageMemory, finding: Finding): number {
  const memText = `${memory.pattern} ${memory.reasoning}`;
  const findText = [
    finding.title,
    finding.description,
    finding.evidence?.request ?? "",
    finding.evidence?.response ?? "",
  ].join(" ");

  const memTokens = tokenise(memText);
  const findTokens = tokenise(findText);
  if (memTokens.size === 0 || findTokens.size === 0) return 0;

  let intersect = 0;
  for (const t of memTokens) if (findTokens.has(t)) intersect += 1;
  const union = memTokens.size + findTokens.size - intersect;
  if (union === 0) return 0;
  const jaccard = intersect / union;

  // Boost if the category matches exactly — category is a very strong signal.
  const categoryBoost = memory.category === finding.category ? 0.25 : 0;
  return Math.min(1, jaccard + categoryBoost);
}

/**
 * Derive a best-effort "package" identifier for a target. Used to match
 * memories with scope=package against incoming findings. For HTTP targets the
 * host is used; for filesystem targets the first path segment is used.
 */
export function inferPackage(target: string): string {
  const trimmed = target.trim();
  try {
    if (/^https?:\/\//i.test(trimmed)) {
      return new URL(trimmed).host.toLowerCase();
    }
  } catch {
    // fall through
  }
  const first = trimmed.split(/[\/\\]/).filter((p) => p.length > 0)[0];
  return (first ?? trimmed).toLowerCase();
}

// ── MemoryStore ──

/**
 * Persistent store of triage memories, backed by the pwnkit SQLite database.
 *
 * MemoryStore accepts either a concrete DB path (it will lazily open
 * `@pwnkit/db`'s `pwnkitDB` the first time a method is called) or a custom
 * `MemoryDbHandle` for dependency injection in tests.
 */
export class MemoryStore {
  private dbHandle: MemoryDbHandle | undefined;
  private readonly dbPath: string | undefined;
  private readonly options: Required<MemoryStoreOptions>;

  constructor(dbPathOrHandle?: string | MemoryDbHandle, options?: MemoryStoreOptions) {
    if (typeof dbPathOrHandle === "string" || dbPathOrHandle === undefined) {
      this.dbPath = dbPathOrHandle;
      this.dbHandle = undefined;
    } else {
      this.dbHandle = dbPathOrHandle;
      this.dbPath = undefined;
    }
    this.options = {
      maxRelevant: options?.maxRelevant ?? DEFAULT_MAX_RELEVANT,
      strongMatchThreshold: options?.strongMatchThreshold ?? DEFAULT_STRONG_MATCH,
    };
  }

  private async db(): Promise<MemoryDbHandle> {
    if (this.dbHandle) return this.dbHandle;
    const mod = await import("@pwnkit/db");
    const instance = new mod.pwnkitDB(this.dbPath);
    this.dbHandle = instance as unknown as MemoryDbHandle;
    return this.dbHandle;
  }

  /** Close the underlying database if MemoryStore owns it. */
  async close(): Promise<void> {
    if (this.dbHandle?.close && this.dbPath !== undefined) {
      this.dbHandle.close();
      this.dbHandle = undefined;
    }
  }

  /**
   * Record that a finding is a false positive. A new TriageMemory row is
   * created with the human-provided reasoning and the finding's category.
   */
  async recordFp(
    finding: Finding,
    reason: string,
    scope: MemoryScope,
    scopeValue?: string,
  ): Promise<TriageMemory> {
    const db = await this.db();
    const memory: TriageMemory = {
      id: randomUUID(),
      scope,
      scopeValue: scope === "global" ? undefined : scopeValue,
      category: finding.category,
      pattern: finding.title,
      reasoning: reason,
      createdAt: Date.now(),
      appliedCount: 0,
    };
    db.insertTriageMemory({
      id: memory.id,
      scope: memory.scope,
      scopeValue: memory.scopeValue ?? null,
      category: memory.category,
      pattern: memory.pattern,
      reasoning: memory.reasoning,
      createdAt: memory.createdAt,
      appliedCount: 0,
    });
    return memory;
  }

  /**
   * Positive reinforcement — mark a finding as a confirmed true positive.
   * This is a no-op for now (the pipeline already learns from the confirmed
   * status), but the hook is reserved so future ML backends can lift signal
   * from both classes symmetrically.
   */
  async recordTp(_finding: Finding): Promise<void> {
    // Reserved for future embedding-based fine-tuning / contrastive learning.
  }

  /**
   * Return all memories that could apply to `finding` on `target`, sorted by
   * relevance score and capped at `options.maxRelevant`. A memory applies if:
   *   - scope=global, OR
   *   - scope=target and scopeValue === target, OR
   *   - scope=package and scopeValue === inferPackage(target)
   */
  async getRelevantMemories(finding: Finding, target: string): Promise<TriageMemory[]> {
    const db = await this.db();
    const pkg = inferPackage(target);
    const rows = db.listTriageMemories({ category: finding.category, limit: 500 });

    const applicable = rows.filter((row) => {
      if (row.scope === "global") return true;
      if (row.scope === "target") return row.scopeValue === target;
      if (row.scope === "package") return row.scopeValue === pkg;
      return false;
    });

    const scored = applicable
      .map((row) => {
        const memory: TriageMemory = {
          id: row.id,
          scope: row.scope,
          scopeValue: row.scopeValue ?? undefined,
          category: row.category,
          pattern: row.pattern,
          reasoning: row.reasoning,
          createdAt: row.createdAt,
          appliedCount: row.appliedCount,
        };
        return { memory, score: scoreMemory(memory, finding) };
      })
      .filter((entry) => entry.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, this.options.maxRelevant);

    return scored.map((entry) => entry.memory);
  }

  /**
   * Evaluate whether any memory is a strong enough match to auto-reject
   * the finding without invoking the LLM. Returns the winning memory (and its
   * score) when one exceeds the configured threshold, `null` otherwise.
   */
  async findStrongMatch(
    finding: Finding,
    target: string,
  ): Promise<{ memory: TriageMemory; score: number } | null> {
    const memories = await this.getRelevantMemories(finding, target);
    for (const memory of memories) {
      const score = scoreMemory(memory, finding);
      if (score >= this.options.strongMatchThreshold) {
        return { memory, score };
      }
    }
    return null;
  }

  /**
   * Track that a memory was surfaced to the verify pipeline. Safe to call
   * repeatedly — the store only cares about relative counts for analytics.
   */
  async recordApplied(memoryId: string): Promise<void> {
    const db = await this.db();
    db.incrementMemoryAppliedCount(memoryId);
  }

  async listAll(): Promise<TriageMemory[]> {
    const db = await this.db();
    const rows = db.listTriageMemories({ limit: 500 });
    return rows.map((row) => ({
      id: row.id,
      scope: row.scope,
      scopeValue: row.scopeValue ?? undefined,
      category: row.category,
      pattern: row.pattern,
      reasoning: row.reasoning,
      createdAt: row.createdAt,
      appliedCount: row.appliedCount,
    }));
  }

  async remove(id: string): Promise<boolean> {
    const db = await this.db();
    return db.deleteTriageMemory(id);
  }

  /**
   * Format a list of memories as a markdown block suitable for injection into
   * a structured-verify system prompt. Returns an empty string when there are
   * no memories so callers can unconditionally concatenate the output.
   */
  async formatForPrompt(memories: TriageMemory[]): Promise<string> {
    if (memories.length === 0) return "";
    const lines: string[] = [];
    lines.push("## Learned False-Positive Memories");
    lines.push("");
    lines.push(
      "The following patterns were previously confirmed as FALSE POSITIVES by human reviewers on this target or similar codebases. Treat them as strong priors: if the current finding matches one of these patterns, lean toward rejecting it.",
    );
    lines.push("");
    for (let i = 0; i < memories.length; i += 1) {
      const m = memories[i]!;
      const scopeLabel =
        m.scope === "global"
          ? "global"
          : `${m.scope}:${m.scopeValue ?? "?"}`;
      lines.push(`${i + 1}. [${scopeLabel}] **${m.pattern}** (${m.category})`);
      lines.push(`   Why it's a FP: ${m.reasoning}`);
    }
    lines.push("");
    return lines.join("\n");
  }
}
