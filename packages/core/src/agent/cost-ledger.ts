// Shared per-scan cost ledger.
//
// A single scan run drives MULTIPLE agent sessions: the unified pipeline
// runs one research session plus a concurrent blind-verify wave (one session
// per finding), and the per-file research loop runs one session per source
// file. Each session tracks its own `state.totalUsage` from zero, so a hard
// per-scan cost ceiling checked against session-local usage binds every
// session individually but never the scan as a whole — a $3 ceiling still
// allowed research($3) + N × verify($3) of real spend (prod 0review scans
// landed at $4.99 / $6.36 against the $3 ZERO_REVIEW_COST_CEILING_USD).
//
// The fix is this ledger: the pipeline creates ONE instance per run and
// threads it through every agent session. Each native-loop turn adds its
// token usage here, and the per-turn ceiling check prices the ledger's
// cross-session cumulative total instead of the session's alone. Verify
// sessions run concurrently (Promise.all); since each adds only its own
// usage and reads the shared total, the wave trips within one turn of the
// collective spend crossing the ceiling (overshoot bounded by one in-flight
// turn per active session).
//
// The ledger is also the source of truth for the scan_completed event's
// cost_usd + per-model cost_breakdown, so the cloud sees the true
// cross-session cumulative rather than any single session's segment.

import { estimateCost, modelProvider, splitCost } from "./cost.js";
import type { CostBreakdownEntry } from "../events/bus.js";
import type { TokenUsageForPricing } from "@pwnkit/shared";

interface UsageBucket {
  inputTokens: number;
  outputTokens: number;
  cachedInputTokens: number;
}

export class ScanCostLedger {
  private inputTokens = 0;
  private outputTokens = 0;
  private cachedInputTokens = 0;
  private readonly perModel = new Map<string, UsageBucket>();

  /**
   * Fold one turn's token usage into the cumulative total. `model` (the
   * session's pricing model) keys the per-model buckets the cost_breakdown
   * is derived from; sessions without a model pick land in "unknown".
   */
  add(usage: TokenUsageForPricing, model?: string): void {
    this.inputTokens += usage.inputTokens;
    this.outputTokens += usage.outputTokens;
    this.cachedInputTokens += usage.cachedInputTokens ?? 0;
    const key = model ?? "unknown";
    const bucket =
      this.perModel.get(key) ??
      { inputTokens: 0, outputTokens: 0, cachedInputTokens: 0 };
    bucket.inputTokens += usage.inputTokens;
    bucket.outputTokens += usage.outputTokens;
    bucket.cachedInputTokens += usage.cachedInputTokens ?? 0;
    this.perModel.set(key, bucket);
  }

  /** Cumulative estimated cost (USD) across every contributing session. */
  costUsd(model?: string): number {
    return estimateCost(
      {
        inputTokens: this.inputTokens,
        outputTokens: this.outputTokens,
        cachedInputTokens: this.cachedInputTokens,
      },
      model,
    );
  }

  /**
   * The model every contributing session used, when they all agree (and it
   * is a real model id, not the "unknown" bucket). Undefined for multi-model
   * runs and for runs whose sessions never named one — the caller then
   * leaves the model field to its own resolution.
   */
  soleModel(): string | undefined {
    if (this.perModel.size !== 1) return undefined;
    const [key] = this.perModel.keys();
    return key === "unknown" ? undefined : key;
  }

  /**
   * Aggregate the recorded usage into the cloud's per-(provider, model)
   * cost_breakdown shape — the same aggregation agentic-scanner's
   * emitScanCompleted applies to its per-stage tally, sourced here from the
   * true cross-session cumulative. Zero-usage buckets are skipped so the
   * breakdown stays honest. Returns null when nothing was recorded at all,
   * so callers omit cost_usd / cost_breakdown rather than emit a
   * misleading $0.
   */
  costBreakdown(): { costUsd: number; breakdown: CostBreakdownEntry[] } | null {
    const acc = new Map<string, CostBreakdownEntry>();
    for (const [model, usage] of this.perModel) {
      if (
        usage.inputTokens === 0 &&
        usage.outputTokens === 0 &&
        usage.cachedInputTokens === 0
      ) {
        continue;
      }
      const priced = model === "unknown" ? undefined : model;
      const provider = modelProvider(priced);
      const key = `${provider}\x1f${model}`;
      const split = splitCost(usage, priced);
      const existing = acc.get(key);
      if (existing) {
        existing.cost_in += split.cost_in;
        existing.cost_out += split.cost_out;
        if (split.cost_cache_read !== undefined) {
          existing.cost_cache_read =
            (existing.cost_cache_read ?? 0) + split.cost_cache_read;
        }
      } else {
        acc.set(key, {
          provider,
          model,
          cost_in: split.cost_in,
          cost_out: split.cost_out,
          ...(split.cost_cache_read !== undefined
            ? { cost_cache_read: split.cost_cache_read }
            : {}),
        });
      }
    }
    if (acc.size === 0) return null;
    const breakdown = Array.from(acc.values());
    const costUsd = breakdown.reduce(
      (sum, e) => sum + e.cost_in + e.cost_out + (e.cost_cache_read ?? 0),
      0,
    );
    return { costUsd, breakdown };
  }
}
