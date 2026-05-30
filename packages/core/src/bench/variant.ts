/**
 * Bench variant descriptor + default variant→scan factory (pwnkit#656).
 *
 * A *variant* is one configuration of the engine under test — a model, a
 * runtime, a scan depth, prompt overrides, feature flags. The A/B tournament
 * (tournament.ts) runs N variants over the same labeled corpus and compares
 * them at pass@k with Wilson-95 CIs, so "variant B finds more real vulns per
 * dollar than variant A" becomes a falsifiable statement instead of a vibe.
 *
 * Layering mirrors the rest of the harness: the tournament takes an INJECTED
 * `VariantScanFactory` and never imports the engine directly, which is what
 * keeps it deterministically unit-testable with mocked scans. The default
 * factory below IS engine-coupled (it wires the real audit/agentic adapters)
 * and is the "batteries included" path, exactly like adapters.ts.
 */

import type { RuntimeMode, ScanDepth } from "@pwnkit/shared";
import type { BenchScan } from "./runner.js";
import {
  createAgenticScanAdapter,
  createPackageAuditScanAdapter,
} from "./adapters.js";

// ── Variant descriptor ────────────────────────────────────────────────

export interface BenchVariant {
  /** Stable, unique id within a tournament (surfaced in every scorecard). */
  id: string;
  /** Human label. */
  label?: string;
  /** Model override forwarded to the engine (e.g. a cheaper/stronger model). */
  model?: string;
  /** Runtime override (api/claude/codex/…). */
  runtime?: RuntimeMode;
  /** Scan/audit depth override. */
  depth?: ScanDepth;
  /** Per-attempt cost ceiling (USD) forwarded to the engine. */
  costCeilingUsdPerAttempt?: number;
  /**
   * Prompt overrides keyed by prompt id. Carried on the descriptor and handed
   * to custom {@link VariantScanFactory}s; the DEFAULT factory below does not
   * yet rewrite the engine's hardcoded prompts (that's a separate prompts.ts
   * parameterization) — wire a custom factory to A/B prompts today.
   */
  promptOverrides?: Record<string, string>;
  /**
   * Feature-flag overrides keyed by flag name. Same contract as
   * `promptOverrides`: carried + exposed to custom factories; the default
   * factory forwards only the knobs the engine adapters already accept.
   */
  featureFlags?: Record<string, boolean>;
}

/** Build the {@link BenchScan} that exercises a given variant. */
export type VariantScanFactory = (variant: BenchVariant) => BenchScan;

// ── Default factory (engine-coupled) ──────────────────────────────────

export interface DefaultVariantScanOptions {
  /** Per-attempt wallclock timeout (ms) for web scans. Default 60_000. */
  webTimeoutMs?: number;
  /** Optional db path forwarded to the audit engine. */
  dbPath?: string;
}

/**
 * Default {@link VariantScanFactory}: dispatches each case to the right real
 * engine adapter and threads the variant's model / runtime / depth / cost
 * ceiling through.
 *
 *   - `source-audit` → `packageAudit` (createPackageAuditScanAdapter)
 *   - `web`          → `agenticScan`  (createAgenticScanAdapter)
 *   - `kernel`       → error result (needs the cloud kernel verify runner,
 *                      which lives in services/ and can't be imported here);
 *                      surfaces as `inconclusive`, never silently mis-run.
 *
 * Only knobs the adapters already accept are wired (model/runtime/depth/cost);
 * `promptOverrides`/`featureFlags` are honoured by custom factories.
 */
export function createDefaultVariantScan(
  variant: BenchVariant,
  opts: DefaultVariantScanOptions = {},
): BenchScan {
  const auditScan = createPackageAuditScanAdapter({
    runtime: variant.runtime,
    model: variant.model,
    depth: variant.depth,
    costCeilingUsdPerAttempt: variant.costCeilingUsdPerAttempt,
    dbPath: opts.dbPath,
  });
  const webScan = createAgenticScanAdapter({
    runtime: variant.runtime,
    model: variant.model,
    costCeilingUsdPerAttempt: variant.costCeilingUsdPerAttempt,
    timeoutMs: opts.webTimeoutMs,
  });

  return async (input) => {
    switch (input.case.target.kind) {
      case "source-audit":
        return auditScan(input);
      case "web":
        return webScan(input);
      case "kernel":
        return {
          error: `default variant scan does not handle kernel case "${input.case.id}" — inject a kernel scan adapter (cloud verify-kernel runner)`,
        };
    }
  };
}
