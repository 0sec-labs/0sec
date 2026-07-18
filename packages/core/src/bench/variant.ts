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
   * Prompt overrides keyed by prompt id. The default factory supports
   * `source_audit.hypothesis` and `web.challenge_hint`; unknown ids fail closed.
   */
  promptOverrides?: Record<string, string>;
  /**
   * Feature-flag overrides keyed by CLI/env-style name (`web_search`,
   * `early_stop`, ...). Applied only for the lifetime of each sequential
   * benchmark scan and restored afterward.
   */
  featureFlags?: Record<string, boolean>;
}

const VARIANT_KEYS = new Set([
  "id", "label", "model", "runtime", "depth", "costCeilingUsdPerAttempt",
  "promptOverrides", "featureFlags",
]);

/** Validate, clone, and freeze the exact descriptor before any scan executes. */
export function snapshotBenchVariant(value: BenchVariant): Readonly<BenchVariant> {
  for (const key of Object.keys(value)) {
    if (!VARIANT_KEYS.has(key)) throw new Error(`unsupported bench variant field: ${key}`);
  }
  if (!/^[a-z0-9][a-z0-9_-]{2,79}$/.test(value.id)) throw new Error("bench variant id must be filesystem-safe");
  if (value.label !== undefined && typeof value.label !== "string") throw new Error("bench variant label must be a string");
  if (value.model !== undefined && (!value.model || value.model !== value.model.trim())) throw new Error("bench variant model must be non-empty and trimmed");
  if (value.runtime !== undefined && !["api", "claude", "codex", "gemini", "ollama", "auto"].includes(value.runtime)) throw new Error("bench variant runtime is unsupported");
  if (value.depth !== undefined && !["quick", "default", "deep"].includes(value.depth)) throw new Error("bench variant depth is unsupported");
  if (value.costCeilingUsdPerAttempt !== undefined && (!Number.isFinite(value.costCeilingUsdPerAttempt) || value.costCeilingUsdPerAttempt <= 0)) throw new Error("bench variant cost ceiling must be positive and finite");
  const promptOverrides = Object.fromEntries(Object.entries(value.promptOverrides ?? {}).sort(([a], [b]) => a.localeCompare(b)));
  resolveVariantPromptOverrides(promptOverrides);
  const featureFlags = Object.fromEntries(Object.entries(value.featureFlags ?? {}).sort(([a], [b]) => a.localeCompare(b)));
  for (const [name, enabled] of Object.entries(featureFlags)) {
    featureEnvironmentName(name);
    if (typeof enabled !== "boolean") throw new Error(`feature flag "${name}" must be boolean`);
  }
  const snapshot: BenchVariant = {
    id: value.id,
    ...(value.label !== undefined ? { label: value.label } : {}),
    ...(value.model !== undefined ? { model: value.model } : {}),
    ...(value.runtime !== undefined ? { runtime: value.runtime } : {}),
    ...(value.depth !== undefined ? { depth: value.depth } : {}),
    ...(value.costCeilingUsdPerAttempt !== undefined ? { costCeilingUsdPerAttempt: value.costCeilingUsdPerAttempt } : {}),
    ...(Object.keys(promptOverrides).length > 0 ? { promptOverrides: Object.freeze(promptOverrides) } : {}),
    ...(Object.keys(featureFlags).length > 0 ? { featureFlags: Object.freeze(featureFlags) } : {}),
  };
  return Object.freeze(snapshot);
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

export interface ResolvedVariantPromptOverrides {
  sourceAuditHypothesis?: string;
  webChallengeHint?: string;
}

/** Resolve the deliberately small prompt surface; typoed/unknown ids fail closed. */
export function resolveVariantPromptOverrides(
  overrides: Record<string, string> = {},
): ResolvedVariantPromptOverrides {
  const resolved: ResolvedVariantPromptOverrides = {};
  for (const [id, value] of Object.entries(overrides)) {
    if (!value.trim()) throw new Error(`prompt override "${id}" must not be empty`);
    if (id === "source_audit.hypothesis") resolved.sourceAuditHypothesis = value.trim();
    else if (id === "web.challenge_hint") resolved.webChallengeHint = value.trim();
    else throw new Error(`unsupported default-factory prompt override: ${id}`);
  }
  return resolved;
}

function featureEnvironmentName(name: string): string {
  if (!/^[a-z0-9_]+$/.test(name)) {
    throw new Error(`invalid feature flag "${name}"; use lowercase CLI/env-style names`);
  }
  return `PWNKIT_FEATURE_${name.toUpperCase()}`;
}

// Feature flags use process.env throughout the engine. Serialize scoped
// overrides so even an accidental parallel caller cannot leak one variant's
// flags into another scan.
let featureFlagTail: Promise<void> = Promise.resolve();

/** Apply flags around one scan attempt and always restore the parent process. */
export async function withVariantFeatureFlags<T>(
  flags: Record<string, boolean> = {},
  run: () => Promise<T>,
): Promise<T> {
  const predecessor = featureFlagTail;
  let release!: () => void;
  featureFlagTail = new Promise<void>((resolve) => {
    release = resolve;
  });
  await predecessor;
  const previous = new Map<string, string | undefined>();
  try {
    for (const [name, enabled] of Object.entries(flags)) {
      const envName = featureEnvironmentName(name);
      previous.set(envName, process.env[envName]);
      process.env[envName] = enabled ? "1" : "0";
    }
    return await run();
  } finally {
    for (const [envName, value] of previous) {
      if (value === undefined) delete process.env[envName];
      else process.env[envName] = value;
    }
    release();
  }
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
 * The prompt surface is intentionally allowlisted and flag overrides are
 * scoped to one attempt. `runTournament` executes variants/cases sequentially,
 * which prevents process-wide environment overrides from crossing attempts.
 */
export function createDefaultVariantScan(
  variant: BenchVariant,
  opts: DefaultVariantScanOptions = {},
): BenchScan {
  const prompts = resolveVariantPromptOverrides(variant.promptOverrides);
  const auditScan = createPackageAuditScanAdapter({
    runtime: variant.runtime,
    model: variant.model,
    depth: variant.depth,
    costCeilingUsdPerAttempt: variant.costCeilingUsdPerAttempt,
    dbPath: opts.dbPath,
    hypothesis: prompts.sourceAuditHypothesis,
  });
  const webScan = createAgenticScanAdapter({
    runtime: variant.runtime,
    model: variant.model,
    costCeilingUsdPerAttempt: variant.costCeilingUsdPerAttempt,
    timeoutMs: opts.webTimeoutMs,
    challengeHint: prompts.webChallengeHint,
  });

  return async (input) =>
    withVariantFeatureFlags(variant.featureFlags, async () => {
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
    });
}
