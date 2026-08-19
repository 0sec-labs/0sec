import { OSS_PRICING } from "./pricing.oss.generated.js";

export interface ModelRates {
  input: number;
  output: number;
  /** Cached-input rate ($/1M). Falls back to `input` if absent. */
  cachedInput?: number;
}

export interface TokenUsageForPricing {
  inputTokens: number;
  outputTokens: number;
  cachedInputTokens?: number;
}

export const PRICING_SNAPSHOT_DATE = "2026-07-05";

/**
 * The IRREDUCIBLE manual residue: models no public pricing feed (LiteLLM, and by
 * extension ccusage / tokencost) carries — open-weight-hosted (glm-*, llama-4-*,
 * mistral-*), the newest Anthropic tiers, and vendor-specific aliases. These are
 * the ONLY prices a human touches; everything else auto-syncs from OSS via
 * `scripts/sync-pricing.ts --write` into pricing.oss.generated.ts.
 */
export const MANUAL_PRICING: Record<string, ModelRates> = {
  // Anthropic (versioned; LiteLLM keys use different suffixes → keep manual)
  "claude-opus-4-7": { input: 5.00, output: 25.00, cachedInput: 0.50 },
  "claude-opus-4-6": { input: 15.00, output: 75.00, cachedInput: 1.50 },
  "claude-sonnet-4-6": { input: 3.00, output: 15.00, cachedInput: 0.30 },
  "claude-haiku-4-5": { input: 0.80, output: 4.00, cachedInput: 0.08 },
  // OpenAI codex alias — mirrors gpt-5.5 (OSS feed has only the bare key)
  "gpt-5.5-codex": { input: 5.00, output: 30.00 },
  // Meta (hosted) — not in the OSS feed
  "llama-4-maverick": { input: 0.50, output: 0.77 },
  "llama-4-scout": { input: 0.20, output: 0.35 },
  // Mistral — not in the OSS feed
  "mistral-large": { input: 2.00, output: 6.00 },
  "mistral-small": { input: 0.10, output: 0.30 },
  // Z.AI (open-weight, hosted) — see provos.org "Finding Zero-Days with Any Model" (Apr 2026)
  "glm-5.3": { input: 1.40, output: 4.40, cachedInput: 0.26 },
  "glm-5.2": { input: 1.40, output: 4.40, cachedInput: 0.26 },
  "glm-5.1": { input: 1.40, output: 4.40, cachedInput: 0.26 },
  "glm-4.5": { input: 0.60, output: 2.20, cachedInput: 0.11 },
  // Moonshot Kimi K3 (open-weight, hosted) — not in the OSS feed; flat-rate
  // coding-plan estimates (mirror the GLM manual-row style).
  "k3": { input: 3.0, output: 15.0, cachedInput: 0.30 },
  "k3[1m]": { input: 3.0, output: 15.0, cachedInput: 0.30 },
  "kimi-for-coding": { input: 3.0, output: 15.0, cachedInput: 0.30 },
  // Alibaba Model Studio Qwen (Token Plan) — list rates mirroring the 0cloud
  // pricing source; actual spend is credit-billed at the operator's
  // subscription discount, so reconcile to the Model Studio invoice. Only the
  // entries the 0cloud rate source carries are pinned; the rest of the
  // catalog deliberately warns + inherits `default` until they are.
  // deepseek-v4-flash-0731 (Token Plan credit lane) is NOT pinned here on
  // purpose: AZURE_DEPLOYMENT_PRICE_ALIASES already resolves it to the
  // DeepSeek-V4-Flash list rate ($0.19/$0.51), the defensible anchor for a
  // credit-billed variant whose per-credit rate Alibaba does not publish.
  "qwen3.8-max": { input: 2.00, output: 6.00 },
  "qwen3.7-max": { input: 2.50, output: 7.50 },
  // Azure Foundry deployment names (verified 2026-07-25) — exact aliases
  // forwarded by the engine. DeepSeek/gpt-oss rates use the Azure-specific `azure_ai/*` LiteLLM feed
  // entries (not the cheaper direct-provider rates). Kimi is Microsoft's
  // published Global Standard price for K2.7 Code. GPT-5.6 SOL, Luna, and
  // Terra use Microsoft's Global Standard short-context rates; Azure Cost
  // Management remains authoritative for cache writes and long-context usage,
  // which this schema cannot represent.
  "DeepSeek-V4-Pro": { input: 1.74, output: 3.48 },
  "DeepSeek-V4-Flash": { input: 0.19, output: 0.51 },
  "Kimi-K2.7-Code": { input: 0.95, output: 4.00, cachedInput: 0.19 },
  "gpt-oss-120b": { input: 0.15, output: 0.60 },
  "gpt-5.6-sol": { input: 5.00, output: 30.00, cachedInput: 0.50 },
  "gpt-5.6-luna": { input: 1.00, output: 6.00, cachedInput: 0.10 },
  "gpt-5.6-terra": { input: 2.50, output: 15.00, cachedInput: 0.25 },
  default: { input: 3.00, output: 15.00 },
};

/**
 * Effective price table = the auto-generated OSS rates (source of truth for every
 * model the feed covers) overlaid with the manual residue. OSS wins where it has
 * data, so refreshing the generated file is the only "maintenance" for those
 * models — no hand-typed rates. Run `pnpm --filter @pwnkit/shared sync-pricing`
 * to check drift, `--write` to refresh.
 */
export const MODEL_PRICING: Record<string, ModelRates> = {
  ...MANUAL_PRICING,
  ...OSS_PRICING,
};

// Azure's runtime model id is the operator deployment name. Accept casing
// differences and Azure's version suffixes while keeping all other pricing
// keys exact, so a deployment such as `DeepSeek-V4-Pro-2026-04-23` cannot
// silently fall back to the generic $3/$15 rate.
const AZURE_DEPLOYMENT_PRICE_ALIASES = new Map<string, string>([
  ["deepseek-v4-pro", "DeepSeek-V4-Pro"],
  ["deepseek-v4-flash", "DeepSeek-V4-Flash"],
  ["kimi-k2.7-code", "Kimi-K2.7-Code"],
  ["gpt-oss-120b", "gpt-oss-120b"],
  ["gpt-5.6-sol", "gpt-5.6-sol"],
  ["gpt-5.6-luna", "gpt-5.6-luna"],
  ["gpt-5.6-terra", "gpt-5.6-terra"],
]);

function azureDeploymentPriceKey(model: string): string | null {
  const lower = model.toLowerCase();
  for (const [alias, canonical] of AZURE_DEPLOYMENT_PRICE_ALIASES) {
    if (lower === alias || lower.startsWith(`${alias}-`)) return canonical;
  }
  return null;
}

/** Known vendor prefixes to strip (e.g. "openai/gpt-4o" -> "gpt-4o"). */
function normalizeModel(model: string): string {
  const prefixes = [
    "openai/",
    "anthropic/",
    "google/",
    "deepseek/",
    "meta/",
    "mistral/",
    "z-ai/",
    "zai/",
    "kimi/",
    "moonshot/",
    "openrouter/",
  ];
  for (const prefix of prefixes) {
    if (model.startsWith(prefix)) return model.slice(prefix.length);
  }
  return model;
}

export function getRates(model?: string): ModelRates {
  const key = model ? normalizeModel(model) : "";
  const aliasKey = azureDeploymentPriceKey(key);
  const rates = MODEL_PRICING[key] ?? (aliasKey ? MODEL_PRICING[aliasKey] : undefined);
  if (!rates) {
    if (model) console.warn(`[pwnkit] Unknown model for cost estimation: ${model}`);
    return MODEL_PRICING.default;
  }
  return rates;
}

export function estimateCost(usage: TokenUsageForPricing, model?: string): number {
  const rates = getRates(model);
  const cachedInputRate = rates.cachedInput ?? rates.input;
  const cached = usage.cachedInputTokens ?? 0;
  const uncachedInput = Math.max(0, usage.inputTokens - cached);
  return (
    (uncachedInput / 1_000_000) * rates.input +
    (cached / 1_000_000) * cachedInputRate +
    (usage.outputTokens / 1_000_000) * rates.output
  );
}

export function priceRun(usage: TokenUsageForPricing, model?: string): number {
  return estimateCost(usage, model);
}

export function modelProvider(model?: string): string {
  if (!model) return "unknown";
  const lowered = model.toLowerCase();
  if (lowered.startsWith("openai/")) return "openai";
  if (lowered.startsWith("anthropic/")) return "anthropic";
  if (lowered.startsWith("google/")) return "google";
  if (lowered.startsWith("deepseek/")) return "deepseek";
  if (lowered.startsWith("meta/")) return "meta";
  if (lowered.startsWith("mistral/")) return "mistral";
  if (lowered.startsWith("z-ai/") || lowered.startsWith("zai/")) return "z-ai";
  if (lowered.startsWith("kimi/") || lowered.startsWith("moonshot/")) return "kimi";
  if (lowered.startsWith("openrouter/")) return "openrouter";

  const stripped = normalizeModel(model).toLowerCase();
  if (stripped.startsWith("gpt-") || stripped.startsWith("o3") || stripped.startsWith("o4-")) return "openai";
  if (stripped.startsWith("claude-")) return "anthropic";
  if (stripped.startsWith("gemini-")) return "google";
  if (stripped.startsWith("deepseek-")) return "deepseek";
  if (stripped.startsWith("llama-")) return "meta";
  if (stripped.startsWith("mistral-")) return "mistral";
  if (stripped.startsWith("glm-")) return "z-ai";
  if (stripped.startsWith("k3") || stripped.startsWith("kimi")) return "kimi";
  if (stripped.startsWith("qwen")) return "qwen";
  return "unknown";
}

export interface CostSplit {
  cost_in: number;
  cost_out: number;
  cost_cache_read?: number;
}

export function splitCost(usage: TokenUsageForPricing, model?: string): CostSplit {
  const rates = getRates(model);
  const cachedInputRate = rates.cachedInput ?? rates.input;
  const cached = usage.cachedInputTokens ?? 0;
  const uncachedInput = Math.max(0, usage.inputTokens - cached);
  const split: CostSplit = {
    cost_in: (uncachedInput / 1_000_000) * rates.input,
    cost_out: (usage.outputTokens / 1_000_000) * rates.output,
  };
  if (usage.cachedInputTokens !== undefined) {
    split.cost_cache_read = (cached / 1_000_000) * cachedInputRate;
  }
  return split;
}
