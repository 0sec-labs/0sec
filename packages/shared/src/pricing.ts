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

export const PRICING_SNAPSHOT_DATE = "2026-06-28";

/** Approximate cost per 1M tokens by provider/model. */
export const MODEL_PRICING: Record<string, ModelRates> = {
  // OpenAI
  "gpt-5.4": { input: 2.50, output: 10.00 },
  "gpt-5.5": { input: 2.50, output: 10.00 },
  "gpt-5.5-codex": { input: 2.50, output: 10.00 },
  "gpt-4o": { input: 2.50, output: 10.00 },
  "gpt-4o-mini": { input: 0.15, output: 0.60 },
  "gpt-4.1": { input: 2.00, output: 8.00 },
  "gpt-4.1-mini": { input: 0.40, output: 1.60 },
  "gpt-4.1-nano": { input: 0.10, output: 0.40 },
  "o3": { input: 2.00, output: 8.00 },
  "o3-mini": { input: 1.10, output: 4.40 },
  "o4-mini": { input: 1.10, output: 4.40 },
  // Anthropic
  "claude-opus-4-7": { input: 5.00, output: 25.00, cachedInput: 0.50 },
  "claude-opus-4-6": { input: 15.00, output: 75.00, cachedInput: 1.50 },
  "claude-sonnet-4-6": { input: 3.00, output: 15.00, cachedInput: 0.30 },
  "claude-haiku-4-5": { input: 0.80, output: 4.00, cachedInput: 0.08 },
  // Google
  "gemini-2.5-pro": { input: 1.25, output: 10.00 },
  "gemini-2.5-flash": { input: 0.15, output: 0.60 },
  "gemini-2.0-flash": { input: 0.10, output: 0.40 },
  // DeepSeek
  "deepseek-chat": { input: 0.27, output: 1.10 },
  "deepseek-reasoner": { input: 0.55, output: 2.19 },
  // Meta (hosted)
  "llama-4-maverick": { input: 0.50, output: 0.77 },
  "llama-4-scout": { input: 0.20, output: 0.35 },
  // Mistral
  "mistral-large": { input: 2.00, output: 6.00 },
  "mistral-small": { input: 0.10, output: 0.30 },
  // Z.AI (open-weight, hosted) -- see provos.org "Finding Zero-Days with Any Model" (Apr 2026)
  "glm-5.2": { input: 1.40, output: 4.40, cachedInput: 0.26 },
  "glm-5.1": { input: 1.40, output: 4.40, cachedInput: 0.26 },
  "glm-4.5": { input: 0.60, output: 2.20, cachedInput: 0.11 },
  default: { input: 3.00, output: 15.00 },
};

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
    "openrouter/",
  ];
  for (const prefix of prefixes) {
    if (model.startsWith(prefix)) return model.slice(prefix.length);
  }
  return model;
}

export function getRates(model?: string): ModelRates {
  const key = model ? normalizeModel(model) : "";
  const rates = MODEL_PRICING[key];
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
  if (lowered.startsWith("openrouter/")) return "openrouter";

  const stripped = normalizeModel(model).toLowerCase();
  if (stripped.startsWith("gpt-") || stripped.startsWith("o3") || stripped.startsWith("o4-")) return "openai";
  if (stripped.startsWith("claude-")) return "anthropic";
  if (stripped.startsWith("gemini-")) return "google";
  if (stripped.startsWith("deepseek-")) return "deepseek";
  if (stripped.startsWith("llama-")) return "meta";
  if (stripped.startsWith("mistral-")) return "mistral";
  if (stripped.startsWith("glm-")) return "z-ai";
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
