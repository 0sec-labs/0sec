// AUTO-GENERATED from the LiteLLM OSS pricing feed by scripts/sync-pricing.ts --write.
// DO NOT EDIT BY HAND. Refresh: pnpm --filter @pwnkit/shared sync-pricing --write
// $ per 1M tokens. Models the feed lacks live in MANUAL_PRICING (src/pricing.ts).

export const OSS_PRICING: Record<string, { input: number; output: number; cachedInput?: number }> = {
  "gpt-5.4": { input: 2.5, output: 15, cachedInput: 0.25 },
  "gpt-5.5": { input: 5, output: 30, cachedInput: 0.5 },
  "gpt-4o": { input: 2.5, output: 10, cachedInput: 1.25 },
  "gpt-4o-mini": { input: 0.15, output: 0.6, cachedInput: 0.075 },
  "gpt-4.1": { input: 2, output: 8, cachedInput: 0.5 },
  "gpt-4.1-mini": { input: 0.4, output: 1.6, cachedInput: 0.1 },
  "gpt-4.1-nano": { input: 0.1, output: 0.4, cachedInput: 0.025 },
  "o3": { input: 2, output: 8, cachedInput: 0.5 },
  "o3-mini": { input: 1.1, output: 4.4, cachedInput: 0.55 },
  "o4-mini": { input: 1.1, output: 4.4, cachedInput: 0.275 },
  "gemini-2.5-pro": { input: 1.25, output: 10, cachedInput: 0.125 },
  "gemini-2.5-flash": { input: 0.3, output: 2.5, cachedInput: 0.03 },
  "gemini-2.0-flash": { input: 0.1, output: 0.4, cachedInput: 0.025 },
  "deepseek-chat": { input: 0.28, output: 0.42, cachedInput: 0.028 },
  "deepseek-reasoner": { input: 0.28, output: 0.42, cachedInput: 0.028 },
};
