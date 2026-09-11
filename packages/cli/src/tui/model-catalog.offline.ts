/**
 * Bundled offline snapshot of the model catalog.
 *
 * The `/model` picker is derived from the local pricing table in @0sec/shared,
 * which only lists ids the engine has hand-priced. That table is authoritative
 * for cost but deliberately narrow, so the picker never shows a model the
 * operator's provider offers that we simply haven't priced yet.
 *
 * `model-catalog-sync.ts` closes that gap by pulling the live catalog from
 * Models.dev and caching it. This file is the *last-resort* fallback for when
 * that cache is cold and the network is unavailable (air-gapped review boxes,
 * first run offline): a small, curated, provider-diverse snapshot so the
 * picker is never emptier than the pricing table alone.
 *
 * Keep it short and representative — it is a floor, not a mirror. Refreshed
 * 2026-09-11 from Models.dev and provider documentation; direct-provider
 * prices take precedence where the feed differs (DeepSeek peak, GLM Flash).
 */

import type { SyncedModel } from "./model-catalog-sync.js";

/** Curated floor: a handful of current models per major provider. */
export const OFFLINE_MODEL_CATALOG: SyncedModel[] = [
  // Anthropic
  { id: "claude-fable-5-1", provider: "anthropic", contextTokens: 1_000_000, input: 10, output: 50 },
  { id: "claude-opus-5", provider: "anthropic", contextTokens: 1_000_000, input: 5, output: 25 },
  { id: "claude-sonnet-5", provider: "anthropic", contextTokens: 1_000_000, input: 2, output: 10 },
  { id: "claude-opus-4-7", provider: "anthropic", contextTokens: 200_000, input: 5, output: 25 },
  { id: "claude-sonnet-4-6", provider: "anthropic", contextTokens: 1_000_000, input: 3, output: 15 },
  { id: "claude-haiku-4-5", provider: "anthropic", contextTokens: 200_000, input: 0.8, output: 4 },
  // OpenAI
  // Astra standard short-context rates; >272K input has a separate price tier.
  { id: "gpt-6-astra", provider: "openai", contextTokens: 1_050_000, input: 10, output: 50 },
  { id: "gpt-5.5", provider: "openai", contextTokens: 400_000, input: 5, output: 30 },
  { id: "gpt-5.6-sol", provider: "openai", contextTokens: 1_050_000 },
  { id: "gpt-5.6-terra", provider: "openai", contextTokens: 1_050_000 },
  { id: "gpt-5.6-luna", provider: "openai", contextTokens: 1_050_000 },
  // Google
  { id: "gemini-3.8-flash", provider: "google", contextTokens: 1_048_576, input: 0.75, output: 3.75 },
  { id: "gemini-3.5-flash-lite", provider: "google", contextTokens: 1_048_576, input: 0.3, output: 2.5 },
  { id: "gemini-3.1-pro-preview", provider: "google", contextTokens: 1_048_576, input: 2, output: 12 },
  // DeepSeek
  { id: "deepseek-flash", provider: "deepseek", contextTokens: 1_000_000, input: 0.3, output: 1.2 },
  // Meta (hosted)
  { id: "llama-4-maverick", provider: "meta", contextTokens: 1_000_000, input: 0.5, output: 0.77 },
  { id: "llama-4-scout", provider: "meta", contextTokens: 10_000_000, input: 0.2, output: 0.35 },
  // Mistral
  { id: "mistral-large", provider: "mistral", contextTokens: 128_000, input: 2, output: 6 },
  // Alibaba Qwen
  { id: "qwen3.8-max", provider: "qwen", contextTokens: 1_000_000, input: 2, output: 6 },
  { id: "qwen3.8-flash", provider: "qwen", contextTokens: 1_000_000, input: 0.15, output: 0.47 },
  { id: "qwen3.8-max-preview", provider: "qwen", contextTokens: 1_000_000 },
  { id: "qwen3.7-max", provider: "qwen", contextTokens: 1_000_000, input: 2.5, output: 7.5 },
  { id: "qwen3.7-plus", provider: "qwen", contextTokens: 1_000_000, input: 0.5, output: 3 },
  { id: "qwen3.6-plus", provider: "qwen", contextTokens: 1_000_000, input: 0.5, output: 3 },
  { id: "qwen3.6-flash", provider: "qwen", contextTokens: 1_000_000, input: 0.1875, output: 1.125 },
  // xAI
  { id: "grok-4.6", provider: "xai", contextTokens: 500_000, input: 2, output: 6 },
  // Moonshot
  { id: "k3", provider: "moonshot", contextTokens: 1_048_576, input: 3, output: 15 },
  // Z.AI
  { id: "glm-5.3", provider: "z-ai", contextTokens: 1_000_000, input: 1.4, output: 4.4 },
  { id: "glm-5.3-flash", provider: "z-ai", contextTokens: 1_000_000, input: 0.15, output: 0.5 },
];
