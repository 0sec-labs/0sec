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
 * Keep it short and representative — it is a floor, not a mirror. Refresh it
 * occasionally from a real Models.dev pull; drift here only affects the
 * offline-first-run experience, never priced/synced rows.
 */

import type { SyncedModel } from "./model-catalog-sync.js";

/** Curated floor: a handful of current models per major provider. */
export const OFFLINE_MODEL_CATALOG: SyncedModel[] = [
  // Anthropic
  { id: "claude-opus-4-7", provider: "anthropic", contextTokens: 200_000, input: 5, output: 25 },
  { id: "claude-sonnet-4-6", provider: "anthropic", contextTokens: 1_000_000, input: 3, output: 15 },
  { id: "claude-haiku-4-5", provider: "anthropic", contextTokens: 200_000, input: 0.8, output: 4 },
  // OpenAI
  { id: "gpt-5.5", provider: "openai", contextTokens: 400_000, input: 5, output: 30 },
  { id: "gpt-5.5-mini", provider: "openai", contextTokens: 400_000, input: 0.25, output: 2 },
  // Google
  { id: "gemini-3-pro", provider: "google", contextTokens: 1_000_000, input: 1.25, output: 10 },
  { id: "gemini-3-flash", provider: "google", contextTokens: 1_000_000, input: 0.3, output: 2.5 },
  // DeepSeek
  { id: "deepseek-v4", provider: "deepseek", contextTokens: 128_000, input: 0.27, output: 1.1 },
  // Meta (hosted)
  { id: "llama-4-maverick", provider: "meta", contextTokens: 1_000_000, input: 0.5, output: 0.77 },
  { id: "llama-4-scout", provider: "meta", contextTokens: 10_000_000, input: 0.2, output: 0.35 },
  // Mistral
  { id: "mistral-large", provider: "mistral", contextTokens: 128_000, input: 2, output: 6 },
  // Alibaba Qwen
  { id: "qwen3.8-max", provider: "qwen", contextTokens: 256_000, input: 2, output: 6 },
  // xAI
  { id: "grok-4.6", provider: "xai", contextTokens: 256_000, input: 2, output: 6 },
  // Moonshot
  { id: "k3", provider: "moonshot", contextTokens: 256_000, input: 3, output: 15 },
  // Z.AI
  { id: "glm-5.3", provider: "z-ai", contextTokens: 200_000, input: 1.4, output: 4.4 },
];
