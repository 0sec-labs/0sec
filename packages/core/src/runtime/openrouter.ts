/**
 * OpenRouter Multi-Model Runtime
 *
 * Provides ensemble support for running challenges across multiple models
 * via OpenRouter's unified API. BoxPwnr achieves 97.1% on XBOW by running
 * ~10 model configs in parallel and taking the best result.
 *
 * This runtime wraps LlmApiRuntime instances configured for different
 * OpenRouter models, enabling:
 *  - Single-model execution with any OpenRouter model
 *  - Ensemble execution: run N models in parallel, return the best result
 *  - Model rotation: cycle through models on retries
 *
 * The OpenRouter API is OpenAI-compatible at https://openrouter.ai/api/v1
 * with model names in provider/model format (e.g., google/gemini-2.5-pro).
 */

import type {
  NativeRuntime,
  NativeMessage,
  NativeStreamCallbacks,
  NativeToolDef,
  NativeRuntimeResult,
  NativeContentBlock,
  RuntimeConfig,
} from "./types.js";
import { LlmApiRuntime } from "./llm-api.js";

// ── Default ensemble model pool ──
// Diverse set of models that perform well on security/CTF tasks.
// Ordered roughly by capability for fallback priority.
export const DEFAULT_ENSEMBLE_MODELS = [
  "anthropic/claude-sonnet-4.6",
  "google/gemini-2.5-pro",
  "openai/o3",
  "deepseek/deepseek-chat",
  "meta-llama/llama-4-maverick",
  "qwen/qwen3-235b-a22b",
] as const;

export interface OpenRouterConfig {
  /** OpenRouter API key. Falls back to OPENROUTER_API_KEY env var. */
  apiKey?: string;
  /** Single model to use (non-ensemble mode). */
  model?: string;
  /** List of models for ensemble execution. */
  ensembleModels?: string[];
  /** Timeout per model call in ms. Default: 120_000. */
  timeout?: number;
  /** Max concurrent model calls in ensemble mode. Default: 3. */
  maxConcurrency?: number;
}

/**
 * Score an agent result to pick the best one in ensemble mode.
 * Higher is better. Prioritizes:
 *  1. Successful completion (not error)
 *  2. Tool use (indicates the model engaged with the task)
 *  3. More content (richer analysis)
 */
function scoreResult(result: NativeRuntimeResult): number {
  let score = 0;

  if (result.stopReason === "error") return -1;

  // Completed normally
  if (result.stopReason === "end_turn") score += 100;
  if (result.stopReason === "tool_use") score += 80;

  // Count content richness
  for (const block of result.content) {
    if (block.type === "text") {
      score += Math.min(block.text.length / 100, 50); // Up to 50 points for text length
    }
    if (block.type === "tool_use") {
      score += 20; // Bonus for tool engagement
    }
  }

  return score;
}

/**
 * OpenRouter runtime with multi-model ensemble support.
 *
 * Usage:
 *   // Single model
 *   const rt = new OpenRouterRuntime({ model: "google/gemini-2.5-pro" });
 *
 *   // Ensemble (runs multiple models, returns best)
 *   const rt = new OpenRouterRuntime({
 *     ensembleModels: ["anthropic/claude-sonnet-4.6", "google/gemini-2.5-pro"],
 *   });
 */
export class OpenRouterRuntime implements NativeRuntime {
  readonly type = "api" as const;
  private config: OpenRouterConfig;
  private apiKey: string;
  private singleRuntime: LlmApiRuntime | null = null;
  private ensembleRuntimes: Array<{ model: string; runtime: LlmApiRuntime }> = [];

  constructor(config: OpenRouterConfig = {}) {
    this.config = config;
    this.apiKey = config.apiKey ?? process.env.OPENROUTER_API_KEY ?? "";

    if (config.ensembleModels && config.ensembleModels.length > 0) {
      // Ensemble mode: create a runtime per model
      for (const model of config.ensembleModels) {
        this.ensembleRuntimes.push({
          model,
          runtime: this.createModelRuntime(model),
        });
      }
    } else {
      // Single model mode
      const model = config.model ?? process.env.PWNKIT_MODEL ?? "anthropic/claude-sonnet-4.6";
      this.singleRuntime = this.createModelRuntime(model);
    }
  }

  private createModelRuntime(model: string): LlmApiRuntime {
    const runtimeConfig: RuntimeConfig = {
      type: "api",
      timeout: this.config.timeout ?? 120_000,
      model,
      apiKey: this.apiKey,
    };
    return new LlmApiRuntime(runtimeConfig);
  }

  /** Get the model name(s) this runtime is configured for. */
  get models(): string[] {
    if (this.ensembleRuntimes.length > 0) {
      return this.ensembleRuntimes.map((e) => e.model);
    }
    return [this.config.model ?? process.env.PWNKIT_MODEL ?? "anthropic/claude-sonnet-4.6"];
  }

  /** Whether this runtime is in ensemble mode. */
  get isEnsemble(): boolean {
    return this.ensembleRuntimes.length > 0;
  }

  /**
   * Execute a single native call. In ensemble mode, runs all models in
   * parallel (up to maxConcurrency) and returns the best result.
   */
  async executeNative(
    system: string,
    messages: NativeMessage[],
    tools: NativeToolDef[],
    callbacks?: NativeStreamCallbacks,
  ): Promise<NativeRuntimeResult> {
    if (this.singleRuntime) {
      return this.singleRuntime.executeNative(system, messages, tools, callbacks);
    }

    // Ensemble mode: run models in parallel with concurrency limit
    const maxConcurrency = this.config.maxConcurrency ?? 3;
    const results: Array<{ model: string; result: NativeRuntimeResult }> = [];
    const pending = [...this.ensembleRuntimes];

    // Process in batches of maxConcurrency
    while (pending.length > 0) {
      const batch = pending.splice(0, maxConcurrency);
      const batchResults = await Promise.allSettled(
        batch.map(async ({ model, runtime }) => {
          const result = await runtime.executeNative(system, messages, tools, callbacks);
          return { model, result };
        }),
      );

      for (const settled of batchResults) {
        if (settled.status === "fulfilled") {
          results.push(settled.value);
        }
      }
    }

    if (results.length === 0) {
      return {
        content: [{ type: "text", text: "" }],
        stopReason: "error",
        durationMs: 0,
        error: "All ensemble models failed",
      };
    }

    // Pick the best result by score
    let best = results[0];
    let bestScore = scoreResult(best.result);

    for (let i = 1; i < results.length; i++) {
      const s = scoreResult(results[i].result);
      if (s > bestScore) {
        best = results[i];
        bestScore = s;
      }
    }

    return best.result;
  }

  /**
   * Run ensemble and return ALL results (not just the best).
   * Useful for the benchmark runner which may want to evaluate each model separately.
   */
  async executeEnsemble(
    system: string,
    messages: NativeMessage[],
    tools: NativeToolDef[],
  ): Promise<Array<{ model: string; result: NativeRuntimeResult }>> {
    const runtimes = this.ensembleRuntimes.length > 0
      ? this.ensembleRuntimes
      : [{ model: this.config.model ?? "default", runtime: this.singleRuntime! }];

    const maxConcurrency = this.config.maxConcurrency ?? 3;
    const results: Array<{ model: string; result: NativeRuntimeResult }> = [];
    const pending = [...runtimes];

    while (pending.length > 0) {
      const batch = pending.splice(0, maxConcurrency);
      const batchResults = await Promise.allSettled(
        batch.map(async ({ model, runtime }) => {
          const result = await runtime.executeNative(system, messages, tools);
          return { model, result };
        }),
      );

      for (const settled of batchResults) {
        if (settled.status === "fulfilled") {
          results.push(settled.value);
        }
      }
    }

    return results;
  }

  /**
   * Create a new OpenRouterRuntime for a specific model from this ensemble.
   * Useful for model rotation on retries.
   */
  forModel(model: string): OpenRouterRuntime {
    return new OpenRouterRuntime({
      ...this.config,
      model,
      ensembleModels: undefined,
    });
  }

  /**
   * Get the next model to try for retry-based rotation.
   * Cycles through ensemble models based on the attempt number.
   */
  getModelForAttempt(attempt: number): string {
    const models = this.ensembleRuntimes.length > 0
      ? this.ensembleRuntimes.map((e) => e.model)
      : DEFAULT_ENSEMBLE_MODELS as unknown as string[];
    return models[attempt % models.length];
  }

  async isAvailable(): Promise<boolean> {
    return !!this.apiKey;
  }
}
