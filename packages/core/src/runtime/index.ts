export type {
  Runtime,
  RuntimeConfig,
  RuntimeContext,
  RuntimeResult,
  RuntimeType,
  NativeRuntime,
  NativeMessage,
  NativeContentBlock,
  NativeToolDef,
  NativeRuntimeResult,
} from "./types.js";
export { LlmApiRuntime } from "./llm-api.js";
export { ProcessRuntime } from "./process.js";
export { CliNativeRuntime } from "./cli-native.js";
export { OpenRouterRuntime, DEFAULT_ENSEMBLE_MODELS } from "./openrouter.js";
export type { OpenRouterConfig } from "./openrouter.js";
export { OllamaRuntime } from "./ollama.js";
export type { OllamaRuntimeOptions } from "./ollama.js";
export {
  RUNTIME_REGISTRY,
  pickRuntimeForStage,
  detectAvailableRuntimes,
  getRuntimeInfo,
} from "./registry.js";

import type { RuntimeConfig, Runtime } from "./types.js";
import { LlmApiRuntime } from "./llm-api.js";
import { ProcessRuntime } from "./process.js";
import { OllamaRuntime } from "./ollama.js";

export function createRuntime(config: RuntimeConfig): Runtime {
  switch (config.type) {
    case "api":
      // LlmApiRuntime implements both Runtime (legacy) and NativeRuntime (agentic)
      // Use it for API mode so we get native tool_use support in agent loops
      return new LlmApiRuntime(config);
    case "claude":
    case "codex":
    case "gemini":
      return new ProcessRuntime(config);
    case "ollama":
      // Local Gemma-4-style model via Ollama's /api/chat. Model is required
      // here and defaults — if absent — to the env var or a documented value
      // so a bare `--runtime ollama` still gives a usable error.
      return new OllamaRuntime({
        model: config.model ?? process.env.PWNKIT_OLLAMA_MODEL ?? "gemma4:27b",
        timeout: config.timeout,
        host: process.env.OLLAMA_HOST,
      });
  }
}
