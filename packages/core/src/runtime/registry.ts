import type { RuntimeType } from "./types.js";
import type { PipelineStage } from "@pwnkit/shared";

export interface RuntimeInfo {
  type: RuntimeType;
  command: string;
  description: string;
  /** Stages this runtime excels at, ordered by preference. */
  strengths: PipelineStage[];
  /** Whether this runtime supports system prompts. */
  supportsSystemPrompt: boolean;
}

/**
 * Registry of all supported runtimes and their characteristics.
 * Used by `--runtime auto` to pick the best runtime per pipeline stage.
 */
export const RUNTIME_REGISTRY: readonly RuntimeInfo[] = [
  {
    type: "claude",
    command: "claude",
    description: "Claude Code CLI — supported local adapter for live target scanning, MCP tool use, and deep analysis",
    strengths: ["attack", "source-analysis", "report"],
    supportsSystemPrompt: true,
  },
  {
    type: "codex",
    command: "codex",
    description: "Codex CLI / direct ChatGPT Codex provider — full parity across web scans, package audits (npm/pypi/cargo/oci), and source code review (incl. linux-kernel). Set PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN to enable subscription auth without the local CLI binary (#402).",
    strengths: ["verify", "source-analysis", "discovery"],
    supportsSystemPrompt: false,
  },
  {
    type: "gemini",
    command: "gemini",
    description: "Gemini CLI (experimental) — large context window, good for source analysis and reports",
    strengths: ["source-analysis", "report", "discovery"],
    supportsSystemPrompt: false,
  },
  {
    type: "ollama",
    // No external binary — health-checked over HTTP. Field is informational
    // so detection tools that key off `command` don't crash; the registry
    // uses `isAvailable()` not `which(command)` for ollama.
    command: "ollama",
    description: "Ollama (local) — Gemma 4 27B via /api/chat with native function-calling. Pairs with `--seed-findings` for full-local hunts. See pwnkit#369.",
    strengths: ["source-analysis", "discovery"],
    supportsSystemPrompt: true,
  },
] as const;

/** Default stage-to-runtime preferences for `--runtime auto`. */
const STAGE_PREFERENCES: Record<PipelineStage, RuntimeType[]> = {
  "discovery": ["claude", "codex", "gemini"],
  "source-analysis": ["claude", "gemini", "codex"],
  "attack": ["claude", "codex", "gemini"],
  "verify": ["codex", "claude", "gemini"],
  "report": ["claude", "gemini", "codex"],
};

/**
 * Pick the best available runtime for a given pipeline stage.
 * Falls back through the preference list until one is available.
 */
export function pickRuntimeForStage(
  stage: PipelineStage,
  availableRuntimes: Set<RuntimeType>,
): RuntimeType {
  const prefs = STAGE_PREFERENCES[stage];
  for (const rt of prefs) {
    if (availableRuntimes.has(rt)) return rt;
  }
  // Fallback: return whatever is available
  const first = availableRuntimes.values().next();
  return first.done ? "claude" : first.value;
}

/**
 * Detect which process-based runtimes are installed on this machine.
 */
export async function detectAvailableRuntimes(): Promise<Set<RuntimeType>> {
  const { ProcessRuntime } = await import("./process.js");
  const available = new Set<RuntimeType>();

  const checks = RUNTIME_REGISTRY.map(async (info) => {
    const rt = new ProcessRuntime({ type: info.type, timeout: 5_000 });
    if (await rt.isAvailable()) {
      available.add(info.type);
    }
  });

  await Promise.all(checks);
  return available;
}

export function getRuntimeInfo(type: RuntimeType): RuntimeInfo | undefined {
  return RUNTIME_REGISTRY.find((r) => r.type === type);
}
