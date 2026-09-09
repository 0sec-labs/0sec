/**
 * Which LLM providers this machine can actually reach.
 *
 * The `/model` picker is derived from the pricing table, which lists every
 * model the tool knows how to price — not every model it can currently call.
 * An operator can therefore pick a model whose provider has no credentials
 * here; the turn then dies with zero tokens and a message about a key they
 * never knew they needed. This module is the truthful side of that: it names
 * the providers the runtime can detect, the exact env vars each one reads,
 * and how to configure the ones that are dark.
 *
 * The mapping below is transcribed from the provider detection in
 * packages/core/src/runtime/llm-api.ts — `resolveFailoverProvider`
 * (~L660-712), `providerForModel` (~L1152-1200), and the env-priority chain
 * in `detectProvider` (~L1386-1533). It is DERIVED, not guessed: several
 * providers deviate from the `<VENDOR>_API_KEY` pattern (`Z_AI_API_KEY`,
 * `AZURE_OPENAI_API_KEY`, and the two `0SEC_CHATGPT_*` tokens), so extend
 * this table by re-reading that file rather than by analogy.
 */

export interface ProviderInfo {
  /** Provider id as the runtime names it, e.g. "anthropic". */
  id: string;
  /** Human label, e.g. "Anthropic". */
  label: string;
  /** Credential protocol; OAuth providers must never be treated as key fields. */
  auth: "api-key" | "oauth";
  /** Every env var that can supply credentials, most-preferred first. */
  envVars: readonly string[];
  /** How to configure it, one line, operator-facing. */
  hint: string;
  /**
   * Set only for providers the runtime can also authenticate from a file on
   * disk. `providerStates` is pure over env and never stats the filesystem,
   * so such a provider can read as unconfigured here while the runtime still
   * finds credentials — the hint says so, and callers that want certainty
   * should ask the runtime, not this table.
   */
  fileSource?: string;
}

export interface ProviderState extends ProviderInfo {
  configured: boolean;
  /** Which env var was actually found, when configured via env. */
  via?: string;
}

/**
 * Ordered by the runtime's real env-priority chain (detectProvider,
 * ~L1386-1533): chatgpt-codex wins outright as an explicit opt-in, then the
 * metered keys, with anthropic last because it doubles as the final fallback.
 * Note the prose comments at llm-api.ts L1205-1207 and L1548 state a
 * DIFFERENT order; the code above is what actually runs, so this follows it.
 */
export const PROVIDERS: readonly ProviderInfo[] = [
  {
    id: "chatgpt-codex",
    label: "ChatGPT Codex",
    auth: "oauth",
    // OAuth, not an API key. Both tokens are accepted and the access token is
    // read first (llm-api.ts L874-875, L1386-1394), so it leads the list.
    envVars: ["0SEC_CHATGPT_ACCESS_TOKEN", "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"],
    fileSource: "~/.codex/auth.json (override with 0SEC_CHATGPT_AUTH_FILE)",
    hint: "run `codex login` to write ~/.codex/auth.json, or invoke 0sec with env 0SEC_CHATGPT_OAUTH_REFRESH_TOKEN=...",
  },
  {
    id: "deepseek",
    label: "DeepSeek",
    auth: "api-key",
    envVars: ["DEEPSEEK_API_KEY"],
    hint: "set DEEPSEEK_API_KEY (endpoint override: DEEPSEEK_BASE_URL)",
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    auth: "api-key",
    envVars: ["OPENROUTER_API_KEY"],
    hint: "set OPENROUTER_API_KEY=sk-or-... from openrouter.ai/keys",
  },
  {
    id: "azure",
    label: "Azure OpenAI",
    auth: "api-key",
    // Only the Azure key authenticates; the deployment URL comes from
    // AZURE_OPENAI_BASE_URL / OPENAI_BASE_URL / ~/.codex/config.toml
    // (L1435-1445). A key with no reachable base URL still counts as
    // configured here because detectProvider selects azure on the key alone.
    envVars: ["AZURE_OPENAI_API_KEY"],
    hint: "set AZURE_OPENAI_API_KEY plus AZURE_OPENAI_BASE_URL (or [model_providers.azure] in ~/.codex/config.toml)",
  },
  {
    id: "openai",
    label: "OpenAI",
    auth: "api-key",
    envVars: ["OPENAI_API_KEY"],
    hint: "set OPENAI_API_KEY=sk-... from platform.openai.com/api-keys",
  },
  {
    id: "z-ai",
    label: "Z.ai GLM",
    auth: "api-key",
    envVars: ["Z_AI_API_KEY"],
    hint: "set Z_AI_API_KEY from your Z.ai Coding Plan (endpoint override: Z_AI_BASE_URL)",
  },
  {
    id: "kimi",
    label: "Moonshot Kimi",
    auth: "api-key",
    envVars: ["KIMI_API_KEY"],
    hint: "set KIMI_API_KEY from your Kimi coding plan (endpoint override: KIMI_BASE_URL)",
  },
  {
    id: "qwen",
    label: "Alibaba Qwen",
    auth: "api-key",
    envVars: ["QWEN_API_KEY"],
    hint: "set QWEN_API_KEY from Alibaba Model Studio (endpoint override: QWEN_BASE_URL)",
  },
  {
    id: "xai",
    label: "xAI Grok",
    auth: "api-key",
    envVars: ["XAI_API_KEY"],
    hint: "set XAI_API_KEY from console.x.ai (endpoint override: XAI_BASE_URL)",
  },
  {
    id: "opencode",
    label: "OpenCode Zen",
    auth: "api-key",
    envVars: ["OPENCODE_API_KEY"],
    hint: "set OPENCODE_API_KEY from opencode.ai/auth (endpoint override: OPENCODE_BASE_URL)",
  },
  {
    id: "anthropic",
    label: "Anthropic",
    auth: "api-key",
    envVars: ["ANTHROPIC_API_KEY"],
    hint: "set ANTHROPIC_API_KEY=sk-ant-... from console.anthropic.com",
  },
];

/**
 * An exported-but-empty variable is the classic way this breaks: `export
 * ANTHROPIC_API_KEY=` in a shell profile, or a CI secret that resolved to the
 * empty string, leaves the name present in `env` while carrying no credential.
 * Treat whitespace-only the same way — a stray newline from `$(cat key.txt)`
 * is not a key either.
 */
function hasCredential(value: string | undefined): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

/** The first env var of `info` that actually holds a credential, if any. */
function satisfyingVar(info: ProviderInfo, env: Record<string, string | undefined>): string | undefined {
  // envVars is ordered most-preferred first, so the first hit is the one the
  // runtime would use — that is what `via` has to report.
  return info.envVars.find((name) => hasCredential(env[name]));
}

/** Pure over an injected environment so it is testable. */
export function providerStates(env: Record<string, string | undefined>): ProviderState[] {
  // Reads only, and only from `env` — never process.env, so a caller can ask
  // "what would this look like under that environment?" without mutating or
  // depending on the ambient one.
  return PROVIDERS.map((info) => {
    const via = satisfyingVar(info, env);
    return via === undefined ? { ...info, configured: false } : { ...info, configured: true, via };
  });
}

/** Is this specific provider usable given the environment? */
export function isProviderConfigured(providerId: string, env: Record<string, string | undefined>): boolean {
  // An unknown id is not an error: the model catalog derives providers from
  // the pricing table, which carries vendors with no direct runtime path
  // ("google", "meta", "mistral", "unknown"). Those are simply not
  // configurable here, so the honest answer is false rather than a throw that
  // would take the picker down.
  const info = PROVIDERS.find((candidate) => candidate.id === providerId);
  return info !== undefined && satisfyingVar(info, env) !== undefined;
}
