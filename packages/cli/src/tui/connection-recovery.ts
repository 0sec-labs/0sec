export interface ConnectionRecovery {
  providerId: string;
  title: string;
  detail: string;
}

/**
 * Converts an authentication failure into a provider-specific recovery route.
 * Tool, target, and model errors deliberately return null: opening credential
 * setup for those failures would send the operator to the wrong surface.
 */
export function connectionRecoveryForError(error: string): ConnectionRecovery | null {
  const detail = error.trim();
  if (!detail) return null;

  if (/chatgpt.*codex|codex.*(?:token|auth|login|backend)|0sec_chatgpt/i.test(detail)) {
    return {
      providerId: "chatgpt-codex",
      title: "ChatGPT Codex needs to reconnect",
      detail,
    };
  }
  if (/azure openai|azure_openai/i.test(detail)) {
    return {
      providerId: "azure",
      title: "Azure OpenAI credentials need attention",
      detail,
    };
  }
  if (/anthropic|claude/i.test(detail)) {
    return {
      providerId: "anthropic",
      title: "Anthropic credentials need attention",
      detail,
    };
  }
  if (/openrouter/i.test(detail)) {
    return {
      providerId: "openrouter",
      title: "OpenRouter credentials need attention",
      detail,
    };
  }
  if (/deepseek/i.test(detail)) {
    return {
      providerId: "deepseek",
      title: "DeepSeek credentials need attention",
      detail,
    };
  }
  if (/\b(?:z[.-]?ai|glm)\b/i.test(detail)) {
    return {
      providerId: "z-ai",
      title: "Z.ai GLM credentials need attention",
      detail,
    };
  }
  if (/moonshot|kimi/i.test(detail)) {
    return {
      providerId: "kimi",
      title: "Moonshot Kimi credentials need attention",
      detail,
    };
  }
  if (/alibaba|qwen/i.test(detail)) {
    return {
      providerId: "qwen",
      title: "Alibaba Qwen credentials need attention",
      detail,
    };
  }
  if (/\bxai\b|x\.ai|grok/i.test(detail)) {
    return {
      providerId: "xai",
      title: "xAI Grok credentials need attention",
      detail,
    };
  }
  if (/openai|api key|api_key/i.test(detail)) {
    return {
      providerId: "openai",
      title: "OpenAI credentials need attention",
      detail,
    };
  }
  return null;
}
