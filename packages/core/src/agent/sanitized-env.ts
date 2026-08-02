// Credentials supplied to the pwnkit process must not reach agent-controlled
// child processes. This is defense in depth only: credentials retained by the
// parent process are a separate process-isolation problem (pwnkit#134).
const SENSITIVE_ENV_PATTERNS = [
  "OPENROUTER_API",
  "ANTHROPIC_API",
  "OPENAI_API",
  "AZURE_OPENAI_API",
  "GEMINI_API",
  "MISTRAL_API",
  "XAI_API",
  "COHERE_API",
  "GROQ_API",
  "TOGETHER_API",
  "PERPLEXITY_API",
  "FIREWORKS_API",
  "AI21_API",
  "DEEPSEEK_API",
  "HUGGING_FACE_",
  "HF_TOKEN",
  "Z_AI_API",
  "KIMI_API",
  "WPSCAN_API_TOKEN",
  "PWNKIT_WPSCAN_API_TOKEN",
  "GITHUB_TOKEN",
  "GITLAB_TOKEN",
  "GH_TOKEN",
  "GL_TOKEN",
  // Per-dispatch secrets injected by 0cloud's worker-controller.
  "PWNKIT_CLOUD_TOKEN",
  "PWNKIT_CHATGPT_ACCESS_TOKEN",
  "PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN",
  "PWNKIT_GITHUB_TOKEN",
  "PWNKIT_GITLAB_TOKEN",
  "PWNKIT_TARGET_AUTH_JSON",
  "PWNKIT_GRAPH_ACCESS_TOKEN",
] as const;

/**
 * Build the environment for an agent-controlled child process.
 *
 * Target authentication is deliberately added by the specific tool invocation,
 * rather than retained here: an authenticated target request is a separate
 * egress-proxy boundary from cloud/provider credentials.
 */
export function sanitizedEnv(
  env: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(env).filter(
      ([key]) => !SENSITIVE_ENV_PATTERNS.some((pattern) => key.includes(pattern)),
    ),
  ) as Record<string, string>;
}
