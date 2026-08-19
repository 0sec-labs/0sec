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
 * Backward-compatible child-environment seam. It now constructs a minimal
 * allowlisted environment rather than copying the parent and trying to redact
 * secrets. Every existing agent-controlled spawn already calls this function,
 * so this is a clean cutover instead of a second, unused safety path.
 *
 * Scoped target-auth names and a few non-secret child-runtime settings remain
 * explicitly listed below; cloud and provider credentials are never inherited.
 */
export function sanitizedEnv(
  env: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  return allowlistedChildEnv({}, env);
}

/**
 * Variables an agent-controlled child process legitimately needs to function
 * at all (paths, locale, terminal basics). This is the ALLOWLIST half of the
 * deepsec pattern (study 2026-08-13): the child env is built from this set
 * plus explicitly injected extras, rather than filtering secrets out of a
 * full process.env copy. A denylist always misses the next secret; an
 * allowlist cannot leak what it never carried.
 */
const CHILD_ENV_ALLOWLIST = [
  "PATH",
  "HOME",
  "SHELL",
  "USER",
  "LOGNAME",
  "TMPDIR",
  "TEMP",
  "TERM",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "SSH_AUTH_SOCK",
  "NODE_OPTIONS",
  "NO_COLOR",
  "CI",
  "GIT_CONFIG_GLOBAL",
  "XDG_CONFIG_HOME",
  "XDG_CACHE_HOME",
  // Target auth and target identity are deliberately available to authorized
  // child requests. They are not provider / cloud control-plane credentials.
  "TARGET",
  "AUTH_HEADER",
  "AUTH_VALUE",
  "AUTH_CURL_FLAG",
  // Existing child-runtime configuration contract; each name is non-secret.
  "PWNKIT_FEATURE_JIT_SKILLS",
  "PWNKIT_BASH_TIMEOUT_MS",
  "PWNKIT_CLOUD_SCAN_ID",
] as const;

/**
 * Build a minimal environment for an agent-controlled child process from an
 * allowlist, then merge caller-supplied extras. Everything else in
 * `process.env` is dropped — prompt injection in scanned content cannot
 * exfiltrate GITHUB_TOKEN / AWS_* / provider keys that never reach the spawn
 * env. Extras are still screened against SENSITIVE_ENV_PATTERNS so a caller
 * cannot accidentally re-introduce a known secret shape.
 */
export function allowlistedChildEnv(
  extras: Record<string, string> = {},
  env: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of CHILD_ENV_ALLOWLIST) {
    const value = env[key];
    if (value !== undefined) out[key] = value;
  }
  for (const [key, value] of Object.entries(extras)) {
    if (SENSITIVE_ENV_PATTERNS.some((pattern) => key.includes(pattern))) continue;
    out[key] = value;
  }
  return out;
}
