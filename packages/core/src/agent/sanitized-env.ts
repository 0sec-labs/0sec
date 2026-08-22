// Credentials supplied to the 0sec process must not reach agent-controlled
// child processes. This is defense in depth only: credentials retained by the
// parent process are a separate process-isolation problem (0sec#134).
//
// Two layers, most-general first:
//
//   1. GENERIC CREDENTIAL SHAPES — substrings that appear in the *name* of
//      almost any secret regardless of vendor. Because the child env is built
//      from an allowlist (see CHILD_ENV_ALLOWLIST) and these patterns only ever
//      screen caller-supplied `extras`, a broad net here can never drop a
//      variable a child legitimately needs — the legit ones are added from the
//      allowlist before screening runs. It CAN stop a caller from re-injecting
//      a freshly-minted secret shape the specific list below never anticipated
//      (e.g. NVD_CREDS, MY_COMPANY_APIKEY, GH_PAT, AWS_SESSION_TOKEN,
//      AWS_ACCESS_KEY_ID). Matching is case-insensitive (see the reducer).
//
//   2. VENDOR-SPECIFIC NAMES — kept for documentation / auditability even where
//      a generic shape already covers them, so the security boundary reads as an
//      explicit inventory of what 0sec knows it handles.
const SENSITIVE_ENV_PATTERNS = [
  // ── Generic credential shapes (see note above) ──────────────────────────
  "TOKEN", // *_TOKEN, AWS_SESSION_TOKEN, API_TOKEN, …
  "SECRET", // *_SECRET, AWS_SECRET_ACCESS_KEY, CLIENT_SECRET, …
  "PASSWORD",
  "PASSWD",
  "PASSPHRASE",
  "CRED", // CREDS, CREDENTIAL(S), NVD_CREDS, …
  "APIKEY", // MY_COMPANY_APIKEY (no separator)
  "API_KEY", // *_API_KEY beyond the vendor list below
  "PRIVATE_KEY",
  "ACCESS_KEY", // AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
  "SECRET_KEY",
  "_PAT", // GH_PAT / *_PAT personal access tokens (NOT "PATH": no underscore)
  "SESSION_TOKEN",
  "AUTH_TOKEN",
  "BEARER",
  // ── Vendor-specific LLM provider keys ────────────────────────────────────
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
  "QWEN_API",
  // Non-LLM service credentials.
  "NVD_API",
  "E2B_API",
  "WPSCAN_API_TOKEN",
  "0SEC_WPSCAN_API_TOKEN",
  "GITHUB_TOKEN",
  "GITLAB_TOKEN",
  "GH_TOKEN",
  "GL_TOKEN",
  // Per-dispatch secrets injected by 0cloud's worker-controller.
  "0SEC_CLOUD_TOKEN",
  "0SEC_CHATGPT_ACCESS_TOKEN",
  "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN",
  "0SEC_GITHUB_TOKEN",
  "0SEC_GITLAB_TOKEN",
  "0SEC_TARGET_AUTH_JSON",
  "0SEC_GRAPH_ACCESS_TOKEN",
  "0SEC_LLM_TARGET_KEY",
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
  "0SEC_FEATURE_JIT_SKILLS",
  "0SEC_BASH_TIMEOUT_MS",
  "0SEC_CLOUD_SCAN_ID",
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
    // Case-insensitive: a lowercase alias (`github_token`) must be screened the
    // same as its canonical uppercase form. Patterns are authored uppercase.
    const upper = key.toUpperCase();
    if (SENSITIVE_ENV_PATTERNS.some((pattern) => upper.includes(pattern))) continue;
    out[key] = value;
  }
  return out;
}
