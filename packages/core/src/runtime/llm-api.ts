import type {
  Runtime,
  NativeRuntime,
  NativeStreamCallbacks,
  RuntimeConfig,
  RuntimeContext,
  RuntimeResult,
  NativeMessage,
  NativeToolDef,
  NativeRuntimeResult,
  NativeContentBlock,
} from "./types.js";

import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { VERSION } from "@pwnkit/shared";
import { features } from "../agent/features.js";
import {
  MESSAGE_CACHE_BREAKPOINTS,
  planMessageBreakpoints,
  providerSupportsPromptCache,
  readCacheUsage,
  withCacheControl,
  type WireBlock,
} from "./prompt-cache.js";

/**
 * Read `usage.input_tokens_details.cached_tokens` off a Responses payload.
 *
 * Returns `{}` when the provider does not report it, so spreading the result
 * never plants an explicit `undefined` on the usage object. Unlike Anthropic,
 * the Responses API counts cached tokens INSIDE `input_tokens`, so this is
 * observability only — no re-adding, no double counting.
 */
function readResponsesCachedTokens(usage: Record<string, unknown>): { cachedInputTokens?: number } {
  const details = usage.input_tokens_details as Record<string, unknown> | undefined;
  const cached = Number(details?.cached_tokens ?? 0);
  return Number.isFinite(cached) && cached > 0 ? { cachedInputTokens: cached } : {};
}

/** Safely parse JSON tool arguments; returns empty object on malformed input. */
function safeParseJson(raw: string | null | undefined): Record<string, unknown> {
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return { _raw: raw };
  }
}

/**
 * Cache for the resolved Azure region, keyed by base URL. The region is
 * probed once per process (per endpoint) and reused thereafter — see
 * {@link probeAzureRegion}.
 */
const azureRegionCache = new Map<string, string>();

/**
 * Probe the Azure OpenAI endpoint once for its deployment region.
 *
 * Azure surfaces the physical region of a resource in the `x-ms-region`
 * response header (e.g. "eastus2"). The URL itself never reveals this —
 * two `*.openai.azure.com` endpoints can live in completely different
 * geographies — so this probe is the only reliable way to tell an
 * operator which data-residency jurisdiction their traffic lands in.
 *
 * The probe issues a single cheap request to `${baseUrl}/models`, reads
 * the header, and caches the result per base URL for the rest of the
 * process. It never throws: on any failure (network error, HTTP error,
 * missing header) the function resolves to "unknown" so startup logging
 * stays a no-op in adverse conditions.
 *
 * Test hook: `PWNKIT_REGION_OVERRIDE` short-circuits the probe entirely.
 * Set it to force a specific region string without hitting the network —
 * this keeps unit tests and air-gapped CI runs deterministic.
 */
export async function probeAzureRegion(
  baseUrl: string,
  apiKey: string,
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  // PWNKIT_REGION_OVERRIDE: lets tests (and operators running offline)
  // force a specific region string without touching the network.
  const override = process.env.PWNKIT_REGION_OVERRIDE;
  if (override && override.trim().length > 0) {
    return override.trim();
  }

  const cached = azureRegionCache.get(baseUrl);
  if (cached) return cached;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const res = await fetchImpl(`${baseUrl.replace(/\/+$/, "")}/models`, {
      method: "GET",
      headers: { "api-key": apiKey },
      signal: controller.signal,
    }).finally(() => clearTimeout(timer));

    // Azure returns x-ms-region even on 401/403 — the header is set by the
    // front door before authentication, so a missing key still reveals the
    // resource geography. We accept any response that has the header.
    const region = res.headers.get("x-ms-region");
    const resolved = region && region.trim().length > 0
      ? prettyRegion(region.trim())
      : "unknown";
    azureRegionCache.set(baseUrl, resolved);
    return resolved;
  } catch {
    azureRegionCache.set(baseUrl, "unknown");
    return "unknown";
  }
}

/** Convert Azure's lowercase region codes into a human-readable label. */
function prettyRegion(code: string): string {
  const map: Record<string, string> = {
    eastus: "East US",
    eastus2: "East US 2",
    westus: "West US",
    westus2: "West US 2",
    westus3: "West US 3",
    centralus: "Central US",
    northcentralus: "North Central US",
    southcentralus: "South Central US",
    westcentralus: "West Central US",
    canadaeast: "Canada East",
    canadacentral: "Canada Central",
    brazilsouth: "Brazil South",
    northeurope: "North Europe",
    westeurope: "West Europe",
    uksouth: "UK South",
    ukwest: "UK West",
    francecentral: "France Central",
    germanywestcentral: "Germany West Central",
    switzerlandnorth: "Switzerland North",
    norwayeast: "Norway East",
    swedencentral: "Sweden Central",
    polandcentral: "Poland Central",
    italynorth: "Italy North",
    eastasia: "East Asia",
    southeastasia: "Southeast Asia",
    japaneast: "Japan East",
    japanwest: "Japan West",
    koreacentral: "Korea Central",
    australiaeast: "Australia East",
    centralindia: "Central India",
    southindia: "South India",
    uaenorth: "UAE North",
    southafricanorth: "South Africa North",
  };
  return map[code.toLowerCase()] ?? code;
}

/** Reset the region cache. Test-only — do not call from production code. */
export function __resetAzureRegionCacheForTests(): void {
  azureRegionCache.clear();
}

/**
 * Tracks which endpoints we've already printed a startup banner for.
 *
 * Stashed on `globalThis` under a `Symbol.for` key so the guard survives
 * module re-evaluation. pnpm monorepos can occasionally resolve this
 * module from more than one path (source vs compiled, different dep
 * hoisting), which hands each importer its own module-local `Set` —
 * the banner then fires once per importer instead of once per process.
 * Keying on a shared global process-wide Set closes that hole.
 */
const PROVIDER_BANNER_KEY = Symbol.for("pwnkit.core.loggedProviderStartup");
type GlobalWithBannerGuard = typeof globalThis & { [PROVIDER_BANNER_KEY]?: Set<string> };
const loggedProviderStartup: Set<string> = ((): Set<string> => {
  const g = globalThis as GlobalWithBannerGuard;
  if (!g[PROVIDER_BANNER_KEY]) g[PROVIDER_BANNER_KEY] = new Set<string>();
  return g[PROVIDER_BANNER_KEY];
})();

function appendNativeTrace(record: Record<string, unknown>): void {
  const file = process.env.PWNKIT_TRACE_NATIVE_RESPONSES;
  if (!file) return;
  try {
    appendFileSync(file, `${JSON.stringify({ ts: new Date().toISOString(), ...record })}\n`, "utf8");
  } catch {
    // best-effort only
  }
}

function shouldLogProviderStartup(): boolean {
  return process.env.PWNKIT_SUPPRESS_PROVIDER_STARTUP_LOG !== "1";
}

// ── Transient-failure retry (429 rate-limit + transient 5xx) ────────────
//
// Burst dispatch (the nightly sweep fires hundreds of scans at once) makes
// the shared ChatGPT/Codex subscription return HTTP 429. Before this, the
// engine's FIRST LLM call bailed with `stopReason:"error"`, the agent loop
// produced zero tool calls + zero cost, and the scan was misfiled as
// "no work — sandbox terminated". We now back off and retry retryable HTTP
// statuses at the wire layer — the only place the `Retry-After` header is
// actually visible — so a rate-limited call WAITS and RETRIES instead of
// failing the whole scan. Caps are env-tunable so a burst can be widened
// without a redeploy.

/** HTTP statuses worth retrying: rate-limit (429) + transient 5xx. */
export function isRetryableHttpStatus(status: number): boolean {
  return (
    status === 429 ||
    status === 500 ||
    status === 502 ||
    status === 503 ||
    status === 504
  );
}

/** Max retries after the initial attempt. `PWNKIT_LLM_MAX_RETRIES` (default 6). */
function llmMaxRetries(): number {
  const raw = process.env.PWNKIT_LLM_MAX_RETRIES;
  if (raw == null || raw.trim() === "") return 6;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : 6;
}

/** Cumulative backoff cap in ms. `PWNKIT_LLM_MAX_RETRY_WAIT_MS` (default 60s). */
function llmMaxRetryWaitMs(): number {
  const raw = process.env.PWNKIT_LLM_MAX_RETRY_WAIT_MS;
  if (raw == null || raw.trim() === "") return 60_000;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : 60_000;
}

/**
 * Max retries after the initial attempt for 429 rate-limits specifically.
 * `PWNKIT_LLM_429_MAX_RETRIES` → `PWNKIT_LLM_MAX_RETRIES` → default 12.
 *
 * ChatGPT/Codex per-minute rate limits reset every ~60s; the generic 6-retry
 * budget exhausts in ~14s (verified in prod raw_logs 2026-07-15: "HTTP 429 —
 * backoff 14144ms (retry 6/6)" then "model did not emit a usable variant
 * plan"), so a rate-limited call could not survive a single limiter window.
 * The 429 budget is sized to span several windows instead.
 */
function llm429MaxRetries(): number {
  const raw =
    process.env.PWNKIT_LLM_429_MAX_RETRIES ?? process.env.PWNKIT_LLM_MAX_RETRIES;
  if (raw == null || raw.trim() === "") return 12;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : 12;
}

/**
 * Cumulative 429 backoff cap in ms.
 * `PWNKIT_LLM_429_MAX_RETRY_WAIT_MS` → `PWNKIT_LLM_MAX_RETRY_WAIT_MS` →
 * default 5 min. Bounds server-guided (`Retry-After`) waits; the per-call
 * abort timer (`config.timeout`) still applies as the outer bound.
 */
function llm429MaxRetryWaitMs(): number {
  const raw =
    process.env.PWNKIT_LLM_429_MAX_RETRY_WAIT_MS ??
    process.env.PWNKIT_LLM_MAX_RETRY_WAIT_MS;
  if (raw == null || raw.trim() === "") return 300_000;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : 300_000;
}

/**
 * Plan-quota exhaustion (ChatGPT/Codex `usage_limit_reached`): the
 * subscription's plan-level quota is spent and resets in hours/days, so
 * retrying is pointless. Thrown by postWithRetry on the FIRST such 429 —
 * never retried — so the caller fails fast with a distinct, greppable error
 * and the orchestrator can reschedule after `resetsAtMs` instead of burning
 * the per-minute retry budget against a day-scale reset.
 */
export class QuotaExhaustedError extends Error {
  override readonly name = "QuotaExhaustedError";
  readonly planType?: string;
  readonly resetsAtMs?: number;
  readonly resetsInSeconds?: number;

  constructor(message: string, details: UsageLimitDetails) {
    super(message);
    this.planType = details.planType;
    this.resetsAtMs = details.resetsAtMs;
    this.resetsInSeconds = details.resetsInSeconds;
  }
}

/** Parsed fields of a ChatGPT/Codex `usage_limit_reached` 429 body. */
export interface UsageLimitDetails {
  planType?: string;
  resetsAtMs?: number;
  resetsInSeconds?: number;
}

/**
 * Classify a 429 response body as plan-quota exhaustion. The ChatGPT Codex
 * backend nests the error object: `{"error":{"type":"usage_limit_reached",
 * "plan_type":"pro","resets_at":<epoch-s>,"resets_in_seconds":<n>}}`. Returns
 * undefined unless the body positively parses as that shape — an unparseable
 * 429 body stays a regular (retryable) rate limit.
 */
export function parseUsageLimitReached(
  body: string,
): UsageLimitDetails | undefined {
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch {
    return undefined;
  }
  const root =
    typeof json === "object" && json !== null
      ? (json as Record<string, unknown>)
      : undefined;
  const err =
    typeof root?.error === "object" && root.error !== null
      ? (root.error as Record<string, unknown>)
      : root;
  if (err?.type !== "usage_limit_reached") return undefined;
  const details: UsageLimitDetails = {};
  if (typeof err.plan_type === "string") details.planType = err.plan_type;
  if (typeof err.resets_in_seconds === "number" && Number.isFinite(err.resets_in_seconds)) {
    details.resetsInSeconds = err.resets_in_seconds;
  }
  if (typeof err.resets_at === "number" && Number.isFinite(err.resets_at)) {
    // Wire form is epoch seconds; tolerate an epoch-ms value defensively.
    details.resetsAtMs =
      err.resets_at > 1e12 ? err.resets_at : err.resets_at * 1000;
  }
  if (details.resetsAtMs == null && details.resetsInSeconds != null) {
    details.resetsAtMs = Date.now() + details.resetsInSeconds * 1000;
  }
  return details;
}

/**
 * Idle watchdog for STREAMING (SSE) calls, in ms.
 * `PWNKIT_LLM_STREAM_IDLE_TIMEOUT_MS` (default 120s).
 *
 * The streaming (responses-wireApi) branch disarms the overall call timer once
 * response HEADERS arrive so a long generation isn't killed mid-stream — but
 * that left `reader.read()` completely unbounded: a server that accepts the
 * request and then holds the SSE stream open without emitting a single byte
 * (queue/hold) hung the whole scan silently until the outer sandbox timeout —
 * the "$0 cost, zero output, died at timeout" failure shape reproduced
 * 2026-07-17 against the ChatGPT Codex backend on both E2B and microsandbox.
 * An idle window with NO bytes at all is never legitimate progress (a healthy
 * stream emits reasoning/text deltas or keep-alives continuously), so we fail
 * the call as a transient-class stall: the agent loop's bounded backoff
 * applies, then the run exits loudly via errorExit instead of hanging.
 */
function llmStreamIdleTimeoutMs(): number {
  const raw = process.env.PWNKIT_LLM_STREAM_IDLE_TIMEOUT_MS;
  if (raw == null || raw.trim() === "") return 120_000;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : 120_000;
}

/**
 * Parse a `Retry-After` header into ms. Supports both the delta-seconds form
 * ("5") and the HTTP-date form ("Wed, 21 Oct 2026 07:28:00 GMT"). Returns
 * undefined when the header is absent or unparseable so the caller falls back
 * to exponential backoff.
 */
export function parseRetryAfterMs(
  headerValue: string | null | undefined,
): number | undefined {
  if (!headerValue) return undefined;
  const trimmed = headerValue.trim();
  if (trimmed === "") return undefined;
  if (/^\d+$/.test(trimmed)) return Number.parseInt(trimmed, 10) * 1000;
  const dateMs = Date.parse(trimmed);
  if (Number.isFinite(dateMs)) {
    const delta = dateMs - Date.now();
    return delta > 0 ? delta : 0;
  }
  return undefined;
}

/** Exponential backoff with full jitter. `attempt` is 0-based: ~0.5s, 1s, 2s … capped at `ceilingMs` (default 20s; the 429 path passes 30s to stretch across a per-minute limiter window). */
export function retryBackoffMs(attempt: number, ceilingMs = 20_000): number {
  const ceiling = Math.min(ceilingMs, 500 * 2 ** attempt);
  return Math.floor(Math.random() * ceiling) + 250;
}

/** Cap on a server-guided 429 wait: a `Retry-After` longer than this is clamped, not honored verbatim. */
const RETRY_AFTER_CAP_MS = 120_000;

/**
 * Server-guided wait for a 429, in ms. Reads `retry-after-ms` (millisecond
 * integer, OpenAI platform form) first, then `retry-after` (delta-seconds or
 * HTTP-date), clamped to RETRY_AFTER_CAP_MS. Returns undefined when neither
 * header is present/parseable so the caller falls back to jittered backoff.
 */
function retryAfterMsFromHeaders(headers: Headers | undefined): number | undefined {
  const msHeader = headers?.get?.("retry-after-ms");
  if (msHeader != null) {
    const n = Number.parseInt(msHeader.trim(), 10);
    if (Number.isFinite(n) && n >= 0) return Math.min(n, RETRY_AFTER_CAP_MS);
  }
  const parsed = parseRetryAfterMs(headers?.get?.("retry-after"));
  return parsed != null ? Math.min(parsed, RETRY_AFTER_CAP_MS) : undefined;
}

/** Sleep that rejects with an AbortError if `signal` fires mid-wait (respects the request budget). */
function sleepWithAbort(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException("Aborted during retry backoff", "AbortError"));
      return;
    }
    const t = setTimeout(resolve, ms);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(new DOMException("Aborted during retry backoff", "AbortError"));
      },
      { once: true },
    );
  });
}

function defaultReasoningEffort(model: string): string | undefined {
  const lower = model.toLowerCase();
  if (lower.includes("gpt-5") || /^o[134]/.test(lower)) return "medium";
  return undefined;
}

/**
 * Emit a single-line startup banner summarising the resolved provider
 * config. For Azure, also probes and logs the physical region. Runs at
 * most once per (provider, baseUrl) tuple per process.
 *
 * Non-Azure providers are a no-op beyond the provider label — the region
 * only matters when the endpoint sits behind Azure's front door. This is
 * called lazily from the first request on an `LlmApiRuntime` instance to
 * avoid forcing a network probe at module import time.
 */
export async function logProviderStartup(
  provider: ApiProvider,
  providerLabel: string,
  baseUrl: string,
  model: string,
  wireApi: WireApi,
  apiKey: string,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  const key = `${provider}:${baseUrl}`;
  if (loggedProviderStartup.has(key)) return;
  loggedProviderStartup.add(key);
  if (!shouldLogProviderStartup()) return;

  if (provider !== "azure") {
    // Non-Azure: brief banner, no region probe.
    console.error(
      `[pwnkit] ${providerLabel} provider initialized\n` +
      `  endpoint: ${baseUrl}\n` +
      `  model: ${model}`,
    );
    return;
  }

  const region = await probeAzureRegion(baseUrl, apiKey, fetchImpl);
  const regionLine = region === "unknown"
    ? "  region: unknown (x-ms-region header absent or probe failed)"
    : `  region: ${region} (probed via x-ms-region header)`;

  console.error(
    `[pwnkit] Azure OpenAI provider initialized\n` +
    `  endpoint: ${baseUrl}\n` +
    `  model: ${model}\n` +
    `${regionLine}\n` +
    `  wire api: ${wireApi}`,
  );
}

/** Reset the startup-banner guard. Test-only. */
export function __resetProviderStartupLogForTests(): void {
  loggedProviderStartup.clear();
}

const DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6";
const DEFAULT_OPENROUTER_MODEL = "anthropic/claude-sonnet-4.6";
const FREE_OPENROUTER_MODEL = "nvidia/nemotron-3-super-120b-a12b:free";
const DEFAULT_OPENAI_MODEL = "gpt-4o";

type ApiProvider = "openrouter" | "anthropic" | "openai" | "azure" | "chatgpt-codex" | "z-ai" | "kimi";
type WireApi = "chat_completions" | "responses";

// ── Z.ai GLM (flat-rate Coding Plan key) ───────────────────────────────
//
// GLM ships an Anthropic-compatible Messages endpoint, so z-ai rides the
// exact same `/v1/messages` wire + parser the `anthropic` provider uses —
// it is NOT OpenAI-compatible. The only z-ai-specific behaviour is:
//   - default base URL + model below (override via Z_AI_BASE_URL / PWNKIT_MODEL)
//   - GLM's hybrid reasoning is OFF by default on this endpoint; we turn it
//     ON via the Anthropic `thinking` body field (a hacking engine wants the
//     model thinking). GLM is lenient about NOT echoing `thinking` blocks on
//     follow-up tool turns (verified 2026-06-17), so we simply drop them from
//     parsed output instead of round-tripping them through the agent loop.
const ZAI_DEFAULT_BASE_URL = "https://api.z.ai/api/anthropic";
const ZAI_DEFAULT_MODEL = "glm-5.2";
// Thinking token budget for GLM. 0 (or unset → default) disables thinking.
// Must stay below the 8192 max_tokens the Anthropic body sends below.
const ZAI_DEFAULT_THINKING_BUDGET = 2048;

function zaiThinkingBudget(): number {
  const raw = process.env.PWNKIT_ZAI_THINKING_BUDGET;
  if (raw == null || raw.trim().length === 0) return ZAI_DEFAULT_THINKING_BUDGET;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : ZAI_DEFAULT_THINKING_BUDGET;
}

// ── Moonshot Kimi K3 (flat-rate coding key) ────────────────────────────
//
// Kimi K3 rides the exact same Anthropic-compatible `/v1/messages` wire +
// header/url/parser path z-ai uses (verified live: POST
// https://api.kimi.com/coding/v1/messages with x-api-key + model "k3" →
// HTTP 200). It is NOT OpenAI-compatible. Unlike GLM, K3 emits native
// `thinking` blocks on the Anthropic wire with no special body param, so
// the z-ai-only thinking-budget fragment is deliberately NOT applied here.
// The only kimi-specific config is the default base URL + model below
// (override via KIMI_BASE_URL / PWNKIT_MODEL); note the base URL differs
// from z.ai so kimi requests never hit api.z.ai.
const KIMI_DEFAULT_BASE_URL = "https://api.kimi.com/coding";
const KIMI_DEFAULT_MODEL = "k3";

// ── ChatGPT Codex backend (subscription auth) ──────────────────────────
//
// Opt-in OAuth-bearer provider that calls OpenAI's internal Codex
// backend on the user's ChatGPT Plus/Pro subscription instead of the
// public Platform API. Activated when PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN
// is set (the worker-controller plumbs this from ~/.codex/auth.json or
// the operator can set it directly for `pwnkit` CLI usage on a host
// that has run `codex login`).
//
// The endpoint and OAuth issuer below are the same ones the official
// Codex CLI uses; we are NOT a different client. Originator header is
// set to `pwnkit` so server-side observability can distinguish our
// traffic from raw Codex CLI traffic.
const CODEX_API_ENDPOINT = "https://chatgpt.com/backend-api/codex/responses";
const CODEX_OAUTH_ISSUER = "https://auth.openai.com";
const CODEX_OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const CODEX_DEFAULT_MODEL = "gpt-5.5";

/**
 * Server-side compaction threshold, in prompt tokens, for the long agent loops
 * that have no context strategy of their own (`craft-scan`: 120 steps,
 * `exploit-scan`: 90 steps — both grow monotonically until the provider limit
 * or the wall-clock deadline kills the run).
 *
 * Why 150,000:
 *
 *  - It must leave room for one more full turn AFTER compaction fires. The
 *    gpt-5 family takes ~272k input tokens, and a single craft/exploit turn can
 *    add the system prompt + tool schemas + several 10,000-token tool outputs.
 *    150k leaves ~120k of headroom, so a compaction that lands mid-turn cannot
 *    be immediately overrun.
 *  - It must be high enough that a run which finishes in a handful of steps
 *    never pays for one. Compaction rewrites the prefix, which voids prompt
 *    caching for the turn after it — worth it once a transcript is genuinely
 *    large, pure loss on a short run.
 *  - It is well above the native loop's 77k client-side threshold on purpose:
 *    that path preserves credential-bearing messages verbatim and is the better
 *    strategy where it exists. This is the fallback for loops that have none.
 */
export const LOOP_SERVER_COMPACTION_TOKENS = 150_000;

/**
 * Process-lifetime session id used as the `session_id` header for the
 * chatgpt-codex provider when no scan-specific id is in scope (e.g.
 * the local CLI's `pwnkit audit foo --runtime api` path without a
 * cloud scan context). Per-scan ids are still preferred — this is
 * just the fallback. Randomised once per process to keep concurrent
 * pwnkit invocations from sharing a session bucket on OpenAI's side.
 */
const PROCESS_SESSION_ID = `pwnkit-${Math.random().toString(36).slice(2, 10)}-${Date.now().toString(36)}`;

interface CodexTokenResponse {
  id_token?: string;
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
}

interface ChatGptCodexAuthState {
  refreshToken: string;
  accountId?: string;
  accessToken?: string;
  /** ms-since-epoch deadline; refresh when within 60s of this. */
  accessTokenExpiresAt: number;
  /**
   * Singleflight handle. When a refresh is in flight, concurrent
   * callers await this same Promise instead of triggering parallel
   * refresh calls. Cleared (set to undefined) when the refresh
   * settles — pass or fail. Critical because OpenAI's refresh
   * endpoint rotates the refresh_token itself on every call: two
   * concurrent refreshes can persist a stale token + lock the user
   * out. See opencode codex.ts:431-447 (which lacks this guard —
   * gets away with it via single-request architecture).
   */
  inflightRefresh?: Promise<void>;
}

/**
 * Module-singleton OAuth-refresh state for the chatgpt-codex provider.
 *
 * One refresh cycle per ~hour amortised across every LlmApiRuntime
 * instance — the alternative (per-instance refresh) would burn a
 * refresh call on every CLI invocation and rapidly hit the OAuth
 * provider's rate-limit. Initialised lazily so `pwnkit audit` runs
 * on hosts WITHOUT the env var pay zero startup cost.
 */
let chatGptCodexAuthState: ChatGptCodexAuthState | undefined;

function readChatGptCodexEnv():
  | { accessToken?: string; refreshToken?: string; accountId?: string }
  | undefined {
  const access = process.env.PWNKIT_CHATGPT_ACCESS_TOKEN;
  const refresh = process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN;
  if ((!access || access.length === 0) && (!refresh || refresh.length === 0)) {
    return undefined;
  }
  const accountId = process.env.PWNKIT_CHATGPT_ACCOUNT_ID;
  return {
    accessToken: access && access.length > 0 ? access : undefined,
    refreshToken: refresh && refresh.length > 0 ? refresh : undefined,
    accountId,
  };
}

function readChatGptCodexAuthFile():
  | { accessToken?: string; refreshToken?: string; accountId?: string }
  | undefined {
  const authPath = process.env.PWNKIT_CHATGPT_AUTH_FILE ?? join(homedir(), ".codex", "auth.json");
  if (!existsSync(authPath)) return undefined;
  try {
    const auth = JSON.parse(readFileSync(authPath, "utf8")) as {
      tokens?: {
        access_token?: unknown;
        refresh_token?: unknown;
        account_id?: unknown;
      };
    };
    const tokens = auth.tokens;
    if (!tokens) return undefined;
    const accessToken = typeof tokens.access_token === "string" && tokens.access_token.length > 0
      ? tokens.access_token
      : undefined;
    const refreshToken = typeof tokens.refresh_token === "string" && tokens.refresh_token.length > 0
      ? tokens.refresh_token
      : undefined;
    if (!accessToken && !refreshToken) return undefined;
    return {
      ...(accessToken ? { accessToken } : {}),
      ...(refreshToken ? { refreshToken } : {}),
      ...(typeof tokens.account_id === "string" && tokens.account_id.length > 0
        ? { accountId: tokens.account_id }
        : {}),
    };
  } catch {
    return undefined;
  }
}

/**
 * Pull the `exp` (seconds since epoch) claim out of an OpenAI-issued
 * JWT and return it as ms-since-epoch. Used when a pre-issued
 * access_token arrives via `PWNKIT_CHATGPT_ACCESS_TOKEN` so we know
 * when it stops working — typically ~1h from issuance.
 *
 * Falls back to a default-1h-from-now estimate when the token isn't a
 * recognisable JWT (defensive — should never happen for OpenAI's
 * tokens). The fallback means a worker forwarding a malformed token
 * still gets ~1h of usage before we throw on expiry, instead of
 * refusing to start.
 */
function accessTokenExpiryMs(accessToken: string): number {
  const claims = parseJwtPayload(accessToken);
  const exp = claims?.exp;
  if (typeof exp === "number" && Number.isFinite(exp)) {
    return exp * 1000;
  }
  return Date.now() + 3600_000;
}

async function refreshChatGptCodexAccessToken(refreshToken: string): Promise<CodexTokenResponse> {
  const res = await fetch(`${CODEX_OAUTH_ISSUER}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CODEX_OAUTH_CLIENT_ID,
    }).toString(),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`ChatGPT Codex token refresh failed: ${res.status} ${body.slice(0, 200)}`);
  }
  return (await res.json()) as CodexTokenResponse;
}

/** Parse a JWT payload (no signature verification — we trust our auth.json). */
function parseJwtPayload(token: string): Record<string, unknown> | undefined {
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as Record<
      string,
      unknown
    >;
  } catch {
    return undefined;
  }
}

function extractChatGptAccountId(tokens: CodexTokenResponse): string | undefined {
  const checkClaims = (claims: Record<string, unknown>): string | undefined => {
    if (typeof claims.chatgpt_account_id === "string") return claims.chatgpt_account_id;
    const authClaim = (claims["https://api.openai.com/auth"] ?? {}) as Record<string, unknown>;
    if (typeof authClaim.chatgpt_account_id === "string") return authClaim.chatgpt_account_id;
    const orgs = claims.organizations;
    if (Array.isArray(orgs) && orgs.length > 0 && orgs[0] && typeof orgs[0] === "object") {
      const id = (orgs[0] as { id?: unknown }).id;
      if (typeof id === "string") return id;
    }
    return undefined;
  };
  for (const tok of [tokens.id_token, tokens.access_token]) {
    if (!tok) continue;
    const claims = parseJwtPayload(tok);
    if (claims) {
      const id = checkClaims(claims);
      if (id) return id;
    }
  }
  return undefined;
}

/**
 * Return a fresh access_token for the chatgpt-codex provider. Caches the
 * token until ~60s before expiry, refreshing on demand. Throws if the
 * refresh fails OR if PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN is unset.
 *
 * Exported so callers outside the runtime (e.g. one-off cli probes)
 * can bootstrap a token with the same logic.
 */
export async function getChatGptCodexAccessToken(): Promise<{
  accessToken: string;
  accountId?: string;
}> {
  if (!chatGptCodexAuthState) {
    const fromEnv = readChatGptCodexEnv() ?? readChatGptCodexAuthFile();
    if (!fromEnv) {
      throw new Error(
        "ChatGPT Codex auth: neither PWNKIT_CHATGPT_ACCESS_TOKEN nor " +
          "PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN is set. Run `codex login` and " +
          "either forward the access token via worker-controller (preferred " +
          "for multi-sandbox dispatch — avoids the OAuth refresh-token " +
          "rotation race) or keep a valid ~/.codex/auth.json on this host.",
      );
    }
    chatGptCodexAuthState = {
      // refreshToken is optional now — the worker-controller path forwards
      // a pre-issued access_token and no refresh capability. Local CLI use
      // still gets a refresh_token from env and refreshes in-process.
      refreshToken: fromEnv.refreshToken ?? "",
      accountId: fromEnv.accountId,
      accessToken: fromEnv.accessToken,
      accessTokenExpiresAt: fromEnv.accessToken
        ? accessTokenExpiryMs(fromEnv.accessToken)
        : 0,
    };
    // Seed accountId from the forwarded access_token's JWT when not
    // already provided — saves one round-trip for cloud sandboxes that
    // never refresh.
    if (fromEnv.accessToken && !chatGptCodexAuthState.accountId) {
      const seedAccountId = extractChatGptAccountId({
        access_token: fromEnv.accessToken,
      } as CodexTokenResponse);
      if (seedAccountId) chatGptCodexAuthState.accountId = seedAccountId;
    }
  }
  const state = chatGptCodexAuthState;
  const now = Date.now();
  // Refresh if we have no token or we're within 60s of expiry.
  const needsRefresh =
    !state.accessToken || state.accessTokenExpiresAt - 60_000 <= now;
  if (needsRefresh && !state.refreshToken) {
    // Forwarded-access-token-only path (typical for E2B sandboxes
    // dispatched from worker-controller). No refresh capability. If the
    // token has expired, the sandbox should be torn down and the
    // controller should dispatch a fresh one with a new token.
    throw new Error(
      "ChatGPT Codex access token expired and no refresh token is " +
        "available. The worker-controller should forward a fresh " +
        "access token at sandbox dispatch.",
    );
  }
  if (needsRefresh) {
    // Singleflight: if a refresh is already in flight, await it. The
    // first concurrent caller wins; the others piggyback on the same
    // refresh response without firing duplicate POSTs.
    if (!state.inflightRefresh) {
      const usedRefresh = state.refreshToken;
      state.inflightRefresh = (async () => {
        try {
          const tokens = await refreshChatGptCodexAccessToken(usedRefresh);
          state.accessToken = tokens.access_token;
          state.accessTokenExpiresAt = Date.now() + (tokens.expires_in ?? 3600) * 1000;
          // Refresh token rotates on every call. Persist the new one
          // immediately or the old one becomes invalid and future
          // refreshes 401. Note: we don't write back to disk here —
          // that's the worker-controller's job for the cloud path,
          // and the CLI path keeps the env-loaded token in-memory only
          // for the lifetime of the process (acceptable since pwnkit-cli
          // is short-lived).
          if (tokens.refresh_token) {
            state.refreshToken = tokens.refresh_token;
          }
          if (!state.accountId) {
            state.accountId = extractChatGptAccountId(tokens);
          }
        } finally {
          // Always clear so the next refresh-needed check can fire
          // again — even on failure (e.g. transient 5xx). The caller
          // sees the rejected promise and handles it.
          state.inflightRefresh = undefined;
        }
      })();
    }
    await state.inflightRefresh;
  }
  if (!state.accessToken) {
    throw new Error("ChatGPT Codex auth: access token still unset after refresh — refresh must have failed.");
  }
  return { accessToken: state.accessToken, accountId: state.accountId };
}

export interface ApiRuntimeDiagnostics {
  valid: boolean;
  provider: ApiProvider;
  providerLabel: string;
  reason?: "missing_key" | "invalid_config";
  fatalError?: string;
}

function parseCodexAzureConfig(): {
  baseUrl?: string;
  model?: string;
  wireApi?: WireApi;
  reasoningEffort?: string;
} {
  const configPath = `${process.env.HOME ?? ""}/.codex/config.toml`;
  if (!existsSync(configPath)) return {};

  try {
    const content = readFileSync(configPath, "utf8");
    const azureSectionMatch = content.match(/\[model_providers\.azure\]([\s\S]*?)(?:\n\[|$)/);
    const activeProviderMatch = content.match(/^\s*model_provider\s*=\s*"([^"]+)"/m);
    const baseUrlMatch = azureSectionMatch?.[1]?.match(/base_url\s*=\s*"([^"]+)"/);
    const wireApiMatch = azureSectionMatch?.[1]?.match(/wire_api\s*=\s*"([^"]+)"/);
    const azureModelMatch = azureSectionMatch?.[1]?.match(/model\s*=\s*"([^"]+)"/);
    const topLevelModelMatch = content.match(/^\s*model\s*=\s*"([^"]+)"/m);
    const reasoningMatch = content.match(/model_reasoning_effort\s*=\s*"([^"]+)"/);

    return {
      baseUrl: baseUrlMatch?.[1],
      model: azureModelMatch?.[1] ?? (activeProviderMatch?.[1] === "azure" ? topLevelModelMatch?.[1] : undefined),
      wireApi: wireApiMatch?.[1] === "responses" ? "responses" : "chat_completions",
      reasoningEffort: reasoningMatch?.[1],
    };
  } catch {
    return {};
  }
}

/**
 * Per-call model→provider routing. Maps a requested model id to its NATURAL
 * provider, returning it only when that provider's auth is present in env. This
 * is what lets a single process fan calls out across providers — e.g. a hunt
 * running with several `models` ([gpt-5.5, glm-5.2, claude-*]) routes each model
 * to its own provider+key simultaneously, instead of the global env-priority
 * picking one provider for the whole process. Returns undefined → fall back to
 * the env-priority chain (existing behaviour).
 */
function providerForModel(model: string | undefined): ApiProvider | undefined {
  if (!model) return undefined;
  const m = model.toLowerCase();
  // Explicit provider prefix → OpenRouter meta-routing (one key, many models).
  if (m.startsWith("openrouter/")) return process.env.OPENROUTER_API_KEY ? "openrouter" : undefined;
  // GLM / Z.ai.
  if (m.startsWith("glm-") || m.startsWith("z-ai/") || m.includes("glm")) {
    return process.env.Z_AI_API_KEY ? "z-ai" : undefined;
  }
  // Kimi K3 / Moonshot.
  if (m.startsWith("k3") || m.startsWith("kimi")) {
    return process.env.KIMI_API_KEY ? "kimi" : undefined;
  }
  // OpenAI GPT-5 / o-series → ChatGPT-Codex subscription if present, else OpenAI.
  if (/^gpt-|^o[1-4](?:[-_]|$)/.test(m)) {
    if (process.env.PWNKIT_CHATGPT_ACCESS_TOKEN || process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN) return "chatgpt-codex";
    if (process.env.OPENAI_API_KEY) return "openai";
    return undefined;
  }
  // Claude / Anthropic → direct anthropic key, else OpenRouter (anthropic/*).
  if (m.startsWith("claude") || m.startsWith("anthropic/") || m.includes("sonnet") || m.includes("opus") || m.includes("haiku")) {
    if (process.env.ANTHROPIC_API_KEY) return "anthropic";
    if (process.env.OPENROUTER_API_KEY) return "openrouter";
    return undefined;
  }
  return undefined;
}

/**
 * Detect which API provider to use based on available keys.
 * When `preferredModel` maps to a provider whose auth is present, that wins
 * (per-call routing). Otherwise priority: PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN ->
 * ANTHROPIC_API_KEY -> Z_AI_API_KEY -> AZURE_OPENAI_API_KEY -> OPENAI_API_KEY -> OPENROUTER_API_KEY (last-resort)
 */
function detectProvider(configApiKey?: string, preferredModel?: string): {
  provider: ApiProvider;
  apiKey: string;
  baseUrl: string;
  defaultModel: string;
  wireApi: WireApi;
  reasoningEffort?: string;
} {
  // If an explicit API key is passed via config, try to guess the provider from the key prefix
  if (configApiKey) {
    if (configApiKey.startsWith("sk-or-")) {
      return {
        provider: "openrouter",
        apiKey: configApiKey,
        baseUrl: "https://openrouter.ai/api/v1",
        defaultModel: DEFAULT_OPENROUTER_MODEL,
        wireApi: "chat_completions",
      };
    }
    if (configApiKey.startsWith("sk-ant-")) {
      return {
        provider: "anthropic",
        apiKey: configApiKey,
        baseUrl: "https://api.anthropic.com",
        defaultModel: DEFAULT_ANTHROPIC_MODEL,
        wireApi: "chat_completions",
      };
    }
    // Assume OpenAI-compatible for other keys
    return {
      provider: "openai",
      apiKey: configApiKey,
      baseUrl: "https://api.openai.com/v1",
      defaultModel: DEFAULT_OPENAI_MODEL,
      wireApi: "chat_completions",
    };
  }

  // Per-call routing: if the requested model maps to a provider whose auth is
  // present, that provider wins over the global env priority — so one process
  // can fan calls across providers (gpt-5.5→codex, glm-5.2→z-ai, claude→anthropic).
  switch (providerForModel(preferredModel)) {
    case "z-ai":
      return { provider: "z-ai", apiKey: process.env.Z_AI_API_KEY as string,
        baseUrl: process.env.Z_AI_BASE_URL ?? ZAI_DEFAULT_BASE_URL, defaultModel: ZAI_DEFAULT_MODEL, wireApi: "chat_completions" };
    case "kimi":
      return { provider: "kimi", apiKey: process.env.KIMI_API_KEY as string,
        baseUrl: process.env.KIMI_BASE_URL ?? KIMI_DEFAULT_BASE_URL, defaultModel: KIMI_DEFAULT_MODEL, wireApi: "chat_completions" };
    case "chatgpt-codex":
      return { provider: "chatgpt-codex", apiKey: "", baseUrl: CODEX_API_ENDPOINT,
        defaultModel: process.env.PWNKIT_MODEL ?? CODEX_DEFAULT_MODEL, wireApi: "responses" };
    case "anthropic":
      return { provider: "anthropic", apiKey: process.env.ANTHROPIC_API_KEY as string,
        baseUrl: process.env.ANTHROPIC_BASE_URL ?? "https://api.anthropic.com", defaultModel: DEFAULT_ANTHROPIC_MODEL, wireApi: "chat_completions" };
    case "openrouter":
      return { provider: "openrouter", apiKey: process.env.OPENROUTER_API_KEY as string,
        baseUrl: "https://openrouter.ai/api/v1", defaultModel: DEFAULT_OPENROUTER_MODEL, wireApi: "chat_completions" };
    case "openai":
      return { provider: "openai", apiKey: process.env.OPENAI_API_KEY as string,
        baseUrl: process.env.OPENAI_BASE_URL ?? "https://api.openai.com/v1", defaultModel: DEFAULT_OPENAI_MODEL, wireApi: "chat_completions" };
    default:
      break; // fall through to env-priority detection
  }

  // Check env vars in priority order. ChatGPT subscription auth wins
  // when present — it's a deliberate operator opt-in via either:
  //
  //   - PWNKIT_CHATGPT_ACCESS_TOKEN — pre-issued access token. The
  //     worker-controller refreshes once at dispatch time, persists the
  //     rotated refresh_token back to auth.json, and forwards just the
  //     access_token to each sandbox. This is the multi-sandbox path
  //     because it eliminates the OAuth refresh-token rotation race
  //     (every sandbox refreshing in parallel against a refresh_token
  //     that gets invalidated on first use).
  //
  //   - PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN — refresh token only. The
  //     in-process provider refreshes on demand. Suitable for local CLI
  //     use (one process at a time); not safe for parallel sandbox
  //     dispatch.
  //
  // Either env present → use the chatgpt-codex provider; we skip the
  // api-key providers entirely because the operator has explicitly told
  // us to use the subscription path.
  const chatGptAccess = process.env.PWNKIT_CHATGPT_ACCESS_TOKEN;
  const chatGptRefresh = process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN;
  const chatGptAuthFile = !chatGptAccess && !chatGptRefresh
    ? readChatGptCodexAuthFile()
    : undefined;
  if (
    (chatGptAccess && chatGptAccess.length > 0) ||
    (chatGptRefresh && chatGptRefresh.length > 0) ||
    !!chatGptAuthFile
  ) {
    return {
      provider: "chatgpt-codex",
      // No api key — auth flows via OAuth bearer that's refreshed on
      // demand by getChatGptCodexAccessToken(). Empty string keeps the
      // existing apiKey-required diagnostics from firing (those check
      // for empty strings; we want "valid but bearer-not-key").
      apiKey: "",
      // baseUrl is informational only — the runtime hardcodes
      // CODEX_API_ENDPOINT for this provider.
      baseUrl: CODEX_API_ENDPOINT,
      defaultModel: process.env.PWNKIT_MODEL ?? CODEX_DEFAULT_MODEL,
      wireApi: "responses",
    };
  }

  // NOTE: OpenRouter is intentionally checked LAST (just before the no-key
  // fallback), not here. It is a last-resort meta-provider; a stale or leaked
  // OPENROUTER_API_KEY must never outrank an explicitly-configured z-ai or
  // chatgpt-codex credential during a per-call multi-provider fan-out.
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  if (anthropicKey) {
    return {
      provider: "anthropic",
      apiKey: anthropicKey,
      baseUrl: process.env.ANTHROPIC_BASE_URL ?? "https://api.anthropic.com",
      defaultModel: DEFAULT_ANTHROPIC_MODEL,
      wireApi: "chat_completions",
    };
  }

  // Z.ai GLM — Anthropic-compatible wire. Selected by Z_AI_API_KEY; in the
  // cloud path the worker injects exactly this one key when the operator
  // picks the z-ai provider. Rides the anthropic header/url/parser paths.
  const zaiKey = process.env.Z_AI_API_KEY;
  if (zaiKey) {
    return {
      provider: "z-ai",
      apiKey: zaiKey,
      baseUrl: process.env.Z_AI_BASE_URL ?? ZAI_DEFAULT_BASE_URL,
      defaultModel: ZAI_DEFAULT_MODEL,
      wireApi: "chat_completions",
    };
  }

  // Moonshot Kimi K3 — Anthropic-compatible wire, same treatment as z-ai.
  // Selected by KIMI_API_KEY (explicit operator opt-in). Defaults to
  // api.kimi.com/coding — distinct from z.ai — so kimi never hits Z.ai.
  const kimiKey = process.env.KIMI_API_KEY;
  if (kimiKey) {
    return {
      provider: "kimi",
      apiKey: kimiKey,
      baseUrl: process.env.KIMI_BASE_URL ?? KIMI_DEFAULT_BASE_URL,
      defaultModel: KIMI_DEFAULT_MODEL,
      wireApi: "chat_completions",
    };
  }

  const azureKey = process.env.AZURE_OPENAI_API_KEY;
  if (azureKey) {
    const azureConfig = parseCodexAzureConfig();
    return {
      provider: "azure",
      apiKey: azureKey,
      baseUrl: process.env.AZURE_OPENAI_BASE_URL ?? process.env.OPENAI_BASE_URL ?? azureConfig.baseUrl ?? "https://api.openai.com/v1",
      defaultModel: process.env.AZURE_OPENAI_MODEL ?? azureConfig.model ?? DEFAULT_OPENAI_MODEL,
      wireApi: (process.env.AZURE_OPENAI_WIRE_API as WireApi) ?? azureConfig.wireApi ?? "chat_completions",
      reasoningEffort: azureConfig.reasoningEffort,
    };
  }

  const openaiKey = process.env.OPENAI_API_KEY;
  if (openaiKey) {
    return {
      provider: "openai",
      apiKey: openaiKey,
      baseUrl: "https://api.openai.com/v1",
      defaultModel: DEFAULT_OPENAI_MODEL,
      wireApi: "chat_completions",
    };
  }

  // OpenRouter — last-resort meta-provider (many models, one key). Checked
  // AFTER z-ai / azure / openai so a stale or leaked OPENROUTER_API_KEY can't
  // hijack a run that has a valid z-ai or chatgpt-codex credential.
  const openrouterKey = process.env.OPENROUTER_API_KEY;
  if (openrouterKey) {
    return {
      provider: "openrouter",
      apiKey: openrouterKey,
      baseUrl: "https://openrouter.ai/api/v1",
      defaultModel: DEFAULT_OPENROUTER_MODEL,
      wireApi: "chat_completions",
    };
  }

  // No key found — default to Anthropic (will fail at runtime with helpful message)
  return {
    provider: "anthropic",
    apiKey: "",
    baseUrl: process.env.ANTHROPIC_BASE_URL ?? "https://api.anthropic.com",
    defaultModel: DEFAULT_ANTHROPIC_MODEL,
    wireApi: "chat_completions",
  };
}

/**
 * Runtime that calls LLM APIs directly.
 *
 * Supports multiple providers with automatic detection:
 * - ChatGPT Codex (PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN) — subscription-backed Codex access
 * - OpenRouter (OPENROUTER_API_KEY) — access many models through one API
 * - Anthropic (ANTHROPIC_API_KEY) — direct Claude API access
 * - OpenAI (OPENAI_API_KEY) — direct OpenAI API access
 *
 * Priority: PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN -> ANTHROPIC_API_KEY -> Z_AI_API_KEY -> AZURE_OPENAI_API_KEY -> OPENAI_API_KEY -> OPENROUTER_API_KEY (last-resort)
 *
 * Model can be overridden with PWNKIT_MODEL env var or --model flag.
 *
 * Supports two modes:
 * - Legacy: single-prompt execute() for backward compat with existing agent loop
 * - Native: structured multi-turn messages with tool_use for the new agent loop
 */
export class LlmApiRuntime implements Runtime, NativeRuntime {
  readonly type = "api" as const;
  private config: RuntimeConfig;
  private provider: ApiProvider;
  private apiKey: string;
  private baseUrl: string;
  private model: string;
  private wireApi: WireApi;
  private reasoningEffort?: string;
  private azureConfig: ReturnType<typeof parseCodexAzureConfig>;
  private serverCompactionTokens?: number;

  constructor(config: RuntimeConfig) {
    this.config = config;
    this.azureConfig = parseCodexAzureConfig();
    // Thread the requested model into detection so provider follows the model
    // per-call (per-call multi-provider routing) when its auth is available.
    const detected = detectProvider(config.apiKey, config.model ?? process.env.PWNKIT_MODEL);
    this.provider = detected.provider;
    this.apiKey = detected.apiKey;
    this.baseUrl = detected.baseUrl;
    this.wireApi = detected.wireApi;
    this.reasoningEffort = process.env.PWNKIT_REASONING_EFFORT ?? detected.reasoningEffort;
    // `compact_threshold` has an API minimum of 1000; clamp rather than send a
    // value the server will reject on the hot path of every request.
    this.serverCompactionTokens = config.serverCompactionTokens !== undefined
      ? Math.max(1000, config.serverCompactionTokens)
      : undefined;
    const requestedModel = config.model ?? process.env.PWNKIT_MODEL;
    // "free" is a special alias for the free OpenRouter model
    if (requestedModel === "free" && this.provider === "openrouter") {
      this.model = FREE_OPENROUTER_MODEL;
    } else {
      this.model = requestedModel ?? detected.defaultModel;
    }

    // Azure GPT-5.6 Sol rejects function tools on /chat/completions even
    // with reasoning_effort="none". The same deployment supports tools on
    // /responses, so upgrade only this exact Azure deployment. Other Azure
    // models keep the operator-selected wire API.
    if (
      this.provider === "azure"
      && this.model.toLowerCase() === "gpt-5.6-sol"
      && this.wireApi === "chat_completions"
    ) {
      this.wireApi = "responses";
    }

    // Fire-and-forget startup banner. For Azure, this probes `/models`
    // once for the x-ms-region header so operators can see where their
    // traffic physically lands (data-residency transparency). The probe
    // is cached and tolerant of failures — never blocks the main path.
    // Skip entirely when no key is configured (the diagnostics path will
    // surface the missing-key error to the user instead).
    if (this.apiKey && !process.env.PWNKIT_SKIP_PROVIDER_BANNER) {
      void logProviderStartup(
        this.provider,
        this.providerLabel,
        this.baseUrl,
        this.model,
        this.wireApi,
        this.apiKey,
      ).catch(() => {
        // Swallow — startup logging must never abort runtime init.
      });
    }
  }

  /** Whether this provider uses OpenAI-compatible chat/completions format. */
  private get isOpenAICompat(): boolean {
    return (
      this.provider === "openrouter" ||
      this.provider === "openai" ||
      this.provider === "azure" ||
      // chatgpt-codex always speaks Responses API; treat it as
      // OpenAI-compat for body-shape branching purposes (the Responses
      // wire-API code paths below already key on `wireApi === "responses"`
      // and produce a body codex's backend accepts as-is).
      this.provider === "chatgpt-codex"
    );
  }

  /**
   * The resolved model id this runtime will actually call — the requested
   * model when one was picked, otherwise the provider's detected default.
   * Surfaced so the pipeline can stamp the engine-resolved model on
   * `scan_completed` (CI review scans are dispatched with no model pick, so
   * this is the only place the concrete id exists).
   */
  resolvedModel(): string {
    return this.model;
  }

  /** Build the appropriate headers for the configured provider. */
  private buildHeaders(): Record<string, string> {
    if (this.provider === "chatgpt-codex") {
      // OAuth bearer set lazily by ensureFreshHeaders() before each
      // request — we keep a sync facade here for caller ergonomics but
      // the actual access_token is injected pre-flight. Setting an
      // empty Authorization here would override the populated one, so
      // intentionally OMIT it — the pre-flight method writes it.
      //
      // `originator` + `User-Agent` mirror opencode's chat.headers hook
      // (codex.ts:610-614): originator identifies the client to
      // OpenAI's server-side analytics (Codex CLI uses `codex_cli_rs`,
      // we ship `pwnkit`), and User-Agent gives them a way to
      // distinguish our version + platform in their access logs.
      return {
        "Content-Type": "application/json",
        originator: "pwnkit",
        "User-Agent": `pwnkit/${VERSION}`,
      };
    }
    if (this.isOpenAICompat) {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (this.provider === "azure") {
        // Azure OpenAI uses api-key header, not Bearer token
        headers["api-key"] = this.apiKey;
      } else {
        headers["Authorization"] = `Bearer ${this.apiKey}`;
      }
      if (this.provider === "openrouter") {
        headers["HTTP-Referer"] = "https://0sec.ai";
        headers["X-Title"] = "pwnkit Security Scanner";
      }
      return headers;
    }
    // Anthropic
    return {
      "Content-Type": "application/json",
      "x-api-key": this.apiKey,
      "anthropic-version": "2023-06-01",
    };
  }

  /**
   * For the chatgpt-codex provider, decorate the headers with the
   * freshly-refreshed OAuth bearer + `ChatGPT-Account-Id` + a
   * stable `session_id` (opencode codex.ts:614 — used by Codex
   * backend for request correlation + rate-limit attribution +
   * prompt-cache affinity). For every other provider it's a no-op
   * that returns the stock headers unchanged. Caller MUST await
   * this before the fetch — that's where token refresh actually
   * happens.
   *
   * session_id is process-stable (PROCESS_SESSION_ID, randomised
   * once at module load). A pwnkit-cli invocation = one scan = one
   * session, so the process-lifetime constant is the right
   * granularity. If we ever want per-scan ids inside a long-lived
   * controller process, add a setter on the runtime; for now this
   * matches how the CLI is actually invoked.
   */
  private async ensureFreshHeaders(): Promise<Record<string, string>> {
    const base = this.buildHeaders();
    if (this.provider !== "chatgpt-codex") return base;
    const { accessToken, accountId } = await getChatGptCodexAccessToken();
    base["Authorization"] = `Bearer ${accessToken}`;
    if (accountId) base["ChatGPT-Account-Id"] = accountId;
    base["session_id"] = PROCESS_SESSION_ID;
    // SSE accept header — pwnkit's existing code uses fetch with raw
    // body so the AI SDK doesn't set this for us. Codex backend
    // streams via SSE; without an explicit Accept header some
    // intermediate CDN can downgrade to non-streaming + buffer the
    // whole response. Set it everywhere for chatgpt-codex.
    base["Accept"] = "text/event-stream";
    return base;
  }

  /** Build the API endpoint URL. */
  private buildUrl(): string {
    if (this.provider === "chatgpt-codex") {
      // Codex backend is a fixed endpoint — no base URL substitution.
      // The path is always `/backend-api/codex/responses` regardless of
      // the requested model; that's how the upstream Codex CLI talks
      // to it too.
      return CODEX_API_ENDPOINT;
    }
    if (this.isOpenAICompat) {
      return `${this.baseUrl}/${this.wireApi === "responses" ? "responses" : "chat/completions"}`;
    }
    return `${this.baseUrl}/v1/messages`;
  }

  /**
   * Chat-completions param name for the token cap. Newer OpenAI model
   * families (gpt-5.*, o1/o2/o3) rejected the legacy `max_tokens` field
   * and require `max_completion_tokens`. Older models still accept the
   * legacy name, so we flip based on model prefix.
   */
  private get maxTokensParamKey(): "max_tokens" | "max_completion_tokens" {
    return /^gpt-5|^o[1-3](?:[-_]|$)/i.test(this.model)
      ? "max_completion_tokens"
      : "max_tokens";
  }

  /**
   * Anthropic `thinking` body fragment for the z-ai/GLM provider. GLM's
   * hybrid reasoning is OFF by default on its Anthropic endpoint; we enable
   * it (a hacking engine wants the model reasoning) via the standard
   * Anthropic extended-thinking field. Returns {} for every other provider
   * (real Anthropic Claude already reasons; we don't change its behaviour)
   * and when the budget is set to 0. The returned `thinking` blocks are
   * dropped from parsed output (GLM doesn't require echoing them back —
   * verified 2026-06-17), so this never perturbs the agent loop's history.
   */
  private anthropicThinkingField(): Record<string, unknown> {
    if (this.provider !== "z-ai") return {};
    const budget = zaiThinkingBudget();
    if (budget <= 0) return {};
    return { thinking: { type: "enabled", budget_tokens: budget } };
  }

  /**
   * Per-turn prompt-cache accounting line, so a run can be shown to actually
   * be hitting cache rather than assumed to be. Off unless
   * `PWNKIT_DEBUG_PROMPT_CACHE` is set — this fires once per agent turn, and an
   * unconditional line would interleave with the TUI on every scan.
   *
   * The same numbers reach the cloud without this flag: `cachedInputTokens`
   * flows into `ScanCostLedger` and the `scan_completed` cost breakdown, which
   * is the durable, queryable proof. This is the local fast path.
   */
  private logCacheUsage(usage: NativeRuntimeResult["usage"]): void {
    if (!usage || !process.env.PWNKIT_DEBUG_PROMPT_CACHE) return;
    const read = usage.cachedInputTokens ?? 0;
    const write = usage.cacheWriteTokens ?? 0;
    const hitRate = usage.inputTokens > 0
      ? Math.round((read / usage.inputTokens) * 100)
      : 0;
    console.error(
      `[pwnkit] prompt-cache ${this.providerLabel}: read=${read} write=${write} ` +
      `uncached=${usage.inputTokens - read - write} total_in=${usage.inputTokens} hit=${hitRate}%`,
    );
  }

  /** Friendly provider name for error messages. */
  private get providerLabel(): string {
    switch (this.provider) {
      case "openrouter": return "OpenRouter";
      case "anthropic": return "Anthropic";
      case "openai": return "OpenAI";
      case "azure": return "Azure OpenAI";
      case "chatgpt-codex": return "ChatGPT (Codex backend)";
      case "z-ai": return "Z.ai (GLM)";
      case "kimi": return "Kimi (Moonshot)";
    }
  }

  private noKeyError(): string {
    return (
      "No provider credential found. Set one of:\n" +
      "  export PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN=... (ChatGPT Codex subscription auth)\n" +
      "  export OPENROUTER_API_KEY=sk-or-...   (OpenRouter — many models, one key)\n" +
      "  export ANTHROPIC_API_KEY=sk-ant-...    (Anthropic — direct Claude access)\n" +
      "  export AZURE_OPENAI_API_KEY=...        (Azure OpenAI — reuse your Codex Azure provider)\n" +
      "  export OPENAI_API_KEY=sk-...           (OpenAI — direct GPT access)\n" +
      "  export Z_AI_API_KEY=...                (Z.ai GLM — flat-rate Coding Plan, Anthropic-compatible)\n" +
      "  export KIMI_API_KEY=...                (Moonshot Kimi K3 — flat-rate coding, Anthropic-compatible)"
    );
  }

  getConfigurationDiagnostics(): ApiRuntimeDiagnostics {
    // chatgpt-codex's "key" is an OAuth refresh token in env, not
    // a Platform API key field — skip the missing-key guard for it
    // and let the refresh attempt surface real errors at request time.
    if (!this.apiKey && this.provider !== "chatgpt-codex") {
      return {
        valid: false,
        provider: this.provider,
        providerLabel: this.providerLabel,
        reason: "missing_key",
        fatalError: this.noKeyError(),
      };
    }

    if (this.provider !== "azure") {
      return {
        valid: true,
        provider: this.provider,
        providerLabel: this.providerLabel,
      };
    }

    const hasConfiguredBaseUrl = !!(
      process.env.AZURE_OPENAI_BASE_URL ||
      process.env.OPENAI_BASE_URL ||
      this.azureConfig.baseUrl
    );
    const hasConfiguredModel = !!(
      this.config.model ||
      process.env.PWNKIT_MODEL ||
      process.env.AZURE_OPENAI_MODEL ||
      this.azureConfig.model
    );

    const missing: string[] = [];
    if (!hasConfiguredBaseUrl) {
      missing.push("AZURE_OPENAI_BASE_URL (or [model_providers.azure].base_url in ~/.codex/config.toml)");
    }
    if (!hasConfiguredModel) {
      missing.push("AZURE_OPENAI_MODEL or an Azure-backed `model = \"...\"` in ~/.codex/config.toml");
    }

    if (missing.length > 0) {
      return {
        valid: false,
        provider: this.provider,
        providerLabel: this.providerLabel,
        reason: "invalid_config",
        fatalError:
          "Azure OpenAI runtime is selected, but the configuration is incomplete.\n" +
          `Missing: ${missing.join("; ")}\n` +
          "pwnkit will not guess Azure defaults because that can silently route to the wrong endpoint or deployment.",
      };
    }

    return {
      valid: true,
      provider: this.provider,
      providerLabel: this.providerLabel,
    };
  }

  /**
   * POST to the provider endpoint and, on a retryable HTTP status
   * (429 rate-limit / transient 5xx), back off and retry — honoring a
   * `Retry-After` header when present, otherwise exponential backoff with
   * full jitter (so a burst of concurrent scans desynchronises instead of
   * hammering the limit in lockstep).
   *
   * Two 429 classes are handled differently:
   * - per-minute rate limit → retry with the wider 429 budget
   *   (PWNKIT_LLM_429_MAX_RETRIES attempts / PWNKIT_LLM_429_MAX_RETRY_WAIT_MS
   *   cumulative, defaults 12 / 5min) since the limiter resets every ~60s;
   *   `Retry-After` / `retry-after-ms` headers are honored up to a 120s cap.
   * - plan-quota exhaustion (`usage_limit_reached`, resets in hours/days) →
   *   throws QuotaExhaustedError on the FIRST response, never retried, so the
   *   scan fails fast with a distinct error instead of burning retries.
   *
   * Other retryable statuses (transient 5xx) keep the generic budget:
   * PWNKIT_LLM_MAX_RETRIES (attempts) and PWNKIT_LLM_MAX_RETRY_WAIT_MS
   * (cumulative backoff). On exhaustion it returns the last still-failing
   * Response with its body intact, so the caller's existing `!res.ok` branch
   * surfaces the clear "API error <status>" message — a rate-limit never
   * masquerades as silent no-work.
   *
   * Headers are re-resolved per attempt (via ensureFreshHeaders → OAuth
   * refresh) so a token that rotated during the wait is picked up. The body
   * is fixed across attempts.
   */
  private async postWithRetry(
    bodyJson: string,
    signal: AbortSignal,
  ): Promise<Response> {
    let waited429Ms = 0;
    let waitedOtherMs = 0;
    for (let attempt = 0; ; attempt++) {
      // buildUrl() is the configured LLM provider endpoint (operator-set via
      // provider config / PWNKIT_* env), never user/attacker input; same
      // trusted endpoint the client already POSTed to, now wrapped in retry.
      // foxguard: ignore[js/no-ssrf]
      const res = await fetch(this.buildUrl(), {
        method: "POST",
        headers: await this.ensureFreshHeaders(),
        body: bodyJson,
        signal,
      });
      if (res.ok || !isRetryableHttpStatus(res.status)) {
        return res;
      }

      const is429 = res.status === 429;
      // A 429 body distinguishes per-minute rate limiting (retry) from plan-
      // quota exhaustion (fail fast), so it must be read to classify. If the
      // response is handed back below, it is re-wrapped with the same body.
      let bodyText: string | undefined;
      if (is429) {
        try {
          bodyText = await res.text?.();
        } catch {
          bodyText = undefined;
        }
        const quota =
          bodyText != null ? parseUsageLimitReached(bodyText) : undefined;
        if (quota) {
          const resetsAtIso =
            quota.resetsAtMs != null
              ? new Date(quota.resetsAtMs).toISOString()
              : "unknown";
          appendNativeTrace({
            kind: "quota-exhausted",
            provider: this.providerLabel,
            status: res.status,
            planType: quota.planType ?? null,
            resetsAtMs: quota.resetsAtMs ?? null,
          });
          process.stderr.write(
            `[pwnkit] ${this.providerLabel} usage_limit_reached — plan quota ` +
              `exhausted (plan=${quota.planType ?? "unknown"}, ` +
              `resets_at=${resetsAtIso}); failing without retry\n`,
          );
          throw new QuotaExhaustedError(
            `${this.providerLabel} usage_limit_reached: plan quota exhausted ` +
              `(plan=${quota.planType ?? "unknown"}, resets_at=${resetsAtIso}) ` +
              `— reschedulable after reset`,
            quota,
          );
        }
      }

      const maxRetries = is429 ? llm429MaxRetries() : llmMaxRetries();
      const maxWaitMs = is429 ? llm429MaxRetryWaitMs() : llmMaxRetryWaitMs();
      const waitedMs = is429 ? waited429Ms : waitedOtherMs;
      // Hand the last still-failing Response back with its body intact.
      const handBack = (): Response =>
        is429 && bodyText != null
          ? new Response(bodyText, {
              status: res.status,
              statusText: res.statusText,
              headers: res.headers,
            })
          : res;
      if (attempt >= maxRetries) {
        return handBack();
      }
      const retryAfter = is429
        ? retryAfterMsFromHeaders(res.headers)
        : parseRetryAfterMs(res.headers?.get?.("retry-after"));
      const delay = retryAfter ?? retryBackoffMs(attempt, is429 ? 30_000 : 20_000);
      if (waitedMs + delay > maxWaitMs) return handBack();
      // Drain the failed response so the socket is released before retrying
      // (429 bodies were already consumed above for classification).
      if (!is429) {
        try {
          await res.text?.();
        } catch {
          // best-effort — a mocked/streamed body may not expose text()
        }
      }
      appendNativeTrace({
        kind: "retry",
        provider: this.providerLabel,
        status: res.status,
        attempt: attempt + 1,
        delayMs: delay,
        retryAfterHonored: retryAfter != null,
      });
      process.stderr.write(
        `[pwnkit] ${this.providerLabel} HTTP ${res.status} — backoff ${delay}ms ` +
          `(retry ${attempt + 1}/${maxRetries})\n`,
      );
      if (is429) {
        waited429Ms += delay;
      } else {
        waitedOtherMs += delay;
      }
      await sleepWithAbort(delay, signal);
    }
  }

  // ── Legacy Runtime interface (single-prompt) ──

  async execute(
    prompt: string,
    context?: RuntimeContext,
  ): Promise<RuntimeResult> {
    const start = Date.now();

    // chatgpt-codex's "key" is an OAuth refresh token in env, not
    // a Platform API key field — skip the missing-key guard for it
    // and let the refresh attempt surface real errors at request time.
    if (!this.apiKey && this.provider !== "chatgpt-codex") {
      return {
        output: "",
        exitCode: 1,
        timedOut: false,
        durationMs: Date.now() - start,
        error: this.noKeyError(),
      };
    }

    const systemPrompt = context?.systemPrompt ?? "";

    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.config.timeout || 120_000,
    );

    try {
      let res: Response;

      if (this.isOpenAICompat && this.wireApi === "chat_completions") {
        // OpenRouter / OpenAI / Azure chat completions format
        const messages: Array<Record<string, string>> = [];
        if (systemPrompt) {
          messages.push({ role: "system", content: systemPrompt });
        }
        messages.push({ role: "user", content: prompt });

        res = await this.postWithRetry(
          JSON.stringify({
            model: this.model,
            [this.maxTokensParamKey]: 8192,
            messages,
          }),
          controller.signal,
        );
      } else if (this.isOpenAICompat && this.wireApi === "responses") {
        // Azure Responses API format
        const input: Array<Record<string, unknown>> = [];
        if (systemPrompt) {
          input.push({
            role: "system",
            content: [{ type: "input_text", text: systemPrompt }],
          });
        }
        input.push({
          role: "user",
          content: [{ type: "input_text", text: prompt }],
        });

        const isCodex = this.provider === "chatgpt-codex";
        res = await this.postWithRetry(
          JSON.stringify({
            model: this.model,
            input,
            ...(isCodex ? { store: false } : { max_output_tokens: 8192 }),
          }),
          controller.signal,
        );
      } else {
        // Anthropic Messages API format (also serves the z-ai/GLM provider).
        res = await this.postWithRetry(
          JSON.stringify({
            model: this.model,
            max_tokens: 8192,
            ...this.anthropicThinkingField(),
            ...(systemPrompt ? { system: systemPrompt } : {}),
            messages: [{ role: "user", content: prompt }],
          }),
          controller.signal,
        );
      }

      clearTimeout(timer);

      const body = await res.text();

      if (!res.ok) {
        appendNativeTrace({
          kind: "error-response",
          provider: this.providerLabel,
          status: res.status,
          body: body.slice(0, 2000),
        });
        return {
          output: "",
          exitCode: 1,
          timedOut: false,
          durationMs: Date.now() - start,
          error: `${this.providerLabel} API error ${res.status}: ${body.slice(0, 500)}`,
        };
      }

      const json = JSON.parse(body);

      // Extract text from response (different formats)
      let text: string;
      if (this.isOpenAICompat && this.wireApi === "chat_completions") {
        const msg = json.choices?.[0]?.message;
        // Some models (reasoning models) return content: null with reasoning field
        text = msg?.content ?? msg?.reasoning ?? "";
      } else if (this.isOpenAICompat && this.wireApi === "responses") {
        text =
          typeof json.output_text === "string" && json.output_text.trim()
            ? json.output_text
            : Array.isArray(json.output)
              ? json.output
                  .flatMap((item: Record<string, unknown>) => Array.isArray(item.content) ? item.content : [])
                  .filter((block: Record<string, unknown>) => block.type === "output_text")
                  .map((block: Record<string, unknown>) => String(block.text ?? ""))
                  .join("\n")
              : "";
      } else {
        text =
          json.content
            ?.filter((b: { type: string }) => b.type === "text")
            .map((b: { text: string }) => b.text)
            .join("\n") ?? "";
      }

      return {
        output: text,
        exitCode: 0,
        timedOut: false,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      clearTimeout(timer);
      if (err instanceof QuotaExhaustedError) {
        // Plan-quota exhaustion: fail fast with the distinct, greppable
        // message (carries usage_limit_reached + resets_at) — never retried.
        return {
          output: "",
          exitCode: 1,
          timedOut: false,
          durationMs: Date.now() - start,
          error: err.message,
        };
      }
      const msg = err instanceof Error ? err.message : String(err);
      const timedOut = msg.includes("abort") || msg.includes("timeout");
      return {
        output: "",
        exitCode: 1,
        timedOut,
        durationMs: Date.now() - start,
        error: timedOut
          ? `${this.providerLabel} API request timed out`
          : `${this.providerLabel} API error: ${msg}`,
      };
    }
  }

  // ── Native Runtime interface (structured messages + tool_use) ──

  async executeNative(
    system: string,
    messages: NativeMessage[],
    tools: NativeToolDef[],
    callbacks?: NativeStreamCallbacks,
  ): Promise<NativeRuntimeResult> {
    const start = Date.now();

    // chatgpt-codex's "key" is an OAuth refresh token in env, not
    // a Platform API key field — skip the missing-key guard for it
    // and let the refresh attempt surface real errors at request time.
    if (!this.apiKey && this.provider !== "chatgpt-codex") {
      return {
        content: [{ type: "text", text: "" }],
        stopReason: "error",
        durationMs: Date.now() - start,
        error: this.noKeyError(),
      };
    }

    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.config.timeout || 120_000,
    );

    try {
      let res: Response;

      if (this.isOpenAICompat && this.wireApi === "chat_completions") {
        // Convert to OpenAI chat completions format
        const chatMessages: Array<Record<string, unknown>> = [];
        chatMessages.push({ role: "system", content: system });

        for (const m of messages) {
          // Batch all tool_use blocks from the same message into a
          // single assistant message with a tool_calls array. gpt-5+
          // strictly validates that every assistant with tool_calls is
          // immediately followed by tool responses for each call id —
          // splitting one turn into multiple assistant messages breaks
          // that invariant and produces a 400 from Azure.
          type ToolCall = {
            id: string;
            type: "function";
            function: { name: string; arguments: string };
          };
          const pendingToolCalls: ToolCall[] = [];
          let pendingAssistantText: string | null = null;
          const flushAssistant = (): void => {
            if (pendingToolCalls.length === 0 && pendingAssistantText === null) return;
            const msg: Record<string, unknown> = { role: "assistant" };
            if (pendingAssistantText !== null) msg.content = pendingAssistantText;
            else msg.content = null;
            if (pendingToolCalls.length > 0) msg.tool_calls = pendingToolCalls.slice();
            chatMessages.push(msg);
            pendingToolCalls.length = 0;
            pendingAssistantText = null;
          };

          for (const block of m.content) {
            if (block.type === "text") {
              if (m.role === "assistant") {
                pendingAssistantText = (pendingAssistantText ?? "") + block.text;
              } else {
                flushAssistant();
                chatMessages.push({ role: m.role, content: block.text });
              }
            } else if (block.type === "tool_use") {
              pendingToolCalls.push({
                id: block.id,
                type: "function",
                function: { name: block.name, arguments: JSON.stringify(block.input) },
              });
            } else if (block.type === "tool_result") {
              flushAssistant();
              chatMessages.push({
                role: "tool",
                tool_call_id: block.tool_use_id,
                content: block.content,
              });
            }
          }
          // End-of-message flush so a turn that ends with tool_use
          // blocks emits one assistant message with the full tool_calls
          // array before the next turn's tool_results land.
          flushAssistant();
        }

        const body: Record<string, unknown> = {
          model: this.model,
          [this.maxTokensParamKey]: 8192,
          messages: chatMessages,
        };

        if (tools.length > 0) {
          body.tools = tools.map((t) => ({
            type: "function",
            function: {
              name: t.name,
              description: t.description,
              parameters: t.input_schema,
            },
          }));
        }

        res = await this.postWithRetry(JSON.stringify(body), controller.signal);
      } else if (this.isOpenAICompat && this.wireApi === "responses") {
        // Responses API uses a flat list of items, not role-based messages.
        // function_call and function_call_output are top-level items, not nested
        // inside content arrays. See: developers.openai.com/docs/api-reference/responses
        //
        // ChatGPT Codex backend deviates: the system/developer prompt MUST
        // travel as the top-level `instructions` body field, not as a
        // role:"system" item inside `input`. A request without `instructions`
        // gets a 400 `{"detail":"Instructions are required"}` regardless of
        // what's in `input`. Send the prompt as `instructions` for codex and
        // skip the in-input system message.
        const isCodexProvider = this.provider === "chatgpt-codex";
        const input: Array<Record<string, unknown>> = isCodexProvider
          ? []
          : [
              {
                role: "system",
                content: [{ type: "input_text", text: system }],
              },
            ];

        for (const m of messages) {
          // ── Retained reasoning ──
          // When this assistant turn carries the provider's own item array AND
          // it was produced by exactly this provider+model+wireApi, replay it
          // verbatim. That is the only supported way to return encrypted
          // reasoning on this backend: `previous_response_id` is unsupported,
          // and a field-by-field reconstruction cannot honour "a reasoning item
          // must be immediately followed by the item it produced" — the flush
          // below emits pending text as a `{role, content}` message BEFORE the
          // function_call, which would land a message between the two and 400
          // with `Item 'rs_…' … without its required following item`.
          //
          // The `continue` is load-bearing: falling through would emit the raw
          // items AND their reconstructed twins.
          //
          // Any identity mismatch degrades to today's exact behaviour, which is
          // also the model-switch strip point — encrypted reasoning is bound to
          // the model that produced it. That covers the ensemble runtime
          // (`openrouter.ts`), which hands ONE shared messages array to N models
          // and appends the winner's turn back: every non-producing model sees a
          // mismatch and reconstructs, instead of 400-ing on a sibling's items.
          if (
            m.role === "assistant"
            && m.providerRaw
            && m.providerRaw.provider === this.provider
            && m.providerRaw.model === this.model
            && m.providerRaw.wireApi === this.wireApi
            && m.providerRaw.output.length > 0
          ) {
            input.push(...(m.providerRaw.output as Array<Record<string, unknown>>));
            continue;
          }

          // Collect text blocks into a role-based message. The OpenAI Responses
          // API distinguishes text content by producer: user/system/developer
          // roles use `input_text`, but the assistant role must use
          // `output_text` (or `refusal`). Sending `input_text` on an assistant
          // message yields a 400 on Azure with:
          //   "Invalid value: 'input_text'. Supported values are:
          //    'output_text' and 'refusal'."
          // The agent loop replays the assistant's prior text replies on every
          // turn, so this bug used to kill every multi-turn scan on Azure
          // starting at turn 2 — the error was misdiagnosed as a "max turns
          // without completion" because each retry failed with the same 400.
          const assistantText = m.role === "assistant";
          const textType = assistantText ? "output_text" : "input_text";
          const textBlocks: Array<Record<string, unknown>> = [];
          for (const block of m.content) {
            if (block.type === "text") {
              textBlocks.push({ type: textType, text: block.text });
            } else if (block.type === "tool_use") {
              // Flush any pending text blocks first
              if (textBlocks.length > 0) {
                input.push({ role: m.role, content: [...textBlocks] });
                textBlocks.length = 0;
              }
              // Assistant tool_use → top-level function_call item
              input.push({
                type: "function_call",
                call_id: block.id,
                name: block.name,
                arguments: JSON.stringify(block.input),
              });
            } else if (block.type === "tool_result") {
              // Flush any pending text blocks first
              if (textBlocks.length > 0) {
                input.push({ role: m.role, content: [...textBlocks] });
                textBlocks.length = 0;
              }
              // Tool result → top-level function_call_output item
              input.push({
                type: "function_call_output",
                call_id: block.tool_use_id,
                output: block.content,
              });
            }
          }
          // Flush remaining text blocks
          if (textBlocks.length > 0) {
            input.push({ role: m.role, content: textBlocks });
          }
        }

        const reasoningEffort = this.reasoningEffort ?? defaultReasoningEffort(this.model);
        // Codex backend rejects `max_output_tokens` set explicitly +
        // expects `store: false` to stay stateless (opencode
        // transform.ts:1056-1063 sets these for every Responses
        // request). For the public Platform API path keep the
        // explicit cap so we stay budget-bounded. Diff is per-key,
        // not per-shape — same body otherwise.
        const isCodex = this.provider === "chatgpt-codex";
        const body: Record<string, unknown> = {
          model: this.model,
          input,
          ...(isCodex
            ? { store: false, instructions: system }
            : { max_output_tokens: 8192 }),
          ...(reasoningEffort
            ? {
                reasoning: {
                  effort: reasoningEffort,
                  summary: "auto",
                },
                include: ["reasoning.encrypted_content"],
              }
            : {}),
          // Server-side compaction, opt-in per runtime. ZDR-friendly: it works
          // with `store: false`, so nothing is retained server-side between
          // requests. Only the loops with no context strategy of their own ask
          // for it — the native loop compacts client-side and must not be
          // compacted twice.
          ...(this.serverCompactionTokens
            ? {
                context_management: {
                  compaction: { compact_threshold: this.serverCompactionTokens },
                },
              }
            : {}),
        };

        if (tools.length > 0) {
          body.tools = tools.map((t) => ({
            type: "function",
            name: t.name,
            description: t.description,
            // Codex backend's Responses API expects `strict` alongside
            // parameters. `false` keeps schema enforcement off so a model
            // that drifts on argument shape still emits the call instead
            // of failing it server-side. The public OpenAI Responses
            // schema tolerates the extra field.
            strict: false,
            parameters: t.input_schema,
          }));
          if (isCodex) {
            // Every reference Codex client (openai/codex,
            // glowbom/glowby) sets these. Omitting them shouldn't be
            // fatal — the backend doesn't 400 — but it leaves the
            // tool-invocation policy implicit. Setting them explicitly
            // matches the canonical client behaviour and rules out a
            // server-side default that gates tool use.
            body.tool_choice = "auto";
            body.parallel_tool_calls = true;
          }
        }

        res = await this.postWithRetry(
          JSON.stringify({ ...body, stream: true }),
          controller.signal,
        );

        clearTimeout(timer);

        if (!res.ok) {
          const responseText = await res.text();
          return {
            content: [{ type: "text", text: "" }],
            stopReason: "error",
            durationMs: Date.now() - start,
            error: `${this.providerLabel} API error ${res.status}: ${responseText.slice(0, 500)}`,
          };
        }

        const streamed = await this.consumeResponsesStream(res, start, callbacks, {
          idleTimeoutMs: llmStreamIdleTimeoutMs(),
        });
        return streamed;
      } else {
        // Anthropic Messages API format
        const apiMessages: Array<{ role: string; content: WireBlock[] }> = messages.map((m) => ({
          role: m.role,
          content: m.content.map((block): WireBlock => {
            if (block.type === "text") return { type: "text", text: block.text };
            if (block.type === "tool_use") {
              return { type: "tool_use", id: block.id, name: block.name, input: block.input };
            }
            if (block.type === "tool_result") {
              return {
                type: "tool_result",
                tool_use_id: block.tool_use_id,
                content: block.content,
                ...(block.is_error ? { is_error: true } : {}),
              };
            }
            // Unreachable for the current block union (`block` narrows to
            // `never` here); kept as the original passthrough so an added
            // block kind degrades to "sent as-is" rather than being dropped.
            return block;
          }),
        }));

        // ── Prompt caching ──
        // Only Anthropic (and explicitly opted-in Anthropic-compatible
        // endpoints) get `cache_control`. This branch is the ONLY one that can
        // emit it: the OpenAI chat-completions and Responses branches above
        // build their bodies independently and never reach this code, so the
        // Azure / OpenAI / Codex / OpenRouter wires are structurally incapable
        // of receiving an Anthropic-shaped field.
        const cacheEnabled =
          features.promptCache && providerSupportsPromptCache(this.provider);

        for (const index of cacheEnabled
          ? planMessageBreakpoints(apiMessages, MESSAGE_CACHE_BREAKPOINTS)
          : []) {
          // Mark the message's LAST block so the cached prefix covers it whole.
          // Breakpoints are recomputed from the current array on every call and
          // never carried across turns — which is exactly what makes recovery
          // from `native-loop`'s compaction automatic: compaction rewrites the
          // transcript and voids these entries, and the next call simply plans
          // fresh breakpoints over the rewritten history.
          const blocks = apiMessages[index]?.content;
          const lastBlock = blocks?.length ? blocks[blocks.length - 1] : undefined;
          if (blocks && lastBlock) blocks[blocks.length - 1] = withCacheControl(lastBlock);
        }

        const body: Record<string, unknown> = {
          model: this.model,
          max_tokens: 8192,
          ...this.anthropicThinkingField(),
          // The remaining breakpoint goes on the system prompt. Because the
          // wire renders `tools` → `system` → `messages`, one marker here
          // caches the tool schemas AND the system prompt together — the
          // largest, most static span in the request, and the one that never
          // changes for the lifetime of an agent session. Sent as a block array
          // (the only shape that accepts `cache_control`) when caching is on,
          // and left as a plain string otherwise so non-caching providers see a
          // byte-identical body to before this change.
          system: cacheEnabled
            ? [withCacheControl({ type: "text", text: system })]
            : system,
          messages: apiMessages,
        };

        if (tools.length > 0) {
          body.tools = tools;
        }

        res = await this.postWithRetry(JSON.stringify(body), controller.signal);
      }

      // Keep the abort timer ARMED through the body read. `fetch()` resolves as
      // soon as the response HEADERS arrive; the body is drained by `res.text()`.
      // If a provider (or a CDN in front of it) flushes a 200 status line early
      // and then trickles/stalls the body, clearing the timer here would leave
      // `res.text()` unbounded — a single call could hang the whole craft loop
      // forever. z.ai/GLM and Anthropic both buffer non-streaming responses and
      // send headers+body together at the end (TTFB≈TOTAL, verified 2026-07-08),
      // so in practice this changes nothing for them; it only closes the latent
      // "timer cleared too early" gap. Cleared right after the body is in hand.
      const responseText = await res.text();

      clearTimeout(timer);

      if (!res.ok) {
        return {
          content: [{ type: "text", text: "" }],
          stopReason: "error",
          durationMs: Date.now() - start,
          error: `${this.providerLabel} API error ${res.status}: ${responseText.slice(0, 500)}`,
        };
      }

      const json = JSON.parse(responseText);
      appendNativeTrace({
        kind: "native-response",
        provider: this.providerLabel,
        wireApi: this.wireApi,
        usage: json.usage ?? null,
        outputPreview: Array.isArray(json.output)
          ? json.output.slice(0, 10).map((item: Record<string, unknown>) => ({
              type: item.type,
              summary: item.summary,
              content: item.content,
              name: item.name,
            }))
          : null,
        topLevelKeys: Object.keys(json),
      });

      // Parse response into unified content blocks
      let content: NativeContentBlock[];
      let stopReason: "end_turn" | "tool_use" | "max_tokens" | "error";
      let usage: NativeRuntimeResult["usage"];
      // Set on the Responses path only — the wire formats that have no
      // replayable item array leave it undefined and keep today's behaviour.
      let providerRaw: NativeRuntimeResult["providerRaw"];

      if (this.isOpenAICompat && this.wireApi === "chat_completions") {
        const choice = json.choices?.[0];
        const msg = choice?.message;
        content = [];

        // Handle reasoning models that return content: null with reasoning field
        const textContent = msg?.content ?? msg?.reasoning;
        if (textContent) {
          content.push({ type: "text", text: textContent });
        }
        if (msg?.tool_calls) {
          for (const tc of msg.tool_calls) {
            content.push({
              type: "tool_use",
              id: tc.id,
              name: tc.function.name,
              input: safeParseJson(tc.function.arguments),
            });
          }
        }

        const finishReason = choice?.finish_reason;
        stopReason =
          finishReason === "tool_calls" || finishReason === "function_call"
            ? "tool_use"
            : finishReason === "length"
              ? "max_tokens"
              : "end_turn";

        if (json.usage) {
          usage = {
            inputTokens: json.usage.prompt_tokens ?? 0,
            outputTokens: json.usage.completion_tokens ?? 0,
          };
        }
      } else if (this.isOpenAICompat && this.wireApi === "responses") {
        content = [];
        // Keep the raw item array so the next turn can replay the reasoning
        // items verbatim — see ProviderRawOutput.
        providerRaw = {
          provider: this.provider,
          model: this.model,
          wireApi: this.wireApi,
          output: (json.output ?? []) as unknown[],
        };
        for (const item of json.output ?? []) {
          if (item.type === "function_call") {
            content.push({
              type: "tool_use",
              id: item.call_id as string,
              name: item.name as string,
              input: safeParseJson(item.arguments as string),
            });
            continue;
          }

          if (item.type === "reasoning") {
            const summaryParts = Array.isArray(item.summary)
              ? item.summary
                  .map((block: Record<string, unknown>) => typeof block.text === "string" ? block.text : "")
                  .filter((text: string) => text.trim().length > 0)
              : [];
            const reasoningText = summaryParts.join("\n").trim();
            if (reasoningText) {
              content.push({ type: "text", text: reasoningText });
            }
            continue;
          }

          for (const block of item.content ?? []) {
            if (block.type === "output_text") {
              content.push({ type: "text", text: block.text as string });
            } else if (block.type === "summary_text" || block.type === "reasoning_text") {
              const text = typeof block.text === "string" ? block.text : "";
              if (text.trim()) content.push({ type: "text", text });
            }
          }
        }

        stopReason = content.some((block) => block.type === "tool_use") ? "tool_use" : "end_turn";

        if (json.usage) {
          usage = {
            inputTokens: json.usage.input_tokens ?? 0,
            outputTokens: json.usage.output_tokens ?? 0,
            // Responses `input_tokens` already includes the cached span, so
            // this is instrumentation only — see the streaming path.
            ...readResponsesCachedTokens(json.usage as Record<string, unknown>),
          };
        }
      } else {
        // Anthropic format (also serves the z-ai/GLM provider).
        const rawBlocks = (json.content ?? []) as Array<Record<string, unknown>>;
        // GLM (thinking enabled) streams a leading `thinking` block. Surface
        // it as reasoning for the UI, then DROP it from the content blocks:
        // GLM does not require echoing thinking blocks back on follow-up tool
        // turns (verified 2026-06-17), so keeping them out of `content` means
        // the agent loop never replays them — and the fallthrough below never
        // JSON-stringifies them into visible output.
        if (callbacks?.onThinking) {
          const thinkingText = rawBlocks
            .filter((b) => b.type === "thinking")
            .map((b) => (typeof b.thinking === "string" ? b.thinking : ""))
            .join("")
            .trim();
          if (thinkingText) callbacks.onThinking(thinkingText);
        }
        content = rawBlocks
          .filter((block) => block.type !== "thinking" && block.type !== "redacted_thinking")
          .map((block: Record<string, unknown>) => {
            if (block.type === "text") {
              return { type: "text", text: block.text as string };
            }
            if (block.type === "tool_use") {
              return {
                type: "tool_use",
                id: block.id as string,
                name: block.name as string,
                input: block.input as Record<string, unknown>,
              };
            }
            return { type: "text", text: JSON.stringify(block) };
          });

        stopReason = json.stop_reason === "tool_use" ? "tool_use" as const
          : json.stop_reason === "max_tokens" ? "max_tokens" as const
          : "end_turn" as const;

        // `readCacheUsage` re-adds the cached spans that Anthropic subtracts
        // out of `input_tokens`, so `inputTokens` keeps meaning "total prompt
        // tokens" whether or not caching is active — see prompt-cache.ts.
        if (json.usage) {
          usage = readCacheUsage(json.usage);
          this.logCacheUsage(usage);
        }
      }

      return {
        content,
        stopReason,
        usage,
        durationMs: Date.now() - start,
        ...(providerRaw ? { providerRaw } : {}),
      };
    } catch (err) {
      clearTimeout(timer);
      if (err instanceof QuotaExhaustedError) {
        // Plan-quota exhaustion: fail fast with the distinct, greppable
        // message (carries usage_limit_reached + resets_at) — never retried.
        return {
          content: [{ type: "text", text: "" }],
          stopReason: "error",
          durationMs: Date.now() - start,
          error: err.message,
        };
      }
      const msg = err instanceof Error ? err.message : String(err);
      const timedOut = msg.includes("abort") || msg.includes("timeout");
      return {
        content: [{ type: "text", text: "" }],
        stopReason: "error",
        durationMs: Date.now() - start,
        error: timedOut
          ? `${this.providerLabel} API request timed out`
          : `${this.providerLabel} API error: ${msg}`,
      };
    }
  }

  private async consumeResponsesStream(
    res: Response,
    start: number,
    callbacks?: NativeStreamCallbacks,
    opts?: { idleTimeoutMs?: number },
  ): Promise<NativeRuntimeResult> {
    const reader = res.body?.getReader();
    if (!reader) {
      return {
        content: [{ type: "text", text: "" }],
        stopReason: "error",
        durationMs: Date.now() - start,
        error: `${this.providerLabel} API error: missing response body`,
      };
    }

    // Idle watchdog on EVERY read — see llmStreamIdleTimeoutMs for why. The
    // overall call timer is already disarmed by the time we get here (headers
    // arrived), so without this nothing bounds a silently-held stream.
    const idleTimeoutMs = opts?.idleTimeoutMs ?? llmStreamIdleTimeoutMs();
    let stalled = false;
    const readBounded = async (): Promise<ReadableStreamReadResult<Uint8Array>> => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        return await Promise.race([
          reader.read(),
          new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => {
              stalled = true;
              reject(new Error("stream stalled"));
            }, idleTimeoutMs);
          }),
        ]);
      } finally {
        if (timer) clearTimeout(timer);
      }
    };

    const decoder = new TextDecoder();
    let buffer = "";
    let completedResponse: Record<string, unknown> | null = null;
    // The ChatGPT Codex backend's `response.completed` payload has NO
    // `output[]` array — it's just `{response: {id, usage, end_turn}}`.
    // Function calls + assistant messages flow exclusively through
    // `response.output_item.done` events during the stream. We collect
    // them here as a fallback the final-output extraction can fall back
    // on when `completedResponse.output` is absent. The public OpenAI
    // Responses API still populates `output` so this is harmless there.
    const streamedOutputItems: Array<Record<string, unknown>> = [];
    let thinkingText = "";
    let lastThinkingEmit = 0;
    let lastThinkingLength = 0;

    const emitThinking = (force = false) => {
      if (!callbacks?.onThinking || !thinkingText.trim()) return;
      if (force && lastThinkingEmit > 0 && lastThinkingLength === thinkingText.length) return;
      const now = Date.now();
      const nextChars = thinkingText.length - lastThinkingLength;
      const firstEmit = lastThinkingLength === 0;
      if (!force) {
        if (firstEmit && thinkingText.length < 96) return;
        if (nextChars < 96 && now - lastThinkingEmit < 250) return;
      }
      lastThinkingEmit = now;
      lastThinkingLength = thinkingText.length;
      callbacks.onThinking(thinkingText);
    };

    while (true) {
      let chunk: ReadableStreamReadResult<Uint8Array>;
      try {
        chunk = await readBounded();
      } catch (err) {
        if (stalled) {
          // Release the held socket best-effort, then surface the stall as a
          // transient-class error (the agent loop's bounded retry applies; a
          // persistent server hold fails loudly via errorExit, never hangs).
          try {
            await reader.cancel();
          } catch {
            /* best-effort — the stream is already broken */
          }
          const secs = Math.round(idleTimeoutMs / 1000);
          process.stderr.write(
            `[pwnkit] ${this.providerLabel} stream stalled — no SSE events for ${secs}s (server hold; aborting call)\n`,
          );
          return {
            content: [{ type: "text", text: "" }],
            stopReason: "error",
            durationMs: Date.now() - start,
            error: `${this.providerLabel} stream stalled — no SSE events for ${secs}s (server accepted but held the stream; transient)`,
          };
        }
        throw err;
      }
      const { done, value } = chunk;
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      let boundary = buffer.indexOf("\n\n");
      while (boundary >= 0) {
        const rawChunk = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        boundary = buffer.indexOf("\n\n");

        const payload = rawChunk
          .split("\n")
          .filter((line) => line.startsWith("data:"))
          .map((line) => line.slice(5).trim())
          .join("\n");
        if (!payload || payload === "[DONE]") continue;

        let event: Record<string, unknown>;
        try {
          event = JSON.parse(payload) as Record<string, unknown>;
        } catch {
          continue;
        }

        const type = String(event.type ?? "");
        if (type === "response.output_text.delta") {
          // Visible assistant text streaming. We don't accumulate locally —
          // the agent loop's batcher is responsible for coalescing fragments
          // before they hit the event bus. Just forward the raw fragment.
          const delta = typeof event.delta === "string" ? event.delta : "";
          if (delta) {
            callbacks?.onDelta?.("assistant_response", delta);
          }
          continue;
        }

        if (type === "response.reasoning_summary_text.delta") {
          const delta = typeof event.delta === "string" ? event.delta : "";
          if (delta) {
            thinkingText += delta;
            // Forward the raw fragment to the cloud-side delta hook BEFORE
            // running the local thinking-emit heuristic — the cloud needs
            // the live stream, not the heuristic-throttled snapshots.
            callbacks?.onDelta?.("reasoning", delta);
            emitThinking(false);
          }
          continue;
        }

        if (type === "response.reasoning_summary_text.done") {
          const text = typeof event.text === "string"
            ? event.text
            : typeof event.part === "object" && event.part && typeof (event.part as Record<string, unknown>).text === "string"
              ? String((event.part as Record<string, unknown>).text)
              : "";
          if (text.trim()) {
            thinkingText = text;
            emitThinking(true);
          }
          continue;
        }

        if (type === "response.output_item.done") {
          // Codex backend (and recent public Responses API streams) emit
          // each output item — including function_call items — through
          // this event. The terminal `response.completed` payload has no
          // `output[]` on the Codex backend, so without capturing items
          // here every tool call gets discarded and the agent loop never
          // sees a tool_use block. Tested against
          // chatgpt.com/backend-api/codex/responses with gpt-5.5.
          const item = event.item as Record<string, unknown> | undefined;
          if (item && typeof item.type === "string") {
            streamedOutputItems.push(item);
          }
          continue;
        }

        if (type === "response.completed" || type === "response.incomplete") {
          const response = event.response as Record<string, unknown> | undefined;
          if (response) {
            completedResponse = response;
            const usage = response.usage as Record<string, unknown> | undefined;
            if (usage) {
              callbacks?.onUsage?.({
                inputTokens: Number(usage.input_tokens ?? 0),
                outputTokens: Number(usage.output_tokens ?? 0),
              });
            }
          }
        }
      }
    }

    emitThinking(true);

    if (!completedResponse) {
      return {
        content: thinkingText ? [{ type: "text", text: thinkingText }] : [{ type: "text", text: "" }],
        stopReason: "error",
        durationMs: Date.now() - start,
        error: `${this.providerLabel} API error: stream completed without final response`,
      };
    }

    appendNativeTrace({
      kind: "native-response-stream",
      provider: this.providerLabel,
      wireApi: this.wireApi,
      usage: completedResponse.usage ?? null,
      outputPreview: Array.isArray(completedResponse.output)
        ? (completedResponse.output as Array<Record<string, unknown>>).slice(0, 10).map((item) => ({
            type: item.type,
            summary: item.summary,
            content: item.content,
            name: item.name,
          }))
        : null,
      streamedItems: streamedOutputItems.slice(0, 10).map((item) => ({
        type: item.type,
        name: item.name,
        call_id: item.call_id,
        argumentsPreview:
          typeof item.arguments === "string"
            ? (item.arguments as string).slice(0, 200)
            : undefined,
      })),
      topLevelKeys: Object.keys(completedResponse),
    });

    // Codex backend's `response.completed.output` is an EMPTY array (`[]`,
    // not absent) because items are already delivered via streamed
    // `response.output_item.done` events. The `??` operator wouldn't fall
    // through on `[]` — we'd keep the empty array and silently drop every
    // streamed function_call. Prefer the streamed list whenever it has any
    // items; only fall back to `completedResponse.output` when nothing was
    // streamed in-band (Azure / public OpenAI fill it; Codex doesn't).
    const completedOutput =
      (completedResponse.output as Array<Record<string, unknown>> | undefined) ??
      [];
    const outputItems =
      streamedOutputItems.length > 0 ? streamedOutputItems : completedOutput;
    const content: NativeContentBlock[] = [];
    for (const item of outputItems) {
      if (item.type === "function_call") {
        content.push({
          type: "tool_use",
          id: String(item.call_id),
          name: String(item.name),
          input: safeParseJson(String(item.arguments ?? "{}")),
        });
        continue;
      }
      if (item.type === "reasoning") {
        const summaryParts = Array.isArray(item.summary)
          ? item.summary
              .map((block: Record<string, unknown>) => typeof block.text === "string" ? block.text : "")
              .filter((text: string) => text.trim().length > 0)
          : [];
        const reasoningText = summaryParts.join("\n").trim();
        if (reasoningText) content.push({ type: "text", text: reasoningText });
        continue;
      }
      for (const block of (item.content as Array<Record<string, unknown>> | undefined) ?? []) {
        if (block.type === "output_text") {
          content.push({ type: "text", text: String(block.text ?? "") });
        }
      }
    }

    const usageRecord = completedResponse.usage as Record<string, unknown> | undefined;
    const usage = usageRecord
      ? {
          inputTokens: Number(usageRecord.input_tokens ?? 0),
          outputTokens: Number(usageRecord.output_tokens ?? 0),
          // Responses `input_tokens` already INCLUDES the cached span (unlike
          // Anthropic, which subtracts it), so no normalisation is needed —
          // this is purely so cache behaviour becomes observable. Without it
          // the Codex cache hit rate is unmeasurable: `prompt-cache.ts`
          // instruments the Anthropic path only.
          ...readResponsesCachedTokens(usageRecord),
        }
      : undefined;

    return {
      content,
      stopReason: content.some((item) => item.type === "tool_use") ? "tool_use" : "end_turn",
      usage,
      durationMs: Date.now() - start,
      // `outputItems` is the complete, correctly-ordered response array —
      // reasoning items with their `encrypted_content` still attached, each
      // immediately followed by the item it produced. Handing it back lets the
      // next turn replay it verbatim instead of re-deriving the reasoning.
      providerRaw: {
        provider: this.provider,
        model: this.model,
        wireApi: this.wireApi,
        output: outputItems,
      },
    };
  }

  async isAvailable(): Promise<boolean> {
    // chatgpt-codex uses an OAuth refresh token (env-supplied) rather
    // than an api key; treat presence of the env var as availability.
    if (this.provider === "chatgpt-codex") {
      const refresh = process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN;
      return typeof refresh === "string" && refresh.length > 0;
    }
    return !!this.apiKey;
  }
}
