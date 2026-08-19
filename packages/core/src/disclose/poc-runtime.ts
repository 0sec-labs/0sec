/**
 * 0sec#171 — PoC execution runtime.
 *
 * Given a {@link Finding} with a `pocSteps` graph (formalised in 0sec#170)
 * plus a {@link PocExecutionTarget} pointing at a live, operator-provisioned
 * instance, run each step in order and capture its observable effect:
 *
 *   - shell  → child_process.spawn, capture stdout/stderr/exit code/duration
 *   - http   → fetch, capture status / response body (capped) / duration
 *   - docker → child_process.spawn("docker", ["run", ...args, image])
 *   - note   → no-op, recorded as `kind: "skipped"`
 *
 * After each step the runtime evaluates the optional {@link PocStepExpect}
 * predicate from #170 and records the per-step verdict. The aggregate
 * verdict (`exploit_still_works` / `exploit_broken` / `could_not_run`) is
 * what the cloud's pre-file gate (0sec-cloud#109) uses to decide whether
 * a finding is still viable to disclose.
 *
 * Design notes:
 *   - Pure function from `(finding, target) → PocExecutionReport`. No DB
 *     writes, no global state. Persistence is the caller's job.
 *   - Hard timeout per step via AbortController for fetch and `child.kill()`
 *     for spawn.
 *   - All captured outputs are capped at 1 MiB. Larger outputs are truncated
 *     with a trailing marker; the spawn streams are still drained so the
 *     child doesn't block on a full pipe.
 *   - The runtime never consults the network / fs without an explicit
 *     `target`. Callers that don't pass `--target-url` get a runtime that
 *     refuses to dispatch http actions cleanly (errored, with an explanatory
 *     message) instead of one that silently no-ops.
 */

import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import type { Finding, PocStep, PocStepAction, PocStepExpect } from "@0sec/shared";

// ── Public types ────────────────────────────────────────────────────────────

export interface PocExecutionTarget {
  /** Base URL for http-action steps. Required for http actions to dispatch. */
  baseUrl?: string;
  /**
   * Pre-resolved auth context keyed by persona name. Steps can opt into a
   * persona by setting an `X-0sec-Persona: <name>` header on an http
   * action; the runtime will then merge in that persona's cookies/headers
   * before sending and strip the marker header.
   */
  personas?: Record<string, { cookies?: string; headers?: Record<string, string> }>;
  /** Shell environment for shell-action steps. Merged on top of process.env. */
  env?: Record<string, string>;
  /** Working directory for shell / docker actions. */
  cwd?: string;
  /** Per-step timeout in milliseconds. Defaults to 30 000. */
  timeoutMs?: number;
  /**
   * Per-host requests-per-second cap for http-action dispatch — rate-limit
   * reverify so we don't accidentally hammer a vendor's production target.
   * Defaults to 2 rps. The bucket is shared across every http step in the
   * graph and refills 1 token / (1000/rps) ms. (Most responsible-disclosure
   * programs require some form of rate limit on testing traffic.)
   */
  rpsPerHost?: number;
  /**
   * Required host patterns authorizing every executable PoC step. HTTP,
   * shell, and docker actions refuse before dispatch when absent or empty.
   * Wildcards: `*.acme.com` matches subdomains but not `acme.com`.
   */
  scopeAllowlist?: string[];
  /**
   * Public CLI callers set this false. Shell and Docker proof steps then
   * refuse before spawning anything on the operator host.
   */
  allowProcessActions?: boolean;
}

/** Per-step verdict returned to the caller. */
export type PocStepVerdict = "passed" | "failed" | "errored" | "skipped";

/** Aggregate verdict on the whole step graph. */
export type PocOverallVerdict =
  | "exploit_still_works"
  | "exploit_broken"
  | "could_not_run";

export interface PocStepResult {
  stepId: string;
  kind: PocStepVerdict;
  observedExit?: number;
  observedStatus?: number;
  /** First MAX_CAPTURE_BYTES of stdout (UTF-8). Truncated with marker if longer. */
  observedStdout?: string;
  /** First MAX_CAPTURE_BYTES of stderr (UTF-8). Truncated with marker if longer. */
  observedStderr?: string;
  /** First MAX_CAPTURE_BYTES of the http response body. */
  observedResponseBody?: string;
  durationMs: number;
  /** Populated on `errored` (timeout, network failure, unsupported action…). */
  error?: string;
}

export interface PocExecutionReport {
  findingId: string;
  startedAt: string;
  endedAt: string;
  steps: PocStepResult[];
  overallVerdict: PocOverallVerdict;
}

// ── Constants ───────────────────────────────────────────────────────────────

/** 1 MiB cap on captured stdout/stderr/response-body, per step, per stream. */
export const MAX_CAPTURE_BYTES = 1024 * 1024;
/** Default per-step timeout, 30 seconds. */
export const DEFAULT_STEP_TIMEOUT_MS = 30_000;
/** Header marker that selects a persona from `target.personas`. */
const PERSONA_HEADER = "X-0sec-Persona";
/** Marker appended when a captured stream is truncated. */
const TRUNCATION_MARKER = "\n…[truncated at 1MiB]";

/** Default per-host requests-per-second cap for http-action dispatch. */
export const DEFAULT_RPS_PER_HOST = 2;

/** Maximum redirect hops for http action dispatch (prevent open-redirect loops). */
const MAX_REDIRECT_HOPS = 5;

// ── Per-host token bucket (responsible-disclosure rate limit) ───────────────
//
// In-memory token bucket keyed on `URL(target).host`. We use a tiny ad-hoc
// implementation rather than pulling in a dependency: the bucket is
// per-host-per-process, so the worst-case state is tiny.
//
// 429 handling: when a host returns 429 we set `retryUntil = now +
// max(parseInt(retryAfter)*1000, 60_000)` — that blocks every subsequent
// acquire until the deadline passes. Conservative: even a 1-second
// `Retry-After` triggers a 60-second cool-off so we don't tarpit-loop the
// target.

interface HostBucket {
  /** Tokens currently available (1 token = 1 request). */
  tokens: number;
  /** Tokens added per millisecond. */
  refillRatePerMs: number;
  /** Maximum tokens (bucket capacity) — also the burst cap. */
  capacity: number;
  /** Last refill timestamp (Date.now). */
  lastRefill: number;
  /** When > now(), all acquires block. Set on 429. */
  retryUntil: number;
}

const hostBuckets = new Map<string, HostBucket>();

function getOrInitBucket(host: string, rps: number): HostBucket {
  let bucket = hostBuckets.get(host);
  if (!bucket) {
    bucket = {
      tokens: rps, // full bucket on first use
      refillRatePerMs: rps / 1000,
      capacity: rps,
      lastRefill: Date.now(),
      retryUntil: 0,
    };
    hostBuckets.set(host, bucket);
  }
  return bucket;
}

function refill(bucket: HostBucket): void {
  const now = Date.now();
  const elapsed = now - bucket.lastRefill;
  if (elapsed > 0) {
    bucket.tokens = Math.min(bucket.capacity, bucket.tokens + elapsed * bucket.refillRatePerMs);
    bucket.lastRefill = now;
  }
}

/**
 * Block until 1 token is available for `host`, then consume it. Honours
 * `retryUntil` (set on 429) by sleeping until the deadline first.
 */
async function acquireHostToken(host: string, rps: number): Promise<void> {
  const bucket = getOrInitBucket(host, rps);
  // 429-induced cool-off: hard sleep until retryUntil before doing anything.
  while (Date.now() < bucket.retryUntil) {
    const waitMs = bucket.retryUntil - Date.now();
    // eslint-disable-next-line no-await-in-loop
    await sleep(Math.min(waitMs, 1000));
  }
  // Refill + consume; spin (with sleep) until we have at least one token.
  // eslint-disable-next-line no-constant-condition
  while (true) {
    refill(bucket);
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return;
    }
    const tokensNeeded = 1 - bucket.tokens;
    const waitMs = Math.max(1, Math.ceil(tokensNeeded / bucket.refillRatePerMs));
    // eslint-disable-next-line no-await-in-loop
    await sleep(waitMs);
  }
}

/**
 * Mark a host as 429-rate-limited until the given deadline. Subsequent
 * `acquireHostToken(host)` calls will block until `retryUntil`.
 */
function markHostRateLimited(host: string, retryAfterHeader: string | null): void {
  const bucket = hostBuckets.get(host);
  if (!bucket) return;
  const parsed = retryAfterHeader ? parseInt(retryAfterHeader, 10) : NaN;
  const retryAfterMs = Number.isFinite(parsed) && parsed > 0 ? parsed * 1000 : 0;
  bucket.retryUntil = Date.now() + Math.max(retryAfterMs, 60_000);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Test-only: reset the in-process token bucket state. Also unsticks any
 * already-parked `acquireHostToken` promise by zeroing the retryUntil and
 * topping up tokens on every still-referenced bucket — otherwise a 429
 * cool-off test would leave a 60-second sleep lingering in the event loop
 * after the assertion has already passed.
 */
export function _resetRateLimitState(): void {
  for (const bucket of hostBuckets.values()) {
    bucket.retryUntil = 0;
    bucket.tokens = bucket.capacity;
  }
  hostBuckets.clear();
}

// ── Scope allowlist (responsible-disclosure: refuse out-of-scope hosts) ─────
//
// `scopeAllowlist` patterns:
//   - exact host match: `acme.com` matches host == "acme.com"
//   - subdomain wildcard: `*.acme.com` matches `a.acme.com`, `b.c.acme.com`
//     but NOT `acme.com` itself (H1's documented semantic)
//   - host comparison is case-insensitive and ignores the port
//   - IPv6 literals are normalised by stripping the `[ ]` brackets so
//     `[2001:db8::1]:443` and `[2001:db8::1]` both match the allowlist
//     entry `[2001:db8::1]` or the bare `2001:db8::1`. A naive
//     `split(":")[0]` would collapse every IPv6 literal to its first
//     hextet — making one allowlisted IPv6 host accidentally match every
//     other IPv6 host.

/**
 * Normalise a host (target or allowlist pattern) for case-insensitive,
 * port-agnostic comparison. Handles IPv6 literals correctly:
 *   - `[2001:db8::1]:443` → `2001:db8::1`
 *   - `[2001:db8::1]`     → `2001:db8::1`
 *   - `2001:db8::1`       → `2001:db8::1` (bare IPv6 — preserved, not port-stripped)
 *   - `acme.com:8080`     → `acme.com`
 *   - `acme.com`          → `acme.com`
 */
function normalizeHostForMatch(value: string): string {
  const trimmed = value.trim().toLowerCase();
  if (trimmed.startsWith("[")) {
    const end = trimmed.indexOf("]");
    return end === -1 ? trimmed : trimmed.slice(1, end);
  }
  // Heuristic for bare (un-bracketed) IPv6 literals: 2+ colons. Don't strip
  // the trailing `:N` because it's a final hextet, not a port. Hostnames and
  // IPv4 with optional `:port` have 0–1 colons.
  if ((trimmed.match(/:/g) ?? []).length >= 2) return trimmed;
  return trimmed.replace(/:\d+$/, "");
}

function hostMatchesAllowlist(host: string, allowlist: string[] | undefined): boolean {
  if (!allowlist || allowlist.length === 0) return true; // no list → no gate
  const target = normalizeHostForMatch(host);
  for (const raw of allowlist) {
    const pattern = normalizeHostForMatch(raw);
    if (!pattern) continue;
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(1); // ".acme.com"
      if (target.endsWith(suffix) && target.length > suffix.length) return true;
    } else if (target === pattern) {
      return true;
    }
  }
  return false;
}

function scopeRequiredResult(
  step: PocStep,
  target: PocExecutionTarget,
  start: number,
): PocStepResult | undefined {
  if (target.scopeAllowlist && target.scopeAllowlist.length > 0) return undefined;
  return {
    stepId: step.id,
    kind: "errored",
    durationMs: Date.now() - start,
    error: "PoC reverify requires a non-empty scope allowlist",
  };
}

function extractUrlsFromShellCommand(cmd: string): string[] {
  const matches = cmd.match(/https?:\/\/[^\s'"]+/g);
  return matches ?? [];
}

function dockerRegistryHost(image: string): string | undefined {
  const separator = image.indexOf("/");
  if (separator === -1) return undefined;
  const firstSegment = image.slice(0, separator);
  return firstSegment.includes(".") || firstSegment.includes(":") || firstSegment === "localhost"
    ? firstSegment
    : undefined;
}

/** Test-only export. */
export const _scopeMatch = hostMatchesAllowlist;

// ── Spawn shim (overridable for tests) ──────────────────────────────────────
//
// Tests inject deterministic spawn / fetch implementations via `setRuntimeDeps`.
// In production we use the real `node:child_process.spawn` and the global
// `fetch`. We don't use vi.mock because the runtime is consumed from both
// vitest tests and the CLI; a runtime-level seam is the simplest path.

type SpawnFn = typeof spawn;
type FetchFn = typeof fetch;

interface RuntimeDeps {
  spawn: SpawnFn;
  fetch: FetchFn;
}

let deps: RuntimeDeps = { spawn, fetch: globalThis.fetch };

/**
 * Override the runtime's spawn / fetch implementations. Intended for tests
 * only. Returns a `restore()` callback that puts the originals back.
 */
export function setRuntimeDeps(overrides: Partial<RuntimeDeps>): () => void {
  const previous = deps;
  deps = { ...previous, ...overrides };
  return () => {
    deps = previous;
  };
}

// ── Top-level entry point ───────────────────────────────────────────────────

/**
 * Execute every step in `finding.pocSteps` against `target` and return the
 * aggregate report. Findings without a step graph round-trip through to a
 * `could_not_run` report — there's nothing to execute.
 */
export async function executePocSteps(
  finding: Finding,
  target: PocExecutionTarget,
): Promise<PocExecutionReport> {
  const startedAt = new Date().toISOString();
  const steps: PocStepResult[] = [];

  const graph = finding.pocSteps ?? [];
  for (const step of graph) {
    // eslint-disable-next-line no-await-in-loop -- steps are intentionally sequential
    const result = await executeStep(step, target);
    steps.push(result);
    // If a non-verify step errors out, downstream steps almost certainly
    // can't run meaningfully. Stop early so we don't waste time hitting a
    // dead target — but only for `errored` (infra failure), not `failed`
    // (clean predicate failure, which we want to *report* on).
    if (result.kind === "errored" && step.kind !== "verify") {
      // Mark every remaining step as skipped so the caller sees a complete
      // graph in the report rather than a truncated one.
      for (let i = graph.indexOf(step) + 1; i < graph.length; i++) {
        steps.push({
          stepId: graph[i].id,
          kind: "skipped",
          durationMs: 0,
          error: "skipped: an earlier step errored",
        });
      }
      break;
    }
  }

  const endedAt = new Date().toISOString();
  return {
    findingId: finding.id,
    startedAt,
    endedAt,
    steps,
    overallVerdict: aggregateVerdict(graph, steps),
  };
}

// ── Per-step dispatch ───────────────────────────────────────────────────────

async function executeStep(
  step: PocStep,
  target: PocExecutionTarget,
): Promise<PocStepResult> {
  const start = Date.now();
  if (
    target.allowProcessActions === false &&
    (step.action.type === "shell" || step.action.type === "docker")
  ) {
    return {
      stepId: step.id,
      kind: "errored",
      durationMs: Date.now() - start,
      error: `PoC ${step.action.type} actions require an isolated execution environment`,
    };
  }
  try {
    switch (step.action.type) {
      case "shell":
        return await runShellStep(step, step.action, target, start);
      case "http":
        return await runHttpStep(step, step.action, target, start);
      case "docker":
        return await runDockerStep(step, step.action, target, start);
      case "note":
        return {
          stepId: step.id,
          kind: "skipped",
          durationMs: Date.now() - start,
        };
      default: {
        // Exhaustive check — TS will flag missing variants here.
        const _exhaustive: never = step.action;
        return {
          stepId: step.id,
          kind: "errored",
          durationMs: Date.now() - start,
          error: `unknown action type: ${JSON.stringify(_exhaustive)}`,
        };
      }
    }
  } catch (err) {
    return {
      stepId: step.id,
      kind: "errored",
      durationMs: Date.now() - start,
      error: errMessage(err),
    };
  }
}

// ── Shell action ────────────────────────────────────────────────────────────

async function runShellStep(
  step: PocStep,
  action: Extract<PocStepAction, { type: "shell" }>,
  target: PocExecutionTarget,
  start: number,
): Promise<PocStepResult> {
  const scopeError = scopeRequiredResult(step, target, start);
  if (scopeError) return scopeError;

  // Scope allowlist (Fix 7): pre-flight extract any URL-shaped tokens and
  // refuse the whole command if any of them point at an out-of-scope host.
  if (target.scopeAllowlist && target.scopeAllowlist.length > 0) {
    for (const u of extractUrlsFromShellCommand(action.cmd)) {
      let host: string;
      try {
        host = new URL(u).host;
      } catch {
        continue;
      }
      if (!hostMatchesAllowlist(host, target.scopeAllowlist)) {
        return {
          stepId: step.id,
          kind: "errored",
          durationMs: Date.now() - start,
          error: `out-of-scope url in shell cmd: ${u} (allowlist: ${target.scopeAllowlist.join(", ")})`,
        };
      }
    }
  }

  const env = { ...process.env, ...(target.env ?? {}) };
  const cwd = action.cwd ?? target.cwd;
  const timeoutMs = target.timeoutMs ?? DEFAULT_STEP_TIMEOUT_MS;

  const spawned = await spawnAndCapture(
    "/bin/sh",
    ["-c", action.cmd],
    { env, cwd, timeoutMs },
  );

  return finaliseProcessStep(step, spawned, start);
}

// ── Docker action ───────────────────────────────────────────────────────────
//
// v1 attempts a real `docker run`. If `docker` is not on PATH the spawn fails
// and the step lands as `errored` with the underlying ENOENT — same shape as
// any other infra failure, so callers don't need a special docker code path.
// If a deployment wants to *forbid* docker actions outright they can wrap
// `executePocSteps` and pre-screen the graph.

async function runDockerStep(
  step: PocStep,
  action: Extract<PocStepAction, { type: "docker" }>,
  target: PocExecutionTarget,
  start: number,
): Promise<PocStepResult> {
  const scopeError = scopeRequiredResult(step, target, start);
  if (scopeError) return scopeError;

  const registryHost = dockerRegistryHost(action.image);
  if (registryHost && !hostMatchesAllowlist(registryHost, target.scopeAllowlist)) {
    return {
      stepId: step.id,
      kind: "errored",
      durationMs: Date.now() - start,
      error: `out-of-scope docker registry: ${registryHost} (allowlist: ${target.scopeAllowlist!.join(", ")})`,
    };
  }

  // Scope allowlist: extract URL-shaped tokens from the docker image + args.
  if (target.scopeAllowlist && target.scopeAllowlist.length > 0) {
    const dockerTokens = [action.image, ...action.args].join(" ");
    for (const u of extractUrlsFromShellCommand(dockerTokens)) {
      let host: string;
      try {
        host = new URL(u).host;
      } catch {
        continue;
      }
      if (!hostMatchesAllowlist(host, target.scopeAllowlist)) {
        return {
          stepId: step.id,
          kind: "errored",
          durationMs: Date.now() - start,
          error: `out-of-scope url in docker action: ${u} (allowlist: ${target.scopeAllowlist.join(", ")})`,
        };
      }
    }
  }

  const env = { ...process.env, ...(target.env ?? {}) };
  const cwd = target.cwd;
  const timeoutMs = target.timeoutMs ?? DEFAULT_STEP_TIMEOUT_MS;

  const spawned = await spawnAndCapture(
    "docker",
    ["run", "--rm", ...action.args, action.image],
    { env, cwd, timeoutMs },
  );

  return finaliseProcessStep(step, spawned, start);
}

// ── HTTP action ─────────────────────────────────────────────────────────────

async function runHttpStep(
  step: PocStep,
  action: Extract<PocStepAction, { type: "http" }>,
  target: PocExecutionTarget,
  start: number,
): Promise<PocStepResult> {
  const scopeError = scopeRequiredResult(step, target, start);
  if (scopeError) return scopeError;

  const url = resolveUrl(action.url, target.baseUrl);
  if (!url) {
    return {
      stepId: step.id,
      kind: "errored",
      durationMs: Date.now() - start,
      error: `http step has a relative url (${action.url}) but no target.baseUrl was provided`,
    };
  }

  // Scope allowlist (Fix 7): refuse before we even touch the wire.
  let host: string;
  try {
    host = new URL(url).host;
  } catch {
    return {
      stepId: step.id,
      kind: "errored",
      durationMs: Date.now() - start,
      error: `http step url is not a valid URL: ${url}`,
    };
  }
  if (!hostMatchesAllowlist(host, target.scopeAllowlist)) {
    return {
      stepId: step.id,
      kind: "errored",
      durationMs: Date.now() - start,
      error: `out-of-scope host: ${host} (allowlist: ${target.scopeAllowlist!.join(", ")})`,
    };
  }

  // Per-host rate limit (Fix 6).
  const rps = target.rpsPerHost ?? DEFAULT_RPS_PER_HOST;
  await acquireHostToken(host, rps);

  const headers = mergePersonaHeaders(action.headers ?? {}, target);

  const timeoutMs = target.timeoutMs ?? DEFAULT_STEP_TIMEOUT_MS;
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);

  // Manual redirect following with scope validation (PK-PUBLIC-005).
  let finalResponse: Response;
  let body = "";
  let currentUrl = url;
  let redirectCount = 0;
  try {
    while (true) {
      finalResponse = await deps.fetch(currentUrl, {
        method: action.method,
        headers,
        body: action.body,
        signal: ac.signal,
        redirect: "manual",
      });

      const status = finalResponse.status;
      const isRedirect = [301, 302, 303, 307, 308].includes(status);

      if (!isRedirect) {
        body = await readBodyCapped(finalResponse);
        if (status === 429) {
          const retryAfter = finalResponse.headers.get("retry-after");
          markHostRateLimited(host, retryAfter);
        }
        break;
      }

      // Redirect hop: validate target against scope allowlist.
      redirectCount++;
      if (redirectCount > MAX_REDIRECT_HOPS) {
        try { finalResponse.body?.cancel(); } catch { /* discard */ }
        clearTimeout(timer);
        return {
          stepId: step.id,
          kind: "errored",
          durationMs: Date.now() - start,
          error: `too many redirects (exceeded ${MAX_REDIRECT_HOPS} hops)`,
        };
      }

      const location = finalResponse.headers.get("location");
      if (!location) {
        // No Location header on redirect — treat as final response.
        body = await readBodyCapped(finalResponse);
        break;
      }

      const nextUrlStr = new URL(location, currentUrl).toString();
      const nextHost = new URL(nextUrlStr).host;

      if (!hostMatchesAllowlist(nextHost, target.scopeAllowlist)) {
        try { finalResponse.body?.cancel(); } catch { /* discard */ }
        clearTimeout(timer);
        return {
          stepId: step.id,
          kind: "errored",
          durationMs: Date.now() - start,
          error: `redirect to out-of-scope host: ${nextHost} (allowlist: ${target.scopeAllowlist!.join(", ")})`,
        };
      }

      // Discard the redirect response body.
      try { finalResponse.body?.cancel(); } catch { /* discard */ }
      currentUrl = nextUrlStr;
      // Continue loop to follow the redirect.
    }
  } catch (err) {
    clearTimeout(timer);
    const aborted = ac.signal.aborted;
    return {
      stepId: step.id,
      kind: "errored",
      durationMs: Date.now() - start,
      error: aborted ? `timeout after ${timeoutMs}ms` : errMessage(err),
    };
  } finally {
    clearTimeout(timer);
  }

  const verdict = evaluateExpect(step.expect, {
    status: finalResponse.status,
    body,
  });

  return {
    stepId: step.id,
    kind: verdict.kind,
    observedStatus: finalResponse.status,
    observedResponseBody: body,
    durationMs: Date.now() - start,
    ...(verdict.error ? { error: verdict.error } : {}),
  };
}

function resolveUrl(stepUrl: string, baseUrl: string | undefined): string | null {
  // Absolute URL passes through unchanged.
  try {
    new URL(stepUrl);
    return stepUrl;
  } catch {
    // Relative URL needs a base.
  }
  if (!baseUrl) return null;
  try {
    return new URL(stepUrl, baseUrl).toString();
  } catch {
    return null;
  }
}

function mergePersonaHeaders(
  stepHeaders: Record<string, string>,
  target: PocExecutionTarget,
): Record<string, string> {
  // Find the persona marker case-insensitively, strip it from the outgoing
  // request, and merge that persona's cookies/headers in.
  const merged: Record<string, string> = {};
  let personaName: string | undefined;
  for (const [k, v] of Object.entries(stepHeaders)) {
    if (k.toLowerCase() === PERSONA_HEADER.toLowerCase()) {
      personaName = v;
      continue;
    }
    merged[k] = v;
  }
  if (!personaName) return merged;
  const persona = target.personas?.[personaName];
  if (!persona) return merged;
  if (persona.headers) {
    for (const [k, v] of Object.entries(persona.headers)) {
      // Step-level headers win over persona defaults.
      if (!(k in merged)) merged[k] = v;
    }
  }
  if (persona.cookies && !("cookie" in lowerKeys(merged))) {
    merged["Cookie"] = persona.cookies;
  }
  return merged;
}

function lowerKeys(obj: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj)) out[k.toLowerCase()] = v;
  return out;
}

async function readBodyCapped(response: Response): Promise<string> {
  // We avoid `response.text()` because it would load the entire body into
  // memory; on a hostile target that could be a denial-of-resource. Stream
  // and stop once we've got MAX_CAPTURE_BYTES.
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: false });
  let captured = "";
  let truncated = false;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    // eslint-disable-next-line no-await-in-loop
    const { value, done } = await reader.read();
    if (done) break;
    if (value) {
      const chunk = decoder.decode(value, { stream: true });
      if (captured.length + chunk.length > MAX_CAPTURE_BYTES) {
        captured += chunk.slice(0, MAX_CAPTURE_BYTES - captured.length);
        truncated = true;
        try {
          await reader.cancel();
        } catch {
          /* swallow */
        }
        break;
      }
      captured += chunk;
    }
  }
  return truncated ? captured + TRUNCATION_MARKER : captured;
}

// ── Process spawn helpers (shared by shell / docker) ────────────────────────

interface SpawnedResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  error?: string;
}

interface SpawnOpts {
  env: NodeJS.ProcessEnv;
  cwd?: string;
  timeoutMs: number;
}

function spawnAndCapture(
  cmd: string,
  args: string[],
  opts: SpawnOpts,
): Promise<SpawnedResult> {
  return new Promise((resolveP) => {
    let child: ChildProcess;
    try {
      child = deps.spawn(cmd, args, {
        env: opts.env,
        cwd: opts.cwd,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      resolveP({
        exitCode: null,
        stdout: "",
        stderr: "",
        timedOut: false,
        error: errMessage(err),
      });
      return;
    }

    let stdout = "";
    let stderr = "";
    let stdoutTruncated = false;
    let stderrTruncated = false;
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill("SIGKILL");
      } catch {
        /* swallow */
      }
    }, opts.timeoutMs);

    child.stdout?.on("data", (chunk: Buffer | string) => {
      const s = typeof chunk === "string" ? chunk : chunk.toString("utf8");
      if (stdout.length + s.length > MAX_CAPTURE_BYTES) {
        if (!stdoutTruncated) {
          stdout += s.slice(0, MAX_CAPTURE_BYTES - stdout.length);
          stdoutTruncated = true;
        }
        return; // keep draining but don't grow `stdout`
      }
      stdout += s;
    });
    child.stderr?.on("data", (chunk: Buffer | string) => {
      const s = typeof chunk === "string" ? chunk : chunk.toString("utf8");
      if (stderr.length + s.length > MAX_CAPTURE_BYTES) {
        if (!stderrTruncated) {
          stderr += s.slice(0, MAX_CAPTURE_BYTES - stderr.length);
          stderrTruncated = true;
        }
        return;
      }
      stderr += s;
    });

    const settle = (exit: number | null, errorMsg?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolveP({
        exitCode: exit,
        stdout: stdoutTruncated ? stdout + TRUNCATION_MARKER : stdout,
        stderr: stderrTruncated ? stderr + TRUNCATION_MARKER : stderr,
        timedOut,
        error: errorMsg,
      });
    };

    child.on("error", (err) => {
      // ENOENT and the like — never fired `exit`. Settle as errored.
      settle(null, errMessage(err));
    });
    child.on("close", (code) => {
      settle(code);
    });
  });
}

function finaliseProcessStep(
  step: PocStep,
  spawned: SpawnedResult,
  start: number,
): PocStepResult {
  const durationMs = Date.now() - start;
  if (spawned.timedOut) {
    return {
      stepId: step.id,
      kind: "errored",
      observedStdout: spawned.stdout,
      observedStderr: spawned.stderr,
      durationMs,
      error: `timeout after ${durationMs}ms`,
    };
  }
  if (spawned.error && spawned.exitCode === null) {
    return {
      stepId: step.id,
      kind: "errored",
      observedStdout: spawned.stdout,
      observedStderr: spawned.stderr,
      durationMs,
      error: spawned.error,
    };
  }

  const verdict = evaluateExpect(step.expect, {
    exitCode: spawned.exitCode,
    stdout: spawned.stdout,
  });

  const result: PocStepResult = {
    stepId: step.id,
    kind: verdict.kind,
    observedStdout: spawned.stdout,
    observedStderr: spawned.stderr,
    durationMs,
  };
  if (spawned.exitCode !== null) result.observedExit = spawned.exitCode;
  if (verdict.error) result.error = verdict.error;
  return result;
}

// ── Predicate evaluation ────────────────────────────────────────────────────

interface ProcessObservation {
  exitCode: number | null;
  stdout: string;
}
interface HttpObservation {
  status: number;
  body: string;
}
type Observation = Partial<ProcessObservation & HttpObservation>;

interface VerdictResult {
  kind: PocStepVerdict;
  error?: string;
}

function evaluateExpect(
  expect: PocStepExpect | undefined,
  obs: Observation,
): VerdictResult {
  if (!expect) {
    // No predicate → informational. Treat any non-thrown execution as pass.
    return { kind: "passed" };
  }
  switch (expect.type) {
    case "exit-zero": {
      if (obs.exitCode === 0) return { kind: "passed" };
      return {
        kind: "failed",
        error: `expected exit-zero, got exitCode=${String(obs.exitCode ?? "unknown")}`,
      };
    }
    case "http-status": {
      const wanted = Array.isArray(expect.status) ? expect.status : [expect.status];
      if (typeof obs.status === "number" && wanted.includes(obs.status)) {
        return { kind: "passed" };
      }
      return {
        kind: "failed",
        error: `expected http-status in [${wanted.join(",")}], got ${String(obs.status ?? "no-response")}`,
      };
    }
    case "body-contains": {
      const haystack = obs.body ?? obs.stdout ?? "";
      if (haystack.includes(expect.text)) return { kind: "passed" };
      return {
        kind: "failed",
        error: `expected body-contains '${expect.text}', not found in observed output`,
      };
    }
    case "body-matches": {
      const haystack = obs.body ?? obs.stdout ?? "";
      let re: RegExp;
      try {
        re = new RegExp(expect.pattern);
      } catch (err) {
        return { kind: "errored", error: `invalid regex: ${errMessage(err)}` };
      }
      if (re.test(haystack)) return { kind: "passed" };
      return {
        kind: "failed",
        error: `expected body-matches /${expect.pattern}/, no match in observed output`,
      };
    }
    case "file-exists": {
      // file-exists is a filesystem-level predicate that's only meaningful in
      // contexts where the runtime can read the target's filesystem (e.g. the
      // executor is running on the same host). For network targets we
      // declare it inconclusive rather than guessing — caller should map
      // file-exists to a `[ -e <path> ]` shell action when the target is
      // remote.
      return {
        kind: "errored",
        error:
          "file-exists predicate cannot be evaluated against a network target; rewrite as a shell action with `[ -e <path> ]`",
      };
    }
    default: {
      const _exhaustive: never = expect;
      return {
        kind: "errored",
        error: `unknown expect type: ${JSON.stringify(_exhaustive)}`,
      };
    }
  }
}

// ── Aggregate verdict ───────────────────────────────────────────────────────

function aggregateVerdict(
  graph: PocStep[],
  steps: PocStepResult[],
): PocOverallVerdict {
  if (graph.length === 0) {
    return "could_not_run";
  }
  const byId = new Map(steps.map((s) => [s.stepId, s]));

  // Did any setup / auth / prerequisite step error before we reached verify?
  // If so we couldn't actually run the exploit.
  let reachedExploitOrVerify = false;
  for (const step of graph) {
    const result = byId.get(step.id);
    if (!result) continue;
    if (step.kind === "exploit" || step.kind === "verify") {
      reachedExploitOrVerify = true;
    }
    if (
      result.kind === "errored" &&
      (step.kind === "setup" || step.kind === "auth" || step.kind === "prerequisite")
    ) {
      return "could_not_run";
    }
  }

  // Verify-kind steps are the load-bearing ones: if any of them cleanly
  // failed, the exploit is broken. If all verify-kind steps passed (or there
  // are none, but we got past prerequisites), the exploit still works.
  const verifySteps = graph.filter((s) => s.kind === "verify");
  if (verifySteps.length > 0) {
    let anyFailed = false;
    let anyErrored = false;
    let allPassed = true;
    for (const v of verifySteps) {
      const result = byId.get(v.id);
      if (!result || result.kind === "skipped") {
        allPassed = false;
        anyErrored = true;
        continue;
      }
      if (result.kind === "failed") {
        anyFailed = true;
        allPassed = false;
      } else if (result.kind === "errored") {
        anyErrored = true;
        allPassed = false;
      }
    }
    if (allPassed) return "exploit_still_works";
    if (anyFailed) return "exploit_broken";
    if (anyErrored) return "could_not_run";
  }

  // No `verify` steps in the graph — fall back on `exploit`. If every exploit
  // step passed, exploitation succeeded; clean failures → broken; errors that
  // weren't caught above → could_not_run.
  const exploitSteps = graph.filter((s) => s.kind === "exploit");
  if (exploitSteps.length > 0) {
    let anyFailed = false;
    let anyErrored = false;
    let allPassed = true;
    for (const e of exploitSteps) {
      const result = byId.get(e.id);
      if (!result || result.kind === "skipped") {
        allPassed = false;
        anyErrored = true;
        continue;
      }
      if (result.kind === "failed") {
        anyFailed = true;
        allPassed = false;
      } else if (result.kind === "errored") {
        anyErrored = true;
        allPassed = false;
      }
    }
    if (allPassed) return "exploit_still_works";
    if (anyFailed) return "exploit_broken";
    if (anyErrored) return "could_not_run";
  }

  // Graph has neither verify nor exploit kinds. We can't make a defensible
  // claim about the exploit's status.
  return reachedExploitOrVerify ? "exploit_still_works" : "could_not_run";
}

// ── Misc ────────────────────────────────────────────────────────────────────

function errMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}
