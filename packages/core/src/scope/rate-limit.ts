/**
 * 0sec#214 — Per-host token-bucket rate limiter for scan-side fetches.
 *
 * Most coordinated-disclosure venues and pentest engagements specify a
 * max requests-per-second per host. The PoC-runtime side (`disclose`)
 * already has a per-host limiter (#206); this module is the generic
 * primitive for the scan-side, wired in at every fetch chokepoint in
 * `tools.ts`, `stages/web.ts`, and `agentic-scanner.ts`.
 *
 * Design notes:
 *   - Lazy refill, no timers: `tokens = min(capacity, tokens + elapsedMs * ratePerMs)`
 *     is computed on each call. A bucket sitting idle for an hour is not
 *     consuming a setInterval slot; it just refills to `capacity` the
 *     first time anyone touches it.
 *   - Per-host isolation. Throttling host A never affects host B.
 *   - 429 honoring. `noteResponse(url, res)` parks the host's bucket
 *     past `Retry-After` (delta-seconds OR HTTP-date form). Conservative
 *     60s floor matches the PoC-runtime semantics: even a 1-second
 *     `Retry-After` triggers a meaningful cool-off so we don't
 *     tarpit-loop the target.
 *   - Burst == capacity. The bucket starts full, so the first N requests
 *     to a previously-untouched host go through immediately and
 *     subsequent requests pace at `rate` rps.
 *
 * Bash-subprocess gap (acknowledged, NOT closed by this module):
 *   The `bash` tool in `tools.ts` shells out to curl/wget/python3, which
 *   bypass node's fetch and therefore bypass this limiter. Mitigating
 *   that requires an egress proxy on the runner — same disclaimer the
 *   scope work made in #218 about bash-extracted URLs. Tracked
 *   separately; see CLAUDE.md / DoD on #214.
 */

import { jitterFor } from "./waf-detect.js";

// ── Types ────────────────────────────────────────────────────────────────

/**
 * Full-jitter pacing on top of the token bucket (engagement hardening).
 *
 * A fixed-interval bucket produces a perfectly periodic request train, which
 * is arguably a STRONGER automation signal to a behavioural SOC than bursty
 * traffic. When configured, every satisfied acquire additionally sleeps a
 * uniform random `[0, baseMs]` (via the shared `jitterFor` helper), so the
 * inter-request interval stops being a constant.
 *
 * Undefined (the default) = fixed-interval, unchanged behaviour.
 */
export interface JitterConfig {
  /** Upper bound of the uniform random delay, in milliseconds. */
  baseMs: number;
  /** Injectable randomness for tests. Defaults to `Math.random`. */
  rng?: () => number;
}

/** Per-host bucket configuration. */
export interface HostRateConfig {
  /** Refill rate, requests per second. Must be > 0. */
  rps: number;
  /**
   * Bucket capacity (also burst cap). Defaults to `rps` so the bucket
   * starts full at one second of traffic. Most callers want this.
   */
  burst?: number;
}

/** Rate-limiter configuration. */
export interface RateLimiterConfig {
  /** Default applied to any host without an explicit override. */
  default: HostRateConfig;
  /** Per-host overrides keyed by lowercased hostname. */
  perHost?: Record<string, HostRateConfig>;
  /**
   * Optional full-jitter pacing applied to EVERY host bucket. Omitted by
   * default, which keeps the historical fixed-interval behaviour.
   */
  jitter?: JitterConfig;
}

// ── Internal bucket state ────────────────────────────────────────────────

interface Bucket {
  /** Tokens currently available (1 token = 1 request). May be fractional. */
  tokens: number;
  /** Tokens added per millisecond. */
  refillRatePerMs: number;
  /** Maximum tokens; also burst. */
  capacity: number;
  /** Last refill timestamp (Date.now). */
  lastRefill: number;
  /** When > now(), all acquires block. Set on 429. */
  retryUntil: number;
}

// ── TokenBucket — single host (exported for tests / advanced use) ────────

/**
 * Single-host token bucket. Lazy refill, no background timer.
 *
 * Semantics:
 *   - `tryConsume(n)` returns true if there were ≥ n tokens after refill,
 *     and consumes them. Returns false otherwise (no block, no consume).
 *   - `acquire(n)` resolves once n tokens have been consumed. Blocks via
 *     `setTimeout`-based sleep when the bucket is dry.
 *   - `markRetryUntil(deadline)` parks the bucket until `deadline` ms.
 *     `acquire` honours this; `tryConsume` returns false during park.
 *
 * Time source is injectable for tests (default: `Date.now`).
 */
export class TokenBucket {
  private state: Bucket;
  private readonly nowFn: () => number;
  private readonly sleepFn: (ms: number) => Promise<void>;
  private readonly jitter?: JitterConfig;

  constructor(
    rps: number,
    capacity: number = rps,
    nowFn: () => number = () => Date.now(),
    sleepFn: (ms: number) => Promise<void> = defaultSleep,
    jitter?: JitterConfig,
  ) {
    if (!Number.isFinite(rps) || rps <= 0) {
      throw new Error(`TokenBucket: rps must be a positive finite number, got ${rps}`);
    }
    if (!Number.isFinite(capacity) || capacity <= 0) {
      throw new Error(`TokenBucket: capacity must be a positive finite number, got ${capacity}`);
    }
    this.nowFn = nowFn;
    this.sleepFn = sleepFn;
    this.jitter = jitter && jitter.baseMs > 0 ? jitter : undefined;
    this.state = {
      tokens: capacity,
      refillRatePerMs: rps / 1000,
      capacity,
      lastRefill: nowFn(),
      retryUntil: 0,
    };
  }

  private refill(): void {
    const now = this.nowFn();
    const elapsed = now - this.state.lastRefill;
    if (elapsed > 0) {
      this.state.tokens = Math.min(
        this.state.capacity,
        this.state.tokens + elapsed * this.state.refillRatePerMs,
      );
      this.state.lastRefill = now;
    }
  }

  /**
   * Non-blocking. Returns true and consumes `n` tokens if available;
   * returns false and consumes nothing otherwise. Blocked during 429
   * cool-off (returns false until park expires).
   */
  tryConsume(n = 1): boolean {
    if (this.nowFn() < this.state.retryUntil) return false;
    this.refill();
    if (this.state.tokens >= n) {
      this.state.tokens -= n;
      return true;
    }
    return false;
  }

  /**
   * Block until `n` tokens are available, then consume them. Honours
   * the 429 park deadline first, then refill-and-spin with sleeps
   * sized to the exact next-token-available time.
   */
  async acquire(n = 1): Promise<void> {
    if (n > this.state.capacity) {
      // Asking for more than the bucket can ever hold: clamp to capacity.
      // Otherwise the loop below would never terminate.
      n = this.state.capacity;
    }
    // 429 cool-off first.
    while (this.nowFn() < this.state.retryUntil) {
      const wait = this.state.retryUntil - this.nowFn();
      // eslint-disable-next-line no-await-in-loop
      await this.sleepFn(Math.max(1, Math.min(wait, 1000)));
    }
    // Refill + consume; sleep precisely to the next token-availability time.
    // eslint-disable-next-line no-constant-condition
    while (true) {
      this.refill();
      if (this.state.tokens >= n) {
        this.state.tokens -= n;
        await this.pace();
        return;
      }
      const tokensNeeded = n - this.state.tokens;
      const waitMs = Math.max(1, Math.ceil(tokensNeeded / this.state.refillRatePerMs));
      // eslint-disable-next-line no-await-in-loop
      await this.sleepFn(waitMs);
    }
  }

  /**
   * Sleep the configured full-jitter delay. No-op (and no `await`-visible
   * sleep) when no jitter is configured, so the default path is unchanged.
   *
   * Reuses `jitterFor` from `waf-detect.ts` — attempt 0 with an injected rng
   * yields full jitter in `[0, baseMs]` — rather than growing a second
   * jitter implementation.
   */
  async pace(): Promise<void> {
    if (!this.jitter) return;
    const ms = jitterFor(0, this.jitter.baseMs, this.jitter.rng ?? Math.random);
    if (ms > 0) await this.sleepFn(ms);
  }

  /**
   * Park the bucket until `deadline` (ms since epoch). Subsequent
   * `acquire`/`tryConsume` calls block until the deadline passes.
   * Idempotent in the "later wins" sense: a longer park overrides a
   * shorter one, but a shorter park does NOT shorten an existing one.
   */
  markRetryUntil(deadline: number): void {
    if (deadline > this.state.retryUntil) {
      this.state.retryUntil = deadline;
    }
  }

  /** Test introspection. */
  _peek(): { tokens: number; retryUntil: number; capacity: number } {
    this.refill();
    return {
      tokens: this.state.tokens,
      retryUntil: this.state.retryUntil,
      capacity: this.state.capacity,
    };
  }
}

// ── RateLimiter — per-host fan-out ───────────────────────────────────────

/**
 * Per-host token-bucket rate limiter. Buckets are created lazily on
 * first acquire for a given host. Hostname is lowercased and the port
 * is stripped before lookup, so `api.example.com:443` and
 * `API.example.com` share a bucket.
 */
export class RateLimiter {
  private readonly buckets = new Map<string, TokenBucket>();
  private readonly defaultCfg: HostRateConfig;
  private readonly perHost: Record<string, HostRateConfig>;
  private readonly jitter?: JitterConfig;
  private readonly nowFn: () => number;
  private readonly sleepFn: (ms: number) => Promise<void>;
  /**
   * Conservative cool-off floor when a 429 lands without a useful
   * `Retry-After`, or with a tiny one. 60s matches the PoC-runtime
   * precedent in #206 — a target that just told us to slow down has
   * earned more than a one-second pause.
   */
  static readonly RETRY_AFTER_FLOOR_MS = 60_000;

  /**
   * Optional observer invoked once whenever a fetch is actually throttled:
   * either an `acquire` that had to block because the bucket was dry, or a
   * 429 response parking the host. Used by the http_audit enforcement
   * tracker to populate `rate_limited_count`. No-op when unset, so the
   * normal scan path is unaffected.
   */
  private readonly onThrottle?: () => void;

  constructor(
    config: RateLimiterConfig,
    opts: {
      nowFn?: () => number;
      sleepFn?: (ms: number) => Promise<void>;
      onThrottle?: () => void;
    } = {},
  ) {
    this.defaultCfg = config.default;
    this.jitter = config.jitter;
    this.perHost = {};
    if (config.perHost) {
      for (const [host, cfg] of Object.entries(config.perHost)) {
        this.perHost[host.toLowerCase()] = cfg;
      }
    }
    this.nowFn = opts.nowFn ?? (() => Date.now());
    this.sleepFn = opts.sleepFn ?? defaultSleep;
    this.onThrottle = opts.onThrottle;
  }

  /**
   * Normalize a URL or host string to a bucket key. Lowercased,
   * port-stripped, IPv6 brackets retained on the literal but dropped
   * from the port suffix (e.g. `[::1]:443` → `[::1]`).
   */
  private hostKey(urlOrHost: string): string | null {
    // Accept a bare host string for callers (e.g. tests) that don't
    // have a full URL. URL parser is the easy path otherwise.
    let host: string;
    try {
      host = new URL(urlOrHost).hostname;
    } catch {
      // Bare host fallback. Strip port if present; treat IPv6 literal
      // (with brackets) as opaque.
      const trimmed = urlOrHost.trim();
      if (!trimmed) return null;
      if (trimmed.startsWith("[")) {
        const close = trimmed.indexOf("]");
        if (close < 0) return null;
        host = trimmed.slice(0, close + 1);
      } else {
        host = trimmed.split(":")[0];
      }
    }
    return host.toLowerCase();
  }

  private getBucket(host: string): TokenBucket {
    let bucket = this.buckets.get(host);
    if (!bucket) {
      const cfg = this.perHost[host] ?? this.defaultCfg;
      bucket = new TokenBucket(
        cfg.rps,
        cfg.burst ?? cfg.rps,
        this.nowFn,
        this.sleepFn,
        this.jitter,
      );
      this.buckets.set(host, bucket);
    }
    return bucket;
  }

  /**
   * Block until a token is available for `urlOrHost`'s host, then
   * consume it. Unparseable input is treated as a no-op (returns
   * immediately) — callers should not rely on rate-limiting unknowable
   * hosts. The fetch sites that wire this up always pass full URLs.
   */
  async acquire(urlOrHost: string, n = 1): Promise<void> {
    const host = this.hostKey(urlOrHost);
    if (!host) return;
    const bucket = this.getBucket(host);
    // Detect whether this acquire will block: if the non-blocking path can
    // satisfy it immediately, no throttle occurred. Otherwise we had to
    // wait, which is the signal the http_audit summary counts. tryConsume
    // consumes the token on the fast path, so we only fall through to the
    // blocking acquire (and fire the observer) when the bucket was dry.
    // The fast path still pays the jitter delay when configured — otherwise a
    // scan that never saturates its bucket (the common case at 1 rps with a
    // slow agent loop) would stay perfectly periodic, which is exactly the
    // signal jitter exists to break. `pace()` is a no-op without jitter, so
    // the default fast path is unchanged.
    if (bucket.tryConsume(n)) {
      await bucket.pace();
      return;
    }
    this.onThrottle?.();
    await bucket.acquire(n);
  }

  /**
   * Non-blocking variant. Returns true and consumes if available,
   * false otherwise. Used by callers that want to fall through to a
   * fast-path / degrade rather than wait.
   */
  tryAcquire(urlOrHost: string, n = 1): boolean {
    const host = this.hostKey(urlOrHost);
    if (!host) return true;
    return this.getBucket(host).tryConsume(n);
  }

  /**
   * Inspect a fetch response and, if it's a 429, park the host's
   * bucket until `Retry-After` (or 60s, whichever is longer). The
   * parsed value supports both delta-seconds (RFC 7231 §7.1.3) and
   * HTTP-date forms; anything else falls back to the floor.
   *
   * No-ops on non-429 responses, or on hosts with no bucket yet
   * (which can't happen if the caller acquired before fetching, but
   * we don't depend on that).
   */
  noteResponse(urlOrHost: string, res: { status: number; headers: { get(name: string): string | null } | Headers }): void {
    if (res.status !== 429) return;
    const host = this.hostKey(urlOrHost);
    if (!host) return;
    this.onThrottle?.();
    const bucket = this.getBucket(host); // create-on-demand is fine
    const retryAfter = readHeader(res.headers, "retry-after");
    const delayMs = parseRetryAfter(retryAfter, this.nowFn());
    const deadline = this.nowFn() + Math.max(delayMs, RateLimiter.RETRY_AFTER_FLOOR_MS);
    bucket.markRetryUntil(deadline);
  }

  /** Test-only. Reset all buckets. */
  _reset(): void {
    this.buckets.clear();
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────

function defaultSleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function readHeader(
  headers: { get(name: string): string | null } | Headers,
  name: string,
): string | null {
  if (typeof (headers as { get?: unknown }).get === "function") {
    return (headers as { get(n: string): string | null }).get(name);
  }
  return null;
}

/**
 * Parse a `Retry-After` header into a delay in milliseconds. Accepts
 * - delta-seconds: `"5"` → 5000
 * - HTTP-date: `"Wed, 21 Oct 2015 07:28:00 GMT"` → ms until that
 *   moment (clamped at 0 if already past)
 *
 * Returns 0 for unparseable / missing values; the caller applies the
 * conservative 60s floor.
 */
export function parseRetryAfter(value: string | null, now: number): number {
  if (!value) return 0;
  const trimmed = value.trim();
  if (!trimmed) return 0;
  // delta-seconds
  if (/^\d+$/.test(trimmed)) {
    const seconds = parseInt(trimmed, 10);
    return Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : 0;
  }
  // HTTP-date
  const date = Date.parse(trimmed);
  if (Number.isFinite(date)) {
    return Math.max(0, date - now);
  }
  return 0;
}

// ── CLI flag parsing ─────────────────────────────────────────────────────

/**
 * Parse a `--rate-limit` flag value into a `RateLimiterConfig`.
 *
 * Grammar:
 *   - Plain rps, applied as the default: `"5"` or `"5:10"` (rps:burst)
 *   - Comma-separated mixture:
 *       `"api.example.com=5,*.example.com=3:6,2"`
 *     where the unprefixed `2` is the default rps. A trailing
 *     `host=rps` without an explicit default falls back to 5 rps,
 *     matching the issue's "default conservative" guidance.
 *
 * NOTE: wildcard hosts (`*.example.com`) are accepted in the spec
 * grammar but currently match by exact-host lookup only. Wildcard
 * matching will land alongside the broader scope-ingestion work in
 * #215 / PR #218, which already has a `*.example.com`-style matcher
 * we'll borrow once that PR merges. Recording the wildcard now keeps
 * the CLI grammar forward-compatible.
 *
 * Throws on malformed input rather than silently dropping rules — a
 * mistyped `--rate-limit` is the kind of bug operators want to find
 * at start-of-scan, not silently five hours in.
 */
export function parseRateLimitFlag(spec: string, fallbackRps = 5): RateLimiterConfig {
  const trimmed = spec.trim();
  if (!trimmed) {
    return { default: { rps: fallbackRps } };
  }
  const parts = trimmed.split(",").map((p) => p.trim()).filter(Boolean);
  let defaultCfg: HostRateConfig | null = null;
  const perHost: Record<string, HostRateConfig> = {};
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq < 0) {
      // No host → default rps[:burst]
      const cfg = parseRpsBurst(part);
      defaultCfg = cfg;
    } else {
      const host = part.slice(0, eq).trim().toLowerCase();
      const cfg = parseRpsBurst(part.slice(eq + 1));
      if (!host) {
        throw new Error(`--rate-limit: empty host in "${part}"`);
      }
      perHost[host] = cfg;
    }
  }
  return {
    default: defaultCfg ?? { rps: fallbackRps },
    perHost: Object.keys(perHost).length > 0 ? perHost : undefined,
  };
}

function parseRpsBurst(s: string): HostRateConfig {
  const trimmed = s.trim();
  if (!trimmed) {
    throw new Error(`--rate-limit: empty rps value`);
  }
  const colon = trimmed.indexOf(":");
  if (colon < 0) {
    const rps = Number(trimmed);
    if (!Number.isFinite(rps) || rps <= 0) {
      throw new Error(`--rate-limit: invalid rps "${trimmed}"`);
    }
    return { rps };
  }
  const rps = Number(trimmed.slice(0, colon));
  const burst = Number(trimmed.slice(colon + 1));
  if (!Number.isFinite(rps) || rps <= 0) {
    throw new Error(`--rate-limit: invalid rps "${trimmed.slice(0, colon)}"`);
  }
  if (!Number.isFinite(burst) || burst <= 0) {
    throw new Error(`--rate-limit: invalid burst "${trimmed.slice(colon + 1)}"`);
  }
  return { rps, burst };
}
