// Rate-limit / anti-automation probe for sensitive endpoints (0sec gap H).
//
// Goal: tell whether a sensitive endpoint (login, password-reset, OTP, etc.)
// enforces throttling. The motivating pilot: 20 rapid POSTs to a
// password-reset endpoint all returned 404 with no 429 and no slowdown —
// a clear "no rate limiting" finding.
//
// SAFETY IS THE DESIGN. This module is deliberately:
//   * BOUNDED  — a small fixed burst (default 15) with a HARD CAP of 25
//                requests. There is no unbounded / DoS path. The cap is
//                clamped here regardless of what the caller asks for.
//   * PURE     — it never opens a socket itself. The caller supplies a
//                `request` thunk, so the responsibility for using a SAFE,
//                side-effect-free input (e.g. a clearly non-existent email
//                so no real password-reset mail is ever sent) lives at the
//                call site, and this module stays trivially testable.
//   * NON-DESTRUCTIVE — it only reads HTTP status codes. It does not retry,
//                amplify, or escalate; the burst size never grows.
//
// NO LLM. No network. No shared-file edits.

/** Default burst size — small enough to be obviously non-abusive. */
export const DEFAULT_BURST = 15;

/**
 * Hard upper bound on the number of requests this probe will ever issue,
 * no matter what `burst` the caller passes. This is a safety rail, not a
 * tuning knob — do not raise it without an operator review.
 */
export const MAX_BURST = 25;

export interface RateLimitResult {
  /** How many requests were actually issued (always <= MAX_BURST). */
  sent: number;
  /** HTTP status of each request, in send order. */
  statuses: number[];
  /** True if any response was HTTP 429 Too Many Requests. */
  saw429: boolean;
  /**
   * True if the endpoint appears to throttle: it returned a 429, OR the
   * status changed clearly mid-burst (e.g. 200…200 then 403/503), which is
   * the signature of a throttle kicking in. False means "no rate limiting
   * observed" — the finding worth flagging.
   */
  throttled: boolean;
  /** Human-readable one-line summary of what was observed. */
  note: string;
}

export interface ProbeRateLimitOptions {
  /**
   * The request thunk. Called once per attempt with the 0-based index `i`,
   * and must resolve to the response status. The CALLER owns using a SAFE,
   * side-effect-free input here (e.g. a non-existent account) and performing
   * the actual HTTP — this module only inspects the resulting status.
   */
  request: (i: number) => Promise<{ status: number }>;
  /**
   * Requested burst size. Clamped to `[1, MAX_BURST]`; defaults to
   * `DEFAULT_BURST`. Values above the cap are silently lowered to the cap —
   * the probe never issues more than `MAX_BURST` requests.
   */
  burst?: number;
}

/**
 * Clamp a requested burst into the safe range `[1, MAX_BURST]`. A missing /
 * non-finite request falls back to `DEFAULT_BURST`. This is the single choke
 * point that guarantees the probe stays bounded.
 */
export function clampBurst(burst?: number): number {
  const requested = Number.isFinite(burst) ? Math.floor(burst as number) : DEFAULT_BURST;
  return Math.max(1, Math.min(requested, MAX_BURST));
}

/**
 * Detect a clear mid-burst status change: the response status flips from one
 * stable value to a different stable value and stays there. This catches a
 * throttle that switches from (say) repeated 404/200 to 403/503 partway
 * through, without firing on incidental jitter at a single position.
 */
function sawStatusChange(statuses: number[]): boolean {
  if (statuses.length < 2) return false;
  const first = statuses[0];
  // Find the first index whose status differs from the opening status…
  const changeAt = statuses.findIndex((s) => s !== first);
  if (changeAt <= 0) return false;
  // …and require that the new status persists to the end of the burst, so a
  // single flaky response doesn't read as throttling.
  const after = statuses[changeAt];
  return statuses.slice(changeAt).every((s) => s === after);
}

/**
 * Fire a small, bounded burst of requests at a sensitive endpoint and report
 * whether it enforces throttling.
 *
 * The burst runs sequentially (no parallel amplification) so the request rate
 * stays modest and the status sequence is meaningful for change-detection.
 *
 * SAFETY: bounded to at most `MAX_BURST` (25) requests; the caller is
 * responsible for supplying a side-effect-free input to `request`.
 */
export async function probeRateLimit(opts: ProbeRateLimitOptions): Promise<RateLimitResult> {
  const burst = clampBurst(opts.burst);
  const statuses: number[] = [];

  for (let i = 0; i < burst; i++) {
    const { status } = await opts.request(i);
    statuses.push(status);
  }

  const saw429 = statuses.includes(429);
  const changed = sawStatusChange(statuses);
  const throttled = saw429 || changed;

  let note: string;
  if (saw429) {
    note = `throttled: saw HTTP 429 within ${statuses.length} requests`;
  } else if (changed) {
    note = `throttled: status changed mid-burst (${statuses[0]} -> ${statuses[statuses.length - 1]})`;
  } else {
    note = `no rate limiting observed: ${statuses.length} requests, no 429, no status change (all ${statuses[0] ?? "n/a"})`;
  }

  return { sent: statuses.length, statuses, saw429, throttled, note };
}
