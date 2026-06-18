/**
 * protocol/http-sender.ts — the LIVE HTTP send seam for the Tier-1 conformance
 * flow (issue #972).
 *
 * `runHttpConformanceCheck` takes an injectable {@link HttpSender}; tests pass a
 * deterministic stub, and the CLI (`pwnkit protocol-check`) passes the live
 * adapter built here so the driver+oracle path runs against a real target.
 *
 * Why a thin direct sender and NOT `ToolExecutor.httpRequest`:
 *   - `ToolExecutor.httpRequest` is a PRIVATE method on a heavyweight class that
 *     requires a full scan context (scope, rate-limiter, attribution, WAF
 *     detector, findings DB) to construct — none of which exist in a one-shot
 *     conformance check.
 *   - More importantly, its method enum is restricted to
 *     GET/POST/PUT/DELETE/PATCH and it forces same-origin SCOPE validation.
 *     Conformance exercises deliberately send arbitrary/unusual verbs (TRACE,
 *     CONNECT, OPTIONS, even custom methods for `<Limit>`-style restriction
 *     bypass tests) at an operator-named target. The scan-shaped sender would
 *     reject exactly the requests this capability exists to send.
 *
 * So this adapter is a minimal `fetch`-based round-trip that returns the SAME
 * `{ success, output: { status, headers, body } }` shape the conformance flow's
 * `toObserved()` consumes — identical to `ToolExecutor.httpRequest`'s return
 * shape (`agent/tools.ts:1868`). It adds nothing to `ToolExecutor`.
 */
import type { HttpSender, HttpSendResult } from "./http-conformance.js";

export interface LiveHttpSenderOptions {
  /** Per-request timeout in ms. Default 15_000. */
  timeoutMs?: number;
  /**
   * Cap on the captured response body (the oracle only reads status + headers,
   * but the body is carried for the audit trail). Default 10_000, matching
   * `ToolExecutor.httpRequest`'s cap.
   */
  maxBodyBytes?: number;
}

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_BODY_BYTES = 10_000;

/**
 * Build a live {@link HttpSender} backed by `fetch`. Sends the exercise's exact
 * method (no enum restriction), captures status + headers + a capped body, and
 * NEVER throws — a transport failure becomes `{ success: false, error }`, which
 * the oracle reads as "no observation" (→ inconclusive, the conservative FP
 * default).
 *
 * Redirects are NOT followed (`redirect: "manual"`) so a conformance exercise
 * observes the implementation's OWN status (e.g. a 301/405) rather than the
 * status of wherever it points — mirroring `ToolExecutor.httpRequest`.
 */
export function createLiveHttpSender(
  opts: LiveHttpSenderOptions = {},
): HttpSender {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

  return async (req): Promise<HttpSendResult> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const init: RequestInit = {
        method: req.method,
        redirect: "manual",
        signal: controller.signal,
        ...(req.headers ? { headers: req.headers } : {}),
        ...(req.body !== undefined ? { body: req.body } : {}),
      };
      const res = await fetch(req.url, init);
      const headers: Record<string, string> = {};
      res.headers.forEach((value, key) => {
        headers[key] = value;
      });
      let body = "";
      try {
        body = (await res.text()).slice(0, maxBodyBytes);
      } catch {
        // A body read failure must not mask a perfectly good status line —
        // the oracle judges on status/headers, so keep going with an empty body.
        body = "";
      }
      return { success: true, output: { status: res.status, headers, body } };
    } catch (err) {
      return {
        success: false,
        error: err instanceof Error ? err.message : String(err),
      };
    } finally {
      clearTimeout(timer);
    }
  };
}
