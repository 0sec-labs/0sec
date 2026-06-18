/**
 * protocol/http-conformance.ts — the minimal Tier-1 conformance flow that wires
 * the three building blocks of issue #972's foundational slice into one pass:
 *
 *   conformance-gen (LLM infer→validate→repair)  →  ranked DivergenceHypotheses
 *        → for each, craft + SEND the exercise via the existing http_request
 *          tool (the only protocol driver that exists today, `recon.ts`)
 *        → oracle-http (deterministic) verdicts
 *        → return CONFIRMED divergences as hypothesis Findings, using the same
 *          confidence/promotion contract as `review.ts` / `kernel-verify.ts`.
 *
 * Reuse, don't reinvent:
 *   - The Finding emitted on confirm mirrors `incompleteFixLeadToFinding`
 *     (`kernel/incomplete-fix-hunt.ts:206`) and the kernel promotion contract
 *     (`verify/kernel-verify.ts:1108` `applyVerificationToFinding`): a CONFIRMED
 *     divergence is `status: "confirmed", confidence: 1.0`; an unconfirmed
 *     hypothesis stays low-confidence and is NOT emitted as a finding here.
 *   - The HTTP send is injectable (an {@link HttpSender}) exactly like
 *     kernel-verify takes an injectable `runner`/`agentInvoker`: the real
 *     `http_request` tool handler lives on the heavyweight `ToolExecutor`
 *     (scope/rate-limit/attribution context), so callers pass a thin adapter
 *     over it and tests pass a deterministic mock — no live network in tests.
 *
 * This is a FUNCTION, not a new global tool — it does NOT touch
 * `agent/tools.ts` or `agentic-scanner.ts`.
 */
import { randomUUID } from "node:crypto";
import type { Finding } from "@pwnkit/shared";
import type { NativeRuntime } from "../runtime/types.js";
import {
  generateConformanceModel,
  type ConformanceGenOptions,
} from "./conformance-gen.js";
import { judgeHttpDivergence } from "./oracle-http.js";
import type {
  DivergenceHypothesis,
  DivergenceVerdict,
  HttpExercise,
  ObservedHttpResponse,
  ProtocolModel,
} from "./model.js";

/**
 * The HTTP send seam. Mirrors the `http_request` tool's output shape
 * (`{ success, output: { status, headers, body } }`, see `agent/tools.ts`),
 * so a caller can adapt the real tool handler with a one-line wrapper. Tests
 * pass a deterministic stub.
 */
export type HttpSender = (req: {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
}) => Promise<HttpSendResult>;

export interface HttpSendResult {
  success: boolean;
  output?: {
    status?: number;
    headers?: Record<string, string>;
    body?: string;
  };
  error?: string;
}

/** Per-hypothesis trace record (kept for audit / debugging, like KernelVerifyAttempt). */
export interface ConformanceAttempt {
  hypothesis: DivergenceHypothesis;
  observed: ObservedHttpResponse;
  verdict: DivergenceVerdict;
}

export interface HttpConformanceResult {
  /** True iff the conformance-gen step produced a validated model. */
  ok: boolean;
  /** CONFIRMED divergences, emitted as hypothesis-promoted Findings. */
  findings: Finding[];
  /** Every hypothesis we exercised + its observation + verdict. */
  attempts: ConformanceAttempt[];
  /** Number of LLM calls conformance-gen made. */
  genIterations: number;
  /** Populated when `ok` is false: why generation failed. */
  reason?: string;
}

export interface HttpConformanceOptions {
  /** Forwarded to conformance-gen (maxIterations, validator, focusHint). */
  gen?: ConformanceGenOptions;
  /**
   * Cap on how many hypotheses to exercise (cost guard, like kernel-verify's
   * attempt cap). Default 8; hypotheses are exercised in the order produced.
   */
  maxExercises?: number;
}

const DEFAULT_MAX_EXERCISES = 8;

/** Build the absolute URL for an exercise against `targetUrl`. */
function exerciseUrl(targetUrl: string, exercise: HttpExercise): string {
  const path = exercise.path ?? "/";
  // Join without double-slashing; respects an absolute path on the exercise.
  const base = targetUrl.replace(/\/+$/, "");
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return `${base}${suffix}`;
}

/** Adapt the http_request tool's output into the oracle's ObservedHttpResponse. */
function toObserved(result: HttpSendResult): ObservedHttpResponse {
  if (!result.success || !result.output || typeof result.output.status !== "number") {
    return { status: 0, error: result.error ?? "http_request did not return a status" };
  }
  const headers: Record<string, string> = {};
  if (result.output.headers) {
    for (const [k, v] of Object.entries(result.output.headers)) headers[k] = v;
  }
  return { status: result.output.status, headers };
}

/**
 * Emit a CONFIRMED divergence as a hypothesis-promoted Finding. Mirrors
 * `incompleteFixLeadToFinding`'s shape and the kernel promotion contract: a
 * confirmed result is `status: "confirmed", confidence: 1.0`, with the oracle's
 * concrete evidence on `evidence.analysis`.
 */
function confirmedDivergenceToFinding(
  protocolModel: ProtocolModel,
  attempt: ConformanceAttempt,
): Finding {
  const { hypothesis, observed, verdict } = attempt;
  return {
    id: randomUUID(),
    templateId: `protocol-conformance-${protocolModel.name}-${hypothesis.ruleId}`,
    title: `${protocolModel.name} conformance divergence: ${hypothesis.ruleId} (${hypothesis.specCitation})`,
    description: [
      `Implementation diverges from ${protocolModel.name} (${protocolModel.specRef}).`,
      `Rule ${hypothesis.specCitation} (${hypothesis.level}): ${hypothesis.rationale}`,
      `Predicted at ${hypothesis.implLocation}.`,
      `Confirmed by sending ${hypothesis.exercise.method} ${hypothesis.exercise.path ?? "/"}`,
      `and observing status ${observed.status}.`,
    ].join(" "),
    severity: "medium",
    category: "missing-validation",
    status: "confirmed",
    evidence: {
      request: `${hypothesis.exercise.method} ${hypothesis.exercise.path ?? "/"}`,
      response: `status=${observed.status}`,
      analysis: [
        "Source: protocol-conformance (Tier-1 HTTP)",
        `Protocol: ${protocolModel.name} ${protocolModel.version} (${protocolModel.specRef})`,
        `Rule: ${hypothesis.specCitation} [${hypothesis.level}]`,
        "Hypothesis: false",
        `Oracle: confirmed`,
        `Evidence: ${verdict.evidence}`,
      ].join("\n"),
    },
    fingerprint: `protoconf:${protocolModel.name}:${hypothesis.ruleId}`,
    triageStatus: "new",
    // Same promotion contract as kernel-verify: confirmed ⇒ confidence 1.0.
    confidence: verdict.confidence,
    timestamp: Date.now(),
  };
}

/**
 * Run the Tier-1 HTTP conformance check end-to-end.
 *
 *   1. conformance-gen infers + validates a ConformanceModel from the spec +
 *      impl excerpts (LLM via the unified `NativeRuntime`; repair loop on bad
 *      JSON).
 *   2. For each ranked hypothesis (up to `maxExercises`), craft the exercise
 *      request and send it via the injected `http_request` adapter.
 *   3. The deterministic oracle judges each observation.
 *   4. CONFIRMED divergences become hypothesis-promoted Findings.
 *
 * Hypotheses that the oracle rules `refuted` or `inconclusive` are recorded in
 * `attempts` but NOT emitted as findings — the conservative FP discipline.
 */
export async function runHttpConformanceCheck(
  specExcerpt: string,
  implExcerpt: string,
  targetUrl: string,
  llm: NativeRuntime,
  send: HttpSender,
  protocol: { name: string; version: string; specRef: string },
  opts: HttpConformanceOptions = {},
): Promise<HttpConformanceResult> {
  const protocolModel: ProtocolModel = {
    name: protocol.name,
    version: protocol.version,
    specRef: protocol.specRef,
    specExcerpt,
  };

  const gen = await generateConformanceModel(
    protocolModel,
    implExcerpt,
    llm,
    opts.gen,
  );

  if (!gen.ok || !gen.model) {
    return {
      ok: false,
      findings: [],
      attempts: [],
      genIterations: gen.iterations,
      reason: `conformance-gen failed after ${gen.iterations} iteration(s): ${gen.errors
        .map((e) => (e.path ? `${e.path}: ${e.message}` : e.message))
        .join("; ")}`,
    };
  }

  const cap = Math.max(0, opts.maxExercises ?? DEFAULT_MAX_EXERCISES);
  const hypotheses = gen.model.hypotheses.slice(0, cap);

  const attempts: ConformanceAttempt[] = [];
  const findings: Finding[] = [];

  for (const hypothesis of hypotheses) {
    const url = exerciseUrl(targetUrl, hypothesis.exercise);
    let observed: ObservedHttpResponse;
    try {
      const sendArgs: Parameters<HttpSender>[0] = {
        url,
        method: hypothesis.exercise.method,
        ...(hypothesis.exercise.headers ? { headers: hypothesis.exercise.headers } : {}),
        ...(hypothesis.exercise.body !== undefined ? { body: hypothesis.exercise.body } : {}),
      };
      const result = await send(sendArgs);
      observed = toObserved(result);
    } catch (err) {
      observed = {
        status: 0,
        error: err instanceof Error ? err.message : String(err),
      };
    }

    const verdict = judgeHttpDivergence(hypothesis, observed);
    const attempt: ConformanceAttempt = { hypothesis, observed, verdict };
    attempts.push(attempt);

    if (verdict.status === "confirmed") {
      findings.push(confirmedDivergenceToFinding(protocolModel, attempt));
    }
  }

  return {
    ok: true,
    findings,
    attempts,
    genIterations: gen.iterations,
  };
}
