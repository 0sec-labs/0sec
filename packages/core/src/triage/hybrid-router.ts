/**
 * Hybrid Triage Router — XGBoost prefiltering + LLM deep analysis
 *
 * Paper-novel contribution for pwnkit#113: combines sub-millisecond
 * XGBoost inference with targeted LLM review for uncertain cases.
 *
 * Flow:
 *   1. Extract 55 features, run XGBoost model
 *   2. p >= 0.85 → auto_accept  (skip all layers, $0)
 *   3. p <= 0.25 → auto_reject  (skip all layers, $0)
 *   4. 0.25 < p < 0.85 → LLM triage on the finding evidence
 *      - If LLM agrees with XGBoost lean → run only free layers
 *      - If LLM disagrees or is uncertain → run full pipeline
 *
 * Cost model: XGBoost = free, LLM review ~ $0.003 per finding,
 * full pipeline ~ $0.05 per finding (6 layers with tool use).
 */

import type { Finding, TriageLayerName } from "@pwnkit/shared";
import type {
  NativeRuntime,
  NativeContentBlock,
} from "../runtime/types.js";
import { routeFinding } from "./learned-router.js";

// ────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────

const ACCEPT_THRESHOLD = 0.85;
const REJECT_THRESHOLD = 0.25;

/** Cost estimates (USD) for LLM triage call. */
const LLM_TRIAGE_COST_USD = 0.003;
const LLM_TRIAGE_LATENCY_MS = 2_000;

const ALL_TRIAGE_LAYERS: TriageLayerName[] = [
  "holding_it_wrong",
  "evidence_gate",
  "reachability",
  "multi_modal",
  "oracle",
  "pov_gate",
];

const FREE_LAYERS: TriageLayerName[] = [
  "holding_it_wrong",
  "evidence_gate",
  "oracle",
];

const EXPENSIVE_LAYERS: TriageLayerName[] = [
  "reachability",
  "multi_modal",
  "pov_gate",
];

// ────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────

export type LlmVerdict = "TRUE_POSITIVE" | "FALSE_POSITIVE" | "UNCERTAIN";

export interface HybridRouterResult {
  decision: "auto_accept" | "auto_reject" | "llm_review";
  xgboostScore: number;
  llmVerdict?: LlmVerdict;
  llmConfidence?: number;
  llmReason?: string;
  layersToRun: TriageLayerName[];
  layersToSkip: TriageLayerName[];
  totalCostUsd: number;
  totalLatencyMs: number;
}

// ────────────────────────────────────────────────────────────────────
// LLM triage prompt
// ────────────────────────────────────────────────────────────────────

const TRIAGE_SYSTEM_PROMPT = `You are a security finding triage expert. Given a vulnerability finding with its evidence, determine whether it is a TRUE_POSITIVE (real vulnerability) or FALSE_POSITIVE (spurious/invalid).

Respond with EXACTLY this JSON format, no other text:
{
  "verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE" or "UNCERTAIN",
  "confidence": <number 0.0-1.0>,
  "reason": "<one sentence explanation>"
}`;

function buildTriageUserMessage(finding: Finding): string {
  const parts = [
    `Title: ${finding.title}`,
    `Category: ${finding.category}`,
    `Severity: ${finding.severity}`,
    `Confidence: ${finding.confidence ?? "unknown"}`,
    `Description: ${finding.description.slice(0, 500)}`,
  ];

  if (finding.evidence.request) {
    parts.push(`Request:\n${finding.evidence.request.slice(0, 1000)}`);
  }
  if (finding.evidence.response) {
    parts.push(`Response:\n${finding.evidence.response.slice(0, 1000)}`);
  }
  if (finding.evidence.analysis) {
    parts.push(`Analysis:\n${finding.evidence.analysis.slice(0, 500)}`);
  }

  return parts.join("\n\n");
}

// ────────────────────────────────────────────────────────────────────
// LLM response parser
// ────────────────────────────────────────────────────────────────────

interface ParsedLlmResponse {
  verdict: LlmVerdict;
  confidence: number;
  reason: string;
}

function extractTextFromBlocks(blocks: NativeContentBlock[]): string {
  for (const block of blocks) {
    if (block.type === "text") {
      return block.text;
    }
  }
  return "";
}

function parseLlmResponse(raw: string): ParsedLlmResponse {
  // Try to extract JSON from the response (may be wrapped in markdown)
  const jsonMatch = raw.match(/\{[\s\S]*?"verdict"[\s\S]*?\}/);
  if (jsonMatch) {
    try {
      const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>;
      const verdict = String(parsed.verdict ?? "UNCERTAIN");
      const validVerdicts: LlmVerdict[] = [
        "TRUE_POSITIVE",
        "FALSE_POSITIVE",
        "UNCERTAIN",
      ];
      return {
        verdict: validVerdicts.includes(verdict as LlmVerdict)
          ? (verdict as LlmVerdict)
          : "UNCERTAIN",
        confidence: typeof parsed.confidence === "number"
          ? Math.max(0, Math.min(1, parsed.confidence))
          : 0.5,
        reason: typeof parsed.reason === "string"
          ? parsed.reason
          : "no reason provided",
      };
    } catch {
      // JSON parse failed — fall through
    }
  }

  // Fallback: look for verdict keywords in raw text
  if (/TRUE.POSITIVE/i.test(raw)) {
    return { verdict: "TRUE_POSITIVE", confidence: 0.5, reason: "parsed from unstructured response" };
  }
  if (/FALSE.POSITIVE/i.test(raw)) {
    return { verdict: "FALSE_POSITIVE", confidence: 0.5, reason: "parsed from unstructured response" };
  }

  return { verdict: "UNCERTAIN", confidence: 0.3, reason: "could not parse LLM response" };
}

// ────────────────────────────────────────────────────────────────────
// Layer selection logic
// ────────────────────────────────────────────────────────────────────

/**
 * Decide which layers to run based on XGBoost score + LLM verdict.
 *
 * Agreement table:
 *   XGB leans TP (>0.5)  + LLM says TP  → free layers only (high agreement)
 *   XGB leans FP (<=0.5) + LLM says FP  → free layers only (high agreement)
 *   XGB + LLM disagree or LLM uncertain → full pipeline
 */
function selectLayers(
  xgbScore: number,
  llmVerdict: LlmVerdict,
  llmConfidence: number,
): { layersToRun: TriageLayerName[]; layersToSkip: TriageLayerName[] } {
  const xgbLeansTP = xgbScore > 0.5;
  const llmLeansTP = llmVerdict === "TRUE_POSITIVE";
  const llmLeansFP = llmVerdict === "FALSE_POSITIVE";

  // Strong agreement: both lean the same way with reasonable confidence
  const agreed =
    (xgbLeansTP && llmLeansTP && llmConfidence >= 0.6) ||
    (!xgbLeansTP && llmLeansFP && llmConfidence >= 0.6);

  if (agreed) {
    return {
      layersToRun: [...FREE_LAYERS],
      layersToSkip: [...EXPENSIVE_LAYERS],
    };
  }

  // Disagreement or uncertainty → run everything
  return {
    layersToRun: [...ALL_TRIAGE_LAYERS],
    layersToSkip: [],
  };
}

// ────────────────────────────────────────────────────────────────────
// Main entry point
// ────────────────────────────────────────────────────────────────────

/**
 * Route a finding through the hybrid XGBoost + LLM triage pipeline.
 *
 * 1. XGBoost prefilter: auto-accept (>=0.85) or auto-reject (<=0.25)
 * 2. Uncertain band (0.25-0.85): invoke LLM for deep analysis
 * 3. Combine signals to decide which expensive triage layers to run
 *
 * If no NativeRuntime is provided and the finding falls in the uncertain
 * band, all layers are scheduled (conservative fallback).
 */
export async function hybridRoute(
  finding: Finding,
  runtime?: NativeRuntime,
): Promise<HybridRouterResult> {
  const startMs = Date.now();

  // Step 1-2: XGBoost inference (sub-millisecond)
  const routerResult = routeFinding(finding);
  const prob = routerResult.tpProbability;

  // Step 3: Auto-accept high-confidence TPs
  if (prob >= ACCEPT_THRESHOLD) {
    return {
      decision: "auto_accept",
      xgboostScore: prob,
      layersToRun: [],
      layersToSkip: [...ALL_TRIAGE_LAYERS],
      totalCostUsd: 0,
      totalLatencyMs: Date.now() - startMs,
    };
  }

  // Step 4: Auto-reject high-confidence FPs
  if (prob <= REJECT_THRESHOLD) {
    return {
      decision: "auto_reject",
      xgboostScore: prob,
      layersToRun: [],
      layersToSkip: [...ALL_TRIAGE_LAYERS],
      totalCostUsd: 0,
      totalLatencyMs: Date.now() - startMs,
    };
  }

  // Step 5: Uncertain band → LLM review
  if (!runtime) {
    // No runtime available — conservative fallback: run all layers
    return {
      decision: "llm_review",
      xgboostScore: prob,
      llmVerdict: "UNCERTAIN",
      llmReason: "no runtime available for LLM triage",
      layersToRun: [...ALL_TRIAGE_LAYERS],
      layersToSkip: [],
      totalCostUsd: 0,
      totalLatencyMs: Date.now() - startMs,
    };
  }

  // 5a: Build triage prompt
  const userMessage = buildTriageUserMessage(finding);

  // 5b: Call LLM
  let llmVerdict: LlmVerdict = "UNCERTAIN";
  let llmConfidence = 0.5;
  let llmReason = "LLM call failed";
  let llmCost = 0;

  try {
    const llmResult = await runtime.executeNative(
      TRIAGE_SYSTEM_PROMPT,
      [
        {
          role: "user",
          content: [{ type: "text", text: userMessage }],
        },
      ],
      [], // no tools needed for triage classification
    );

    // 5c: Parse LLM response
    const rawText = extractTextFromBlocks(llmResult.content);
    const parsed = parseLlmResponse(rawText);
    llmVerdict = parsed.verdict;
    llmConfidence = parsed.confidence;
    llmReason = parsed.reason;
    llmCost = LLM_TRIAGE_COST_USD;
  } catch {
    // LLM call failed — fall back to full pipeline
    llmVerdict = "UNCERTAIN";
    llmConfidence = 0;
    llmReason = "LLM call threw an exception";
  }

  // 5d: Select layers based on XGBoost + LLM agreement
  const { layersToRun, layersToSkip } = selectLayers(
    prob,
    llmVerdict,
    llmConfidence,
  );

  return {
    decision: "llm_review",
    xgboostScore: prob,
    llmVerdict,
    llmConfidence,
    llmReason,
    layersToRun,
    layersToSkip,
    totalCostUsd: llmCost,
    totalLatencyMs: Date.now() - startMs,
  };
}
