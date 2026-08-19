/**
 * Learned Triage Router — loads the XGBoost model at runtime
 *
 * Pure TypeScript tree evaluator that reads the XGBoost JSON model format
 * directly. No native bindings, no ONNX, no Python. Sub-millisecond
 * inference on CPU.
 *
 * v2 model: 200 trees, 55 features (45 web + 10 kernel), trained on
 * triage-dataset-v2.jsonl (1514 rows). 5-fold CV F1=0.962, precision=0.960,
 * recall=0.963. Replaces the v1 model (100 trees, F1=0.944).
 *
 * Feature flag: 0SEC_FEATURE_LEARNED_ROUTER (default OFF).
 * See 0sec#113 for the design doc.
 */

import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding, TriageLayerName } from "@0sec/shared";
import { extractFeatures, FEATURE_NAMES } from "./feature-extractor.js";

// ────────────────────────────────────────────────────────────────────
// XGBoost JSON model evaluator (pure TypeScript, ~50 lines of logic)
// ────────────────────────────────────────────────────────────────────

interface XGBTree {
  split_indices: number[];
  split_conditions: number[];
  left_children: number[];
  right_children: number[];
  base_weights: number[];
  default_left: number[];
}

export interface XGBModel {
  trees: XGBTree[];
  baseScore: number;
}

/** Exported for unit testing (#519). */
export function parseModel(json: unknown): XGBModel {
  const d = json as Record<string, unknown>;
  const learner = d.learner as Record<string, unknown>;
  const params = learner.learner_model_param as Record<string, string>;
  const gb = learner.gradient_booster as Record<string, unknown>;
  const model = gb.model as Record<string, unknown>;
  const rawTrees = model.trees as Record<string, unknown>[];

  const trees: XGBTree[] = rawTrees.map((t) => ({
    split_indices: t.split_indices as number[],
    split_conditions: t.split_conditions as number[],
    left_children: t.left_children as number[],
    right_children: t.right_children as number[],
    base_weights: t.base_weights as number[],
    default_left: t.default_left as number[],
  }));

  const rawBase = (params.base_score ?? "0.5").replace(/[\[\]]/g, "");
  // Guard against `parseFloat(...) || 0.5` coercing a legitimate base_score
  // of 0 to the fallback (#519). `0 || 0.5` would wrongly yield 0.5, shifting
  // the sigmoid offset by 0.5 in logit space across the accept/reject bands.
  const parsed = parseFloat(rawBase);
  return {
    trees,
    baseScore: Number.isFinite(parsed) ? parsed : 0.5,
  };
}

function evaluateTree(tree: XGBTree, features: number[]): number {
  let nodeIdx = 0;
  while (tree.left_children[nodeIdx] !== -1) {
    const splitFeature = tree.split_indices[nodeIdx];
    const splitValue = tree.split_conditions[nodeIdx];
    const featureValue = features[splitFeature] ?? 0;

    if (featureValue < splitValue) {
      nodeIdx = tree.left_children[nodeIdx];
    } else {
      nodeIdx = tree.right_children[nodeIdx];
    }
  }
  return tree.base_weights[nodeIdx];
}

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

function predict(model: XGBModel, features: number[]): number {
  let sum = model.baseScore;
  for (const tree of model.trees) {
    sum += evaluateTree(tree, features);
  }
  return sigmoid(sum);
}

// ────────────────────────────────────────────────────────────────────
// Router API
// ────────────────────────────────────────────────────────────────────

export type RouterDecision = "auto_accept" | "auto_reject" | "run_layers";

export interface RouterResult {
  decision: RouterDecision;
  /** Model's TP probability (0-1). */
  tpProbability: number;
  reason: string;
  layersToRun: TriageLayerName[];
  layersToSkip: TriageLayerName[];
}

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

let cachedModel: XGBModel | null = null;

function getModel(): XGBModel | null {
  if (cachedModel) return cachedModel;

  const thisDir = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    // From packages/core/src/triage/ → packages/benchmark/results/
    join(thisDir, "../../../../benchmark/results/triage-router-v2.json"),
    // From packages/core/dist/triage/ → packages/benchmark/results/
    join(thisDir, "../../../../benchmark/results/triage-router-v2.json"),
    // From monorepo root
    join(process.cwd(), "packages/benchmark/results/triage-router-v2.json"),
    // From packages/core/
    join(process.cwd(), "../benchmark/results/triage-router-v2.json"),
    // Fallback
    join(process.cwd(), "triage-router-v2.json"),
  ];

  for (const path of candidates) {
    if (existsSync(path)) {
      try {
        const raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
        cachedModel = parseModel(raw);
        return cachedModel;
      } catch {
        // corrupt model file — fall through
      }
    }
  }

  return null;
}

/**
 * Route a finding through the trained XGBoost model.
 *
 * Returns auto_accept / auto_reject / run_layers based on the model's
 * TP probability. Thresholds derived from the training data:
 *   - accept_threshold: 0.85 (above → auto-accept, skip expensive layers)
 *   - reject_threshold: 0.25 (below → auto-reject)
 *   - middle band → run layers (free layers if prob > 0.5, all if < 0.5)
 *
 * Falls back to "run all layers" if the model file is not found.
 */
export function routeFinding(finding: Finding): RouterResult {
  const model = getModel();

  if (!model) {
    return {
      decision: "run_layers",
      tpProbability: 0.5,
      reason: "model file not found, running full pipeline",
      layersToRun: ALL_TRIAGE_LAYERS,
      layersToSkip: [],
    };
  }

  const features = extractFeatures(finding);
  const prob = predict(model, features);

  if (prob >= 0.85) {
    return {
      decision: "auto_accept",
      tpProbability: prob,
      reason: `model score ${prob.toFixed(3)} >= 0.85`,
      layersToRun: [],
      layersToSkip: ALL_TRIAGE_LAYERS,
    };
  }

  if (prob <= 0.25) {
    return {
      decision: "auto_reject",
      tpProbability: prob,
      reason: `model score ${prob.toFixed(3)} <= 0.25`,
      layersToRun: [],
      layersToSkip: ALL_TRIAGE_LAYERS,
    };
  }

  if (prob > 0.5) {
    return {
      decision: "run_layers",
      tpProbability: prob,
      reason: `model score ${prob.toFixed(3)} — moderate confidence, free layers only`,
      layersToRun: FREE_LAYERS,
      layersToSkip: EXPENSIVE_LAYERS,
    };
  }

  return {
    decision: "run_layers",
    tpProbability: prob,
    reason: `model score ${prob.toFixed(3)} — low confidence, full pipeline`,
    layersToRun: ALL_TRIAGE_LAYERS,
    layersToSkip: [],
  };
}
