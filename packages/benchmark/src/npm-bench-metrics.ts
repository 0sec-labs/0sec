import { wilsonIntervalTuple } from "./wilson.js";

export type NpmBenchVerdict = "malicious" | "vulnerable" | "safe";

export interface NpmBenchMetricResult {
  verdict: NpmBenchVerdict;
  hasFindings: boolean;
  infrastructureError: boolean;
}

export interface NpmBenchMetrics {
  accuracy: number | null;
  accuracyCI95: [number, number] | null;
  detectionRate: number | null;
  detectionRateCI95: [number, number] | null;
  falsePositiveRate: number | null;
  falsePositiveRateCI95: [number, number] | null;
  f1: number | null;
  tp: number;
  fn: number;
  fp: number;
  tn: number;
}

function shouldHaveFindings(verdict: NpmBenchVerdict): boolean {
  return verdict === "malicious" || verdict === "vulnerable";
}

export function computeNpmBenchMetrics(
  results: readonly NpmBenchMetricResult[],
  validScore: boolean,
): NpmBenchMetrics {
  let tp = 0;
  let fn = 0;
  let fp = 0;
  let tn = 0;

  for (const r of results) {
    if (r.infrastructureError) continue;
    const expectPositive = shouldHaveFindings(r.verdict);
    if (expectPositive && r.hasFindings) tp++;
    else if (expectPositive && !r.hasFindings) fn++;
    else if (!expectPositive && r.hasFindings) fp++;
    else tn++;
  }

  const scoredAttempts = tp + fn + fp + tn;
  const detectionDenom = tp + fn;
  const fpDenom = fp + tn;
  const precision = validScore ? (tp + fp > 0 ? tp / (tp + fp) : 0) : 0;
  const detectionRate = validScore ? (detectionDenom > 0 ? tp / detectionDenom : 0) : null;
  const falsePositiveRate = validScore ? (fpDenom > 0 ? fp / fpDenom : 0) : null;
  const accuracy = validScore ? (scoredAttempts > 0 ? (tp + tn) / scoredAttempts : 0) : null;
  const recall = detectionRate;
  const f1 = validScore && recall !== null && precision + recall > 0
    ? (2 * precision * recall) / (precision + recall)
    : validScore
      ? 0
      : null;

  return {
    accuracy,
    accuracyCI95: validScore ? wilsonIntervalTuple(tp + tn, scoredAttempts) : null,
    detectionRate,
    detectionRateCI95: validScore ? wilsonIntervalTuple(tp, detectionDenom) : null,
    falsePositiveRate,
    falsePositiveRateCI95: validScore ? wilsonIntervalTuple(fp, fpDenom) : null,
    f1,
    tp,
    fn,
    fp,
    tn,
  };
}
