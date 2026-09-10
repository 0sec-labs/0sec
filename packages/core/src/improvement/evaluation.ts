import { evaluateImprovementPromotion } from "../bench/improvement-promotion.js";
import type { ResearchScoreSnapshot } from "../bench/improvement.js";
import { wilson95 } from "../bench/scorecard.js";
import { canonicalEvolutionJson, parseEvolutionConfig } from "./config.js";
import { evolutionDigest, verifyEvolutionSnapshot } from "./registry.js";
import { createDockerEvolutionSandbox, resolveEvolutionImage } from "./sandbox.js";
import type {
  EvolutionAttempt, EvolutionConfig, EvolutionDependencies, EvolutionEvaluation,
  EvolutionLane, EvolutionSnapshot,
} from "./types.js";

function score(attempts: EvolutionAttempt[], lane: EvolutionLane): ResearchScoreSnapshot {
  const selected = attempts.filter((entry) => entry.lane === lane);
  const successes = selected.filter((entry) => entry.matched && !entry.inconclusive).length;
  const count = selected.length;
  const rate = count === 0 ? 0 : successes / count;
  const caseOutcomes = new Map<string, boolean>();
  let caseSuccesses = 0;
  let stable = true;
  for (const entry of selected) {
    const success = entry.matched && !entry.inconclusive;
    if (!caseOutcomes.has(entry.caseId)) {
      caseOutcomes.set(entry.caseId, success);
      if (success) caseSuccesses++;
    } else if (caseOutcomes.get(entry.caseId) !== success) {
      stable = false;
    }
  }
  return {
    cases: caseOutcomes.size,
    successRate: rate,
    // Repeats test stability, not independent evidence. Unstable runs have no informative interval.
    successRateCI95: stable ? wilson95(caseSuccesses, caseOutcomes.size) : [0, 1],
    falsePositiveRate: count === 0 ? 0 : selected.filter((entry) => !entry.matched && !entry.inconclusive).length / count,
    costPerSuccessUsd: successes === 0 ? null : selected.reduce((sum, entry) => sum + entry.costUsd, 0) / successes,
    inconclusiveRate: count === 0 ? 1 : selected.filter((entry) => entry.inconclusive).length / count,
  };
}

/** Host-owned exact JSON oracle. Candidate output is data, never an evaluator receipt. */
export async function evaluateEvolutionCandidate(
  baseline: EvolutionSnapshot,
  candidate: EvolutionSnapshot,
  rawConfig: EvolutionConfig,
  deps: EvolutionDependencies = {},
): Promise<EvolutionEvaluation> {
  const config = parseEvolutionConfig(rawConfig);
  deps.signal?.throwIfAborted();
  if (!deps.sandbox) config.image = await resolveEvolutionImage(config.image);
  const configDigest = evolutionDigest(config);
  if (baseline.digest === candidate.digest) throw new Error("candidate does not change the baseline artifact");
  verifyEvolutionSnapshot(baseline);
  verifyEvolutionSnapshot(candidate);
  const sandbox = deps.sandbox ?? createDockerEvolutionSandbox();
  const attempts: EvolutionEvaluation["attempts"] = { baseline: [], candidate: [] };
  let spent = 0;
  const evaluatorIdentity = {
    protocol: "0sec-evolution-exact-json-v1",
    configDigest,
    implementation: [
      evaluateEvolutionCandidate.toString(), score.toString(), wilson95.toString(),
      canonicalEvolutionJson.toString(), evaluateImprovementPromotion.toString(),
    ],
  };
  const evaluatorDigest = evolutionDigest(evaluatorIdentity);
  // Alternate the order to avoid consistently giving one variant a warm-cache advantage.
  evaluation: for (let repeat = 0; repeat < config.repeats; repeat++) {
    for (const fixture of config.cases) {
      for (const variant of repeat % 2 === 0 ? ["baseline", "candidate"] as const : ["candidate", "baseline"] as const) {
        deps.signal?.throwIfAborted();
        const maximumNextCost = config.timeoutMs / 1000 * config.computeUsdPerSecond;
        if (spent + maximumNextCost > config.maxEvaluationCostUsd) {
          throw new Error("evaluation budget cannot cover the next bounded execution");
        }
        const snapshot = variant === "baseline" ? baseline : candidate;
        verifyEvolutionSnapshot(snapshot);
        const execution = await sandbox({ snapshot, config, input: fixture.input, signal: deps.signal });
        verifyEvolutionSnapshot(snapshot);
        let inconclusive = execution.exitCode !== 0 || execution.timedOut || Boolean(execution.error)
          || !Number.isFinite(execution.durationMs) || execution.durationMs < 0;
        let matched = false;
        if (!inconclusive) {
          try {
            const output: unknown = JSON.parse(execution.stdout);
            matched = canonicalEvolutionJson(output) === canonicalEvolutionJson(fixture.expected);
          } catch {
            inconclusive = true;
          }
        }
        const costUsd = Number.isFinite(execution.durationMs) && execution.durationMs >= 0
          ? execution.durationMs / 1000 * config.computeUsdPerSecond : 0;
        spent += costUsd;
        attempts[variant].push({ caseId: fixture.id, lane: fixture.lane, repeat, matched, inconclusive, costUsd, execution });
        deps.log?.(`[evolve] ${variant} ${fixture.lane}/${fixture.id} repeat=${repeat + 1}: ${inconclusive ? "inconclusive" : matched ? "matched" : "mismatch"}`);
        if (spent > config.maxEvaluationCostUsd) throw new Error("evaluation cost ceiling exceeded");
        // An unavailable oracle already disqualifies the candidate; retain the
        // failure rather than spending the remaining budget repeating it.
        if (inconclusive) break evaluation;
      }
    }
  }
  const negativeBase = score(attempts.baseline, "negative-control");
  const negativeCandidate = score(attempts.candidate, "negative-control");
  const repeatedResultsStable = Object.values(attempts).every((entries) => {
    const firstResult = new Map<string, boolean>();
    for (const entry of entries) {
      if (firstResult.has(entry.caseId) && firstResult.get(entry.caseId) !== entry.matched) return false;
      firstResult.set(entry.caseId, entry.matched);
    }
    return true;
  });
  const result: EvolutionEvaluation["result"] = {
    schemaVersion: 1,
    candidateId: candidate.id,
    manifestId: `evolution:${configDigest}`,
    developmentCorpusDigest: evolutionDigest(config.cases.filter((entry) => entry.lane === "development")),
    heldOutCorpusDigest: evolutionDigest(config.cases.filter((entry) => entry.lane === "held-out")),
    negativeControlCorpusDigest: evolutionDigest(config.cases.filter((entry) => entry.lane === "negative-control")),
    evaluatorDigestBefore: evaluatorDigest,
    evaluatorDigestAfter: evolutionDigest(evaluatorIdentity),
    ciPassed: repeatedResultsStable && [...attempts.baseline, ...attempts.candidate].every((entry) => !entry.inconclusive),
    development: { champion: score(attempts.baseline, "development"), challenger: score(attempts.candidate, "development") },
    heldOut: { champion: score(attempts.baseline, "held-out"), challenger: score(attempts.candidate, "held-out") },
    negativeControls: {
      champion: { cases: negativeBase.cases, falsePositiveRate: negativeBase.falsePositiveRate, inconclusiveRate: negativeBase.inconclusiveRate },
      challenger: { cases: negativeCandidate.cases, falsePositiveRate: negativeCandidate.falsePositiveRate, inconclusiveRate: negativeCandidate.inconclusiveRate },
    },
    evidenceRefs: [evolutionDigest(attempts)],
  };
  if (evolutionDigest(config) !== configDigest) throw new Error("evaluation contract changed during execution");
  verifyEvolutionSnapshot(baseline);
  verifyEvolutionSnapshot(candidate);
  const decision = evaluateImprovementPromotion({
    schemaVersion: 1,
    candidateId: candidate.id,
    kind: config.kind === "source" ? "source" : "policy",
    baseArtifactDigest: baseline.digest,
    candidateArtifactDigest: candidate.digest,
    result,
  }, config.promotionPolicy);
  const unsigned = {
    schemaVersion: 1 as const,
    candidateId: candidate.id,
    baselineDigest: baseline.digest,
    candidateDigest: candidate.digest,
    configDigest,
    attempts,
    result,
    decision,
  };
  return { ...unsigned, receiptDigest: evolutionDigest(unsigned) };
}
