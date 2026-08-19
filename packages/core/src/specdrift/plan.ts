import { runSpecdriftScan } from "./map.js";
import type {
  DriftHypothesis,
  ImplementationCandidate,
  PlanSpecdriftHypothesesOptions,
  RunSpecdriftPlanOptions,
  SpecInvariant,
  SpecdriftAdapterKind,
  SpecdriftPlanResult,
} from "./types.js";

function adapterFor(invariant: SpecInvariant, candidate: ImplementationCandidate): SpecdriftAdapterKind {
  const file = candidate.file.toLowerCase();
  if (/\b(kernel|net|drivers)\b/.test(file)) return "kernel-repro";
  if (invariant.kind === "state" || invariant.kind === "ordering") return "stateful-transcript";
  if (/\.(c|h|cc|cpp|cxx|rs|go)$/i.test(file) && (invariant.kind === "range" || invariant.kind === "length" || invariant.kind === "rejection")) return "raw-bytes";
  if (/\.(js|ts|py|java|kt)$/i.test(file)) return "unit-test";
  return "request-response";
}

function questionFor(invariant: SpecInvariant, candidate: ImplementationCandidate): string {
  const subject = invariant.subject ? ` for ${invariant.subject}` : "";
  if (invariant.kind === "rejection") {
    return `Does ${candidate.file}:${candidate.lineStart} reject inputs that violate the spec rule${subject}: ${invariant.summary}?`;
  }
  if (invariant.kind === "state" || invariant.kind === "ordering") {
    return `Can an input transcript reach ${candidate.file}:${candidate.lineStart} in an order/state forbidden by the spec rule${subject}: ${invariant.summary}?`;
  }
  if (invariant.kind === "range" || invariant.kind === "length") {
    return `Does ${candidate.file}:${candidate.lineStart} enforce the spec bound${subject}: ${invariant.summary}?`;
  }
  return `Does ${candidate.file}:${candidate.lineStart} implement the spec invariant${subject}: ${invariant.summary}?`;
}

export function planSpecdriftHypotheses(opts: PlanSpecdriftHypothesesOptions): DriftHypothesis[] {
  const byInvariant = new Map(opts.scan.invariants.map((inv) => [inv.id, inv]));
  const max = opts.maxHypotheses ?? 20;
  const hypotheses: DriftHypothesis[] = [];

  for (const candidate of opts.scan.candidates) {
    const invariant = byInvariant.get(candidate.invariantId);
    if (!invariant) continue;
    const suggestedAdapter = adapterFor(invariant, candidate);
    hypotheses.push({
      id: `hyp-${String(hypotheses.length + 1).padStart(3, "0")}-${invariant.id.replace(/^inv-\d+-/, "").slice(0, 40)}`,
      invariantId: invariant.id,
      candidateFile: candidate.file,
      candidateLineStart: candidate.lineStart,
      candidateLineEnd: candidate.lineEnd,
      question: questionFor(invariant, candidate),
      suggestedAdapter,
      rationale: `Spec invariant (${invariant.kind}, ${invariant.securityRelevance} relevance) matched ${candidate.matchedTerms.join(", ")} in candidate code. This is a hypothesis only; adapter execution or skeptic review must prove/refute behavior.`,
      status: "hypothesis",
      confidence: Math.min(0.9, candidate.confidence * (invariant.securityRelevance === "high" ? 1 : 0.85)),
    });
    if (hypotheses.length >= max) break;
  }

  return hypotheses;
}

export function runSpecdriftPlan(opts: RunSpecdriftPlanOptions): SpecdriftPlanResult {
  const scan = runSpecdriftScan(opts);
  return {
    ...scan,
    stage: "plan",
    hypotheses: planSpecdriftHypotheses({ scan, ...(opts.maxHypotheses ? { maxHypotheses: opts.maxHypotheses } : {}) }),
  };
}
