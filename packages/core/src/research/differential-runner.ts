export interface DifferentialSide<T> {
  id: string;
  target: T;
}

export interface DifferentialPair<T> {
  baseline: DifferentialSide<T>;
  candidate: DifferentialSide<T>;
}

export interface DifferentialObservation<O> {
  sideId: string;
  ok: boolean;
  observation?: O;
  error?: string;
  durationMs?: number;
}

export interface DifferentialComparison<D = unknown> {
  status: "same" | "divergent" | "inconclusive";
  summary: string;
  data?: D;
}

export interface DifferentialRunResult<O, D = unknown> {
  pair: { baselineId: string; candidateId: string };
  baseline: DifferentialObservation<O>;
  candidate: DifferentialObservation<O>;
  comparison: DifferentialComparison<D>;
}

export type DifferentialExecutor<T, I, O> = (target: T, input: I) => Promise<O>;
export type DifferentialComparator<O, D = unknown> = (baseline: O, candidate: O) => DifferentialComparison<D>;

/** Run identical input against two targets; failed execution can never become a divergence claim. */
export async function runDifferential<T, I, O, D = unknown>(opts: {
  pair: DifferentialPair<T>;
  input: I;
  execute: DifferentialExecutor<T, I, O>;
  compare: DifferentialComparator<O, D>;
}): Promise<DifferentialRunResult<O, D>> {
  const observe = async (side: DifferentialSide<T>): Promise<DifferentialObservation<O>> => {
    const started = Date.now();
    try {
      return { sideId: side.id, ok: true, observation: await opts.execute(side.target, opts.input), durationMs: Date.now() - started };
    } catch (error) {
      return { sideId: side.id, ok: false, error: error instanceof Error ? error.message : String(error), durationMs: Date.now() - started };
    }
  };
  const [baseline, candidate] = await Promise.all([observe(opts.pair.baseline), observe(opts.pair.candidate)]);
  const comparison = baseline.ok && candidate.ok
    ? opts.compare(baseline.observation as O, candidate.observation as O)
    : {
        status: "inconclusive" as const,
        summary: `differential execution incomplete: baseline=${baseline.ok ? "ok" : "error"}, candidate=${candidate.ok ? "ok" : "error"}`,
      };
  return {
    pair: { baselineId: opts.pair.baseline.id, candidateId: opts.pair.candidate.id },
    baseline,
    candidate,
    comparison,
  };
}
