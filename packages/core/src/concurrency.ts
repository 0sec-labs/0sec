// Bounded-concurrency map helper.
//
// A leaf module with no agent/pipeline deps, so both the unified pipeline's
// blind-verify wave and the agent's concurrent subagent fan-out
// (`spawn_agents`) can share one implementation without pulling either into
// the other's import graph.

/**
 * Run `fn` over `items` with at most `limit` in flight, preserving input order.
 *
 * Deliberately NOT the `pool()` helper in `stages/hunt-scan.ts`: that one maps a
 * throwing task to `null`, which in the verify wave would be read downstream as
 * "no verdict" and could turn an infrastructure error into a dropped finding.
 * This mirrors `Promise.all` instead — the first rejection propagates, so a
 * caller's existing try/catch still converts it into a stage warning rather than
 * a silent per-item loss. (Callers that must survive per-item failure — e.g.
 * `spawn_agents` — pass an `fn` that never throws and encodes failure in its
 * return value.)
 */
export async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from(
    { length: Math.max(1, Math.min(limit, items.length)) },
    async () => {
      for (;;) {
        const i = next++;
        if (i >= items.length) return;
        out[i] = await fn(items[i], i);
      }
    },
  );
  await Promise.all(workers);
  return out;
}
