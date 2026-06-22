/** Strategy registry + composition. */
import type { Behavior, Payload, Strategy } from "../types.js";
import { framingStrategies } from "./framing.js";
import { concealmentStrategies } from "./concealment.js";

export * from "./framing.js";
export * from "./concealment.js";

export const allStrategies: Strategy[] = [...framingStrategies, ...concealmentStrategies];

export function getStrategy(id: string): Strategy | undefined {
  return allStrategies.find((s) => s.id === id);
}

/** Compose a framing strategy (visible body) with an optional concealment
 *  strategy (hidden reinforcement appended). */
export function compose(framing: Strategy, concealment?: Strategy): Strategy {
  if (!concealment) return framing;
  return {
    id: `${framing.id}+${concealment.id}`,
    kind: "composite",
    rationale: `${framing.rationale} | ${concealment.rationale}`,
    build(behavior: Behavior): Payload {
      const base = framing.build(behavior);
      const wrapped = concealment.build(behavior, base.text);
      return {
        text: wrapped.text,
        strategies: [...base.strategies, ...wrapped.strategies],
        hiddenSegments: wrapped.hiddenSegments,
        behaviorId: behavior.id,
      };
    },
  };
}

/**
 * Generate a diverse candidate set for a behaviour: every framing alone, plus
 * every framing × every concealment. This is the default attack surface the
 * engine sweeps.
 */
export function generateCandidates(
  behavior: Behavior,
  opts: { framings?: Strategy[]; concealments?: Strategy[] } = {},
): Payload[] {
  const framings = opts.framings ?? framingStrategies;
  const concealments = opts.concealments ?? concealmentStrategies;
  const out: Payload[] = [];
  for (const f of framings) {
    out.push(f.build(behavior));
    for (const c of concealments) out.push(compose(f, c).build(behavior));
  }
  return out;
}
