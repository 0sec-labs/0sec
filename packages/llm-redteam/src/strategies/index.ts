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

/** Keep only strategies that produce sensible payloads for this behaviour's vector. */
function forVector(strategies: Strategy[], behavior: Behavior): Strategy[] {
  return strategies.filter((s) => !s.vectors || s.vectors.includes(behavior.vector));
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

/** Stack multiple concealment channels onto one framing (the "kitchen-sink"
 *  escalation: visible framing + every hidden reinforcement at once). */
export function composeMany(framing: Strategy, concealments: Strategy[]): Strategy {
  return {
    id: [framing.id, ...concealments.map((c) => c.id)].join("+"),
    kind: "composite",
    rationale: `escalation: ${framing.id} + ${concealments.map((c) => c.id).join(" + ")}`,
    build(behavior: Behavior): Payload {
      let text = framing.build(behavior).text;
      const strategies = [...framing.build(behavior).strategies];
      const hidden: string[] = [];
      for (const c of concealments) {
        const w = c.build(behavior, text);
        text = w.text;
        strategies.push(...w.strategies);
        if (w.hiddenSegments) hidden.push(...w.hiddenSegments);
      }
      return { text, strategies, hiddenSegments: hidden, behaviorId: behavior.id };
    },
  };
}

/**
 * Escalated candidates for models that survived the base sweep: each framing
 * with ALL concealment channels stacked at once. This is the v5 "combine every
 * technique" move that we used on the hardest arena models.
 */
export function escalatedCandidates(
  behavior: Behavior,
  opts: { framings?: Strategy[]; concealments?: Strategy[] } = {},
): Payload[] {
  const framings = opts.framings ?? forVector(framingStrategies, behavior);
  const concealments = opts.concealments ?? concealmentStrategies;
  return framings.map((f) => composeMany(f, concealments).build(behavior));
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
  const framings = opts.framings ?? forVector(framingStrategies, behavior);
  const concealments = opts.concealments ?? concealmentStrategies;
  const out: Payload[] = [];
  for (const f of framings) {
    out.push(f.build(behavior));
    for (const c of concealments) out.push(compose(f, c).build(behavior));
  }
  return out;
}
