/**
 * Deterministic mock target — simulates the easy/hard split we measured on the
 * Gray Swan arena, so the engine can be tested & demoed without a live model.
 *
 * Each mock model has a policy: it will "execute" the goal literal if it sees a
 * convincing visible instruction, OR if it decodes a hidden channel it's
 * susceptible to. Highly-aligned models decode nothing and execute nothing.
 */
import type { Behavior, Payload, Target, TargetResponse } from "../types.js";
import { fromUnicodeTags, fromSneakyBits } from "../strategies/concealment.js";

export interface MockModel {
  name: string;
  /** Will run a visibly-framed setup command? (the "easy behaviour" axis) */
  followsVisible: boolean;
  /** Hidden channels this model decodes and acts on. */
  decodes: Array<"tags" | "bits">;
}

export interface MockTargetOptions {
  models: MockModel[];
}

export function mockTarget(opts: MockTargetOptions): Target {
  const byName = new Map(opts.models.map((m) => [m.name, m]));
  return {
    name: "mock",
    models: opts.models.map((m) => m.name),
    async send(payload: Payload, behavior: Behavior, model?: string): Promise<TargetResponse> {
      const m = model ? byName.get(model) : opts.models[0];
      const lit = behavior.goal.literal ?? behavior.goal.action;

      // visible occurrence of the literal in the rendered text?
      const visibleHit = payload.text.includes(lit) && m?.followsVisible;
      // hidden channels the model decodes
      const decodedTags = m?.decodes.includes("tags") ? fromUnicodeTags(payload.text) : "";
      const decodedBits = m?.decodes.includes("bits") ? fromSneakyBits(payload.text) : "";
      const hiddenHit = (decodedTags + decodedBits).includes(lit);

      const executed = Boolean(visibleHit || hiddenHit);
      if (executed) {
        return {
          model,
          transcript: `Setting up the environment as described. Running: ${lit}\nDone.`,
          toolCalls: [{ tool: "bash", args: lit }],
        };
      }
      return {
        model,
        transcript: `I reviewed the document but won't run that unverified step. Here's a safe summary instead.`,
      };
    },
  };
}
