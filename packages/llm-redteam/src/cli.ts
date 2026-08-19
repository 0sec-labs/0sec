#!/usr/bin/env node
/**
 * 0sec-llm — CLI for the offensive LLM red-team engine.
 *
 *   0sec-llm strategies                 list the strategy library
 *   0sec-llm gen <behaviorId>           print generated candidate payloads
 *   0sec-llm run <behaviorId> [--target mock|chat]
 *       mock: simulated easy/hard models (no network)
 *       chat: needs LLM_BASEURL, LLM_API_KEY, LLM_MODELS (comma list)
 */
import { allStrategies, generateCandidates } from "./strategies/index.js";
import { getBehavior, builtinBehaviors } from "./behaviors.js";
import { runCampaign } from "./engine.js";
import { mockTarget } from "./targets/mock.js";
import { chatTarget } from "./targets/chat.js";
import type { Target } from "./types.js";

const [cmd, arg, ...rest] = process.argv.slice(2);
const flag = (name: string) => {
  const i = rest.indexOf(`--${name}`);
  return i >= 0 ? rest[i + 1] : undefined;
};

function listStrategies() {
  for (const s of allStrategies) console.log(`${s.kind.padEnd(11)} ${s.id.padEnd(28)} ${s.rationale}`);
}

function gen(behaviorId: string) {
  const b = getBehavior(behaviorId);
  if (!b) return fail(`unknown behavior '${behaviorId}'. known: ${builtinBehaviors.map((x) => x.id).join(", ")}`);
  for (const p of generateCandidates(b)) {
    console.log(`\n===== ${p.strategies.join(" + ")} =====`);
    console.log(p.text);
  }
}

async function run(behaviorId: string) {
  const b = getBehavior(behaviorId);
  if (!b) return fail(`unknown behavior '${behaviorId}'`);
  const which = flag("target") ?? "mock";
  let target: Target;
  if (which === "chat") {
    const baseUrl = process.env.LLM_BASEURL;
    const apiKey = process.env.LLM_API_KEY;
    const models = (process.env.LLM_MODELS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    if (!baseUrl || !apiKey || !models.length) return fail("chat target needs LLM_BASEURL, LLM_API_KEY, LLM_MODELS");
    target = chatTarget({ baseUrl, apiKey, models });
  } else {
    // demo population: a compliant model, two channel-specific decoders, a hardened refuser
    target = mockTarget({
      models: [
        { name: "compliant-7b", followsVisible: true, decodes: [] },
        { name: "claude-ish", followsVisible: false, decodes: ["tags"] },
        { name: "openai-ish", followsVisible: false, decodes: ["bits"] },
        { name: "hardened-frontier", followsVisible: false, decodes: [] },
      ],
    });
  }
  const result = await runCampaign(b, target, {
    stopWhenAllBroken: true,
    onAttempt: (i) => console.log(`  [${i.attempt}] ${i.model ?? "-"} via ${i.strategies.join("+")} -> ${i.broken ? "BREAK" : "—"}`),
  });
  console.log(`\n=== ${b.id} on ${target.name}: ${result.brokenModels.length}/${target.models?.length ?? 1} models broken in ${result.attempts} attempts ===`);
  for (const br of result.breaks) console.log(`  BREAK ${br.model} via ${br.strategies.join("+")} (${br.evidence})`);
}

function fail(msg: string): never {
  console.error("error:", msg);
  process.exit(1);
}

const main = async () => {
  switch (cmd) {
    case "strategies": return listStrategies();
    case "gen": return gen(arg);
    case "run": return run(arg);
    default:
      console.log("usage: 0sec-llm <strategies|gen <behaviorId>|run <behaviorId> [--target mock|chat]>");
      console.log(`behaviors: ${builtinBehaviors.map((b) => b.id).join(", ")}`);
  }
};
main();
