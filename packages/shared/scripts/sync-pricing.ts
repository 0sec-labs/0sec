/**
 * Keep our price table honest against the community-maintained OSS pricing feed
 * that ccusage / tokencost / openai-cost-calculator all consume under the hood:
 * LiteLLM's `model_prices_and_context_window.json`.
 *
 * Two modes:
 *   (default)  drift report — our $/M vs OSS $/M per model, exit non-zero on drift.
 *   --write    regenerate `src/pricing.oss.generated.ts` from the OSS feed for the
 *              CURATED models it covers (EXACT key match only — no fuzzy aliasing,
 *              so generated data is always trustworthy). Nobody hand-types a rate.
 *
 * Run: `pnpm --filter @pwnkit/shared sync-pricing`         (check drift)
 *      `pnpm --filter @pwnkit/shared sync-pricing --write` (refresh the table)
 *
 * Models the OSS feed does NOT cover (glm-*, llama-4-*, mistral-*, newest Claude)
 * stay in MANUAL_PRICING in src/pricing.ts — that residue is irreducible because
 * no public feed prices them.
 */
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { MODEL_PRICING, MANUAL_PRICING, PRICING_SNAPSHOT_DATE, type ModelRates } from "../src/pricing.js";

const LITELLM_URL =
  "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json";

/**
 * Models we want auto-priced from OSS. Only EXACT LiteLLM key matches are used;
 * anything here the feed lacks simply isn't emitted (and should live in
 * MANUAL_PRICING instead). Add a model key here once the OSS feed carries it.
 */
const CURATED = [
  "gpt-5.4", "gpt-5.5", "gpt-4o", "gpt-4o-mini",
  "gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano",
  "o3", "o3-mini", "o4-mini",
  "gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash",
  "deepseek-chat", "deepseek-reasoner",
];

interface LiteLlmEntry {
  input_cost_per_token?: number;
  output_cost_per_token?: number;
  cache_read_input_token_cost?: number;
}

// $/token → $/1M, rounded to kill IEEE-754 noise (0.4, not 0.39999999999997).
const perM = (x?: number): number | undefined =>
  x === undefined ? undefined : Number((x * 1_000_000).toFixed(6));
const fmt = (n?: number): string => (n === undefined ? "  —  " : `$${n.toFixed(2)}`);

function driftLabel(ours: number, oss?: number): string {
  if (oss === undefined) return "not-in-oss";
  const d = oss - ours;
  if (Math.abs(d) < 0.005) return "ok";
  return `DRIFT ${d > 0 ? "+" : ""}${d.toFixed(2)}`;
}

async function fetchOss(): Promise<Record<string, LiteLlmEntry>> {
  process.stdout.write("Fetching LiteLLM OSS pricing…\n");
  const res = await fetch(LITELLM_URL);
  if (!res.ok) throw new Error(`LiteLLM fetch failed: HTTP ${res.status}`);
  return (await res.json()) as Record<string, LiteLlmEntry>;
}

async function writeGenerated(oss: Record<string, LiteLlmEntry>): Promise<void> {
  const rows: string[] = [];
  const missing: string[] = [];
  for (const key of CURATED) {
    const e = oss[key];
    const input = perM(e?.input_cost_per_token);
    const output = perM(e?.output_cost_per_token);
    if (input === undefined || output === undefined) {
      missing.push(key);
      continue;
    }
    const cached = perM(e?.cache_read_input_token_cost);
    const rate = cached !== undefined
      ? `{ input: ${input}, output: ${output}, cachedInput: ${cached} }`
      : `{ input: ${input}, output: ${output} }`;
    rows.push(`  ${JSON.stringify(key)}: ${rate},`);
  }
  const here = dirname(fileURLToPath(import.meta.url));
  const out = join(here, "..", "src", "pricing.oss.generated.ts");
  const banner =
    "// AUTO-GENERATED from the LiteLLM OSS pricing feed by scripts/sync-pricing.ts --write.\n" +
    "// DO NOT EDIT BY HAND. Refresh: pnpm --filter @pwnkit/shared sync-pricing --write\n" +
    "// $ per 1M tokens. Models the feed lacks live in MANUAL_PRICING (src/pricing.ts).\n";
  const body =
    `export const OSS_PRICING: Record<string, { input: number; output: number; cachedInput?: number }> = {\n` +
    rows.join("\n") +
    "\n};\n";
  writeFileSync(out, banner + "\n" + body);
  process.stdout.write(`Wrote ${rows.length} models to src/pricing.oss.generated.ts\n`);
  if (missing.length) {
    process.stdout.write(`Not in OSS feed (keep in MANUAL_PRICING): ${missing.join(", ")}\n`);
  }
}

function driftReport(oss: Record<string, LiteLlmEntry>): number {
  let drifted = 0;
  const rows: string[] = [];
  for (const [key, rates] of Object.entries(MODEL_PRICING) as [string, ModelRates][]) {
    if (key === "default") continue;
    const manualOnly = key in MANUAL_PRICING;
    const e = oss[key];
    const ossIn = perM(e?.input_cost_per_token);
    const ossOut = perM(e?.output_cost_per_token);
    const inL = driftLabel(rates.input, ossIn);
    const outL = driftLabel(rates.output, ossOut);
    if ((inL.startsWith("DRIFT") || outL.startsWith("DRIFT")) && !manualOnly) drifted++;
    const tag = manualOnly ? " (manual)" : "";
    rows.push(
      `${(key + tag).padEnd(30)} in ours=${fmt(rates.input)} oss=${fmt(ossIn)} [${inL}]  ` +
        `out ours=${fmt(rates.output)} oss=${fmt(ossOut)} [${outL}]`,
    );
  }
  process.stdout.write(rows.join("\n") + "\n\n");
  process.stdout.write(`Snapshot ${PRICING_SNAPSHOT_DATE}. ${drifted} non-manual model(s) drifted.\n`);
  if (drifted) process.stdout.write("→ Run with --write to regenerate the table, then commit.\n");
  return drifted;
}

async function main(): Promise<void> {
  const oss = await fetchOss();
  if (process.argv.includes("--write")) {
    await writeGenerated(oss);
    return;
  }
  const drifted = driftReport(oss);
  process.exit(drifted > 0 ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`${err}\n`);
  process.exit(1);
});
