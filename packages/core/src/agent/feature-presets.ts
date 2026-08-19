/**
 * Feature presets — named bundles of `0SEC_FEATURE_*` env vars.
 *
 * ## Why this exists
 *
 * `agent/features.ts` states the blocker plainly: the v0.6.0 FP-moat layers
 * "need explicit enablement in CI before any FP-moat A/B claim can be made."
 * Every one of those layers is default-OFF and gated behind its own env var,
 * so "enable the moat" currently means setting seven separate variables and
 * getting all seven right. Nothing in the repo names the full set, which makes
 * an A/B run something you reconstruct by reading source each time — and
 * therefore something that is easy to get subtly wrong and impossible to cite.
 *
 * A preset makes the set a single named, reviewable, testable object. That is
 * the point: not to turn the moat on, but to make turning it on reproducible
 * enough that the resulting measurement means something.
 *
 * ## What this is NOT
 *
 * Applying a preset is not a claim that these layers help. We have measured
 * this once already — the 2026-04-11 ablation
 * (`docs/src/content/docs/research/2026-04-11-ablation.md`, 21 profiles) — and
 * the result was slice-dependent, not a win:
 *
 *   - XBOW white-box: the moat cost 0-2 flags for ~60% fewer findings. Batch 2
 *     put the flag gap inside run-to-run noise at N=50.
 *   - XBOW black-box: the moat strictly dominated — MORE flags (19 vs 18),
 *     fewer findings, and cheaper per flag.
 *   - npm-bench: a no-op. The batch-1 FPR attribution was retracted in batch 2
 *     as a ~2-package noise swing.
 *
 * Read that carefully, because the headline is easy to garble: the large drop
 * is in FINDINGS, which is the moat doing its job, while the FLAG count (the
 * ground-truth-correct outcome) stayed roughly flat. "Fewer findings" is the
 * intended effect, not the regression.
 *
 * Exactly one layer was measured as genuinely broken: `egats` tree search went
 * 2 → 1 flags at 10× the worst per-flag cost on stubborn-14, and was removed
 * from the default aliases (0sec#116). Its flag no longer exists in this
 * codebase, so it cannot reappear through this preset.
 *
 * The preset exists so that measurement can be REPEATED — the profile aliases
 * the 2026-04-11 run used (`moat`, `moat-only`, `no-triage`, `none`) are gone
 * from the repo and from CI, which is why re-running the A/B currently means
 * reconstructing the flag set by reading source. That is the gap this closes.
 *
 * ## Precedence: an explicit env var always wins
 *
 * {@link applyFeaturePreset} never overwrites a variable that is already set.
 * An operator running `0SEC_FEATURE_POV_GATE=0` with the moat preset gets
 * the moat minus the PoV gate — which is exactly the single-layer ablation you
 * need to attribute an effect to one layer. Silently overriding the operator
 * would make per-layer ablation impossible, so the precedence is deliberate.
 *
 * Usage:
 *   0SEC_FEATURE_PRESET=fp-moat 0sec scan …
 *   0sec scan --features fp-moat …
 */

/** Names of the presets this module knows how to apply. */
export type FeaturePresetName = "fp-moat";

/**
 * The full opt-in false-positive moat.
 *
 * Every entry is a layer that `agent/features.ts` documents as default-OFF and
 * requiring explicit enablement before an A/B claim. The always-on filters
 * (`holding_it_wrong`, `evidence_gate`) and the unconditional `oracle` layer
 * are absent on purpose — they already run, so including them would imply the
 * preset changes something it does not.
 *
 * Deliberately excluded despite being FP-adjacent:
 *   - `0SEC_FEATURE_LEARNED_ROUTER` and `0SEC_FEATURE_DYNAMIC_TRIAGE` —
 *     these ROUTE layers (they decide which layers to skip per finding).
 *     Turning them on alongside the moat would let the router suppress the
 *     very layers the A/B is trying to measure, confounding the result. They
 *     are separately measurable and belong in their own preset.
 *   - `0SEC_FEATURE_INLINE_VALIDATION` — it runs inside the attack loop and
 *     changes EGATS scoring, so it alters discovery as well as triage. Mixing
 *     a discovery-side change into a triage A/B would make the arms
 *     non-comparable.
 */
const FP_MOAT_FLAGS: readonly string[] = [
  "0SEC_FEATURE_REACHABILITY_GATE",
  "0SEC_FEATURE_MULTIMODAL",
  "0SEC_FEATURE_PUBLISHABILITY_GATE",
  "0SEC_FEATURE_POV_GATE",
  "0SEC_FEATURE_POC_GEN_STATIC",
  "0SEC_FEATURE_CONSENSUS_VERIFY",
] as const;

/** Every preset, by name. */
export const FEATURE_PRESETS: Readonly<Record<FeaturePresetName, readonly string[]>> =
  Object.freeze({
    "fp-moat": FP_MOAT_FLAGS,
  });

/** Tokens accepted as preset names, including hyphen/underscore spellings. */
const PRESET_ALIASES: Readonly<Record<string, FeaturePresetName>> = Object.freeze({
  "fp-moat": "fp-moat",
  fp_moat: "fp-moat",
  fpmoat: "fp-moat",
  moat: "fp-moat",
});

/**
 * Resolve a user-supplied token to a preset name, or `undefined` when the
 * token is not a preset. Case- and separator-insensitive so `--features MOAT`
 * and `--features fp_moat` both work.
 */
export function resolveFeaturePreset(token: string): FeaturePresetName | undefined {
  return PRESET_ALIASES[token.trim().toLowerCase()];
}

/** What {@link applyFeaturePreset} did, for logging and for tests. */
export interface PresetApplication {
  preset: FeaturePresetName;
  /** Vars this call set to "1". */
  applied: readonly string[];
  /**
   * Vars left alone because they were already set. Their existing value wins —
   * this is the per-layer ablation escape hatch described in the module header.
   */
  preserved: readonly string[];
}

/**
 * Apply a preset by setting each of its env vars to "1", skipping any var that
 * is already set to anything (including "0").
 *
 * `env` is injectable so tests can assert against a plain object rather than
 * mutating the real process environment.
 *
 * Timing note: every flag in `agent/features.ts` is a getter that reads
 * `process.env` at access time, so applying a preset inside a CLI action
 * handler — after the module graph has loaded — is still honoured. That is why
 * this can be wired into command setup rather than requiring a shell export.
 */
export function applyFeaturePreset(
  preset: FeaturePresetName,
  env: NodeJS.ProcessEnv = process.env,
): PresetApplication {
  const applied: string[] = [];
  const preserved: string[] = [];

  for (const flag of FEATURE_PRESETS[preset]) {
    if (env[flag] !== undefined) {
      preserved.push(flag);
      continue;
    }
    env[flag] = "1";
    applied.push(flag);
  }

  return { preset, applied, preserved };
}

/**
 * Apply the preset named by `0SEC_FEATURE_PRESET`, if any. Returns
 * `undefined` when the variable is unset or names something unrecognized —
 * an unknown preset is ignored rather than fatal so a stale CI variable
 * degrades to default behaviour instead of failing the run.
 */
export function applyFeaturePresetFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): PresetApplication | undefined {
  const raw = env["0SEC_FEATURE_PRESET"];
  if (!raw) return undefined;
  const preset = resolveFeaturePreset(raw);
  if (!preset) return undefined;
  return applyFeaturePreset(preset, env);
}
