/**
 * Cross-family adversarial refuter — decorrelate finder and refuter errors
 * (issue #661).
 *
 * `makeSkepticVerifier` (hunt-scan.ts) re-reads a claimed finding and tries hard
 * to REFUTE it (assume-FP). By default that refute pass runs through the same
 * provider-agnostic loop — typically the same model FAMILY that produced the
 * finding, and in the CLI hunt path (`hunt.ts`, which hands the skeptic
 * `models[0]`) literally the SAME MODEL. A model is worst at catching its own
 * systematic errors: same blind spots, same hallucinated sinks, so correlated
 * errors survive. An adversarial gate whose adversary shares the finder's priors
 * is not an adversarial gate; it is a second opinion from the same witness.
 *
 * This module forces the refute pass onto a model of a DIFFERENT family than the
 * finder before a finding can be promoted. The errors decorrelate — a
 * hallucinated or non-reproducible finding gets caught by the second family, and
 * the ones that survive two families are genuinely disclosure-grade.
 *
 * ON by default (see {@link crossFamilyRefuteEnabled}) because every path out of
 * this module degrades to today's exact behaviour when a second family is not
 * actually reachable:
 *
 *   - Only one provider configured → the roster has at most one family, it
 *     equals the finder's, and {@link selectCrossFamilyRefuter} returns the
 *     configured refuter UNCHANGED (status `no-distinct-family`). No error, no
 *     skipped refutation — the same-family skeptic still runs, exactly as before.
 *   - Finder family unknown (no `models` passed, provider default in play) →
 *     passthrough, status `unknown-finder-family`. There is nothing to
 *     decorrelate FROM, so guessing would be worse than not trying.
 *   - The cross-family model is configured but the CALL fails (model id not
 *     enabled on the account, provider outage) → hunt-scan.ts retries the refute
 *     once on the ORIGINAL model and records status `degraded-refuter-error`.
 *     This matters: a throwing verifier is treated as fail-closed upstream
 *     (`runHuntScan` records a warning and drops the finding;
 *     `makeMultiLensVerifier` counts the lens as errored, lowering the survivor
 *     count), so without the retry a bad roster entry would silently DELETE real
 *     findings. Degrading to the same-family refuter loses decorrelation; it
 *     never loses the gate.
 *
 * Falling back to the same-family refuter rather than dropping the finding is
 * the assume-FP-safe choice throughout: a finding is never promoted on LESS
 * scrutiny than today, and never dropped for an infrastructure reason.
 *
 * {@link selectCrossFamilyRefuter} is a PURE selector (no LLM calls, no env, no
 * I/O) so the promotion gate stays unit-testable; the env-reading helpers
 * ({@link crossFamilyRefuteEnabled}, {@link availableRefuterCandidates}) sit
 * beside it and are applied by the wiring layer in hunt-scan.ts.
 */

import { modelProvider } from "@pwnkit/shared";

/**
 * Default ON (issue #661). This deliberately breaks from
 * `huntFlywheelEnabled()`'s opt-in discipline: the flywheel changes WHICH
 * findings reach the gate (a coverage/ordering claim that needs an A/B), while
 * this only changes WHO refutes a finding that is going through the gate
 * regardless. It adds no extra LLM call — the refute pass runs either way — and
 * every failure mode degrades to the pre-existing same-family behaviour (see the
 * module header). Set `PWNKIT_HUNT_CROSS_FAMILY=0` to pin the old correlated
 * behaviour for an ablation.
 */
export function crossFamilyRefuteEnabled(): boolean {
  const raw = process.env.PWNKIT_HUNT_CROSS_FAMILY;
  // Unset → ON. Explicitly empty/0/false/no → OFF (matches the `env()` helper
  // convention in agent/features.ts, where an unset var takes the default).
  if (raw === undefined) return true;
  return !["", "0", "false", "no"].includes(raw.toLowerCase());
}

/**
 * The model family a refuter/finder id belongs to, for decorrelation purposes.
 *
 * Wraps `modelProvider` with one correction that matters here and nowhere else:
 * `modelProvider("openrouter/anthropic/claude-...")` answers `"openrouter"`,
 * which is a ROUTING vendor, not a model family. Treating it as a family would
 * let an OpenRouter-fronted Claude "decorrelate" from a direct Claude finder —
 * the exact same weights, counted as a second opinion. Strip the routing prefix
 * and classify the underlying model instead.
 */
export function refuterFamily(model?: string): string {
  if (!model) return "unknown";
  const unwrapped = model.toLowerCase().startsWith("openrouter/") ? model.slice("openrouter/".length) : model;
  return modelProvider(unwrapped);
}

/**
 * One representative model per family, used when the caller supplies no explicit
 * `refuterCandidates`. Values mirror the per-provider defaults in
 * `runtime/llm-api.ts` (DEFAULT_ANTHROPIC_MODEL / CODEX_DEFAULT_MODEL /
 * ZAI_DEFAULT_MODEL / KIMI_DEFAULT_MODEL); they are duplicated rather than
 * imported so this module keeps its `@pwnkit/shared`-only dependency and stays
 * trivially unit-testable. `envKeys` are the auth vars `providerForModel`
 * (llm-api.ts) actually checks before it will route a model to that provider —
 * listing a family whose auth is absent would produce a refuter that cannot be
 * called.
 *
 * Ordered strongest-adversary-first: the refute pass is a careful re-read of
 * source, so a weak model in this slot buys decorrelation at the cost of rigour.
 *
 * Deliberately EXCLUDED:
 *   - google/gemini — `providerForModel` has no Google branch, so a Gemini id
 *     cannot be routed today no matter which key is set.
 *   - openrouter — a meta-router; the key alone does not say which family you
 *     get. Operators who want it can name explicit `openrouter/<vendor>/<model>`
 *     ids via PWNKIT_HUNT_REFUTER_CANDIDATES, which {@link refuterFamily}
 *     classifies correctly.
 *   - AZURE_OPENAI_API_KEY — same family as OpenAI (so it buys no
 *     decorrelation against a GPT finder), and Azure addresses models by
 *     account-specific DEPLOYMENT name, which we cannot guess. Operators with
 *     an Azure-only OpenAI path should name their deployment explicitly via
 *     PWNKIT_HUNT_REFUTER_CANDIDATES.
 */
const REFUTER_ROSTER: ReadonlyArray<{ model: string; envKeys: readonly string[] }> = [
  { model: "claude-sonnet-4-6", envKeys: ["ANTHROPIC_API_KEY"] },
  { model: "gpt-5.5", envKeys: ["PWNKIT_CHATGPT_ACCESS_TOKEN", "PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN", "OPENAI_API_KEY"] },
  { model: "glm-5.3", envKeys: ["Z_AI_API_KEY"] },
  { model: "k3", envKeys: ["KIMI_API_KEY"] },
  { model: "qwen3.8-max", envKeys: ["QWEN_API_KEY"] },
];

/**
 * Candidate refuter models whose provider auth is actually present in this
 * process, in preference order — the default `candidates` for
 * {@link selectCrossFamilyRefuter} when the caller names none.
 *
 * This is what makes the default-ON flag mean anything: no production call site
 * passes a candidate roster, so without it the selector would have nothing to
 * pick from and every run would silently passthrough. Deriving the roster from
 * configured auth is also what makes default-ON SAFE — a single-provider
 * deployment yields a roster of one family, which is the finder's own, so the
 * selector passthroughs and behaviour is byte-identical to before.
 *
 * `PWNKIT_HUNT_REFUTER_CANDIDATES` (comma-separated model ids) overrides the
 * roster entirely, for operators who know which model ids their accounts can
 * actually reach. An override is taken verbatim — no auth filtering, because we
 * cannot know which key backs an arbitrary id.
 */
export function availableRefuterCandidates(): string[] {
  const override = process.env.PWNKIT_HUNT_REFUTER_CANDIDATES;
  if (override && override.trim()) {
    return override.split(",").map((m) => m.trim()).filter(Boolean);
  }
  return REFUTER_ROSTER.filter((r) => r.envKeys.some((k) => Boolean(process.env[k]))).map((r) => r.model);
}

export interface CrossFamilyRefuteConfig {
  /**
   * Off → the configured refuter is returned unchanged (byte-identical to the
   * pre-#661 path). Defaults to {@link crossFamilyRefuteEnabled} at the call site.
   */
  enabled: boolean;
  /** The finder model/family the refuter must decorrelate from. */
  finderModel?: string;
  /**
   * ALL finder models in play when the hunt fans out over several
   * (`runHuntScan`'s `models` axis). The chosen refuter must differ from EVERY
   * one of their families, not just the first — a two-model hunt refuted by one
   * of its own finder families is still correlated for half its findings.
   * Unioned with {@link finderModel}.
   */
  finderModels?: readonly string[];
  /** The refuter model already configured (env `HUNT_SKEPTIC_MODEL` / `opts.model`). */
  refuterModel?: string;
  /** Alternate refuter models to pick a distinct family from, tried in order. */
  candidates?: readonly string[];
}

/**
 * Why the refute pass is (or is not) decorrelated from the finder. This is the
 * observability primitive: before it, the only outward signal that cross-family
 * had done anything was a substring inside a free-text `reason`, so "the flag is
 * on but nothing is happening" was indistinguishable from "the flag is working"
 * from outside the process.
 *
 *   - `enforced`             — a distinct-family refuter was selected and used.
 *   - `already-cross-family` — the configured refuter was already a different
 *                              family; kept as-is, pairing recorded.
 *   - `disabled`             — the flag is off; same-family refute, as before.
 *   - `unknown-finder-family`— no finder model known, nothing to decorrelate from.
 *   - `no-distinct-family`   — only one family is reachable (the single-provider
 *                              deployment); same-family refute, as before.
 *   - `degraded-refuter-error` — a cross-family refuter was selected but its call
 *                              failed, so the refute was re-run on the original
 *                              model. Stamped by hunt-scan.ts, never by the
 *                              selector.
 */
export type CrossFamilyStatus =
  | "enforced"
  | "already-cross-family"
  | "disabled"
  | "unknown-finder-family"
  | "no-distinct-family"
  | "degraded-refuter-error";

export interface CrossFamilyRefuteChoice {
  /** The model the refute pass should use (undefined = the provider default). */
  model?: string;
  /** True ONLY when a distinct-family refuter is actually being enforced. */
  crossFamily: boolean;
  /** Why {@link crossFamily} is what it is — see {@link CrossFamilyStatus}. */
  status: CrossFamilyStatus;
  /** The finder family avoided — set only when {@link crossFamily} is true. */
  finderFamily?: string;
  /** The refuter family used — set only when {@link crossFamily} is true. */
  refuterFamily?: string;
}

/**
 * Choose the refute pass's model so it decorrelates from the finder's family.
 *
 * Passthrough (crossFamily:false, model unchanged) whenever enforcement can't
 * apply: disabled, the finder family is unknown, or no distinct-family
 * candidate is available. Otherwise, if the already-configured refuter is
 * itself a different family, keep it (and just record the pairing); else pick
 * the first candidate from a family none of the finders belong to.
 *
 * Pure: every input arrives through `cfg`, so a test can drive any deployment
 * shape without touching env or the network.
 */
export function selectCrossFamilyRefuter(cfg: CrossFamilyRefuteConfig): CrossFamilyRefuteChoice {
  const passthrough = (status: CrossFamilyStatus): CrossFamilyRefuteChoice => ({
    model: cfg.refuterModel,
    crossFamily: false,
    status,
  });
  if (!cfg.enabled) return passthrough("disabled");

  // Every family the hunt's finders belong to — the refuter must avoid ALL of
  // them, not merely the first.
  const finderFamilies = new Set(
    [cfg.finderModel, ...(cfg.finderModels ?? [])]
      .map((m) => refuterFamily(m))
      .filter((f) => f !== "unknown"),
  );
  // Without a known finder family there is nothing to decorrelate FROM.
  if (finderFamilies.size === 0) return passthrough("unknown-finder-family");
  const finderFamily = [...finderFamilies].join("+");

  // Already cross-family? Keep the configured refuter — just record the pairing.
  const configuredFamily = refuterFamily(cfg.refuterModel);
  if (configuredFamily !== "unknown" && !finderFamilies.has(configuredFamily)) {
    return {
      model: cfg.refuterModel,
      crossFamily: true,
      status: "already-cross-family",
      finderFamily,
      refuterFamily: configuredFamily,
    };
  }

  // Otherwise pick the first candidate from a family no finder belongs to.
  for (const candidate of cfg.candidates ?? []) {
    const family = refuterFamily(candidate);
    if (family !== "unknown" && !finderFamilies.has(family)) {
      return { model: candidate, crossFamily: true, status: "enforced", finderFamily, refuterFamily: family };
    }
  }

  // No distinct family available → byte-identical to today (assume-FP safe).
  return passthrough("no-distinct-family");
}

/** One-line human-readable summary of a refuter choice, for run logs. */
export function describeRefuterChoice(choice: CrossFamilyRefuteChoice): string {
  return choice.crossFamily
    ? `cross-family refute ${choice.status}: refuter=${choice.refuterFamily} (${choice.model ?? "provider default"}) vs finder=${choice.finderFamily}`
    : `cross-family refute NOT applied (${choice.status}) — refuter shares the finder's family; errors stay correlated`;
}
