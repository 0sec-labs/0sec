/**
 * Impact-assessment triage layer (issue #1103).
 *
 * Findings carry `severity` + a raw exploitability/confidence signal, but NOT
 * the decision-relevant impact. That gap makes "critical" meaningless as a
 * priority: an FS-image UAF is scored `critical` but needs root to mount an
 * attacker image (= noise), while a remote NFC crash is only `high` but hits
 * every device with the radio on (= the headline). This layer computes the
 * qualifier a human triager actually reasons about:
 *
 *   - reachability_tier — how the attacker must be positioned (remote-unauth …
 *     needs-host-migration). The gate that turns raw severity into real risk.
 *   - blast_radius      — who/what is affected ("every device with NFC").
 *   - weaponizability   — what the attacker gets (dos-crash … rce).
 *   - business_impact   — the coarse tier the engine ranks on (headline …
 *     noise). This is the single knob self-prioritization sorts by.
 *   - rationale         — a short, stable justification.
 *
 * NETWORK SEAM. The assessment is produced by an LLM routed through the shared
 * {@link NativeRuntime} (no raw keys). The runtime is injected so unit tests can
 * pass a fake model and stay deterministic + offline. When the model is
 * unavailable or returns something unparseable, we fall back to a deterministic
 * heuristic derived from severity/category — the layer never throws and never
 * blocks a finding.
 *
 * GUARDRAIL. This module only *computes* an assessment. It never drops or
 * mutates a finding; ranking consumers decide what to do with `business_impact`.
 */

import type {
  BusinessImpact,
  Finding,
  ImpactAssessment,
  ReachabilityTier,
  Weaponizability,
} from "@pwnkit/shared";
import type { NativeRuntime } from "../runtime/types.js";

// ────────────────────────────────────────────────────────────────────
// Vocabularies (single source of truth for validation + ranking)
// ────────────────────────────────────────────────────────────────────

const REACHABILITY_TIERS: readonly ReachabilityTier[] = [
  "remote-unauth",
  "proximity-rf",
  "local-unpriv",
  "local-priv",
  "needs-hardware",
  "needs-host-migration",
];

const WEAPONIZABILITY: readonly Weaponizability[] = [
  "dos-crash",
  "info-leak",
  "lpe-to-root",
  "rce",
];

const BUSINESS_IMPACTS: readonly BusinessImpact[] = [
  "headline",
  "notable",
  "modest",
  "noise",
];

/**
 * Ranking weight for the coarse tier. Higher = more urgent. The engine sorts
 * findings by this so `headline` floats to the top and `noise` sinks — the
 * whole point of the layer (deprioritize noise, escalate headline).
 */
export const BUSINESS_IMPACT_RANK: Record<BusinessImpact, number> = {
  headline: 3,
  notable: 2,
  modest: 1,
  noise: 0,
};

// ────────────────────────────────────────────────────────────────────
// Options
// ────────────────────────────────────────────────────────────────────

export interface AssessImpactOptions {
  /**
   * The model, routed through the shared runtime (no raw keys). Injected so
   * tests can pass a fake NativeRuntime. When omitted, {@link assessImpact}
   * returns the deterministic heuristic baseline (no network).
   */
  runtime?: NativeRuntime;
}

// ────────────────────────────────────────────────────────────────────
// Prompt
// ────────────────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a senior vulnerability triager. Given a security finding, assess its REAL business impact — not the nominal severity label. The decision that matters is: how much does this bug actually matter, and how hard is it to reach?

A nominally "critical" bug gated behind root access plus a host filesystem migration (e.g. a UAF that only triggers when the victim mounts an attacker-supplied image) is NOISE. A "high" bug reachable remotely with no auth that hits every deployed device is the HEADLINE. Score reachability and blast radius honestly.

Respond with ONLY a JSON object, no prose, matching this schema exactly:
{
  "reachability_tier": one of "remote-unauth" | "proximity-rf" | "local-unpriv" | "local-priv" | "needs-hardware" | "needs-host-migration",
  "blast_radius": "one short sentence naming who/what is affected",
  "weaponizability": one of "dos-crash" | "info-leak" | "lpe-to-root" | "rce",
  "business_impact": one of "headline" | "notable" | "modest" | "noise",
  "rationale": "one or two sentences justifying the tier"
}

reachability_tier: how the attacker must be positioned. remote-unauth is worst; needs-host-migration / needs-hardware / local-priv are the weakest (attacker already privileged or needs the victim to import an artifact).
weaponizability: what the attacker gains. rce > lpe-to-root > info-leak > dos-crash.
business_impact: the single coarse tier. headline = remotely reachable AND high weaponizability AND broad blast radius; noise = needs strong preconditions OR only a local crash with narrow blast radius.`;

function buildUserMessage(finding: Finding): string {
  const evidence = finding.evidence;
  const parts = [
    `Title: ${finding.title}`,
    `Category: ${finding.category}`,
    `Severity (nominal): ${finding.severity}`,
  ];
  if (typeof finding.confidence === "number") {
    parts.push(`Agent confidence: ${finding.confidence}`);
  }
  if (typeof finding.cvssScore === "number") {
    parts.push(`CVSS: ${finding.cvssScore}`);
  }
  parts.push(`Description: ${finding.description}`);
  if (evidence?.analysis) {
    parts.push(`Analysis: ${evidence.analysis.slice(0, 1200)}`);
  }
  parts.push(
    "",
    "Assess the real business impact of THIS finding. Return only the JSON object.",
  );
  return parts.join("\n");
}

// ────────────────────────────────────────────────────────────────────
// Parsing + validation
// ────────────────────────────────────────────────────────────────────

function inSet<T extends string>(set: readonly T[], value: unknown): value is T {
  return typeof value === "string" && (set as readonly string[]).includes(value);
}

/**
 * Parse + validate a model response into an {@link ImpactAssessment}. Returns
 * null when the text is not valid JSON or any enum field is out of vocabulary —
 * callers fall back to the heuristic. Tolerant of markdown code fences.
 */
export function parseImpactAssessment(text: string): ImpactAssessment | null {
  let jsonStr = text.trim();
  const fence = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fence) jsonStr = fence[1].trim();
  // Fall back to the first {...} block if the model wrapped it in prose.
  if (!jsonStr.startsWith("{")) {
    const brace = jsonStr.match(/\{[\s\S]*\}/);
    if (brace) jsonStr = brace[0];
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const o = parsed as Record<string, unknown>;

  if (!inSet(REACHABILITY_TIERS, o.reachability_tier)) return null;
  if (!inSet(WEAPONIZABILITY, o.weaponizability)) return null;
  if (!inSet(BUSINESS_IMPACTS, o.business_impact)) return null;
  const blastRadius =
    typeof o.blast_radius === "string" && o.blast_radius.trim().length > 0
      ? o.blast_radius.trim()
      : null;
  if (!blastRadius) return null;
  const rationale =
    typeof o.rationale === "string" ? o.rationale.trim() : "";

  return {
    reachability_tier: o.reachability_tier,
    blast_radius: blastRadius,
    weaponizability: o.weaponizability,
    business_impact: o.business_impact,
    rationale,
  };
}

// ────────────────────────────────────────────────────────────────────
// Deterministic heuristic (baseline + fallback)
// ────────────────────────────────────────────────────────────────────

/**
 * Category → default weaponizability. Coarse, but enough for a fallback when no
 * model is available or the model response is unusable.
 */
const CATEGORY_WEAPONIZABILITY: Partial<Record<string, Weaponizability>> = {
  "sql-injection": "rce",
  "command-injection": "rce",
  "code-injection": "rce",
  "unsafe-deserialization": "rce",
  ssrf: "info-leak",
  "path-traversal": "info-leak",
  "information-disclosure": "info-leak",
  xss: "info-leak",
  "regex-dos": "dos-crash",
};

const SEVERITY_TO_IMPACT: Record<string, BusinessImpact> = {
  critical: "headline",
  high: "notable",
  medium: "modest",
  low: "noise",
  info: "noise",
};

/**
 * Deterministic, network-free impact assessment from the coarse signals a
 * finding always carries. Used as the baseline when no runtime is injected and
 * as the fallback when an LLM assessment fails to parse. Conservative: it never
 * invents a `remote-unauth` headline it can't justify from the fields.
 */
export function heuristicImpact(finding: Finding): ImpactAssessment {
  const weaponizability: Weaponizability =
    CATEGORY_WEAPONIZABILITY[finding.category] ?? "dos-crash";
  const business_impact: BusinessImpact =
    SEVERITY_TO_IMPACT[finding.severity] ?? "modest";
  return {
    // Unknown positioning from static fields alone — assume a local unprivileged
    // attacker (neither the best nor worst case) rather than over/under-claiming.
    reachability_tier: "local-unpriv",
    blast_radius: `heuristic baseline for a ${finding.severity} ${finding.category} finding`,
    weaponizability,
    business_impact,
    rationale:
      "Deterministic fallback derived from severity + category (no model assessment available).",
  };
}

// ────────────────────────────────────────────────────────────────────
// Public API — assessImpact
// ────────────────────────────────────────────────────────────────────

/**
 * Assess the real business impact of a finding.
 *
 * Routes an LLM assessment through the injected {@link NativeRuntime} (no raw
 * keys). Falls back to {@link heuristicImpact} when no runtime is provided, the
 * model is unavailable, or the response is unparseable — so the function is
 * total (never throws, always returns an assessment).
 */
export async function assessImpact(
  finding: Finding,
  options: AssessImpactOptions = {},
): Promise<ImpactAssessment> {
  const runtime = options.runtime;
  if (!runtime) return heuristicImpact(finding);

  try {
    const result = await runtime.executeNative(
      SYSTEM_PROMPT,
      [{ role: "user", content: [{ type: "text", text: buildUserMessage(finding) }] }],
      [], // no tools
    );
    if (result.error) return heuristicImpact(finding);
    const textBlock = result.content.find((b) => b.type === "text");
    if (!textBlock || textBlock.type !== "text") return heuristicImpact(finding);
    const parsed = parseImpactAssessment(textBlock.text);
    return parsed ?? heuristicImpact(finding);
  } catch {
    return heuristicImpact(finding);
  }
}

// ────────────────────────────────────────────────────────────────────
// Mapping + ranking (persistence + self-prioritization)
// ────────────────────────────────────────────────────────────────────

/**
 * Map an {@link ImpactAssessment} to the value persisted in the
 * `findings.impact_assessment` jsonb column. A field whitelist (not a
 * pass-through) so an over-eager model can't smuggle extra keys into storage.
 */
export function impactAssessmentToColumn(
  assessment: ImpactAssessment,
): ImpactAssessment {
  return {
    reachability_tier: assessment.reachability_tier,
    blast_radius: assessment.blast_radius,
    weaponizability: assessment.weaponizability,
    business_impact: assessment.business_impact,
    rationale: assessment.rationale,
  };
}

/**
 * The coarse ranking tier for a finding. Reads the computed assessment when
 * present; findings not yet assessed rank as `modest` (neutral — neither
 * escalated nor deprioritized) so they don't jump the queue or get buried.
 */
export function businessImpactOf(finding: Finding): BusinessImpact {
  return finding.impactAssessment?.business_impact ?? "modest";
}

/**
 * Numeric ranking weight for a finding's business impact — higher sorts first.
 * The engine's self-prioritization sorts descending on this so `headline`
 * findings surface and `noise` sinks.
 */
export function impactRank(finding: Finding): number {
  return BUSINESS_IMPACT_RANK[businessImpactOf(finding)];
}

/**
 * Comparator that orders findings most→least impactful (headline first, noise
 * last). Stable for equal ranks. Use with `Array.prototype.sort`.
 */
export function compareByImpactDesc(a: Finding, b: Finding): number {
  return impactRank(b) - impactRank(a);
}
