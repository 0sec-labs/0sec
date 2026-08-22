import type { AttackCategory, Finding, ReachabilityTier, Severity } from "@0sec/shared";

export interface CvssSuggestion {
  vector: string;
  score: number;
  /**
   * Where the exploitability metrics came from:
   *   - "finding" — the agent already emitted a full vector + score; used verbatim.
   *   - "impact-assessment" — AV/PR/UI derived from the finding's
   *     `impactAssessment.reachability_tier` (a real assessment of how the
   *     attacker must be positioned), impact metrics from category.
   *   - "heuristic" — no assessment present; AV/UI default to network/none and
   *     PR is floored from severity. A first-pass guess, not a measurement.
   */
  source: "finding" | "impact-assessment" | "heuristic";
}

// Heuristic: pick impact (C/I/A) from category, privilege-required from severity
// floor, and default reachability to network. The operator can override in the
// GHSA editor; this is a first-pass suggestion, not an authoritative score.
const IMPACT_BY_CATEGORY: Record<AttackCategory, { C: "N" | "L" | "H"; I: "N" | "L" | "H"; A: "N" | "L" | "H"; scope: "U" | "C" }> = {
  "prompt-injection":        { C: "L", I: "L", A: "N", scope: "U" },
  "jailbreak":               { C: "L", I: "L", A: "N", scope: "U" },
  "system-prompt-extraction":{ C: "H", I: "N", A: "N", scope: "U" },
  "data-exfiltration":       { C: "H", I: "N", A: "N", scope: "C" },
  "tool-misuse":             { C: "H", I: "H", A: "L", scope: "C" },
  "output-manipulation":     { C: "L", I: "H", A: "N", scope: "U" },
  "encoding-bypass":         { C: "L", I: "L", A: "N", scope: "U" },
  "multi-turn":              { C: "L", I: "L", A: "N", scope: "U" },
  "prototype-pollution":     { C: "H", I: "H", A: "H", scope: "U" },
  "path-traversal":          { C: "H", I: "H", A: "L", scope: "U" },
  "command-injection":       { C: "H", I: "H", A: "H", scope: "U" },
  "code-injection":          { C: "H", I: "H", A: "H", scope: "U" },
  "regex-dos":               { C: "N", I: "N", A: "H", scope: "U" },
  "unsafe-deserialization":  { C: "H", I: "H", A: "H", scope: "U" },
  "information-disclosure":  { C: "H", I: "N", A: "N", scope: "C" },
  "ssrf":                    { C: "H", I: "N", A: "N", scope: "C" },
  "sql-injection":           { C: "H", I: "H", A: "H", scope: "U" },
  "xss":                     { C: "L", I: "L", A: "N", scope: "C" },
  "cors":                    { C: "L", I: "L", A: "N", scope: "U" },
  "security-misconfiguration": { C: "L", I: "L", A: "N", scope: "U" },
  "missing-validation":      { C: "L", I: "L", A: "L", scope: "U" },
  "crypto-misuse":           { C: "H", I: "H", A: "N", scope: "U" },
  "heap-overflow":           { C: "H", I: "H", A: "H", scope: "U" },
  "out-of-bounds-read":      { C: "H", I: "N", A: "L", scope: "U" },
  "out-of-bounds-write":     { C: "H", I: "H", A: "H", scope: "U" },
  "use-after-free":          { C: "H", I: "H", A: "H", scope: "U" },
  "stack-buffer-overflow":   { C: "H", I: "H", A: "H", scope: "U" },
  "null-pointer-deref":      { C: "N", I: "N", A: "H", scope: "U" },
  "null-deref":              { C: "N", I: "N", A: "H", scope: "U" },
  "integer-overflow":        { C: "L", I: "L", A: "L", scope: "U" },
  "integer-truncation":      { C: "L", I: "L", A: "L", scope: "U" },
  "race-condition":          { C: "L", I: "L", A: "L", scope: "U" },
  "denial-of-service":       { C: "N", I: "N", A: "H", scope: "U" },
  "toctou":                  { C: "L", I: "L", A: "L", scope: "U" },
  "type-confusion":          { C: "H", I: "H", A: "H", scope: "U" },
  "double-free":             { C: "H", I: "H", A: "H", scope: "U" },
  "format-string":           { C: "H", I: "H", A: "H", scope: "U" },
  "uninitialized-memory":    { C: "H", I: "N", A: "L", scope: "U" },
  "known-vulnerable-package":{ C: "L", I: "L", A: "L", scope: "U" },
  "supply-chain":            { C: "H", I: "H", A: "H", scope: "C" },
  "other":                   { C: "L", I: "L", A: "L", scope: "U" },
};

// Metric weights from CVSS 3.1 specification §7.1.
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { N: 0, L: 0.22, H: 0.56 },
};

function roundUp(n: number): number {
  return Math.ceil(n * 10) / 10;
}

// Minimal CVSS 3.1 base-score implementation — enough to produce a
// consistent number for the suggested vector. See the spec for edge cases;
// we keep only the common path.
function computeBaseScore(av: keyof typeof W.AV, ac: keyof typeof W.AC, pr: "N" | "L" | "H", ui: "N" | "R", scope: "U" | "C", c: "N" | "L" | "H", i: "N" | "L" | "H", a: "N" | "L" | "H"): number {
  const iss = 1 - (1 - W.CIA[c]) * (1 - W.CIA[i]) * (1 - W.CIA[a]);
  const impact = scope === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const prWeight = (scope === "C" ? W.PR_C : W.PR_U)[pr];
  const exploit = 8.22 * W.AV[av] * W.AC[ac] * prWeight * W.UI[ui];
  if (impact <= 0) return 0;
  const base = scope === "U" ? Math.min(impact + exploit, 10) : Math.min(1.08 * (impact + exploit), 10);
  return roundUp(base);
}

// Map finding severity (already emitted by the agent) to the CVSS
// privileges-required metric. Fresh-signup or no-auth findings would need an
// explicit override in the advisory.
function prForSeverity(severity: Severity): "N" | "L" | "H" {
  switch (severity) {
    case "critical":
      return "N";
    case "high":
      return "L";
    case "medium":
    case "low":
      return "L";
    default:
      return "H";
  }
}

/**
 * Derive the CVSS exploitability metrics (Attack Vector, Privileges Required,
 * User Interaction) from a real reachability assessment — "how must the
 * attacker be positioned to reach the sink". This is exactly the
 * attack-prerequisites axis that severity + category cannot express, which is
 * why an assessed finding gets a materially better vector than the heuristic
 * one. Impact metrics (C/I/A/S) still come from category; reachability speaks
 * only to exploitability.
 *
 * The mapping is intentionally conservative at the edges (RF proximity → the
 * Adjacent vector rather than Network; a hardware requirement → Physical), so a
 * derived score never over-claims reach relative to the heuristic default.
 */
function metricsForReachability(
  tier: ReachabilityTier,
): { av: keyof typeof W.AV; pr: "N" | "L" | "H"; ui: "N" | "R" } {
  switch (tier) {
    case "remote-unauth":
      return { av: "N", pr: "N", ui: "N" };
    case "proximity-rf":
      return { av: "A", pr: "N", ui: "N" };
    case "local-unpriv":
      return { av: "L", pr: "L", ui: "N" };
    case "local-priv":
      return { av: "L", pr: "H", ui: "N" };
    case "needs-hardware":
      return { av: "P", pr: "N", ui: "N" };
    case "needs-host-migration":
      // The victim must mount / import an attacker-supplied artifact: a local
      // vector that requires user interaction and no attacker privileges.
      return { av: "L", pr: "N", ui: "R" };
  }
}

export function suggestCvss(finding: Finding): CvssSuggestion {
  if (finding.cvssVector && finding.cvssScore !== undefined) {
    return { vector: finding.cvssVector, score: finding.cvssScore, source: "finding" };
  }
  const impact = IMPACT_BY_CATEGORY[finding.category] ?? { C: "L", I: "L", A: "L", scope: "U" as const };
  const ac = "L" as const;

  // Strictly additive: only a finding that carries a real reachability
  // assessment departs from the historic default. A finding without one
  // produces the exact same vector it always did (AV:N / UI:N / PR-from-
  // severity), so every caller and pinned test is unaffected.
  const assessed = finding.impactAssessment
    ? metricsForReachability(finding.impactAssessment.reachability_tier)
    : undefined;
  const av = assessed?.av ?? ("N" as const);
  const pr = assessed?.pr ?? prForSeverity(finding.severity);
  const ui = assessed?.ui ?? ("N" as const);

  const vector = `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${impact.scope}/C:${impact.C}/I:${impact.I}/A:${impact.A}`;
  const score = computeBaseScore(av, ac, pr, ui, impact.scope, impact.C, impact.I, impact.A);
  return { vector, score, source: assessed ? "impact-assessment" : "heuristic" };
}

// ─────────────────────────────────────────────────────────────────────────────
// CVSS 4.0
// ─────────────────────────────────────────────────────────────────────────────
//
// A faithful, dependency-free TypeScript port of the official FIRST.org CVSS
// v4.0 base-score algorithm (the "MacroVector" method): the vector is mapped to
// a 6-digit macrovector, its base score is read from the published lookup
// table, and the final score is interpolated by the severity distance to the
// highest-severity vector in the same macrovector, normalized against the
// maximal scoring difference to the next-lower macrovector.
//
// Source of truth: https://github.com/FIRSTdotorg/cvss-v4-calculator
//   - cvss_lookup.js (cvssLookup_global) — CVSS40_LOOKUP below
//   - max_composed.js (maxComposed)      — CVSS40_MAX_COMPOSED below
//   - max_severity.js (maxSeverity)      — CVSS40_MAX_SEVERITY below
//   - cvss_score.js (m/macroVector/cvss_score) — ported verbatim below
//
// The 3.1 support above is untouched. This block is strictly additive.

/** Base (mandatory) CVSS 4.0 metric keys. */
export type Cvss4BaseKey =
  | "AV" | "AC" | "AT" | "PR" | "UI"
  | "VC" | "VI" | "VA" | "SC" | "SI" | "SA";

/** A parsed, validated CVSS 4.0 selection (metric short-code → value). */
export type Cvss4Selection = Record<string, string>;

export interface Cvss4Score {
  /** The (re-normalized) vector string, always prefixed `CVSS:4.0/`. */
  vector: string;
  /** Base score 0.0–10.0, rounded to one decimal per spec. */
  score: number;
  /** Qualitative rating from the CVSS 4.0 severity-rating scale. */
  severity: "None" | "Low" | "Medium" | "High" | "Critical";
  /** The 6-digit macrovector the score was derived from (debug/traceability). */
  macroVector: string;
}

/** Thrown when a CVSS 4.0 vector string is malformed or missing base metrics. */
export class Cvss4ParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "Cvss4ParseError";
  }
}

// Allowed values per metric. Base metrics are mandatory; threat (E),
// environmental (CR/IR/AR + modified M*), and supplemental metrics are optional
// and — except where the algorithm reads them — do not change the base score.
const CVSS4_ALLOWED: Record<string, ReadonlySet<string>> = {
  AV: new Set(["N", "A", "L", "P"]),
  AC: new Set(["L", "H"]),
  AT: new Set(["N", "P"]),
  PR: new Set(["N", "L", "H"]),
  UI: new Set(["N", "P", "A"]),
  VC: new Set(["H", "L", "N"]),
  VI: new Set(["H", "L", "N"]),
  VA: new Set(["H", "L", "N"]),
  SC: new Set(["H", "L", "N"]),
  SI: new Set(["H", "L", "N"]),
  SA: new Set(["H", "L", "N"]),
  // Threat
  E: new Set(["X", "A", "P", "U"]),
  // Environmental (requirements)
  CR: new Set(["X", "H", "M", "L"]),
  IR: new Set(["X", "H", "M", "L"]),
  AR: new Set(["X", "H", "M", "L"]),
  // Environmental (modified base)
  MAV: new Set(["X", "N", "A", "L", "P"]),
  MAC: new Set(["X", "L", "H"]),
  MAT: new Set(["X", "N", "P"]),
  MPR: new Set(["X", "N", "L", "H"]),
  MUI: new Set(["X", "N", "P", "A"]),
  MVC: new Set(["X", "H", "L", "N"]),
  MVI: new Set(["X", "H", "L", "N"]),
  MVA: new Set(["X", "H", "L", "N"]),
  MSC: new Set(["X", "H", "L", "N"]),
  MSI: new Set(["X", "S", "H", "L", "N"]),
  MSA: new Set(["X", "S", "H", "L", "N"]),
  // Supplemental (do not affect score)
  S: new Set(["X", "N", "P"]),
  AU: new Set(["X", "N", "Y"]),
  R: new Set(["X", "A", "U", "I"]),
  V: new Set(["X", "D", "C"]),
  RE: new Set(["X", "L", "M", "H"]),
  U: new Set(["X", "Clear", "Green", "Amber", "Red"]),
};

const CVSS4_BASE_KEYS: readonly Cvss4BaseKey[] = [
  "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
];

// Metric-value → ordinal level. Lower level = higher severity contribution.
// Verbatim from cvss_score.js.
const AV_levels: Record<string, number> = { N: 0.0, A: 0.1, L: 0.2, P: 0.3 };
const PR_levels: Record<string, number> = { N: 0.0, L: 0.1, H: 0.2 };
const UI_levels: Record<string, number> = { N: 0.0, P: 0.1, A: 0.2 };
const AC_levels: Record<string, number> = { L: 0.0, H: 0.1 };
const AT_levels: Record<string, number> = { N: 0.0, P: 0.1 };
const VC_levels: Record<string, number> = { H: 0.0, L: 0.1, N: 0.2 };
const VI_levels: Record<string, number> = { H: 0.0, L: 0.1, N: 0.2 };
const VA_levels: Record<string, number> = { H: 0.0, L: 0.1, N: 0.2 };
const SC_levels: Record<string, number> = { H: 0.1, L: 0.2, N: 0.3 };
const SI_levels: Record<string, number> = { S: 0.0, H: 0.1, L: 0.2, N: 0.3 };
const SA_levels: Record<string, number> = { S: 0.0, H: 0.1, L: 0.2, N: 0.3 };
const CR_levels: Record<string, number> = { H: 0.0, M: 0.1, L: 0.2 };
const IR_levels: Record<string, number> = { H: 0.0, M: 0.1, L: 0.2 };
const AR_levels: Record<string, number> = { H: 0.0, M: 0.1, L: 0.2 };

// The published CVSS 4.0 macrovector → base-score lookup (cvssLookup_global).
const CVSS40_LOOKUP: Record<string, number> = {
  "000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2, "000100": 10, "000101": 9.6, "000110": 9.3,
  "000111": 8.7, "000120": 9.1, "000121": 8.1, "000200": 9.3, "000201": 9, "000210": 8.9, "000211": 8, "000220": 8.1, "000221": 6.8,
  "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4, "001100": 9.3, "001101": 9.2, "001110": 8.9,
  "001111": 8.1, "001120": 8.1, "001121": 6.5, "001200": 8.8, "001201": 8, "001210": 7.8, "001211": 7, "001220": 6.9, "001221": 4.8,
  "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9, "002111": 6.9, "002121": 5, "002201": 6.9, "002211": 5.5, "002221": 2.7,
  "010000": 9.9, "010001": 9.7, "010010": 9.5, "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9,
  "010111": 8.3, "010120": 8.4, "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2, "010211": 7.1, "010220": 7.2, "010221": 5.3,
  "011000": 9.5, "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8,
  "011111": 7.2, "011120": 7, "011121": 5.9, "011200": 8.4, "011201": 7, "011210": 7.1, "011211": 5.2, "011220": 5, "011221": 3,
  "012001": 8.6, "012011": 7.5, "012021": 5.2, "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3, "012211": 2.9, "012221": 1.7,
  "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1, "100100": 9.4, "100101": 8.9, "100110": 8.6,
  "100111": 7.4, "100120": 7.7, "100121": 6.4, "100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
  "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7, "101100": 8.6, "101101": 7.6, "101110": 7.4,
  "101111": 5.8, "101120": 5.9, "101121": 5, "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5,
  "102001": 8.3, "102011": 7, "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6, "102201": 5.3, "102211": 2.1, "102221": 1.3,
  "110000": 9.5, "110001": 9, "110010": 8.8, "110011": 7.6, "110020": 7.6, "110021": 7, "110100": 9, "110101": 7.7, "110110": 7.5,
  "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2, "110221": 3,
  "111000": 8.9, "111001": 7.8, "111010": 7.6, "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4, "111101": 5.9, "111110": 5.7,
  "111111": 5.7, "111120": 4.7, "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7, "111211": 2.9, "111220": 2.4, "111221": 1.6,
  "112001": 7.1, "112011": 5.9, "112021": 3, "112101": 5.8, "112111": 2.6, "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
  "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8, "200100": 8.6, "200101": 7.4, "200110": 7.4,
  "200111": 6.1, "200120": 5.6, "200121": 3.4, "200200": 7, "200201": 5.4, "200210": 5.2, "200211": 4, "200220": 4, "200221": 2.2,
  "201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1, "201100": 7.2, "201101": 5.7, "201110": 5.5,
  "201111": 4.1, "201120": 4.6, "201121": 1.9, "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
  "202001": 6.4, "202011": 5.1, "202021": 2, "202101": 4.7, "202111": 2.1, "202121": 1.1, "202201": 2.4, "202211": 0.9, "202221": 0.4,
  "210000": 8.8, "210001": 7.5, "210010": 7.3, "210011": 5.3, "210020": 6, "210021": 5, "210100": 7.3, "210101": 5.5, "210110": 5.9,
  "210111": 4, "210120": 4.1, "210121": 2, "210200": 5.4, "210201": 4.3, "210210": 4.5, "210211": 2.2, "210220": 2, "210221": 1.1,
  "211000": 7.5, "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4, "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8,
  "211111": 1.8, "211120": 2, "211121": 0.9, "211200": 4.6, "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8, "211221": 0.2,
  "212001": 5.3, "212011": 2.4, "212021": 1.4, "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1, "212211": 0.3, "212221": 0.1,
};

// maxComposed: highest-severity vectors composing each EQ level (max_composed.js).
const CVSS40_MAX_COMPOSED: {
  eq1: Record<number, string[]>;
  eq2: Record<number, string[]>;
  eq3: Record<number, Record<string, string[]>>;
  eq4: Record<number, string[]>;
  eq5: Record<number, string[]>;
} = {
  eq1: {
    0: ["AV:N/PR:N/UI:N/"],
    1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
    2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
  },
  eq2: {
    0: ["AC:L/AT:N/"],
    1: ["AC:H/AT:N/", "AC:L/AT:P/"],
  },
  eq3: {
    0: { "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"], "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"] },
    1: { "0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"], "1": ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"] },
    2: { "1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"] },
  },
  eq4: {
    0: ["SC:H/SI:S/SA:S/"],
    1: ["SC:H/SI:H/SA:H/"],
    2: ["SC:L/SI:L/SA:L/"],
  },
  eq5: {
    0: ["E:A/"],
    1: ["E:P/"],
    2: ["E:U/"],
  },
};

// maxSeverity: max severity distances (+1) per EQ level (max_severity.js).
const CVSS40_MAX_SEVERITY: {
  eq1: Record<number, number>;
  eq2: Record<number, number>;
  eq3eq6: Record<number, Record<number, number>>;
  eq4: Record<number, number>;
  eq5: Record<number, number>;
} = {
  eq1: { 0: 1, 1: 4, 2: 5 },
  eq2: { 0: 1, 1: 2 },
  eq3eq6: { 0: { 0: 7, 1: 6 }, 1: { 0: 8, 1: 8 }, 2: { 1: 10 } },
  eq4: { 0: 6, 1: 5, 2: 4 },
  eq5: { 0: 1, 1: 1, 2: 1 },
};

/**
 * Resolve the effective value of a metric, applying the spec's default rules:
 * E:X → A (worst case), CR/IR/AR:X → H (worst case), and any modified metric
 * (`M<metric>`) overrides its base when present and not X. Ported from `m()`.
 */
function m4(sel: Cvss4Selection, metric: string): string {
  const selected = sel[metric];
  if (metric === "E" && (selected === undefined || selected === "X")) return "A";
  if (
    (metric === "CR" || metric === "IR" || metric === "AR") &&
    (selected === undefined || selected === "X")
  ) {
    return "H";
  }
  const modified = sel["M" + metric];
  if (modified !== undefined && modified !== "X") return modified;
  return selected ?? "";
}

/** Compute the 6-digit macrovector for a selection. Ported from `macroVector()`. */
function cvss4MacroVector(sel: Cvss4Selection): string {
  // EQ1
  let eq1: string;
  if (m4(sel, "AV") === "N" && m4(sel, "PR") === "N" && m4(sel, "UI") === "N") {
    eq1 = "0";
  } else if (
    (m4(sel, "AV") === "N" || m4(sel, "PR") === "N" || m4(sel, "UI") === "N") &&
    !(m4(sel, "AV") === "N" && m4(sel, "PR") === "N" && m4(sel, "UI") === "N") &&
    m4(sel, "AV") !== "P"
  ) {
    eq1 = "1";
  } else {
    eq1 = "2";
  }

  // EQ2
  const eq2 = m4(sel, "AC") === "L" && m4(sel, "AT") === "N" ? "0" : "1";

  // EQ3
  let eq3: string;
  if (m4(sel, "VC") === "H" && m4(sel, "VI") === "H") {
    eq3 = "0";
  } else if (
    !(m4(sel, "VC") === "H" && m4(sel, "VI") === "H") &&
    (m4(sel, "VC") === "H" || m4(sel, "VI") === "H" || m4(sel, "VA") === "H")
  ) {
    eq3 = "1";
  } else {
    eq3 = "2";
  }

  // EQ4
  let eq4: string;
  if (m4(sel, "MSI") === "S" || m4(sel, "MSA") === "S") {
    eq4 = "0";
  } else if (m4(sel, "SC") === "H" || m4(sel, "SI") === "H" || m4(sel, "SA") === "H") {
    eq4 = "1";
  } else {
    eq4 = "2";
  }

  // EQ5
  let eq5: string;
  if (m4(sel, "E") === "A") eq5 = "0";
  else if (m4(sel, "E") === "P") eq5 = "1";
  else eq5 = "2";

  // EQ6
  const eq6 =
    (m4(sel, "CR") === "H" && m4(sel, "VC") === "H") ||
    (m4(sel, "IR") === "H" && m4(sel, "VI") === "H") ||
    (m4(sel, "AR") === "H" && m4(sel, "VA") === "H")
      ? "0"
      : "1";

  return eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
}

function cvss4EqMaxes(macro: string, eq: 1 | 2 | 4 | 5): string[] {
  const idx = Number(macro[eq - 1]);
  if (eq === 1) return CVSS40_MAX_COMPOSED.eq1[idx];
  if (eq === 2) return CVSS40_MAX_COMPOSED.eq2[idx];
  if (eq === 4) return CVSS40_MAX_COMPOSED.eq4[idx];
  return CVSS40_MAX_COMPOSED.eq5[idx];
}

function extractValueMetric(metric: string, str: string): string {
  const start = str.indexOf(metric) + metric.length + 1;
  const extracted = str.slice(start);
  const slash = extracted.indexOf("/");
  return slash > 0 ? extracted.substring(0, slash) : extracted;
}

/**
 * Core CVSS 4.0 base-score computation from a parsed selection. This is a
 * faithful port of `cvss_score()` from the FIRST reference implementation.
 * Returns 0.0–10.0 rounded to one decimal.
 */
export function computeCvss4BaseScore(sel: Cvss4Selection): number {
  // Exception for no impact on system (shortcut).
  if (["VC", "VI", "VA", "SC", "SI", "SA"].every((metric) => m4(sel, metric) === "N")) {
    return 0.0;
  }

  const macroVectorResult = cvss4MacroVector(sel);
  let value = CVSS40_LOOKUP[macroVectorResult];

  const eq1 = parseInt(macroVectorResult[0], 10);
  const eq2 = parseInt(macroVectorResult[1], 10);
  const eq3 = parseInt(macroVectorResult[2], 10);
  const eq4 = parseInt(macroVectorResult[3], 10);
  const eq5 = parseInt(macroVectorResult[4], 10);
  const eq6 = parseInt(macroVectorResult[5], 10);

  const eq1_next_lower_macro = `${eq1 + 1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
  const eq2_next_lower_macro = `${eq1}${eq2 + 1}${eq3}${eq4}${eq5}${eq6}`;

  let eq3eq6_next_lower_macro = "";
  let eq3eq6_next_lower_macro_left = "";
  let eq3eq6_next_lower_macro_right = "";
  if (eq3 === 1 && eq6 === 1) {
    eq3eq6_next_lower_macro = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`;
  } else if (eq3 === 0 && eq6 === 1) {
    eq3eq6_next_lower_macro = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`;
  } else if (eq3 === 1 && eq6 === 0) {
    eq3eq6_next_lower_macro = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6 + 1}`;
  } else if (eq3 === 0 && eq6 === 0) {
    eq3eq6_next_lower_macro_left = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6 + 1}`;
    eq3eq6_next_lower_macro_right = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`;
  } else {
    eq3eq6_next_lower_macro = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6 + 1}`;
  }

  const eq4_next_lower_macro = `${eq1}${eq2}${eq3}${eq4 + 1}${eq5}${eq6}`;
  const eq5_next_lower_macro = `${eq1}${eq2}${eq3}${eq4}${eq5 + 1}${eq6}`;

  const score_eq1_next_lower_macro = CVSS40_LOOKUP[eq1_next_lower_macro];
  const score_eq2_next_lower_macro = CVSS40_LOOKUP[eq2_next_lower_macro];

  let score_eq3eq6_next_lower_macro: number;
  if (eq3 === 0 && eq6 === 0) {
    const left = CVSS40_LOOKUP[eq3eq6_next_lower_macro_left];
    const right = CVSS40_LOOKUP[eq3eq6_next_lower_macro_right];
    score_eq3eq6_next_lower_macro = left > right ? left : right;
  } else {
    score_eq3eq6_next_lower_macro = CVSS40_LOOKUP[eq3eq6_next_lower_macro];
  }

  const score_eq4_next_lower_macro = CVSS40_LOOKUP[eq4_next_lower_macro];
  const score_eq5_next_lower_macro = CVSS40_LOOKUP[eq5_next_lower_macro];

  const eq1_maxes = cvss4EqMaxes(macroVectorResult, 1);
  const eq2_maxes = cvss4EqMaxes(macroVectorResult, 2);
  const eq3_eq6_maxes = CVSS40_MAX_COMPOSED.eq3[eq3][macroVectorResult[5]];
  const eq4_maxes = cvss4EqMaxes(macroVectorResult, 4);
  const eq5_maxes = cvss4EqMaxes(macroVectorResult, 5);

  const max_vectors: string[] = [];
  for (const a of eq1_maxes)
    for (const b of eq2_maxes)
      for (const c of eq3_eq6_maxes)
        for (const d of eq4_maxes)
          for (const e of eq5_maxes) max_vectors.push(a + b + c + d + e);

  let severity_distance_AV = 0, severity_distance_PR = 0, severity_distance_UI = 0;
  let severity_distance_AC = 0, severity_distance_AT = 0;
  let severity_distance_VC = 0, severity_distance_VI = 0, severity_distance_VA = 0;
  let severity_distance_SC = 0, severity_distance_SI = 0, severity_distance_SA = 0;
  let severity_distance_CR = 0, severity_distance_IR = 0, severity_distance_AR = 0;

  for (const max_vector of max_vectors) {
    severity_distance_AV = AV_levels[m4(sel, "AV")] - AV_levels[extractValueMetric("AV", max_vector)];
    severity_distance_PR = PR_levels[m4(sel, "PR")] - PR_levels[extractValueMetric("PR", max_vector)];
    severity_distance_UI = UI_levels[m4(sel, "UI")] - UI_levels[extractValueMetric("UI", max_vector)];
    severity_distance_AC = AC_levels[m4(sel, "AC")] - AC_levels[extractValueMetric("AC", max_vector)];
    severity_distance_AT = AT_levels[m4(sel, "AT")] - AT_levels[extractValueMetric("AT", max_vector)];
    severity_distance_VC = VC_levels[m4(sel, "VC")] - VC_levels[extractValueMetric("VC", max_vector)];
    severity_distance_VI = VI_levels[m4(sel, "VI")] - VI_levels[extractValueMetric("VI", max_vector)];
    severity_distance_VA = VA_levels[m4(sel, "VA")] - VA_levels[extractValueMetric("VA", max_vector)];
    severity_distance_SC = SC_levels[m4(sel, "SC")] - SC_levels[extractValueMetric("SC", max_vector)];
    severity_distance_SI = SI_levels[m4(sel, "SI")] - SI_levels[extractValueMetric("SI", max_vector)];
    severity_distance_SA = SA_levels[m4(sel, "SA")] - SA_levels[extractValueMetric("SA", max_vector)];
    severity_distance_CR = CR_levels[m4(sel, "CR")] - CR_levels[extractValueMetric("CR", max_vector)];
    severity_distance_IR = IR_levels[m4(sel, "IR")] - IR_levels[extractValueMetric("IR", max_vector)];
    severity_distance_AR = AR_levels[m4(sel, "AR")] - AR_levels[extractValueMetric("AR", max_vector)];

    const anyNegative = [
      severity_distance_AV, severity_distance_PR, severity_distance_UI,
      severity_distance_AC, severity_distance_AT,
      severity_distance_VC, severity_distance_VI, severity_distance_VA,
      severity_distance_SC, severity_distance_SI, severity_distance_SA,
      severity_distance_CR, severity_distance_IR, severity_distance_AR,
    ].some((v) => v < 0);
    if (anyNegative) continue;
    break;
  }

  const current_severity_distance_eq1 = severity_distance_AV + severity_distance_PR + severity_distance_UI;
  const current_severity_distance_eq2 = severity_distance_AC + severity_distance_AT;
  const current_severity_distance_eq3eq6 =
    severity_distance_VC + severity_distance_VI + severity_distance_VA +
    severity_distance_CR + severity_distance_IR + severity_distance_AR;
  const current_severity_distance_eq4 = severity_distance_SC + severity_distance_SI + severity_distance_SA;

  const step = 0.1;

  const available_distance_eq1 = value - score_eq1_next_lower_macro;
  const available_distance_eq2 = value - score_eq2_next_lower_macro;
  const available_distance_eq3eq6 = value - score_eq3eq6_next_lower_macro;
  const available_distance_eq4 = value - score_eq4_next_lower_macro;
  const available_distance_eq5 = value - score_eq5_next_lower_macro;

  let n_existing_lower = 0;
  let normalized_severity_eq1 = 0;
  let normalized_severity_eq2 = 0;
  let normalized_severity_eq3eq6 = 0;
  let normalized_severity_eq4 = 0;
  let normalized_severity_eq5 = 0;

  const maxSeverity_eq1 = CVSS40_MAX_SEVERITY.eq1[eq1] * step;
  const maxSeverity_eq2 = CVSS40_MAX_SEVERITY.eq2[eq2] * step;
  const maxSeverity_eq3eq6 = CVSS40_MAX_SEVERITY.eq3eq6[eq3][eq6] * step;
  const maxSeverity_eq4 = CVSS40_MAX_SEVERITY.eq4[eq4] * step;

  if (!Number.isNaN(available_distance_eq1)) {
    n_existing_lower += 1;
    normalized_severity_eq1 = available_distance_eq1 * (current_severity_distance_eq1 / maxSeverity_eq1);
  }
  if (!Number.isNaN(available_distance_eq2)) {
    n_existing_lower += 1;
    normalized_severity_eq2 = available_distance_eq2 * (current_severity_distance_eq2 / maxSeverity_eq2);
  }
  if (!Number.isNaN(available_distance_eq3eq6)) {
    n_existing_lower += 1;
    normalized_severity_eq3eq6 = available_distance_eq3eq6 * (current_severity_distance_eq3eq6 / maxSeverity_eq3eq6);
  }
  if (!Number.isNaN(available_distance_eq4)) {
    n_existing_lower += 1;
    normalized_severity_eq4 = available_distance_eq4 * (current_severity_distance_eq4 / maxSeverity_eq4);
  }
  if (!Number.isNaN(available_distance_eq5)) {
    n_existing_lower += 1;
    // eq5 percentage is always 0.
    normalized_severity_eq5 = available_distance_eq5 * 0;
  }

  let mean_distance: number;
  if (n_existing_lower === 0) {
    mean_distance = 0;
  } else {
    mean_distance =
      (normalized_severity_eq1 + normalized_severity_eq2 + normalized_severity_eq3eq6 +
        normalized_severity_eq4 + normalized_severity_eq5) / n_existing_lower;
  }

  value -= mean_distance;
  if (value < 0) value = 0.0;
  if (value > 10) value = 10.0;
  return Math.round(value * 10) / 10;
}

/** The CVSS 4.0 qualitative severity-rating scale. */
export function cvss4Severity(score: number): Cvss4Score["severity"] {
  if (score <= 0) return "None";
  if (score < 4.0) return "Low";
  if (score < 7.0) return "Medium";
  if (score < 9.0) return "High";
  return "Critical";
}

const CVSS4_METRIC_ORDER: readonly string[] = [
  "AV", "AC", "AT", "PR", "UI",
  "VC", "VI", "VA", "SC", "SI", "SA",
  "E", "CR", "IR", "AR",
  "MAV", "MAC", "MAT", "MPR", "MUI",
  "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
  "S", "AU", "R", "V", "RE", "U",
];

/**
 * Parse and validate a CVSS 4.0 vector string into a metric selection. Throws
 * {@link Cvss4ParseError} on a bad prefix, unknown metric, illegal value, a
 * duplicate metric, or a missing mandatory base metric.
 */
export function parseCvss4Vector(vector: string): Cvss4Selection {
  const trimmed = vector.trim();
  if (!trimmed.startsWith("CVSS:4.0/")) {
    throw new Cvss4ParseError(`Not a CVSS 4.0 vector (must start with "CVSS:4.0/"): ${vector}`);
  }
  const body = trimmed.slice("CVSS:4.0/".length);
  const parts = body.split("/").filter((p) => p.length > 0);
  if (parts.length === 0) {
    throw new Cvss4ParseError(`CVSS 4.0 vector has no metrics: ${vector}`);
  }
  const sel: Cvss4Selection = {};
  for (const part of parts) {
    const eq = part.indexOf(":");
    if (eq < 0) throw new Cvss4ParseError(`Malformed metric segment "${part}" in ${vector}`);
    const key = part.slice(0, eq);
    const val = part.slice(eq + 1);
    const allowed = CVSS4_ALLOWED[key];
    if (!allowed) throw new Cvss4ParseError(`Unknown CVSS 4.0 metric "${key}" in ${vector}`);
    if (!allowed.has(val)) {
      throw new Cvss4ParseError(`Illegal value "${val}" for metric "${key}" in ${vector}`);
    }
    if (key in sel) throw new Cvss4ParseError(`Duplicate metric "${key}" in ${vector}`);
    sel[key] = val;
  }
  for (const base of CVSS4_BASE_KEYS) {
    if (!(base in sel)) {
      throw new Cvss4ParseError(`Missing mandatory base metric "${base}" in ${vector}`);
    }
  }
  return sel;
}

/** Re-emit a selection as a canonical, ordered CVSS 4.0 vector string. */
export function formatCvss4Vector(sel: Cvss4Selection): string {
  const segs: string[] = [];
  for (const key of CVSS4_METRIC_ORDER) {
    const v = sel[key];
    if (v !== undefined && v !== "X") segs.push(`${key}:${v}`);
  }
  return `CVSS:4.0/${segs.join("/")}`;
}

/**
 * Parse, validate, score, and rate a CVSS 4.0 vector string in one call.
 * Deterministic and pure. Throws {@link Cvss4ParseError} on a bad vector.
 */
export function scoreCvss4Vector(vector: string): Cvss4Score {
  const sel = parseCvss4Vector(vector);
  const score = computeCvss4BaseScore(sel);
  return {
    vector: formatCvss4Vector(sel),
    score,
    severity: cvss4Severity(score),
    macroVector: cvss4MacroVector(sel),
  };
}

// Derive CVSS 4.0 base metrics from a finding, mirroring the 3.1 heuristic:
// impact (VC/VI/VA) from category, exploitability (AV/AT/PR/UI) from the
// reachability assessment when present. Subsequent-system impact (SC/SI/SA) is
// mapped from the 3.1 scope hint (S:C ⇒ some subsequent impact) so a
// scope-changing category still scores subsequent effects under 4.0's model.
function cvss4MetricsForReachability(
  tier: ReachabilityTier,
): { AV: string; AT: string; PR: string; UI: string } {
  switch (tier) {
    case "remote-unauth":
      return { AV: "N", AT: "N", PR: "N", UI: "N" };
    case "proximity-rf":
      return { AV: "A", AT: "N", PR: "N", UI: "N" };
    case "local-unpriv":
      return { AV: "L", AT: "N", PR: "L", UI: "N" };
    case "local-priv":
      return { AV: "L", AT: "N", PR: "H", UI: "N" };
    case "needs-hardware":
      return { AV: "P", AT: "N", PR: "N", UI: "N" };
    case "needs-host-migration":
      return { AV: "L", AT: "N", PR: "N", UI: "A" };
  }
}

/**
 * Suggest a CVSS 4.0 vector + score for a finding, analogous to
 * {@link suggestCvss} (3.1). Impact metrics come from the finding's category;
 * exploitability from a reachability assessment when present, else a
 * network/none heuristic with PR floored from severity. Additive: never
 * consulted by the 3.1 path.
 */
export function suggestCvss4(finding: Finding): { vector: string; score: number; severity: Cvss4Score["severity"]; source: CvssSuggestion["source"] } {
  const impact = IMPACT_BY_CATEGORY[finding.category] ?? { C: "L", I: "L", A: "L", scope: "U" as const };
  const assessed = finding.impactAssessment
    ? cvss4MetricsForReachability(finding.impactAssessment.reachability_tier)
    : undefined;

  const AV = assessed?.AV ?? "N";
  const AT = assessed?.AT ?? "N";
  const pr31: "N" | "L" | "H" = assessed
    ? (assessed.PR as "N" | "L" | "H")
    : prForSeverity(finding.severity);
  const UI = assessed?.UI ?? "N";

  // Subsequent-system impact: only when the 3.1 category hint flags a scope
  // change (the closest analogue to 4.0's vulnerable/subsequent split).
  const subsequent = impact.scope === "C";

  const sel: Cvss4Selection = {
    AV,
    AC: "L",
    AT,
    PR: pr31,
    UI,
    VC: impact.C,
    VI: impact.I,
    VA: impact.A,
    SC: subsequent ? impact.C : "N",
    SI: subsequent ? impact.I : "N",
    SA: subsequent ? impact.A : "N",
  };
  const score = computeCvss4BaseScore(sel);
  return {
    vector: formatCvss4Vector(sel),
    score,
    severity: cvss4Severity(score),
    source: assessed ? "impact-assessment" : "heuristic",
  };
}

/**
 * Render a CVSS vector + score as a one-line markdown fragment for a report,
 * e.g. `**CVSS 4.0: 9.3 (High)** — \`CVSS:4.0/…\``. Detects the version from the
 * vector prefix; falls back to a generic "CVSS" label for other strings.
 */
export function renderCvssSection(opts: { vector: string; score: number; severity?: string }): string {
  const version = opts.vector.startsWith("CVSS:4.0/")
    ? "4.0"
    : opts.vector.startsWith("CVSS:3.1/")
      ? "3.1"
      : opts.vector.startsWith("CVSS:3.0/")
        ? "3.0"
        : undefined;
  const label = version ? `CVSS ${version}` : "CVSS";
  const rating = opts.severity ? ` (${opts.severity})` : "";
  return `**${label}: ${opts.score.toFixed(1)}${rating}** — \`${opts.vector}\``;
}
