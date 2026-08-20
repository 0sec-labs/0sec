import type { AttackCategory, Finding, Severity } from "@0sec/shared";

export interface CvssSuggestion {
  vector: string;
  score: number;
  source: "finding" | "heuristic";
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

export function suggestCvss(finding: Finding): CvssSuggestion {
  if (finding.cvssVector && finding.cvssScore !== undefined) {
    return { vector: finding.cvssVector, score: finding.cvssScore, source: "finding" };
  }
  const impact = IMPACT_BY_CATEGORY[finding.category] ?? { C: "L", I: "L", A: "L", scope: "U" as const };
  const av = "N" as const;
  const ac = "L" as const;
  const pr = prForSeverity(finding.severity);
  const ui = "N" as const;
  const vector = `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${impact.scope}/C:${impact.C}/I:${impact.I}/A:${impact.A}`;
  const score = computeBaseScore(av, ac, pr, ui, impact.scope, impact.C, impact.I, impact.A);
  return { vector, score, source: "heuristic" };
}
