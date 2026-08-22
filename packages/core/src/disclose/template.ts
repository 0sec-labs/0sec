import type { Finding, ReachabilityTier, Weaponizability } from "@0sec/shared";
import { suggestCwesForCategory, formatCweSection } from "./cwe.js";
import type { CweEntry } from "./cwe.js";
import {
  suggestCvss,
  suggestCvss4,
  renderCvssSection,
  type CvssSuggestion,
} from "./cvss.js";
import { formatPatchStatusSection, type ReverifyResult } from "./canary.js";
import { formatVersionRangeLine, type VersionRangeResult } from "./version-range.js";
import type { SiblingFixCandidate } from "./sibling-fix.js";
import type { PocExecutionReport } from "./poc-runtime.js";

export interface AdvisoryScreenshot {
  alt: string;
  /** Markdown-ready href (usually a path relative to the advisory file). */
  relativePath: string;
  caption?: string;
  width?: number;
}

export interface AdvisoryContext {
  target?: string;
  targetRef?: string;
  commitHash?: string;
  osecVersion?: string;
  scanId?: string;
  screenshots?: AdvisoryScreenshot[];
  patchStatus?: ReverifyResult;
  versionRange?: VersionRangeResult;
  /**
   * "Correct pattern already present in the repo" snippet extracted from a
   * sibling file. Renders into the Suggested fix section as a fallback when
   * the finding has no `remediation.codeExample.after`.
   */
  siblingFix?: SiblingFixCandidate;
  /**
   * Captured PoC execution report from `disclose --target-url`. Renders into
   * the Patch status section as a behavioural verdict line.
   */
  pocExecution?: PocExecutionReport;
}

export interface RenderedAdvisory {
  filename: string;
  markdown: string;
  cvssVector: string;
  cvssScore: number;
  primaryCwe: string;
  severity: string;
}

/**
 * Thrown by {@link renderAdvisoryMarkdown} when the finding has no
 * reproducible PoC content (no `pocSteps`, no `evidence.request`, no
 * `evidence.response`, no screenshots in `ctx`). Publishing an advisory
 * with a literal "to fill in" placeholder is the canonical "AI-generated
 * low-quality" trigger that gets reports auto-closed at any responsible
 * disclosure venue. The CLI catches this error and routes the finding
 * into `_dropped/` with an `unverified-poc` reason file so the audit
 * trail is explicit.
 */
export class EmptyPocError extends Error {
  readonly findingId: string;
  constructor(findingId: string) {
    super(`Finding ${findingId} has no PoC content (pocSteps, evidence, or screenshots) — refusing to render advisory.`);
    this.name = "EmptyPocError";
    this.findingId = findingId;
  }
}

// ── Sensitive-data redaction ────────────────────────────────────────────────
//
// Publishing an advisory that leaks the operator's session cookie, AWS key,
// or JWT into a triage queue is the textbook "sensitive-data disclosure"
// own-goal — and most responsible-disclosure programs treat it as a CoC
// violation that earns the report a fast-track close. Mask values for known
// auth headers (case-insensitive), AWS access keys, and JWT-looking strings.
// Inline by design — this is a small, mechanical transform applied right
// before content is emitted into the advisory or the screenshot session text.

const SENSITIVE_HEADER_NAMES = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "x-auth-token",
  "x-api-key",
  "x-csrf-token",
]);

const AWS_KEY_RE = /\bAKIA[0-9A-Z]{16}\b/g;
// JWT: three base64url segments separated by dots, total length >= 80.
// Base64url charset: A-Z a-z 0-9 - _, with optional `=` padding.
const JWT_RE = /\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+={0,2}\b/g;

// Inline `Bearer <token>` matches anywhere in a line. Targets shell commands
// like `curl -H "Authorization: Bearer eyJ..."` where the line-oriented
// `^Header:` matcher doesn't fire because the header lives inside an arg.
// Token is "non-whitespace, non-quote" so we don't swallow trailing quote
// or shell separators.
const INLINE_BEARER_RE = /\b(Bearer)\s+([^\s"'`]+)/gi;

// Inline `-H 'Sensitive-Header: ...'` / `-H "Sensitive-Header: ..."` /
// `--header 'Sensitive-Header: ...'` for curl-style commands. Quoting is
// optional (`-H Sensitive-Header: ...` is valid curl too).
const INLINE_CURL_HEADER_RE =
  /(-H|--header)(\s+|=)(["']?)([A-Za-z][A-Za-z0-9-]*)\s*:\s*([^"'\n]*)\3/gi;

/**
 * Redact sensitive header values, AWS access keys, and JWT-looking strings
 * from a block of text. Header redaction is line-oriented and case-
 * insensitive — `Authorization: Bearer xyz` becomes
 * `Authorization: <REDACTED-Authorization>`. AWS keys and JWTs are masked
 * wherever they appear in the body.
 *
 * Also masks two shell-command patterns that wouldn't be caught by the
 * line-oriented `^Header:` matcher:
 *   - inline `Bearer <token>` (e.g. embedded in a `curl -H` arg)
 *   - `curl -H 'Cookie: ...'` / `--header "Authorization: ..."`
 * Without these, a `pocSteps` shell step that wraps a real bearer token
 * inside its `cmd` field would leak verbatim into the rendered advisory.
 */
export function redactSensitiveHeaders(text: string): string {
  if (!text) return text;
  const lines = text.split("\n");
  const redactedLines = lines.map((line) => {
    // Header line: `Name: value` or `Name:value`. Allow leading whitespace
    // (request indentation) and arbitrary case on the header name.
    const m = /^(\s*)([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.*)$/.exec(line);
    if (m && SENSITIVE_HEADER_NAMES.has(m[2].toLowerCase())) {
      return `${m[1]}${m[2]}: <REDACTED-${m[2]}>`;
    }
    return line;
  });
  let out = redactedLines.join("\n");
  // Inline `curl -H 'Sensitive: ...'` patterns. Apply BEFORE bearer/JWT/AWS
  // sweeps so the value is wholly replaced, not partially masked.
  out = out.replace(INLINE_CURL_HEADER_RE, (match, flag, sep, quote, name, _value) => {
    if (!SENSITIVE_HEADER_NAMES.has(name.toLowerCase())) return match;
    return `${flag}${sep}${quote}${name}: <REDACTED-${name}>${quote}`;
  });
  // Inline `Bearer <token>` anywhere in the text — handles cases the
  // `^Authorization:` matcher above already covered, but also wraps
  // tokens embedded in shell args.
  out = out.replace(INLINE_BEARER_RE, "$1 <REDACTED-Bearer>");
  out = out.replace(AWS_KEY_RE, "<REDACTED-AWS-KEY>");
  // Apply JWT regex AFTER header redaction so we don't double-replace masks.
  // The mask placeholder doesn't match the JWT pattern so this is safe.
  out = out.replace(JWT_RE, (match) => {
    // Skip strings that don't look like real JWTs (need to be 80+ chars).
    if (match.length < 80) return match;
    return "<REDACTED-JWT>";
  });
  return out;
}

/**
 * Human-readable gloss of a reachability tier — the "who can do this" line a
 * vendor triager needs, phrased the way a disclosure email would put it.
 */
function reachabilityLabel(tier: ReachabilityTier): string {
  switch (tier) {
    case "remote-unauth":
      return "remote, unauthenticated — reachable over the network with no credentials";
    case "proximity-rf":
      return "RF/physical proximity — attacker must be within radio range (NFC/BLE/Wi-Fi)";
    case "local-unpriv":
      return "local, unprivileged — requires an unprivileged account on the host";
    case "local-priv":
      return "local, privileged — requires an already-privileged local account";
    case "needs-hardware":
      return "requires specific or attacker-supplied hardware";
    case "needs-host-migration":
      return "requires the victim to mount/import an attacker-supplied artifact";
  }
}

/** Human-readable gloss of what the attacker gains once the bug fires. */
function weaponizabilityLabel(w: Weaponizability): string {
  switch (w) {
    case "rce":
      return "remote code execution";
    case "lpe-to-root":
      return "local privilege escalation to root/SYSTEM";
    case "info-leak":
      return "information disclosure";
    case "dos-crash":
      return "denial of service (crash)";
  }
}

function severityHeading(severity: string): string {
  const upper = severity.toUpperCase();
  return upper === "CRITICAL" || upper === "HIGH" || upper === "MEDIUM" || upper === "LOW" ? upper : severity;
}

function slugifyTitle(title: string, max = 80): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, max);
}

function indentEvidenceBlock(raw: string, lang = ""): string {
  const trimmed = raw.trim();
  if (!trimmed) return "";
  return "```" + lang + "\n" + trimmed + "\n```";
}

function renderPocSteps(finding: Finding): string[] {
  if (!finding.pocSteps || finding.pocSteps.length === 0) return [];
  const lines: string[] = ["**Step graph:**", ""];
  for (const [index, step] of finding.pocSteps.entries()) {
    lines.push(`${index + 1}. **${step.kind}** — ${step.summary} _(id: \`${step.id}\`)_`);
    if (step.action.type === "shell") {
      lines.push("", indentEvidenceBlock(step.action.cmd, "bash"));
    } else if (step.action.type === "http") {
      const method = step.action.method.toUpperCase();
      lines.push("", indentEvidenceBlock(`${method} ${step.action.url}${step.action.body ? `\n\n${step.action.body}` : ""}`, "http"));
    } else if (step.action.type === "docker") {
      lines.push("", indentEvidenceBlock(`docker run ${step.action.image} ${step.action.args.join(" ")}`.trim(), "bash"));
    } else {
      lines.push("", step.action.text);
    }
    if (step.expect) {
      lines.push("", `Expected result: \`${step.expect.type}\``);
    }
    lines.push("");
  }
  return lines;
}

export function renderAdvisoryMarkdown(finding: Finding, ctx: AdvisoryContext = {}): RenderedAdvisory {
  const cwes = suggestCwesForCategory(finding.category);
  const cvss = suggestCvss(finding);
  const severity = severityHeading(finding.severity);

  // Prefix by severity rank so lexicographic sort = criticals-first.
  // Explicit numeric map because "critical" < "high" alphabetically.
  const rank: Record<string, string> = { critical: "1", high: "2", medium: "3", low: "4", info: "5" };
  const filenameSlug = slugifyTitle(finding.title);
  const filename = `${rank[finding.severity] ?? "9"}-${finding.severity}-${filenameSlug}.md`;

  let affectedLine: string;
  if (ctx.versionRange) {
    affectedLine = formatVersionRangeLine(ctx.versionRange);
  } else if (ctx.target) {
    affectedLine = `\`${ctx.target}\`${ctx.targetRef ? ` at \`${ctx.targetRef}\`` : ""}${ctx.commitHash ? ` (commit \`${ctx.commitHash.slice(0, 12)}\`)` : ""}`;
  } else {
    affectedLine = "_Pass `--repo <path>` to `0sec-cli disclose` to auto-detect the affected version range from git tags._";
  }

  const cvssSource =
    cvss.source === "finding"
      ? "populated on the finding by 0sec"
      : cvss.source === "impact-assessment"
        ? "exploitability metrics derived from 0sec's reachability assessment; impact from category — verify against your deployment"
        : "heuristic from category + severity — override in the GHSA editor if the operator disagrees";

  const remediation = finding.remediation;
  const suggestedFixParts: string[] = [];
  if (remediation?.summary) suggestedFixParts.push(remediation.summary);
  if (remediation?.steps?.length) {
    suggestedFixParts.push(remediation.steps.map((step, i) => `${i + 1}. ${step}`).join("\n"));
  }
  if (remediation?.codeExample?.after) {
    const lang = remediation.codeExample.language || "";
    suggestedFixParts.push(
      remediation.codeExample.before
        ? `**Before:**\n\n\`\`\`${lang}\n${remediation.codeExample.before}\n\`\`\`\n\n**After:**\n\n\`\`\`${lang}\n${remediation.codeExample.after}\n\`\`\``
        : `\`\`\`${lang}\n${remediation.codeExample.after}\n\`\`\``,
    );
  } else if (ctx.siblingFix) {
    const ref = `${ctx.siblingFix.fileRef.file}${ctx.siblingFix.fileRef.line ? `:${ctx.siblingFix.fileRef.line}` : ""}`;
    suggestedFixParts.push(
      `**Correct pattern already present in the repo at \`${ref}\`** *(extracted by 0sec):*\n\n\`\`\`${ctx.siblingFix.language}\n${ctx.siblingFix.snippet}\n\`\`\``,
    );
  }
  const suggestedFix = suggestedFixParts.length > 0
    ? suggestedFixParts.join("\n\n")
    : "_To fill in: copy-paste the correct pattern from a sibling handler in the same repo._";

  const evidenceAnalysis = finding.evidence?.analysis?.trim() ?? "";

  const out: string[] = [];
  out.push("# Title", "");
  out.push(finding.title, "");

  out.push("# Severity", "");
  out.push(`**${severity}** — ${cvss.vector} (~${cvss.score.toFixed(1)})`, "");
  out.push(`_CVSS source: ${cvssSource}._`, "");

  // Impact + attack prerequisites: rendered only when the finding carries a
  // real assessment, so an unassessed advisory is byte-identical to before.
  // This is the section a vendor reads to decide "how bad, and who can do it".
  const impactAssessment = finding.impactAssessment;
  if (impactAssessment) {
    out.push("# Impact", "");
    out.push(`**Attacker gains:** ${weaponizabilityLabel(impactAssessment.weaponizability)}`, "");
    out.push(`**Attack prerequisites:** ${reachabilityLabel(impactAssessment.reachability_tier)}`, "");
    if (impactAssessment.blast_radius) {
      out.push(`**Blast radius:** ${impactAssessment.blast_radius}`, "");
    }
    if (impactAssessment.rationale) {
      out.push(`_${impactAssessment.rationale}_`, "");
    }
  }

  out.push(formatCweSection(cwes), "");

  out.push("# Affected versions", "");
  out.push(affectedLine, "");

  if (ctx.osecVersion || ctx.scanId) {
    const bits: string[] = [];
    if (ctx.osecVersion) bits.push(`0sec \`${ctx.osecVersion}\``);
    if (ctx.scanId) bits.push(`scan \`${ctx.scanId.slice(0, 8)}\``);
    // Honesty gate: only claim "code-verified" when BOTH the canary
    // patch-status check (#170) and the behavioural reverify (#171)
    // returned positive verdicts. Without that pair the advisory is a
    // static draft, not a live-verified issue — claiming otherwise is
    // misrepresentation, and most disclosure venues treat that as a
    // hard CoC violation. The negative branch is deliberately neutral:
    // saying "not behaviourally re-verified" is itself a false claim
    // when ctx.pocExecution exists with verdict exploit_broken or
    // could_not_run (the run happened, it just didn't confirm). The
    // Patch Status section below carries the actual reverify state.
    const canaryPositive = ctx.patchStatus?.status === "still-vulnerable";
    const behaviouralPositive = ctx.pocExecution?.overallVerdict === "exploit_still_works";
    if (canaryPositive && behaviouralPositive) {
      out.push(`> Code-verified by ${bits.join(", ")}.`, "");
    } else {
      out.push(`_Generated by ${bits.join(", ")}._`, "");
    }
  }

  out.push("## Summary", "");
  out.push(finding.description.trim(), "");

  if (evidenceAnalysis && evidenceAnalysis !== finding.description.trim()) {
    out.push("## Analysis", "");
    out.push(evidenceAnalysis, "");
  }

  // ── Empty-PoC gate ──
  // Refuse to render an advisory whose PoC section would be a literal
  // "to fill in" placeholder. Publishing that gets the advisory auto-closed
  // at any responsible-disclosure venue and burns operator reputation.
  // Callers (CLI, bundle) catch EmptyPocError and route the finding into
  // _dropped/ with reason `unverified-poc`.
  const pocStepsBlock = renderPocSteps(finding);
  const hasRequest = !!finding.evidence?.request?.trim();
  const hasResponse = !!finding.evidence?.response?.trim();
  const hasScreenshots = !!ctx.screenshots && ctx.screenshots.length > 0;
  if (pocStepsBlock.length === 0 && !hasRequest && !hasResponse && !hasScreenshots) {
    throw new EmptyPocError(finding.id);
  }

  out.push("## PoC", "");
  if (pocStepsBlock.length > 0) {
    // Redact the rendered step graph before emitting. PoC step bodies are
    // operator-supplied shell commands and HTTP request/response chunks —
    // a real bearer token, cookie, or JWT can land here verbatim. Without
    // this pass the rendered advisory leaks the operator's auth context
    // (sensitive-data disclosure → instant CoC violation).
    const redactedSteps = redactSensitiveHeaders(pocStepsBlock.join("\n")).split("\n");
    out.push(...redactedSteps);
  }
  if (hasScreenshots) {
    for (const shot of ctx.screenshots!) {
      const width = shot.width ? ` width="${shot.width}"` : "";
      out.push(`<img${width} alt="${shot.alt}" src="${shot.relativePath}" />`, "");
      if (shot.caption) {
        out.push(`> ${shot.caption}`, "");
      }
    }
  }
  if (hasRequest) {
    out.push("**Request:**", "");
    out.push(indentEvidenceBlock(redactSensitiveHeaders(finding.evidence!.request), "http"), "");
  }
  if (hasResponse) {
    out.push("**Response:**", "");
    out.push(indentEvidenceBlock(redactSensitiveHeaders(finding.evidence!.response), "http"), "");
  }

  out.push("## Suggested fix", "");
  out.push(suggestedFix, "");

  out.push("## Patch status", "");
  if (ctx.patchStatus) {
    out.push(formatPatchStatusSection(ctx.patchStatus), "");
  } else {
    out.push("_Pass `--repo <path>` to `0sec-cli disclose` to auto-verify this against the target's current HEAD or a specific tag._", "");
  }
  if (ctx.pocExecution) {
    const verdict = ctx.pocExecution.overallVerdict === "exploit_still_works"
      ? "**Behavioural check: exploit still reproducible.**"
      : ctx.pocExecution.overallVerdict === "exploit_broken"
        ? "**Behavioural check: exploit no longer reproducible.**"
        : "**Behavioural check: could not run.**";
    out.push(verdict, "");
    out.push(`> Verdict: \`${ctx.pocExecution.overallVerdict}\` (${ctx.pocExecution.steps.length} step${ctx.pocExecution.steps.length === 1 ? "" : "s"} executed).`, "");
  }

  out.push("## Credits", "");
  out.push(
    "Discovered by **0sec**, 0sec's AI-assisted security engine ([0sec.ai](https://0sec.ai)).",
    "",
    "Reporter: _(your github handle)_",
    "",
  );

  return {
    filename,
    markdown: out.join("\n").replace(/\n{3,}/g, "\n\n"),
    cvssVector: cvss.vector,
    cvssScore: cvss.score,
    primaryCwe: cwes[0]?.id ?? "",
    severity: finding.severity,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform report templates
// ─────────────────────────────────────────────────────────────────────────────
//
// Impact-first, submission-ready report templates mapped to each bug-bounty /
// disclosure platform's expectations. Data-driven: a template is a small record
// (id, label, required-section headings, and a `render`) selectable by platform
// id through {@link reportTemplate}. Every template reuses the same shared
// section builders below (summary, impact narrative, steps, PoC, affected
// assets, severity/CVSS, remediation, references) and only differs in ordering,
// headings, and the platform-specific severity taxonomy it surfaces.
//
// All emitted PoC/evidence content is run through `redactSensitiveHeaders`
// (secret sweep) exactly like `renderAdvisoryMarkdown`, and the same
// {@link EmptyPocError} gate applies — a submission-grade report is never
// rendered with a "to fill in" PoC placeholder.

/** Supported report platforms. `generic` is the platform-neutral default. */
export type ReportPlatform =
  | "hackerone"
  | "bugcrowd"
  | "intigriti"
  | "immunefi"
  | "generic";

/** One rendered section: a heading and its markdown body. */
export interface ReportSection {
  heading: string;
  body: string;
}

export interface RenderedPlatformReport {
  platform: ReportPlatform;
  title: string;
  markdown: string;
  cvssVector: string;
  cvssScore: number;
  severity: string;
  /** The section list, in render order — handy for callers that re-layout. */
  sections: ReportSection[];
}

export interface PlatformReportTemplate {
  id: ReportPlatform;
  /** Human-readable name for a picker. */
  label: string;
  /** One-line description of what this template emphasizes. */
  description: string;
  /** Heading strings this platform's report always contains. */
  requiredSections: readonly string[];
  render: (finding: Finding, ctx?: AdvisoryContext) => RenderedPlatformReport;
}

// ── Shared section builders ─────────────────────────────────────────────────

function buildAffectedLine(finding: Finding, ctx: AdvisoryContext): string {
  if (ctx.versionRange) return formatVersionRangeLine(ctx.versionRange);
  if (ctx.target) {
    return `\`${ctx.target}\`${ctx.targetRef ? ` at \`${ctx.targetRef}\`` : ""}${
      ctx.commitHash ? ` (commit \`${ctx.commitHash.slice(0, 12)}\`)` : ""
    }`;
  }
  return "_Affected component/version: to be filled in by the operator before submission._";
}

/**
 * Impact-first narrative: leads with what the attacker gains and who can do it,
 * then blast radius and rationale. Falls back to the finding description when no
 * structured impact assessment is present.
 */
function buildImpactNarrative(finding: Finding): string {
  const a = finding.impactAssessment;
  if (!a) {
    return (
      `This ${finding.category.replace(/-/g, " ")} issue is rated **${severityHeading(
        finding.severity,
      )}**. ` + finding.description.trim()
    );
  }
  const parts: string[] = [];
  parts.push(
    `An attacker gains **${weaponizabilityLabel(a.weaponizability)}**. ` +
      `Attack prerequisites: ${reachabilityLabel(a.reachability_tier)}.`,
  );
  if (a.blast_radius) parts.push(`**Blast radius:** ${a.blast_radius}`);
  if (a.rationale) parts.push(a.rationale);
  return parts.join("\n\n");
}

/**
 * The attacker path as a short chain: how they must be positioned → what they
 * gain. Used by the immunefi "Attack scenario" section; empty when unassessed.
 */
function buildAttackScenario(finding: Finding): string {
  const a = finding.impactAssessment;
  if (!a) return "";
  return (
    `1. Attacker position: ${reachabilityLabel(a.reachability_tier)}.\n` +
    `2. Trigger the ${finding.category.replace(/-/g, " ")} condition described above.\n` +
    `3. Result: ${weaponizabilityLabel(a.weaponizability)}${
      a.blast_radius ? ` — ${a.blast_radius}` : ""
    }.`
  );
}

/** Steps-to-reproduce markdown from the PoC step graph; empty when none. */
function buildStepsToReproduce(finding: Finding): string {
  const block = renderPocSteps(finding);
  if (block.length === 0) return "";
  return redactSensitiveHeaders(block.join("\n"));
}

/**
 * PoC evidence (screenshots, request, response), redacted. Returns "" when
 * there is no evidence content — the caller pairs this with the empty-PoC gate.
 */
function buildPocEvidence(finding: Finding, ctx: AdvisoryContext): string {
  const out: string[] = [];
  if (ctx.screenshots && ctx.screenshots.length > 0) {
    for (const shot of ctx.screenshots) {
      const width = shot.width ? ` width="${shot.width}"` : "";
      out.push(`<img${width} alt="${shot.alt}" src="${shot.relativePath}" />`, "");
      if (shot.caption) out.push(`> ${shot.caption}`, "");
    }
  }
  if (finding.evidence?.request?.trim()) {
    out.push("**Request:**", "", indentEvidenceBlock(redactSensitiveHeaders(finding.evidence.request), "http"), "");
  }
  if (finding.evidence?.response?.trim()) {
    out.push("**Response:**", "", indentEvidenceBlock(redactSensitiveHeaders(finding.evidence.response), "http"), "");
  }
  return out.join("\n").trim();
}

function buildRemediation(finding: Finding, ctx: AdvisoryContext): string {
  const remediation = finding.remediation;
  const parts: string[] = [];
  if (remediation?.summary) parts.push(remediation.summary);
  if (remediation?.steps?.length) {
    parts.push(remediation.steps.map((step, i) => `${i + 1}. ${step}`).join("\n"));
  }
  if (remediation?.codeExample?.after) {
    const lang = remediation.codeExample.language || "";
    parts.push(
      remediation.codeExample.before
        ? `**Before:**\n\n\`\`\`${lang}\n${remediation.codeExample.before}\n\`\`\`\n\n**After:**\n\n\`\`\`${lang}\n${remediation.codeExample.after}\n\`\`\``
        : `\`\`\`${lang}\n${remediation.codeExample.after}\n\`\`\``,
    );
  } else if (ctx.siblingFix) {
    const ref = `${ctx.siblingFix.fileRef.file}${ctx.siblingFix.fileRef.line ? `:${ctx.siblingFix.fileRef.line}` : ""}`;
    parts.push(
      `**Correct pattern already present in the repo at \`${ref}\`** *(extracted by 0sec):*\n\n\`\`\`${ctx.siblingFix.language}\n${ctx.siblingFix.snippet}\n\`\`\``,
    );
  }
  return parts.length > 0
    ? parts.join("\n\n")
    : "_Recommended fix: apply input validation / correct handling per the referenced CWE guidance._";
}

function buildReferences(finding: Finding, cwes: CweEntry[]): string {
  const lines: string[] = [];
  for (const cwe of cwes) {
    const num = cwe.id.replace(/^CWE-/i, "");
    lines.push(`- [${cwe.id}: ${cwe.name}](https://cwe.mitre.org/data/definitions/${num}.html)`);
  }
  for (const ref of finding.remediation?.references ?? []) {
    lines.push(`- ${ref}`);
  }
  return lines.length > 0 ? lines.join("\n") : "_No external references._";
}

/** Bugcrowd VRT priority (P1–P5) mapped from finding severity. */
function bugcrowdPriority(severity: string): string {
  switch (severity) {
    case "critical":
      return "P1 (Critical)";
    case "high":
      return "P2 (High)";
    case "medium":
      return "P3 (Medium)";
    case "low":
      return "P4 (Low)";
    default:
      return "P5 (Informational)";
  }
}

/** Immunefi impact-based severity label (funds/assets at risk). */
function immunefiSeverity(severity: string): string {
  switch (severity) {
    case "critical":
      return "Critical — direct loss/freezing of funds or protocol insolvency";
    case "high":
      return "High — significant impact to funds or protocol integrity";
    case "medium":
      return "Medium — limited impact, bounded or conditional";
    default:
      return "Low — informational / minor impact";
  }
}

/**
 * Shared prelude every platform template runs: compute CVSS + CWEs, enforce the
 * empty-PoC gate, and produce the reusable section bodies. Throws
 * {@link EmptyPocError} when the finding has no reproducible PoC content.
 */
interface CommonReportParts {
  cvss: CvssSuggestion;
  cwes: CweEntry[];
  severity: string;
  title: string;
  summary: string;
  impact: string;
  attackScenario: string;
  steps: string;
  poc: string;
  affected: string;
  remediation: string;
  references: string;
  /** Severity + CVSS 3.1 one-liner. */
  severityCvss31: string;
  /** Severity + CVSS 4.0 one-liner (derived; used by web3 template). */
  severityCvss40: string;
}

function buildCommonParts(finding: Finding, ctx: AdvisoryContext): CommonReportParts {
  const cwes = suggestCwesForCategory(finding.category);
  const cvss = suggestCvss(finding);
  const cvss4 = suggestCvss4(finding);
  const severity = severityHeading(finding.severity);

  const steps = buildStepsToReproduce(finding);
  const poc = buildPocEvidence(finding, ctx);
  // Empty-PoC gate — identical semantics to renderAdvisoryMarkdown: refuse to
  // emit a submission-grade report with no reproducible PoC.
  if (!steps && !poc) throw new EmptyPocError(finding.id);

  return {
    cvss,
    cwes,
    severity,
    title: finding.title,
    summary: finding.description.trim(),
    impact: buildImpactNarrative(finding),
    attackScenario: buildAttackScenario(finding),
    steps,
    poc,
    affected: buildAffectedLine(finding, ctx),
    remediation: buildRemediation(finding, ctx),
    references: buildReferences(finding, cwes),
    severityCvss31: renderCvssSection({ vector: cvss.vector, score: cvss.score, severity }),
    severityCvss40: renderCvssSection({
      vector: cvss4.vector,
      score: cvss4.score,
      severity: cvss4.severity,
    }),
  };
}

/** Assemble the final rendered report from an ordered section list. */
function assembleReport(
  platform: ReportPlatform,
  parts: CommonReportParts,
  sections: ReportSection[],
): RenderedPlatformReport {
  const out: string[] = [`# ${parts.title}`, ""];
  for (const s of sections) {
    out.push(`## ${s.heading}`, "", s.body, "");
  }
  return {
    platform,
    title: parts.title,
    markdown: out.join("\n").replace(/\n{3,}/g, "\n\n"),
    cvssVector: parts.cvss.vector,
    cvssScore: parts.cvss.score,
    severity: parts.severity,
    sections,
  };
}

// ── Platform templates ──────────────────────────────────────────────────────
//
// Each template arranges the shared parts into the platform's expected shape.
// `stepsBody` degrades to a pointer at the PoC when the finding carries only
// request/response evidence (no structured step graph).

function stepsBodyOrPoc(parts: CommonReportParts): string {
  return parts.steps || "_See the Proof of Concept section below for the reproduction._";
}

const HACKERONE_TEMPLATE: PlatformReportTemplate = {
  id: "hackerone",
  label: "HackerOne",
  description:
    "H1 field order: Summary → Steps To Reproduce → PoC → Impact → Severity (CVSS) → Remediation → Supporting Material.",
  requiredSections: [
    "Summary",
    "Steps To Reproduce",
    "Proof of Concept",
    "Impact",
    "Severity",
    "Remediation",
    "Supporting Material / References",
  ],
  render(finding, ctx = {}) {
    const parts = buildCommonParts(finding, ctx);
    const sections: ReportSection[] = [
      { heading: "Summary", body: parts.summary },
      { heading: "Affected Asset", body: parts.affected },
      { heading: "Steps To Reproduce", body: stepsBodyOrPoc(parts) },
      { heading: "Proof of Concept", body: parts.poc || "_See Steps To Reproduce._" },
      { heading: "Impact", body: parts.impact },
      { heading: "Severity", body: `${parts.severityCvss31}\n\n_${cvssSourceLabel(parts.cvss)}_` },
      { heading: "Remediation", body: parts.remediation },
      { heading: "Supporting Material / References", body: parts.references },
    ];
    return assembleReport("hackerone", parts, sections);
  },
};

const BUGCROWD_TEMPLATE: PlatformReportTemplate = {
  id: "bugcrowd",
  label: "Bugcrowd",
  description:
    "Bugcrowd VRT-first: leads with Business Impact + VRT priority (P1–P5), then Vulnerability Details, Steps, PoC, Remediation.",
  requiredSections: [
    "Vulnerability Details",
    "Business Impact",
    "Bugcrowd VRT / Priority",
    "Steps to Reproduce",
    "Proof of Concept",
    "Remediation",
    "References",
  ],
  render(finding, ctx = {}) {
    const parts = buildCommonParts(finding, ctx);
    const sections: ReportSection[] = [
      { heading: "Business Impact", body: parts.impact },
      {
        heading: "Bugcrowd VRT / Priority",
        body: `**${bugcrowdPriority(finding.severity)}**\n\n${parts.severityCvss31}`,
      },
      { heading: "Vulnerability Details", body: parts.summary },
      { heading: "Affected Target", body: parts.affected },
      { heading: "Steps to Reproduce", body: stepsBodyOrPoc(parts) },
      { heading: "Proof of Concept", body: parts.poc || "_See Steps to Reproduce._" },
      { heading: "Remediation", body: parts.remediation },
      { heading: "References", body: parts.references },
    ];
    return assembleReport("bugcrowd", parts, sections);
  },
};

const INTIGRITI_TEMPLATE: PlatformReportTemplate = {
  id: "intigriti",
  label: "Intigriti",
  description:
    "Intigriti order: Summary → Domain/Endpoint → Vulnerability Type (CWE) → Impact → Steps → PoC → Severity (CVSS) → Recommended Fix.",
  requiredSections: [
    "Summary",
    "Domain / Endpoint",
    "Vulnerability Type",
    "Impact",
    "Steps to Reproduce",
    "Proof of Concept",
    "Severity",
    "Recommended Fix",
  ],
  render(finding, ctx = {}) {
    const parts = buildCommonParts(finding, ctx);
    const primaryCwe = parts.cwes[0];
    const sections: ReportSection[] = [
      { heading: "Summary", body: parts.summary },
      { heading: "Domain / Endpoint", body: parts.affected },
      {
        heading: "Vulnerability Type",
        body: primaryCwe
          ? `${primaryCwe.id}: ${primaryCwe.name} (category: \`${finding.category}\`)`
          : `Category: \`${finding.category}\``,
      },
      { heading: "Impact", body: parts.impact },
      { heading: "Steps to Reproduce", body: stepsBodyOrPoc(parts) },
      { heading: "Proof of Concept", body: parts.poc || "_See Steps to Reproduce._" },
      { heading: "Severity", body: parts.severityCvss31 },
      { heading: "Recommended Fix", body: parts.remediation },
      { heading: "References", body: parts.references },
    ];
    return assembleReport("intigriti", parts, sections);
  },
};

const IMMUNEFI_TEMPLATE: PlatformReportTemplate = {
  id: "immunefi",
  label: "Immunefi (web3)",
  description:
    "Immunefi web3 order: Bug Description → Impact (funds/assets at risk) → Impact-in-Detail → Attack Scenario → PoC → Affected Assets → Recommendation. Impact-based severity + CVSS 4.0.",
  requiredSections: [
    "Bug Description",
    "Impact",
    "Severity",
    "Attack Scenario",
    "Proof of Concept",
    "Affected Assets",
    "Recommendation",
  ],
  render(finding, ctx = {}) {
    const parts = buildCommonParts(finding, ctx);
    const sections: ReportSection[] = [
      { heading: "Bug Description", body: parts.summary },
      { heading: "Impact", body: parts.impact },
      {
        heading: "Severity",
        body: `**${immunefiSeverity(finding.severity)}**\n\n${parts.severityCvss40}\n\n${parts.severityCvss31}`,
      },
      {
        heading: "Attack Scenario",
        body: parts.attackScenario || stepsBodyOrPoc(parts),
      },
      {
        heading: "Proof of Concept",
        body: [parts.steps, parts.poc].filter(Boolean).join("\n\n") || "_Attach a runnable PoC / test before submission._",
      },
      { heading: "Affected Assets", body: parts.affected },
      { heading: "Recommendation", body: parts.remediation },
      { heading: "References", body: parts.references },
    ];
    return assembleReport("immunefi", parts, sections);
  },
};

const GENERIC_TEMPLATE: PlatformReportTemplate = {
  id: "generic",
  label: "Generic / Default",
  description:
    "Platform-neutral, impact-first structure: Summary → Impact → Affected → Steps → PoC → Severity (CVSS) → Remediation → References.",
  requiredSections: [
    "Summary",
    "Impact",
    "Affected Assets",
    "Steps to Reproduce",
    "Proof of Concept",
    "Severity",
    "Remediation",
    "References",
  ],
  render(finding, ctx = {}) {
    const parts = buildCommonParts(finding, ctx);
    const sections: ReportSection[] = [
      { heading: "Summary", body: parts.summary },
      { heading: "Impact", body: parts.impact },
      { heading: "Affected Assets", body: parts.affected },
      { heading: "Steps to Reproduce", body: stepsBodyOrPoc(parts) },
      { heading: "Proof of Concept", body: parts.poc || "_See Steps to Reproduce._" },
      { heading: "Severity", body: `${parts.severityCvss31}\n\n_${cvssSourceLabel(parts.cvss)}_` },
      { heading: "Remediation", body: parts.remediation },
      { heading: "References", body: parts.references },
    ];
    return assembleReport("generic", parts, sections);
  },
};

function cvssSourceLabel(cvss: CvssSuggestion): string {
  return cvss.source === "finding"
    ? "CVSS source: populated on the finding by 0sec."
    : cvss.source === "impact-assessment"
      ? "CVSS source: exploitability derived from 0sec's reachability assessment; impact from category — verify against your deployment."
      : "CVSS source: heuristic from category + severity — verify before submission.";
}

const TEMPLATE_REGISTRY: Record<ReportPlatform, PlatformReportTemplate> = {
  hackerone: HACKERONE_TEMPLATE,
  bugcrowd: BUGCROWD_TEMPLATE,
  intigriti: INTIGRITI_TEMPLATE,
  immunefi: IMMUNEFI_TEMPLATE,
  generic: GENERIC_TEMPLATE,
};

/** The platform list, for a picker/selector UI. */
export const REPORT_PLATFORMS: readonly {
  id: ReportPlatform;
  label: string;
  description: string;
}[] = (Object.values(TEMPLATE_REGISTRY) as PlatformReportTemplate[]).map((t) => ({
  id: t.id,
  label: t.label,
  description: t.description,
}));

/**
 * Selector: return the report template for a platform id. Unknown/undefined ids
 * fall back to the platform-neutral generic template.
 */
export function reportTemplate(platform?: ReportPlatform | string): PlatformReportTemplate {
  if (platform && platform in TEMPLATE_REGISTRY) {
    return TEMPLATE_REGISTRY[platform as ReportPlatform];
  }
  return GENERIC_TEMPLATE;
}

/**
 * Convenience: render a finding into a platform-specific, submission-ready
 * report. Pure/deterministic; throws {@link EmptyPocError} when the finding has
 * no reproducible PoC content.
 */
export function renderPlatformReport(
  finding: Finding,
  platform?: ReportPlatform | string,
  ctx: AdvisoryContext = {},
): RenderedPlatformReport {
  return reportTemplate(platform).render(finding, ctx);
}
