import type { Finding } from "@0sec/shared";
import { suggestCwesForCategory, formatCweSection } from "./cwe.js";
import { suggestCvss } from "./cvss.js";
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

  const cvssSource = cvss.source === "finding"
    ? "populated on the finding by 0sec"
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
