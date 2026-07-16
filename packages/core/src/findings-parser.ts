import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import type { Finding, Severity } from "@pwnkit/shared";
import { derivePocStepsFromEvidence } from "./poc-steps.js";
import { parseSanitizerLog, renderSanitizerVerdict } from "./review/sanitizer-log.js";

export interface ParseFindingsOptions {
  templatePrefix?: string;
  /**
   * Absolute path to the scope root (the cloned repo / target directory). When
   * provided, `parseFindingsFromCliOutput` validates that any cited
   * `file:line` references actually exist under the scope. Findings that cite
   * a fabricated path are downgraded to `severity: info` /
   * `status: false-positive` with a `triageNote` explaining the reason —
   * never silently dropped, so the operator can still see what the agent
   * claimed.
   *
   * When `scopePath` is undefined (caller has no scope context), validation
   * is skipped to preserve existing behaviour. Closes #286 (control-flow
   * audit H5: fabricated path defense).
   */
  scopePath?: string;
}

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

/**
 * Max file size (bytes) for which a cited file is read to count its lines.
 * Larger files skip the line-range check entirely — slurping a
 * multi-hundred-MB minified bundle or vendored artifact to count lines is
 * not worth the memory spike.
 */
const MAX_LINE_COUNT_FILE_BYTES = 4 * 1024 * 1024;

export interface FileRefProbe {
  /** The resolved path exists. */
  exists: boolean;
  /**
   * Line count of the cited file, when it is a regular file small enough to
   * read. Undefined means "no line information available" (directory,
   * unreadable, or too large) — callers MUST skip any line-range check in
   * that case (the conservative outcome).
   */
  lineCount?: number;
}

/**
 * Existence + line-count probe for a cited file reference, shared by the CLI
 * findings parser (`validateFileRef`) and the native `save_finding` tool so
 * both annotation paths agree on what a "fabricated location" is.
 *
 * NEVER throws. `existsSync` is true for directories, so the previous
 * readFileSync-based line count crashed with EISDIR on a `dir:1` citation —
 * discarding every finding from the output with it. Any stat/read failure
 * yields the conservative `{ exists: true }` with no lineCount, matching
 * validateFileRef's documented "can't prove it's fake → valid" posture.
 */
export function probeFileRefTarget(absPath: string): FileRefProbe {
  if (!existsSync(absPath)) return { exists: false };
  try {
    const stat = statSync(absPath);
    if (!stat.isFile()) return { exists: true }; // directory etc. — no lines to count
    if (stat.size > MAX_LINE_COUNT_FILE_BYTES) return { exists: true };
    return {
      exists: true,
      lineCount: readFileSync(absPath, "utf8").split(/\r?\n/).length,
    };
  } catch {
    return { exists: true };
  }
}

/**
 * Repo-relative path rule for review annotations. Mirrors the orchestrator's
 * zod schema (`@0cloud/cloud-contracts` finding.ts `reviewAnnotation.path`
 * refine) EXACTLY — the cloud 400s the ENTIRE finding POST when any of these
 * fail, so every engine path that produces an annotation must pre-check with
 * this predicate:
 *   - no leading `/`           (absolute POSIX path)
 *   - no `C:\` / `C:/` prefix  (Windows drive-absolute path)
 *   - no backslashes anywhere  (Windows separators break the cloud renderer)
 *   - no `..` segments
 */
export function isRepoRelativePath(path: string): boolean {
  return (
    path.length > 0 &&
    !path.startsWith("/") &&
    !/^[A-Za-z]:[\\/]/.test(path) &&
    !path.includes("\\") &&
    !path.split("/").includes("..")
  );
}

/**
 * Max suggestion length accepted by the cloud schema
 * (`reviewAnnotation.suggestion` is `z.string().max(20_000)`).
 */
export const SUGGESTION_MAX_LENGTH = 20_000;

/**
 * A suggestion is only attachable when the cloud can store it AND a PR
 * provider can render it. Oversized suggestions are DROPPED, never truncated
 * — a half-function inside a ```suggestion block applies as broken code.
 * Fenced / unified-diff content is dropped for the same reason: a line
 * starting with ``` or `@@ ` renders broken inside a GitHub suggestion
 * block. All three annotation paths (CLI parser, save_finding, cloud sink)
 * gate on this one predicate.
 */
export function isSuggestionAcceptable(suggestion: string): boolean {
  if (suggestion.length > SUGGESTION_MAX_LENGTH) return false;
  return !suggestion
    .split(/\r?\n/)
    .some((line) => line.startsWith("```") || line.startsWith("@@ "));
}

function parseFileLine(fileRef: string): { path: string; line: number } | null {
  const match = fileRef.trim().match(/^(.+?):([1-9]\d*)(?::\d+)?$/);
  if (!match) return null;
  return { path: match[1]!, line: Number(match[2]) };
}

/**
 * Validate a `file` or `file:line` reference against a scope root. Conservative:
 * a reference is considered valid when scope is unknown (we can't prove it's
 * fake) or when the resolved absolute path exists inside the scope.
 *
 * Path traversal that escapes the scope (`../../../etc/passwd`) is treated as
 * fabricated — the agent has no business citing files outside the audit
 * target. Absolute paths are also rejected, on the same grounds.
 *
 * Mirrors `disclose/canary.ts:93 verifyAgainstRef`'s `existsSync(abs)` check
 * but runs at parse time rather than disclose time.
 */
export function validateFileRef(
  fileRef: string,
  scopePath: string | undefined,
): { valid: boolean; reason?: string } {
  if (!scopePath) return { valid: true }; // can't validate, accept
  const trimmed = fileRef.trim();
  if (!trimmed) return { valid: true }; // no file cited; nothing to validate
  const parsed = parseFileLine(trimmed);
  const path = parsed?.path ?? trimmed;
  if (!path) return { valid: true };

  // Reject absolute paths and any traversal that escapes scope. resolve()
  // collapses `..` segments so we can compare against the scope prefix.
  const scopeAbs = resolve(scopePath);
  if (isAbsolute(path)) {
    return { valid: false, reason: `fabricated path: ${path}` };
  }
  const abs = resolve(scopeAbs, path);
  if (abs !== scopeAbs && !abs.startsWith(scopeAbs + "/")) {
    return { valid: false, reason: `fabricated path: ${path}` };
  }
  const probe = probeFileRefTarget(abs);
  if (!probe.exists) {
    return { valid: false, reason: `fabricated path: ${path}` };
  }
  if (parsed && probe.lineCount !== undefined && parsed.line > probe.lineCount) {
    return { valid: false, reason: `fabricated line: ${path}:${parsed.line}` };
  }
  return { valid: true };
}

function attachReviewAnnotation(
  finding: Finding,
  fileRef: unknown,
  suggestion: unknown,
  scopePath: string | undefined,
  valid: boolean,
): void {
  if (!valid || !scopePath || typeof fileRef !== "string") return;
  const parsed = parseFileLine(fileRef);
  if (!parsed) return;
  finding.reviewAnnotation = {
    path: parsed.path,
    startLine: parsed.line,
    ...(typeof suggestion === "string" &&
    suggestion.length > 0 &&
    isSuggestionAcceptable(suggestion)
      ? { suggestion }
      : {}),
  };
}

/**
 * Parse findings from CLI agent output.
 *
 * Tries two strategies:
 * 1. JSON structured output (from --json-schema / --output-schema)
 * 2. Structured ---FINDING--- / ---END--- blocks
 *
 * Returns empty array if no structured findings found.
 * Never manufactures findings from unstructured prose.
 */
export function parseFindingsFromCliOutput(
  output: string,
  opts?: ParseFindingsOptions,
): Finding[] {
  const prefix = opts?.templatePrefix ?? "cli";
  const scopePath = opts?.scopePath;

  // Strategy 1: JSON structured output
  const jsonFindings = parseJsonOutput(output, prefix, scopePath);
  if (jsonFindings.length > 0) return jsonFindings;

  // Strategy 2: ---FINDING--- blocks
  const structured = parseStructuredBlocks(output, prefix, scopePath);
  if (structured.length > 0) return structured;

  return [];
}

/** Parse JSON structured output (from --json-schema / --output-schema). */
function parseJsonOutput(output: string, prefix: string, scopePath?: string): Finding[] {
  try {
    const parsed = JSON.parse(output.trim());
    if (parsed.findings && Array.isArray(parsed.findings)) {
      return parsed.findings
        .filter((f: any) => f.title && f.severity)
        .map((f: any) => {
          const evidence = {
            request: f.file ?? "",
            response: f.sanitizer_log ?? f.sanitizerLog ?? f.poc ?? "",
            analysis: f.description ?? "",
          };
          const explicitSteps = Array.isArray(f.poc_steps) ? f.poc_steps : Array.isArray(f.pocSteps) ? f.pocSteps : undefined;
          const derivedSteps = derivePocStepsFromEvidence(evidence);
          const validation = typeof f.file === "string" && f.file.length > 0
            ? validateFileRef(f.file, scopePath)
            : { valid: true };

          const baseSeverity = (VALID_SEVERITIES.has(f.severity) ? f.severity : "info") as Severity;
          const finding: Finding = {
            id: randomUUID(),
            templateId: `${prefix}-${Date.now()}`,
            title: f.title,
            description: f.description ?? "",
            severity: baseSeverity,
            category: (f.category ?? "other") as Finding["category"],
            status: "discovered" as const,
            evidence,
            ...(explicitSteps ? { pocSteps: explicitSteps } : derivedSteps.length > 0 ? { pocSteps: derivedSteps } : {}),
            // Pass-through with clamping when the upstream JSON schema includes
            // `confidence`. Downstream cloud-sink also clamps; this is defence
            // in depth so an agent runtime that reports a wild value (1.5,
            // -0.2, NaN) never escapes the OSS engine. Absent → undefined,
            // which the cloud column accepts as NULL.
            confidence: clampConfidence(f.confidence),
            timestamp: Date.now(),
          };

          applySanitizerEvidence(finding, f.sanitizer_log ?? f.sanitizerLog);
          attachReviewAnnotation(
            finding,
            f.file,
            f.suggested_replacement ?? f.suggestedReplacement,
            scopePath,
            validation.valid,
          );

          if (!validation.valid) {
            finding.severity = "info";
            finding.status = "false-positive";
            finding.triageNote = validation.reason;
          }

          return finding;
        });
    }
  } catch {
    // Not valid JSON
  }
  return [];
}

/**
 * Clamp an arbitrary confidence value to [0,1], or return `undefined` if
 * the input isn't a usable finite number. Mirrors the `cloud-sink.ts`
 * normalizer so OSS-side and wire-side agree on what "no confidence
 * signal" looks like.
 */
function clampConfidence(v: unknown): number | undefined {
  if (typeof v !== "number" || !Number.isFinite(v)) return undefined;
  if (v < 0) return 0;
  if (v > 1) return 1;
  return v;
}

function applySanitizerEvidence(finding: Finding, rawLog: unknown): void {
  if (typeof rawLog !== "string" || rawLog.trim().length === 0) return;
  const verdict = parseSanitizerLog(rawLog);
  if (!verdict) return;

  finding.category = verdict.category;
  finding.status = "confirmed";
  finding.confidence = Math.max(finding.confidence ?? 0, 0.95);
  finding.evidence.response = rawLog.trim();
  finding.evidence.analysis = [
    finding.evidence.analysis,
    `Sanitizer verdict: ${renderSanitizerVerdict(verdict)}`,
  ].filter(Boolean).join("\n\n");
}

function extractStructuredField(content: string, field: string): string | undefined {
  const fields = [
    "title",
    "severity",
    "category",
    "subsystem",
    "description",
    "file",
    "suggested_replacement",
    "hypothesis",
    "confidence",
    "reproducer_shape",
    "reproducer",
    "harness",
    "sanitizer_log",
    "tier",
  ].join("|");
  const pattern = new RegExp(
    `^${field}:\\s*([\\s\\S]*?)(?=^(?:${fields}|---)\\s*:?|(?![\\s\\S]))`,
    "m",
  );
  return content.match(pattern)?.[1]?.trim();
}

/** Parse ---FINDING--- / ---END--- delimited blocks. */
function parseStructuredBlocks(output: string, prefix: string, scopePath?: string): Finding[] {
  const blocks = output.split("---FINDING---").slice(1);
  if (blocks.length === 0) return [];

  return blocks.map((block) => {
    const endIdx = block.indexOf("---END---");
    const content = endIdx >= 0 ? block.slice(0, endIdx) : block;

    const title = extractStructuredField(content, "title") ?? "Security finding";
    const severity = extractStructuredField(content, "severity")?.toLowerCase() ?? "info";
    const category = extractStructuredField(content, "category") ?? "other";
    const description = extractStructuredField(content, "description") ?? "";
    const file = extractStructuredField(content, "file") ?? "";
    const sanitizerLog = extractStructuredField(content, "sanitizer_log");
    const suggestedReplacement = extractStructuredField(content, "suggested_replacement");
    const subsystem = extractStructuredField(content, "subsystem");
    const hypothesis = extractStructuredField(content, "hypothesis");
    const confidence = extractStructuredField(content, "confidence");
    const reproducerShape = extractStructuredField(content, "reproducer_shape");
    const reproducer = extractStructuredField(content, "reproducer");

    const evidence = {
      request: file || "Automated AI analysis",
      response: sanitizerLog ?? reproducer ?? description,
      analysis: [
        `Found by ${prefix} agent`,
        subsystem ? `Subsystem: ${subsystem}` : "",
        hypothesis ? `Hypothesis: ${hypothesis}` : "",
        reproducerShape ? `Reproducer shape: ${reproducerShape}` : "",
      ].filter(Boolean).join("\n"),
    };
    const derivedSteps = derivePocStepsFromEvidence(evidence);
    const validation = file
      ? validateFileRef(file, scopePath)
      : { valid: true };

    const finding: Finding = {
      id: randomUUID(),
      templateId: `${prefix}-${Date.now()}`,
      title,
      description,
      severity: (VALID_SEVERITIES.has(severity) ? severity : "info") as Severity,
      category: category as Finding["category"],
      status: "discovered" as const,
      evidence,
      ...(derivedSteps.length > 0 ? { pocSteps: derivedSteps } : {}),
      confidence: clampConfidence(confidence === undefined ? undefined : Number(confidence)),
      timestamp: Date.now(),
    };

    applySanitizerEvidence(finding, sanitizerLog);
    attachReviewAnnotation(
      finding,
      file,
      suggestedReplacement,
      scopePath,
      validation.valid,
    );

    if (!validation.valid) {
      finding.severity = "info";
      finding.status = "false-positive";
      finding.triageNote = validation.reason;
    }

    return finding;
  });
}
