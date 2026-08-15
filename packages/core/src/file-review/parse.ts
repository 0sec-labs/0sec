import type { ReviewFinding, ReviewRefusalReport } from "./types.js";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const VALID_SEVERITIES: Record<string, true> = {
  critical: true, high: true, medium: true, low: true, info: true,
};
const VALID_CONFIDENCE: Record<string, true> = {
  high: true, medium: true, low: true,
};

function normalizeFilePath(fp: string): string {
  return fp.replaceAll("\\", "/").replace(/^\.\//, "").trim();
}

export const REFUSAL_FOLLOWUP_PROMPT =
  'Looking back at the investigation: was there anything you declined to fully analyze, refused to look at, or skipped because the content or the task felt uncomfortable or out of scope? Answer as JSON: {"refused": boolean, "reason": string?, "skipped": [{"filePath": string?, "reason": string}]?}';

const FENCED_JSON_RE = /```json\s*([\s\S]*?)```/g;
const BARE_OBJECT_RE = /\{[\s\S]*\}/;
const BARE_ARRAY_RE = /\[[\s\S]*\]/;

export function extractFencedJson(text: string): unknown {
  let lastContent: string | undefined;
  let m: RegExpExecArray | null;
  FENCED_JSON_RE.lastIndex = 0;
  while ((m = FENCED_JSON_RE.exec(text)) !== null) {
    lastContent = m[1].trim();
  }
  if (lastContent) {
    try {
      return JSON.parse(lastContent);
    } catch {
      // fenced block wasn't valid JSON — fall through
    }
  }

  const arrayMatch = text.match(BARE_ARRAY_RE);
  if (arrayMatch) {
    try {
      return JSON.parse(arrayMatch[0]);
    } catch {
      // not valid JSON
    }
  }

  const objMatch = text.match(BARE_OBJECT_RE);
  if (objMatch) {
    try {
      return JSON.parse(objMatch[0]);
    } catch {
      // not valid JSON
    }
  }

  throw new Error("No parseable JSON found in text");
}

export interface ParseResult {
  results: Array<{ filePath: string; findings: ReviewFinding[] }>;
  invalid: Array<{ filePath: string; issues: string[]; raw: unknown }>;
}

export function parseInvestigateResults(
  text: string,
  batch: ReadonlyArray<{ filePath: string }>,
): ParseResult {
  const batchPaths = new Set(batch.map((b) => normalizeFilePath(b.filePath)));
  const parsed = extractFencedJson(text);
  let entries: unknown[];

  if (Array.isArray(parsed)) {
    entries = parsed;
  } else if (isObject(parsed)) {
    const obj = parsed as Record<string, unknown>;
    entries =
      (Array.isArray(obj.results) ? obj.results : undefined) ??
      (Array.isArray(obj.files) ? obj.files : undefined) ??
      (Array.isArray(obj.entries) ? obj.entries : undefined) ??
      [];
    if (entries.length === 0 && typeof obj.filePath === "string") {
      entries = [obj];
    }
  } else {
    throw new Error("Parsed JSON is neither an array nor an object");
  }

  const results: Array<{ filePath: string; findings: ReviewFinding[] }> = [];
  const invalid: Array<{ filePath: string; issues: string[]; raw: unknown }> = [];

  for (const entry of entries) {
    if (!isObject(entry)) {
      invalid.push({ filePath: "unknown", issues: ["Entry is not an object"], raw: entry });
      continue;
    }
    const e = entry as Record<string, unknown>;
    const rawFp =
      typeof e.filePath === "string"
        ? e.filePath
        : typeof e.file === "string"
          ? e.file
          : "";
    const filePath = normalizeFilePath(rawFp);

    if (!filePath || !batchPaths.has(filePath)) {
      invalid.push({
        filePath: filePath || "unknown",
        issues: [`filePath "${filePath}" not in batch`],
        raw: entry,
      });
      continue;
    }

    const rawFindings = Array.isArray(e.findings) ? e.findings : [];
    const validFindings: ReviewFinding[] = [];
    const fileIssues: string[] = [];

    for (const f of rawFindings) {
      if (!isObject(f)) {
        fileIssues.push("Finding is not an object");
        continue;
      }
      const fo = f as Record<string, unknown>;
      const issues: string[] = [];

      const severity = String(fo.severity ?? "");
      if (!VALID_SEVERITIES[severity]) {
        issues.push(`severity must be one of critical|high|medium|low|info, got "${severity}"`);
      }

      const vulnSlug = String(fo.vulnSlug ?? "");
      if (!vulnSlug) issues.push("vulnSlug is empty");

      const title = String(fo.title ?? "");
      if (!title) issues.push("title is empty");

      const description = String(fo.description ?? "");
      if (!description) issues.push("description is empty");

      const lineNumbers = Array.isArray(fo.lineNumbers)
        ? (fo.lineNumbers as unknown[]).filter(
            (n): n is number => typeof n === "number" && Number.isInteger(n) && n >= 0,
          )
        : [];
      if (Array.isArray(fo.lineNumbers) && fo.lineNumbers.length > 0 && lineNumbers.length === 0) {
        issues.push("lineNumbers must be non-negative integers");
      }

      const confidence = String(fo.confidence ?? "");
      if (!VALID_CONFIDENCE[confidence]) {
        issues.push(`confidence must be one of high|medium|low, got "${confidence}"`);
      }

      const recommendation = String(fo.recommendation ?? "");

      if (issues.length > 0) {
        fileIssues.push(...issues);
        continue;
      }

      validFindings.push({
        severity: severity as ReviewFinding["severity"],
        vulnSlug,
        title,
        description,
        lineNumbers,
        recommendation,
        confidence: confidence as ReviewFinding["confidence"],
      });
    }

    results.push({ filePath, findings: validFindings });
    if (fileIssues.length > 0) {
      invalid.push({ filePath, issues: fileIssues, raw: entry });
    }
  }

  return { results, invalid };
}

const REFUSAL_MARKERS = /\b(can't|cannot|decline|refuse|refused|uncomfortable|policy)\b/i;

export function parseRefusalReport(raw: string): ReviewRefusalReport | undefined {
  if (!raw || !raw.trim()) return undefined;

  let parsed: unknown;
  try {
    parsed = extractFencedJson(raw);
  } catch {
    parsed = undefined;
  }

  if (isObject(parsed)) {
    const obj = parsed as Record<string, unknown>;
    if (typeof obj.refused === "boolean") {
      const report: ReviewRefusalReport = {
        refused: obj.refused,
        raw: raw.slice(0, 1000),
      };
      if (typeof obj.reason === "string") report.reason = obj.reason;
      if (Array.isArray(obj.skipped)) report.skipped = obj.skipped as ReviewRefusalReport["skipped"];
      return report;
    }
  }

  if (REFUSAL_MARKERS.test(raw)) {
    return {
      refused: true,
      reason: `heuristic: ${raw.slice(0, 200)}`,
      raw: raw.slice(0, 1000),
    };
  }

  return undefined;
}