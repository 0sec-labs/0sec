import type { AttackCategory } from "@0sec/shared";

export interface FoxguardFinding {
  ruleId: string;
  message: string;
  file: string;
  startLine?: number;
  endLine?: number;
  level?: string;
  /** Our best guess at a 0sec AttackCategory, derived from the rule id / message. */
  category?: AttackCategory;
}

interface SarifLocation {
  physicalLocation?: {
    artifactLocation?: { uri?: string };
    region?: { startLine?: number; endLine?: number };
  };
}

interface SarifResult {
  ruleId?: string;
  rule?: { id?: string };
  level?: string;
  message?: { text?: string } | string;
  locations?: SarifLocation[];
}

interface SarifRun {
  results?: SarifResult[];
}

interface SarifLog {
  runs?: SarifRun[];
}

export function parseFoxguardSarif(sarifText: string): FoxguardFinding[] {
  let parsed: SarifLog;
  try {
    parsed = JSON.parse(sarifText) as SarifLog;
  } catch {
    return [];
  }
  const out: FoxguardFinding[] = [];
  for (const run of parsed.runs ?? []) {
    for (const result of run.results ?? []) {
      const ruleId = result.ruleId ?? result.rule?.id ?? "unknown";
      const message =
        typeof result.message === "string"
          ? result.message
          : result.message?.text ?? "";
      for (const loc of result.locations ?? []) {
        const uri = loc.physicalLocation?.artifactLocation?.uri;
        if (!uri) continue;
        out.push({
          ruleId,
          message,
          file: uri,
          startLine: loc.physicalLocation?.region?.startLine,
          endLine: loc.physicalLocation?.region?.endLine,
          level: result.level,
          category: inferCategoryFromRule(ruleId, message),
        });
      }
    }
  }
  return out;
}

const CATEGORY_KEYWORDS: Array<{ category: AttackCategory; patterns: RegExp[] }> = [
  { category: "sql-injection", patterns: [/sql[-_ ]?inject/i, /sqli/i] },
  { category: "xss", patterns: [/\bxss\b/i, /cross[- ]site[- ]script/i] },
  { category: "ssrf", patterns: [/\bssrf\b/i, /server[- ]side[- ]request/i] },
  { category: "command-injection", patterns: [/command[- ]?inject/i, /\brce\b/i, /shell[- ]?inject/i] },
  { category: "code-injection", patterns: [/code[- ]?inject/i, /\beval\b/i, /unsafe[- ]?eval/i] },
  { category: "path-traversal", patterns: [/path[- ]?travers/i, /directory[- ]?travers/i, /zip[- ]?slip/i] },
  { category: "prototype-pollution", patterns: [/prototype[- ]?pollut/i] },
  { category: "regex-dos", patterns: [/redos/i, /regex[- ]?dos/i, /catastrophic[- ]?backtrack/i] },
  { category: "unsafe-deserialization", patterns: [/deserial/i, /unsafe[- ]?pickle/i, /yaml[- ]?load/i] },
  { category: "information-disclosure", patterns: [/info[- ]?disclos/i, /hard[- ]?coded[- ]?(secret|cred)/i, /leak/i] },
  { category: "cors", patterns: [/\bcors\b/i] },
  { category: "security-misconfiguration", patterns: [/misconfig/i, /insecure[- ]?config/i] },
];

export function inferCategoryFromRule(
  ruleId: string,
  message: string,
): AttackCategory | undefined {
  const text = `${ruleId} ${message}`;
  for (const { category, patterns } of CATEGORY_KEYWORDS) {
    for (const p of patterns) {
      if (p.test(text)) return category;
    }
  }
  return undefined;
}
