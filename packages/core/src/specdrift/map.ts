import { readFileSync } from "node:fs";
import { relative } from "node:path";
import { collectScopeFiles } from "../source-files.js";
import { extractSpecInvariants } from "./extract.js";
import type {
  ImplementationCandidate,
  MapInvariantsToImplementationOptions,
  RunSpecdriftScanOptions,
  SpecInvariant,
  SpecdriftScanResult,
} from "./types.js";

const STOPWORDS = new Set([
  "the", "and", "that", "this", "with", "from", "when", "while", "must", "shall", "should", "not", "may",
  "been", "have", "has", "are", "is", "be", "for", "into", "whose", "their", "there", "then", "than",
  "frame", "field", "message", "payload", "implementation", "implementations",
]);

const KIND_HINTS: Record<SpecInvariant["kind"], RegExp[]> = {
  range: [/\b(?:len|length|size|limit|max|min|range|bounds?)\b/i, /[<>]=?|\bbetween\b/i],
  length: [/\b(?:len|length|size|payload|bytes?|octets?)\b/i, /[<>]=?/],
  ordering: [/\b(?:before|after|state|phase|order|seq|sequence)\b/i],
  state: [/\b(?:state|phase|handshake|session|stream|open|closed|init)\b/i],
  rejection: [/\b(?:reject|invalid|error|fail|abort|discard|close|return|throw)\b/i],
  canonicalization: [/\b(?:canonical|normalize|normalise|lower|upper|duplicate|unique)\b/i],
  requirement: [/\b(?:validate|check|require|assert|if|return|throw)\b/i],
};

const SOURCE_EXTS = new Set([
  ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp",
  ".rs", ".go", ".java", ".kt", ".py",
  ".js", ".ts", ".jsx", ".tsx",
]);

function termsFor(invariant: SpecInvariant): string[] {
  const raw = `${invariant.subject ?? ""} ${invariant.summary} ${invariant.rule}`
    .toLowerCase()
    .replace(/[`*_]/g, " ")
    .match(/[a-z][a-z0-9-]{2,}/g) ?? [];
  const out: string[] = [];
  for (const term of raw) {
    const normalized = term.replace(/-/g, "");
    if (STOPWORDS.has(term) || STOPWORDS.has(normalized)) continue;
    if (!out.includes(term)) out.push(term);
    if (out.length >= 12) break;
  }
  return out;
}

function snippet(lines: string[], line: number): { lineStart: number; lineEnd: number; text: string } {
  const start = Math.max(1, line - 2);
  const end = Math.min(lines.length, line + 2);
  const text = lines.slice(start - 1, end).map((l, idx) => `${start + idx}: ${l}`).join("\n");
  return { lineStart: start, lineEnd: end, text };
}

function scoreLine(invariant: SpecInvariant, line: string, terms: string[]): { score: number; matchedTerms: string[] } {
  const lowered = line.toLowerCase();
  const matchedTerms = terms.filter((term) => lowered.includes(term));
  let score = matchedTerms.length;
  for (const hint of KIND_HINTS[invariant.kind]) if (hint.test(line)) score += 2;
  if (/\b(if|switch|case|return|throw|goto|break|continue)\b/.test(line)) score += 1;
  if (/^\s*(\/\/|\*|#)/.test(line)) score -= 2;
  return { score, matchedTerms };
}

export function mapInvariantsToImplementation(opts: MapInvariantsToImplementationOptions): { candidates: ImplementationCandidate[]; warnings: string[] } {
  const warnings: string[] = [];
  const files = collectScopeFiles(opts.sourceRoot, { maxFiles: opts.maxFiles ?? 400, extensions: SOURCE_EXTS });
  if (files.length === (opts.maxFiles ?? 400)) warnings.push(`source file scan capped at ${files.length}; raise --max-files to widen mapping`);

  const candidates: ImplementationCandidate[] = [];
  const maxPerInvariant = opts.maxCandidatesPerInvariant ?? 5;

  for (const invariant of opts.invariants) {
    const terms = termsFor(invariant);
    if (terms.length === 0) continue;
    const ranked: Array<ImplementationCandidate & { rawScore: number }> = [];

    for (const file of files) {
      let source: string;
      try { source = readFileSync(file, "utf8"); } catch { continue; }
      const lines = source.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const { score, matchedTerms } = scoreLine(invariant, lines[i] ?? "", terms);
        if (score < 3 || matchedTerms.length === 0) continue;
        const snip = snippet(lines, i + 1);
        ranked.push({
          invariantId: invariant.id,
          file: relative(opts.sourceRoot, file),
          lineStart: snip.lineStart,
          lineEnd: snip.lineEnd,
          snippet: snip.text,
          matchedTerms,
          reason: `${invariant.kind} invariant terms matched implementation code`,
          confidence: Math.min(0.95, 0.25 + score * 0.08),
          status: "candidate",
          rawScore: score,
        });
      }
    }

    ranked.sort((a, b) => b.rawScore - a.rawScore || a.file.localeCompare(b.file) || a.lineStart - b.lineStart);
    candidates.push(...ranked.slice(0, maxPerInvariant).map(({ rawScore: _rawScore, ...candidate }) => candidate));
  }

  if (opts.invariants.length > 0 && candidates.length === 0) warnings.push("no implementation candidates matched extracted invariants");
  return { candidates, warnings };
}

export function runSpecdriftScan(opts: RunSpecdriftScanOptions): SpecdriftScanResult {
  const extracted = extractSpecInvariants({
    specName: opts.specName,
    specText: opts.specText,
    ...(opts.maxInvariants ? { maxInvariants: opts.maxInvariants } : {}),
  });
  const mapped = mapInvariantsToImplementation({
    sourceRoot: opts.sourceRoot,
    invariants: extracted.invariants,
    ...(opts.maxFiles ? { maxFiles: opts.maxFiles } : {}),
    ...(opts.maxCandidatesPerInvariant ? { maxCandidatesPerInvariant: opts.maxCandidatesPerInvariant } : {}),
  });

  return {
    mode: "specdrift",
    stage: "scan",
    spec: opts.specName,
    source: opts.sourceRoot,
    invariants: extracted.invariants,
    candidates: mapped.candidates,
    warnings: [...extracted.warnings, ...mapped.warnings],
  };
}
