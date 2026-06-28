import type { ExtractSpecInvariantsOptions, SpecInvariant, SpecInvariantKind, SpecdriftExtractResult } from "./types.js";

interface SectionLine {
  n: number;
  text: string;
  section?: string;
}

const MODAL_RE = /\b(MUST(?:\s+NOT)?|SHALL(?:\s+NOT)?|SHOULD(?:\s+NOT)?|MAY|REQUIRED|OPTIONAL|MUST be|MUST have)\b/i;
const RANGE_RE = /\b(?:between|minimum|maximum|at least|at most|less than|greater than|[0-9]+\s*(?:-|to)\s*[0-9]+|0x[0-9a-f]+)\b/i;
const LENGTH_RE = /\b(length|size|bytes?|octets?|bits?|payload|frame size|field)\b/i;
const STATE_RE = /\b(state|transition|handshake|stream|session|before|after|until|when|while|once)\b/i;
const REJECT_RE = /\b(reject(?:ed|s|ing)?|error|invalid|malformed|abort(?:ed|s|ing)?|terminate(?:d|s|ing)?|discard(?:ed|s|ing)?|fail(?:ed|s|ing)?|close(?:d|s|ing)?)\b/i;
const ORDER_RE = /\b(before|after|first|then|prior to|followed by|precede|order)\b/i;
const CANON_RE = /\b(canonical|normalize|normalise|case-sensitive|case-insensitive|duplicate|unique)\b/i;

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48) || "rule";
}

function splitLines(specText: string): SectionLine[] {
  const out: SectionLine[] = [];
  let section: string | undefined;
  const lines = specText.replace(/\r\n/g, "\n").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    const trimmed = raw.trim();
    const mdHeading = /^#{1,6}\s+(.+)$/.exec(trimmed);
    const numberedHeading = /^(\d+(?:\.\d+)*\.?\s+.+)$/.exec(trimmed);
    if (mdHeading?.[1]) section = mdHeading[1].trim();
    else if (numberedHeading?.[1] && trimmed.length < 120) section = numberedHeading[1].trim();
    out.push({ n: i + 1, text: raw, ...(section ? { section } : {}) });
  }
  return out;
}

function sentences(lines: SectionLine[]): SectionLine[] {
  const out: SectionLine[] = [];
  let buf = "";
  let start = 1;
  let section: string | undefined;
  for (const line of lines) {
    const trimmed = line.text.trim();
    if (!trimmed) continue;
    if (/^#{1,6}\s+/.test(trimmed) || /^(\d+(?:\.\d+)*\.?\s+.+)$/.test(trimmed)) continue;
    if (!buf) {
      start = line.n;
      section = line.section;
    }
    buf = buf ? `${buf} ${trimmed}` : trimmed;
    if (/[.!?]$/.test(trimmed) || buf.length > 420) {
      out.push({ n: start, text: buf, ...(section ? { section } : {}) });
      buf = "";
      section = undefined;
    }
  }
  if (buf) out.push({ n: start, text: buf, ...(section ? { section } : {}) });
  return out;
}

function kindFor(text: string): SpecInvariantKind {
  if (REJECT_RE.test(text)) return "rejection";
  if (STATE_RE.test(text)) return "state";
  if (RANGE_RE.test(text)) return "range";
  if (LENGTH_RE.test(text)) return "length";
  if (ORDER_RE.test(text)) return "ordering";
  if (CANON_RE.test(text)) return "canonicalization";
  return "requirement";
}

function relevanceFor(kind: SpecInvariantKind, text: string): "low" | "medium" | "high" {
  if (/\b(auth|encrypt|signature|certificate|key|nonce|token|permission|credential)\b/i.test(text)) return "high";
  if (kind === "state" || kind === "rejection") return "high";
  if (kind === "range" || kind === "length") return "medium";
  return "low";
}

function subjectFor(text: string): string | undefined {
  const match = /(?:the|a|an)\s+([A-Za-z0-9_.-]+(?:\s+[A-Za-z0-9_.-]+){0,4})\s+(?:MUST|SHALL|SHOULD|MAY|is|required|contains|has)\b/i.exec(text);
  return match?.[1]?.trim();
}

function summarize(text: string): string {
  return text.replace(/\s+/g, " ").slice(0, 180).replace(/[.;:,\s]+$/g, "");
}

export function extractSpecInvariants(opts: ExtractSpecInvariantsOptions): SpecdriftExtractResult {
  const max = opts.maxInvariants ?? 40;
  const warnings: string[] = [];
  const lines = splitLines(opts.specText);
  const candidates = sentences(lines)
    .filter((s) => MODAL_RE.test(s.text) || REJECT_RE.test(s.text) || (STATE_RE.test(s.text) && (RANGE_RE.test(s.text) || LENGTH_RE.test(s.text))))
    .slice(0, max);

  if (candidates.length === max) warnings.push(`capped invariants at ${max}; raise --max-invariants to widen extraction`);
  if (candidates.length === 0) warnings.push("no normative invariants found; spec may need OCR cleanup or LLM extraction");

  const invariants: SpecInvariant[] = candidates.map((c, idx) => {
    const kind = kindFor(c.text);
    const summary = summarize(c.text);
    return {
      id: `inv-${String(idx + 1).padStart(3, "0")}-${slug(summary)}`,
      kind,
      summary,
      rule: c.text,
      ...(subjectFor(c.text) ? { subject: subjectFor(c.text) } : {}),
      citations: [{ spec: opts.specName, ...(c.section ? { section: c.section } : {}), lineStart: c.n, lineEnd: c.n, text: c.text }],
      securityRelevance: relevanceFor(kind, c.text),
    };
  });

  return {
    mode: "specdrift",
    stage: "extract",
    spec: opts.specName,
    invariants,
    warnings,
  };
}
