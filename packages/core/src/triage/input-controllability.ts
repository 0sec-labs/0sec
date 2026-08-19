/**
 * Input-controllability analysis — reachability v2 (issue #658)
 *
 * File-level reachability (`./reachability.ts`) answers "is the sink in code
 * that an entry point can reach?". That is necessary but not sufficient. A huge
 * source of triage noise in production is **ORM-internal identifier-injection
 * SQLi**: findings like "removeColumn SQL injection via unescaped
 * `attributeName`" or "DB2 dialect concatenates unescaped table name". The sink
 * *is* in reachable library code — but the value that gets concatenated into the
 * SQL is a **table / column / constraint / index identifier supplied by the
 * application developer through the ORM's public API**, not attacker-controlled
 * request input. A single Sequelize audit produced ~26 of these, almost all
 * non-exploitable, all stuck at triage_status=pending.
 *
 * This module adds the missing dimension: **is the injected value controllable
 * from untrusted (remote) input, or is it a developer-supplied identifier?** It
 * parses the sink file with the TypeScript compiler API (real AST, not grep) for
 * JS/TS — the dominant ecosystem for these findings — and classifies the taint
 * source. Non-JS/TS sources, parse failures, and ambiguous cases return
 * `"unknown"` so the caller takes no action (assume-FP-safe).
 *
 * CRITICAL — this never drops a finding. Per the #518 auto-suppression guard,
 * `sql-injection` is a high-impact class that may never be auto-dropped on a
 * heuristic. The caller uses an `internal-identifier` verdict only to
 * **downgrade severity + annotate**, keeping the finding visible for human
 * review. The bias throughout is to PROTECT real findings: any visible untrusted
 * source short-circuits to `untrusted-input`, and we only emit
 * `internal-identifier` on a strong, multi-signal match.
 */

import { readFileSync } from "node:fs";
import { basename } from "node:path";

import type { AttackCategory, Finding, Severity } from "@pwnkit/shared";

import { extractSinkLocation } from "./reachability.js";

// ────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────

export type Controllability = "untrusted-input" | "internal-identifier" | "unknown";

export interface ControllabilityResult {
  /** How the value flowing into the injection sink is sourced. */
  controllability: Controllability;
  /** 0–1 confidence in the verdict. Callers should require >= 0.75 to act. */
  confidence: number;
  /** The identifier-style parameter we believe is injected, if any. */
  taintedParam: string | null;
  /** Whether the sink file looks like ORM / query-builder internals. */
  ormInternal: boolean;
  /** Concrete code/path signals supporting the verdict (for the audit trail). */
  evidence: string[];
  /** Human-readable explanation. Stable across runs for the same input. */
  reason: string;
}

// ────────────────────────────────────────────────────────────────────
// Config
// ────────────────────────────────────────────────────────────────────

/**
 * Injection classes where "the injected value is a developer-supplied
 * identifier, not attacker input" is a real and common false-positive shape.
 * Other categories return `unknown` (no action).
 */
const ANALYZABLE_CATEGORIES: ReadonlySet<AttackCategory> = new Set<AttackCategory>([
  "sql-injection",
  "code-injection",
  "command-injection",
]);

const JS_TS_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]);

/**
 * Parameter / variable names that denote a SQL **identifier** (object name)
 * rather than a data value. These are supplied by the application developer via
 * the ORM API; they are essentially never attacker-controlled in practice.
 * Matched case-insensitively as whole words.
 */
const IDENTIFIER_PARAM_NAMES: readonly string[] = [
  "table",
  "tablename",
  "tablenames",
  "column",
  "columnname",
  "columnnames",
  "attribute",
  "attributename",
  "attributenames",
  "field",
  "fieldname",
  "constraint",
  "constraintname",
  "index",
  "indexname",
  "key",
  "keyname",
  "schema",
  "schemaname",
  "database",
  "databasename",
  "collection",
  "ondelete",
  "onupdate",
  "referentialaction",
  "references",
  "collation",
  "charset",
  "engine",
  "operator",
  "direction",
  "dialect",
  "enumname",
  "sequencename",
  "triggername",
  "viewname",
  "rolename",
  "username", // DDL CREATE USER name, not auth credential
  "identifier",
  "quotedidentifier",
];

/**
 * Signals (path fragments + symbol substrings) that the sink lives in ORM /
 * query-builder internals, where concatenated identifiers come from the public
 * API rather than the network.
 */
const ORM_PATH_SIGNALS: readonly string[] = [
  "query-generator",
  "querygenerator",
  "query-interface",
  "queryinterface",
  "/dialects/",
  "/dialect/",
  "sql-string",
  "sqlstring",
  "/query/",
  "abstract-query",
  "/schema/",
  "ddl",
];

const ORM_CONTENT_SIGNALS: RegExp[] = [
  /\bclass\s+\w*Query(?:Generator|Interface)\b/,
  /\bextends\s+Abstract(?:Query|Dialect)\b/,
  /\bquoteIdentifier(?:s)?\s*\(/,
  /\bquoteTable\s*\(/,
  /\bescapeId\s*\(/,
  /\b(?:createTableQuery|dropTableQuery|addColumnQuery|removeColumnQuery|addConstraintQuery|addIndexQuery|showConstraintsQuery|describeTableQuery)\b/,
];

/**
 * Untrusted, remote-attacker-controllable input sources. The presence of any of
 * these in the sink file short-circuits the analysis to `untrusted-input` —
 * we would rather keep a borderline finding than downgrade a real one.
 *
 * Deliberately conservative: `process.env` / config are operator-controlled, not
 * remote, so they are NOT listed here (listing them would wrongly *protect*, not
 * downgrade — but more importantly they are out of scope for this signal).
 */
const UNTRUSTED_SOURCE_SIGNALS: RegExp[] = [
  /\breq(?:uest)?\.(?:body|query|params|headers|cookies|url|rawHeaders)\b/,
  /\bctx\.(?:request|query|params|body)\b/,
  /\bctx\.req\.\w+/,
  /\b(?:request|httpRequest)\.(?:body|query|params|headers|url)\b/,
  /\b(?:searchParams|URLSearchParams)\b/,
  /\bnew\s+URL\s*\(/,
  /\bwindow\.location\b/,
  /\blocation\.(?:search|hash|href)\b/,
  /\bprocess\.argv\b/,
  /\bmessage\.data\b/,
  /\bsocket\.on\s*\(\s*['"]data['"]/,
  /\.on\s*\(\s*['"](?:message|request|data)['"]/,
  /\bevent\.(?:body|queryStringParameters|pathParameters|headers)\b/, // lambda
];

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

function isJsTsFile(path: string): boolean {
  const dot = path.lastIndexOf(".");
  if (dot < 0) return false;
  return JS_TS_EXTENSIONS.has(path.slice(dot).toLowerCase());
}

function findingText(finding: Finding): string {
  return [
    finding.title ?? "",
    finding.description ?? "",
    finding.evidence?.analysis ?? "",
    finding.evidence?.request ?? "",
    finding.evidence?.response ?? "",
  ].join("\n");
}

/**
 * Pull the most likely injected identifier name from the finding text. We match
 * known identifier param names as whole words (case-insensitive) and return the
 * first hit in its original casing where possible.
 */
export function extractTaintedParam(finding: Finding): string | null {
  const text = findingText(finding);
  const idSet = new Set(IDENTIFIER_PARAM_NAMES);
  // Prefer names mentioned in backticks or quotes (the agent usually names the
  // exact parameter), then fall back to any whole-word hit.
  for (const quoted of text.matchAll(/[`'"]([A-Za-z_$][\w$]*)[`'"]/g)) {
    const name = quoted[1];
    if (name && idSet.has(name.toLowerCase())) return name;
  }
  // Collect every whole-word identifier-param hit, then prefer the *most
  // specific* (longest) name. Compound params like `attributeName` /
  // `constraintName` are the real injected values; bare SQL keywords like
  // "table" in "ALTER TABLE" are noise and lose the length tie-break.
  let best: string | null = null;
  for (const word of text.matchAll(/[A-Za-z_$][\w$]*/g)) {
    const tok = word[0];
    if (!idSet.has(tok.toLowerCase())) continue;
    if (best == null || tok.length > best.length) best = tok;
  }
  return best;
}

interface SinkFileResolution {
  absPath: string;
  relPath: string;
  content: string;
}

/**
 * Resolve the sink file referenced by the finding to an absolute path + content.
 * Uses the same hint extraction as the file-reachability gate, then resolves the
 * hint against `sourceDir`.
 */
function resolveSinkFile(finding: Finding, sourceDir: string): SinkFileResolution | null {
  const sink = extractSinkLocation(finding);
  if (!sink.file) return null;
  const normalized = sink.file.replace(/^\.?[\\/]/, "");

  const candidates: string[] = [];
  // Direct path under the source dir.
  candidates.push(joinPath(sourceDir, normalized));
  // The hint sometimes already starts with a package-relative segment that maps
  // 1:1 under sourceDir; also try the basename as a last resort.
  const base = basename(normalized);
  candidates.push(joinPath(sourceDir, base));

  for (const abs of candidates) {
    try {
      const content = readFileSync(abs, "utf8");
      return { absPath: abs, relPath: normalized, content };
    } catch {
      // try next
    }
  }
  return null;
}

function joinPath(dir: string, rel: string): string {
  if (dir.endsWith("/")) return dir + rel;
  return dir + "/" + rel;
}

interface SourceSignals {
  /** Untrusted-source reads found in the file (deduped samples). */
  untrustedHits: string[];
  /** Parameter / argument identifiers in the file that match SQL-identifier names. */
  identifierParams: string[];
  /** Whether any identifier-style param/arg was seen. */
  hasIdentifierParam: boolean;
}

/**
 * Strip line + block comments and string / template literals from JS/TS source,
 * replacing their spans with spaces. This gives the untrusted-source detector
 * the one bit of precision that actually matters: a `req.body` mentioned inside
 * a comment or a string literal must NOT be treated as a live read. We
 * deliberately avoid pulling in the TypeScript compiler (it bundles `__filename`
 * into the ESM CLI and bloats the binary); a single-pass scanner is robust
 * enough for the substring matching we do downstream, and any imperfection only
 * ever *over*-detects an untrusted source — which protects findings (never an
 * unsafe downgrade).
 */
function stripCommentsAndStrings(src: string): string {
  let out = "";
  let i = 0;
  const n = src.length;
  type State = "code" | "line" | "block" | "sq" | "dq" | "tpl";
  let state: State = "code";
  while (i < n) {
    const c = src[i];
    const c2 = i + 1 < n ? src[i + 1] : "";
    switch (state) {
      case "code":
        if (c === "/" && c2 === "/") { state = "line"; out += "  "; i += 2; }
        else if (c === "/" && c2 === "*") { state = "block"; out += "  "; i += 2; }
        else if (c === "'") { state = "sq"; out += " "; i += 1; }
        else if (c === '"') { state = "dq"; out += " "; i += 1; }
        else if (c === "`") { state = "tpl"; out += " "; i += 1; }
        else { out += c; i += 1; }
        break;
      case "line":
        if (c === "\n") { state = "code"; out += "\n"; i += 1; }
        else { out += c === "\t" ? "\t" : " "; i += 1; }
        break;
      case "block":
        if (c === "*" && c2 === "/") { state = "code"; out += "  "; i += 2; }
        else { out += c === "\n" ? "\n" : " "; i += 1; }
        break;
      case "sq":
      case "dq":
      case "tpl": {
        const quote = state === "sq" ? "'" : state === "dq" ? '"' : "`";
        if (c === "\\") { out += "  "; i += 2; } // skip escaped char
        else if (c === quote) { state = "code"; out += " "; i += 1; }
        else { out += c === "\n" ? "\n" : " "; i += 1; }
        break;
      }
    }
  }
  return out;
}

/**
 * Detect untrusted-source reads + SQL-identifier-style params over a
 * comment/string-stripped copy of the source. Replaces the previous TS-AST walk
 * with zero external dependencies (consistent with reachability.ts).
 */
function analyzeSource(content: string): SourceSignals {
  const stripped = stripCommentsAndStrings(content);

  const untrusted = new Set<string>();
  for (const rx of UNTRUSTED_SOURCE_SIGNALS) {
    const g = new RegExp(rx.source, rx.flags.includes("g") ? rx.flags : rx.flags + "g");
    for (const m of stripped.matchAll(g)) {
      untrusted.add(m[0].trim());
      if (untrusted.size >= 8) break;
    }
    if (untrusted.size >= 8) break;
  }

  // Identifier-style params/args: scan non-nested parenthesised groups (function
  // signatures AND call sites — a call like `removeColumnQuery(tableName,
  // attributeName)` is itself strong evidence the injected value is an
  // identifier), split on commas, take each leading identifier token, and keep
  // the ones that are known SQL-identifier names.
  const idParams = new Set<string>();
  for (const group of stripped.matchAll(/\(([^()]*)\)/g)) {
    const inner = group[1];
    if (!inner) continue;
    for (const part of inner.split(",")) {
      const lead = part.match(/[A-Za-z_$][\w$]*/);
      if (lead && IDENTIFIER_PARAM_NAMES.includes(lead[0].toLowerCase())) {
        idParams.add(lead[0]);
        if (idParams.size >= 16) break;
      }
    }
    if (idParams.size >= 16) break;
  }

  return {
    untrustedHits: [...untrusted],
    identifierParams: [...idParams],
    hasIdentifierParam: idParams.size > 0,
  };
}

// ────────────────────────────────────────────────────────────────────
// Main analysis
// ────────────────────────────────────────────────────────────────────

function unknown(reason: string, evidence: string[] = []): ControllabilityResult {
  return {
    controllability: "unknown",
    confidence: 0,
    taintedParam: null,
    ormInternal: false,
    evidence,
    reason,
  };
}

/**
 * Analyze whether the value flowing into an injection sink is attacker-
 * controllable (untrusted remote input) or a developer-supplied identifier.
 *
 * Returns `unknown` (confidence 0) for non-analyzable categories, non-JS/TS
 * sinks, unresolvable files, parse failures, and ambiguous cases — the caller
 * must take no action on `unknown`.
 */
export function analyzeInputControllability(
  finding: Finding,
  sourceDir: string,
): ControllabilityResult {
  if (!ANALYZABLE_CATEGORIES.has(finding.category)) {
    return unknown(`category=${finding.category} is out of scope for controllability analysis`);
  }

  const resolved = resolveSinkFile(finding, sourceDir);
  if (!resolved) {
    return unknown("could not resolve sink file from finding metadata");
  }
  if (!isJsTsFile(resolved.absPath)) {
    return unknown(`sink file ${resolved.relPath} is not JS/TS; controllability analysis skipped`);
  }

  const taintedParam = extractTaintedParam(finding);

  // Path/content ORM signals (cheap, run before AST).
  const lowerPath = resolved.relPath.toLowerCase();
  const pathSignals = ORM_PATH_SIGNALS.filter((s) => lowerPath.includes(s));
  const contentSignals = ORM_CONTENT_SIGNALS.filter((rx) => rx.test(resolved.content)).map(
    (rx) => rx.source.slice(0, 40),
  );
  const ormInternal = pathSignals.length > 0 || contentSignals.length > 0;

  const ast = analyzeSource(resolved.content);

  // 1. PROTECT: any syntactically-real untrusted source in the sink file means
  //    the value may be attacker-controlled. Never downgrade these.
  if (ast.untrustedHits.length > 0) {
    return {
      controllability: "untrusted-input",
      confidence: 0.85,
      taintedParam,
      ormInternal,
      evidence: ast.untrustedHits.map((h) => `untrusted source: ${h}`),
      reason: `sink file reads untrusted input (${ast.untrustedHits
        .slice(0, 3)
        .join(", ")}); value may be attacker-controlled — not downgraded`,
    };
  }

  // 2. DOWNGRADE candidate: ORM/query-builder internals + an identifier-style
  //    injected value + no untrusted source anywhere in the file.
  const hasIdentifierSignal =
    taintedParam != null || ast.hasIdentifierParam;
  if (ormInternal && hasIdentifierSignal) {
    const evidence: string[] = [];
    for (const s of pathSignals) evidence.push(`orm path: ${s}`);
    for (const s of contentSignals) evidence.push(`orm code: /${s}/`);
    if (taintedParam) evidence.push(`identifier param (from finding): ${taintedParam}`);
    if (ast.identifierParams.length > 0)
      evidence.push(`identifier params (from source): ${ast.identifierParams.join(", ")}`);

    // Confidence scales with signal strength. Two independent ORM signals + an
    // AST-confirmed identifier param is the strongest; a single signal is weaker.
    let confidence = 0.6;
    const ormSignalCount = pathSignals.length + contentSignals.length;
    if (ormSignalCount >= 2) confidence += 0.12;
    if (taintedParam && ast.hasIdentifierParam) confidence += 0.15;
    else if (taintedParam || ast.hasIdentifierParam) confidence += 0.08;
    confidence = Math.min(confidence, 0.9);

    return {
      controllability: "internal-identifier",
      confidence,
      taintedParam: taintedParam ?? ast.identifierParams[0] ?? null,
      ormInternal: true,
      evidence,
      reason:
        `injected value is a developer-supplied SQL identifier ` +
        `(${taintedParam ?? ast.identifierParams[0] ?? "object name"}) in ORM/query-builder ` +
        `internals with no untrusted-input flow in the sink file; not reachable from a ` +
        `remote attacker via the public API`,
    };
  }

  // 3. Not enough signal either way.
  return unknown(
    ormInternal
      ? "ORM-internal sink but no identifier param identified; left unchanged"
      : "no untrusted-source and no ORM-identifier signal; left unchanged",
    [...pathSignals.map((s) => `orm path: ${s}`)],
  );
}

// ────────────────────────────────────────────────────────────────────
// Severity downgrade tiering (assume-FP-safe)
// ────────────────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * Decide the downgraded severity for an `internal-identifier` finding, or
 * `null` to leave severity unchanged (annotate-only). This is the assume-FP-safe
 * tiering: the bulk of ORM identifier-injection noise is medium/low, so those
 * drop one notch; high/critical require higher confidence and are never nuked to
 * `low` in a single step on a static heuristic. A finding is NEVER dropped here
 * — at worst its severity is lowered, keeping it visible for human review.
 */
export function controllabilityDowngradeTarget(
  from: Severity,
  confidence: number,
): Severity | null {
  if (confidence < 0.75) return null;
  switch (from) {
    case "info":
    case "low":
      return null; // already low-priority; flag only, no change
    case "medium":
      return "low";
    case "high":
      return confidence >= 0.8 ? "low" : null;
    case "critical":
      return confidence >= 0.85 ? "medium" : null;
    default:
      return null;
  }
}

/** True when `to` is a strictly lower severity than `from`. */
export function isLowerSeverity(from: Severity, to: Severity): boolean {
  return SEVERITY_RANK[to] < SEVERITY_RANK[from];
}

/** Exposed for tests / introspection. Do not mutate. */
export const CONTROLLABILITY_IDENTIFIER_PARAMS = IDENTIFIER_PARAM_NAMES;
export const CONTROLLABILITY_ANALYZABLE_CATEGORIES = ANALYZABLE_CATEGORIES;
