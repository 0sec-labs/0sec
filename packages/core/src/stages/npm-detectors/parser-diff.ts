/**
 * Detector: `parser-diff` — differential parser confusion in IP/host SSRF
 * filters (CWE-918 / CWE-20).
 *
 * Ported from the proven prototype `scratchpad/parser-diff/ip-cidr/` (found the
 * cidr-tools SSRF mis-normalization). Oracle-vs-impl divergence: a ground-truth
 * `inet_aton` oracle (glibc getaddrinfo semantics — the address a real
 * `connect()` actually targets) is compared against a package-based SSRF filter.
 * CONFIRMED only when the oracle resolves the input to an UNSAFE target
 * (loopback / private / link-local / metadata) yet the filter would treat it as
 * SAFE-to-connect — an observed, exploitable divergence, not a style nit.
 */

import type {
  Detector,
  DetectorCandidate,
  DetectorConfirmation,
  PackageProbe,
  PackageRef,
} from "./types.js";

// ── the oracle (ground truth) ────────────────────────────────────────────────

export interface OracleResult {
  ok: boolean;
  long?: number;
  dotted?: string;
  cls?: string;
}

function parsePart(s: string): number | null {
  if (s === "") return null;
  let val: number;
  let m: RegExpExecArray | null;
  if ((m = /^0[xX]([0-9a-fA-F]+)$/.exec(s))) val = parseInt(m[1], 16);
  else if (/^0[0-7]*$/.exec(s)) val = parseInt(s, 8);
  else if (/^0[0-7]*[89]/.exec(s)) return null;
  else if (/^[0-9]+$/.exec(s)) val = parseInt(s, 10);
  else return null;
  if (!Number.isFinite(val) || val < 0) return null;
  return val;
}

/** glibc inet_aton: octal/hex/decimal, 1–4 parts. The socket-truth resolver. */
export function inetAton(input: string): OracleResult {
  if (typeof input !== "string") return { ok: false };
  const parts = input.split(".");
  if (parts.length < 1 || parts.length > 4) return { ok: false };
  const nums = parts.map(parsePart);
  if (nums.some((n) => n === null)) return { ok: false };
  const n = nums.length;
  const v = nums as number[];
  let long: number;
  if (n === 1) {
    if (v[0] > 0xffffffff) return { ok: false };
    long = v[0] >>> 0;
  } else if (n === 2) {
    if (v[0] > 0xff || v[1] > 0xffffff) return { ok: false };
    long = ((v[0] << 24) | v[1]) >>> 0;
  } else if (n === 3) {
    if (v[0] > 0xff || v[1] > 0xff || v[2] > 0xffff) return { ok: false };
    long = ((v[0] << 24) | (v[1] << 16) | v[2]) >>> 0;
  } else {
    if (v.some((x) => x > 0xff)) return { ok: false };
    long = ((v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3]) >>> 0;
  }
  const dotted = [long >>> 24, (long >>> 16) & 255, (long >>> 8) & 255, long & 255].join(".");
  return { ok: true, long, dotted, cls: classify(long) };
}

export function classify(long: number): string {
  const a = long >>> 24;
  const b = (long >>> 16) & 255;
  if (a === 127) return "loopback";
  if (a === 10) return "private";
  if (a === 172 && b >= 16 && b <= 31) return "private";
  if (a === 192 && b === 168) return "private";
  if (a === 169 && b === 254) return long === 0xa9fea9fe ? "metadata(169.254.169.254)" : "linklocal";
  if (a === 100 && b >= 64 && b <= 127) return "cgnat";
  if (a === 0) return "this-network";
  return "PUBLIC";
}

/** Is this an "unsafe" target an SSRF filter must block? */
export function isUnsafe(cls: string | undefined): boolean {
  return !!cls && cls !== "PUBLIC";
}

/** Inputs whose glibc-resolved target diverges from naive IP parsing. */
export const PARSER_DIFF_CORPUS: readonly string[] = [
  // octal / hex / decimal encodings of loopback + metadata
  "0177.0.0.1", "0177.00.00.01", "0x7f.0.0.1", "0x7f000001", "0x7f.1",
  "2130706433", "017700000001", "127.1", "127.0.1",
  // metadata (169.254.169.254) in many encodings
  "169.254.169.254", "0251.0376.0251.0376", "0xa9.0xfe.0xa9.0xfe",
  "169.254.43518", "169.16689150", "2852039166",
  // private
  "0300.0250.0.01", "010.0.0.1", "192.168.257",
  // whitespace-wrapped loopback (clients trim, getaddrinfo does not)
  " 127.0.0.1", "127.0.0.1 ", "0177.0.0.1 ",
];

// ── candidate + generic confirm (the dispose) ────────────────────────────────

export interface ParserDiffCandidate extends DetectorCandidate {
  /**
   * For an input, would the package-based SSRF filter treat it as SAFE to
   * connect (i.e. NOT blocked as private/loopback/etc)? `treatedAsSafe: true`
   * on an oracle-unsafe input is the exploitable divergence.
   */
  filterVerdict(input: string): { treatedAsSafe: boolean; note: string };
}

export interface ParserDiffHit {
  input: string;
  socketTarget: string;
  cls: string;
  note: string;
}

/** Deterministic divergence scan for one candidate filter. */
export function scanDivergences(candidate: ParserDiffCandidate, corpus: readonly string[] = PARSER_DIFF_CORPUS): ParserDiffHit[] {
  const hits: ParserDiffHit[] = [];
  for (const input of corpus) {
    const oracle = inetAton(input);
    if (!oracle.ok || !isUnsafe(oracle.cls)) continue;
    let verdict: { treatedAsSafe: boolean; note: string };
    try {
      verdict = candidate.filterVerdict(input);
    } catch {
      continue;
    }
    if (verdict.treatedAsSafe) {
      hits.push({ input, socketTarget: oracle.dotted!, cls: oracle.cls!, note: verdict.note });
    }
  }
  return hits;
}

export function confirmParserDiff(candidate: ParserDiffCandidate): DetectorConfirmation {
  const hits = scanDivergences(candidate);
  if (hits.length === 0) return { confirmed: false, evidence: { observation: "" } };
  const h = hits[0];
  return {
    confirmed: true,
    severity: "high",
    source: candidate.label,
    evidence: {
      observation: `oracle resolves ${JSON.stringify(h.input)} to ${h.socketTarget} [${h.cls}] but ${candidate.label} treats it as safe (${h.note})`,
      payload: h.input,
      analysis: [
        `${candidate.label} disagrees with glibc getaddrinfo (inet_aton) semantics on ${hits.length}`,
        `input(s). A real socket connect() targets the internal address while the filter classifies`,
        `it public → SSRF allowlist bypass (CWE-918). Sample: ${hits.slice(0, 3).map((x) => `${x.input}→${x.socketTarget}`).join(", ")}.`,
      ].join(" "),
    },
  };
}

// ── SSRF-filter adapters (candidate proposal) ────────────────────────────────

type UnknownFn = (...a: unknown[]) => unknown;
function safe<T>(f: () => T): T | undefined {
  try {
    return f();
  } catch {
    return undefined;
  }
}
function fnOf(mod: Record<string, unknown>, key: string): UnknownFn | undefined {
  const v = mod[key];
  return typeof v === "function" ? (v as UnknownFn) : undefined;
}

interface FilterAdapter {
  id: string;
  matches(pkgName: string, mod: Record<string, unknown>): boolean;
  candidate(pkgName: string, mod: Record<string, unknown>): ParserDiffCandidate | undefined;
}

const ADAPTERS: FilterAdapter[] = [
  // `ip`: isPrivate / isPublic / isLoopback booleans.
  {
    id: "ip",
    matches: (name, mod) => name === "ip" || (!!fnOf(mod, "isPrivate") && !!fnOf(mod, "isPublic")),
    candidate(name, mod) {
      const isPublic = fnOf(mod, "isPublic");
      const isPrivate = fnOf(mod, "isPrivate");
      const isLoopback = fnOf(mod, "isLoopback");
      if (!isPublic && !isPrivate) return undefined;
      return {
        id: `${name}.isPublic`,
        label: `${name}.isPublic`,
        field: "",
        filterVerdict(input) {
          const pub = safe(() => isPublic?.(input));
          if (pub === true) return { treatedAsSafe: true, note: "ip.isPublic=true" };
          const priv = safe(() => isPrivate?.(input));
          const lo = safe(() => isLoopback?.(input));
          if (priv === false && lo === false) return { treatedAsSafe: true, note: "ip.isPrivate=false&isLoopback=false" };
          return { treatedAsSafe: false, note: "blocked" };
        },
      } as ParserDiffCandidate;
    },
  },
  // `ipaddr.js`: isValid + parse().range(); invalid ⇒ filter skips ⇒ bypass.
  {
    id: "ipaddr.js",
    matches: (name, mod) => name === "ipaddr.js" || (!!fnOf(mod, "isValid") && !!fnOf(mod, "parse")),
    candidate(name, mod) {
      const isValid = fnOf(mod, "isValid");
      const parse = fnOf(mod, "parse");
      if (!isValid || !parse) return undefined;
      const SAFE_RANGES = /loopback|private|linkLocal|carrierGradeNat|unspecified/;
      return {
        id: `${name}.range`,
        label: `${name}.range`,
        field: "",
        filterVerdict(input) {
          const valid = safe(() => isValid(input));
          if (valid !== true) return { treatedAsSafe: true, note: "ipaddr.isValid=false(filter-skips)" };
          const range = safe(() => {
            const p = parse(input) as { range?: () => string };
            return p.range ? p.range() : undefined;
          });
          if (typeof range === "string" && !SAFE_RANGES.test(range)) {
            return { treatedAsSafe: true, note: `ipaddr.range=${range}(unsafe-as-safe)` };
          }
          return { treatedAsSafe: false, note: "blocked" };
        },
      } as ParserDiffCandidate;
    },
  },
  // `is-ip`: not-recognized-as-IP ⇒ host passed straight to DNS/fetch ⇒ bypass.
  {
    id: "is-ip",
    matches: (name, mod) => name === "is-ip" || typeof mod["isIP"] === "function" || typeof mod["default"] === "function",
    candidate(name, mod) {
      const isIP = fnOf(mod, "isIP") ?? (typeof mod["default"] === "function" ? (mod["default"] as UnknownFn) : undefined);
      if (!isIP) return undefined;
      return {
        id: `${name}.isIP`,
        label: `${name}.isIP`,
        field: "",
        filterVerdict(input) {
          const rec = safe(() => isIP(input));
          if (rec === false) return { treatedAsSafe: true, note: "is-ip=NOT-IP(passed-to-DNS)" };
          return { treatedAsSafe: false, note: "recognized" };
        },
      } as ParserDiffCandidate;
    },
  },
  // `cidr-tools`: normalizeCidr mis-normalization — the confirmed win. If the
  // filter normalises the input to a base whose oracle class is public while the
  // input's true target is internal, the allowlist is bypassed.
  {
    id: "cidr-tools",
    matches: (name, mod) => name === "cidr-tools" || !!fnOf(mod, "normalizeCidr"),
    candidate(name, mod) {
      const normalizeCidr = fnOf(mod, "normalizeCidr");
      if (!normalizeCidr) return undefined;
      return {
        id: `${name}.normalizeCidr`,
        label: `${name}.normalizeCidr`,
        field: "",
        filterVerdict(input) {
          const norm = safe(() => normalizeCidr(input));
          const normStr = Array.isArray(norm) ? String(norm[0] ?? "") : String(norm ?? "");
          if (!normStr) return { treatedAsSafe: true, note: "normalizeCidr=∅(filter-skips)" };
          const base = normStr.split("/")[0].trim();
          const baseOracle = inetAton(base);
          if (baseOracle.ok && !isUnsafe(baseOracle.cls)) {
            return { treatedAsSafe: true, note: `normalizeCidr→${normStr}(base ${baseOracle.cls})` };
          }
          return { treatedAsSafe: false, note: "blocked" };
        },
      } as ParserDiffCandidate;
    },
  },
];

// ── the detector ─────────────────────────────────────────────────────────────

export const parserDiffDetector: Detector<ParserDiffCandidate> = {
  id: "parser-diff",
  title: "SSRF Filter Parser Confusion (differential)",
  cwe: "CWE-918",
  category: "ssrf",
  severityFloor: "high",
  description:
    "Differential IP/host parser confusion: compares a package SSRF filter against a glibc inet_aton oracle; confirmed when the oracle resolves an input to an internal target the filter treats as public.",
  appliesTo(_pkg: PackageRef): boolean {
    // Adapter matching in identify is the real filter.
    return true;
  },
  identifyCandidates(probe: PackageProbe): ParserDiffCandidate[] {
    const mod = probe.load(probe.pkg.name);
    if (mod === undefined || (typeof mod !== "object" && typeof mod !== "function")) {
      probe.note?.(`parser-diff: could not load ${probe.pkg.name}`);
      return [];
    }
    const modRec = mod as Record<string, unknown>;
    const out: ParserDiffCandidate[] = [];
    for (const adapter of ADAPTERS) {
      let matched = false;
      try {
        matched = adapter.matches(probe.pkg.name, modRec);
      } catch {
        matched = false;
      }
      if (!matched) continue;
      const c = safe(() => adapter.candidate(probe.pkg.name, modRec));
      if (c) out.push(c);
    }
    return out;
  },
  confirm(candidate: ParserDiffCandidate): DetectorConfirmation {
    return confirmParserDiff(candidate);
  },
};
