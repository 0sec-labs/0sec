import { execFileSync } from "node:child_process";
import type { SemgrepFinding } from "@pwnkit/shared";

/**
 * Haskell static-analysis SEED layer for the `cardano-haskell` review profile.
 *
 * ROOT CAUSE THIS FIXES: Semgrep / Foxguard cannot parse Haskell, so a
 * `cardano-haskell` review runs with an EMPTY `semgrepResults` list — the LLM
 * review starts from a blind full-tree pass over large multi-package cabal
 * projects. This module gives that review CONCRETE seeds (file:line + rule +
 * snippet + why) to hunt from, in the exact `SemgrepFinding` shape the review
 * prompt already consumes (`cardanoHaskellReviewAgentPrompt`).
 *
 * MVP SCOPE (honest): this is a ripgrep/regex seed layer. It is a LEAD
 * generator, not a verifier — every seed is "this token appears here, look at
 * it", and the review agent still does the reachability + total-function +
 * already-caught analysis the profile mandates. Regex cannot prove a `head` is
 * reachable from untrusted input; it can only point the agent at the call site.
 * `hlint --json` integration (and a Stan pass) is a deliberate FOLLOW-UP — both
 * need a Haskell toolchain in the sandbox that is not present today (`hlint` is
 * not on PATH in the engine image). The regex layer ships now and needs only
 * ripgrep, which the engine already depends on.
 *
 * The bug classes mirror the `cardano-haskell` profile's "Hypothesis classes"
 * section, so the seeds and the prompt speak the same language.
 */

/** A single regex rule within a bug class. */
interface HaskellRule {
  /** Sub-rule id (becomes the suffix of the SemgrepFinding ruleId). */
  id: string;
  /** Source-text regex. Matched against the whole line. */
  re: RegExp;
  /** Short "why this matters" shown to the review agent. */
  why: string;
}

/** A bug class = a group of rules sharing a severity bucket. */
interface HaskellBugClass {
  /** Class id (prefixes the ruleId, e.g. `partial-function`). */
  klass: string;
  /** Default severity bucket for seeds in this class. */
  severity: "high" | "medium" | "low" | "info";
  rules: HaskellRule[];
}

/**
 * Bug classes the `cardano-haskell` profile cares about. These are LEADS, not
 * findings — severity reflects "how often this token is the actual bug", not a
 * confirmed impact. FFI memory-safety is the only class with classic
 * memory-corruption potential, so it ranks highest.
 */
const BUG_CLASSES: HaskellBugClass[] = [
  {
    klass: "ffi-memory-safety",
    severity: "high",
    rules: [
      { id: "foreign-import", re: /\bforeign\s+import\b/, why: "FFI boundary — the cardano-base encryptedDerivePublic OOB class lives here; check every length assumption against actual ByteString length." },
      { id: "peekByteOff", re: /\bpeekByteOff\b/, why: "Offset pointer read — OOB read if the offset/length is attacker-influenced or unchecked against the buffer size." },
      { id: "pokeByteOff", re: /\bpokeByteOff\b/, why: "Offset pointer write — OOB write if the offset/length is attacker-influenced or unchecked." },
      { id: "peek", re: /(?<![A-Za-z0-9_])peek(Array|Elemen|CString)?\b/, why: "Raw pointer/array read — verify the count/length is bounded by the real buffer, not an assumed constant." },
      { id: "poke", re: /(?<![A-Za-z0-9_])poke(Array|Elemen)?\b/, why: "Raw pointer/array write — verify the count/length is bounded by the real buffer." },
      { id: "ptr-arith", re: /\b(plusPtr|castPtr)\b/, why: "Pointer arithmetic / cast — re-typed or offset pointer; OOB if the new view exceeds the allocation." },
      { id: "mallocBytes", re: /\b(mallocBytes|callocBytes|reallocBytes)\b/, why: "Manual allocation — size derived from input can under-allocate vs. later writes." },
      { id: "allocaBytes", re: /\ballocaBytes\b/, why: "Stack buffer sized off one value but possibly written off another — classic size/length mismatch." },
      { id: "withForeignPtr", re: /\bwithForeignPtr\b/, why: "ForeignPtr unwrapped to a raw Ptr — bounds are the caller's responsibility inside the block." },
      { id: "unsafeForeignPtrToPtr", re: /\bunsafeForeignPtrToPtr\b/, why: "ForeignPtr escapes its lifetime as a raw Ptr — use-after-free / OOB if the buffer is freed or shorter than assumed." },
      { id: "unsafeUseAsCString", re: /\bunsafeUseAsCString(Len)?\b/, why: "ByteString viewed as a raw C string without copying — length assumptions cross the FFI boundary here." },
    ],
  },
  {
    klass: "unsafe-escape",
    severity: "high",
    rules: [
      { id: "unsafePerformIO", re: /\bunsafePerformIO\b/, why: "Breaks referential transparency — if the IO is effectful or input-dependent it can be reordered/cached wrongly." },
      { id: "unsafeDupablePerformIO", re: /\bunsafeDupablePerformIO\b/, why: "Like unsafePerformIO but may run twice concurrently — unsafe for non-idempotent or shared-state IO." },
      { id: "accursedUnutterablePerformIO", re: /\baccursedUnutterablePerformIO\b/, why: "The most dangerous unsafe IO escape — any input-dependent effect here is a latent miscompile/UB." },
      { id: "unsafeCoerce", re: /\bunsafeCoerce\b/, why: "Type confusion — reinterprets bits across types; if attacker-influenced data flows in, it is exploitable." },
    ],
  },
  {
    klass: "deserialization-cbor",
    severity: "medium",
    rules: [
      { id: "unsafeFromBuiltinData", re: /\bunsafeFromBuiltinData\b/, why: "Trusts Plutus Data structure it did NOT verify — malformed datum/redeemer causes partial-decode panic or wrong decode." },
      { id: "fromBuiltinData", re: /\bfromBuiltinData\b/, why: "Plutus Data decode — check the malformed/truncated path returns Nothing cleanly rather than throwing." },
      { id: "decodeFull", re: /\bdecodeFull(Decoder|')?\b/, why: "CBOR full-decode of untrusted bytes — verify truncated/malformed input yields a DecoderError, not an exception." },
      { id: "deserialise", re: /\bdeserialise(FromBytes|OrFail|Incremental)?\b/, why: "CBOR deserialisation — `deserialise` (no -OrFail) THROWS on malformed bytes; that is a DoS on an untrusted-input path." },
      { id: "fromCBOR", re: /\b(fromCBOR|decCBOR|decodeCBOR)\b/, why: "CBOR decoder instance — hand-rolled ones often index assumed elements after decodeListLen; check the malformed path." },
      { id: "decodeListLen", re: /\bdecode(ListLen|MapLen|ListLenOf)\b/, why: "Reads an attacker-declared element count — if elements are indexed/allocated off it without a bound, panic or allocate-before-validate OOM." },
    ],
  },
  {
    klass: "partial-function",
    severity: "medium",
    rules: [
      { id: "fromJust", re: /\bfromJust\b/, why: "Throws on Nothing — if attacker bytes can make the Maybe Nothing on this path, it is an uncaught-exception DoS." },
      { id: "head", re: /(?<![A-Za-z0-9_.])head\b/, why: "Throws on []— if attacker input can empty the list reaching here, uncaught-exception DoS. Confirm reachability + non-empty invariant." },
      { id: "tail", re: /(?<![A-Za-z0-9_.])tail\b/, why: "Throws on [] — same empty-list reachability question as head." },
      { id: "last", re: /(?<![A-Za-z0-9_.])last\b/, why: "Throws on [] — attacker-emptied list → uncaught exception." },
      { id: "init", re: /(?<![A-Za-z0-9_.])init\b/, why: "Throws on [] — attacker-emptied list → uncaught exception." },
      { id: "index-op", re: /!!/, why: "List index (!!) throws on out-of-range — if the index is derived from untrusted input, DoS." },
      { id: "map-bang", re: /\b(Map|IntMap|HashMap)\s*\.\s*!/, why: "Map.! throws on a missing key — attacker-chosen key not present → uncaught exception." },
      { id: "read", re: /(?<![A-Za-z0-9_.])read\b(?!s|er|File|Process|able|Only|Write|MVar|TVar|IORef|Ln|Line)/, why: "`read` throws on unparseable input — never run it on untrusted text; use readMaybe." },
      { id: "error", re: /(?<![A-Za-z0-9_.])error\b/, why: "Explicit error call — if a reachable branch on an untrusted-input path hits it, uncaught-exception DoS." },
      { id: "undefined", re: /(?<![A-Za-z0-9_.])undefined\b/, why: "Bottom — if reachable from input, it diverges/throws." },
      { id: "incomplete-case", re: /\bcase\b.*\bof\b/, why: "case expression — best-effort lead: check it is exhaustive for attacker-reachable constructors (partial case throws)." },
    ],
  },
  {
    klass: "arithmetic",
    severity: "low",
    rules: [
      { id: "div-mod", re: /(?<![A-Za-z0-9_.])(div|mod|quot|rem)(?![A-Za-z0-9_'])/, why: "Division/modulo — divide-by-zero throws if the denominator is derived from untrusted input." },
      { id: "natural-subtract", re: /\bNatural\b/, why: "Natural arithmetic — subtraction underflow (a - b with b > a) throws; check subtraction sites on this type." },
      { id: "fromIntegral", re: /\bfromIntegral\b/, why: "Width-changing conversion — narrowing (e.g. Integer→Int/Word8) silently truncates; a length/size truncated here can desync a later check." },
      { id: "toEnum", re: /\btoEnum\b/, why: "toEnum throws on an out-of-range Int — if the value comes from a decoded tag/byte, range-check first." },
    ],
  },
  {
    klass: "lazy-eval-dos",
    severity: "low",
    rules: [
      { id: "lazy-foldl", re: /(?<![A-Za-z0-9_.])foldl(?!')\b/, why: "Non-strict foldl over input-sized data builds a thunk chain → space leak / OOM. Prefer foldl'." },
      { id: "lazy-insertWith", re: /\binsertWith\b(?!')/, why: "Lazy Map.insertWith accumulates unforced thunks in the map values → space leak under attacker-sized input." },
      { id: "lazy-scanl", re: /(?<![A-Za-z0-9_.])scanl(?!')\b/, why: "Non-strict scanl over input-sized data builds thunks → space leak." },
    ],
  },
];

/** Per-class cap so the seed list stays useful, not enormous. */
const PER_CLASS_CAP = 25;
/** Global cap across all classes (the prompt only renders the first 30 anyway). */
const GLOBAL_CAP = 120;
/** ripgrep wall-clock guard. */
const RG_TIMEOUT_MS = 60_000;

interface RgMatch {
  path: string;
  lineNumber: number;
  line: string;
  column: number;
}

/**
 * Strip lookbehind/lookahead groups from a regex source so it is accepted by
 * ripgrep's default (Rust regex) engine, which rejects lookaround. The rule's
 * lookarounds never contain a nested `)`, so a flat removal is safe. The
 * resulting pattern OVER-matches (e.g. `head` now also matches `subhead`);
 * `classifyLine` re-applies the precise rule regex in JS to drop those.
 */
function toRgSource(source: string): string {
  return source
    .replace(/\(\?<[=!][^)]*\)/g, "") // lookbehind (?<=...) / (?<!...)
    .replace(/\(\?[=!][^)]*\)/g, ""); // lookahead  (?=...)  / (?!...)
}

/**
 * Run ripgrep for one bug class (all its rules OR-ed via -e) and return raw
 * line matches. We OR the class's patterns into ONE ripgrep invocation (~6
 * processes total, not one-per-rule) and re-classify each hit in JS against the
 * rule table — fast over big trees, precise per-rule labelling.
 */
function rgClass(targetPath: string, klass: HaskellBugClass): RgMatch[] {
  // Build a single alternation of the class's patterns for ONE ripgrep pass.
  // ripgrep's default (Rust regex) engine rejects lookaround, and the engine
  // image's rg is not guaranteed to be PCRE2-enabled — so we STRIP lookbehind/
  // lookahead for the rg pass (it merely over-matches), then re-classify every
  // hit in JS with the precise lookaround-bearing rule regex. This keeps a
  // single source of truth (the rule's `re`) while staying portable.
  const combined = klass.rules.map((r) => `(?:${toRgSource(r.re.source)})`).join("|");
  const args = [
    "--json",
    "-g",
    "*.hs",
    "-g",
    "*.lhs",
    // Skip build artifacts that occasionally survive in a tree.
    "-g",
    "!dist-newstyle/**",
    "-g",
    "!dist/**",
    "-g",
    "!.stack-work/**",
    "-e",
    combined,
    targetPath,
  ];

  let raw = "";
  try {
    raw = execFileSync("rg", args, {
      timeout: RG_TIMEOUT_MS,
      stdio: "pipe",
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (err) {
    // ripgrep exits 1 when there are no matches — that is not an error for us.
    const code = err && typeof err === "object" && "status" in err ? (err as { status: number }).status : undefined;
    const stdout = err && typeof err === "object" && "stdout" in err ? (err as { stdout?: Buffer | string }).stdout : undefined;
    if (code === 1 && !stdout) return [];
    raw = typeof stdout === "string" ? stdout : stdout ? stdout.toString("utf-8") : "";
    if (!raw) return [];
  }

  const matches: RgMatch[] = [];
  for (const rawLine of raw.split("\n")) {
    if (!rawLine.trim()) continue;
    let obj: unknown;
    try {
      obj = JSON.parse(rawLine);
    } catch {
      continue;
    }
    if (!obj || typeof obj !== "object") continue;
    const rec = obj as { type?: string; data?: any };
    if (rec.type !== "match" || !rec.data) continue;
    const path: string | undefined = rec.data.path?.text;
    const lineNumber: number | undefined = rec.data.line_number;
    const lineText: string | undefined = rec.data.lines?.text;
    const column: number = rec.data.submatches?.[0]?.start ?? 0;
    if (!path || !lineNumber || lineText === undefined) continue;
    matches.push({ path, lineNumber, line: lineText.replace(/\n$/, ""), column });
  }
  return matches;
}

/**
 * Decide whether a matched line should be dropped as obvious noise:
 * - pure comment lines (`-- ...`, `{- ... -}`), where a token is documented not used;
 * - import lines (the symbol is imported, not a call site) EXCEPT for the FFI
 *   class, where `foreign import` IS the signal.
 */
function isNoiseLine(line: string, klass: string): boolean {
  const trimmed = line.trimStart();
  if (trimmed.startsWith("--") || trimmed.startsWith("{-") || trimmed.startsWith("-- |")) return true;
  if (klass !== "ffi-memory-safety" && /^import(\s|$)/.test(trimmed)) return true;
  return false;
}

/**
 * Classify a matched line to the first rule in the class whose regex matches.
 * Returns undefined if none re-match (can happen when the combined alternation
 * matched via a different rule's overlap — rare; we just skip).
 */
function classifyLine(line: string, klass: HaskellBugClass): HaskellRule | undefined {
  for (const rule of klass.rules) {
    // Rebuild a global-free copy to avoid lastIndex state across calls.
    const re = new RegExp(rule.re.source, rule.re.flags.replace("g", ""));
    if (re.test(line)) return rule;
  }
  return undefined;
}

/**
 * Generate Haskell seeds for a source tree, as `SemgrepFinding[]` ready to push
 * into the review pipeline's `semgrepFindings` list. Paths are made
 * tree-relative so they match the rest of the pipeline's conventions.
 */
export function generateHaskellSeeds(targetPath: string): SemgrepFinding[] {
  const base = targetPath.endsWith("/") ? targetPath : `${targetPath}/`;
  const seeds: SemgrepFinding[] = [];

  for (const klass of BUG_CLASSES) {
    let kept = 0;
    let raw: RgMatch[];
    try {
      raw = rgClass(targetPath, klass);
    } catch {
      // ripgrep missing or failed for this class — skip it, keep the others.
      continue;
    }
    for (const m of raw) {
      if (kept >= PER_CLASS_CAP) break;
      if (isNoiseLine(m.line, klass.klass)) continue;
      const rule = classifyLine(m.line, klass);
      if (!rule) continue;
      const relPath = m.path.startsWith(base) ? m.path.slice(base.length) : m.path;
      seeds.push({
        ruleId: `haskell-seed.${klass.klass}.${rule.id}`,
        message: rule.why,
        severity: klass.severity,
        path: relPath,
        startLine: m.lineNumber,
        endLine: m.lineNumber,
        snippet: m.line.trim().slice(0, 300),
        metadata: {
          source: "haskell-seed",
          bugClass: klass.klass,
          rule: rule.id,
          // Honest provenance: this is a regex lead, not a verified finding.
          seedKind: "regex",
        },
      });
      kept++;
    }
  }

  // Stable, useful ordering: highest-severity classes first (FFI / unsafe), and
  // hard-cap the total so the prompt sees the most promising leads.
  const sevRank: Record<string, number> = { high: 0, medium: 1, low: 2, info: 3 };
  seeds.sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9));
  return seeds.slice(0, GLOBAL_CAP);
}
