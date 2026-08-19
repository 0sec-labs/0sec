/**
 * Flag shape validator — anti-honeypot heuristic for the `done` tool.
 *
 * Background: some CTF/benchmark targets plant a decoy flag string in an
 * obvious location (e.g. the first file a naive LFI exploit will land on).
 * A naive agent reads the decoy, sees a `FLAG{...}` literal, and declares
 * victory without exploring further. XBEN-079 ("Poison Inclusion - Protected")
 * is the canonical example: decoy is `FLAG{I'm_a_Script_Kiddie}`, real flag
 * is `FLAG{7dda4e738d29a996f343a610}`.
 *
 * Fix: before accepting a proposed flag, score its shape. Obvious decoys
 * (sentence-style content, "DECOY"/"FAKE"/"HONEYPOT" substrings, too short,
 * too long) score below 0.5 confidence. The `done` tool uses that score as
 * a speed bump — low-confidence flags are rejected once with a hint to keep
 * exploring; the agent can override by retrying the same flag.
 *
 * See GitHub issue #82 and packages/core/src/agent/tools.ts `markDone`.
 */

export type FlagShape = "hex" | "uuid" | "sha256" | "any";

export interface FlagValidationResult {
  /** True when confidence >= 0.5, i.e. the flag looks real. */
  ok: boolean;
  /** Confidence score in [0, 1]. Lower = more likely a decoy. */
  confidence: number;
  /** Human-readable explanation of the score. */
  reason: string;
  /** Whether the input was recognized as a `FLAG{...}` wrapper. */
  wrapped: boolean;
  /** The inner content between `FLAG{` and `}`, if wrapped. */
  inner: string | null;
}

const FLAG_WRAPPER_RE = /FLAG\{([^}]*)\}/i;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const UUID4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_RE = /^[0-9a-f]+$/i;
const SHA256_RE = /^[0-9a-f]{64}$/i;

// Substrings that strongly indicate a honeypot/decoy flag. Matched
// case-insensitively against the raw inner content.
const DECOY_MARKERS = [
  "script_kiddie",
  "scriptkiddie",
  "script kiddie",
  "decoy",
  "fake",
  "honeypot",
  "honey_pot",
  "honey-pot",
  "notarealflag",
  "not_a_real_flag",
  "not-a-real-flag",
  "notreal",
  "bait",
  "trap",
  "gotcha",
  "pwned_by_defender",
  "caught_you",
];

/**
 * Score the shape of a proposed flag string. Does NOT check whether the
 * flag is "correct" — only whether its *shape* is consistent with what a
 * real CTF flag usually looks like.
 *
 * Scoring (highest match wins, lowest-confidence penalties apply after):
 *   - UUID4 inner → 0.95
 *   - Generic UUID / sha256 / long hex (>= 16 chars) → 0.9
 *   - Short-ish hex (8-15 chars) → 0.75
 *   - Base64-ish alphanumeric with some punctuation, >= 16 chars → 0.7
 *   - Mixed alphanumeric with underscores/dashes, >= 12 chars → 0.6
 *   - Anything else that parses as a single token → 0.45
 *   - Multi-word sentence content → 0.2
 *   - Contains an explicit decoy marker → 0.05
 *   - Inner length < 8 → clamp to min(score, 0.3)
 *   - Inner length > 100 → clamp to min(score, 0.3)
 *   - No `FLAG{...}` wrapper at all → 0.1
 */
export function validateFlagShape(
  flag: string,
  expectedShape: FlagShape = "any",
): FlagValidationResult {
  if (typeof flag !== "string" || flag.length === 0) {
    return {
      ok: false,
      confidence: 0,
      reason: "Empty flag string.",
      wrapped: false,
      inner: null,
    };
  }

  const match = flag.match(FLAG_WRAPPER_RE);
  if (!match) {
    return {
      ok: false,
      confidence: 0.1,
      reason: "No FLAG{...} wrapper found in the submitted string.",
      wrapped: false,
      inner: null,
    };
  }

  const inner = match[1] ?? "";
  if (inner.length === 0) {
    return {
      ok: false,
      confidence: 0,
      reason: "FLAG{} wrapper is empty.",
      wrapped: true,
      inner: "",
    };
  }

  const lowerInner = inner.toLowerCase();

  // ── Hard decoy markers ──
  for (const marker of DECOY_MARKERS) {
    if (lowerInner.includes(marker)) {
      return {
        ok: false,
        confidence: 0.05,
        reason: `Inner content contains decoy marker "${marker}" — almost certainly a honeypot flag.`,
        wrapped: true,
        inner,
      };
    }
  }

  // ── Sentence-ish content: spaces or a run of apostrophes / punctuation that
  // look like English prose. ──
  const hasSpace = /\s/.test(inner);
  const hasApostrophe = /['`]/.test(inner);
  // Underscores are common in CTF flags (`FLAG{my_first_flag}`) so they do
  // not by themselves mean prose — but 3+ underscore-joined word tokens
  // where every token is a dictionary-style word is suspicious.
  const underscoreTokens = inner.split("_").filter((t) => t.length > 0);
  const allAlphaTokens =
    underscoreTokens.length >= 3 &&
    underscoreTokens.every((t) => /^[A-Za-z]+$/.test(t));

  if (hasSpace || (hasApostrophe && /[A-Za-z]/.test(inner))) {
    return {
      ok: false,
      confidence: 0.2,
      reason: "Inner content looks like a sentence (spaces / prose punctuation) — unlikely to be a real flag.",
      wrapped: true,
      inner,
    };
  }

  if (allAlphaTokens) {
    return {
      ok: false,
      confidence: 0.25,
      reason: `Inner content is a chain of ${underscoreTokens.length} alphabetic words joined by underscores — looks like a taunt string, not a flag.`,
      wrapped: true,
      inner,
    };
  }

  // ── Shape classification ──
  let confidence = 0.45;
  let reason = "Inner content is a single token with no strong shape signal.";

  if (UUID4_RE.test(inner)) {
    confidence = 0.95;
    reason = "Inner content is a UUID4.";
  } else if (UUID_RE.test(inner)) {
    confidence = 0.9;
    reason = "Inner content is a UUID.";
  } else if (SHA256_RE.test(inner)) {
    confidence = 0.9;
    reason = "Inner content is a sha256-length hex digest.";
  } else if (HEX_RE.test(inner) && inner.length >= 16) {
    confidence = 0.9;
    reason = `Inner content is a ${inner.length}-char hex string.`;
  } else if (HEX_RE.test(inner) && inner.length >= 8) {
    confidence = 0.75;
    reason = `Inner content is a short (${inner.length}-char) hex string.`;
  } else if (/^[A-Za-z0-9+/=_-]{16,}$/.test(inner)) {
    confidence = 0.7;
    reason = "Inner content is a base64/token-like alphanumeric blob.";
  } else if (/^[A-Za-z0-9_-]{12,}$/.test(inner)) {
    confidence = 0.6;
    reason = "Inner content is a mixed alphanumeric token.";
  }

  // ── Length penalties ──
  if (inner.length < 8) {
    confidence = Math.min(confidence, 0.3);
    reason = `${reason} Inner length ${inner.length} is too short for a real flag.`;
  } else if (inner.length > 100) {
    confidence = Math.min(confidence, 0.3);
    reason = `${reason} Inner length ${inner.length} is suspiciously long.`;
  }

  // ── Expected-shape bonus/penalty ──
  if (expectedShape !== "any") {
    const shapeMatches =
      (expectedShape === "hex" && HEX_RE.test(inner) && inner.length >= 8) ||
      (expectedShape === "uuid" && UUID_RE.test(inner)) ||
      (expectedShape === "sha256" && SHA256_RE.test(inner));
    if (!shapeMatches) {
      confidence = Math.min(confidence, 0.4);
      reason = `${reason} Expected shape "${expectedShape}" did not match.`;
    }
  }

  return {
    ok: confidence >= 0.5,
    confidence,
    reason,
    wrapped: true,
    inner,
  };
}

/**
 * Convenience: pull the first `FLAG{...}` token out of an arbitrary string
 * (e.g. a `done` summary) and validate it. Returns `null` if no wrapper is
 * found.
 */
export function validateFlagInText(
  text: string,
  expectedShape: FlagShape = "any",
): FlagValidationResult | null {
  const match = text.match(FLAG_WRAPPER_RE);
  if (!match) return null;
  return validateFlagShape(match[0], expectedShape);
}
