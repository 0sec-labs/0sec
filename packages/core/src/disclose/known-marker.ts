/**
 * #674 Part E — known-marker signal.
 *
 * A conservative, regex-only classifier that scans supplied source evidence for
 * explicit TODO, FIXME, XXX markers or documented-limitation phrasing. It never
 * auto-drops, auto-promotes, sets severity, or alters verification evidence.
 * The result is a structured courtesy/human-review warning attached to the
 * vendor-notification draft so an operator can decide whether the finding is
 * worth filing.
 *
 * SAFETY: pure — no I/O, no network, no state. A false-positive (flags normal
 * prose as a marker) wastes an operator glance; a false-negative (misses a real
 * marker) is harmless because the operator still reads the finding. The
 * classifier is deliberately narrow to keep the signal trustworthy.
 */

import type { Finding } from "@0sec/shared";

// ── Marker patterns ────────────────────────────────────────────────────────

/** Regex matching the source markers which signal documented maintainer awareness. */
const SOURCE_MARKER_RE =
  /\b(TODO|FIXME|XXX|HACK)\b(?:[(:]\s*(.*?)\s*[):])?|(\bknown[ -](?:limitation|issue)s?\b|\bdocumented[ -]limitation\b)/gi;


/**
 * Fast boolean form of the same marker vocabulary used by {@link detectKnownMarkers}.
 * Keep source-range gates and disclosure-draft warnings semantically aligned.
 */
export function hasKnownMarkerText(source: string): boolean {
  SOURCE_MARKER_RE.lastIndex = 0;
  const matched = SOURCE_MARKER_RE.test(source);
  SOURCE_MARKER_RE.lastIndex = 0;
  return matched;
}
/**
 * One recognized known-marker occurrence.
 *
 * Every field is derived from the supplied source text — nothing is invented.
 * When the caller cannot provide line numbers (raw blob without line info),
 * `lineNumber` stays undefined.
 */
export interface KnownMarker {
  /** The matched marker tag, e.g. "TODO", "FIXME", "XXX", "known limitation". */
  marker: string;
  /** The full line (or excerpt up to 200 chars) that contains the marker. */
  line: string;
  /** 1-based line number, when the caller supplies it. */
  lineNumber?: number;
  /** Source path supplied by the caller, when the marker came from a file. */
  sourcePath?: string;
  /**
   * Up to two surrounding lines of context (the line before and after the
   * marker line), when available. Empty when there is no surrounding text.
   */
  context?: string;
}

/**
 * Structured marker evidence. Never a boolean-only guess: `hasKnownMarker` is
 * a convenience field derived from `markers.length > 0`.
 */
export interface KnownMarkerSignal {
  /** True when one or more explicit markers were recognized. */
  hasKnownMarker: boolean;
  /** Every recognized marker occurrence in scan order. */
  markers: KnownMarker[];
}

// ── Detection ───────────────────────────────────────────────────────────────

/**
 * Scan `source` text for explicit TODO / FIXME / XXX markers and documented /
 * known limitation phrasing. Returns structured marker evidence — never a
 * bare boolean.
 *
 * When `filePath` is supplied it is recorded in the signal for downstream
 * rendering but does not affect detection.
 */
export function detectKnownMarkers(
  source: string,
  filePath?: string,
): KnownMarkerSignal {
  const lines = source.split("\n");
  const markers: KnownMarker[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Reset lastIndex because we reuse the same regex across lines.
    SOURCE_MARKER_RE.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = SOURCE_MARKER_RE.exec(line)) !== null) {
      // Groups: 1 = TODO/FIXME/XXX tag, 2 = optional parenthetical note,
      //         3 = "known limitation" / "documented limitation" phrase.
      const tag = match[1]; // e.g. "TODO"
      const phrase = match[3]; // e.g. "known limitation"
      const markerText = tag ?? phrase ?? match[0];

      // Build context from surrounding lines (never more than the file has).
      const contextLines: string[] = [];
      if (i > 0) contextLines.push(lines[i - 1]);
      contextLines.push(line);
      if (i < lines.length - 1) contextLines.push(lines[i + 1]);

      markers.push({
        marker: markerText.toLowerCase(),
        line: line.length > 200 ? line.slice(0, 100) + "..." + line.slice(line.length - 97) : line,
        lineNumber: i + 1,
        sourcePath: filePath,
        context: contextLines.join("\n"),
      });
    }
  }

  return {
    hasKnownMarker: markers.length > 0,
    markers,
  };
}

// ── Integration helpers ─────────────────────────────────────────────────────

/**
 * Convenience: scan every text-like field on a {@link Finding} that could
 * plausibly carry source-evidence excerpts and aggregate all known markers.
 *
 * Scanned fields:
 *  - `evidence.analysis`
 *  - `description`
 *  - `evidence.request`
 *  - `evidence.response`
 *
 * SAFETY: this function never mutates the finding, never decides anything
 * about severity/status/auto-drop, and returns an advisory signal only.
 */
export function analyzeFindingForKnownMarkers(
  finding: Finding,
): KnownMarkerSignal {
  const texts: string[] = [];
  if (finding.evidence?.analysis) texts.push(finding.evidence.analysis);
  if (finding.description) texts.push(finding.description);
  if (finding.evidence?.request) texts.push(finding.evidence.request);
  if (finding.evidence?.response) texts.push(finding.evidence.response);

  const allMarkers: KnownMarker[] = [];
  for (const text of texts) {
    const signal = detectKnownMarkers(text);
    allMarkers.push(...signal.markers);
  }

  return {
    hasKnownMarker: allMarkers.length > 0,
    markers: allMarkers,
  };
}
