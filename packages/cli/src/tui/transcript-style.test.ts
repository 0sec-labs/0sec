import { describe, expect, it } from "vitest";

import {
  DEFAULT_ROLE_LABEL_STYLE,
  DEFAULT_TOOL_CARD_STYLE,
  DEFAULT_TRANSCRIPT_DETAIL,
  DEFAULT_TRANSCRIPT_STYLE,
  ROLE_LABEL_STYLES,
  TOOL_CARD_STYLES,
  TRANSCRIPT_DETAILS,
  TRANSCRIPT_STYLES,
  foldSummary,
  isCollapsibleEntry,
  planTranscript,
  resolveTranscriptStyleSettings,
  roleLabelText,
  roleLabelWidth,
  speechFrame,
  toolCompactLine,
  toolDetailWidth,
  toolFrame,
  toolGlyphState,
  toolHeaderColumns,
  toolHeaderPrefix,
  type CollapseEntryLike,
  type SpeechKind,
  type ToolCardStyle,
  type TranscriptStyle,
} from "./transcript-style.js";

/** Dense enough to catch an off-by-one at every boundary the layout has. */
const WIDTHS = Array.from({ length: 201 }, (_, index) => index);
const SPEECH_KINDS: SpeechKind[] = ["user", "assistant", "error", "reasoning", "notice"];

function isWidth(n: number): boolean {
  return Number.isInteger(n) && n >= 0;
}

// ---------------------------------------------------------------------------
// The sweep — the invariant this module exists to guarantee
// ---------------------------------------------------------------------------

describe("layout invariants — the sweep", () => {
  it("never lets a speaking turn claim more cells than its pane, at any width or style", () => {
    for (const style of TRANSCRIPT_STYLES) {
      for (const kind of SPEECH_KINDS) {
        for (const width of WIDTHS) {
          const frame = speechFrame(style, kind, width);
          expect(isWidth(frame.railWidth), `railWidth ${style}/${kind}@${width}`).toBe(true);
          expect(isWidth(frame.contentGap)).toBe(true);
          expect(isWidth(frame.contentWidth)).toBe(true);
          expect(isWidth(frame.markdownWidth)).toBe(true);
          expect(isWidth(frame.extraMarginTop)).toBe(true);

          // The cells the row spends on chrome plus the content it claims must
          // never exceed the pane it was handed.
          const chrome =
            frame.railWidth +
            frame.contentGap +
            (frame.bordered ? 4 : 0);
          expect(
            chrome + frame.contentWidth,
            `${style}/${kind}@${width} claimed ${chrome + frame.contentWidth} > ${width}`,
          ).toBeLessThanOrEqual(width);
        }
      }
    }
  });

  it("never lets a tool/subagent card overflow, for every tool style and success state", () => {
    for (const style of TOOL_CARD_STYLES) {
      for (const success of [true, false, undefined] as const) {
        for (const width of WIDTHS) {
          const frame = toolFrame(style, width, success);
          for (const value of [
            frame.railWidth,
            frame.outerMarginLeft,
            frame.contentGap,
            frame.contentWidth,
          ]) {
            expect(isWidth(value), `${style}/${success}@${width}`).toBe(true);
          }
          const claimed =
            frame.outerMarginLeft + frame.railWidth + frame.contentGap + frame.contentWidth;
          expect(
            claimed,
            `${style}/${success}@${width} claimed ${claimed} > ${width}`,
          ).toBeLessThanOrEqual(width);

          if (!frame.render) continue;
          // The header row (icon + prefix + name) must fit the content column.
          const { state } = toolGlyphState(success);
          const prefix = toolHeaderPrefix(state);
          const detail = toolDetailWidth(frame.contentWidth, width);
          const cols = toolHeaderColumns(frame.contentWidth, prefix.length, detail);
          expect(isWidth(cols.iconWidth)).toBe(true);
          expect(isWidth(cols.prefixWidth)).toBe(true);
          expect(isWidth(cols.nameWidth)).toBe(true);
          expect(
            cols.iconWidth + cols.prefixWidth + cols.nameWidth,
            `header ${style}/${success}@${width}`,
          ).toBeLessThanOrEqual(frame.contentWidth);
        }
      }
    }
  });

  it("never returns a negative, fractional, NaN or Infinite width for degenerate panes", () => {
    for (const width of [-100, -1, 0, 0.5, NaN, Infinity, -Infinity]) {
      for (const style of TRANSCRIPT_STYLES) {
        const frame = speechFrame(style, "assistant", width);
        expect(isWidth(frame.contentWidth)).toBe(true);
        expect(isWidth(frame.markdownWidth)).toBe(true);
      }
      for (const style of TOOL_CARD_STYLES) {
        const frame = toolFrame(style, width, false);
        expect(isWidth(frame.contentWidth)).toBe(true);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// rail: the default must not change on upgrade
// ---------------------------------------------------------------------------

describe("rail is the default and preserves today's geometry", () => {
  it("defaults to rail / full / rail", () => {
    expect(DEFAULT_TRANSCRIPT_STYLE).toBe("rail");
    expect(DEFAULT_ROLE_LABEL_STYLE).toBe("full");
    expect(DEFAULT_TOOL_CARD_STYLE).toBe("rail");
  });

  it("reproduces the speech geometry the component used before the refactor", () => {
    // Today: rail = width 1, gap 1 (marginLeft), content = rest,
    // markdown width = max(8, width - 2).
    for (const width of [40, 56, 72, 80, 100, 120]) {
      for (const kind of SPEECH_KINDS) {
        const frame = speechFrame("rail", kind, width);
        expect(frame.bordered).toBe(false);
        expect(frame.railWidth).toBe(1);
        expect(frame.contentGap).toBe(1);
        expect(frame.contentWidth).toBe(width - 2);
        expect(frame.markdownWidth).toBe(Math.max(8, width - 2));
      }
    }
  });

  it("reproduces the tool card geometry the component used before the refactor", () => {
    for (const width of [40, 55, 56, 72, 80, 120]) {
      const frame = toolFrame("rail", width, true);
      const expectedIndent = width < 56 ? 0 : 2;
      expect(frame.outerMarginLeft).toBe(expectedIndent);
      expect(frame.railWidth).toBe(1);
      expect(frame.contentGap).toBe(1);
      expect(frame.contentWidth).toBe(width - expectedIndent - 2);
      expect(frame.showDetail).toBe(true);
      expect(frame.singleLine).toBe(false);
    }
  });

  it("reproduces the header name budget when the pane is not tiny", () => {
    // Old code: name budgeted to max(1, detailWidth - prefix.length - 1),
    // detailWidth = max(20, width - 8). Verify the pure fn agrees at widths
    // where the old code did not overflow (content >= header, i.e. wide enough
    // that the prefix and a 1-cell name both fit — roughly width >= 40).
    for (const width of [40, 56, 72, 80, 120]) {
      const frame = toolFrame("rail", width, true);
      const prefix = toolHeaderPrefix("complete");
      const detail = Math.max(20, width - 8);
      expect(toolDetailWidth(frame.contentWidth, width)).toBe(detail);
      const cols = toolHeaderColumns(frame.contentWidth, prefix.length, detail);
      expect(cols.nameWidth).toBe(Math.max(1, detail - prefix.length - 1));
    }
  });
});

// ---------------------------------------------------------------------------
// role labels
// ---------------------------------------------------------------------------

describe("role label styles produce the documented widths", () => {
  it("full", () => {
    expect(roleLabelText("user", "full")).toBe("▌ operator");
    expect(roleLabelText("assistant", "full")).toBe("▌ 0sec");
    expect(roleLabelWidth("user", "full")).toBe("▌ operator".length);
    expect(roleLabelWidth("assistant", "full")).toBe("▌ 0sec".length);
  });

  it("short", () => {
    expect(roleLabelText("user", "short")).toBe("op");
    expect(roleLabelText("assistant", "short")).toBe("0sec");
    expect(roleLabelWidth("user", "short")).toBe(2);
    expect(roleLabelWidth("assistant", "short")).toBe(4);
  });

  it("glyph", () => {
    expect(roleLabelText("user", "glyph")).toBe("▌");
    expect(roleLabelText("assistant", "glyph")).toBe("▌");
    expect(roleLabelWidth("user", "glyph")).toBe(1);
  });

  it("off suppresses the label entirely", () => {
    expect(roleLabelText("user", "off")).toBeNull();
    expect(roleLabelText("assistant", "off")).toBeNull();
    expect(roleLabelWidth("user", "off")).toBe(0);
  });

  it("carries the age separator as text, only when an age is present", () => {
    expect(roleLabelText("user", "full", "12s")).toBe("▌ operator · 12s");
    expect(roleLabelText("user", "full", "")).toBe("▌ operator");
    expect(roleLabelText("user", "glyph", "12s")).toBe("▌");
  });
});

// ---------------------------------------------------------------------------
// hidden tool cards still show failures
// ---------------------------------------------------------------------------

describe("hidden tool cards", () => {
  it("drops successful and running calls", () => {
    expect(toolFrame("hidden", 80, true).render).toBe(false);
    expect(toolFrame("hidden", 80, undefined).render).toBe(false);
  });

  it("never hides a failure", () => {
    const frame = toolFrame("hidden", 80, false);
    expect(frame.render).toBe(true);
    expect(frame.showDetail).toBe(true);
    expect(frame.singleLine).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// tool styles' distinct shapes
// ---------------------------------------------------------------------------

describe("tool card styles are genuinely distinct", () => {
  it("compact is one line with detail only on failure", () => {
    expect(toolFrame("compact", 80, true).showDetail).toBe(false);
    expect(toolFrame("compact", 80, false).showDetail).toBe(true);
    expect(toolFrame("compact", 80, true).singleLine).toBe(true);
    expect(toolFrame("compact", 80, true).railWidth).toBe(0);
  });

  it("inline has no rail but keeps the detail", () => {
    const frame = toolFrame("inline", 80, true);
    expect(frame.railWidth).toBe(0);
    expect(frame.outerMarginLeft).toBe(0);
    expect(frame.showDetail).toBe(true);
    expect(frame.singleLine).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// transcript styles' distinct shapes
// ---------------------------------------------------------------------------

describe("transcript styles are genuinely distinct, not tints", () => {
  it("bubble borders speech but never reasoning or notices", () => {
    expect(speechFrame("bubble", "assistant", 80).bordered).toBe(true);
    expect(speechFrame("bubble", "user", 80).bordered).toBe(true);
    expect(speechFrame("bubble", "error", 80).bordered).toBe(true);
    expect(speechFrame("bubble", "reasoning", 80).bordered).toBe(false);
    expect(speechFrame("bubble", "notice", 80).bordered).toBe(false);
  });

  it("plain and compact give content every cell", () => {
    expect(speechFrame("plain", "assistant", 80).contentWidth).toBe(80);
    expect(speechFrame("compact", "assistant", 80).contentWidth).toBe(80);
    expect(speechFrame("plain", "assistant", 80).railWidth).toBe(0);
  });

  it("compact inlines the label; plain and document keep it on its own row", () => {
    expect(speechFrame("compact", "assistant", 80).labelOwnRow).toBe(false);
    expect(speechFrame("plain", "assistant", 80).labelOwnRow).toBe(true);
    expect(speechFrame("document", "assistant", 80).labelOwnRow).toBe(true);
  });

  it("document adds breathing room above each turn", () => {
    expect(speechFrame("document", "assistant", 80).extraMarginTop).toBe(1);
    expect(speechFrame("rail", "assistant", 80).extraMarginTop).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// edge content: long token, empty message, multi-line markdown
// ---------------------------------------------------------------------------

describe("degenerate content never overflows", () => {
  const longToken = "x".repeat(500);

  it("a single very long token is fitted to the content width for every style", () => {
    for (const style of TRANSCRIPT_STYLES) {
      for (const width of [1, 8, 24, 80, 120]) {
        const frame = speechFrame(style, "assistant", width);
        // The component fits markdown to markdownWidth; assert that budget is
        // itself within the pane (never larger than the width).
        expect(frame.markdownWidth).toBeLessThanOrEqual(Math.max(8, width));
      }
    }
    // The compact tool line fits a runaway name into its width.
    for (const width of [1, 5, 12, 40, 80]) {
      const line = toolCompactLine("×", longToken, "failed", width);
      expect(line.length).toBeLessThanOrEqual(width);
    }
  });

  it("an empty message produces valid, non-negative geometry", () => {
    for (const style of TRANSCRIPT_STYLES) {
      const frame = speechFrame(style, "assistant", 80);
      expect(isWidth(frame.contentWidth)).toBe(true);
    }
    expect(toolCompactLine("✓", "", "complete", 40).length).toBeLessThanOrEqual(40);
    expect(toolCompactLine("✓", "", "complete", 0)).toBe("");
  });
});

// ---------------------------------------------------------------------------
// settings resolution
// ---------------------------------------------------------------------------

describe("resolveTranscriptStyleSettings", () => {
  it("falls back to defaults for an object without the keys", () => {
    expect(resolveTranscriptStyleSettings({})).toEqual({
      transcriptStyle: "rail",
      roleLabelStyle: "full",
      toolCardStyle: "rail",
    });
  });

  it("reads valid settings values", () => {
    const resolved = resolveTranscriptStyleSettings({
      transcriptStyle: "bubble",
      roleLabelStyle: "short",
      toolCardStyle: "compact",
    });
    expect(resolved).toEqual({
      transcriptStyle: "bubble",
      roleLabelStyle: "short",
      toolCardStyle: "compact",
    });
  });

  it("rejects invalid values and falls back", () => {
    const resolved = resolveTranscriptStyleSettings({
      transcriptStyle: "rainbow",
      roleLabelStyle: 42,
      toolCardStyle: null,
    });
    expect(resolved).toEqual({
      transcriptStyle: "rail",
      roleLabelStyle: "full",
      toolCardStyle: "rail",
    });
  });

  it("lets an environment variable override settings", () => {
    const resolved = resolveTranscriptStyleSettings(
      { transcriptStyle: "rail" },
      {
        OSEC_TRANSCRIPT_STYLE: "document",
        OSEC_ROLE_LABEL_STYLE: "glyph",
        OSEC_TOOL_CARD_STYLE: "hidden",
      },
    );
    expect(resolved).toEqual({
      transcriptStyle: "document",
      roleLabelStyle: "glyph",
      toolCardStyle: "hidden",
    });
  });

  it("tolerates non-object settings", () => {
    expect(resolveTranscriptStyleSettings(null)).toEqual({
      transcriptStyle: "rail",
      roleLabelStyle: "full",
      toolCardStyle: "rail",
    });
    expect(resolveTranscriptStyleSettings("nope")).toEqual({
      transcriptStyle: "rail",
      roleLabelStyle: "full",
      toolCardStyle: "rail",
    });
  });
});

// ---------------------------------------------------------------------------
// Transcript detail — collapse planning
// ---------------------------------------------------------------------------

function entry(
  kind: CollapseEntryLike["kind"],
  turn: number,
  extra: Partial<CollapseEntryLike> = {},
): CollapseEntryLike {
  return { kind, turn, ...extra };
}

describe("transcript detail — the collapse contract", () => {
  it("declares collapsed the default", () => {
    expect(DEFAULT_TRANSCRIPT_DETAIL).toBe("collapsed");
    expect(TRANSCRIPT_DETAILS).toEqual(["collapsed", "expanded"]);
  });

  it("folds successful tools and reasoning but never a failure", () => {
    expect(isCollapsibleEntry(entry("tool", 1, { success: true }))).toBe(true);
    // A still-running tool (no success yet) may fold; a failed one never does.
    expect(isCollapsibleEntry(entry("tool", 1))).toBe(true);
    expect(isCollapsibleEntry(entry("tool", 1, { success: false }))).toBe(false);
    expect(isCollapsibleEntry(entry("reasoning", 1))).toBe(true);
    expect(isCollapsibleEntry(entry("subagent", 1, { subagentOutcome: "completed" }))).toBe(true);
    expect(isCollapsibleEntry(entry("subagent", 1, { subagentOutcome: "failed" }))).toBe(false);
    // Speech and errors always render in full.
    expect(isCollapsibleEntry(entry("user", 1))).toBe(false);
    expect(isCollapsibleEntry(entry("assistant", 1))).toBe(false);
    expect(isCollapsibleEntry(entry("error", 1))).toBe(false);
  });

  it("passes every entry through untouched in expanded mode", () => {
    const entries = [
      entry("user", 1),
      entry("reasoning", 1),
      entry("tool", 1, { success: true, text: "run_command" }),
      entry("assistant", 1),
    ];
    const plan = planTranscript(entries, "expanded");
    expect(plan).toHaveLength(entries.length);
    expect(plan.every((item) => item.type === "entry")).toBe(true);
  });

  it("folds a turn's successful detail into a single summary line", () => {
    const entries = [
      entry("user", 1),
      entry("reasoning", 1),
      entry("tool", 1, { success: true, text: "run_command" }),
      entry("tool", 1, { success: true, text: "read_file" }),
      entry("assistant", 1),
    ];
    const plan = planTranscript(entries, "collapsed");
    // user, fold(3), assistant.
    expect(plan.map((item) => item.type)).toEqual(["entry", "fold", "entry"]);
    const fold = plan[1];
    if (fold.type !== "fold") throw new Error("expected a fold");
    expect(fold.entries).toHaveLength(3);
    expect(fold.summary).toBe("3 steps · thinking, run_command, read_file");
  });

  it("never hides a failure — it breaks the fold and renders in full", () => {
    const entries = [
      entry("tool", 1, { success: true, text: "run_command" }),
      entry("tool", 1, { success: false, text: "curl" }),
      entry("tool", 1, { success: true, text: "read_file" }),
    ];
    const plan = planTranscript(entries, "collapsed");
    // fold(run_command), the failure as its own entry, fold(read_file).
    expect(plan.map((item) => item.type)).toEqual(["fold", "entry", "fold"]);
    const failure = plan[1];
    if (failure.type !== "entry") throw new Error("expected an entry");
    expect(failure.entry.success).toBe(false);
  });

  it("does not fold across a turn boundary", () => {
    const entries = [
      entry("tool", 1, { success: true, text: "a" }),
      entry("tool", 2, { success: true, text: "b" }),
    ];
    const plan = planTranscript(entries, "collapsed");
    expect(plan.map((item) => item.type)).toEqual(["fold", "fold"]);
    expect(plan[0].type === "fold" && plan[0].turn).toBe(1);
    expect(plan[1].type === "fold" && plan[1].turn).toBe(2);
  });

  it("folds a lone reasoning or tool to its name", () => {
    expect(foldSummary([entry("reasoning", 1)])).toBe("thinking");
    expect(foldSummary([entry("tool", 1, { success: true, text: "run_command" })])).toBe(
      "run_command",
    );
  });

  it("treats an expanded turn as expanded even in collapsed mode", () => {
    const entries = [
      entry("tool", 1, { success: true, text: "a" }),
      entry("reasoning", 1),
    ];
    const plan = planTranscript(entries, "collapsed", new Set([1]));
    expect(plan.map((item) => item.type)).toEqual(["entry", "entry"]);
  });
});
