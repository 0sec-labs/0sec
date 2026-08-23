import { describe, expect, it } from "vitest";

import {
  abbreviateHomePath,
  buildStatusSegments,
  fitStatusSegments,
  fitStatusPills,
  pillText,
  formatTokenCount,
  sidebarToggleIcons,
  sidebarIconsWidth,
  type StatusBarInput,
  type StatusSegment,
  type StatusSegmentKind,
} from "./status-bar.js";

/**
 * The bar the status line is modelled on, copied verbatim.
 *
 * The renderer, not this module, decides how segments are grouped and
 * spaced on screen — which is why the assembly below uses the reference
 * bar's own spacing rather than the default separator. What is being
 * pinned here is the *content* of each segment: get one of these strings
 * wrong and no amount of layout work reproduces the target.
 */
const REFERENCE_BAR =
  "GPT-5.6-Terra · max   ~/coding/0sec-labs/0sec   publish/main-integration *54 ?29   1.4%/1M  (sub)";

const REFERENCE_INPUT: StatusBarInput = {
  model: "GPT-5.6-Terra",
  effort: "max",
  cwd: "/home/dev/coding/0sec-labs/0sec",
  home: "/home/dev",
  branch: "publish/main-integration",
  modified: 54,
  untracked: 29,
  contextWindow: 1_000_000,
  contextUsed: 14_000,
  plan: "sub",
};

/** A bar with every segment populated, for the fitting tests. */
const RICH_INPUT: StatusBarInput = {
  model: "claude-opus-5[1m]",
  effort: "max",
  mode: "Standard",
  cwd: "/home/dev/coding/0sec-labs/0sec",
  home: "/home/dev",
  branch: "publish/main-integration",
  modified: 54,
  untracked: 29,
  inputTokens: 128_450,
  outputTokens: 9_310,
  contextWindow: 1_000_000,
  contextUsed: 214_000,
  plan: "sub",
};

function textOf(segments: StatusSegment[], kind: StatusSegmentKind): string | undefined {
  return segments.find((segment) => segment.kind === kind)?.text;
}

function kinds(segments: StatusSegment[]): StatusSegmentKind[] {
  return segments.map((segment) => segment.kind);
}

describe("abbreviateHomePath", () => {
  it("replaces the home prefix with a tilde", () => {
    expect(abbreviateHomePath("/home/dev/coding/x", "/home/dev")).toBe("~/coding/x");
  });

  it("collapses the home directory itself to a bare tilde", () => {
    expect(abbreviateHomePath("/home/dev", "/home/dev")).toBe("~");
  });

  it("leaves paths outside home untouched", () => {
    expect(abbreviateHomePath("/var/log/syslog", "/home/dev")).toBe("/var/log/syslog");
  });

  it("does not rewrite a different directory that shares home's characters", () => {
    // The false-prefix case: a raw startsWith would yield "~eloper/x".
    expect(abbreviateHomePath("/home/developer/x", "/home/dev")).toBe("/home/developer/x");
    expect(abbreviateHomePath("/home/deviant", "/home/dev")).toBe("/home/deviant");
  });

  it("leaves the path alone when home is missing or empty", () => {
    expect(abbreviateHomePath("/home/dev/coding/x")).toBe("/home/dev/coding/x");
    expect(abbreviateHomePath("/home/dev/coding/x", "")).toBe("/home/dev/coding/x");
  });

  it("tolerates a trailing slash on home", () => {
    expect(abbreviateHomePath("/home/dev/coding/x", "/home/dev/")).toBe("~/coding/x");
  });

  it("refuses to abbreviate the filesystem root", () => {
    expect(abbreviateHomePath("/etc/hosts", "/")).toBe("/etc/hosts");
  });

  it("returns an empty string for an empty path", () => {
    expect(abbreviateHomePath("", "/home/dev")).toBe("");
  });
});

describe("formatTokenCount", () => {
  it("prints counts under a thousand plainly", () => {
    expect(formatTokenCount(0)).toBe("0");
    expect(formatTokenCount(999)).toBe("999");
  });

  it("switches to thousands at 1000", () => {
    expect(formatTokenCount(1000)).toBe("1k");
    expect(formatTokenCount(1234)).toBe("1.2k");
    expect(formatTokenCount(12_345)).toBe("12.3k");
  });

  it("drops a trailing .0", () => {
    expect(formatTokenCount(12_000)).toBe("12k");
    expect(formatTokenCount(2_000_000)).toBe("2M");
  });

  it("promotes to millions rather than printing 1000k", () => {
    expect(formatTokenCount(999_999)).toBe("1M");
    expect(formatTokenCount(1_000_000)).toBe("1M");
    expect(formatTokenCount(1_234_567)).toBe("1.2M");
  });

  it("never emits a negative or non-finite count", () => {
    expect(formatTokenCount(-5)).toBe("0");
    expect(formatTokenCount(Number.NaN)).toBe("0");
    expect(formatTokenCount(Number.POSITIVE_INFINITY)).toBe("0");
  });
});

describe("buildStatusSegments", () => {
  it("reproduces the reference bar from a realistic input", () => {
    const segments = buildStatusSegments(REFERENCE_INPUT);

    expect(kinds(segments)).toEqual([
      "model",
      "effort",
      "cwd",
      "branch",
      "dirty",
      "context",
      "plan",
    ]);

    const bar =
      `${textOf(segments, "model")} · ${textOf(segments, "effort")}` +
      `   ${textOf(segments, "cwd")}` +
      `   ${textOf(segments, "branch")} ${textOf(segments, "dirty")}` +
      `   ${textOf(segments, "context")}` +
      `  ${textOf(segments, "plan")}`;

    expect(bar).toBe(REFERENCE_BAR);
  });

  it("orders segments model, effort, mode, cwd, branch, dirty, tokens, context, plan", () => {
    expect(kinds(buildStatusSegments(RICH_INPUT))).toEqual([
      "model",
      "effort",
      "mode",
      "cwd",
      "branch",
      "dirty",
      "tokens",
      "context",
      "plan",
    ]);
  });

  it("emits nothing for an empty input", () => {
    expect(buildStatusSegments({})).toEqual([]);
  });

  it("never invents a context percentage without a window", () => {
    // The load-bearing rule: usage alone cannot produce a percentage, and
    // guessing a window would put a plausible-looking lie on screen.
    const segments = buildStatusSegments({ model: "m", contextUsed: 214_000 });
    expect(kinds(segments)).toEqual(["model"]);
    expect(textOf(segments, "context")).toBeUndefined();
  });

  it("omits the context segment when usage is unknown", () => {
    const segments = buildStatusSegments({ model: "m", contextWindow: 1_000_000 });
    expect(textOf(segments, "context")).toBeUndefined();
  });

  it("omits the context segment for a zero or negative window", () => {
    expect(
      textOf(buildStatusSegments({ contextWindow: 0, contextUsed: 10 }), "context"),
    ).toBeUndefined();
    expect(
      textOf(buildStatusSegments({ contextWindow: -1, contextUsed: 10 }), "context"),
    ).toBeUndefined();
  });

  it("formats the context segment as percent-of-window", () => {
    expect(
      textOf(buildStatusSegments({ contextWindow: 1_000_000, contextUsed: 14_000 }), "context"),
    ).toBe("1.4%/1M");
    expect(
      textOf(buildStatusSegments({ contextWindow: 200_000, contextUsed: 0 }), "context"),
    ).toBe("0%/200k");
    expect(
      textOf(buildStatusSegments({ contextWindow: 200_000, contextUsed: 200_000 }), "context"),
    ).toBe("100%/200k");
  });

  it("omits the dirty segment for a clean tree", () => {
    const clean = buildStatusSegments({ branch: "main", modified: 0, untracked: 0 });
    expect(kinds(clean)).toEqual(["branch"]);

    const unknown = buildStatusSegments({ branch: "main" });
    expect(textOf(unknown, "dirty")).toBeUndefined();
  });

  it("shows only the non-zero half of the dirty counts", () => {
    expect(textOf(buildStatusSegments({ modified: 54, untracked: 29 }), "dirty")).toBe("*54 ?29");
    expect(textOf(buildStatusSegments({ modified: 54 }), "dirty")).toBe("*54");
    expect(textOf(buildStatusSegments({ untracked: 29 }), "dirty")).toBe("?29");
  });

  it("omits the branch segment when git reports no branch", () => {
    expect(textOf(buildStatusSegments({ branch: null }), "branch")).toBeUndefined();
    expect(textOf(buildStatusSegments({ branch: "  " }), "branch")).toBeUndefined();
  });

  it("formats session tokens as in/out and hides them at zero", () => {
    expect(
      textOf(buildStatusSegments({ inputTokens: 128_450, outputTokens: 9_310 }), "tokens"),
    ).toBe("128k/9.3k");
    expect(textOf(buildStatusSegments({ inputTokens: 0, outputTokens: 0 }), "tokens")).toBeUndefined();
    expect(textOf(buildStatusSegments({}), "tokens")).toBeUndefined();
  });

  it("parenthesizes the plan and abbreviates the cwd", () => {
    const segments = buildStatusSegments(RICH_INPUT);
    expect(textOf(segments, "plan")).toBe("(sub)");
    expect(textOf(segments, "cwd")).toBe("~/coding/0sec-labs/0sec");
  });

  it("marks the model as undroppable and the cwd as the first to go", () => {
    const segments = buildStatusSegments(RICH_INPUT);
    const priority = (kind: StatusSegmentKind): number =>
      segments.find((segment) => segment.kind === kind)!.priority;

    expect(priority("model")).toBe(0);
    const droppable = segments.filter((segment) => segment.priority > 0);
    const lowest = Math.min(...droppable.map((segment) => segment.priority));
    expect(priority("cwd")).toBe(lowest);
    expect(priority("dirty")).toBeLessThan(priority("branch"));
    expect(priority("mode")).toBeGreaterThan(priority("effort"));
  });
});

describe("modelDisplay", () => {
  it("keeps the model in the bar for the unset default and for statusbar", () => {
    expect(textOf(buildStatusSegments({ model: "m" }), "model")).toBe("m");
    expect(textOf(buildStatusSegments({ model: "m", modelDisplay: "statusbar" }), "model")).toBe("m");
  });

  it("drops the model segment for message and off", () => {
    expect(textOf(buildStatusSegments({ model: "m", modelDisplay: "message" }), "model")).toBeUndefined();
    expect(textOf(buildStatusSegments({ model: "m", modelDisplay: "off" }), "model")).toBeUndefined();
  });

  it("still prices cost from the model even when it is hidden from the bar", () => {
    const segments = buildStatusSegments({
      model: "claude-sonnet-4-6",
      modelDisplay: "off",
      showCost: true,
      inputTokens: 1_000_000,
      outputTokens: 0,
    });
    expect(textOf(segments, "model")).toBeUndefined();
    expect(textOf(segments, "cost")).toBe("$3.00"); // 1M input @ $3/M
  });
});

describe("context meter", () => {
  it("replaces the plain percent with a bar when enabled", () => {
    const meter = textOf(
      buildStatusSegments({ contextWindow: 1_000_000, contextUsed: 500_000, showContextMeter: true }),
      "meter",
    );
    expect(meter).toBe("▰▰▰▱▱▱ 50% of 1M");
  });

  it("emits the meter instead of the context segment, never both", () => {
    const segments = buildStatusSegments({
      contextWindow: 200_000,
      contextUsed: 100_000,
      showContextMeter: true,
    });
    expect(textOf(segments, "meter")).toBeDefined();
    expect(textOf(segments, "context")).toBeUndefined();
  });

  it("clamps the bar fill at full and empty", () => {
    expect(
      textOf(buildStatusSegments({ contextWindow: 100, contextUsed: 100, showContextMeter: true }), "meter"),
    ).toBe("▰▰▰▰▰▰ 100% of 100");
    expect(
      textOf(buildStatusSegments({ contextWindow: 100, contextUsed: 0, showContextMeter: true }), "meter"),
    ).toBe("▱▱▱▱▱▱ 0% of 100");
  });

  it("still needs both window and usage to draw a meter", () => {
    expect(textOf(buildStatusSegments({ contextUsed: 10, showContextMeter: true }), "meter")).toBeUndefined();
    expect(textOf(buildStatusSegments({ contextWindow: 100, showContextMeter: true }), "meter")).toBeUndefined();
  });
});

describe("cost", () => {
  it("prices a known model from session tokens", () => {
    // claude-sonnet-4-6 is $3/M in, $15/M out.
    expect(
      textOf(
        buildStatusSegments({ model: "claude-sonnet-4-6", showCost: true, inputTokens: 1_000_000, outputTokens: 1_000_000 }),
        "cost",
      ),
    ).toBe("$18.00");
  });

  it("prices a differently-cased or vendor-prefixed id", () => {
    expect(
      textOf(
        buildStatusSegments({ model: "anthropic/claude-sonnet-4-6", showCost: true, inputTokens: 1_000_000, outputTokens: 0 }),
        "cost",
      ),
    ).toBe("$3.00");
  });

  it("shows a sub-cent estimate as <$0.01", () => {
    expect(
      textOf(buildStatusSegments({ model: "claude-sonnet-4-6", showCost: true, inputTokens: 1_000, outputTokens: 0 }), "cost"),
    ).toBe("<$0.01");
  });

  it("shows $— for a model with no known rate rather than the fallback rate", () => {
    expect(
      textOf(buildStatusSegments({ model: "totally-made-up-model", showCost: true, inputTokens: 1_000_000, outputTokens: 0 }), "cost"),
    ).toBe("$—");
  });

  it("omits cost entirely without usage or when disabled", () => {
    expect(textOf(buildStatusSegments({ model: "claude-sonnet-4-6", showCost: true }), "cost")).toBeUndefined();
    expect(
      textOf(buildStatusSegments({ model: "claude-sonnet-4-6", inputTokens: 1_000_000, outputTokens: 0 }), "cost"),
    ).toBeUndefined();
  });
});

describe("fitStatusSegments", () => {
  const segments = buildStatusSegments(RICH_INPUT);
  const full = segments.map((segment) => segment.text).join(" · ");

  it("joins every segment when there is room", () => {
    expect(fitStatusSegments(segments, 500)).toBe(full);
    expect(fitStatusSegments(segments, full.length)).toBe(full);
  });

  it("honours a custom separator", () => {
    expect(fitStatusSegments(segments, 500, " | ")).toBe(
      segments.map((segment) => segment.text).join(" | "),
    );
  });

  it("returns an empty string for a non-positive width", () => {
    expect(fitStatusSegments(segments, 0)).toBe("");
    expect(fitStatusSegments(segments, -10)).toBe("");
  });

  it("returns an empty string when there is nothing to show", () => {
    expect(fitStatusSegments([], 80)).toBe("");
  });

  it("drops the cwd before anything else", () => {
    const cwd = textOf(segments, "cwd")!;
    const bar = fitStatusSegments(segments, full.length - 1);
    expect(bar).not.toContain(cwd);
    expect(bar).toContain(textOf(segments, "model")!);
    expect(bar).toContain(textOf(segments, "mode")!);
  });

  it("truncates with an ellipsis when even the model does not fit", () => {
    const model = textOf(segments, "model")!;
    const bar = fitStatusSegments(segments, 8);
    expect(bar.length).toBe(8);
    expect(bar.endsWith("...")).toBe(true);
    expect(model.startsWith(bar.slice(0, -3))).toBe(true);
  });

  it("never exceeds the given width, for any width from 0 to 200", () => {
    for (let width = 0; width <= 200; width += 1) {
      const bar = fitStatusSegments(segments, width);
      expect(bar.length, `overflowed at width ${width}: ${JSON.stringify(bar)}`).toBeLessThanOrEqual(
        width,
      );
    }
  });

  it("degrades gracefully: a segment only survives if every more important one does", () => {
    // Rank 0 ("never drop") is the top of the ordering, not the bottom.
    const rank = (priority: number): number =>
      priority === 0 ? Number.POSITIVE_INFINITY : priority;

    for (let width = 1; width <= 200; width += 1) {
      const bar = fitStatusSegments(segments, width);
      const present = segments.filter((segment) => bar.includes(segment.text));

      for (const kept of present) {
        for (const other of segments) {
          if (rank(other.priority) > rank(kept.priority)) {
            expect(
              present,
              `at width ${width}, kept "${kept.kind}" but dropped "${other.kind}"`,
            ).toContain(other);
          }
        }
      }
    }
  });

  it("sheds segments monotonically as the terminal narrows", () => {
    let previous = new Set<StatusSegmentKind>();
    for (let width = 1; width <= 200; width += 1) {
      const bar = fitStatusSegments(segments, width);
      const present = new Set(
        segments.filter((segment) => bar.includes(segment.text)).map((segment) => segment.kind),
      );
      for (const kind of previous) {
        expect(present, `"${kind}" reappeared then vanished around width ${width}`).toContain(kind);
      }
      previous = present;
    }
    expect(previous.size).toBe(segments.length);
  });
});

describe("segment colour role + icon (OMP pills)", () => {
  it("attaches a colour role and a single-cell icon to every segment", () => {
    for (const segment of buildStatusSegments(RICH_INPUT)) {
      expect(segment.colorRole, `role for ${segment.kind}`).toBeTruthy();
      // Icons are one column each (or empty); never a runaway multi-char string.
      expect(segment.icon.length).toBeLessThanOrEqual(2);
    }
  });

  it("routes the mode segment onto its own role so the renderer can colour it", () => {
    const [mode] = buildStatusSegments({ mode: "Co-pilot" });
    expect(mode.colorRole).toBe("mode");
  });

  it("shares one colour role between the plain percent and the visual meter", () => {
    const plain = buildStatusSegments({ contextWindow: 1_000_000, contextUsed: 500_000 });
    const meter = buildStatusSegments({
      contextWindow: 1_000_000,
      contextUsed: 500_000,
      showContextMeter: true,
    });
    expect(plain.find((s) => s.kind === "context")?.colorRole).toBe("context");
    expect(meter.find((s) => s.kind === "meter")?.colorRole).toBe("context");
  });
});

describe("fitStatusPills", () => {
  it("keeps every segment when the row is wide enough", () => {
    const segments = buildStatusSegments(RICH_INPUT);
    const pills = fitStatusPills(segments, 1000);
    expect(pills.map((s) => s.kind)).toEqual(segments.map((s) => s.kind));
  });

  it("never lets the rendered pill row exceed the width, at any width", () => {
    const segments = buildStatusSegments(RICH_INPUT);
    const sep = " · ";
    for (let width = 1; width <= 160; width += 1) {
      const pills = fitStatusPills(segments, width);
      const rendered =
        pills.length === 0
          ? 0
          : pills.reduce((sum, s) => sum + pillText(s).length, 0) + sep.length * (pills.length - 1);
      expect(rendered, `overflow at width ${width}`).toBeLessThanOrEqual(width);
    }
  });

  it("sheds the least important segment first, keeping the model longest", () => {
    const segments = buildStatusSegments(RICH_INPUT);
    // A width that forces several drops but not all of them.
    const pills = fitStatusPills(segments, 40);
    expect(pills.some((s) => s.kind === "model")).toBe(true);
    expect(pills.some((s) => s.kind === "cwd")).toBe(false);
  });

  it("truncates the undroppable model's label but keeps its glyph when alone", () => {
    const segments = buildStatusSegments({ model: "a-very-long-model-identifier-x" });
    const pills = fitStatusPills(segments, 10);
    expect(pills).toHaveLength(1);
    expect(pillText(pills[0]).length).toBeLessThanOrEqual(10);
    expect(pills[0].icon.length).toBeGreaterThan(0);
  });

  it("returns nothing for a non-positive width", () => {
    expect(fitStatusPills(buildStatusSegments(RICH_INPUT), 0)).toEqual([]);
  });
});

describe("sidebarToggleIcons", () => {
  it("returns the two sidebars, left first, in a stable order", () => {
    const icons = sidebarToggleIcons({ showLeft: false, showRight: false });
    expect(icons.map((i) => i.side)).toEqual(["left", "right"]);
  });

  it("gives an open sidebar a distinct glyph and tone from a closed one", () => {
    const [openLeft] = sidebarToggleIcons({ showLeft: true, showRight: false });
    const [closedLeft] = sidebarToggleIcons({ showLeft: false, showRight: false });

    expect(openLeft.open).toBe(true);
    expect(closedLeft.open).toBe(false);
    expect(openLeft.tone).toBe("accent");
    expect(closedLeft.tone).toBe("muted");
    expect(openLeft.glyph).not.toBe(closedLeft.glyph);
  });

  it("carries the chord, label and an aria string that names side, state and action", () => {
    const [left, right] = sidebarToggleIcons({ showLeft: true, showRight: false });

    expect(left.chord).toBe("ctrl+b");
    expect(left.label).toBe("Sessions");
    expect(left.aria).toContain("Left sidebar");
    expect(left.aria).toContain("open");
    expect(left.aria).toContain("ctrl+b to hide");

    expect(right.chord).toBe("ctrl+l");
    expect(right.label).toBe("Agents");
    expect(right.aria).toContain("Right sidebar");
    expect(right.aria).toContain("closed");
    expect(right.aria).toContain("ctrl+l to show");
  });

  it("distinguishes the two sides by glyph so a closed toggle still reads as its side", () => {
    const bothClosed = sidebarToggleIcons({ showLeft: false, showRight: false });
    const bothOpen = sidebarToggleIcons({ showLeft: true, showRight: true });

    expect(bothClosed[0].glyph).not.toBe(bothClosed[1].glyph);
    expect(bothOpen[0].glyph).not.toBe(bothOpen[1].glyph);
  });

  it("handles all four open/closed combinations", () => {
    const mixed = sidebarToggleIcons({ showLeft: true, showRight: false });
    expect(mixed[0].tone).toBe("accent");
    expect(mixed[1].tone).toBe("muted");

    const other = sidebarToggleIcons({ showLeft: false, showRight: true });
    expect(other[0].tone).toBe("muted");
    expect(other[1].tone).toBe("accent");
  });

  it("uses one cell per glyph, so the whole cluster is cheap to reserve", () => {
    const icons = sidebarToggleIcons({ showLeft: true, showRight: true });
    for (const icon of icons) expect(icon.glyph.length).toBe(1);
    // Two glyphs joined by a single space = 3 cells.
    expect(sidebarIconsWidth(icons)).toBe(3);
    expect(sidebarIconsWidth([])).toBe(0);
  });

  it("is a pure function: same input yields deeply equal output", () => {
    expect(sidebarToggleIcons({ showLeft: true, showRight: false })).toEqual(
      sidebarToggleIcons({ showLeft: true, showRight: false }),
    );
  });
});
