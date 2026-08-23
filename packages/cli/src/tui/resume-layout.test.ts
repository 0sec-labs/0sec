import { describe, expect, it } from "vitest";

import { computeDialogPanel } from "./dialog-select-layout.js";
import { buildDialogRows } from "./dialog-select-layout.js";
import type { StoredSessionMeta } from "./session-store.js";
import {
  CATEGORY_OTHER,
  CATEGORY_THIS,
  clipResumeDetailLines,
  formatSavedAt,
  isFilterKey,
  resumeDetailLines,
  resumeFooterHint,
  resumeItems,
  sessionCategory,
  sessionLabel,
  sessionMeta,
  shellChromeRows,
} from "./resume-layout.js";

// A fixed clock so every age string is deterministic.
const NOW = 1_700_000_000_000;
const MINUTE = 60_000;

function session(overrides: Partial<StoredSessionMeta> = {}): StoredSessionMeta {
  return {
    id: "console-1",
    savedAt: NOW - 5 * MINUTE,
    cwd: "/home/op/project-a",
    messageCount: 12,
    preview: "scan app.example.com for idor",
    ...overrides,
  };
}

// A small realistic set spanning two working directories.
const SESSIONS: StoredSessionMeta[] = [
  session({
    id: "s-here-new",
    savedAt: NOW - MINUTE,
    cwd: "/home/op/project-a",
    summary: "IDOR sweep of the billing API",
    preview: "look at /api/invoices for idor",
    messageCount: 40,
    model: "gpt-5.5",
    mode: "auto",
    target: "app.example.com",
  }),
  session({
    id: "s-here-old",
    savedAt: NOW - 3 * MINUTE,
    cwd: "/home/op/project-a",
    preview: "enumerate subdomains",
    messageCount: 8,
    model: "claude-opus",
  }),
  session({
    id: "s-elsewhere",
    savedAt: NOW - 2 * MINUTE,
    cwd: "/home/op/project-b",
    summary: "SSRF in the image proxy",
    preview: "test the image fetcher",
    messageCount: 21,
    model: "gpt-5.5",
  }),
];

// ---------------------------------------------------------------------------
// Category split
// ---------------------------------------------------------------------------

describe("sessionCategory", () => {
  it("splits on the current working directory", () => {
    expect(sessionCategory(session({ cwd: "/x" }), "/x")).toBe(CATEGORY_THIS);
    expect(sessionCategory(session({ cwd: "/y" }), "/x")).toBe(CATEGORY_OTHER);
  });

  it("returns no category when there is no current directory to contrast", () => {
    expect(sessionCategory(session(), undefined)).toBeUndefined();
    expect(sessionCategory(session(), "")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// List projection
// ---------------------------------------------------------------------------

describe("sessionLabel", () => {
  it("prefers the summary, falls back to the preview, then a placeholder", () => {
    expect(sessionLabel(session({ summary: "obj", preview: "prev" }))).toBe("obj");
    expect(sessionLabel(session({ summary: undefined, preview: "prev" }))).toBe("prev");
    expect(sessionLabel(session({ summary: "", preview: "" }))).toBe("(no prompt)");
  });
});

describe("sessionMeta", () => {
  it("is age · N msgs · model, with the model omitted when absent", () => {
    expect(sessionMeta(session({ savedAt: NOW - 5 * MINUTE, messageCount: 12, model: "gpt-5.5" }), NOW)).toBe(
      "5m · 12 msgs · gpt-5.5",
    );
    expect(sessionMeta(session({ messageCount: 1, model: undefined }), NOW)).toBe("5m · 1 msg");
  });

  it("drops a blank age rather than printing a dangling separator", () => {
    // savedAt of 0 is the store's unorderable sentinel; relativeAge returns "".
    expect(sessionMeta(session({ savedAt: 0, messageCount: 3, model: "m" }), NOW)).toBe("3 msgs · m");
  });
});

describe("resumeItems", () => {
  it("groups this project first, then other projects, newest-first within each", () => {
    const items = resumeItems({ sessions: SESSIONS, currentCwd: "/home/op/project-a", now: NOW });
    expect(items.map((item) => item.id)).toEqual(["s-here-new", "s-here-old", "s-elsewhere"]);
    expect(items.map((item) => item.category)).toEqual([CATEGORY_THIS, CATEGORY_THIS, CATEGORY_OTHER]);
  });

  it("renders a flat, uncategorised list when no current directory is given", () => {
    const items = resumeItems({ sessions: SESSIONS, now: NOW });
    expect(items.every((item) => item.category === undefined)).toBe(true);
    expect(items.map((item) => item.id)).toEqual(SESSIONS.map((s) => s.id));
  });

  it("marks the current session and no other", () => {
    const items = resumeItems({ sessions: SESSIONS, currentId: "s-here-old", now: NOW });
    expect(items.filter((item) => item.current).map((item) => item.id)).toEqual(["s-here-old"]);
  });

  it("filters AND-over-terms across summary and preview only", () => {
    // "ssrf" is only in a summary; "image" only in a preview.
    expect(resumeItems({ sessions: SESSIONS, now: NOW, filter: "ssrf image" }).map((i) => i.id)).toEqual([
      "s-elsewhere",
    ]);
    // A term present nowhere in summary/preview (a model id) matches nothing.
    expect(resumeItems({ sessions: SESSIONS, now: NOW, filter: "gpt-5.5" })).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Absolute timestamp
// ---------------------------------------------------------------------------

describe("formatSavedAt", () => {
  it("renders a stable UTC stamp and blanks an unorderable one", () => {
    expect(formatSavedAt(Date.UTC(2026, 7, 22, 14, 30))).toBe("2026-08-22 14:30 UTC");
    expect(formatSavedAt(0)).toBe("");
    expect(formatSavedAt(Number.NaN)).toBe("");
  });
});

// ---------------------------------------------------------------------------
// Detail pane
// ---------------------------------------------------------------------------

describe("resumeDetailLines", () => {
  it("leads with the objective and shows the opening prompt beneath it", () => {
    const lines = resumeDetailLines({ session: SESSIONS[0], now: NOW }, 60);
    const text = lines.map((line) => line.text).join("\n");
    expect(text).toContain("IDOR sweep of the billing API");
    expect(text).toContain("Opened with: look at /api/invoices for idor");
  });

  it("carries the full metadata block and omits absent optional fields", () => {
    const text = resumeDetailLines({ session: SESSIONS[0], now: NOW }, 60)
      .map((line) => line.text)
      .join("\n");
    expect(text).toContain("Messages: 40");
    expect(text).toContain("Model: gpt-5.5");
    expect(text).toContain("Mode: auto");
    expect(text).toContain("Target: app.example.com");
    expect(text).toContain("Cwd: /home/op/project-a");
    expect(text).toMatch(/Saved: .+ UTC \(1m ago\)/);

    // s-here-old has no summary, mode or target — those lines must be absent.
    const bare = resumeDetailLines({ session: SESSIONS[1], now: NOW }, 60)
      .map((line) => line.text)
      .join("\n");
    expect(bare).not.toContain("Mode:");
    expect(bare).not.toContain("Target:");
    expect(bare).toContain("enumerate subdomains");
  });

  it("returns nothing for a missing session or a zero-width pane", () => {
    expect(resumeDetailLines({ session: undefined, now: NOW }, 60)).toEqual([]);
    expect(resumeDetailLines({ session: SESSIONS[0], now: NOW }, 0)).toEqual([]);
  });
});

describe("clipResumeDetailLines", () => {
  it("caps the line count and marks the cut", () => {
    const lines = resumeDetailLines({ session: SESSIONS[0], now: NOW }, 40);
    const clipped = clipResumeDetailLines(lines, 3, 40);
    expect(clipped).toHaveLength(3);
    expect(clipped[2]?.text.endsWith("...")).toBe(true);
  });

  it("returns the lines untouched when they already fit", () => {
    const lines = resumeDetailLines({ session: SESSIONS[1], now: NOW }, 40);
    expect(clipResumeDetailLines(lines, 100, 40)).toEqual(lines);
  });
});

// ---------------------------------------------------------------------------
// Hints and keys
// ---------------------------------------------------------------------------

describe("resumeFooterHint", () => {
  it("names the real bindings per mode", () => {
    expect(resumeFooterHint("browse")).toContain("enter resume");
    expect(resumeFooterHint("browse")).toContain("d delete");
    expect(resumeFooterHint("browse", true)).toContain("esc clear filter");
    expect(resumeFooterHint("filter")).toContain("type to filter");
    expect(resumeFooterHint("confirm-delete")).toContain("confirm delete");
  });

  it("drops resume/delete when there is nothing to act on", () => {
    const empty = resumeFooterHint("browse", false, false);
    expect(empty).not.toContain("enter resume");
    expect(empty).not.toContain("d delete");
  });
});

describe("isFilterKey", () => {
  it("accepts printable single characters and rejects control/non-strings", () => {
    expect(isFilterKey("a")).toBe(true);
    expect(isFilterKey(" ")).toBe(true);
    expect(isFilterKey("")).toBe(false);
    expect(isFilterKey("ab")).toBe(false);
    expect(isFilterKey(undefined)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Overflow sweep — the detail pane must fit the box the panel hands it.
// ---------------------------------------------------------------------------

/**
 * Mirrors exactly how `ResumeScreen` sizes the panel and the detail pane, so a
 * green sweep here is a proof about what the screen renders.
 */
function paneFor(width: number, height: number, totalRows: number, hasStatus: boolean) {
  const contentWidth = Math.max(0, width - 4);
  const bodyRows = Math.max(0, height - shellChromeRows(width) - (hasStatus ? 1 : 0));
  const panel = computeDialogPanel({
    width: contentWidth,
    height,
    size: "large",
    totalRows,
    withDetail: true,
    bodyRows,
  });
  return { contentWidth, panel };
}

describe("detail-pane overflow sweep", () => {
  // A pathological session: long objective, long preview, long cwd/target, so
  // wrapping and clipping are actually exercised at every width.
  const HEAVY = session({
    id: "heavy",
    summary:
      "A very long engagement objective that keeps going well past any reasonable pane width so it must wrap across several rows without ever overhanging the box",
    preview:
      "an equally long opening prompt naming a target host and a scope and a bunch of paths under test /a/b/c/d/e/f/g",
    cwd: "/home/operator/very/deeply/nested/engagement/working/directory/project",
    target: "some-very-long-subdomain.staging.internal.corp.example.com",
    model: "claude-opus-4.1-thinking",
    mode: "autonomous",
    messageCount: 137,
  });

  it("never overflows at 80x24 or 120x40", () => {
    for (const [w, h] of [
      [80, 24],
      [120, 40],
    ] as const) {
      for (const hasStatus of [false, true]) {
        const { panel } = paneFor(w, h, 30, hasStatus);
        expect(panel.showDetail).toBe(true);
        const lines = clipResumeDetailLines(
          resumeDetailLines({ session: HEAVY, now: NOW, compact: panel.visibleRows < 12 }, panel.detailWidth),
          panel.visibleRows,
          panel.detailWidth,
        );
        expect(lines.length).toBeLessThanOrEqual(panel.visibleRows);
        for (const line of lines) expect(line.text.length).toBeLessThanOrEqual(panel.detailWidth);
      }
    }
  });

  it("fits the detail pane across a full width/height sweep", () => {
    for (let width = 40; width <= 200; width += 7) {
      for (let height = 8; height <= 60; height += 5) {
        const { panel } = paneFor(width, height, 40, height % 2 === 0);
        if (!panel.showDetail) continue;
        const lines = clipResumeDetailLines(
          resumeDetailLines({ session: HEAVY, now: NOW, compact: panel.visibleRows < 12 }, panel.detailWidth),
          panel.visibleRows,
          panel.detailWidth,
        );
        expect(lines.length).toBeLessThanOrEqual(panel.visibleRows);
        for (const line of lines) {
          expect(line.text.length).toBeLessThanOrEqual(panel.detailWidth);
        }
      }
    }
  });

  it("keeps the interleaved-heading row count in step with buildDialogRows", () => {
    // The screen's inline totalRows counter must match what the shared body
    // actually renders, or the window math scrolls against the wrong total.
    const items = resumeItems({ sessions: SESSIONS, currentCwd: "/home/op/project-a", now: NOW });
    let count = 0;
    let group: string | undefined;
    for (const item of items) {
      if (item.category && item.category !== group) {
        group = item.category;
        count += 1;
      }
      count += 1;
    }
    expect(count).toBe(buildDialogRows(items).length);
  });
});
