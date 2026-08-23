import { describe, expect, it } from "vitest";

import type { Finding } from "@0sec/shared";

import {
  buildFindingRows,
  computeActionRow,
  computeFindingDetailLayout,
  computeFindingKvLayout,
  computeScrollWindow,
  findingActions,
  findingDetailFooterHint,
  findingDetailTitle,
  maxScrollOffset,
  severityDetailTone,
  type FindingDetailLayout,
} from "./finding-detail-layout.js";

const isInteger = (value: number): boolean => Number.isInteger(value) && value >= 0;

/** Every cell and row count a layout exposes, flattened for the sweep. */
function layoutNumbers(layout: FindingDetailLayout): [string, number][] {
  return [
    ["contentWidth", layout.contentWidth],
    ["bodyRows", layout.bodyRows],
    ["actionRows", layout.actionRows],
    ["pane.width", layout.pane.width],
    ["pane.innerWidth", layout.pane.innerWidth],
    ["pane.height", layout.pane.height],
    ["pane.bodyRows", layout.pane.bodyRows],
    ["kv.width", layout.kv.width],
    ["kv.labelWidth", layout.kv.labelWidth],
    ["kv.gap", layout.kv.gap],
    ["kv.valueWidth", layout.kv.valueWidth],
    ["action.width", layout.action.width],
    ["action.count", layout.action.count],
    ["action.cellWidth", layout.action.cellWidth],
    ["action.gap", layout.action.gap],
    ["visibleRows", layout.visibleRows],
  ];
}

// ---------------------------------------------------------------------------

describe("computeFindingDetailLayout — the sweep", () => {
  /**
   * The invariant this whole module exists for: no allocation may exceed the
   * container it was carved out of, on either axis, at any terminal size. Yoga
   * does not clip — a row of siblings claiming more cells than the row has is
   * shrunk, not truncated, and a box claiming more rows than its column has
   * paints its own bottom border through its last line. Both are silent at
   * compile time.
   */
  it("never lets the pane, a row or the action buttons exceed what they were given", () => {
    for (let width = 0; width <= 200; width++) {
      for (let height = 0; height <= 80; height++) {
        const actionCount = (width + height) % 5; // 0..4 buttons, swept too
        const layout = computeFindingDetailLayout({ width, height, actionCount });
        const at = `${width}x${height} (${actionCount} actions)`;

        for (const [name, value] of layoutNumbers(layout)) {
          expect(isInteger(value), `${name} was ${value} at ${at}`).toBe(true);
        }

        // -- horizontal --
        expect(layout.contentWidth, `contentWidth exceeded width at ${at}`).toBeLessThanOrEqual(
          Math.max(0, width),
        );
        expect(layout.pane.width, `pane wider than content at ${at}`).toBeLessThanOrEqual(
          layout.contentWidth,
        );

        // -- key/value row columns --
        const kv = layout.kv;
        expect(kv.width, `kv row wider than the pane at ${at}`).toBe(layout.pane.innerWidth);
        expect(
          kv.labelWidth + kv.gap + kv.valueWidth,
          `kv claimed ${kv.labelWidth + kv.gap + kv.valueWidth} of ${kv.width} at ${at}`,
        ).toBe(kv.width);
        if (kv.valueWidth > 0) {
          expect(kv.gap, `kv value had no gap at ${at}`).toBe(1);
          expect(kv.labelWidth, `kv label squeezed out at ${at}`).toBeGreaterThan(0);
        }

        // -- action row buttons --
        const action = layout.action;
        expect(action.width, `action row wider than content at ${at}`).toBeLessThanOrEqual(
          layout.contentWidth,
        );
        if (action.count > 0) {
          expect(
            action.cellWidth * action.count + action.gap * (action.count - 1),
            `action row claimed more than it declared at ${at}`,
          ).toBe(action.width);
          expect(action.cellWidth, `action button squeezed out at ${at}`).toBeGreaterThan(0);
        }

        // -- vertical --
        expect(
          layout.pane.height + layout.actionRows,
          `pane plus actions taller than the body at ${at}`,
        ).toBeLessThanOrEqual(layout.bodyRows);
        expect(
          layout.visibleRows,
          `visibleRows exceeded the pane body at ${at}`,
        ).toBeLessThanOrEqual(layout.pane.bodyRows);

        // A rendered pane always has room for at least one row of content and
        // one cell of text; a pane below that is dropped.
        if (layout.pane.width > 0) {
          expect(layout.pane.innerWidth, `zero-width pane at ${at}`).toBeGreaterThan(0);
        }
        if (layout.pane.height > 0) {
          expect(layout.pane.bodyRows, `zero-body pane at ${at}`).toBeGreaterThan(0);
          const chromeRows = (layout.bordered ? 2 : 0) + 1;
          expect(layout.pane.height - layout.pane.bodyRows, `pane chrome miscounted at ${at}`).toBe(
            chromeRows,
          );
          expect(layout.pane.width - layout.pane.innerWidth).toBe(layout.bordered ? 4 : 0);
        }

        // The action row only appears when a real one was requested.
        if (layout.actionRows > 0) {
          expect(actionCount, `action row reserved with no actions at ${at}`).toBeGreaterThan(0);
        }
      }
    }
  });

  it("survives garbage geometry without throwing or producing garbage", () => {
    for (const width of [Number.NaN, Number.POSITIVE_INFINITY, -100, 0.5, -0]) {
      for (const height of [Number.NaN, Number.POSITIVE_INFINITY, -100, 0.5, -0]) {
        const layout = computeFindingDetailLayout({ width, height, actionCount: 4 });
        for (const [name, value] of layoutNumbers(layout)) {
          expect(isInteger(value), `${name} was ${value} at ${width}x${height}`).toBe(true);
        }
      }
    }
  });
});

describe("computeActionRow", () => {
  it("never claims more than the width it was given", () => {
    for (let width = 0; width <= 200; width++) {
      for (let count = 0; count <= 6; count++) {
        const row = computeActionRow(width, count);
        expect(row.width).toBeLessThanOrEqual(Math.max(0, width));
        if (row.count > 0) {
          expect(row.cellWidth * row.count + row.gap * (row.count - 1)).toBe(row.width);
        }
      }
    }
  });

  it("drops the row when a button cannot get a single cell", () => {
    expect(computeActionRow(2, 4).count).toBe(0);
    expect(computeActionRow(0, 4).count).toBe(0);
    expect(computeActionRow(40, 0).count).toBe(0);
  });
});

describe("computeFindingKvLayout", () => {
  it("keeps the columns inside the row at every width", () => {
    for (let width = 0; width <= 200; width++) {
      const kv = computeFindingKvLayout(width);
      expect(kv.width).toBe(Math.max(0, Math.trunc(width)));
      expect(kv.labelWidth + kv.gap + kv.valueWidth).toBe(kv.width);
    }
  });
});

describe("computeScrollWindow", () => {
  it("clamps the offset and slices within range at every position", () => {
    const total = 40;
    for (let visible = 0; visible <= 50; visible++) {
      for (let offset = -5; offset <= 60; offset++) {
        const window = computeScrollWindow({ total, offset, visible });
        expect(window.start).toBeGreaterThanOrEqual(0);
        expect(window.end).toBeLessThanOrEqual(total);
        expect(window.count).toBe(window.end - window.start);
        expect(window.count).toBeLessThanOrEqual(Math.max(0, Math.trunc(visible)));
        expect(window.start).toBeLessThanOrEqual(maxScrollOffset(total, visible));
      }
    }
  });

  it("reports whether there is more above and below", () => {
    const window = computeScrollWindow({ total: 20, offset: 5, visible: 5 });
    expect(window.hasAbove).toBe(true);
    expect(window.hasBelow).toBe(true);
    const top = computeScrollWindow({ total: 20, offset: 0, visible: 5 });
    expect(top.hasAbove).toBe(false);
    expect(top.hasBelow).toBe(true);
    const fits = computeScrollWindow({ total: 3, offset: 0, visible: 10 });
    expect(fits.hasAbove).toBe(false);
    expect(fits.hasBelow).toBe(false);
  });
});

describe("severityDetailTone", () => {
  it("reserves red (error) for critical and high only", () => {
    expect(severityDetailTone("critical")).toBe("error");
    expect(severityDetailTone("high")).toBe("error");
    expect(severityDetailTone("medium")).toBe("warn");
    expect(severityDetailTone("low")).toBe("accent");
    expect(severityDetailTone("info")).toBe("muted");
    expect(severityDetailTone(undefined)).toBe("text");
  });
});

describe("findingActions / hints / title", () => {
  it("offers status actions only when a status handler is wired", () => {
    expect(findingActions().map((a) => a.key)).toEqual(["f", "c"]);
    expect(findingActions({ canStatus: true }).map((a) => a.key)).toEqual(["f", "c", "v", "d"]);
    expect(findingActions({ canFix: false, canCopy: false }).length).toBe(0);
  });

  it("names the finding in the title, or falls back", () => {
    expect(findingDetailTitle({ id: "F-1" } as Finding)).toBe("FINDING · F-1");
    expect(findingDetailTitle(undefined)).toBe("FINDING");
  });

  it("lists the keys that work in the footer hint", () => {
    const hint = findingDetailFooterHint({ canStatus: true });
    expect(hint).toContain("f fix");
    expect(hint).toContain("c copy report");
    expect(hint).toContain("v verify");
    expect(hint).toContain("esc back");
  });
});

// ---------------------------------------------------------------------------

const SAMPLE: Finding = {
  id: "F-42",
  templateId: "tmpl-xss",
  title: "Reflected XSS in the search parameter",
  description: "The `q` parameter is reflected without encoding, allowing script injection.",
  severity: "high",
  category: "injection" as Finding["category"],
  status: "verified",
  confidence: 0.9,
  cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
  cvssScore: 8.1,
  evidence: {
    request: "GET /search?q=<script>alert(1)</script>\nAuthorization: Bearer abcdef123456",
    response: "<div><script>alert(1)</script></div>",
    analysis: "The payload executes in the victim's browser.",
  },
  remediation: {
    summary: "Encode reflected output.",
    steps: ["Use context-aware output encoding.", "Add a strict CSP."],
    references: ["https://owasp.org/xss"],
  },
  reviewAnnotation: { path: "src/search.ts", startLine: 12, endLine: 18 },
} as Finding;

describe("buildFindingRows", () => {
  it("renders the full finding as tone-tagged rows", () => {
    const rows = buildFindingRows(SAMPLE, 60);
    const flat = rows
      .map((r) => (r.kind === "kv" ? `${r.label}: ${r.value}` : r.kind === "blank" ? "" : r.text))
      .join("\n");
    expect(flat).toContain("Reflected XSS");
    expect(flat).toContain("Severity: HIGH");
    expect(flat).toContain("src/search.ts:12-18");
    expect(flat).toContain("CVSS");
    expect(flat).toContain("https://owasp.org/xss");
    // Severity row is painted red for a high finding.
    const severityRow = rows.find((r) => r.kind === "kv" && r.label === "Severity");
    expect(severityRow && severityRow.kind === "kv" && severityRow.tone).toBe("error");
  });

  it("routes raw evidence through the injected redactor", () => {
    const rows = buildFindingRows(SAMPLE, 200, {
      redact: (t) => t.replace(/Bearer \S+/g, "Bearer <REDACTED>"),
    });
    const flat = rows.map((r) => (r.kind === "text" ? r.text : "")).join("\n");
    expect(flat).not.toContain("abcdef123456");
    expect(flat).toContain("Bearer <REDACTED>");
  });

  it("never lets a rendered line exceed the inner width", () => {
    for (const width of [12, 24, 40, 80, 120]) {
      for (const row of buildFindingRows(SAMPLE, width)) {
        if (row.kind === "text" || row.kind === "heading") {
          expect(row.text.length, `line "${row.text}" exceeded ${width}`).toBeLessThanOrEqual(width);
        }
      }
    }
  });

  it("shows an em-dash for missing fields rather than fabricating them", () => {
    const sparse = { id: "F-0", title: "Bare finding", severity: "low" } as Finding;
    const rows = buildFindingRows(sparse, 60);
    const flat = rows
      .map((r) => (r.kind === "kv" ? `${r.label}: ${r.value}` : r.kind === "text" ? r.text : ""))
      .join("\n");
    expect(flat).toContain("—");
    expect(flat).toContain("Bare finding");
  });

  it("returns a placeholder row when no finding is supplied", () => {
    const rows = buildFindingRows(undefined, 60);
    expect(rows).toEqual([{ kind: "text", text: "No finding selected.", tone: "muted" }]);
  });
});
