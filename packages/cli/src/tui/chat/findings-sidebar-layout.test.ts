import { describe, expect, it } from "vitest";
import {
  budgetWrappedRows,
  findingSeverityCells,
  findingTitleFirstWidth,
  wrapFinding,
  type SidebarFinding,
} from "./findings-sidebar-layout.js";

describe("findingSeverityCells", () => {
  it("shows the whole severity word when the column has room", () => {
    expect(findingSeverityCells("high", 24)).toBe(4);
    expect(findingSeverityCells("critical", 24)).toBe(8);
  });

  it("caps the badge so the title keeps at least four cells", () => {
    // width 8 → at most 8-4 = 4 badge cells even for a longer word.
    expect(findingSeverityCells("critical", 8)).toBe(4);
  });

  it("collapses to zero in a column too narrow for both", () => {
    expect(findingSeverityCells("high", 4)).toBe(0);
    expect(findingSeverityCells("high", 3)).toBe(0);
  });
});

describe("findingTitleFirstWidth", () => {
  it("reserves the badge and its gap on the first line", () => {
    expect(findingTitleFirstWidth(24, 4)).toBe(19);
    expect(findingTitleFirstWidth(20, 0)).toBe(20);
  });

  it("never returns less than one cell", () => {
    expect(findingTitleFirstWidth(2, 4)).toBe(1);
  });

  it("first line + badge + gap never exceed the column", () => {
    for (let width = 1; width <= 40; width++) {
      for (const sev of ["info", "low", "medium", "high", "critical"]) {
        const badge = findingSeverityCells(sev, width);
        const first = findingTitleFirstWidth(width, badge);
        const consumed = first + (badge > 0 ? badge + 1 : 0);
        expect(consumed).toBeLessThanOrEqual(Math.max(1, width));
      }
    }
  });
});

describe("wrapFinding", () => {
  const finding: SidebarFinding = {
    title: "Unsafe tar extraction of attacker-controlled archive leads to RCE",
    severity: "high",
    id: "F-1",
  };

  it("wraps the title to at most two rows by default", () => {
    const wrapped = wrapFinding(finding, 20);
    expect(wrapped.rows).toBeLessThanOrEqual(2);
    expect(wrapped.rows).toBe(wrapped.lines.length);
    expect(wrapped.severityCells).toBe(4);
  });

  it("sweep: line one fits beside the badge and later lines fit the column", () => {
    const samples: SidebarFinding[] = [
      { title: "SSRF in webhook fetcher", severity: "medium" },
      {
        title: "Unauthenticated RCE via deserialization of session cookie payload",
        severity: "critical",
      },
      { title: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", severity: "low" },
      { title: "info leak", severity: "info" },
    ];
    for (const sample of samples) {
      for (let width = 1; width <= 40; width++) {
        for (const maxLines of [1, 2, 3]) {
          const wrapped = wrapFinding(sample, width, maxLines);
          expect(wrapped.rows).toBeGreaterThanOrEqual(1);
          expect(wrapped.rows).toBeLessThanOrEqual(maxLines);
          const firstWidth = findingTitleFirstWidth(width, wrapped.severityCells);
          wrapped.lines.forEach((line, idx) => {
            const limit = idx === 0 ? firstWidth : width;
            expect(line.length).toBeLessThanOrEqual(limit);
          });
          // The whole first line — title slice + badge + gap — fits the column.
          const consumed =
            firstWidth + (wrapped.severityCells > 0 ? wrapped.severityCells + 1 : 0);
          expect(consumed).toBeLessThanOrEqual(Math.max(1, width));
        }
      }
    }
  });
});

describe("findings section budgeting", () => {
  const makeFindings = (n: number): SidebarFinding[] =>
    Array.from({ length: n }, (_, i) => ({
      title: `Finding number ${i} with a fairly long descriptive title to force wrapping`,
      severity: ["info", "low", "medium", "high", "critical"][i % 5],
      id: `F-${i}`,
    }));

  it("sweep: rendered rows never exceed the item budget and all items are accounted for", () => {
    for (const width of [20, 34]) {
      for (let count = 0; count <= 12; count++) {
        const findings = makeFindings(count);
        const wrapped = findings.map((f) => wrapFinding(f, width));
        for (let itemRows = 0; itemRows <= 12; itemRows++) {
          const { visible, overflow } = budgetWrappedRows(
            wrapped.map((w) => w.rows),
            itemRows,
          );
          const shown = wrapped.slice(Math.max(0, wrapped.length - visible));
          const paintedItemRows = shown.reduce((acc, w) => acc + w.rows, 0);
          const painted = paintedItemRows + (overflow > 0 ? 1 : 0);
          if (itemRows > 0) expect(painted).toBeLessThanOrEqual(itemRows);
          else expect(visible).toBe(0);
          expect(visible + overflow).toBe(count);
        }
      }
    }
  });
});
