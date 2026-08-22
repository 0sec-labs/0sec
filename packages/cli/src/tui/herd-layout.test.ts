import { describe, expect, it } from "vitest";

import {
  HERD_PEER_TTL_MS,
  HERD_STATUS_ORDER,
  abbreviateHomePath,
  buildHerdRows,
  clampHerdSelection,
  clipDetailLines,
  computeHerdLayout,
  computeHerdWindow,
  firstSelectableIndex,
  formatRelativeAge,
  herdDetailLines,
  herdListTitle,
  herdRowLabelText,
  herdRowStatusText,
  herdStatusOf,
  isPeerStale,
  lastSelectableIndex,
  moveHerdSelection,
  wrapCells,
  type HerdLayout,
  type HerdPeer,
  type HerdRow,
  type HerdStatus,
} from "./herd-layout.js";

const isInteger = (value: number): boolean => Number.isInteger(value) && value >= 0;

const NOW = 1_000_000_000;

/** A peer that is `ageMs` old as of {@link NOW}, in the given phase. */
function peer(id: string, over: Partial<HerdPeer> = {}): HerdPeer {
  return {
    id,
    kind: "session",
    pid: 4242,
    cwd: "/home/dev/project",
    lastSeen: NOW,
    ...over,
  };
}

/** One peer per status bucket, so grouping has something in every group. */
function everyStatusRoster(): HerdPeer[] {
  return [
    peer("work", { activity: { phase: "working" } }),
    peer("idleone"),
    peer("blk", { activity: { phase: "blocked" } }),
    peer("fin", { activity: { phase: "done" } }),
    peer("dead", { lastSeen: NOW - HERD_PEER_TTL_MS - 1 }),
  ];
}

// ---------------------------------------------------------------------------
// Status derivation — must match registry.isStale at the TTL boundary
// ---------------------------------------------------------------------------

describe("status derivation mirrors registry.statusOf", () => {
  it("is INCLUSIVE-ALIVE at the TTL boundary", () => {
    // age exactly == ttl is still active; age one ms past becomes stale.
    const atBoundary = peer("p", { lastSeen: NOW - HERD_PEER_TTL_MS });
    const pastBoundary = peer("p", { lastSeen: NOW - HERD_PEER_TTL_MS - 1 });
    expect(isPeerStale(atBoundary, NOW)).toBe(false);
    expect(isPeerStale(pastBoundary, NOW)).toBe(true);
    expect(herdStatusOf(atBoundary, NOW)).not.toBe("stale");
    expect(herdStatusOf(pastBoundary, NOW)).toBe("stale");
  });

  it("honours a custom ttl and falls back on a bad one", () => {
    const p = peer("p", { lastSeen: NOW - 100 });
    expect(isPeerStale(p, NOW, 50)).toBe(true);
    expect(isPeerStale(p, NOW, 200)).toBe(false);
    // non-positive / non-finite ttl falls back to the default (not "everything stale")
    expect(isPeerStale(p, NOW, 0)).toBe(false);
    expect(isPeerStale(p, NOW, Number.NaN)).toBe(false);
    expect(isPeerStale(p, NOW, -5)).toBe(false);
  });

  it("stale wins over an activity phase", () => {
    const p = peer("p", {
      lastSeen: NOW - HERD_PEER_TTL_MS - 1,
      activity: { phase: "working" },
    });
    expect(herdStatusOf(p, NOW)).toBe("stale");
  });

  it("an active peer with no activity is idle", () => {
    expect(herdStatusOf(peer("p"), NOW)).toBe("idle");
  });
});

// ---------------------------------------------------------------------------
// Grouping
// ---------------------------------------------------------------------------

describe("buildHerdRows — grouping", () => {
  it("buckets peers into the right groups, in stable order, with counts", () => {
    const rows = buildHerdRows(everyStatusRoster(), NOW);
    const headings = rows.filter((r): r is Extract<HerdRow, { kind: "heading" }> => r.kind === "heading");
    expect(headings.map((h) => h.status)).toEqual(HERD_STATUS_ORDER);
    for (const h of headings) expect(h.count).toBe(1);
  });

  it("omits empty groups", () => {
    const rows = buildHerdRows([peer("a"), peer("b")], NOW); // both idle
    const statuses = new Set(rows.map((r) => r.status));
    expect([...statuses]).toEqual(["idle"]);
    expect(rows[0]).toMatchObject({ kind: "heading", status: "idle", count: 2 });
    expect(rows.filter((r) => r.kind === "peer")).toHaveLength(2);
  });

  it("preserves provider order within a group", () => {
    const rows = buildHerdRows([peer("first"), peer("second"), peer("third")], NOW);
    const ids = rows.filter((r) => r.kind === "peer").map((r) => (r.kind === "peer" ? r.peer.id : ""));
    expect(ids).toEqual(["first", "second", "third"]);
  });

  it("an all-empty roster yields no rows (empty state), not a crash", () => {
    expect(buildHerdRows([], NOW)).toEqual([]);
    // and the title reflects it
    const window = computeHerdWindow({ rows: [], selected: -1, visible: 10 });
    expect(herdListTitle(window)).toBe("HERD 0");
  });

  it("ignores malformed roster entries", () => {
    const rows = buildHerdRows(
      [peer("ok"), undefined as unknown as HerdPeer, { id: 5 } as unknown as HerdPeer],
      NOW,
    );
    expect(rows.filter((r) => r.kind === "peer")).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

describe("navigation skips headings, wraps and clamps", () => {
  const rows = buildHerdRows(everyStatusRoster(), NOW);

  it("first/last selectable land on peers, never headings", () => {
    expect(rows[firstSelectableIndex(rows)]?.kind).toBe("peer");
    expect(rows[lastSelectableIndex(rows)]?.kind).toBe("peer");
  });

  it("moving down never stops on a heading", () => {
    let index = firstSelectableIndex(rows);
    for (let step = 0; step < rows.length * 2; step++) {
      index = moveHerdSelection(rows, index, 1);
      expect(rows[index]?.kind).toBe("peer");
    }
  });

  it("wraps from last peer forward to first and vice versa", () => {
    const first = firstSelectableIndex(rows);
    const last = lastSelectableIndex(rows);
    expect(moveHerdSelection(rows, last, 1)).toBe(first);
    expect(moveHerdSelection(rows, first, -1)).toBe(last);
  });

  it("clamps a stale index onto a peer", () => {
    expect(rows[clampHerdSelection(rows, 0)]?.kind).toBe("peer"); // 0 is a heading
    expect(rows[clampHerdSelection(rows, 999)]?.kind).toBe("peer");
    expect(clampHerdSelection([], 3)).toBe(-1);
  });

  it("a heading-only list terminates rather than spinning", () => {
    const headingOnly: HerdRow[] = [{ kind: "heading", status: "idle", count: 0 }];
    expect(moveHerdSelection(headingOnly, 0, 1)).toBe(-1);
    expect(firstSelectableIndex(headingOnly)).toBe(-1);
  });
});

// ---------------------------------------------------------------------------
// Windowing keeps the selection visible
// ---------------------------------------------------------------------------

describe("computeHerdWindow", () => {
  const rows = buildHerdRows(
    Array.from({ length: 20 }, (_, i) => peer(`p${i}`)),
    NOW,
  );

  it("keeps the cursor inside the window as it moves", () => {
    let anchor = 0;
    let selected = firstSelectableIndex(rows);
    for (let step = 0; step < 60; step++) {
      const window = computeHerdWindow({ rows, selected, visible: 6, anchor });
      expect(selected).toBeGreaterThanOrEqual(window.start);
      expect(selected).toBeLessThan(window.end);
      expect(window.end - window.start).toBe(window.count);
      anchor = window.start;
      selected = moveHerdSelection(rows, selected, 1);
    }
  });

  it("pulls in the group heading above the cursor when it can", () => {
    const grouped = buildHerdRows(everyStatusRoster(), NOW);
    // select the first peer of the "idle" group (its heading sits just above)
    const idleHeading = grouped.findIndex((r) => r.kind === "heading" && r.status === "idle");
    const firstIdlePeer = idleHeading + 1;
    const window = computeHerdWindow({ rows: grouped, selected: firstIdlePeer, visible: 3, anchor: firstIdlePeer });
    expect(window.start).toBeLessThanOrEqual(idleHeading);
  });

  it("degrades to empty at zero capacity", () => {
    const window = computeHerdWindow({ rows, selected: 1, visible: 0 });
    expect(window).toMatchObject({ start: 0, end: 0, count: 0 });
  });
});

// ---------------------------------------------------------------------------
// The sweep — nothing exceeds its container, at any geometry
// ---------------------------------------------------------------------------

function layoutNumbers(layout: HerdLayout): [string, number][] {
  return [
    ["contentWidth", layout.contentWidth],
    ["bodyRows", layout.bodyRows],
    ["paneGap", layout.paneGap],
    ["visibleRows", layout.visibleRows],
    ["list.width", layout.list.width],
    ["list.innerWidth", layout.list.innerWidth],
    ["list.height", layout.list.height],
    ["list.bodyRows", layout.list.bodyRows],
    ["detail.width", layout.detail.width],
    ["detail.innerWidth", layout.detail.innerWidth],
    ["detail.height", layout.detail.height],
    ["detail.bodyRows", layout.detail.bodyRows],
    ["row.width", layout.row.width],
    ["row.markerWidth", layout.row.markerWidth],
    ["row.markerGap", layout.row.markerGap],
    ["row.labelWidth", layout.row.labelWidth],
    ["row.statusGap", layout.row.statusGap],
    ["row.statusWidth", layout.row.statusWidth],
  ];
}

describe("computeHerdLayout — the sweep", () => {
  it("never lets a pane, a row or a column exceed what it was given", () => {
    for (let width = 0; width <= 200; width++) {
      for (let height = 0; height <= 80; height++) {
        const layout = computeHerdLayout({ width, height });
        const at = `${width}x${height}`;

        for (const [name, value] of layoutNumbers(layout)) {
          expect(isInteger(value), `${name} was ${value} at ${at}`).toBe(true);
        }

        expect(layout.contentWidth, `contentWidth exceeded width at ${at}`).toBeLessThanOrEqual(
          Math.max(0, width - 4),
        );

        // horizontal: panes + gap fit the content column
        if (layout.stacked) {
          expect(layout.list.width, `stacked list too wide at ${at}`).toBeLessThanOrEqual(
            layout.contentWidth,
          );
          expect(layout.detail.width, `stacked detail too wide at ${at}`).toBeLessThanOrEqual(
            layout.contentWidth,
          );
          expect(layout.paneGap, `stacked panes had a horizontal gap at ${at}`).toBe(0);
        } else if (layout.list.width > 0 && layout.detail.width > 0) {
          const claimed = layout.list.width + layout.paneGap + layout.detail.width;
          expect(claimed, `panes claimed ${claimed} of ${layout.contentWidth} at ${at}`)
            .toBeLessThanOrEqual(layout.contentWidth);
        }

        // the row columns sum EXACTLY to the row width, which is the list inner width
        const row = layout.row;
        expect(row.width, `row wider than the list pane at ${at}`).toBe(layout.list.innerWidth);
        const rowClaimed =
          row.markerWidth + row.markerGap + row.labelWidth + row.statusGap + row.statusWidth;
        expect(rowClaimed, `row claimed ${rowClaimed} of ${row.width} at ${at}`).toBe(row.width);

        // vertical: panes fit the body rows
        expect(layout.list.height, `list taller than the body at ${at}`).toBeLessThanOrEqual(
          layout.bodyRows,
        );
        expect(layout.detail.height, `detail taller than the body at ${at}`).toBeLessThanOrEqual(
          layout.bodyRows,
        );
        if (layout.stacked && layout.list.height > 0 && layout.detail.height > 0) {
          const rows = layout.list.height + layout.detail.height;
          expect(rows, `stacked panes claimed ${rows} of ${layout.bodyRows} rows at ${at}`)
            .toBeLessThanOrEqual(layout.bodyRows);
        }
        expect(layout.visibleRows, `visibleRows exceeded the list body at ${at}`)
          .toBeLessThanOrEqual(layout.list.bodyRows);

        // per-pane internal consistency
        for (const pane of [layout.list, layout.detail]) {
          if (pane.width > 0) expect(pane.innerWidth, `zero-width pane at ${at}`).toBeGreaterThan(0);
          if (pane.height > 0) expect(pane.bodyRows, `zero-body pane at ${at}`).toBeGreaterThan(0);
          expect(pane.innerWidth).toBeLessThanOrEqual(pane.width);
          expect(pane.bodyRows).toBeLessThanOrEqual(pane.height);
          if (pane.width > 0) {
            expect(pane.width - pane.innerWidth).toBe(layout.bordered ? 4 : 0);
          }
        }
      }
    }
  });

  it("keeps the body inside the terminal once the shell has taken its chrome", () => {
    for (let width = 0; width <= 200; width++) {
      for (let height = 0; height <= 80; height++) {
        const layout = computeHerdLayout({ width, height });
        expect(
          layout.bodyRows + shellChromeRowsAt(width),
          `body + chrome exceeded height at ${width}x${height}`,
        ).toBeLessThanOrEqual(Math.max(height, shellChromeRowsAt(width)));
      }
    }
  });

  it("survives garbage geometry without throwing or producing garbage", () => {
    const junk = [Number.NaN, Infinity, -Infinity, -10, 3.7, undefined, null];
    for (const width of junk) {
      for (const height of junk) {
        const layout = computeHerdLayout({ width: width as number, height: height as number });
        for (const [name, value] of layoutNumbers(layout)) {
          expect(isInteger(value), `${name} was ${value} at ${String(width)}x${String(height)}`).toBe(true);
        }
      }
    }
  });

  it("stacks on a narrow terminal and splits on a wide one", () => {
    expect(computeHerdLayout({ width: 60, height: 40 }).stacked).toBe(true);
    expect(computeHerdLayout({ width: 79, height: 40 }).stacked).toBe(true);
    expect(computeHerdLayout({ width: 120, height: 40 }).stacked).toBe(false);
  });

  it("drops pane borders before it drops rows of content", () => {
    expect(computeHerdLayout({ width: 120, height: 40 }).bordered).toBe(true);
    expect(computeHerdLayout({ width: 120, height: 10 }).bordered).toBe(false);
  });
});

/** Re-derive the shell chrome the same way the layout does, for the body test. */
function shellChromeRowsAt(width: number): number {
  const total = Math.max(0, Math.trunc(width));
  const headerContentWidth = total - 4 - 4;
  const headerContentRows = headerContentWidth < 88 ? 3 : 2;
  const contentWidth = Math.max(1, total - 4);
  const footerRows = contentWidth >= 64 ? 1 : 3;
  return 1 + (headerContentRows + 3) + footerRows;
}

// ---------------------------------------------------------------------------
// Untrusted display — control characters are stripped
// ---------------------------------------------------------------------------

describe("untrusted peer fields render stripped", () => {
  const evil = "a\x1b[2Jb\x07‮c\td"; // CSI clear, BEL, RTL override, tab

  it("strips control characters from label and cwd", () => {
    const p = peer("id", { label: evil, cwd: `/home/dev/${evil}` });
    expect(herdRowLabelText(p)).not.toMatch(/[\x00-\x1f\x7f‮]/);
    expect(abbreviateHomePath(p.cwd, "/home/dev")).not.toMatch(/[\x00-\x1f\x7f‮]/);
    // ~ abbreviation still applies under home
    expect(abbreviateHomePath("/home/dev/project", "/home/dev")).toBe("~/project");
    expect(abbreviateHomePath("/home/dev", "/home/dev")).toBe("~");
  });

  it("strips control characters from detail lines and the status column", () => {
    const p = peer("id", {
      label: evil,
      cwd: `/x/${evil}`,
      activity: { phase: "working", tool: evil, note: evil },
    });
    for (const line of herdDetailLines(p, [], 60, NOW)) {
      expect(line.text, `detail line leaked control chars: ${JSON.stringify(line.text)}`)
        .not.toMatch(/[\x00-\x08\x0b-\x1f\x7f‮]/);
    }
    expect(herdRowStatusText(p, "working")).not.toMatch(/[\x00-\x1f\x7f‮]/);
  });

  it("strips control characters from an untrusted inbox message", () => {
    const p = peer("id");
    const lines = herdDetailLines(p, [{ from: "peer", body: evil, ts: NOW }], 60, NOW);
    for (const line of lines) {
      expect(line.text).not.toMatch(/[\x00-\x08\x0b-\x1f\x7f‮]/);
    }
  });
});

// ---------------------------------------------------------------------------
// Detail pane + helpers
// ---------------------------------------------------------------------------

describe("herdDetailLines", () => {
  it("returns nothing without a peer or width", () => {
    expect(herdDetailLines(undefined, [], 40, NOW)).toEqual([]);
    expect(herdDetailLines(peer("p"), [], 0, NOW)).toEqual([]);
  });

  it("reports an empty inbox honestly and a populated one with a count", () => {
    const empty = herdDetailLines(peer("p"), [], 60, NOW).map((l) => l.text);
    expect(empty).toContain("Inbox: empty");
    const full = herdDetailLines(
      peer("p"),
      [
        { from: "a", body: "hi", ts: NOW },
        { from: "b", body: "yo", ts: NOW },
      ],
      60,
      NOW,
    ).map((l) => l.text);
    expect(full).toContain("Inbox (2)");
  });

  it("no line ever exceeds the width", () => {
    const p = peer("p", {
      label: "a very long engagement label that will need wrapping across lines",
      cwd: "/home/dev/some/deeply/nested/project/directory/that/keeps/going",
      activity: { phase: "working", turn: 3, maxTurns: 8, tool: "read_file", note: "poking at auth" },
    });
    for (let width = 1; width <= 80; width++) {
      for (const line of herdDetailLines(p, [{ from: "peer", body: "a ".repeat(60), ts: NOW }], width, NOW)) {
        expect(line.text.length, `line "${line.text}" exceeded ${width}`).toBeLessThanOrEqual(width);
      }
    }
  });

  it("clipDetailLines marks the cut", () => {
    const lines = herdDetailLines(peer("p"), [], 40, NOW);
    const clipped = clipDetailLines(lines, 3, 40);
    expect(clipped).toHaveLength(3);
    expect(clipped.at(-1)?.text).toContain("...");
    expect(clipDetailLines(lines, 0, 40)).toEqual([]);
  });
});

describe("formatRelativeAge", () => {
  it("reads as expected across scales", () => {
    expect(formatRelativeAge(NOW, NOW)).toBe("just now");
    expect(formatRelativeAge(NOW + 5000, NOW)).toBe("just now"); // clock skew -> not the future
    expect(formatRelativeAge(NOW - 3000, NOW)).toBe("3s ago");
    expect(formatRelativeAge(NOW - 5 * 60_000, NOW)).toBe("5m ago");
    expect(formatRelativeAge(NOW - 2 * 3_600_000, NOW)).toBe("2h ago");
    expect(formatRelativeAge(NOW - 3 * 86_400_000, NOW)).toBe("3d ago");
  });
});

describe("wrapCells", () => {
  it("never emits a line wider than the limit and hard-breaks long tokens", () => {
    const long = "supercalifragilisticexpialidocious";
    for (let width = 1; width <= 40; width++) {
      for (const line of wrapCells(`${long} short words here ${long}`, width)) {
        expect(line.length).toBeLessThanOrEqual(width);
      }
    }
    expect(wrapCells("", 10)).toEqual([]);
    expect(wrapCells("x", 0)).toEqual([]);
  });
});

describe("herdRowStatusText", () => {
  it("prefers tool, then turn counter, then the status word", () => {
    expect(herdRowStatusText(peer("p", { activity: { phase: "working", tool: "grep" } }), "working")).toBe("grep");
    expect(herdRowStatusText(peer("p", { activity: { phase: "working", turn: 2, maxTurns: 9 } }), "working")).toBe("2/9");
    expect(herdRowStatusText(peer("p", { activity: { phase: "working", turn: 2 } }), "working")).toBe("t2");
    expect(herdRowStatusText(peer("p"), "idle")).toBe("idle");
    // stale never shows a stale tool as if it were live
    expect(herdRowStatusText(peer("p", { activity: { tool: "grep" } }), "stale")).toBe("stale");
  });
});
